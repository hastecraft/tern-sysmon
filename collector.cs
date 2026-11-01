// collector.cs — the System Monitor's sampler, a long-lived native process.
//
// Built once by the plugin with the in-box .NET Framework compiler (C# 5):
//   csc /target:winexe /platform:x64 /optimize+ /out:<data>\sysmon-collector-<hash>.exe collector.cs
// Run as: sysmon-collector.exe <data dir> <owner token>
//
// It reads the kernel directly (NtQuerySystemInformation) instead of the
// Win32_PerfFormattedData_* / PDH performance counters, which are missing on
// machines whose counter registry is broken. Every process is visible this
// way, services included, without elevation.
//
// Protocol, all files in <data dir>:
//   heartbeat      written by the plugin each poll; holds the interval in ms.
//                  The collector exits when it goes stale.
//   owner          the token of the collector the plugin wants; any other
//                  collector exits (a plugin reload starts a new one).
//   snapshot.json  written here every interval, replaced atomically.
//   collector.err  the last fatal error, for the plugin to show.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace TernSysmon
{
    static class Native
    {
        public const int SystemProcessInformation = 5;
        public const int SystemProcessorPerformanceInformation = 8;
        public const uint StatusInfoLengthMismatch = 0xC0000004;

        [DllImport("ntdll.dll")]
        public static extern uint NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returned);

        [StructLayout(LayoutKind.Sequential)]
        public struct MemoryStatusEx
        {
            public uint Length;
            public uint MemoryLoad;
            public ulong TotalPhys;
            public ulong AvailPhys;
            public ulong TotalPageFile;
            public ulong AvailPageFile;
            public ulong TotalVirtual;
            public ulong AvailVirtual;
            public ulong AvailExtendedVirtual;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx status);

        [StructLayout(LayoutKind.Sequential)]
        public struct PerformanceInformation
        {
            public uint Size;
            public UIntPtr CommitTotal;
            public UIntPtr CommitLimit;
            public UIntPtr CommitPeak;
            public UIntPtr PhysicalTotal;
            public UIntPtr PhysicalAvailable;
            public UIntPtr SystemCache;
            public UIntPtr KernelTotal;
            public UIntPtr KernelPaged;
            public UIntPtr KernelNonpaged;
            public UIntPtr PageSize;
            public uint HandleCount;
            public uint ProcessCount;
            public uint ThreadCount;
        }

        [DllImport("kernel32.dll", EntryPoint = "K32GetPerformanceInfo", SetLastError = true)]
        public static extern bool GetPerformanceInfo(ref PerformanceInformation info, uint size);

        [DllImport("kernel32.dll")]
        public static extern ulong GetTickCount64();

        // The kernel graphics interface Task Manager's GPU page reads (D3DKMT): every
        // adapter's engines and memory segments, for any vendor, without counters.
        [DllImport("gdi32.dll")]
        public static extern int D3DKMTEnumAdapters2(IntPtr enumAdapters);

        [DllImport("gdi32.dll")]
        public static extern int D3DKMTQueryAdapterInfo(IntPtr query);

        [DllImport("gdi32.dll")]
        public static extern int D3DKMTQueryStatistics(IntPtr query);

        [DllImport("gdi32.dll")]
        public static extern int D3DKMTCloseAdapter(IntPtr close);
    }

    sealed class ProcPrev
    {
        public long Create;
        public long Cpu;
        public long Io;
        public long Read;
        public long Write;
        public string Name;
    }

    sealed class Proc
    {
        public long Pid;
        public string Name;
        public double Cpu;
        public long WorkingSet;
        public long Private;
        public int Threads;
        public double Io;
    }

    sealed class Volume
    {
        public string Name;
        public string Label;
        public long Size;
        public long Free;
    }

    sealed class NetRate
    {
        public string Name;
        public double Rx;
        public double Tx;
    }

    sealed class Gpu
    {
        public string Name;
        public long Luid;
        public int Segments;
        public long[] PrevRun;
        public double Util;
        public long MemUsed;
        public long MemTotal;
    }

    static class Collector
    {
        const int CoreStride = 48; // SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
        const int MinStaleMs = 15000;

        static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
        static readonly Stopwatch Clock = Stopwatch.StartNew();

        static string os;
        static string cpuName;
        static int cores;

        static IntPtr procBuf = IntPtr.Zero;
        static int procBufLen = 1 << 20;
        static IntPtr coreBuf = IntPtr.Zero;

        // Previous readings, for the deltas that make rates.
        static double prevAt = -1;
        static long[] prevIdle;
        static long[] prevTotal;
        static readonly Dictionary<long, ProcPrev> prevProc = new Dictionary<long, ProcPrev>();
        static readonly Dictionary<string, long[]> prevNet = new Dictionary<string, long[]>();

        // Slow-changing inventories, refreshed every few samples.
        static List<Volume> volumes = new List<Volume>();
        static NetworkInterface[] nics = new NetworkInterface[0];
        static double volumesAt = -1e9;
        static double nicsAt = -1e9;

        // The current sample.
        static double[] coreUse;
        static double cpuTotal;
        static List<Proc> procs = new List<Proc>();
        static List<NetRate> net = new List<NetRate>();
        static List<Gpu> gpus = new List<Gpu>();
        static IntPtr statBuf = IntPtr.Zero;
        static double ioRead;
        static double ioWrite;
        static long seq;

        static int Main(string[] args)
        {
            string dir = args.Length > 0 ? args[0] : null;
            try
            {
                if (args.Length < 2)
                {
                    throw new ArgumentException("usage: sysmon-collector <data dir> <owner token>");
                }
                if (IntPtr.Size != 8)
                {
                    throw new PlatformNotSupportedException("the collector must run as a 64-bit process");
                }
                Run(dir, args[1]);
                return 0;
            }
            catch (Exception e)
            {
                if (dir != null)
                {
                    try { File.WriteAllText(Path.Combine(dir, "collector.err"), e.ToString()); } catch (Exception) { }
                }
                Console.Error.WriteLine(e);
                return 1;
            }
        }

        static void Run(string dir, string token)
        {
            try { Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.BelowNormal; } catch (Exception) { }

            string heartbeat = Path.Combine(dir, "heartbeat");
            string owner = Path.Combine(dir, "owner");
            string snapshot = Path.Combine(dir, "snapshot.json");
            try { File.Delete(Path.Combine(dir, "collector.err")); } catch (Exception) { }

            Describe();
            coreBuf = Marshal.AllocHGlobal(CoreStride * cores);
            procBuf = Marshal.AllocHGlobal(procBufLen);

            // Two quick samples, so the first snapshot already carries rates.
            Sample();
            Thread.Sleep(500);
            Sample();
            int interval = 2000;
            while (true)
            {
                Write(snapshot, interval);

                string want = ReadText(owner);
                if (want == null || want.Trim() != token)
                {
                    return; // replaced by a newer collector, or the plugin stopped us
                }
                int asked;
                double age = HeartbeatAge(heartbeat, out asked);
                if (asked > 0)
                {
                    interval = asked;
                }
                if (age < 0 || age > Math.Max(MinStaleMs, interval * 4))
                {
                    return; // nobody is watching
                }
                Thread.Sleep(interval);
                Sample();
            }
        }

        // ---- machine description (once) ------------------------------------

        static void Describe()
        {
            cores = Environment.ProcessorCount;
            os = "Windows";
            cpuName = "";
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (k != null)
                    {
                        string product = Convert.ToString(k.GetValue("ProductName"), Inv);
                        string build = Convert.ToString(k.GetValue("CurrentBuildNumber"), Inv);
                        string display = Convert.ToString(k.GetValue("DisplayVersion"), Inv);
                        int b;
                        // ProductName still says "Windows 10" on Windows 11.
                        if (int.TryParse(build, NumberStyles.Integer, Inv, out b) && b >= 22000 && product.StartsWith("Windows 10"))
                        {
                            product = "Windows 11" + product.Substring("Windows 10".Length);
                        }
                        os = product + (display.Length > 0 ? " " + display : "") + (build.Length > 0 ? " (" + build + ")" : "");
                    }
                }
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0"))
                {
                    if (k != null)
                    {
                        cpuName = Convert.ToString(k.GetValue("ProcessorNameString"), Inv).Trim();
                    }
                }
            }
            catch (Exception) { }
            try { DescribeGpus(); } catch (Exception) { gpus = new List<Gpu>(); }
        }

        // D3DKMT_QUERYSTATISTICS (x64): Type at 0, AdapterLuid at 4, the result
        // union at 24, the segment or node id at 0x320; 0x328 bytes in all.
        const int StatSize = 0x328, StatResult = 24, StatQueryId = 0x320;
        const int StatAdapter = 0, StatSegment = 3, StatNode = 5;

        static bool Stat(int type, long luid, int id)
        {
            for (int i = 0; i < StatSize; i += 8) Marshal.WriteInt64(statBuf, i, 0);
            Marshal.WriteInt32(statBuf, 0, type);
            Marshal.WriteInt64(statBuf, 4, luid);
            Marshal.WriteInt32(statBuf, StatQueryId, id);
            return Native.D3DKMTQueryStatistics(statBuf) == 0;
        }

        // The real GPUs: adapters with engines and dedicated memory, once per LUID
        // (each display output can list its adapter again; software renderers have neither).
        static void DescribeGpus()
        {
            statBuf = Marshal.AllocHGlobal(StatSize);
            IntPtr e = Marshal.AllocHGlobal(16);
            IntPtr infos = IntPtr.Zero;
            IntPtr reg = Marshal.AllocHGlobal(4 * 260 * 2);
            IntPtr q = Marshal.AllocHGlobal(24);
            try
            {
                Marshal.WriteInt32(e, 0, 0);
                Marshal.WriteInt64(e, 8, 0);
                if (Native.D3DKMTEnumAdapters2(e) != 0) return;
                int n = Marshal.ReadInt32(e, 0);
                if (n <= 0) return;
                infos = Marshal.AllocHGlobal(20 * n); // D3DKMT_ADAPTERINFO: handle, LUID, sources, flag
                Marshal.WriteInt64(e, 8, infos.ToInt64());
                if (Native.D3DKMTEnumAdapters2(e) != 0) return;
                n = Marshal.ReadInt32(e, 0);
                var seen = new HashSet<long>();
                for (int a = 0; a < n; a++)
                {
                    IntPtr info = IntPtr.Add(infos, a * 20);
                    int handle = Marshal.ReadInt32(info, 0);
                    long luid = Marshal.ReadInt64(info, 4);
                    string name = null;
                    // D3DKMT_QUERYADAPTERINFO: KMTQAITYPE_ADAPTERREGISTRYINFO (8) gives the adapter's name.
                    Marshal.WriteInt32(q, 0, handle);
                    Marshal.WriteInt32(q, 4, 8);
                    Marshal.WriteInt64(q, 8, reg.ToInt64());
                    Marshal.WriteInt32(q, 16, 4 * 260 * 2);
                    if (Native.D3DKMTQueryAdapterInfo(q) == 0) name = Marshal.PtrToStringUni(reg);
                    Marshal.WriteInt32(q, 0, handle);
                    Native.D3DKMTCloseAdapter(q);
                    if (string.IsNullOrEmpty(name) || !seen.Add(luid) || !Stat(StatAdapter, luid, 0)) continue;
                    int segments = Marshal.ReadInt32(statBuf, StatResult);
                    int nodes = Marshal.ReadInt32(statBuf, StatResult + 4);
                    var g = new Gpu();
                    g.Name = name.Trim();
                    g.Luid = luid;
                    g.Segments = segments;
                    g.PrevRun = new long[Math.Max(0, nodes)];
                    for (int k = 0; k < g.PrevRun.Length; k++) g.PrevRun[k] = -1;
                    SampleGpuMemory(g);
                    if (nodes > 0 && g.MemTotal > 0) gpus.Add(g);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(e);
                Marshal.FreeHGlobal(reg);
                Marshal.FreeHGlobal(q);
                if (infos != IntPtr.Zero) Marshal.FreeHGlobal(infos);
            }
        }

        // Dedicated memory: the segments not in the system aperture.
        // D3DKMT_QUERYSTATISTICS_SEGMENT_INFORMATION: CommitLimit, BytesCommitted, BytesResident, …, Aperture at 40.
        static void SampleGpuMemory(Gpu g)
        {
            long total = 0, used = 0;
            for (int s = 0; s < g.Segments; s++)
            {
                if (!Stat(StatSegment, g.Luid, s) || Marshal.ReadInt32(statBuf, StatResult + 40) != 0) continue;
                total += Math.Max(0, Marshal.ReadInt64(statBuf, StatResult));
                used += Math.Max(0, Marshal.ReadInt64(statBuf, StatResult + 16));
            }
            g.MemTotal = total;
            g.MemUsed = Math.Min(used, total);
        }

        // Busy as Task Manager shows it: the busiest engine's share of the interval.
        static void SampleGpus(double dt)
        {
            foreach (Gpu g in gpus)
            {
                double busiest = 0;
                for (int k = 0; k < g.PrevRun.Length; k++)
                {
                    if (!Stat(StatNode, g.Luid, k)) continue;
                    long run = Marshal.ReadInt64(statBuf, StatResult); // running time, 100 ns
                    if (g.PrevRun[k] >= 0 && dt > 0 && run >= g.PrevRun[k])
                    {
                        busiest = Math.Max(busiest, (run - g.PrevRun[k]) / (dt * 1e7) * 100);
                    }
                    g.PrevRun[k] = run;
                }
                g.Util = Math.Min(100, busiest);
                SampleGpuMemory(g);
            }
        }

        // ---- sampling ---------------------------------------------------------

        static void Sample()
        {
            double now = Clock.Elapsed.TotalSeconds;
            double dt = prevAt < 0 ? 0 : now - prevAt;
            SampleCores();
            SampleProcesses(dt);
            if (now - volumesAt > 10)
            {
                SampleVolumes();
                volumesAt = now;
            }
            SampleNet(dt, now);
            SampleGpus(dt);
            prevAt = now;
            seq++;
        }

        static void SampleCores()
        {
            int returned;
            uint status = Native.NtQuerySystemInformation(Native.SystemProcessorPerformanceInformation, coreBuf, CoreStride * cores, out returned);
            if (status != 0)
            {
                throw new InvalidOperationException("NtQuerySystemInformation(processor) failed: 0x" + status.ToString("X8", Inv));
            }
            int n = Math.Min(cores, returned / CoreStride);
            if (prevIdle == null)
            {
                prevIdle = new long[n];
                prevTotal = new long[n];
                coreUse = new double[n];
            }
            double busySum = 0;
            for (int i = 0; i < n; i++)
            {
                IntPtr p = IntPtr.Add(coreBuf, i * CoreStride);
                long idle = Marshal.ReadInt64(p, 0);
                long kernel = Marshal.ReadInt64(p, 8); // includes idle
                long user = Marshal.ReadInt64(p, 16);
                long total = kernel + user;
                long dTotal = total - prevTotal[i];
                long dIdle = idle - prevIdle[i];
                double use = dTotal > 0 ? 100.0 * (dTotal - dIdle) / dTotal : 0;
                coreUse[i] = Math.Max(0, Math.Min(100, use));
                busySum += coreUse[i];
                prevIdle[i] = idle;
                prevTotal[i] = total;
            }
            cpuTotal = n > 0 ? busySum / n : 0;
        }

        static void SampleProcesses(double dt)
        {
            int returned;
            uint status;
            while (true)
            {
                status = Native.NtQuerySystemInformation(Native.SystemProcessInformation, procBuf, procBufLen, out returned);
                if (status != Native.StatusInfoLengthMismatch)
                {
                    break;
                }
                Marshal.FreeHGlobal(procBuf);
                procBufLen = Math.Max(procBufLen * 2, returned + (64 << 10));
                procBuf = Marshal.AllocHGlobal(procBufLen);
            }
            if (status != 0)
            {
                throw new InvalidOperationException("NtQuerySystemInformation(process) failed: 0x" + status.ToString("X8", Inv));
            }

            // 100 ns units of CPU over the interval, across every core.
            double capacity = dt * 1e7 * cores;
            var seen = new HashSet<long>();
            var list = new List<Proc>(procs.Count + 16);
            double readSum = 0;
            double writeSum = 0;
            int offset = 0;
            while (true)
            {
                // SYSTEM_PROCESS_INFORMATION, x64 layout.
                IntPtr p = IntPtr.Add(procBuf, offset);
                int next = Marshal.ReadInt32(p, 0);
                int threads = Marshal.ReadInt32(p, 4);
                long create = Marshal.ReadInt64(p, 32);
                long cpu = Marshal.ReadInt64(p, 40) + Marshal.ReadInt64(p, 48); // user + kernel
                long pid = Marshal.ReadIntPtr(p, 80).ToInt64();
                long ws = Marshal.ReadIntPtr(p, 144).ToInt64();
                long priv = Marshal.ReadIntPtr(p, 200).ToInt64();
                long read = Marshal.ReadInt64(p, 232);
                long write = Marshal.ReadInt64(p, 240);
                long other = Marshal.ReadInt64(p, 248);
                long io = read + write + other;

                if (pid != 0) // the idle process is idle time, not a process
                {
                    seen.Add(pid);
                    ProcPrev prev;
                    bool same = prevProc.TryGetValue(pid, out prev) && prev.Create == create;
                    if (!same)
                    {
                        ushort len = (ushort)Marshal.ReadInt16(p, 56);
                        IntPtr namePtr = Marshal.ReadIntPtr(p, 64);
                        string name = namePtr == IntPtr.Zero || len == 0 ? (pid == 4 ? "System" : "pid " + pid) : Marshal.PtrToStringUni(namePtr, len / 2);
                        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        {
                            name = name.Substring(0, name.Length - 4);
                        }
                        prev = new ProcPrev();
                        prev.Create = create;
                        prev.Name = name;
                        prev.Cpu = cpu;
                        prev.Io = io;
                        prev.Read = read;
                        prev.Write = write;
                        prevProc[pid] = prev;
                    }
                    var proc = new Proc();
                    proc.Pid = pid;
                    proc.Name = prev.Name;
                    proc.WorkingSet = ws;
                    proc.Private = priv;
                    proc.Threads = threads;
                    if (same && dt > 0)
                    {
                        proc.Cpu = capacity > 0 ? Math.Max(0, 100.0 * (cpu - prev.Cpu) / capacity) : 0;
                        proc.Io = Math.Max(0, (io - prev.Io) / dt);
                        readSum += Math.Max(0, read - prev.Read);
                        writeSum += Math.Max(0, write - prev.Write);
                    }
                    prev.Cpu = cpu;
                    prev.Io = io;
                    prev.Read = read;
                    prev.Write = write;
                    list.Add(proc);
                }

                if (next == 0)
                {
                    break;
                }
                offset += next;
            }

            // Forget the processes that exited.
            var gone = new List<long>();
            foreach (long pid in prevProc.Keys)
            {
                if (!seen.Contains(pid))
                {
                    gone.Add(pid);
                }
            }
            foreach (long pid in gone)
            {
                prevProc.Remove(pid);
            }

            procs = list;
            ioRead = dt > 0 ? readSum / dt : 0;
            ioWrite = dt > 0 ? writeSum / dt : 0;
        }

        static void SampleVolumes()
        {
            var list = new List<Volume>();
            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                try
                {
                    if (d.DriveType != DriveType.Fixed || !d.IsReady)
                    {
                        continue;
                    }
                    var v = new Volume();
                    v.Name = d.Name.TrimEnd('\\');
                    v.Label = d.VolumeLabel ?? "";
                    v.Size = d.TotalSize;
                    v.Free = d.TotalFreeSpace;
                    list.Add(v);
                }
                catch (Exception) { }
            }
            volumes = list;
        }

        static bool Interesting(NetworkInterface nic)
        {
            if (nic.OperationalStatus != OperationalStatus.Up)
            {
                return false;
            }
            NetworkInterfaceType t = nic.NetworkInterfaceType;
            if (t == NetworkInterfaceType.Loopback || t == NetworkInterfaceType.Tunnel)
            {
                return false;
            }
            string n = nic.Name;
            // Filter-driver bindings show up as clones of the real adapter.
            return n.IndexOf("-0000", StringComparison.Ordinal) < 0
                && n.IndexOf("Filter", StringComparison.OrdinalIgnoreCase) < 0
                && n.IndexOf("Npcap", StringComparison.OrdinalIgnoreCase) < 0
                && n.IndexOf("QoS", StringComparison.OrdinalIgnoreCase) < 0;
        }

        static void SampleNet(double dt, double now)
        {
            if (now - nicsAt > 10)
            {
                var keep = new List<NetworkInterface>();
                try
                {
                    foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                    {
                        if (Interesting(nic))
                        {
                            keep.Add(nic);
                        }
                    }
                }
                catch (NetworkInformationException) { }
                nics = keep.ToArray();
                nicsAt = now;
            }
            var list = new List<NetRate>(nics.Length);
            foreach (NetworkInterface nic in nics)
            {
                long rx, tx;
                try
                {
                    IPInterfaceStatistics s = nic.GetIPStatistics();
                    rx = s.BytesReceived;
                    tx = s.BytesSent;
                }
                catch (Exception)
                {
                    continue; // the adapter went away
                }
                long[] prev;
                var r = new NetRate();
                r.Name = nic.Name;
                if (prevNet.TryGetValue(nic.Id, out prev) && dt > 0)
                {
                    r.Rx = Math.Max(0, (rx - prev[0]) / dt);
                    r.Tx = Math.Max(0, (tx - prev[1]) / dt);
                }
                prevNet[nic.Id] = new long[] { rx, tx };
                list.Add(r);
            }
            net = list;
        }

        // ---- output -----------------------------------------------------------

        static void Write(string path, int interval)
        {
            var m = new Native.MemoryStatusEx();
            m.Length = (uint)Marshal.SizeOf(typeof(Native.MemoryStatusEx));
            Native.GlobalMemoryStatusEx(ref m);
            var pi = new Native.PerformanceInformation();
            pi.Size = (uint)Marshal.SizeOf(typeof(Native.PerformanceInformation));
            bool havePi = Native.GetPerformanceInfo(ref pi, pi.Size);
            ulong page = havePi ? pi.PageSize.ToUInt64() : 4096;

            var sb = new StringBuilder(64 << 10);
            sb.Append("{\"v\":1,\"seq\":").Append(seq.ToString(Inv));
            sb.Append(",\"at\":").Append(((long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds).ToString(Inv));
            sb.Append(",\"interval\":").Append(interval.ToString(Inv));
            sb.Append(",\"os\":"); Str(sb, os);
            sb.Append(",\"cpuName\":"); Str(sb, cpuName);
            sb.Append(",\"up\":").Append((Native.GetTickCount64() / 1000).ToString(Inv));

            sb.Append(",\"cpu\":{\"total\":"); Num(sb, cpuTotal);
            sb.Append(",\"cores\":[");
            for (int i = 0; i < coreUse.Length; i++)
            {
                if (i > 0) sb.Append(',');
                Num(sb, coreUse[i]);
            }
            sb.Append("]}");

            sb.Append(",\"mem\":{\"total\":").Append(m.TotalPhys.ToString(Inv));
            sb.Append(",\"avail\":").Append(m.AvailPhys.ToString(Inv));
            sb.Append(",\"commit\":").Append((m.TotalPageFile - m.AvailPageFile).ToString(Inv));
            sb.Append(",\"limit\":").Append(m.TotalPageFile.ToString(Inv));
            if (havePi)
            {
                sb.Append(",\"cache\":").Append((pi.SystemCache.ToUInt64() * page).ToString(Inv));
                sb.Append(",\"kpaged\":").Append((pi.KernelPaged.ToUInt64() * page).ToString(Inv));
                sb.Append(",\"knonpaged\":").Append((pi.KernelNonpaged.ToUInt64() * page).ToString(Inv));
            }
            sb.Append('}');
            if (havePi)
            {
                sb.Append(",\"counts\":{\"proc\":").Append(pi.ProcessCount.ToString(Inv));
                sb.Append(",\"thread\":").Append(pi.ThreadCount.ToString(Inv));
                sb.Append(",\"handle\":").Append(pi.HandleCount.ToString(Inv)).Append('}');
            }

            sb.Append(",\"io\":{\"read\":"); Num(sb, ioRead);
            sb.Append(",\"write\":"); Num(sb, ioWrite); sb.Append('}');

            sb.Append(",\"disk\":[");
            for (int i = 0; i < volumes.Count; i++)
            {
                Volume v = volumes[i];
                if (i > 0) sb.Append(',');
                sb.Append("{\"name\":"); Str(sb, v.Name);
                sb.Append(",\"label\":"); Str(sb, v.Label);
                sb.Append(",\"size\":").Append(v.Size.ToString(Inv));
                sb.Append(",\"free\":").Append(v.Free.ToString(Inv)).Append('}');
            }
            sb.Append(']');

            sb.Append(",\"net\":[");
            for (int i = 0; i < net.Count; i++)
            {
                NetRate r = net[i];
                if (i > 0) sb.Append(',');
                sb.Append("{\"name\":"); Str(sb, r.Name);
                sb.Append(",\"rx\":"); Num(sb, r.Rx);
                sb.Append(",\"tx\":"); Num(sb, r.Tx); sb.Append('}');
            }
            sb.Append(']');

            // [{name, util %, dedicated memory used, total}]
            sb.Append(",\"gpu\":[");
            for (int i = 0; i < gpus.Count; i++)
            {
                Gpu g = gpus[i];
                if (i > 0) sb.Append(',');
                sb.Append("{\"name\":"); Str(sb, g.Name);
                sb.Append(",\"util\":"); Num(sb, g.Util);
                sb.Append(",\"memUsed\":").Append(g.MemUsed.ToString(Inv));
                sb.Append(",\"memTotal\":").Append(g.MemTotal.ToString(Inv)).Append('}');
            }
            sb.Append(']');

            // [pid, name, cpu %, working set, private bytes, threads, io bytes/s]
            sb.Append(",\"proc\":[");
            for (int i = 0; i < procs.Count; i++)
            {
                Proc p = procs[i];
                if (i > 0) sb.Append(',');
                sb.Append('[').Append(p.Pid.ToString(Inv)).Append(',');
                Str(sb, p.Name);
                sb.Append(','); Num(sb, p.Cpu);
                sb.Append(',').Append(p.WorkingSet.ToString(Inv));
                sb.Append(',').Append(p.Private.ToString(Inv));
                sb.Append(',').Append(p.Threads.ToString(Inv));
                sb.Append(','); Num(sb, p.Io);
                sb.Append(']');
            }
            sb.Append("]}");

            string tmp = path + ".tmp";
            try
            {
                File.WriteAllText(tmp, sb.ToString(), new UTF8Encoding(false));
                if (File.Exists(path))
                {
                    File.Replace(tmp, path, null);
                }
                else
                {
                    File.Move(tmp, path);
                }
            }
            catch (IOException) { } // the reader held it open; the next sample replaces it
            catch (UnauthorizedAccessException) { }
        }

        static void Num(StringBuilder sb, double v)
        {
            if (double.IsNaN(v) || double.IsInfinity(v))
            {
                v = 0;
            }
            sb.Append(Math.Round(v, 2).ToString("0.##", Inv));
        }

        static void Str(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s ?? "")
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20)
                        {
                            sb.Append("\\u").Append(((int)c).ToString("x4", Inv));
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }
            sb.Append('"');
        }

        // ---- files --------------------------------------------------------------

        static string ReadText(string path)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var r = new StreamReader(fs))
                {
                    return r.ReadToEnd();
                }
            }
            catch (Exception)
            {
                return null;
            }
        }

        // Milliseconds since the heartbeat was written (-1 when missing), and the interval it asks for.
        static double HeartbeatAge(string path, out int interval)
        {
            interval = 0;
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists)
                {
                    return -1;
                }
                string text = ReadText(path);
                int ms;
                if (text != null && int.TryParse(text.Trim(), NumberStyles.Integer, Inv, out ms) && ms >= 250)
                {
                    interval = Math.Min(ms, 60000);
                }
                return (DateTime.UtcNow - fi.LastWriteTimeUtc).TotalMilliseconds;
            }
            catch (Exception)
            {
                return -1;
            }
        }
    }
}
