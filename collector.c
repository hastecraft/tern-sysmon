// collector.c — the System Monitor's sampler on Linux and macOS, a long-lived
// native process. The Windows twin is collector.cs; both write the same
// snapshot.json.
//
// Built once by the plugin with the system C compiler:
//   Linux: cc -O2 -o <data>/sysmon-collector-<hash> collector.c
//   macOS: cc -O2 -o <data>/sysmon-collector-<hash> collector.c -framework IOKit -framework CoreFoundation
// Run as: sysmon-collector <data dir> <owner token>
//
// Linux reads /proc and /sys; macOS reads Mach host statistics, libproc,
// IOKit and sysctl. Nothing needs root: processes the OS hides from this
// user (on macOS, other users' tasks) are listed without their CPU and I/O.
//
// Protocol, all files in <data dir>:
//   heartbeat      written by the plugin each poll; holds the interval in ms.
//                  The collector exits when it goes stale.
//   owner          the token of the collector the plugin wants; any other
//                  collector exits (a plugin reload starts a new one).
//   snapshot.json  written here every interval, replaced atomically.
//   collector.err  the last fatal error, for the plugin to show.

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/storage/IOBlockStorageDriver.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <dlfcn.h>
#include <mntent.h>
#include <sys/utsname.h>
#else
#error "collector.c supports Linux and macOS; Windows uses collector.cs"
#endif

#define MIN_STALE_MS 15000.0
#define NAME_MAX_LEN 64
#define MAX_VOLUMES 16
#define MAX_NICS 32

// ---- small helpers ---------------------------------------------------------------

static char g_dir[4096];

static void die(const char *fmt, ...) {
	char msg[1024];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof msg, fmt, ap);
	va_end(ap);
	if (g_dir[0]) {
		char path[4200];
		snprintf(path, sizeof path, "%s/collector.err", g_dir);
		FILE *f = fopen(path, "w");
		if (f) {
			fprintf(f, "%s\n", msg);
			fclose(f);
		}
	}
	fprintf(stderr, "%s\n", msg);
	exit(1);
}

static void *xrealloc(void *p, size_t n) {
	void *q = realloc(p, n ? n : 1);
	if (!q) die("out of memory");
	return q;
}

static double mono_s(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

static double wall_ms(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (double)tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

static void sleep_ms(int ms) {
	struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
	while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}

// Reads up to cap-1 bytes of a file into buf, NUL-terminated; -1 when unreadable.
static ssize_t read_file(const char *path, char *buf, size_t cap) {
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return -1;
	size_t len = 0;
	while (len + 1 < cap) {
		ssize_t r = read(fd, buf + len, cap - 1 - len);
		if (r < 0) {
			if (errno == EINTR) continue;
			close(fd);
			return -1;
		}
		if (r == 0) break;
		len += (size_t)r;
	}
	close(fd);
	buf[len] = 0;
	return (ssize_t)len;
}

static void copy_name(char *dst, const char *src, size_t n) {
	size_t len = strlen(src);
	if (len > n) len = n;
	if (len > NAME_MAX_LEN - 1) len = NAME_MAX_LEN - 1;
	memcpy(dst, src, len);
	dst[len] = 0;
}

static double clamp_pos(double v) { return v > 0 && isfinite(v) ? v : 0; }

static double rate(uint64_t now, uint64_t before, double dt) {
	return dt > 0 && now >= before ? (double)(now - before) / dt : 0;
}

// ---- the growing JSON buffer -------------------------------------------------------

static char *js;
static size_t js_len, js_cap;

static void js_raw(const char *s, size_t n) {
	if (js_len + n + 1 > js_cap) {
		while (js_len + n + 1 > js_cap) js_cap = js_cap ? js_cap * 2 : 65536;
		js = xrealloc(js, js_cap);
	}
	memcpy(js + js_len, s, n);
	js_len += n;
	js[js_len] = 0;
}

static void js_put(const char *s) { js_raw(s, strlen(s)); }

static void js_u64(uint64_t v) {
	char b[32];
	snprintf(b, sizeof b, "%llu", (unsigned long long)v);
	js_put(b);
}

// A number rounded to two decimals, without trailing zeros.
static void js_num(double v) {
	char b[64];
	if (!isfinite(v)) v = 0;
	snprintf(b, sizeof b, "%.2f", v);
	char *dot = strchr(b, '.');
	if (dot) {
		char *end = b + strlen(b) - 1;
		while (end > dot && *end == '0') *end-- = 0;
		if (end == dot) *end = 0;
	}
	if (strcmp(b, "-0") == 0) strcpy(b, "0");
	js_put(b);
}

// A JSON string; bytes that are not valid UTF-8 become U+FFFD.
static void js_str(const char *s) {
	const unsigned char *p = (const unsigned char *)s;
	js_raw("\"", 1);
	while (*p) {
		unsigned char c = *p;
		if (c == '"' || c == '\\') {
			char e[2] = { '\\', (char)c };
			js_raw(e, 2);
			p++;
		} else if (c < 0x20) {
			char e[8];
			snprintf(e, sizeof e, "\\u%04x", c);
			js_put(e);
			p++;
		} else if (c < 0x80) {
			js_raw((const char *)p, 1);
			p++;
		} else {
			int n = c >= 0xF0 && c <= 0xF4 ? 4 : c >= 0xE0 ? 3 : c >= 0xC2 && c < 0xE0 ? 2 : 0;
			int ok = n > 0;
			for (int i = 1; ok && i < n; i++) ok = (p[i] & 0xC0) == 0x80;
			if (ok) {
				js_raw((const char *)p, (size_t)n);
				p += n;
			} else {
				js_put("\xEF\xBF\xBD");
				p++;
			}
		}
	}
	js_raw("\"", 1);
}

// ---- what a sample holds ---------------------------------------------------------

typedef struct {
	int pid;
	char name[NAME_MAX_LEN];
	double cpu; // percent of the whole machine
	uint64_t ws, priv;
	int threads;
	double io; // bytes per second
} Proc;

typedef struct {
	char name[256];
	char label[256];
	uint64_t size, free;
} Volume;

typedef struct {
	char name[64];
	double rx, tx;
} Nic;

// What a process looked like last sample, keyed by pid.
typedef struct {
	int pid; // 0 = empty slot
	uint64_t start;
	uint64_t cpu; // OS units: clock ticks (Linux) or nanoseconds (macOS)
	uint64_t io;
	char name[NAME_MAX_LEN];
} Prev;

typedef struct {
	Prev *slots;
	size_t cap; // a power of two
} PrevTable;

static Prev *prev_find(PrevTable *t, int pid) {
	if (!t->cap) return NULL;
	size_t i = ((size_t)pid * 2654435761u) & (t->cap - 1);
	while (t->slots[i].pid) {
		if (t->slots[i].pid == pid) return &t->slots[i];
		i = (i + 1) & (t->cap - 1);
	}
	return NULL;
}

static Prev *prev_insert(PrevTable *t, int pid) {
	size_t i = ((size_t)pid * 2654435761u) & (t->cap - 1);
	while (t->slots[i].pid && t->slots[i].pid != pid) i = (i + 1) & (t->cap - 1);
	t->slots[i].pid = pid;
	return &t->slots[i];
}

static void prev_reset(PrevTable *t, size_t count) {
	size_t cap = 64;
	while (cap < count * 2 + 16) cap <<= 1;
	if (cap != t->cap) {
		t->slots = xrealloc(t->slots, cap * sizeof(Prev));
		t->cap = cap;
	}
	memset(t->slots, 0, cap * sizeof(Prev));
}

static char os_name[256], cpu_name[256];
static int ncores;
static double up_s;

static double *core_use;
static double cpu_total;

static uint64_t mem_total, mem_avail, mem_cache, mem_kernel, mem_wired, swap_total, swap_used;
static uint64_t count_proc, count_thread, count_files;
static int have_files;

static Proc *procs;
static size_t nprocs, procs_cap;
static PrevTable prev_a, prev_b, *prev_cur = &prev_a, *prev_next = &prev_b;

static Volume volumes[MAX_VOLUMES];
static size_t nvolumes;
static double volumes_at = -1e9;

static Nic nics[MAX_NICS];
static size_t nnics;

// GPUs: utilization in percent (-1 when the driver doesn't say) and dedicated
// memory (0 total when it shares system memory or doesn't say).
#define MAX_GPUS 8
typedef struct {
	char name[128];
	double util;
	uint64_t used, total;
} Gpu;
static Gpu gpus[MAX_GPUS];
static size_t ngpus;

static double io_read, io_write;
static double prev_at = -1;
static uint64_t seq;

static Proc *proc_push(void) {
	if (nprocs == procs_cap) {
		procs_cap = procs_cap ? procs_cap * 2 : 512;
		procs = xrealloc(procs, procs_cap * sizeof(Proc));
	}
	Proc *p = &procs[nprocs++];
	memset(p, 0, sizeof *p);
	return p;
}

// Records one process: keeps the name it had when first seen (a pid reused by
// a new process starts over) and turns its counters into rates. `capacity` is
// the CPU time the whole machine had over the interval, in the units of `cpu`.
static void proc_record(int pid, uint64_t start, const char *name, uint64_t cpu, int cpu_known,
	uint64_t io, int io_known, uint64_t ws, uint64_t priv, int threads, double dt, double capacity) {
	Prev *old = prev_find(prev_cur, pid);
	int same = old && old->start == start;
	Prev *now = prev_insert(prev_next, pid);
	now->start = start;
	now->cpu = cpu;
	now->io = io;
	const char *keep = same && old->name[0] ? old->name : name;
	copy_name(now->name, keep, strlen(keep));

	Proc *p = proc_push();
	p->pid = pid;
	memcpy(p->name, now->name, sizeof p->name);
	p->ws = ws;
	p->priv = priv;
	p->threads = threads;
	if (same && dt > 0) {
		if (cpu_known && capacity > 0 && cpu >= old->cpu) p->cpu = 100.0 * (double)(cpu - old->cpu) / capacity;
		if (io_known) p->io = rate(io, old->io, dt);
	}
}

static void procs_begin(size_t expected) {
	nprocs = 0;
	prev_reset(prev_next, expected);
}

static void procs_end(void) {
	PrevTable *t = prev_cur;
	prev_cur = prev_next;
	prev_next = t;
}

static void set_cores(int n) {
	if (n == ncores && core_use) return;
	ncores = n;
	core_use = xrealloc(core_use, (size_t)(n > 0 ? n : 1) * sizeof(double));
	memset(core_use, 0, (size_t)(n > 0 ? n : 1) * sizeof(double));
}

// =============================================================================
#if defined(__linux__)
// =============================================================================

static long clk_tck;
static long page_size;
static uint64_t *core_busy_prev, *core_total_prev;
static int core_prev_n;
static uint64_t disk_read_prev, disk_write_prev;
static int have_disk_prev;

typedef struct {
	char name[64];
	uint64_t rx, tx;
} NicPrev;
static NicPrev nic_prev[MAX_NICS];
static size_t nnic_prev;

static char buf[1 << 16];

static void describe(void) {
	clk_tck = sysconf(_SC_CLK_TCK);
	page_size = sysconf(_SC_PAGESIZE);
	if (clk_tck <= 0) clk_tck = 100;
	if (page_size <= 0) page_size = 4096;

	struct utsname u;
	char kernel[128] = "";
	if (uname(&u) == 0) {
		snprintf(kernel, sizeof kernel, "%s", u.release);
		char *dash = strchr(kernel, '-');
		if (dash) *dash = 0;
	}
	strcpy(os_name, "Linux");
	if (read_file("/etc/os-release", buf, sizeof buf) > 0 || read_file("/usr/lib/os-release", buf, sizeof buf) > 0) {
		char *line = strstr(buf, "PRETTY_NAME=");
		if (line && (line == buf || line[-1] == '\n')) {
			line += strlen("PRETTY_NAME=");
			char *end = strchr(line, '\n');
			if (end) *end = 0;
			if (*line == '"' || *line == '\'') {
				char q = *line++;
				char *close = strrchr(line, q);
				if (close) *close = 0;
			}
			if (*line) snprintf(os_name, sizeof os_name, "%s", line);
		}
	}
	if (kernel[0]) {
		size_t len = strlen(os_name);
		snprintf(os_name + len, sizeof os_name - len, " (%s)", kernel);
	}

	cpu_name[0] = 0;
	if (read_file("/proc/cpuinfo", buf, sizeof buf) > 0) {
		const char *keys[] = { "model name", "Model", "Hardware", "cpu model" };
		for (size_t k = 0; k < sizeof keys / sizeof *keys && !cpu_name[0]; k++) {
			for (char *line = buf; line && *line; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL) {
				size_t kl = strlen(keys[k]);
				if (strncmp(line, keys[k], kl) == 0 && (line[kl] == '\t' || line[kl] == ' ' || line[kl] == ':')) {
					char *colon = strchr(line, ':');
					char *end = strchr(line, '\n');
					if (!colon || (end && colon > end)) continue;
					colon++;
					while (*colon == ' ') colon++;
					size_t n = end ? (size_t)(end - colon) : strlen(colon);
					if (n >= sizeof cpu_name) n = sizeof cpu_name - 1;
					memcpy(cpu_name, colon, n);
					cpu_name[n] = 0;
					break;
				}
			}
		}
	}
	if (!cpu_name[0] && uname(&u) == 0) snprintf(cpu_name, sizeof cpu_name, "%s", u.machine);
}

static void sample_cores(void) {
	if (read_file("/proc/stat", buf, sizeof buf) <= 0) die("cannot read /proc/stat: %s", strerror(errno));
	int n = 0;
	for (char *line = buf; line && *line; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL) {
		if (strncmp(line, "cpu", 3) != 0) break; // the cpu lines come first
		if (line[3] >= '0' && line[3] <= '9') n++;
	}
	if (n == 0) die("/proc/stat lists no processors");
	set_cores(n);
	if (core_prev_n != n) {
		core_busy_prev = xrealloc(core_busy_prev, (size_t)n * sizeof(uint64_t));
		core_total_prev = xrealloc(core_total_prev, (size_t)n * sizeof(uint64_t));
		memset(core_busy_prev, 0, (size_t)n * sizeof(uint64_t));
		memset(core_total_prev, 0, (size_t)n * sizeof(uint64_t));
		core_prev_n = n;
	}
	int i = 0;
	double sum = 0;
	for (char *line = buf; line && *line && i < n; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL) {
		if (strncmp(line, "cpu", 3) != 0) break;
		if (!(line[3] >= '0' && line[3] <= '9')) continue;
		unsigned long long v[8] = { 0 };
		char *p = line + 3;
		while (*p >= '0' && *p <= '9') p++;
		for (int k = 0; k < 8; k++) v[k] = strtoull(p, &p, 10);
		// user nice system idle iowait irq softirq steal; guest time is inside user.
		uint64_t idle = v[3] + v[4];
		uint64_t total = 0;
		for (int k = 0; k < 8; k++) total += v[k];
		uint64_t busy = total - idle;
		uint64_t dt = total - core_total_prev[i];
		uint64_t db = busy - core_busy_prev[i];
		double use = total > core_total_prev[i] && busy >= core_busy_prev[i] ? 100.0 * (double)db / (double)dt : 0;
		core_use[i] = use < 0 ? 0 : use > 100 ? 100 : use;
		sum += core_use[i];
		core_busy_prev[i] = busy;
		core_total_prev[i] = total;
		i++;
	}
	cpu_total = sum / n;
}

static int is_pid(const char *s) {
	if (!*s) return 0;
	for (; *s; s++)
		if (*s < '0' || *s > '9') return 0;
	return 1;
}

static int *pid_list;
static size_t pid_cap;

static void sample_processes(double dt) {
	DIR *d = opendir("/proc");
	if (!d) die("cannot open /proc: %s", strerror(errno));
	size_t count = 0;
	struct dirent *e;
	while ((e = readdir(d)) != NULL) {
		if (!is_pid(e->d_name)) continue;
		if (count == pid_cap) {
			pid_cap = pid_cap ? pid_cap * 2 : 1024;
			pid_list = xrealloc(pid_list, pid_cap * sizeof(int));
		}
		pid_list[count++] = atoi(e->d_name);
	}
	closedir(d);

	double capacity = dt * (double)clk_tck * (double)ncores;
	uint64_t threads = 0;
	procs_begin(count);
	char path[64], small[4096];
	for (size_t i = 0; i < count; i++) {
		int pid = pid_list[i];
		snprintf(path, sizeof path, "/proc/%d/stat", pid);
		if (read_file(path, small, sizeof small) <= 0) continue; // it exited
		char *open_paren = strchr(small, '(');
		char *close_paren = strrchr(small, ')');
		if (!open_paren || !close_paren || close_paren < open_paren) continue;
		*close_paren = 0;
		char name[NAME_MAX_LEN];
		copy_name(name, open_paren + 1, (size_t)(close_paren - open_paren - 1));
		// Fields after the name, from field 3 (state): t[k] is field k + 3.
		char *p = close_paren + 2;
		unsigned long long t[22] = { 0 };
		if (*p) p++; // state
		for (int k = 1; k < 22; k++) t[k] = strtoull(p, &p, 10);
		uint64_t cpu = t[11] + t[12]; // utime + stime
		int nthreads = (int)t[17];
		uint64_t start = t[19];
		uint64_t rss = t[21] * (uint64_t)page_size;
		uint64_t priv = rss;
		snprintf(path, sizeof path, "/proc/%d/statm", pid);
		if (read_file(path, small, sizeof small) > 0) {
			unsigned long long sz, res, shared;
			if (sscanf(small, "%llu %llu %llu", &sz, &res, &shared) == 3) {
				rss = res * (uint64_t)page_size;
				priv = (res > shared ? res - shared : 0) * (uint64_t)page_size;
			}
		}
		// rchar + wchar: every read and write, as the Windows collector counts I/O.
		// Only the user's own processes are readable without root.
		uint64_t io = 0;
		int io_known = 0;
		snprintf(path, sizeof path, "/proc/%d/io", pid);
		if (read_file(path, small, sizeof small) > 0) {
			char *r = strstr(small, "rchar:");
			char *w = strstr(small, "wchar:");
			if (r && w) {
				io = strtoull(r + 6, NULL, 10) + strtoull(w + 6, NULL, 10);
				io_known = 1;
			}
		}
		threads += (uint64_t)(nthreads > 0 ? nthreads : 0);
		proc_record(pid, start, name, cpu, 1, io, io_known, rss, priv, nthreads, dt, capacity);
	}
	procs_end();
	count_proc = nprocs;
	count_thread = threads;
	have_files = 0;
	if (read_file("/proc/sys/fs/file-nr", small, sizeof small) > 0) {
		count_files = strtoull(small, NULL, 10);
		have_files = 1;
	}
}

static uint64_t meminfo_kb(const char *text, const char *key) {
	const char *p = text;
	size_t kl = strlen(key);
	while ((p = strstr(p, key)) != NULL) {
		if ((p == text || p[-1] == '\n') && p[kl] == ':') return strtoull(p + kl + 1, NULL, 10) * 1024;
		p += kl;
	}
	return 0;
}

static void sample_memory(void) {
	if (read_file("/proc/meminfo", buf, sizeof buf) <= 0) die("cannot read /proc/meminfo: %s", strerror(errno));
	mem_total = meminfo_kb(buf, "MemTotal");
	mem_avail = meminfo_kb(buf, "MemAvailable");
	if (!mem_avail) mem_avail = meminfo_kb(buf, "MemFree") + meminfo_kb(buf, "Cached") + meminfo_kb(buf, "Buffers");
	// As `free` counts buff/cache.
	mem_cache = meminfo_kb(buf, "Buffers") + meminfo_kb(buf, "Cached") + meminfo_kb(buf, "SReclaimable");
	mem_kernel = meminfo_kb(buf, "Slab") + meminfo_kb(buf, "KernelStack") + meminfo_kb(buf, "PageTables");
	swap_total = meminfo_kb(buf, "SwapTotal");
	uint64_t swap_free = meminfo_kb(buf, "SwapFree");
	swap_used = swap_total > swap_free ? swap_total - swap_free : 0;

	if (read_file("/proc/uptime", buf, sizeof buf) > 0) up_s = strtod(buf, NULL);
}

// Whole disks only: partitions and device-mapper/md stacks would count twice.
static int whole_disk(const char *name) {
	static const char *skip[] = { "loop", "ram", "zram", "dm-", "md", "sr", "fd", "nbd" };
	for (size_t i = 0; i < sizeof skip / sizeof *skip; i++)
		if (strncmp(name, skip[i], strlen(skip[i])) == 0) return 0;
	char path[300];
	snprintf(path, sizeof path, "/sys/block/%s", name);
	return access(path, F_OK) == 0;
}

static void sample_disk_io(double dt) {
	if (read_file("/proc/diskstats", buf, sizeof buf) <= 0) {
		io_read = io_write = 0;
		return;
	}
	uint64_t rd = 0, wr = 0;
	for (char *line = buf; line && *line; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL) {
		unsigned major, minor;
		char name[128];
		unsigned long long f[8];
		// major minor name reads merged sectors_read ms writes merged sectors_written
		if (sscanf(line, "%u %u %127s %llu %llu %llu %llu %llu %llu %llu", &major, &minor, name,
			&f[0], &f[1], &f[2], &f[3], &f[4], &f[5], &f[6]) != 10)
			continue;
		if (!whole_disk(name)) continue;
		rd += f[2] * 512;
		wr += f[6] * 512;
	}
	io_read = have_disk_prev ? rate(rd, disk_read_prev, dt) : 0;
	io_write = have_disk_prev ? rate(wr, disk_write_prev, dt) : 0;
	disk_read_prev = rd;
	disk_write_prev = wr;
	have_disk_prev = 1;
}

static void sample_volumes(void) {
	FILE *f = setmntent("/proc/self/mounts", "r");
	nvolumes = 0;
	if (!f) return;
	struct mntent *m;
	dev_t seen[MAX_VOLUMES];
	while ((m = getmntent(f)) != NULL && nvolumes < MAX_VOLUMES) {
		if (strncmp(m->mnt_fsname, "/dev/", 5) != 0) continue;
		if (strncmp(m->mnt_fsname, "/dev/loop", 9) == 0) continue;
		if (strcmp(m->mnt_type, "squashfs") == 0 || strcmp(m->mnt_type, "iso9660") == 0) continue;
		struct stat st;
		if (stat(m->mnt_dir, &st) != 0) continue;
		int dup = 0;
		for (size_t i = 0; i < nvolumes; i++) dup |= seen[i] == st.st_dev;
		if (dup) continue; // bind mounts and btrfs subvolumes of one filesystem
		struct statvfs v;
		if (statvfs(m->mnt_dir, &v) != 0 || v.f_blocks == 0) continue;
		Volume *vol = &volumes[nvolumes];
		seen[nvolumes] = st.st_dev;
		snprintf(vol->name, sizeof vol->name, "%s", m->mnt_dir);
		const char *base = strrchr(m->mnt_fsname, '/');
		snprintf(vol->label, sizeof vol->label, "%s · %s", base ? base + 1 : m->mnt_fsname, m->mnt_type);
		vol->size = (uint64_t)v.f_blocks * v.f_frsize;
		vol->free = (uint64_t)v.f_bavail * v.f_frsize;
		nvolumes++;
	}
	endmntent(f);
}

// Physical interfaces only: bridges, veths, tunnels and VPNs carry the same bytes again.
static int virtual_nic(const char *name) {
	char path[300];
	snprintf(path, sizeof path, "/sys/devices/virtual/net/%s", name);
	return access(path, F_OK) == 0;
}

static void sample_net(double dt) {
	nnics = 0;
	if (read_file("/proc/net/dev", buf, sizeof buf) <= 0) return;
	NicPrev cur[MAX_NICS];
	size_t ncur = 0;
	for (int pass = 0; pass < 2 && ncur == 0; pass++) {
		// The second pass takes virtual interfaces too, for machines that only have those.
		char *line = strchr(buf, '\n');
		line = line ? strchr(line + 1, '\n') : NULL; // two header lines
		for (line = line ? line + 1 : NULL; line && *line && ncur < MAX_NICS; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL) {
			char *colon = strchr(line, ':');
			char *end = strchr(line, '\n');
			if (!colon || (end && colon > end)) continue;
			char *name = line;
			while (*name == ' ') name++;
			size_t n = (size_t)(colon - name);
			if (n == 0 || n >= sizeof cur[0].name) continue;
			char nm[64];
			memcpy(nm, name, n);
			nm[n] = 0;
			if (strcmp(nm, "lo") == 0) continue;
			if (pass == 0 && virtual_nic(nm)) continue;
			char *p = colon + 1;
			unsigned long long v[9];
			for (int k = 0; k < 9; k++) v[k] = strtoull(p, &p, 10);
			memcpy(cur[ncur].name, nm, n + 1);
			cur[ncur].rx = v[0];
			cur[ncur].tx = v[8];
			ncur++;
		}
	}
	for (size_t i = 0; i < ncur; i++) {
		Nic *out = &nics[nnics++];
		memcpy(out->name, cur[i].name, sizeof out->name);
		out->rx = out->tx = 0;
		for (size_t j = 0; j < nnic_prev; j++) {
			if (strcmp(nic_prev[j].name, cur[i].name) == 0) {
				out->rx = rate(cur[i].rx, nic_prev[j].rx, dt);
				out->tx = rate(cur[i].tx, nic_prev[j].tx, dt);
				break;
			}
		}
	}
	memcpy(nic_prev, cur, ncur * sizeof(NicPrev));
	nnic_prev = ncur;
}

// NVIDIA through NVML, the library nvidia-smi uses, loaded only where the
// driver installed it. Signatures as in nvml.h.
typedef struct {
	unsigned int gpu, memory;
} NvmlUtil;
typedef struct {
	unsigned long long total, free, used;
} NvmlMem;
static void *nvml;
static int nvml_tried;
static int (*nvml_count)(unsigned int *);
static int (*nvml_handle)(unsigned int, void **);
static int (*nvml_util)(void *, NvmlUtil *);
static int (*nvml_mem)(void *, NvmlMem *);
static int (*nvml_name)(void *, char *, unsigned int);

static void nvml_open(void) {
	nvml_tried = 1;
	void *lib = dlopen("libnvidia-ml.so.1", RTLD_LAZY | RTLD_LOCAL);
	if (!lib) return;
	int (*init)(void) = (int (*)(void))dlsym(lib, "nvmlInit_v2");
	*(void **)&nvml_count = dlsym(lib, "nvmlDeviceGetCount_v2");
	*(void **)&nvml_handle = dlsym(lib, "nvmlDeviceGetHandleByIndex_v2");
	*(void **)&nvml_util = dlsym(lib, "nvmlDeviceGetUtilizationRates");
	*(void **)&nvml_mem = dlsym(lib, "nvmlDeviceGetMemoryInfo");
	*(void **)&nvml_name = dlsym(lib, "nvmlDeviceGetName");
	if (!init || !nvml_count || !nvml_handle || !nvml_util || !nvml_mem || !nvml_name || init() != 0) {
		dlclose(lib);
		return;
	}
	nvml = lib;
}

static void sample_gpus(void) {
	ngpus = 0;
	if (!nvml_tried) nvml_open();
	unsigned int count = 0;
	if (nvml && nvml_count(&count) == 0) {
		for (unsigned int i = 0; i < count && ngpus < MAX_GPUS; i++) {
			void *dev;
			if (nvml_handle(i, &dev) != 0) continue;
			Gpu *g = &gpus[ngpus++];
			if (nvml_name(dev, g->name, sizeof g->name) != 0) snprintf(g->name, sizeof g->name, "NVIDIA GPU %u", i);
			NvmlUtil u;
			g->util = nvml_util(dev, &u) == 0 ? (double)u.gpu : -1;
			NvmlMem m;
			if (nvml_mem(dev, &m) == 0) {
				g->used = m.used;
				g->total = m.total;
			} else {
				g->used = g->total = 0;
			}
		}
	}
	// AMD (amdgpu) reports its busy share and VRAM in sysfs.
	DIR *d = opendir("/sys/class/drm");
	if (!d) return;
	struct dirent *e;
	char path[600], text[256];
	while ((e = readdir(d)) != NULL && ngpus < MAX_GPUS) {
		if (strncmp(e->d_name, "card", 4) != 0 || strchr(e->d_name, '-')) continue; // connectors are card0-DP-1
		snprintf(path, sizeof path, "/sys/class/drm/%s/device/gpu_busy_percent", e->d_name);
		if (read_file(path, text, sizeof text) <= 0) continue;
		Gpu *g = &gpus[ngpus++];
		g->util = strtod(text, NULL);
		snprintf(path, sizeof path, "/sys/class/drm/%s/device/mem_info_vram_used", e->d_name);
		g->used = read_file(path, text, sizeof text) > 0 ? strtoull(text, NULL, 10) : 0;
		snprintf(path, sizeof path, "/sys/class/drm/%s/device/mem_info_vram_total", e->d_name);
		g->total = read_file(path, text, sizeof text) > 0 ? strtoull(text, NULL, 10) : 0;
		snprintf(path, sizeof path, "/sys/class/drm/%s/device/product_name", e->d_name);
		if (read_file(path, text, sizeof text) > 0 && text[0] && text[0] != '\n') {
			char *nl = strchr(text, '\n');
			if (nl) *nl = 0;
			copy_name(g->name, text, sizeof g->name - 1);
		} else {
			snprintf(g->name, sizeof g->name, "AMD GPU (%.32s)", e->d_name);
		}
	}
	closedir(d);
}

// =============================================================================
#elif defined(__APPLE__)
// =============================================================================

static mach_port_t host_port;
static double ns_per_tick = 1;
static uint64_t *core_busy_prev, *core_total_prev;
static int core_prev_n;
static uint64_t disk_read_prev, disk_write_prev;
static int have_disk_prev;

typedef struct {
	char name[64];
	uint64_t rx, tx;
} NicPrev;
static NicPrev nic_prev[MAX_NICS];
static size_t nnic_prev;

static void sysctl_str(const char *key, char *out, size_t cap) {
	size_t len = cap;
	if (sysctlbyname(key, out, &len, NULL, 0) != 0) out[0] = 0;
	else out[cap - 1] = 0;
}

static void describe(void) {
	host_port = mach_host_self();
	mach_timebase_info_data_t tb;
	if (mach_timebase_info(&tb) == 0 && tb.denom) ns_per_tick = (double)tb.numer / tb.denom;
	char ver[64], build[64];
	sysctl_str("kern.osproductversion", ver, sizeof ver);
	sysctl_str("kern.osversion", build, sizeof build);
	snprintf(os_name, sizeof os_name, "macOS %s%s%s%s", ver[0] ? ver : "", build[0] ? " (" : "", build, build[0] ? ")" : "");
	sysctl_str("machdep.cpu.brand_string", cpu_name, sizeof cpu_name);
	if (!cpu_name[0]) sysctl_str("hw.model", cpu_name, sizeof cpu_name);
}

static void sample_cores(void) {
	natural_t count = 0;
	processor_info_array_t info;
	mach_msg_type_number_t info_count;
	if (host_processor_info(host_port, PROCESSOR_CPU_LOAD_INFO, &count, &info, &info_count) != KERN_SUCCESS)
		die("host_processor_info failed");
	int n = (int)count;
	set_cores(n);
	if (core_prev_n != n) {
		core_busy_prev = xrealloc(core_busy_prev, (size_t)n * sizeof(uint64_t));
		core_total_prev = xrealloc(core_total_prev, (size_t)n * sizeof(uint64_t));
		memset(core_busy_prev, 0, (size_t)n * sizeof(uint64_t));
		memset(core_total_prev, 0, (size_t)n * sizeof(uint64_t));
		core_prev_n = n;
	}
	double sum = 0;
	for (int i = 0; i < n; i++) {
		unsigned int *t = (unsigned int *)&info[i * CPU_STATE_MAX];
		uint64_t busy = (uint64_t)t[CPU_STATE_USER] + t[CPU_STATE_SYSTEM] + t[CPU_STATE_NICE];
		uint64_t total = busy + t[CPU_STATE_IDLE];
		double use = total > core_total_prev[i] && busy >= core_busy_prev[i]
			? 100.0 * (double)(busy - core_busy_prev[i]) / (double)(total - core_total_prev[i])
			: 0;
		core_use[i] = use < 0 ? 0 : use > 100 ? 100 : use;
		sum += core_use[i];
		core_busy_prev[i] = busy;
		core_total_prev[i] = total;
	}
	vm_deallocate(mach_task_self(), (vm_address_t)info, (vm_size_t)info_count * sizeof(integer_t));
	cpu_total = n > 0 ? sum / n : 0;
}

static int *pid_list;
static size_t pid_cap;

static void sample_processes(double dt) {
	int want = proc_listallpids(NULL, 0);
	if (want <= 0) die("proc_listallpids failed: %s", strerror(errno));
	size_t need = (size_t)want + 64;
	if (need > pid_cap) {
		pid_cap = need * 2;
		pid_list = xrealloc(pid_list, pid_cap * sizeof(int));
	}
	int got = proc_listallpids(pid_list, (int)(pid_cap * sizeof(int)));
	if (got <= 0) die("proc_listallpids failed: %s", strerror(errno));
	size_t count = (size_t)got;

	double capacity = dt * 1e9 * (double)ncores;
	uint64_t threads = 0;
	procs_begin(count);
	for (size_t i = 0; i < count; i++) {
		int pid = pid_list[i];
		if (pid == 0) continue; // kernel_task is pid 0 and readable only as root
		struct proc_taskallinfo ti;
		char name[NAME_MAX_LEN] = "";
		uint64_t start = 0, cpu = 0, ws = 0, priv = 0, io = 0;
		int nthreads = 0, cpu_known = 0, io_known = 0;
		int r = proc_pidinfo(pid, PROC_PIDTASKALLINFO, 0, &ti, sizeof ti);
		if (r == (int)sizeof ti) {
			copy_name(name, ti.pbsd.pbi_name[0] ? ti.pbsd.pbi_name : ti.pbsd.pbi_comm, sizeof ti.pbsd.pbi_name);
			start = (uint64_t)ti.pbsd.pbi_start_tvsec * 1000000u + ti.pbsd.pbi_start_tvusec;
			cpu = (uint64_t)((double)(ti.ptinfo.pti_total_user + ti.ptinfo.pti_total_system) * ns_per_tick);
			ws = ti.ptinfo.pti_resident_size;
			priv = ws;
			nthreads = ti.ptinfo.pti_threadnum;
			cpu_known = 1;
		} else {
			// Another user's process: its name and start time only.
			struct proc_bsdshortinfo si;
			if (proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &si, sizeof si) != (int)sizeof si) continue;
			copy_name(name, si.pbsi_comm, sizeof si.pbsi_comm);
			struct proc_bsdinfo bi;
			if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, sizeof bi) == (int)sizeof bi)
				start = (uint64_t)bi.pbi_start_tvsec * 1000000u + bi.pbi_start_tvusec;
		}
		struct rusage_info_v2 ru;
		if (proc_pid_rusage(pid, RUSAGE_INFO_V2, (rusage_info_t *)&ru) == 0) {
			io = ru.ri_diskio_bytesread + ru.ri_diskio_byteswritten;
			io_known = 1;
			priv = ru.ri_phys_footprint; // what Activity Monitor calls Memory
			if (!ws) ws = ru.ri_resident_size;
		}
		threads += (uint64_t)nthreads;
		proc_record(pid, start, name, cpu, cpu_known, io, io_known, ws, priv, nthreads, dt, capacity);
	}
	procs_end();
	count_proc = nprocs;
	count_thread = threads;
	int files = 0;
	size_t len = sizeof files;
	have_files = sysctlbyname("kern.num_files", &files, &len, NULL, 0) == 0;
	count_files = have_files && files > 0 ? (uint64_t)files : 0;
}

static void sample_memory(void) {
	uint64_t total = 0;
	size_t len = sizeof total;
	if (sysctlbyname("hw.memsize", &total, &len, NULL, 0) != 0) die("sysctl hw.memsize failed");
	mem_total = total;
	vm_size_t page = 0;
	if (host_page_size(host_port, &page) != KERN_SUCCESS || !page) page = 4096;
	vm_statistics64_data_t vs;
	mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
	if (host_statistics64(host_port, HOST_VM_INFO64, (host_info64_t)&vs, &count) != KERN_SUCCESS)
		die("host_statistics64 failed");
	// Activity Monitor's Memory Used: app memory + wired + compressed.
	uint64_t app = vs.internal_page_count > vs.purgeable_count ? vs.internal_page_count - vs.purgeable_count : 0;
	uint64_t used = (app + vs.wire_count + vs.compressor_page_count) * (uint64_t)page;
	mem_avail = used < total ? total - used : 0;
	mem_cache = ((uint64_t)vs.external_page_count + vs.purgeable_count) * (uint64_t)page;
	mem_wired = (uint64_t)vs.wire_count * page;
	struct xsw_usage sw;
	len = sizeof sw;
	if (sysctlbyname("vm.swapusage", &sw, &len, NULL, 0) == 0) {
		swap_total = sw.xsu_total;
		swap_used = sw.xsu_used;
	}
	struct timeval boot;
	len = sizeof boot;
	if (sysctlbyname("kern.boottime", &boot, &len, NULL, 0) == 0) {
		struct timeval now;
		gettimeofday(&now, NULL);
		up_s = (double)(now.tv_sec - boot.tv_sec);
	}
}

static uint64_t dict_u64(CFDictionaryRef d, const char *key) {
	CFStringRef k = CFStringCreateWithCString(kCFAllocatorDefault, key, kCFStringEncodingUTF8);
	CFNumberRef n = (CFNumberRef)CFDictionaryGetValue(d, k);
	CFRelease(k);
	int64_t v = 0;
	if (n && CFGetTypeID(n) == CFNumberGetTypeID()) CFNumberGetValue(n, kCFNumberSInt64Type, &v);
	return v > 0 ? (uint64_t)v : 0;
}

static void sample_disk_io(double dt) {
	io_iterator_t it;
	uint64_t rd = 0, wr = 0;
	// MACH_PORT_NULL is the default main port on every macOS version.
	if (IOServiceGetMatchingServices(MACH_PORT_NULL, IOServiceMatching(kIOBlockStorageDriverClass), &it) == KERN_SUCCESS) {
		io_registry_entry_t e;
		while ((e = IOIteratorNext(it)) != 0) {
			CFMutableDictionaryRef props = NULL;
			if (IORegistryEntryCreateCFProperties(e, &props, kCFAllocatorDefault, 0) == KERN_SUCCESS && props) {
				CFDictionaryRef stats = (CFDictionaryRef)CFDictionaryGetValue(props, CFSTR(kIOBlockStorageDriverStatisticsKey));
				if (stats && CFGetTypeID(stats) == CFDictionaryGetTypeID()) {
					rd += dict_u64(stats, kIOBlockStorageDriverStatisticsBytesReadKey);
					wr += dict_u64(stats, kIOBlockStorageDriverStatisticsBytesWrittenKey);
				}
				CFRelease(props);
			}
			IOObjectRelease(e);
		}
		IOObjectRelease(it);
	}
	io_read = have_disk_prev ? rate(rd, disk_read_prev, dt) : 0;
	io_write = have_disk_prev ? rate(wr, disk_write_prev, dt) : 0;
	disk_read_prev = rd;
	disk_write_prev = wr;
	have_disk_prev = 1;
}

static void sample_volumes(void) {
	struct statfs *m;
	int n = getmntinfo(&m, MNT_NOWAIT);
	nvolumes = 0;
	for (int i = 0; i < n && nvolumes < MAX_VOLUMES; i++) {
		if (!(m[i].f_flags & MNT_LOCAL) || (m[i].f_flags & MNT_DONTBROWSE)) continue;
		if (strcmp(m[i].f_fstypename, "devfs") == 0 || strcmp(m[i].f_fstypename, "autofs") == 0) continue;
		if (m[i].f_blocks == 0) continue;
		Volume *v = &volumes[nvolumes++];
		snprintf(v->name, sizeof v->name, "%s", m[i].f_mntonname);
		const char *base = strrchr(m[i].f_mntfromname, '/');
		snprintf(v->label, sizeof v->label, "%s · %s", base ? base + 1 : m[i].f_mntfromname, m[i].f_fstypename);
		v->size = (uint64_t)m[i].f_blocks * m[i].f_bsize;
		v->free = (uint64_t)m[i].f_bavail * m[i].f_bsize;
	}
}

// VPN tunnels, AirDrop and bridges carry the same bytes as the physical links again.
static int virtual_nic(const char *name) {
	static const char *skip[] = { "utun", "awdl", "llw", "gif", "stf", "anpi", "ipsec", "bridge", "ap" };
	for (size_t i = 0; i < sizeof skip / sizeof *skip; i++)
		if (strncmp(name, skip[i], strlen(skip[i])) == 0) return 1;
	return 0;
}

static void sample_net(double dt) {
	nnics = 0;
	int mib[6] = { CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0 };
	size_t len = 0;
	if (sysctl(mib, 6, NULL, &len, NULL, 0) != 0 || len == 0) return;
	char *table = malloc(len);
	if (!table) return;
	if (sysctl(mib, 6, table, &len, NULL, 0) != 0) {
		free(table);
		return;
	}
	NicPrev cur[MAX_NICS];
	size_t ncur = 0;
	for (int pass = 0; pass < 2 && ncur == 0; pass++) {
		for (char *p = table; p < table + len && ncur < MAX_NICS;) {
			struct if_msghdr *h = (struct if_msghdr *)p;
			if (h->ifm_msglen == 0) break;
			p += h->ifm_msglen;
			if (h->ifm_type != RTM_IFINFO2) continue;
			struct if_msghdr2 *h2 = (struct if_msghdr2 *)h;
			if (!(h2->ifm_flags & IFF_UP) || (h2->ifm_flags & IFF_LOOPBACK)) continue;
			char nm[IF_NAMESIZE];
			if (!if_indextoname(h2->ifm_index, nm)) continue;
			if (pass == 0 && virtual_nic(nm)) continue;
			if (h2->ifm_data.ifi_ibytes + h2->ifm_data.ifi_obytes == 0) continue; // never used
			snprintf(cur[ncur].name, sizeof cur[ncur].name, "%s", nm);
			cur[ncur].rx = h2->ifm_data.ifi_ibytes;
			cur[ncur].tx = h2->ifm_data.ifi_obytes;
			ncur++;
		}
	}
	free(table);
	for (size_t i = 0; i < ncur; i++) {
		Nic *out = &nics[nnics++];
		memcpy(out->name, cur[i].name, sizeof out->name);
		out->rx = out->tx = 0;
		for (size_t j = 0; j < nnic_prev; j++) {
			if (strcmp(nic_prev[j].name, cur[i].name) == 0) {
				out->rx = rate(cur[i].rx, nic_prev[j].rx, dt);
				out->tx = rate(cur[i].tx, nic_prev[j].tx, dt);
				break;
			}
		}
	}
	memcpy(nic_prev, cur, ncur * sizeof(NicPrev));
	nnic_prev = ncur;
}

// A CFString or CFData property as text.
static void cf_text(CFTypeRef v, char *out, size_t cap) {
	out[0] = 0;
	if (!v) return;
	if (CFGetTypeID(v) == CFStringGetTypeID()) {
		CFStringGetCString((CFStringRef)v, out, (CFIndex)cap, kCFStringEncodingUTF8);
	} else if (CFGetTypeID(v) == CFDataGetTypeID()) {
		CFIndex n = CFDataGetLength((CFDataRef)v);
		if ((size_t)n >= cap) n = (CFIndex)cap - 1;
		memcpy(out, CFDataGetBytePtr((CFDataRef)v), (size_t)n);
		out[n] = 0;
	}
}

// Every GPU's accelerator publishes PerformanceStatistics, as Activity Monitor reads them.
static void sample_gpus(void) {
	ngpus = 0;
	io_iterator_t it;
	if (IOServiceGetMatchingServices(MACH_PORT_NULL, IOServiceMatching("IOAccelerator"), &it) != KERN_SUCCESS) return;
	io_registry_entry_t e;
	while ((e = IOIteratorNext(it)) != 0) {
		CFMutableDictionaryRef props = NULL;
		if (ngpus < MAX_GPUS && IORegistryEntryCreateCFProperties(e, &props, kCFAllocatorDefault, 0) == KERN_SUCCESS && props) {
			CFDictionaryRef perf = (CFDictionaryRef)CFDictionaryGetValue(props, CFSTR("PerformanceStatistics"));
			if (perf && CFGetTypeID(perf) == CFDictionaryGetTypeID()) {
				Gpu *g = &gpus[ngpus++];
				CFNumberRef u = (CFNumberRef)CFDictionaryGetValue(perf, CFSTR("Device Utilization %"));
				g->util = u ? (double)dict_u64(perf, "Device Utilization %") : -1;
				g->used = dict_u64(perf, "vramUsedBytes");
				uint64_t freeBytes = dict_u64(perf, "vramFreeBytes");
				g->total = g->used && freeBytes ? g->used + freeBytes : 0; // Apple silicon shares system memory
				if (!g->total) g->used = dict_u64(perf, "In use system memory");
				CFTypeRef model = IORegistryEntrySearchCFProperty(e, kIOServicePlane, CFSTR("model"), kCFAllocatorDefault,
					kIORegistryIterateRecursively | kIORegistryIterateParents);
				cf_text(model, g->name, sizeof g->name);
				if (model) CFRelease(model);
				if (!g->name[0]) snprintf(g->name, sizeof g->name, "GPU %zu", ngpus);
			}
			CFRelease(props);
		}
		IOObjectRelease(e);
	}
	IOObjectRelease(it);
}

#endif

// ---- sampling and output (both systems) ------------------------------------------

static void sample(void) {
	double now = mono_s();
	double dt = prev_at < 0 ? 0 : now - prev_at;
	sample_cores();
	sample_processes(dt);
	sample_memory();
	sample_disk_io(dt);
	if (now - volumes_at > 10) {
		sample_volumes();
		volumes_at = now;
	}
	sample_net(dt);
	sample_gpus();
	prev_at = now;
	seq++;
}

static void write_snapshot(const char *path, int interval) {
	js_len = 0;
	js_put("{\"v\":1,\"seq\":");
	js_u64(seq);
	js_put(",\"at\":");
	js_u64((uint64_t)wall_ms());
	js_put(",\"interval\":");
	js_u64((uint64_t)interval);
	js_put(",\"os\":");
	js_str(os_name);
	js_put(",\"cpuName\":");
	js_str(cpu_name);
	js_put(",\"up\":");
	js_u64((uint64_t)clamp_pos(up_s));

	js_put(",\"cpu\":{\"total\":");
	js_num(cpu_total);
	js_put(",\"cores\":[");
	for (int i = 0; i < ncores; i++) {
		if (i) js_put(",");
		js_num(core_use[i]);
	}
	js_put("]}");

	js_put(",\"mem\":{\"total\":");
	js_u64(mem_total);
	js_put(",\"avail\":");
	js_u64(mem_avail);
	js_put(",\"cache\":");
	js_u64(mem_cache);
	js_put(",\"swap\":");
	js_u64(swap_used);
	js_put(",\"swapTotal\":");
	js_u64(swap_total);
	if (mem_wired) {
		js_put(",\"wired\":");
		js_u64(mem_wired);
	}
	if (mem_kernel) {
		js_put(",\"kernel\":");
		js_u64(mem_kernel);
	}
	js_put("}");

	js_put(",\"counts\":{\"proc\":");
	js_u64(count_proc);
	js_put(",\"thread\":");
	js_u64(count_thread);
	if (have_files) {
		js_put(",\"files\":");
		js_u64(count_files);
	}
	js_put("}");

	js_put(",\"io\":{\"read\":");
	js_num(io_read);
	js_put(",\"write\":");
	js_num(io_write);
	js_put("}");

	js_put(",\"disk\":[");
	for (size_t i = 0; i < nvolumes; i++) {
		if (i) js_put(",");
		js_put("{\"name\":");
		js_str(volumes[i].name);
		js_put(",\"label\":");
		js_str(volumes[i].label);
		js_put(",\"size\":");
		js_u64(volumes[i].size);
		js_put(",\"free\":");
		js_u64(volumes[i].free);
		js_put("}");
	}
	js_put("]");

	js_put(",\"net\":[");
	for (size_t i = 0; i < nnics; i++) {
		if (i) js_put(",");
		js_put("{\"name\":");
		js_str(nics[i].name);
		js_put(",\"rx\":");
		js_num(nics[i].rx);
		js_put(",\"tx\":");
		js_num(nics[i].tx);
		js_put("}");
	}
	js_put("]");

	js_put(",\"gpu\":[");
	for (size_t i = 0; i < ngpus; i++) {
		if (i) js_put(",");
		js_put("{\"name\":");
		js_str(gpus[i].name);
		js_put(",\"util\":");
		js_num(gpus[i].util < 0 ? -1 : gpus[i].util > 100 ? 100 : gpus[i].util);
		js_put(",\"memUsed\":");
		js_u64(gpus[i].used);
		js_put(",\"memTotal\":");
		js_u64(gpus[i].total);
		js_put("}");
	}
	js_put("]");

	// [pid, name, cpu %, resident, private, threads, io bytes/s]
	js_put(",\"proc\":[");
	for (size_t i = 0; i < nprocs; i++) {
		Proc *p = &procs[i];
		if (i) js_put(",");
		js_put("[");
		js_u64((uint64_t)p->pid);
		js_put(",");
		js_str(p->name);
		js_put(",");
		js_num(clamp_pos(p->cpu));
		js_put(",");
		js_u64(p->ws);
		js_put(",");
		js_u64(p->priv);
		js_put(",");
		js_u64((uint64_t)(p->threads > 0 ? p->threads : 0));
		js_put(",");
		js_num(clamp_pos(p->io));
		js_put("]");
	}
	js_put("]}");

	char tmp[4300];
	snprintf(tmp, sizeof tmp, "%s.tmp", path);
	int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) return; // the next sample tries again
	size_t off = 0;
	while (off < js_len) {
		ssize_t w = write(fd, js + off, js_len - off);
		if (w < 0) {
			if (errno == EINTR) continue;
			break;
		}
		off += (size_t)w;
	}
	close(fd);
	if (off == js_len) rename(tmp, path);
	else unlink(tmp);
}

// The owner file holds exactly this collector's token.
static int still_owner(const char *path, const char *token) {
	char text[256];
	if (read_file(path, text, sizeof text) < 0) return 0;
	char *s = text;
	while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
	char *e = s + strlen(s);
	while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n')) *--e = 0;
	return strcmp(s, token) == 0;
}

// Milliseconds since the heartbeat was written (-1 when missing), and the interval it asks for.
static double heartbeat_age(const char *path, int *interval) {
	*interval = 0;
	struct stat st;
	if (stat(path, &st) != 0) return -1;
	char text[64];
	if (read_file(path, text, sizeof text) > 0) {
		char *end;
		long ms = strtol(text, &end, 10);
		if (end != text && ms >= 250) *interval = (int)(ms > 60000 ? 60000 : ms);
	}
#if defined(__APPLE__)
	double mtime = (double)st.st_mtimespec.tv_sec * 1000.0 + st.st_mtimespec.tv_nsec / 1e6;
#else
	double mtime = (double)st.st_mtim.tv_sec * 1000.0 + st.st_mtim.tv_nsec / 1e6;
#endif
	return wall_ms() - mtime;
}

int main(int argc, char **argv) {
	if (argc < 3) {
		if (argc > 1) snprintf(g_dir, sizeof g_dir, "%s", argv[1]);
		die("usage: sysmon-collector <data dir> <owner token>");
	}
	snprintf(g_dir, sizeof g_dir, "%s", argv[1]);
	const char *token = argv[2];
	signal(SIGPIPE, SIG_IGN);
	setpriority(PRIO_PROCESS, 0, 10); // stay out of the way, as BelowNormal does on Windows

	char heartbeat[4200], owner[4200], snapshot[4200], err[4200];
	snprintf(heartbeat, sizeof heartbeat, "%s/heartbeat", g_dir);
	snprintf(owner, sizeof owner, "%s/owner", g_dir);
	snprintf(snapshot, sizeof snapshot, "%s/snapshot.json", g_dir);
	snprintf(err, sizeof err, "%s/collector.err", g_dir);
	struct stat st;
	if (stat(g_dir, &st) != 0 || !S_ISDIR(st.st_mode)) die("no data directory: %s", g_dir);
	unlink(err);

	describe();
	// Two quick samples, so the first snapshot already carries rates.
	sample();
	sleep_ms(500);
	sample();
	int interval = 2000;
	for (;;) {
		write_snapshot(snapshot, interval);
		if (!still_owner(owner, token)) return 0; // replaced, or the plugin stopped us
		int asked;
		double age = heartbeat_age(heartbeat, &asked);
		if (asked > 0) interval = asked;
		double limit = interval * 4.0 > MIN_STALE_MS ? interval * 4.0 : MIN_STALE_MS;
		if (age < 0 || age > limit) return 0; // nobody is watching
		sleep_ms(interval);
		sample();
	}
}
