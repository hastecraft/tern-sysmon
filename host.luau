--!strict
-- host.luau — the `monitor` block: this machine, drawn natively in Tern.
--
-- A native sampler runs while any monitor block is open and writes
-- snapshot.json into the plugin's data folder every interval: collector.cs
-- on Windows (built once with the in-box C# compiler), collector.c on Linux
-- and macOS (built once with the system C compiler). This file polls that
-- snapshot and draws it; one collector serves every open block. See the
-- collector sources for the file protocol (heartbeat, owner, snapshot.json,
-- collector.err).

local ui = tern.ui

local OS = tern.runtime.os
local WINDOWS = OS == "windows"
local SEP = if WINDOWS then "\\" else "/"
local SOURCE = if WINDOWS then "collector.cs" else "collector.c"
local CSC_PATH = "\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe"
local NO_CC = "There is no C compiler (cc) on this machine. The collector is built from source once;\n"
	.. "install one, then press R:  sudo apt install gcc  ·  sudo dnf install gcc  ·  sudo pacman -S gcc"
local NO_CLT = "The Xcode Command Line Tools are not installed. The collector is built from source once;\n"
	.. "run  xcode-select --install  in a terminal, then press R."
local INTERVALS = { 1000, 2000, 5000, 10000 } -- the sample intervals the head's select offers
local DEFAULT_MS = 2000
local TREND = 30 -- samples a process sparkline draws
local BEAT_MS = 2000
local BUILD_TIMEOUT_MS = 120000
local MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
-- What a user can change in Settings, kept in tern.kv under "settings".
local DEFAULTS: { [string]: any } = {
	stats = true,
	cpu = true,
	cores = true,
	mem = true,
	net = true,
	io = true,
	vol = true,
	procs = true,
	gpu = true,
	history = 120, -- samples a history chart draws
	rows = 20, -- rows the process table lists (0: every process)
}
local HISTORY_OPTIONS: { { any } } = { { 60, "60 samples" }, { 120, "120 samples" }, { 300, "300 samples" } }
local ROW_OPTIONS: { { any } } = { { 10, "10" }, { 20, "20" }, { 50, "50" }, { 0, "All" } }
-- The process table's sortable columns, in the order `s` cycles through the busy ones.
local SORT_CYCLE = { "cpu", "mem", "io" }
local SORT_COLS: { [string]: boolean } = { pid = true, name = true, cpu = true, mem = true, io = true, thr = true }

type Proc = { pid: number, name: string, cpu: number, ws: number, priv: number, threads: number, io: number }
type Volume = { name: string, label: string, size: number, free: number }
type Nic = { name: string, rx: number, tx: number }
-- util is a percentage, or -1 when the driver doesn't report one; memTotal is 0
-- when the GPU shares system memory (or doesn't say).
type Gpu = { name: string, util: number, memUsed: number, memTotal: number }
type Mem = {
	total: number,
	avail: number,
	cache: number?,
	commit: number?, -- Windows: committed bytes and the commit limit
	limit: number?,
	kpaged: number?, -- Windows: kernel paged and nonpaged pools
	knonpaged: number?,
	kernel: number?, -- Linux: slab, kernel stacks and page tables
	wired: number?, -- macOS: wired memory
	swap: number?, -- Linux and macOS: swap in use and its size
	swapTotal: number?,
}
type Counts = { proc: number, thread: number, handle: number?, files: number? }
type Snapshot = {
	seq: number,
	at: number,
	interval: number,
	os: string,
	cpuName: string,
	up: number,
	cpu: { total: number, cores: { number } },
	mem: Mem,
	counts: Counts?,
	io: { read: number, write: number },
	disk: { Volume },
	net: { Nic },
	gpu: { Gpu }?, -- absent from collectors before 0.3
	proc: { Proc },
}
type Sort = { col: string, dir: string }
type Confirm = { pid: number, name: string, busy: boolean }
type Block = { cx: BlockCx, sort: Sort, selected: string?, confirm: Confirm?, settingsOpen: boolean }

-- The view is built from Tern's own kinds (stats, charts, tables, cards, tabs,
-- buttons, select), which size, theme and lay themselves out: no stylesheet.

-- ---- shared state: one collector, one poll loop, every open block ----------

local blocks: { [number]: Block } = {}

local data = tern.plugin.data
local function path(name: string): string
	return data .. SEP .. name
end

local function kv_get(key: string): any
	local ok, value = pcall(tern.kv.get, key)
	return if ok then value else nil
end

-- The nearest offered interval to `ms`.
local function snap_interval(ms: number): number
	local best = INTERVALS[1]
	for _, v in INTERVALS do
		if math.abs(v - ms) < math.abs(best - ms) then
			best = v
		end
	end
	return best
end

local interval: number = snap_interval(tonumber(kv_get("interval")) or DEFAULT_MS)
local snap: Snapshot? = nil
local lastAt = -1
local changedAt = 0
local stale = false
-- The saved settings over the defaults; a value of the wrong type falls back.
local function load_settings(): { [string]: any }
	local out = table.clone(DEFAULTS)
	local saved = kv_get("settings")
	if type(saved) == "table" then
		for k, v in DEFAULTS do
			if type(saved[k]) == type(v) then
				out[k] = saved[k]
			end
		end
	end
	return out
end
local settings = load_settings()

-- Machine-wide histories (newest last), and a short CPU trend per process.
local hist = {
	cpu = {} :: { number },
	mem = {} :: { number },
	rx = {} :: { number },
	tx = {} :: { number },
	read = {} :: { number },
	write = {} :: { number },
}
local procTrend: { [number]: { number } } = {}
local gpuHist: { { number } } = {}
-- idle | building | starting | running | error
local status = "idle"
local problem: string? = nil
local collector = { token = nil :: string?, running = false, building = false, retryAt = 0, failures = 0 }
local pollTimer: TimerHandle? = nil
local lastBeat = -1e12
local exeName: string? = nil

-- ---- formatting ---------------------------------------------------------------

local UNITS = { "B", "KiB", "MiB", "GiB", "TiB", "PiB" }

local function human(bytes: number): string
	local v, i = bytes, 1
	while v >= 1024 and i < #UNITS do
		v /= 1024
		i += 1
	end
	if i == 1 then
		return string.format("%d B", v)
	end
	return string.format(if v < 10 then "%.1f %s" else "%.0f %s", v, UNITS[i])
end

local function rate(bps: number): string
	return human(bps) .. "/s"
end

local function pct(v: number): string
	if v >= 99.5 then
		return "100%"
	elseif v >= 9.95 then
		return string.format("%.0f%%", v)
	end
	return string.format("%.1f%%", v)
end

local function grouped(n: number): string
	local s = tostring(math.floor(n))
	local out = string.reverse((string.gsub(string.reverse(s), "(%d%d%d)", "%1,")))
	return (string.gsub(out, "^,", ""))
end

local function duration(seconds: number): string
	local d = seconds // 86400
	local h = seconds % 86400 // 3600
	local m = seconds % 3600 // 60
	if d > 0 then
		return string.format("%dd %dh", d, h)
	elseif h > 0 then
		return string.format("%dh %dm", h, m)
	end
	return string.format("%dm", m)
end

local function first_lines(text: string, n: number): string
	local out = {}
	for line in string.gmatch(text, "[^\r\n]+") do
		table.insert(out, line)
		if #out == n then
			break
		end
	end
	return table.concat(out, "\n")
end

local function with(node: Node, props: { [string]: any }): Node
	local p: { [string]: any } = node.p or {}
	for k, v in props do
		p[k] = v
	end
	node.p = p
	return node
end

-- ---- the collector process ----------------------------------------------------

local function render_all()
	for _, b in blocks do
		b.cx:render()
	end
end

-- Keeps the settings and redraws every open monitor: they share them.
local function save_settings()
	pcall(tern.kv.set, "settings", settings)
	render_all()
end

local function fail(message: string)
	status = "error"
	problem = message
	collector.failures += 1
	collector.retryAt = tern.now() + math.min(60000, 5000 * 2 ^ (collector.failures - 1))
	render_all()
end

local function beat()
	pcall(tern.fs.write, path("heartbeat"), tostring(interval))
	lastBeat = tern.now()
end

-- FNV-1a of the source, so an edited collector gets a fresh build.
local function fnv1a(s: string): number
	local h = 2166136261
	for i = 1, #s do
		h = bit32.bxor(h, (string.byte(s, i)))
		h = (bit32.lshift(h, 24) + h * 403) % 4294967296
	end
	return h
end

local function exe_path(): string
	if not exeName then
		local hash = fnv1a(tern.fs.read(SOURCE))
		exeName = string.format("sysmon-collector-%08x%s", hash, if WINDOWS then ".exe" else "")
	end
	return path(exeName :: string)
end

-- Old builds; one an old collector still runs is locked (Windows) and goes next time.
local function prune_builds()
	local ok, names = pcall(tern.fs.list, data)
	if not ok then
		return
	end
	for _, name in names do
		local build = string.match(name, "^sysmon%-collector%-%x+$") or string.match(name, "^sysmon%-collector%-%x+%.exe$")
		if build and name ~= exeName then
			pcall(tern.fs.remove, path(name))
		end
	end
end

local function launch(exe: string)
	local token = string.format("%x-%x", math.random(0, 0x7fffffff), math.floor(tern.now()))
	collector.token = token
	tern.fs.write(path("owner"), token)
	beat()
	if status ~= "running" then
		status = "starting"
	end
	collector.running = true
	local ok, err = pcall(function()
		tern.process.run({ exe, data, token }, {}, function(result: ProcessResult)
			if collector.token ~= token then
				return -- replaced by a newer collector
			end
			collector.running = false
			if next(blocks) == nil then
				return
			end
			local okRead, text = pcall(tern.fs.read, path("collector.err"), 65536)
			local err = if okRead and text ~= "" then text else nil
			if result.status ~= 0 or err then
				if status == "starting" and not err then
					-- It died before its first snapshot without saying why: likely a
					-- truncated or foreign build. The next attempt compiles afresh.
					pcall(tern.fs.remove, exe)
				end
				fail("The collector stopped (exit " .. result.status .. ").\n" .. first_lines(err or result.stderr, 4))
			else
				-- A clean exit means it saw a stale heartbeat (the machine slept, the
				-- daemon paused): start another at the next poll.
				collector.retryAt = 0
			end
		end)
	end)
	if not ok then
		collector.running = false
		pcall(tern.fs.remove, exe) -- a broken build; the next attempt compiles again
		fail("Tern could not start the collector: " .. tostring(err))
	end
end

-- The compiler command for this OS, or nil and why there is none.
local function compile_argv(exe: string): ({ string }?, string?)
	local src = tern.plugin.dir .. SEP .. SOURCE
	if WINDOWS then
		local root = tern.getenv("SystemRoot") or tern.getenv("WINDIR") or "C:\\Windows"
		local csc = root .. CSC_PATH
		if not tern.fs.exists(csc) then
			return nil, "The in-box C# compiler is missing:\n" .. csc
		end
		return { csc, "/nologo", "/optimize+", "/target:winexe", "/platform:x64", "/out:" .. exe, src }
	elseif OS == "macos" then
		return { "cc", "-O2", "-o", exe, src, "-framework", "IOKit", "-framework", "CoreFoundation" }
	elseif OS == "linux" then
		-- -ldl: glibc before 2.34 keeps dlopen (for NVIDIA's NVML) in libdl.
		return { "cc", "-O2", "-o", exe, src, "-ldl" }
	end
	return nil, "System Monitor runs on Windows, macOS and Linux; this host runs " .. OS .. "."
end

local function compile(exe: string, argv: { string })
	local function built(result: ProcessResult)
		collector.building = false
		if next(blocks) == nil then
			return
		end
		if result.status ~= 0 or not tern.fs.exists(exe) then
			pcall(tern.fs.remove, exe)
			local tool = if WINDOWS then "csc" else "cc"
			local why = first_lines(result.stdout .. "\n" .. result.stderr, 6)
			-- macOS's /usr/bin/cc is a stub that fails without the command line tools.
			if OS == "macos" and string.find(why, "xcode-select", 1, true) then
				fail(NO_CLT)
			else
				fail("Building the collector failed (" .. tool .. " exit " .. result.status .. ").\n" .. why)
			end
			return
		end
		prune_builds()
		launch(exe)
		render_all()
	end
	local ok, err = pcall(function()
		tern.process.run(argv, { timeout_ms = BUILD_TIMEOUT_MS }, built)
	end)
	if not ok then
		collector.building = false
		-- Spawning fails when the compiler is not on PATH at all.
		fail(if WINDOWS then "Tern could not start csc: " .. tostring(err) elseif OS == "macos" then NO_CLT else NO_CC)
	end
end

local function build_then_launch()
	local exe = exe_path()
	if tern.fs.exists(exe) then
		launch(exe)
		return
	end
	local argv, why = compile_argv(exe)
	if not argv then
		fail(why :: string)
		return
	end
	collector.building = true
	status = "building"
	render_all()
	if OS ~= "macos" then
		compile(exe, argv)
		return
	end
	-- Asking first keeps the stub cc from popping up the tools installer on its own.
	local ok = pcall(tern.process.run, { "xcode-select", "-p" }, { timeout_ms = 15000 }, function(result: ProcessResult)
		if result.status ~= 0 then
			collector.building = false
			fail(NO_CLT)
			return
		end
		compile(exe, argv)
	end)
	if not ok then
		collector.building = false
		fail(NO_CLT)
	end
end

local function ensure_collector()
	if collector.running or collector.building or tern.now() < collector.retryAt then
		return
	end
	local ok, err = pcall(function()
		build_then_launch()
	end)
	if not ok then
		collector.building = false
		fail(tostring(err))
	end
end

-- ---- snapshots and history ----------------------------------------------------

local function push(list: { number }, v: number, cap: number?)
	table.insert(list, v)
	while #list > (cap or settings.history) do
		table.remove(list, 1)
	end
end

-- True when a new sample arrived.
local function read_snapshot(): boolean
	local ok, text = pcall(tern.fs.read, path("snapshot.json"), MAX_SNAPSHOT_BYTES)
	if not ok then
		return false
	end
	local at = tonumber(string.match(text, '^{"v":1,"seq":%d+,"at":(%d+)'))
	-- A file left by an earlier run is not news.
	if not at or at == lastAt or at < (os.time() - 60) * 1000 then
		return false
	end
	local okDecode, value = pcall(tern.json.decode, text)
	if not okDecode or type(value) ~= "table" then
		return false
	end
	local raw: any = value
	local procs: { Proc } = table.create(#raw.proc)
	for i, r in raw.proc do
		procs[i] = { pid = r[1], name = r[2], cpu = r[3], ws = r[4], priv = r[5], threads = r[6], io = r[7] }
	end
	raw.proc = procs
	local s: Snapshot = raw

	lastAt = at
	changedAt = tern.now()
	snap = s
	push(hist.cpu, s.cpu.total / 100)
	push(hist.mem, if s.mem.total > 0 then (s.mem.total - s.mem.avail) / s.mem.total else 0)
	local rx, tx = 0, 0
	for _, n in s.net do
		rx += n.rx
		tx += n.tx
	end
	push(hist.rx, rx)
	push(hist.tx, tx)
	push(hist.read, s.io.read)
	push(hist.write, s.io.write)
	local gs: { Gpu } = s.gpu or {}
	if #gpuHist ~= #gs then
		gpuHist = {}
	end
	for i, g in gs do
		gpuHist[i] = gpuHist[i] or {}
		push(gpuHist[i], math.max(0, g.util))
	end

	-- Short trends per process and interface; the ones that went away are dropped.
	local seen: { [number]: { number } } = {}
	for _, p in s.proc do
		local t = procTrend[p.pid] or {}
		push(t, p.cpu, TREND)
		seen[p.pid] = t
	end
	procTrend = seen
	return true
end

-- ---- the poll loop ------------------------------------------------------------

local function prune_blocks()
	local live: { [number]: boolean } = {}
	for _, p in tern.pane.list() do
		live[p.pane] = true
	end
	for pane in blocks do
		if not live[pane] then
			blocks[pane] = nil
		end
	end
end

local function stop()
	if pollTimer then
		pollTimer:cancel()
		pollTimer = nil
	end
	collector.token = nil
	collector.running = false
	pcall(tern.fs.write, path("owner"), "") -- the collector exits within one interval
	status = "idle"
end

local poll: () -> ()

local function kick()
	if pollTimer then
		pollTimer:cancel()
	end
	pollTimer = tern.timer(0, function()
		poll()
	end)
end

function poll()
	pollTimer = nil
	prune_blocks()
	if next(blocks) == nil then
		stop()
		return
	end
	if tern.now() - lastBeat >= BEAT_MS then
		beat()
	end
	ensure_collector()
	local changed = false
	if read_snapshot() then
		changed = true
		if status ~= "running" then
			status = "running"
			problem = nil
			collector.failures = 0
		end
	end
	local nowStale = status == "running" and tern.now() - changedAt > interval * 3 + 5000
	if nowStale ~= stale then
		stale = nowStale
		changed = true
	end
	if changed then
		render_all()
	end
	pollTimer = tern.timer(math.clamp(interval // 4, 250, 1000), function()
		poll()
	end)
end

local function set_interval(ms: number)
	interval = snap_interval(ms)
	pcall(tern.kv.set, "interval", interval)
	beat()
end

-- ---- view helpers ----------------------------------------------------------------

local GIB = 1024 * 1024 * 1024

local function round(v: number, places: number): number
	local m = 10 ^ places
	return math.floor(v * m + 0.5) / m
end

local function ago(seconds: number): string
	if seconds >= 90 then
		return string.format("%d min ago", math.floor(seconds / 60 + 0.5))
	end
	return string.format("%d s ago", math.floor(seconds + 0.5))
end

-- X labels for a history of `n` samples: how long ago the first one was, and now.
local function time_labels(n: number): { string }
	local labels: { string } = table.create(n, "")
	if n >= 2 then
		labels[1] = ago((n - 1) * interval / 1000)
		labels[n] = "now"
	end
	return labels
end

-- The byte-rate unit that keeps a chart's numbers short at `peak`: its divisor and name.
local function rate_unit(peak: number): (number, string)
	local div, i = 1, 1
	while peak / div >= 1024 and i < #UNITS do
		div *= 1024
		i += 1
	end
	return div, UNITS[i] .. "/s"
end

local function peak_of(lists: { { number } }): number
	local peak = 0
	for _, list in lists do
		for _, v in list do
			peak = math.max(peak, v)
		end
	end
	return peak
end

local function divided(values: { number }, div: number): { number }
	local out: { number } = table.create(#values)
	for i, v in values do
		out[i] = round(v / div, 2)
	end
	return out
end

-- A tone only when the value needs attention: warning past `warn`, error past `bad`.
local function alarm(frac: number, warn: number, bad: number): string?
	return if frac >= bad then "error" elseif frac >= warn then "warning" else nil
end

-- A chart in a flex cell: a chart's own min/max props are its value domain, so its
-- width comes from the column around it.
local function sized(key: string, props: { [string]: any }, chart: Node): Node
	props.key = key
	return ui.node("col", props, { chart })
end

local function legend(entries: { { any } }): Node
	local spans: { Span } = {}
	for i, entry in entries do
		if i > 1 then
			spans[#spans + 1] = ui.span("   ")
		end
		for _, k in entry[1] :: { string } do
			spans[#spans + 1] = ui.span(k, "key")
		end
		spans[#spans + 1] = ui.span(" " .. (entry[2] :: string), "muted")
	end
	return ui.node("text", { key = "keys", spans = spans })
end

-- ---- processes: order, selection ---------------------------------------------------

local function field(p: Proc, col: string): any
	if col == "pid" then
		return p.pid
	elseif col == "name" then
		return string.lower(p.name)
	elseif col == "mem" then
		return p.ws
	elseif col == "io" then
		return p.io
	elseif col == "thr" then
		return p.threads
	end
	return p.cpu
end

local function sorted(procs: { Proc }, sort: Sort): { Proc }
	local list = table.clone(procs)
	local col, desc = sort.col, sort.dir == "desc"
	table.sort(list, function(a: Proc, b: Proc): boolean
		local x, y = field(a, col), field(b, col)
		if x == y then
			return a.pid < b.pid
		end
		if desc then
			return x > y
		end
		return x < y
	end)
	return list
end

local function row_id(pid: number): string
	return "p" .. pid
end

local function find_proc(s: Snapshot, id: string?): Proc?
	if not id then
		return nil
	end
	for _, p in s.proc do
		if row_id(p.pid) == id then
			return p
		end
	end
	return nil
end

-- A process's dot: idle, running, or busy (a whole core) and very busy (half the machine).
local function busy_tone(p: Proc, cores: number): string
	if p.cpu <= 0 then
		return "muted"
	end
	local frac = p.cpu / 100
	return if frac >= 0.5 then "error" elseif frac >= 1 / cores then "warning" else "success"
end

-- ---- page parts --------------------------------------------------------------------

local function status_badge(): Node
	local text, tone
	if status == "error" then
		text, tone = "Stopped", "error"
	elseif status == "building" then
		text, tone = "Building", "pending"
	elseif status ~= "running" then
		text, tone = "Starting", "pending"
	elseif stale then
		text, tone = "No sample for " .. (tern.now() - changedAt) // 1000 .. " s", "warning"
	else
		text, tone = "Live", "success"
	end
	return with(ui.badge(text, tone), { key = "status" })
end

local function head(s: Snapshot?): Node
	local spans: { Span } = { ui.span("System Monitor", "title") }
	if s then
		local meta = "   " .. s.os .. " · up " .. duration(s.up)
		if s.counts then
			local c = s.counts :: Counts
			meta ..= " · " .. grouped(c.thread) .. " threads"
			if c.handle then
				meta ..= " · " .. grouped(c.handle) .. " handles"
			elseif c.files then
				meta ..= " · " .. grouped(c.files) .. " open files"
			end
		end
		meta ..= " · sampled " .. (os.date("%H:%M:%S", s.at // 1000) :: string)
		spans[2] = ui.span(meta, "muted")
	end
	local options = {}
	for i, ms in INTERVALS do
		options[i] = { value = tostring(ms), label = string.format("%g s", ms / 1000) }
	end
	return ui.node("row", { key = "head", justify = "between", align = "center", wrap = true, gap = "md" }, {
		ui.node("text", { key = "title", spans = spans }),
		ui.node("row", { key = "controls", gap = "sm", align = "center" }, {
			status_badge(),
			ui.node("select", {
				key = "interval",
				variant = "quiet",
				label = "Every",
				value = tostring(interval),
				options = options,
				title = "How often the collector samples (- and +)",
			}),
			ui.button("Restart", {
				key = "restart",
				icon = "repeat",
				keys = { "r" },
				title = "Restart the collector",
				actions = { click = "restart" },
			}),
			ui.button("", {
				key = "settings",
				icon = "sliders",
				keys = { "," },
				title = "Settings",
				actions = { click = "settings" },
			}),
		}),
	})
end

local function stats(s: Snapshot): Node
	local m = s.mem
	local used = math.max(0, m.total - m.avail)
	local memFrac = if m.total > 0 then used / m.total else 0
	local rx, tx = 0, 0
	for _, n in s.net do
		rx += n.rx
		tx += n.tx
	end
	return with(ui.stats({
		{
			label = "CPU",
			value = pct(s.cpu.total),
			sub = #s.cpu.cores .. " threads",
			tone = alarm(s.cpu.total / 100, 0.6, 0.85),
		},
		{
			label = "Memory",
			value = pct(memFrac * 100),
			sub = human(used) .. " of " .. human(m.total),
			tone = alarm(memFrac, 0.8, 0.92),
		},
		{ label = "Network", value = "↓ " .. rate(rx), sub = "↑ " .. rate(tx) },
		{
			label = "Disk",
			value = rate(s.io.read + s.io.write),
			sub = "read " .. rate(s.io.read) .. " · write " .. rate(s.io.write),
		},
	}), { key = "stats" })
end

-- The collector's failure, in place: what failed, its own message, and Retry.
local function alert(): Node
	local wait = math.max(0, collector.retryAt - tern.now()) // 1000
	local body: { Node } = {
		ui.button("Retry", { key = "end", icon = "repeat", keys = { "r" }, actions = { click = "restart" } }),
		ui.code(problem or "unknown error"),
	}
	if wait > 0 then
		body[#body + 1] = ui.text({ ui.span("Retrying on its own in " .. wait .. " s.", "muted") })
	end
	return ui.card("The collector stopped", body, { key = "alert", icon = "warn", tone = "error", ["end"] = "main.alert.end" })
end

-- ---- overview --------------------------------------------------------------------

local function cpu_card(s: Snapshot): Node
	local cores = s.cpu.cores
	local bars = table.create(#cores)
	for i, use in cores do
		bars[i] = {
			value = round(use, 1),
			label = "C" .. (i - 1),
			title = "C" .. (i - 1) .. " · " .. pct(use),
			tone = alarm(use / 100, 0.6, 0.85),
		}
	end
	local history: { number } = table.create(#hist.cpu)
	for i, v in hist.cpu do
		history[i] = round(v * 100, 1)
	end
	local parts: { Node } = {
		sized("history", { grow = 3, basis = 0, min = { w = "40ch" } }, ui.node("chart", {
			kind = "line",
			unit = "%",
			min = 0,
			max = 100,
			series = history,
			labels = time_labels(#history),
			marks = { { value = 85, tone = "warning", title = "Busy" } },
		})),
	}
	if settings.cores then
		parts[2] = sized("cores", { grow = 2, basis = 0, min = { w = "30ch" } }, ui.node("chart", {
			kind = "bars",
			min = 0,
			max = 100,
			series = bars,
			summary = "per thread",
		}))
	end
	return ui.card("CPU", {
		ui.node("row", { key = "body", gap = "lg", wrap = true, align = "end" }, parts),
	}, { key = "cpu", icon = "cpu", meta = s.cpuName .. " · " .. #cores .. " threads", basis = 1 })
end

local function gpu_card(s: Snapshot): Node?
	local gs = s.gpu
	if not gs or #gs == 0 then
		return nil
	end
	local n = #(gpuHist[1] or {})
	local chart: Node
	if #gs == 1 then
		chart = ui.node("chart", {
			kind = "line",
			unit = "%",
			min = 0,
			max = 100,
			series = divided(gpuHist[1] or {}, 1),
			labels = time_labels(n),
			token = "info",
		})
	else
		local series = {}
		for i, g in gs do
			series[i] = { label = g.name, values = divided(gpuHist[i] or {}, 1) }
		end
		chart = ui.node("chart", { kind = "line", unit = "%", min = 0, max = 100, series = series, labels = time_labels(n) })
	end
	local body: { Node } = { with(chart, { key = "history" }) }
	for i, g in gs do
		local parts: { Node } = {
			ui.node("row", { key = "facts", justify = "between", gap = "md" }, {
				ui.text({ ui.span(g.name, "strong") }),
				ui.text({ ui.span(if g.util >= 0 then pct(g.util) else "—", "mono"), ui.span(" busy", "muted") }),
			}),
		}
		if g.memTotal > 0 then
			parts[2] = ui.node("meter", {
				key = "vram",
				value = g.memUsed / g.memTotal,
				thresholds = { warn = 0.85, bad = 0.95 },
				label = { ui.span(human(g.memUsed), "mono"), ui.span(" of " .. human(g.memTotal), "muted") },
			})
		end
		body[#body + 1] = ui.node("col", { key = "g" .. i, gap = "xs" }, parts)
	end
	return ui.card("GPU", body, {
		key = "gpu",
		icon = "monitor",
		meta = if #gs == 1 then (if gs[1].memTotal > 0 then human(gs[1].memTotal) .. " memory" else nil) else #gs .. " GPUs",
	})
end

local function mem_card(s: Snapshot): Node
	local m = s.mem
	local used = math.max(0, m.total - m.avail)
	-- The donut's legend carries in use and available; the list adds what it can't.
	local items: { { Spans } } = {}
	if m.cache then
		items[#items + 1] = { "Cache", ui.span(human(m.cache :: number), "mono") }
	end
	if m.commit and m.limit then
		items[#items + 1] = {
			"Committed",
			{ ui.span(human(m.commit :: number), "mono"), ui.span(" of " .. human(m.limit :: number), "muted") },
		}
	end
	if m.swapTotal and (m.swapTotal :: number) > 0 then
		items[#items + 1] = {
			"Swap",
			{ ui.span(human(m.swap or 0), "mono"), ui.span(" of " .. human(m.swapTotal :: number), "muted") },
		}
	end
	if m.kpaged and m.knonpaged then
		local paged, nonpaged = m.kpaged :: number, m.knonpaged :: number
		items[#items + 1] = {
			"Kernel",
			{ ui.span(human(paged + nonpaged), "mono"), ui.span("  paged " .. human(paged), "muted") },
		}
	elseif m.kernel then
		items[#items + 1] = { "Kernel", ui.span(human(m.kernel :: number), "mono") }
	end
	if m.wired then
		items[#items + 1] = { "Wired", ui.span(human(m.wired :: number), "mono") }
	end
	local history: { number } = table.create(#hist.mem)
	for i, v in hist.mem do
		history[i] = round(v * m.total / GIB, 2)
	end
	return ui.card("Memory", {
		ui.node("row", { key = "facts", gap = "lg", align = "center", wrap = true }, {
			ui.node("chart", {
				key = "split",
				kind = "donut",
				size = "sm",
				unit = "GiB",
				total = human(m.total),
				series = {
					{ label = "In use", value = round(used / GIB, 1) },
					{ label = "Available", value = round(m.avail / GIB, 1) },
				},
			}),
			with(ui.kv(items), { key = "kv" }),
		}),
		ui.node("chart", {
			key = "history",
			kind = "area",
			size = "sm",
			unit = "GiB",
			min = 0,
			max = round(m.total / GIB, 1),
			series = history,
			labels = time_labels(#history),
		}),
	}, { key = "mem", icon = "layers", meta = pct(used / math.max(1, m.total) * 100) .. " in use" })
end

-- Two byte rates over time in one area chart, in a unit that suits their peak.
local function rate_chart(key: string, a: string, av: { number }, bname: string, bv: { number }, size: string): Node
	local div, unit = rate_unit(peak_of({ av, bv }))
	return ui.node("chart", {
		key = key,
		kind = "area",
		size = size,
		unit = unit,
		labels = time_labels(#av),
		series = {
			{ label = a, values = divided(av, div) },
			{ label = bname, token = "pending", values = divided(bv, div) },
		},
	})
end

local function net_card(s: Snapshot): Node
	-- Busiest interfaces first; idle ones only when nothing moves.
	local list: { Nic } = table.create(#s.net)
	for i, n in s.net do
		list[i] = n -- decoded JSON arrays are read-only: copy before sorting
	end
	table.sort(list, function(a: Nic, b: Nic): boolean
		return a.rx + a.tx > b.rx + b.tx
	end)
	local items: { { Spans } } = {}
	for _, n in list do
		if #items == 3 or (#items > 0 and n.rx + n.tx == 0) then
			break
		end
		items[#items + 1] = {
			n.name,
			-- No-break spaces: a rate wraps as a whole, never between its arrow, number and unit.
			{
				ui.span((string.gsub("↓ " .. rate(n.rx), " ", "\u{A0}")), "mono"),
				ui.span("  "),
				ui.span((string.gsub("↑ " .. rate(n.tx), " ", "\u{A0}")), "mono"),
			},
		}
	end
	local body: { Node } = { rate_chart("history", "Down", hist.rx, "Up", hist.tx, "sm") }
	if #items > 0 then
		body[2] = with(ui.kv(items), { key = "nics" })
	end
	return ui.card("Network", body, { key = "net", icon = "globe", meta = list[1] and list[1].name })
end

local function io_card(s: Snapshot): Node
	return ui.card("Disk I/O", {
		rate_chart("history", "Read", hist.read, "Write", hist.write, "sm"),
	}, { key = "io", icon = "activity", meta = "read " .. rate(s.io.read) .. " · write " .. rate(s.io.write) })
end

local function volumes_card(s: Snapshot): Node
	local body: { Node } = {}
	for i, d in s.disk do
		local usedBytes = math.max(0, d.size - d.free)
		local frac = if d.size > 0 then usedBytes / d.size else 0
		-- The name and what's free over a full-width bar, so long labels never squeeze it.
		body[i] = ui.node("col", { key = "v" .. i, gap = "xs" }, {
			ui.node("row", { key = "facts", justify = "between", gap = "md" }, {
				ui.text({ ui.span(d.name, "strong"), ui.span(if d.label ~= "" then "  " .. d.label else "", "muted") }),
				ui.text({ ui.span(human(d.free), "mono"), ui.span(" free of " .. human(d.size), "muted") }),
			}),
			ui.node("meter", {
				key = "bar",
				value = frac,
				thresholds = { warn = 0.85, bad = 0.95 },
				label = { ui.span(pct(frac * 100), "mono") },
			}),
		})
	end
	if #body == 0 then
		body[1] = ui.node("empty", {
			key = "none",
			variant = "inline",
			icon = "database",
			title = "No local volumes",
			text = "The collector found no fixed disks it can read.",
		})
	end
	return ui.card("Volumes", body, { key = "vol", icon = "database", meta = #s.disk .. " local" })
end

-- ---- processes ---------------------------------------------------------------------

local SORT_NAME: { [string]: string } = {
	pid = "PID",
	name = "name",
	cpu = "CPU",
	mem = "memory",
	io = "I/O",
	thr = "threads",
}

local function detail(p: Proc, s: Snapshot): Node
	local trend = procTrend[p.pid] or {}
	local cores = math.max(1, #s.cpu.cores)
	return ui.card(p.name, {
		ui.button("End process", {
			key = "end",
			size = "sm",
			variant = "danger",
			icon = "x-circle",
			keys = { "x" },
			actions = { click = "end" },
		}),
		with(ui.kv({
			{ "CPU", { ui.span(pct(p.cpu), "mono"), ui.span("  of the machine", "muted") } },
			{ "One core", ui.span(pct(math.min(100, p.cpu * cores)), "mono") },
			{ "Memory", ui.span(human(p.ws), "mono") },
			{ "Private", ui.span(human(p.priv), "mono") },
			{ "Threads", ui.span(tostring(p.threads), "mono") },
			{ "I/O", ui.span(if p.io > 0 then rate(p.io) else "none", "mono") },
		}), { key = "kv" }),
		ui.node("chart", {
			key = "trend",
			kind = "area",
			size = "sm",
			unit = "%",
			min = 0,
			series = divided(trend, 1),
			labels = time_labels(#trend),
			summary = "CPU, % of the machine",
		}),
	}, {
		key = "detail",
		icon = "activity",
		meta = "PID " .. p.pid,
		["end"] = "main.board.procs.body.detail.end",
		min = { w = "40ch" },
		max = { w = "56ch" },
		grow = 1,
		basis = 0,
	})
end

local function processes(s: Snapshot, b: Block): Node
	local all = sorted(s.proc, b.sort)
	local list = all
	if settings.rows > 0 and #all > settings.rows then
		list = table.create(settings.rows)
		for i = 1, settings.rows do
			list[i] = all[i]
		end
	end
	local cores = math.max(1, #s.cpu.cores)
	local trends: { { number } } = {}
	for _, t in procTrend do
		trends[#trends + 1] = t
	end
	local sparkMax = math.max(peak_of(trends), 0.1)
	local rows = table.create(#list)
	for i, p in list do
		rows[i] = {
			id = row_id(p.pid),
			menu = { "End process…", "Copy PID" },
			cells = {
				pid = tostring(p.pid),
				name = { text = p.name, dot = busy_tone(p, cores) },
				cpu = pct(p.cpu),
				trend = { spark = { values = procTrend[p.pid] or {}, min = 0, max = sparkMax } },
				mem = human(p.ws),
				io = if p.io > 0 then rate(p.io) else "—",
				thr = tostring(p.threads),
			},
		}
	end
	local table_node = ui.node("table", {
		key = "table",
		cols = ({
			{ id = "pid", head = "PID", align = "end", mono = true, sortable = true, priority = 2 },
			{ id = "name", head = "Process", grow = 1, truncate = "end", sortable = true, priority = 9 },
			{ id = "cpu", head = "CPU", align = "end", mono = true, sortable = true, priority = 8 },
			{ id = "trend", head = "Trend", priority = 1 },
			{ id = "mem", head = "Memory", align = "end", mono = true, sortable = true, priority = 7 },
			{ id = "io", head = "I/O", align = "end", mono = true, sortable = true, priority = 5 },
			{ id = "thr", head = "Threads", align = "end", mono = true, sortable = true, priority = 3 },
		} :: { Col }),
		rows = rows,
		selectable = true,
		selected = b.selected,
		sort = b.sort,
		empty = "No processes",
	})
	local quick = {}
	for i, col in SORT_CYCLE do
		quick[i] = { id = col, label = if col == "mem" then "Memory" elseif col == "io" then "I/O" else "CPU" }
	end
	local toolbar = ui.node("row", { key = "bar", justify = "between", align = "center", gap = "md" }, {
		ui.text({
			ui.span("Processes", "strong"),
			ui.span(
				"   " .. (if #list < #all then "top " .. #list .. " of " else "") .. #all .. " by " .. SORT_NAME[b.sort.col]
					.. (if b.sort.dir == "desc" then " ↓" else " ↑"),
				"muted"
			),
		}),
		ui.node("tabs", {
			key = "sort",
			variant = "segmented",
			active = if b.sort.dir == "desc" and table.find(SORT_CYCLE, b.sort.col) then b.sort.col else nil,
			items = quick,
		}),
	})
	local body: { Node } = {
		ui.node("col", { key = "list", grow = 2, basis = 0, min = { w = "50ch" } }, { table_node }),
	}
	local p = find_proc(s, b.selected)
	if p then
		body[2] = detail(p, s)
	end
	return ui.node("col", { key = "procs", gap = "sm", basis = 1 }, {
		toolbar,
		ui.node("row", { key = "body", gap = "lg", align = "start", wrap = true }, body),
	})
end

-- ---- the dashboard and its settings -------------------------------------------------

-- Every panel on one page, as btop draws it; settings hide the ones you don't want.
local function dashboard(s: Snapshot, b: Block): Node
	local function tile(card: Node): Node
		return with(card, { grow = 1, basis = 0, min = { w = "44ch" } })
	end
	local panels: { Node } = {}
	-- CPU and GPU share the top row, which nothing else joins.
	local top: { Node } = {}
	if settings.cpu then
		top[1] = with(cpu_card(s), { basis = 0, grow = 2, min = { w = "60ch" } })
	end
	local gpu = if settings.gpu then gpu_card(s) else nil
	if gpu then
		top[#top + 1] = with(gpu, { basis = 0, grow = 1, min = { w = "40ch" } })
	end
	if #top > 0 then
		panels[1] = ui.node("row", { key = "top", basis = 1, gap = "md", wrap = true, align = "stretch" }, top)
	end
	if settings.mem then
		panels[#panels + 1] = tile(mem_card(s))
	end
	if settings.net then
		panels[#panels + 1] = tile(net_card(s))
	end
	if settings.io then
		panels[#panels + 1] = tile(io_card(s))
	end
	if settings.vol then
		panels[#panels + 1] = tile(volumes_card(s))
	end
	if settings.procs then
		panels[#panels + 1] = processes(s, b)
	end
	if #panels == 0 then
		panels[1] = ui.node("empty", {
			key = "none",
			icon = "eye-off",
			title = "Every panel is hidden",
			text = "Turn some back on in Settings.",
			grow = 1,
		}, {
			ui.button("Settings", { key = "open", icon = "sliders", keys = { "," }, actions = { click = "settings" } }),
		})
	end
	return ui.node("row", { key = "board", gap = "md", wrap = true, align = "stretch" }, panels)
end

local function choice(key: string, value: number, options: { { any } }): Node
	local opts = {}
	for i, o in options do
		opts[i] = { value = tostring(o[1]), label = o[2] }
	end
	return ui.node("select", { key = key, value = tostring(value), options = opts, size = "sm" })
end

local function setting_switch(key: string, label: string, hint: string?): Node
	return ui.node("switch", { key = key, label = label, hint = hint, on = settings[key] == true })
end

-- The settings sheet, docked to the right; every change applies at once and is kept.
local function settings_sheet(): Node
	local intervals: { { any } } = {}
	for i, ms in INTERVALS do
		intervals[i] = { ms, string.format("%g s", ms / 1000) }
	end
	return ui.node("overlay", {
		key = "settings",
		side = "right",
		size = "sm",
		head = "Settings",
		icon = "sliders",
		meta = "System Monitor",
		["end"] = "layer.settings.end",
		foot = "layer.settings.foot",
	}, {
		ui.button("", { key = "end", icon = "x", variant = "quiet", title = "Close", keys = { "esc" }, actions = { click = "close" } }),
		ui.node("col", { key = "sampling" }, {
			ui.node("field", { key = "f-interval", variant = "row", label = "Sample every", hint = "Also - and +" }, {
				choice("interval", interval, intervals),
			}),
			ui.node("field", { key = "f-history", variant = "row", label = "History", hint = "How far back the charts reach" }, {
				choice("history", settings.history, HISTORY_OPTIONS),
			}),
			ui.node("field", { key = "f-rows", variant = "row", label = "Process rows", hint = "Rows the process table lists" }, {
				choice("rows", settings.rows, ROW_OPTIONS),
			}),
		}),
		ui.rule("Panels"),
		ui.node("col", { key = "panels" }, {
			setting_switch("stats", "Headline numbers", "CPU, memory, network and disk at the top"),
			setting_switch("cpu", "CPU"),
			setting_switch("cores", "Per-thread bars", "Beside the CPU history"),
			setting_switch("gpu", "GPU", "Busy share and dedicated memory per GPU"),
			setting_switch("mem", "Memory"),
			setting_switch("net", "Network"),
			setting_switch("io", "Disk I/O"),
			setting_switch("vol", "Volumes"),
			setting_switch("procs", "Processes"),
		}),
		ui.node("row", { key = "foot", justify = "between", gap = "sm" }, {
			ui.button("Reset to defaults", { key = "reset", variant = "quiet", actions = { click = "reset" } }),
			ui.button("Done", { key = "done", variant = "primary", keys = { "esc" }, actions = { click = "close" } }),
		}),
	})
end


-- ---- loading and the dock ------------------------------------------------------------

local function loading(): Node
	local parts: { Node } = {}
	if status == "building" then
		parts[1] = ui.node("shimmer", { key = "work", text = "Compiling the collector (first run only)…" })
	end
	parts[#parts + 1] = ui.node("skeleton", { key = "stats", shape = "card", tiles = 4 })
	parts[#parts + 1] = ui.node("skeleton", { key = "chart", shape = "block", min = { h = "8lines" } })
	parts[#parts + 1] = ui.node("skeleton", { key = "rows", shape = "rows", rows = 6 })
	return ui.node("col", { key = "view", gap = "lg" }, parts)
end

local function confirm_strip(c: Confirm): Node
	return ui.card("End " .. c.name .. " (PID " .. c.pid .. ")?", {
		ui.node("row", { key = "end", gap = "sm" }, {
			ui.button("Cancel", { key = "cancel", variant = "quiet", keys = { "esc" }, actions = { click = "cancel" } }),
			ui.button("End process", {
				key = "go",
				variant = "danger",
				keys = { "enter" },
				busy = c.busy,
				actions = { click = "confirm-end" },
			}),
		}),
		ui.text({ ui.span("It stops at once, without a chance to save its work.", "muted") }),
	}, { key = "confirm", tone = "error", icon = "warn", ["end"] = "dock.confirm.end" })
end

local function dock(b: Block): Node
	local entries: { { any } } = {}
	local function add(keys: { string }, label: string)
		entries[#entries + 1] = { keys, label }
	end
	if settings.procs then
		add({ "↑", "↓" }, "select")
		add({ "x" }, "end process")
		add({ "s" }, "sort")
	end
	add({ "-", "+" }, "interval")
	add({ "," }, "settings")
	add({ "r" }, "restart")
	add({ "q" }, "close")
	local parts: { Node } = {}
	if b.confirm then
		parts[1] = confirm_strip(b.confirm :: Confirm)
	end
	parts[#parts + 1] = legend(entries)
	return ui.col(parts)
end

-- ---- actions -------------------------------------------------------------------------------

local function restart()
	collector.failures = 0
	collector.retryAt = 0
	if collector.running then
		collector.token = nil -- the old one exits when the new owner lands
		collector.running = false
	end
	kick()
end

local function ask_end(b: Block, pid: number?)
	local s = snap
	if not s then
		return
	end
	local p = find_proc(s, if pid then row_id(pid) else b.selected)
	if p then
		b.selected = row_id(p.pid)
		b.confirm = { pid = p.pid, name = p.name, busy = false }
	end
end

local function end_process(b: Block)
	local c = b.confirm
	if not c or c.busy then
		return
	end
	c.busy = true
	local pid = tostring(c.pid)
	local argv = if WINDOWS then { "taskkill", "/PID", pid, "/F" } else { "kill", "-TERM", pid }
	local ok, err = pcall(function()
		tern.process.run(argv, { timeout_ms = 10000 }, function(result: ProcessResult)
			b.confirm = nil
			if result.status ~= 0 then
				b.cx:toast("error", "Couldn't end " .. c.name, first_lines(result.stderr .. "\n" .. result.stdout, 2))
			end
			b.cx:render()
		end)
	end)
	if not ok then
		b.confirm = nil
		b.cx:toast("error", "Couldn't end " .. c.name, tostring(err))
	end
end

local function move_selection(b: Block, step: number)
	local s = snap
	if not s then
		return
	end
	local list = sorted(s.proc, b.sort)
	if #list == 0 then
		return
	end
	local at = 0
	for i, p in list do
		if row_id(p.pid) == b.selected then
			at = i
			break
		end
	end
	local nextAt = if at == 0 then (if step > 0 then 1 else #list) else math.clamp(at + step, 1, #list)
	b.selected = row_id(list[nextAt].pid)
end

local function step_interval(step: number)
	local at = table.find(INTERVALS, interval) or 2
	set_interval(INTERVALS[math.clamp(at + step, 1, #INTERVALS)])
	render_all()
end

-- ---- the block -----------------------------------------------------------------------------

local function saved_sort(saved: any): Sort
	if type(saved) == "table" and type(saved.sort) == "table" and SORT_COLS[saved.sort.col] then
		return { col = saved.sort.col, dir = if saved.sort.dir == "asc" then "asc" else "desc" }
	elseif type(saved) == "table" and type(saved.sort) == "string" and table.find(SORT_CYCLE, saved.sort) then
		return { col = saved.sort, dir = "desc" } -- saved by 0.2
	end
	return { col = "cpu", dir = "desc" }
end

local monitor: BlockDef<Block> = {
	font = "sans",

	init = function(cx, _args, saved)
		pcall(tern.fs.mkdir, data)
		local b: Block = { cx = cx, sort = saved_sort(saved), selected = nil, confirm = nil, settingsOpen = false }
		blocks[cx.pane] = b
		kick()
		return b
	end,

	-- No host name, here or anywhere: screenshots of the monitor stay anonymous.
	title = function(_b)
		return "System Monitor"
	end,

	view = function(b, _cx)
		local s = snap
		local main: { Node } = { head(s) }
		if s and settings.stats then
			main[#main + 1] = stats(s)
		end
		if status == "error" then
			main[#main + 1] = alert()
		end
		if s then
			main[#main + 1] = dashboard(s, b)
		elseif status ~= "error" then
			main[#main + 1] = loading()
		end
		local view: BlockView = { main = ui.col(main), dock = dock(b) }
		if b.settingsOpen then
			view.layer = ui.col({ settings_sheet() })
		end
		return view
	end,

	key = function(b, key, cx)
		local name, text = key.name, key.text
		if b.confirm then
			if name == "escape" then
				b.confirm = nil
				return true
			elseif name == "enter" then
				end_process(b)
				return true
			end
		end
		if b.settingsOpen and (name == "escape" or name == ",") then
			b.settingsOpen = false
		elseif name == "," then
			b.settingsOpen = true
		elseif name == "+" or name == "=" or text == "+" then
			step_interval(1)
		elseif name == "-" or name == "_" then
			step_interval(-1)
		elseif name == "r" then
			restart()
		elseif name == "q" then
			blocks[cx.pane] = nil
			cx:exit(0)
		elseif settings.procs and (name == "down" or name == "j") then
			move_selection(b, 1)
		elseif settings.procs and (name == "up" or name == "k") then
			move_selection(b, -1)
		elseif settings.procs and (name == "x" or name == "delete") then
			ask_end(b, nil)
		elseif settings.procs and name == "s" then
			local at = if b.sort.dir == "desc" then table.find(SORT_CYCLE, b.sort.col) or 0 else 0
			b.sort = { col = SORT_CYCLE[at % #SORT_CYCLE + 1], dir = "desc" }
		else
			return false
		end
		return true
	end,

	event = function(b, ev, cx)
		local id = ev.id or ""
		local last = string.match(id, "([^.]+)$") or ""
		if ev.ev == "select" and last == "sort" then
			if table.find(SORT_CYCLE, ev.item) then
				b.sort = { col = ev.item, dir = "desc" }
			end
		elseif ev.ev == "select" or ev.ev == "activate" then
			if type(ev.item) == "string" and string.sub(ev.item, 1, 1) == "p" then
				b.selected = ev.item
			end
		elseif ev.ev == "change" and last == "interval" then
			local ms = tonumber(ev.value)
			if ms then
				set_interval(ms)
				render_all()
			end
		elseif ev.ev == "change" and (last == "history" or last == "rows") then
			local n = tonumber(ev.value)
			if n then
				settings[last] = n
				save_settings()
			end
		elseif ev.ev == "change" and type(ev.value) == "boolean" and type(DEFAULTS[last]) == "boolean" then
			settings[last] = ev.value
			save_settings()
		elseif ev.ev == "action" then
			local act = ev.act
			if act == "sort" and type(ev.value) == "table" and SORT_COLS[ev.value.col] then
				b.sort = { col = ev.value.col, dir = if ev.value.dir == "desc" then "desc" else "asc" }
			elseif act == "restart" then
				restart()
			elseif act == "settings" then
				b.settingsOpen = true
			elseif act == "close" then
				b.settingsOpen = false
			elseif act == "reset" then
				settings = table.clone(DEFAULTS)
				save_settings()
			elseif act == "end" then
				ask_end(b, nil)
			elseif act == "End process…" then
				ask_end(b, tonumber(string.sub(tostring(ev.item), 2)))
			elseif act == "Copy PID" then
				cx:copy(string.sub(tostring(ev.item), 2))
			elseif act == "cancel" then
				b.confirm = nil
			elseif act == "confirm-end" then
				end_process(b)
			end
		end
	end,

	save = function(b)
		return { sort = b.sort }
	end,
}

tern.block.define("monitor", monitor)
