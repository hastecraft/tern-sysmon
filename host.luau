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
local MIN_MS = 1000
local MAX_MS = 10000
local DEFAULT_MS = 2000
local HISTORY = 160 -- samples kept: exactly what a graph draws (GRAPH_W)
local BEAT_MS = 2000
local BUILD_TIMEOUT_MS = 120000
local MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
local SORTS = { "cpu", "mem", "io" }
local SORT_LABEL: { [string]: string } = { cpu = "CPU", mem = "Memory", io = "I/O" }
local NBSP = "\u{A0}"
local EIGHTHS = { "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█" }

type Proc = { pid: number, name: string, cpu: number, ws: number, priv: number, threads: number, io: number }
type Volume = { name: string, label: string, size: number, free: number }
type Nic = { name: string, rx: number, tx: number }
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
	proc: { Proc },
}
type Block = { cx: BlockCx, sort: string }

-- Blocks are not told their pane size in this Tern build (cx.cols/rows stay
-- 80×24 and `resize` never fires), so the layout is all CSS: cards wrap with
-- the pane, and graphs draw GRAPH_W columns anchored right, so a narrow pane
-- clips the oldest samples, never the newest.
local GRAPH_W = 160
local PROC_ROWS = 25

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

local interval: number = math.clamp(tonumber(kv_get("interval")) or DEFAULT_MS, MIN_MS, MAX_MS)
local snap: Snapshot? = nil
local lastAt = -1
local changedAt = 0
local stale = false
local hist = { cpu = {} :: { number }, mem = {} :: { number }, rx = {} :: { number }, tx = {} :: { number } }
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

-- The tone of a fraction against its warn and bad levels.
local function level(frac: number, warn: number, bad: number): string
	return if frac >= bad then "error" elseif frac >= warn then "warning" else "success"
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
		return { "cc", "-O2", "-o", exe, src }
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

local function push(list: { number }, v: number)
	table.insert(list, v)
	if #list > HISTORY then
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
	interval = math.clamp(ms, MIN_MS, MAX_MS)
	pcall(tern.kv.set, "interval", interval)
	beat()
end

-- ---- view pieces ----------------------------------------------------------------

-- A block graph of `values` (fractions 0–1, newest last): GRAPH_W columns by
-- `height` rows, newest at the right. Each column takes the tone `tone_of`
-- gives its value, as a meter colors its bar; runs of one tone share a span.
local function graph(key: string, values: { number }, height: number, tone_of: (number) -> string): Node
	local rows: { Node } = table.create(height)
	local n = #values
	for r = 1, height do
		local base = (height - r) * 8
		local runs: { Node } = {}
		local run: { string } = {}
		local runTone = ""
		local function flush()
			if #run > 0 then
				runs[#runs + 1] = ui.el("span", { class = runTone, key = #runs + 1, text = table.concat(run) })
				run = {}
			end
		end
		for c = 1, GRAPH_W do
			local v = values[n - GRAPH_W + c]
			local ch, tone = NBSP, ""
			if v then
				local fill = math.floor(math.clamp(v, 0, 1) * height * 8 + 0.5) - base
				if fill >= 8 then
					ch = EIGHTHS[8]
				elseif fill >= 1 then
					ch = EIGHTHS[fill]
				elseif r == height and v > 0 then
					ch = EIGHTHS[1] -- any activity shows
				end
				if ch ~= NBSP then
					tone = tone_of(v)
				end
			end
			if tone ~= runTone then
				flush()
				runTone = tone
			end
			run[#run + 1] = ch
		end
		flush()
		rows[r] = ui.el("div", { class = "sm-gl", key = r }, runs)
	end
	return ui.el("div", { class = "sm-graph", key = key }, rows)
end

-- Green, amber past `warn`, red past `bad`: the thresholds the matching meters use.
local function levels(warn: number, bad: number): (number) -> string
	return function(v: number): string
		return if v >= bad then "bad" elseif v >= warn then "warn" else "ok"
	end
end

local function flat(tone: string): (number) -> string
	return function(_v: number): string
		return tone
	end
end

-- The last GRAPH_W values scaled to their own peak; the peak too.
local function scaled(values: { number }): ({ number }, number)
	local width = GRAPH_W
	local n = #values
	local peak = 0
	for i = math.max(1, n - width + 1), n do
		peak = math.max(peak, values[i])
	end
	local scale = math.max(peak, 1024)
	local out: { number } = table.create(math.min(n, width))
	for i = math.max(1, n - width + 1), n do
		table.insert(out, values[i] / scale)
	end
	return out, peak
end

local function kbd(key: string): Node
	return ui.node("kbd", { keys = { key } })
end


local function header(s: Snapshot): Node
	local left: { any } = {
		ui.span(s.os, "strong"),
		ui.span("   up ", "muted"),
		ui.span(duration(s.up), "num"),
	}
	if s.counts then
		local c = s.counts :: Counts
		table.insert(left, ui.span("   " .. grouped(c.proc), "num"))
		table.insert(left, ui.span(" processes  ", "muted"))
		table.insert(left, ui.span(grouped(c.thread), "num"))
		table.insert(left, ui.span(" threads", "muted"))
		local handles, label = c.handle or c.files, if c.handle then " handles" else " open files"
		if handles then
			table.insert(left, ui.span("  " .. grouped(handles), "num"))
			table.insert(left, ui.span(label, "muted"))
		end
	end
	local right = if stale
		then ui.text({ ui.span("no new sample for " .. (tern.now() - changedAt) // 1000 .. "s", "warning") })
		else ui.text({ ui.span("sampled ", "muted"), ui.span(os.date("%H:%M:%S", s.at // 1000) :: string, "num") })
	-- The facts wrap onto a second line in a narrow pane; the sample time never splits.
	return with(ui.row({ with(ui.text(left), { grow = 1 }), with(right, { wrap = "none" }) }), {
		justify = "between",
		key = "header",
	})
end

local function core_cell(i: number, use: number): Node
	return ui.el("div", { class = "sm-core", key = "c" .. i }, {
		with(ui.text({ ui.span("C" .. (i - 1), "muted") }), { wrap = "none" }),
		ui.node("meter", {
			value = use / 100,
			thresholds = { warn = 0.6, bad = 0.85 },
			label = { ui.span(pct(use), "num") },
		}),
	})
end

local function cpu_card(s: Snapshot): Node
	local total = s.cpu.total
	local cores: { Node } = table.create(#s.cpu.cores)
	for i, use in s.cpu.cores do
		cores[i] = core_cell(i, use)
	end
	local head = {
		ui.span("CPU", "strong"),
		ui.span("  " .. pct(total), "num strong " .. level(total / 100, 0.6, 0.85)),
		ui.span("   " .. s.cpuName .. " · " .. #s.cpu.cores .. " threads", "muted"),
	}
	local kcols = if #s.cpu.cores > 16 then 4 else 2
	local height = math.clamp(math.ceil(#s.cpu.cores / kcols), 4, 10)
	local body = ui.el("div", { class = "sm-cpu" }, {
		graph("hist", hist.cpu, height, levels(0.6, 0.85)),
		ui.el("div", { class = "sm-cores k" .. kcols, key = "cores" }, cores),
	})
	return with(ui.card(head, { body }), { key = "cpu", role = "sysmon.wide" })
end

local function mem_card(s: Snapshot): Node
	local m = s.mem
	local used = math.max(0, m.total - m.avail)
	local frac = if m.total > 0 then used / m.total else 0
	local items: { { Spans } } = {
		{ "In use", { ui.span(human(used), "num strong"), ui.span(" / " .. human(m.total), "muted") } },
		{ "Available", ui.span(human(m.avail), "num") },
	}
	if m.cache then
		items[#items + 1] = { "Cache", ui.span(human(m.cache :: number), "num") }
	end
	if m.commit and m.limit then
		items[#items + 1] = {
			"Committed",
			{ ui.span(human(m.commit :: number), "num"), ui.span(" / " .. human(m.limit :: number), "muted") },
		}
	end
	if m.swapTotal and (m.swapTotal :: number) > 0 then
		items[#items + 1] = {
			"Swap",
			{ ui.span(human(m.swap or 0), "num"), ui.span(" / " .. human(m.swapTotal :: number), "muted") },
		}
	end
	if m.kpaged and m.knonpaged then
		local paged, nonpaged = m.kpaged :: number, m.knonpaged :: number
		items[#items + 1] = {
			"Kernel",
			{ ui.span(human(paged + nonpaged), "num"), ui.span("  paged " .. human(paged), "muted") },
		}
	elseif m.kernel then
		items[#items + 1] = { "Kernel", ui.span(human(m.kernel :: number), "num") }
	end
	if m.wired then
		items[#items + 1] = { "Wired", ui.span(human(m.wired :: number), "num") }
	end
	local head = {
		ui.span("Memory", "strong"),
		ui.span("  " .. pct(frac * 100), "num strong " .. level(frac, 0.8, 0.92)),
	}
	return with(ui.card(head, {
		ui.node("meter", {
			value = frac,
			size = "md",
			thresholds = { warn = 0.8, bad = 0.92 },
			label = { ui.span(human(used), "num") },
			total = "of " .. human(m.total),
		}),
		ui.kv(items),
		graph("hist", hist.mem, 3, levels(0.8, 0.92)),
	}), { key = "mem", role = "sysmon.card" })
end

local function disk_card(s: Snapshot): Node
	local rows: { { Cell } } = {}
	for _, d in s.disk do
		local usedBytes = math.max(0, d.size - d.free)
		local frac = if d.size > 0 then usedBytes / d.size else 0
		rows[#rows + 1] = {
			{ ui.span(d.name, "strong"), ui.span(if d.label ~= "" then "  " .. d.label else "", "muted") },
			ui.span(human(usedBytes), "num"),
			ui.span(human(d.free), "num"),
			ui.meter_cell(frac, { 0.85, 0.95 }),
		}
	end
	local body: { Node } = {
		ui.table({
			{ id = "name", head = "Volume", grow = 1, truncate = "end" },
			{ id = "used", head = "Used", align = "end", priority = 1 },
			{ id = "free", head = "Free", align = "end", priority = 2 },
			{ id = "fill", head = "Fill", grow = 1, priority = 3 },
		}, rows),
		ui.text({
			ui.span("I/O  ", "muted"),
			ui.span("read ", "muted"),
			ui.span(rate(s.io.read), "num"),
			ui.span("   write ", "muted"),
			ui.span(rate(s.io.write), "num"),
		}),
	}
	return with(ui.card(ui.span("Volumes", "strong"), body), { key = "disk", role = "sysmon.card" })
end

local function net_card(s: Snapshot): Node
	local rx, tx = 0, 0
	local active: { Nic } = {}
	for _, n in s.net do
		rx += n.rx
		tx += n.tx
		if n.rx + n.tx > 0 then
			table.insert(active, n)
		end
	end
	table.sort(active, function(a, b)
		return a.rx + a.tx > b.rx + b.tx
	end)
	local down, downPeak = scaled(hist.rx)
	local up, upPeak = scaled(hist.tx)
	local head = { ui.span("Network", "strong") }
	if active[1] then
		table.insert(head, ui.span("  " .. active[1].name, "muted"))
	end
	local body: { Node } = {
		with(ui.row({
			ui.text({ ui.span("↓ ", "info"), ui.span(rate(rx), "num strong") }),
			ui.text({ ui.span("peak " .. rate(downPeak), "muted") }),
		}), { justify = "between" }),
		graph("down", down, 3, flat("info")),
		with(ui.row({
			ui.text({ ui.span("↑ ", "accent"), ui.span(rate(tx), "num strong") }),
			ui.text({ ui.span("peak " .. rate(upPeak), "muted") }),
		}), { justify = "between" }),
		graph("up", up, 3, flat("acc")),
	}
	if #active > 1 then
		local rows: { { Cell } } = {}
		for i, n in active do
			if i > 4 then
				break
			end
			rows[#rows + 1] = { n.name, ui.span(rate(n.rx), "num"), ui.span(rate(n.tx), "num") }
		end
		table.insert(body, ui.table({
			{ id = "name", head = "Interface", grow = 1, truncate = "middle" },
			{ id = "down", head = "↓ Down", align = "end", priority = 1 },
			{ id = "up", head = "↑ Up", align = "end", priority = 1 },
		}, rows))
	end
	return with(ui.card(head, body), { key = "net", role = "sysmon.card" })
end

local function sort_value(sort: string): (Proc) -> number
	if sort == "mem" then
		return function(p)
			return p.ws
		end
	elseif sort == "io" then
		return function(p)
			return p.io
		end
	end
	return function(p)
		return p.cpu
	end
end

local function proc_card(s: Snapshot, b: Block): Node
	local procs = s.proc
	local value = sort_value(b.sort)
	table.sort(procs, function(x, y)
		local a, c = value(x), value(y)
		if a == c then
			return x.ws > y.ws
		end
		return a > c
	end)
	local top = if procs[1] then math.max(value(procs[1]), 1e-9) else 1
	local cores = math.max(1, #s.cpu.cores)
	local rows: { { Cell } } = {}
	for i, p in procs do
		if i > PROC_ROWS then
			break
		end
		rows[#rows + 1] = {
			ui.span(tostring(p.pid), "muted"),
			ui.span(p.name, if i <= 3 then "strong" else ""),
			ui.span(pct(p.cpu), "num " .. level(p.cpu / 100, 1 / cores, 0.5)),
			ui.meter_cell(value(p) / top),
			ui.span(human(p.ws), "num"),
			ui.span(if p.io > 0 then rate(p.io) else "—", if p.io > 0 then "num" else "muted"),
			ui.span(tostring(p.threads), "muted"),
		}
	end

	local tabs: { Node } = {}
	for _, k in SORTS do
		table.insert(tabs, with(ui.badge(SORT_LABEL[k], if k == b.sort then "accent" else "neutral"), {
			key = "sort-" .. k,
			actions = { click = "sort=" .. k },
		}))
	end
	table.insert(tabs, ui.text({ ui.span("  ", ""), ui.span("s", "key"), ui.span(" cycles the order", "muted") }))

	local function head(id: string, label: string): string
		return if id == b.sort then label .. " ▾" else label
	end
	local head_spans = {
		ui.span("Processes", "strong"),
		ui.span("  top " .. #rows .. " of " .. #procs .. " by " .. string.lower(SORT_LABEL[b.sort]), "muted"),
	}
	return with(ui.card(head_spans, {
		ui.row(tabs),
		ui.table({
			{ id = "pid", head = "PID", align = "end", priority = 2 },
			{ id = "name", head = "Process", grow = 1, truncate = "end", priority = 9 },
			{ id = "cpu", head = head("cpu", "CPU"), align = "end", priority = 8 },
			{ id = "bar", head = "", grow = 1, priority = 3 },
			{ id = "mem", head = head("mem", "Memory"), align = "end", priority = 7 },
			{ id = "io", head = head("io", "I/O"), align = "end", priority = 5 },
			{ id = "thr", head = "Threads", align = "end", priority = 1 },
		}, rows),
	}), { key = "proc", role = "sysmon.wide" })
end

local function waiting(text: string): Node
	return ui.card(ui.span("System Monitor", "strong"), {
		ui.node("spinner", { style = "dots", label = { ui.span(text, "muted") } }),
	})
end

local function problem_card(): Node
	local wait = math.max(0, collector.retryAt - tern.now()) // 1000
	local retry: { any } = { ui.span("r", "key"), ui.span(" retries now", "muted") }
	if wait > 0 then
		table.insert(retry, 1, ui.span("retrying in " .. wait .. "s · ", "muted"))
	end
	return with(ui.card({ ui.span("Collector", "strong"), ui.span("  stopped", "error") }, {
		ui.text({ ui.span(problem or "unknown error", "error") }),
		ui.text(retry),
	}), { tone = "error", key = "problem" })
end

-- A region's root is not drawn, only its children: the row needs a root around it.
local function dock(): Node
	return ui.col({ ui.row({
		ui.text({ ui.span("every ", "muted"), ui.span(string.format("%gs", interval / 1000), "num") }),
		kbd("-"),
		kbd("+"),
		ui.text({ ui.span("interval  ", "muted") }),
		kbd("s"),
		ui.text({ ui.span("sort  ", "muted") }),
		kbd("r"),
		ui.text({ ui.span("restart collector  ", "muted") }),
		kbd("q"),
		ui.text({ ui.span("close", "muted") }),
	}) })
end

-- ---- the block ----------------------------------------------------------------

local function restart()
	collector.failures = 0
	collector.retryAt = 0
	if collector.running then
		collector.token = nil -- the old one exits when the new owner lands
		collector.running = false
	end
	kick()
end

local monitor: BlockDef<Block> = {
	init = function(cx, _args, saved)
		pcall(tern.fs.mkdir, data)
		local sort = if type(saved) == "table" and SORT_LABEL[saved.sort] then saved.sort else "cpu"
		local b: Block = { cx = cx, sort = sort }
		blocks[cx.pane] = b
		kick()
		return b
	end,

	-- No host name, here or anywhere: screenshots of the monitor stay anonymous.
	title = function(_b)
		return "System Monitor"
	end,

	view = function(b, cx)
		local s = snap
		if not s then
			local main = if status == "error"
				then problem_card()
				elseif status == "building" then waiting("Compiling the collector (first run only)…")
				else waiting("Starting the collector…")
			return { main = with(ui.col({ main }), { role = "sysmon.main" }), dock = dock() }
		end
		local cards: { Node } = {
			cpu_card(s),
			mem_card(s),
			net_card(s),
			disk_card(s),
			proc_card(s, b),
		}
		local main: { Node } = { header(s) }
		if status == "error" then
			table.insert(main, problem_card())
		end
		table.insert(main, ui.el("div", { class = "sm-grid", key = "grid" }, cards))
		return { main = with(ui.col(main), { role = "sysmon.main" }), dock = dock() }
	end,

	key = function(b, key, cx)
		local name, text = key.name, key.text
		if name == "s" or name == "tab" then
			local i = table.find(SORTS, b.sort) or 1
			b.sort = SORTS[i % #SORTS + 1]
			return true
		elseif name == "+" or name == "=" or text == "+" then
			set_interval(interval + 1000)
			render_all()
			return true
		elseif name == "-" or name == "_" then
			set_interval(interval - 1000)
			render_all()
			return true
		elseif name == "r" then
			restart()
			return true
		elseif name == "q" then
			blocks[cx.pane] = nil
			cx:exit(0)
			return true
		end
		return false
	end,

	event = function(b, ev, _cx)
		if ev.ev ~= "action" then
			return
		end
		if ev.act == "sort" and SORT_LABEL[ev.value] then
			b.sort = ev.value
		end
	end,

	save = function(b)
		return { sort = b.sort }
	end,
}

tern.block.define("monitor", monitor)
