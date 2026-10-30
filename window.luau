--!strict
-- window.luau — open the monitor, or focus the one this window already shows.

local KIND = "sysmon.monitor"
local TITLE = "System Monitor"

local function open_monitor(cx: WindowCx)
	for _, pane in cx.session:panes() do
		if string.sub(pane.title, 1, #TITLE) == TITLE then
			cx.layout:focus(pane.pane)
			return
		end
	end
	if cx:new_block(KIND, nil, "beside") == nil then
		cx:toast("error", "System Monitor is not loaded on this host", "Install the plugin where your panes run.")
	end
end

tern.command({
	id = "open",
	title = "Open system monitor",
	icon = "gauge",
	run = open_monitor,
})

tern.bind("alt+shift+m", "plugin.sysmon.open")
