package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rivo/tview"
)

type PacketRow struct {
	Time   string
	Src    string
	Dst    string
	Proto  string
	Length int
	Info   string
}

type Sniffer struct {
	ifaceName  string
	handle     *pcap.Handle
	filter     string
	running    bool
	pause      bool
	mu         sync.RWMutex
	stopCh     chan struct{}
	packetChan chan gopacket.Packet
}

func NewSniffer() *Sniffer {
	return &Sniffer{
		stopCh:     make(chan struct{}),
		packetChan: make(chan gopacket.Packet, 1000),
	}
}

func (s *Sniffer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return fmt.Errorf("already running")
	}
	if s.ifaceName == "" {
		return fmt.Errorf("no interface selected")
	}

	// Open live capture
	handle, err := pcap.OpenLive(s.ifaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open live: %w", err)
	}
	if s.filter != "" {
		if err := handle.SetBPFFilter(s.filter); err != nil {
			handle.Close()
			return fmt.Errorf("bpf filter error: %w", err)
		}
	}
	s.handle = handle
	s.running = true
	s.pause = false

	go func() {
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			select {
			case <-s.stopCh:
				return
			case pkt, ok := <-src.Packets():
				if !ok {
					return
				}
				s.mu.RLock()
				paused := s.pause
				s.mu.RUnlock()
				if paused {
					continue
				}
				s.packetChan <- pkt
			}
		}
	}()

	return nil
}

func (s *Sniffer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	close(s.stopCh)
	if s.handle != nil {
		s.handle.Close()
	}
	s.handle = nil
	s.running = false
	s.stopCh = make(chan struct{})
}

func (s *Sniffer) TogglePause() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	s.pause = !s.pause
}

func (s *Sniffer) SetFilter(f string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.filter = strings.TrimSpace(f)
}

func (s *Sniffer) SetIface(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ifaceName = name
}

// UI application
type AppUI struct {
	app         *tview.Application
	devices     []pcap.Interface
	deviceList  *tview.List
	table       *tview.Table
	status      *tview.TextView
	help        *tview.TextView
	filterField *tview.InputField
	pages       *tview.Pages
	sniffer     *Sniffer
	rowLimit    int
	rowCount    int
	startedAt   time.Time
}

func NewAppUI() *AppUI {
	a := &AppUI{
		app:      tview.NewApplication(),
		sniffer:  NewSniffer(),
		rowLimit: 500,
	}
	return a
}

func (ui *AppUI) loadDevices() error {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}
	ui.devices = devs
	return nil
}

func ifaceDisplayName(d pcap.Interface) string {
	var ips []string
	for _, a := range d.Addresses {
		if a.IP.To4() != nil {
			ips = append(ips, a.IP.String())
		}
	}
	ipStr := strings.Join(ips, ",")
	if ipStr != "" {
		return fmt.Sprintf("%s (%s)  [%s]", d.Name, d.Description, ipStr)
	}
	return fmt.Sprintf("%s (%s)", d.Name, d.Description)
}

func (ui *AppUI) buildDeviceList() *tview.List {
	list := tview.NewList().ShowSecondaryText(false)
	list.SetBorder(true).SetTitle(" Select an interface ")
	for i, d := range ui.devices {
		idx := i
		list.AddItem(ifaceDisplayName(d), "", rune('a'+i), func() {
			ui.sniffer.SetIface(ui.devices[idx].Name)
			ui.pages.SwitchToPage("capture")
			ui.updateStatus("Ready. Press F5 to start capture.")
		})
	}
	if len(ui.devices) == 0 {
		list.AddItem("No interfaces found", "", 0, nil)
	}
	ui.deviceList = list
	return list
}

func (ui *AppUI) buildTable() *tview.Table {
	tbl := tview.NewTable().SetBorders(false).SetFixed(1, 0)
	headers := []string{"Time", "Src", "Dst", "Proto", "Len", "Info"}
	for i, h := range headers {
		cell := tview.NewTableCell(fmt.Sprintf("[yellow]%s", h)).
			SetSelectable(false).
			SetExpansion(1)
		tbl.SetCell(0, i, cell)
	}
	tbl.SetBorder(true).SetTitle(" Packets ")
	ui.table = tbl
	return tbl
}

func (ui *AppUI) appendRow(row PacketRow) {
	// Limit rows
	if ui.rowCount >= ui.rowLimit {
		// shift up by deleting row 1 and moving others up
		ui.table.RemoveRow(1)
		ui.rowCount--
	}
	r := ui.rowCount + 1
	ui.table.SetCell(r, 0, tview.NewTableCell(row.Time))
	ui.table.SetCell(r, 1, tview.NewTableCell(row.Src))
	ui.table.SetCell(r, 2, tview.NewTableCell(row.Dst))
	ui.table.SetCell(r, 3, tview.NewTableCell(row.Proto))
	ui.table.SetCell(r, 4, tview.NewTableCell(fmt.Sprintf("%d", row.Length)))
	ui.table.SetCell(r, 5, tview.NewTableCell(row.Info).SetExpansion(2))
	ui.rowCount++
}

func (ui *AppUI) buildStatus() *tview.TextView {
	tv := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(false).
		SetTextAlign(tview.AlignLeft)
	tv.SetBorder(true).SetTitle(" Status ")
	ui.status = tv
	return tv
}

func (ui *AppUI) buildHelp() *tview.TextView {
	help := tview.NewTextView().
		SetDynamicColors(true).
		SetText(`Keys: [yellow]F5[start] Start  [yellow]F6[white] Stop  [yellow]Space[white] Pause/Resume  [yellow]F2[white] Set BPF filter  [yellow]Tab[white] Focus cycle  [yellow]Q[white] Quit`)
	help.SetBorder(true).SetTitle(" Help ")
	ui.help = help
	return help
}

func (ui *AppUI) buildFilterField() *tview.InputField {
	in := tview.NewInputField().
		SetLabel("BPF Filter: ").
		SetFieldWidth(40).
		SetDoneFunc(func(key tcell.Key) {
			if key == tcell.KeyEnter {
				val := ui.filterField.GetText()
				ui.sniffer.SetFilter(val)
				ui.updateStatus(fmt.Sprintf("Filter set to: %q. Restart capture to apply.", val))
				ui.pages.SwitchToPage("capture")
				ui.app.SetFocus(ui.table)
			}
		})
	in.SetBorder(true).SetTitle(" Filter ")
	ui.filterField = in
	return in
}

func (ui *AppUI) updateStatus(msg string) {
	now := time.Now().Format("15:04:05")
	ui.status.SetText(fmt.Sprintf("[%s] %s", now, msg))
}

func (ui *AppUI) startCapture() {
	if err := ui.sniffer.Start(); err != nil {
		ui.updateStatus(fmt.Sprintf("Error: %v", err))
		return
	}
	ui.startedAt = time.Now()
	ui.updateStatus(fmt.Sprintf("Capturing on %s. Filter: %q", ui.sniffer.ifaceName, ui.sniffer.filter))
	go ui.consumePackets()
}

func (ui *AppUI) stopCapture() {
	ui.sniffer.Stop()
	ui.updateStatus("Stopped")
}

func (ui *AppUI) consumePackets() {
	for pkt := range ui.sniffer.packetChan {
		row := decodePacket(pkt)
		if row.Time == "" {
			continue
		}
		// update UI in goroutine safe manner
		r := row
		ui.app.QueueUpdateDraw(func() {
			ui.appendRow(r)
		})
	}
}

func decodePacket(pkt gopacket.Packet) PacketRow {
	ts := pkt.Metadata().Timestamp.Format("15:04:05.000")
	// Link layer may be Ethernet or others
	var srcIP, dstIP string
	var proto string
	var info string
	length := len(pkt.Data())

	if net4 := pkt.Layer(layers.LayerTypeIPv4); net4 != nil {
		ip := net4.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		switch ip.Protocol {
		case layers.IPProtocolTCP:
			if tcpL := pkt.Layer(layers.LayerTypeTCP); tcpL != nil {
				t := tcpL.(*layers.TCP)
				proto = "TCP"
				info = fmt.Sprintf("%d → %d", t.SrcPort, t.DstPort)
			}
		case layers.IPProtocolUDP:
			if udpL := pkt.Layer(layers.LayerTypeUDP); udpL != nil {
				u := udpL.(*layers.UDP)
				proto = "UDP"
				info = fmt.Sprintf("%d → %d", u.SrcPort, u.DstPort)
			}
		default:
			proto = ip.Protocol.String()
		}
	} else if net6 := pkt.Layer(layers.LayerTypeIPv6); net6 != nil {
		ip := net6.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		if tcpL := pkt.Layer(layers.LayerTypeTCP); tcpL != nil {
			t := tcpL.(*layers.TCP)
			proto = "TCP6"
			info = fmt.Sprintf("%d → %d", t.SrcPort, t.DstPort)
		} else if udpL := pkt.Layer(layers.LayerTypeUDP); udpL != nil {
			u := udpL.(*layers.UDP)
			proto = "UDP6"
			info = fmt.Sprintf("%d → %d", u.SrcPort, u.DstPort)
		} else {
			proto = "IPv6"
		}
	} else {
		// Non IP packet
		proto = "Link"
		srcIP, dstIP = "-", "-"
	}

	return PacketRow{
		Time:   ts,
		Src:    srcIP,
		Dst:    dstIP,
		Proto:  proto,
		Length: length,
		Info:   info,
	}
}

func (ui *AppUI) buildCapturePage() tview.Primitive {
	grid := tview.NewGrid().
		SetRows(0, 3).
		SetColumns(0).
		SetBorders(false)
	grid.AddItem(ui.buildTable(), 0, 0, 1, 1, 0, 0, true)

	bottom := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(ui.buildStatus(), 0, 2, false).
		AddItem(ui.buildHelp(), 0, 1, false)
	grid.AddItem(bottom, 1, 0, 1, 1, 0, 0, false)

	return grid
}

func (ui *AppUI) buildRoot() tview.Primitive {
	pages := tview.NewPages()
	ui.pages = pages

	// Page: select device
	devList := ui.buildDeviceList()
	devFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewTextView().SetText("Select a network interface to capture from").SetTextAlign(tview.AlignCenter), 3, 0, false).
		AddItem(devList, 0, 1, true)
	pages.AddPage("devices", devFlex, true, true)

	// Page: capture
	capture := ui.buildCapturePage()
	pages.AddPage("capture", capture, true, false)

	// Page: filter
	filter := ui.buildFilterField()
	filterFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(filter, 3, 0, true)
	pages.AddPage("filter", filterFlex, true, false)

	return pages
}

func (ui *AppUI) Run() error {
	if err := ui.loadDevices(); err != nil {
		return fmt.Errorf("pcap devices: %w", err)
	}

	root := ui.buildRoot()
	ui.updateStatus("Select an interface")
	ui.app.SetRoot(root, true).SetFocus(ui.deviceList)

	ui.app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyF5:
			ui.startCapture()
			return nil
		case tcell.KeyF6:
			ui.stopCapture()
			return nil
		case tcell.KeyRune:
			switch ev.Rune() {
			case 'q', 'Q':
				ui.stopCapture()
				ui.app.Stop()
				return nil
			case ' ':
				ui.sniffer.TogglePause()
				if ui.sniffer.pause {
					ui.updateStatus("Paused")
				} else {
					ui.updateStatus("Resumed")
				}
				return nil
			case '\t':
				// allow default tab focus handling
				return ev
			}
		}
		switch ev.Key() {
		case tcell.KeyF2:
			ui.pages.SwitchToPage("filter")
			ui.app.SetFocus(ui.filterField)
			return nil
		}
		return ev
	})

	// Ctrl+C handler to cleanly stop
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		ui.stopCapture()
		ui.app.Stop()
	}()

	return ui.app.Run()
}

func main() {
	// Capturing may require elevated privileges on your OS
	ui := NewAppUI()
	if err := ui.Run(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}
