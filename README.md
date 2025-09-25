# GoPacketSniffer

A simple cross‑platform terminal UI packet viewer written in Go. It uses libpcap via gopacket and tview for the UI. You can select a network interface, apply a BPF filter, and watch packets in a live table.

> Use this tool only on networks you own or have explicit permission to monitor. Capturing other people’s traffic may be illegal in your jurisdiction.

## Features

- Interface selection screen
- Live packet table with Time, Src, Dst, Proto, Length, and Info
- Optional BPF filter input (press F2)
- Start (F5), Stop (F6), Pause/Resume (Space), Quit (Q)
- Keeps the most recent 500 rows for smooth scrolling

## Requirements

- Go 1.22 or newer
- libpcap/Npcap installed
  - **Linux**: install `libpcap` and run with `sudo`
  - **macOS**: run with `sudo`; you may need to grant terminal screen recording permissions for some OS versions
  - **Windows**: install [Npcap](https://nmap.org/npcap/) and run as Administrator

## Build

```bash
git clone https://github.com/devzephyr/GoPacketSniffer.git
cd GoPacketSniffer
go build ./...
```

Or run directly:

```bash
go run .
```

## Usage

1. Start the app
2. Pick an interface from the list
3. Press F2 to set an optional BPF filter such as `tcp` or `port 53`
4. Press F5 to start capture
5. Use Space to pause and F6 to stop
6. Press Q to quit

## BPF filter examples

- `tcp`
- `udp and port 53`
- `host 192.168.1.10`
- `tcp and port 443`

## Notes

- You need admin privileges for live capture on most systems
- The table shows the last 500 packets to keep memory stable
- Packet lengths show the captured size, not the full original frame length if a snaplen is in effect

