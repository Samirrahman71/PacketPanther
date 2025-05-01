# 🐆 PacketPanther

[![Release](https://img.shields.io/github/v/release/Samirrahman71/PacketPanther?color=brightgreen)](https://github.com/Samirrahman71/PacketPanther/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/Samirrahman71/PacketPanther)](https://goreportcard.com/report/github.com/Samirrahman71/PacketPanther)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker Pulls](https://img.shields.io/github/downloads/Samirrahman71/PacketPanther/total)](https://github.com/Samirrahman71/PacketPanther/pkgs/container/packet-panther)

**Five NOC tools → one 20MB binary.**

PacketPanther is a single self-contained Go binary that combines multiple network tools:
- 📦 **Packet capture & top-talker stats** using Google's gopacket
- 🔍 **Hop-by-hop latency traceroute** using aeden/traceroute 
- 🚪 **100-worker TCP port scanner** with high-performance concurrent scanning
- 📡 **SNMP v2c/v3 inventory** using gosnmp
- 💾 **SQLite persistence** for all captured data
- 📊 **Web dashboard** on port 8080 using Go templates

Builds for macOS, Windows, Linux, ARM, and Docker—with zero cloud cost.

![PacketPanther Dashboard](https://github.com/Samirrahman71/PacketPanther/raw/main/docs/dashboard.gif)

## Quick Start

### Option 1: Download Binary

```bash
# Linux/macOS
curl -sL https://github.com/Samirrahman71/PacketPanther/releases/latest/download/install.sh | bash

# Run it
ppanther
```

### Option 2: Docker

```bash
# Run with host network access
docker run --net=host ghcr.io/samirrahman71/packet-panther
```

### Option 3: Go Install

```bash
go install github.com/Samirrahman71/PacketPanther/cmd/ppanther@latest
```

## Features

### Packet Capture

Capture and analyze network traffic on selected interfaces:

```bash
# Capture on default interface
ppanther --capture

# Specify interface(s)
ppanther --interface eth0,wlan0
```

### Traceroute

Perform hop-by-hop latency measurements:

```bash
# Trace to a specific host
ppanther --trace --host example.com

# Trace multiple hosts
ppanther --trace --host example.com,google.com
```

### Port Scanner

Scan for open ports with 100 concurrent workers:

```bash
# Scan default ports (22, 80, 443)
ppanther --scan --host 192.168.1.100

# Scan specific ports
ppanther --scan --host 192.168.1.100 --port 22,80,443,3389,8080
```

### SNMP Polling

Collect system and interface information from SNMP devices:

```bash
# Poll with community string
ppanther --snmp --host 192.168.1.1 --community public

# Specify SNMP version
ppanther --snmp --host 192.168.1.1 --community public --snmp-version 2
```

### Web Dashboard

Access the web dashboard for visualization and results:

```bash
# Default port 8080
ppanther

# Custom port
ppanther --web-port 9000
```

## Building from Source

```bash
# Clone repository
git clone https://github.com/Samirrahman71/PacketPanther.git
cd PacketPanther

# Build
go build -o ppanther ./cmd/ppanther

# Run
./ppanther
```

## Project Structure

```
/cmd/ppanther     - Cobra CLI application
/pkg/
  /capture        - Packet capture using gopacket
  /tracer         - Traceroute implementation
  /scan           - Port scanning with worker pool
  /snmp           - SNMP polling implementation
  /storage        - SQLite data persistence
  /web            - Web dashboard and API
/web/
  /static         - CSS, JavaScript, etc.
  /templates      - HTML templates
/.github/workflows - CI/CD pipeline
```

## System Requirements

- Go 1.22 or higher (for building)
- libpcap-dev (for packet capture)
- Connected network interface(s)
- Root/Administrator privileges (for raw socket operations)

## Docker

The Docker image is based on a minimal scratch image and is less than 10MB:

```bash
# Build Docker image
docker build -t packet-panther .

# Run with host networking
docker run --net=host packet-panther
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.