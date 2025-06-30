# apiping – Ping API Endpoints Like `ping`

A simple CLI tool written in Go to test and monitor HTTP(S) API endpoints by sending periodic requests and showing response time, status code, DNS lookup, body size, etc.

---

## 🔧 Features

- Continuous or limited pings (`-c`)
- Response time (RTT)
- HTTP status code
- Body size (`-b`)
- DNS resolution time
- TCP connection time
- Custom interval (`-i`)
- Verbose output (`-v`)
- JSON output (`-j`)
- Basic Auth (`-auth`)
- Bearer Token (`-bearer`)
- Custom Headers (`-H`)
- Timeout control (`-t`)
- Insecure TLS (`--insecure`)
- DNS-only mode (`--dns`)
- TCP ping (`--tcp`)

---

## 🚀 Installation

### From Source

Make sure you have Go installed (>=1.20 recommended):

```bash
git clone https://github.com/ <your-username>/apiping.git
cd apiping
go build -o apiping
sudo mv apiping /usr/local/bin/