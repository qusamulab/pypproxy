# Getting Started

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

## Installation

### From PyPI

```bash
pip install pypproxy
```

### With Frida support

```bash
pip install 'pypproxy[frida]'
```

### From source

```bash
git clone https://github.com/qusamulab/pypproxy
cd pypproxy
uv sync
```

## Running

### GUI mode (default)

```bash
pypproxy
```

Open `http://localhost:8081` in your browser.

### CUI mode

```bash
pypproxy --mode cui
```

## Startup output

```
pypproxy MITM proxy
  proxy : 0.0.0.0:8080
  UI    : http://0.0.0.0:8081
  CA    : /Users/you/.pypproxy/ca-cert.pem
  DB    : /Users/you/.paxy/pypproxy.db
```

On first run, `~/.pypproxy/ca-cert.pem` and `~/.pypproxy/ca-key.pem` are generated automatically.

## Install the CA certificate

### macOS (system-wide)

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.pypproxy/ca-cert.pem
```

### Firefox

1. **Settings** → **Privacy & Security** → **View Certificates** → **Authorities**
2. **Import** → select `~/.pypproxy/ca-cert.pem`
3. Check **Trust this CA to identify websites**

### Android

1. Transfer `ca-cert.pem` to the device
2. **Settings** → **Security** → **Install from storage**

### iOS

1. Send the certificate via email or AirDrop
2. Open it — iOS prompts to install a profile
3. **Settings** → **General** → **VPN & Device Management** → install
4. **Settings** → **General** → **About** → **Certificate Trust Settings** → enable full trust

## Configure the proxy

### macOS

```bash
networksetup -setwebproxy Wi-Fi 127.0.0.1 8080
networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 8080

# To disable:
networksetup -setwebproxystate Wi-Fi off
networksetup -setsecurewebproxystate Wi-Fi off
```

### Android / iOS

**Settings** → **Wi-Fi** → your network → **Proxy: Manual**

- Host: your machine's IP (e.g. `192.168.1.10`)
- Port: `8080`

## Open the UI

Navigate to `http://localhost:8081`. Switch between **dark and light mode** using the ☀ button in the toolbar.
