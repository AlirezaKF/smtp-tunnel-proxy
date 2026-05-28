# 📧 SMTP Tunnel Proxy

> **A TCP tunnel that presents an SMTP-like outer protocol before STARTTLS, intended for controlled privacy/censorship-circumvention deployments.**

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐      ┌──────────────┐
│ Application │─────▶│   Client    │─────▶│   Server    │─────▶│  Internet    │
│  (Browser)  │ TCP  │ SOCKS5:1080 │ SMTP │  Port 587   │ TCP  │              │
│             │◀─────│             │◀─────│             │◀─────│              │
└─────────────┘      └─────────────┘      └─────────────┘      └──────────────┘
                            │                    │
                            │   Looks like       │
                            │   Email Traffic    │
                            ▼                    ▼
                     ┌────────────────────────────────┐
                     │     DPI Firewall               │
                     │  Sees: SMTP-like/TLS metadata  │
                     │  Payload protected by TLS      │
                     └────────────────────────────────┘
```

---

## 🎯 Features

| Feature | Description |
|---------|-------------|
| 🔒 **TLS Encryption** | All traffic encrypted with TLS 1.2+ after STARTTLS |
| 🎭 **Protocol Camouflage** | Initial handshake is SMTP-like and configurable |
| ⚡ **High Speed** | Binary streaming protocol after handshake - minimal overhead |
| 👥 **Multi-User** | Per-user secrets, IP whitelists, and logging settings |
| 🔑 **Authentication** | Per-user pre-shared keys with HMAC-SHA256 |
| 🌐 **SOCKS5 Proxy** | Standard proxy interface - works with any application |
| 📡 **Multiplexing** | Multiple connections over single tunnel |
| 🛡️ **IP Whitelist** | Per-user access control by IP address/CIDR |
| 📦 **Easy Install** | GitHub bootstrap installer with systemd service |
| 🎁 **Client Packages** | Auto-generated ZIP and Linux service tarball for each user |
| 🔄 **Auto-Reconnect** | Client automatically reconnects on connection loss |

> 📚 For in-depth technical details, protocol specifications, and security analysis, see [TECHNICAL.md](TECHNICAL.md).

### Current Tunnel Mode

The default mode is a persistent outbound tunnel:

1. `client.py` runs beside your application and exposes a local SOCKS5 proxy.
2. `client.py` opens one outbound TCP connection to `server.py`.
3. The connection performs an SMTP-like handshake, upgrades with STARTTLS, authenticates, then enters binary mode.
4. Future SOCKS5 CONNECT requests are multiplexed over that same existing TLS tunnel using per-channel frame IDs.

This means existing deployments already use one persistent outbound multiplexed session. Reverse-listen/reverse-dial mode is not part of the default behavior.

---

## ⚡ Quick Start

### 📋 Prerequisites

- **Server**: Linux VPS with Python 3.8+, port 587 open
- **Client**: Windows/macOS/Linux with Python 3.8+
- **Domain name**: Required for TLS certificate verification (free options: [DuckDNS](https://www.duckdns.org), [No-IP](https://www.noip.com), [FreeDNS](https://freedns.afraid.org))

---

## 🚀 Server Setup (VPS)

### Step 1️⃣: Get a Domain Name

Get a free domain pointing to your VPS:
- 🦆 **[DuckDNS](https://www.duckdns.org)** - Recommended, simple and free
- 🌐 **[No-IP](https://www.noip.com)** - Free tier available
- 🆓 **[FreeDNS](https://freedns.afraid.org)** - Many domain options

Example: `myserver.duckdns.org` → `203.0.113.50` (your VPS IP)

### Step 2️⃣: Run the Installer

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role server \
  --repo OWNER/REPO \
  --ref main
```

The installer will:
1. 📥 Download and install everything
2. ❓ Ask for your domain name
3. 🔐 Generate TLS certificates automatically
4. 👤 Offer to create your first user
5. 🔥 Configure firewall
6. 🚀 Start the service

**That's it!** Your server is ready.

### ➕ Add More Users Later

```bash
smtp-tunnel-adduser bob      # Add user + generate client ZIP
smtp-tunnel-listusers        # List all users
smtp-tunnel-deluser bob      # Remove a user
```

Restart the server after adding, deleting, or changing users:

```bash
sudo systemctl restart smtp-tunnel
```

### 🔄 Update Server

Use the bootstrap upgrade flow in the production section. It backs up `/opt/smtp-tunnel`, `/etc/smtp-tunnel`, certificates, users, and the systemd unit before replacing files.

---

## 💻 Client Setup

### Option A: Easy Way (Recommended)

1. Get your `username.zip` file from the server admin
2. Extract the ZIP file
3. Run the launcher:

| Platform | How to Run |
|----------|------------|
| 🪟 **Windows** | Double-click `start.bat` |
| 🐧 **Linux** | Run `./start.sh` |
| 🍎 **macOS** | Run `./start.sh` |

The launcher will automatically install dependencies and start the client.

✅ You should see:
```
SMTP Tunnel Proxy Client
User: alice

[INFO] Starting SMTP Tunnel...
[INFO] SOCKS5 proxy will be available at 127.0.0.1:1080

Connecting to myserver.duckdns.org:587
Connected - binary mode active
SOCKS5 proxy on 127.0.0.1:1080
```

### Option B: Manual Way

```bash
cd alice
pip install -r requirements.txt
python client.py
```

### Option C: Custom Configuration

```bash
# Download files
scp root@myserver.duckdns.org:/etc/smtp-tunnel/certs/ca.crt .

# Create config.yaml:
cat > config.yaml << EOF
client:
  server_host: "myserver.duckdns.org"
  server_port: 587
  socks_port: 1080
  username: "alice"
  secret: "your-secret-from-admin"
  ca_cert: "ca.crt"
EOF

# Run client
python client.py -c config.yaml
```

---

## 📖 Usage

### 🌐 Configure Your Applications

Set SOCKS5 proxy to: `127.0.0.1:1080`

#### 🦊 Firefox
1. Settings → Network Settings → Settings
2. Manual proxy configuration
3. SOCKS Host: `127.0.0.1`, Port: `1080`
4. Select SOCKS v5
5. ✅ Check "Proxy DNS when using SOCKS v5"

#### 🌐 Chrome
1. Install "Proxy SwitchyOmega" extension
2. Create profile with SOCKS5: `127.0.0.1:1080`

#### 🪟 Windows (System-wide)
Settings → Network & Internet → Proxy → Manual setup → `socks=127.0.0.1:1080`

#### 🍎 macOS (System-wide)
System Preferences → Network → Advanced → Proxies → SOCKS Proxy → `127.0.0.1:1080`

#### 🐧 Linux (System-wide)
```bash
export ALL_PROXY=socks5://127.0.0.1:1080
```

#### 💻 Command Line

```bash
# curl
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me

# git
git config --global http.proxy socks5://127.0.0.1:1080

# Environment variable
export ALL_PROXY=socks5://127.0.0.1:1080
```

### ✅ Test Connection

```bash
# Should show your VPS IP
curl -x socks5://127.0.0.1:1080 https://ifconfig.me
```

---

## ⚙️ Configuration Reference

### 🖥️ Server Options (`config.yaml`)

| Option | Description | Default |
|--------|-------------|---------|
| `host` | Listen interface | `0.0.0.0` |
| `port` | Listen port | `587` |
| `hostname` | SMTP hostname (must match certificate) | `mail.example.com` |
| `cert_file` | TLS certificate path | `server.crt` |
| `key_file` | TLS private key path | `server.key` |
| `users_file` | Path to users configuration | `users.yaml` |
| `log_users` | Global logging setting | `true` |

### 👥 User Options (`users.yaml`)

Each user can have individual settings:

```yaml
users:
  alice:
    secret: "auto-generated-secret"
    # whitelist:              # Optional: restrict to specific IPs
    #   - "192.168.1.100"
    #   - "10.0.0.0/8"        # CIDR notation supported
    # logging: true           # Optional: disable to stop logging this user

  bob:
    secret: "another-secret"
    whitelist:
      - "203.0.113.50"        # Bob can only connect from this IP
    logging: false            # Don't log Bob's activity
```

| Option | Description | Default |
|--------|-------------|---------|
| `secret` | User's authentication secret | Required |
| `whitelist` | Allowed IPs for this user (CIDR supported) | All IPs |
| `logging` | Enable activity logging for this user | `true` |

### 💻 Client Options

| Option | Description | Default |
|--------|-------------|---------|
| `server_host` | Server domain name | Required |
| `server_port` | Server port | `587` |
| `socks_port` | Local SOCKS5 port | `1080` |
| `socks_host` | Local SOCKS5 interface | `127.0.0.1` |
| `username` | Your username | Required |
| `secret` | Your authentication secret | Required |
| `ca_cert` | CA certificate for verification | Recommended |

### Tunnel Runtime Options

| Option | Description | Default |
|--------|-------------|---------|
| `tunnel.keepalive_interval` | Client-originated application keepalive interval in seconds; `0` disables it | `45` for new installs, `0` if absent |
| `tunnel.keepalive_timeout` | Seconds to wait for keepalive ACK before reconnect/close | `120` for new installs, `30` if absent |
| `tunnel.reconnect_initial_delay` | Initial client reconnect delay after failure/loss | `2` |
| `tunnel.reconnect_max_delay` | Maximum reconnect delay | `60` for new installs, `30` if absent |
| `tunnel.reconnect_jitter` | Reconnect delay jitter ratio | `0.35` for new installs, `0.2` if absent |

### SMTP Compatibility Options

| Option | Description | Default |
|--------|-------------|---------|
| `smtp.ehlo_name` | EHLO name sent by the client during the SMTP-like handshake | Installer asks/generates one; legacy fallback is `tunnel-client.local` |

---

## 📋 Service Management

```bash
# Check status
sudo systemctl status smtp-tunnel

# Restart after config changes
sudo systemctl restart smtp-tunnel

# View logs
sudo journalctl -u smtp-tunnel -n 100

# Uninstall
sudo /opt/smtp-tunnel/uninstall.sh
```

---

## Quick GitHub Install

Use this when the project is pushed to GitHub and you want each server to install directly from the repository.

Server/VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role server \
  --repo OWNER/REPO \
  --ref main
```

Client/Iran-side server:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role client \
  --repo OWNER/REPO \
  --ref main
```

Safer two-step install:

```bash
curl -fsSL -o bootstrap.sh https://raw.githubusercontent.com/OWNER/REPO/main/scripts/bootstrap.sh
less bootstrap.sh
sudo bash bootstrap.sh --role server --repo OWNER/REPO --ref main
```

The bootstrap script downloads the selected branch/tag/ref, then runs `install.sh`. It supports GitHub tarball download, optional `git clone`, and fallback to `curl` or `wget`.

---

## Production Install And Upgrade

### Fresh Server Install

Run this on the VPS/outside server:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role server \
  --repo OWNER/REPO \
  --ref main
```

Interactive server install asks for listen host, listen port, public hostname/domain for certificate generation, systemd service name, whether to generate certificates, whether to create the first user, that user's secret using hidden input, and whether to export a client bundle.

Non-interactive example:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role server \
  --repo OWNER/REPO \
  --ref v1.0.0 \
  --hostname mail.example.com \
  --listen-port 587 \
  --service-name smtp-tunnel \
  --non-interactive
```

The server installer:
- installs code and a venv under `/opt/smtp-tunnel`;
- writes active config under `/etc/smtp-tunnel/config.yaml`;
- stores users in `/etc/smtp-tunnel/users.yaml`;
- stores generated certificates under `/etc/smtp-tunnel/certs`;
- creates `/etc/systemd/system/smtp-tunnel.service`;
- preserves existing config/certs/users unless `--migrate-config` or `--reset-config` is explicitly used;
- backs up existing deployments under `/var/backups/smtp-tunnel/YYYYMMDD-HHMMSS/` and writes `rollback.sh`.

After adding users, restart the server because `users.yaml` is loaded at startup:

```bash
sudo smtp-tunnel-adduser alice
sudo systemctl restart smtp-tunnel
```

### Fresh Client Install

Run this on the Iran-side host where V2Ray will connect to local SOCKS5:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role client \
  --repo OWNER/REPO \
  --ref main
```

Interactive client install asks for server host, server port, local SOCKS host, local SOCKS port, username, secret using hidden input, CA certificate path or pasted PEM, service name, and EHLO name.

Non-interactive client installs should avoid command-line secrets. Use a root-readable secret file, an environment variable, an existing config, or a server-generated package:

```bash
install -m 600 /dev/null /root/alice.secret
# Put the user's secret in /root/alice.secret using your preferred secure method.

curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role client \
  --repo OWNER/REPO \
  --ref v1.0.0 \
  --server-host mail.example.com \
  --server-port 587 \
  --socks-host 127.0.0.1 \
  --socks-port 1080 \
  --username alice \
  --secret-file /root/alice.secret \
  --ca-cert /root/ca.crt \
  --service-name smtp-tunnel \
  --non-interactive
```

TLS verification is enabled when `--ca-cert` is supplied or when a client package includes `ca.crt`. If no CA cert is provided, the installer warns loudly; non-interactive installs require `--allow-insecure-no-ca` to continue without verification.

### Install From Client Package

On the server, create a user and export the service-install bundle:

```bash
sudo smtp-tunnel-adduser alice --output-dir /root
```

This creates `/root/smtp-tunnel-client-alice.tar.gz` with the client config, CA certificate when available, runtime files, and install notes. It does not include server private keys or other users' secrets.

Copy that tarball to the client server, then install with either local source:

```bash
sudo bash ./install.sh --role client --from-package /path/to/smtp-tunnel-client-alice.tar.gz
```

or GitHub bootstrap:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role client \
  --repo OWNER/REPO \
  --ref main \
  --from-package /path/to/smtp-tunnel-client-alice.tar.gz
```

### Upgrade Existing Deployment

Run bootstrap again with the same role. Existing secrets, users, certificates, and active config are backed up and preserved by default:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role server --repo OWNER/REPO --ref main --non-interactive

curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role client --repo OWNER/REPO --ref main --non-interactive
```

To adopt the new production defaults after backup, use `--migrate-config --yes` and provide the required values:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role server --repo OWNER/REPO --ref main \
  --hostname mail.example.com --migrate-config --yes

curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role client --repo OWNER/REPO --ref main \
  --server-host mail.example.com --username alice \
  --secret-file /root/alice.secret --ca-cert /root/ca.crt \
  --migrate-config --yes
```

### Rollback

Every upgrade over an existing deployment prints a backup path like:

```text
/var/backups/smtp-tunnel/20260529-153000/
```

Rollback command:

```bash
sudo /var/backups/smtp-tunnel/YYYYMMDD-HHMMSS/rollback.sh
```

The rollback script stops the service, restores `/opt/smtp-tunnel`, `/etc/smtp-tunnel`, and the previous systemd unit if they were backed up, runs `systemctl daemon-reload`, and restarts the service.

### Validation

Check config without starting the tunnel:

```bash
/opt/smtp-tunnel/venv/bin/python /opt/smtp-tunnel/server.py -c /etc/smtp-tunnel/config.yaml --check
/opt/smtp-tunnel/venv/bin/python /opt/smtp-tunnel/client.py -c /etc/smtp-tunnel/config.yaml --check
```

The installer runs the matching check command before restarting the service. If validation fails, it exits without restarting a working service.

### V2Ray And SOCKS5 Test

Point V2Ray at the local SOCKS5 listener:

```text
SOCKS host: 127.0.0.1
SOCKS port: 1080
```

Manual test:

```bash
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me
```

Concurrency smoke test:

```bash
for i in 1 2 3 4 5; do curl -x socks5h://127.0.0.1:1080 https://ifconfig.me & done; wait
```

Logs and service controls:

```bash
sudo systemctl daemon-reload
sudo systemctl enable smtp-tunnel
sudo systemctl restart smtp-tunnel
sudo journalctl -u smtp-tunnel -f
```

### Known Limitations

- No tunnel can guarantee avoidance of DPI/firewall detection or blocking.
- Long-lived TLS over an SMTP-like port can still be behaviorally unusual.
- Python/OpenSSL TLS fingerprints are still visible.
- This stage does not implement true reverse-listen or reverse-dial mode.
- Keepalive defaults are intended for upgraded client and server deployments; old configs remain preserved unless migrated.

---

## 🔧 Command Line Options

### 🖥️ Server
```bash
python server.py [-c CONFIG] [--check] [-d]

  -c, --config    Config file (default: config.yaml)
  --check         Validate configuration and exit
  -d, --debug     Enable debug logging
```

### 💻 Client
```bash
python client.py [-c CONFIG] [--server HOST] [--server-port PORT]
                 [-p SOCKS_PORT] [-u USERNAME] [-s SECRET] [--ca-cert FILE] [-d]

  -c, --config      Config file (default: config.yaml)
  --server          Override server domain
  --server-port     Override server port
  -p, --socks-port  Override local SOCKS port
  -u, --username    Your username
  -s, --secret      Override secret
  --ca-cert         CA certificate path
  --check           Validate configuration and exit
  -d, --debug       Enable debug logging
```

### 👥 User Management
```bash
smtp-tunnel-adduser <username> [-u USERS_FILE] [-c CONFIG] [--no-zip|--no-package]
    Add a new user and generate client package

smtp-tunnel-deluser <username> [-u USERS_FILE] [-f]
    Remove a user (use -f to skip confirmation)

smtp-tunnel-listusers [-u USERS_FILE] [-v]
    List all users (use -v for detailed info)

smtp-tunnel-update
    Legacy update helper; prefer the bootstrap upgrade flow above
```

---

## 📁 File Structure

```
smtp_proxy/
├── 📄 server.py               # Server (runs on VPS)
├── 📄 client.py               # Client (runs locally)
├── 📄 common.py               # Shared utilities
├── 📄 generate_certs.py       # Certificate generator
├── 📄 config.yaml             # Server/client configuration
├── 📄 users.yaml              # User database
├── 📄 requirements.txt        # Python dependencies
├── 📄 install.sh              # Role-aware installer/upgrader
├── 📄 smtp-tunnel.service     # Systemd unit file
├── 🔧 smtp-tunnel-adduser     # Add user script
├── 🔧 smtp-tunnel-deluser     # Remove user script
├── 🔧 smtp-tunnel-listusers   # List users script
├── 🔧 smtp-tunnel-update      # Update server script
├── 📄 README.md               # This file
└── 📄 TECHNICAL.md            # Technical documentation
```

### 📦 Installation Paths (after install.sh)

```
/opt/smtp-tunnel/              # Application files
/opt/smtp-tunnel/venv/         # Python virtual environment used by systemd
/etc/smtp-tunnel/              # Configuration files
  ├── config.yaml
  ├── users.yaml
  └── certs/
      ├── ca.crt
      ├── server.crt
      └── server.key
/var/backups/smtp-tunnel/      # Timestamped backups and rollback.sh
/usr/local/bin/                # Management commands
  ├── smtp-tunnel-adduser
  ├── smtp-tunnel-deluser
  ├── smtp-tunnel-listusers
  └── smtp-tunnel-update
```

---

## 🔧 Troubleshooting

### ❌ "Connection refused"
- Check server is running: `systemctl status smtp-tunnel` or `ps aux | grep server.py`
- Check port is open: `netstat -tlnp | grep 587`
- Check firewall: `ufw status`

### ❌ "Auth failed"
- Verify `username` and `secret` match in users.yaml
- Check server time is accurate (within 5 minutes)
- Run `smtp-tunnel-listusers -v` to verify user exists

### ❌ "IP not whitelisted"
- Check user's whitelist in users.yaml
- Your current IP must match a whitelist entry
- CIDR notation is supported (e.g., `10.0.0.0/8`)

### ❌ "Certificate verify failed"
- Ensure you're using a domain name, not IP address
- Verify `server_host` matches the certificate hostname
- Ensure you have the correct `ca.crt` from the server

### 🐛 Debug Mode

```bash
# Enable detailed logging
python server.py -d
python client.py -d

# View systemd logs
journalctl -u smtp-tunnel -f
```

---

## 🔐 Security Notes

- ✅ **Always use a domain name** for proper TLS verification
- ✅ **Always use `ca_cert`** to prevent man-in-the-middle attacks
- ✅ **Use `smtp-tunnel-adduser`** to generate strong secrets automatically
- ✅ **Use per-user IP whitelists** if you know client IPs
- ✅ **Protect `users.yaml`** - contains all user secrets (chmod 600)
- ✅ **Disable logging** for sensitive users with `logging: false`

> 📚 For detailed security analysis and threat model, see [TECHNICAL.md](TECHNICAL.md).

---

## 📄 License

This project is provided for educational and authorized use only. Use responsibly and in accordance with applicable laws.

---

## ⚠️ Disclaimer

This tool is designed for legitimate privacy and censorship circumvention purposes. Users are responsible for ensuring their use complies with applicable laws and regulations.

---

*Made with ❤️ for internet freedom*
