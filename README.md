# SMTP Tunnel Proxy — Installation and Usage Guide

SMTP Tunnel Proxy is a TCP tunnel with a local SOCKS5 listener. It carries client/server traffic through an SMTP-like / STARTTLS connection.

Default normal architecture:

```text
V2Ray / Application
        │
        ▼
Local SOCKS5 on client
127.0.0.1:1080
        │
        ▼
Persistent outbound tunnel
SMTP-like handshake + STARTTLS + auth + binary frames
        │
        ▼
VPS server on port 587
        │
        ▼
Internet
```

Normal mode remains the default and is backward compatible. This version also supports optional true reverse mode:

```text
V2Ray / Application
        |
        v
Access Node in Iran
local SOCKS5 127.0.0.1:1080
reverse listener on port 587
        ^
        |
Exit Node on foreign VPS dials inward
SMTP-like handshake + STARTTLS + auth + binary frames
        |
        v
Internet exit from VPS
```

In reverse mode the Iran-side Access Node is the TLS server and needs the certificate/key. The VPS Exit Node is the TLS client and must verify the Access Node certificate.

> No tunnel can guarantee that it will never be detected or blocked by DPI/firewall systems. This project aims to improve stability, configurability, and remove obvious static fingerprints, but detection is still possible.

---

## Values to Replace

This guide uses placeholders. Replace them before running commands:

```text
GITHUB_USER/REPO_NAME    your GitHub repository path
YOUR_DOMAIN              a domain or hostname that belongs to your VPS
IRAN_SERVER_IP           client server IP address
USERNAME                 tunnel username, for example client1
```

Example:

```text
YOUR_DOMAIN = mail.example.com
USERNAME = client1
```

Do not use domains like `gmail.com`, `outlook.com`, or any domain you do not own.

---

## Installation Layout

After installation:

```text
/opt/smtp-tunnel/                  application files
/opt/smtp-tunnel/venv/             Python virtualenv
/etc/smtp-tunnel/config.yaml       main config
/etc/smtp-tunnel/users.yaml        users and secrets
/etc/smtp-tunnel/certs/            CA and certificates
/etc/systemd/system/smtp-tunnel.service
/var/backups/smtp-tunnel/          backups and rollback.sh
/usr/local/bin/smtp-tunnel-adduser
/usr/local/bin/smtp-tunnel-deluser
/usr/local/bin/smtp-tunnel-listusers
/usr/local/bin/smtp-tunnel-update
```

---

## Requirements

On the foreign VPS:

```text
Ubuntu/Debian Linux
Python 3.8+
Port 587 must be open
A domain or hostname is recommended
```

On the client server:

```text
Ubuntu/Debian Linux
root or sudo access
A free local SOCKS port, usually 127.0.0.1:1080
```

For reverse mode, the Iran-side Access Node must also have an inbound TCP port reachable from the VPS. If the Access Node is behind NAT/CGNAT, true reverse mode requires port forwarding or another rendezvous design.

---

# Reverse Mode Quick Install

Iran-side Access Node with Let's Encrypt HTTP-01:

```bash
curl -fsSL https://raw.githubusercontent.com/AlirezaKF/smtp-tunnel-proxy/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role client \
  --mode reverse-listen \
  --repo AlirezaKF/smtp-tunnel-proxy \
  --ref main \
  --socks-host 127.0.0.1 \
  --socks-port 1080 \
  --reverse-domain ACCESS_DOMAIN \
  --reverse-port 587 \
  --reverse-cert-mode letsencrypt \
  --letsencrypt-challenge http-01 \
  --letsencrypt-email admin@example.com \
  --allowed-dialer-ip VPS_PUBLIC_IP \
  --username reverse1 \
  --secret-file /root/reverse.secret \
  --performance-profile throughput \
  --yes
```

For HTTP-01, `ACCESS_DOMAIN` must resolve to the Iran-side Access Node, public TCP/80 must be reachable, and no other service may occupy port 80 during issuance.

VPS Exit Node:

```bash
curl -fsSL https://raw.githubusercontent.com/AlirezaKF/smtp-tunnel-proxy/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role server \
  --mode reverse-dial \
  --repo AlirezaKF/smtp-tunnel-proxy \
  --ref main \
  --reverse-host ACCESS_DOMAIN \
  --reverse-port 587 \
  --reverse-domain ACCESS_DOMAIN \
  --tls-verify-mode system-ca \
  --username reverse1 \
  --secret-file /root/reverse.secret \
  --connections 4 \
  --performance-profile throughput \
  --yes
```

Firewall recommendation on the Access Node:

```bash
sudo ufw allow from VPS_PUBLIC_IP to any port 587 proto tcp
```

Test from the Access Node:

```bash
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me
```

Verify that multiple reverse sessions are established from the VPS:

```bash
sudo ss -tnp | grep ':587'
sudo journalctl -u smtp-tunnel -f
```

Stage 2 reverse mode uses `tunnel.connections` independent tunnel sessions. New SOCKS channels are assigned to the least-active reverse session. This improves aggregate throughput and concurrent flows when the network benefits from parallel streams. It does not stripe one TCP flow across multiple tunnels, so a single download or single TCP connection can still be limited by one tunnel session.

Recommended starting point:

```yaml
tunnel:
  connections: 4
  connect_timeout: 10

performance:
  profile: balanced

metrics:
  enabled: true
  log_interval: 30

logging:
  log_destinations: false
  log_session_events: true
  log_metrics: true

transport:
  read_chunk_size: 65535
  drain_bytes: 262144
  drain_interval_ms: 10
  tcp_nodelay: true
  tcp_keepalive: true
```

If 4 is worse than 2 or 8 on your specific route, test and use the value that performs best.

Count session distribution on the VPS Exit Node:

```bash
sudo journalctl -u smtp-tunnel --since "10 minutes ago" --no-pager \
  | grep -oE '\[reverse session [0-9]+\]' \
  | sort \
  | uniq -c
```

Verify periodic reverse status logs:

```bash
sudo journalctl -u smtp-tunnel -f | grep -i 'Reverse status'
```

Lightweight concurrency test:

```bash
for i in 1 2 3 4 5 6 7 8; do
  curl -sS --max-time 10 \
    -x socks5h://127.0.0.1:1080 \
    -o /dev/null \
    -w "req$i code:%{http_code} total:%{time_total}\n" \
    https://ifconfig.me &
done
wait
```

Four-flow throughput test:

```bash
for i in 1 2 3 4; do
  curl -sS -L --http1.1 --connect-timeout 10 --max-time 25 \
    -x socks5h://127.0.0.1:1080 \
    -o /dev/null \
    -w "flow$i code:%{http_code} bytes:%{size_download} speed:%{speed_download} total:%{time_total}\n" \
    "https://speed.cloudflare.com/__down?bytes=50000000" &
done
wait
```

By default, CONNECT destination hostnames and IPs are redacted in logs. Set `logging.log_destinations: true` only for short debug windows when you need full destination visibility.

For throughput testing, you can temporarily switch the VPS and Access Node to:

```yaml
performance:
  profile: throughput
```

This keeps the same wire protocol but uses larger local socket buffers and less frequent DATA drain calls. If it performs worse on a lossy path, return to `balanced` or test `compatibility`.

Local VPS HTTP baseline test:

```bash
python3 -m http.server 18080 --bind 127.0.0.1
curl -o /dev/null -w "local bytes:%{size_download} speed:%{speed_download} total:%{time_total}\n" \
  http://127.0.0.1:18080/
```

CPU and TCP state checks:

```bash
top -p "$(pgrep -f 'smtp-tunnel|client.py|server.py' | paste -sd, -)"
sudo ss -tinp | grep ':587'
```

Let's Encrypt renewal test:

```bash
sudo certbot renew --dry-run
```

DNS-01/manual mode is available with `--reverse-cert-mode letsencrypt --letsencrypt-challenge dns-01`. It requires DNS control. DNS API provider plugins are not automated in Stage 1.

Private CA fallback is available with `--reverse-cert-mode private-ca`. Copy the generated public CA from the Access Node or use the exported reverse-dial bundle, then install the VPS with `--tls-verify-mode private-ca --reverse-ca-cert /path/to/ca.crt`.

Reverse-dial bundles do not include the reverse auth secret unless you explicitly pass `--include-reverse-secret` or answer yes to the installer prompt. Bundles never include the Access Node TLS private key, Let's Encrypt `privkey.pem`, `users.yaml`, or unrelated secrets.

---

# Fresh Install on the VPS, Server Role

If you want a clean install, remove the previous installation first:

```bash
sudo systemctl stop smtp-tunnel 2>/dev/null || true
sudo systemctl disable smtp-tunnel 2>/dev/null || true

sudo pkill -f 'python.*server.py' 2>/dev/null || true
sudo pkill -f 'python.*client.py' 2>/dev/null || true
sudo pkill -f smtp-tunnel 2>/dev/null || true

sudo rm -f /etc/systemd/system/smtp-tunnel.service
sudo rm -rf /opt/smtp-tunnel
sudo rm -rf /etc/smtp-tunnel
sudo rm -rf /var/log/smtp-tunnel
sudo rm -f /usr/local/bin/smtp-tunnel-*

sudo systemctl daemon-reload
sudo systemctl reset-failed

sudo ss -ltnp | grep ':587' || true
```

If the final command prints nothing, port 587 is free.

Install the server:

```bash
curl -fsSL https://raw.githubusercontent.com/GITHUB_USER/REPO_NAME/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role server \
  --repo GITHUB_USER/REPO_NAME \
  --ref main \
  --hostname YOUR_DOMAIN \
  --listen-port 587 \
  --ehlo-name YOUR_DOMAIN \
  --service-name smtp-tunnel \
  --export-client-package \
  --yes
```

Choose a simple username during installation:

```text
client1
client2
iran1
```

The secret may be complex, but the username should stay simple.

---

## Recommended Interactive Server Answers

If the installer prompts you:

```text
systemd service name: press Enter
server listen host: press Enter
server listen port: press Enter
public hostname/domain: YOUR_DOMAIN
EHLO name: press Enter
Generate private CA and server certificate now? y
Create the first user now? y
username: USERNAME
secret: press Enter to auto-generate, or enter a strong secret manually
Export a client bundle to /root for this user? y
```

A successful install should show:

```text
Generating private CA and server certificate
OK: server config is valid
Service is active: smtp-tunnel
Client service bundle created
```

---

## Check the Server

On the VPS:

```bash
sudo systemctl status smtp-tunnel --no-pager
sudo journalctl -u smtp-tunnel -n 100 --no-pager
sudo ss -ltnp | grep ':587' || true
sudo ls -lh /etc/smtp-tunnel/certs/
ls -lh /root/smtp-tunnel-client-*.tar.gz
```

Validate the config:

```bash
sudo /opt/smtp-tunnel/venv/bin/python /opt/smtp-tunnel/server.py \
  -c /etc/smtp-tunnel/config.yaml \
  --check
```

Expected result:

```text
OK: server config is valid
```

---

# Add a New User on the Server

Create a new user:

```bash
cd /opt/smtp-tunnel
sudo ./smtp-tunnel-adduser USERNAME --output-dir /root
sudo systemctl restart smtp-tunnel
```

Or, if the wrapper is installed correctly:

```bash
sudo smtp-tunnel-adduser USERNAME --output-dir /root
sudo systemctl restart smtp-tunnel
```

This should create a client package:

```text
/root/smtp-tunnel-client-USERNAME.tar.gz
```

List users:

```bash
sudo smtp-tunnel-listusers
```

Delete a user:

```bash
sudo smtp-tunnel-deluser USERNAME
sudo systemctl restart smtp-tunnel
```

Important: the server reads `users.yaml` at startup, so restart the service after adding or deleting users.

---

# Copy the Client Package to the Client Server

On the VPS:

```bash
scp /root/smtp-tunnel-client-USERNAME.tar.gz root@IRAN_SERVER_IP:/root/
```

If the filename is different:

```bash
ls -lh /root/smtp-tunnel-client-*.tar.gz
```

---

# Fresh Install on the Client Server, Client Role

Remove any previous installation first:

```bash
sudo systemctl stop smtp-tunnel 2>/dev/null || true
sudo systemctl disable smtp-tunnel 2>/dev/null || true

sudo pkill -f 'python.*server.py' 2>/dev/null || true
sudo pkill -f 'python.*client.py' 2>/dev/null || true
sudo pkill -f smtp-tunnel 2>/dev/null || true

sudo rm -f /etc/systemd/system/smtp-tunnel.service
sudo rm -rf /opt/smtp-tunnel
sudo rm -rf /etc/smtp-tunnel
sudo rm -rf /var/log/smtp-tunnel
sudo rm -f /usr/local/bin/smtp-tunnel-*

sudo systemctl daemon-reload
sudo systemctl reset-failed

sudo ss -ltnp | grep ':1080' || true
```

If port 1080 is already in use, stop the conflicting service or choose another SOCKS port during client installation.

Install the client from the package:

```bash
curl -fsSL https://raw.githubusercontent.com/GITHUB_USER/REPO_NAME/main/scripts/bootstrap.sh -o /root/bootstrap.sh

sudo bash /root/bootstrap.sh \
  --role client \
  --repo GITHUB_USER/REPO_NAME \
  --ref main \
  --from-package /root/smtp-tunnel-client-USERNAME.tar.gz
```

---

## Check the Client

On the client server:

```bash
sudo systemctl status smtp-tunnel --no-pager
sudo journalctl -u smtp-tunnel -n 100 --no-pager
sudo ss -ltnp | grep ':1080' || true
```

Validate the config:

```bash
sudo /opt/smtp-tunnel/venv/bin/python /opt/smtp-tunnel/client.py \
  -c /etc/smtp-tunnel/config.yaml \
  --check
```

---

# Test the SOCKS Connection

On the client server:

```bash
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me
```

Concurrent test:

```bash
for i in 1 2 3 4 5; do
  curl -x socks5h://127.0.0.1:1080 https://ifconfig.me &
done
wait
```

If an output IP is returned, the tunnel is working.

---

# V2Ray Configuration

Configure V2Ray to use the local SOCKS5 proxy:

```text
SOCKS host: 127.0.0.1
SOCKS port: 1080
SOCKS version: 5
```

For curl and command-line tools, prefer `socks5h` so DNS resolution also goes through the proxy:

```bash
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me
```

---

# Service Management

On both servers:

```bash
sudo systemctl status smtp-tunnel --no-pager
sudo systemctl restart smtp-tunnel
sudo systemctl stop smtp-tunnel
sudo systemctl start smtp-tunnel
sudo journalctl -u smtp-tunnel -f
```

Enable at boot:

```bash
sudo systemctl enable smtp-tunnel
```

---

# Upgrade an Existing Installation

To upgrade without deleting configs or secrets:

On the server:

```bash
curl -fsSL https://raw.githubusercontent.com/GITHUB_USER/REPO_NAME/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role server \
  --repo GITHUB_USER/REPO_NAME \
  --ref main \
  --non-interactive
```

On the client:

```bash
curl -fsSL https://raw.githubusercontent.com/GITHUB_USER/REPO_NAME/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role client \
  --repo GITHUB_USER/REPO_NAME \
  --ref main \
  --non-interactive
```

The installer creates backups before replacing files.

---

# Rollback

If an install or upgrade fails, the installer prints a backup path, for example:

```text
/var/backups/smtp-tunnel/YYYYMMDD-HHMMSS/
```

Rollback:

```bash
sudo /var/backups/smtp-tunnel/YYYYMMDD-HHMMSS/rollback.sh
sudo systemctl daemon-reload
sudo systemctl restart smtp-tunnel
```

---

# Important Config Settings

Config path:

```text
/etc/smtp-tunnel/config.yaml
```

Recommended fresh-install settings:

```yaml
tunnel:
  keepalive_interval: 45
  keepalive_timeout: 120
  reconnect_initial_delay: 2
  reconnect_max_delay: 60
  reconnect_jitter: 0.35

smtp:
  ehlo_name: YOUR_DOMAIN
```

Use your own domain or hostname for `smtp.ehlo_name`.

---

# Certificates and TLS

Server certificate and CA files are created here:

```text
/etc/smtp-tunnel/certs/
```

Important files:

```text
ca.crt
ca.key
server.crt
server.key
```

Only `ca.crt` is needed on the client.

Never upload these files to GitHub:

```text
ca.key
server.key
real users.yaml
real config.yaml containing secrets
real client packages
secret files
```

---

# Troubleshooting

## Service does not start

```bash
sudo systemctl status smtp-tunnel --no-pager
sudo journalctl -u smtp-tunnel -n 150 --no-pager
```

## Server port is not listening

On the VPS:

```bash
sudo ss -ltnp | grep ':587' || true
```

## Client SOCKS port is not listening

On the client server:

```bash
sudo ss -ltnp | grep ':1080' || true
```

## Certificate errors

On the server:

```bash
sudo ls -lh /etc/smtp-tunnel/certs/
```

These files should exist:

```text
ca.crt
server.crt
server.key
```

If they do not exist:

```bash
sudo mkdir -p /etc/smtp-tunnel/certs

sudo /opt/smtp-tunnel/venv/bin/python /opt/smtp-tunnel/generate_certs.py \
  --hostname YOUR_DOMAIN \
  --output-dir /etc/smtp-tunnel/certs

sudo systemctl restart smtp-tunnel
```

## Authentication failed

On the server:

```bash
sudo smtp-tunnel-listusers
sudo journalctl -u smtp-tunnel -n 100 --no-pager
```

After adding a new user:

```bash
sudo systemctl restart smtp-tunnel
```

## Incomplete package

If user creation prints warnings like:

```text
client.py not found
common.py not found
requirements.txt not found
```

run the command from the application directory:

```bash
cd /opt/smtp-tunnel
sudo ./smtp-tunnel-adduser USERNAME --output-dir /root
```

Then inspect the package:

```bash
tar -tzf /root/smtp-tunnel-client-USERNAME.tar.gz | head -50
```

---

# Known Issue

You may see this after installation:

```text
workdir: unbound variable
```

If the following messages appeared before it:

```text
OK: server config is valid
Service is active: smtp-tunnel
Bootstrap complete
```

then installation completed. The `scripts/bootstrap.sh` cleanup logic should still be fixed so it does not reference an undefined variable.

---

# Security Notes

- `users.yaml` contains user secrets.
- Do not publish private keys.
- Do not pass production secrets through command-line arguments.
- Use the package generated for the specific user.
- Restart the server after adding or deleting users.
- A public repository must not contain real configs, real secrets, private keys, or real client packages.

---

# Limitations

- This project does not guarantee that traffic will never be detected or blocked.
- Python/OpenSSL TLS fingerprints remain observable.
- Long-lived TLS over an SMTP-like port may look unusual.
- Reverse mode is optional. Stage 2 supports multiple reverse tunnel sessions for concurrent flows. mTLS and single-flow striping are planned separately.
- Use this tool only in environments where you have authorization and where its use is lawful.

---

# License

See `LICENSE`.
