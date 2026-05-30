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
reverse listener on port 8443
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
Normal mode: port 587 must be open on the VPS
Reverse mode: outbound access to the Access Node reverse port, tested target 8443
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
  --reverse-port 8443 \
  --reverse-cert-mode letsencrypt \
  --letsencrypt-challenge http-01 \
  --letsencrypt-email admin@example.com \
  --allowed-dialer-ip VPS_PUBLIC_IP \
  --username reverse1 \
  --secret-file /root/reverse.secret \
  --adaptive-connections \
  --min-connections 8 \
  --max-connections 20 \
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
  --reverse-port 8443 \
  --reverse-domain ACCESS_DOMAIN \
  --tls-verify-mode system-ca \
  --username reverse1 \
  --secret-file /root/reverse.secret \
  --connections 20 \
  --adaptive-connections \
  --min-connections 8 \
  --max-connections 20 \
  --performance-profile throughput \
  --yes
```

Firewall recommendation on the Access Node:

```bash
sudo ufw allow from VPS_PUBLIC_IP to any port 8443 proto tcp
```

Test from the Access Node:

```bash
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me
```

Verify that multiple reverse sessions are established from the VPS:

```bash
sudo ss -tnp | grep ':8443'
sudo journalctl -u smtp-tunnel -f
```

Stage 2 reverse mode uses `tunnel.connections` independent tunnel sessions. New SOCKS channels are assigned to the least-active reverse session. This improves aggregate throughput and concurrent flows when the network benefits from parallel streams. It does not stripe one TCP flow across multiple tunnels, so a single download or single TCP connection can still be limited by one tunnel session.

Final tested production target for this deployment:

```yaml
tunnel:
  connections: 20
  adaptive_connections: true
  min_connections: 8
  max_connections: 20
  scale_up_active_channels: 6
  scale_up_bytes_per_second: 524288
  scale_down_idle_seconds: 300
  session_start_interval_seconds: 2
  session_start_jitter_seconds: 5
  reconnect_global_backoff: true
  reconnect_circuit_breaker_failures: 10
  reconnect_circuit_breaker_window_seconds: 120
  reconnect_circuit_breaker_cooldown: 300
  idle_session_recycle: false
  connect_timeout: 10

performance:
  profile: throughput

metrics:
  enabled: true
  log_interval: 30
  verbose: false

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

Raw port behavior matters. In this deployment, port `8443` tested better than `587`, and adaptive `8-20` sessions is the recommended daily production setting. Fixed `20` sessions gave the best always-on load performance but has a larger idle footprint. If maximum speed is required temporarily, use fixed `20`; if upload degrades, lower `max_connections` to `16`.

Connection-count guidance from deployment testing:

- `4`: conservative
- `8`: improved aggregate throughput
- `12`: good balance
- `16`: high performance
- `20`: recommended production value for this deployment
- `24`: experimental; may improve download but can hurt upload and increase noise
- `>24`: not recommended without explicit testing

Fixed high-speed mode:

```bash
sudo bash ./install.sh --role server --mode reverse-dial \
  --connections 20 \
  --no-adaptive-connections \
  --performance-profile throughput \
  --migrate-config --non-interactive
```

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

Adaptive scale-down is based on user DATA bytes and channel open/close activity.
Keepalive/control frames can increase diagnostic `bytes_in` and `bytes_out`, but
they do not keep the tunnel "busy" for adaptive scale decisions.

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
sudo ss -tinp | grep ':8443'
```

Raw reverse-port baseline test:

```bash
# Access Node
sudo systemctl stop smtp-tunnel
sudo iperf3 -s -p PORT --one-off

# Exit Node
iperf3 -c ACCESS_IP -p PORT -P 4 -t 20
```

Recommended ports to compare: `587`, `8443`, `2525`, `5202`, and `443` if free. The tunnel cannot exceed a bad raw path. Server-side HTTP endpoints such as Cloudflare speed tests can rate-limit concurrent curls with HTTP `429`, so treat those results as endpoint-limited when they return tiny byte counts. Mobile speed tests may differ from server-side multi-flow tests, and upload/download can behave differently.

Verify the production reverse session count:

```bash
sudo ss -tnp | grep ':8443' | wc -l
```

Expected value with `tunnel.connections: 20` is `20`.

Production status log:

```bash
sudo journalctl -u smtp-tunnel -f | grep -iE 'Reverse status|disconnect|reconnect|failure'
```

Expected steady state: `active=20` and `failures=0`.

Troubleshooting:

- If phone download is low but 20 sessions are active, the app may not use enough parallel flows.
- If upload is low, try lowering `tunnel.connections` to `16`.
- If `active` drops below the configured count, inspect firewall and reconnect logs.
- If failures increase, lower from `20` to `16` and retest.
- If one single download remains slow, future single-flow striping is the relevant optional work.

Let's Encrypt renewal test:

```bash
sudo certbot renew --dry-run
```

DNS-01/manual mode is available with `--reverse-cert-mode letsencrypt --letsencrypt-challenge dns-01`. It requires DNS control. DNS API provider plugins are not automated in Stage 1.

Private CA fallback is available with `--reverse-cert-mode private-ca`. Copy the generated public CA from the Access Node or use the exported reverse-dial bundle, then install the VPS with `--tls-verify-mode private-ca --reverse-ca-cert /path/to/ca.crt`.

Reverse-dial bundles do not include the reverse auth secret unless you explicitly pass `--include-reverse-secret` or answer yes to the installer prompt. Bundles never include the Access Node TLS private key, Let's Encrypt `privkey.pem`, `users.yaml`, or unrelated secrets.

---

# Production Reverse Migration

To migrate an existing reverse-listen Access Node to the tested production port/profile without replacing TLS settings, credentials, SOCKS settings, or Let's Encrypt paths:

```bash
curl -fsSL https://raw.githubusercontent.com/AlirezaKF/smtp-tunnel-proxy/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role client \
  --mode reverse-listen \
  --repo AlirezaKF/smtp-tunnel-proxy \
  --ref main \
  --reverse-port 8443 \
  --performance-profile throughput \
  --migrate-config \
  --non-interactive
```

To migrate an existing reverse-dial Exit Node:

```bash
curl -fsSL https://raw.githubusercontent.com/AlirezaKF/smtp-tunnel-proxy/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role server \
  --mode reverse-dial \
  --repo AlirezaKF/smtp-tunnel-proxy \
  --ref main \
  --reverse-port 8443 \
  --connections 20 \
  --performance-profile throughput \
  --migrate-config \
  --non-interactive
```

The migration path only changes the requested reverse port, `tunnel.connections` on reverse-dial when passed, `performance.profile` when passed, and missing runtime defaults under `metrics`, `logging`, `transport`, and `tunnel.connect_timeout`.

You can also use the preset flag in reverse mode:

```bash
sudo bash ./install.sh --role server --mode reverse-dial --production-reverse-tuning --migrate-config --non-interactive
```

`--production-reverse-tuning` sets `performance.profile: throughput`; for reverse-dial it also sets `tunnel.connections: 20` unless `--connections` was explicitly provided.

---

# VPS IP Change Without Reinstall

Changing the foreign VPS public IP does not require reinstalling the tunnel. On the Access Node, update only `client.reverse.allowed_dialer_ips` in `/etc/smtp-tunnel/config.yaml`, then allow the new VPS IP in the firewall:

```bash
sudo ufw allow from NEW_VPS_IP to any port 8443 proto tcp
sudo systemctl restart smtp-tunnel
```

Then restart the Exit Node service:

```bash
sudo systemctl restart smtp-tunnel
```

Verify:

```bash
sudo ss -tnp | grep ':8443'
sudo journalctl -u smtp-tunnel -f | grep -iE 'Reverse status|disconnect|reconnect|failure'
```

Do not rewrite reverse domain, certificate paths, Let's Encrypt settings, username, secret file path, SOCKS host/port, or performance profile for an IP-only VPS change.

Path checks:

```bash
nc -vz -w5 ACCESS_DOMAIN 8443
sudo tcpdump -ni any host VPS_IP and port 8443
```

ICMP/ping alone is not conclusive.

---

# Clean Reverse Reinstall

Preserve only the shared reverse secret before a clean reinstall:

```bash
sudo mkdir -p /root/smtp-tunnel-keep
sudo cp /etc/smtp-tunnel/reverse.secret /root/smtp-tunnel-keep/reverse.secret
sudo chmod 600 /root/smtp-tunnel-keep/reverse.secret
```

Clean removal:

```bash
sudo systemctl stop smtp-tunnel 2>/dev/null || true
sudo systemctl disable smtp-tunnel 2>/dev/null || true
sudo rm -f /etc/systemd/system/smtp-tunnel.service
sudo rm -rf /opt/smtp-tunnel
sudo rm -rf /etc/smtp-tunnel
sudo rm -rf /var/log/smtp-tunnel
sudo rm -f /usr/local/bin/smtp-tunnel-*
sudo systemctl daemon-reload
sudo systemctl reset-failed
```

Do not remove `/etc/letsencrypt`, Xray/3x-ui files, or `/root/smtp-tunnel-keep/reverse.secret` during tunnel reinstall.

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
