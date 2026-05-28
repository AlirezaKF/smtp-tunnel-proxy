# SMTP Tunnel Proxy — راهنمای نصب و استفاده

SMTP Tunnel Proxy یک تانل TCP با SOCKS5 محلی است که اتصال بین کلاینت و سرور را داخل یک اتصال SMTP-like / STARTTLS منتقل می‌کند.

معماری پیش‌فرض پروژه:

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

این نسخه **reverse mode ندارد**. یعنی سرور خارجی به کلاینت وصل نمی‌شود. کلاینت به VPS وصل می‌شود و چندین اتصال SOCKS5 داخل همان tunnel multiplex می‌شوند.

> هیچ تانلی نمی‌تواند تضمین کند که توسط DPI یا firewall شناسایی یا بلاک نمی‌شود. هدف این پروژه پایداری بهتر، تنظیم‌پذیری بهتر، و حذف fingerprintهای واضح است.

---

## مقدارهایی که باید جایگزین شوند

در این راهنما از placeholder استفاده شده است. قبل از اجرای دستورها، این مقادیر را با اطلاعات خودت جایگزین کن:

```text
GITHUB_USER/REPO_NAME    مسیر repo در GitHub
YOUR_DOMAIN              دامنه یا hostname متعلق به VPS
IRAN_SERVER_IP           آی‌پی سرور کلاینت
USERNAME                 نام کاربر tunnel، مثل client1
```

نمونه:

```text
YOUR_DOMAIN = mail.example.com
USERNAME = client1
```

از دامنه‌هایی مثل `gmail.com`، `outlook.com` یا هر دامنه‌ای که مالک آن نیستی استفاده نکن.

---

## مسیرهای نصب

بعد از نصب:

```text
/opt/smtp-tunnel/                  فایل‌های برنامه
/opt/smtp-tunnel/venv/             Python virtualenv
/etc/smtp-tunnel/config.yaml       کانفیگ اصلی
/etc/smtp-tunnel/users.yaml        کاربران و secretها
/etc/smtp-tunnel/certs/            CA و certificateها
/etc/systemd/system/smtp-tunnel.service
/var/backups/smtp-tunnel/          بکاپ‌ها و rollback.sh
/usr/local/bin/smtp-tunnel-adduser
/usr/local/bin/smtp-tunnel-deluser
/usr/local/bin/smtp-tunnel-listusers
/usr/local/bin/smtp-tunnel-update
```

---

## پیش‌نیازها

روی VPS خارجی:

```text
Ubuntu/Debian Linux
Python 3.8+
Port 587 باز باشد
یک دامنه یا hostname بهتر است داشته باشی
```

روی سرور کلاینت:

```text
Ubuntu/Debian Linux
دسترسی root یا sudo
پورت محلی SOCKS آزاد باشد، معمولاً 127.0.0.1:1080
```

---

# نصب از صفر روی VPS خارجی، یعنی Server

اگر می‌خواهی نصب کاملاً تمیز باشد، اول نصب قبلی را پاک کن:

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

اگر دستور آخر خروجی نداد، پورت 587 آزاد است.

نصب server:

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

هنگام نصب، username را ساده انتخاب کن:

```text
client1
client2
iran1
```

secret می‌تواند پیچیده باشد، ولی username بهتر است ساده باشد.

---

## جواب‌های پیشنهادی در نصب interactive سرور

اگر installer سؤال پرسید:

```text
systemd service name: Enter
server listen host: Enter
server listen port: Enter
public hostname/domain: YOUR_DOMAIN
EHLO name: Enter
Generate private CA and server certificate now? y
Create the first user now? y
username: USERNAME
secret: Enter برای auto-generate یا secret قوی دستی
Export a client bundle to /root for this user? y
```

بعد از نصب موفق باید این‌ها را ببینی:

```text
Generating private CA and server certificate
OK: server config is valid
Service is active: smtp-tunnel
Client service bundle created
```

---

## چک کردن Server

روی VPS:

```bash
sudo systemctl status smtp-tunnel --no-pager
sudo journalctl -u smtp-tunnel -n 100 --no-pager
sudo ss -ltnp | grep ':587' || true
sudo ls -lh /etc/smtp-tunnel/certs/
ls -lh /root/smtp-tunnel-client-*.tar.gz
```

Validation:

```bash
sudo /opt/smtp-tunnel/venv/bin/python /opt/smtp-tunnel/server.py \
  -c /etc/smtp-tunnel/config.yaml \
  --check
```

خروجی درست:

```text
OK: server config is valid
```

---

# ساخت کاربر جدید روی Server

برای ساخت کاربر جدید:

```bash
cd /opt/smtp-tunnel
sudo ./smtp-tunnel-adduser USERNAME --output-dir /root
sudo systemctl restart smtp-tunnel
```

اگر wrapper درست نصب شده باشد:

```bash
sudo smtp-tunnel-adduser USERNAME --output-dir /root
sudo systemctl restart smtp-tunnel
```

فایل package ساخته می‌شود:

```text
/root/smtp-tunnel-client-USERNAME.tar.gz
```

لیست کاربران:

```bash
sudo smtp-tunnel-listusers
```

حذف کاربر:

```bash
sudo smtp-tunnel-deluser USERNAME
sudo systemctl restart smtp-tunnel
```

نکته: سرور `users.yaml` را هنگام startup می‌خواند، پس بعد از add/delete کردن user باید سرویس restart شود.

---

# کپی package به سرور کلاینت

روی VPS:

```bash
scp /root/smtp-tunnel-client-USERNAME.tar.gz root@IRAN_SERVER_IP:/root/
```

اگر نام فایل فرق داشت:

```bash
ls -lh /root/smtp-tunnel-client-*.tar.gz
```

---

# نصب از صفر روی سرور کلاینت

اول نصب قبلی را پاک کن:

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

اگر پورت 1080 آزاد نبود، یا سرویس مزاحم را متوقف کن یا در نصب client پورت SOCKS دیگری بده.

نصب client از package:

```bash
curl -fsSL https://raw.githubusercontent.com/GITHUB_USER/REPO_NAME/main/scripts/bootstrap.sh -o /root/bootstrap.sh

sudo bash /root/bootstrap.sh \
  --role client \
  --repo GITHUB_USER/REPO_NAME \
  --ref main \
  --from-package /root/smtp-tunnel-client-USERNAME.tar.gz
```

---

## چک کردن Client

روی سرور کلاینت:

```bash
sudo systemctl status smtp-tunnel --no-pager
sudo journalctl -u smtp-tunnel -n 100 --no-pager
sudo ss -ltnp | grep ':1080' || true
```

Validation:

```bash
sudo /opt/smtp-tunnel/venv/bin/python /opt/smtp-tunnel/client.py \
  -c /etc/smtp-tunnel/config.yaml \
  --check
```

---

# تست اتصال SOCKS

روی سرور کلاینت:

```bash
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me
```

تست همزمان:

```bash
for i in 1 2 3 4 5; do
  curl -x socks5h://127.0.0.1:1080 https://ifconfig.me &
done
wait
```

اگر IP خروجی نشان داده شد، tunnel کار می‌کند.

---

# تنظیم V2Ray

در V2Ray، outbound یا proxy را روی SOCKS5 محلی بگذار:

```text
SOCKS host: 127.0.0.1
SOCKS port: 1080
SOCKS version: 5
```

برای curl بهتر است از `socks5h` استفاده شود تا DNS هم از سمت proxy انجام شود:

```bash
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me
```

---

# مدیریت سرویس

روی هر دو سرور:

```bash
sudo systemctl status smtp-tunnel --no-pager
sudo systemctl restart smtp-tunnel
sudo systemctl stop smtp-tunnel
sudo systemctl start smtp-tunnel
sudo journalctl -u smtp-tunnel -f
```

فعال‌سازی در boot:

```bash
sudo systemctl enable smtp-tunnel
```

---

# آپدیت نصب موجود

برای آپدیت بدون پاک کردن config و secretها:

روی server:

```bash
curl -fsSL https://raw.githubusercontent.com/GITHUB_USER/REPO_NAME/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role server \
  --repo GITHUB_USER/REPO_NAME \
  --ref main \
  --non-interactive
```

روی client:

```bash
curl -fsSL https://raw.githubusercontent.com/GITHUB_USER/REPO_NAME/main/scripts/bootstrap.sh | sudo bash -s -- \
  --role client \
  --repo GITHUB_USER/REPO_NAME \
  --ref main \
  --non-interactive
```

Installer قبل از جایگزینی فایل‌ها backup می‌سازد.

---

# Rollback

اگر نصب یا آپدیت خراب شد، installer مسیر backup را چاپ می‌کند، مثلاً:

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

# تنظیمات مهم config

مسیر config:

```text
/etc/smtp-tunnel/config.yaml
```

تنظیمات پیشنهادی برای نصب جدید:

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

برای `smtp.ehlo_name` از دامنه یا hostname خودت استفاده کن.

---

# Certificate و TLS

Server certificate و CA در این مسیر ساخته می‌شوند:

```text
/etc/smtp-tunnel/certs/
```

فایل‌های مهم:

```text
ca.crt
ca.key
server.crt
server.key
```

برای client فقط `ca.crt` لازم است.

فایل‌های زیر را روی GitHub نگذار:

```text
ca.key
server.key
users.yaml واقعی
config.yaml واقعی دارای secret
client packageهای واقعی
secret fileها
```

---

# عیب‌یابی

## سرویس بالا نمی‌آید

```bash
sudo systemctl status smtp-tunnel --no-pager
sudo journalctl -u smtp-tunnel -n 150 --no-pager
```

## پورت server باز نیست

روی VPS:

```bash
sudo ss -ltnp | grep ':587' || true
```

## پورت client باز نیست

روی سرور کلاینت:

```bash
sudo ss -ltnp | grep ':1080' || true
```

## خطای certificate

روی server:

```bash
sudo ls -lh /etc/smtp-tunnel/certs/
```

باید این‌ها وجود داشته باشند:

```text
ca.crt
server.crt
server.key
```

اگر نبودند:

```bash
sudo mkdir -p /etc/smtp-tunnel/certs

sudo /opt/smtp-tunnel/venv/bin/python /opt/smtp-tunnel/generate_certs.py \
  --hostname YOUR_DOMAIN \
  --output-dir /etc/smtp-tunnel/certs

sudo systemctl restart smtp-tunnel
```

## Auth failed

روی server:

```bash
sudo smtp-tunnel-listusers
sudo journalctl -u smtp-tunnel -n 100 --no-pager
```

بعد از اضافه کردن user جدید:

```bash
sudo systemctl restart smtp-tunnel
```

## Package ناقص ساخته شده

اگر هنگام ساخت user این هشدارها را دیدی:

```text
client.py not found
common.py not found
requirements.txt not found
```

از مسیر درست اجرا کن:

```bash
cd /opt/smtp-tunnel
sudo ./smtp-tunnel-adduser USERNAME --output-dir /root
```

بعد:

```bash
tar -tzf /root/smtp-tunnel-client-USERNAME.tar.gz | head -50
```

---

# خطای شناخته‌شده فعلی

ممکن است بعد از نصب این خط دیده شود:

```text
workdir: unbound variable
```

اگر قبل از آن این‌ها آمده باشند:

```text
OK: server config is valid
Service is active: smtp-tunnel
Bootstrap complete
```

نصب انجام شده، ولی `scripts/bootstrap.sh` باید اصلاح شود تا در cleanup از متغیر تعریف‌نشده استفاده نکند.

---

# امنیت

- فایل `users.yaml` شامل secret کاربران است.
- فایل‌های private key را public نکن.
- برای production، secret را در command line ننویس.
- از package تولیدشده برای همان user استفاده کن.
- بعد از حذف یا اضافه کردن user، server را restart کن.
- repo عمومی نباید config واقعی، secret واقعی، key خصوصی یا package واقعی client داشته باشد.

---

# محدودیت‌ها

- این پروژه تضمین نمی‌کند اتصال هرگز شناسایی یا بلاک نمی‌شود.
- Python/OpenSSL TLS fingerprint همچنان قابل مشاهده است.
- رفتار long-lived TLS روی پورت SMTP-like ممکن است غیرعادی باشد.
- reverse mode در این نسخه پیاده‌سازی نشده است.
- استفاده از این ابزار باید مطابق قوانین و مجوزهای محیط خودت باشد.

---

# License

See `LICENSE`.
