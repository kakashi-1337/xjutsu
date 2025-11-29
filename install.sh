#!/bin/bash
#
# XJutsu v5 - One-Click Installer
# by Dave Lester B. Mondina / ANBU Black Ops Security
#
# Usage: curl -sSL https://raw.githubusercontent.com/kakashi-1337/xjutsu/main/install.sh | bash
# Or: chmod +x install.sh && ./install.sh
#

set -e

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     XJutsu v5 - XSS Hunter Framework Installer            ║"
echo "║     by Dave Lester B. Mondina / ANBU Black Ops Security   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] Running without root. Some commands may need sudo.${NC}"
fi

echo -e "${GREEN}[1/8] Updating system packages...${NC}"
apt update -y

echo -e "${GREEN}[2/8] Installing Python and dependencies...${NC}"
apt install -y python3 python3-pip python3-venv git curl nginx

echo -e "${GREEN}[3/8] Installing Docker...${NC}"
# Install Docker if not present
if ! command -v docker &> /dev/null; then
    apt install -y ca-certificates gnupg
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null || true
    chmod a+r /etc/apt/keyrings/docker.gpg 2>/dev/null || true
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
      tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt update -y
    apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || {
        echo -e "${YELLOW}[!] Docker CE install failed, trying docker.io...${NC}"
        apt install -y docker.io docker-compose
    }
    systemctl start docker
    systemctl enable docker
    echo -e "${GREEN}[+] Docker installed successfully${NC}"
else
    echo -e "${CYAN}[*] Docker already installed${NC}"
fi

echo -e "${GREEN}[4/8] Finding XJutsu directory...${NC}"
cd /home/*/xjutsu 2>/dev/null || cd ~/xjutsu 2>/dev/null || cd xjutsu 2>/dev/null || {
    echo -e "${RED}[!] XJutsu directory not found. Please clone first:${NC}"
    echo "    git clone https://github.com/kakashi-1337/xjutsu.git"
    exit 1
}
echo -e "${CYAN}[*] Working in: $(pwd)${NC}"

echo -e "${GREEN}[5/8] Creating virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

echo -e "${GREEN}[6/8] Installing Python packages...${NC}"
pip install --upgrade pip
pip install django==4.2
pip install channels channels-redis
pip install requests beautifulsoup4 lxml
pip install gunicorn uvicorn
pip install python-dotenv
pip install whitenoise  # Static files

echo -e "${GREEN}[7/8] Setting up environment...${NC}"
if [ ! -f .env ]; then
    SECRET=$(openssl rand -hex 32)
    cat > .env << ENVEOF
DEBUG=False
SECRET_KEY=xjutsu-${SECRET}
SHORT_DOMAIN=6u.gg
ALLOWED_HOSTS=*
DATABASE_URL=sqlite:///xjutsu.db
ENVEOF
    echo -e "${YELLOW}[!] Created .env file. Edit SHORT_DOMAIN to your domain!${NC}"
else
    echo -e "${CYAN}[*] .env file already exists${NC}"
fi

echo -e "${GREEN}[8/8] Running migrations...${NC}"
python manage.py migrate --run-syncdb

echo ""
echo -e "${YELLOW}Create admin account (or skip if exists):${NC}"
python manage.py createsuperuser --username admin --email admin@xjutsu.local 2>/dev/null || {
    echo -e "${CYAN}[*] Superuser may already exist. Skipping...${NC}"
}

# Start Redis container for WebSocket support
echo ""
echo -e "${GREEN}[+] Starting Redis container...${NC}"
docker run -d --name xjutsu-redis -p 6379:6379 --restart unless-stopped redis:alpine 2>/dev/null || {
    echo -e "${CYAN}[*] Redis container may already be running${NC}"
}

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     XJutsu v5 - Installation Complete!                    ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}To start the server:${NC}"
echo "  cd $(pwd)"
echo "  source venv/bin/activate"
echo "  python manage.py runserver 0.0.0.0:8000"
echo ""
echo -e "${GREEN}Or for production:${NC}"
echo "  gunicorn core.wsgi:application -b 0.0.0.0:8000"
echo ""
echo -e "${GREEN}Access dashboard:${NC}"
echo "  http://YOUR-IP:8000/dashboard/"
echo ""
echo -e "${YELLOW}Don't forget to:${NC}"
echo "  1. Edit .env and set SHORT_DOMAIN to your domain (e.g., 6u.gg)"
echo "  2. Point your domain DNS to this server"
echo "  3. Setup nginx reverse proxy for HTTPS"
echo ""
echo -e "${GREEN}Happy hunting! 🥷${NC}"
