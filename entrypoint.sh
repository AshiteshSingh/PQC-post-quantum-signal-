#!/bin/sh
set -e

APP_PORT="${PORT:-8000}"

echo "======================================================================"
echo " [+] INITIALIZING PQ-RATCHET DUAL-PLANE DAEMON (CLEARNET + TOR ONION) "
echo "======================================================================"

# Prepare Tor directories and permissions
mkdir -p /var/lib/tor/hidden_service
chmod 700 /var/lib/tor/hidden_service
chown -R debian-tor:debian-tor /var/lib/tor

# Generate dynamic torrc pointing port 80 to the application port
cat <<EOF > /etc/tor/torrc
User debian-tor
DataDirectory /var/lib/tor
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServiceVersion 3
HiddenServicePort 80 127.0.0.1:${APP_PORT}
EOF

# Start Tor daemon in background
echo "[+] Starting Tor v3 onion service daemon..."
tor -f /etc/tor/torrc --runasdaemon 1

# Wait for Tor to publish and generate hostname
echo "[+] Awaiting Tor v3 cryptographic address generation..."
for i in $(seq 1 45); do
  if [ -s /var/lib/tor/hidden_service/hostname ]; then
    break
  fi
  sleep 1
done

if [ -s /var/lib/tor/hidden_service/hostname ]; then
  ONION_ADDR=$(cat /var/lib/tor/hidden_service/hostname)
  echo ""
  echo "======================================================================"
  echo " [!] TOR ONION SERVICE IS ONLINE AND REACHABLE!"
  echo " [!] ONION URL (Tor Browser only):  http://${ONION_ADDR}"
  echo " [!] CLEARNET URL (Render Web):     https://pqc-post-quantum-signal.onrender.com"
  echo " [!] LOCAL LISTENER:               0.0.0.0:${APP_PORT}"
  echo "======================================================================"
  echo ""
else
  echo "[!] Notice: Tor hostname file is still initializing in the background."
fi

# Launch PQ-Ratchet web server
exec pq-ratchet web --host 0.0.0.0 --port "${APP_PORT}" --allow-insecure-http
