#!/bin/bash
# NoEyes Connection Troubleshooting Script

echo "=========================================="
echo "NoEyes Connection Troubleshooting"
echo "=========================================="
echo ""

# Check if server is running
echo "1. Checking if server is listening on port 5000..."
if netstat -tuln 2>/dev/null | grep -q ":5000"; then
    echo "   ✅ Server is listening on port 5000"
    netstat -tuln | grep ":5000"
else
    echo "   ❌ Server is NOT listening on port 5000"
    echo "   → Start server: python noeyes.py --server --port 5000"
fi
echo ""

# Check firewall
echo "2. Checking firewall status..."
if command -v ufw &> /dev/null; then
    if ufw status | grep -q "5000/tcp"; then
        echo "   ✅ Firewall allows port 5000"
    else
        echo "   ⚠️  Firewall may be blocking port 5000"
        echo "   → Run: sudo ufw allow 5000/tcp"
    fi
    ufw status | grep -E "(Status|5000)" || echo "   Firewall status unknown"
else
    echo "   ⚠️  UFW not found, check firewall manually"
fi
echo ""

# Check local IP
echo "3. Your PC's local IP address:"
LOCAL_IP=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d'/' -f1 | head -1)
if [ -n "$LOCAL_IP" ]; then
    echo "   Local IP: $LOCAL_IP"
    if [ "$LOCAL_IP" = "192.168.1.105" ]; then
        echo "   ✅ Matches port forwarding rule (192.168.1.105)"
    else
        echo "   ⚠️  WARNING: Does NOT match port forwarding LAN IP (192.168.1.105)"
        echo "   → Update port forwarding rule to use: $LOCAL_IP"
    fi
else
    echo "   ❌ Could not determine local IP"
fi
echo ""

# Get public IP
echo "4. Your public IP address:"
PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null)
if [ -n "$PUBLIC_IP" ]; then
    echo "   Public IP: $PUBLIC_IP"
    echo "   → Connect from phone using: python noeyes.py --connect $PUBLIC_IP --port 5000"
else
    echo "   ⚠️  Could not determine public IP (check internet connection)"
fi
echo ""

# Test local connection
echo "5. Testing local connection..."
if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/5000" 2>/dev/null; then
    echo "   ✅ Local connection works (server is responding)"
else
    echo "   ❌ Local connection failed (server may not be running)"
fi
echo ""

echo "=========================================="
echo "Common Issues:"
echo "=========================================="
echo "• Is server running? Check step 1"
echo "• Is firewall allowing port 5000? Check step 2"
echo "• Is local IP correct? Check step 3"
echo "• Is phone on mobile data? Try WiFi instead"
echo "• Router may have firewall blocking incoming connections"
echo ""
