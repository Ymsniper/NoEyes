#!/bin/bash
# NoEyes Firewall Setup Script
# This script helps configure firewall rules for NoEyes server

PORT=5000

echo "=========================================="
echo "NoEyes Firewall Configuration Helper"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  This script needs sudo privileges to configure firewall."
    echo "Please run: sudo bash setup_firewall.sh"
    exit 1
fi

# Check firewall status
echo "📊 Checking firewall status..."
if command -v ufw &> /dev/null; then
    echo "Detected: UFW firewall"
    ufw status | head -5
    
    echo ""
    echo "🔧 Configuring UFW firewall..."
    echo "   Allowing port $PORT for NoEyes server..."
    ufw allow $PORT/tcp comment "NoEyes chat server"
    
    echo ""
    echo "✅ Firewall rule added!"
    echo ""
    echo "Current firewall status:"
    ufw status numbered | grep -E "(Status|$PORT)"
    
elif command -v firewall-cmd &> /dev/null; then
    echo "Detected: firewalld"
    echo "🔧 Configuring firewalld..."
    firewall-cmd --permanent --add-port=$PORT/tcp
    firewall-cmd --reload
    echo "✅ Firewall rule added!"
    
elif command -v iptables &> /dev/null; then
    echo "Detected: iptables"
    echo "🔧 Configuring iptables..."
    iptables -I INPUT -p tcp --dport $PORT -j ACCEPT
    echo "✅ Firewall rule added!"
    echo "⚠️  Note: iptables rules are temporary. To make permanent, save them."
    
else
    echo "❌ No common firewall tool detected (ufw/firewalld/iptables)"
    echo "   You may need to configure firewall manually."
fi

echo ""
echo "=========================================="
echo "Next Steps:"
echo "=========================================="
echo "1. Find your PC's IP address:"
echo "   Local IP: ip addr show | grep 'inet '"
echo ""
echo "2. Test connection from phone:"
echo "   python test_connection.py YOUR_PC_IP 5000"
echo ""
echo "3. If still not working, check:"
echo "   - Are both devices on same WiFi? (use local IP)"
echo "   - If different networks, configure port forwarding"
echo ""
