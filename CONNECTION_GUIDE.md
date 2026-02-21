# NoEyes Connection Troubleshooting Guide

## Quick Fix Steps

### Step 1: Configure Firewall on PC (Linux)

**Option A: Using UFW (Ubuntu/Debian/Kali)**
```bash
sudo ufw allow 5000/tcp
sudo ufw status  # Verify it's active
```

**Option B: Using the setup script**
```bash
sudo bash setup_firewall.sh
```

**Option C: Manual iptables (if UFW not available)**
```bash
sudo iptables -I INPUT -p tcp --dport 5000 -j ACCEPT
# To make permanent (Debian/Ubuntu):
sudo apt-get install iptables-persistent
sudo netfilter-persistent save
```

### Step 2: Determine Your Network Setup

**Are both devices on the SAME WiFi network?**
- ✅ YES → Use **local IP** (192.168.x.x) - Skip port forwarding
- ❌ NO → Use **public IP** + port forwarding (see Step 3)

**Find your PC's local IP:**
```bash
ip addr show | grep 'inet ' | grep -v '127.0.0.1'
# or
hostname -I
```

Example output: `inet 192.168.1.100/24` → Your IP is `192.168.1.100`

### Step 3: Port Forwarding (Only if Different Networks)

**When you need port forwarding:**
- Phone on mobile data + PC on WiFi
- Phone on WiFi A + PC on WiFi B
- Any scenario where devices are on different networks

**How to set up port forwarding:**

1. **Find your router's admin IP:**
   ```bash
   ip route | grep default
   # Usually 192.168.1.1 or 192.168.0.1
   ```

2. **Access router admin panel:**
   - Open browser: `http://192.168.1.1` (or your router IP)
   - Login (check router label for default username/password)

3. **Configure port forwarding:**
   - Look for: "Port Forwarding", "Virtual Server", "NAT", or "Applications & Gaming"
   - Add rule:
     - **External Port:** 5000
     - **Internal IP:** Your PC's local IP (e.g., 192.168.1.100)
     - **Internal Port:** 5000
     - **Protocol:** TCP
     - **Name:** NoEyes

4. **Find your public IP:**
   ```bash
   curl ifconfig.me
   # or visit: https://whatismyip.com
   ```

5. **Connect from phone:**
   ```bash
   python noeyes.py --connect YOUR_PUBLIC_IP --port 5000
   ```

### Step 4: Test Connection

**On PC (server):**
```bash
python noeyes.py --server --port 5000
```

**On phone (test first):**
```bash
python test_connection.py YOUR_PC_IP 5000
```

**If test succeeds but NoEyes doesn't work:**
- Check passphrase matches
- Check server is actually running
- Try restarting both server and client

## Common Issues & Solutions

### Issue: "Connection refused" (Errno 111)
**Causes:**
- Firewall blocking port
- Server not running
- Wrong IP address

**Fix:**
1. Check server is running: `netstat -tuln | grep 5000`
2. Configure firewall (Step 1)
3. Verify IP address

### Issue: "Connection timed out"
**Causes:**
- Firewall blocking
- Port forwarding not configured (if different networks)
- Mobile carrier blocking (if phone on mobile data)

**Fix:**
1. Configure firewall (Step 1)
2. If different networks: Set up port forwarding (Step 3)
3. Use WiFi on phone, not mobile data

### Issue: Works on same PC but not from phone
**Causes:**
- Firewall blocking external connections
- Using 127.0.0.1 instead of local IP

**Fix:**
1. Use PC's local IP (192.168.x.x), not 127.0.0.1
2. Configure firewall to allow external connections
3. Ensure both devices on same WiFi

## Quick Checklist

- [ ] Firewall allows port 5000
- [ ] Server is running (`python noeyes.py --server`)
- [ ] Using correct IP address (local for same WiFi, public for different networks)
- [ ] Port forwarding configured (if different networks)
- [ ] Both devices using same passphrase
- [ ] Phone is on WiFi (not mobile data) if acting as server

## Testing Commands

**Check if port is open (from phone):**
```bash
nc -zv PC_IP 5000
# or
telnet PC_IP 5000
```

**Check if server is listening (on PC):**
```bash
netstat -tuln | grep 5000
# Should show: tcp 0.0.0.0:5000 LISTEN
```

**Check firewall status (on PC):**
```bash
sudo ufw status
# Should show: 5000/tcp ALLOW
```
