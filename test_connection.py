#!/usr/bin/env python3
"""
Quick connectivity test for NoEyes server.
Run this on the client device to test if the server port is reachable.
"""

import socket
import sys

def test_connection(host: str, port: int) -> None:
    """Test if a TCP connection can be established."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            print(f"✅ SUCCESS: Port {port} is open on {host}")
        else:
            print(f"❌ FAILED: Cannot connect to {host}:{port}")
            print(f"   Error code: {result}")
            print("\nPossible issues:")
            print("  - Server is not running")
            print("  - Firewall is blocking the port")
            print("  - Wrong IP address")
            print("  - Port forwarding not configured")
            sys.exit(1)
    except socket.timeout:
        print(f"⏱️  TIMEOUT: Connection to {host}:{port} timed out")
        print("\nPossible issues:")
        print("  - Server is not running")
        print("  - Firewall is blocking the port")
        print("  - Network routing issue")
        sys.exit(1)
    except Exception as e:
        print(f"❌ ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python test_connection.py HOST PORT")
        print("Example: python test_connection.py 192.168.1.100 5000")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    test_connection(host, port)
