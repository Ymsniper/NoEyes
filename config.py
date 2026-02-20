"""
Configuration for the NoEyes secure terminal chat tool.

This module centralizes constants so they can be reused by the
server, client and encryption modules.
"""

DEFAULT_PORT: int = 5000
BUFFER_SIZE: int = 4096
ENCODING: str = "utf-8"

# Cryptography / key-derivation settings
KDF_ITERATIONS: int = 390_000

# In a real system this salt should be random and secret per deployment.
# For this academic project we use a fixed salt so all participants can
# derive the same key from the same passphrase.
KDF_SALT: bytes = b"noeyes-static-salt-v1"

# Default values
DEFAULT_SERVER_HOST: str = "0.0.0.0"

