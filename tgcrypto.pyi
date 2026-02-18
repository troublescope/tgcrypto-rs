def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-IGE Encryption"""
def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-IGE Decryption"""
def ctr256_encrypt(data: bytes, key: bytes, iv: bytes, state: int) -> bytes:
    """AES-256-CTR Encryption"""
def ctr256_decrypt(data: bytes, key: bytes, iv: bytes, state: int) -> bytes:
    """AES-256-CTR Decryption"""
def cbc256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC Encryption"""
def cbc256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC Decryption"""
def sha1(data: bytes) -> bytes:
    """Compute SHA-1 hash"""
def sha256(data: bytes) -> bytes:
    """Compute SHA-256 hash"""
def rsa_encrypt(data: bytes, fingerprint: int) -> bytes:
    """RSA encrypt using Telegram server public key"""
def factorize(pq: int) -> int:
    """Find a non-trivial factor using Pollard's rho algorithm"""
def get_session_id(auth_key: bytes) -> bytes:
    """Generate session ID from auth key"""
