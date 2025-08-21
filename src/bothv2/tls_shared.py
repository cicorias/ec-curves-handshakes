# tls_shared.py
import hashlib
import hmac
import os
import base64

# --- Toy transcript hash ---
def transcript_hash(messages):
    """Hash concatenated handshake messages (toy SHA-256)."""
    m = hashlib.sha256()
    for msg in messages:
        m.update(msg.encode())
    return m.digest()

# --- Toy PRF (HKDF-like) ---
def toy_prf(secret, label, seed, out_len=32):
    """
    Simplified PRF using HMAC-SHA256.
    secret: key material
    label: string
    seed: context (usually transcript hash)
    """
    return hmac.new(secret, label.encode() + seed, hashlib.sha256).digest()[:out_len]

# --- Toy MAC ---
def compute_mac(key, message):
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

def verify_mac(key, message, mac_hex):
    expected = compute_mac(key, message)
    return hmac.compare_digest(expected, mac_hex)

# --- Mock Ed25519 keys ---
def generate_mock_ed25519_keypair():
    priv = os.urandom(32)
    pub = hashlib.sha256(priv).digest()
    return priv, pub

def sign_with_mock_ed25519(priv, message):
    return hmac.new(priv, message, hashlib.sha256).digest()

def verify_with_mock_ed25519(pub, message, signature):
    expected = hashlib.sha256(pub + message).digest()[:len(signature)]
    return expected == signature

# --- Pretty print helpers ---
def b64(b):
    return base64.b64encode(b).decode()
