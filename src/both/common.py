# common.py
# Toy helpers for a TLS 1.3-like educational handshake. NOT FOR REAL CRYPTO.

import hashlib, hmac, json, secrets

# -----------------------------
# Global toy params & constants
# -----------------------------
L = 97  # toy "group order" for our fake curve
SPACES64 = b"\x20" * 64
CTX_SERVER = b"TLS 1.3, server CertificateVerify"

# -----------------------------
# Hash / HMAC / PRF / HKDF-lite
# -----------------------------
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()

def PRF(secret: bytes, label: bytes, context: bytes = b"", outlen: int = 32) -> bytes:
    """
    Toy PRF (TLS-like): one-shot HMAC-SHA256(secret, label || context), truncated.
    """
    return hmac_sha256(secret, label + context)[:outlen]

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac_sha256(salt, ikm)

def hkdf_expand(prk: bytes, info: bytes, outlen: int = 32) -> bytes:
    """
    Minimal HKDF-Expand: single-block expand (good enough for demo / 32B).
    """
    return hmac_sha256(prk, info + b"\x01")[:outlen]

# -----------------------------
# Toy hash -> integer mod L
# -----------------------------
def H_modL(*parts: bytes) -> int:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return int.from_bytes(h.digest(), "big") % L

def enc_int(i: int, size=2) -> bytes:
    return i.to_bytes(size, "big", signed=False)

def enc_point(mult: int) -> bytes:
    # We model points as multiples of a base point B, encode that multiple.
    return enc_int(mult % L, size=2)

# -----------------------------
# Toy Ed25519-like signatures
# -----------------------------
class ToyEd25519:
    """
    DO NOT USE FOR REAL CRYPTO.
    Public key A is modeled as the integer multiple 'a' of base point B (A = a·B).
    Signature verifies by checking S·B == R + k·A as multiples mod L.
    """
    def __init__(self, secret_scalar_a: int, prefix: bytes):
        self.a = secret_scalar_a % L
        self.prefix = prefix
        self.A = self.a % L  # "public key" multiple

    def sign(self, M: bytes):
        # r = H(prefix || M) mod L; R = r·B (encode as multiple r)
        r = H_modL(self.prefix, M)
        R = r % L
        # k = H(enc(R) || enc(A) || M) mod L
        k = H_modL(enc_point(R), enc_point(self.A), M)
        # S = (r + k*a) mod L
        S = (r + k * self.a) % L
        return (R, S)

    @staticmethod
    def verify(M: bytes, A_multiple: int, sig):
        R, S = sig
        k = H_modL(enc_point(R), enc_point(A_multiple), M)
        left = S % L
        right = (R + (k * A_multiple) % L) % L
        return left == right

# -----------------------------
# Toy ECDHE (multiples of B)
# -----------------------------
def gen_eph_scalar() -> int:
    # random scalar in 1..L-1
    x = 0
    while x == 0:
        x = secrets.randbelow(L)
    return x

def dh_pub(x: int) -> int:
    return x % L

def dh_shared(priv: int, peer_pub_multiple: int) -> int:
    # shared multiple = priv * peer_pub (since pub is a multiple of B)
    return (priv * peer_pub_multiple) % L

def derive_handshake_secret(shared_multiple: int) -> bytes:
    """
    Derive a handshake secret from the toy shared multiple using HKDF (salt = zeros).
    """
    ikm = enc_int(shared_multiple, size=4)
    salt = b"\x00" * 32
    prk = hkdf_extract(salt, ikm)
    hs_secret = hkdf_expand(prk, b"toy hs secret", 32)
    return hs_secret

# -----------------------------
# Transcript (JSON-encoded)
# -----------------------------
class Transcript:
    """
    Running SHA-256 over JSON-encoded messages (stable: sort_keys + compact separators).
    Provides helper to recompute a digest up to a given index.
    """
    def __init__(self):
        self._msgs = []  # store dicts
        self._cache_digest = None  # optional cache of full digest

    @staticmethod
    def _serialize(msg: dict) -> bytes:
        return json.dumps(msg, sort_keys=True, separators=(",", ":")).encode()

    def add(self, typ: str, **fields):
        msg = {"type": typ, **fields}
        self._msgs.append(msg)
        self._cache_digest = None  # invalidate
        return msg

    @property
    def messages(self):
        return list(self._msgs)

    def digest(self) -> bytes:
        if self._cache_digest is None:
            h = hashlib.sha256()
            for m in self._msgs:
                h.update(self._serialize(m))
            self._cache_digest = h.digest()
        return self._cache_digest

    def digest_until(self, count: int) -> bytes:
        """
        Compute transcript hash of the first `count` messages (0..count-1).
        """
        h = hashlib.sha256()
        for i in range(min(count, len(self._msgs))):
            h.update(self._serialize(self._msgs[i]))
        return h.digest()

    def count(self) -> int:
        return len(self._msgs)

# -----------------------------
# Finished keys & MACs (toy)
# -----------------------------
def make_finished_key(handshake_secret: bytes, label: bytes, transcript_hash: bytes) -> bytes:
    """
    In real TLS 1.3, finished_key = HKDF-Expand-Label(base_secret, "finished", "", Hash.length).
    We keep it simple but *bind it to the transcript hash*:
      finished_key = PRF(handshake_secret, label, transcript_hash)
    """
    return PRF(handshake_secret, label, transcript_hash, outlen=32)

def make_finished_mac(finished_key: bytes, transcript_hash: bytes) -> bytes:
    """
    Finished MAC is HMAC over the transcript hash with the finished key.
    """
    return hmac_sha256(finished_key, transcript_hash)
