#!/usr/bin/env python3
import hashlib, json, secrets

# =========================
# Toy parameters / helpers
# =========================

L = 97  # toy group order (real Ed25519 has ~2^252-…)
SPACES64 = b"\x20" * 64
CTX_SERVER = b"TLS 1.3, server CertificateVerify"

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def H_modL(*parts: bytes) -> int:
    """Toy hash -> integer mod L."""
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return int.from_bytes(h.digest(), "big") % L

def enc_int(i: int, size=2) -> bytes:
    return i.to_bytes(size, "big")

def enc_point(mult: int) -> bytes:
    """We model points as multiples of base point B; encode that multiple."""
    return enc_int(mult % L, size=2)

# =========================
# Toy "Ed25519-like" keypair/sign/verify
# =========================

class ToyEd25519:
    """
    Do NOT use for real crypto.
    We represent points as integer multiples of base point B.
    Public key A = a * B is represented by integer 'a' modulo L.
    """

    def __init__(self, secret_scalar_a: int, prefix: bytes):
        self.a = secret_scalar_a % L    # secret scalar
        self.prefix = prefix            # deterministic nonce prefix
        self.A = self.a % L             # "public key" (the multiple), integer in [0, L-1]

    def sign(self, M: bytes):
        # r = H(prefix || M) mod L
        r = H_modL(self.prefix, M)
        R = r % L  # "point" multiple
        # k = H( enc(R) || enc(A) || M ) mod L
        k = H_modL(enc_point(R), enc_point(self.A), M)
        # S = (r + k*a) mod L
        S = (r + k * self.a) % L
        return R, S

    @staticmethod
    def verify(M: bytes, A: int, sig):
        R, S = sig
        # recompute k
        k = H_modL(enc_point(R), enc_point(A), M)
        # check: S·B == R + k·A  (since we model points as multiples, compare multiples mod L)
        left = S % L
        right = (R + (k * A) % L) % L
        return left == right

# =========================
# Toy ECDHE (multiples of B)
# =========================

def gen_eph_scalar() -> int:
    # choose random in [1, L-1]
    x = 0
    while x == 0:
        x = secrets.randbelow(L)
    return x

def dh_pub(x: int) -> int:
    # public share is x*B -> represented by multiple 'x'
    return x % L

def dh_shared(x_priv: int, peer_pub_multiple: int) -> int:
    # shared multiple = x_priv * peer_pub (since pub is already a multiple of B)
    return (x_priv * peer_pub_multiple) % L

def kdf(shared_multiple: int) -> bytes:
    # derive "keys" from the shared multiple (teaching only)
    return sha256(enc_int(shared_multiple, size=4))

# =========================
# Transcript helper
# =========================

class Transcript:
    def __init__(self):
        self._h = hashlib.sha256()

    def add(self, typ: str, **fields):
        msg = {"type": typ, **fields}
        blob = json.dumps(msg, sort_keys=True, separators=(",", ":")).encode()
        self._h.update(blob)
        return blob  # returning helps log/display

    @property
    def digest(self) -> bytes:
        return self._h.digest()

# =========================
# Roles
# =========================

class ToyServer:
    def __init__(self):
        # Fixed "certificate" keypair (teaching): a and prefix chosen arbitrarily
        self.cert = ToyEd25519(secret_scalar_a=29, prefix=b"\x0a\x0b")
        self.eph_priv = None
        self.eph_pub = None
        self.shared = None

    def on_client_hello(self, tr: Transcript, client_keyshare, sigalgs):
        # choose ed25519 and produce our ECDHE share
        self.eph_priv = gen_eph_scalar()
        self.eph_pub = dh_pub(self.eph_priv)

        tr.add("ServerHello",
               chosen_sigalg="ed25519",
               server_keyshare=self.eph_pub)

        tr.add("EncryptedExtensions", note="(empty for demo)")

        # "send" our certificate (just the public multiple A)
        tr.add("Certificate", ed25519_pubA=self.cert.A)

    def certificate_verify(self, tr: Transcript):
        # Compute the string to sign per TLS 1.3: 64 spaces || context || 0x00 || transcript_hash
        M = SPACES64 + CTX_SERVER + b"\x00" + tr.digest()
        R, S = self.cert.sign(M)
        tr.add("CertificateVerify", R=R, S=S)
        return (R, S)

    def compute_shared(self, client_keyshare):
        # derive shared from ECDHE
        self.shared = dh_shared(self.eph_priv, client_keyshare)
        return kdf(self.shared)

class ToyClient:
    def __init__(self):
        self.eph_priv = gen_eph_scalar()
        self.eph_pub = dh_pub(self.eph_priv)
        self.shared = None

    def client_hello(self, tr: Transcript):
        tr.add("ClientHello",
               sigalgs=["rsa_pss_rsae_sha256", "ed25519"],
               client_keyshare=self.eph_pub)

    def verify_server(self, tr: Transcript, server_pubA, sig):
        # Sign input
        M = SPACES64 + CTX_SERVER + b"\x00" + tr.digest()
        ok = ToyEd25519.verify(M, A=server_pubA, sig=sig)
        return ok

    def compute_shared(self, server_keyshare):
        self.shared = dh_shared(self.eph_priv, server_keyshare)
        return kdf(self.shared)

# =========================
# Demo flow (single-process "wire")
# =========================

def main():
    print("=== Toy TLS 1.3 handshake demo (NOT REAL TLS) ===\n")

    tr = Transcript()
    client = ToyClient()
    server = ToyServer()

    # Step 1: ClientHello
    client.client_hello(tr)
    print("ClientHello sent.")

    # Server receives: build ServerHello, EncryptedExtensions, Certificate
    server.on_client_hello(tr, client_keyshare=client.eph_pub,
                           sigalgs=["rsa_pss_rsae_sha256", "ed25519"])
    print("ServerHello + EncryptedExtensions + Certificate sent.")

    # Server: CertificateVerify
    sig = server.certificate_verify(tr)
    print(f"Server CertificateVerify signature: R={sig[0]}, S={sig[1]}")

    # Client verifies
    ok = client.verify_server(tr, server_pubA=server.cert.A, sig=sig)
    print(f"Client verification of server CertificateVerify: {'OK' if ok else 'FAIL'}")

    # Both derive shared keys
    client_key = client.compute_shared(server_keyshare=server.eph_pub)
    server_key = server.compute_shared(client_keyshare=client.eph_pub)
    print(f"Client derived key: {client_key.hex()}")
    print(f"Server derived key: {server_key.hex()}")

    print("\nShared secrets match? ", "YES" if client_key == server_key else "NO")

    # For visibility, dump the transcript hash used in CertVerify
    print("\nTranscript hash (SHA-256) at CertVerify:", hashlib.sha256().hexdigest())  # placeholder
    # The actual transcript digest used was tr.digest at that moment. For display:
    print("Transcript hash used (hex):", tr.digest.hex())

if __name__ == "__main__":
    main()
# This is a toy implementation and should not be used for real cryptographic purposes.
