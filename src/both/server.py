# server.py
# Toy TLS 1.3-like server using common.py
# NOT FOR REAL CRYPTO.

import sys, json
from common import (
    SPACES64, CTX_SERVER,
    ToyEd25519, Transcript,
    gen_eph_scalar, dh_pub, dh_shared,
    derive_handshake_secret, make_finished_key, make_finished_mac
)

LABEL_FIN_S = b"fin s"  # label for server finished key

def run_server():
    tr = Transcript()

    # "Certificate" (fixed for demo): Ed25519-like toy keypair
    cert = ToyEd25519(secret_scalar_a=29, prefix=b"\x0a\x0b")

    # Read ClientHello JSON (single line) from stdin
    line = sys.stdin.readline()
    ch = json.loads(line)
    assert ch.get("type") == "ClientHello"
    client_share = int(ch["client_keyshare"])

    # Track incoming ClientHello in our transcript
    tr.add("ClientHello", **ch)

    # Prepare ServerHello
    eph_priv = gen_eph_scalar()
    eph_pub = dh_pub(eph_priv)
    tr.add("ServerHello", chosen_sigalg="ed25519", server_keyshare=eph_pub)

    # EncryptedExtensions (empty in our demo)
    tr.add("EncryptedExtensions")

    # Certificate (send public A)
    tr.add("Certificate", ed25519_pubA=cert.A)

    # ----- CertificateVerify -----
    # Sign M = 64 spaces || context || 0x00 || th_before_cv
    th_before_cv = tr.digest()  # up to Certificate
    M = SPACES64 + CTX_SERVER + b"\x00" + th_before_cv
    R, S = cert.sign(M)
    tr.add("CertificateVerify", R=R, S=S)

    # ----- Finished (Server) -----
    # Derive handshake secret from ECDHE
    shared_multiple = dh_shared(eph_priv, client_share)
    hs_secret = derive_handshake_secret(shared_multiple)

    # Server Finished key depends on transcript up to Certificate (th_before_cv)
    server_finished_key = make_finished_key(hs_secret, LABEL_FIN_S, th_before_cv)

    # Finished MAC covers transcript up to and including CertificateVerify
    th_before_srv_fin = tr.digest()
    server_finished_mac = make_finished_mac(server_finished_key, th_before_srv_fin)

    tr.add("Finished", who="server", mac=server_finished_mac.hex())

    # Send all server handshake messages to the client as NDJSON
    out = [
        {"type":"ServerHello","server_keyshare":eph_pub,"chosen_sigalg":"ed25519"},
        {"type":"EncryptedExtensions"},
        {"type":"Certificate","ed25519_pubA":cert.A},
        {"type":"CertificateVerify","R":R,"S":S},
        {"type":"Finished","mac":server_finished_mac.hex()}
    ]
    for m in out:
        print(json.dumps(m), flush=True)

    # Expect client's Finished
    cl_line = sys.stdin.readline()
    client_fin = json.loads(cl_line)
    assert client_fin.get("type") == "Finished"

    # Verify client's Finished
    # Build transcript hash BEFORE client's Finished (i.e., includes server Finished)
    tr.add("Finished", who="client", mac=client_fin["mac"])  # record (order doesn't affect our check below, we recompute)
    # For verification, re-create the transcript up to *before* client Finished:
    # (i.e., after adding server Finished but not client Finished)
    # We can re-hash from our saved messages (count - 1).
    th_before_client_fin = tr.digest_until(tr.count() - 1)

    # Client finished key label could be different; in our toy we bind it also to th_before_cv
    LABEL_FIN_C = b"fin c"
    client_finished_key = make_finished_key(hs_secret, LABEL_FIN_C, th_before_srv_fin)  # bind to transcript that client saw (includes CV)
    expected_client_mac = make_finished_mac(client_finished_key, th_before_client_fin).hex()

    ok = (client_fin["mac"] == expected_client_mac)
    print(json.dumps({"type":"ServerResult","client_finished_ok":ok}), flush=True, file=sys.stdout)

if __name__ == "__main__":
    run_server()
