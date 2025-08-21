# client.py
# Toy TLS 1.3-like client using common.py
# NOT FOR REAL CRYPTO.

import sys, json, subprocess
from common import (
    SPACES64, CTX_SERVER,
    ToyEd25519, Transcript,
    gen_eph_scalar, dh_pub, dh_shared,
    derive_handshake_secret, make_finished_key, make_finished_mac
)

LABEL_FIN_S = b"fin s"
LABEL_FIN_C = b"fin c"

def run_client():
    tr = Transcript()

    # Ephemeral (client) for toy ECDHE
    c_priv = gen_eph_scalar()
    c_pub = dh_pub(c_priv)

    # Launch server
    p = subprocess.Popen([sys.executable, "server.py"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    # ----- ClientHello -----
    ch = {"type":"ClientHello",
          "sigalgs":["rsa_pss_rsae_sha256","ed25519"],
          "client_keyshare":c_pub}
    p.stdin.write(json.dumps(ch) + "\n"); p.stdin.flush()
    tr.add("ClientHello", **ch)

    # Receive 5 lines: SH, EE, CERT, CV, FIN
    srv_msgs = [json.loads(p.stdout.readline()) for _ in range(5)]
    sh, ee, cert, cv, fin = srv_msgs

    # Track messages into transcript in order
    tr.add("ServerHello", **sh)
    tr.add("EncryptedExtensions")
    tr.add("Certificate", **cert)

    # ----- Verify CertificateVerify -----
    # Build M = 64 spaces || context || 0x00 || th_before_cv
    th_before_cv = tr.digest()  # up to Certificate
    M = SPACES64 + CTX_SERVER + b"\x00" + th_before_cv
    R, S = int(cv["R"]), int(cv["S"])
    A = int(cert["ed25519_pubA"])
    ok_sig = ToyEd25519.verify(M, A, (R, S))

    # Add CV after checking
    tr.add("CertificateVerify", R=R, S=S)

    # ----- Derive handshake secret -----
    s_priv = None  # not needed here; we have server share from SH
    s_share = int(sh["server_keyshare"])
    shared_multiple = dh_shared(c_priv, s_share)
    hs_secret = derive_handshake_secret(shared_multiple)

    # ----- Verify Server Finished -----
    # Server finished key bound to th_before_cv (client's view)
    server_finished_key = make_finished_key(hs_secret, LABEL_FIN_S, th_before_cv)

    # Server Finished MAC covers transcript including CV
    th_before_srv_fin = tr.digest()
    server_fin_mac = bytes.fromhex(fin["mac"])
    expected_srv_mac = make_finished_mac(server_finished_key, th_before_srv_fin)

    ok_fin = (server_fin_mac == expected_srv_mac)

    # ----- Send Client Finished -----
    # Client Finished key: bind to transcript that includes CV (and which the server had for its Finished)
    client_finished_key = make_finished_key(hs_secret, LABEL_FIN_C, th_before_srv_fin)

    # MAC covers transcript up to (but not including) Client Finished; i.e., includes Server Finished
    tr.add("Finished", who="server", mac=fin["mac"])  # track server Finished in transcript
    th_before_client_fin = tr.digest()

    client_fin_mac = make_finished_mac(client_finished_key, th_before_client_fin).hex()
    msg = {"type":"Finished","mac":client_fin_mac}
    p.stdin.write(json.dumps(msg) + "\n"); p.stdin.flush()

    # Read server's result on our Finished
    server_result = json.loads(p.stdout.readline())

    # Print a compact summary to stdout (you can adjust as you like)
    summary = {
        "sig_verify_ok": ok_sig,
        "server_finished_ok": ok_fin,
        "client_finished_ok_on_server": server_result.get("client_finished_ok", False)
    }
    print(json.dumps({"type":"ClientSummary", **summary}))

if __name__ == "__main__":
    run_client()
