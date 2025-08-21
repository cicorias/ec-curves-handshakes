# tls_client.py
import socket
from tls_shared import (
    transcript_hash, verify_with_mock_ed25519, b64
)

HOST = "127.0.0.1"
PORT = 44444

def run_client():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    transcript = []

    # Step 1: Send ClientHello
    ch = "ClientHello:supported=ed25519"
    s.sendall(ch.encode())
    transcript.append(ch)

    # Step 2: Receive ServerHello
    sh = s.recv(4096).decode()
    print("[Client] Got:", sh)
    transcript.append(sh)

    # Step 3: Receive Certificate
    cert = s.recv(4096).decode()
    print("[Client] Got:", cert)
    transcript.append(cert)

    # Step 4: Receive CertificateVerify
    cv = s.recv(4096).decode()
    print("[Client] Got:", cv)
    transcript.append(cv)

    # Parse cert + signature
    server_pub_b64 = cert.split(":",1)[1]
    signature_b64 = cv.split(":",1)[1]

    import base64
    server_pub = base64.b64decode(server_pub_b64)
    signature = base64.b64decode(signature_b64)

    thash = transcript_hash(transcript[:-1])  # exclude CV when verifying
    ok = verify_with_mock_ed25519(server_pub, thash, signature)
    print("[Client] CertificateVerify valid?", ok)

    # Step 5: Finished
    finished = s.recv(4096).decode()
    print("[Client] Got:", finished)

    s.close()

if __name__ == "__main__":
    run_client()
