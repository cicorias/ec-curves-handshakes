# tls_server.py
import socket
import time
from tls_shared import (
    transcript_hash, toy_prf,
    generate_mock_ed25519_keypair, sign_with_mock_ed25519, b64
)

HOST = "127.0.0.1"
PORT = 44444

def run_server():
    # Mock server key pair
    server_priv, server_pub = generate_mock_ed25519_keypair()

    # Start socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)
    print("[Server] Listening...")

    conn, addr = s.accept()
    print(f"[Server] Connected by {addr}")

    transcript = []

    # Step 1: Receive ClientHello
    client_hello = conn.recv(4096).decode()
    print("[Server] Got ClientHello:", client_hello)
    transcript.append(client_hello)

    # Step 2: Send ServerHello + ephemeral pubkey
    server_hello = "ServerHello:curveX,keyY"
    conn.sendall(server_hello.encode())
    transcript.append(server_hello)

    # Step 3: Send Certificate (mock pubkey)
    cert_msg = f"Certificate: {b64(server_pub)}"
    conn.sendall(cert_msg.encode())
    transcript.append(cert_msg)

    # Step 4: CertificateVerify
    thash = transcript_hash(transcript)
    signature = sign_with_mock_ed25519(server_priv, thash)
    cv_msg = f"CertificateVerify:{b64(signature)}"
    conn.sendall(cv_msg.encode())
    transcript.append(cv_msg)

    # Derive "Finished" key (toy PRF)
    master_secret = toy_prf(server_priv, "handshake", thash)
    finished = f"Finished:{b64(master_secret[:16])}"
    conn.sendall(finished.encode())

    print("[Server] Handshake complete, sent Finished.")
    conn.close()
    s.close()

if __name__ == "__main__":
    run_server()
