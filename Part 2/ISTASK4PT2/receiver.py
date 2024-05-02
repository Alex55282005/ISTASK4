import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Load public key from the first application
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    HOST = 'localhost'
    PORT = 8000
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        public_key_bytes = conn.recv(4096)
        public_key = serialization.load_pem_public_key(
            public_key_bytes,
            backend=default_backend()
        )

        # Receive message and signature together with a delimiter
        received_data = conn.recv(4096)
        delimiter_index = received_data.find(b"###")
        message = received_data[:delimiter_index]
        signature = received_data[delimiter_index + len(b"###"):]
        print("Received message:", message)
        print("Received signature:", signature)

        # Verify signature
        try:
            # Verify message integrity
            h = hashes.Hash(hashes.SHA256(), backend=default_backend())
            h.update(message)
            received_message_hash = h.finalize()

            # Verify the signature
            public_key.verify(
                signature,
                received_message_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Signature verified: Message authentic.")
        except Exception as e:
            print("Signature verification failed:", e)
