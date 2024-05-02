from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import socket


def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature verified successfully.")
    except:
        print("Invalid signature.")


def main():
    host = '127.0.0.1'
    port = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        public_key = s.recv(1024)
        message = s.recv(1024)
        signature = s.recv(1024)

        public_key = serialization.load_pem_public_key(
            public_key,
            backend=default_backend()
        )

        verify_signature(public_key, message, signature)


if __name__ == "__main__":
    main()
