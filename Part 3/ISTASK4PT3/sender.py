from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import socket


def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def main():
    host = '127.0.0.1'
    port = 12345

    private_key = serialization.load_pem_private_key(
        open("private_key.pem", "rb").read(),
        password=None,
        backend=default_backend()
    )

    message = b"Hello, this is a test message."
    signature = sign_message(private_key, message)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        s.sendall(message)
        s.sendall(signature)


if __name__ == "__main__":
    main()
