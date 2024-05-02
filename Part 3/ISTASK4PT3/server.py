import socket


def main():
    host = '127.0.0.1'
    port = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            public_key = conn.recv(1024)
            message = conn.recv(1024)
            signature = conn.recv(1024)
            # Do something with the received data


if __name__ == "__main__":
    main()
