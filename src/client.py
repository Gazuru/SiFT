import socket


def run_client(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(b"Hello")
        data = s.recv(1024)

    print(f"Received {data!r}")
