import socket

from MTP import decrypt, encrypt


def run_server(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        end = True
        while end:
            s.listen()
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                while True:
                    data = conn.recv(4096)

                    data = decrypt(data, b'\x00\x10', "server/rcvstate.txt")
                    if data == 0:
                        end = False
                        break

                    print(f"Received {data!r}")
                    
                    data = encrypt(data, b'\x00\x10',"server/sndstate.txt")

                    conn.sendall(data)
