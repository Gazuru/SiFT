import socket

from MTP import decrypt, encrypt


def run_client(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        while True:
            message = input()

            if message == "exit":
                break

            data = encrypt(message.encode('utf-8'), b'\x00\x10',"client/sndstate.txt")
            s.sendall(data)
            data = s.recv(4096)

            data = decrypt(data, b'\x00\x10', "client/rcvstate.txt")
            if data == 0:
                break

            print(f"Received {data!r}")



        #sndstate.txt
        #rcvstate.txt
