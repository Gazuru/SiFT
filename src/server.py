import socket
import _thread

from MTP import decrypt, encrypt

def on_new_client(conn, addr):
    print(f"Connected by {addr}")
    while True:
        data = conn.recv(4096)

        data = decrypt(data, b'\x00\x10', "server/rcvstate.txt")
        if data == 0:
            break

        print(f"Received {data!r}")
        
        data = encrypt(data, b'\x00\x10',"server/sndstate.txt")

        conn.sendall(data)
    print(f"Disconnected {addr}")
    conn.close()

def run_server(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        while True:
            conn, addr = s.accept()
            _thread.start_new_thread(on_new_client,(conn,addr))

