import _thread
import os
import socket

from command import command_server
from login import login_server
from src.download import download_server
from upload import upload_server


def on_new_client(conn, addr, number):
    print(f"Connected by {addr}")

    with open("server/rcvstate" + str(number) + ".txt", "w") as f:
        f.write("sqn: 0\n")
    with open("server/sndstate" + str(number) + ".txt", "w") as f:
        f.write("sqn: 0\n")

    logged_in = False
    state = 0
    user = None
    current_dir = None

    while True:
        if not logged_in:
            message, user = login_server(conn, number)
            if message:
                logged_in = True
            else:
                break
            current_dir = "/home/" + user

            print("Waiting for commands from " + user + " on " + str(addr) + "!")
        else:
            if state == 0:
                state, param = command_server(conn, number, user, current_dir)

                if state == -1:
                    break
                elif state in [1, 2]:
                    filename = param
                else:
                    current_dir = param

            elif state == 1:
                state = upload_server(conn, number, current_dir, filename)

                if state == -1:
                    break
            elif state == 2:
                state = download_server(conn, number, current_dir, filename)

                if state == -1:
                    break

            """
            data = conn.recv(2048)
            if data == b'':
                break

            data = decrypt(data, "server", str(number))
            if data == 0:
                break

            print(f"Received {data!r}")
        
            data = encrypt(data, b'\x00\x20',"server", str(number))

            conn.sendall(data)
            """

    print(f"Disconnected {addr}")
    os.remove("server/rcvstate" + str(number) + ".txt")
    os.remove("server/sndstate" + str(number) + ".txt")
    conn.close()


def run_server(port):
    number = 0
    with open("server/number.txt", "w") as f:
        f.write("0")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((socket.gethostbyname(socket.gethostname()), port))
            s.listen()
            while True:
                conn, addr = s.accept()
                _thread.start_new_thread(on_new_client, (conn, addr, number))
                number += 1
    except KeyboardInterrupt as e:
        for i in range(number):
            if os.path.exists("server/rcvstate" + str(i) + ".txt"):
                os.remove("server/rcvstate" + str(i) + ".txt")
                os.remove("server/sndstate" + str(i) + ".txt")
        os.remove("server/number.txt")
        s = None
    except Exception as e:
        os.remove("server/number.txt")
