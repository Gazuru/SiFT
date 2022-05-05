import socket
import _thread
import os
from MTP import decrypt, encrypt
from command import command_server

from login import login_server 

def on_new_client(conn, addr, number):
    print(f"Connected by {addr}")
    
    with open("server/rcvstate" + str(number) + ".txt", "w") as f:
        f.write("sqn: 0\n")
    with open("server/sndstate" + str(number) + ".txt", "w") as f:
        f.write("sqn: 0\n")
    
    logged_in = False
    state = 0
    user = None

    while True:
        if not logged_in:
            message, user = login_server(conn, number)

            if message:
                logged_in = True
            else:
                break
            print("Waiting for commands from " + user + " on " + str(addr) + "!")
        else:
            if state == 0:
                state, message = command_server(conn, number, user)
                            
                if state == -1:
                    break

            elif state == 1:
                #TODO upload
                pass
            elif state == 2:
                #TODO download
                pass

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

def run_server(host, port):
    number = 0
    with open("server/number.txt", "w") as f:
        f.write("0")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen()
            while True:
                conn, addr = s.accept()
                _thread.start_new_thread(on_new_client,(conn,addr,number))
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

