import socket
import os

from MTP import decrypt, encrypt
from getpass import getpass

from login import login_client, login_req

def run_client(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if os.path.exists("server/number.txt"):
                with open("server/number.txt", "r") as f:
                    number = int(f.readline(), base=10)
                with open("server/number.txt", "w") as f:
                    f.write(str(number+1))
            else:
                number = 0

            with open("client/rcvstate" + str(number) + ".txt", "w") as f:
                f.write("sqn: 0\n")
            with open("client/sndstate" + str(number) + ".txt", "w") as f:
                f.write("sqn: 0\n")
            
            s.connect((host, port))
            logged_in = False
            state = 0
            user = None

            while True :
                try:
                    if not logged_in:
                        message, user = login_client(s, number)

                        if message:
                            logged_in = True
                        else:
                            break
                        print("Login succesful for " + user + "!")
                    else:
                        if state == 0:
                            #TODO command
                            pass
                        elif state == 1:
                            #TODO upload
                            pass
                        elif state == 2:
                            #TODO download
                            pass

                        message = input()
                        if message =="exit":
                            break
                        s.sendall(encrypt(message.encode('utf-8'), b'\x00\x20', "client", str(number)))
                        data = s.recv(2048)
                        data = decrypt(data, "client", str(number))
                        if data == 0:
                            break

                        print(f"Received {data!r}")

                except socket.error as e:
                    break
            os.remove("client/rcvstate" + str(number) + ".txt")
            os.remove("client/sndstate" + str(number) + ".txt")
                
    except KeyboardInterrupt as e:
        os.remove("client/rcvstate" + str(number) + ".txt")
        os.remove("client/sndstate" + str(number) + ".txt")
        s.close()
        s = None
