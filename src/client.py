import os
import socket

from command import command_client
from login import login_client
from download import download_client
from upload import upload_client


def run_client(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if os.path.exists("server/number.txt"):
                with open("server/number.txt", "r") as f:
                    number = int(f.readline(), base=10)
                with open("server/number.txt", "w") as f:
                    f.write(str(number + 1))
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

            while True:
                try:
                    if not logged_in:
                        success, user = login_client(s, number)

                        if success:
                            logged_in = True
                        else:
                            break
                        print("Login succesful for " + user + "!")
                    else:
                        if state == 0:
                            state, param = command_client(s, number, user)
                            if state == -1:
                                break
                            elif state == 1:
                                upl_file = param
                            elif state == 2:
                                dnl_file = param[0]
                                dnl_size = param[1][0]
                                dnl_hash = param[1][1]
                            elif param != None:
                                print(param)
                        elif state == 1:
                            print("Uploading...")
                            state = upload_client(s, number, upl_file)

                            if state == -1:
                                break
                        elif state == 2:
                            print("Downloading...")
                            state = download_client(s, number, dnl_file, dnl_size, dnl_hash)

                            if state == -1:
                                break

                except socket.error as e:
                    break
            os.remove("client/rcvstate" + str(number) + ".txt")
            os.remove("client/sndstate" + str(number) + ".txt")

    except KeyboardInterrupt as e:
        os.remove("client/rcvstate" + str(number) + ".txt")
        os.remove("client/sndstate" + str(number) + ".txt")
        s.close()
        s = None
