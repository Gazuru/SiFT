import os.path

from src.MTP import encrypt, DOWNLOAD_RES_0, DOWNLOAD_RES_1, decrypt


def download_server(socket, number, dl_file):
    data = socket.recv()

    size = os.path.getsize("server/" + dl_file)

    with open("server/" + dl_file, "rb") as f:
        file = f.read()

    fragments = size // 1024

    if size % 1024 == 0:
        fragments -= 1
    for i in range(fragments):
        message = file[i * 1024: (i + 1) * 1024]
        data = encrypt(message, DOWNLOAD_RES_0, "server", str(number))
        socket.sendall(data)

    message = file[fragments * 1024:]
    data = encrypt(message, DOWNLOAD_RES_1, "server", str(number))
    socket.sendall(data)


def download_client(conn, number, filename):
    done = False
    while not done:
        data = conn.recv(1052)
        if data[2:4] not in [DOWNLOAD_RES_0, DOWNLOAD_RES_1]:
            return -1

        if data[2:4] == DOWNLOAD_RES_1:
            done = True

        msg = decrypt(data, "client", str(number))
        if msg == 0:
            return -1

        with open(f"{os.getcwd()}/{filename}", 'ab') as f:
            f.write(msg)

    return 0
