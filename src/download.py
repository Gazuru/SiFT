import os.path
import shutil

from Crypto.Hash import SHA256

from src.MTP import encrypt, DOWNLOAD_RES_0, DOWNLOAD_RES_1, decrypt, DOWNLOAD_REQ


def download_server(conn, number, current_dir, dl_file):
    data = conn.recv(1052)
    message = decrypt(data, "server", str(number))
    if message == 0:
        return -1
    if data[2:4] != DOWNLOAD_REQ:
        return -1
    if message.decode("utf-8") == "Cancel":
        return 0
    else:
        size = os.path.getsize("server/" + current_dir + "/" + dl_file)

        with open("server/" + current_dir + "/" + dl_file, "rb") as f:
            file = f.read()

        fragments = size // 1024

        if size % 1024 == 0:
            fragments -= 1
        for i in range(fragments):
            message = file[i * 1024: (i + 1) * 1024]
            data = encrypt(message, DOWNLOAD_RES_0, "server", str(number))
            conn.sendall(data)

        message = file[fragments * 1024:]
        data = encrypt(message, DOWNLOAD_RES_1, "server", str(number))
        conn.sendall(data)

        return 0


def download_client(socket, number, filename, size, hash):
    command = input(f"File size is {size}. Do you want to proceed? (y/n)\n")
    if not command.lower() in ["y", "n"]:
        print("Wrong input!")
        return 2
    elif command.lower() == "n":
        data = encrypt("Cancel".encode("utf-8"), DOWNLOAD_REQ, "client", str(number))
        socket.sendall(data)
        return 0
    else:
        data = encrypt("Ready".encode("utf-8"), DOWNLOAD_REQ, "client", str(number))
        socket.sendall(data)
        done = False
        while not done:
            data = socket.recv(1052)
            if data[2:4] not in [DOWNLOAD_RES_0, DOWNLOAD_RES_1]:
                return -1

            if data[2:4] == DOWNLOAD_RES_1:
                done = True

            msg = decrypt(data, "client", str(number))
            if msg == 0:
                return -1

            with open(f"client/{filename}", 'ab') as f:
                f.write(msg)

        data = None
        with open(f"client/{filename}", "rb") as f:
            file = f.read()
            data = f
        SHA = SHA256.new()
        SHA.update(file)
        computed_hash = SHA.digest()

        if computed_hash.hex() != bytes.fromhex(hash).hex() or os.path.getsize(data.name) != int(size, base=10):
            print("File hash or size mismatch!")
            return -1

        shutil.copy(data.name, os.getcwd() + "/" + filename)
        os.remove(data.name)

        return 0
