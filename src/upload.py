import os

from MTP import UPLOAD_REQ_0, UPLOAD_REQ_1, UPLOAD_RES, decrypt, encrypt
from Crypto.Hash import SHA256

def upload_res(path):
    with open(path, "rb") as f:
        data = f.read()

    SHA = SHA256.new()
    SHA.update(data)
    hash = SHA.digest()

    size = os.path.getsize(path)

    message = hash.hex() + '\n'
    message += str(size)

    return message

def upload_client(socket, number, upl_file):
    size = os.path.getsize("client/" + upl_file)

    with open("client/" + upl_file, "rb") as f:
        file = f.read()

    fragements = size // 1024

    for i in range(fragements):
        message = file[ i * 1024 : (i+1) * 1024]
        data = encrypt(message, UPLOAD_REQ_0, "client", str(number))
        socket.sendall(data)

    message = file[fragements * 1024:]
    data = encrypt(message, UPLOAD_REQ_1, "client", str(number))
    socket.sendall(data)

    SHA = SHA256.new()
    SHA.update(file)
    hash = SHA.digest()

    data = socket.recv(2048)

    if data[2:4] != UPLOAD_RES:
        return -1
    msg = decrypt(data, "client", str(number))
    if msg == 0:
        return -1

    data = msg.decode('utf-8').split('\n')

    file_hash = bytes.fromhex(data[0])
    file_size = int(data[1], base=10)

    if file_hash != hash or file_size != size:
        return -1

    os.remove("client/" + upl_file)

    return 0

def upload_server(conn, number, current_dir, filename):
    done = False
    while not done:
        data = conn.recv(1052)
        if data[2:4] != UPLOAD_REQ_0 and data[2:4] != UPLOAD_REQ_1:
            return -1
        
        if data[2:4] == UPLOAD_REQ_1:
            done = True

        msg = decrypt(data, "server", str(number))
        if msg == 0:
            return -1

        with open("server/" + current_dir + '/' + filename, 'ab') as f:
            f.write(msg)

    message = upload_res("server/" + current_dir + '/' + filename).encode('utf-8')
    data = encrypt(message, UPLOAD_RES, 'server', str(number))
    conn.sendall(data)

    return 0