from Crypto.Hash import SHA256
from MTP import COMMAND_REQ, COMMAND_RES, decrypt, encrypt


def command_req(command):
    message = command + '\n'
    message += "param_1"

    return message

def command_res(command, message):
    SHA = SHA256.new()
    SHA.update(message)
    request_hash = SHA.digest()

    message = command + '\n'
    message += request_hash.hex() + '\n'
    message += "result_1"

    return message


def command_client(socket, number, user):
    command = input(user + ":~$ ")
    if command not in ["pwd", "lst", "chd", "mkd", "del", "upl", "dnl"]:
        if command == "exit":
            return -1, None
        else:
            print(command + ": command not found")
            return 0, None
    
    message = command_req(command).encode("utf-8")
    data = encrypt(message, COMMAND_REQ, "client", str(number))
    socket.sendall(data)

    SHA = SHA256.new()
    SHA.update(message)
    hash = SHA.digest()

    data = socket.recv(2048)

    if data[2:4] != COMMAND_RES:
        return -1, None
    msg = decrypt(data, "client", str(number))
    if msg == 0:
        return -1, None

    data = msg.decode('utf-8').split('\n')

    request_hash = bytes.fromhex(data[1])
    param_1 = data[2]

    if request_hash != hash:
        return -1, None

    return 0, None

def command_server(conn, number, user):
    data = conn.recv(2048)
    if data[2:4] != COMMAND_REQ:
        return -1, None

    msg = decrypt(data, "server", str(number))
    if msg == 0:
        return -1, None
    
    data = msg.decode('utf-8').split('\n')

    command = data[0]
    param_1 = data[1]

    message = command_res(command, msg).encode("utf-8")

    data = encrypt(message, COMMAND_RES, 'server', str(number))
    conn.sendall(data)


    return 0, None