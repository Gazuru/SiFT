import os
from Crypto.Hash import SHA256
from cv2 import cubeRoot
from MTP import COMMAND_REQ, COMMAND_RES, decrypt, encrypt

def pwd(current_dir):
    if current_dir == None:
        return "failure" + '\n' + "Current working directory not found!"
    if not os.path.exists("server" + current_dir):
        return "failure" + '\n' + "Current working directory not found!"
    else:
        return "success" + '\n' + current_dir

def chd(params, current_dir, user):
    if current_dir == None:
        return "failure" + '\n' + "Current working directory not found!", current_dir
    if params[0] != "..":
        if not os.path.exists("server" + current_dir + '/' + params[0]):
            return "failure" + '\n' + "Directory '" + params[0] + "' does not exist!", current_dir
        else:
            current_dir += '/' + params[0]
            return "success", current_dir
    else:
        parts = current_dir.split('/')
        current_dir_temp = ""
        for part in parts[1:-1]:
            current_dir_temp += '/' + part
        if not os.path.exists("server" + current_dir_temp + '/' + params[0]):
            return "failure" + '\n' + "Directory  does not exist!", current_dir
        if not current_dir_temp.startswith("/home/" + user):
            return "failure" + '\n' + "Access denied!", current_dir
        else:
            current_dir = current_dir_temp
            return "success", current_dir

def get_message(command, results):
    if command == "pwd":
        return results[1]
    if command == "chd":
        try:
            return results[1]
        except Exception as e:
            return None

def command_req(command, param):
    message = command
    
    if command == "pwd":
        pass
    if command == "chd":
        message += '\n' + param

    return message

def command_res(command, params, message, user, current_dir):
    SHA = SHA256.new()
    SHA.update(message)
    request_hash = SHA.digest()

    message = command + '\n'
    message += request_hash.hex() + '\n'
    
    if command == "pwd":
        message += pwd(current_dir)
    if command == "chd":
        results, current_dir = chd(params, current_dir, user)
        message += results

    return message, current_dir


def command_client(socket, number, user):
    command = input(user + ":~$ ")
    try:
        data = command.split(' ')
        command = data[0]
        param = data[1]
    except Exception as e:
        param = ""
    if command not in ["pwd", "lst", "chd", "mkd", "del", "upl", "dnl"]:
        if command == "exit":
            return -1, None
        else:
            print(command + ": command not found")
            return 0, None
    
    message = command_req(command, param).encode("utf-8")
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
    if request_hash != hash:
        return -1, None
    
    message = get_message(command, data[2:])

    return 0, message

def command_server(conn, number, user, current_dir):
    data = conn.recv(2048)
    if data[2:4] != COMMAND_REQ:
        return -1, None

    msg = decrypt(data, "server", str(number))
    if msg == 0:
        return -1, None
    
    data = msg.decode('utf-8').split('\n')

    command = data[0]
    params = data[1:]

    message, current_dir = command_res(command, params, msg, user, current_dir)

    message = message.encode("utf-8")

    data = encrypt(message, COMMAND_RES, 'server', str(number))
    conn.sendall(data)

    return 0, current_dir