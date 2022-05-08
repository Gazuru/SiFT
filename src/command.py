import base64
import os
import shutil

from Crypto.Hash import SHA256

from MTP import COMMAND_REQ, COMMAND_RES, decrypt, encrypt


def pwd(current_dir):
    if current_dir is None:
        return "failure" + '\n' + "Current working directory not found!"
    if not os.path.exists("server" + current_dir):
        return "failure" + '\n' + "Current working directory not found!"
    else:
        return "success" + '\n' + current_dir


def chd(params, current_dir, user):
    if current_dir is None:
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


def lst(current_dir):
    if current_dir is None:
        return "failure" + '\n' + "Current working directory not found!"
    if not os.path.exists("server" + current_dir):
        return "failure" + '\n' + "Current working directory not found!"
    else:
        response = "success"
        for item in os.listdir("server" + current_dir):
            item_bytes = item.encode()
            b64_bytes = base64.b64encode(item_bytes)
            b64_string = b64_bytes.decode()
            response += f"\n{b64_string}"
        return response


def mkd(current_dir, params):
    if current_dir is None:
        return "failure'\nCurrent working directory not found!"
    if not os.path.exists("server" + current_dir):
        return "failure" + '\n' + "Current working directory not found!"
    try:
        os.mkdir(f"server{current_dir}/{params[0]}")
        return "success"
    except OSError as e:
        return f"failure\n{e}"


def delete(current_dir, params):
    if current_dir is None:
        return "failure\nCurrent working directory not found!"
    if not os.path.exists("server" + current_dir):
        return "failure" + '\n' + "Current working directory not found!"
    path = f"server{current_dir}/{params[0]}"
    if not os.path.exists(path):
        return "failure\nPath doesn't exist!"
    try:
        os.chmod(path, 0o777)
        os.remove(path)
        return "success"
    except Exception as e:
        try:
            os.rmdir(path)
            return "success"
        except OSError as e:
            return f"failure\n{e}"


def upl(current_dir, params):
    if current_dir is None:
        return "reject\nCurrent working directory not found!"
    if not os.path.exists("server" + current_dir):
        return "reject" + '\n' + "Current working directory not found!"
    if os.path.exists("server" + current_dir + '/' + params[0]):
        return "reject" + '\n' + "Already existing file with same name!"
    else:
        return "accept"


def dnl(current_dir, params):
    # TODO
    pass


def get_message(command, results):
    if command == "pwd":
        return results[1]
    elif command in ["chd", "mkd", "del", "upl"]:
        try:
            return results[1]
        except Exception as e:
            return None
    elif command == "lst":
        response = ""
        for res in results[1:]:
            b64_bytes = res.encode()
            string_bytes = base64.b64decode(b64_bytes)
            string = string_bytes.decode()
            response += f"{string}"
            if results[-1] != res:
                response += "\n"
        return response


def command_req(command, param):
    message = command

    if command in ["pwd", "lst"]:
        return message
    elif command == "upl":
        if os.path.exists(os.getcwd() + '/' + param[0]):
            shutil.copyfile(os.getcwd() + '/' + param[0], "client/" + param[0])

            with open("client/" + param[0], "rb") as f:
                data = f.read()

                SHA = SHA256.new()
                SHA.update(data)
                hash = SHA.digest()

            message += '\n' + param[0] 
            message += '\n' + str(os.path.getsize("client/" + param[0]))
            message += '\n' + hash.hex()
        else:
            print("File not found!")
            return None
    elif command == "dnl":
        # TODO dl req megoldása
        pass
    else:
        message += f"\n{param[0]}"

    return message


def command_res(command, params, message, user, current_dir):
    SHA = SHA256.new()
    SHA.update(message)
    request_hash = SHA.digest()

    message = command + '\n'
    message += request_hash.hex() + '\n'

    if command == "pwd":
        message += pwd(current_dir)
    elif command == "chd":
        results, current_dir = chd(params, current_dir, user)
        message += results
    elif command == "lst":
        message += lst(current_dir)
    elif command == "mkd":
        message += mkd(current_dir, params)
    elif command == "del":
        message += delete(current_dir, params)
    elif command == "upl":
        message += upl(current_dir, params)
    elif command == "dnl":
        # TODO
        pass


    return message, current_dir


def command_client(socket, number, user):
    command = input(user + ":~$ ")
    try:
        data = command.split(' ')
        command = data[0]
        param = data[1:]
    except Exception as e:
        param = ""
    if command not in ["pwd", "lst", "chd", "mkd", "del", "upl", "dnl"]:
        if command == "exit":
            return -1, None
        else:
            print(command + ": command not found")
            return 0, None

    #dl_req küldése

    message = command_req(command, param)

    if message is None:
        return 0, None

    message = message.encode("utf-8")
    
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

    #DL RES megoldása
    message = get_message(command, data[2:])

    if command == "upl" and data[2] == "accept":
        return 1, param[0]
    elif command == "dnl":
        # TODO dl res esetén
        pass
    
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

    #DL REQ megoldása

    message, current_dir = command_res(command, params, msg, user, current_dir)

    message = message.encode("utf-8")

    data = encrypt(message, COMMAND_RES, 'server', str(number))

    conn.sendall(data)

    if command == "upl" and message.decode("utf-8").split('\n')[2] == "accept":
        return 1, params[0]
    elif command == "dnl":
        # TODO DL res küldése esetén
        pass

    return 0, current_dir
