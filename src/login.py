from getpass import getpass
import time
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Hash import SHA512, SHA256
from Crypto import Random

from MTP import LOGIN_REQ, LOGIN_RES, decrypt, encrypt

def create_hash(username, password):
    salt = Random.get_random_bytes(16)
    hash = PBKDF2(password, salt, 64, count=1000000, hmac_hash_module=SHA512)
    with open('server/shadow.txt', 'a') as f:
        line =  username + ':$6$' + salt.hex() + '$' + hash.hex() + '\n'
        f.write(line)

def check_user(username, password):
    with open('server/shadow.txt', 'rt') as f:
        lines = f.readlines()
        for line in lines:
            parts = line.split(':')
            if parts[0] == username:
                salt = bytes.fromhex(parts[1].split('$')[2])
                hash = PBKDF2(password, salt, 64, count=1000000, hmac_hash_module=SHA512)
                if hash.hex() == parts[1].split('$')[3].split('\n')[0]:
                    return True
        return False

def check_timestamp(timestamp):
    current_time = time.time_ns()

    difference = 60 * pow(10, 9)

    if timestamp < (current_time - difference) or timestamp > (current_time + difference):
        return False
    else:
        return True

def login_req(username, password):
    timestamp = time.time_ns()
    client_random = Random.get_random_bytes(16)

    message = str(timestamp) + '\n'
    message += username + '\n'
    message += password + '\n'
    message += client_random.hex()
    
    return message

def login_res(message):
    SHA = SHA256.new()
    SHA.update(message)
    request_hash = SHA.digest()

    server_random = Random.get_random_bytes(16)

    message = request_hash.hex() + '\n'
    message += server_random.hex()

    return message

def login_client(socket, number):
    username = input("Username: ")
    if username == "exit":
        return False, None
    password = getpass("Password: ")   

    message = login_req(username, password).encode('utf-8')
    data = encrypt(message, LOGIN_REQ, "client", str(number))
    socket.sendall(data)

    SHA = SHA256.new()
    SHA.update(message)
    hash = SHA.digest()

    data = socket.recv(2048)

    if data[2:4] != LOGIN_RES:
        return False, None
    msg = decrypt(data, "client", str(number))
    if msg == 0:
        return False, None

    data = msg.decode('utf-8').split('\n')

    request_hash = bytes.fromhex(data[0])
    server_random = bytes.fromhex(data[1])

    if request_hash != hash:
        return False, username

    client_random = bytes.fromhex(message.decode('utf-8').split('\n')[3])

    key = HKDF(client_random + server_random, 32, hash, SHA256)

    with open("client/sndstate" + str(number) + ".txt", 'a') as sf:
        sf.write("key: " + key.hex())
    with open("client/rcvstate" + str(number) + ".txt", 'rt') as sf:
        sqn = int(sf.readline()[len("sqn: "):], base=10)
    with open("client/rcvstate" + str(number) + ".txt", 'wt') as sf:
        state = "sqn: " + str(sqn) + '\n'
        state +=  "key: " + key.hex()
        sf.write(state)

    return True, username

def login_server(conn, number):
    data = conn.recv(2048)

    if data[2:4] != LOGIN_REQ:
        return False, None
    msg = decrypt(data, "server", str(number))
    if msg == 0:
        return False, None

    data = msg.decode('utf-8').split('\n')

    timestamp = int(data[0], base=10)
    user = data[1]
    password = data[2]
    client_random = bytes.fromhex(data[3])

    if not check_user(user, password):
        return False, None
    if not check_timestamp(timestamp):
        return False, None

    message = login_res(msg).encode('utf-8')

    data = encrypt(message, LOGIN_RES, 'server', str(number))
    conn.sendall(data)

    server_random = bytes.fromhex(message.decode('utf-8').split('\n')[1])
    hash = bytes.fromhex(message.decode('utf-8').split('\n')[0])

    key = HKDF(client_random + server_random, 32, hash, SHA256)

    with open("server/rcvstate" + str(number) + ".txt", 'a') as sf:
        sf.write("key: " + key.hex())
    with open("server/sndstate" + str(number) + ".txt", 'rt') as sf:
        sqn = int(sf.readline()[len("sqn: "):], base=10)
    with open("server/sndstate" + str(number) + ".txt", 'wt') as sf:
        state = "sqn: " + str(sqn) + '\n'
        state +=  "key: " + key.hex()
        sf.write(state)

    return True, user
