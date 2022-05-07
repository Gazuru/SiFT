import sys

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

# constans
LOGIN_REQ = b'\x00\x00'
LOGIN_RES = b'\x00\x10'
COMMAND_REQ = b'\x01\x00'
COMMAND_RES = b'\x01\x10'
UPLOAD_REQ_0 = b'\x02\x00'
UPLOAD_REQ_1 = b'\x02\x01'
UPLOAD_RES = b'\x02\x10'
DOWNLOAD_REQ = b'\x03\x00'
DOWNLOAD_RES_0 = b'\x03\x10'
DOWNLOAD_RES_1 = b'\x03\x11'


def load_publickey(pubkeyfile):
    with open(pubkeyfile, 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except ValueError:
        print('Error: Cannot import public key from file ' + pubkeyfile)
        sys.exit(1)


def load_keypair(privkeyfile):
    with open(privkeyfile, 'rb') as f:
        keypairstr = f.read()
    try:
        return RSA.import_key(keypairstr, passphrase="crysys")
    except ValueError:
        print('Error: Cannot import private key from file ' + privkeyfile)
        sys.exit(1)


def encrypt(payload, type, state, number):
    statefile = state + '/sndstate' + number + '.txt'

    login = False
    if type == LOGIN_REQ:
        login = True

    # read the content of the state file
    with open(statefile, 'rt') as sf:
        sqn = int(sf.readline()[len("sqn: "):], base=10)  # type should be integer
        if not login:
            key = bytes.fromhex(sf.readline()[len("key: "):len("key: ") + 64])  # type should be byte string

    # compute payload_length and set authtag_length
    payload_length = len(payload)
    authtag_length = 12  # we'd like to use a 12-byte long authentication tag

    # compute message length...
    # header: 16 bytes
    #    version: 2 bytes
    #    type:    1 btye
    #    length:  2 btyes
    #    sqn:     4 bytes
    # .   rnd:     7 bytes
    # payload: payload_length
    # authtag: authtag_length
    msg_length = 16 + payload_length + authtag_length

    # login
    if login:
        statefile2 = state + '/rcvstate' + number + '.txt'
        pubkeyfile = "client/pubkey.pem"
        key = Random.get_random_bytes(32)
        msg_length += 256
        pubkey = load_publickey(pubkeyfile)
        RSAcipher = PKCS1_OAEP.new(pubkey)
        etk = RSAcipher.encrypt(key)

        # create header
    header_ver = b'\x01\x00'  # protocol version 1.0
    header_typ = type  # message type
    header_len = msg_length.to_bytes(2, byteorder='big')  # message length (encoded on 2 bytes)
    header_sqn = (sqn + 1).to_bytes(2, byteorder='big')  # next message sequence number (encoded on 2 bytes)
    header_rnd = Random.get_random_bytes(6)  # 6-byte long random value
    header_rsv = b'\x00\x00'  # 2 reserved bytes
    header = header_ver + header_typ + header_len + header_sqn + header_rnd + header_rsv

    # encrypt the payload and compute the authentication tag over the header and the payload
    # with AES in GCM mode using nonce = header_sqn + header_rnd
    nonce = header_sqn + header_rnd
    AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=authtag_length)
    AE.update(header)
    encrypted_payload, authtag = AE.encrypt_and_digest(payload)

    # save state
    state = "sqn: " + str(sqn + 1) + '\n'
    if not login:
        state += "key: " + key.hex()
    else:
        with open(statefile2, 'a') as sf:
            sf.write("key: " + key.hex())
    with open(statefile, 'wt') as sf:
        sf.write(state)

    if login:
        return header + encrypted_payload + authtag + etk
    else:
        return header + encrypted_payload + authtag


def decrypt(msg, state, number):
    statefile = state + '/rcvstate' + number + '.txt'

    login_req = False

    # parse the message msg
    header = msg[0:16]  # header is 16 bytes long
    header_ver = header[0:2]  # version is encoded on 2 bytes
    header_typ = header[2:4]  # type is encoded on 2 bytes
    header_len = header[4:6]  # msg length is encoded on 2 bytes
    header_sqn = header[6:8]  # msg sqn is encoded on 2 bytes
    header_rnd = header[8:14]  # random is encoded on 6 bytes
    header_rsv = header[14:16]  # rsv is encoded on 2 bytes

    if header_typ == LOGIN_REQ:
        login_req = True

    if login_req:
        etk = msg[-256:]
        authtag = msg[-268:-256]
        encrypted_payload = msg[16:-268]
        statefile2 = state + '/sndstate' + number + '.txt'
    else:
        authtag = msg[-12:]  # last 12 bytes is the authtag
        encrypted_payload = msg[16:-12]  # encrypted payload is between header and authtag

    # read the content of the state file
    with open(statefile, 'rt') as sf:
        rcvsqn = int(sf.readline()[len("sqn: "):], base=10)  # type should be integer
        if not login_req:
            key = bytes.fromhex(sf.readline()[len("key: "):len("key: ") + 64])  # type should be byte string

    # check the sequence number
    sndsqn = int.from_bytes(header_sqn, byteorder='big')
    if sndsqn <= rcvsqn:
        return 0

    if login_req:
        privkeyfile = 'server/keypair.pem'
        keypair = load_keypair(privkeyfile)
        RSAcipher = PKCS1_OAEP.new(keypair)
        key = RSAcipher.decrypt(etk)

        # verify and decrypt the encrypted payload
    nonce = header_sqn + header_rnd
    AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=12)
    AE.update(header)
    try:
        payload = AE.decrypt_and_verify(encrypted_payload, authtag)
    except Exception as e:
        return 0

    # save state
    state = "sqn: " + str(sndsqn) + '\n'
    if not login_req:
        state += "key: " + key.hex()
    else:
        with open(statefile2, 'a') as sf:
            key = "key: " + key.hex()
            sf.write(key)
    with open(statefile, 'wt') as sf:
        sf.write(state)

    return payload
