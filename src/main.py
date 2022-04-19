import argparse

import client
import server


def parse_mode():
    parser = argparse.ArgumentParser()

    parser.add_argument('--mode', type=str, required=True)

    return parser.parse_args().mode


HOST = "127.0.0.1"
PORT = 5150


if __name__ == '__main__':
    mode = parse_mode()

    if mode == "server":
        server.run_server(HOST, PORT)
    elif mode == "client":
        client.run_client(HOST, PORT)


