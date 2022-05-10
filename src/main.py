import argparse
import socket

import client
import server


def parse_mode():
    parser = argparse.ArgumentParser()

    parser.add_argument('--mode', type=str, required=True)

    return parser.parse_args().mode


HOST = "10.71.0.43"
PORT = 5150

if __name__ == '__main__':
    mode = parse_mode()

    if mode == "server":
        server.run_server(PORT)
    elif mode == "client":
        client.run_client(HOST, PORT)
