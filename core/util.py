import socket

from core.config import get_ports


def get_available_port(port):
    if not is_open(port):
        return port

    for i in get_ports():
        if not is_open(i):
            return i

    return -1


def is_open(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('0.0.0.0', port))
    sock.close()
    return result == 0
