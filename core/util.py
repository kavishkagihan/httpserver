def get_available_port(port):
    from core.config import get_ports
    if not is_open(port):
        return port

    for i in get_ports():
        if not is_open(i):
            return i

    return -1


def is_b64(s):
    try:
        import base64
        return base64.b64encode(base64.b64decode(s)).decode() == s
    except Exception:
        return False


def is_open(port):
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('0.0.0.0', port))
    sock.close()
    return result == 0
