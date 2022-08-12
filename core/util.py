from core.constants import EXTERNAL_BIND, DEFAULT_BIND


def get_available_port(bind, port):
    from core.config import get_ports
    if is_closed(bind, port):
        return port

    for i in get_ports():
        if is_closed(bind, i):
            return i

    return -1


def get_external_ip():
    from requests import get
    return get('https://api.ipify.org', verify=False).content.decode('utf8')


def is_b64(s):
    try:
        import base64
        return base64.b64encode(base64.b64decode(s)).decode() == s
    except Exception:
        return False


def is_closed(bind, port):
    if bind == EXTERNAL_BIND:
        bind = DEFAULT_BIND

    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((bind, port))
            s.close()
            return True
    except OSError as e:
        return False
