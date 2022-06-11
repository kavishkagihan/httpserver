import json
import os.path

import netifaces as ni

from core.constants import DEFAULT_BIND
from core.log import log_error

data = None


def get_json():
    # cache it
    global data
    if data:
        return data
    path = os.path.dirname(os.path.realpath(__file__))
    fd = open(path + '/../config.json')
    data = json.load(fd)
    fd.close()
    return data


def get_index():
    data = get_json()
    return data['index']


def get_ports():
    data = get_json()
    return data['ports']


def eval_bind(bind):
    data = get_json()
    if data['bind']:
        try:
            return ni.ifaddresses(data['bind'])[ni.AF_INET][0]['addr']
        except:
            pass
    return DEFAULT_BIND if not bind else bind


def eval_index(index):
    data = get_json()

    if index == "rev":
        return os.path.dirname(os.path.realpath(__file__)) + "/shell.sh"

    for i, v in data['alias'].items():
        if index == i:
            return v

    if not os.path.exists(index):
        import re
        pattern = re.compile(index)

        for r, d, f in os.walk("."):
            for file in f:
                if pattern.match(file):
                    return os.path.abspath(os.path.join(r, file))

        log_error("No match found", exit=True)

    return index
