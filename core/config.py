import json
import os.path

from core.log import log_error


def get_json():
    path = os.path.dirname(os.path.realpath(__file__))
    fd = open(path + '/../config.json')
    res = json.load(fd)
    fd.close()
    return res


def get_index():
    data = get_json()
    return data['index']


def get_ports():
    data = get_json()
    return data['ports']


def eval_index(index):
    data = get_json()

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
