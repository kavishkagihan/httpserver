HEADER = '\033[95m'
INFO = '\033[94m'
VERBOSE = '\033[96m'
SUCCESS = '\033[92m'
WARNING = '\033[93m'
ERROR = '\033[91m'
YELLOW = '\033[0;33m'
ASK = '\033[35m'
NO_COLOR = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

is_verbose = False


def log_success(log: str):
    print(f"{SUCCESS}{BOLD} {log}{NO_COLOR}")


def is_verbose_mode():
    return is_verbose


def set_global_verbose(v):
    global is_verbose
    is_verbose = v


def log_normal(log: str):
    print(log)


def log_verbose(log: str):
    if is_verbose:
        print(log)


def log_warning(log: str):
    print(f"{WARNING} {log}{NO_COLOR}")


def log_info(log: str, bold=False):
    if bold:
        print(f"{INFO}{BOLD} {log}{NO_COLOR}")
    else:
        print(f"{INFO} {log}{NO_COLOR}")


def log_error(log: str, exit: bool = False):
    print(f"{ERROR} {log}{NO_COLOR}")
    if exit:
        import sys
        sys.exit(1)
