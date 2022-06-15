#! /usr/bin/env python3
__all__ = [
    "HTTPServer", "ThreadingHTTPServer", "BaseHTTPRequestHandler",
    "SimpleHTTPRequestHandler",
]

import contextlib
import datetime
import email.utils
import http.client
import io
import json
import mimetypes
import os
import posixpath
import shutil
import socket
import socketserver
import ssl
import sys
import time
import urllib.parse
from functools import partial
from http import HTTPStatus

from binaryornot.check import is_binary

from core.config import eval_index, get_index, eval_bind
from core.constants import DEFAULT_PORT, DEFAULT_BIND
from core.log import log_normal, set_global_verbose, log_verbose, YELLOW, NO_COLOR, log_error, is_verbose_mode, ask, \
    log_success
from core.ssl_util import cert_gen
from core.util import get_available_port


# Default error message template


class HTTPServer(socketserver.TCPServer):
    allow_reuse_address = 1  # Seems to make sense in testing environment

    def server_bind(self):
        self.allow_reuse_address = True
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = socket.getfqdn(host)
        self.server_port = port


class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True


class BaseHTTPRequestHandler(socketserver.StreamRequestHandler):
    default_request_version = "HTTP/0.9"

    def parse_request(self):

        self.command = None  # set in case of error on the first line
        self.request_version = version = self.default_request_version
        self.close_connection = True
        requestline = str(self.raw_requestline, 'iso-8859-1')
        requestline = requestline.rstrip('\r\n')
        self.requestline = requestline
        words = requestline.split()
        if len(words) == 0:
            return False

        if len(words) >= 3:  # Enough to determine protocol version
            version = words[-1]
            try:
                if not version.startswith('HTTP/'):
                    raise ValueError
                base_version_number = version.split('/', 1)[1]
                version_number = base_version_number.split(".")

                if len(version_number) != 2:
                    raise ValueError
                version_number = int(version_number[0]), int(version_number[1])
            except (ValueError, IndexError):
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Bad request version (%r)" % version)
                return False
            if version_number >= (1, 1) and self.protocol_version >= "HTTP/1.1":
                self.close_connection = False
            if version_number >= (2, 0):
                self.send_error(
                    HTTPStatus.HTTP_VERSION_NOT_SUPPORTED,
                    "Invalid HTTP version (%s)" % base_version_number)
                return False
            self.request_version = version

        if not 2 <= len(words) <= 3:
            self.send_error(
                HTTPStatus.BAD_REQUEST,
                "Bad request syntax (%r)" % requestline)
            return False
        command, path = words[:2]
        if len(words) == 2:
            self.close_connection = True
            if command != 'GET':
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Bad HTTP/0.9 request type (%r)" % command)
                return False
        self.command, self.path = command, path

        # Examine the headers and look for a Connection directive.
        try:
            self.headers = http.client.parse_headers(self.rfile,
                                                     _class=self.MessageClass)

            self.post_data = None
            if self.headers['Content-Length']:
                content_length = int(self.headers['Content-Length'])
                self.post_data = self.rfile.read(content_length).decode("utf-8")
        except http.client.LineTooLong as err:
            self.send_error(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Line too long",
                str(err))
            return False
        except http.client.HTTPException as err:
            self.send_error(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Too many headers",
                str(err)
            )
            return False

        conntype = self.headers.get('Connection', "")
        if conntype.lower() == 'close':
            self.close_connection = True
        elif (conntype.lower() == 'keep-alive' and
              self.protocol_version >= "HTTP/1.1"):
            self.close_connection = False
        # Examine the headers and look for an Expect directive
        expect = self.headers.get('Expect', "")
        if (expect.lower() == "100-continue" and
                self.protocol_version >= "HTTP/1.1" and
                self.request_version >= "HTTP/1.1"):
            if not self.handle_expect_100():
                return False
        return True

    def handle_expect_100(self):
        self.send_response_only(HTTPStatus.CONTINUE)
        self.end_headers()
        return True

    def handle_one_request(self):
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(HTTPStatus.REQUEST_URI_TOO_LONG)
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            if not self.parse_request():
                # An error code has been sent, just exit
                return
            mname = 'do_' + self.command
            if not hasattr(self, mname):
                method = getattr(self, "do_GET")
            else:
                method = getattr(self, mname)
            method()
            self.wfile.flush()  # actually send the response if not already done.
        except socket.timeout as e:
            # a read or a write timed out.  Discard this connection
            self.log_error("Request timed out: %r", e)
            self.close_connection = True
            return

    def handle(self):
        """Handle multiple requests if necessary."""
        self.close_connection = True

        self.handle_one_request()
        while not self.close_connection:
            self.handle_one_request()

    def send_error(self, code, message=None, explain=None):

        try:
            shortmsg, longmsg = self.responses[code]
        except KeyError:
            shortmsg, longmsg = '???', '???'
        if message is None:
            message = shortmsg
        if explain is None:
            explain = longmsg
        self.send_response(code, message)
        self.send_header('Connection', 'close')

        body = None
        if (code >= 200 and
                code not in (HTTPStatus.NO_CONTENT,
                             HTTPStatus.RESET_CONTENT,
                             HTTPStatus.NOT_MODIFIED)):
            content = json.dumps({
                "error": message
            })
            body = content.encode('UTF-8', 'replace')
            self.send_header("Content-Type", "application/json;charset=utf-8")
            self.send_header('Content-Length', str(len(body)))
        self.end_headers()

        if self.command != 'HEAD' and body:
            self.wfile.write(body)

    def send_response(self, code, message=None):
        """Add the response header to the headers buffer and log the
        response code.

        Also send two standard headers with the server software
        version and the current date.

        """
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header('Date', self.date_time_string())

    def send_response_only(self, code, message=None):
        """Send the response header only."""
        if self.request_version != 'HTTP/0.9':
            if message is None:
                if code in self.responses:
                    message = self.responses[code][0]
                else:
                    message = ''
            if not hasattr(self, '_headers_buffer'):
                self._headers_buffer = []
            self._headers_buffer.append(("%s %d %s\r\n" %
                                         (self.protocol_version, code, message)).encode(
                'latin-1', 'strict'))

    def send_header(self, keyword, value):
        """Send a MIME header to the headers buffer."""
        if self.request_version != 'HTTP/0.9':
            if not hasattr(self, '_headers_buffer'):
                self._headers_buffer = []
            self._headers_buffer.append(
                ("%s: %s\r\n" % (keyword, value)).encode('latin-1', 'strict'))

        if keyword.lower() == 'connection':
            if value.lower() == 'close':
                self.close_connection = True
            elif value.lower() == 'keep-alive':
                self.close_connection = False

    def end_headers(self):
        """Send the blank line ending the MIME headers."""
        if self.request_version != 'HTTP/0.9':
            self._headers_buffer.append(b"\r\n")
            self.flush_headers()

    def flush_headers(self):
        if hasattr(self, '_headers_buffer'):
            self.wfile.write(b"".join(self._headers_buffer))
            self._headers_buffer = []

    def log_request(self, code='-', size='-'):

        if isinstance(code, HTTPStatus):
            code = code.value
        self.log_message('"%s" %s %s',
                         self.requestline, str(code), str(size))

        if is_verbose_mode():
            log_normal("\n<!---------- Request Start ----------\n")
            log_normal(self.requestline)
            log_normal(self.headers)
            if self.post_data:
                log_normal(self.post_data)
            log_normal("----------  Request End  ----------!>\n")

    def date_time_string(self, timestamp=None):
        """Return the current date and time formatted for a message header."""
        if timestamp is None:
            timestamp = time.time()
        return email.utils.formatdate(timestamp, usegmt=True)

    def log_error(self, format, *args):
        self.log_message(format, *args)

    def log_message(self, format, *args):
        log_normal("%s - - [%s] %s" %
                   (self.address_string(),
                    self.log_date_time_string(),
                    format % args))

    def log_date_time_string(self):
        """Return the current time formatted for logging."""
        now = time.time()
        year, month, day, hh, mm, ss, x, y, z = time.localtime(now)
        s = "%02d/%3s/%04d %02d:%02d:%02d" % (
            day, self.monthname[month], year, hh, mm, ss)
        return s

    weekdayname = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

    monthname = [None,
                 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    def address_string(self):
        """Return the client address."""
        return self.client_address[0]

    # Essentially static class variables

    # The version of the HTTP protocol we support.
    # Set this to HTTP/1.1 to enable automatic keepalive
    protocol_version = "HTTP/1.0"

    # MessageClass used to parse headers
    MessageClass = http.client.HTTPMessage

    # hack to maintain backwards compatibility
    responses = {
        v: (v.phrase, v.description)
        for v in HTTPStatus.__members__.values()
    }


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    """Simple HTTP request handler with GET and HEAD commands.

    This serves files from the current directory and any of its
    subdirectories.  The MIME type for files is determined by
    calling the .guess_type() method.

    The GET and HEAD requests are identical except that the HEAD
    request omits the actual contents of the file.

    """

    def __init__(self, *args, index=None, replacers={}, **kwargs):
        if index is None:
            index = os.getcwd()
        self.index = index
        self.replacers = replacers
        super().__init__(*args, **kwargs)

    def do_HEAD(self):
        """Serve a GET request."""
        f = self.send_head()
        if f:
            f.close()

    def do_GET(self):
        """Serve a GET request."""
        f = self.send_head()

        path = self.translate_path(self.path)

        if f:
            try:
                if os.path.isdir(path) or (str(type(f)) == "<class '_io.BufferedReader'>" and not is_binary(path)):
                    s = str(f.read().decode('utf-8'))
                    for key, value in replacers.items():
                        s = s.replace(key, value)
                    self.wfile.write(bytes(s, "utf-8"))
                else:
                    self.copyfile(f, self.wfile)
            finally:
                f.close()

    def send_head(self):

        path = self.translate_path(self.path)

        if os.path.isdir(path):
            parts = urllib.parse.urlsplit(self.path)
            if not parts.path.endswith('/'):
                # redirect browser - doing basically what apache does
                self.send_response(HTTPStatus.MOVED_PERMANENTLY)
                new_parts = (parts[0], parts[1], parts[2] + '/',
                             parts[3], parts[4])
                new_url = urllib.parse.urlunsplit(new_parts)
                self.send_header("Location", new_url)
                self.end_headers()
                return None
            for index in get_index():
                index = os.path.join(path, index)
                if os.path.exists(index):
                    path = index
                    break
            else:
                return self.list_directory()
        ctype = self.guess_type(path)

        if path.endswith("/"):
            self.send_error(HTTPStatus.NOT_FOUND)
            return None

        try:
            f = open(path, 'rb')
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return None

        try:
            fs = os.fstat(f.fileno())
            # Use browser cache if possible
            if ("If-Modified-Since" in self.headers
                    and "If-None-Match" not in self.headers):
                # compare If-Modified-Since and time of last file modification
                try:
                    ims = email.utils.parsedate_to_datetime(
                        self.headers["If-Modified-Since"])
                except (TypeError, IndexError, OverflowError, ValueError):
                    # ignore ill-formed values
                    pass
                else:
                    if ims.tzinfo is None:
                        # obsolete format with no timezone, cf.
                        # https://tools.ietf.org/html/rfc7231#section-7.1.1.1
                        ims = ims.replace(tzinfo=datetime.timezone.utc)
                    if ims.tzinfo is datetime.timezone.utc:
                        # compare to UTC datetime of last modification
                        last_modif = datetime.datetime.fromtimestamp(
                            fs.st_mtime, datetime.timezone.utc)
                        # remove microseconds, like in If-Modified-Since
                        last_modif = last_modif.replace(microsecond=0)

                        if last_modif <= ims:
                            self.send_response(HTTPStatus.NOT_MODIFIED)
                            self.end_headers()
                            f.close()
                            return None

            self.send_response(HTTPStatus.OK)
            self.send_header("Content-type", ctype)
            self.send_header("Last-Modified",
                             self.date_time_string(fs.st_mtime))
            self.end_headers()
            return f
        except:
            f.close()
            raise

    def list_directory(self):
        enc = sys.getfilesystemencoding()

        encoded = json.dumps({
            "error": "No file specified"
        }).encode(enc, 'surrogateescape')
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(HTTPStatus.NOT_FOUND)
        self.send_header("Content-type", "application/json; charset=%s" % enc)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        return f

    def translate_path(self, path):

        if os.path.isfile(self.index):
            return self.index

        """Translate a /-separated PATH to the local filename syntax.

        Components that mean special things to the local file system
        (e.g. drive or directory names) are ignored.  (XXX They should
        probably be diagnosed.)

        """
        # abandon query parameters
        path = path.split('?', 1)[0]
        path = path.split('#', 1)[0]

        try:
            path = urllib.parse.unquote(path, errors='surrogatepass')
        except UnicodeDecodeError:
            path = urllib.parse.unquote(path)
        path = posixpath.normpath(path)
        words = path.split('/')
        words = filter(None, words)
        path = self.index
        for word in words:
            if os.path.dirname(word) or word in (os.curdir, os.pardir):
                # Ignore components that are not a simple file/directory name
                continue
            path = os.path.join(path, word)

        return path

    def copyfile(self, source, outputfile):
        shutil.copyfileobj(source, outputfile)

    def guess_type(self, path):
        base, ext = posixpath.splitext(path)
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        else:
            return self.extensions_map['']

    if not mimetypes.inited:
        mimetypes.init()  # try to read system mime.types
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({
        '': 'application/octet-stream',  # Default
        '.py': 'text/plain',
        '.c': 'text/plain',
        '.h': 'text/plain',
    })


nobody = None


def nobody_uid():
    """Internal routine to get nobody's uid"""
    global nobody
    if nobody:
        return nobody
    try:
        import pwd
    except ImportError:
        return -1
    try:
        nobody = pwd.getpwnam('nobody')[2]
    except KeyError:
        nobody = 1 + max(x[2] for x in pwd.getpwall())
    return nobody


def executable(path):
    """Test for executable file."""
    return os.access(path, os.X_OK)


def _get_best_family(*address):
    infos = socket.getaddrinfo(
        *address,
        type=socket.SOCK_STREAM,
        flags=socket.AI_PASSIVE,
    )
    family, type, proto, canonname, sockaddr = next(iter(infos))
    return family, sockaddr


# ensure dual-stack is not disabled; ref #38907
class DualStackServer(ThreadingHTTPServer):
    def server_bind(self):
        # suppress exception when protocol is IPv4
        with contextlib.suppress(Exception):
            self.socket.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        return super().server_bind()


class CORSRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        SimpleHTTPRequestHandler.end_headers(self)


def copy(text):
    command = 'echo \'' + text.strip() + '\' | xclip -r -sel clip'
    os.system(command)


def check_copy(index, address):
    if index.endswith(".sh"):
        copy_str = f"curl -k -s {address} | bash"
    elif index.endswith(".ps1"):
        copy_str = f'IEX(New-Object Net.Webclient).downloadString("{address}")'
    else:
        copy_str = f"wget {address} -O /dev/shm/{os.path.basename(index)}"

    if copy_str and ask(f"Copy '{copy_str}' to clipboard? "):
        copy(copy_str)
        log_success("Copied ✔️")


def start(port, bind, index, use_ssl):
    server_class = DualStackServer
    protocol = "HTTP/1.0"

    index = eval_index(index)
    bind = eval_bind(bind)

    port = get_available_port(port)

    if port < 0:
        log_error("No open port available", exit=True)

    server_class.address_family, addr = _get_best_family(bind, port)

    address = f"http{'s' if use_ssl else ''}://{bind}:{port}"
    log_normal(
        f"Serving {YELLOW + os.path.abspath(index) + NO_COLOR} at {address}")

    if os.path.isfile(index):
        check_copy(index, address)

    HandlerClass = partial(CORSRequestHandler,
                           index=index, replacers=replacers)

    HandlerClass.protocol_version = protocol
    with server_class(addr, HandlerClass) as httpd:
        try:
            if use_ssl:
                certfile = cert_gen()
                httpd.socket = ssl.wrap_socket(httpd.socket,
                                               server_side=True,
                                               certfile=certfile,
                                               ssl_version=ssl.PROTOCOL_TLS)
            httpd.serve_forever()
        except KeyboardInterrupt:
            log_error("\nKeyboard interrupt received, exiting.", exit=True)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--bind', '-b', metavar='addr',
                        help=f'Specify alternate bind address, default: {DEFAULT_BIND}')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Increase verbosity, print request')
    parser.add_argument('index', default=os.getcwd(), nargs='?',
                        help='Specify content to serve, defaults to current directory')
    parser.add_argument('port', action='store',
                        default=9000, type=int,
                        nargs='?',
                        help=f'Specify alternate port, default: {DEFAULT_PORT}')
    parser.add_argument('--ssl', '-ssl', action='store_true',
                        help='Use SSL')

    parser.add_argument('--kv', default="", metavar='K1=V1:K2=V2',
                        help='Specify match-and-replace rules')

    args = parser.parse_args()

    set_global_verbose(args.verbose)

    key_values = args.kv
    replacers = {}

    if key_values:
        try:
            log_verbose("Rules:")
            for part in key_values.split(":"):
                pair = part.split("=")
                replacers[pair[0]] = pair[1]
                log_verbose(f"\t{pair[0]} ➝  {pair[1]}")
                pass
        except:
            log_normal("Invalid replace values given")

    start(
        port=args.port,
        bind=args.bind,
        index=args.index,
        use_ssl=args.ssl,
    )
