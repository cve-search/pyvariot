# Python client and module to query the VARIoT IoT vulnerabilities and exploits databases

This is a Python client and module to query the [VARIoT IoT vulnerabilities and exploits databases](https://www.variotdbs.pl/api/).

## Installation

```bash
pip install pyvariot
```

## Usage

### Command line

You can use the `pyvariot` command to query the database:

```bash
$ pyvariot --help
usage: pyvariot [-h] [--url URL] [--apikey APIKEY]
                (--vulnerability_id VULNERABILITY_ID | --exploit_id EXPLOIT_ID)

Get a vulnerability or an exploit by ID.

options:
  -h, --help            show this help message and exit
  --url URL             URL of the instance.
  --apikey APIKEY       Your personal API key.
  --vulnerability_id VULNERABILITY_ID
                        ID of the vulnerability.
  --exploit_id EXPLOIT_ID
                        ID of the exploit.

```

### Library

See [API Reference](https://pyvariot.readthedocs.io/en/latest/api_reference.html)
