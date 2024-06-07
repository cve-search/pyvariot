from __future__ import annotations

import argparse
import json
import sys

from .api import PyVARIoT

__all__ = ['PyVARIoT']


def main() -> None:
    parser = argparse.ArgumentParser(description='Get a vulnerability or an exploit by ID.')
    parser.add_argument('--url', type=str, help='URL of the instance.')
    parser.add_argument('--apikey', type=str, help='Your personal API key.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--vulnerability_id', type=str, help='ID of the vulnerability.')
    group.add_argument('--exploit_id', type=str, help='ID of the exploit.')
    args = parser.parse_args()

    if args.url:
        client = PyVARIoT(args.url)
    else:
        client = PyVARIoT()

    if args.apikey:
        client.apikey = args.apikey

    if not client.is_up:
        print(f'Unable to reach {client.root_url}. Is the server up?')
        sys.exit(1)

    if args.vulnerability_id:
        vulnerability = client.get_vulnerability(args.vulnerability_id)
        print(json.dumps(vulnerability, indent=2))

    if args.exploit_id:
        exploit = client.get_exploit(args.exploit_id)
        print(json.dumps(exploit, indent=2))
