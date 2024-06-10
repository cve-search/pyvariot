#!/usr/bin/env python3

from __future__ import annotations

from datetime import datetime
from importlib.metadata import version
from typing import Any, Generator
from urllib.parse import urljoin, urlparse, parse_qsl
from pathlib import PurePosixPath

import requests


class PyVARIoT():

    def __init__(self, root_url: str='https://www.variotdbs.pl/', useragent: str | None=None,
                 *, proxies: dict[str, str] | None=None):
        '''Query a specific instance.

        :params root_url: URL of the instance to query.
        :params useragent: The User Agent used by requests to run the HTTP requests against the instance.
        :params proxies: The proxies to use to connect to theinstance - More details: https://requests.readthedocs.io/en/latest/user/advanced/#proxies
        '''
        self.root_url = root_url

        if not urlparse(self.root_url).scheme:
            self.root_url = 'http://' + self.root_url
        if not self.root_url.endswith('/'):
            self.root_url += '/'
        self.session = requests.session()
        self.session.headers['user-agent'] = useragent if useragent else f'PyVARIoT / {version("pyvariot")}'
        if proxies:
            self.session.proxies.update(proxies)

        self._apikey: str | None = None

    @property
    def apikey(self) -> str | None:
        return self._apikey

    @apikey.setter
    def apikey(self, apikey: str) -> None:
        '''Set the API key to use for the requests.

        :params apikey: The API key to use for the requests.
        '''
        self._apikey = apikey
        self.session.headers['Authorization'] = f'Token {self._apikey}'

    @property
    def is_up(self) -> bool:
        '''Test if the given instance is accessible'''
        try:
            r = self.session.head(self.root_url)
        except requests.exceptions.ConnectionError:
            return False
        return r.status_code == 200

    def get_vulnerability(self, vulnerability_id: str, /, *, jsonld: bool=False) -> dict[str, Any]:
        '''Get a vulnerability by its ID.

        :param vulnerability_id: The ID of the vulnerability to get.
        :param jsonld: Whether to return the JSON-LD representation of the vulnerability.
        '''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('api', 'vuln', vulnerability_id))),
                             params={'jsonld': jsonld})
        return r.json()

    def get_exploit(self, exploit_id: str, /, *, jsonld: bool=False) -> dict[str, Any]:
        '''Get an exploit by its ID.

        :param exploit_id: The ID of the exploit to get.
        :param jsonld: Whether to return the JSON-LD representation of the exploit.
        '''
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('api', 'exploit', exploit_id))),
                             params={'jsonld': jsonld})
        return r.json()

    def __prepare_params(self, jsonld: bool=False,
                         since: datetime | None=None, before: datetime | None=None,
                         limit: int | None=None, offset: int | None=None) -> dict[str, bool | str | int]:
        '''Prepare the parameters for the requests.'''
        params: dict[str, bool | str | int] = {'jsonld': jsonld}
        if since:
            params['since'] = since.isoformat()
        if before:
            params['before'] = before.isoformat()
        if limit:
            params['limit'] = limit
        if offset:
            params['offset'] = offset
        return params

    def get_vulnerabilities(self, /, *, jsonld: bool=False,
                            since: datetime | None=None, before: datetime | None=None,
                            limit: int | None=None, offset: int | None=None) -> dict[str, Any]:
        '''Get vulnerabilities on an interval.

        :param jsonld: Whether to return the JSON-LD representation of the vulnerabilities.
        :param since: The date from which to get the vulnerabilities.
        :param before: The date until which to get the vulnerabilities.
        :param limit: The maximum number of vulnerabilities to get in one call.
        :param offset: The offset to start getting the vulnerabilities.
        '''
        params = self.__prepare_params(jsonld, since, before, limit, offset)
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('api', 'vulns'))),
                             params=params)
        return r.json()

    def get_vulnerabilities_iter(self, /, *, jsonld: bool=False,
                                 since: datetime | None=None, before: datetime | None=None,
                                 limit: int | None=None, offset: int | None=None) -> Generator[dict[str, Any], None, None]:
        '''Get vulnerabilities on an interval, automatically iterates over all the matching vulerabilities.

        :param jsonld: Whether to return the JSON-LD representation of the vulnerabilities.
        :param since: The date from which to get the vulnerabilities.
        :param before: The date until which to get the vulnerabilities.
        :param limit: The maximum number of vulnerabilities to get in one call.
        :param offset: The offset to start getting the vulnerabilities.
        '''
        while True:
            r = self.get_vulnerabilities(jsonld=jsonld, since=since, before=before, limit=limit, offset=offset)
            if not r:
                break
            for vuln in r['results']:
                yield vuln
            if not r['next']:
                break
            next_params = dict(parse_qsl(urlparse(r['next']).query))
            since = datetime.fromisoformat(next_params['since']) if next_params.get('since') else None
            before = datetime.fromisoformat(next_params['before']) if next_params.get('before') else None
            limit = int(next_params['limit'])
            offset = int(next_params['offset'])
            jsonld = False if next_params['offset'] == 'False' else True

    def get_exploits(self, /, *, jsonld: bool=False,
                     since: datetime | None=None, before: datetime | None=None,
                     limit: int | None=None, offset: int | None=None) -> dict[str, Any]:
        '''Get exploits on an interval.

        :param jsonld: Whether to return the JSON-LD representation of the exploits.
        :param since: The date from which to get the exploits.
        :param before: The date until which to get the exploits.
        :param limit: The maximum number of exploits to get in one call.
        :param offset: The offset to start getting the exploits.
        '''
        params = self.__prepare_params(jsonld, since, before, limit, offset)
        r = self.session.get(urljoin(self.root_url, str(PurePosixPath('api', 'exploits'))),
                             params=params)
        return r.json()

    def get_exploits_iter(self, /, *, jsonld: bool=False,
                          since: datetime | None=None, before: datetime | None=None,
                          limit: int | None=None, offset: int | None=None) -> Generator[dict[str, Any], None, None]:
        '''Get exploits on an interval, automatically iterates over all the matching exploits.

        :param jsonld: Whether to return the JSON-LD representation of the exploits.
        :param since: The date from which to get the exploits.
        :param before: The date until which to get the exploits.
        :param limit: The maximum number of exploits to get in one call.
        :param offset: The offset to start getting the exploits.
        '''
        while True:
            r = self.get_exploits(jsonld=jsonld, since=since, before=before, limit=limit, offset=offset)
            if not r:
                break
            for exploit in r['results']:
                yield exploit
            if not r['next']:
                break
            next_params = dict(parse_qsl(urlparse(r['next']).query))
            since = datetime.fromisoformat(next_params['since'])
            before = datetime.fromisoformat(next_params['before'])
            limit = int(next_params['limit'])
            offset = int(next_params['offset'])
            jsonld = False if next_params['offset'] == 'False' else True
