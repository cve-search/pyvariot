#!/usr/bin/env python3

import unittest

from datetime import datetime, timezone

from pyvariot import PyVARIoT


class TestBasic(unittest.TestCase):

    def setUp(self) -> None:
        self.client = PyVARIoT()
        # self.client.apikey = ''

    def test_up(self) -> None:
        self.assertTrue(self.client.is_up)

    def test_get_vulnerability(self) -> None:
        vuln = self.client.get_vulnerability('VAR-202405-2633')
        self.assertEqual(vuln['id'], 'VAR-202405-2633')
        vuln = self.client.get_vulnerability('VAR-202405-2633', jsonld=True)
        self.assertEqual(vuln['id'], 'VAR-202405-2633')
        self.assertEqual(vuln['affected_products']['@context']['@vocab'], 'https://www.variotdbs.pl/ref/affected_products#')

    def test_get_exploit(self) -> None:
        exploit = self.client.get_exploit('VAR-E-202403-0059')
        self.assertEqual(exploit['id'], 'VAR-E-202403-0059')
        exploit = self.client.get_exploit('VAR-E-202403-0059', jsonld=True)
        self.assertEqual(exploit['id'], 'VAR-E-202403-0059')
        self.assertEqual(exploit['affected_products']['@context']['@vocab'], 'https://www.variotdbs.pl/ref/affected_products#')

    def test_get_vulnerabilities(self) -> None:
        since = datetime(2024, 6, 2, 22, tzinfo=timezone.utc)
        before = datetime(2024, 6, 2, 23, tzinfo=timezone.utc)
        limit = 1
        offset = 0
        vulns = self.client.get_vulnerabilities(since=since, before=before, limit=limit, offset=offset)
        self.assertEqual(len(vulns['results']), 1)

    def test_get_vulnerabilities_iter(self) -> None:
        since = datetime(2024, 6, 2, 22, tzinfo=timezone.utc)
        before = datetime(2024, 6, 2, 23, tzinfo=timezone.utc)
        limit = 20
        vulns_ids = []
        for vuln in self.client.get_vulnerabilities_iter(since=since, before=before, limit=limit):
            vulns_ids.append(vuln['id'])
        self.assertEqual(len(vulns_ids), 29)

    def test_get_exploits_iter(self) -> None:
        since = datetime(2023, 12, 13, 13, tzinfo=timezone.utc)
        before = datetime(2023, 12, 13, 14, tzinfo=timezone.utc)
        limit = 5
        exploits_ids = []
        for exploit in self.client.get_exploits_iter(since=since, before=before, limit=limit):
            exploits_ids.append(exploit['id'])
        self.assertEqual(len(exploits_ids), 11)
