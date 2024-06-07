#!/usr/bin/env python3

import unittest

from pyproject import PyProject


class TestBasic(unittest.TestCase):

    def setUp(self) -> None:
        self.client = PyProject(root_url="http://127.0.0.1:9999")

    def test_up(self) -> None:
        self.assertTrue(self.client.is_up)
        self.assertTrue(self.client.redis_up())
