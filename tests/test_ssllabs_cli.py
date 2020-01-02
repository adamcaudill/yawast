#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import json
import os
from unittest import TestCase

from tests import utils
from yawast.scanner.cli.ssl_labs import (
    _get_cert_info,
    _get_protocol_info,
    _get_vulnerability_info,
)
from yawast.shared import output


class TestSslLabsCLI(TestCase):
    def test__get_cert_info(self):
        output.setup(False, False, False)
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/ssl_labs_analyze_data.json")
        with open(path) as json_file:
            body = json.load(json_file)

        try:
            for ep in body["endpoints"]:
                with utils.capture_sys_output():
                    _get_cert_info(body, ep, "http://adamcaudill.com")
        except Exception as error:
            print(error)
            self.assertIsNone(error)

    def test__get_protocol_info(self):
        output.setup(False, False, False)
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/ssl_labs_analyze_data.json")
        with open(path) as json_file:
            body = json.load(json_file)

        try:
            for ep in body["endpoints"]:
                with utils.capture_sys_output():
                    _get_protocol_info(ep, "http://adamcaudill.com")
        except Exception as error:
            print(error)
            self.assertIsNone(error)

    def test__get_vulnerability_info(self):
        output.setup(False, False, False)
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/ssl_labs_analyze_data.json")
        with open(path) as json_file:
            body = json.load(json_file)

        try:
            for ep in body["endpoints"]:
                with utils.capture_sys_output():
                    _get_vulnerability_info(ep, "http://adamcaudill.com")
        except Exception as error:
            print(error)
            self.assertIsNone(error)
