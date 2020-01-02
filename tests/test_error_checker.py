#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from unittest import TestCase

import requests
import requests_mock

from yawast.scanner.plugins.http import error_checker


class TestErrorChecker(TestCase):
    def test_check_response_none(self):
        with requests_mock.Mocker() as m:
            url = "http://example.com"
            m.get(url, text="body")

            resp = requests.get(url)

        res = error_checker.check_response(url, resp)

        self.assertEqual(0, len(res))

    def test_check_response_php(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="Fatal error: Call to a member function getId() on a non-object "
                "in /var/www/docroot/application/modules/controllers/"
                "ModalController.php on line 609",
            )

            resp = requests.get(url)

        res = error_checker.check_response(url, resp)

        self.assertEqual(1, len(res))

    def test_check_response_java(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="Failed to convert property value of type [java.lang.String] to"
                " required type [boolean] for property order; nested exception is"
                " java.lang.IllegalArgumentException",
            )

            resp = requests.get(url)

        res = error_checker.check_response(url, resp)

        self.assertEqual(1, len(res))

    def test_check_response_fp(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(url, text="at (202)")

            resp = requests.get(url)

        res = error_checker.check_response(url, resp)

        self.assertEqual(0, len(res))
