#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from unittest import TestCase

import requests
import requests_mock

from yawast.scanner.plugins.http import http_basic
from yawast.scanner.plugins.http.http_basic import get_cookie_issues


class TestGetCookieIssues(TestCase):
    def test__get_cookie_issues_no_sec_no_tls(self):
        http_basic.reset()

        with requests_mock.Mocker() as m:
            url = "http://example.com"
            m.get(
                url,
                text="body",
                headers={
                    "Set-Cookie": "sessionid=38afes7a8; HttpOnly; SameSite=Lax; Path=/"
                },
            )

            resp = requests.get(url)

        res = get_cookie_issues(resp, url)

        self.assertEqual(0, len(res))

    def test__get_cookie_issues_sec_no_tls(self):
        http_basic.reset()

        with requests_mock.Mocker() as m:
            url = "http://example.com"
            m.get(
                url,
                text="body",
                headers={
                    "Set-Cookie": "sessionid=38afes7a8; HttpOnly; Secure; SameSite=Lax; Path=/"
                },
            )

            resp = requests.get(url)

        res = get_cookie_issues(resp, url)

        self.assertEqual(1, len(res))
        self.assertIn("Cookie Secure Flag Invalid (over HTTP)", res[0].message)

    def test__get_cookie_issues_no_sec_ssn(self):
        http_basic.reset()

        with requests_mock.Mocker() as m:
            url = "https://example.com"
            m.get(
                url,
                text="body",
                headers={
                    "Set-Cookie": "sessionid=38afes7a8; HttpOnly; SameSite=None; Path=/"
                },
            )

            resp = requests.get(url)

        res = get_cookie_issues(resp, url)

        self.assertEqual(2, len(res))
        self.assertIn("Cookie Missing Secure Flag", res[0].message)
        self.assertIn(
            "Cookie SameSite=None Flag Invalid (without Secure flag)", res[1].message
        )

    def test__get_cookie_issues_ssn(self):
        http_basic.reset()

        with requests_mock.Mocker() as m:
            url = "https://example.com"
            m.get(
                url,
                text="body",
                headers={
                    "Set-Cookie": "sessionid=38afes7a8; HttpOnly; Secure; SameSite=None; Path=/"
                },
            )

            resp = requests.get(url)

        res = get_cookie_issues(resp, url)

        self.assertEqual(1, len(res))

    def test__get_cookie_issues_no_sec(self):
        http_basic.reset()

        with requests_mock.Mocker() as m:
            url = "https://example.com"
            m.get(
                url,
                text="body",
                headers={
                    "Set-Cookie": "sessionid=38afes7a8; HttpOnly; SameSite=Lax; Path=/"
                },
            )

            resp = requests.get(url)

        res = get_cookie_issues(resp, url)

        self.assertEqual(1, len(res))
        self.assertIn("Cookie Missing Secure Flag", res[0].message)

    def test__get_cookie_issues_no_ho(self):
        http_basic.reset()

        with requests_mock.Mocker() as m:
            url = "http://example.com"
            m.get(
                url,
                text="body",
                headers={"Set-Cookie": "sessionid=38afes7a8; SameSite=Lax; Path=/"},
            )

            resp = requests.get(url)

        res = get_cookie_issues(resp, url)

        self.assertEqual(1, len(res))
        self.assertIn("Cookie Missing HttpOnly Flag", res[0].message)

    def test__get_cookie_issues_no_ss(self):
        http_basic.reset()

        with requests_mock.Mocker() as m:
            url = "https://example.com"
            m.get(
                url,
                text="body",
                headers={"Set-Cookie": "sessionid=38afes7a8; Secure; HttpOnly; Path=/"},
            )

            resp = requests.get(url)

        res = get_cookie_issues(resp, url)

        self.assertEqual(1, len(res))
        self.assertIn("Cookie Missing SameSite Flag", res[0].message)

    def test__get_cookie_bigip_1(self):
        http_basic.reset()

        with requests_mock.Mocker() as m:
            url = "http://example.com"
            m.get(
                url,
                text="body",
                headers={
                    "Set-Cookie": "BIGipServerWEB=2263487148.3013.0000; HttpOnly; SameSite=Lax; Path=/"
                },
            )

            resp = requests.get(url)

        res = get_cookie_issues(resp, url)

        self.assertEqual(1, len(res))
        self.assertIn("Big-IP Internal IP Address Disclosure", res[0].message)

    def test__get_cookie_bigip_2(self):
        http_basic.reset()

        with requests_mock.Mocker() as m:
            url = "http://example.com"
            m.get(
                url,
                text="body",
                headers={
                    "Set-Cookie": "BIGipServerWEB=rd5o00000000000000000000ffffc0000201o80; HttpOnly; SameSite=Lax; Path=/"
                },
            )

            resp = requests.get(url)

        res = get_cookie_issues(resp, url)

        self.assertEqual(1, len(res))
        self.assertIn("Big-IP Internal IP Address Disclosure", res[0].message)

    def test__get_cookie_bigip_3(self):
        http_basic.reset()

        with requests_mock.Mocker() as m:
            url = "http://example.com"
            m.get(
                url,
                text="body",
                headers={
                    "Set-Cookie": "BIGipServerWEB=vi20010112000000000000000000000030.20480; HttpOnly; SameSite=Lax; Path=/"
                },
            )

            resp = requests.get(url)

        res = get_cookie_issues(resp, url)

        self.assertEqual(1, len(res))
        self.assertIn("Big-IP Internal IP Address Disclosure", res[0].message)

    def test__get_cookie_bigip_4(self):
        http_basic.reset()

        with requests_mock.Mocker() as m:
            url = "http://example.com"
            m.get(
                url,
                text="body",
                headers={
                    "Set-Cookie": "BIGipServerWEB=rd3o20010112000000000000000000000030o80; HttpOnly; SameSite=Lax; Path=/"
                },
            )

            resp = requests.get(url)

        res = get_cookie_issues(resp, url)

        self.assertEqual(1, len(res))
        self.assertIn("Big-IP Internal IP Address Disclosure", res[0].message)
