#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.
import os
from pathlib import Path
from unittest import TestCase

import requests
import requests_mock

from tests import utils
from yawast import command_line
from yawast.scanner.cli import http
from yawast.scanner.plugins.http import http_basic, response_scanner, file_search
from yawast.scanner.plugins.http.applications import wordpress, jira
from yawast.scanner.plugins.http.response_scanner import _check_cache_headers
from yawast.scanner.plugins.http.servers import rails, python, nginx, php
from yawast.scanner.session import Session
from yawast.shared import network, output


class TestHttpBasic(TestCase):
    def test_get_header_issues_no_sec_headers(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(url, text="body")

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        self.assertEqual(7, len(res))

    def test_get_header_issues_none(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="body",
                headers={
                    "X-XSS-Protection": "1",
                    "X-Frame-Options": "blah",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "blah",
                    "Referrer-Policy": "blah",
                    "Feature-Policy": "blah",
                    "Strict-Transport-Security": "blah",
                    "Server": "blah",
                },
            )

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        self.assertEqual(0, len(res))

    def test_get_header_issues_powered_by(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="body",
                headers={
                    "X-XSS-Protection": "1",
                    "X-Frame-Options": "blah",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "blah",
                    "Referrer-Policy": "blah",
                    "Feature-Policy": "blah",
                    "Strict-Transport-Security": "blah",
                    "X-Powered-By": "blah",
                },
            )

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        self.assertEqual(1, len(res))
        self.assertIn("X-Powered-By Header Present", res[0].message)

    def test_get_header_issues_xss(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="body",
                headers={
                    "X-XSS-Protection": "0",
                    "X-Frame-Options": "blah",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "blah",
                    "Referrer-Policy": "blah",
                    "Feature-Policy": "blah",
                    "Strict-Transport-Security": "blah",
                },
            )

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        self.assertEqual(1, len(res))
        self.assertIn("X-XSS-Protection Disabled Header Present", res[0].message)

    def test_get_header_issues_runtime(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="body",
                headers={
                    "X-XSS-Protection": "1",
                    "X-Frame-Options": "blah",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "blah",
                    "Referrer-Policy": "blah",
                    "Feature-Policy": "blah",
                    "Strict-Transport-Security": "blah",
                    "X-Runtime": "1",
                },
            )

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        self.assertEqual(1, len(res))
        self.assertIn("X-Runtime Header Present", res[0].message)

    def test_get_header_issues_backend(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="body",
                headers={
                    "X-XSS-Protection": "1",
                    "X-Frame-Options": "blah",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "blah",
                    "Referrer-Policy": "blah",
                    "Feature-Policy": "blah",
                    "Strict-Transport-Security": "blah",
                    "X-Backend-Server": "1",
                },
            )

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        self.assertEqual(1, len(res))
        self.assertIn("X-Backend-Server Header Present", res[0].message)

    def test_get_header_issues_via(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="body",
                headers={
                    "X-XSS-Protection": "1",
                    "X-Frame-Options": "blah",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "blah",
                    "Referrer-Policy": "blah",
                    "Feature-Policy": "blah",
                    "Strict-Transport-Security": "blah",
                    "Via": "1",
                },
            )

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        self.assertEqual(1, len(res))
        self.assertIn("Via Header Present", res[0].message)

    def test_get_header_issues_xfa(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="body",
                headers={
                    "X-XSS-Protection": "1",
                    "X-Frame-Options": "allow",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "blah",
                    "Referrer-Policy": "blah",
                    "Feature-Policy": "blah",
                    "Strict-Transport-Security": "blah",
                },
            )

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        self.assertEqual(1, len(res))
        self.assertIn("X-Frame-Options Header", res[0].message)

    def test_get_header_issues_acao(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="body",
                headers={
                    "X-XSS-Protection": "1",
                    "X-Frame-Options": "blah",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "blah",
                    "Referrer-Policy": "blah",
                    "Feature-Policy": "blah",
                    "Strict-Transport-Security": "blah",
                    "Access-Control-Allow-Origin": "*",
                },
            )

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        self.assertEqual(1, len(res))
        self.assertIn("Access-Control-Allow-Origin: Unrestricted", res[0].message)

    def test_check_propfind_none_err(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("PROPFIND", url, text="body", status_code=500)

            res = http_basic.check_propfind(url)

        for r in res:
            self.assertNotIn("PROPFIND Enabled", r.message)

    def test_check_propfind_none_ok(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("PROPFIND", url, text="body", status_code=200)

            res = http_basic.check_propfind(url)

        for r in res:
            self.assertNotIn("PROPFIND Enabled", r.message)

    def test_check_propfind(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri(
                "PROPFIND",
                url,
                text="body",
                status_code=200,
                headers={"Content-Type": "text/xml"},
            )

            res = http_basic.check_propfind(url)

        self.assertTrue(any("PROPFIND Enabled" in r.message for r in res))

    def test_check_trace_none_err(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("TRACE", url, text="body", status_code=500)

            res = http_basic.check_trace(url)

        for r in res:
            self.assertNotIn("HTTP TRACE Enabled", r.message)

    def test_check_trace_none_ok(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("TRACE", url, text="body", status_code=200)

            res = http_basic.check_trace(url)

        for r in res:
            self.assertNotIn("HTTP TRACE Enabled", r.message)

    def test_check_trace(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("TRACE", url, text="TRACE / HTTP/1.1", status_code=200)

            res = http_basic.check_trace(url)

        self.assertTrue(any("HTTP TRACE Enabled" in r.message for r in res))

    def test_check_opts_none_err(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("OPTIONS", url, status_code=500)

            res = http_basic.check_options(url)

        for r in res:
            self.assertNotIn("HTTP Verbs (OPTIONS)", r.message)

    def test_check_opts_none_ok(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("OPTIONS", url, status_code=200)

            res = http_basic.check_options(url)

        for r in res:
            self.assertNotIn("HTTP Verbs (OPTIONS)", r.message)

    def test_check_opts_allow(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("OPTIONS", url, status_code=200, headers={"Allow": "GET"})

            res = http_basic.check_options(url)

        self.assertTrue(any("Allow HTTP Verbs (OPTIONS)" in r.message for r in res))

    def test_check_opts_public(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("OPTIONS", url, status_code=200, headers={"Public": "GET"})

            res = http_basic.check_options(url)

        self.assertTrue(any("Public HTTP Verbs (OPTIONS)" in r.message for r in res))

    def test_cache_headers_none(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.get(url, text="body", headers={})

            resp = requests.get(url)

        res = _check_cache_headers(url, resp)

        self.assertTrue(any("Cache-Control Header Not Found" in r.message for r in res))
        self.assertTrue(any("Expires Header Not Found" in r.message for r in res))
        self.assertTrue(any("Pragma: no-cache Not Found" in r.message for r in res))

    def test_cache_headers_expires(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.get(url, text="body", headers={"Expires": "1"})

            resp = requests.get(url)

        res = _check_cache_headers(url, resp)

        self.assertFalse(any("Expires Header Not Found" in r.message for r in res))

    def test_cache_headers_pragma(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.get(url, text="body", headers={"Pragma": "no-cache"})

            resp = requests.get(url)

        res = _check_cache_headers(url, resp)

        self.assertFalse(any("Pragma: no-cache Not Found" in r.message for r in res))

    def test_cache_headers_cc_public(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.get(url, text="body", headers={"Cache-Control": "Public"})

            resp = requests.get(url)

        res = _check_cache_headers(url, resp)

        self.assertTrue(any("Cache-Control: Public" in r.message for r in res))
        self.assertTrue(
            any("Cache-Control: no-cache Not Found" in r.message for r in res)
        )
        self.assertTrue(
            any("Cache-Control: no-store Not Found" in r.message for r in res)
        )
        self.assertTrue(
            any("Cache-Control: private Not Found" in r.message for r in res)
        )

    def test_cache_headers_cc_private(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.get(url, text="body", headers={"Cache-Control": "Private"})

            resp = requests.get(url)

        res = _check_cache_headers(url, resp)

        self.assertTrue(
            any("Cache-Control: no-cache Not Found" in r.message for r in res)
        )
        self.assertTrue(
            any("Cache-Control: no-store Not Found" in r.message for r in res)
        )

    def test_response_scanner(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"
        resp = network.http_get(url)

        http.reset()
        res = response_scanner.check_response(url, resp)

        self.assertTrue(any("External JavaScript File" in r.message for r in res))
        self.assertTrue(any("Vulnerable JavaScript" in r.message for r in res))

    def test_rails_cve_2019_5418_none(self):
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(url, text="body")

            rails.reset()
            res = rails.check_cve_2019_5418(url)

        self.assertFalse(any("Rails CVE-2019-5418" in r.message for r in res))

    def test_rails_cve_2019_5418(self):
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(url, text="root:x:0:0:root:/root:/bin/bash")

            rails.reset()
            res = rails.check_cve_2019_5418(url)

        self.assertTrue(any("Rails CVE-2019-5418" in r.message for r in res))

    def test_rails_cve_2019_5418_fp(self):
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(url, text="root: File")

            rails.reset()
            res = rails.check_cve_2019_5418(url)

        self.assertFalse(any("Rails CVE-2019-5418" in r.message for r in res))

    def test_python_check_banner(self):
        res = python.check_banner("Python/3.0.3", "head_data", "http://example.com")

        self.assertTrue(any("Python Version Exposed" in r.message for r in res))

    def test_nginx_check_banner_gen(self):
        res = nginx.check_banner("nginx", "head_data", "http://example.com")

        self.assertTrue(
            any("Generic Nginx Server Banner Found" in r.message for r in res)
        )

    def test_nginx_check_banner(self):
        res = nginx.check_banner("nginx/1.0.0", "head_data", "http://example.com")

        self.assertTrue(any("Nginx Version Exposed" in r.message for r in res))

    def test_nginx_check_banner_outdated(self):
        res = nginx.check_banner("nginx/1.0.0", "head_data", "http://example.com")

        self.assertTrue(any("Nginx Outdated" in r.message for r in res))

    def test_wp_path_disc_nix(self):
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(
                requests_mock.ANY,
                text="<b>Fatal error</b>:  x y() in <b>/home/akismet.php</b> on line <b>32</b><br />",
            )

            res = wordpress.check_path_disclosure(url)

        self.assertTrue(any("WordPress File Path Disclosure" in r.message for r in res))
        self.assertTrue(any("/home/akismet.php" in r.message for r in res))

    def test_wp_path_disc_win(self):
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(
                requests_mock.ANY,
                text="<b>Fatal error</b>:  x y() in <b>C:\\home\\akismet.php</b> on line <b>32</b><br />",
            )

            res = wordpress.check_path_disclosure(url)

        self.assertTrue(any("WordPress File Path Disclosure" in r.message for r in res))
        self.assertTrue(any("C:\\home\\akismet.php" in r.message for r in res))

    def test_wp_path_disc_none_err(self):
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(
                requests_mock.ANY,
                text="<b>Fatal error</b>:  x y() in /home/akismet.php on line 32",
            )

            res = wordpress.check_path_disclosure(url)

        self.assertFalse(
            any("WordPress File Path Disclosure" in r.message for r in res)
        )

    def test_wp_path_disc_none(self):
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(requests_mock.ANY, text="hello world")

            res = wordpress.check_path_disclosure(url)

        self.assertFalse(
            any("WordPress File Path Disclosure" in r.message for r in res)
        )

    def test_php_find_info(self):
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(requests_mock.ANY, text='</a><h1 class="p">PHP Version 4.4.1</h1>')

            res = php.find_phpinfo([url])

        self.assertTrue(any("PHP Info Found" in r.message for r in res))

    def test_php_find_info_none(self):
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(requests_mock.ANY, text="</a><h1>PHP Version 4.4.1</h1>")

            res = php.find_phpinfo([url])

        self.assertFalse(any("PHP Info Found" in r.message for r in res))

    def test_check_404(self):
        network.init("", "", "X-Test=123")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(requests_mock.ANY, text="body", status_code=200)

                try:
                    file, _, _, _ = network.check_404_response(url)
                except Exception as error:
                    self.assertIsNone(error)

            self.assertNotIn("Exception", stderr.getvalue())
            self.assertNotIn("Error", stderr.getvalue())

    def test_check_put(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.put(requests_mock.ANY, text="body", status_code=200)

                try:
                    res = network.http_put(url, "data")
                except Exception as error:
                    self.assertIsNone(error)

            self.assertNotIn("Exception", stderr.getvalue())
            self.assertNotIn("Error", stderr.getvalue())
            self.assertIsNotNone(res)

    def test_wp_ident(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            try:
                _, res = wordpress.identify(url)
            except Exception as error:
                self.assertIsNone(error)

            self.assertNotIn("Exception", stderr.getvalue())
            self.assertNotIn("Error", stderr.getvalue())
            self.assertTrue(any("Found WordPress" in r.message for r in res))

    def test_wp_json_user_enum(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            try:
                res = wordpress.check_json_user_enum(url)
            except Exception as error:
                self.assertIsNone(error)

            self.assertNotIn("Exception", stderr.getvalue())
            self.assertNotIn("Error", stderr.getvalue())
            self.assertTrue(
                any("WordPress WP-JSON User Enumeration" in r.message for r in res)
            )

    def test_find_backup_ext(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            try:
                http.reset()
                _, _ = file_search.find_backups(
                    [url, f"{url}readme.html", f"{url}#test"]
                )
            except Exception as error:
                self.assertIsNone(error)

            self.assertNotIn("Exception", stderr.getvalue())
            self.assertNotIn("Error", stderr.getvalue())

    def test_find_backup_ext_all(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(requests_mock.ANY, text="body", status_code=200)
                m.head(requests_mock.ANY, status_code=200)

                try:
                    http.reset()
                    _, res = file_search.find_backups([url, f"{url}test/readme.html"])
                except Exception as error:
                    self.assertIsNone(error)

            self.assertNotIn("Exception", stderr.getvalue())
            self.assertNotIn("Error", stderr.getvalue())
            self.assertTrue(any("Found backup file" in r.message for r in res))

    def test_net_init_empty(self):
        try:
            network.init("", "", "")
        except Exception as error:
            self.assertIsNone(error)

        self.assertIsNotNone(network._requester)

        network.reset()

    def test_net_init_none(self):
        try:
            network.init(None, None, None)
        except Exception as error:
            self.assertIsNone(error)

        self.assertIsNotNone(network._requester)

        network.reset()

    def test_net_init_valid_proxy(self):
        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                network.init("http://127.0.0.1:1234", "", "")
        except Exception as error:
            self.assertIsNone(error)

        self.assertIsNotNone(network._requester)
        self.assertNotIn("Exception", stderr.getvalue())
        self.assertNotIn("Error", stdout.getvalue())
        self.assertNotIn("Invalid proxy server specified", stdout.getvalue())

        network.reset()

    def test_net_init_valid_proxy_alt(self):
        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                network.init("127.0.0.1:1234", "", "")
        except Exception as error:
            self.assertIsNone(error)

        self.assertIsNotNone(network._requester)
        self.assertNotIn("Exception", stderr.getvalue())
        self.assertNotIn("Error", stdout.getvalue())
        self.assertNotIn("Invalid proxy server specified", stdout.getvalue())

        network.reset()

    def test_net_init_invalid_proxy_ftp(self):
        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                network.init("ftp://127.0.0.1:1234", "", "")

                _ = network.http_get("http://example.com")
        except Exception as error:
            self.assertIsNone(error)

        self.assertIsNotNone(network._requester)
        self.assertNotIn("Exception", stderr.getvalue())
        self.assertIn("Error", stdout.getvalue())
        self.assertIn("Invalid proxy server specified", stdout.getvalue())

        network.reset()

    def test_net_init_valid_cookie(self):
        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                network.init("", "SESSION=123", "")

                _ = network.http_get("http://example.com")
        except Exception as error:
            self.assertIsNone(error)

        self.assertIsNotNone(network._requester)
        self.assertNotIn("Exception", stderr.getvalue())
        self.assertNotIn("Error", stdout.getvalue())
        self.assertNotIn("cookie must be in NAME=VALUE format", stdout.getvalue())

        network.reset()

    def test_net_init_two_valid_cookie(self):
        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                network.init("", "SESSION=123;C=456", "")

                _ = network.http_get("http://example.com")
        except Exception as error:
            self.assertIsNone(error)

        self.assertIsNotNone(network._requester)
        self.assertNotIn("Exception", stderr.getvalue())
        self.assertNotIn("Error", stdout.getvalue())
        self.assertNotIn("cookie must be in NAME=VALUE format", stdout.getvalue())

        network.reset()

    def test_net_init_invalid_cookie(self):
        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                network.init("", "SESSION123", "")

                _ = network.http_get("http://example.com")
        except Exception as error:
            self.assertIsNone(error)

        self.assertIsNotNone(network._requester)
        self.assertNotIn("Exception", stderr.getvalue())
        self.assertIn("Error", stdout.getvalue())
        self.assertIn("cookie must be in NAME=VALUE format", stdout.getvalue())

        network.reset()

    def test_net_init_valid_header(self):
        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                network.init("", "", "AUTH=123")

                _ = network.http_get("http://example.com")
        except Exception as error:
            self.assertIsNone(error)

        self.assertIsNotNone(network._requester)
        self.assertNotIn("Exception", stderr.getvalue())
        self.assertNotIn("Error", stdout.getvalue())
        self.assertNotIn("header must be in NAME=VALUE format", stdout.getvalue())

        network.reset()

    def test_net_init_valid_header_alt(self):
        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                network.init("", "", "AUTH: 123")

                _ = network.http_get("http://example.com")
        except Exception as error:
            self.assertIsNone(error)

        self.assertIsNotNone(network._requester)
        self.assertNotIn("Exception", stderr.getvalue())
        self.assertNotIn("Error", stdout.getvalue())
        self.assertNotIn("header must be in NAME=VALUE format", stdout.getvalue())

        network.reset()

    def test_net_init_invalid_header(self):
        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                network.init("", "", "AUTH123")

                _ = network.http_get("http://example.com")
        except Exception as error:
            self.assertIsNone(error)

        self.assertIsNotNone(network._requester)
        self.assertNotIn("Exception", stderr.getvalue())
        self.assertIn("Error", stdout.getvalue())
        self.assertIn("header must be in NAME=VALUE format", stdout.getvalue())

        network.reset()

    def test_jira_found(self):
        url = "https://www.example.org/"

        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/jira_dashboard.txt")
        contents = Path(path).read_text()

        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                with requests_mock.Mocker() as m:
                    m.get(url, text="body", status_code=200)
                    m.get(f"{url}secure/Dashboard.jspa", text=contents, status_code=200)
                    m.get(
                        f"{url}jira/secure/Dashboard.jspa", text="body", status_code=404
                    )

                    session = Session(None, url)

                    results, jira_url = jira.check_for_jira(session)
        except Exception as error:
            self.assertIsNone(error)

        self.assertIsNotNone(jira_url)
        self.assertIsNotNone(results)
        self.assertTrue(len(results) > 0)
        self.assertNotIn("Exception", stderr.getvalue())
        self.assertNotIn("Error", stdout.getvalue())
        self.assertTrue(any("Jira Installation Found" in r.message for r in results))
        self.assertTrue(any("v8.1.0-801000" in r.message for r in results))

        network.reset()

    def test_jira_user_reg(self):
        url = "https://www.example.org/secure/Dashboard.jspa"

        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/jira_registration.txt")
        contents = Path(path).read_text()

        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                with requests_mock.Mocker() as m:
                    m.get(
                        "https://www.example.org/secure/Signup!default.jspa",
                        text=contents,
                        status_code=200,
                    )

                    results = jira.check_jira_user_registration(url)
        except Exception as error:
            self.assertIsNone(error)

        self.assertIsNotNone(results)
        self.assertTrue(len(results) > 0)
        self.assertNotIn("Exception", stderr.getvalue())
        self.assertNotIn("Error", stdout.getvalue())
        self.assertTrue(
            any("Jira User Registration Enabled" in r.message for r in results)
        )

        network.reset()

    def test_ds_store(self):
        url = "https://www.example.org/"

        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                with requests_mock.Mocker() as m:
                    m.get(requests_mock.ANY, content=b"\0\0\0\1Bud1\0", status_code=200)

                    results = file_search.find_ds_store([url])
        except Exception as error:
            self.assertIsNone(error)

        self.assertIsNotNone(results)
        self.assertTrue(len(results) > 0)
        self.assertNotIn("Exception", stderr.getvalue())
        self.assertNotIn("Error", stdout.getvalue())
        self.assertTrue(any(".DS_Store File Found" in r.message for r in results))

        network.reset()

    def test_cve_2019_11043_false(self):
        network.init("", "", "")
        output.setup(False, False, False)
        url = "https://www.example.org/"

        p = command_line.build_parser()
        ns = p.parse_args(args=["scan"])
        s = Session(ns, url)

        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                with requests_mock.Mocker() as m:
                    m.get(requests_mock.ANY, status_code=200)
                    m.head(requests_mock.ANY, status_code=200)

                    results = php.check_cve_2019_11043(
                        s, ["https://www.example.org/test/"]
                    )
        except Exception as error:
            self.assertIsNone(error)

        self.assertIsNotNone(results)
        self.assertTrue(len(results) == 0)
        self.assertNotIn("Exception", stderr.getvalue())
        self.assertNotIn("Error", stdout.getvalue())

        network.reset()
