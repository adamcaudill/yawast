#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from unittest import TestCase

from yawast.shared import utils


class TestExtractUrl(TestCase):
    def test_extract_url_clean(self):
        self.assertEqual(
            "https://adamcaudill.com/", utils.extract_url("https://adamcaudill.com/")
        )

    def test_extract_url_clean_port(self):
        self.assertEqual(
            "https://adamcaudill.com:8080/",
            utils.extract_url("https://adamcaudill.com:8080/"),
        )

    def test_extract_url_clean_creds(self):
        self.assertEqual(
            "https://user:pass@adamcaudill.com/",
            utils.extract_url("https://user:pass@adamcaudill.com/"),
        )

    def test_extract_url_clean_wss(self):
        self.assertEqual(
            "wss://adamcaudill.com/", utils.extract_url("wss://adamcaudill.com/")
        )

    def test_extract_url_path(self):
        self.assertEqual(
            "https://adamcaudill.com/t/",
            utils.extract_url("https://adamcaudill.com/t/"),
        )

    def test_extract_url_path_upper(self):
        self.assertEqual(
            "https://adamcaudill.com/T/",
            utils.extract_url("HTTPS://ADAMCAUDILL.COM/T/"),
        )

    def test_extract_url_missing_colon(self):
        self.assertEqual(
            "https://adamcaudill.com/", utils.extract_url("https//adamcaudill.com/")
        )

    def test_extract_url_missing_slash(self):
        self.assertEqual(
            "https://adamcaudill.com/", utils.extract_url("https:/adamcaudill.com/")
        )

    def test_extract_url_extra_slash(self):
        self.assertEqual(
            "https://adamcaudill.com/", utils.extract_url("https:///adamcaudill.com/")
        )

    def test_extract_url_extra_extra_slash(self):
        self.assertEqual(
            "https://adamcaudill.com/", utils.extract_url("https:////adamcaudill.com/")
        )

    def test_extract_url_missing_path(self):
        self.assertEqual(
            "https://adamcaudill.com/", utils.extract_url("https://adamcaudill.com")
        )

    def test_extract_url_file_name(self):
        self.assertEqual(
            "https://adamcaudill.com/",
            utils.extract_url("https://adamcaudill.com/index.html"),
        )

    def test_extract_url_file_path(self):
        self.assertEqual(
            "https://adamcaudill.com/t/",
            utils.extract_url("https://adamcaudill.com/t/index.html"),
        )

    def test_extract_url_query(self):
        self.assertEqual(
            "https://adamcaudill.com/",
            utils.extract_url("https://adamcaudill.com/?1=2"),
        )

    def test_extract_url_query_path_file(self):
        self.assertEqual(
            "https://adamcaudill.com/t/",
            utils.extract_url("https://adamcaudill.com/t/x.php?1=2"),
        )

    def test_extract_url_fragment(self):
        self.assertEqual(
            "https://adamcaudill.com/", utils.extract_url("https://adamcaudill.com/#1")
        )

    def test_extract_url_parameter(self):
        self.assertEqual(
            "https://adamcaudill.com/", utils.extract_url("https://adamcaudill.com/a;b")
        )

    def test_extract_url_ipv4(self):
        self.assertEqual("https://127.0.0.1/", utils.extract_url("https://127.0.0.1"))

    def test_extract_url_ipv6(self):
        self.assertEqual("https://[2001::1]/", utils.extract_url("https://[2001::1]"))

    def test_extract_url_idn(self):
        self.assertEqual(
            "https://bücher.example/", utils.extract_url("https://Bücher.example")
        )

    def test_extract_url_punnycode(self):
        self.assertEqual(
            "https://xn--bcher-kva.example/",
            utils.extract_url("https://xn--bcher-kva.example"),
        )
