#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from unittest import TestCase

from yawast.shared import network


class TestCheckSslRedirect(TestCase):
    def test_check_ssl_redirect_valid(self):
        self.assertEqual(
            "https://adamcaudill.com/",
            network.check_ssl_redirect("http://adamcaudill.com/"),
        )

    def test_check_ssl_redirect_https(self):
        self.assertEqual(
            "https://adamcaudill.com/",
            network.check_ssl_redirect("https://adamcaudill.com/"),
        )

    def test_check_ssl_redirect_none(self):
        self.assertEqual(
            "http://example.com/", network.check_ssl_redirect("http://example.com/")
        )

    def test_check_ssl_redirect_path(self):
        self.assertEqual(
            "https://mail.google.com/",
            network.check_ssl_redirect("http://mail.google.com/"),
        )
