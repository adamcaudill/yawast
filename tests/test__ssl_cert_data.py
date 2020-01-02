#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from unittest import TestCase

from yawast.scanner.plugins.ssl import cert_info
from yawast.scanner.plugins.ssl.cert_info import _get_ct_log_data


class TestSslCertData(TestCase):
    def test__get_ct_log_data(self):
        recs = _get_ct_log_data()

        self.assertTrue(len(recs) > 0)

    def test_get_ct_log_name(self):
        self.assertEqual(
            "Google 'Argon2018' log",
            cert_info.get_ct_log_name(
                "a4501269055a15545e6211ab37bc103f62ae5576a45e4b1714453e1b22106a25"
            ),
        )

    def test_get_ct_log_name_bad(self):
        self.assertEqual("(Unknown: ffffff)", cert_info.get_ct_log_name("ffffff"))
