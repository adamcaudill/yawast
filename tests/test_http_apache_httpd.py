#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from unittest import TestCase

from yawast.scanner.plugins.http.servers import apache_httpd


class TestHttpApacheHttpd(TestCase):
    def test_check_banner(self):
        res = apache_httpd.check_banner(
            "Apache", "<raw-request-data>", "http://adamcaudill.com"
        )

        self.assertEqual(1, len(res))
        self.assertEqual("Generic Apache Server Banner Found", res[0].message)

    def test_check_banner_future(self):
        res = apache_httpd.check_banner(
            "Apache/99.9.9", "<raw-request-data>", "http://adamcaudill.com"
        )

        self.assertEqual(1, len(res))
        self.assertEqual("Apache Server Version Exposed: Apache/99.9.9", res[0].message)

    def test_check_banner_old_24(self):
        res = apache_httpd.check_banner(
            "Apache/2.4.7", "<raw-request-data>", "http://adamcaudill.com"
        )

        self.assertEqual(2, len(res))
        self.assertEqual("Apache Server Version Exposed: Apache/2.4.7", res[0].message)
        self.assertIn("Apache Server Outdated:", res[1].message)

    def test_check_banner_old_php(self):
        res = apache_httpd.check_banner(
            "Apache/2.4.6 (FreeBSD) PHP/5.4.23",
            "<raw-request-data>",
            "http://adamcaudill.com",
        )

        self.assertEqual(4, len(res))
        self.assertEqual("Apache Server Version Exposed: Apache/2.4.6", res[0].message)
        self.assertIn("Apache Server Outdated:", res[1].message)
        self.assertEqual("PHP Version Exposed: PHP/5.4.23", res[2].message)
        self.assertIn("PHP Outdated:", res[3].message)

    def test_check_banner_old_php_ossl(self):
        res = apache_httpd.check_banner(
            "Apache/2.4.6 (FreeBSD) PHP/5.4.23 OpenSSL/0.9.8n",
            "<raw-request-data>",
            "http://adamcaudill.com",
        )

        self.assertEqual(5, len(res))
        self.assertEqual("Apache Server Version Exposed: Apache/2.4.6", res[0].message)
        self.assertIn("Apache Server Outdated:", res[1].message)
        self.assertEqual("PHP Version Exposed: PHP/5.4.23", res[2].message)
        self.assertIn("PHP Outdated:", res[3].message)
        self.assertEqual("OpenSSL Version Exposed: OpenSSL/0.9.8n", res[4].message)

    def test_check_banner_old_22(self):
        res = apache_httpd.check_banner(
            "Apache/2.2.7", "<raw-request-data>", "http://adamcaudill.com"
        )

        self.assertEqual(2, len(res))
        self.assertEqual("Apache Server Version Exposed: Apache/2.2.7", res[0].message)
        self.assertIn("Apache Server Outdated:", res[1].message)

    def test_check_banner_old_invalid(self):
        res = apache_httpd.check_banner(
            "Apache/1.1.7", "<raw-request-data>", "http://adamcaudill.com"
        )

        self.assertEqual(2, len(res))
        self.assertEqual("Apache Server Version Exposed: Apache/1.1.7", res[0].message)
        self.assertIn("Apache Server Outdated:", res[1].message)
