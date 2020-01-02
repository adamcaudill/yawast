#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from unittest import TestCase

from dns import resolver

from yawast.scanner.plugins.dns.caa import _get_caa_records


class TestGetCaaRecords(TestCase):
    def test__get_caa_records(self):
        resv = resolver.Resolver()
        resv.nameservers = ["1.1.1.1", "8.8.8.8"]

        recs = _get_caa_records("adamcaudill.com", resv)

        self.assertTrue(len(recs) > 0)

    def test__get_caa_records_none(self):
        resv = resolver.Resolver()
        resv.nameservers = ["1.1.1.1", "8.8.8.8"]

        recs = _get_caa_records("www.google.com", resv)

        self.assertTrue(len(recs) == 0)
