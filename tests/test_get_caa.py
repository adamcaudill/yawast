#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from unittest import TestCase

from yawast.scanner.plugins.dns import caa


class TestGetCaa(TestCase):
    def test_get_caa(self):
        recs = caa.get_caa("cntest.adamcaudill.com")

        self.assertTrue(len(recs) > 0)

        # RECORD 1
        # check the domain
        self.assertEqual("cntest.adamcaudill.com", recs[0][0])

        # check the type of the CNAME
        self.assertEqual("CNAME", recs[0][1])

        # check the return of the CNAME
        self.assertEqual("www.google.com.", recs[0][2])

        # RECORD 2
        # check the domain
        self.assertEqual("www.google.com", recs[1][0])

        # check the type of record
        self.assertEqual("CAA", recs[1][1])

        # check the return of the CAA
        self.assertEqual([], recs[1][2])

        # RECORD 3
        # check the domain
        self.assertEqual("google.com", recs[2][0])

        # check the type of record
        self.assertEqual("CAA", recs[2][1])

        # check the record length for the CAA data
        self.assertTrue(len(recs[2][2]) > 0)
