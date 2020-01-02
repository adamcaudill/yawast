#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import os
from unittest import TestCase

from yawast.scanner.plugins.dns import subdomains


class TestFindSubdomains(TestCase):
    def test_find_subdomains(self):
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/subdomains.txt")

        recs = subdomains.find_subdomains("adamcaudill.com", path)

        self.assertTrue(len(recs) > 0)

        self.assertEqual("www.adamcaudill.com.", recs[0][1])
