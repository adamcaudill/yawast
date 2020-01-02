#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from unittest import TestCase

from tests import utils
from yawast import main
from yawast._version import get_version
from yawast.shared import output


class TestPrintHeader(TestCase):
    def test_print_header(self):
        output.setup(False, True, True)
        with utils.capture_sys_output() as (stdout, stderr):
            main.print_header()

        self.assertIn("(v%s)" % get_version(), stdout.getvalue())
