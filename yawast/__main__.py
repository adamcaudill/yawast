#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.


MIN_PYTHON = (3, 7)


def main():
    # Launcher file for YAWAST. This verifies that we are using a compatible version.
    import os
    import sys

    if sys.version_info[0] < 3:
        python3 = os.popen("which python3 2> /dev/null").read().rstrip()
        if python3:
            args = sys.argv[:]
            args.insert(0, python3)
            os.execv(python3, args)
        else:
            sys.exit(
                "YAWAST requires Python 3.x (python3 not in PATH). Currently using Python %s"
                % "".join(sys.version.splitlines())
            )

    # check to make sure we have at least Python 3.7
    if sys.version_info < MIN_PYTHON:
        sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)

    from yawast import main

    main.main()
