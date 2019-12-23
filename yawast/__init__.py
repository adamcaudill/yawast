#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

try:
    from ._version import __version__

    __all__ = ["__version__"]
    del _version  # remove to avoid confusion with __version__
except Exception:
    # if we get here, something is very wrong - running under python2?
    pass
