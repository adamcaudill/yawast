#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from typing import List

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.result import Result


def check_banner(banner: str, raw: str, url: str) -> List[Result]:
    if not banner.startswith("Python/"):
        return []

    results = [
        Result(
            f"Python Version Exposed: {banner}",
            Vulnerabilities.HTTP_BANNER_PYTHON_VERSION,
            url,
            {"response": raw, "banner": banner},
        )
    ]

    return results
