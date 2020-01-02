#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from typing import List, cast
from urllib.parse import urljoin

from packaging import version

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.http import version_checker, response_scanner
from yawast.scanner.plugins.result import Result
from yawast.shared import network


def check_all(url: str) -> List[Result]:
    results: List[Result] = []

    results += check_status(url)

    return results


def check_banner(banner: str, raw: str, url: str) -> List[Result]:
    if not banner.startswith("nginx"):
        return []

    results: List[Result] = []

    if "/" in banner:
        # we've got a Nginx version
        results.append(
            Result(
                f"Nginx Version Exposed: {banner}",
                Vulnerabilities.HTTP_BANNER_NGINX_VERSION,
                url,
                {"response": raw, "banner": banner},
            )
        )

        # parse the version, and get the latest version - see if the server is up to date
        ver = cast(version.Version, version.parse(banner.split("/")[1]))
        curr_version = version_checker.get_latest_version("nginx", ver)

        if curr_version is not None and curr_version > ver:
            results.append(
                Result(
                    f"Nginx Outdated: {ver} - Current: {curr_version}",
                    Vulnerabilities.SERVER_NGINX_OUTDATED,
                    url,
                    {"response": raw, "banner": banner},
                )
            )
    else:
        # this means that it's just a generic banner, with no info
        results.append(
            Result(
                "Generic Nginx Server Banner Found",
                Vulnerabilities.HTTP_BANNER_GENERIC_NGINX,
                url,
                {"response": raw, "banner": banner},
            )
        )

    return results


def check_status(url: str) -> List[Result]:
    results: List[Result] = []
    search = ["status/", "stats/"]

    for path in search:
        target = urljoin(url, path)

        res = network.http_get(target, False)
        body = res.text

        if res.status_code == 200 and "Active connections:" in body:
            results.append(
                Result(
                    f"Nginx status page found: {target}",
                    Vulnerabilities.SERVER_NGINX_STATUS_EXPOSED,
                    target,
                    [
                        network.http_build_raw_request(res.request),
                        network.http_build_raw_response(res),
                    ],
                )
            )

        results += response_scanner.check_response(target, res)

    return results
