#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from typing import List, cast
from urllib.parse import urljoin

from packaging import version

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.http import version_checker, response_scanner
from yawast.scanner.plugins.http.servers import php
from yawast.scanner.plugins.result import Result
from yawast.shared import network


def check_banner(banner: str, raw: str, url: str) -> List[Result]:
    # don't bother if this doesn't look like Apache
    if "Apache" not in banner or "Apache-" in banner:
        return []

    results = []

    if "/" in banner:
        # this means that we have a version
        modules = banner.split(" ")

        # double check that we have a '/' in the first part
        if "/" in modules[0]:
            # we have a version
            results.append(
                Result(
                    f"Apache Server Version Exposed: {modules[0]}",
                    Vulnerabilities.HTTP_BANNER_APACHE_VERSION,
                    url,
                    raw,
                )
            )

            # parse the version, and get the latest version - see if the server is up to date
            ver = cast(version.Version, version.parse(modules[0].split("/")[1]))
            curr_version = version_checker.get_latest_version("apache_httpd", ver)

            if curr_version is not None and curr_version > ver:
                results.append(
                    Result(
                        f"Apache Server Outdated: {ver} - Current: {curr_version}",
                        Vulnerabilities.SERVER_APACHE_OUTDATED,
                        url,
                        raw,
                    )
                )

        # check to see what else we have
        if len(modules) > 1:
            if modules[1].startswith("("):
                # this is a distro string, garbage
                modules.remove(modules[1])

            for module in modules:
                if module.startswith("PHP/"):
                    results += php.check_version(module, raw, url)

                if module.startswith("OpenSSL/"):
                    results.append(
                        Result(
                            f"OpenSSL Version Exposed: {module}",
                            Vulnerabilities.HTTP_BANNER_OPENSSL_VERSION,
                            url,
                            raw,
                        )
                    )

    else:
        # this means that it's just a generic 'Apache' banner, with no info
        results.append(
            Result(
                "Generic Apache Server Banner Found",
                Vulnerabilities.HTTP_BANNER_GENERIC_APACHE,
                url,
                raw,
            )
        )

    return results


def check_all(url: str) -> List[Result]:
    results: List[Result] = []

    results += check_server_status(url)
    results += check_server_info(url)

    return results


def check_server_status(url: str) -> List[Result]:
    results = []

    target = urljoin(url, "server-status/")

    res = network.http_get(target, False)
    body = res.text

    if "Apache Server Status" in body:
        results.append(
            Result(
                f"Apache HTTPD Server Status found: {target}",
                Vulnerabilities.SERVER_APACHE_STATUS,
                url,
                body,
            )
        )

    results += response_scanner.check_response(url, res)

    return results


def check_server_info(url: str) -> List[Result]:
    results = []

    target = urljoin(url, "server-info/")

    res = network.http_get(target, False)
    body = res.text

    if "Apache Server Information" in body:
        results.append(
            Result(
                f"Apache HTTPD Server Status found: {target}",
                Vulnerabilities.SERVER_APACHE_INFO,
                url,
                body,
            )
        )

    results += response_scanner.check_response(url, res)

    return results
