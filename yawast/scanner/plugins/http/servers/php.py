#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.
from concurrent.futures import as_completed
from concurrent.futures.thread import ThreadPoolExecutor
from typing import List, cast, Tuple
from urllib.parse import urljoin, urlparse, quote

from packaging import version
from requests import Response

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.session import Session
from yawast.scanner.plugins.evidence import Evidence
from yawast.scanner.plugins.http import version_checker
from yawast.scanner.plugins.result import Result
from yawast.shared import network


def check_version(banner: str, raw: str, url: str) -> List[Result]:
    results = []

    if not banner.startswith("PHP/"):
        return []

    # we've got a PHP version
    results.append(
        Result(
            f"PHP Version Exposed: {banner}",
            Vulnerabilities.HTTP_PHP_VERSION_EXPOSED,
            url,
            raw,
        )
    )

    # parse the version, and get the latest version - see if the server is up to date
    ver = cast(version.Version, version.parse(banner.split("/")[1]))
    curr_version = version_checker.get_latest_version("php", ver)

    if curr_version is not None and curr_version > ver:
        results.append(
            Result(
                f"PHP Outdated: {ver} - Current: {curr_version}",
                Vulnerabilities.SERVER_PHP_OUTDATED,
                url,
                raw,
            )
        )

    return results


def find_phpinfo(links: List[str]) -> List[Result]:
    results = []
    queue = []

    def _get_resp(url: str) -> Tuple[bool, Response]:
        return network.http_file_exists(url, False)

    def _process(url: str, result: Tuple[bool, Response]):
        nonlocal results

        found, res = result

        if found and '<h1 class="p">PHP Version' in res.text:
            results.append(
                Result.from_evidence(
                    Evidence.from_response(res),
                    f"PHP Info Found: {url}",
                    Vulnerabilities.SERVER_PHP_PHPINFO,
                )
            )

    targets = ["phpinfo.php", "info.php", "version.php", "x.php"]

    for link in links:
        if link.endswith("/"):
            for target in targets:
                turl = urljoin(link, target)

                queue.append(turl)

    with ThreadPoolExecutor() as executor:
        f = {executor.submit(_get_resp, url): url for url in queue}
        for future in as_completed(f):
            url = f[future]
            resp = future.result()
            _process(url, resp)

    return results


def check_cve_2019_11043(session: Session, links: List[str]) -> List[Result]:
    min_qsl = 1500
    max_qsl = 1950
    qsl_step = 5
    results = []
    targets = []

    if session.args.php_page is not None and len(session.args.php_page) > 0:
        php_page = str(session.args.php_page)

        if php_page.startswith("http://") or php_page.startswith("https://"):
            targets.append(urljoin(session.url, php_page))
        elif php_page.startswith(session.url):
            targets.append(php_page)

    for link in links:
        if link.endswith(".php"):
            targets.append(link)
        elif link.endswith("/"):
            targets.append(f"{link}index.php")

    def _get_resp(url: str, q_count: int) -> Response:
        path_info = "/PHP\nindex.php"
        u = urlparse(url)
        orig_path = quote(u.path)
        new_path = quote(u.path + path_info)
        delta = len(new_path) - len(path_info) - len(orig_path)
        prime = q_count - delta / 2
        req_url = urljoin(url, new_path + "?" + "Q" * int(prime))

        return network.http_get(req_url, False)

    for target in targets:
        # start by making sure that we have a valid target
        if network.http_head(target, False).status_code < 400:
            # get our baseline status code
            res = _get_resp(target, 1500)
            base_status_code = res.status_code

            for qsl in range(min_qsl + qsl_step, max_qsl, qsl_step):
                res = _get_resp(target, qsl)
                if res.status_code != base_status_code:
                    results.append(
                        Result.from_evidence(
                            Evidence.from_response(res, {"qsl": qsl}),
                            f"Detected susceptibility to PHP Remote Code Execution (CVE-2019-11043) (QSL {qsl})",
                            Vulnerabilities.SERVER_PHP_CVE_2019_11043,
                        )
                    )
                    break

    return results
