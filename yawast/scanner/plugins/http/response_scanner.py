#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import inspect
from typing import List, Union

from bs4 import BeautifulSoup
from requests.models import Response

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.evidence import Evidence
from yawast.scanner.plugins.http import http_basic, retirejs, error_checker, http_utils
from yawast.scanner.plugins.http.servers import rails, apache_tomcat, iis
from yawast.scanner.plugins.result import Result
from yawast.shared import network, output


def check_response(
    url: str, res: Response, soup: Union[BeautifulSoup, None] = None
) -> List[Result]:
    # make sure we actually have something
    if res is None:
        return []

    results: List[Result] = []

    raw_full = network.http_build_raw_response(res)

    if http_utils.is_text(res):
        body = res.text

        if soup is None:
            soup = BeautifulSoup(body, "html.parser")

        # check for things thar require parsed HTML
        results += retirejs.get_results(soup, url, res)
        results += apache_tomcat.get_version(url, res)
        results += error_checker.check_response(url, res, body)
        results += iis.check_telerik_rau_enabled(soup, url)

        results += _check_cache_headers(url, res)

    results += http_basic.get_header_issues(res, raw_full, url)
    results += http_basic.get_cookie_issues(res, url)

    results += rails.check_cve_2019_5418(url)

    results += _check_charset(url, res)

    return results


def _check_charset(url: str, res: Response) -> List[Result]:
    results: List[Result] = []

    # if the body is empty, we really don't care about this
    if len(res.content) == 0:
        return results

    try:
        if "Content-Type" in res.headers:
            content_type = str(res.headers["Content-Type"]).lower()

            if "charset" not in content_type and "text/html" in content_type:
                # not charset specified
                results.append(
                    Result.from_evidence(
                        Evidence.from_response(res, {"content-type": content_type}),
                        f"Charset Not Defined in '{res.headers['Content-Type']}' at {url}",
                        Vulnerabilities.HTTP_HEADER_CONTENT_TYPE_NO_CHARSET,
                    )
                )
        else:
            # content-type missing
            results.append(
                Result.from_evidence(
                    Evidence.from_response(res),
                    f"Content-Type Missing: {url} ({res.request.method} - {res.status_code})",
                    Vulnerabilities.HTTP_HEADER_CONTENT_TYPE_MISSING,
                )
            )
    except Exception:
        output.debug_exception()

    return results


def _check_cache_headers(url: str, res: Response) -> List[Result]:
    results = []

    try:
        if "Cache-Control" in res.headers:
            # we have the header, check the content
            if "public" in str(res.headers["Cache-Control"]).lower():
                results.append(
                    Result.from_evidence(
                        Evidence.from_response(res),
                        f"Cache-Control: Public: {url}",
                        Vulnerabilities.HTTP_HEADER_CACHE_CONTROL_PUBLIC,
                    )
                )

            if "no-cache" not in str(res.headers["Cache-Control"]).lower():
                results.append(
                    Result.from_evidence(
                        Evidence.from_response(res),
                        f"Cache-Control: no-cache Not Found: {url}",
                        Vulnerabilities.HTTP_HEADER_CACHE_CONTROL_NO_CACHE_MISSING,
                    )
                )

            if "no-store" not in str(res.headers["Cache-Control"]).lower():
                results.append(
                    Result.from_evidence(
                        Evidence.from_response(res),
                        f"Cache-Control: no-store Not Found: {url}",
                        Vulnerabilities.HTTP_HEADER_CACHE_CONTROL_NO_STORE_MISSING,
                    )
                )

            if "private" not in str(res.headers["Cache-Control"]).lower():
                results.append(
                    Result.from_evidence(
                        Evidence.from_response(res),
                        f"Cache-Control: private Not Found: {url}",
                        Vulnerabilities.HTTP_HEADER_CACHE_CONTROL_PRIVATE_MISSING,
                    )
                )
        else:
            # header missing
            results.append(
                Result.from_evidence(
                    Evidence.from_response(res),
                    f"Cache-Control Header Not Found: {url}",
                    Vulnerabilities.HTTP_HEADER_CACHE_CONTROL_MISSING,
                )
            )

        if "Expires" not in res.headers:
            results.append(
                Result.from_evidence(
                    Evidence.from_response(res),
                    f"Expires Header Not Found: {url}",
                    Vulnerabilities.HTTP_HEADER_EXPIRES_MISSING,
                )
            )

        else:
            # TODO: parse the value and see if it's less than now
            pass

        if "Pragma" not in res.headers or "no-cache" not in str(res.headers["Pragma"]):
            results.append(
                Result.from_evidence(
                    Evidence.from_response(res),
                    f"Pragma: no-cache Not Found: {url}",
                    Vulnerabilities.HTTP_HEADER_PRAGMA_NO_CACHE_MISSING,
                )
            )
    except Exception:
        output.debug_exception()

    return results
