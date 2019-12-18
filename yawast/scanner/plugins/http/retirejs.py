#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import json
from typing import List, Dict, Tuple, Any, Union
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from requests import Response

from yawast.external import retirejs
from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.evidence import Evidence
from yawast.scanner.plugins.result import Result
from yawast.shared import output, network, utils

_data: Union[Dict[Any, Any], None] = {}
_checked: List[str] = []
_reports: List[str] = []


def get_results(soup: BeautifulSoup, url: str, res: Response) -> List[Result]:
    global _reports

    results: List[Result] = []

    try:
        parsed = urlparse(url)
        domain = utils.get_domain(parsed.netloc)

        issues, r = _get_retirejs_results(soup, url, domain, res)
        results += r
        for js_url, issue in issues:
            comp = issue["component"]
            ver = issue["version"]

            if "vulnerabilities" in issue:
                for vuln in issue["vulnerabilities"]:
                    info = (
                        f'Vulnerable JavaScript: {comp}-{ver} ({js_url}): Severity: {vuln["severity"]} - '
                        f'Info: {" ".join(vuln["info"])}'
                    )

                    # make sure we haven't reported this issue before
                    if info not in _reports:
                        _reports.append(info)

                        results.append(
                            Result.from_evidence(
                                Evidence.from_response(
                                    res,
                                    {
                                        "js_file": js_url,
                                        "js_lib": comp,
                                        "js_lib_ver": ver,
                                        "vuln_info": list(vuln["info"]),
                                        "vuln_sev": vuln["severity"],
                                    },
                                ),
                                info,
                                Vulnerabilities.JS_VULNERABLE_VERSION,
                            )
                        )
    except Exception:
        output.debug_exception()

    return results


def reset():
    global _checked, _reports

    _checked = []
    _reports = []


def _get_retirejs_results(
    soup: BeautifulSoup, url: str, domain: str, res: Response
) -> Tuple[List[Tuple[str, Dict]], List[Result]]:
    global _data, _checked
    issues = []
    results: List[Result] = []

    if _data is None or len(_data) == 0:
        _get_data()

    if _data is not None:
        # get all the JS files
        files = [i.get("src") for i in soup.find_all("script") if i.get("src")]

        for file in files:
            # fix relative URLs
            if str(file).startswith("//"):
                file = f"https:{file}"
            if str(file).startswith("/") or (not str(file).startswith("http")):
                if urlparse(url).scheme == "https":
                    file = urljoin(f"https://{domain}", file)
                else:
                    file = urljoin(f"http://{domain}", file)

            if file not in _checked:
                findings = retirejs.scan_endpoint(file, _data)

                _checked.append(file)

                if domain not in file:
                    # external JS file
                    results.append(
                        Result.from_evidence(
                            Evidence.from_response(res, {"js_file": file}),
                            f"External JavaScript File: {file}",
                            Vulnerabilities.JS_EXTERNAL_FILE,
                        )
                    )

                for find in findings:
                    issues.append((file, find))

        return issues, results
    else:
        # this means we couldn't get the data, so bail
        return [], []


def _get_data() -> None:
    global _data

    data: Union[Dict[Any, Any], None] = None
    data_url = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"

    try:
        raw = network.http_get(data_url).content
        raw_js = raw.decode("utf-8").replace("§§version§§", "[0-9][0-9.a-z_\\\\-]+")

        data = json.loads(raw_js)

    except Exception as error:
        output.debug(f"Failed to get version data: {error}")
        output.debug_exception()

    _data = data
