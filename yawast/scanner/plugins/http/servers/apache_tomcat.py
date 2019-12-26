#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import base64
import re
import secrets
from typing import List, cast, Union, Optional
from urllib.parse import urljoin

from packaging import version
from requests import Response

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.http import version_checker, response_scanner
from yawast.scanner.plugins.result import Result
from yawast.shared import network, output


def check_all(url: str, links: List[str]) -> List[Result]:
    results: List[Result] = []

    results += check_version(url)
    results += check_manager(url)
    results += check_cve_2017_12615(url)
    results += check_struts_sample(url)
    results += check_cve_2019_0232(links)

    return results


def get_version(url: str, res: Response, method: Optional[str] = None) -> List[Result]:
    """Check a server response to see if it contains a Tomcat version.

    :param method:
    :param url:
    :param res:
    :return:
    """

    results: List[Result] = []

    try:
        body = res.text
        ver = _get_version_from_body(body, res.status_code)
        if ver is not None:
            msg = f"Apache Tomcat version exposed: {ver}"
            if method is not None:
                msg += f" (Via {method})"

            results.append(
                Result(
                    msg,
                    Vulnerabilities.SERVER_TOMCAT_VERSION,
                    url,
                    [
                        ver,
                        network.http_build_raw_request(res.request),
                        network.http_build_raw_response(res),
                    ],
                )
            )

            results += _check_version_outdated(ver, url, body)
    except Exception:
        output.debug_exception()

    return results


def check_version(url: str) -> List[Result]:
    """Search for the version of Tomcat used, by using various methods.
    Methods include sending a POST request to a page that likely doesn't
    support POST, sending an invalid HTTP verb, and triggering a 404.

    :param url:
    :return:
    """

    results: List[Result] = []

    results += _check_version_404(url)
    results += _check_version_verb(url)
    results += _check_version_post(url)
    results += _check_version_406(url)

    return results


def check_manager(url: str) -> List[Result]:
    results = []

    try:
        for p in [urljoin(url, "manager/"), urljoin(url, "host-manager/")]:
            # check for both Tomcat 6, and 7+
            for path in [urljoin(p, "html/"), p]:

                res = network.http_get(path, False)

                body = res.text

                if "<tt>conf/tomcat-users.xml</tt>" in body:
                    # we have a finding
                    vuln = Vulnerabilities.SERVER_TOMCAT_MANAGER_EXPOSED
                    if "host-manager" in path:
                        vuln = Vulnerabilities.SERVER_TOMCAT_HOST_MANAGER_EXPOSED

                    results.append(
                        Result(
                            f"Apache Tomcat Manager found: {path}",
                            vuln,
                            path,
                            [
                                network.http_build_raw_request(res.request),
                                network.http_build_raw_response(res),
                            ],
                        )
                    )

                    # check to see if we can get in with a default password
                    results += check_manager_password(url)
                else:
                    # if we didn't get a hit, go ahead and scan it to see if there's
                    #  anything else that we should be picking up.
                    results += response_scanner.check_response(path, res)
    except Exception:
        output.debug_exception()

    return results


def check_manager_password(url: str) -> List[Result]:
    results = []

    try:
        creds = [
            b"tomcat:tomcat",
            b"tomcat:password",
            b"tomcat:",
            b"admin:admin",
            b"admin:password",
            b"admin:",
        ]

        for cred in creds:
            ce = base64.b64encode(cred)

            res = network.http_get(url, False, {"Authorization": ce})
            body = res.text

            if (
                '<font size="+2">Tomcat Web Application Manager</font>' in body
                or '<font size="+2">Tomcat Virtual Host Manager</font>' in body
            ):
                # we got in
                results.append(
                    Result(
                        f"Apache Tomcat Weak Manager Password: '{cred}' - {url}",
                        Vulnerabilities.SERVER_TOMCAT_MANAGER_WEAK_PASSWORD,
                        url,
                        [
                            network.http_build_raw_request(res.request),
                            network.http_build_raw_response(res),
                        ],
                    )
                )
            else:
                # if we didn't get a hit, go ahead and scan it to see if there's
                #  anything else that we should be picking up.
                results += response_scanner.check_response(url, res)
    except Exception:
        output.debug_exception()

    return results


def check_cve_2017_12615(url: str) -> List[Result]:
    results = []

    try:
        file_name = secrets.token_hex(12)
        check_value = secrets.token_hex(12)

        target = urljoin(url, f"{file_name}.jsp/")
        res_put = network.http_put(target, f"<% out.println({check_value});%>", False)

        if res_put.status_code < 300:
            # code should be 2xx for this to work
            # now we need to check to see if it worked
            created_file = urljoin(url, f"{file_name}.jsp")

            res_get = network.http_get(created_file, False)

            if check_value in res_get.text:
                # we have RCE
                results.append(
                    Result(
                        f"Apache Tomcat PUT RCE (CVE-2017-12615): {created_file}",
                        Vulnerabilities.SERVER_TOMCAT_CVE_2017_12615,
                        url,
                        [
                            network.http_build_raw_request(res_put.request),
                            network.http_build_raw_response(res_put),
                            network.http_build_raw_request(res_get.request),
                            network.http_build_raw_response(res_get),
                        ],
                    )
                )
            else:
                results += response_scanner.check_response(created_file, res_get)
        else:
            # if we didn't get a hit, go ahead and scan it to see if there's
            #  anything else that we should be picking up.
            results += response_scanner.check_response(target, res_put)
    except Exception:
        output.debug_exception()

    return results


def check_cve_2019_0232(links: List[str]) -> List[Result]:
    results: List[Result] = []

    try:
        targets: List[str] = []

        for link in links:
            if "cgi-bin" in link:
                if "?" in link:
                    targets.append(f"{link}&dir")
                else:
                    targets.append(f"{link}?dir")

        for target in targets:
            res = network.http_get(target, False)
            body = res.text

            if "<DIR>" in body:
                # we have a hit
                results.append(
                    Result(
                        f"Apache Tomcat RCE (CVE-2019-0232): {target}",
                        Vulnerabilities.SERVER_TOMCAT_CVE_2019_0232,
                        target,
                        [
                            network.http_build_raw_request(res.request),
                            network.http_build_raw_response(res),
                        ],
                    )
                )

            results += response_scanner.check_response(target, res)
    except Exception:
        output.debug_exception()

    return results


def check_struts_sample(url: str) -> List[Result]:
    results: List[Result] = []

    try:
        # make sure we have real 404s
        file_good, _, _, _ = network.check_404_response(url)
        if not file_good:
            return results

        search = [
            "Struts2XMLHelloWorld/User/home.action",
            "struts2-showcase/showcase.action",
            "struts2-showcase/titles/index.action",
            "struts2-bootstrap-showcase/",
            "struts2-showcase/index.action",
            "struts2-bootstrap-showcase/index.action",
            "struts2-rest-showcase/",
        ]

        for path in search:
            target = urljoin(url, path)

            res = network.http_get(target, False)

            # check for other issues
            results += response_scanner.check_response(target, res)

            if res.status_code == 200:
                results.append(
                    Result(
                        f"Struts Sample Found: {target}",
                        Vulnerabilities.SERVER_TOMCAT_STRUTS_SAMPLE,
                        target,
                        [
                            network.http_build_raw_request(res.request),
                            network.http_build_raw_response(res),
                        ],
                    )
                )
    except Exception:
        output.debug_exception()

    return results


def _check_version_404(url: str) -> List[Result]:
    results: List[Result] = []

    try:
        rnd = secrets.token_hex(12)

        target = urljoin(url, f"{rnd}.jsp")

        res = network.http_get(target, False)

        if res.status_code > 400:
            results += get_version(target, res, "404 Error Message")

        results += response_scanner.check_response(res.url, res)
    except Exception:
        output.debug_exception()

    return results


def _check_version_verb(url: str) -> List[Result]:
    results: List[Result] = []

    try:
        res = network.http_custom("XYZ", url)

        if res.status_code > 400:
            results += get_version(url, res, "Invalid HTTP Verb")

        results += response_scanner.check_response(res.url, res)
    except Exception:
        output.debug_exception()

    return results


def _check_version_post(url: str) -> List[Result]:
    results: List[Result] = []

    try:
        res = network.http_custom("POST", url)

        if res.status_code > 400:
            results += get_version(url, res, "POST to root")

        results += response_scanner.check_response(res.url, res)
    except Exception:
        output.debug_exception()

    return results


def _check_version_406(url: str) -> List[Result]:
    results: List[Result] = []

    try:
        res = network.http_get(
            url, False, {"Accept": "application/pkcs8", "Accept-Encoding": "*;q=0"}
        )

        if res.status_code > 400:
            results += get_version(url, res, "Unacceptable Accept")

        results += response_scanner.check_response(res.url, res)
    except Exception:
        output.debug_exception()

    return results


def _get_version_from_body(body, status_code) -> Union[str, None]:
    if "Apache Tomcat" in body and status_code >= 400:
        # we only care if:
        #  'Apache Tomcat' is in the body
        #  We have a status code that indicates an error
        ver = re.search(r"Apache Tomcat/\d*.\d*.\d*\b", body)

        if ver:
            # split it, and only return the number itself
            return ver.group(0).split("/")[1]

    return None


def _check_version_outdated(ver: str, url: str, body: str) -> List[Result]:
    results: List[Result] = []

    # parse the version, and get the latest version - see if the server is up to date
    ver = cast(version.Version, version.parse(ver))
    curr_version = version_checker.get_latest_version("apache_tomcat", ver)

    if curr_version is not None and curr_version > ver:
        results.append(
            Result(
                f"Apache Tomcat Outdated: {ver} - Current: {curr_version}",
                Vulnerabilities.SERVER_TOMCAT_OUTDATED,
                url,
                [ver, curr_version, body],
            )
        )

    return results
