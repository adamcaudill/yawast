#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.
import re
from typing import List, Union, Tuple

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.evidence import Evidence
from yawast.scanner.plugins.http import response_scanner
from yawast.scanner.plugins.result import Result
from yawast.scanner.session import Session
from yawast.shared import output, network


def check_for_jira(session: Session) -> Tuple[List[Result], Union[str, None]]:
    # this checks for an instance of Jira relative to the session URL
    results: List[Result] = []
    jira_url = None

    try:
        targets = [
            f"{session.url}secure/Dashboard.jspa",
            f"{session.url}jira/secure/Dashboard.jspa",
        ]

        for target in targets:
            res = network.http_get(target, False)

            if (
                res.status_code == 200
                and 'name="application-name" content="JIRA"' in res.text
            ):
                # we have a Jira instance
                jira_url = target

                # try to get the version
                ver_str = "unknown"
                try:
                    ver_pattern = (
                        r"<meta name=\"ajs-version-number\" content=\"([\d\.]+)\">"
                    )
                    version = re.search(ver_pattern, res.text).group(1)

                    build_pattern = (
                        r"<meta name=\"ajs-build-number\" content=\"(\d+)\">"
                    )
                    build = re.search(build_pattern, res.text).group(1)

                    ver_str = f"v{version}-{build}"
                except Exception:
                    output.debug_exception()

                results.append(
                    Result.from_evidence(
                        Evidence.from_response(res),
                        f"Jira Installation Found ({ver_str}): {target}",
                        Vulnerabilities.APP_JIRA_FOUND,
                    )
                )

            results += response_scanner.check_response(target, res)

            break
    except Exception:
        output.debug_exception()

    return results, jira_url


def check_jira_user_registration(jira_url: str) -> List[Result]:
    results: List[Result] = []

    try:
        target = f"{jira_url.rsplit('/', 1)[0]}/Signup!default.jspa"
        res = network.http_get(target, False)

        if res.status_code == 200 and "<title>Sign up for Jira" in res.text:
            results.append(
                Result.from_evidence(
                    Evidence.from_response(res),
                    f"Jira User Registration Enabled: {target}",
                    Vulnerabilities.APP_JIRA_USER_REG_ENABLED,
                )
            )

        results += response_scanner.check_response(target, res)
    except Exception:
        output.debug_exception()

    return results
