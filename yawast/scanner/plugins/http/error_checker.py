#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import re
from typing import Union, List, cast

from requests import Response

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.evidence import Evidence
from yawast.scanner.plugins.result import Result
from yawast.shared import network, output


class _MatchRule:
    def __init__(self, data: str):
        fields = data.split("\t")

        # clean up regex, to eliminate issues from using Java-flavored regex
        pattern = fields[0].replace("}+", "}").replace("++", "+")
        self.pattern = re.compile(pattern)

        self.match_group = fields[1]
        self.type = fields[2]
        self.confidence = fields[4]


_data: List[_MatchRule] = []
_reports: List[str] = []


def check_response(
    url: str, res: Response, body: Union[str, None] = None
) -> List[Result]:
    global _data, _reports
    results = []

    try:
        # make sure we actually have something
        if res is None:
            return []

        if _data is None or len(_data) == 0:
            _get_data()

        if body is None:
            body = res.text

        for rule in _data:
            rule = cast(_MatchRule, rule)

            mtch = re.search(rule.pattern, body)

            if mtch:
                val = mtch.group(int(rule.match_group))

                err_start = body.find(val)

                # get the error, plus 25 characters on each side
                err = body[err_start - 25 : err_start + len(val) + 25]
                msg = (
                    f"Found error message (confidence: {rule.confidence}) "
                    f"on {url} ({res.request.method}): ...{err}..."
                )

                if msg not in _reports:
                    results.append(
                        Result.from_evidence(
                            Evidence.from_response(res),
                            msg,
                            Vulnerabilities.HTTP_ERROR_MESSAGE,
                        )
                    )

                    _reports.append(msg)

                    break
                else:
                    output.debug(f"Ignored duplicate error message: {msg}")
    except Exception:
        output.debug_exception()

    return results


def reset():
    global _reports

    _reports = []


def _get_data() -> None:
    global _data
    data_url = "https://raw.githubusercontent.com/augustd/burp-suite-error-message-checks/master/src/main/resources/burp/match-rules.tab"

    try:
        raw = network.http_get(data_url).text

        for line in raw.splitlines():
            _data.append(_MatchRule(line))

    except Exception as error:
        output.debug(f"Failed to get version data: {error}")
        output.debug_exception()
