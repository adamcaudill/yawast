#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import uuid
from typing import Union, List, Dict, Any

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.evidence import Evidence


class Result:
    evidence: Dict[str, Any]
    url: str
    vulnerability: Vulnerabilities
    message: str

    def __init__(
        self,
        msg: str,
        vuln: Vulnerabilities,
        url: str,
        evidence: Union[str, List[str], Dict[str, Any], None] = None,
    ):
        self.message = msg
        self.vulnerability = vuln
        self.url = url

        if evidence is not None:
            if isinstance(evidence, dict) or isinstance(evidence, Evidence):
                self.evidence = evidence
            elif isinstance(evidence, str):
                # if the evidence is a string, lets tack on the message as an extra element
                self.evidence = {"e": str(evidence), "message": msg}
            else:
                self.evidence = {"e": evidence}
        else:
            # fall back to the message if we don't have evidence - better than nothing
            self.evidence = {"message": msg}

        self.id = uuid.uuid4().hex

    def __repr__(self):
        return f"Result: {self.id} - {self.vulnerability.name} - {self.url} - {self.message}"

    @classmethod
    def from_evidence(cls, ev: Evidence, msg: str, vuln: Vulnerabilities):
        r = cls(msg, vuln, ev.url, ev)

        return r
