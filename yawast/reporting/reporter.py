#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import gc
import hashlib
import json
import os
import time
import zipfile
from datetime import datetime
from typing import Dict, List, cast, Optional, Any, Union

from yawast.external.memory_size import Size
from yawast.external.total_size import total_size
from yawast.reporting.enums import Vulnerabilities, Severity
from yawast.reporting.issue import Issue
from yawast.scanner.plugins.result import Result
from yawast.shared import output
from yawast.shared.exec_timer import ExecutionTimer

_issues: Dict[str, Dict[Vulnerabilities, List[Issue]]] = {}
_info: Dict[str, Any] = {}
_data: Dict[str, Any] = {}
_evidence: Dict[str, Any] = {}
_domain: str = ""
_output_file: str = ""


def init(output_file: Union[str, None] = None) -> None:
    global _output_file

    if output_file is not None:
        # if we have something, let's figure out what
        output_file = os.path.abspath(output_file)
        if os.path.isdir(output_file):
            # it's a directory, so we are going to create a name
            name = f"yawast_{int(time.time())}.json"
            output_file = os.path.join(output_file, name)
        elif os.path.isfile(output_file) or os.path.isfile(f"{_output_file}.zip"):
            # the file already exists
            print("WARNING: Output file already exists; it will be replaced.")

        _output_file = output_file


def save_output(spinner=None):
    global _issues, _info, _output_file, _data

    # add some extra debug data
    register_info("memsize_issues", total_size(_issues))
    register_info("memsize_info", total_size(_info))
    register_info("memsize_data", total_size(_data))
    register_info("memsize_evidence", total_size(_evidence))
    register_info("gc_stats", gc.get_stats())
    register_info("gc_objects", len(gc.get_objects()))

    if spinner:
        spinner.stop()
    print("Saving...")
    if spinner:
        spinner.start()

    vulns = {}
    for vuln in Vulnerabilities:
        vulns[vuln.name] = {
            "severity": vuln.severity,
            "description": vuln.description,
            "id": vuln.id,
        }

    data = {
        "_info": _convert_keys(_info),
        "data": _convert_keys(_data),
        "issues": _convert_keys(_issues),
        "evidence": _convert_keys(_evidence),
        "vulnerabilities": vulns,
    }
    json_data = json.dumps(data, indent=4)

    try:
        zf = zipfile.ZipFile(f"{_output_file}.zip", "x", zipfile.ZIP_BZIP2)

        with ExecutionTimer() as tm:
            zf.writestr(
                f"{os.path.basename(_output_file)}",
                json_data.encode("utf_8", "backslashreplace"),
            )

        zf.close()

        orig = "{0:cM}".format(Size(len(json_data)))
        comp = "{0:cM}".format(Size(os.path.getsize(f"{_output_file}.zip")))

        if spinner:
            spinner.stop()
        print(
            f"Saved {_output_file}.zip (size reduced from {orig} to {comp} in {tm.to_ms()}ms)"
        )
    except Exception as error:
        if spinner:
            spinner.stop()

        print(f"Error writing output file: {error}")


def get_output_file() -> str:
    global _output_file

    if len(_output_file) > 0:
        return f"{_output_file}.zip"
    else:
        return ""


def setup(domain: str) -> None:
    global _domain, _issues, _data

    _domain = domain

    if _domain not in _issues:
        _issues[_domain] = {}

    if _domain not in _data:
        _data[_domain] = {}

    if _domain not in _evidence:
        _evidence[_domain] = {}


def is_registered(vuln: Vulnerabilities) -> bool:
    global _issues, _domain

    if _issues is None:
        return False
    else:
        if _domain in _issues:
            if _issues[_domain].get(vuln) is None:
                return False
            else:
                return True
        else:
            return False


def register_info(key: str, value: Any):
    global _info, _output_file

    if _output_file is not None and len(_output_file) > 0:
        _info[key] = value


def register_data(key: str, value: Any):
    global _data, _output_file, _domain

    if _output_file is not None and len(_output_file) > 0:
        if _domain is not None:
            if _domain in _data:
                _register_data(_data[_domain], key, value)
            else:
                _data[_domain] = {}
                _register_data(_data[_domain], key, value)
        else:
            _register_data(_data, key, value)


def register_message(value: str, kind: str):
    global _info, _output_file

    if _output_file is not None and len(_output_file) > 0:
        if "messages" not in _info:
            _info["messages"] = {}

        if kind not in _info["messages"]:
            _info["messages"][kind] = []

        _info["messages"][kind].append(f"[{datetime.utcnow()} UTC]: {value}")


def register(issue: Issue) -> None:
    global _issues, _domain, _evidence

    # make sure the Dict for _domain exists - this shouldn't normally be an issue, but is for unit tests
    if _domain not in _issues:
        _issues[_domain] = {}

    # add the evidence to the evidence list, and swap the value in the object for its hash.
    # the point of this is to minimize cases where we are holding the same (large) string
    # multiple times in memory. should reduce memory by up to 20%
    if _domain not in _evidence:
        _evidence[_domain] = {}

    if "request" in issue.evidence and issue.evidence["request"] is not None:
        req = str(issue.evidence["request"]).encode("utf-8")
        req_id = hashlib.blake2b(req, digest_size=16).hexdigest()

        if req_id not in _evidence[_domain]:
            _evidence[_domain][req_id] = issue.evidence["request"]

        issue.evidence["request"] = req_id

    if "response" in issue.evidence and issue.evidence["response"] is not None:
        res = str(issue.evidence["response"]).encode("utf-8")
        res_id = hashlib.blake2b(res, digest_size=16).hexdigest()

        if res_id not in _evidence[_domain]:
            _evidence[_domain][res_id] = issue.evidence["response"]

        issue.evidence["response"] = res_id

    # if we haven't handled this issue yet, create a List for it
    if not is_registered(issue.vulnerability):
        _issues[_domain][issue.vulnerability] = []

    # we need to check to see if we already have this issue, for this URL, so we don't create dups
    # TODO: This isn't exactly efficient - refactor
    findings = _issues[_domain][issue.vulnerability]
    findings = cast(List[Issue], findings)
    for finding in findings:
        if finding.url == issue.url and finding.evidence == issue.evidence:
            # just bail out
            output.debug(f"Duplicate Issue: {issue.id} (duplicate of {finding.id})")

            return

    _issues[_domain][issue.vulnerability].append(issue)


def display(msg: str, issue: Issue) -> None:
    if issue.vulnerability.display_all or not is_registered(issue.vulnerability):
        if issue.severity == Severity.CRITICAL or issue.severity == Severity.HIGH:
            output.vuln(msg)
        elif issue.severity == Severity.MEDIUM:
            output.warn(msg)
        else:
            output.info(msg)

    # if there's no evidence, default to the msg - better than nothing
    if issue.evidence is None:
        issue.evidence = msg.strip()

    register(issue)


def display_results(results: List[Result], padding: Optional[str] = ""):
    for res in results:
        iss = Issue.from_result(res)
        display(f"{padding}{res.message}", iss)


def _register_data(data: Dict, key: str, value: Any):
    if key in data and type(data[key]) is list and type(value) is list:
        ls = cast(list, data[key])
        ls.extend(value)
    elif key in data and type(data[key]) is dict and type(value) is dict:
        dt = cast(dict, data[key])
        dt.update(value)
    else:
        data[key] = value


def _convert_keys(dct: Dict) -> Dict:
    ret = {}

    for k, v in dct.items():
        if type(k) is Vulnerabilities:
            k = k.name

        if type(v) is dict:
            v = _convert_keys(v)

        try:
            _ = json.dumps(v)
        except Exception as error:
            output.debug(f"Error serializing data: {str(error)}")
            # convert to string - this may be wrong, but at least it won't fail
            v = str(v)

        ret[k] = v

    return ret
