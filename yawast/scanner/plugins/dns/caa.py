#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import copy
from typing import Union, Dict, List

from dns import resolver, exception
from dns.resolver import Resolver

from yawast.shared import output

_checked: Dict[str, bool] = {}
_results: List[List[Union[str, List[str]]]] = []


def get_caa(domain: str) -> List[List[Union[str, List[str]]]]:
    global _checked, _results

    # force DNS resolver to something that works
    # this is done to ensure that ISP resolvers don't get in the way
    # at some point, should probably do something else, but works for now
    # (Cloudflare & Google)
    resv: Resolver = resolver.Resolver()
    resv.nameservers = ["1.1.1.1", "8.8.8.8"]

    _chase_domain(domain, resv)

    # reset global data
    ret = copy.deepcopy(_results)
    _results = []
    _checked = {}

    return ret


def _chase_domain(domain: str, resv: Resolver):
    global _checked, _results
    curr: Union[str, None] = domain

    while curr is not None:
        # check to see if we've already ran into this one
        if _checked.get(curr) is not None:
            return

        _checked[curr] = True

        # first, see if this is a CNAME. we do this explicitly because
        # some resolvers flatten in an odd way that prevents just checking
        # for the CAA record directly
        cname = _get_cname(curr, resv)
        if cname is not None:
            _results.append([curr, "CNAME", cname])
            _chase_domain(cname.rstrip("."), resv)
        else:
            caa = _get_caa_records(curr, resv)
            _results.append([curr, "CAA", caa])

        if "." in curr:
            curr = curr.split(".", 1)[-1]
        else:
            curr = None


def _get_caa_records(domain: str, resv: Resolver) -> List[str]:
    records: List[str] = []

    try:
        answers = resv.query(domain, "CAA", lifetime=3)

        for data in answers:
            records.append(data.to_text())
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()

    return records


def _get_cname(domain: str, resv: Resolver) -> Union[str, None]:
    name = None

    try:
        answers = resv.query(domain, "CNAME", lifetime=3)

        for data in answers:
            name = str(data.target)
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()

    return name
