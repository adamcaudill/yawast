#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from dns import resolver, exception, dnssec

from yawast.shared import output


def get_dnskey(domain):
    records = []

    try:
        answers = resolver.query(domain, "DNSKEY")

        for data in answers:
            flags = format(data.flags, "016b")
            proto = data.protocol
            alg = dnssec.algorithm_to_text(data.algorithm)
            key = data.key

            records.append([flags, proto, alg, key])
    except (resolver.NoAnswer, resolver.NXDOMAIN, exception.Timeout):
        pass
    except (resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA):
        output.debug_exception()

    return records
