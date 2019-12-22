#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import base64
from typing import List, Dict, cast

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from yawast.shared import network

_ct_log_info: Dict[str, str] = {}


def format_extensions(cert: x509.Certificate):
    extensions = []

    for ext in cert.extensions:
        name = ext.oid._name
        critical = ext.critical

        # exclude SUBJECT_ALTERNATIVE_NAME & PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
        if (
            ext.oid.dotted_string != "2.5.29.17"
            and ext.oid.dotted_string != "1.3.6.1.4.1.11129.2.4.2"
        ):
            data = ""
            for prop, value in vars(ext.value).items():
                if type(value) is bytes:
                    # convert byte strings to hex

                    value = value.hex()
                elif type(value) is list:
                    # some values are lists of more values, these need special processing.

                    item_data = []
                    for item in value:
                        if type(item) is x509.ObjectIdentifier:
                            # if this is an OID, we only care about the name

                            if item._name != "Unknown OID":
                                item_data.append(item._name)
                            else:
                                item_data.append(item.dotted_string)
                        elif type(item) is x509.PolicyInformation:
                            item_data.append(
                                "policy_identifier={oid}, policy_qualifiers={pq}".format(
                                    oid=item.policy_identifier.dotted_string,
                                    pq=item.policy_qualifiers,
                                )
                            )
                        elif type(item) is x509.DistributionPoint:
                            points = []

                            for point in item.full_name:
                                points.append(point.value)

                            item_data.append(" ".join(points).strip())
                        elif type(item) is x509.AccessDescription:
                            if item.access_method._name != "Unknown OID":
                                name = item.access_method._name
                            else:
                                name = item.access_method.dotted_string

                            item_data.append(
                                "{name}={url}".format(
                                    name=name, url=item.access_location.value
                                )
                            )
                        else:
                            item_data.append(str(item))

                    # assemble and clean up the data
                    value = "(" + ", ".join(item_data).rstrip().rstrip(",") + ")"

                data += "{prop}={val}, ".format(prop=prop.lstrip("_"), val=value)

            data = data.rstrip().rstrip(",")

            extensions.append(
                "{name}, critical={critical}, {value}".format(
                    name=name, critical=critical, value=data
                )
            )

    return extensions


def get_scts(cert: x509.Certificate):
    scts = []

    for ext in cert.extensions:
        # check for the PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS OID
        if ext.oid.dotted_string == "1.3.6.1.4.1.11129.2.4.2":
            for sct in ext.value:
                scts.append(
                    [sct.version, bytes.hex(sct.log_id), sct.timestamp, sct.entry_type]
                )

    return scts


def get_common_names(cert: x509.Certificate) -> List[str]:
    names = []

    for name in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        names.append(name.value)

    return names


def get_alt_names(cert: x509.Certificate) -> List[str]:
    for ext in cert.extensions:
        # SUBJECT_ALTERNATIVE_NAME
        if ext.oid.dotted_string == "2.5.29.17":
            ext = cast(x509.SubjectAlternativeName, ext)

            return ext.value.get_values_for_type(x509.DNSName)

    return []


def get_must_staple(cert: x509.Certificate):
    ret = False

    for ext in cert.extensions:
        # Must Staple OID
        if ext.oid.dotted_string == "1.3.6.1.5.5.7.1.24":
            ret = True

    return ret


def check_symantec_root(root_hash):
    # list of Symantec root cert hashes
    roots = [
        "08297a4047dba23680c731db6e317653ca7848e1bebd3a0b0179a707f92cf178",
        "2399561127a57125de8cefea610ddf2fa078b5c8067f4e828290bfb860e84b3c",
        "2834991cf677466d22baac3b0055e5b911d9a9e55f5b85ba02dc566782c30e8a",
        "2930bd09a07126bdc17288d4f2ad84645ec948607907a97b5ed0b0b05879ef69",
        "2f274e48aba4ac7b765933101775506dc30ee38ef6acd5c04932cfe041234220",
        "309b4a87f6ca56c93169aaa99c6d988854d7892bd5437e2d07b29cbeda55d35d",
        "3266967e59cd68008d9dd320811185c704205e8d95fdd84f1c7b311e6704fc32",
        "341de98b1392abf7f4ab90a960cf25d4bd6ec65b9a51ce6ed067d00ec7ce9b7f",
        "363f3c849eab03b0a2a0f636d7b86d04d3ac7fcfe26a0a9121ab9795f6e176df",
        "37d51006c512eaab626421f1ec8c92013fc5f82ae98ee533eb4619b8deb4d06c",
        "3a43e220fe7f3ea9653d1e21742eac2b75c20fd8980305bc502caf8c2d9b41a1",
        "3f9f27d583204b9e09c8a3d2066c4b57d3a2479c3693650880505698105dbce9",
        "44640a0a0e4d000fbd574d2b8a07bdb4d1dfed3b45baaba76f785778c7011961",
        "4b03f45807ad70f21bfc2cae71c9fde4604c064cf5ffb686bae5dbaad7fdd34c",
        "53dfdfa4e297fcfe07594e8c62d5b8ab06b32c7549f38a163094fd6429d5da43",
        "5b38bd129e83d5a0cad23921089490d50d4aae370428f8ddfffffa4c1564e184",
        "5edb7ac43b82a06a8761e8d7be4979ebf2611f7dd79bf91c1c6b566a219ed766",
        "5f0b62eab5e353ea6521651658fbb65359f443280a4afbd104d77d10f9f04c07",
        "614fd18da1490560cdad1196e2492ab7062eab1a67b3a30f1d0585a7d6ba6824",
        "69ddd7ea90bb57c93e135dc85ea6fcd5480b603239bdc454fc758b2a26cf7f79",
        "76ef4762e573206006cbc338b17ca4bc200574a11928d90c3ef31c5e803e6c6f",
        "83ce3c1229688a593d485f81973c0f9195431eda37cc5e36430e79c7a888638b",
        "87c678bfb8b25f38f7e97b336956bbcf144bbacaa53647e61a2325bc1055316b",
        "8d722f81a9c113c0791df136a2966db26c950a971db46b4199f4ea54b78bfb9f",
        "8dbb5a7c06c20ef62dd912a36740992ff6e1e8583d42ede257c3affd7c769399",
        "8f9e2751dcd574e9ba90e744ea92581fd0af640ae86ac1ce2198c90f96b44823",
        "92a9d9833fe1944db366e8bfae7a95b6480c2d6c6c2a1be65d4236b608fca1bb",
        "944554239d91ed9efedcf906d5e8113160b46fc816dc6bdc77b89da29b6562b9",
        "9acfab7e43c8d880d06b262a94deeee4b4659989c3d0caf19baf6405e41ab7df",
        "9d190b2e314566685be8a889e27aa8c7d7ae1d8aaddba3c1ecf9d24863cd34b9",
        "9e503738722e0a104cf659ff9f92f0b5b3662acd112d4664d1e7db93abf46a59",
        "a0234f3bc8527ca5628eec81ad5d69895da5680dc91d1cb8477f33f878b95b0b",
        "a0459b9f63b22559f5fa5d4c6db3f9f72ff19342033578f073bf1d1b46cbb912",
        "a4310d50af18a6447190372a86afaf8b951ffb431d837f1e5688b45971ed1557",
        "a4b6b3996fc2f306b3fd8681bd63413d8c5009cc4fa329c2ccf0e2fa1b140305",
        "b32396746453442f353e616292bb20bbaa5d23b546450fdb9c54b8386167d529",
        "b478b812250df878635c2aa7ec7d155eaa625ee82916e2cd294361886cd1fbd4",
        "bb6ce72f0e64bfd93ade14b1becf8c41e7bc927cafb477a3a95878c01aa26c3e",
        "bcff2ab03578ebbfb219b65e854cf26a3d8dfe6d1acf3e765b8636827b81eaee",
        "c38dcb38959393358691ea4d4f3ce495ce748996e64ed1891d897a0fc4dd55c6",
        "c4fa68f8270924c300cbc0d3615a7b88e82231749cf6522452272222c9f0a83e",
        "ca2d82a08677072f8ab6764ff035676cfe3e5e325e012172df3f92096db79b85",
        "cb627d18b58ad56dde331a30456bc65c601a4e9b18dedcea08e7daaa07815ff0",
        "cb6b05d9e8e57cd882b10b4db70de4bb1de42ba48a7bd0318b635bf6e7781a9d",
        "cbb02707160f4f77291a27561448691ca5901808e5f36e758449a862aa5272cb",
        "cbb5af185e942a2402f9eacbc0ed5bb876eea3c1223623d00447e4f3ba554b65",
        "cf56ff46a4a186109dd96584b5eeb58a510c4275b0e5f94f40bbae865e19f673",
        "d17cd8ecd586b712238a482ce46fa5293970742f276d8ab6a9e46ee0288f3355",
        "ddcef1660de3b06996507f56168865a20b43cda89cf7e8735a82b83bba00c498",
        "e389360d0fdbaeb3d250584b4730314e222f39c156a020144e8d960561791506",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "e6b8f8766485f807ae7f8dac1670461f07c0a13eef3a1ff717538d7abad391b4",
        "eb04cf5eb1f39afa762f2bb120f296cba520c1b97db1589565b81cb9a17b7244",
        "ebf3c02a8789b1fb7d511995d663b72906d913ce0d5e10568a8a77e2586167e7",
        "f5074a8f5b9a5b8142f34abe152f60364d770eae75ee3eeceb45b6b996509788",
        "f59db3f45d57fcec94ccd516e6c8ccb20dd4363feb2c44d8656e95f50fdd8df8",
        "fe863d0822fe7a2353fa484d5924e875656d3dc9fb58771f6f616f9d571bc592",
        "ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a",
    ]

    return root_hash in roots


def get_ct_log_name(log_id: str):
    global _ct_log_info

    # check to see if we have the CT log info cached
    if len(_ct_log_info) == 0:
        _ct_log_info = _get_ct_log_data()

    if _ct_log_info.get(log_id) is not None:
        return _ct_log_info[log_id]
    else:
        return "(Unknown: {hash})".format(hash=log_id)


def _get_ct_log_data():
    ct_log_info: Dict[str, str] = {}

    data, _ = network.http_json(
        "https://www.gstatic.com/ct/log_list/all_logs_list.json"
    )

    for log in data["logs"]:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(base64.b64decode(log["key"]))
        final = digest.finalize()
        value = bytes.hex(final)

        ct_log_info[value] = log["description"]

    return ct_log_info
