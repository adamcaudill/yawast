#  Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import distutils
import opcode
import sys
from os import path
from pathlib import Path
from typing import List, Union, Tuple

from requirementslib import Lockfile
from setuptools import find_packages

if "build_exe" in sys.argv:
    from cx_Freeze import setup, Executable
else:
    from setuptools import setup

    # fake Executable class to avoid cx_Freeze on non-Windows
    # noinspection Mypy
    class Executable:
        # noinspection PyUnusedLocal
        def __init__(self, script=None, base=None):
            pass


# effectively a NOP, to keep the import
# we are doing this as a hack, to fix a cx_Freeze issue.
_ = distutils.__version__
distutils_path = path.join(path.dirname(opcode.__file__), "distutils")

if getattr(sys, "frozen", False):
    # frozen
    root_path = path.dirname(sys.executable)
else:
    # unfrozen
    root_path = path.dirname(path.realpath(__file__))

# search for DLL files needed for SSL support
if hasattr(sys, "real_prefix"):
    win_search_path = sys.real_prefix
else:
    win_search_path = sys.base_prefix

win_search_pattern = ["**/libcrypto-*.dll", "**/libssl-*.dll"]
win_include_files: List[Union[str, Tuple[Union[bytes, str], str]]] = []
for srch in win_search_pattern:
    for dll in Path(win_search_path).glob(srch):
        full_path = str(dll.resolve(True))
        target_name = path.join("lib", path.basename(full_path))
        win_include_files.append((full_path, target_name))
        break

win_include_files.append((distutils_path, "distutils"))

# Dependencies are automatically detected.
# I'm not sure about the *version.py files, but this hack works.
build_exe_options = {
    "packages": ["os", "dns"],
    "includes": [
        "six",
        "appdirs",
        "packaging.version",
        "packaging.specifiers",
        "packaging.requirements",
        "html.parser",
        "setuptools.msvc",
        "psutil",
        "colorama",
        "validator_collection",
        "jsonschema",
        "cryptography",
        "_cffi_backend",
        "requests",
        "requests.packages.idna",
        "requests.packages.idna.idnadata",
        "idna.idnadata",
        "publicsuffixlist",
        "sslyze",
        "bs4",
        "selenium",
        "configparser",
        "ordered_set",
    ],
    "excludes": ["tkinter", "distutils"],
    "include_files": win_include_files,
}
bdist_msi_options = {"add_to_path": True}


def get_version_and_cmdclass(package_path):
    """Load version.py module without importing the whole package.

    Template code from miniver
    """
    import os
    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("version", os.path.join(package_path, "_version.py"))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.__version__, module.cmdclass


version, cmdclass = get_version_and_cmdclass("yawast")


def get_long_description():
    """Convert the README file into the long description.
    """
    with open(path.join(root_path, "README.md"), encoding="utf-8") as f:
        long_description = f.read()
    return long_description


def get_install_reqs():
    try:
        lf = Lockfile.load(root_path)

        return lf.requirements_list
    except AttributeError:
        # if it fails, return an empty list - lock file likely missing
        return []


setup(
    name="yawast",
    version=version,
    cmdclass=cmdclass,
    description="The YAWAST Antecedent Web Application Security Toolkit",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/adamcaudill/yawast",
    project_urls={
        "Bug Reports": "https://github.com/adamcaudill/yawast/issues",
        "Source": "https://github.com/adamcaudill/yawast",
        "Changelog": "https://github.com/adamcaudill/yawast/blob/master/CHANGELOG.md",
    },
    author="Adam Caudill",
    author_email="adam@adamcaudill.com",
    license="MIT",
    options={"build_exe": build_exe_options, "build_msi": bdist_msi_options},
    executables=[Executable("bin/yawast", base=None)],
    packages=find_packages(exclude=["tests"]),
    entry_points={"console_scripts": ["yawast = yawast.__main__:main"]},
    install_requires=get_install_reqs(),
    include_package_data=True,
    package_data={"yawast": ["resources/*"]},
    zip_safe=False,
    python_requires=">=3.7",
    keywords="security tls ssl dns http scan vulnerability",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: MIT License",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Natural Language :: English",
        "Topic :: Internet :: Name Service (DNS)",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking",
        "Topic :: Software Development :: Testing",
        "Topic :: Security",
    ],
)
