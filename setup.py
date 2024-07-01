# Modifications have been made to the original file (available at https://github.com/IdentityPython/pyMDOC-CBOR)
# All modifications Copyright (c) 2023 European Commission

# All modifications licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re

from glob import glob
from setuptools import setup


def readme():
    with open("README.md") as f:
        return f.read()


_pkg_name = "pymdoccbor"

with open(f"{_pkg_name}/__init__.py", "r") as fd:
    VERSION = re.search(
        r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]', fd.read(), re.MULTILINE
    ).group(1)

setup(
    name=_pkg_name,
    version=VERSION,
    description="Python parser and writer for Mobile Driving License and EUDI Wallet MDOC CBOR.",
    long_description=readme(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    url="https://github.com/peppelinux/pyMDL-MDOC",
    author="Giuseppe De Marco",
    author_email="demarcog83@gmail.com",
    license="License :: OSI Approved :: Apache Software License",
    # scripts=[f'{_pkg_name}/bin/{_pkg_name}'],
    packages=[f"{_pkg_name}"],
    package_dir={f"{_pkg_name}": f"{_pkg_name}"},
    package_data={
        f"{_pkg_name}": [
            i.replace(f"{_pkg_name}/", "")
            for i in glob(f"{_pkg_name}/**", recursive=True)
        ]
    },
    install_requires=[
        "cbor2>=5.4.0,<5.5.0",
        "cwt>=2.3.0,<2.4",
        "pycose @ git+https://github.com/devisefutures/pycose.git@hsm",
    ],
)
