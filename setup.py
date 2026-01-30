import re
from setuptools import setup, find_packages


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
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    url="https://github.com/IdentityPython/pyMDL-MDOC",
    author="Giuseppe De Marco",
    author_email="demarcog83@gmail.com",
    license="License :: OSI Approved :: Apache Software License",
    # scripts=[f'{_pkg_name}/bin/{_pkg_name}'],
    packages=find_packages(include=["pymdoccbor", "pymdoccbor.*"]),
    include_package_data=True,
    install_requires=["cbor2>=5.4.0", "cbor-diag>=1.1.0", "pycose>=1.0.1"],
)
