from setuptools import setup
from setuptools import find_packages

version = "0.1.0"

install_requires = [
    "acme>=1.22.0",
    "certbot>=1.22.0",
    "setuptools",
    "requests>=2.26.0",
    "bs4>=0.0.1",
]

# read the contents of your README file
from os import path

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, "README.rst")) as f:
    long_description = f.read()

setup(
    name="certbot-dns-freedns",
    version=version,
    description="FreeDNS Authenticator plugin for Certbot",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/schleuss/certbot-dns-freedns",
    author="Rafael Schleuss",
    author_email="rschleuss@gmail.com",
    license="Apache License 2.0",
    python_requires=">=3.0",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Plugins",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: System :: Installation/Setup",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    entry_points={
        "certbot.plugins": [
            "dns-freedns = certbot_dns_freedns.dns_freedns:Authenticator"
        ]
    }
)
