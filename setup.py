"""Setup configuration for CertSeal."""

from setuptools import setup, find_packages

setup(
    name="certseal",
    version="1.0.0",
    description="Open-source PKI cryptographic tool — CertSeal",
    author="Alish Twati",
    license="MIT",
    packages=find_packages(),
    install_requires=["cryptography>=41.0.0"],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "certseal=cli.main:main",
        ],
    },
)
