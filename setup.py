from setuptools import setup, find_packages

setup(
    name="pq-ratchet",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "cryptography>=47.0.0",
    ],
    entry_points={
        "console_scripts": [
            "pq-ratchet=pq_ratchet.cli:main",
        ],
    },
)
