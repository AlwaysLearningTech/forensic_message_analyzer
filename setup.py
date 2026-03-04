import re
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

# Read version from the single source of truth
with open("src/__init__.py", "r") as fh:
    _version = re.search(r'__version__\s*=\s*["\']([^"\']+)', fh.read()).group(1)

setup(
    name="forensic-message-analyzer",
    version=_version,
    author="Forensic Analysis System",
    description="A legally-compliant forensic analysis tool for digital communications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Legal Industry",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "forensic-analyze=src.main:main",
        ],
    },
)
