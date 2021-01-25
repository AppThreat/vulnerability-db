import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="appthreat-vulnerability-db",
    version="1.6.5",
    author="Team AppThreat",
    author_email="cloud@appthreat.com",
    description="AppThreat's vulnerability database and package search library with a built-in file based storage. CVE, GitHub, npm are the primary sources of vulnerabilities.",
    entry_points={"console_scripts": ["vdb=vdb.cli:main"]},
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/appthreat/vulnerability-db",
    packages=setuptools.find_packages(),
    install_requires=["requests", "appdirs", "tabulate", "msgpack", "orjson", "semver"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Utilities",
        "Topic :: Security",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
