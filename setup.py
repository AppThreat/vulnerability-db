import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="appthreat-vulndb",
    version="1.0.1",
    author="Team AppThreat",
    author_email="cloud@appthreat.com",
    description="Vulnerability database and package search for sources such as CVE, GitHub, and so on. Uses a built-in file based storage.",
    entry_points={"console_scripts": ["vdb=vulndb.cli:main"]},
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/appthreat/vulndb",
    packages=setuptools.find_packages(),
    install_requires=["requests", "appdirs", "tabulate", "msgpack"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Utilities",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">= 3",
)
