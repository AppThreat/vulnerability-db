# Introduction

This repo is a vulnerability database and package search for sources such as Aqua Security vuln-list, OSV, NVD, GitHub, and NPM. Vulnerability data are downloaded from the sources and stored in a custom file based storage with indexes to allow offline access and quick searches.

## Vulnerability Data sources

- Linux [vuln-list](https://github.com/appthreat/vuln-list) (Forked from AquaSecurity)
- OSV (1)
- NVD (2)
- GitHub
- NPM

1 - We exclude linux and oss-fuzz feeds by default. Set the environment variable `OSV_INCLUDE_FUZZ` to include them.

2 - We exclude hardware (h) by default. Set the environment variable `NVD_EXCLUDE_TYPES` to exclude additional types such as OS (o) or application (a). An empty value means include all categories. Comma separated values are allowed. Eg: `o,h`

## Linux distros

- AlmaLinux
- Debian
- Alpine
- Amazon Linux
- Arch Linux
- RHEL/CentOS
- Rocky Linux
- Ubuntu
- OpenSUSE/SLES
- Photon
- Chainguard
- Wolfi OS

## Installation

```bash
pip install appthreat-vulnerability-db
```

## Usage

This package is ideal as a library for managing vulnerabilities. This is used by [dep-scan](http://github.com/AppThreat/dep-scan), a free open-source dependency audit tool. However, there is a limited cli capability available with few features to test this tool directly.

### Download pre-built database

Use the [ORAS cli](https://oras.land/cli/) to download a pre-built database containing all application and OS vulnerabilities.

```
export VDB_HOME=$HOME/vdb
oras pull ghcr.io/appthreat/vdb:v5 -o $VDB_HOME
```

### Cache vulnerability data

Cache application vulnerabilities

```bash
vdb --cache
```

Typical size of this database is over 1.1 GB.

Cache application and OS vulnerabilities

```bash
vdb --cache-os
```

Note the size of the database with OS vulnerabilities is over 3.1 GB.

Cache from just [OSV](https://osv.dev)

```bash
vdb --cache --only-osv
```

It is possible to customise the cache behaviour by increasing the historic data period to cache by setting the following environment variables.

- NVD_START_YEAR - Default: 2018. Supports upto 2002
- GITHUB_PAGE_COUNT - Default: 2. Supports upto 20

### Periodic sync

To periodically sync the latest vulnerabilities and update the database cache.

```bash
vdb --sync
```

### Basic search

It is possible to perform simple search using the cli.

```bash
vdb --search android:8.0

vdb --search google:android:8.0

vdb --search android:8.0,simplesamlphp:1.14.11

vdb --search pkg:pypi/xml2dict@0.2.2
```

Syntax is package:version,package:version or vendor : package : version (Without space)
