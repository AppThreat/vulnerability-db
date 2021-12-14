# Introduction

This repo is a vulnerability database and package search for sources such as OSV, NVD, GitHub, and NPM. Vulnerability data are downloaded from the sources and stored in a custom file based storage with indexes to allow offline access and quick searches.

## Installation

```bash
pip install appthreat-vulnerability-db
```

## Usage

This package is ideal as a library for managing vulnerabilities. This is used by [dep-scan](http://github.com/AppThreat/dep-scan), a free open-source dependency audit tool. However, there is a limited cli capability available with few features to test this tool directly.

### Cache vulnerability data

Cache from all sources

```bash
vdb --cache
```

Cache from just [OSV](https://osv.dev)

```bash
vdb --cache --only-osv
```

It is possible to customise the cache behaviour by increasing the historic data period to cache by setting the following environment variables.

- NVD_START_YEAR - Default: 2016. Supports upto 2002
- GITHUB_PAGE_COUNT - Default: 5. Supports upto 20

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
```

Syntax is package:version,package:version or vendor : package : version (Without space)
