# Checks Before Pull Request

In order to consider your pull request please follow the following steps:

- Make sure the installation is working for the in the README mentioned options
  - [Add Plugin](./../README.md#add-plugin)
  - [Installation via Docker for developing and testing purposes](./../README.md#installation-via-docker-for-developing-and-testing-purposes)
- Check features of the plugin
  - Check if plugin is callable
  - Check the device import process
  - Check the connection import process

## General Readiness

check if 

- `plugins/d3c/findings/list/` and
- `plugins/d3c/communication_finding/list/`

are callable. Import the following data from `/data/` via netbox standard import:

|menu |filename|
|-|-|
|device|test_netbox_device.csv|
|interface|test_netbox_interface.csv|
|ipam ip-addresses|test_netbox_ipam.csv|

Assign IPv4 Address as primary under each device

> Note: This check should be automated

## Device Import

1. Check [Import Data](#import-data)
2. Check [Findings](#findings)
3. Check [Device Finding](#mapping)

### Import Data

Check the import of data via the plugin

- Check if import std function in the plugin is working
- Check if import dddc function is working properly
- Check if import of raw data is working properly
- Check if Regex is working properly
- Check if StringMinder is working (not useable yet)

### Findings

- Check multiple ip and mac function using `test_easy.csv` and `test_multi.csv`
- Check create device
- Check mapping

### Mapping

- Check if findings are displayed properly
- Check the spellchecker
- Check the apply function
  - overwriting existing field
  - set empty field

## Connection Import

> Note: Skip this until the mask error is resolved by PullRequest #

Use `ds-dump-communications.json` via the Build Add Option in the menu.
