# plyara

[![PyPi Version](http://img.shields.io/pypi/v/plyara.svg)](https://pypi.python.org/pypi/plyara)
![Testing Status](http://img.shields.io/github/actions/workflow/status/plyara/plyara/test-action.yaml)
![GitHub License](https://img.shields.io/github/license/plyara/plyara)
![GitHub Repo stars](https://img.shields.io/github/stars/plyara/plyara)

Parse [YARA](https://virustotal.github.io/yara/) rules into a dictionary representation.

Plyara is a script and library that lexes and parses a file consisting of one more YARA rules into a python dictionary representation. The goal of this tool is to make it easier to perform bulk operations or transformations of large sets of YARA rules, such as extracting indicators, updating attributes, and analyzing a corpus. Other applications include linters and dependency checkers.

Plyara leverages the Python module [PLY](https://ply.readthedocs.io/en/latest/) for lexing YARA rules.

This is a community-maintained fork of the [original plyara](https://github.com/8u1a/plyara) by [8u1a](https://github.com/8u1a). The "plyara" trademark is used with permission.