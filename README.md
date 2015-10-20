plyara
======

tl;dr: Parse Yara rules into a dictionary representation.

Plyara is a script that lexes and parses a file consisting of one more Yara rules into a python dictionary representation.  The goal of this tool is to make it easier to perform bulk operations or transformations of large sets of Yara rules, such as extracting indicators, updating attributes, and analyzing a corpus.  Other applications include linters and dependency checkers.

Plyara leverages the Python module Ply for lexing Yara.

More info:

http://www.dabeaz.com/ply/

http://plusvic.github.io/yara/
