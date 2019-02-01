#!/usr/bin/env python3
# Copyright 2014 Christian Buia
# Copyright 2019 plyara Maintainers
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""plyara exceptions.

This module contains the set of plyara's exceptions.
"""


class ParseError(Exception):
    """Base parsing error exception type.

    It stores also the line number and lex position as instance
    attributes 'lineno' and 'lexpos' respectively.
    """

    def __init__(self, message, lineno, lexpos):
        """Initialize exception object."""
        self.lineno = lineno
        self.lexpos = lexpos
        super().__init__(message)


class ParseTypeError(ParseError):
    """Error emmited during parsing when a wrong token type is encountered.

    It stores also the line number and lex position as instance
    attributes 'lineno' and 'lexpos' respectively.
    """

    def __init__(self, message, lineno, lexpos):
        """Initialize exception object."""
        super().__init__(message, lineno, lexpos)


class ParseValueError(ParseError):
    """Error emmited during parsing when a wrong value is encountered.

    It stores also the line number and lex position as instance
    attributes 'lineno' and 'lexpos' respectively.
    """

    def __init__(self, message, lineno, lexpos):
        """Initialize exception object."""
        super().__init__(message, lineno, lexpos)
