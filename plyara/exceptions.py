"""plyara exceptions.

This module contains the set of plyara's exceptions.
"""


class ParseError(Exception):
    """Base parsing error exception type.

    It stores also the line number and lex position as instance
    attributes 'lineno' and 'lexpos' respectively.
    """

    def __init__(self, lineno, lexpos, message=None):
        """Initialize exception object."""
        self.lineno = lineno
        self.lexpos = lexpos
        if message is not None:
            super(ParseError, self).__init__(message)


class ParseTypeError(ParseError):
    """Error emmited during parsing when a wrong token type is encountered.

    It stores also the line number and lex position as instance
    attributes 'lineno' and 'lexpos' respectively.
    """

    def __init__(self, message, lineno, lexpos):
        """Initialize exception object."""
        super(ParseTypeError, self).__init__(lineno, lexpos, message)


class ParseValueError(ParseError):
    """Error emmited during parsing when a wrong value is encountered.

    It stores also the line number and lex position as instance
    attributes 'lineno' and 'lexpos' respectively.
    """

    def __init__(self, message, lineno, lexpos):
        """Initialize exception object."""
        super(ParseValueError, self).__init__(lineno, lexpos, message)
