// This ruleset is used for unit tests - Modification will require test updates

rule Text
{
    strings:
        $text_string = "foobar"

    condition:
       $text_string
}

rule FullwordText
{
    strings:
        $text_string = "foobar" fullword

    condition:
       $text_string
}

rule CaseInsensitiveText
{
    strings:
        $text_string = "foobar" nocase

    condition:
        $text_string
}

rule WideCharText
{
    strings:
        $wide_string = "Borland" wide

    condition:
       $wide_string
}

rule WideCharAsciiText
{
    strings:
        $wide_and_ascii_string = "Borland" wide ascii

    condition:
       $wide_and_ascii_string
}

rule HexWildcard
{
    strings:
       $hex_string = { E2 34 ?? C8 A? FB }

    condition:
       $hex_string
}

rule HexJump
{
    strings:
        $hex_string = { F4 23 [4-6] 62 B4 }

    condition:
        $hex_string
}

rule HexAlternatives
{
    strings:
       $hex_string = { F4 23 ( 62 B4 | 56 ) 45 }

    condition:
       $hex_string
}

rule HexMultipleAlternatives
{
    strings:
       $hex_string = { F4 23 ( 62 B4 | 56 | 45 ?? 67 ) 45 }

    condition:
       $hex_string
}

rule RegExp
{
    strings:
        $re1 = /md5: [0-9a-fA-F]{32}/nocase // no case for hash
        $re2 = /state: (on|off)/i//no case for state
        $re3 = /\x00https?:\/\/[^\x00]{4,500}\x00\x00\x00/

    condition:
        $re1 and $re2 and $re3
}

rule Xor
{
    strings:
        $xor_string = "This program cannot" xor

    condition:
       $xor_string
}

rule WideXorAscii
{
    strings:
        $xor_string = "This program cannot" xor wide ascii

    condition:
        $xor_string
}

rule WideXor
{
    strings:
        $xor_string = "This program cannot" xor wide

    condition:
        $xor_string
}

rule DoubleBackslash
{
    strings:
        $bs = "\"\\\\\\\""

    condition:
        $bs
}

rule DoubleQuote
{
    strings:
        $text_string = "foobar\""

    condition:
       $text_string
}

rule HorizontalTab
{
    strings:
        $text_string = "foo\tbar"

    condition:
       $text_string
}

rule Newline
{
    strings:
        $text_string = "foo\nbar"

    condition:
       $text_string
}

rule HexEscape
{
    strings:
        $text_string = "foo\x00bar"

    condition:
       $text_string
}
