rule bad_parsed_subtraction{
    meta:
        author = "Rakovskij Stanislav / disasm.me"
        date = "09.03.2021"
        description = "test rule in which we have bad parsing of minus sign between two variables"
    strings:
        $a = "Test"
        $b = "Test 2"
    condition:
         @a-@b<128
}

rule good_parsed_addition{
    meta:
        author = "Rakovskij Stanislav / disasm.me"
        date = "09.03.2021"
        description = "test rule in which we have bad parsing of minus sign between two variables"
    strings:
        $a = "Test"
        $b = "Test 2"
    condition:
         @a+@b<128
}

rule rule_extra_empty_line
{
    meta:
        author = "Rakovskij Stanislav / disasm.me"
        date = "09.03.2021"
        description = "actually magic"
    strings:
        $a = "hello"
        $b = "world"
    condition:
        @b-@a<128
}
