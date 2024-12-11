rule minus_bad{
	meta:
        author = "Rakovskij Stanislav / disasm.me"
        date = "22.08.2020"
        description = "test rule in which we have bad parsing of minus sign"
	strings:
	$str_after = "END_TAG"
        $str_bef = "START_TAG"
	condition:
		 $str_bef in (@str_after-512 .. @str_after)
}

rule minus_good{
    meta:
        author = "Rakovskij Stanislav / disasm.me"
        date = "22.08.2020"
        description = "test rule in which we have good parsing of minus sign"
    strings:
    $str_after = "END_TAG"
        $str_bef = "START_TAG"
    condition:
         $str_bef in (@str_after - 512 .. @str_after)
}

rule minus_very_bad{
    meta:
        author = "Rakovskij Stanislav / disasm.me"
        date = "22.08.2020"
        description = "test rule in which we have bad parsing of minus sign"
    strings:
    $str_after = "END_TAG"
        $str_bef = "START_TAG"
    condition:
         $str_bef in (@str_after- -512 .. @str_after)
}

rule minus_very_very_bad{
    meta:
        author = "Rakovskij Stanislav / disasm.me"
        date = "22.08.2020"
        description = "test rule in which we have bad parsing of minus sign"
    strings:
    $str_after = "END_TAG"
        $str_bef = "START_TAG"
    condition:
         $str_bef in (@str_after--512 .. @str_after)
}

rule minus_bad_hexnum{
	meta:
        author = "Rakovskij Stanislav / disasm.me"
        date = "22.08.2020"
        description = "test rule in which we have bad parsing of minus sign"
	strings:
	$str_after = "END_TAG"
        $str_bef = "START_TAG"
	condition:
		 $str_bef in (@str_after-0x200 .. @str_after)
}

rule minus_good_hexnum{
    meta:
        author = "Rakovskij Stanislav / disasm.me"
        date = "22.08.2020"
        description = "test rule in which we have good parsing of minus sign"
    strings:
    $str_after = "END_TAG"
        $str_bef = "START_TAG"
    condition:
         $str_bef in (@str_after - 0x200 .. @str_after)
}

rule minus_very_bad_hexnum{
    meta:
        author = "Rakovskij Stanislav / disasm.me"
        date = "22.08.2020"
        description = "test rule in which we have bad parsing of minus sign"
    strings:
    $str_after = "END_TAG"
        $str_bef = "START_TAG"
    condition:
         $str_bef in (@str_after- -0x200 .. @str_after)
}

rule minus_very_very_bad_hexnum{
    meta:
        author = "Rakovskij Stanislav / disasm.me"
        date = "22.08.2020"
        description = "test rule in which we have bad parsing of minus sign"
    strings:
    $str_after = "END_TAG"
        $str_bef = "START_TAG"
    condition:
         $str_bef in (@str_after--0x200 .. @str_after)
}
