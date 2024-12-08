rule minus_bad{
	meta:
        author = "Rakovskij Stanislav / disasm.me"
        date = "22.08.2020"
        description = "test rule in which we have bad parsing of minus sign"
	strings:
	$str_after = "END_TAG"
        $str_before = "START_TAG"
	condition:
		 $str_before in (@str_after-512 .. @str_after)
}


rule minus_good{
	meta:
        author = "Rakovskij Stanislav / disasm.me"
        date = "22.08.2020"
        description = "test rule in which we have good parsing of minus sign"
	strings:
	$str_after = "END_TAG"
        $str_before = "START_TAG"
	condition:
		 $str_before in (@str_after - 512 .. @str_after)
}
