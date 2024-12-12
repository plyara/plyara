rule sanity_check_external_variables {
	meta:
		author = "Rakovskij Stanislav / disasm.me"
		date = "22.08.2020"
	strings:
		$a = "test"
	condition:
		for count_of_test i in (1..#a) : ( @a[i] < 100 )
}
