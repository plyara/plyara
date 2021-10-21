rule FirstRule
{
	strings:
		$a = "hark, a \"string\" here" fullword ascii
		$b = { 00 22 44 66 88 aa cc ee }

	condition:
		all of them
}
rule SecondRule : aTag
{
	strings:
		$x = "hi"
		$y = /state: (on|off)/ wide
		$z = "bye"

	condition:
		for all of them : (#>2)
}
rule ForthRule
{
	condition:
		uint8(0)^unit8(1)==0x12
}
rule FifthRule
{
	condition:
		file_name icontains "filename" and file_name endswith ".exe" and file_name iendswith ".exe"
}
rule SixthRule
{
	condition:
		file_name startswith "file" and file_name istartswith "file"
}
