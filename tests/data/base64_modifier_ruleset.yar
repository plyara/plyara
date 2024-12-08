// The following work with YARA >= 3.12.0

rule base64_unmodified
{
    strings:
        $a = "one" base64
    condition:
        all of them
}

rule base64wide_unmodified
{
    strings:
        $a = "one" base64wide
    condition:
        all of them
}

rule base64_mod_custom
{
    strings:
        $a = "one" base64("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu")
    condition:
        all of them
}

rule base64wide_mod_custom
{
    strings:
        $a = "one" base64wide("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu")
    condition:
        all of them
}
