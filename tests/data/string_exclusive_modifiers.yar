rule duplicate_modifier
{
    strings:
        $a = "one" xor xor
    condition:
        all of them
}

rule invalid_xor_modifier
{
    strings:
        $a = /AA/ xor(500)
    condition:
        all of them
}

rule base64_error_nocase
{
    strings:
        $a = "one" base64("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu") nocase
        $b = "two" base64wide("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu") nocase
    condition:
        all of them
}

rule base64_error_xor
{
    strings:
        $a = "one" base64("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu") xor
        $b = "two" base64wide("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu") xor
    condition:
        all of them
}

rule base64_error_xor
{
    strings:
        $a = "one" base64("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstuxyz") xor
        $b = "two" base64wide("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstuxyz") xor
    condition:
        all of them
}

rule base64_error_xor
{
    strings:
        $a = "one" base64("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZ") xor
        $b = "two" base64wide("!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZ") xor
    condition:
        all of them
}
