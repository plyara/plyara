rule xor_unmodified
{
    strings:
        $a = "one" xor wide
    condition:
        all of them
}

// The following work with YARA >= 3.11.0

rule xor_mod_num_single
{
    strings:
        $a = "one" xor(16)
    condition:
        all of them
}

rule xor_mod_num_range
{
    strings:
        $a = "one" xor( 16 - 128 )
    condition:
        all of them
}

rule xor_mod_hexnum_single
{
    strings:
        $a = "one" xor(0x10)
    condition:
        all of them
}

rule xor_mod_hexnum_range
{
    strings:
        $a = "one" xor( 0x10 - 0x80 )
    condition:
        all of them
}

rule xor_mod_mixed_range
{
    strings:
        $a = "one" xor( 16 - 0x80 )
    condition:
        all of them
}
