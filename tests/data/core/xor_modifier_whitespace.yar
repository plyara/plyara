rule XorExample1
{
    strings:
        $xor_string = "This program cannot" xor(0x01-0xff)
    condition:
        $xor_string
}

rule XorExample2
{
    strings:
        $xor_string = "This program cannot" xor (0x01-0xff)
    condition:
        $xor_string
}

rule XorExample3
{
    strings:
        $xor_string = "This program cannot" xor( 0x01-0xff)
    condition:
        $xor_string
}

rule XorExample4
{
    strings:
        $xor_string = "This program cannot" xor(0x01 -0xff)
    condition:
        $xor_string
}

rule XorExample5
{
    strings:
        $xor_string = "This program cannot" xor(0x01- 0xff)
    condition:
        $xor_string
}

rule XorExample6
{
    strings:
        $xor_string = "This program cannot" xor(0x01-0xff )
    condition:
        $xor_string
}

rule XorExample7
{
    strings:
        $xor_string = "This program cannot" xor ( 0x01 - 0xff )
    condition:
        $xor_string
}

rule XorExample8
{
    strings:
        $xor_string = "This program cannot" xor     (   0x01 - 0xff   )
    condition:
        $xor_string
}
