rule test1
{
    strings:
        $op = { AA AA ~AA }
    condition:
        $op
}

rule test2
{
    strings:
        $op = { AA AA~AA }
    condition:
        $op
}

rule test3
{
    meta:
        one = -0
    condition:
        true
}

rule test4
{
    condition:
        -0.5
}

rule test5
{
    condition:
        -1.5
}
