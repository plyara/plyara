rule rule1
{
    strings:
        $op = { ABABABABABABABABABABAB }
    condition:
        $op
}
💩
rule rule2
{
    strings:
        $op = { ABABABABABABABABABABAB }
    condition:
        $op
}
