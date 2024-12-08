// This ruleset is used for unit tests - Modification will require test updates

rule rule_two
{
    strings:
        $a = "two"
    condition:
        all of them
}

rule rule_three
{
    strings:
        $a = "three"
    condition:
        all of them
}
