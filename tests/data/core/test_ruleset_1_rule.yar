// This ruleset is used for unit tests - Modification will require test updates

rule rule_one
{
    strings:
        $a = "one"
    condition:
        all of them
}
