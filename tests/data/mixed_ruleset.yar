// This ruleset is used for unit tests - Modification will require test updates

rule FirstRule
{
    meta:
        author = "Andrés Iniesta"
        date = "2015-01-01"
    strings:
        $a = "hark, a \"string\" here" fullword ascii
        $b = { 00 22 44 66 88 aa cc ee }
    condition:
        all of them
}
