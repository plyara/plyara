// This ruleset is used for unit tests - Modification will require test updates

import "pe"

rule pe_001
{
    condition:
        pe.number_of_sections == 1
}

rule pe_002
{
    condition:
        pe.exports("CPlApplet")
}

rule pe_003
{
    condition:
        pe.characteristics & pe.DLL
}
