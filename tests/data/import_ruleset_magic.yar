// This ruleset is used for unit tests - Modification will require test updates

import "magic"

rule magic_001
{
    condition:
        magic.type() contains "PDF"
}

rule magic_002
{
    condition:
        magic.mime_type() == "application/pdf"
}
