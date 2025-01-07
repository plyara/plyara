// This ruleset is used for unit tests - Modification will require test updates

import "math"

rule math_001
{
    condition:
        uint16(0) == 0x5A4D and math.entropy(0, filesize) > 7.0
}
