global rule name : asdf    // nameline
{   // openbrace
    meta:    // metasection
        author = "Malware Utkonos"  // metakv
        date = "2025-01-05"
        description = "TESTRULE"
    strings:   // stringssection
        $op = { ABABABABABAB      // bytestringinternal1
                CDCDCDCDCDCD      // bytestringinternal2
                ~EF }             // bytestring
    condition:    // conditionsection
        uint16(0) == 0x5a4d and                     // conditioninternal1
        pe.is_pe and                                // conditioninternal2
        uint32(uint32(0x3c)) == 0x00004550 and      // conditioninternal3
        $op                                         // condition
}   // closebrace
