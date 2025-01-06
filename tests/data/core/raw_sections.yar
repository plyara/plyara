rule name
{
    meta:
        author = "Malware Utkonos"  // Name
        date = "2025-01-05"
        description = "TESTRULE"
    strings:
        $op = { ABABABABABAB      // Line 1
                CDCDCDCDCDCD }    // Line 2
    condition:
        uint16(0) == 0x5a4d and                     // Foo
        uint32(uint32(0x3c)) == 0x00004550 and      // Bar
        $op                                         // Baz
}
