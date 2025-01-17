rule test1
{
    strings:
        $op = { ABABABABABAB      // bytestringinternal1
                CDCDCDCDCDCD      
                EFEFEFEFEFEF      // bytestringinternal2
                A1A1A1A1A1A1      /* bytestringinternal3a
                                     bytestringinternal3b
                                     bytestringinternal3c */
                B1B1B1B1B1B1      // bytestringinternal4
                C1C1C1C1C1C1
                D1D1D1D1D1D1      /* bytestringinternal5a
                                     bytestringinternal5b */
                ~EF }
    condition:
        $op
}
