rule test1
{
    strings:
        $op = { ABABABABABAB      // bytestringinternal1
                CDCDCDCDCDCD      // bytestringinternal2
                ~EF }
    condition:
        $op
}
