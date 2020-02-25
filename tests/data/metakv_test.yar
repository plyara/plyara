import "pe"

rule meta_test
{
    meta:
        author = "Malware Utkonos"
        date = "2020-01-04"
        tlp = "Green"
    strings:
        $op = { 55 8B EC 81 [2] 00 00 00 89 [5] 89 }
    condition:
        pe.exports("initTest") and all of them
}

rule meta_test2
{
    meta:
        author = "Malware Utkonos"
        date = "2020-01-04"
        tlp = "Green"
        author = "Someone else"
    strings:
        $op = { 55 8B EC 81 [2] 00 00 00 89 [5] 89 }
    condition:
        pe.exports("initTest") and all of them
}
