import "pe"

rule minimal_test {
    condition:
       True
}

rule minimal_test2 {
    condition:
       True and pe.is_pe
}
