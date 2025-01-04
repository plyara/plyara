rule test
{
    strings:
        $xbug = "CatalogChangeListener-##-##" xor(0x01-0xff)
    condition:
        $xbug
}
