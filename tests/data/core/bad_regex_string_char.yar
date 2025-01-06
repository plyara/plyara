rule badrexchar
{
    strings:
        $a = /foobar🔥bazfoo/
    condition:
        all of them
}
