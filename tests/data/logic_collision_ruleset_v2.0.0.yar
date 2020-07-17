// This ruleset is used for unit tests - Modification will require test updates

rule Set001_Rule001
{
    strings:
        $a = "foobar"

    condition:
        $a
}

rule Set001_Rule002
{
    strings:
        $b = "foobar"

    condition:
        $b
}

rule Set001_Rule003
{
    strings:
        $aaa = "foobar"

    condition:
        $*
}

rule Set001_Rule004
{
    strings:
        $ = "foobar"

    condition:
        $*
}


rule Set002_Rule001
{
    strings:
        $b = "foo"
        $a = "bar"

    condition:
        all of them
}

rule Set002_Rule002
{
    strings:
        $b = "bar"
        $a = "foo"

    condition:
        all of $*
}

rule Set002_Rule003
{
    strings:
        $ = "bar"
        $ = "foo"

    condition:
        all of $*
}

rule Set002_Rule004
{
    strings:
        $ = "bar"
        $ = "foo"

    condition:
        all of them
}
