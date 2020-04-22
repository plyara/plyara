// This ruleset is used for unit tests for hashing strings and condition - Modification will require test updates

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

/*
// Although they match identical content as the above two rules,
// the following four rules do not yet return the same hash.

rule Set001_Rule003
{
    strings:
        $aaa = "foobar"

    condition:
        any of ($*)
}

rule Set001_Rule004
{
    strings:
        $ = "foobar"

    condition:
        any of them
}

rule Set001_Rule005
{
    strings:
        $ = "foobar"

    condition:
        all of ($*)
}

rule Set001_Rule006
{
    strings:
        $ = "foobar"

    condition:
            all of them
}

*/

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
        all of ($*)
}

rule Set002_Rule003
{
    strings:
        $ = "bar"
        $ = "foo"

    condition:
        all of ($*)
}

rule Set002_Rule004
{
    strings:
        $ = "bar"
        $ = "foo"

    condition:
        all of them
}
