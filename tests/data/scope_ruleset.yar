// This ruleset is used for unit tests - Modification will require test updates

global rule GlobalScope
{
    condition: false
}

private rule PrivateScope
{
    condition: false
}

global private rule PrivateGlobalScope
{
    condition: false
}
