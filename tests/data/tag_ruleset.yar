// This ruleset is used for unit tests - Modification will require test updates

rule OneTag: tag1
{
    condition: false
}

rule TwoTags : tag1 tag2
{
    condition: false
}

rule ThreeTags : tag1 tag2 tag3
{
    condition: false
}
