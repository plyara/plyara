// This ruleset is used for unit tests - Modification will require test updates

import "hash"

rule hash_001
{
    condition:
        hash.md5("dummy") == "275876e34cf609db118f3d84b799a790"
}

rule hash_002
{
    condition:
        hash.md5(0, filesize) == "feba6c919e3797e7778e8f2e85fa033d"
}
