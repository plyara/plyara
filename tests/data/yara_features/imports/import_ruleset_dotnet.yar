// This ruleset is used for unit tests - Modification will require test updates

import "dotnet"

rule dotnet_001
{
    condition:
        dotnet.number_of_streams != 5
}

rule dotnet_002
{
    condition:
        for any i in (0..dotnet.number_of_streams - 1):
            (dotnet.streams[i].name == "#Blop")
}
