// This ruleset is used for unit tests - Modification will require test updates

import "cuckoo"

rule cuckoo_001
{
    condition:
        cuckoo.network.http_request(/http:\/\/someone\.doingevil\.com/)
}
