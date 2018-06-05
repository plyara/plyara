// This ruleset is used for unit tests - Modification will require test updates

import "androguard"

rule androguard_001
{
    condition:
        androguard.package_name(/videogame/)
}

rule androguard_002
{
    condition:
        androguard.activity(/\.sms\./) or
        androguard.activity("com.package.name.sendSMS")
}
