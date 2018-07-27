/*
   License:
    This file contains rules licensed under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html)
    Version 1-20180211, author:unixfreaxjp
*/

private rule is__osx
{
 meta:
    date = "2018-02-12"
    author = "@unixfreaxjp"
 condition:
    uint32(0) == 0xfeedface     or uint32(0) == 0xcafebabe
    or uint32(0) == 0xbebafeca  or uint32(0) == 0xcefaedfe
    or uint32(0) == 0xfeedfacf  or uint32(0) == 0xcffaedfe
}

private rule priv01 {
 meta:
    date = "2018-02-11"
    author = "@unixfreaxjp"
 strings:
    $vara01 = { 73 3A 70 3A 00 }
    $vara02 = "Usage: %s" fullword nocase wide ascii
    $vara03 = "[ -s secret ]" fullword nocase wide ascii
    $vara04 = "[ -p port ]" fullword nocase wide ascii
 condition:
    all of them
}

private rule priv03 {
 meta:
    date = "2018-02-10"
    author = "@unixfreaxjp"
 strings:
    $varb01 = { 41 57 41 56 41 55 41 54 55 53 0F B6 06 }
    $varb02 = { 48 C7 07 00 00 00 00 48 C7 47 08 00 00 }
    $vard01 = { 55 48 89 E5 41 57 41 56 41 55 41 54 53 }
    $vard02 = { 55 48 89 E5 48 C7 47 08 00 00 00 00 48 }
    // can be added
 condition:
    (2 of ($varb*)) or (2 of ($vard*))
}
rule MALW_TinyShell_backconnect_OSX {
 meta:
    date = "2018-02-10"
    author = "@unixfreaxjp"
 condition:
    is__osx
    and priv01
    and priv02
    and priv03
    and priv04
    and filesize < 100KB
}

rule MALW_TinyShell_backconnect_ELF {
 meta:
    date = "2018-02-10"
    author = "@unixfreaxjp"
 condition:
    is__elf
    and priv01
    and ((priv02)
      or ((priv03)
        or (priv04)))
    and filesize < 100KB
}

rule MALW_TinyShell_backconnect_Gen {
 meta:
    date = "2018-02-11"
    author = "@unixfreaxjp"
 condition:
    ((is__elf) or  (is__osx))
    and priv01
    and priv02
    and filesize < 100KB
}

rule MALW_TinyShell_backdoor_Gen {
 meta:
    date = "2018-02-11"
    author = "@unixfreaxjp"
 condition:
    ((is__elf) or  (is__osx))
    and priv01
    and filesize > 20KB
}

rule test_rule_01 {
condition:
    (is__elf)
}

rule test_rule_02 {
condition:
    is__osx and is__elf
}

rule test_rule_03 {
condition:
    is__osx
}

rule test_rule_04 {
condition:
    (is__elf or is__osx)
}
