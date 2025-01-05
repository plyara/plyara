rule FirstRule {
  // test comment
  meta:
    author = "Andrés Iniesta"
    date = "2015-01-01"
  strings:
    $a = "hark, a \"string\" here" fullword ascii
    $b = { 00 22 44 66 88 aa cc ee }
  condition:
    all of them
  }

import "bingo"
import "bango"
rule SecondRule : aTag {
  meta:
    author = "Ivan Rakitić"
    date = "2015-02-01"
  strings:
    /* test
       multiline
       comment
    */
    $x = "hi"
    $y = /state: (on|off)/ wide
    $z = "bye"
  condition:
    for all of them : ( # > 2 )
}

rule ThirdRule {condition: false}

rule ForthRule {
    condition:
        uint8(0) ^ unit8(1) == 0x12
}
