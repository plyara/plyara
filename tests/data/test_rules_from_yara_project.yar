/*
Copyright (c) 2016. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// This file of YARA rules is derived from
// https://raw.githubusercontent.com/VirusTotal/yara/master/tests/test-rules.c
// License left intact
// Rules that test for errors in rule syntax are removed


// Boolean operators
rule test { condition: true }

rule test { condition: true or false }

rule test { condition: true and true }

rule test { condition: 0x1 and 0x2}

rule test { condition: false }

rule test { condition: true and false }

rule test { condition: false or false }


// Comparison operators
rule test { condition: 2 > 1 }

rule test { condition: 1 < 2 }

rule test { condition: 2 >= 1 }

rule test { condition: 1 <= 1 }

rule test { condition: 1 == 1 }

rule test { condition: 1.5 == 1.5}

rule test { condition: 1.0 == 1}

rule test { condition: 1.5 >= 1.0}

rule test { condition: 1.0 != 1.000000000000001 }

rule test { condition: 1.0 < 1.000000000000001 }

rule test { condition: 1.0 >= 1.000000000000001 }

rule test { condition: 1.000000000000001 > 1 }

rule test { condition: 1.000000000000001 <= 1 }

rule test { condition: 1.0 == 1.0000000000000001 }

rule test { condition: 1.0 >= 1.0000000000000001 }

rule test { condition: 1.5 >= 1}

rule test { condition: 1.0 >= 1}

rule test { condition: 0.5 < 1}

rule test { condition: 0.5 <= 1}

rule test { condition: 1.0 <= 1}

rule test { condition: "abc" == "abc"}

rule test { condition: "abc" <= "abc"}

rule test { condition: "abc" >= "abc"}

rule test { condition: "ab" < "abc"}

rule test { condition: "abc" > "ab"}

rule test { condition: "abc" < "abd"}

rule test { condition: "abd" > "abc"}

rule test { condition: 1 != 1}

rule test { condition: 1 != 1.0}

rule test { condition: 2 > 3}

rule test { condition: 2.1 < 2}

rule test { condition: "abc" != "abc"}

rule test { condition: "abc" > "abc"}

rule test { condition: "abc" < "abc"}


// Arithmetic operators
rule test { condition: (1 + 1) * 2 == (9 - 1) \\ 2 }

rule test { condition: 5 % 2 == 1 }

rule test { condition: 1.5 + 1.5 == 3}

rule test { condition: 3 \\ 2 == 1}

rule test { condition: 3.0 \\ 2 == 1.5}

rule test { condition: 1 + -1 == 0}

rule test { condition: -1 + -1 == -2}

rule test { condition: 4 --2 * 2 == 8}

rule test { condition: -1.0 * 1 == -1.0}

rule test { condition: 1-1 == 0}

rule test { condition: -2.0-3.0 == -5}

rule test { condition: --1 == 1}

rule test { condition: 1--1 == 2}

rule test { condition: 2 * -2 == -4}

rule test { condition: -4 * 2 == -8}

rule test { condition: -4 * -4 == 16}

rule test { condition: -0x01 == -1}

rule test { condition: 0o10 == 8 }

rule test { condition: 0o100 == 64 }

rule test { condition: 0o755 == 493 }


// Bitwise operators
rule test { condition: 0x55 | 0xAA == 0xFF }

rule test { condition: ~0xAA ^ 0x5A & 0xFF == (~0xAA) ^ (0x5A & 0xFF) }

rule test { condition: ~0x55 & 0xFF == 0xAA }

rule test { condition: 8 >> 2 == 2 }

rule test { condition: 1 << 3 == 8 }

rule test { condition: 1 << 64 == 0 }

rule test { condition: 1 >> 64 == 0 }

rule test { condition: 1 | 3 ^ 3 == 1 | (3 ^ 3) }

rule test { condition: ~0xAA ^ 0x5A & 0xFF == 0x0F }

rule test { condition: 1 | 3 ^ 3 == (1 | 3) ^ 3}


// Anonymous strings
rule test { strings: $ = "a" $ = "b" condition: all of them }


// Strings
rule test { strings: $a = "a" condition: $a }

rule test { strings: $a = "ab" condition: $a }

rule test { strings: $a = "abc" condition: $a }

rule test { strings: $a = "xyz" condition: $a }

rule test { strings: $a = "abc" nocase fullword condition: $a }

rule test { strings: $a = "aBc" nocase  condition: $a }

rule test { strings: $a = "abc" fullword condition: $a }

rule test { strings: $a = "a" fullword condition: $a }

rule test { strings: $a = "ab" fullword condition: $a }

rule test { strings: $a = "abc" wide fullword condition: $a }

rule test { strings: $a = "a" wide condition: $a }

rule test { strings: $a = "a" wide ascii condition: $a }

rule test { strings: $a = "ab" wide condition: $a }

rule test { strings: $a = "ab" wide ascii condition: $a }

rule test { strings: $a = "abc" wide condition: $a }

rule test { strings: $a = "abc" wide nocase fullword condition: $a }

rule test { strings: $a = "aBc" wide nocase condition: $a }

rule test { strings: $a = "aBc" wide ascii nocase condition: $a }

rule test { strings: $a = "---xyz" wide nocase condition: $a }

rule test { strings: $a = "abc" fullword condition: $a }

rule test { strings: $a = "abc" fullword condition: $a }

rule test { strings: $a = "abc" fullword condition: $a }

rule test { strings: $a = "abc" fullword condition: $a }

rule test { strings: $a = "abc" wide condition: $a }

rule test { strings: $a = "abcdef" wide condition: $a }

rule test { strings: $a = "abc" ascii wide fullword condition: $a }

rule test { strings: $a = "abc" ascii wide fullword condition: $a }

rule test { strings: $a = "abc" wide fullword condition: $a }

rule test { strings: $a = "abc" wide fullword condition: $a }

rule test { strings: $a = "ab" wide fullword condition: $a }

rule test { strings: $a = "abc" wide fullword condition: $a }

rule test { strings: $a = "abc" wide fullword condition: $a }

rule test {
         strings:
             $a = "abcdef"
             $b = "cdef"
             $c = "ef"
         condition:
             all of them
       }

rule test {
      strings:
        $a = "This program cannot" xor
      condition:
        #a == 255
    }

rule test {
      strings:
        $a = "This program cannot" xor ascii
      condition:
        #a == 256
    }

rule test {
      strings:
        $a = "This program cannot" xor wide
      condition:
        #a == 256
    }

rule test {
      strings:
        $a = "ab" xor fullword
      condition:
        #a == 1084
    }


// Wildcard strings
rule test {
         strings:
             $s1 = "abc"
             $s2 = "xyz"
         condition:
             for all of ($*) : ($)
      }


// Hex strings
rule test {
        strings: $a = { 64 01 00 00 60 01 }
        condition: $a }

rule test {
        strings: $a = { 64 0? 00 00 ?0 01 }
        condition: $a }

rule test {
        strings: $a = { 6? 01 00 00 60 0? }
        condition: $a }

rule test {
        strings: $a = { 64 01 [1-3] 60 01 }
        condition: $a }

rule test {
        strings: $a = { 64 01 [1-3] (60|61) 01 }
        condition: $a }

rule test {
        strings: $a = { 4D 5A [-] 6A 2A [-] 58 C3}
        condition: $a }

rule test {
        strings: $a = { 4D 5A [300-] 6A 2A [-] 58 C3}
        condition: $a }

rule test {
        strings: $a = { 2e 7? (65 | ?? ) 78 }
        condition: $a }

rule test {
        strings: $a = { 4D 5A [0-300] 6A 2A }
        condition: $a }

rule test {
        strings: $a = { 4D 5A [0-128] 45 [0-128] 01 [0-128]  C3 }
        condition: $a }

rule test {
        strings: $a = { 31 32 [-] 38 39 }
        condition: $a }

rule test {
        strings: $a = { 31 32 [-] // Inline comment
          38 39 }
        condition: $a }

rule test {
        strings: $a = { 31 32 /* Inline comment */ [-] 38 39 }
        condition: $a }

rule test {
        strings: $a = { 31 32 /* Inline multi-line
                                 comment */ [-] 38 39 }
        condition: $a }

rule test {
        strings: $a = {
         31 32 [-] 38 39
     }
        condition: $a }

rule test {
        strings: $a = { 31 32 [-] 33 34 [-] 38 39 }
        condition: $a }

rule test {
        strings: $a = { 31 32 [1] 34 35 [2] 38 39 }
        condition: $a }

rule test {
         strings: $a = { 31 32 [1-] 34 35 [1-] 38 39 }
         condition: $a }

rule test {
        strings: $a = { 31 32 [0-3] 34 35 [1-] 38 39 }
        condition: $a }

rule test {
        strings: $a = { 31 32 [0-2] 35 [1-] 37 38 39 }
        condition: $a }

rule test {
        strings: $a = { 31 32 [0-1] 33 }
        condition: !a == 3}

rule test {
        strings: $a = { 31 32 [0-1] 34 }
        condition: !a == 4}

rule test {
        strings: $a = { 31 32 [0-2] 34 }
        condition: !a == 4 }

rule test {
        strings: $a = { 31 32 [-] 38 39 }
        condition: all of them }

rule test {
        strings: $a = { 31 32 [-] 32 33 }
        condition: $a }

rule test {
        strings: $a = { 35 36 [-] 31 32 }
        condition: $a }

rule test {
        strings: $a = { 31 32 [2-] 34 35 }
        condition: $a }

rule test {
        strings: $a = { 31 32 [0-1] 33 34 [0-2] 36 37 }
        condition: $a }

rule test {
        strings: $a = { 31 32 [0-1] 34 35 [0-2] 36 37 }
        condition: $a }

rule test {
        strings: $a = { 31 32 [0-3] 37 38 }
        condition: $a }

rule test {
        strings: $a = { 31 32 [1] 33 34 }
        condition: $a }

rule test {
        strings: $a = {31 32 [3-6] 32}
        condition: !a == 6 }

rule test {
        strings: $a = {31 [0-3] (32|33)}
        condition: !a == 2 }


// Test count
rule test { strings: $a = "ssi" condition: #a == 2 }


// Test at
rule test {
        strings: $a = "ssi"
        condition: $a at 2 and $a at 5 }

rule test {
        strings: $a = "mis"
        condition: $a at ~0xFF & 0xFF }

rule test {
        strings: $a = { 00 00 00 00 ?? 74 65 78 74 }
        condition: $a at 308}


// Test in
rule test {
        strings: $a = { 6a 2a 58 c3 }
        condition: $a in (entrypoint .. entrypoint + 1) }


// Test offset
rule test { strings: $a = "ssi" condition: @a == 2 }

rule test { strings: $a = "ssi" condition: @a == @a[1] }

rule test { strings: $a = "ssi" condition: @a[2] == 5 }


// Test length
rule test { strings: $a = /m.*?ssi/ condition: !a == 5 }

rule test { strings: $a = /m.*?ssi/ condition: !a[1] == 5 }

rule test { strings: $a = /m.*ssi/ condition: !a == 8 }

rule test { strings: $a = /m.*ssi/ condition: !a[1] == 8 }

rule test { strings: $a = /ssi.*ppi/ condition: !a[1] == 9 }

rule test { strings: $a = /ssi.*ppi/ condition: !a[2] == 6 }

rule test { strings: $a = { 6D [1-3] 73 73 69 } condition: !a == 5}

rule test { strings: $a = { 6D [-] 73 73 69 } condition: !a == 5}

rule test { strings: $a = { 6D [-] 70 70 69 } condition: !a == 11}

rule test { strings: $a = { 6D 69 73 73 [-] 70 69 } condition: !a == 11}


// Test of
rule test { strings: $a = "ssi" $b = "mis" $c = "oops"
      condition: any of them }

rule test { strings: $a = "ssi" $b = "mis" $c = "oops"
      condition: 1 of them }

rule test { strings: $a = "ssi" $b = "mis" $c = "oops"
      condition: 2 of them }

rule test { strings: $a1 = "dummy1" $b1 = "dummy1" $b2 = "ssi"
      condition: any of ($a*, $b*) }

rule test {
         strings:
           $ = /abc/
           $ = /def/
           $ = /ghi/
         condition:
           for any of ($*) : ( for any i in (1..#): (uint8(@[i] - 1) == 0x00) )
       }

rule test {
        strings:
          $a = "ssi"
          $b = "mis"
          $c = "oops"
        condition:
          all of them
      }


// Test for
rule test {
        strings:
          $a = "ssi"
        condition:
          for all i in (1..#a) : (@a[i] >= 2 and @a[i] <= 5)
      }

rule test {
        strings:
          $a = "ssi"
          $b = "mi"
        condition:
          for all i in (1..#a) : ( for all j in (1..#b) : (@a[i] >= @b[j]))
      }

rule test {
        strings:
          $a = "ssi"
        condition:
          for all i in (1..#a) : (@a[i] == 5)
      }


// Test re
rule test { strings: $a = /ssi/ condition: $a }

rule test { strings: $a = /ssi(s|p)/ condition: $a }

rule test { strings: $a = /ssim*/ condition: $a }

rule test { strings: $a = /ssa?/ condition: $a }

rule test { strings: $a = /Miss/ nocase condition: $a }

rule test { strings: $a = /(M|N)iss/ nocase condition: $a }

rule test { strings: $a = /[M-N]iss/ nocase condition: $a }

rule test { strings: $a = /(Mi|ssi)ssippi/ nocase condition: $a }

rule test { strings: $a = /ppi\\tmi/ condition: $a }

rule test { strings: $a = /ppi\\.mi/ condition: $a }

rule test { strings: $a = /^mississippi/ fullword condition: $a }

rule test { strings: $a = /mississippi.*mississippi$/s condition: $a }

rule test { strings: $a = /^ssi/ condition: $a }

rule test { strings: $a = /ssi$/ condition: $a }

rule test { strings: $a = /ssissi/ fullword condition: $a }

rule test { strings: $a = /^[isp]+/ condition: $a }

rule test { strings: $a = /a.{1,2}b/ wide condition: !a == 6 }

rule test { strings: $a = /a.{1,2}b/ wide condition: !a == 8 }

rule test { strings: $a = /\\babc/ wide condition: $a }

rule test { strings: $a = /\\babc/ wide condition: $a }

rule test { strings: $a = /\\babc/ wide condition: $a }

rule test { strings: $a = /\\babc/ wide condition: $a }

rule test { strings: $a = /\\babc/ wide condition: $a }

rule test { strings: $a = /abc\\b/ wide condition: $a }

rule test { strings: $a = /abc\\b/ wide condition: $a }

rule test { strings: $a = /abc\\b/ wide condition: $a }

rule test { strings: $a = /abc\\b/ wide condition: $a }

rule test { strings: $a = /abc\\b/ wide condition: $a }

rule test { strings: $a = /\\b/ wide condition: $a }

rule test {
        strings: $a = /MZ.{300,}t/
        condition: !a == 317 }

rule test {
        strings: $a = /MZ.{300,}?t/
        condition: !a == 314 }

rule test { strings: $a = /abc[^d]/ nocase condition: $a }

rule test { strings: $a = /abc[^d]/ condition: $a }

rule test { strings: $a = /abc[^D]/ nocase condition: $a }

rule test { strings: $a = /abc[^D]/ condition: $a }

rule test { strings: $a = /abc[^f]/ nocase condition: $a }

rule test { strings: $a = /abc[^f]/ condition: $a }

rule test { strings: $a = /abc[^F]/ nocase condition: $a }

rule test { strings: $a = /abc[^F]/ condition: $a }

rule test { strings: $a = " cmd.exe " nocase wide condition: $a }


// Test entry point
rule test {
        strings: $a = { 6a 2a 58 c3 }
        condition: $a at entrypoint }

rule test {
        strings: $a = { b8 01 00 00 00 bb 2a }
        condition: $a at entrypoint }

rule test {
        strings: $a = { b8 01 00 00 00 bb 2a }
        condition: $a at entrypoint }

rule test { condition: entrypoint >= 0 }


// Test file size
rule test { condition: filesize == %zd }


// Test comments
rule test {
         condition:
             //  this is a comment
             /*** this is a comment ***/
             /* /* /*
                 this is a comment
             */
             true
      }


// Test matches operator
rule test { condition: "foo" matches /foo/ }

rule test { condition: "foo" matches /bar/ }

rule test { condition: "FoO" matches /fOo/i }

rule test { condition: "xxFoOxx" matches /fOo/i }

rule test { condition: "xxFoOxx" matches /^fOo/i }

rule test { condition: "xxFoOxx" matches /fOo$/i }

rule test { condition: "foo" matches /^foo$/i }

rule test { condition: "foo\\nbar" matches /foo.*bar/s }

rule test { condition: "foo\\nbar" matches /foo.*bar/ }


// Test global rules
global private rule global_rule {
        condition:
          true
      }
      rule test {
        condition: true
      }

global private rule global_rule {
        condition:
          false
      }
      rule test {
        condition: true
      }


// Test modules
import "tests"
       rule test {
        condition: tests.constants.one + 1 == tests.constants.two
      }

import "tests"
       rule test {
        condition: tests.constants.foo == "foo"
      }

import "tests"
       rule test {
        condition: tests.constants.empty == ""
      }

import "tests"
       rule test {
        condition: tests.empty() == ""
      }

import "tests"
       rule test {
        condition: tests.struct_array[1].i == 1
      }

import "tests"
       rule test {
        condition: tests.struct_array[0].i == 1 or true
      }

import "tests"
       rule test {
        condition: tests.integer_array[0] == 0
      }

import "tests"
       rule test {
        condition: tests.integer_array[1] == 1
      }

import "tests"
       rule test {
        condition: tests.integer_array[256] == 256
      }

import "tests"
       rule test {
        condition: tests.string_array[0] == "foo"
      }

import "tests"
       rule test {
        condition: tests.string_array[2] == "baz"
      }

import "tests"
       rule test {
        condition: tests.string_dict["foo"] == "foo"
      }

import "tests"
       rule test {
        condition: tests.string_dict["bar"] == "bar"
      }

import "tests"
       rule test {
        condition: tests.isum(1,2) == 3
      }

import "tests"
       rule test {
        condition: tests.isum(1,2,3) == 6
      }

import "tests"
       rule test {
        condition: tests.fsum(1.0,2.0) == 3.0
      }

import "tests"
       rule test {
        condition: tests.fsum(1.0,2.0,3.0) == 6.0
      }

import "tests"
       rule test {
        condition: tests.foobar(1) == tests.foobar(1)
      }

import "tests"
       rule test {
        condition: tests.foobar(1) != tests.foobar(2)
      }

import "tests"
       rule test {
        condition: tests.length("dummy") == 5
      }

import "tests"
      rule test { condition: tests.struct_array[0].i == 1
      }

import "tests"
      rule test { condition: tests.isum(1,1) == 3
      }

import "tests"
      rule test { condition: tests.fsum(1.0,1.0) == 3.0
      }

import "tests"
      rule test { condition: tests.match(/foo/,"foo") == 3
      }

import "tests"
      rule test { condition: tests.match(/foo/,"bar") == -1
      }

import "tests"
      rule test { condition: tests.match(/foo.bar/i,"FOO\\nBAR") == -1
      }

import "tests"
      rule test { condition: tests.match(/foo.bar/is,"FOO\\nBAR") == 7
      }


// Test time module
import "time"
        rule test { condition: time.now() > 0 }


// Test hash module
import "hash"
       rule test {
        condition:
          hash.md5(0, filesize) ==
            "ab56b4d92b40713acc5af89985d4b786"
            and
          hash.md5(1, filesize) ==
            "e02cfbe5502b64aa5ae9f2d0d69eaa8d"
            and
          hash.sha1(0, filesize) ==
            "03de6c570bfe24bfc328ccd7ca46b76eadaf4334"
            and
          hash.sha1(1, filesize) ==
            "a302d65ae4d9e768a1538d53605f203fd8e2d6e2"
            and
          hash.sha256(0, filesize) ==
            "36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c"
            and
          hash.sha256(1, filesize) ==
            "aaaaf2863e043b9df604158ad5c16ff1adaf3fd7e9fcea5dcb322b6762b3b59a"
      }

import "hash"
       rule test {
        condition:
          hash.md5(0, filesize) ==
            "ab56b4d92b40713acc5af89985d4b786"
            and
          hash.md5(1, filesize) ==
            "e02cfbe5502b64aa5ae9f2d0d69eaa8d"
            and
          hash.md5(0, filesize) ==
            "ab56b4d92b40713acc5af89985d4b786"
            and
          hash.md5(1, filesize) ==
            "e02cfbe5502b64aa5ae9f2d0d69eaa8d"
      }


// Test integer functions
rule test { condition: uint8(0) == 0xAA}

rule test { condition: uint16(0) == 0xBBAA}

rule test { condition: uint32(0) == 0xDDCCBBAA}

rule test { condition: uint8be(0) == 0xAA}

rule test { condition: uint16be(0) == 0xAABB}

rule test { condition: uint32be(0) == 0xAABBCCDD}


// Test include files
include "tests/data/baz.yar" rule t { condition: baz }

include "tests/data/foo.yar" rule t { condition: foo }


// Test process scan
rule test {
      strings:
        $a = { 48 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21 }
      condition:
        all of them
    }


// Test performance warnings
rule test {
        strings: $a = { 01 }
        condition: $a }

rule test {
        strings: $a = { 01 ?? }
        condition: $a }

rule test {
        strings: $a = { 01 ?? ?? }
        condition: $a }

rule test {
        strings: $a = { 01 ?? ?? 02 }
        condition: $a }

rule test {
        strings: $a = { 01 ?? ?2 03 }
        condition: $a }

rule test {
        strings: $a = { 01 ?? 02 1? }
        condition: $a }

rule test {
        strings: $a = { 1? 2? 3? }
        condition: $a }

rule test {
        strings: $a = { 1? 2? 3? 04 }
        condition: $a }

rule test {
        strings: $a = { 1? ?? 03 }
        condition: $a }

rule test {
        strings: $a = { 00 01 }
        condition: $a }

rule test {
        strings: $a = { 01 00 }
        condition: $a }

rule test {
        strings: $a = { 00 00 }
        condition: $a }

rule test {
        strings: $a = { 00 00 00 }
        condition: $a }

rule test {
        strings: $a = { 00 00 01 }
        condition: $a }

rule test {
        strings: $a = { 00 00 00 00 }
        condition: $a }

rule test {
        strings: $a = { 00 00 00 01 }
        condition: $a }

rule test {
        strings: $a = { FF FF FF FF }
        condition: $a }

rule test {
        strings: $a = { 00 00 01 02 }
        condition: $a }

rule test {
        strings: $a = { 00 01 02 03 }
        condition: $a }

rule test {
        strings: $a = { 01 02 03 04 }
        condition: $a }

rule test {
        strings: $a = { 01 02 03 }
        condition: $a }

rule test {
        strings: $a = { 20 01 02 }
        condition: $a }

rule test {
        strings: $a = { 01 02 }
        condition: $a }

rule test {
        strings: $a = "foo" wide
        condition: $a }

rule test {
        strings: $a = "MZ"
        condition: $a }
