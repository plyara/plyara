rule testrule {

strings:
    $a = {  79 61 72 /* test */
           61 }

condition:
    all of them
}
