rule test{
    strings:
        $TEST1 = "testy"
        $test2 = "tasty"
    condition:
        ( #TEST1 > 5 ) and ( #test2 > 5 )
}
