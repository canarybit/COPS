package play

import data.testapi.testdata

default check = false
default check2 = false
check {
         m := input.OperatingSystem
         n := input.Kernel
         pattern := "(Linux (([5-9].(([1-9][5-9])+|([2-9][0-9])))))+|(Linux (([6-9].(([0-9].)))))"
         contains(m,"Ubuntu"); re_match(pattern, n)
     }

check2 {
         m := input.OperatingSystem
         n := input.Kernel
         pattern := "(Linux (([5-9].(([1-9][5-9])+|([2-9][0-9])))))+|(Linux (([6-9].(([0-9].)))))"
         contains(m,"Linux"); re_match(pattern, n)
     }


