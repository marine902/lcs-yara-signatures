rule symmi
{
    meta:
        family = "symmi"
        time_to_build = "6.23 min"
        nb_strings = "3"
        nb_bounded_gaps = "5"
        nb_hex_bytes = "143"
        t_load = "0.05 sec"
        t_clustering = "14.059 sec"
        t_pair_selection = "13.445 sec"
        t_alignment = "345.993 sec"
        t_filtering = "0.001 sec"
    strings:
        $s0 = { 68 65 6d 61 73 2d 6d 69 63 72 6f 73 6f 66 74 2d 63 6f 6d 3a 61 73 6d 2e 76 31 22 20 78 6d 6c 6e 73 3a 61 73 6d 76 33 3d 22 75 72 6e 3a 73 63 68 65 6d 61 73 2d 6d 69 63 72 6f 73 6f 66 74 2d 63 6f 6d 3a 61 73 6d 2e 76 33 22 3e 0d 0a 20 3c 61 73 73 65 6d 62 6c 79 49 }
        $s1 = { 77 73 53 65 74 74 69 6e 67 73 3e 0d 0a 20 3c 2f 61 73 6d 76 33 3a 61 70 70 6c 69 63 61 74 69 6f 6e 3e 0d 0a [2-4] 73 [3-3] 6c [3-8] 4e }
        $s2 = { 4e 47 58 58 50 41 44 44 49 4e 47 [1-1] 41 44 44 [0-1] 49 4e }

    condition:
        any of them
}