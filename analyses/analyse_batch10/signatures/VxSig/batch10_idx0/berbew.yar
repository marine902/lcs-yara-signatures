rule berbew_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         90909090
         // 0043300c: nop 
         // 00433012: nop 
         // 0043301a: nop 
         // 0043301b: nop 

  }
  condition:
    all of them
}
