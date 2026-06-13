rule berbew_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         9090909090
         // 00432000: nop 
         // 00432001: nop 
         // 00432004: nop 
         // 00432005: nop 
         // 0043200b: nop 

  }
  condition:
    all of them
}
