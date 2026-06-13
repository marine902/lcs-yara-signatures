rule berbew_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         909090909090
         // 00432001: nop 
         // 00432002: nop 
         // 00432003: nop 
         // 00432018: nop 
         // 00432019: nop 
         // 0043201a: nop 

  }
  condition:
    all of them
}
