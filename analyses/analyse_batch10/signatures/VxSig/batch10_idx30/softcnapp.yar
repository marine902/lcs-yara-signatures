rule softcnapp_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         33c085c974
         // 00452fd4: xor eax, eax
         // 00452fd6: test ecx, ecx
         // 00452fd8: jz 0x452fea
      [-]83e80274
         // 0050b309: sub eax, 0x2
         // 0050b30c: jz 0x50b312
      [-]6a006a00
         // 004608e8: push 0x0
         // 004608ea: push 0x0
      [-]6a006a00e8
         // 004608ee: push 0x0
         // 004608f0: push 0x0
         // 004608f2: call __beginthreadex
      [-]83c41885c07405
         // 004608f7: add esp, 0x18
         // 004608fa: test eax, eax
         // 004608fc: jz 0x460903
      [-]83f8ff7502
         // 004608fe: cmp eax, 0xffffffffffffffff
         // 00460901: jnz 0x460905
      [-]83c404c707????????
         // 0051789d: add esp, 0x4
         // 005178a0: mov ds:[edi], 0x0
      [-]010083c4
         // 005283ea: add esp, 0xc
      [-]5733ff397e
         // 0046aa76: push edi
         // 0046aa77: xor edi, edi
         // 0046aa79: cmp ds:[esi+0x40], edi
      [-]83c404c746
         // 0046aab4: add esp, 0x4
         // 0046aab7: mov ds:[esi+0x3c], 0x0
      [-]0fb60650e8
         // 0046ac4e: movzx eax, b1 ds:[esi]
         // 0046ac51: push eax
         // 0046ac52: call _isdigit
      [-]83c40485c074
         // 0046ac57: add esp, 0x4
         // 0046ac5a: test eax, eax
         // 0046ac5c: jz 0x46aca6
      [-]83c40485c074
         // 00523d7a: add esp, 0x4
         // 00523d7d: test eax, eax
         // 00523d7f: jz 0x523db8
      [-]83c40485c074
         // 00523d8b: add esp, 0x4
         // 00523d8e: test eax, eax
         // 00523d90: jz 0x523db8
      [-]807e032075
         // 0046ac80: cmp b1 ds:[esi+0x3], b1 0x20
         // 0046ac84: jnz 0x46aca6
      [-]6a0a6a0056e8
         // 0046ac86: push 0xa
         // 0046ac88: push 0x0
         // 0046ac8a: push esi
         // 0046ac8b: call _strtol
      [-]83c4108901
         // 0046ac9a: add esp, 0x10
         // 0046ac9d: mov ds:[ecx], eax
      [-]83c40885c074
         // 005252fc: add esp, 0x8
         // 005252ff: test eax, eax
         // 00525301: jz 0x525307
      [-]5f5e5dc3
         // 0046b905: pop edi
         // 0046b906: pop esi
         // 0046b907: pop ebp
         // 0046b908: retn 
      [-]6a0d6a01
         // 00540623: push 0xd
         // 00540625: push 0x1
      [-]6a0e6a01
         // 00460c03: push 0xe
         // 00460c05: push 0x1
      [-]00008bd083c4
         // 00526890: mov edx, eax
         // 00526892: add esp, 0xc
      [-]85d20f85
         // 00526895: test edx, edx
         // 00526897: jnz 0x526978
      [-]00008bd083c4
         // 004619a6: mov edx, eax
         // 004619a8: add esp, 0xc
      [-]ff83c408ba????????8bc2
         // 00436d9f: add esp, 0x8
         // 00436da2: mov edx, 0x43
         // 00436da7: mov eax, edx
      [-]000083c4
         // 0052693c: add esp, 0xc
      [-]83c40c33c0
         // 00477579: add esp, 0xc
         // 0047757c: xor eax, eax
      [-]83c40885c07403
         // 0052ce67: add esp, 0x8
         // 0052ce6a: test eax, eax
         // 0052ce6c: jz 0x52ce71

  }
  condition:
    all of them
}
