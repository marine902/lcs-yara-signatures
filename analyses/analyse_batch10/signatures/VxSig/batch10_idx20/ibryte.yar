rule ibryte_10_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         00c20400
         // 00403016: retn b2 0x4
      [-]088bf1e8
         // 0040972a: mov esi, ecx
         // 0040972c: call 0x4096ab
      [-]8bc18360040083600800c700
         // 0046b978: mov eax, ecx
         // 0046b97a: and ds:[eax+0x4], 0x0
         // 0046b97e: and ds:[eax+0x8], 0x0
         // 0046b982: mov ds:[eax], ??_7exception@std@@6B@
      [-]8bff558bec568bf1e8
         // 0045f196: mov edi, edi
         // 0045f198: push ebp
         // 0045f199: mov ebp, esp
         // 0045f19b: push esi
         // 0045f19c: mov esi, ecx
         // 0045f19e: call 0x45f12d
      [-]fffffff64508017407
         // 0045f1a3: test b1 ss:[ebp+0x8], b1 0x1
         // 0045f1a7: jz 0x45f1b0
      [-]8bc65e5dc20400
         // 0045f1b0: mov eax, esi
         // 0045f1b2: pop esi
         // 0045f1b3: pop ebp
         // 0045f1b4: retn b2 0x4
      [-]8bff56b8
         // 0047c7b6: mov edi, edi
         // 0047c7b8: push esi
         // 0047c7b9: mov eax, 0x4aff9c
      [-]578bf83bc6730f
         // 0047c7c3: push edi
         // 0047c7c4: mov edi, eax
         // 0047c7c6: cmp eax, esi
         // 0047c7c8: jnb 0x47c7d9
      [-]8b0785c07402
         // 0046fe0a: mov eax, ds:[edi]
         // 0046fe0c: test eax, eax
         // 0046fe0e: jz 0x46fe12
      [-]83c7043bfe72f1
         // 0046fe12: add edi, 0x4
         // 0046fe15: cmp edi, esi
         // 0046fe17: jb 0x46fe0a
      [-]8bff56b8
         // 0047c7dc: mov edi, edi
         // 0047c7de: push esi
         // 0047c7df: mov eax, 0x4affa4
      [-]578bf83bc6730f
         // 0047c7e9: push edi
         // 0047c7ea: mov edi, eax
         // 0047c7ec: cmp eax, esi
         // 0047c7ee: jnb 0x47c7ff
      [-]8b0785c07402
         // 0046fe30: mov eax, ds:[edi]
         // 0046fe32: test eax, eax
         // 0046fe34: jz 0x46fe38
      [-]83c7043bfe72f1
         // 0046fe38: add edi, 0x4
         // 0046fe3b: cmp edi, esi
         // 0046fe3d: jb 0x46fe30
      [-]ffff59c3
         // 0048101d: pop ecx
         // 0048101e: retn 
      [-]8bff558bec8b45085633f63bc6751d
         // 004737e2: mov edi, edi
         // 004737e4: push ebp
         // 004737e5: mov ebp, esp
         // 004737e7: mov eax, ss:[ebp+0x8]
         // 004737ea: push esi
         // 004737eb: xor esi, esi
         // 004737ed: cmp eax, esi
         // 004737ef: jnz 0x47380e
      [-]5656565656c700????????e8
         // 0048454e: push esi
         // 0048454f: push esi
         // 00484550: push esi
         // 00484551: push esi
         // 00484552: push esi
         // 00484553: mov ds:[eax], 0x16
         // 00484559: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 0048455e: add esp, 0x14
         // 00484561: push 0x16
         // 00484563: pop eax
         // 00484564: jmp 0x484570
      [-]890833c0
         // 00480217: mov ds:[eax], ecx
         // 00480219: xor eax, eax
      [-]8bff558bec8b45085633f63bc6751d
         // 0047381b: mov edi, edi
         // 0047381d: push ebp
         // 0047381e: mov ebp, esp
         // 00473820: mov eax, ss:[ebp+0x8]
         // 00473823: push esi
         // 00473824: xor esi, esi
         // 00473826: cmp eax, esi
         // 00473828: jnz 0x473847
      [-]5656565656c700????????e8
         // 00484587: push esi
         // 00484588: push esi
         // 00484589: push esi
         // 0048458a: push esi
         // 0048458b: push esi
         // 0048458c: mov ds:[eax], 0x16
         // 00484592: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 00484597: add esp, 0x14
         // 0048459a: push 0x16
         // 0048459c: pop eax
         // 0048459d: jmp 0x4845a9
      [-]890833c0
         // 00480250: mov ds:[eax], ecx
         // 00480252: xor eax, eax
      [-]8bff558bec8b45085633f63bc6751d
         // 00473854: mov edi, edi
         // 00473856: push ebp
         // 00473857: mov ebp, esp
         // 00473859: mov eax, ss:[ebp+0x8]
         // 0047385c: push esi
         // 0047385d: xor esi, esi
         // 0047385f: cmp eax, esi
         // 00473861: jnz 0x473880
      [-]5656565656c700????????e8
         // 004845c0: push esi
         // 004845c1: push esi
         // 004845c2: push esi
         // 004845c3: push esi
         // 004845c4: push esi
         // 004845c5: mov ds:[eax], 0x16
         // 004845cb: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 004845d0: add esp, 0x14
         // 004845d3: push 0x16
         // 004845d5: pop eax
         // 004845d6: jmp 0x4845e2
      [-]890833c0
         // 00480289: mov ds:[eax], ecx
         // 0048028b: xor eax, eax

  }
  condition:
    all of them
}
