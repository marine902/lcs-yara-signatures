rule ibryte_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         5dc20400
         // 0044cc0a: pop ebp
         // 0044cc0b: retn b2 0x4
      [-]8bc18360040083600800c700
         // 00461948: mov eax, ecx
         // 0046194a: and ds:[eax+0x4], 0x0
         // 0046194e: and ds:[eax+0x8], 0x0
         // 00461952: mov ds:[eax], ??_7exception@std@@6B@
      [-]8bff558bec568bf1e8
         // 004617cc: mov edi, edi
         // 004617ce: push ebp
         // 004617cf: mov ebp, esp
         // 004617d1: push esi
         // 004617d2: mov esi, ecx
         // 004617d4: call 0x461763
      [-]fffffff64508017407
         // 004617d9: test b1 ss:[ebp+0x8], b1 0x1
         // 004617dd: jz 0x4617e6
      [-]8bc65e5dc20400
         // 004617e6: mov eax, esi
         // 004617e8: pop esi
         // 004617e9: pop ebp
         // 004617ea: retn b2 0x4
      [-]8bff51c701
         // 00461aba: mov edi, edi
         // 00461abc: push ecx
         // 00461abd: mov ds:[ecx], ??_7type_info@@6B@
      [-]8bff558bec568bf1e8e3fffffff64508017407
         // 00461824: mov edi, edi
         // 00461826: push ebp
         // 00461827: mov ebp, esp
         // 00461829: push esi
         // 0046182a: mov esi, ecx
         // 0046182c: call 0x461814
         // 00461831: test b1 ss:[ebp+0x8], b1 0x1
         // 00461835: jz 0x46183e
      [-]8bc65e5dc20400
         // 0046183e: mov eax, esi
         // 00461840: pop esi
         // 00461841: pop ebp
         // 00461842: retn b2 0x4
      [-]8bff56b8
         // 004726d6: mov edi, edi
         // 004726d8: push esi
         // 004726d9: mov eax, 0x4a230c
      [-]00578bf83bc6730f
         // 004726e3: push edi
         // 004726e4: mov edi, eax
         // 004726e6: cmp eax, esi
         // 004726e8: jnb 0x4726f9
      [-]8b0785c07402
         // 0047243a: mov eax, ds:[edi]
         // 0047243c: test eax, eax
         // 0047243e: jz 0x472442
      [-]83c7043bfe72f1
         // 00472442: add edi, 0x4
         // 00472445: cmp edi, esi
         // 00472447: jb 0x47243a
      [-]8bff56b8
         // 004726fc: mov edi, edi
         // 004726fe: push esi
         // 004726ff: mov eax, 0x4a2314
      [-]00578bf83bc6730f
         // 00472709: push edi
         // 0047270a: mov edi, eax
         // 0047270c: cmp eax, esi
         // 0047270e: jnb 0x47271f
      [-]8b0785c07402
         // 00472460: mov eax, ds:[edi]
         // 00472462: test eax, eax
         // 00472464: jz 0x472468
      [-]83c7043bfe72f1
         // 00472468: add edi, 0x4
         // 0047246b: cmp edi, esi
         // 0047246d: jb 0x472460
      [-]8bff558bec8b45085633f63bc6751d
         // 00475e12: mov edi, edi
         // 00475e14: push ebp
         // 00475e15: mov ebp, esp
         // 00475e17: mov eax, ss:[ebp+0x8]
         // 00475e1a: push esi
         // 00475e1b: xor esi, esi
         // 00475e1d: cmp eax, esi
         // 00475e1f: jnz 0x475e3e
      [-]ff5656565656c70016000000e8
         // 004773c6: push esi
         // 004773c7: push esi
         // 004773c8: push esi
         // 004773c9: push esi
         // 004773ca: push esi
         // 004773cb: mov ds:[eax], 0x16
         // 004773d1: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 004773d6: add esp, 0x14
         // 004773d9: push 0x16
         // 004773db: pop eax
         // 004773dc: jmp 0x4773e8
      [-]00890833c0
         // 004760f4: mov ds:[eax], ecx
         // 004760f6: xor eax, eax
      [-]8bff558bec8b45085633f63bc6751d
         // 00475e4b: mov edi, edi
         // 00475e4d: push ebp
         // 00475e4e: mov ebp, esp
         // 00475e50: mov eax, ss:[ebp+0x8]
         // 00475e53: push esi
         // 00475e54: xor esi, esi
         // 00475e56: cmp eax, esi
         // 00475e58: jnz 0x475e77
      [-]ff5656565656c70016000000e8
         // 00469b6e: push esi
         // 00469b6f: push esi
         // 00469b70: push esi
         // 00469b71: push esi
         // 00469b72: push esi
         // 00469b73: mov ds:[eax], 0x16
         // 00469b79: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 00469b7e: add esp, 0x14
         // 00469b81: push 0x16
         // 00469b83: pop eax
         // 00469b84: jmp 0x469b90
      [-]00890833c0
         // 0047612d: mov ds:[eax], ecx
         // 0047612f: xor eax, eax
      [-]8bff558bec8b45085633f63bc6751d
         // 00475e84: mov edi, edi
         // 00475e86: push ebp
         // 00475e87: mov ebp, esp
         // 00475e89: mov eax, ss:[ebp+0x8]
         // 00475e8c: push esi
         // 00475e8d: xor esi, esi
         // 00475e8f: cmp eax, esi
         // 00475e91: jnz 0x475eb0
      [-]ff5656565656c70016000000e8
         // 00477438: push esi
         // 00477439: push esi
         // 0047743a: push esi
         // 0047743b: push esi
         // 0047743c: push esi
         // 0047743d: mov ds:[eax], 0x16
         // 00477443: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 00477448: add esp, 0x14
         // 0047744b: push 0x16
         // 0047744d: pop eax
         // 0047744e: jmp 0x47745a
      [-]00890833c0
         // 00476166: mov ds:[eax], ecx
         // 00476168: xor eax, eax

  }
  condition:
    all of them
}
