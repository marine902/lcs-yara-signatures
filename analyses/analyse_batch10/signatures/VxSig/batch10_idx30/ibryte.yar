rule ibryte_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8bc18360040083600800c700
         // 00471b82: mov eax, ecx
         // 00471b84: and ds:[eax+0x4], 0x0
         // 00471b88: and ds:[eax+0x8], 0x0
         // 00471b8c: mov ds:[eax], ??_7exception@std@@6B@
      [-]8bff558bec568bf1e8
         // 00420329: mov edi, edi
         // 0042032b: push ebp
         // 0042032c: mov ebp, esp
         // 0042032e: push esi
         // 0042032f: mov esi, ecx
         // 00420331: call 0x420240
      [-]fffffff64508017407
         // 00420336: test b1 ss:[ebp+0x8], b1 0x1
         // 0042033a: jz 0x420343
      [-]8bc65e5dc20400
         // 00420343: mov eax, esi
         // 00420345: pop esi
         // 00420346: pop ebp
         // 00420347: retn b2 0x4
      [-]8bff56b8
         // 0044f0fc: mov edi, edi
         // 0044f0fe: push esi
         // 0044f0ff: mov eax, 0x471f28
      [-]578bf83bc6730f
         // 0044f109: push edi
         // 0044f10a: mov edi, eax
         // 0044f10c: cmp eax, esi
         // 0044f10e: jnb 0x44f11f
      [-]8b0785c07402
         // 0042ff4c: mov eax, ds:[edi]
         // 0042ff4e: test eax, eax
         // 0042ff50: jz 0x42ff54
      [-]83c7043bfe72f1
         // 0042ff54: add edi, 0x4
         // 0042ff57: cmp edi, esi
         // 0042ff59: jb 0x42ff4c
      [-]8bff56b8
         // 0044f122: mov edi, edi
         // 0044f124: push esi
         // 0044f125: mov eax, 0x471f30
      [-]578bf83bc6730f
         // 0044f12f: push edi
         // 0044f130: mov edi, eax
         // 0044f132: cmp eax, esi
         // 0044f134: jnb 0x44f145
      [-]8b0785c07402
         // 0042ff72: mov eax, ds:[edi]
         // 0042ff74: test eax, eax
         // 0042ff76: jz 0x42ff7a
      [-]83c7043bfe72f1
         // 0042ff7a: add edi, 0x4
         // 0042ff7d: cmp edi, esi
         // 0042ff7f: jb 0x42ff72
      [-]8bff558bec8b45085633f63bc6751d
         // 0043d7e8: mov edi, edi
         // 0043d7ea: push ebp
         // 0043d7eb: mov ebp, esp
         // 0043d7ed: mov eax, ss:[ebp+0x8]
         // 0043d7f0: push esi
         // 0043d7f1: xor esi, esi
         // 0043d7f3: cmp eax, esi
         // 0043d7f5: jnz 0x43d814
      [-]5656565656c700????????e8
         // 00453b85: push esi
         // 00453b86: push esi
         // 00453b87: push esi
         // 00453b88: push esi
         // 00453b89: push esi
         // 00453b8a: mov ds:[eax], 0x16
         // 00453b90: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 00453b95: add esp, 0x14
         // 00453b98: push 0x16
         // 00453b9a: pop eax
         // 00453b9b: jmp 0x453ba7
      [-]890833c0
         // 00453ba3: mov ds:[eax], ecx
         // 00453ba5: xor eax, eax
      [-]8bff558bec8b45085633f63bc6751d
         // 0043d821: mov edi, edi
         // 0043d823: push ebp
         // 0043d824: mov ebp, esp
         // 0043d826: mov eax, ss:[ebp+0x8]
         // 0043d829: push esi
         // 0043d82a: xor esi, esi
         // 0043d82c: cmp eax, esi
         // 0043d82e: jnz 0x43d84d
      [-]5656565656c700????????e8
         // 00453bbe: push esi
         // 00453bbf: push esi
         // 00453bc0: push esi
         // 00453bc1: push esi
         // 00453bc2: push esi
         // 00453bc3: mov ds:[eax], 0x16
         // 00453bc9: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 00453bce: add esp, 0x14
         // 00453bd1: push 0x16
         // 00453bd3: pop eax
         // 00453bd4: jmp 0x453be0
      [-]890833c0
         // 00453bdc: mov ds:[eax], ecx
         // 00453bde: xor eax, eax
      [-]8bff558bec8b45085633f63bc6751d
         // 0043d85a: mov edi, edi
         // 0043d85c: push ebp
         // 0043d85d: mov ebp, esp
         // 0043d85f: mov eax, ss:[ebp+0x8]
         // 0043d862: push esi
         // 0043d863: xor esi, esi
         // 0043d865: cmp eax, esi
         // 0043d867: jnz 0x43d886
      [-]5656565656c700????????e8
         // 00453bf7: push esi
         // 00453bf8: push esi
         // 00453bf9: push esi
         // 00453bfa: push esi
         // 00453bfb: push esi
         // 00453bfc: mov ds:[eax], 0x16
         // 00453c02: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 00453c07: add esp, 0x14
         // 00453c0a: push 0x16
         // 00453c0c: pop eax
         // 00453c0d: jmp 0x453c19
      [-]890833c0
         // 00453c15: mov ds:[eax], ecx
         // 00453c17: xor eax, eax

  }
  condition:
    all of them
}
