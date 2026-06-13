rule salgorea_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         80790800c701
         // 004585d1: cmp b1 ds:[ecx+0x8], b1 0x0
         // 004585d5: mov ds:[ecx], 0x4b8b20
      [-]8bff558becff75086a00ff7104ff15
         // 004585ec: mov edi, edi
         // 004585ee: push ebp
         // 004585ef: mov ebp, esp
         // 004585f1: push ss:[ebp+0x8]
         // 004585f4: push 0x0
         // 004585f6: push ds:[ecx+0x4]
         // 004585f9: call ds:[HeapAlloc]
      [-]5dc20400
         // 004585ff: pop ebp
         // 00458600: retn b2 0x4
      [-]8bff558bec837d0800740e
         // 0041032a: mov edi, edi
         // 0041032c: push ebp
         // 0041032d: mov ebp, esp
         // 0041032f: cmp ss:[ebp+0x8], 0x0
         // 00410333: jz 0x410343
      [-]ff75086a00ff7104ff15
         // 0045860e: push ss:[ebp+0x8]
         // 00458611: push 0x0
         // 00458613: push ds:[ecx+0x4]
         // 00458616: call ds:[HeapFree]
      [-]5dc20400
         // 00410343: pop ebp
         // 00410344: retn b2 0x4
      [-]8bff558bec33c03945087509
         // 00410347: mov edi, edi
         // 00410349: push ebp
         // 0041034a: mov ebp, esp
         // 0041034c: xor eax, eax
         // 0041034e: cmp ss:[ebp+0x8], eax
         // 00410351: jnz 0x41035c
      [-]ff750c8b01ff10eb21
         // 00410353: push ss:[ebp+0xc]
         // 00410356: mov eax, ds:[ecx]
         // 00410358: call ds:[eax]
         // 0041035a: jmp 0x41037d
      [-]39450c750c
         // 0041035c: cmp ss:[ebp+0xc], eax
         // 0041035f: jnz 0x41036d
      [-]ff75088b01ff500433c0eb10
         // 00410361: push ss:[ebp+0x8]
         // 00410364: mov eax, ds:[ecx]
         // 00410366: call ds:[eax+0x4]
         // 00410369: xor eax, eax
         // 0041036b: jmp 0x41037d
      [-]ff750cff750850ff7104ff15
         // 00458646: push ss:[ebp+0xc]
         // 00458649: push ss:[ebp+0x8]
         // 0045864c: push eax
         // 0045864d: push ds:[ecx+0x4]
         // 00458650: call ds:[HeapReAlloc]
      [-]5dc20800
         // 0041037d: pop ebp
         // 0041037e: retn b2 0x8
      [-]8bff558becff75086a00ff7104ff15
         // 0045865a: mov edi, edi
         // 0045865c: push ebp
         // 0045865d: mov ebp, esp
         // 0045865f: push ss:[ebp+0x8]
         // 00458662: push 0x0
         // 00458664: push ds:[ecx+0x4]
         // 00458667: call ds:[HeapSize]
      [-]5dc20400
         // 0045866d: pop ebp
         // 0045866e: retn b2 0x4
      [-]8bff558bec568bf1e853fffffff64508017407
         // 00410398: mov edi, edi
         // 0041039a: push ebp
         // 0041039b: mov ebp, esp
         // 0041039d: push esi
         // 0041039e: mov esi, ecx
         // 004103a0: call 0x4102f8
         // 004103a5: test b1 ss:[ebp+0x8], b1 0x1
         // 004103a9: jz 0x4103b2
      [-]8bc65e5dc20400
         // 004103b2: mov eax, esi
         // 004103b4: pop esi
         // 004103b5: pop ebp
         // 004103b6: retn b2 0x4
      [-]558bec8b450cf7651085d27505
         // 004103bb: push ebp
         // 004103bc: mov ebp, esp
         // 004103be: mov eax, ss:[ebp+0xc]
         // 004103c1: mul ss:[ebp+0x10]
         // 004103c4: test edx, edx
         // 004103c6: jnz 0x4103cd
      [-]83f8ff7607
         // 004103c8: cmp eax, 0xffffffffffffffff
         // 004103cb: jbe 0x4103d4
      [-]b8????????5dc3
         // 004103cd: mov eax, 0xffffffff80070216
         // 004103d2: pop ebp
         // 004103d3: retn 
      [-]8b4d088901
         // 004103d4: mov ecx, ss:[ebp+0x8]
         // 004103d7: mov ds:[ecx], eax
      [-]8bff558bec8b49048b015dff6004
         // 004103dd: mov edi, edi
         // 004103df: push ebp
         // 004103e0: mov ebp, esp
         // 004103e2: mov ecx, ds:[ecx+0x4]
         // 004103e5: mov eax, ds:[ecx]
         // 004103e7: pop ebp
         // 004103e8: jmp ds:[eax+0x4]
      [-]33d28d411442f00fc1108d4108c3
         // 004103eb: xor edx, edx
         // 004103ed: lea eax, ds:[ecx+0x14]
         // 004103f0: inc edx
         // 004103f1: lock xadd ds:[eax], edx
         // 004103f5: lea eax, ds:[ecx+0x8]
         // 004103f8: retn 
      [-]558bec8b450c8b4d1083caff2bd03bd17307
         // 00410420: push ebp
         // 00410421: mov ebp, esp
         // 00410423: mov eax, ss:[ebp+0xc]
         // 00410426: mov ecx, ss:[ebp+0x10]
         // 00410429: or edx, 0xffffffffffffffff
         // 0041042c: sub edx, eax
         // 0041042e: cmp edx, ecx
         // 00410430: jnb 0x410439
      [-]b8????????5dc3
         // 00410432: mov eax, 0xffffffff80070216
         // 00410437: pop ebp
         // 00410438: retn 
      [-]03c18b4d088901
         // 00410439: add eax, ecx
         // 0041043b: mov ecx, ss:[ebp+0x8]
         // 0041043e: mov ds:[ecx], eax
      [-]8bff558bec568b750857ff750c83c60883e6f88d450856508bf9e856ffffff83c40c85c07836
         // 00410444: mov edi, edi
         // 00410446: push ebp
         // 00410447: mov ebp, esp
         // 00410449: push esi
         // 0041044a: mov esi, ss:[ebp+0x8]
         // 0041044d: push edi
         // 0041044e: push ss:[ebp+0xc]
         // 00410451: add esi, 0x8
         // 00410454: and esi, 0xfffffffffffffff8
         // 00410457: lea eax, ss:[ebp+0x8]
         // 0041045a: push esi
         // 0041045b: push eax
         // 0041045c: mov edi, ecx
         // 0041045e: call 0x4103b9
         // 00410463: add esp, 0xc
         // 00410466: test eax, eax
         // 00410468: js 0x4104a0
      [-]ff75088d45086a1050e8a6ffffff83c40c85c07821
         // 0041046a: push ss:[ebp+0x8]
         // 0041046d: lea eax, ss:[ebp+0x8]
         // 00410470: push 0x10
         // 00410472: push eax
         // 00410473: call 0x41041e
         // 00410478: add esp, 0xc
         // 0041047b: test eax, eax
         // 0041047d: js 0x4104a0
      [-]8b4f04ff75088b01ff1085c07413
         // 0041047f: mov ecx, ds:[edi+0x4]
         // 00410482: push ss:[ebp+0x8]
         // 00410485: mov eax, ds:[ecx]
         // 00410487: call ds:[eax]
         // 00410489: test eax, eax
         // 0041048b: jz 0x4104a0
      [-]4e836004008938c7400c????????897008eb02
         // 0041048d: dec esi
         // 0041048e: and ds:[eax+0x4], 0x0
         // 00410492: mov ds:[eax], edi
         // 00410494: mov ds:[eax+0xc], 0x1
         // 0041049b: mov ds:[eax+0x8], esi
         // 0041049e: jmp 0x4104a2
      [-]5f5e5dc20800
         // 004104a2: pop edi
         // 004104a3: pop esi
         // 004104a4: pop ebp
         // 004104a5: retn b2 0x8
      [-]8bff558bec568b750c57ff751083c60883e6f88d450c56508bf9e8f2feffff83c40c85c0782d
         // 004104a8: mov edi, edi
         // 004104aa: push ebp
         // 004104ab: mov ebp, esp
         // 004104ad: push esi
         // 004104ae: mov esi, ss:[ebp+0xc]
         // 004104b1: push edi
         // 004104b2: push ss:[ebp+0x10]
         // 004104b5: add esi, 0x8
         // 004104b8: and esi, 0xfffffffffffffff8
         // 004104bb: lea eax, ss:[ebp+0xc]
         // 004104be: push esi
         // 004104bf: push eax
         // 004104c0: mov edi, ecx
         // 004104c2: call 0x4103b9
         // 004104c7: add esp, 0xc
         // 004104ca: test eax, eax
         // 004104cc: js 0x4104fb
      [-]ff750c8d450c6a1050e842ffffff83c40c85c07818
         // 004104ce: push ss:[ebp+0xc]
         // 004104d1: lea eax, ss:[ebp+0xc]
         // 004104d4: push 0x10
         // 004104d6: push eax
         // 004104d7: call 0x41041e
         // 004104dc: add esp, 0xc
         // 004104df: test eax, eax
         // 004104e1: js 0x4104fb
      [-]ff750c8b4f04ff75088b01ff500885c07406
         // 004104e3: push ss:[ebp+0xc]
         // 004104e6: mov ecx, ds:[edi+0x4]
         // 004104e9: push ss:[ebp+0x8]
         // 004104ec: mov eax, ds:[ecx]
         // 004104ee: call ds:[eax+0x8]
         // 004104f1: test eax, eax
         // 004104f3: jz 0x4104fb
      [-]4e897008eb02
         // 004104f5: dec esi
         // 004104f6: mov ds:[eax+0x8], esi
         // 004104f9: jmp 0x4104fd
      [-]5f5e5dc20c00
         // 004104fd: pop edi
         // 004104fe: pop esi
         // 004104ff: pop ebp
         // 00410500: retn b2 0xc
      [-]8bff558bec56ff75088bf1e8
         // 0041eb91: mov edi, edi
         // 0041eb93: push ebp
         // 0041eb94: mov ebp, esp
         // 0041eb96: push esi
         // 0041eb97: push ss:[ebp+0x8]
         // 0041eb9a: mov esi, ecx
         // 0041eb9c: call ??0exception@std@@QAE@ABV01@@Z
      [-]8bc65e5dc20400
         // 0041eba7: mov eax, esi
         // 0041eba9: pop esi
         // 0041ebaa: pop ebp
         // 0041ebab: retn b2 0x4
      [-]8bff558bec56ff75088bf1e8
         // 0041ebde: mov edi, edi
         // 0041ebe0: push ebp
         // 0041ebe1: mov ebp, esp
         // 0041ebe3: push esi
         // 0041ebe4: push ss:[ebp+0x8]
         // 0041ebe7: mov esi, ecx
         // 0041ebe9: call ??0exception@std@@QAE@ABV01@@Z
      [-]008bc65e5dc20400
         // 0041ebf4: mov eax, esi
         // 0041ebf6: pop esi
         // 0041ebf7: pop ebp
         // 0041ebf8: retn b2 0x4
      [-]8bff558bec56ff75088bf1e8
         // 0042041e: mov edi, edi
         // 00420420: push ebp
         // 00420421: mov ebp, esp
         // 00420423: push esi
         // 00420424: push ss:[ebp+0x8]
         // 00420427: mov esi, ecx
         // 00420429: call ??0exception@std@@QAE@ABV01@@Z
      [-]008bc65e5dc20400
         // 00420434: mov eax, esi
         // 00420436: pop esi
         // 00420437: pop ebp
         // 00420438: retn b2 0x4
      [-]8b5424088d420c8b4a
         // 00422ee0: mov edx, ss:[esp+0x8]
         // 00422ee4: lea eax, ds:[edx+0xc]
         // 00422ee7: mov ecx, ds:[edx+0xffffffffffffffd4]

  }
  condition:
    all of them
}
