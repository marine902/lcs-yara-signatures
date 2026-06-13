rule salgorea_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec6afe68
         // 00401000: push ebp
         // 00401001: mov ebp, esp
         // 00401003: push 0xfffffffffffffffe
         // 00401005: push stru_4287A8.GSCookieOffset
      [-]64a1????????5083ec
         // 0040100f: mov eax, fs:[0x0]
         // 00401015: push eax
         // 00401016: sub esp, 0x10
      [-]535657a1
         // 00401019: push ebx
         // 0040101a: push esi
         // 0040101b: push edi
         // 0040101c: mov eax, ds:[___security_cookie]
      [-]003145f833c5508d45f064a3????????8965e8
         // 00401021: xor ss:[ebp+0xfffffffffffffff8], eax
         // 00401024: xor eax, ebp
         // 00401026: push eax
         // 00401027: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040102a: mov fs:[0x0], eax
         // 00401030: mov ss:[ebp+0xffffffffffffffe8], esp
      [-]c745fc????????8b
         // 004010a3: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 004010aa: mov eax, ss:[ebp+0xffffffffffffffe4]
      [-]8b4df064890d????????595f5e5b8be55dc3
         // 004010ad: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004010b0: mov fs:[0x0], ecx
         // 004010b7: pop ecx
         // 004010b8: pop edi
         // 004010b9: pop esi
         // 004010ba: pop ebx
         // 004010bb: mov esp, ebp
         // 004010bd: pop ebp
         // 004010be: retn 
      [-]08????????c7
         // 00403484: mov ds:[eax+0xc], 0xffffffffbb67ae85
      [-]0c????????c7
         // 0040348b: mov ds:[eax+0x10], 0x3c6ef372
      [-]10????????c7
         // 00403492: mov ds:[eax+0x14], 0xffffffffa54ff53a
      [-]14????????c7
         // 00403499: mov ds:[eax+0x18], 0x510e527f
      [-]18????????c7
         // 004034a0: mov ds:[eax+0x1c], 0xffffffff9b05688c
      [-]1c????????c7
         // 004034a7: mov ds:[eax+0x20], 0x1f83d9ab
      [-]20????????c7
         // 004034ae: mov ds:[eax+0x24], 0x5be0cd19
      [-]24????????c3
         // 004034b5: retn 
      [-]897ddc8b
         // 00403730: mov ss:[ebp+0xffffffffffffffec], edi
         // 00403739: mov ss:[ebp+0xffffffffffffffdc], eax
         // 0040373c: mov eax, edi
      [-]c1c80233
         // 0040378f: ror eax, b1 0x2
         // 00403792: xor ebx, eax
      [-]c1c80233
         // 00403a9e: ror eax, b1 0x2
         // 00403aa1: xor ebx, eax
      [-]2345ec0b
         // 00403aa8: and edi, esi
         // 00403aac: and eax, ss:[ebp+0xffffffffffffffec]
         // 00403ab2: or eax, edi
      [-]c1c80233
         // 00403df8: ror eax, b1 0x2
         // 00403dfb: xor edi, eax
      [-]2345ec0b
         // 00403e05: and eax, ss:[ebp+0xffffffffffffffec]
         // 00403e08: or eax, ebx
      [-]2345f003
         // 00403e74: and eax, ss:[ebp+0xfffffffffffffff0]
         // 00403e79: add eax, edi
      [-]c1c00a33
         // 00403e8f: rol eax, b1 0xa
         // 00403e92: xor ebx, eax
      [-]c1c80233
         // 00403e96: ror eax, b1 0x2
         // 00403e99: xor ebx, eax
      [-]c1c00a33
         // 004043c7: rol eax, b1 0xa
         // 004043ca: xor ebx, eax
      [-]c1c80233
         // 004043ce: ror eax, b1 0x2
         // 004043d1: xor ebx, eax
      [-]8bcfc1c10e
         // 004044b9: mov ecx, edi
         // 004044bb: rol ecx, b1 0xe
      [-]8bcfc1c10e
         // 004046c0: mov ecx, edi
         // 004046c2: rol ecx, b1 0xe
      [-]0355f48b
         // 0040482a: add edx, ss:[ebp+0xffffffffffffff1c]
         // 00404836: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 00404839: mov edi, edx
      [-]c1c80233
         // 0040491f: ror eax, b1 0x2
         // 00404922: xor edi, eax
      [-]c1e80a33
         // 004049f7: shr eax, b1 0xa
         // 004049fa: xor ebx, eax
      [-]03d08b45
         // 00404a5d: add edx, eax
         // 00404a62: mov eax, ss:[ebp+0xffffffffffffffdc]
      [-]c1c8068b
         // 00404b94: ror eax, b1 0x6
         // 00404b99: mov eax, ss:[ebp+0xffffffffffffffe8]
      [-]c1c80233
         // 0040504a: ror eax, b1 0x2
         // 0040504d: xor edi, eax
      [-]c1e80a33
         // 00405072: shr eax, b1 0xa
         // 00405075: xor ebx, eax
      [-]c1c80233
         // 004055d9: ror eax, b1 0x2
         // 004055dc: xor ebx, eax
      [-]c1c80633
         // 00405639: ror eax, b1 0x6
         // 0040563c: xor edi, eax
      [-]c1c90b33
         // 004057f8: ror ecx, b1 0xb
         // 004057fe: xor ecx, edi
      [-]c1c00a33
         // 00405b11: rol eax, b1 0xa
         // 00405b14: xor edi, eax
      [-]c1c80233
         // 00405b18: ror eax, b1 0x2
         // 00405b1b: xor edi, eax
      [-]c1c80633
         // 00405b40: ror eax, b1 0x6
         // 00405b43: xor esi, eax
      [-]c1e80333
         // 00405b4f: shr eax, b1 0x3
         // 00405b57: xor edi, eax
      [-]2345dc03
         // 00405b76: and eax, ss:[ebp+0xffffffffffffffdc]
         // 00405b79: add edi, esi
      [-]c1c00a33
         // 00405b99: rol eax, b1 0xa
         // 00405b9c: xor edi, eax
      [-]c1c80233
         // 00405ba0: ror eax, b1 0x2
         // 00405ba3: xor edi, eax
      [-]5b8be55dc3
         // 00405c03: pop ebx
         // 00405c04: mov esp, ebp
         // 00405c06: pop ebp
         // 00405c07: retn 
      [-]3fbb????????03
         // 00405c1f: mov ebx, 0x40
         // 00405c24: add ecx, edi
      [-]8b45fc83c4
         // 00403672: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00403675: add esp, 0xc
      [-]0083c40c
         // 00405c9c: add esp, 0xc
      [-]8be55dc3
         // 00405ca1: mov esp, ebp
         // 00405ca3: pop ebp
         // 00405ca4: retn 
      [-]558bec83ec18a1
         // 00405cb0: push ebp
         // 00405cb1: mov ebp, esp
         // 00405cb3: sub esp, 0x18
         // 00405cb6: mov eax, ds:[___security_cookie]
      [-]0033c58945fc53568bf1
         // 00405cbb: xor eax, ebp
         // 00405cbd: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00405cc0: push ebx
         // 00405cc1: push esi
         // 00405cc9: mov esi, ecx
      [-]108845f58bc1
         // 00405cea: mov b1 ss:[ebp+0xfffffffffffffff7], b1 al
         // 00405cf4: mov b1 ss:[ebp+0xfffffffffffffff5], b1 bl
         // 00405cf7: mov ebx, eax
         // 00405cfb: shr eax, b1 0x18
      [-]188845f88bc2c1e8108845f98bc2c1
         // 00405cfe: mov b1 ss:[ebp+0xfffffffffffffff8], b1 al
         // 00405d01: mov eax, edx
         // 00405d03: shr eax, b1 0x10
         // 00405d06: mov b1 ss:[ebp+0xfffffffffffffff9], b1 al
         // 00405d09: mov eax, edx
         // 00405d0e: shr ebx, b1 0x8
      [-]3f8845fa88
         // 00405d14: mov b1 ss:[ebp+0xfffffffffffffffa], b1 al
         // 00405d17: mov b1 ss:[ebp+0xfffffffffffffff6], b1 bl
      [-]8855fbb8????????83
         // 00405d1a: mov b1 ss:[ebp+0xfffffffffffffffb], b1 dl
         // 00405d1d: mov eax, 0x38
         // 00405d22: cmp ecx, 0x38
      [-]b8????????
         // 00405d27: mov eax, 0x78
      [-]feffff83c404
         // 00405d3c: add esp, 0x4
      [-]bf????????83
         // 00405d43: mov edi, 0x8
         // 00405d48: and eax, 0x3f
      [-]ec83ff4072
         // 00405d8c: mov ss:[ebp+0xffffffffffffffec], 0x0
         // 00405d93: cmp edi, 0x40
         // 00405d96: jb 0x405db9
      [-]8bc7c1e8068945f0
         // 00405d98: mov eax, edi
         // 00405d9a: shr eax, b1 0x6
         // 00405d9d: mov ss:[ebp+0xfffffffffffffff0], eax
      [-]ffff83ef4083c340ff4df075
         // 004037d9: sub edi, 0x40
         // 004037dc: add ebx, 0x40
         // 004037df: dec ss:[ebp+0xfffffffffffffff0]
         // 004037e2: jnz 0x4037d0
      [-]0083c40c
         // 00405dcf: add esp, 0xc
      [-]5e33cd5be8
         // 00405ec5: pop esi
         // 00405ec6: xor ecx, ebp
         // 00405ecb: pop ebx
         // 00405ecc: call @__security_check_cookie@4
      [-]008be55dc3
         // 00405ed1: mov esp, ebp
         // 00405ed3: pop ebp
         // 00405ed4: retn 
      [-]558bec6afe68
         // 00405fa0: push ebp
         // 00405fa1: mov ebp, esp
         // 00405fa3: push 0xfffffffffffffffe
         // 00405fa5: push stru_4288C8.GSCookieOffset
      [-]64a1????????5081ec????????a1
         // 00405faf: mov eax, fs:[0x0]
         // 00405fb5: push eax
         // 00405fb6: sub esp, 0x120
         // 00405fbc: mov eax, ds:[___security_cookie]
      [-]003145f833c58945e4535657508d45f064a3????????8965e833
         // 00405fc1: xor ss:[ebp+0xfffffffffffffff8], eax
         // 00405fc4: xor eax, ebp
         // 00405fc6: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00405fc9: push ebx
         // 00405fca: push esi
         // 00405fcb: push edi
         // 00405fcc: push eax
         // 00405fcd: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00405fd0: mov fs:[0x0], eax
         // 00405fd6: mov ss:[ebp+0xffffffffffffffe8], esp
         // 00405fd9: xor eax, eax
      [-]e0feffff68????????
         // 00405fe6: push 0x103
      [-]8d85????????50e8
         // 00405fec: lea eax, ss:[ebp+0xfffffffffffffee1]
         // 00405ff2: push eax
         // 00405ff3: call _memset
      [-]0083c40cc785????????????????8d
         // 00405ff8: add esp, 0xc
         // 00405ffb: mov ss:[ebp+0xfffffffffffffed4], 0x104
         // 00406005: lea ecx, ss:[ebp+0xfffffffffffffed4]
      [-]0085c074
         // 00406019: test eax, eax
         // 0040601b: jz 0x40607d
      [-]ba????????8995????????8d
         // 0040601d: mov edx, 0x6
         // 00406022: mov ss:[ebp+0xfffffffffffffed0], edx
         // 00406028: lea ecx, ss:[ebp+0xfffffffffffffee0]
      [-]4a8995????????85
         // 00406039: dec edx
         // 0040603a: mov ss:[ebp+0xfffffffffffffed0], edx
         // 00406040: test esi, esi
      [-]c745fc????????8b
         // 0040607d: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 00406084: mov eax, esi
      [-]8b4df064890d????????595f5e5b8b4de433cde8
         // 00406086: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 00406089: mov fs:[0x0], ecx
         // 00406090: pop ecx
         // 00406091: pop edi
         // 00406092: pop esi
         // 00406093: pop ebx
         // 00406094: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 00406097: xor ecx, ebp
         // 00406099: call @__security_check_cookie@4
      [-]008be55dc3
         // 0040609e: mov esp, ebp
         // 004060a0: pop ebp
         // 004060a1: retn 
      [-]558bec6aff68
         // 004060b0: push ebp
         // 004060b1: mov ebp, esp
         // 004060b3: push 0xffffffffffffffff
         // 004060b5: push 0x4230e8
      [-]64a1????????5081ec
         // 004060ba: mov eax, fs:[0x0]
         // 004060c0: push eax
         // 004060c1: sub esp, 0x4ac
      [-]0033c58945ec535657508d45f464a3????????8965f089
         // 004060cc: xor eax, ebp
         // 004060ce: mov ss:[ebp+0xffffffffffffffec], eax
         // 004060d1: push ebx
         // 004060d2: push esi
         // 004060d3: push edi
         // 004060d4: push eax
         // 004060d5: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 004060d8: mov fs:[0x0], eax
         // 004060de: mov ss:[ebp+0xfffffffffffffff0], esp
         // 004060e9: mov ss:[ebp+0xfffffffffffffb4c], eax
      [-]c645fc01ff15
         // 00406117: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
         // 0040611b: call ds:[CoCreateInstance]
      [-]060000c645fc0239
         // 00403b83: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x2
         // 00403b87: cmp ss:[ebp+0x10], ebx
      [-]8d781089bd????????33
         // 0040625e: lea edi, ds:[eax+0x10]
         // 00406261: mov ss:[ebp+0xfffffffffffffb80], edi
         // 00406267: xor ecx, ecx
      [-]c645fc05
         // 00406275: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x5
      [-]c4fbffff
      [-]33c083c40c
         // 00406286: xor eax, eax
         // 00406288: add esp, 0xc
      [-]0085c00f84
         // 00406315: test eax, eax
         // 00406317: jz 0x4066bf
      [-]8d85????????508d
         // 0040631d: lea eax, ss:[ebp+0xfffffffffffffbc4]
         // 00406323: push eax
         // 00406324: lea ecx, ss:[ebp+0xffffffffffffffc8]
      [-]0a00008bbd????????83c4
         // 00406338: mov edi, ss:[ebp+0xfffffffffffffb80]
         // 0040633e: add esp, 0xc
      [-]c645fc068b85
         // 004063de: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x6
         // 004063e2: mov eax, ss:[ebp+0xfffffffffffffb78]
      [-]8d95????????528d95
         // 004063e8: lea edx, ss:[ebp+0xfffffffffffffb74]
         // 004063ee: push edx
         // 004063ef: lea edx, ss:[ebp+0xfffffffffffffb54]
      [-]8b085250ff
         // 004063fb: mov ecx, ds:[eax]
         // 004063fd: push edx
         // 004063fe: push eax
         // 00406402: call eax
      [-]8b85????????0f85
         // 00406406: mov eax, ss:[ebp+0xfffffffffffffb74]
         // 0040640c: jnz 0x4066af
      [-]68????????5250e8
         // 00406545: push 0x23c34600
         // 0040654a: push edx
         // 0040654b: push eax
         // 0040654c: call __allmul
      [-]8d85????????508d
         // 0040655d: lea eax, ss:[ebp+0xfffffffffffffbb4]
         // 00406563: push eax
         // 00406564: lea ecx, ss:[ebp+0xfffffffffffffb58]
      [-]fbffff8b85????????8d95????????c785
         // 0040658b: mov eax, ss:[ebp+0xfffffffffffffb74]
         // 00406591: mov b2 ss:[ebp+0xfffffffffffffba8], b2 cx
         // 00406598: mov b2 ss:[ebp+0xfffffffffffffb94], b2 dx
         // 0040659f: lea ecx, ss:[ebp+0xfffffffffffffb84]
         // 004065af: mov ss:[ebp+0xfffffffffffffb9c], 0xf
      [-]c785????????????????8b
         // 004065b9: mov ss:[ebp+0xfffffffffffffba4], 0x1
         // 004065c5: mov edx, ds:[edx+0xc]
      [-]0000c645fc058b85????????e9
         // 004065db: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x5
         // 004065df: mov eax, ss:[ebp+0xfffffffffffffb74]
         // 004065e5: jmp 0x4066b3
      [-]0000c645fc058b85????????e9
         // 00406611: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x5
         // 00406615: mov eax, ss:[ebp+0xfffffffffffffb74]
         // 0040661b: jmp 0x4066b3
      [-]c645fc08
         // 0040664b: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x8
      [-]0000c645fc058b85????????eb
         // 0040665e: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x5
         // 00406662: mov eax, ss:[ebp+0xfffffffffffffb74]
         // 00406668: jmp 0x4066b3
      [-]c645fc05
         // 004066af: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x5
      [-]8b0850ff
         // 004040f8: mov ecx, ds:[eax]
         // 004040fa: push eax
         // 004040fb: call ds:[ecx+0x8]
      [-]c645fc0285c074
         // 004066e6: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x2
         // 004066ea: test eax, eax
         // 004066ec: jz 0x4066f6
      [-]8b0850ff
         // 00404133: mov ecx, ds:[eax]
         // 00404135: push eax
         // 00404136: call ds:[ecx+0x8]
      [-]c645fc018b
         // 004066f6: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
         // 004066fa: mov eax, ss:[ebp+0xfffffffffffffb60]
      [-]0cf00fc1
         // 00406709: lock xadd ds:[ecx], edx
      [-]c645fc0085c074
         // 00406722: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x0
         // 00406726: test eax, eax
         // 00406728: jz 0x406732
      [-]8b0850ff
         // 00404168: mov ecx, ds:[eax]
         // 0040416a: push eax
         // 0040416b: call ds:[ecx+0x8]
      [-]8b4df464890d????????595f5e5b8b4dec33cde8
         // 00406738: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040673b: mov fs:[0x0], ecx
         // 00406742: pop ecx
         // 00406743: pop edi
         // 00406744: pop esi
         // 00406745: pop ebx
         // 00406746: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 00406749: xor ecx, ebp
         // 0040674b: call @__security_check_cookie@4
      [-]008be55dc3
         // 00406750: mov esp, ebp
         // 00406752: pop ebp
         // 00406753: retn 
      [-]558bec6afe68
         // 00406780: push ebp
         // 00406781: mov ebp, esp
         // 00406783: push 0xfffffffffffffffe
         // 00406785: push stru_429288.GSCookieOffset
      [-]64a1????????5083ec0c535657a1
         // 0040678f: mov eax, fs:[0x0]
         // 00406795: push eax
         // 00406796: sub esp, 0xc
         // 00406799: push ebx
         // 0040679a: push esi
         // 0040679b: push edi
         // 0040679c: mov eax, ds:[___security_cookie]
      [-]003145f833c5508d45f064a3????????8965e8c745fc????????
         // 004067a1: xor ss:[ebp+0xfffffffffffffff8], eax
         // 004067a4: xor eax, ebp
         // 004067a6: push eax
         // 004067a7: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 004067aa: mov fs:[0x0], eax
         // 004067b0: mov ss:[ebp+0xffffffffffffffe8], esp
         // 004067b3: mov ss:[ebp+0xfffffffffffffffc], 0x0
      [-]f8ffff83c4
         // 004067c7: add esp, 0x8
      [-]8945e4c745fc????????8b4df064890d????????595f5e5b8be55dc3
         // 004067d7: mov ss:[ebp+0xffffffffffffffe4], eax
         // 004067da: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 004067e1: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004067e4: mov fs:[0x0], ecx
         // 004067eb: pop ecx
         // 004067ec: pop edi
         // 004067ed: pop esi
         // 004067ee: pop ebx
         // 004067ef: mov esp, ebp
         // 004067f1: pop ebp
         // 004067f2: retn 
      [-]558bec6aff68
         // 00406820: push ebp
         // 00406821: mov ebp, esp
         // 00406823: push 0xffffffffffffffff
         // 00406825: push 0x423068
      [-]64a1????????50
         // 0040682a: mov eax, fs:[0x0]
         // 00406830: push eax
      [-]0033c5508d45f464a3????????8bf1
         // 00406839: xor eax, ebp
         // 0040683b: push eax
         // 0040683c: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0040683f: mov fs:[0x0], eax
         // 00406845: mov esi, ecx
      [-]500c83c010
         // 0040684f: mov edx, ds:[eax+0xc]
         // 00406859: add eax, 0x10
      [-]c745fc????????85
         // 0040685e: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00406865: test esi, esi
      [-]000085c074
         // 0040687d: test eax, eax
         // 0040687f: jz 0x4068ac
      [-]e847010000eb21
         // 00406884: call 0x4069d0
         // 00406889: jmp 0x4068ac
      [-]8b4df464890d????????595f5e8be55dc20400
         // 004068ae: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 004068b1: mov fs:[0x0], ecx
         // 004068b8: pop ecx
         // 004068b9: pop edi
         // 004068ba: pop esi
         // 004068bc: mov esp, ebp
         // 004068be: pop ebp
         // 004068bf: retn b2 0x4
      [-]558bec53568b
         // 004043f0: push ebp
         // 004043f1: mov ebp, esp
         // 004043f3: push ebx
         // 004043f4: push esi
         // 004043f5: mov esi, ss:[ebp+0xc]
      [-]83c40485
         // 00404425: add esp, 0x4
         // 00404428: test edi, edi
      [-]558bec51
         // 00406af0: push ebp
         // 00406af1: mov ebp, esp
         // 00406af3: push ecx
      [-]0083c408
         // 00406b27: add esp, 0x8
      [-]b9????????2b
         // 00406b2a: mov ecx, 0x7fffffff
         // 00406b2f: sub ecx, eax
      [-]fc8b40f82b
         // 00406b5a: mov eax, ds:[eax+0xfffffffffffffff8]
         // 00406b5d: sub eax, edi
      [-]83c4103b
         // 0040454f: add esp, 0x10
         // 00404552: cmp esi, ds:[eax+0xfffffffffffffff8]
      [-]8be55dc20800
         // 00406ba7: mov esp, ebp
         // 00406ba9: pop ebp
         // 00406baa: retn b2 0x8
      [-]558bec56
         // 00406c10: push ebp
         // 00406c11: mov ebp, esp
         // 00406c14: push esi
      [-]5dc20800
         // 004045a5: pop ebp
         // 004045a6: retn b2 0x8
      [-]fc8b40f82b
         // 00406c5f: mov eax, ds:[eax+0xfffffffffffffff8]
         // 00406c62: sub eax, ebx
      [-]83c4103b
         // 00406c9e: add esp, 0x10
         // 00406ca2: cmp ebx, ds:[eax+0xfffffffffffffff8]
      [-]33c966890c
         // 00406cac: xor ecx, ecx
         // 00406cae: mov b2 ds:[esi+eax], b2 cx
      [-]5dc20800
         // 00406cb5: pop ebp
         // 00406cb6: retn b2 0x8
      [-]8b106a02
         // 0040473e: mov edx, ds:[eax]
         // 00404740: push 0x2
      [-]008bf083c40885f6
         // 00404828: mov esi, eax
         // 0040482a: add esp, 0x8
         // 0040482d: test esi, esi
      [-]008b0783c4103b70f87f
         // 0040485b: mov eax, ds:[edi]
         // 0040485d: add esp, 0x10
         // 00404860: cmp esi, ds:[eax+0xfffffffffffffff8]
         // 00404863: jg 0x404877
      [-]8970f48b0733c9
         // 00406e66: mov ds:[eax+0xfffffffffffffff4], esi
         // 00406e69: mov eax, ds:[edi]
         // 00406e6b: xor ecx, ecx
      [-]66890c70
         // 00406e6d: mov b2 ds:[eax+esi*0x2], b2 cx
      [-]558bec51535657
         // 00406e80: push ebp
         // 00406e81: mov ebp, esp
         // 00406e83: push ecx
         // 00406e84: push ebx
         // 00406e85: push esi
         // 00406e86: push edi
      [-]5f5e33c05b8be55dc3
         // 00406f34: pop edi
         // 00406f35: pop esi
         // 00406f36: xor eax, eax
         // 00406f38: pop ebx
         // 00406f39: mov esp, ebp
         // 00406f3b: pop ebp
         // 00406f3c: retn 
      [-]5b8be55dc3
         // 00406f41: pop ebx
         // 00406f42: mov esp, ebp
         // 00406f44: pop ebp
         // 00406f45: retn 
      [-]558bec8b4508
         // 00406f50: push ebp
         // 00406f51: mov ebp, esp
         // 00406f53: mov eax, ss:[ebp+0x8]
      [-]4000ff24
         // 00406fae: jmp ds:[jpt_406FAE+edx*0x4]
      [-]68????????e8
         // 00406fc9: push 0xffffffff80004005
         // 00406fce: call 0x406f50
      [-]558bec6afe68
         // 004070a0: push ebp
         // 004070a1: mov ebp, esp
         // 004070a3: push 0xfffffffffffffffe
         // 004070a5: push stru_428768.GSCookieOffset
      [-]420064a1????????5083ec0c535657a1
         // 004070af: mov eax, fs:[0x0]
         // 004070b5: push eax
         // 004070b6: sub esp, 0xc
         // 004070b9: push ebx
         // 004070ba: push esi
         // 004070bb: push edi
         // 004070bc: mov eax, ds:[___security_cookie]
      [-]003145f833c5508d45f064a3????????8965e8c645e701c745fc????????525153b8????????bb????????b9????????ba????????ed81fb????????0f9445e75b595ac745fc????????8a45e78b4df064890d????????595f5e5b8be55dc3
         // 004070c1: xor ss:[ebp+0xfffffffffffffff8], eax
         // 004070c4: xor eax, ebp
         // 004070c6: push eax
         // 004070c7: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 004070ca: mov fs:[0x0], eax
         // 004070d0: mov ss:[ebp+0xffffffffffffffe8], esp
         // 004070d3: mov b1 ss:[ebp+0xffffffffffffffe7], b1 0x1
         // 004070d7: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 004070de: push edx
         // 004070df: push ecx
         // 004070e0: push ebx
         // 004070e1: mov eax, 0x564d5868
         // 004070e6: mov ebx, 0x0
         // 004070eb: mov ecx, 0xa
         // 004070f0: mov edx, 0x5658
         // 004070f5: in eax, b2 dx
         // 004070f6: cmp ebx, 0x564d5868
         // 004070fc: setz b1 ss:[ebp+0xffffffffffffffe7]
         // 00407100: pop ebx
         // 00407101: pop ecx
         // 00407102: pop edx
         // 00407103: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 0040710a: mov b1 al, b1 ss:[ebp+0xffffffffffffffe7]
         // 0040710d: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 00407110: mov fs:[0x0], ecx
         // 00407117: pop ecx
         // 00407118: pop edi
         // 00407119: pop esi
         // 0040711a: pop ebx
         // 0040711b: mov esp, ebp
         // 0040711d: pop ebp
         // 0040711e: retn 
      [-]558bec6afe68
         // 00407150: push ebp
         // 00407151: mov ebp, esp
         // 00407153: push 0xfffffffffffffffe
         // 00407155: push stru_4288A8.GSCookieOffset
      [-]64a1????????5083ec14535657a1
         // 0040715f: mov eax, fs:[0x0]
         // 00407165: push eax
         // 00407166: sub esp, 0x14
         // 00407169: push ebx
         // 0040716a: push esi
         // 0040716b: push edi
         // 0040716c: mov eax, ds:[___security_cookie]
      [-]003145f833c5508d45f064a3????????8965e8
         // 00407171: xor ss:[ebp+0xfffffffffffffff8], eax
         // 00407174: xor eax, ebp
         // 00407176: push eax
         // 00407177: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040717a: mov fs:[0x0], eax
         // 00407180: mov ss:[ebp+0xffffffffffffffe8], esp
      [-]53bb????????b8????????0f3f070b85db0f9445e75beb38
         // 0040718b: push ebx
         // 0040718c: mov ebx, 0x0
         // 00407191: mov eax, 0x1
         // 00407196: vpcext b1 0x7, b1 0xb
         // 0040719a: test ebx, ebx
         // 0040719c: setz b1 ss:[ebp+0xffffffffffffffe7]
         // 004071a0: pop ebx
         // 004071a1: jmp 0x4071db
      [-]c745fc????????8a45e78b4df064890d????????595f5e5b8be55dc3
         // 004071db: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 004071e2: mov b1 al, b1 ss:[ebp+0xffffffffffffffe7]
         // 004071e5: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004071e8: mov fs:[0x0], ecx
         // 004071ef: pop ecx
         // 004071f0: pop edi
         // 004071f1: pop esi
         // 004071f2: pop ebx
         // 004071f3: mov esp, ebp
         // 004071f5: pop ebp
         // 004071f6: retn 
      [-]0083c4045dc3
         // 00404bab: add esp, 0x4
         // 00404bae: pop ebp
         // 00404baf: retn 
      [-]0083c4045dc3
         // 00404bbb: add esp, 0x4
         // 00404bbe: pop ebp
         // 00404bbf: retn 
      [-]558bec6aff68
         // 00407240: push ebp
         // 00407241: mov ebp, esp
         // 00407243: push 0xffffffffffffffff
         // 00407245: push 0x422d8b
      [-]64a1????????5081ec
         // 0040724a: mov eax, fs:[0x0]
         // 00407250: push eax
         // 00407251: sub esp, 0xa0
      [-]0033c58945ec535657508d45f464a3????????8965f0
         // 0040725c: xor eax, ebp
         // 0040725e: mov ss:[ebp+0xffffffffffffffec], eax
         // 00407261: push ebx
         // 00407262: push esi
         // 00407263: push edi
         // 00407264: push eax
         // 00407265: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00407268: mov fs:[0x0], eax
         // 0040726e: mov ss:[ebp+0xfffffffffffffff0], esp
      [-]c645fc0133
         // 004072a9: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
         // 004072ad: xor ecx, ecx
      [-]85c07402
         // 004073ae: test eax, eax
         // 004073b0: jz 0x4073b4
      [-]c785????????????????e8
         // 004073cf: mov ss:[ebp+0xffffffffffffff7c], 0x0
         // 004073d9: call _memset
      [-]0200008b
         // 00404e42: mov edx, ds:[esi]
      [-]000083c41485c075
         // 004074e7: add esp, 0x14
         // 004074ea: test eax, eax
         // 004074ec: jnz 0x407503
      [-]0083c404
         // 00407560: add esp, 0x4
      [-]8b4df464890d????????595f5e5b8b4dec33cde8
         // 00407569: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040756c: mov fs:[0x0], ecx
         // 00407573: pop ecx
         // 00407574: pop edi
         // 00407575: pop esi
         // 00407576: pop ebx
         // 00407577: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 0040757a: xor ecx, ebp
         // 0040757c: call @__security_check_cookie@4
      [-]008be55dc3
         // 00407581: mov esp, ebp
         // 00407583: pop ebp
         // 00407584: retn 
      [-]558bec6afe68
         // 004075a0: push ebp
         // 004075a1: mov ebp, esp
         // 004075a3: push 0xfffffffffffffffe
         // 004075a5: push stru_428E38.GSCookieOffset
      [-]64a1????????5083ec0c535657a1
         // 004075af: mov eax, fs:[0x0]
         // 004075b5: push eax
         // 004075b6: sub esp, 0xc
         // 004075b9: push ebx
         // 004075ba: push esi
         // 004075bb: push edi
         // 004075bc: mov eax, ds:[___security_cookie]
      [-]003145f833c5508d45f064a3????????8965e8c745fc????????
         // 004075c1: xor ss:[ebp+0xfffffffffffffff8], eax
         // 004075c4: xor eax, ebp
         // 004075c6: push eax
         // 004075c7: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 004075ca: mov fs:[0x0], eax
         // 004075d0: mov ss:[ebp+0xffffffffffffffe8], esp
         // 004075d3: mov ss:[ebp+0xfffffffffffffffc], 0x0
      [-]fcffff83c4
         // 004075e7: add esp, 0x8
      [-]8945e4c745fc????????8b4df064890d????????595f5e5b8be55dc3
         // 004075f7: mov ss:[ebp+0xffffffffffffffe4], eax
         // 004075fa: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 00407601: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 00407604: mov fs:[0x0], ecx
         // 0040760b: pop ecx
         // 0040760c: pop edi
         // 0040760d: pop esi
         // 0040760e: pop ebx
         // 0040760f: mov esp, ebp
         // 00407611: pop ebp
         // 00407612: retn 
      [-]0083c404
         // 0040762c: add esp, 0x4
      [-]0085c074
         // 00409f2a: test eax, eax
         // 00409f2c: jz 0x409f17
      [-]837e040074
         // 00409f45: cmp ds:[esi+0x4], 0x0
         // 00409f49: jz 0x409f17
      [-]85c0740d
         // 00409f92: test eax, eax
         // 00409f94: jz 0x409fa3
      [-]50ff1528
         // 00409f96: push eax
         // 00409f97: call ds:[RegCloseKey]
      [-]00c706????????
         // 00409f9d: mov ds:[esi], 0x0
      [-]c746????????00
         // 00409fa3: mov ds:[esi+0x4], 0x0
      [-]558bec6aff68
         // 00409fb0: push ebp
         // 00409fb1: mov ebp, esp
         // 00409fb3: push 0xffffffffffffffff
         // 00409fb5: push 0x422d20
      [-]64a1????????5083ec28535657a1
         // 00409fba: mov eax, fs:[0x0]
         // 00409fc0: push eax
         // 00409fc1: sub esp, 0x28
         // 00409fc4: push ebx
         // 00409fc5: push esi
         // 00409fc6: push edi
         // 00409fc7: mov eax, ds:[___security_cookie]
      [-]0033c5508d45f464a3????????8965f033f633
         // 00409fcc: xor eax, ebp
         // 00409fce: push eax
         // 00409fcf: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00409fd2: mov fs:[0x0], eax
         // 00409fd8: mov ss:[ebp+0xfffffffffffffff0], esp
         // 00409fde: xor esi, esi
         // 00409fe5: xor ebx, ebx
      [-]0100008b
         // 00409ff9: mov ecx, ss:[ebp+0xffffffffffffffe0]
      [-]6a055656ff15
         // 0040a005: push 0x5
         // 0040a007: push esi
         // 0040a008: push esi
         // 0040a009: call ds:[OpenSCManagerW]
      [-]008bf8897d
         // 0040a00f: mov edi, eax
         // 0040a011: mov ss:[ebp+0xffffffffffffffe4], edi
      [-]8d45e850
         // 0040a036: lea eax, ss:[ebp+0xffffffffffffffe8]
         // 0040a039: push eax
      [-]ffff8b45d08b
         // 0040a06d: mov eax, ss:[ebp+0xffffffffffffffd0]
         // 0040a070: mov edi, ss:[ebp+0xffffffffffffffcc]
      [-]3b45e875
         // 0040a075: cmp eax, ss:[ebp+0xffffffffffffffe8]
         // 0040a078: jnz 0x40a0af
      [-]8d4de8515053
         // 0040a07e: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 0040a081: push ecx
         // 0040a082: push eax
         // 0040a084: push ebx
      [-]6a006a006a006a006a006a006a00
         // 0040ac36: push 0x0
         // 0040ac38: push 0x0
         // 0040ac3a: push 0x0
         // 0040ac3c: push 0x0
         // 0040ac3e: push 0x0
         // 0040ac40: push 0x0
         // 0040ac42: push 0x0
      [-]c645fc008b
         // 0040a0da: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x0
         // 0040a0de: mov eax, ss:[ebp+0xffffffffffffffe0]
      [-]8b4df464890d????????595f5e5b8be55dc3
         // 0040a123: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040a126: mov fs:[0x0], ecx
         // 0040a12d: pop ecx
         // 0040a12e: pop edi
         // 0040a12f: pop esi
         // 0040a130: pop ebx
         // 0040a131: mov esp, ebp
         // 0040a133: pop ebp
         // 0040a134: retn 
      [-]558bec6afe68
         // 0040a140: push ebp
         // 0040a141: mov ebp, esp
         // 0040a143: push 0xfffffffffffffffe
         // 0040a145: push stru_428DF8.GSCookieOffset
      [-]64a1????????5083ec08535657a1
         // 0040a14f: mov eax, fs:[0x0]
         // 0040a155: push eax
         // 0040a156: sub esp, 0x8
         // 0040a159: push ebx
         // 0040a15a: push esi
         // 0040a15b: push edi
         // 0040a15c: mov eax, ds:[___security_cookie]
      [-]003145f833c5508d45f064a3????????8965e8c745fc????????e831feffffeb09
         // 0040a161: xor ss:[ebp+0xfffffffffffffff8], eax
         // 0040a164: xor eax, ebp
         // 0040a166: push eax
         // 0040a167: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040a16a: mov fs:[0x0], eax
         // 0040a170: mov ss:[ebp+0xffffffffffffffe8], esp
         // 0040a173: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040a17a: call 0x409fb0
         // 0040a17f: jmp 0x40a18a
      [-]c745fc????????8b4df064890d????????595f5e5b8be55dc3
         // 0040a18a: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 0040a191: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040a194: mov fs:[0x0], ecx
         // 0040a19b: pop ecx
         // 0040a19c: pop edi
         // 0040a19d: pop esi
         // 0040a19e: pop ebx
         // 0040a19f: mov esp, ebp
         // 0040a1a1: pop ebp
         // 0040a1a2: retn 
      [-]558bec6aff68
         // 0040a1b0: push ebp
         // 0040a1b1: mov ebp, esp
         // 0040a1b3: push 0xffffffffffffffff
         // 0040a1b5: push 0x422cf1
      [-]64a1????????5083ec24535657a1
         // 0040a1ba: mov eax, fs:[0x0]
         // 0040a1c0: push eax
         // 0040a1c1: sub esp, 0x24
         // 0040a1c4: push ebx
         // 0040a1c5: push esi
         // 0040a1c6: push edi
         // 0040a1c7: mov eax, ds:[___security_cookie]
      [-]0033c5508d45f464a3????????8965f08b
         // 0040a1cc: xor eax, ebp
         // 0040a1ce: push eax
         // 0040a1cf: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0040a1d2: mov fs:[0x0], eax
         // 0040a1d8: mov ss:[ebp+0xfffffffffffffff0], esp
         // 0040a1db: mov esi, ss:[ebp+0xc]
      [-]8975d089
         // 0040a232: mov ss:[ebp+0xffffffffffffffd0], esi
         // 0040a235: mov ss:[ebp+0xffffffffffffffd4], eax
      [-]d8c645fc02
         // 0040a23b: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x2
      [-]80f38f8a
         // 0040a256: xor b1 bl, b1 0x8f
         // 0040a259: mov b1 cl, b1 bl
      [-]ef885def3b
         // 0040a267: mov b1 ss:[ebp+0xffffffffffffffef], b1 bl
         // 0040a26a: cmp edx, eax
      [-]d48b75d0
         // 0040a2c0: mov esi, ss:[ebp+0xffffffffffffffd0]
      [-]d48b75d0
         // 0040a320: mov esi, ss:[ebp+0xffffffffffffffd0]
      [-]d48b75d0
         // 0040a392: mov esi, ss:[ebp+0xffffffffffffffd0]
      [-]d48b75d0
         // 0040a3e8: mov esi, ss:[ebp+0xffffffffffffffd0]
      [-]d48b75d0
         // 0040a450: mov esi, ss:[ebp+0xffffffffffffffd0]
      [-]d48b75d0
         // 0040a4a3: mov esi, ss:[ebp+0xffffffffffffffd0]
      [-]d485f67504
         // 0040a4b1: test esi, esi
         // 0040a4b3: jnz 0x40a4b9
      [-]ffff85f674
         // 0040a4db: test esi, esi
         // 0040a4dd: jz 0x40a4e8
      [-]0083c404
         // 0040a4e5: add esp, 0x4
      [-]8b4df464890d????????595f5e5b8be55dc3
         // 0040a4eb: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040a4ee: mov fs:[0x0], ecx
         // 0040a4f5: pop ecx
         // 0040a4f6: pop edi
         // 0040a4f7: pop esi
         // 0040a4f8: pop ebx
         // 0040a4f9: mov esp, ebp
         // 0040a4fb: pop ebp
         // 0040a4fc: retn 
      [-]5010837e0c008d
         // 0040a51d: cmp ds:[esi+0xc], 0x0
         // 0040a521: lea ecx, ds:[esi+0xc]
      [-]8bfeb8????????f00fc1
         // 0040a52a: mov edi, esi
         // 0040a52c: mov eax, 0x1
         // 0040a531: lock xadd ds:[ecx], eax
      [-]8bc75f5ec3
         // 0040a535: mov eax, edi
         // 0040a537: pop edi
         // 0040a538: pop esi
         // 0040a539: retn 
      [-]8bf885ff
         // 0040a548: mov edi, eax
         // 0040a54a: test edi, edi
      [-]0083c4085dc20400
         // 0040b0f1: add esp, 0x8
         // 0040b0f4: pop ebp
         // 0040b0f5: retn b2 0x4
      [-]558bec568b7508
         // 0040a910: push ebp
         // 0040a911: mov ebp, esp
         // 0040a917: push esi
         // 0040a918: mov esi, ss:[ebp+0x8]
      [-]0088064683c4083b
         // 0040a92d: mov b1 ds:[esi], b1 al
         // 0040a92f: inc esi
         // 0040a930: add esp, 0x8
         // 0040a933: cmp esi, ebx
      [-]5e5dc20800
         // 0040b12b: pop esi
         // 0040b12c: pop ebp
         // 0040b12d: retn b2 0x8
      [-]0083c4085dc20400
         // 0040b141: add esp, 0x8
         // 0040b144: pop ebp
         // 0040b145: retn b2 0x4
      [-]558bec568b7508
         // 0040a960: push ebp
         // 0040a961: mov ebp, esp
         // 0040a967: push esi
         // 0040a968: mov esi, ss:[ebp+0x8]
      [-]0088064683c4083b
         // 0040a97d: mov b1 ds:[esi], b1 al
         // 0040a97f: inc esi
         // 0040a980: add esp, 0x8
         // 0040a983: cmp esi, ebx
      [-]5e5dc20800
         // 0040b17b: pop esi
         // 0040b17c: pop ebp
         // 0040b17d: retn b2 0x8
      [-]558bec568bf18b46
         // 0040aa10: push ebp
         // 0040aa11: mov ebp, esp
         // 0040aa13: push esi
         // 0040aa14: mov esi, ecx
         // 0040aa16: mov eax, ds:[esi+0x14]
      [-]f6450801c706
         // 0040aa3c: test b1 ss:[ebp+0x8], b1 0x1
         // 0040aa40: mov ds:[esi], ??_7facet@locale@std@@6B@
      [-]0083c404
         // 0040aa4e: add esp, 0x4
      [-]8bc65e5dc20400
         // 0040aa51: mov eax, esi
         // 0040aa53: pop esi
         // 0040aa54: pop ebp
         // 0040aa55: retn b2 0x4
      [-]8d47015f5ec7
         // 0040ad7b: lea eax, ds:[edi+0x1]
         // 0040ad7e: pop edi
         // 0040ad7f: pop esi
         // 0040ad80: mov ds:[edx], 0x80
      [-]992bc2d1f839
         // 0040b2c7: cdq 
         // 0040b2c8: sub eax, edx
         // 0040b2ca: sar eax, b1 0x1
         // 0040b2cc: cmp ds:[ecx], eax
      [-]33db33ff
         // 0040adb7: xor ebx, ebx
         // 0040adb9: xor edi, edi
      [-]0083c302473b5d
         // 0040ae29: add ebx, 0x2
         // 0040ae2c: inc edi
         // 0040ae2d: cmp ebx, ss:[ebp+0x8]
      [-]b8????????5e
         // 0040ae39: mov eax, 0x1
         // 0040ae3e: pop esi
      [-]558bec6aff68
         // 0040ae50: push ebp
         // 0040ae51: mov ebp, esp
         // 0040ae53: push 0xffffffffffffffff
         // 0040ae55: push 0x423008
      [-]64a1????????5083ec08535657a1
         // 0040ae5a: mov eax, fs:[0x0]
         // 0040ae60: push eax
         // 0040ae61: sub esp, 0x8
         // 0040ae64: push ebx
         // 0040ae65: push esi
         // 0040ae66: push edi
         // 0040ae67: mov eax, ds:[___security_cookie]
      [-]0033c5508d45f464a3????????8965f0
         // 0040ae6c: xor eax, ebp
         // 0040ae6e: push eax
         // 0040ae6f: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0040ae72: mov fs:[0x0], eax
         // 0040ae78: mov ss:[ebp+0xfffffffffffffff0], esp
      [-]8d70108975ec
         // 0040ae8f: lea esi, ds:[eax+0x10]
         // 0040ae92: mov ss:[ebp+0xffffffffffffffec], esi
      [-]ffff8b75ec
         // 0040b3d2: mov esi, ss:[ebp+0xffffffffffffffec]
      [-]0083c408
         // 0040aec1: add esp, 0x8
      [-]ffff84c07509
         // 0040aecd: test b1 al, b1 al
         // 0040aecf: jnz 0x40aeda
      [-]ffff84c074
         // 0040aed6: test b1 al, b1 al
         // 0040aed8: jz 0x40aee1
      [-]bf????????eb
         // 0040aeda: mov edi, 0x1
         // 0040aedf: jmp 0x40aee3
      [-]fff00fc1
         // 0040b433: lock xadd ds:[eax], ecx
      [-]8bc78b4df464890d????????595f5e5b8be55dc3
         // 0040af26: mov eax, edi
         // 0040af28: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040af2b: mov fs:[0x0], ecx
         // 0040af32: pop ecx
         // 0040af33: pop edi
         // 0040af34: pop esi
         // 0040af35: pop ebx
         // 0040af36: mov esp, ebp
         // 0040af38: pop ebp
         // 0040af39: retn 
      [-]558bec6afe68
         // 0040af40: push ebp
         // 0040af41: mov ebp, esp
         // 0040af43: push 0xfffffffffffffffe
         // 0040af45: push stru_429268.GSCookieOffset
      [-]420064a1????????5083ec0c535657a1
         // 0040af4f: mov eax, fs:[0x0]
         // 0040af55: push eax
         // 0040af56: sub esp, 0xc
         // 0040af59: push ebx
         // 0040af5a: push esi
         // 0040af5b: push edi
         // 0040af5c: mov eax, ds:[___security_cookie]
      [-]003145f833c5508d45f064a3????????8965e8c745fc????????e8d1feffffeb0e
         // 0040af61: xor ss:[ebp+0xfffffffffffffff8], eax
         // 0040af64: xor eax, ebp
         // 0040af66: push eax
         // 0040af67: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040af6a: mov fs:[0x0], eax
         // 0040af70: mov ss:[ebp+0xffffffffffffffe8], esp
         // 0040af73: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040af7a: call 0x40ae50
         // 0040af7f: jmp 0x40af8f
      [-]8945e4c745fc????????8b4df064890d????????595f5e5b8be55dc3
         // 0040af8f: mov ss:[ebp+0xffffffffffffffe4], eax
         // 0040af92: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 0040af99: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040af9c: mov fs:[0x0], ecx
         // 0040afa3: pop ecx
         // 0040afa4: pop edi
         // 0040afa5: pop esi
         // 0040afa6: pop ebx
         // 0040afa7: mov esp, ebp
         // 0040afa9: pop ebp
         // 0040afaa: retn 
      [-]558bec6aff68
         // 0040afb0: push ebp
         // 0040afb1: mov ebp, esp
         // 0040afb3: push 0xffffffffffffffff
         // 0040afb5: push 0x423168
      [-]64a1????????5083ec
         // 0040afba: mov eax, fs:[0x0]
         // 0040afc0: push eax
         // 0040afc1: sub esp, 0x24
      [-]535657a1
         // 0040afc4: push ebx
         // 0040afc5: push esi
         // 0040afc6: push edi
         // 0040afc7: mov eax, ds:[___security_cookie]
      [-]0033c5508d45f464a3????????8965f08b
         // 0040afcc: xor eax, ebp
         // 0040afce: push eax
         // 0040afcf: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0040afd2: mov fs:[0x0], eax
         // 0040afd8: mov ss:[ebp+0xfffffffffffffff0], esp
         // 0040afdb: mov edi, ss:[ebp+0x8]
      [-]0085c00f84
         // 0040b00f: test eax, eax
         // 0040b011: jz 0x40b199
      [-]6a146a65
         // 0040b017: push 0x14
         // 0040b019: push 0x65
      [-]ffff83c4
         // 0040b076: add esp, 0x8
      [-]3bf00f94
         // 0040b0cb: cmp esi, eax
         // 0040b0cd: setz b1 cl
      [-]0083c414
         // 0040b0d8: add esp, 0x14
      [-]c645fc02e8
         // 0040b627: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x2
         // 0040b62b: call 0x4043c0
      [-]8b4df464890d????????595f5e5b8be55dc3
         // 0040b19c: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040b19f: mov fs:[0x0], ecx
         // 0040b1a6: pop ecx
         // 0040b1a7: pop edi
         // 0040b1a8: pop esi
         // 0040b1a9: pop ebx
         // 0040b1aa: mov esp, ebp
         // 0040b1ac: pop ebp
         // 0040b1ad: retn 
      [-]558bec6afe68
         // 0040b1b0: push ebp
         // 0040b1b1: mov ebp, esp
         // 0040b1b3: push 0xfffffffffffffffe
         // 0040b1b5: push stru_429350.GSCookieOffset
      [-]64a1????????5083ec0c535657a1
         // 0040b1bf: mov eax, fs:[0x0]
         // 0040b1c5: push eax
         // 0040b1c6: sub esp, 0xc
         // 0040b1c9: push ebx
         // 0040b1ca: push esi
         // 0040b1cb: push edi
         // 0040b1cc: mov eax, ds:[___security_cookie]
      [-]003145f833c5508d45f064a3????????8965e8c745fc????????e8
         // 0040b1d1: xor ss:[ebp+0xfffffffffffffff8], eax
         // 0040b1d4: xor eax, ebp
         // 0040b1d6: push eax
         // 0040b1d7: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040b1da: mov fs:[0x0], eax
         // 0040b1e0: mov ss:[ebp+0xffffffffffffffe8], esp
         // 0040b1e3: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040b1ee: call 0x40afb0
      [-]fdffffeb0b
         // 0040b1f6: jmp 0x40b203
      [-]8945e4c745fc????????8b4df064890d????????595f5e5b8be55dc3
         // 0040b203: mov ss:[ebp+0xffffffffffffffe4], eax
         // 0040b206: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 0040b20d: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040b210: mov fs:[0x0], ecx
         // 0040b217: pop ecx
         // 0040b218: pop edi
         // 0040b219: pop esi
         // 0040b21a: pop ebx
         // 0040b21b: mov esp, ebp
         // 0040b21d: pop ebp
         // 0040b21e: retn 
      [-]558bec6aff68
         // 0040b220: push ebp
         // 0040b221: mov ebp, esp
         // 0040b223: push 0xffffffffffffffff
         // 0040b225: push 0x423130
      [-]64a1????????5083ec
         // 0040b22a: mov eax, fs:[0x0]
         // 0040b230: push eax
         // 0040b231: sub esp, 0x1c
      [-]535657a1
         // 0040b234: push ebx
         // 0040b235: push esi
         // 0040b236: push edi
         // 0040b237: mov eax, ds:[___security_cookie]
      [-]0033c5508d45f464a3????????8965f0
         // 0040b23c: xor eax, ebp
         // 0040b23e: push eax
         // 0040b23f: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0040b242: mov fs:[0x0], eax
         // 0040b248: mov ss:[ebp+0xfffffffffffffff0], esp
      [-]c645fc02
         // 0040b29b: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x2
      [-]c645fc03
         // 0040b2b5: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x3
      [-]1e0000c645fc048b
         // 0040b8ac: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x4
         // 0040b8b0: mov edx, ds:[eax]
      [-]837b0c008d730c7c
         // 0040b2de: cmp ds:[ebx+0xc], 0x0
         // 0040b2e2: lea esi, ds:[ebx+0xc]
         // 0040b2e5: jl 0x40b312
      [-]fff00fc1
         // 0040b2f7: lock xadd ds:[esi], eax
      [-]ffff8b75
         // 0040b8fe: mov esi, ss:[ebp+0xffffffffffffffec]
      [-]837ef400c645fc038b
         // 0040b322: cmp ds:[esi+0xfffffffffffffff4], 0x0
         // 0040b326: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x3
         // 0040b32a: mov eax, ss:[ebp+0xffffffffffffffd8]
      [-]0f95c383
         // 0040b32d: setnz b1 bl
         // 0040b330: add eax, 0xfffffffffffffff0
      [-]f083c9ff
         // 0040b336: or ecx, 0xffffffffffffffff
      [-]4985c97f
         // 0040b33d: dec ecx
         // 0040b33e: test ecx, ecx
         // 0040b340: jg 0x40b34c
      [-]ffff6a0168
         // 0040b940: push 0x1
         // 0040b942: push 0x4410bc
      [-]0085c00f85
         // 0040b959: test eax, eax
         // 0040b95b: jnz 0x40b897
      [-]003d????????
         // 0040b39b: cmp eax, 0xb7
      [-]fff00fc1
         // 0040b9bc: lock xadd ds:[eax], ecx
      [-]8b4df464890d????????595f5e5b8be55dc3
         // 0040b416: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040b419: mov fs:[0x0], ecx
         // 0040b420: pop ecx
         // 0040b421: pop edi
         // 0040b422: pop esi
         // 0040b423: pop ebx
         // 0040b424: mov esp, ebp
         // 0040b426: pop ebp
         // 0040b427: retn 
      [-]558bec6aff68
         // 0040b450: push ebp
         // 0040b451: mov ebp, esp
         // 0040b453: push 0xffffffffffffffff
         // 0040b455: push 0x422fd6
      [-]64a1????????5081ec
         // 0040b45a: mov eax, fs:[0x0]
         // 0040b460: push eax
         // 0040b461: sub esp, 0x2e4
      [-]0033c58945ec535657508d45f464a3????????8965f0
         // 0040b46c: xor eax, ebp
         // 0040b46e: mov ss:[ebp+0xffffffffffffffec], eax
         // 0040b471: push ebx
         // 0040b472: push esi
         // 0040b473: push edi
         // 0040b474: push eax
         // 0040b475: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0040b478: mov fs:[0x0], eax
         // 0040b47e: mov ss:[ebp+0xfffffffffffffff0], esp
      [-]c645fc01e8
         // 0040b4ab: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
         // 0040b4af: call 0x4075a0
      [-]0085c075
         // 0040b4e3: test eax, eax
         // 0040b4e5: jnz 0x40b551
      [-]68????????506689
         // 0040bb07: push 0x206
         // 0040bb0c: push eax
         // 0040bb0d: mov b2 ss:[ebp+0xfffffffffffffde4], b2 ax
      [-]e4fdffff
      [-]0083c40c8d
         // 0040bb20: add esp, 0xc
         // 0040bb23: lea eax, ss:[ebp+0xfffffffffffffde4]
      [-]68????????ff15
         // 0040bb2a: push 0x104
         // 0040bb2f: call ds:[GetTempPathW]
      [-]0085c00f84
         // 0040bb35: test eax, eax
         // 0040bb37: jz 0x40bd66
      [-]0085c00f84
         // 0040b531: test eax, eax
         // 0040b533: jz 0x40b6ca
      [-]0085c00f84
         // 0040b549: test eax, eax
         // 0040b54b: jz 0x40b6ca
      [-]c645fc02e8
         // 0040bb85: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x2
         // 0040bb89: call 0x40ec40
      [-]0083c404
         // 0040b6da: add esp, 0x4
      [-]8b4df464890d????????595f5e5b8b4dec33cde8
         // 0040b6e3: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040b6e6: mov fs:[0x0], ecx
         // 0040b6ed: pop ecx
         // 0040b6ee: pop edi
         // 0040b6ef: pop esi
         // 0040b6f0: pop ebx
         // 0040b6f1: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 0040b6f4: xor ecx, ebp
         // 0040b6f6: call @__security_check_cookie@4
      [-]008be55dc3
         // 0040b6fb: mov esp, ebp
         // 0040b6fd: pop ebp
         // 0040b6fe: retn 
      [-]558bec83ec
         // 0040be10: push ebp
         // 0040be11: mov ebp, esp
         // 0040be13: sub esp, 0x10
      [-]526a0033
         // 0040b78d: push edx
         // 0040b78e: push 0x0
         // 0040b790: xor eax, eax
      [-]6a000f95
         // 0040b796: push 0x0
         // 0040b798: setnz b1 al
      [-]6a006a00
         // 0040b79b: push 0x0
         // 0040b79d: push 0x0
      [-]0085c075
         // 0040b7b3: test eax, eax
         // 0040b7b5: jnz 0x40b7fc
      [-]85c00f94
         // 0040b7ea: test eax, eax
         // 0040b7ec: setz b1 dl
      [-]558bec6aff68
         // 0040b860: push ebp
         // 0040b861: mov ebp, esp
         // 0040b863: push 0xffffffffffffffff
         // 0040b865: push 0x4231fe
      [-]64a1????????5081ec????????a1
         // 0040b86a: mov eax, fs:[0x0]
         // 0040b870: push eax
         // 0040b871: sub esp, 0x230
         // 0040b877: mov eax, ds:[___security_cookie]
      [-]0033c58945ec535657508d45f464a3????????8965f033c068????????c745fc????????
         // 0040b87c: xor eax, ebp
         // 0040b87e: mov ss:[ebp+0xffffffffffffffec], eax
         // 0040b881: push ebx
         // 0040b882: push esi
         // 0040b883: push edi
         // 0040b884: push eax
         // 0040b885: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0040b888: mov fs:[0x0], eax
         // 0040b88e: mov ss:[ebp+0xfffffffffffffff0], esp
         // 0040b891: xor eax, eax
         // 0040b893: push 0x206
         // 0040b89f: mov ss:[ebp+0xfffffffffffffffc], 0x0
      [-]668985e4fdffff
         // 0040b8a7: mov b2 ss:[ebp+0xfffffffffffffde4], b2 ax
      [-]0083c40c
         // 0040b8b3: add esp, 0xc
      [-]6a006a1a
         // 0040b8b6: push 0x0
         // 0040b8b8: push 0x1a
      [-]6a00ff15
         // 0040b8c1: push 0x0
         // 0040b8c3: call ds:[SHGetSpecialFolderPathW]
      [-]0085c00f84
         // 0040b8c9: test eax, eax
         // 0040b8cb: jz 0x40bcb0
      [-]ffffc645fc01
         // 0040b8e3: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
      [-]83c0108985????????
         // 0040b8f7: add eax, 0x10
         // 0040b8fa: mov ss:[ebp+0xfffffffffffffde0], eax
      [-]8d8d????????c645fc02e8
         // 0040b900: lea ecx, ss:[ebp+0xfffffffffffffddc]
         // 0040b90c: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x2
         // 0040b910: call 0x40a1b0
      [-]c645fc03e8
         // 0040b924: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x3
         // 0040b928: call 0x40a1b0
      [-]8b85????????8378f4000f84
         // 0040b935: mov eax, ss:[ebp+0xfffffffffffffddc]
         // 0040b93b: cmp ds:[eax+0xfffffffffffffff4], 0x0
         // 0040b93f: jz 0x40bc18
      [-]f4000f84
         // 0040b94f: jz 0x40bc18
      [-]8d85????????
         // 0040b955: lea eax, ss:[ebp+0xfffffffffffffdcc]
      [-]000085c00f84
         // 0040b973: test eax, eax
         // 0040b975: jz 0x40bc18
      [-]8b8d????????e8
         // 0040b97b: mov ecx, ss:[ebp+0xfffffffffffffde0]
         // 0040b981: call 0x40b220
      [-]ffff85c00f84
         // 0040b986: test eax, eax
         // 0040b988: jz 0x40bc18
      [-]000085c00f84
         // 0040c028: test eax, eax
         // 0040c02a: jz 0x40c321
      [-]000085c00f84
         // 0040c03d: test eax, eax
         // 0040c03f: jz 0x40c321
      [-]ffff83c40485c00f84
         // 0040b9c5: add esp, 0x4
         // 0040b9c8: test eax, eax
         // 0040b9ca: jz 0x40bc18
      [-]ffff85c07464
         // 0040c07c: test eax, eax
         // 0040c07e: jz 0x40c0e4
      [-]c645fc05e8
         // 0040ba06: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x5
         // 0040ba0a: call 0x40a1b0
      [-]c645fc06e8
         // 0040ba12: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x6
         // 0040ba16: call 0x40d290
      [-]8d8d????????e8
         // 0040c0e9: lea ecx, ss:[ebp+0xfffffffffffffdc4]
         // 0040c0ef: call 0x40ad60
      [-]c645fc07e8
         // 0040c0ff: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x7
         // 0040c103: call 0x40ad60
      [-]ffffc645fc088b85????????8378f4000f84
         // 0040c108: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x8
         // 0040c10c: mov eax, ss:[ebp+0xfffffffffffffdc4]
         // 0040c112: cmp ds:[eax+0xfffffffffffffff4], 0x0
         // 0040c116: jz 0x40c30b
      [-]f4000f84
         // 0040ba94: jz 0x40bc02
      [-]8d85????????
         // 0040ba9a: lea eax, ss:[ebp+0xfffffffffffffdcc]
      [-]000085c00f84
         // 0040bab8: test eax, eax
         // 0040baba: jz 0x40bc02
      [-]8b8d????????e8
         // 0040bac0: mov ecx, ss:[ebp+0xfffffffffffffde0]
         // 0040bac6: call 0x40b220
      [-]ffff85c00f84
         // 0040bacb: test eax, eax
         // 0040bacd: jz 0x40bc02
      [-]000085c00f84
         // 0040c17b: test eax, eax
         // 0040c17d: jz 0x40c30b
      [-]ffff83c40485c00f84
         // 0040bafb: add esp, 0x4
         // 0040bafe: test eax, eax
         // 0040bb00: jz 0x40bc02
      [-]fcffff85c00f84
         // 0040bb11: test eax, eax
         // 0040bb13: jz 0x40bc02
      [-]c645fc09e8
         // 0040bb39: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x9
         // 0040bb3d: call 0x40a1b0
      [-]ffffc645fc0a8b
         // 0040bb45: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0xa
         // 0040bb49: mov edx, ss:[ebp+0xfffffffffffffdd8]
      [-]f4000f84
         // 0040bb53: jz 0x40bbec
      [-]f4000f84
         // 0040bb63: jz 0x40bbec
      [-]ffff8bf083c4
         // 0040bb85: mov esi, eax
         // 0040bb87: add esp, 0x8
      [-]ffff85c074
         // 0040bb93: test eax, eax
         // 0040bb95: jz 0x40bbb6
      [-]ffff8bf083c4
         // 0040bbb1: mov esi, eax
         // 0040bbb3: add esp, 0x8
      [-]ffff6a006a006a00
         // 0040bbd1: push 0x0
         // 0040bbd3: push 0x0
         // 0040bbd5: push 0x0
      [-]6a006a00ff15
         // 0040bbd8: push 0x0
         // 0040bbda: push 0x0
         // 0040bbdc: call ds:[ShellExecuteW]
      [-]c645fc038b
         // 0040bc18: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x3
         // 0040bc1c: mov eax, ss:[ebp+0xfffffffffffffdc8]
      [-]c645fc028b
         // 0040bc3e: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x2
         // 0040bc42: mov eax, ss:[ebp+0xfffffffffffffddc]
      [-]0cf00fc1
         // 0040bc51: lock xadd ds:[ecx], edx
      [-]c645fc018b
         // 0040bc64: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
         // 0040bc68: mov eax, ss:[ebp+0xfffffffffffffde0]
      [-]0cf00fc1
         // 0040bc77: lock xadd ds:[ecx], edx
      [-]c645fc008b
         // 0040bc8a: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x0
         // 0040bc8e: mov eax, ss:[ebp+0xfffffffffffffdcc]
      [-]0cf00fc1
         // 0040bc9d: lock xadd ds:[ecx], edx
      [-]8b4df464890d????????595f5e5b8b4dec33cde8
         // 0040bcb0: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040bcb3: mov fs:[0x0], ecx
         // 0040bcba: pop ecx
         // 0040bcbb: pop edi
         // 0040bcbc: pop esi
         // 0040bcbd: pop ebx
         // 0040bcbe: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 0040bcc1: xor ecx, ebp
         // 0040bcc3: call @__security_check_cookie@4
      [-]008be55dc3
         // 0040bcc8: mov esp, ebp
         // 0040bcca: pop ebp
         // 0040bccb: retn 
      [-]558bec6afe68
         // 0040bce0: push ebp
         // 0040bce1: mov ebp, esp
         // 0040bce3: push 0xfffffffffffffffe
         // 0040bce5: push stru_429370.GSCookieOffset
      [-]420064a1????????5083ec08535657a1
         // 0040bcef: mov eax, fs:[0x0]
         // 0040bcf5: push eax
         // 0040bcf6: sub esp, 0x8
         // 0040bcf9: push ebx
         // 0040bcfa: push esi
         // 0040bcfb: push edi
         // 0040bcfc: mov eax, ds:[___security_cookie]
      [-]003145f833c5508d45f064a3????????8965e8c745fc????????e8
         // 0040bd01: xor ss:[ebp+0xfffffffffffffff8], eax
         // 0040bd04: xor eax, ebp
         // 0040bd06: push eax
         // 0040bd07: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040bd0a: mov fs:[0x0], eax
         // 0040bd10: mov ss:[ebp+0xffffffffffffffe8], esp
         // 0040bd13: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040bd1a: call 0x40b860
      [-]ffffeb09
         // 0040bd1f: jmp 0x40bd2a
      [-]c745fc????????8b4df064890d????????595f5e5b8be55dc3
         // 0040bd2a: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 0040bd31: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040bd34: mov fs:[0x0], ecx
         // 0040bd3b: pop ecx
         // 0040bd3c: pop edi
         // 0040bd3d: pop esi
         // 0040bd3e: pop ebx
         // 0040bd3f: mov esp, ebp
         // 0040bd41: pop ebp
         // 0040bd42: retn 
      [-]558bec6afe68
         // 0040bd50: push ebp
         // 0040bd51: mov ebp, esp
         // 0040bd53: push 0xfffffffffffffffe
         // 0040bd55: push stru_4289E8.GSCookieOffset
      [-]64a1????????5081ec
         // 0040bd5f: mov eax, fs:[0x0]
         // 0040bd65: push eax
         // 0040bd66: sub esp, 0x2a8
      [-]003145f833c58945e4535657508d45f064a3????????8965e88b
         // 0040bd71: xor ss:[ebp+0xfffffffffffffff8], eax
         // 0040bd74: xor eax, ebp
         // 0040bd76: mov ss:[ebp+0xffffffffffffffe4], eax
         // 0040bd79: push ebx
         // 0040bd7a: push esi
         // 0040bd7b: push edi
         // 0040bd7c: push eax
         // 0040bd7d: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040bd80: mov fs:[0x0], eax
         // 0040bd86: mov ss:[ebp+0xffffffffffffffe8], esp
         // 0040bd89: mov edi, ecx
      [-]ffff8d55c4
         // 0040bdf3: lea edx, ss:[ebp+0xffffffffffffffc4]
      [-]68????????
         // 0040be04: push 0xfc
      [-]8d85????????50e8
         // 0040be0a: lea eax, ss:[ebp+0xfffffffffffffd5c]
         // 0040be10: push eax
         // 0040be11: call _memset
      [-]0068????????
         // 0040be16: push 0x104
      [-]8d85????????50e8
         // 0040be2c: lea eax, ss:[ebp+0xfffffffffffffd58]
         // 0040be32: push eax
         // 0040be33: call 0x4012d0
      [-]83c43485c075
         // 0040be38: add esp, 0x34
         // 0040be3b: test eax, eax
         // 0040be3d: jnz 0x40be8e
      [-]83c610eb
         // 0040be71: add esi, 0x10
         // 0040be74: jmp 0x40be4a
      [-]c745fc????????8b
         // 0040be8e: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 0040be95: mov eax, ebx
      [-]8b4df064890d????????595f5e5b8b4de433cde8
         // 0040be97: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040be9a: mov fs:[0x0], ecx
         // 0040bea1: pop ecx
         // 0040bea2: pop edi
         // 0040bea3: pop esi
         // 0040bea4: pop ebx
         // 0040bea5: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 0040bea8: xor ecx, ebp
         // 0040beaa: call @__security_check_cookie@4
      [-]008be55dc3
         // 0040beaf: mov esp, ebp
         // 0040beb1: pop ebp
         // 0040beb2: retn 
      [-]558bec6afe68
         // 0040bec0: push ebp
         // 0040bec1: mov ebp, esp
         // 0040bec3: push 0xfffffffffffffffe
         // 0040bec5: push stru_4289C8.GSCookieOffset
      [-]64a1????????5081ec
         // 0040becf: mov eax, fs:[0x0]
         // 0040bed5: push eax
         // 0040bed6: sub esp, 0x2a4
      [-]003145f833c58945e4535657508d45f064a3????????8965e88b
         // 0040bee1: xor ss:[ebp+0xfffffffffffffff8], eax
         // 0040bee4: xor eax, ebp
         // 0040bee6: mov ss:[ebp+0xffffffffffffffe4], eax
         // 0040bee9: push ebx
         // 0040beea: push esi
         // 0040beeb: push edi
         // 0040beec: push eax
         // 0040beed: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040bef0: mov fs:[0x0], eax
         // 0040bef6: mov ss:[ebp+0xffffffffffffffe8], esp
         // 0040bef9: mov edi, ecx
      [-]ffff8d55c4
         // 0040bf63: lea edx, ss:[ebp+0xffffffffffffffc4]
      [-]68????????
         // 0040bf74: push 0xfc
      [-]8d85????????50e8
         // 0040bf7a: lea eax, ss:[ebp+0xfffffffffffffd5c]
         // 0040bf80: push eax
         // 0040bf81: call _memset
      [-]0068????????
         // 0040bf86: push 0x104
      [-]8d85????????50e8
         // 0040bf9c: lea eax, ss:[ebp+0xfffffffffffffd58]
         // 0040bfa2: push eax
         // 0040bfa3: call 0x4012d0
      [-]83c43485c075
         // 0040bfa8: add esp, 0x34
         // 0040bfab: test eax, eax
         // 0040bfad: jnz 0x40bff3
      [-]83c610eb
         // 0040bfd6: add esi, 0x10
         // 0040bfd9: jmp 0x40bfb4
      [-]c745fc????????8b
         // 0040bff3: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 0040bffa: mov eax, ebx
      [-]8b4df064890d????????595f5e5b8b4de433cde8
         // 0040bffc: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040bfff: mov fs:[0x0], ecx
         // 0040c006: pop ecx
         // 0040c007: pop edi
         // 0040c008: pop esi
         // 0040c009: pop ebx
         // 0040c00a: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 0040c00d: xor ecx, ebp
         // 0040c00f: call @__security_check_cookie@4
      [-]008be55dc3
         // 0040c014: mov esp, ebp
         // 0040c016: pop ebp
         // 0040c017: retn 
      [-]558bec6afe68
         // 0040c020: push ebp
         // 0040c021: mov ebp, esp
         // 0040c023: push 0xfffffffffffffffe
         // 0040c025: push stru_428D80.GSCookieOffset
      [-]64a1????????5083ec
         // 0040c02f: mov eax, fs:[0x0]
         // 0040c035: push eax
         // 0040c036: sub esp, 0xc
      [-]535657a1
         // 0040c039: push ebx
         // 0040c03a: push esi
         // 0040c03b: push edi
         // 0040c03c: mov eax, ds:[___security_cookie]
      [-]003145f833c5508d45f064a3????????8965e88b
         // 0040c041: xor ss:[ebp+0xfffffffffffffff8], eax
         // 0040c044: xor eax, ebp
         // 0040c046: push eax
         // 0040c047: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040c04a: mov fs:[0x0], eax
         // 0040c050: mov ss:[ebp+0xffffffffffffffe8], esp
         // 0040c053: mov edi, ecx
      [-]c745fc????????8b
         // 0040c104: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 0040c10b: mov eax, ss:[ebp+0xffffffffffffffe4]
      [-]8b4df064890d????????595f5e5b8be55dc3
         // 0040c10e: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040c111: mov fs:[0x0], ecx
         // 0040c118: pop ecx
         // 0040c119: pop edi
         // 0040c11a: pop esi
         // 0040c11b: pop ebx
         // 0040c11c: mov esp, ebp
         // 0040c11e: pop ebp
         // 0040c11f: retn 
      [-]558bec6aff68
         // 0040c120: push ebp
         // 0040c121: mov ebp, esp
         // 0040c123: push 0xffffffffffffffff
         // 0040c125: push 0x422f98
      [-]64a1????????5083ec2c535657a1
         // 0040c12a: mov eax, fs:[0x0]
         // 0040c130: push eax
         // 0040c131: sub esp, 0x2c
         // 0040c134: push ebx
         // 0040c135: push esi
         // 0040c136: push edi
         // 0040c137: mov eax, ds:[___security_cookie]
      [-]0033c5508d45f464a3????????8965f0
         // 0040c13c: xor eax, ebp
         // 0040c13e: push eax
         // 0040c13f: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0040c142: mov fs:[0x0], eax
         // 0040c148: mov ss:[ebp+0xfffffffffffffff0], esp
      [-]33f656566a03566a0168????????
         // 0040c14e: xor esi, esi
         // 0040c150: push esi
         // 0040c151: push esi
         // 0040c152: push 0x3
         // 0040c154: push esi
         // 0040c155: push 0x1
         // 0040c157: push 0xffffffff80000000
      [-]8975fcff15
         // 0040c163: mov ss:[ebp+0xfffffffffffffffc], esi
         // 0040c166: call ds:[CreateFileW]
      [-]8975c88975
         // 0040c1a0: mov ss:[ebp+0xffffffffffffffc8], esi
         // 0040c1a3: mov ss:[ebp+0xffffffffffffffcc], esi
      [-]c645fc01
         // 0040c1b4: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
      [-]c645ef00
         // 0040c1ba: mov b1 ss:[ebp+0xffffffffffffffef], b1 0x0
      [-]0085c00f84
         // 0040c1fa: test eax, eax
         // 0040c1fc: jz 0x40c41d
      [-]ffff83c4
         // 0040c22a: add esp, 0x8
      [-]85c00f84
         // 0040c22d: test eax, eax
         // 0040c22f: jz 0x40c41d
      [-]fdffff83c4
         // 0040c8e1: add esp, 0x4
      [-]85c00f84
         // 0040c8e7: test eax, eax
         // 0040c8e9: jz 0x40ca49
      [-]fdffff83c4
         // 0040c8fe: add esp, 0x4
      [-]85c00f84
         // 0040c904: test eax, eax
         // 0040c906: jz 0x40ca49
      [-]fdffff83c4
         // 0040c918: add esp, 0x4
      [-]85c00f84
         // 0040c91e: test eax, eax
         // 0040c920: jz 0x40ca49
      [-]fdffff83c4
         // 0040c932: add esp, 0x4
      [-]85c00f84
         // 0040c938: test eax, eax
         // 0040c93a: jz 0x40ca49
      [-]fdffff83c4
         // 0040c94c: add esp, 0x4
      [-]85c00f84
         // 0040c952: test eax, eax
         // 0040c954: jz 0x40ca49
      [-]fdffff83c4
         // 0040c966: add esp, 0x4
      [-]85c00f84
         // 0040c96c: test eax, eax
         // 0040c96e: jz 0x40ca49
      [-]fdffff83c4
         // 0040c980: add esp, 0x4
      [-]85c00f84
         // 0040c986: test eax, eax
         // 0040c988: jz 0x40ca49
      [-]fdffff83c4
         // 0040c99a: add esp, 0x4
      [-]85c00f84
         // 0040c9a0: test eax, eax
         // 0040c9a2: jz 0x40ca49
      [-]ffff83c4
         // 0040c326: add esp, 0x8
      [-]85c00f84
         // 0040c329: test eax, eax
         // 0040c32b: jz 0x40c41d
      [-]ffff83c4
         // 0040c9d1: add esp, 0x4
      [-]fcffff83c4
         // 0040c35c: add esp, 0x8
      [-]fcffff83c4
         // 0040c9fd: add esp, 0x4
      [-]fcffff83c4
         // 0040ca13: add esp, 0x4
      [-]fcffff83c4
         // 0040ca29: add esp, 0x4
      [-]fcffff83c4
         // 0040ca3f: add esp, 0x4
      [-]c745????????ff85
         // 0040c425: mov ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0040c42c: test ebx, ebx
      [-]8b4df464890d????????595f5e5b8be55dc3
         // 0040c452: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040c455: mov fs:[0x0], ecx
         // 0040c45c: pop ecx
         // 0040c45d: pop edi
         // 0040c45e: pop esi
         // 0040c45f: pop ebx
         // 0040c460: mov esp, ebp
         // 0040c462: pop ebp
         // 0040c463: retn 
      [-]0083c404
         // 0040c46e: add esp, 0x4
      [-]558bec6afe68
         // 0040c490: push ebp
         // 0040c491: mov ebp, esp
         // 0040c493: push 0xfffffffffffffffe
         // 0040c495: push stru_429160.GSCookieOffset
      [-]64a1????????5083ec0c535657a1
         // 0040c49f: mov eax, fs:[0x0]
         // 0040c4a5: push eax
         // 0040c4a6: sub esp, 0xc
         // 0040c4a9: push ebx
         // 0040c4aa: push esi
         // 0040c4ab: push edi
         // 0040c4ac: mov eax, ds:[___security_cookie]
      [-]003145f833c5508d45f064a3????????8965e833c08945fc
         // 0040c4b1: xor ss:[ebp+0xfffffffffffffff8], eax
         // 0040c4b4: xor eax, ebp
         // 0040c4b6: push eax
         // 0040c4b7: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040c4ba: mov fs:[0x0], eax
         // 0040c4c0: mov ss:[ebp+0xffffffffffffffe8], esp
         // 0040c4c3: xor eax, eax
         // 0040c4c5: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]fcffffeb0b
         // 0040cb75: jmp 0x40cb82
      [-]c745fc????????8b4df064890d????????595f5e5b8be55dc3
         // 0040c4ea: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 0040c4f1: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040c4f4: mov fs:[0x0], ecx
         // 0040c4fb: pop ecx
         // 0040c4fc: pop edi
         // 0040c4fd: pop esi
         // 0040c4fe: pop ebx
         // 0040c4ff: mov esp, ebp
         // 0040c501: pop ebp
         // 0040c502: retn 
      [-]558bec6aff68
         // 0040c510: push ebp
         // 0040c511: mov ebp, esp
         // 0040c513: push 0xffffffffffffffff
         // 0040c515: push 0x423267
      [-]64a1????????5081ec????????a1
         // 0040c51a: mov eax, fs:[0x0]
         // 0040c520: push eax
         // 0040c521: sub esp, 0xa0
         // 0040c527: mov eax, ds:[___security_cookie]
      [-]0033c58945ec535657508d45f464a3????????8965f08d
         // 0040c52c: xor eax, ebp
         // 0040c52e: mov ss:[ebp+0xffffffffffffffec], eax
         // 0040c531: push ebx
         // 0040c532: push esi
         // 0040c533: push edi
         // 0040c534: push eax
         // 0040c535: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0040c538: mov fs:[0x0], eax
         // 0040c53e: mov ss:[ebp+0xfffffffffffffff0], esp
         // 0040c544: lea ecx, ds:[eax+0xc]
      [-]c645fc01
         // 0040cc13: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
      [-]0000c645fc028b
         // 0040cc2d: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x2
         // 0040cc31: mov ecx, ss:[ebp+0xffffffffffffff54]
      [-]ebffffe8
         // 0040cc46: call 0x40b460
      [-]8b85????????
         // 0040c5e6: mov eax, ss:[ebp+0xffffffffffffff5c]
      [-]c645fc04
         // 0040c614: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x4
      [-]0000c645fc068b85????????8d
         // 0040c624: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x6
         // 0040c628: mov eax, ss:[ebp+0xffffffffffffff68]
         // 0040c62e: lea edx, ss:[ebp+0xffffffffffffff6c]
      [-]0083c404
         // 0040c63e: add esp, 0x4
      [-]8b85????????
         // 0040c641: mov eax, ss:[ebp+0xffffffffffffff64]
      [-]c785????????????????8d
         // 0040c652: mov ss:[ebp+0xffffffffffffff58], 0x40
         // 0040c65c: lea esi, ds:[ecx+0x1]
      [-]ffff83c40885c00f84
         // 0040c676: add esp, 0x8
         // 0040c679: test eax, eax
         // 0040c67b: jz 0x40c81e
      [-]f8ffff85c00f84
         // 0040c693: test eax, eax
         // 0040c695: jz 0x40c81e
      [-]f8ffff85c00f84
         // 0040cd39: test eax, eax
         // 0040cd3b: jz 0x40ce7c
      [-]ffff85c00f84
         // 0040cd50: test eax, eax
         // 0040cd52: jz 0x40ce7c
      [-]ffff85c00f84
         // 0040cd67: test eax, eax
         // 0040cd69: jz 0x40ce7c
      [-]ffff85c00f84
         // 0040cd7e: test eax, eax
         // 0040cd80: jz 0x40ce7c
      [-]f7ffff85c00f84
         // 0040cd95: test eax, eax
         // 0040cd97: jz 0x40ce7c
      [-]f7ffff85c00f84
         // 0040cdac: test eax, eax
         // 0040cdae: jz 0x40ce7c
      [-]f7ffff85c00f84
         // 0040cdc3: test eax, eax
         // 0040cdc5: jz 0x40ce7c
      [-]f7ffff85c00f84
         // 0040cdda: test eax, eax
         // 0040cddc: jz 0x40ce7c
      [-]f7ffff85c00f84
         // 0040cdf1: test eax, eax
         // 0040cdf3: jz 0x40ce7c
      [-]f7ffff85c0
         // 0040ce08: test eax, eax
      [-]f7ffff85c074
         // 0040ce1b: test eax, eax
         // 0040ce1d: jz 0x40ce7c
      [-]ffff85c074
         // 0040ce2e: test eax, eax
         // 0040ce30: jz 0x40ce7c
      [-]ffff85c074
         // 0040ce41: test eax, eax
         // 0040ce43: jz 0x40ce7c
      [-]ffff85c074
         // 0040ce54: test eax, eax
         // 0040ce56: jz 0x40ce7c
      [-]ffff85c07411
         // 0040ce67: test eax, eax
         // 0040ce69: jz 0x40ce7c
      [-]8b85????????
         // 0040c81e: mov eax, ss:[ebp+0xffffffffffffff64]
      [-]c645fc008b
         // 0040c88f: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x0
         // 0040c893: mov eax, ss:[ebp+0xffffffffffffff60]
      [-]0cf00fc1
         // 0040c8a2: lock xadd ds:[ecx], edx
      [-]8b4df464890d????????595f5e5b8b4dec33cde8
         // 0040c8b5: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040c8b8: mov fs:[0x0], ecx
         // 0040c8bf: pop ecx
         // 0040c8c0: pop edi
         // 0040c8c1: pop esi
         // 0040c8c2: pop ebx
         // 0040c8c3: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 0040c8c6: xor ecx, ebp
         // 0040c8c8: call @__security_check_cookie@4
      [-]008be55dc3
         // 0040c8cd: mov esp, ebp
         // 0040c8cf: pop ebp
         // 0040c8d0: retn 
      [-]558bec6afe68
         // 0040c8e0: push ebp
         // 0040c8e1: mov ebp, esp
         // 0040c8e3: push 0xfffffffffffffffe
         // 0040c8e5: push stru_429418.GSCookieOffset
      [-]64a1????????5083ec08b8????????e8
         // 0040c8ef: mov eax, fs:[0x0]
         // 0040c8f5: push eax
         // 0040c8f6: sub esp, 0x8
         // 0040c8f9: mov eax, 0x8590
         // 0040c8fe: call __alloca_probe
      [-]003145f833c58945e4535657508d45f064a3????????8965e88b
         // 0040c908: xor ss:[ebp+0xfffffffffffffff8], eax
         // 0040c90b: xor eax, ebp
         // 0040c90d: mov ss:[ebp+0xffffffffffffffe4], eax
         // 0040c910: push ebx
         // 0040c911: push esi
         // 0040c912: push edi
         // 0040c913: push eax
         // 0040c914: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040c917: mov fs:[0x0], eax
         // 0040c91d: mov ss:[ebp+0xffffffffffffffe8], esp
         // 0040c920: mov eax, ss:[ebp+0x10]
      [-]dc????????c745e0????????
         // 0040c971: mov ss:[ebp+0xffffffffffffffe0], 0xffffffffa1a5c861
      [-]006a118d45a050e8
         // 0040c9b7: push 0x11
         // 0040c9b9: lea eax, ss:[ebp+0xffffffffffffffa0]
         // 0040c9bc: push eax
         // 0040c9bd: call __strlwr_s
      [-]c785????????????????c785????????????????c785????????????????c785????????????????
         // 0040c9e9: mov ss:[ebp+0xffffffffffff7abc], 0x67452301
         // 0040c9f3: mov ss:[ebp+0xffffffffffff7ac0], 0xffffffffefcdab89
         // 0040c9fd: mov ss:[ebp+0xffffffffffff7ac4], 0xffffffff98badcfe
         // 0040ca07: mov ss:[ebp+0xffffffffffff7ac8], 0x10325476
      [-]ffff8d4d
         // 0040ca42: lea ecx, ss:[ebp+0xffffffffffffffd4]
      [-]0083c40c85c00f84
         // 0040d143: add esp, 0xc
         // 0040d146: test eax, eax
         // 0040d148: jz 0x40d318
      [-]0085c00f84
         // 0040cba9: test eax, eax
         // 0040cbab: jz 0x40cceb
      [-]ffff85c00f84
         // 0040cbb6: test eax, eax
         // 0040cbb8: jz 0x40cceb
      [-]f8ffff85c00f84
         // 0040cc0d: test eax, eax
         // 0040cc0f: jz 0x40cceb
      [-]33c06689850c7bffff68????????
         // 0040cc15: xor eax, eax
         // 0040cc17: mov b2 ss:[ebp+0xffffffffffff7b0c], b2 ax
         // 0040cc1e: push 0x7ffe
      [-]8d85????????508d
         // 0040cc37: lea eax, ss:[ebp+0xfffffffffffffb0c]
         // 0040cc3d: push eax
         // 0040cc3e: lea ecx, ss:[ebp+0xfffffffffffffd14]
      [-]68????????8d
         // 0040cc4a: push 0x4000
         // 0040cc4f: lea edx, ss:[ebp+0xffffffffffff7b0c]
      [-]8d85????????50e8
         // 0040cc64: lea eax, ss:[ebp+0xffffffffffff7a5c]
         // 0040cc6a: push eax
         // 0040cc6b: call _memset
      [-]0083c430c785????????????????33
         // 0040cc70: add esp, 0x30
         // 0040cc73: mov ss:[ebp+0xffffffffffff7a58], 0x44
         // 0040cc7d: xor ecx, ecx
      [-]887affff
      [-]8985????????8d
         // 0040cca0: mov ss:[ebp+0xffffffffffff7aa8], eax
         // 0040cca6: lea edx, ss:[ebp+0xffffffffffff7a9c]
      [-]8d85????????50
         // 0040ccad: lea eax, ss:[ebp+0xffffffffffff7a58]
         // 0040ccb3: push eax
      [-]68????????
         // 0040ccb6: push 0x8000000
      [-]c745fc????????33c08b4df064890d????????595f5e5b8b4de433cde8
         // 0040cd0b: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 0040cd12: xor eax, eax
         // 0040cd14: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040cd17: mov fs:[0x0], ecx
         // 0040cd1e: pop ecx
         // 0040cd1f: pop edi
         // 0040cd20: pop esi
         // 0040cd21: pop ebx
         // 0040cd22: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 0040cd25: xor ecx, ebp
         // 0040cd27: call @__security_check_cookie@4
      [-]008be55dc21000
         // 0040cd2c: mov esp, ebp
         // 0040cd2e: pop ebp
         // 0040cd2f: retn b2 0x10
      [-]558bec6aff68
         // 0040cd40: push ebp
         // 0040cd41: mov ebp, esp
         // 0040cd43: push 0xffffffffffffffff
         // 0040cd45: push 0x423068
      [-]64a1????????50
         // 0040cd4a: mov eax, fs:[0x0]
         // 0040cd50: push eax
      [-]0033c5508d45f464a3????????8bf1
         // 0040cd59: xor eax, ebp
         // 0040cd5b: push eax
         // 0040cd5c: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0040cd5f: mov fs:[0x0], eax
         // 0040cd65: mov esi, ecx
      [-]500c83c010
         // 0040cd6f: mov edx, ds:[eax+0xc]
         // 0040cd79: add eax, 0x10
      [-]c745fc????????85
         // 0040cd7e: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040cd85: test esi, esi
      [-]ffff85c074
         // 0040cd9d: test eax, eax
         // 0040cd9f: jz 0x40cdc5
      [-]8b4df464890d????????595f5e8be55dc20400
         // 0040cdc7: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040cdca: mov fs:[0x0], ecx
         // 0040cdd1: pop ecx
         // 0040cdd2: pop edi
         // 0040cdd3: pop esi
         // 0040cdd5: mov esp, ebp
         // 0040cdd7: pop ebp
         // 0040cdd8: retn b2 0x4
      [-]0c00538d
         // 0040cdf7: push ebx
         // 0040cdf8: lea ebx, ds:[esi+0xc]
      [-]ffff8945
         // 0040ce08: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]fff00fc1
         // 0040ce0e: lock xadd ds:[ebx], eax
      [-]558bec83ec
         // 0040ce50: push ebp
         // 0040ce51: mov ebp, esp
         // 0040ce53: sub esp, 0x1c
      [-]3bf00f83
         // 0040ceb6: cmp esi, eax
         // 0040ceb8: jnb 0x40d077
      [-]0083c40885c07417
         // 0040cec7: add esp, 0x8
         // 0040ceca: test eax, eax
         // 0040cecc: jz 0x40cee5
      [-]0083c40885c075
         // 0040d52e: add esp, 0x8
         // 0040d531: test eax, eax
         // 0040d533: jnz 0x40d521
      [-]8bc68d5002
         // 0040cee9: mov eax, esi
         // 0040ceeb: lea edx, ds:[eax+0x2]
      [-]668b0883c0026685c975f5
         // 0040cef0: mov b2 cx, b2 ds:[eax]
         // 0040cef3: add eax, 0x2
         // 0040cef6: test b2 cx, b2 cx
         // 0040cef9: jnz 0x40cef0
      [-]2bc2d1f8eb02
         // 0040cefb: sub eax, edx
         // 0040cefd: sar eax, b1 0x1
         // 0040ceff: jmp 0x40cf03
      [-]5b8be55dc2
         // 0040d07b: pop ebx
         // 0040d07c: mov esp, ebp
         // 0040d07e: pop ebp
         // 0040d07f: retn b2 0xc
      [-]83c4083b45
         // 0040d1b2: add esp, 0x8
         // 0040d1b5: cmp eax, ss:[ebp+0xfffffffffffffffc]
      [-]5b8be55dc20c00
         // 0040d1e1: pop ebx
         // 0040d1e2: mov esp, ebp
         // 0040d1e4: pop ebp
         // 0040d1e5: retn b2 0xc
      [-]f085c974
         // 0040d1f5: test ecx, ecx
         // 0040d1f7: jz 0x40d204
      [-]5e5b8be55dc20c00
         // 0040d22c: pop esi
         // 0040d22d: pop ebx
         // 0040d22e: mov esp, ebp
         // 0040d230: pop ebp
         // 0040d231: retn b2 0xc
      [-]c703????????8b
         // 0040d237: mov ds:[ebx], 0xffffffffffffffff
         // 0040d23d: mov ecx, ds:[eax]
      [-]85c9740b
         // 0040d242: test ecx, ecx
         // 0040d244: jz 0x40d251
      [-]68????????e8
         // 0040d265: push 0xffffffff80004005
         // 0040d26a: call 0x406f50
      [-]8970f48b
         // 0040d2d4: mov ds:[eax+0xfffffffffffffff4], esi
         // 0040d2d7: mov edx, ds:[edi]
      [-]558bec6aff68
         // 0040d350: push ebp
         // 0040d351: mov ebp, esp
         // 0040d353: push 0xffffffffffffffff
         // 0040d355: push 0x422eba
      [-]64a1????????5083ec
         // 0040d35a: mov eax, fs:[0x0]
         // 0040d360: push eax
         // 0040d361: sub esp, 0x10
      [-]535657a1
         // 0040d364: push ebx
         // 0040d365: push esi
         // 0040d366: push edi
         // 0040d367: mov eax, ds:[___security_cookie]
      [-]0033c5508d45f464a3????????8965f08b
         // 0040d36c: xor eax, ebp
         // 0040d36e: push eax
         // 0040d36f: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0040d372: mov fs:[0x0], eax
         // 0040d378: mov ss:[ebp+0xfffffffffffffff0], esp
         // 0040d37b: mov edi, ss:[ebp+0x8]
      [-]c745fc????????84
         // 0040d3c6: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 0040d3cd: test b1 cl, b1 cl
      [-]8b480403
         // 0040d440: mov ecx, ds:[eax+0x4]
         // 0040d443: add ecx, edi
      [-]8b410c0b
         // 0040d449: mov eax, ds:[ecx+0xc]
         // 0040d44c: or eax, edx
      [-]837938007503
         // 0040d44e: cmp ds:[ecx+0x38], 0x0
         // 0040d452: jnz 0x40d457
      [-]0084c07507
         // 0040d46a: test b1 al, b1 al
         // 0040d46c: jnz 0x40d475
      [-]8b4df464890d????????595f5e5b8be55dc2
         // 0040d492: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040d495: mov fs:[0x0], ecx
         // 0040d49c: pop ecx
         // 0040d49d: pop edi
         // 0040d49e: pop esi
         // 0040d49f: pop ebx
         // 0040d4a0: mov esp, ebp
         // 0040d4a2: pop ebp
         // 0040d4a3: retn b2 0x10
      [-]83c8ffc20400
         // 0040d600: or eax, 0xffffffffffffffff
         // 0040d603: retn b2 0x4
      [-]83c8ffc3
         // 0040d620: or eax, 0xffffffffffffffff
         // 0040d623: retn 
      [-]83c40885
         // 0040d918: add esp, 0x8
         // 0040d91b: test eax, eax
      [-]33d2668914
         // 0040d9bc: xor edx, edx
         // 0040d9be: mov b2 ds:[ecx+eax*0x2], b2 dx
      [-]0064a1????????5083ec
         // 0040dc2a: mov eax, fs:[0x0]
         // 0040dc30: push eax
         // 0040dc31: sub esp, 0x2c
      [-]64a3????????8b
         // 0040dc45: mov fs:[0x0], eax
         // 0040dc4b: mov ebx, ss:[ebp+0x8]
      [-]83f8017f
         // 0040dd27: cmp eax, 0x1
         // 0040dd2a: jg 0x40dd90
      [-]85f60f85
         // 0040dd71: test esi, esi
         // 0040dd73: jnz 0x40dcf0
      [-]83f80375
         // 0040dd90: cmp eax, 0x3
         // 0040dd93: jnz 0x40ddd6
      [-]64890d????????595f5e5b8b
         // 0040dde4: mov fs:[0x0], ecx
         // 0040ddeb: pop ecx
         // 0040ddec: pop edi
         // 0040dded: pop esi
         // 0040ddee: pop ebx
         // 0040ddef: mov ecx, ss:[ebp+0xfffffffffffffff0]
      [-]008be55dc20400
         // 0040ddf9: mov esp, ebp
         // 0040ddfb: pop ebp
         // 0040ddfc: retn b2 0x4
      [-]558bec538b5d08568bf18b46
         // 0040de00: push ebp
         // 0040de01: mov ebp, esp
         // 0040de03: push ebx
         // 0040de04: mov ebx, ss:[ebp+0x8]
         // 0040de07: push esi
         // 0040de08: mov esi, ecx
         // 0040de0a: mov eax, ds:[esi+0x20]
      [-]83fbff7408
         // 0040de1a: cmp ebx, 0xffffffffffffffff
         // 0040de1d: jz 0x40de27
      [-]5b5dc20400
         // 0040de3b: pop ebx
         // 0040de3c: pop ebp
         // 0040de3d: retn b2 0x4
      [-]85c07438
         // 0040de43: test eax, eax
         // 0040de45: jz 0x40de7f
      [-]83fbff7433
         // 0040de47: cmp ebx, 0xffffffffffffffff
         // 0040de4a: jz 0x40de7f
      [-]0083c40883f8ff7513
         // 0040e2fb: add esp, 0x8
         // 0040e2fe: cmp eax, 0xffffffffffffffff
         // 0040e301: jnz 0x40e316
      [-]5e8bc35b5d
         // 0040de77: pop esi
         // 0040de78: mov eax, ebx
         // 0040de7a: pop ebx
         // 0040de7b: pop ebp
         // 0040de7c: retn b2 0x4

  }
  condition:
    all of them
}
