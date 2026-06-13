rule softcnapp_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         0083c40c
         // 004146e6: add esp, 0xc
      [-]558bec8b4d088b450c894108
         // 00417650: push ebp
         // 00417651: mov ebp, esp
         // 00417653: mov ecx, ss:[ebp+0x8]
         // 00417656: mov eax, ss:[ebp+0xc]
         // 00417659: mov ds:[ecx+0x8], eax
      [-]898120050000
         // 00417660: mov ds:[ecx+0x520], eax
      [-]00007514
         // 005182ab: jnz 0x5182c1
      [-]6a03e84c01000083c404
         // 004176ed: push 0x3
         // 004176ef: call 0x417840
         // 004176f4: add esp, 0x4
      [-]8d45fc50e8
         // 005182c1: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 005182c4: push eax
         // 005182c5: call 0x51faa0
      [-]00008b4dfc
         // 005182ca: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]558beca1
         // 00518400: push ebp
         // 00518401: mov ebp, esp
         // 00518403: mov eax, ds:[0x6816d0]
      [-]538b5d08c705
         // 00417d48: push ebx
         // 00417d49: mov ebx, ss:[ebp+0x8]
         // 00417d4c: mov ds:[0x6069c4], _malloc
      [-]f6c3027409
         // 00417d7e: test b1 bl, b1 0x2
         // 00417d81: jz 0x417d8c
      [-]e838000000
         // 00417893: call 0x4178d0
      [-]558bec81ec94010000a1
         // 00513cb0: push ebp
         // 00513cb1: mov ebp, esp
         // 00513cb3: sub esp, 0x194
         // 00513cb9: mov eax, ds:[___security_cookie]
      [-]0033c58945fc8d856cfeffff506802020000ff15
         // 00513cbe: xor eax, ebp
         // 00513cc0: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00513cc3: lea eax, ss:[ebp+0xfffffffffffffe6c]
         // 00513cc9: push eax
         // 00513cca: push 0x202
         // 00513ccf: call ds:[WSAStartup]
      [-]3c027517
         // 004178ff: cmp b1 al, b1 0x2
         // 00417901: jnz 0x41791a
      [-]c1e8083c027510
         // 00417903: shr eax, b1 0x8
         // 00417906: cmp b1 al, b1 0x2
         // 00417908: jnz 0x41791a
      [-]8b4dfc33cde8
         // 00513cec: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00513cef: xor ecx, ebp
         // 00513cf1: call @__security_check_cookie@4
      [-]8be55dc3
         // 00513cf6: mov esp, ebp
         // 00513cf8: pop ebp
         // 00513cf9: retn 
      [-]8be55dc3
         // 0041792f: mov esp, ebp
         // 00417931: pop ebp
         // 00417932: retn 
      [-]558bec566a08ff15
         // 0051a330: push ebp
         // 0051a331: mov ebp, esp
         // 0051a333: push esi
         // 0051a334: push 0x8
         // 0051a336: call ds:[0x67b020]
      [-]ff750cff15
         // 00419105: push ss:[ebp+0xc]
         // 00419108: call ds:[0x607980]
      [-]558bec568b7508
         // 004179a0: push ebp
         // 004179a1: mov ebp, esp
         // 004179a3: push esi
         // 004179a4: mov esi, ss:[ebp+0x8]
      [-]570f1f4000
         // 004179ab: push edi
         // 004179ac: nop ds:[eax+0x0]
      [-]8b068b7e04
         // 004179b0: mov eax, ds:[esi]
         // 004179b2: mov edi, ds:[esi+0x4]
      [-]0083c404
         // 0051a3c0: add esp, 0x4
      [-]558bec8b4508
         // 004179e0: push ebp
         // 004179e1: mov ebp, esp
         // 004179e3: mov eax, ss:[ebp+0x8]
      [-]558bec81ec38040000a1
         // 00515c10: push ebp
         // 00515c11: mov ebp, esp
         // 00515c13: sub esp, 0x438
         // 00515c19: mov eax, ds:[___security_cookie]
      [-]0033c58945fc8b45088985dcfbffff8b450c538985e8fbffff8b4518568b75148985ecfbffff8b451c6a008985e0fbffffc785d8fbffff00000000e8
         // 00515c1e: xor eax, ebp
         // 00515c20: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00515c23: mov eax, ss:[ebp+0x8]
         // 00515c26: mov ss:[ebp+0xfffffffffffffbdc], eax
         // 00515c2c: mov eax, ss:[ebp+0xc]
         // 00515c2f: push ebx
         // 00515c30: mov ss:[ebp+0xfffffffffffffbe8], eax
         // 00515c36: mov eax, ss:[ebp+0x18]
         // 00515c39: push esi
         // 00515c3a: mov esi, ss:[ebp+0x14]
         // 00515c3d: mov ss:[ebp+0xfffffffffffffbec], eax
         // 00515c43: mov eax, ss:[ebp+0x1c]
         // 00515c46: push 0x0
         // 00515c48: mov ss:[ebp+0xfffffffffffffbe0], eax
         // 00515c4e: mov ss:[ebp+0xfffffffffffffbd8], 0x0
         // 00515c58: call __time64
      [-]6a406a018985c8fbffff8995ccfbffffc785f8fbffff00000000ff15
         // 00515c5d: push 0x40
         // 00515c5f: push 0x1
         // 00515c61: mov ss:[ebp+0xfffffffffffffbc8], eax
         // 00515c67: mov ss:[ebp+0xfffffffffffffbcc], edx
         // 00515c6d: mov ss:[ebp+0xfffffffffffffbf8], 0x0
         // 00515c77: call ds:[0x669030]
      [-]83c40c899dd0fbffff
         // 00515c7f: add esp, 0xc
         // 00515c82: mov ss:[ebp+0xfffffffffffffbd0], ebx
      [-]5e5b8b4dfc33cde8
         // 00415f28: pop esi
         // 00415f29: pop ebx
         // 00415f2a: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00415f2d: xor ecx, ebp
         // 00415f2f: call @__security_check_cookie@4
      [-]8be55dc3
         // 00415f34: mov esp, ebp
         // 00415f36: pop ebp
         // 00415f37: retn 
      [-]837d1000570f84f3040000
         // 00417a8c: cmp ss:[ebp+0x10], 0x0
         // 00417a90: push edi
         // 00417a91: jz 0x417f8a
      [-]6888130000ff15
         // 0051a487: push 0x1388
         // 0051a48c: call ds:[0x67b020]
      [-]83c40489bdf0fbffff
         // 0051a494: add esp, 0x4
         // 0051a497: mov ss:[ebp+0xfffffffffffffbf0], edi
      [-]0f8447090000
         // 0051a49f: jz 0x51adec
      [-]6a3b56e8
         // 00419265: push 0x3b
         // 00419267: push esi
         // 00419268: call _strchr
      [-]8a0e83c4088985e4fbffff84c9742a
         // 0041926d: mov b1 cl, b1 ds:[esi]
         // 0041926f: add esp, 0x8
         // 00419272: mov ss:[ebp+0xfffffffffffffbe4], eax
         // 00419278: test b1 cl, b1 cl
         // 0041927a: jz 0x4192a6
      [-]0f1f4000
         // 00417acc: nop ds:[eax+0x0]
      [-]80f9207405
         // 00417ad0: cmp b1 cl, b1 0x20
         // 00417ad3: jz 0x417ada
      [-]80f909751c
         // 00417ad5: cmp b1 cl, b1 0x9
         // 00417ad8: jnz 0x417af6
      [-]8a4e014684c975ee
         // 00417ada: mov b1 cl, b1 ds:[esi+0x1]
         // 00417add: inc esi
         // 00417ade: test b1 cl, b1 cl
         // 00417ae0: jnz 0x417ad0
      [-]8bbdf0fbffff
         // 00417af0: mov edi, ss:[ebp+0xfffffffffffffbf0]
      [-]578d85fcfbffffc607005068
         // 00509b46: push edi
         // 00509b47: lea eax, ss:[ebp+0xfffffffffffffbfc]
         // 00509b4d: mov b1 ds:[edi], b1 0x0
         // 00509b50: push eax
         // 00509b51: push 0x634c90
      [-]0056c685fcfbffff00e8
         // 00509b56: push esi
         // 00509b57: mov b1 ss:[ebp+0xfffffffffffffbfc], b1 0x0
         // 00509b5e: call 0x469bf0
      [-]83c41083f8010f8c26030000
         // 00509b63: add esp, 0x10
         // 00509b66: cmp eax, 0x1
         // 00509b69: jl 0x509e95
      [-]8a014184c075f9
         // 00417b24: mov b1 al, b1 ds:[ecx]
         // 00417b26: inc ecx
         // 00417b27: test b1 al, b1 al
         // 00417b29: jnz 0x417b24
      [-]2bca8d95fcfbffff8d7a01
         // 00417b2b: sub ecx, edx
         // 00417b2d: lea edx, ss:[ebp+0xfffffffffffffbfc]
         // 00417b33: lea edi, ds:[edx+0x1]
      [-]8a024284c075f9
         // 00417b36: mov b1 al, b1 ds:[edx]
         // 00417b38: inc edx
         // 00417b39: test b1 al, b1 al
         // 00417b3b: jnz 0x417b36
      [-]2bd703d68a0284c07410
         // 00417b3d: sub edx, edi
         // 00417b3f: add edx, esi
         // 00417b41: mov b1 al, b1 ds:[edx]
         // 00417b43: test b1 al, b1 al
         // 00417b45: jz 0x417b57
      [-]3c207404
         // 00417b47: cmp b1 al, b1 0x20
         // 00417b49: jz 0x417b4f
      [-]3c097508
         // 00417b4b: cmp b1 al, b1 0x9
         // 00417b4d: jnz 0x417b57
      [-]8a42014284c075f0
         // 00417b4f: mov b1 al, b1 ds:[edx+0x1]
         // 00417b52: inc edx
         // 00417b53: test b1 al, b1 al
         // 00417b55: jnz 0x417b47
      [-]8a028b95f0fbffff8885f7fbffff
         // 00417b57: mov b1 al, b1 ds:[edx]
         // 00417b59: mov edx, ss:[ebp+0xfffffffffffffbf0]
         // 00417b5f: mov b1 ss:[ebp+0xfffffffffffffbf7], b1 al
      [-]0f1f8000000000
         // 00417b69: nop ds:[eax+0x0]
      [-]8a440aff3c207404
         // 00417b70: mov b1 al, b1 ds:[edx+ecx+0xffffffffffffffff]
         // 00417b74: cmp b1 al, b1 0x20
         // 00417b76: jz 0x417b7c
      [-]3c09750a
         // 00417b78: cmp b1 al, b1 0x9
         // 00417b7a: jnz 0x417b86
      [-]c6440aff00
         // 00417b7c: mov b1 ds:[edx+ecx+0xffffffffffffffff], b1 0x0
      [-]84c07412
         // 00417b8a: test b1 al, b1 al
         // 00417b8c: jz 0x417ba0
      [-]3c207404
         // 00417b90: cmp b1 al, b1 0x20
         // 00417b92: jz 0x417b98
      [-]3c097508
         // 00417b94: cmp b1 al, b1 0x9
         // 00417b96: jnz 0x417ba0
      [-]8a47014784c075f0
         // 00417b98: mov b1 al, b1 ds:[edi+0x1]
         // 00417b9b: inc edi
         // 00417b9c: test b1 al, b1 al
         // 00417b9e: jnz 0x417b90
      [-]8b85e4fbffff
         // 00417e45: mov eax, ss:[ebp+0xfffffffffffffbe4]
      [-]8038007453
         // 00417e4f: cmp b1 ds:[eax], b1 0x0
         // 00417e52: jz 0x417ea7
      [-]8d70018a0684c07413
         // 00417e54: lea esi, ds:[eax+0x1]
         // 00417e57: mov b1 al, b1 ds:[esi]
         // 00417e59: test b1 al, b1 al
         // 00417e5b: jz 0x417e70
      [-]3c207404
         // 00417e60: cmp b1 al, b1 0x20
         // 00417e62: jz 0x417e68
      [-]3c097508
         // 00417e64: cmp b1 al, b1 0x9
         // 00417e66: jnz 0x417e70
      [-]8a46014684c075f0
         // 00417e68: mov b1 al, b1 ds:[esi+0x1]
         // 00417e6b: inc esi
         // 00417e6c: test b1 al, b1 al
         // 00417e6e: jnz 0x417e60
      [-]6a3b56e8
         // 00417d00: push 0x3b
         // 00417d02: push esi
         // 00417d03: call _strchr
      [-]83c40889bde4fbffff
         // 00417d0a: add esp, 0x8
         // 00417d0d: mov ss:[ebp+0xfffffffffffffbe4], edi
         // 00417d13: test edi, edi
      [-]0f8565fcffff
         // 00417d15: jnz 0x417980
      [-]38067418
         // 00417e8b: cmp b1 ds:[esi], b1 al
         // 00417e8d: jz 0x417ea7
      [-]83c4088985e4fbffff
         // 00416342: add esp, 0x8
         // 00416345: mov ss:[ebp+0xfffffffffffffbe4], eax
      [-]0f8549fcffff
         // 0041634d: jnz 0x415f9c
      [-]8bbdf8fbffff
         // 00417ea7: mov edi, ss:[ebp+0xfffffffffffffbf8]
      [-]0f85ae000000
         // 00417eaf: jnz 0x417f63
      [-]397b107525
         // 00417eb5: cmp ds:[ebx+0x10], edi
         // 00417eb8: jnz 0x417edf
      [-]8b85ecfbffff
         // 00417eba: mov eax, ss:[ebp+0xfffffffffffffbec]
      [-]0083c404894310
         // 0051a8bb: add esp, 0x4
         // 0051a8be: mov ds:[ebx+0x10], eax
      [-]e984000000
         // 00417eda: jmp 0x417f63
      [-]837b0c00757e
         // 00417edf: cmp ds:[ebx+0xc], 0x0
         // 00417ee3: jnz 0x417f63
      [-]8bb5e0fbffff
         // 00417ee5: mov esi, ss:[ebp+0xfffffffffffffbe0]
      [-]6a3f56e8
         // 0051a8df: push 0x3f
         // 0051a8e1: push esi
         // 0051a8e2: call _strchr
      [-]6a2f56e8
         // 004196ae: push 0x2f
         // 004196b0: push esi
         // 004196b1: call _strrchr
      [-]020083c408eb0e
         // 004196b6: add esp, 0x8
         // 004196b9: jmp 0x4196c9
      [-]2bc6506a2f56e8
         // 0051a8fb: sub eax, esi
         // 0051a8fd: push eax
         // 0051a8fe: push 0x2f
         // 0051a900: push esi
         // 0051a901: call 0x527530
      [-]2bb5e0fbffff468d460150ff15
         // 0041840f: sub esi, ss:[ebp+0xfffffffffffffbe0]
         // 00418415: inc esi
         // 00418416: lea eax, ds:[esi+0x1]
         // 00418419: push eax
         // 0041841a: call ds:[0x6069c4]
      [-]0083c40489430c
         // 00418420: add esp, 0x4
         // 00418423: mov ds:[ebx+0xc], eax
      [-]56ffb5e0fbffff50e8
         // 00417f3a: push esi
         // 00417f3b: push ss:[ebp+0xfffffffffffffbe0]
         // 00417f41: push eax
         // 00417f42: call _memmove_0
      [-]8b430c83c40cc6040600eb10
         // 00417f47: mov eax, ds:[ebx+0xc]
         // 00417f4a: add esp, 0xc
         // 00417f4d: mov b1 ds:[esi+eax], b1 0x0
         // 00417f51: jmp 0x417f63
      [-]c785f8fbffff010000008bbdf8fbffff
         // 00417f53: mov ss:[ebp+0xfffffffffffffbf8], 0x1
         // 00417f5d: mov edi, ss:[ebp+0xfffffffffffffbf8]
      [-]ffb5f0fbffffff15
         // 0051a953: push ss:[ebp+0xfffffffffffffbf0]
         // 0051a959: call ds:[0x67b024]
      [-]0083c404
         // 0051a95f: add esp, 0x4
      [-]397b040f8570020000
         // 00417f76: cmp ds:[ebx+0x4], edi
         // 00417f79: jnz 0x4181ef
      [-]0056c785ecfbffff00000000e8
         // 0041643d: push esi
         // 0041643e: mov ss:[ebp+0xfffffffffffffbec], 0x0
         // 00416448: call 0x44280c
      [-]83c60ac7433801000000
         // 00417fa8: add esi, 0xa
         // 00417fab: mov ds:[ebx+0x38], 0x1
      [-]803e230f8441040000
         // 00417fb2: cmp b1 ds:[esi], b1 0x23
         // 00417fb5: jz 0x4183fc
      [-]6a0d56e8
         // 0051a9ab: push 0xd
         // 0051a9ad: push esi
         // 0051a9ae: call _strchr
      [-]6a0a56e8
         // 0051a9bd: push 0xa
         // 0051a9bf: push esi
         // 0051a9c0: call _strchr
      [-]8d85ecfbffff5068
         // 0051a9cf: lea eax, ss:[ebp+0xfffffffffffffbec]
         // 0051a9d5: push eax
         // 0051a9d6: push 0x5d5134
      [-]0f84fe030000
         // 0051a9e8: jz 0x51adec
      [-]6a3a57e8
         // 0051a9ee: push 0x3a
         // 0051a9f0: push edi
         // 0051a9f1: call _strchr
      [-]0f85eb030000
         // 0051a9fb: jnz 0x51adec
      [-]83bdf8fbffff000f8596010000
         // 00418013: cmp ss:[ebp+0xfffffffffffffbf8], 0x0
         // 0041801a: jnz 0x4181b6
      [-]83fe060f876c010000
         // 00418020: cmp esi, 0x6
         // 00418023: ja def_418029
      [-]84d27412
         // 004180b6: test b1 dl, b1 dl
         // 004180b8: jz 0x4180cc
      [-]8a50013a5101750e
         // 004180ba: mov b1 dl, b1 ds:[eax+0x1]
         // 004180bd: cmp b1 dl, b1 ds:[ecx+0x1]
         // 004180c0: jnz 0x4180d0
      [-]84d275e4
         // 004180c8: test b1 dl, b1 dl
         // 004180ca: jnz 0x4180b0
      [-]0083c40489430c
         // 0051aad0: add esp, 0x4
         // 0051aad3: mov ds:[ebx+0xc], eax
      [-]0f85a7000000
         // 0051aad8: jnz def_51AA19
      [-]c785f8fbffff01000000e998000000
         // 004180ee: mov ss:[ebp+0xfffffffffffffbf8], 0x1
         // 004180f8: jmp def_418029
      [-]8d85ecfbffff5068
         // 0051ab85: lea eax, ss:[ebp+0xfffffffffffffbec]
         // 0051ab8b: push eax
         // 0051ab8c: push 0x5d5134
      [-]006a00e8
         // 0051ab91: push 0x0
         // 0051ab93: call 0x527200
      [-]83c40c46
         // 0051ab9a: add esp, 0xc
         // 0051ab9d: inc esi
      [-]0f855dfeffff
         // 0051aba0: jnz 0x51aa03
      [-]83fe06751e
         // 004181b6: cmp esi, 0x6
         // 004181b9: jnz 0x4181d9
      [-]0083c404894308
         // 0051abb6: add esp, 0x4
         // 0051abb9: mov ds:[ebx+0x8], eax
      [-]0f84abfdffff
         // 0051abbe: jz 0x51a96f
      [-]83bdf8fbffff000f8599fdffff
         // 004181d9: cmp ss:[ebp+0xfffffffffffffbf8], 0x0
         // 004181e0: jnz 0x417f7f
      [-]83fe070f8590fdffff
         // 004181e6: cmp esi, 0x7
         // 004181e9: jnz 0x417f7f
      [-]8b95e8fbffff8b4a08
         // 004181ef: mov edx, ss:[ebp+0xfffffffffffffbe8]
         // 004181f5: mov ecx, ds:[edx+0x8]
      [-]394a10740c
         // 004181fc: cmp ds:[edx+0x10], ecx
         // 004181ff: jz 0x41820d
      [-]8b43180b431c0f8472fdffff
         // 00418201: mov eax, ds:[ebx+0x18]
         // 00418204: or eax, ds:[ebx+0x1c]
         // 00418207: jz 0x417f7f
      [-]0f843c010000
         // 00418216: jz 0x418358
      [-]837a0800743b
         // 00418358: cmp ds:[edx+0x8], 0x0
         // 0041835c: jz 0x418399
      [-]00ffb5dcfbffffe8
         // 00419b35: push ss:[ebp+0xfffffffffffffbdc]
         // 00419b3b: call 0x423880
      [-]8b95e8fbffff83c424
         // 00419b40: mov edx, ss:[ebp+0xfffffffffffffbe8]
         // 00419b46: add esp, 0x24
      [-]8b85d8fbffff
         // 0041839d: mov eax, ss:[ebp+0xfffffffffffffbd8]
      [-]ff420c5e5b8b4dfc33cde8
         // 004183ac: inc ds:[edx+0xc]
         // 004183af: pop esi
         // 004183b0: pop ebx
         // 004183b1: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004183b4: xor ecx, ebp
         // 004183b6: call @__security_check_cookie@4
      [-]8be55dc3
         // 004183bb: mov esp, ebp
         // 004183bd: pop ebp
         // 004183be: retn 
      [-]5f5e5b8b4dfc33cde8
         // 004183eb: pop edi
         // 004183ec: pop esi
         // 004183ed: pop ebx
         // 004183ee: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004183f1: xor ecx, ebp
         // 004183f3: call @__security_check_cookie@4
      [-]8be55dc3
         // 004183f8: mov esp, ebp
         // 004183fa: pop ebp
         // 004183fb: retn 
      [-]558bec578b7d08
         // 00418440: push ebp
         // 00418441: mov ebp, esp
         // 00418443: push edi
         // 00418444: mov edi, ss:[ebp+0x8]
      [-]0083c404
         // 00419c09: add esp, 0x4
      [-]0083c404
         // 00419c2c: add esp, 0x4
      [-]558bec51568b750c578b7d10c745fc01000000
         // 00418710: push ebp
         // 00418711: mov ebp, esp
         // 00418713: push ecx
         // 00418714: push esi
         // 00418715: mov esi, ss:[ebp+0xc]
         // 00418718: push edi
         // 00418719: mov edi, ss:[ebp+0x10]
         // 0041871c: mov ss:[ebp+0xfffffffffffffffc], 0x1
      [-]6a146a01ff15
         // 0051b117: push 0x14
         // 0051b119: push 0x1
         // 0051b11b: call ds:[0x67b030]
      [-]5f5e8be55dc3
         // 0041873a: pop edi
         // 0041873b: pop esi
         // 0041873c: mov esp, ebp
         // 0041873e: pop ebp
         // 0041873f: retn 
      [-]000f45c650ff15
         // 0051b137: cmovnz eax, esi
         // 0051b13a: push eax
         // 0051b13b: call ds:[0x67b02c]
      [-]0083c404894704
         // 0051b141: add esp, 0x4
         // 0051b144: mov ds:[edi+0x4], eax
      [-]c747080000000053
         // 00418757: mov ds:[edi+0x8], 0x0
         // 0041875e: push ebx
      [-]83c404c745fc00000000
         // 00416c28: add esp, 0x4
         // 00416c2b: mov ss:[ebp+0xfffffffffffffffc], 0x0
      [-]803e007412
         // 0041878a: cmp b1 ds:[esi], b1 0x0
         // 0041878d: jz 0x4187a1
      [-]8b4514894710
         // 004187a3: mov eax, ss:[ebp+0x14]
         // 004187a6: mov ds:[edi+0x10], eax
      [-]0f849a000000
         // 004187ab: jz 0x41884b
      [-]6888130000ff15
         // 00418ca1: push 0x1388
         // 00418ca6: call ds:[0x6069c4]
      [-]53688813000056e8
         // 0051b1b5: push ebx
         // 0051b1b6: push 0x1388
         // 0051b1bb: push esi
         // 0051b1bc: call _fgets
      [-]020083c40c
         // 0051b1c1: add esp, 0xc
      [-]6a0b5668
         // 0051b1c8: push 0xb
         // 0051b1ca: push esi
         // 0051b1cb: push 0x658694
      [-]000083c40c
         // 0051b1d5: add esp, 0xc
      [-]3c207404
         // 00418800: cmp b1 al, b1 0x20
         // 00418802: jz 0x418808
      [-]3c097508
         // 00418804: cmp b1 al, b1 0x9
         // 00418806: jnz 0x418810
      [-]8a41014184c075f0
         // 00418808: mov b1 al, b1 ds:[ecx+0x1]
         // 0041880b: inc ecx
         // 0041880c: test b1 al, b1 al
         // 0041880e: jnz 0x418800
      [-]6a006a00515257ff7508e8e1f1ffff53688813000056e8
         // 0051b200: push 0x0
         // 0051b202: push 0x0
         // 0051b204: push ecx
         // 0051b205: push edx
         // 0051b206: push edi
         // 0051b207: push ss:[ebp+0x8]
         // 0051b20a: call 0x51a3f0
         // 0051b20f: push ebx
         // 0051b210: push 0x1388
         // 0051b215: push esi
         // 0051b216: call _fgets
      [-]020083c424
         // 0051b21b: add esp, 0x24
      [-]0083c404
         // 00419fe9: add esp, 0x4
      [-]837dfc007409
         // 0041883c: cmp ss:[ebp+0xfffffffffffffffc], 0x0
         // 00418840: jz 0x41884b
      [-]8be55dc3
         // 0051b247: mov esp, ebp
         // 0051b249: pop ebp
         // 0051b24a: retn 
      [-]558bec568b
         // 0041a080: push ebp
         // 0041a081: mov ebp, esp
         // 0041a083: push esi
         // 0041a088: mov edi, ds:[esi+0x410]
      [-]be10040000
      [-]6a026a0256e8
         // 0041a093: push 0x2
         // 0041a095: push 0x2
         // 0041a097: push esi
         // 0041a098: call 0x426ad1
      [-]000083c40c
         // 0041a09d: add esp, 0xc
      [-]ffb6e0010000ffb618040000ff3756e80cfeffff
         // 0051b2e0: push ds:[esi+0x1e0]
         // 0051b2e6: push ds:[esi+0x418]
         // 0051b2ec: push ds:[edi]
         // 0051b2ee: push esi
         // 0051b2ef: call 0x51b100
      [-]ffb610040000e881f0ffff6a02
         // 00418914: push ds:[esi+0x410]
         // 0041891a: call 0x4179a0
         // 0041891f: push 0x2
      [-]000083c40c
         // 0041892d: add esp, 0xc
      [-]5f5e5dc3
         // 00418930: pop edi
         // 00418931: pop esi
         // 00418932: pop ebp
         // 00418933: retn 
      [-]558bec568b750883be48030000007447
         // 00418940: push ebp
         // 00418941: mov ebp, esp
         // 00418943: push esi
         // 00418944: mov esi, ss:[ebp+0x8]
         // 00418947: cmp ds:[esi+0x348], 0x0
         // 0041894e: jz 0x418997
      [-]837d0c00741d
         // 00418997: cmp ss:[ebp+0xc], 0x0
         // 0041899b: jz 0x4189ba
      [-]8b8610040000
         // 0041899d: mov eax, ds:[esi+0x410]
      [-]50e8f3efffff83c404c7861004000000000000
         // 004189a7: push eax
         // 004189a8: call 0x4179a0
         // 004189ad: add esp, 0x4
         // 004189b0: mov ds:[esi+0x410], 0x0
      [-]6a026a0256e8
         // 00516bca: push 0x2
         // 00516bcc: push 0x2
         // 00516bce: push esi
         // 00516bcf: call 0x522ab0
      [-]8b86180400003b4118740e
         // 004189d4: mov eax, ds:[esi+0x418]
         // 004189da: cmp eax, ds:[ecx+0x18]
         // 004189dd: jz 0x4189ed
      [-]ffb618040000e856faffff83c404
         // 004189df: push ds:[esi+0x418]
         // 004189e5: call 0x418440
         // 004189ea: add esp, 0x4
      [-]6a0256e8
         // 00516bfd: push 0x2
         // 00516bff: push esi
         // 00516c00: call 0x522af0
      [-]000083c4085e5dc3
         // 00516c05: add esp, 0x8
         // 00516c08: pop esi
         // 00516c09: pop ebp
         // 00516c0a: retn 
      [-]558bec51568b7508c745fc00000000
         // 00418a00: push ebp
         // 00418a01: mov ebp, esp
         // 00418a03: push ecx
         // 00418a04: push esi
         // 00418a05: mov esi, ss:[ebp+0x8]
         // 00418a08: mov ss:[ebp+0xfffffffffffffffc], 0x0
      [-]0f84ca000000
         // 00418a11: jz 0x418ae1
      [-]837e0c000f84c0000000
         // 00418a17: cmp ds:[esi+0xc], 0x0
         // 00418a1b: jz 0x418ae1
      [-]53578b7d0c5768
         // 0051b411: push ebx
         // 0051b412: push edi
         // 0051b413: mov edi, ss:[ebp+0xc]
         // 0051b416: push edi
         // 0051b417: push 0x65012c
      [-]83c404c745fc01000000
         // 00416eeb: add esp, 0x4
         // 00416eee: mov ss:[ebp+0xfffffffffffffffc], 0x1
      [-]8b3683c408
         // 004188fc: mov esi, ds:[esi]
         // 004188fe: add esp, 0x8
      [-]56e855010000
         // 00418a75: push esi
         // 00418a76: call 0x418bd0
      [-]008b3683c410
         // 0041a247: mov esi, ds:[esi]
         // 0041a249: add esp, 0x10
      [-]837dfc007509
         // 00418aa0: cmp ss:[ebp+0xfffffffffffffffc], 0x0
         // 00418aa4: jnz 0x418aaf
      [-]5e8be55dc3
         // 00418ab3: pop esi
         // 00418ab4: mov esp, ebp
         // 00418ab6: pop ebp
         // 00418ab7: retn 
      [-]83c408837dfc007509
         // 0041a273: add esp, 0x8
         // 0041a276: cmp ss:[ebp+0xfffffffffffffffc], 0x0
         // 0041a27a: jnz 0x41a285
      [-]5e8be55dc3
         // 00418adc: pop esi
         // 00418add: mov esp, ebp
         // 00418adf: pop ebp
         // 00418ae0: retn 
      [-]5e8be55dc3
         // 00418ae3: pop esi
         // 00418ae4: mov esp, ebp
         // 00418ae6: pop ebp
         // 00418ae7: retn 
      [-]558bec568b75088b4620
         // 00418b40: push ebp
         // 00418b41: mov ebp, esp
         // 00418b43: push esi
         // 00418b44: mov esi, ss:[ebp+0x8]
         // 00418b47: mov eax, ds:[esi+0x20]
      [-]0083c404
         // 0041a305: add esp, 0x4
      [-]0083c404
         // 0041a36b: add esp, 0x4
      [-]558bec8b5508b9
         // 00516de0: push ebp
         // 00516de1: mov ebp, esp
         // 00516de3: mov edx, ss:[ebp+0x8]
         // 00516de6: mov ecx, 0x559c01
      [-]005356578b4208bf
         // 00516deb: push ebx
         // 00516dec: push esi
         // 00516ded: push edi
         // 00516dee: mov eax, ds:[edx+0x8]
         // 00516df1: mov edi, 0x5595ac
      [-]000f45c88b420c
         // 00516dfd: cmovnz ecx, eax
         // 00516e00: mov eax, ds:[edx+0xc]
      [-]0f45f88b4210
         // 00516e05: cmovnz edi, eax
         // 00516e08: mov eax, ds:[edx+0x10]
      [-]0f45d8837a2400740e
         // 00516e0d: cmovnz ebx, eax
         // 00516e10: cmp ds:[edx+0x24], 0x0
         // 00516e14: jz 0x516e24
      [-]80382ebe
         // 0041a3ba: cmp b1 ds:[eax], b1 0x2e
         // 0041a3bd: mov esi, 0x45d5c4
      [-]837a300051ff7204b9
         // 0041a3c9: cmp ds:[edx+0x30], 0x0
         // 0041a3cd: push ecx
         // 0041a3ce: push ds:[edx+0x4]
         // 0041a3d1: mov ecx, 0x45d540
      [-]00c74508
         // 0041a3d6: mov ss:[ebp+0x8], 0x45d548
      [-]00ff721c
         // 0041a3dd: push ds:[edx+0x1c]
      [-]ff72180f444508837a2400500f444d08b8
         // 0041a3e2: push ds:[edx+0x18]
         // 0041a3e5: cmovz eax, ss:[ebp+0x8]
         // 0041a3e9: cmp ds:[edx+0x24], 0x0
         // 0041a3ed: push eax
         // 0041a3ee: cmovz ecx, ss:[ebp+0x8]
         // 0041a3f2: mov eax, 0x45d530
      [-]00837a3800575153b9
         // 0041a3f7: cmp ds:[edx+0x38], 0x0
         // 0041a3fb: push edi
         // 0041a3fc: push ecx
         // 0041a3fd: push ebx
         // 0041a3fe: mov ecx, 0x45d470
      [-]00560f44c15068
         // 0041a403: push esi
         // 0041a404: cmovz eax, ecx
         // 0041a407: push eax
         // 0041a408: push 0x45d5c8
      [-]83c42c5f5e5b5dc3
         // 0041a412: add esp, 0x2c
         // 0041a415: pop edi
         // 0041a416: pop esi
         // 0041a417: pop ebx
         // 0041a418: pop ebp
         // 0041a419: retn 
      [-]558bec568b75088b06
         // 00418ca0: push ebp
         // 00418ca1: mov ebp, esp
         // 00418ca3: push esi
         // 00418ca4: mov esi, ss:[ebp+0x8]
         // 00418ca7: mov eax, ds:[esi]
      [-]0083c404
         // 0041a464: add esp, 0x4
      [-]ff750cff15
         // 0041a467: push ss:[ebp+0xc]
         // 0041a46a: call ds:[0x607980]
      [-]0083c40489065e5dc3
         // 0041a470: add esp, 0x4
         // 0041a473: mov ds:[esi], eax
         // 0041a475: pop esi
         // 0041a476: pop ebp
         // 0041a477: retn 
      [-]558bec8b55088d4a010f1f8000000000
         // 00418cd0: push ebp
         // 00418cd1: mov ebp, esp
         // 00418cd3: mov edx, ss:[ebp+0x8]
         // 00418cd6: lea ecx, ds:[edx+0x1]
         // 00418cd9: nop ds:[eax+0x0]
      [-]8a024284c075f9
         // 00418ce0: mov b1 al, b1 ds:[edx]
         // 00418ce2: inc edx
         // 00418ce3: test b1 al, b1 al
         // 00418ce5: jnz 0x418ce0
      [-]2bd18b4d0c538d5901
         // 00418ce7: sub edx, ecx
         // 00418ce9: mov ecx, ss:[ebp+0xc]
         // 00418cec: push ebx
         // 00418ced: lea ebx, ds:[ecx+0x1]
      [-]8a014184c075f9
         // 00418cf0: mov b1 al, b1 ds:[ecx]
         // 00418cf2: inc ecx
         // 00418cf3: test b1 al, b1 al
         // 00418cf5: jnz 0x418cf0
      [-]2bcb5b3bd17604
         // 00418cf7: sub ecx, ebx
         // 00418cf9: pop ebx
         // 00418cfa: cmp edx, ecx
         // 00418cfc: jbe 0x418d02
      [-]2bca034d0c51ff7508e8
         // 0051b6c2: sub ecx, edx
         // 0051b6c4: add ecx, ss:[ebp+0xc]
         // 0051b6c7: push ecx
         // 0051b6c8: push ss:[ebp+0x8]
         // 0051b6cb: call 0x527300
      [-]558bec538b5d1056578b7d08ff77108b470453ff750cffd08b0f83c40c8b04818945088b30
         // 00418d20: push ebp
         // 00418d21: mov ebp, esp
         // 00418d23: push ebx
         // 00418d24: mov ebx, ss:[ebp+0x10]
         // 00418d27: push esi
         // 00418d28: push edi
         // 00418d29: mov edi, ss:[ebp+0x8]
         // 00418d2c: push ds:[edi+0x10]
         // 00418d2f: mov eax, ds:[edi+0x4]
         // 00418d32: push ebx
         // 00418d33: push ss:[ebp+0xc]
         // 00418d36: call eax
         // 00418d38: mov ecx, ds:[edi]
         // 00418d3a: add esp, 0xc
         // 00418d3d: mov eax, ds:[ecx+eax*0x4]
         // 00418d40: mov ss:[ebp+0x8], eax
         // 00418d43: mov esi, ds:[eax]
      [-]0f1f8000000000
         // 00418d49: nop ds:[eax+0x0]
      [-]8b0653ff750cff7008ff70048b4708ffd083c410
         // 00418d50: mov eax, ds:[esi]
         // 00418d52: push ebx
         // 00418d53: push ss:[ebp+0xc]
         // 00418d56: push ds:[eax+0x8]
         // 00418d59: push ds:[eax+0x4]
         // 00418d5c: mov eax, ds:[edi+0x8]
         // 00418d5f: call eax
         // 00418d61: add esp, 0x10
      [-]5756ff7508e8
         // 00516f51: push edi
         // 00516f52: push esi
         // 00516f53: push ss:[ebp+0x8]
         // 00516f56: call 0x522ea0
      [-]000083c40cff4f14
         // 00516f5b: add esp, 0xc
         // 00516f5e: dec ds:[edi+0x14]
      [-]ff751453ff750ce843040000
         // 00418d81: push ss:[ebp+0x14]
         // 00418d84: push ebx
         // 00418d85: push ss:[ebp+0xc]
         // 00418d88: call 0x4191d0
      [-]8b450856ff700450e8
         // 0051b756: mov eax, ss:[ebp+0x8]
         // 0051b759: push esi
         // 0051b75a: push ds:[eax+0x4]
         // 0051b75d: push eax
         // 0051b75e: call 0x5275c0
      [-]000083c40c
         // 0051b763: add esp, 0xc
      [-]ff47148b45145f5e5b5dc3
         // 00418daa: inc ds:[edi+0x14]
         // 00418dad: mov eax, ss:[ebp+0x14]
         // 00418db0: pop edi
         // 00418db1: pop esi
         // 00418db2: pop ebx
         // 00418db3: pop ebp
         // 00418db4: retn 
      [-]ff7604ff15
         // 0041a565: push ds:[esi+0x4]
         // 0041a568: call ds:[0x607978]
      [-]0056ff15
         // 0041a56e: push esi
         // 0041a56f: call ds:[0x607978]
      [-]0083c408
         // 0041a575: add esp, 0x8
      [-]558bec568b750857
         // 00418e30: push ebp
         // 00418e31: mov ebp, esp
         // 00418e33: push esi
         // 00418e34: mov esi, ss:[ebp+0x8]
         // 00418e37: push edi
      [-]397e107e1e
         // 00418e3a: cmp ds:[esi+0x10], edi
         // 00418e3d: jle 0x418e5d
      [-]8b0656ff34b8e8
         // 00517020: mov eax, ds:[esi]
         // 00517022: push esi
         // 00517023: push ds:[eax+edi*0x4]
         // 00517026: call 0x522dc0
      [-]00008b0683c408c704b800000000473b7e107ce3
         // 0051702b: mov eax, ds:[esi]
         // 0051702d: add esp, 0x8
         // 00517030: mov ds:[eax+edi*0x4], 0x0
         // 00517037: inc edi
         // 00517038: cmp edi, ds:[esi+0x10]
         // 0051703b: jl 0x517020
      [-]ff36ff15
         // 0041a60d: push ds:[esi]
         // 0041a60f: call ds:[0x607978]
      [-]0083c404c70600000000c7461400000000c74610000000005f5e5dc3
         // 0041a615: add esp, 0x4
         // 0041a618: mov ds:[esi], 0x0
         // 0041a61e: mov ds:[esi+0x14], 0x0
         // 0041a625: mov ds:[esi+0x10], 0x0
         // 0041a62c: pop edi
         // 0041a62d: pop esi
         // 0041a62e: pop ebp
         // 0041a62f: retn 
      [-]558bec5157
         // 0051b840: push ebp
         // 0051b841: mov ebp, esp
         // 0051b843: push ecx
         // 0051b844: push edi
      [-]8b078b04888945088b30
         // 00418e94: mov eax, ds:[edi]
         // 00418e96: mov eax, ds:[eax+ecx*0x4]
         // 00418e99: mov ss:[ebp+0x8], eax
         // 00418e9c: mov esi, ds:[eax]
      [-]8b068b5e08ff30ff750cff551083c408
         // 00418ea2: mov eax, ds:[esi]
         // 00418ea4: mov ebx, ds:[esi+0x8]
         // 00418ea7: push ds:[eax]
         // 00418ea9: push ss:[ebp+0xc]
         // 00418eac: call ss:[ebp+0x10]
         // 00418eaf: add esp, 0x8
      [-]5756ff7508e8
         // 00517096: push edi
         // 00517097: push esi
         // 00517098: push ss:[ebp+0x8]
         // 0051709b: call 0x522ea0
      [-]000083c40cff4f14
         // 005170a0: add esp, 0xc
         // 005170a3: dec ds:[edi+0x14]
      [-]41894dfc3b4f107cbc
         // 00418ecf: inc ecx
         // 00418ed0: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00418ed3: cmp ecx, ds:[edi+0x10]
         // 00418ed6: jl 0x418e94
      [-]5f8be55dc3
         // 00418eda: pop edi
         // 00418edb: mov esp, ebp
         // 00418edd: pop ebp
         // 00418ede: retn 
      [-]558bec538b5d1056578b7d08
         // 0051b8a0: push ebp
         // 0051b8a1: mov ebp, esp
         // 0051b8a3: push ebx
         // 0051b8a4: mov ebx, ss:[ebp+0x10]
         // 0051b8a7: push esi
         // 0051b8a8: push edi
         // 0051b8a9: mov edi, ss:[ebp+0x8]
      [-]558bec568b7508
         // 00418f50: push ebp
         // 00418f51: mov ebp, esp
         // 00418f53: push esi
         // 00418f54: mov esi, ss:[ebp+0x8]
      [-]56e8cffeffff56ff15
         // 0041a70b: push esi
         // 0041a70c: call 0x41a5e0
         // 0041a711: push esi
         // 0041a712: call ds:[0x607978]
      [-]0083c408
         // 0041a718: add esp, 0x8
      [-]558bec538b5d085657ff73108b4304ff7510ff750cffd08b0b83c40c8b34818b36
         // 00419060: push ebp
         // 00419061: mov ebp, esp
         // 00419063: push ebx
         // 00419064: mov ebx, ss:[ebp+0x8]
         // 00419067: push esi
         // 00419068: push edi
         // 00419069: push ds:[ebx+0x10]
         // 0041906c: mov eax, ds:[ebx+0x4]
         // 0041906f: push ss:[ebp+0x10]
         // 00419072: push ss:[ebp+0xc]
         // 00419075: call eax
         // 00419077: mov ecx, ds:[ebx]
         // 00419079: add esp, 0xc
         // 0041907c: mov esi, ds:[ecx+eax*0x4]
         // 0041907f: mov esi, ds:[esi]
      [-]ff75108b3eff750c8b4308ff7708ff7704ffd083c410
         // 00419085: push ss:[ebp+0x10]
         // 00419088: mov edi, ds:[esi]
         // 0041908a: push ss:[ebp+0xc]
         // 0041908d: mov eax, ds:[ebx+0x8]
         // 00419090: push ds:[edi+0x8]
         // 00419093: push ds:[edi+0x4]
         // 00419096: call eax
         // 00419098: add esp, 0x10
      [-]8b075f5e5b5dc3
         // 004190ad: mov eax, ds:[edi]
         // 004190af: pop edi
         // 004190b0: pop esi
         // 004190b1: pop ebx
         // 004190b2: pop ebp
         // 004190b3: retn 
      [-]558bec814508a8030000
         // 0051bbf0: push ebp
         // 0051bbf1: mov ebp, esp
         // 0051bbf3: add ss:[ebp+0x8], 0x3a8
      [-]558bec83ec50a1
         // 00517420: push ebp
         // 00517421: mov ebp, esp
         // 00517423: sub esp, 0x50
         // 00517426: mov eax, ds:[___security_cookie]
      [-]0033c58945fc8b4514538b5d10568b750c578b7d088945d4c700000000008d45d850566a02e8
         // 0051742b: xor eax, ebp
         // 0051742d: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00517430: mov eax, ss:[ebp+0x14]
         // 00517433: push ebx
         // 00517434: mov ebx, ss:[ebp+0x10]
         // 00517437: push esi
         // 00517438: mov esi, ss:[ebp+0xc]
         // 0051743b: push edi
         // 0051743c: mov edi, ss:[ebp+0x8]
         // 0051743f: mov ss:[ebp+0xffffffffffffffd4], eax
         // 00517442: mov ds:[eax], 0x0
         // 00517448: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 0051744b: push eax
         // 0051744c: push esi
         // 0051744d: push 0x2
         // 0051744f: call 0x524080
      [-]000083c40c53
         // 00517454: add esp, 0xc
         // 00517457: push ebx
      [-]568d45d8506a02e8
         // 00417728: push esi
         // 00417729: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 0041772c: push eax
         // 0041772d: push 0x2
         // 0041772f: call 0x42404c
      [-]000083c4105f5e5b8b4dfc33cde8
         // 00417734: add esp, 0x10
         // 00417737: pop edi
         // 00417738: pop esi
         // 00417739: pop ebx
         // 0041773a: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0041773d: xor ecx, ebp
         // 0041773f: call @__security_check_cookie@4
      [-]8be55dc3
         // 00417744: mov esp, ebp
         // 00417746: pop ebp
         // 00417747: retn 
      [-]8b47740f57c00f1145b068
         // 0051bc5c: mov eax, ds:[edi+0x74]
         // 0051bc5f: xorps b16 xmm0, b16 xmm0
         // 0051bc62: movups b16 ss:[ebp+0xffffffffffffffb0], b16 xmm0
         // 0051bc66: push 0x5b5c94
      [-]008945b88d45dc6a20500f1145c0c745b402000000e8
         // 0051bc6b: mov ss:[ebp+0xffffffffffffffb8], eax
         // 0051bc6e: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 0051bc71: push 0x20
         // 0051bc73: push eax
         // 0051bc74: movups b16 ss:[ebp+0xffffffffffffffc0], b16 xmm0
         // 0051bc78: mov ss:[ebp+0xffffffffffffffb4], 0x2
         // 0051bc7f: call _snprintf
      [-]8d45b050535657e8
         // 0051bc84: lea eax, ss:[ebp+0xffffffffffffffb0]
         // 0051bc87: push eax
         // 0051bc88: push ebx
         // 0051bc89: push esi
         // 0051bc8a: push edi
         // 0051bc8b: call 0x51c090
      [-]04000083c420
         // 0051bc90: add esp, 0x20
      [-]8b45d45f5e5bc70001000000
         // 00417783: mov eax, ss:[ebp+0xffffffffffffffd4]
         // 00417786: pop edi
         // 00417787: pop esi
         // 00417788: pop ebx
         // 00417789: mov ds:[eax], 0x1
      [-]8b4dfc33cde8
         // 00417791: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00417794: xor ecx, ebp
         // 00417796: call @__security_check_cookie@4
      [-]8be55dc3
         // 0041779b: mov esp, ebp
         // 0041779d: pop ebp
         // 0041779e: retn 
      [-]005057e8
         // 0051bcb9: push eax
         // 0051bcba: push edi
         // 0051bcbb: call 0x526300
      [-]0000505668
         // 0051bcc0: push eax
         // 0051bcc1: push esi
         // 0051bcc2: push 0x6587c8
      [-]00ff37e8
         // 0051bcc7: push ds:[edi]
         // 0051bcc9: call 0x5188d0
      [-]45d0508d45b0508d45dc5056e8
         // 0051bcd1: push eax
         // 0051bcd2: lea eax, ss:[ebp+0xffffffffffffffb0]
         // 0051bcd5: push eax
         // 0051bcd6: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 0051bcd9: push eax
         // 0051bcda: push esi
         // 0051bcdb: call 0x527800
      [-]000083c428
         // 0051bce0: add esp, 0x28
      [-]005057e8
         // 0041981d: push eax
         // 0041981e: push edi
         // 0041981f: call 0x426e00
      [-]000050535668
         // 00419824: push eax
         // 00419825: push ebx
         // 00419826: push esi
         // 00419827: push 0x45c748
      [-]00ff37e8
         // 0041982c: push ds:[edi]
         // 0041982e: call 0x4225c0
      [-]5f5e5b8b4dfc33cde8
         // 00419838: pop edi
         // 00419839: pop esi
         // 0041983a: pop ebx
         // 0041983b: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0041983e: xor ecx, ebp
         // 00419840: call @__security_check_cookie@4
      [-]8be55dc3
         // 00419845: mov esp, ebp
         // 00419847: pop ebp
         // 00419848: retn 
      [-]8b4dfc8b45d033cd5f5e5be8
         // 00417805: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00417808: mov eax, ss:[ebp+0xffffffffffffffd0]
         // 0041780b: xor ecx, ebp
         // 0041780d: pop edi
         // 0041780e: pop esi
         // 0041780f: pop ebx
         // 00417810: call @__security_check_cookie@4
      [-]8be55dc3
         // 00417815: mov esp, ebp
         // 00417817: pop ebp
         // 00417818: retn 
      [-]558bec538b5d08578b038bbbbc0300008945088b450cc70000000000
         // 004193a0: push ebp
         // 004193a1: mov ebp, esp
         // 004193a3: push ebx
         // 004193a4: mov ebx, ss:[ebp+0x8]
         // 004193a7: push edi
         // 004193a8: mov eax, ds:[ebx]
         // 004193aa: mov edi, ds:[ebx+0x3bc]
         // 004193b0: mov ss:[ebp+0x8], eax
         // 004193b3: mov eax, ss:[ebp+0xc]
         // 004193b6: mov ds:[eax], 0x0
      [-]56ff7710ff15
         // 0041ab70: push esi
         // 0041ab71: push ds:[edi+0x10]
         // 0041ab74: call ds:[EnterCriticalSection]
      [-]558bec568b750857
         // 00517680: push ebp
         // 00517681: mov ebp, esp
         // 00517683: push esi
         // 00517684: mov esi, ss:[ebp+0x8]
         // 00517687: push edi
      [-]b6bc030000e8
         // 0051768a: push ds:[esi+0x3bc]
         // 00517690: call 0x5241b0
      [-]000083c404
         // 00517695: add esp, 0x4
      [-]56e85e010000
         // 0051be6c: push esi
         // 0051be6d: call 0x51bfd0
      [-]8b450cc786b403000001000000
         // 004194b7: mov eax, ss:[ebp+0xc]
         // 004194ba: mov ds:[esi+0x3b4], 0x1
      [-]8b8eb00300008908
         // 004194c8: mov ecx, ds:[esi+0x3b0]
         // 004194ce: mov ds:[eax], ecx
      [-]83beb003000000752e
         // 004194d0: cmp ds:[esi+0x3b0], 0x0
         // 004194d7: jnz 0x419507
      [-]83bea4010000007412
         // 004194d9: cmp ds:[esi+0x1a4], 0x0
         // 004194e0: jz 0x4194f4
      [-]0056e853030000
         // 0051bea7: push esi
         // 0051bea8: call 0x51c200
      [-]0056e841030000
         // 0051beb9: push esi
         // 0051beba: call 0x51c200
      [-]8d86a803000050e83d00000083c404
         // 00419507: lea eax, ds:[esi+0x3a8]
         // 0041950d: push eax
         // 0041950e: call 0x419550
         // 00419513: add esp, 0x4
      [-]83beb003000000750a
         // 00419518: cmp ds:[esi+0x3b0], 0x0
         // 0041951f: jnz 0x41952b
      [-]c7869801000001000000
         // 00419521: mov ds:[esi+0x198], 0x1
      [-]5f5e5dc3
         // 0041952b: pop edi
         // 0041952c: pop esi
         // 0041952d: pop ebp
         // 0041952e: retn 
      [-]558bec568b
         // 00419550: push ebp
         // 00419551: mov ebp, esp
         // 00419553: push esi
         // 00419558: mov eax, ds:[esi]
      [-]0083c404
         // 0041ad15: add esp, 0x4
      [-]8b470483f8ff7407
         // 0041956f: mov eax, ds:[edi+0x4]
         // 00419572: cmp eax, 0xffffffffffffffff
         // 00419575: jz 0x41957e
      [-]50ff1500
         // 0041ad27: push eax
         // 0041ad28: call ds:[closesocket]
      [-]833f007409
         // 0041957e: cmp ds:[edi], 0x0
         // 00419581: jz 0x41958c
      [-]000083c404
         // 0050b5a9: add esp, 0x4
      [-]8d471050e82b000000ff7614ff15
         // 0041ad3c: lea eax, ds:[edi+0x10]
         // 0041ad3f: push eax
         // 0041ad40: call 0x41ad70
         // 0041ad45: push ds:[esi+0x14]
         // 0041ad48: call ds:[0x607978]
      [-]0083c408
         // 0041ad4e: add esp, 0x8
      [-]06000000005e5dc3
         // 0050b5cf: pop esi
         // 0050b5d0: pop ebp
         // 0050b5d1: retn 
      [-]558bec568b75088b06
         // 004195c0: push ebp
         // 004195c1: mov ebp, esp
         // 004195c3: push esi
         // 004195c4: mov esi, ss:[ebp+0x8]
         // 004195c7: mov eax, ds:[esi]
      [-]00ff36ff15
         // 0041ad84: push ds:[esi]
         // 0041ad86: call ds:[0x607978]
      [-]0083c404
         // 0041ad8c: add esp, 0x4
      [-]0083c404
         // 0041ad9d: add esp, 0x4
      [-]6a386a0056e8
         // 0041adb0: push 0x38
         // 0041adb2: push 0x0
         // 0041adb4: push esi
         // 0041adb5: call _memset
      [-]83c40c5e5dc3
         // 0041adba: add esp, 0xc
         // 0041adbd: pop esi
         // 0041adbe: pop ebp
         // 0041adbf: retn 
      [-]558bec5356576a486a01ff15
         // 0051c090: push ebp
         // 0051c091: mov ebp, esp
         // 0051c093: push ebx
         // 0051c094: push esi
         // 0051c095: push edi
         // 0051c096: push 0x48
         // 0051c098: push 0x1
         // 0051c09a: call ds:[0x67b030]
      [-]008b7508
         // 0051c0a0: mov esi, ss:[ebp+0x8]
      [-]89bebc030000
         // 0051c0ad: mov ds:[esi+0x3bc], edi
      [-]0f84b1000000
         // 0051c0b5: jz 0x51c16c
      [-]ff75148b4d108d471051ff750c898eac030000c786b403000000000000c786b803000000000000c786b00300000000000050c74704ffffffffc70700000000e8a100000083c410
         // 004196fb: push ss:[ebp+0x14]
         // 004196fe: mov ecx, ss:[ebp+0x10]
         // 00419701: lea eax, ds:[edi+0x10]
         // 00419704: push ecx
         // 00419705: push ss:[ebp+0xc]
         // 00419708: mov ds:[esi+0x3ac], ecx
         // 0041970e: mov ds:[esi+0x3b4], 0x0
         // 00419718: mov ds:[esi+0x3b8], 0x0
         // 00419722: mov ds:[esi+0x3b0], 0x0
         // 0041972c: push eax
         // 0041972d: mov ds:[edi+0x4], 0xffffffffffffffff
         // 00419734: mov ds:[edi], 0x0
         // 0041973a: call 0x4197e0
         // 0041973f: add esp, 0x10
      [-]8b86a8030000
         // 00419746: mov eax, ds:[esi+0x3a8]
      [-]0083c404c786a803000000000000
         // 0041af07: add esp, 0x4
         // 0041af0a: mov ds:[esi+0x3a8], 0x0
      [-]ff750cff15
         // 0051c124: push ss:[ebp+0xc]
         // 0051c127: call ds:[0x67b02c]
      [-]0083c4048986a8030000
         // 0051c12d: add esp, 0x4
         // 0051c130: mov ds:[esi+0x3a8], eax
      [-]6a006a026a02ff15
         // 0050b79a: push 0x0
         // 0050b79c: push 0x2
         // 0050b79e: push 0x2
         // 0050b7a0: call ds:[socket]
      [-]0089470483f8ff741e
         // 0050b7a6: mov ds:[edi+0x4], eax
         // 0050b7a9: cmp eax, 0xffffffffffffffff
         // 0050b7ac: jz 0x50b7cc
      [-]8d47105068
         // 0051c14e: lea eax, ds:[edi+0x10]
         // 0051c151: push eax
         // 0051c152: push 0x51c000
      [-]000083c4088907
         // 0051c15c: add esp, 0x8
         // 0051c15f: mov ds:[edi], eax
      [-]8d86a803000050e898fdffff83c40453ff15
         // 0051c16c: lea eax, ds:[esi+0x3a8]
         // 0051c172: push eax
         // 0051c173: call 0x51bf10
         // 0051c178: add esp, 0x4
         // 0051c17b: push ebx
         // 0051c17c: call ds:[SetLastError]
      [-]558bec568b75086a386a0056e8
         // 00417c8c: push ebp
         // 00417c8d: mov ebp, esp
         // 00417c8f: push esi
         // 00417c90: mov esi, ss:[ebp+0x8]
         // 00417c93: push 0x38
         // 00417c95: push 0x0
         // 00417c97: push esi
         // 00417c98: call 0x43ecbc
      [-]8b45106a1889460cff15
         // 00417c9d: mov eax, ss:[ebp+0x10]
         // 00417ca0: push 0x18
         // 00417ca2: mov ds:[esi+0xc], eax
         // 00417ca5: call ds:[0x606664]
      [-]0083c4108906
         // 00417cab: add esp, 0x10
         // 00417cae: mov ds:[esi], eax
      [-]00ff750cc7461000000000ff15
         // 0051c1cf: push ss:[ebp+0xc]
         // 0051c1d2: mov ds:[esi+0x10], 0x0
         // 0051c1d9: call ds:[0x67b02c]
      [-]0083c404894608
         // 0051c1df: add esp, 0x4
         // 0051c1e2: mov ds:[esi+0x8], eax
      [-]56e889fdffff83c404
         // 00419831: push esi
         // 00419832: call 0x4195c0
         // 00419837: add esp, 0x4
      [-]558bec568b7508ffb6b803000056e8
         // 00419840: push ebp
         // 00419841: mov ebp, esp
         // 00419843: push esi
         // 00419844: mov esi, ss:[ebp+0x8]
         // 00419847: push ds:[esi+0x3b8]
         // 0041984d: push esi
         // 0041984e: call 0x426910
      [-]000050ffb6a8030000ff750c68
         // 00419853: push eax
         // 00419854: push ds:[esi+0x3a8]
         // 0041985a: push ss:[ebp+0xc]
         // 0041985d: push 0x45c6dc
      [-]00ff36e8
         // 00419862: push ds:[esi]
         // 00419864: call 0x422030
      [-]83c41c5e5dc3
         // 00419869: add esp, 0x1c
         // 0041986c: pop esi
         // 0041986d: pop ebp
         // 0041986e: retn 
      [-]00007417
         // 0041b0e7: jz 0x41b100
      [-]f4ffff83c404c705
         // 0051c303: add esp, 0x4
         // 0051c306: mov ds:[0x6816f4], 0x0
      [-]0000000000
      [-]558bec83ec08568b750883be64020000ff7448
         // 004199b0: push ebp
         // 004199b1: mov ebp, esp
         // 004199b3: sub esp, 0x8
         // 004199b6: push esi
         // 004199b7: mov esi, ss:[ebp+0x8]
         // 004199ba: cmp ds:[esi+0x264], 0xffffffffffffffff
         // 004199c1: jz 0x419a0b
      [-]833e007443
         // 004199c3: cmp ds:[esi], 0x0
         // 004199c6: jz 0x419a0b
      [-]837e1000740d
         // 004199c8: cmp ds:[esi+0x10], 0x0
         // 004199cc: jz 0x4199db
      [-]6a026a0356e8
         // 0050b9ee: push 0x2
         // 0050b9f0: push 0x3
         // 0050b9f2: push esi
         // 0050b9f3: call 0x5168f0
      [-]000083c40c
         // 0050b9f8: add esp, 0xc
      [-]8d45f850e8
         // 00517bcb: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00517bce: push eax
         // 00517bcf: call __time64
      [-]ff75fcff75f8ffb664020000ff36e8f902000083c414837e1000740b
         // 00517bd4: push ss:[ebp+0xfffffffffffffffc]
         // 00517bd7: push ss:[ebp+0xfffffffffffffff8]
         // 00517bda: push ds:[esi+0x264]
         // 00517be0: push ds:[esi]
         // 00517be2: call 0x517ee0
         // 00517be7: add esp, 0x14
         // 00517bea: cmp ds:[esi+0x10], 0x0
         // 00517bee: jz 0x517bfb
      [-]6a0356e8
         // 0050ba20: push 0x3
         // 0050ba22: push esi
         // 0050ba23: call 0x516930
      [-]000083c408
         // 0050ba28: add esp, 0x8
      [-]5e8be55dc3
         // 00419a0b: pop esi
         // 00419a0c: mov esp, ebp
         // 00419a0e: pop ebp
         // 00419a0f: retn 
      [-]558bec8b4d08
         // 00419a30: push ebp
         // 00419a31: mov ebp, esp
         // 00419a33: mov ecx, ss:[ebp+0x8]
      [-]0f1f4000
         // 00419a3c: nop ds:[eax+0x0]
      [-]8b491c40
         // 00419a40: mov ecx, ds:[ecx+0x1c]
         // 00419a43: inc eax
      [-]558bec8b4d088b410483e8027404
         // 00419a50: push ebp
         // 00419a51: mov ebp, esp
         // 00419a53: mov ecx, ss:[ebp+0x8]
         // 00419a56: mov eax, ds:[ecx+0x4]
         // 00419a59: sub eax, 0x2
         // 00419a5c: jz 0x419a62
      [-]ff75108b4118ff750c83c004506a02e8
         // 00417f0e: push ss:[ebp+0x10]
         // 00417f11: mov eax, ds:[ecx+0x18]
         // 00417f14: push ss:[ebp+0xc]
         // 00417f17: add eax, 0x4
         // 00417f1a: push eax
         // 00417f1b: push 0x2
         // 00417f1d: call 0x42635c
      [-]000083c4105dc3
         // 00417f22: add esp, 0x10
         // 00417f25: pop ebp
         // 00417f26: retn 
      [-]558bec568b7508837e1000740d
         // 00419c40: push ebp
         // 00419c41: mov ebp, esp
         // 00419c43: push esi
         // 00419c44: mov esi, ss:[ebp+0x8]
         // 00419c47: cmp ds:[esi+0x10], 0x0
         // 00419c4b: jz 0x419c5a
      [-]6a026a0356e8
         // 0050bc6d: push 0x2
         // 0050bc6f: push 0x3
         // 0050bc71: push esi
         // 0050bc72: call 0x5168f0
      [-]000083c40c
         // 0050bc77: add esp, 0xc
      [-]578b7d0c834710ff7519
         // 00419c5a: push edi
         // 00419c5b: mov edi, ss:[ebp+0xc]
         // 00419c5e: add ds:[edi+0x10], 0xffffffffffffffff
         // 00419c62: jnz 0x419c7d
      [-]8b47080b470c7511
         // 00419c64: mov eax, ds:[edi+0x8]
         // 00419c67: or eax, ds:[edi+0xc]
         // 00419c6a: jnz 0x419c7d
      [-]000057ff15
         // 0041b423: push edi
         // 0041b424: call ds:[0x607978]
      [-]0083c408
         // 0041b42a: add esp, 0x8
      [-]837e10005f740b
         // 00419c7d: cmp ds:[esi+0x10], 0x0
         // 00419c81: pop edi
         // 00419c82: jz 0x419c8f
      [-]6a0356e8
         // 0050bca4: push 0x3
         // 0050bca6: push esi
         // 0050bca7: call 0x516930
      [-]000083c408
         // 0050bcac: add esp, 0x8
      [-]558bec83ec14a1
         // 0041819c: push ebp
         // 0041819d: mov ebp, esp
         // 0041819f: sub esp, 0x14
         // 004181a2: mov eax, ds:[___security_cookie]
      [-]0033c58945fc8b450c8b4d088945ec8b45108945f48b45148945f88d45ec68
         // 004181a7: xor eax, ebp
         // 004181a9: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004181ac: mov eax, ss:[ebp+0xc]
         // 004181af: mov ecx, ss:[ebp+0x8]
         // 004181b2: mov ss:[ebp+0xffffffffffffffec], eax
         // 004181b5: mov eax, ss:[ebp+0x10]
         // 004181b8: mov ss:[ebp+0xfffffffffffffff4], eax
         // 004181bb: mov eax, ss:[ebp+0x14]
         // 004181be: mov ss:[ebp+0xfffffffffffffff8], eax
         // 004181c1: lea eax, ss:[ebp+0xffffffffffffffec]
         // 004181c4: push 0x4181f0
      [-]005051e8
         // 004181c9: push eax
         // 004181ca: push ecx
         // 004181cb: call 0x41732c
      [-]f1ffff8b4dfc83c40c33cde8
         // 004181d0: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004181d3: add esp, 0xc
         // 004181d6: xor ecx, ebp
         // 004181d8: call @__security_check_cookie@4
      [-]8be55dc3
         // 004181dd: mov esp, ebp
         // 004181df: pop ebp
         // 004181e0: retn 
      [-]558bec8b45088b4d0c56578b78088b700c2b79088b001b710c993bf27c0f
         // 00419d40: push ebp
         // 00419d41: mov ebp, esp
         // 00419d43: mov eax, ss:[ebp+0x8]
         // 00419d46: mov ecx, ss:[ebp+0xc]
         // 00419d49: push esi
         // 00419d4a: push edi
         // 00419d4b: mov edi, ds:[eax+0x8]
         // 00419d4e: mov esi, ds:[eax+0xc]
         // 00419d51: sub edi, ds:[ecx+0x8]
         // 00419d54: mov eax, ds:[eax]
         // 00419d56: sbb esi, ds:[ecx+0xc]
         // 00419d59: cdq 
         // 00419d5a: cmp esi, edx
         // 00419d5c: jl 0x419d6d
      [-]3bf87209
         // 00419d60: cmp edi, eax
         // 00419d62: jb 0x419d6d
      [-]558bec83ec14a1
         // 0041b530: push ebp
         // 0041b531: mov ebp, esp
         // 0041b533: sub esp, 0x14
         // 0041b536: mov eax, ds:[___security_cookie]
      [-]0033c58945fc837d0c00568b7508745a
         // 0041b53b: xor eax, ebp
         // 0041b53d: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0041b540: cmp ss:[ebp+0xc], 0x0
         // 0041b544: push esi
         // 0041b545: mov esi, ss:[ebp+0x8]
         // 0041b548: jz 0x41b5a4
      [-]83be64020000ff7451
         // 00419d9a: cmp ds:[esi+0x264], 0xffffffffffffffff
         // 00419da1: jz 0x419df4
      [-]833e00744c
         // 00419da3: cmp ds:[esi], 0x0
         // 00419da6: jz 0x419df4
      [-]8d45f450e8
         // 00418254: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00418257: push eax
         // 00418258: call 0x448379
      [-]8b8664020000
         // 0041825d: mov eax, ds:[esi+0x264]
      [-]8945ec8d45ec50e87affffff83c40c
         // 00418266: mov ss:[ebp+0xffffffffffffffec], eax
         // 00418269: lea eax, ss:[ebp+0xffffffffffffffec]
         // 0041826c: push eax
         // 0041826d: call 0x4181ec
         // 00418272: add esp, 0xc
      [-]008d45ec50ff36e8
         // 0050bdf2: lea eax, ss:[ebp+0xffffffffffffffec]
         // 0050bdf5: push eax
         // 0050bdf6: push ds:[esi]
         // 0050bdf8: call 0x50aea0
      [-]f0ffff83c40c
         // 0050bdfd: add esp, 0xc
      [-]8be55dc3
         // 0050be10: mov esp, ebp
         // 0050be12: pop ebp
         // 0050be13: retn 
      [-]8b4dfc33
         // 00419df5: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00419df8: xor eax, eax
      [-]8be55dc3
         // 00419e01: mov esp, ebp
         // 00419e03: pop ebp
         // 00419e04: retn 
      [-]558bec83ec0c53578b7d08
         // 0050be30: push ebp
         // 0050be31: mov ebp, esp
         // 0050be33: sub esp, 0xc
         // 0050be36: push ebx
         // 0050be37: push edi
         // 0050be38: mov edi, ss:[ebp+0x8]
      [-]57c745fc00000000895df8c7872005000001000000e8
         // 0050be3d: push edi
         // 0050be3e: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 0050be45: mov ss:[ebp+0xfffffffffffffff8], ebx
         // 0050be48: mov ds:[edi+0x520], 0x1
         // 0050be52: call 0x50c5b0
      [-]07000083c404
         // 0050be57: add esp, 0x4
      [-]0f8500020000
         // 0050be5c: jnz 0x50c062
      [-]568d45fc5057e8
         // 0051c802: push esi
         // 0051c803: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0051c806: push eax
         // 0051c807: push edi
         // 0051c808: call 0x51dc50
      [-]5f5b8be55dc3
         // 0041a042: pop edi
         // 0041a043: pop ebx
         // 0041a044: mov esp, ebp
         // 0041a046: pop ebp
         // 0041a047: retn 
      [-]558bec83ec18a1
         // 0041b800: push ebp
         // 0041b801: mov ebp, esp
         // 0041b803: sub esp, 0x18
         // 0041b806: mov eax, ds:[___security_cookie]
      [-]0033c58945fc8b4d088b451053568b31578b7d0c8945ec83bee400000000740a
         // 0041b80b: xor eax, ebp
         // 0041b80d: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0041b810: mov ecx, ss:[ebp+0x8]
         // 0041b813: mov eax, ss:[ebp+0x10]
         // 0041b816: push ebx
         // 0041b817: push esi
         // 0041b818: mov esi, ds:[ecx]
         // 0041b81a: push edi
         // 0041b81b: mov edi, ss:[ebp+0xc]
         // 0041b81e: mov ss:[ebp+0xffffffffffffffec], eax
         // 0041b821: cmp ds:[esi+0xe4], 0x0
         // 0041b828: jz 0x41b834
      [-]83c7f48386dc0000000a
         // 0041a07a: add edi, 0xfffffffffffffff4
         // 0041a07d: add ds:[esi+0xdc], 0xa
      [-]ffb1840200008b8180020000576a01ffb6dc000000ffd0
         // 0041a084: push ds:[ecx+0x284]
         // 0041a08a: mov eax, ds:[ecx+0x280]
         // 0041a090: push edi
         // 0041a091: push 0x1
         // 0041a093: push ds:[esi+0xdc]
         // 0041a099: call eax
      [-]83c41081fb00000010752d
         // 0041a09d: add esp, 0x10
         // 0041a0a0: cmp ebx, 0x10000000
         // 0041a0a6: jnz 0x41a0d5
      [-]8b45ec83c4085f5ec70000000000
         // 005182a3: mov eax, ss:[ebp+0xffffffffffffffec]
         // 005182a6: add esp, 0x8
         // 005182a9: pop edi
         // 005182aa: pop esi
         // 005182ab: mov ds:[eax], 0x0
         // 005182b1: mov eax, 0x2a
      [-]5b8b4dfc33cde8
         // 005182b6: pop ebx
         // 005182b7: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 005182ba: xor ecx, ebp
         // 005182bc: call @__security_check_cookie@4
      [-]8be55dc3
         // 005182c1: mov esp, ebp
         // 005182c3: pop ebp
         // 005182c4: retn 
      [-]81fb010000107533
         // 0041a0d5: cmp ebx, 0x10000001
         // 0041a0db: jnz 0x41a110
      [-]838ec00000002083bee4000000007407
         // 0041a0dd: or ds:[esi+0xc0], 0x20
         // 0041a0e4: cmp ds:[esi+0xe4], 0x0
         // 0041a0eb: jz 0x41a0f4
      [-]8386dc000000f6
         // 0041a0ed: add ds:[esi+0xdc], 0xfffffffffffffff6
      [-]8b45ec5f5e5bc70000000000
         // 004185a0: mov eax, ss:[ebp+0xffffffffffffffec]
         // 004185a3: pop edi
         // 004185a4: pop esi
         // 004185a5: pop ebx
         // 004185a6: mov ds:[eax], 0x0
      [-]8b4dfc33cde8
         // 004185ae: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004185b1: xor ecx, ebp
         // 004185b3: call @__security_check_cookie@4
      [-]8be55dc3
         // 004185b8: mov esp, ebp
         // 004185ba: pop ebp
         // 004185bb: retn 
      [-]3bdf762d
         // 0041a110: cmp ebx, edi
         // 0041a112: jbe 0x41a141
      [-]8b45ec68
         // 0051cad4: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0051cad7: push 0x658840
      [-]0056c70000000000e8
         // 0051cadc: push esi
         // 0051cadd: mov ds:[eax], 0x0
         // 0051cae3: call 0x518830
      [-]5f5e5b8b4dfc33cde8
         // 0051caf0: pop edi
         // 0051caf1: pop esi
         // 0051caf2: pop ebx
         // 0051caf3: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0051caf6: xor ecx, ebp
         // 0051caf8: call @__security_check_cookie@4
      [-]8be55dc3
         // 0051cafd: mov esp, ebp
         // 0051caff: pop ebp
         // 0051cb00: retn 
      [-]83beec000000000f8591000000
         // 0041a141: cmp ds:[esi+0xec], 0x0
         // 0041a148: jnz 0x41a1df
      [-]83bee4000000000f8484000000
         // 0041a14e: cmp ds:[esi+0xe4], 0x0
         // 0041a155: jz 0x41a1df
      [-]83bee401000000b8
         // 0051cb1b: cmp ds:[esi+0x1e4], 0x0
         // 0051cb22: mov eax, 0x5f015c
      [-]000f45f88d45f0575368
         // 0051cb2c: cmovnz edi, eax
         // 0051cb2f: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0051cb32: push edi
         // 0051cb33: push ebx
         // 0051cb34: push 0x658864
      [-]006a0b50e8
         // 0051cb39: push 0xb
         // 0051cb3b: push eax
         // 0051cb3c: call _snprintf
      [-]2986dc00000003d8508945e88d45f050ffb6dc000000e8
         // 0051cb41: sub ds:[esi+0xdc], eax
         // 0051cb47: add ebx, eax
         // 0051cb49: push eax
         // 0051cb4a: mov ss:[ebp+0xffffffffffffffe8], eax
         // 0051cb4d: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0051cb50: push eax
         // 0051cb51: push ds:[esi+0xdc]
         // 0051cb57: call _memmove_0
      [-]83c4208d5101
         // 0051cb5e: add esp, 0x20
         // 0051cb61: lea edx, ds:[ecx+0x1]
      [-]8a014184c075f9
         // 0041a1a4: mov b1 al, b1 ds:[ecx]
         // 0041a1a6: inc ecx
         // 0041a1a7: test b1 al, b1 al
         // 0041a1a9: jnz 0x41a1a4
      [-]8b86dc0000002bca5103c35750e8
         // 0041a1ab: mov eax, ds:[esi+0xdc]
         // 0041a1b1: sub ecx, edx
         // 0041a1b3: push ecx
         // 0041a1b4: add eax, ebx
         // 0041a1b6: push edi
         // 0041a1b7: push eax
         // 0041a1b8: call _memmove_0
      [-]83c40c2b45e8750a
         // 0041a1bf: add esp, 0xc
         // 0041a1c2: sub eax, ss:[ebp+0xffffffffffffffe8]
         // 0041a1c5: jnz 0x41a1d1
      [-]c786c400000001000000
         // 0041a1c7: mov ds:[esi+0xc4], 0x1
      [-]8a074784c075f9
         // 0041a1d4: mov b1 al, b1 ds:[edi]
         // 0041a1d6: inc edi
         // 0041a1d7: test b1 al, b1 al
         // 0041a1d9: jnz 0x41a1d4
      [-]2bf903df
         // 0041a1db: sub edi, ecx
         // 0041a1dd: add ebx, edi
      [-]8b45ec8b4dfc5f5e891833cd
         // 0041868b: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0041868e: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00418691: pop edi
         // 00418692: pop esi
         // 00418693: mov ds:[eax], ebx
         // 00418695: xor ecx, ebp
      [-]8be55dc3
         // 0041869f: mov esp, ebp
         // 004186a1: pop ebp
         // 004186a2: retn 
      [-]558bec8b4d0c8b
         // 0041a480: push ebp
         // 0041a481: mov ebp, esp
         // 0041a483: mov ecx, ss:[ebp+0xc]
         // 0041a488: mov edx, ss:[ebp+0x10]
      [-]55100bc2535657745a
         // 0041a48b: or eax, edx
         // 0041a48d: push ebx
         // 0041a48e: push esi
         // 0041a48f: push edi
         // 0041a490: jz 0x41a4ec
      [-]8b75088bbe100200008b
         // 0041a492: mov esi, ss:[ebp+0x8]
         // 0041a495: mov edi, ds:[esi+0x210]
         // 0041a49d: mov ebx, ds:[esi+0x214]
      [-]9e140200000bc37445
         // 0041a4a3: or eax, ebx
         // 0041a4a5: jz 0x41a4ec
      [-]8b8608020000
         // 0041a4a7: mov eax, ds:[esi+0x208]
      [-]3bd37f36
         // 0041a4b2: cmp edx, ebx
         // 0041a4b4: jg 0x41a4ec
      [-]3bcf7730
         // 0041a4b8: cmp ecx, edi
         // 0041a4ba: ja 0x41a4ec
      [-]83c408c7869c86000001000000
         // 0051ce87: add esp, 0x8
         // 0051ce8a: mov ds:[esi+0x869c], 0x1
      [-]5f5e5b5dc3
         // 0051ce96: pop edi
         // 0051ce97: pop esi
         // 0051ce98: pop ebx
         // 0051ce99: pop ebp
         // 0051ce9a: retn 
      [-]3bd37c0d
         // 0041a4db: cmp edx, ebx
         // 0041a4dd: jl 0x41a4ec
      [-]3bcf7207
         // 0041a4e1: cmp ecx, edi
         // 0041a4e3: jb 0x41a4ec
      [-]558bec568b750883be00040000007516
         // 0041a580: push ebp
         // 0041a581: mov ebp, esp
         // 0041a583: push esi
         // 0041a584: mov esi, ss:[ebp+0x8]
         // 0041a587: cmp ds:[esi+0x400], 0x0
         // 0041a58e: jnz 0x41a5a6
      [-]8b861401000089
         // 0051cf66: mov eax, ds:[esi+0x114]
         // 0051cf6c: mov ds:[esi+0x85bc], eax
      [-]000089be1c01000089
         // 0051cf87: mov ds:[esi+0x11c], edi
         // 0051cf8d: mov ds:[esi+0x8548], edi
      [-]85000089be
         // 0051cf93: mov ds:[esi+0x8568], edi
      [-]86000089
         // 0051cf99: mov ds:[esi+0x8620], edi
         // 0051cf9f: mov ds:[esi+0x866c], edi
      [-]86000089beec850000
         // 0051cfa5: mov ds:[esi+0x85ec], edi
      [-]0083c40489beb8860000
         // 0041bda6: add esp, 0x4
         // 0041bda9: mov ds:[esi+0x86b8], edi
      [-]89beb886000039be100400007409
         // 0041a5ff: mov ds:[esi+0x86b8], edi
         // 0041a605: cmp ds:[esi+0x410], edi
         // 0041a60b: jz 0x41a616
      [-]e2ffff83c404
         // 00518803: add esp, 0x4
      [-]39be14040000740f
         // 0041a616: cmp ds:[esi+0x414], edi
         // 0041a61c: jz 0x41a62d
      [-]56e85c0d0000
         // 0050c64e: push esi
         // 0050c64f: call 0x50d3b0
      [-]e80377000056e8
         // 0050c668: call 0x513d70
         // 0050c66d: push esi
         // 0050c66e: call 0x51e310
      [-]000083c408
         // 00418b03: add esp, 0x8
      [-]8b86a0010000
         // 0041a65a: mov eax, ds:[esi+0x1a0]
      [-]000083c408
         // 00418b17: add esp, 0x8
      [-]5f5e5dc3
         // 0041a670: pop edi
         // 0041a671: pop esi
         // 0041a672: pop ebp
         // 0041a673: retn 
      [-]558bec8b450856578b30c780d80100000000000083a6c0000000fd83be30010000000f85c4000000
         // 0041a680: push ebp
         // 0041a681: mov ebp, esp
         // 0041a683: mov eax, ss:[ebp+0x8]
         // 0041a686: push esi
         // 0041a687: push edi
         // 0041a688: mov esi, ds:[eax]
         // 0041a68a: mov ds:[eax+0x1d8], 0x0
         // 0041a694: and ds:[esi+0xc0], 0xfffffffffffffffd
         // 0041a69b: cmp ds:[esi+0x130], 0x0
         // 0041a6a2: jnz 0x41a76c
      [-]83be18020000030f84b7000000
         // 0041a6a8: cmp ds:[esi+0x218], 0x3
         // 0041a6af: jz 0x41a76c
      [-]8b8634010000
         // 0041a6b5: mov eax, ds:[esi+0x134]
      [-]6a006a006a00ffb684010000ffd083c410
         // 0041a6bf: push 0x0
         // 0041a6c1: push 0x0
         // 0041a6c3: push 0x0
         // 0041a6c5: push ds:[esi+0x184]
         // 0041a6cb: call eax
         // 0041a6cd: add esp, 0x10
      [-]0f8494000000
         // 0041a6d2: jz 0x41a76c
      [-]5f5e5dc3
         // 0041be9c: pop edi
         // 0041be9d: pop esi
         // 0041be9e: pop ebp
         // 0041be9f: retn 
      [-]8b8668010000
         // 0041a6f0: mov eax, ds:[esi+0x168]
      [-]ffb6980100006a0156ffd0
         // 0041beaa: push ds:[esi+0x198]
         // 0041beb0: push 0x1
         // 0041beb2: push esi
         // 0041beb3: call eax
      [-]5f5e5dc3
         // 0051d0ee: pop edi
         // 0051d0ef: pop esi
         // 0051d0f0: pop ebp
         // 0051d0f1: retn 
      [-]81be54010000
         // 0041bee2: cmp ds:[esi+0x154], _fread
      [-]6a006a00ffb604010000e8
         // 0051892e: push 0x0
         // 00518930: push 0x0
         // 00518932: push ds:[esi+0x104]
         // 00518938: call _fseek
      [-]83c40c83f8ff7517
         // 0051893d: add esp, 0xc
         // 00518940: cmp eax, 0xffffffffffffffff
         // 00518943: jnz 0x51895c
      [-]5f5e5dc3
         // 0050c798: pop edi
         // 0050c799: pop esi
         // 0050c79a: pop ebp
         // 0050c79b: retn 
      [-]558bec83ec08538b5d085657c74508000000008b3b8b8b500400008d7718c78350040000000000008b96a8000000
         // 0041a780: push ebp
         // 0041a781: mov ebp, esp
         // 0041a783: sub esp, 0x8
         // 0041a786: push ebx
         // 0041a787: mov ebx, ss:[ebp+0x8]
         // 0041a78a: push esi
         // 0041a78b: push edi
         // 0041a78c: mov ss:[ebp+0x8], 0x0
         // 0041a793: mov edi, ds:[ebx]
         // 0041a795: mov ecx, ds:[ebx+0x450]
         // 0041a79b: lea esi, ds:[edi+0x18]
         // 0041a79e: mov ds:[ebx+0x450], 0x0
         // 0041a7a8: mov edx, ds:[esi+0xa8]
      [-]2415894df83c01750b
         // 0041a7b0: and b1 al, b1 0x15
         // 0041a7b2: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 0041a7b5: cmp b1 al, b1 0x1
         // 0041a7b7: jnz 0x41a7c4
      [-]8b831c0200008945fceb07
         // 0041a7b9: mov eax, ds:[ebx+0x21c]
         // 0041a7bf: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0041a7c2: jmp 0x41a7cb
      [-]c745fcffffffff
         // 0041a7c4: mov ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
      [-]80e22a80fa027508
         // 0041a7cb: and b1 dl, b1 0x2a
         // 0041a7ce: cmp b1 dl, b1 0x2
         // 0041a7d1: jnz 0x41a7db
      [-]8b8320020000eb03
         // 0041a7d3: mov eax, ds:[ebx+0x220]
         // 0041a7d9: jmp 0x41a7de
      [-]5150ff75fce8
         // 0051d1a2: push ecx
         // 0051d1a3: push eax
         // 0051d1a4: push ss:[ebp+0xfffffffffffffffc]
         // 0051d1a7: call 0x52fc50
      [-]83c40c894df8
         // 0051d1ae: add esp, 0xc
         // 0051d1b1: mov ss:[ebp+0xfffffffffffffff8], ecx
      [-]83f904751a
         // 0041a7f4: cmp ecx, 0x4
         // 0041a7f7: jnz 0x41a813
      [-]5f5e5b8be55dc3
         // 0041bfbc: pop edi
         // 0041bfbd: pop esi
         // 0041bfbe: pop ebx
         // 0041bfbf: mov esp, ebp
         // 0041bfc1: pop ebp
         // 0041bfc2: retn 
      [-]f686a8000000017436
         // 0041a813: test b1 ds:[esi+0xa8], b1 0x1
         // 0041a81a: jz 0x41a852
      [-]f6c1017509
         // 0041a81c: test b1 cl, b1 0x1
         // 0041a81f: jnz 0x41a82a
      [-]83bbf0010000007428
         // 0041a821: cmp ds:[ebx+0x1f0], 0x0
         // 0041a828: jz 0x41a852
      [-]ff750c8d450850565357e8b70c000083c414
         // 0041a82a: push ss:[ebp+0xc]
         // 0041a82d: lea eax, ss:[ebp+0x8]
         // 0041a830: push eax
         // 0041a831: push esi
         // 0041a832: push ebx
         // 0041a833: push edi
         // 0041a834: call 0x41b4f0
         // 0041a839: add esp, 0x14
      [-]0f8530020000
         // 0041a83e: jnz 0x41aa74
      [-]8b4d0c39010f8525020000
         // 0041a844: mov ecx, ss:[ebp+0xc]
         // 0041a847: cmp ds:[ecx], eax
         // 0041a849: jnz 0x41aa74
      [-]8b86a800000023c1a8027417
         // 0041a852: mov eax, ds:[esi+0xa8]
         // 0041a858: and eax, ecx
         // 0041a85a: test b1 al, b1 0x2
         // 0041a85c: jz 0x41a875
      [-]8d450850565357e85613000083c410
         // 0041a85e: lea eax, ss:[ebp+0x8]
         // 0041a861: push eax
         // 0041a862: push esi
         // 0041a863: push ebx
         // 0041a864: push edi
         // 0041a865: call 0x41bbc0
         // 0041a86a: add esp, 0x10
      [-]0f85ff010000
         // 0041a86f: jnz 0x41aa74
      [-]0000837d08008946408956447426
         // 00518a6a: cmp ss:[ebp+0x8], 0x0
         // 00518a6e: mov ds:[esi+0x40], eax
         // 00518a71: mov ds:[esi+0x44], edx
         // 00518a74: jz 0x518a9c
      [-]8b462089018b4624894104
         // 0041a88d: mov eax, ds:[esi+0x20]
         // 0041a890: mov ds:[ecx], eax
         // 0041a892: mov eax, ds:[esi+0x24]
         // 0041a895: mov ds:[ecx+0x4], eax
      [-]8b462889018b462c894104eb42
         // 0041a89f: mov eax, ds:[esi+0x28]
         // 0041a8a2: mov ds:[ecx], eax
         // 0041a8a4: mov eax, ds:[esi+0x2c]
         // 0041a8a7: mov ds:[ecx+0x4], eax
         // 0041a8aa: jmp 0x41a8ee
      [-]83be84000000017539
         // 0041a8ac: cmp ds:[esi+0x84], 0x1
         // 0041a8b3: jnz 0x41a8ee
      [-]ffb680000000ff767c5250e8
         // 00518aa5: push ds:[esi+0x80]
         // 00518aab: push ds:[esi+0x7c]
         // 00518aae: push edx
         // 00518aaf: push eax
         // 00518ab0: call 0x522f50
      [-]000083c4103de80300007e1f
         // 00518ab5: add esp, 0x10
         // 00518ab8: cmp eax, 0x3e8
         // 00518abd: jle 0x518ade
      [-]838ea80000000268
         // 00418d7b: or ds:[esi+0xa8], 0x2
         // 00418d82: push 0x45ab88
      [-]0057c7868400000000000000e8
         // 00418d87: push edi
         // 00418d88: mov ds:[esi+0x84], 0x0
         // 00418d92: call 0x42057c
      [-]010083c404
         // 0051d2b4: add esp, 0x4
      [-]0f8550010000
         // 0051d2b9: jnz 0x51d40f
      [-]ff7644ff764057e8
         // 0051d2bf: push ds:[esi+0x44]
         // 0051d2c2: push ds:[esi+0x40]
         // 0051d2c5: push edi
         // 0051d2c6: call 0x52ea30
      [-]010083c40c
         // 0051d2cb: add esp, 0xc
      [-]0f855e010000
         // 0051d2d0: jnz 0x51d434
      [-]3986a80000000f849a000000
         // 0041a916: cmp ds:[esi+0xa8], eax
         // 0041a91c: jz 0x41a9bc
      [-]508d5e405357e8
         // 0051d2e2: push eax
         // 0051d2e3: lea ebx, ds:[esi+0x40]
         // 0051d2e6: push ebx
         // 0051d2e7: push edi
         // 0051d2e8: call 0x524ab0
      [-]000083c40c
         // 0051d2ed: add esp, 0xc
      [-]0f8923010000
         // 0051d2f2: jns 0x51d41b
      [-]4e0423c183f8ff743c
         // 0041a93f: and eax, ecx
         // 0041a941: cmp eax, 0xffffffffffffffff
         // 0041a944: jz 0x41a982
      [-]5152ff7624ff7620ffb7b4040000ffb7b0040000ff7304ff33e8
         // 0041c0f6: push ecx
         // 0041c0f7: push edx
         // 0041c0f8: push ds:[esi+0x24]
         // 0041c0fb: push ds:[esi+0x20]
         // 0041c0fe: push ds:[edi+0x4b4]
         // 0041c104: push ds:[edi+0x4b0]
         // 0041c10a: push ds:[ebx+0x4]
         // 0041c10d: push ds:[ebx]
         // 0041c10f: call 0x426f60
      [-]000083c4105068
         // 0041c114: add esp, 0x10
         // 0041c117: push eax
         // 0041c118: push 0x45db88
      [-]5f5e5b8be55dc3
         // 0041c12b: pop edi
         // 0041c12c: pop esi
         // 0041c12d: pop ebx
         // 0041c12e: mov esp, ebp
         // 0041c130: pop ebp
         // 0041c131: retn 
      [-]ff7624ff7620ffb7b4040000ffb7b0040000ff7304ff33e8
         // 0041c132: push ds:[esi+0x24]
         // 0041c135: push ds:[esi+0x20]
         // 0041c138: push ds:[edi+0x4b4]
         // 0041c13e: push ds:[edi+0x4b0]
         // 0041c144: push ds:[ebx+0x4]
         // 0041c147: push ds:[ebx]
         // 0041c149: call 0x426f60
      [-]000083c4105068
         // 0041c14e: add esp, 0x10
         // 0041c151: push eax
         // 0041c152: push 0x45dbd8
      [-]0057e883
         // 0041c157: push edi
         // 0041c158: call 0x4237e0
      [-]5f5e5b8be55dc3
         // 0041c165: pop edi
         // 0041c166: pop esi
         // 0041c167: pop ebx
         // 0041c168: mov esp, ebp
         // 0041c16a: pop ebp
         // 0041c16b: retn 
      [-]8b87d4020000
         // 0041a9bc: mov eax, ds:[edi+0x2d4]
      [-]4e0423c183f8ff743c
         // 0041a9cd: and eax, ecx
         // 0041a9cf: cmp eax, 0xffffffffffffffff
         // 0041a9d2: jz 0x41aa10
      [-]8b46208945088b46243956207504
         // 0041a9d4: mov eax, ds:[esi+0x20]
         // 0041a9d7: mov ss:[ebp+0x8], eax
         // 0041a9da: mov eax, ds:[esi+0x24]
         // 0041a9dd: cmp ds:[esi+0x20], edx
         // 0041a9e0: jnz 0x41a9e6
      [-]3bc1742a
         // 0041a9e2: cmp eax, ecx
         // 0041a9e4: jz 0x41aa10
      [-]8b87d4020000
         // 0041aa10: mov eax, ds:[edi+0x2d4]
      [-]3986c80000007420
         // 0041aa1a: cmp ds:[esi+0xc8], eax
         // 0041aa20: jz 0x41aa42
      [-]837b1c08741a
         // 0041aa22: cmp ds:[ebx+0x1c], 0x8
         // 0041aa26: jz 0x41aa42
      [-]5f5e5b8be55dc3
         // 0041c1eb: pop edi
         // 0041c1ec: pop esi
         // 0041c1ed: pop ebx
         // 0041c1ee: mov esp, ebp
         // 0041c1f0: pop ebp
         // 0041c1f1: retn 
      [-]010083c404
         // 0051d408: add esp, 0x4
      [-]5b8be55dc3
         // 0041aa56: pop ebx
         // 0041aa57: mov esp, ebp
         // 0041aa59: pop ebp
         // 0041aa5a: retn 
      [-]f786a800000033000000
         // 0041aa5b: test ds:[esi+0xa8], 0x33
      [-]8b4d0c0f94c08901
         // 0041aa6a: mov ecx, ss:[ebp+0xc]
         // 0041aa6d: setz b1 al
         // 0041aa70: mov ds:[ecx], eax
      [-]5f5e5b8be55dc3
         // 0041aa74: pop edi
         // 0041aa75: pop esi
         // 0041aa76: pop ebx
         // 0041aa77: mov esp, ebp
         // 0041aa79: pop ebp
         // 0041aa7a: retn 
      [-]558bec83ec08568b75085768
         // 0050cab0: push ebp
         // 0050cab1: mov ebp, esp
         // 0050cab3: sub esp, 0x8
         // 0050cab6: push esi
         // 0050cab7: mov esi, ss:[ebp+0x8]
         // 0050caba: push edi
         // 0050cabb: push 0x6355d4
      [-]008b068945088b3857e8
         // 0050cac0: mov eax, ds:[esi]
         // 0050cac2: mov ss:[ebp+0x8], eax
         // 0050cac5: mov edi, ds:[eax]
         // 0050cac7: push edi
         // 0050cac8: call 0x507f30
      [-]8b45086a006a00c78098010000010000008d450850e86921000083c414
         // 0050cacd: mov eax, ss:[ebp+0x8]
         // 0050cad0: push 0x0
         // 0050cad2: push 0x0
         // 0050cad4: mov ds:[eax+0x198], 0x1
         // 0050cade: lea eax, ss:[ebp+0x8]
         // 0050cae1: push eax
         // 0050cae2: call 0x50ec50
         // 0050cae7: add esp, 0x14
      [-]83f8377544
         // 0041aabe: cmp eax, 0x37
         // 0041aac1: jnz 0x41ab07
      [-]8d45fcc745fc01000000508d45f8505657e8171e0000
         // 0041aac3: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0041aac6: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 0041aacd: push eax
         // 0041aace: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0041aad1: push eax
         // 0041aad2: push esi
         // 0041aad3: push edi
         // 0041aad4: call 0x41c8f0
         // 0041aad9: add esp, 0x10

  }
  condition:
    all of them
}
