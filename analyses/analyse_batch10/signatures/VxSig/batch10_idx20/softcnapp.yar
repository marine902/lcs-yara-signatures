rule softcnapp_10_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         000033c0c3
         // 00415448: xor eax, eax
         // 0041544a: retn 
      [-]33c03905
         // 00415d6a: xor eax, eax
         // 00415d6c: cmp ds:[0x6073ec], eax
      [-]0f94c0c3
         // 00415d72: setz b1 al
         // 00415d75: retn 
      [-]8b3e85ff74
         // 00444665: mov edi, ds:[esi]
         // 00444667: test edi, edi
         // 00444669: jz 0x444674
      [-]83c6043bf372
         // 00444674: add esi, 0x4
         // 00444677: cmp esi, ebx
         // 00444679: jb 0x444665
      [-]8b3e85ff74
         // 00444690: mov edi, ds:[esi]
         // 00444692: test edi, edi
         // 00444694: jz 0x44469f
      [-]83c6043bf372
         // 0044469f: add esi, 0x4
         // 004446a2: cmp esi, ebx
         // 004446a4: jb 0x444690
      [-]558bec8b4d088b450c89410885c07506
         // 004cb850: push ebp
         // 004cb851: mov ebp, esp
         // 004cb853: mov ecx, ss:[ebp+0x8]
         // 004cb856: mov eax, ss:[ebp+0xc]
         // 004cb859: mov ds:[ecx+0x8], eax
         // 004cb85c: test eax, eax
         // 004cb85e: jnz 0x4cb866
      [-]8981????????
         // 004cb860: mov ds:[ecx+0x520], eax
      [-]558bec568b750868????????6a008d461850e8
         // 00416010: push ebp
         // 00416011: mov ebp, esp
         // 00416013: push esi
         // 00416014: mov esi, ss:[ebp+0x8]
         // 00416017: push 0xd8
         // 0041601c: push 0x0
         // 0041601e: lea eax, ds:[esi+0x18]
         // 00416021: push eax
         // 00416022: call _memset
      [-]83c40cc74628????????c7462c????????5e5dc3
         // 00416027: add esp, 0xc
         // 0041602a: mov ds:[esi+0x28], 0xffffffffffffffff
         // 00416031: mov ds:[esi+0x2c], 0xffffffffffffffff
         // 00416038: pop esi
         // 00416039: pop ebp
         // 0041603a: retn 
      [-]558bec8b450885c07409
         // 004cb8a0: push ebp
         // 004cb8a1: mov ebp, esp
         // 004cb8a3: mov eax, ss:[ebp+0x8]
         // 004cb8a6: test eax, eax
         // 004cb8a8: jz 0x4cb8b3
      [-]8945085de9
         // 004607aa: mov ss:[ebp+0x8], eax
         // 004607ad: pop ebp
         // 004607ae: jmp 0x465740
      [-]558bec51833d
         // 00416080: push ebp
         // 00416081: mov ebp, esp
         // 00416083: push ecx
         // 00416084: cmp ds:[0x608250], 0x0
      [-]01000083c40485c07406
         // 004cb8f4: add esp, 0x4
         // 004cb8f7: test eax, eax
         // 004cb8f9: jz 0x4cb901
      [-]33c08be55dc3
         // 004cb8fb: xor eax, eax
         // 004cb8fd: mov esp, ebp
         // 004cb8ff: pop ebp
         // 004cb900: retn 
      [-]8d45fc50e8
         // 00460801: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00460804: push eax
         // 00460805: call 0x4661b0
      [-]00008b4dfc33d283c40485c00f45ca8bc18be55dc3
         // 0046080a: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0046080d: xor edx, edx
         // 0046080f: add esp, 0x4
         // 00460812: test eax, eax
         // 00460814: cmovnz ecx, edx
         // 00460817: mov eax, ecx
         // 00460819: mov esp, ebp
         // 0046081b: pop ebp
         // 0046081c: retn 
      [-]558bec568b750885f67506
         // 004cb920: push ebp
         // 004cb921: mov ebp, esp
         // 004cb923: push esi
         // 004cb924: mov esi, ss:[ebp+0x8]
         // 004cb927: test esi, esi
         // 004cb929: jnz 0x4cb931
      [-]8d462b5e5dc3
         // 004cb92b: lea eax, ds:[esi+0x2b]
         // 004cb92e: pop esi
         // 004cb92f: pop ebp
         // 004cb930: retn 
      [-]8b461085c07406
         // 004cb931: mov eax, ds:[esi+0x10]
         // 004cb934: test eax, eax
         // 004cb936: jz 0x4cb93e
      [-]83781400755e
         // 004cb938: cmp ds:[eax+0x14], 0x0
         // 004cb93c: jnz 0x4cb99c
      [-]83be????????007436
         // 004cb93e: cmp ds:[esi+0x310], 0x0
         // 004cb945: jz 0x4cb97d
      [-]8b460483f802742e
         // 004cb947: mov eax, ds:[esi+0x4]
         // 004cb94a: cmp eax, 0x2
         // 004cb94d: jz 0x4cb97d
      [-]83f8017517
         // 004cb94f: cmp eax, 0x1
         // 004cb952: jnz 0x4cb96b
      [-]000083c404c746????????00c706????????
         // 0046085b: add esp, 0x4
         // 0046085e: mov ds:[esi+0x4], 0x0
         // 00460865: mov ds:[esi], 0x0
      [-]000085c07409
         // 00516110: test eax, eax
         // 00516112: jz 0x51611d
      [-]8906c74604????????
         // 004cb974: mov ds:[esi], eax
         // 004cb976: mov ds:[esi+0x4], 0x2
      [-]833e00751a
         // 004cb97d: cmp ds:[esi], 0x0
         // 004cb980: jnz 0x4cb99c
      [-]c74604????????e8
         // 00460882: mov ds:[esi+0x4], 0x1
         // 00460889: call ?try_get_FlsSetValue@@YAP6GHKPAX@ZXZ
      [-]0000890685c07508
         // 0046088e: mov ds:[esi], eax
         // 00460890: test eax, eax
         // 00460892: jnz 0x46089c
      [-]b8????????5e5dc3
         // 004cb994: mov eax, 0x1b
         // 004cb999: pop esi
         // 004cb99a: pop ebp
         // 004cb99b: retn 
      [-]83be????????007516
         // 004cb99c: cmp ds:[esi+0x524], 0x0
         // 004cb9a3: jnz 0x4cb9bb
      [-]6aff6a00e8
         // 004608a5: push 0xffffffffffffffff
         // 004608a7: push 0x0
         // 004608a9: call 0x466140
      [-]000083c4088986????????85c074d9
         // 004608ae: add esp, 0x8
         // 004608b1: mov ds:[esi+0x524], eax
         // 004608b7: test eax, eax
         // 004608b9: jz 0x460894
      [-]000083c4045e5dc3
         // 004608c1: add esp, 0x4
         // 004608c4: pop esi
         // 004608c5: pop ebp
         // 004608c6: retn 
      [-]558beca1
         // 004161e0: push ebp
         // 004161e1: mov ebp, esp
         // 004161e3: mov eax, ds:[0x608250]
      [-]8bc840a3
         // 004161e8: mov ecx, eax
         // 004161ea: inc eax
         // 004161eb: mov ds:[0x608250], eax
      [-]85c97404
         // 004161f0: test ecx, ecx
         // 004161f2: jz 0x4161f8
      [-]33c05dc3
         // 004cba64: xor eax, eax
         // 004cba66: pop ebp
         // 004cba67: retn 
      [-]538b5d08c705
         // 00416cb8: push ebx
         // 00416cb9: mov ebx, ss:[ebp+0x8]
         // 00416cbc: mov ds:[0x608164], _malloc
      [-]00c705??
         // 00416cda: mov ds:[0x608170], __strdup
      [-]00000085c07509
         // 004cbab6: test eax, eax
         // 004cbab8: jnz 0x4cbac3
      [-]85c07408
         // 00417341: test eax, eax
         // 00417343: jz 0x41734d
      [-]b8????????5b5dc3
         // 004cbac3: mov eax, 0x2
         // 004cbac8: pop ebx
         // 004cbac9: pop ebp
         // 004cbaca: retn 
      [-]000033c05b5dc3
         // 00416258: xor eax, eax
         // 0041625a: pop ebx
         // 0041625b: pop ebp
         // 0041625c: retn 
      [-]558bec81ec????????a1
         // 00416270: push ebp
         // 00416271: mov ebp, esp
         // 00416273: sub esp, 0x194
         // 00416279: mov eax, ds:[___security_cookie]
      [-]0033c58945fc8d85????????5068????????ff15
         // 0041627e: xor eax, ebp
         // 00416280: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00416283: lea eax, ss:[ebp+0xfffffffffffffe6c]
         // 00416289: push eax
         // 0041628a: push 0x202
         // 0041628f: call ds:[WSAStartup]
      [-]0085c07527
         // 00416295: test eax, eax
         // 00416297: jnz 0x4162c0
      [-]8b85????????3c027517
         // 004cbb19: mov eax, ss:[ebp+0xfffffffffffffe6c]
         // 004cbb1f: cmp b1 al, b1 0x2
         // 004cbb21: jnz 0x4cbb3a
      [-]c1e8083c027510
         // 004cbb23: shr eax, b1 0x8
         // 004cbb26: cmp b1 al, b1 0x2
         // 004cbb28: jnz 0x4cbb3a
      [-]33c08b4dfc33cde8
         // 004162aa: xor eax, eax
         // 004162ac: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004162af: xor ecx, ebp
         // 004162b1: call @__security_check_cookie@4
      [-]8be55dc3
         // 004162b6: mov esp, ebp
         // 004162b8: pop ebp
         // 004162b9: retn 
      [-]8b4dfcb8????????33cde8
         // 004162c0: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004162c3: mov eax, 0x2
         // 004162c8: xor ecx, ebp
         // 004162ca: call @__security_check_cookie@4
      [-]8be55dc3
         // 004162cf: mov esp, ebp
         // 004162d1: pop ebp
         // 004162d2: retn 
      [-]558bec81ec????????a1
         // 004eff00: push ebp
         // 004eff01: mov ebp, esp
         // 004eff03: sub esp, 0x438
         // 004eff09: mov eax, ds:[___security_cookie]
      [-]0033c58945fc8b45088985????????8b450c538985????????8b4518568b75148985????????8b451c6a008985????????c785????????????????e8
         // 004eff0e: xor eax, ebp
         // 004eff10: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004eff13: mov eax, ss:[ebp+0x8]
         // 004eff16: mov ss:[ebp+0xfffffffffffffbdc], eax
         // 004eff1c: mov eax, ss:[ebp+0xc]
         // 004eff1f: push ebx
         // 004eff20: mov ss:[ebp+0xfffffffffffffbe8], eax
         // 004eff26: mov eax, ss:[ebp+0x18]
         // 004eff29: push esi
         // 004eff2a: mov esi, ss:[ebp+0x14]
         // 004eff2d: mov ss:[ebp+0xfffffffffffffbec], eax
         // 004eff33: mov eax, ss:[ebp+0x1c]
         // 004eff36: push 0x0
         // 004eff38: mov ss:[ebp+0xfffffffffffffbe0], eax
         // 004eff3e: mov ss:[ebp+0xfffffffffffffbd8], 0x0
         // 004eff48: call __time64
      [-]6a406a018985????????8995????????c785????????????????ff15
         // 004eff4d: push 0x40
         // 004eff4f: push 0x1
         // 004eff51: mov ss:[ebp+0xfffffffffffffbc8], eax
         // 004eff57: mov ss:[ebp+0xfffffffffffffbcc], edx
         // 004eff5d: mov ss:[ebp+0xfffffffffffffbf8], 0x0
         // 004eff67: call ds:[0x573c80]
      [-]8bd883c40c899d????????85db7510
         // 004eff6d: mov ebx, eax
         // 004eff6f: add esp, 0xc
         // 004eff72: mov ss:[ebp+0xfffffffffffffbd0], ebx
         // 004eff78: test ebx, ebx
         // 004eff7a: jnz 0x4eff8c
      [-]5e5b8b4dfc33cde8
         // 0041641c: pop esi
         // 0041641d: pop ebx
         // 0041641e: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00416421: xor ecx, ebp
         // 00416423: call @__security_check_cookie@4
      [-]8be55dc3
         // 00416428: mov esp, ebp
         // 0041642a: pop ebp
         // 0041642b: retn 
      [-]837d1000570f84f3040000
         // 004cdadc: cmp ss:[ebp+0x10], 0x0
         // 004cdae0: push edi
         // 004cdae1: jz 0x4cdfda
      [-]68????????ff15
         // 00416437: push 0x1388
         // 0041643c: call ds:[0x6073f4]
      [-]8bf883c40489bd????????85ff0f8447090000
         // 00416442: mov edi, eax
         // 00416444: add esp, 0x4
         // 00416447: mov ss:[ebp+0xfffffffffffffbf0], edi
         // 0041644d: test edi, edi
         // 0041644f: jz 0x416d9c
      [-]6a3b56e8
         // 00416455: push 0x3b
         // 00416457: push esi
         // 00416458: call _strchr
      [-]8a0e83c4088985????????84c9742a
         // 0041645d: mov b1 cl, b1 ds:[esi]
         // 0041645f: add esp, 0x8
         // 00416462: mov ss:[ebp+0xfffffffffffffbe4], eax
         // 00416468: test b1 cl, b1 cl
         // 0041646a: jz 0x416496
      [-]0f1f4000
         // 004cdb1c: nop ds:[eax+0x0]
      [-]80f9207405
         // 004cdb20: cmp b1 cl, b1 0x20
         // 004cdb23: jz 0x4cdb2a
      [-]80f909751c
         // 004cdb25: cmp b1 cl, b1 0x9
         // 004cdb28: jnz 0x4cdb46
      [-]8a4e014684c975ee
         // 004cdb2a: mov b1 cl, b1 ds:[esi+0x1]
         // 004cdb2d: inc esi
         // 004cdb2e: test b1 cl, b1 cl
         // 004cdb30: jnz 0x4cdb20
      [-]8bbd????????
         // 004cdb40: mov edi, ss:[ebp+0xfffffffffffffbf0]
      [-]578d85????????c607005068
         // 0051b226: push edi
         // 0051b227: lea eax, ss:[ebp+0xfffffffffffffbfc]
         // 0051b22d: mov b1 ds:[edi], b1 0x0
         // 0051b230: push eax
         // 0051b231: push 0x65b810
      [-]56c685fcfbffff00e8
         // 0051b236: push esi
         // 0051b237: mov b1 ss:[ebp+0xfffffffffffffbfc], b1 0x0
         // 0051b23e: call 0x4775e0
      [-]83c41083f8010f8c26030000
         // 0051b243: add esp, 0x10
         // 0051b246: cmp eax, 0x1
         // 0051b249: jl 0x51b575
      [-]8bcf8d5101
         // 004cdb6f: mov ecx, edi
         // 004cdb71: lea edx, ds:[ecx+0x1]
      [-]8a014184c075f9
         // 004cdb74: mov b1 al, b1 ds:[ecx]
         // 004cdb76: inc ecx
         // 004cdb77: test b1 al, b1 al
         // 004cdb79: jnz 0x4cdb74
      [-]2bca8d95????????8d7a01
         // 004cdb7b: sub ecx, edx
         // 004cdb7d: lea edx, ss:[ebp+0xfffffffffffffbfc]
         // 004cdb83: lea edi, ds:[edx+0x1]
      [-]8a024284c075f9
         // 004cdb86: mov b1 al, b1 ds:[edx]
         // 004cdb88: inc edx
         // 004cdb89: test b1 al, b1 al
         // 004cdb8b: jnz 0x4cdb86
      [-]2bd703d68a0284c07410
         // 004cdb8d: sub edx, edi
         // 004cdb8f: add edx, esi
         // 004cdb91: mov b1 al, b1 ds:[edx]
         // 004cdb93: test b1 al, b1 al
         // 004cdb95: jz 0x4cdba7
      [-]3c207404
         // 004cdb97: cmp b1 al, b1 0x20
         // 004cdb99: jz 0x4cdb9f
      [-]3c097508
         // 004cdb9b: cmp b1 al, b1 0x9
         // 004cdb9d: jnz 0x4cdba7
      [-]8a42014284c075f0
         // 004cdb9f: mov b1 al, b1 ds:[edx+0x1]
         // 004cdba2: inc edx
         // 004cdba3: test b1 al, b1 al
         // 004cdba5: jnz 0x4cdb97
      [-]8a028b95????????8885f7fbffff85c9741d
         // 004cdba7: mov b1 al, b1 ds:[edx]
         // 004cdba9: mov edx, ss:[ebp+0xfffffffffffffbf0]
         // 004cdbaf: mov b1 ss:[ebp+0xfffffffffffffbf7], b1 al
         // 004cdbb5: test ecx, ecx
         // 004cdbb7: jz 0x4cdbd6
      [-]0f1f80????????
         // 004cdbb9: nop ds:[eax+0x0]
      [-]8a440aff3c207404
         // 004cdbc0: mov b1 al, b1 ds:[edx+ecx+0xffffffffffffffff]
         // 004cdbc4: cmp b1 al, b1 0x20
         // 004cdbc6: jz 0x4cdbcc
      [-]3c09750a
         // 004cdbc8: cmp b1 al, b1 0x9
         // 004cdbca: jnz 0x4cdbd6
      [-]c6440aff0083e90175ea
         // 004cdbcc: mov b1 ds:[edx+ecx+0xffffffffffffffff], b1 0x0
         // 004cdbd1: sub ecx, 0x1
         // 004cdbd4: jnz 0x4cdbc0
      [-]8a028bfa84c07412
         // 004cdbd6: mov b1 al, b1 ds:[edx]
         // 004cdbd8: mov edi, edx
         // 004cdbda: test b1 al, b1 al
         // 004cdbdc: jz 0x4cdbf0
      [-]3c207404
         // 004cdbe0: cmp b1 al, b1 0x20
         // 004cdbe2: jz 0x4cdbe8
      [-]3c097508
         // 004cdbe4: cmp b1 al, b1 0x9
         // 004cdbe6: jnz 0x4cdbf0
      [-]8a47014784c075f0
         // 004cdbe8: mov b1 al, b1 ds:[edi+0x1]
         // 004cdbeb: inc edi
         // 004cdbec: test b1 al, b1 al
         // 004cdbee: jnz 0x4cdbe0
      [-]85c97555
         // 004cdbf0: test ecx, ecx
         // 004cdbf2: jnz 0x4cdc49
      [-]8d85????????5068
         // 00416544: lea eax, ss:[ebp+0xfffffffffffffbfc]
         // 0041654a: push eax
         // 0041654b: push 0x45a4b8
      [-]000083c40885c0740c
         // 00416555: add esp, 0x8
         // 00416558: test eax, eax
         // 0041655a: jz 0x416568
      [-]c74330????????e97d020000
         // 004cdc0c: mov ds:[ebx+0x30], 0x1
         // 004cdc13: jmp 0x4cde95
      [-]8d85????????5068
         // 00416568: lea eax, ss:[ebp+0xfffffffffffffbfc]
         // 0041656e: push eax
         // 0041656f: push 0x45a4c0
      [-]000083c40885c0740c
         // 00416579: add esp, 0x8
         // 0041657c: test eax, eax
         // 0041657e: jz 0x41658c
      [-]c74338????????e959020000
         // 004cdc30: mov ds:[ebx+0x38], 0x1
         // 004cdc37: jmp 0x4cde95
      [-]80bdf7fbffff3d0f854c020000
         // 004cdc3c: cmp b1 ss:[ebp+0xfffffffffffffbf7], b1 0x3d
         // 004cdc43: jnz 0x4cde95
      [-]8d85????????5068
         // 00416599: lea eax, ss:[ebp+0xfffffffffffffbfc]
         // 0041659f: push eax
         // 004165a0: push 0x45a4cc
      [-]000083c40885c07415
         // 004165aa: add esp, 0x8
         // 004165ad: test eax, eax
         // 004165af: jz 0x4165c6
      [-]8d730c5756e8
         // 004cdc61: lea esi, ds:[ebx+0xc]
         // 004cdc64: push edi
         // 004cdc65: push esi
         // 004cdc66: call 0x4cecc0
      [-]10000083c408833e00e919020000
         // 004cdc6b: add esp, 0x8
         // 004cdc6e: cmp ds:[esi], 0x0
         // 004cdc71: jmp 0x4cde8f
      [-]8d85????????5068
         // 004165c6: lea eax, ss:[ebp+0xfffffffffffffbfc]
         // 004165cc: push eax
         // 004165cd: push 0x45a4d4
      [-]000083c40885c00f84d5000000
         // 004165d7: add esp, 0x8
         // 004165da: test eax, eax
         // 004165dc: jz 0x4166b7
      [-]803f2e8d7701bb????????0f45f7
         // 004cdc92: cmp b1 ds:[edi], b1 0x2e
         // 004cdc95: lea esi, ds:[edi+0x1]
         // 004cdc98: mov ebx, 0x1
         // 004cdc9d: cmovnz esi, edi
      [-]6a2e56e8
         // 004165f0: push 0x2e
         // 004165f2: push esi
         // 004165f3: call _strchr
      [-]83c40885c0740a
         // 004165f8: add esp, 0x8
         // 004165fb: test eax, eax
         // 004165fd: jz 0x416609
      [-]3bf07401
         // 004cdcaf: cmp esi, eax
         // 004cdcb1: jz 0x4cdcb4
      [-]8d7001ebe7
         // 004cdcb4: lea esi, ds:[eax+0x1]
         // 004cdcb7: jmp 0x4cdca0
      [-]83fb028b9d????????7d23
         // 004cdcb9: cmp ebx, 0x2
         // 004cdcbc: mov ebx, ss:[ebp+0xfffffffffffffbd0]
         // 004cdcc2: jge 0x4cdce7
      [-]ffb5????????c785????????????????e8
         // 0051b3aa: push ss:[ebp+0xfffffffffffffbdc]
         // 0051b3b0: mov ss:[ebp+0xfffffffffffffbf8], 0x1
         // 0051b3ba: call 0x519610
      [-]83c40ce9ae010000
         // 0051b3bf: add esp, 0xc
         // 0051b3c2: jmp 0x51b575
      [-]803f2e8d4f018b85????????0f45cf898d????????85c0743c
         // 004cdce7: cmp b1 ds:[edi], b1 0x2e
         // 004cdcea: lea ecx, ds:[edi+0x1]
         // 004cdced: mov eax, ss:[ebp+0xfffffffffffffbec]
         // 004cdcf3: cmovnz ecx, edi
         // 004cdcf6: mov ss:[ebp+0xfffffffffffffbd4], ecx
         // 004cdcfc: test eax, eax
         // 004cdcfe: jz 0x4cdd3c
      [-]000083c40885c07528
         // 004cdd07: add esp, 0x8
         // 004cdd0a: test eax, eax
         // 004cdd0c: jnz 0x4cdd36
      [-]ffb5????????c785????????????????68
         // 0051b3ee: push ss:[ebp+0xfffffffffffffbd4]
         // 0051b3f4: mov ss:[ebp+0xfffffffffffffbf8], 0x1
         // 0051b3fe: push 0x65b884
      [-]ffb5????????e8
         // 0051b403: push ss:[ebp+0xfffffffffffffbdc]
         // 0051b409: call 0x519610
      [-]83c40ce95f010000
         // 0051b40e: add esp, 0xc
         // 0051b411: jmp 0x51b575
      [-]8b8d????????
         // 004cdd36: mov ecx, ss:[ebp+0xfffffffffffffbd4]
      [-]80392e8d41018d73100f45c15056e8
         // 004cdd3c: cmp b1 ds:[ecx], b1 0x2e
         // 004cdd3f: lea eax, ds:[ecx+0x1]
         // 004cdd42: lea esi, ds:[ebx+0x10]
         // 004cdd45: cmovnz eax, ecx
         // 004cdd48: push eax
         // 004cdd49: push esi
         // 004cdd4a: call 0x4cecc0
      [-]0f000083c408833e000f84ca010000
         // 004cdd4f: add esp, 0x8
         // 004cdd52: cmp ds:[esi], 0x0
         // 004cdd55: jz 0x4cdf25
      [-]c74324????????e92e010000
         // 004cdd5b: mov ds:[ebx+0x24], 0x1
         // 004cdd62: jmp 0x4cde95
      [-]8d85????????5068
         // 0051b447: lea eax, ss:[ebp+0xfffffffffffffbfc]
         // 0051b44d: push eax
         // 0051b44e: push 0x5f3a9c
      [-]000083c40885c07415
         // 0051b458: add esp, 0x8
         // 0051b45b: test eax, eax
         // 0051b45d: jz 0x51b474
      [-]8d73285756e8
         // 004cdd7f: lea esi, ds:[ebx+0x28]
         // 004cdd82: push edi
         // 004cdd83: push esi
         // 004cdd84: call 0x4cecc0
      [-]0f000083c408833e00e9fb000000
         // 004cdd89: add esp, 0x8
         // 004cdd8c: cmp ds:[esi], 0x0
         // 004cdd8f: jmp 0x4cde8f
      [-]8d85????????5068
         // 004166e4: lea eax, ss:[ebp+0xfffffffffffffbfc]
         // 004166ea: push eax
         // 004166eb: push 0x45a548
      [-]000083c40885c0743c
         // 004166f5: add esp, 0x8
         // 004166f8: test eax, eax
         // 004166fa: jz 0x416738
      [-]8d732c5756e8
         // 004cddac: lea esi, ds:[ebx+0x2c]
         // 004cddaf: push edi
         // 004cddb0: push esi
         // 004cddb1: call 0x4cecc0
      [-]0f00008b0683c40885c00f8462010000
         // 004cddb6: mov eax, ds:[esi]
         // 004cddb8: add esp, 0x8
         // 004cddbb: test eax, eax
         // 004cddbd: jz 0x4cdf25
      [-]8038227501
         // 004cddc3: cmp b1 ds:[eax], b1 0x22
         // 004cddc6: jnz 0x4cddc9
      [-]6a0a6a0050e8
         // 00416719: push 0xa
         // 0041671b: push 0x0
         // 0041671d: push eax
         // 0041671e: call _strtol
      [-]83c40c0385????????9989431889531ce9ad000000
         // 00416723: add esp, 0xc
         // 00416726: add eax, ss:[ebp+0xfffffffffffffbc8]
         // 0041672c: cdq 
         // 0041672d: mov ds:[ebx+0x18], eax
         // 00416730: mov ds:[ebx+0x1c], edx
         // 00416733: jmp 0x4167e5
      [-]8d85????????5068
         // 00416738: lea eax, ss:[ebp+0xfffffffffffffbfc]
         // 0041673e: push eax
         // 0041673f: push 0x45a550
      [-]000083c40885c07460
         // 00416749: add esp, 0x8
         // 0041674c: test eax, eax
         // 0041674e: jz 0x4167b0
      [-]8d73205756e8
         // 004cde00: lea esi, ds:[ebx+0x20]
         // 004cde03: push edi
         // 004cde04: push esi
         // 004cde05: call 0x4cecc0
      [-]0e000083c408833e000f840f010000
         // 004cde0a: add esp, 0x8
         // 004cde0d: cmp ds:[esi], 0x0
         // 004cde10: jz 0x4cdf25
      [-]8d85????????50ffb5????????e8
         // 00416766: lea eax, ss:[ebp+0xfffffffffffffbc8]
         // 0041676c: push eax
         // 0041676d: push ss:[ebp+0xfffffffffffffbf0]
         // 00416773: call 0x422110
      [-]000089531c83c4088b4b1c8bd08943180bc1750c
         // 00416778: mov ds:[ebx+0x1c], edx
         // 0041677b: add esp, 0x8
         // 0041677e: mov ecx, ds:[ebx+0x1c]
         // 00416781: mov edx, eax
         // 00416783: mov ds:[ebx+0x18], eax
         // 00416786: or eax, ecx
         // 00416788: jnz 0x416796
      [-]c74318????????89431ceb4f
         // 004cde3a: mov ds:[ebx+0x18], 0x1
         // 004cde41: mov ds:[ebx+0x1c], eax
         // 004cde44: jmp 0x4cde95
      [-]85c97f4b
         // 004cde46: test ecx, ecx
         // 004cde48: jg 0x4cde95
      [-]85d27345
         // 004cde4c: test edx, edx
         // 004cde4e: jnb 0x4cde95
      [-]c743????????00c743????????00eb35
         // 004cde50: mov ds:[ebx+0x18], 0x0
         // 004cde57: mov ds:[ebx+0x1c], 0x0
         // 004cde5e: jmp 0x4cde95
      [-]837b0400752f
         // 004cde60: cmp ds:[ebx+0x4], 0x0
         // 004cde64: jnz 0x4cde95
      [-]8d85????????50ff15??
         // 004167b6: lea eax, ss:[ebp+0xfffffffffffffbfc]
         // 004167bc: push eax
         // 004167bd: call ds:[0x607400]
      [-]57894304ff15??
         // 004167c3: push edi
         // 004167c4: mov ds:[ebx+0x4], eax
         // 004167c7: call ds:[0x607400]
      [-]83c408894308837b04000f8498000000
         // 004167cd: add esp, 0x8
         // 004167d0: mov ds:[ebx+0x8], eax
         // 004167d3: cmp ds:[ebx+0x4], 0x0
         // 004167d7: jz 0x416875
      [-]0f8490000000
         // 004cde8f: jz 0x4cdf25
      [-]8b85????????85c07458
         // 004cde95: mov eax, ss:[ebp+0xfffffffffffffbe4]
         // 004cde9b: test eax, eax
         // 004cde9d: jz 0x4cdef7
      [-]8038007453
         // 004cde9f: cmp b1 ds:[eax], b1 0x0
         // 004cdea2: jz 0x4cdef7
      [-]8d70018a0684c07413
         // 004cdea4: lea esi, ds:[eax+0x1]
         // 004cdea7: mov b1 al, b1 ds:[esi]
         // 004cdea9: test b1 al, b1 al
         // 004cdeab: jz 0x4cdec0
      [-]3c207404
         // 004cdeb0: cmp b1 al, b1 0x20
         // 004cdeb2: jz 0x4cdeb8
      [-]3c097508
         // 004cdeb4: cmp b1 al, b1 0x9
         // 004cdeb6: jnz 0x4cdec0
      [-]8a46014684c075f0
         // 004cdeb8: mov b1 al, b1 ds:[esi+0x1]
         // 004cdebb: inc esi
         // 004cdebc: test b1 al, b1 al
         // 004cdebe: jnz 0x4cdeb0
      [-]6a3b56e8
         // 0051b5a0: push 0x3b
         // 0051b5a2: push esi
         // 0051b5a3: call _strchr
      [-]8bf883c40889bd????????85ff0f8565fcffff
         // 0051b5a8: mov edi, eax
         // 0051b5aa: add esp, 0x8
         // 0051b5ad: mov ss:[ebp+0xfffffffffffffbe4], edi
         // 0051b5b3: test edi, edi
         // 0051b5b5: jnz 0x51b220
      [-]38067418
         // 004cdedb: cmp b1 ds:[esi], b1 al
         // 004cdedd: jz 0x4cdef7
      [-]83c4088985????????85c00f8549fcffff
         // 00416836: add esp, 0x8
         // 00416839: mov ss:[ebp+0xfffffffffffffbe4], eax
         // 0041683f: test eax, eax
         // 00416841: jnz 0x416490
      [-]8bbd????????85ff0f85ae000000
         // 004cdef7: mov edi, ss:[ebp+0xfffffffffffffbf8]
         // 004cdefd: test edi, edi
         // 004cdeff: jnz 0x4cdfb3
      [-]397b107525
         // 004cdf05: cmp ds:[ebx+0x10], edi
         // 004cdf08: jnz 0x4cdf2f
      [-]8b85????????85c0741b
         // 004cdf0a: mov eax, ss:[ebp+0xfffffffffffffbec]
         // 004cdf10: test eax, eax
         // 004cdf12: jz 0x4cdf2f
      [-]50ff15??
         // 00416864: push eax
         // 00416865: call ds:[0x607400]
      [-]83c40489431085c0750a
         // 0041686b: add esp, 0x4
         // 0041686e: mov ds:[ebx+0x10], eax
         // 00416871: test eax, eax
         // 00416873: jnz 0x41687f
      [-]bf????????e984000000
         // 004cdf25: mov edi, 0x1
         // 004cdf2a: jmp 0x4cdfb3
      [-]837b0c00757e
         // 004cdf2f: cmp ds:[ebx+0xc], 0x0
         // 004cdf33: jnz 0x4cdfb3
      [-]8bb5????????85f67474
         // 004cdf35: mov esi, ss:[ebp+0xfffffffffffffbe0]
         // 004cdf3b: test esi, esi
         // 004cdf3d: jz 0x4cdfb3
      [-]6a3f56e8
         // 0041688f: push 0x3f
         // 00416891: push esi
         // 00416892: call _strchr
      [-]83c40885c0750d
         // 00416897: add esp, 0x8
         // 0041689a: test eax, eax
         // 0041689c: jnz 0x4168ab
      [-]6a2f56e8
         // 0041799e: push 0x2f
         // 004179a0: push esi
         // 004179a1: call _strrchr
      [-]0083c408eb0e
         // 004179a6: add esp, 0x8
         // 004179a9: jmp 0x4179b9
      [-]2bc6506a2f56e8
         // 004168ab: sub eax, esi
         // 004168ad: push eax
         // 004168ae: push 0x2f
         // 004168b0: push esi
         // 004168b1: call 0x423f70
      [-]000083c40c
         // 004168b6: add esp, 0xc
      [-]8bf085f67444
         // 004cdf69: mov esi, eax
         // 004cdf6b: test esi, esi
         // 004cdf6d: jz 0x4cdfb3
      [-]2bb5????????468d460150ff15
         // 005186ef: sub esi, ss:[ebp+0xfffffffffffffbe0]
         // 005186f5: inc esi
         // 005186f6: lea eax, ds:[esi+0x1]
         // 005186f9: push eax
         // 005186fa: call ds:[0x670020]
      [-]83c40489430c85c07419
         // 00518700: add esp, 0x4
         // 00518703: mov ds:[ebx+0xc], eax
         // 00518706: test eax, eax
         // 00518708: jz 0x518723
      [-]56ffb5????????50e8
         // 004168da: push esi
         // 004168db: push ss:[ebp+0xfffffffffffffbe0]
         // 004168e1: push eax
         // 004168e2: call _memmove_0
      [-]8b430c83c40cc6040600eb10
         // 004168e7: mov eax, ds:[ebx+0xc]
         // 004168ea: add esp, 0xc
         // 004168ed: mov b1 ds:[esi+eax], b1 0x0
         // 004168f1: jmp 0x416903
      [-]c785????????????????8bbd????????
         // 004cdfa3: mov ss:[ebp+0xfffffffffffffbf8], 0x1
         // 004cdfad: mov edi, ss:[ebp+0xfffffffffffffbf8]
      [-]ffb5????????ff15
         // 00416903: push ss:[ebp+0xfffffffffffffbf0]
         // 00416909: call ds:[0x6073f8]
      [-]83c40485ff7509
         // 0041690f: add esp, 0x4
         // 00416912: test edi, edi
         // 00416914: jnz 0x41691f
      [-]397b040f8570020000
         // 004cdfc6: cmp ds:[ebx+0x4], edi
         // 004cdfc9: jnz 0x4ce23f
      [-]53e8bb0b0000e979040000
         // 004cdfcf: push ebx
         // 004cdfd0: call 0x4ceb90
         // 004cdfd5: jmp 0x4ce453
      [-]56c785????????????????e8
         // 00416931: push esi
         // 00416932: mov ss:[ebp+0xfffffffffffffbec], 0x0
         // 0041693c: call _strncmp
      [-]83c40c85c0750a
         // 00416941: add esp, 0xc
         // 00416944: test eax, eax
         // 00416946: jnz 0x416952
      [-]83c60ac74338????????
         // 004cdff8: add esi, 0xa
         // 004cdffb: mov ds:[ebx+0x38], 0x1
      [-]803e230f8441040000
         // 004ce002: cmp b1 ds:[esi], b1 0x23
         // 004ce005: jz 0x4ce44c
      [-]6a0d56e8
         // 0041695b: push 0xd
         // 0041695d: push esi
         // 0041695e: call _strchr
      [-]83c40885c07403
         // 00416963: add esp, 0x8
         // 00416966: test eax, eax
         // 00416968: jz 0x41696d
      [-]6a0a56e8
         // 0041696d: push 0xa
         // 0041696f: push esi
         // 00416970: call _strchr
      [-]83c40885c07403
         // 00416975: add esp, 0x8
         // 00416978: test eax, eax
         // 0041697a: jz 0x41697f
      [-]8d85????????5068
         // 0041697f: lea eax, ss:[ebp+0xfffffffffffffbec]
         // 00416985: push eax
         // 00416986: push 0x45a564
      [-]00008bf883c40c85ff0f84fe030000
         // 00416991: mov edi, eax
         // 00416993: add esp, 0xc
         // 00416996: test edi, edi
         // 00416998: jz 0x416d9c
      [-]6a3a57e8
         // 0041745e: push 0x3a
         // 00417460: push edi
         // 00417461: call _strchr
      [-]83c40885c00f85eb030000
         // 00417466: add esp, 0x8
         // 00417469: test eax, eax
         // 0041746b: jnz 0x41785c
      [-]83bd????????000f8596010000
         // 004ce063: cmp ss:[ebp+0xfffffffffffffbf8], 0x0
         // 004ce06a: jnz 0x4ce206
      [-]83fe060f876c010000
         // 004ce070: cmp esi, 0x6
         // 004ce073: ja def_4CE079
      [-]803f2e8d47010f45c750ff15??
         // 004169d0: cmp b1 ds:[edi], b1 0x2e
         // 004169d3: lea eax, ds:[edi+0x1]
         // 004169d6: cmovnz eax, edi
         // 004169d9: push eax
         // 004169da: call ds:[0x607400]
      [-]83c40489431085c00f8547010000
         // 004169e0: add esp, 0x4
         // 004169e3: mov ds:[ebx+0x10], eax
         // 004169e6: test eax, eax
         // 004169e8: jnz def_4169C9
      [-]c785????????????????e938010000
         // 004ce09e: mov ss:[ebp+0xfffffffffffffbf8], 0x1
         // 004ce0a8: jmp def_4CE079
      [-]000083c408f7d81bc0f7d8894324e91c010000
         // 00461168: add esp, 0x8
         // 0046116b: neg eax
         // 0046116d: sbb eax, eax
         // 0046116f: neg eax
         // 00461171: mov ds:[ebx+0x24], eax
         // 00461174: jmp def_461129
      [-]8a103a11751a
         // 004ce0d0: mov b1 dl, b1 ds:[eax]
         // 004ce0d2: cmp b1 dl, b1 ds:[ecx]
         // 004ce0d4: jnz 0x4ce0f0
      [-]84d27412
         // 004ce0d6: test b1 dl, b1 dl
         // 004ce0d8: jz 0x4ce0ec
      [-]8a50013a5101750e
         // 004ce0da: mov b1 dl, b1 ds:[eax+0x1]
         // 004ce0dd: cmp b1 dl, b1 ds:[ecx+0x1]
         // 004ce0e0: jnz 0x4ce0f0
      [-]83c00283c10284d275e4
         // 004ce0e2: add eax, 0x2
         // 004ce0e5: add ecx, 0x2
         // 004ce0e8: test b1 dl, b1 dl
         // 004ce0ea: jnz 0x4ce0d0
      [-]33c0eb05
         // 004ce0ec: xor eax, eax
         // 004ce0ee: jmp 0x4ce0f5
      [-]1bc083c801
         // 004ce0f0: sbb eax, eax
         // 004ce0f2: or eax, 0x1
      [-]85c07454
         // 004ce0f5: test eax, eax
         // 004ce0f7: jz 0x4ce14d
      [-]8a103a11751a
         // 004ce100: mov b1 dl, b1 ds:[eax]
         // 004ce102: cmp b1 dl, b1 ds:[ecx]
         // 004ce104: jnz 0x4ce120
      [-]84d27412
         // 004ce106: test b1 dl, b1 dl
         // 004ce108: jz 0x4ce11c
      [-]8a50013a5101750e
         // 004ce10a: mov b1 dl, b1 ds:[eax+0x1]
         // 004ce10d: cmp b1 dl, b1 ds:[ecx+0x1]
         // 004ce110: jnz 0x4ce120
      [-]83c00283c10284d275e4
         // 004ce112: add eax, 0x2
         // 004ce115: add ecx, 0x2
         // 004ce118: test b1 dl, b1 dl
         // 004ce11a: jnz 0x4ce100
      [-]33c0eb05
         // 004ce11c: xor eax, eax
         // 004ce11e: jmp 0x4ce125
      [-]1bc083c801
         // 004ce120: sbb eax, eax
         // 004ce122: or eax, 0x1
      [-]85c07424
         // 004ce125: test eax, eax
         // 004ce127: jz 0x4ce14d
      [-]57ff15??
         // 00416a79: push edi
         // 00416a7a: call ds:[0x607400]
      [-]83c40489430c85c00f85a7000000
         // 00416a80: add esp, 0x4
         // 00416a83: mov ds:[ebx+0xc], eax
         // 00416a86: test eax, eax
         // 00416a88: jnz def_4169C9
      [-]c785????????????????e998000000
         // 004ce13e: mov ss:[ebp+0xfffffffffffffbf8], 0x1
         // 004ce148: jmp def_4CE079
      [-]8b8d????????83c40485c089430cb8????????0f44c8898d????????8d7002
         // 00416aa8: mov ecx, ss:[ebp+0xfffffffffffffbf8]
         // 00416aae: add esp, 0x4
         // 00416ab1: test eax, eax
         // 00416ab3: mov ds:[ebx+0xc], eax
         // 00416ab6: mov eax, 0x1
         // 00416abb: cmovz ecx, eax
         // 00416abe: mov ss:[ebp+0xfffffffffffffbf8], ecx
         // 00416ac4: lea esi, ds:[eax+0x2]
      [-]000083c408f7d81bc0f7d8894330eb55
         // 00416ad2: add esp, 0x8
         // 00416ad5: neg eax
         // 00416ad7: sbb eax, eax
         // 00416ad9: neg eax
         // 00416adb: mov ds:[ebx+0x30], eax
         // 00416ade: jmp def_4169C9
      [-]6a0a6a0057e8
         // 00416ae0: push 0xa
         // 00416ae2: push 0x0
         // 00416ae4: push edi
         // 00416ae5: call __strtoi64
      [-]83c40c89431889531ceb40
         // 00416aea: add esp, 0xc
         // 00416aed: mov ds:[ebx+0x18], eax
         // 00416af0: mov ds:[ebx+0x1c], edx
         // 00416af3: jmp def_4169C9
      [-]57ff15??
         // 00416af5: push edi
         // 00416af6: call ds:[0x607400]
      [-]83c40489430485c0752f
         // 00416afc: add esp, 0x4
         // 00416aff: mov ds:[ebx+0x4], eax
         // 00416b02: test eax, eax
         // 00416b04: jnz def_4169C9
      [-]c785????????????????eb23
         // 004ce1b6: mov ss:[ebp+0xfffffffffffffbf8], 0x1
         // 004ce1c0: jmp def_4CE079
      [-]57ff15??
         // 00416b12: push edi
         // 00416b13: call ds:[0x607400]
      [-]8b8d????????83c40485c0894308b8????????0f44c8898d????????
         // 00416b19: mov ecx, ss:[ebp+0xfffffffffffffbf8]
         // 00416b1f: add esp, 0x4
         // 00416b22: test eax, eax
         // 00416b24: mov ds:[ebx+0x8], eax
         // 00416b27: mov eax, 0x1
         // 00416b2c: cmovz ecx, eax
         // 00416b2f: mov ss:[ebp+0xfffffffffffffbf8], ecx
      [-]8d85????????5068
         // 0051b8c5: lea eax, ss:[ebp+0xfffffffffffffbec]
         // 0051b8cb: push eax
         // 0051b8cc: push 0x5d7934
      [-]00008bf883c40c4685ff0f855dfeffff
         // 0051b8d8: mov edi, eax
         // 0051b8da: add esp, 0xc
         // 0051b8dd: inc esi
         // 0051b8de: test edi, edi
         // 0051b8e0: jnz 0x51b743
      [-]83fe06751e
         // 004ce206: cmp esi, 0x6
         // 004ce209: jnz 0x4ce229
      [-]83c40489430885c00f84abfdffff
         // 00416b66: add esp, 0x4
         // 00416b69: mov ds:[ebx+0x8], eax
         // 00416b6c: test eax, eax
         // 00416b6e: jz 0x41691f
      [-]be????????
         // 004ce224: mov esi, 0x7
      [-]83bd????????000f8599fdffff
         // 004ce229: cmp ss:[ebp+0xfffffffffffffbf8], 0x0
         // 004ce230: jnz 0x4cdfcf
      [-]83fe070f8590fdffff
         // 004ce236: cmp esi, 0x7
         // 004ce239: jnz 0x4cdfcf
      [-]8b95????????8b4a0885c97511
         // 004ce23f: mov edx, ss:[ebp+0xfffffffffffffbe8]
         // 004ce245: mov ecx, ds:[edx+0x8]
         // 004ce248: test ecx, ecx
         // 004ce24a: jnz 0x4ce25d
      [-]394a10740c
         // 004ce24c: cmp ds:[edx+0x10], ecx
         // 004ce24f: jz 0x4ce25d
      [-]8b43180b431c0f8472fdffff
         // 004ce251: mov eax, ds:[ebx+0x18]
         // 004ce254: or eax, ds:[ebx+0x1c]
         // 004ce257: jz 0x4cdfcf
      [-]894b3433ff8b3285f60f843c010000
         // 004ce25d: mov ds:[ebx+0x34], ecx
         // 004ce260: xor edi, edi
         // 004ce262: mov esi, ds:[edx]
         // 004ce264: test esi, esi
         // 004ce266: jz 0x4ce3a8
      [-]0f1f4000
         // 004ce26c: nop ds:[eax+0x0]
      [-]ff7304ff7604e8
         // 00416bc0: push ds:[ebx+0x4]
         // 00416bc3: push ds:[esi+0x4]
         // 00416bc6: call 0x423d40
      [-]000083c40885c00f8499010000
         // 00416bcb: add esp, 0x8
         // 00416bce: test eax, eax
         // 00416bd0: jz 0x416d6f
      [-]8b461085c07422
         // 004ce286: mov eax, ds:[esi+0x10]
         // 004ce289: test eax, eax
         // 004ce28b: jz 0x4ce2af
      [-]8b4b1085c97413
         // 004ce28d: mov ecx, ds:[ebx+0x10]
         // 004ce290: test ecx, ecx
         // 004ce292: jz 0x4ce2a7
      [-]000083c40885c07517
         // 00416beb: add esp, 0x8
         // 00416bee: test eax, eax
         // 00416bf0: jnz 0x416c09
      [-]e978010000
         // 004ce2a2: jmp 0x4ce41f
      [-]85c00f8570010000
         // 004ce2a7: test eax, eax
         // 004ce2a9: jnz 0x4ce41f
      [-]837b10000f8566010000
         // 004ce2af: cmp ds:[ebx+0x10], 0x0
         // 004ce2b3: jnz 0x4ce41f
      [-]8b460c85c00f844f010000
         // 004ce2b9: mov eax, ds:[esi+0xc]
         // 004ce2bc: test eax, eax
         // 004ce2be: jz 0x4ce413
      [-]8b4b0c85c90f8440010000
         // 004ce2c4: mov ecx, ds:[ebx+0xc]
         // 004ce2c7: test ecx, ecx
         // 004ce2c9: jz 0x4ce40f
      [-]000083c40885c00f843c010000
         // 00416c26: add esp, 0x8
         // 00416c29: test eax, eax
         // 00416c2b: jz 0x416d6d
      [-]837b3400bf????????750a
         // 004ce2e1: cmp ds:[ebx+0x34], 0x0
         // 004ce2e5: mov edi, 0x1
         // 004ce2ea: jnz 0x4ce2f6
      [-]837e34000f85d9fcffff
         // 004ce2ec: cmp ds:[esi+0x34], 0x0
         // 004ce2f0: jnz 0x4cdfcf
      [-]8b068903ff7604ff15
         // 00416c46: mov eax, ds:[esi]
         // 00416c48: mov ds:[ebx], eax
         // 00416c4a: push ds:[esi+0x4]
         // 00416c4d: call ds:[0x6073f8]
      [-]8b460883c40485c0740a
         // 00416c53: mov eax, ds:[esi+0x8]
         // 00416c56: add esp, 0x4
         // 00416c59: test eax, eax
         // 00416c5b: jz 0x416c67
      [-]8b461085c0740a
         // 004ce317: mov eax, ds:[esi+0x10]
         // 004ce31a: test eax, eax
         // 004ce31c: jz 0x4ce328
      [-]8b460c85c0740a
         // 004ce328: mov eax, ds:[esi+0xc]
         // 004ce32b: test eax, eax
         // 004ce32d: jz 0x4ce339
      [-]8b462085c0740a
         // 004ce339: mov eax, ds:[esi+0x20]
         // 004ce33c: test eax, eax
         // 004ce33e: jz 0x4ce34a
      [-]8b462885c0740a
         // 004ce34a: mov eax, ds:[esi+0x28]
         // 004ce34d: test eax, eax
         // 004ce34f: jz 0x4ce35b
      [-]8b462c85c0740a
         // 004ce35b: mov eax, ds:[esi+0x2c]
         // 004ce35e: test eax, eax
         // 004ce360: jz 0x4ce36c
      [-]0f1003530f11060f1043100f1146100f1043200f1146200f1043300f114630ff15
         // 00416cbc: movups b16 xmm0, b16 ds:[ebx]
         // 00416cbf: push ebx
         // 00416cc0: movups b16 ds:[esi], b16 xmm0
         // 00416cc3: movups b16 xmm0, b16 ds:[ebx+0x10]
         // 00416cc7: movups b16 ds:[esi+0x10], b16 xmm0
         // 00416ccb: movups b16 xmm0, b16 ds:[ebx+0x20]
         // 00416ccf: movups b16 ds:[esi+0x20], b16 xmm0
         // 00416cd3: movups b16 xmm0, b16 ds:[ebx+0x30]
         // 00416cd7: movups b16 ds:[esi+0x30], b16 xmm0
         // 00416cdb: call ds:[0x6073f8]
      [-]83c4048bde
         // 00416ce1: add esp, 0x4
         // 00416ce4: mov ebx, esi
      [-]89b5????????8b3685f675f4
         // 004ce396: mov ss:[ebp+0xfffffffffffffbd8], esi
         // 004ce39c: mov esi, ds:[esi]
         // 004ce39e: test esi, esi
         // 004ce3a0: jnz 0x4ce396
      [-]8b95????????
         // 004ce3a2: mov edx, ss:[ebp+0xfffffffffffffbe8]
      [-]837a0800743b
         // 004ce3a8: cmp ds:[edx+0x8], 0x0
         // 004ce3ac: jz 0x4ce3e9
      [-]ff731cb9
         // 004f085e: push ds:[ebx+0x1c]
         // 004f0861: mov ecx, 0x52f51c
      [-]85ffff7318b8
         // 004f0866: test edi, edi
         // 004f0868: push ds:[ebx+0x18]
         // 004f086b: mov eax, 0x52f510
      [-]ff730c0f44c1ff7310ff7308ff73045068
         // 004f0870: push ds:[ebx+0xc]
         // 004f0873: cmovz eax, ecx
         // 004f0876: push ds:[ebx+0x10]
         // 004f0879: push ds:[ebx+0x8]
         // 004f087c: push ds:[ebx+0x4]
         // 004f087f: push eax
         // 004f0880: push 0x52f524
      [-]ffb5????????e8
         // 004f0885: push ss:[ebp+0xfffffffffffffbdc]
         // 004f088b: call 0x4ee4a0
      [-]8b95????????83c424
         // 004f0890: mov edx, ss:[ebp+0xfffffffffffffbe8]
         // 004f0896: add esp, 0x24
      [-]85ff7549
         // 004ce3e9: test edi, edi
         // 004ce3eb: jnz 0x4ce436
      [-]8b85????????85c0743d
         // 004ce3ed: mov eax, ss:[ebp+0xfffffffffffffbd8]
         // 004ce3f3: test eax, eax
         // 004ce3f5: jz 0x4ce434
      [-]5f89188bc3ff420c5e5b8b4dfc33cde8
         // 0051bad7: pop edi
         // 0051bad8: mov ds:[eax], ebx
         // 0051bada: mov eax, ebx
         // 0051badc: inc ds:[edx+0xc]
         // 0051badf: pop esi
         // 0051bae0: pop ebx
         // 0051bae1: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0051bae4: xor ecx, ebp
         // 0051bae6: call @__security_check_cookie@4
      [-]8be55dc3
         // 0051baeb: mov esp, ebp
         // 0051baed: pop ebp
         // 0051baee: retn 
      [-]85c0750a
         // 004ce40f: test eax, eax
         // 004ce411: jnz 0x4ce41d
      [-]837b0c000f84c4feffff
         // 004ce413: cmp ds:[ebx+0xc], 0x0
         // 004ce417: jz 0x4ce2e1
      [-]89b5????????8b3685f60f8541feffff
         // 004ce41f: mov ss:[ebp+0xfffffffffffffbd8], esi
         // 004ce425: mov esi, ds:[esi]
         // 004ce427: test esi, esi
         // 004ce429: jnz 0x4ce270
      [-]e96effffff
         // 004ce42f: jmp 0x4ce3a2
      [-]ff420c8bc35f5e5b8b4dfc33cde8
         // 0051bb16: inc ds:[edx+0xc]
         // 0051bb19: mov eax, ebx
         // 0051bb1b: pop edi
         // 0051bb1c: pop esi
         // 0051bb1d: pop ebx
         // 0051bb1e: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0051bb21: xor ecx, ebp
         // 0051bb23: call @__security_check_cookie@4
      [-]8be55dc3
         // 0051bb28: mov esp, ebp
         // 0051bb2a: pop ebp
         // 0051bb2b: retn 
      [-]8b4dfc83c40433cd33c05f5e5be8
         // 00416da3: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00416da6: add esp, 0x4
         // 00416da9: xor ecx, ebp
         // 00416dab: xor eax, eax
         // 00416dad: pop edi
         // 00416dae: pop esi
         // 00416daf: pop ebx
         // 00416db0: call @__security_check_cookie@4
      [-]8be55dc3
         // 00416db5: mov esp, ebp
         // 00416db7: pop ebp
         // 00416db8: retn 
      [-]558bec578b7d0885ff7434
         // 004ce490: push ebp
         // 004ce491: mov ebp, esp
         // 004ce493: push edi
         // 004ce494: mov edi, ss:[ebp+0x8]
         // 004ce497: test edi, edi
         // 004ce499: jz 0x4ce4cf
      [-]8b470485c0740a
         // 004ce49b: mov eax, ds:[edi+0x4]
         // 004ce49e: test eax, eax
         // 004ce4a0: jz 0x4ce4ac
      [-]8b0785c07413
         // 004ce4ac: mov eax, ds:[edi]
         // 004ce4ae: test eax, eax
         // 004ce4b0: jz 0x4ce4c5
      [-]8b3050e8d506000083c4048bc685f675ef
         // 004ce4b3: mov esi, ds:[eax]
         // 004ce4b5: push eax
         // 004ce4b6: call 0x4ceb90
         // 004ce4bb: add esp, 0x4
         // 004ce4be: mov eax, esi
         // 004ce4c0: test esi, esi
         // 004ce4c2: jnz 0x4ce4b3
      [-]6a01ff36e87c00000083c408c706????????c746????????00
         // 004ce4eb: push 0x1
         // 004ce4ed: push ds:[esi]
         // 004ce4ef: call 0x4ce570
         // 004ce4f4: add esp, 0x8
         // 004ce4f7: mov ds:[esi], 0x0
         // 004ce4fd: mov ds:[esi+0xc], 0x0
      [-]558bec8b550885d27453
         // 004ce510: push ebp
         // 004ce511: mov ebp, esp
         // 004ce513: mov edx, ss:[ebp+0x8]
         // 004ce516: test edx, edx
         // 004ce518: jz 0x4ce56d
      [-]578b3a85ff744b
         // 004ce51a: push edi
         // 004ce51b: mov edi, ds:[edx]
         // 004ce51d: test edi, edi
         // 004ce51f: jz 0x4ce56c
      [-]53568bc78bdf
         // 004ce521: push ebx
         // 004ce522: push esi
         // 004ce523: mov eax, edi
         // 004ce525: mov ebx, edi
      [-]8b48180b481c8b30752f
         // 004ce527: mov ecx, ds:[eax+0x18]
         // 004ce52a: or ecx, ds:[eax+0x1c]
         // 004ce52d: mov esi, ds:[eax]
         // 004ce52f: jnz 0x4ce560
      [-]3bd80f44de3bf87513
         // 004ce531: cmp ebx, eax
         // 004ce533: cmovz ebx, esi
         // 004ce536: cmp edi, eax
         // 004ce538: jnz 0x4ce54d
      [-]508bfee84e0600008b550883c404ff4a0ceb15
         // 004ce53a: push eax
         // 004ce53b: mov edi, esi
         // 004ce53d: call 0x4ceb90
         // 004ce542: mov edx, ss:[ebp+0x8]
         // 004ce545: add esp, 0x4
         // 004ce548: dec ds:[edx+0xc]
         // 004ce54b: jmp 0x4ce562
      [-]508937e83b0600008b550883c404ff4a0ceb02
         // 004ce54d: push eax
         // 004ce54e: mov ds:[edi], esi
         // 004ce550: call 0x4ceb90
         // 004ce555: mov edx, ss:[ebp+0x8]
         // 004ce558: add esp, 0x4
         // 004ce55b: dec ds:[edx+0xc]
         // 004ce55e: jmp 0x4ce562
      [-]8bc685f675bf
         // 004ce562: mov eax, esi
         // 004ce564: test esi, esi
         // 004ce566: jnz 0x4ce527
      [-]5e891a5b
         // 004ce568: pop esi
         // 004ce569: mov ds:[edx], ebx
         // 004ce56b: pop ebx
      [-]558bec8b450885c07425
         // 004ce570: push ebp
         // 004ce571: mov ebp, esp
         // 004ce573: mov eax, ss:[ebp+0x8]
         // 004ce576: test eax, eax
         // 004ce578: jz 0x4ce59f
      [-]56578b7d0c90
         // 004ce57a: push esi
         // 004ce57b: push edi
         // 004ce57c: mov edi, ss:[ebp+0xc]
         // 004ce57f: nop 
      [-]8b305085ff7407
         // 004ce580: mov esi, ds:[eax]
         // 004ce582: push eax
         // 004ce583: test edi, edi
         // 004ce585: jz 0x4ce58e
      [-]e804060000eb06
         // 004ce587: call 0x4ceb90
         // 004ce58c: jmp 0x4ce594
      [-]83c4048bc685f675e3
         // 004ce594: add esp, 0x4
         // 004ce597: mov eax, esi
         // 004ce599: test esi, esi
         // 004ce59b: jnz 0x4ce580
      [-]558bec83ec0c5356576a00e8
         // 00416f00: push ebp
         // 00416f01: mov ebp, esp
         // 00416f03: sub esp, 0xc
         // 00416f06: push ebx
         // 00416f07: push esi
         // 00416f08: push edi
         // 00416f09: push 0x0
         // 00416f0b: call __time64
      [-]8b750833db83c4048945f433ff8955f8895dfc85f60f8417010000
         // 00416f10: mov esi, ss:[ebp+0x8]
         // 00416f13: xor ebx, ebx
         // 00416f15: add esp, 0x4
         // 00416f18: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00416f1b: xor edi, edi
         // 00416f1d: mov ss:[ebp+0xfffffffffffffff8], edx
         // 00416f20: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 00416f23: test esi, esi
         // 00416f25: jz 0x417042
      [-]8b3685f60f840d010000
         // 004ce5db: mov esi, ds:[esi]
         // 004ce5dd: test esi, esi
         // 004ce5df: jz 0x4ce6f2
      [-]8b56188bc28b4e1c0bc17414
         // 004ce5e5: mov edx, ds:[esi+0x18]
         // 004ce5e8: mov eax, edx
         // 004ce5ea: mov ecx, ds:[esi+0x1c]
         // 004ce5ed: or eax, ecx
         // 004ce5ef: jz 0x4ce605
      [-]3b4df80f8cb8000000
         // 004ce5f1: cmp ecx, ss:[ebp+0xfffffffffffffff8]
         // 004ce5f4: jl 0x4ce6b2
      [-]3b55f40f86ad000000
         // 004ce5fc: cmp edx, ss:[ebp+0xfffffffffffffff4]
         // 004ce5ff: jbe 0x4ce6b2
      [-]837e3000b8????????0f45451485c00f8498000000
         // 004ce605: cmp ds:[esi+0x30], 0x0
         // 004ce609: mov eax, 0x1
         // 004ce60e: cmovnz eax, ss:[ebp+0x14]
         // 004ce612: test eax, eax
         // 004ce614: jz 0x4ce6b2
      [-]8b461085c0742d
         // 004ce61a: mov eax, ds:[esi+0x10]
         // 004ce61d: test eax, eax
         // 004ce61f: jz 0x4ce64e
      [-]837e24007415
         // 004ce621: cmp ds:[esi+0x24], 0x0
         // 004ce625: jz 0x4ce63c
      [-]ff750c50e8
         // 004ce627: push ss:[ebp+0xc]
         // 004ce62a: push eax
         // 004ce62b: call 0x4cecf0
      [-]06000083c40885c07517
         // 004ce630: add esp, 0x8
         // 004ce633: test eax, eax
         // 004ce635: jnz 0x4ce64e
      [-]3946247576
         // 004ce637: cmp ds:[esi+0x24], eax
         // 004ce63a: jnz 0x4ce6b2
      [-]ff7610ff750ce8
         // 00416f8c: push ds:[esi+0x10]
         // 00416f8f: push ss:[ebp+0xc]
         // 00416f92: call 0x423d40
      [-]000083c40885c07464
         // 00416f97: add esp, 0x8
         // 00416f9a: test eax, eax
         // 00416f9c: jz 0x417002
      [-]8b560c85d27428
         // 004ce64e: mov edx, ds:[esi+0xc]
         // 004ce651: test edx, edx
         // 004ce653: jz 0x4ce67d
      [-]8bca8d5901660f1f440000
         // 004ce655: mov ecx, edx
         // 004ce657: lea ebx, ds:[ecx+0x1]
         // 004ce65a: nop b2 ds:[eax+eax+0x0]
      [-]8a014184c075f9
         // 004ce660: mov b1 al, b1 ds:[ecx]
         // 004ce662: inc ecx
         // 004ce663: test b1 al, b1 al
         // 004ce665: jnz 0x4ce660
      [-]2bcb51ff751052e8
         // 00416fb7: sub ecx, ebx
         // 00416fb9: push ecx
         // 00416fba: push ss:[ebp+0x10]
         // 00416fbd: push edx
         // 00416fbe: call _strncmp
      [-]8b5dfc83c40c85c07535
         // 00416fc3: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00416fc6: add esp, 0xc
         // 00416fc9: test eax, eax
         // 00416fcb: jnz 0x417002
      [-]6a40ff15
         // 00416fcd: push 0x40
         // 00416fcf: call ds:[0x6073f4]
      [-]83c40485c0744f
         // 00416fd5: add esp, 0x4
         // 00416fd8: test eax, eax
         // 00416fda: jz 0x41702b
      [-]0f100643895dfc0f11000f1046100f1140100f1046200f1140200f1046300f11403089388bf8
         // 004ce68c: movups b16 xmm0, b16 ds:[esi]
         // 004ce68f: inc ebx
         // 004ce690: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 004ce693: movups b16 ds:[eax], b16 xmm0
         // 004ce696: movups b16 xmm0, b16 ds:[esi+0x10]
         // 004ce69a: movups b16 ds:[eax+0x10], b16 xmm0
         // 004ce69e: movups b16 xmm0, b16 ds:[esi+0x20]
         // 004ce6a2: movups b16 ds:[eax+0x20], b16 xmm0
         // 004ce6a6: movups b16 xmm0, b16 ds:[esi+0x30]
         // 004ce6aa: movups b16 ds:[eax+0x30], b16 xmm0
         // 004ce6ae: mov ds:[eax], edi
         // 004ce6b0: mov edi, eax
      [-]8b3685f60f8529ffffff
         // 004ce6b2: mov esi, ds:[esi]
         // 004ce6b4: test esi, esi
         // 004ce6b6: jnz 0x4ce5e5
      [-]85db0f8487000000
         // 004ce6bc: test ebx, ebx
         // 004ce6be: jz 0x4ce74b
      [-]8d049d0000000050ff15
         // 00417014: lea eax, ds:[ebx*0x4]
         // 0041701b: push eax
         // 0041701c: call ds:[0x6073f4]
      [-]8bf083c40485f67520
         // 00417022: mov esi, eax
         // 00417024: add esp, 0x4
         // 00417027: test esi, esi
         // 00417029: jnz 0x41704b
      [-]85ff7413
         // 004ce6db: test edi, edi
         // 004ce6dd: jz 0x4ce6f2
      [-]8b3757ff15
         // 00417030: mov esi, ds:[edi]
         // 00417032: push edi
         // 00417033: call ds:[0x6073f8]
      [-]83c4048bfe85f675ee
         // 00417039: add esp, 0x4
         // 0041703c: mov edi, esi
         // 0041703e: test esi, esi
         // 00417040: jnz 0x417030
      [-]5f5e33c05b8be55dc3
         // 004ce6f2: pop edi
         // 004ce6f3: pop esi
         // 004ce6f4: xor eax, eax
         // 004ce6f6: pop ebx
         // 004ce6f7: mov esp, ebp
         // 004ce6f9: pop ebp
         // 004ce6fa: retn 
      [-]85ff740d
         // 004ce6fb: test edi, edi
         // 004ce6fd: jz 0x4ce70c
      [-]89388d40048b3f85ff75f5
         // 004ce701: mov ds:[eax], edi
         // 004ce703: lea eax, ds:[eax+0x4]
         // 004ce706: mov edi, ds:[edi]
         // 004ce708: test edi, edi
         // 004ce70a: jnz 0x4ce701
      [-]6a045356e8
         // 00417061: push 0x4
         // 00417063: push ebx
         // 00417064: push esi
         // 00417065: call _qsort
      [-]8b3e83c41033d283c3ff740e
         // 0041706a: mov edi, ds:[esi]
         // 0041706c: add esp, 0x10
         // 0041706f: xor edx, edx
         // 00417071: add ebx, 0xffffffffffffffff
         // 00417074: jz 0x417084
      [-]8b0c968b4496044289013bd372f2
         // 004ce726: mov ecx, ds:[esi+edx*0x4]
         // 004ce729: mov eax, ds:[esi+edx*0x4]
         // 004ce72d: inc edx
         // 004ce72e: mov ds:[ecx], eax
         // 004ce730: cmp edx, ebx
         // 004ce732: jb 0x4ce726
      [-]8b4dfc568b4c8efcc701????????ff15
         // 00417084: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00417087: push esi
         // 00417088: mov ecx, ds:[esi+ecx*0x4]
         // 0041708c: mov ds:[ecx], 0x0
         // 00417092: call ds:[0x6073f8]
      [-]8bc75f5e5b8be55dc3
         // 004ce74b: mov eax, edi
         // 004ce74d: pop edi
         // 004ce74e: pop esi
         // 004ce74f: pop ebx
         // 004ce750: mov esp, ebp
         // 004ce752: pop ebp
         // 004ce753: retn 
      [-]558bec51568b750c578b7d10c745fc????????85ff7530
         // 004ce760: push ebp
         // 004ce761: mov ebp, esp
         // 004ce763: push ecx
         // 004ce764: push esi
         // 004ce765: mov esi, ss:[ebp+0xc]
         // 004ce768: push edi
         // 004ce769: mov edi, ss:[ebp+0x10]
         // 004ce76c: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 004ce773: test edi, edi
         // 004ce775: jnz 0x4ce7a7
      [-]6a146a01ff15
         // 004170c7: push 0x14
         // 004170c9: push 0x1
         // 004170cb: call ds:[0x607404]
      [-]8bf883c40885ff7506
         // 004170d1: mov edi, eax
         // 004170d3: add esp, 0x8
         // 004170d6: test edi, edi
         // 004170d8: jnz 0x4170e0
      [-]5f5e8be55dc3
         // 004ce78a: pop edi
         // 004ce78b: pop esi
         // 004ce78c: mov esp, ebp
         // 004ce78e: pop ebp
         // 004ce78f: retn 
      [-]0f45c650ff15??
         // 004170e7: cmovnz eax, esi
         // 004170ea: push eax
         // 004170eb: call ds:[0x607400]
      [-]83c404894704
         // 004170f1: add esp, 0x4
         // 004170f4: mov ds:[edi+0x4], eax
      [-]c747????????005385f6743e
         // 004ce7a7: mov ds:[edi+0x8], 0x0
         // 004ce7ae: push ebx
         // 004ce7af: test esi, esi
         // 004ce7b1: jz 0x4ce7f1
      [-]83c40885c07415
         // 0041710e: add esp, 0x8
         // 00417111: test eax, eax
         // 00417113: jz 0x41712a
      [-]83c404c745fc????????8bd8eb19
         // 0041711c: add esp, 0x4
         // 0041711f: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00417126: mov ebx, eax
         // 00417128: jmp 0x417143
      [-]803e007412
         // 004ce7da: cmp b1 ds:[esi], b1 0x0
         // 004ce7dd: jz 0x4ce7f1
      [-]83c4088bd8eb02
         // 0041713a: add esp, 0x8
         // 0041713d: mov ebx, eax
         // 0041713f: jmp 0x417143
      [-]8b451489471085db0f849a000000
         // 004ce7f3: mov eax, ss:[ebp+0x14]
         // 004ce7f6: mov ds:[edi+0x10], eax
         // 004ce7f9: test ebx, ebx
         // 004ce7fb: jz 0x4ce89b
      [-]68????????ff15
         // 00417151: push 0x1388
         // 00417156: call ds:[0x6073f4]
      [-]8bf083c40485f67477
         // 0041715c: mov esi, eax
         // 0041715e: add esp, 0x4
         // 00417161: test esi, esi
         // 00417163: jz 0x4171dc
      [-]5368????????56e8
         // 00417165: push ebx
         // 00417166: push 0x1388
         // 0041716b: push esi
         // 0041716c: call _fgets
      [-]0083c40c85c0745a
         // 00417171: add esp, 0xc
         // 00417174: test eax, eax
         // 00417176: jz 0x4171d2
      [-]6a0b5668
         // 00417178: push 0xb
         // 0041717a: push esi
         // 0041717b: push 0x45a5d8
      [-]000083c40c85c0740a
         // 00417185: add esp, 0xc
         // 00417188: test eax, eax
         // 0041718a: jz 0x417196
      [-]8d4e0bba????????eb04
         // 004ce83c: lea ecx, ds:[esi+0xb]
         // 004ce83f: mov edx, 0x1
         // 004ce844: jmp 0x4ce84a
      [-]8bce33d2
         // 004ce846: mov ecx, esi
         // 004ce848: xor edx, edx
      [-]8a0184c07410
         // 004ce84a: mov b1 al, b1 ds:[ecx]
         // 004ce84c: test b1 al, b1 al
         // 004ce84e: jz 0x4ce860
      [-]3c207404
         // 004ce850: cmp b1 al, b1 0x20
         // 004ce852: jz 0x4ce858
      [-]3c097508
         // 004ce854: cmp b1 al, b1 0x9
         // 004ce856: jnz 0x4ce860
      [-]8a41014184c075f0
         // 004ce858: mov b1 al, b1 ds:[ecx+0x1]
         // 004ce85b: inc ecx
         // 004ce85c: test b1 al, b1 al
         // 004ce85e: jnz 0x4ce850
      [-]6a006a00515257ff7508e8e1f1ffff5368????????56e8
         // 004171b0: push 0x0
         // 004171b2: push 0x0
         // 004171b4: push ecx
         // 004171b5: push edx
         // 004171b6: push edi
         // 004171b7: push ss:[ebp+0x8]
         // 004171ba: call 0x4163a0
         // 004171bf: push ebx
         // 004171c0: push 0x1388
         // 004171c5: push esi
         // 004171c6: call _fgets
      [-]0083c42485c075a6
         // 004171cb: add esp, 0x24
         // 004171ce: test eax, eax
         // 004171d0: jnz 0x417178
      [-]837dfc007409
         // 004ce88c: cmp ss:[ebp+0xfffffffffffffffc], 0x0
         // 004ce890: jz 0x4ce89b
      [-]5bc74708????????8bc75f5e8be55dc3
         // 004ce89b: pop ebx
         // 004ce89c: mov ds:[edi+0x8], 0x1
         // 004ce8a3: mov eax, edi
         // 004ce8a5: pop edi
         // 004ce8a6: pop esi
         // 004ce8a7: mov esp, ebp
         // 004ce8a9: pop ebp
         // 004ce8aa: retn 
      [-]558bec8b4508535633db8bb0????????85f67455
         // 004ce8b0: push ebp
         // 004ce8b1: mov ebp, esp
         // 004ce8b3: mov eax, ss:[ebp+0x8]
         // 004ce8b6: push ebx
         // 004ce8b7: push esi
         // 004ce8b8: xor ebx, ebx
         // 004ce8ba: mov esi, ds:[eax+0x418]
         // 004ce8c0: test esi, esi
         // 004ce8c2: jz 0x4ce919
      [-]395e0c7450
         // 004ce8c4: cmp ds:[esi+0xc], ebx
         // 004ce8c7: jz 0x4ce919
      [-]8b365785f67432
         // 004ce8c9: mov esi, ds:[esi]
         // 004ce8cb: push edi
         // 004ce8cc: test esi, esi
         // 004ce8ce: jz 0x4ce902
      [-]56e84a0300008bf883c40485ff742a
         // 004ce8d0: push esi
         // 004ce8d1: call 0x4cec20
         // 004ce8d6: mov edi, eax
         // 004ce8d8: add esp, 0x4
         // 004ce8db: test edi, edi
         // 004ce8dd: jz 0x4ce909
      [-]ffff57894508ff15
         // 00417236: push edi
         // 00417237: mov ss:[ebp+0x8], eax
         // 0041723a: call ds:[0x6073f8]
      [-]8b450883c40c85c0740f
         // 00417240: mov eax, ss:[ebp+0x8]
         // 00417243: add esp, 0xc
         // 00417246: test eax, eax
         // 00417248: jz 0x417259
      [-]8b368bd885f675ce
         // 004ce8fa: mov esi, ds:[esi]
         // 004ce8fc: mov ebx, eax
         // 004ce8fe: test esi, esi
         // 004ce900: jnz 0x4ce8d0
      [-]5f5e8bc35b5dc3
         // 004ce902: pop edi
         // 004ce903: pop esi
         // 004ce904: mov eax, ebx
         // 004ce906: pop ebx
         // 004ce907: pop ebp
         // 004ce908: retn 
      [-]ffff83c40433c05f5e5b5dc3
         // 004ce90f: add esp, 0x4
         // 004ce912: xor eax, eax
         // 004ce914: pop edi
         // 004ce915: pop esi
         // 004ce916: pop ebx
         // 004ce917: pop ebp
         // 004ce918: retn 
      [-]5e33c05b5dc3
         // 004ce919: pop esi
         // 004ce91a: xor eax, eax
         // 004ce91c: pop ebx
         // 004ce91d: pop ebp
         // 004ce91e: retn 
      [-]558bec568b7508578bbe????????85ff744e
         // 004ce920: push ebp
         // 004ce921: mov ebp, esp
         // 004ce923: push esi
         // 004ce924: mov esi, ss:[ebp+0x8]
         // 004ce927: push edi
         // 004ce928: mov edi, ds:[esi+0x410]
         // 004ce92e: test edi, edi
         // 004ce930: jz 0x4ce980
      [-]6a026a0256e8
         // 00417282: push 0x2
         // 00417284: push 0x2
         // 00417286: push esi
         // 00417287: call 0x423cc0
      [-]000083c40c90
         // 0041728c: add esp, 0xc
         // 0041728f: nop 
      [-]ffb6????????ffb6????????ff3756e80cfeffff8986????????83c4108b7f0485ff75dc
         // 004ce940: push ds:[esi+0x1e0]
         // 004ce946: push ds:[esi+0x418]
         // 004ce94c: push ds:[edi]
         // 004ce94e: push esi
         // 004ce94f: call 0x4ce760
         // 004ce954: mov ds:[esi+0x418], eax
         // 004ce95a: add esp, 0x10
         // 004ce95d: mov edi, ds:[edi+0x4]
         // 004ce960: test edi, edi
         // 004ce962: jnz 0x4ce940
      [-]ffb6????????e8
         // 004172b4: push ds:[esi+0x410]
         // 004172ba: call 0x416340
      [-]ffff6a025689be????????e8
         // 004172bf: push 0x2
         // 004172c1: push esi
         // 004172c2: mov ds:[esi+0x410], edi
         // 004172c8: call 0x423d00
      [-]000083c40c
         // 004172cd: add esp, 0xc
      [-]5f5e5dc3
         // 004ce980: pop edi
         // 004ce981: pop esi
         // 004ce982: pop ebp
         // 004ce983: retn 
      [-]558bec568b750883be????????007447
         // 004ce990: push ebp
         // 004ce991: mov ebp, esp
         // 004ce993: push esi
         // 004ce994: mov esi, ss:[ebp+0x8]
         // 004ce997: cmp ds:[esi+0x348], 0x0
         // 004ce99e: jz 0x4ce9e7
      [-]83be????????007409
         // 004ce9a0: cmp ds:[esi+0x410], 0x0
         // 004ce9a7: jz 0x4ce9b2
      [-]56e871ffffff83c404
         // 004ce9a9: push esi
         // 004ce9aa: call 0x4ce920
         // 004ce9af: add esp, 0x4
      [-]6a026a0256e8
         // 00417302: push 0x2
         // 00417304: push 0x2
         // 00417306: push esi
         // 00417307: call 0x423cc0
      [-]0000ffb6????????ffb6????????e88300000083c41485c07443
         // 0041730c: push ds:[esi+0x348]
         // 00417312: push ds:[esi+0x418]
         // 00417318: call 0x4173a0
         // 0041731d: add esp, 0x14
         // 00417320: test eax, eax
         // 00417322: jz 0x417367
      [-]ffb6????????68
         // 00417324: push ds:[esi+0x348]
         // 0041732a: push 0x45a6b8
      [-]837d0c00741d
         // 004ce9e7: cmp ss:[ebp+0xc], 0x0
         // 004ce9eb: jz 0x4cea0a
      [-]8b86????????85c07413
         // 004ce9ed: mov eax, ds:[esi+0x410]
         // 004ce9f3: test eax, eax
         // 004ce9f5: jz 0x4cea0a
      [-]ffff83c404c786????????????????
         // 004ce9fd: add esp, 0x4
         // 004cea00: mov ds:[esi+0x410], 0x0
      [-]6a026a0256e8
         // 0041735a: push 0x2
         // 0041735c: push 0x2
         // 0041735e: push esi
         // 0041735f: call 0x423cc0
      [-]837d0c007420
         // 004cea17: cmp ss:[ebp+0xc], 0x0
         // 004cea1b: jz 0x4cea3d
      [-]8b4e1085c9740b
         // 004cea1d: mov ecx, ds:[esi+0x10]
         // 004cea20: test ecx, ecx
         // 004cea22: jz 0x4cea2f
      [-]8b86????????3b4118740e
         // 004cea24: mov eax, ds:[esi+0x418]
         // 004cea2a: cmp eax, ds:[ecx+0x18]
         // 004cea2d: jz 0x4cea3d
      [-]ffb6????????e856faffff83c404
         // 004cea2f: push ds:[esi+0x418]
         // 004cea35: call 0x4ce490
         // 004cea3a: add esp, 0x4
      [-]6a0256e8
         // 0041738d: push 0x2
         // 0041738f: push esi
         // 00417390: call 0x423d00
      [-]000083c4085e5dc3
         // 00417395: add esp, 0x8
         // 00417398: pop esi
         // 00417399: pop ebp
         // 0041739a: retn 
      [-]558bec51568b7508c745fc????????85f60f84ca000000
         // 004cea50: push ebp
         // 004cea51: mov ebp, esp
         // 004cea53: push ecx
         // 004cea54: push esi
         // 004cea55: mov esi, ss:[ebp+0x8]
         // 004cea58: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 004cea5f: test esi, esi
         // 004cea61: jz 0x4ceb31
      [-]837e0c000f84c0000000
         // 004cea67: cmp ds:[esi+0xc], 0x0
         // 004cea6b: jz 0x4ceb31
      [-]53578b7d0c5768
         // 004173c1: push ebx
         // 004173c2: push edi
         // 004173c3: mov edi, ss:[ebp+0xc]
         // 004173c6: push edi
         // 004173c7: push 0x45a5d0
      [-]83c40885c07415
         // 004173d1: add esp, 0x8
         // 004173d4: test eax, eax
         // 004173d6: jz 0x4173ed
      [-]83c404c745fc????????8bd8eb14
         // 0051c16f: add esp, 0x4
         // 0051c172: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 0051c179: mov ebx, eax
         // 0051c17b: jmp 0x51c191
      [-]8bd883c40885db7474
         // 004173f8: mov ebx, eax
         // 004173fa: add esp, 0x8
         // 004173fd: test ebx, ebx
         // 004173ff: jz 0x417475
      [-]8b3683c40885f6742b
         // 0041740c: mov esi, ds:[esi]
         // 0041740e: add esp, 0x8
         // 00417411: test esi, esi
         // 00417413: jz 0x417440
      [-]56e8550100008bf883c40485ff7434
         // 004ceac5: push esi
         // 004ceac6: call 0x4cec20
         // 004ceacb: mov edi, eax
         // 004ceacd: add esp, 0x4
         // 004cead0: test edi, edi
         // 004cead2: jz 0x4ceb08
      [-]8b3683c41085f675d5
         // 00461b97: mov esi, ds:[esi]
         // 00461b99: add esp, 0x10
         // 00461b9c: test esi, esi
         // 00461b9e: jnz 0x461b75
      [-]837dfc007509
         // 004ceaf0: cmp ss:[ebp+0xfffffffffffffffc], 0x0
         // 004ceaf4: jnz 0x4ceaff
      [-]5f5b33c05e8be55dc3
         // 004ceaff: pop edi
         // 004ceb00: pop ebx
         // 004ceb01: xor eax, eax
         // 004ceb03: pop esi
         // 004ceb04: mov esp, ebp
         // 004ceb06: pop ebp
         // 004ceb07: retn 
      [-]83c408837dfc007509
         // 004f0fc3: add esp, 0x8
         // 004f0fc6: cmp ss:[ebp+0xfffffffffffffffc], 0x0
         // 004f0fca: jnz 0x4f0fd5
      [-]5f5bb8????????5e8be55dc3
         // 004ceb25: pop edi
         // 004ceb26: pop ebx
         // 004ceb27: mov eax, 0x1
         // 004ceb2c: pop esi
         // 004ceb2d: mov esp, ebp
         // 004ceb2f: pop ebp
         // 004ceb30: retn 
      [-]33c05e8be55dc3
         // 004ceb31: xor eax, eax
         // 004ceb33: pop esi
         // 004ceb34: mov esp, ebp
         // 004ceb36: pop ebp
         // 004ceb37: retn 
      [-]558bec8b4508568b088b450c8b510c8b3085d2740e
         // 004ceb40: push ebp
         // 004ceb41: mov ebp, esp
         // 004ceb43: mov eax, ss:[ebp+0x8]
         // 004ceb46: push esi
         // 004ceb47: mov ecx, ds:[eax]
         // 004ceb49: mov eax, ss:[ebp+0xc]
         // 004ceb4c: mov edx, ds:[ecx+0xc]
         // 004ceb4f: mov esi, ds:[eax]
         // 004ceb51: test edx, edx
         // 004ceb53: jz 0x4ceb63
      [-]8a024284c075f9
         // 004ceb58: mov b1 al, b1 ds:[edx]
         // 004ceb5a: inc edx
         // 004ceb5b: test b1 al, b1 al
         // 004ceb5d: jnz 0x4ceb58
      [-]2bd1eb02
         // 004ceb5f: sub edx, ecx
         // 004ceb61: jmp 0x4ceb65
      [-]8b4e0c85c97419
         // 004ceb65: mov ecx, ds:[esi+0xc]
         // 004ceb68: test ecx, ecx
         // 004ceb6a: jz 0x4ceb85
      [-]8d710190
         // 004ceb6c: lea esi, ds:[ecx+0x1]
         // 004ceb6f: nop 
      [-]8a014184c075f9
         // 004ceb70: mov b1 al, b1 ds:[ecx]
         // 004ceb72: inc ecx
         // 004ceb73: test b1 al, b1 al
         // 004ceb75: jnz 0x4ceb70
      [-]2bce3bca760c
         // 004ceb77: sub ecx, esi
         // 004ceb79: cmp ecx, edx
         // 004ceb7b: jbe 0x4ceb89
      [-]b8????????5e5dc3
         // 004ceb7d: mov eax, 0x1
         // 004ceb82: pop esi
         // 004ceb83: pop ebp
         // 004ceb84: retn 
      [-]33c93bca
         // 004ceb85: xor ecx, ecx
         // 004ceb87: cmp ecx, edx
      [-]1bc05e5dc3
         // 004ceb89: sbb eax, eax
         // 004ceb8b: pop esi
         // 004ceb8c: pop ebp
         // 004ceb8d: retn 
      [-]558bec568b75088b462085c0740a
         // 004ceb90: push ebp
         // 004ceb91: mov ebp, esp
         // 004ceb93: push esi
         // 004ceb94: mov esi, ss:[ebp+0x8]
         // 004ceb97: mov eax, ds:[esi+0x20]
         // 004ceb9a: test eax, eax
         // 004ceb9c: jz 0x4ceba8
      [-]8b461085c0740a
         // 004ceba8: mov eax, ds:[esi+0x10]
         // 004cebab: test eax, eax
         // 004cebad: jz 0x4cebb9
      [-]8b460c85c0740a
         // 004cebb9: mov eax, ds:[esi+0xc]
         // 004cebbc: test eax, eax
         // 004cebbe: jz 0x4cebca
      [-]8b460485c0740a
         // 004cebca: mov eax, ds:[esi+0x4]
         // 004cebcd: test eax, eax
         // 004cebcf: jz 0x4cebdb
      [-]8b460885c0740a
         // 004cebdb: mov eax, ds:[esi+0x8]
         // 004cebde: test eax, eax
         // 004cebe0: jz 0x4cebec
      [-]8b462c85c0740a
         // 004cebec: mov eax, ds:[esi+0x2c]
         // 004cebef: test eax, eax
         // 004cebf1: jz 0x4cebfd
      [-]8b462885c0740a
         // 004cebfd: mov eax, ds:[esi+0x28]
         // 004cec00: test eax, eax
         // 004cec02: jz 0x4cec0e
      [-]83c4045e5dc3
         // 00417565: add esp, 0x4
         // 00417568: pop esi
         // 00417569: pop ebp
         // 0041756a: retn 
      [-]558bec8b5508b9
         // 00417570: push ebp
         // 00417571: mov ebp, esp
         // 00417573: mov edx, ss:[ebp+0x8]
         // 00417576: mov ecx, 0x45a498
      [-]5356578b4208bf
         // 0041757b: push ebx
         // 0041757c: push esi
         // 0041757d: push edi
         // 0041757e: mov eax, ds:[edx+0x8]
         // 00417581: mov edi, 0x45a578
      [-]0f45c88b420c85c00f45f88b421085c00f45d8837a2400740e
         // 0041758d: cmovnz ecx, eax
         // 00417590: mov eax, ds:[edx+0xc]
         // 00417593: test eax, eax
         // 00417595: cmovnz edi, eax
         // 00417598: mov eax, ds:[edx+0x10]
         // 0041759b: test eax, eax
         // 0041759d: cmovnz ebx, eax
         // 004175a0: cmp ds:[edx+0x24], 0x0
         // 004175a4: jz 0x4175b4
      [-]85c0740a
         // 004cec56: test eax, eax
         // 004cec58: jz 0x4cec64
      [-]80382ebe
         // 004175aa: cmp b1 ds:[eax], b1 0x2e
         // 004175ad: mov esi, 0x45a5ec
      [-]837a300051ff7204b9
         // 0051c349: cmp ds:[edx+0x30], 0x0
         // 0051c34d: push ecx
         // 0051c34e: push ds:[edx+0x4]
         // 0051c351: mov ecx, 0x65b8d0
      [-]ff721c8bc1ff72180f444508837a2400500f444d08b8
         // 0051c35d: push ds:[edx+0x1c]
         // 0051c360: mov eax, ecx
         // 0051c362: push ds:[edx+0x18]
         // 0051c365: cmovz eax, ss:[ebp+0x8]
         // 0051c369: cmp ds:[edx+0x24], 0x0
         // 0051c36d: push eax
         // 0051c36e: cmovz ecx, ss:[ebp+0x8]
         // 0051c372: mov eax, 0x65b8c4
      [-]837a3800575153b9
         // 0051c377: cmp ds:[edx+0x38], 0x0
         // 0051c37b: push edi
         // 0051c37c: push ecx
         // 0051c37d: push ebx
         // 0051c37e: mov ecx, 0x55e2e1
      [-]560f44c15068
         // 0051c383: push esi
         // 0051c384: cmovz eax, ecx
         // 0051c387: push eax
         // 0051c388: push 0x65b94c
      [-]83c42c5f5e5b5dc3
         // 0051c392: add esp, 0x2c
         // 0051c395: pop edi
         // 0051c396: pop esi
         // 0051c397: pop ebx
         // 0051c398: pop ebp
         // 0051c399: retn 
      [-]558bec568b75088b0685c0740a
         // 004cecc0: push ebp
         // 004cecc1: mov ebp, esp
         // 004cecc3: push esi
         // 004cecc4: mov esi, ss:[ebp+0x8]
         // 004cecc7: mov eax, ds:[esi]
         // 004cecc9: test eax, eax
         // 004ceccb: jz 0x4cecd7
      [-]ff750cff15??
         // 00417657: push ss:[ebp+0xc]
         // 0041765a: call ds:[0x607400]
      [-]83c40489065e5dc3
         // 00417660: add esp, 0x4
         // 00417663: mov ds:[esi], eax
         // 00417665: pop esi
         // 00417666: pop ebp
         // 00417667: retn 
      [-]558bec8b55088d4a010f1f80????????
         // 004cecf0: push ebp
         // 004cecf1: mov ebp, esp
         // 004cecf3: mov edx, ss:[ebp+0x8]
         // 004cecf6: lea ecx, ds:[edx+0x1]
         // 004cecf9: nop ds:[eax+0x0]
      [-]8a024284c075f9
         // 004ced00: mov b1 al, b1 ds:[edx]
         // 004ced02: inc edx
         // 004ced03: test b1 al, b1 al
         // 004ced05: jnz 0x4ced00
      [-]2bd18b4d0c538d5901
         // 004ced07: sub edx, ecx
         // 004ced09: mov ecx, ss:[ebp+0xc]
         // 004ced0c: push ebx
         // 004ced0d: lea ebx, ds:[ecx+0x1]
      [-]8a014184c075f9
         // 004ced10: mov b1 al, b1 ds:[ecx]
         // 004ced12: inc ecx
         // 004ced13: test b1 al, b1 al
         // 004ced15: jnz 0x4ced10
      [-]2bcb5b3bd17604
         // 004ced17: sub ecx, ebx
         // 004ced19: pop ebx
         // 004ced1a: cmp edx, ecx
         // 004ced1c: jbe 0x4ced22
      [-]33c05dc3
         // 004ced1e: xor eax, eax
         // 004ced20: pop ebp
         // 004ced21: retn 
      [-]2bca034d0c51ff7508e8
         // 004176a2: sub ecx, edx
         // 004176a4: add ecx, ss:[ebp+0xc]
         // 004176a7: push ecx
         // 004176a8: push ss:[ebp+0x8]
         // 004176ab: call 0x423d40
      [-]000083c408f7d81bc0f7d85dc3
         // 004176b0: add esp, 0x8
         // 004176b3: neg eax
         // 004176b5: sbb eax, eax
         // 004176b7: neg eax
         // 004176b9: pop ebp
         // 004176ba: retn 
      [-]558bec538b5d1056578b7d08ff77108b470453ff750cffd08b0f83c40c8b04818945088b3085f67438
         // 004ced40: push ebp
         // 004ced41: mov ebp, esp
         // 004ced43: push ebx
         // 004ced44: mov ebx, ss:[ebp+0x10]
         // 004ced47: push esi
         // 004ced48: push edi
         // 004ced49: mov edi, ss:[ebp+0x8]
         // 004ced4c: push ds:[edi+0x10]
         // 004ced4f: mov eax, ds:[edi+0x4]
         // 004ced52: push ebx
         // 004ced53: push ss:[ebp+0xc]
         // 004ced56: call eax
         // 004ced58: mov ecx, ds:[edi]
         // 004ced5a: add esp, 0xc
         // 004ced5d: mov eax, ds:[ecx+eax*0x4]
         // 004ced60: mov ss:[ebp+0x8], eax
         // 004ced63: mov esi, ds:[eax]
         // 004ced65: test esi, esi
         // 004ced67: jz 0x4ceda1
      [-]0f1f80????????
         // 004ced69: nop ds:[eax+0x0]
      [-]8b0653ff750cff7008ff70048b4708ffd083c41085c07509
         // 004ced70: mov eax, ds:[esi]
         // 004ced72: push ebx
         // 004ced73: push ss:[ebp+0xc]
         // 004ced76: push ds:[eax+0x8]
         // 004ced79: push ds:[eax+0x4]
         // 004ced7c: mov eax, ds:[edi+0x8]
         // 004ced7f: call eax
         // 004ced81: add esp, 0x10
         // 004ced84: test eax, eax
         // 004ced86: jnz 0x4ced91
      [-]8b760885f675e1
         // 004ced88: mov esi, ds:[esi+0x8]
         // 004ced8b: test esi, esi
         // 004ced8d: jnz 0x4ced70
      [-]5756ff7508e8
         // 00417711: push edi
         // 00417712: push esi
         // 00417713: push ss:[ebp+0x8]
         // 00417716: call 0x4240a0
      [-]000083c40cff4f14
         // 0041771b: add esp, 0xc
         // 0041771e: dec ds:[edi+0x14]
      [-]ff751453ff750ce8430400008bf083c40c85f67432
         // 004ceda1: push ss:[ebp+0x14]
         // 004ceda4: push ebx
         // 004ceda5: push ss:[ebp+0xc]
         // 004ceda8: call 0x4cf1f0
         // 004cedad: mov esi, eax
         // 004cedaf: add esp, 0xc
         // 004cedb2: test esi, esi
         // 004cedb4: jz 0x4cede8
      [-]8b450856ff700450e8
         // 00417736: mov eax, ss:[ebp+0x8]
         // 00417739: push esi
         // 0041773a: push ds:[eax+0x4]
         // 0041773d: push eax
         // 0041773e: call 0x424000
      [-]000083c40c85c0740b
         // 00417743: add esp, 0xc
         // 00417746: test eax, eax
         // 00417748: jz 0x417755
      [-]ff47148b45145f5e5b5dc3
         // 004cedca: inc ds:[edi+0x14]
         // 004cedcd: mov eax, ss:[ebp+0x14]
         // 004cedd0: pop edi
         // 004cedd1: pop esi
         // 004cedd2: pop ebx
         // 004cedd3: pop ebp
         // 004cedd4: retn 
      [-]ff7604ff15
         // 00417755: push ds:[esi+0x4]
         // 00417758: call ds:[0x6073f8]
      [-]5f5e33c05b5dc3
         // 004cede8: pop edi
         // 004cede9: pop esi
         // 004cedea: xor eax, eax
         // 004cedec: pop ebx
         // 004ceded: pop ebp
         // 004cedee: retn 
      [-]558bec837d0800744e
         // 004cedf0: push ebp
         // 004cedf1: mov ebp, esp
         // 004cedf3: cmp ss:[ebp+0x8], 0x0
         // 004cedf7: jz 0x4cee47
      [-]837d0c007448
         // 004cedf9: cmp ss:[ebp+0xc], 0x0
         // 004cedfd: jz 0x4cee47
      [-]837d10007442
         // 004cedff: cmp ss:[ebp+0x10], 0x0
         // 004cee03: jz 0x4cee47
      [-]837d1400743c
         // 004cee05: cmp ss:[ebp+0x14], 0x0
         // 004cee09: jz 0x4cee47
      [-]566a18ff15
         // 0041778b: push esi
         // 0041778c: push 0x18
         // 0041778e: call ds:[0x6073f4]
      [-]8bf083c40485f67425
         // 00417794: mov esi, eax
         // 00417796: add esp, 0x4
         // 00417799: test esi, esi
         // 0041779b: jz 0x4177c2
      [-]ff7514ff7510ff750cff750856e86101000083c41485c0740c
         // 004cee1d: push ss:[ebp+0x14]
         // 004cee20: push ss:[ebp+0x10]
         // 004cee23: push ss:[ebp+0xc]
         // 004cee26: push ss:[ebp+0x8]
         // 004cee29: push esi
         // 004cee2a: call 0x4cef90
         // 004cee2f: add esp, 0x14
         // 004cee32: test eax, eax
         // 004cee34: jz 0x4cee42
      [-]83c40433f6
         // 004177bd: add esp, 0x4
         // 004177c0: xor esi, esi
      [-]8bc65e5dc3
         // 004cee42: mov eax, esi
         // 004cee44: pop esi
         // 004cee45: pop ebp
         // 004cee46: retn 
      [-]33c05dc3
         // 004cee47: xor eax, eax
         // 004cee49: pop ebp
         // 004cee4a: retn 
      [-]558bec568b75085733ff397e107e1e
         // 004cee50: push ebp
         // 004cee51: mov ebp, esp
         // 004cee53: push esi
         // 004cee54: mov esi, ss:[ebp+0x8]
         // 004cee57: push edi
         // 004cee58: xor edi, edi
         // 004cee5a: cmp ds:[esi+0x10], edi
         // 004cee5d: jle 0x4cee7d
      [-]8b0656ff34b8e8
         // 004177e0: mov eax, ds:[esi]
         // 004177e2: push esi
         // 004177e3: push ds:[eax+edi*0x4]
         // 004177e6: call 0x423fc0
      [-]00008b0683c408c704b8????????473b
         // 004177eb: mov eax, ds:[esi]
         // 004177ed: add esp, 0x8
         // 004177f0: mov ds:[eax+edi*0x4], 0x0
         // 004177f7: inc edi
         // 004177f8: cmp edi, ds:[esi+0x10]
         // 004177fb: jl 0x4177e0

  }
  condition:
    all of them
}
