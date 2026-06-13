rule neshta_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         5383c4bcbb????????54e8a9fffffff644242c017405
         // 00401098: push ebx
         // 00401099: add esp, 0xffffffffffffffbc
         // 0040109c: mov ebx, 0xa
         // 004010a1: push esp
         // 004010a2: call GetStartupInfoA
         // 004010a7: test b1 ss:[esp+0x2c], b1 0x1
         // 004010ac: jz 0x4010b3
      [-]0fb75c2430
         // 004010ae: movzx ebx, b2 ss:[esp+0x30]
      [-]8bc383c4445bc3
         // 004010b3: mov eax, ebx
         // 004010b5: add esp, 0x44
         // 004010b8: pop ebx
         // 004010b9: retn 
      [-]5356be????????833e00753a
         // 004010fc: push ebx
         // 004010fd: push esi
         // 004010fe: mov esi, 0x40a5d0
         // 00401103: cmp ds:[esi], 0x0
         // 00401106: jnz 0x401142
      [-]68????????6a00e8a8ffffff8bc885c97505
         // 00401108: push 0x644
         // 0040110d: push 0x0
         // 0040110f: call LocalAlloc
         // 00401114: mov ecx, eax
         // 00401116: test ecx, ecx
         // 00401118: jnz 0x40111f
      [-]33c05e5bc3
         // 0040111a: xor eax, eax
         // 0040111c: pop esi
         // 0040111d: pop ebx
         // 0040111e: retn 
      [-]a1????????8901890d????????33d2
         // 0040111f: mov eax, ds:[0x40a5cc]
         // 00401124: mov ds:[ecx], eax
         // 00401126: mov ds:[0x40a5cc], ecx
         // 0040112c: xor edx, edx
      [-]8bc203c08d44c1048b1e891889064283fa6475ec
         // 0040112e: mov eax, edx
         // 00401130: add eax, eax
         // 00401132: lea eax, ds:[ecx+eax*0x8]
         // 00401136: mov ebx, ds:[esi]
         // 00401138: mov ds:[eax], ebx
         // 0040113a: mov ds:[esi], eax
         // 0040113c: inc edx
         // 0040113d: cmp edx, 0x64
         // 00401140: jnz 0x40112e
      [-]8b068b1089165e5bc3
         // 00401142: mov eax, ds:[esi]
         // 00401144: mov edx, ds:[eax]
         // 00401146: mov ds:[esi], edx
         // 00401148: pop esi
         // 00401149: pop ebx
         // 0040114a: retn 
      [-]8900894004c3
         // 0040114c: mov ds:[eax], eax
         // 0040114e: mov ds:[eax+0x4], eax
         // 00401151: retn 
      [-]53568bf28bd8e89dffffff85c07505
         // 00401154: push ebx
         // 00401155: push esi
         // 00401156: mov esi, edx
         // 00401158: mov ebx, eax
         // 0040115a: call 0x4010fc
         // 0040115f: test eax, eax
         // 00401161: jnz 0x401168
      [-]33c05e5bc3
         // 00401163: xor eax, eax
         // 00401165: pop esi
         // 00401166: pop ebx
         // 00401167: retn 
      [-]8b168950088b560489500c8b1389108958048942048903b0015e5bc3
         // 00401168: mov edx, ds:[esi]
         // 0040116a: mov ds:[eax+0x8], edx
         // 0040116d: mov edx, ds:[esi+0x4]
         // 00401170: mov ds:[eax+0xc], edx
         // 00401173: mov edx, ds:[ebx]
         // 00401175: mov ds:[eax], edx
         // 00401177: mov ds:[eax+0x4], ebx
         // 0040117a: mov ds:[edx+0x4], eax
         // 0040117d: mov ds:[ebx], eax
         // 0040117f: mov b1 al, b1 0x1
         // 00401181: pop esi
         // 00401182: pop ebx
         // 00401183: retn 
      [-]8b50048b08890a8951048b15????????8910a3????????c3
         // 00401184: mov edx, ds:[eax+0x4]
         // 00401187: mov ecx, ds:[eax]
         // 00401189: mov ds:[edx], ecx
         // 0040118b: mov ds:[ecx+0x4], edx
         // 0040118e: mov edx, ds:[0x40a5d0]
         // 00401194: mov ds:[eax], edx
         // 00401196: mov ds:[0x40a5d0], eax
         // 0040119b: retn 
      [-]53565755518bf18914248be88b5d008b04248b1089168b5004895604
         // 0040119c: push ebx
         // 0040119d: push esi
         // 0040119e: push edi
         // 0040119f: push ebp
         // 004011a0: push ecx
         // 004011a1: mov esi, ecx
         // 004011a3: mov ss:[esp], edx
         // 004011a6: mov ebp, eax
         // 004011a8: mov ebx, ss:[ebp+0x0]
         // 004011ab: mov eax, ss:[esp]
         // 004011ae: mov edx, ds:[eax]
         // 004011b0: mov ds:[esi], edx
         // 004011b2: mov edx, ds:[eax+0x4]
         // 004011b5: mov ds:[esi+0x4], edx
      [-]8b3b8b068b530803530c3bc27514
         // 004011b8: mov edi, ds:[ebx]
         // 004011ba: mov eax, ds:[esi]
         // 004011bc: mov edx, ds:[ebx+0x8]
         // 004011bf: add edx, ds:[ebx+0xc]
         // 004011c2: cmp eax, edx
         // 004011c4: jnz 0x4011da
      [-]8bc3e8b7ffffff8b430889068b430c014604eb15
         // 004011c6: mov eax, ebx
         // 004011c8: call 0x401184
         // 004011cd: mov eax, ds:[ebx+0x8]
         // 004011d0: mov ds:[esi], eax
         // 004011d2: mov eax, ds:[ebx+0xc]
         // 004011d5: add ds:[esi+0x4], eax
         // 004011d8: jmp 0x4011ef
      [-]0346043b4308750d
         // 004011da: add eax, ds:[esi+0x4]
         // 004011dd: cmp eax, ds:[ebx+0x8]
         // 004011e0: jnz 0x4011ef
      [-]8bc3e89bffffff8b430c014604
         // 004011e2: mov eax, ebx
         // 004011e4: call 0x401184
         // 004011e9: mov eax, ds:[ebx+0xc]
         // 004011ec: add ds:[esi+0x4], eax
      [-]8bdf3beb75c3
         // 004011ef: mov ebx, edi
         // 004011f1: cmp ebp, ebx
         // 004011f3: jnz 0x4011b8
      [-]8bd68bc5e856ffffff84c07504
         // 004011f5: mov edx, esi
         // 004011f7: mov eax, ebp
         // 004011f9: call 0x401154
         // 004011fe: test b1 al, b1 al
         // 00401200: jnz 0x401206
      [-]33c08906
         // 00401202: xor eax, eax
         // 00401204: mov ds:[esi], eax
      [-]5a5d5f5e5bc3
         // 00401206: pop edx
         // 00401207: pop ebp
         // 00401208: pop edi
         // 00401209: pop esi
         // 0040120a: pop ebx
         // 0040120b: retn 
      [-]5356575583c4f88bd88bfb
         // 0040120c: push ebx
         // 0040120d: push esi
         // 0040120e: push edi
         // 0040120f: push ebp
         // 00401210: add esp, 0xfffffffffffffff8
         // 00401213: mov ebx, eax
         // 00401215: mov edi, ebx
      [-]8b328b43083bf07270
         // 00401217: mov esi, ds:[edx]
         // 00401219: mov eax, ds:[ebx+0x8]
         // 0040121c: cmp esi, eax
         // 0040121e: jb 0x401290
      [-]8bce034a048be8036b0c3bcd7762
         // 00401220: mov ecx, esi
         // 00401222: add ecx, ds:[edx+0x4]
         // 00401225: mov ebp, eax
         // 00401227: add ebp, ds:[ebx+0xc]
         // 0040122a: cmp ecx, ebp
         // 0040122c: ja 0x401290
      [-]3bf0751b
         // 0040122e: cmp esi, eax
         // 00401230: jnz 0x40124d
      [-]8b42040143088b420429430c837b0c007548
         // 00401232: mov eax, ds:[edx+0x4]
         // 00401235: add ds:[ebx+0x8], eax
         // 00401238: mov eax, ds:[edx+0x4]
         // 0040123b: sub ds:[ebx+0xc], eax
         // 0040123e: cmp ds:[ebx+0xc], 0x0
         // 00401242: jnz 0x40128c
      [-]8bc3e839ffffffeb3f
         // 00401244: mov eax, ebx
         // 00401246: call 0x401184
         // 0040124b: jmp 0x40128c
      [-]8bce8b7a0403cf8be8036b0c3bcd7505
         // 0040124d: mov ecx, esi
         // 0040124f: mov edi, ds:[edx+0x4]
         // 00401252: add ecx, edi
         // 00401254: mov ebp, eax
         // 00401256: add ebp, ds:[ebx+0xc]
         // 00401259: cmp ecx, ebp
         // 0040125b: jnz 0x401262
      [-]297b0ceb2a
         // 0040125d: sub ds:[ebx+0xc], edi
         // 00401260: jmp 0x40128c
      [-]8b0a034a04890c248b7b08037b0c2bf9897c24042bf089730c8bd48bc3e8d0feffff84c07504
         // 00401262: mov ecx, ds:[edx]
         // 00401264: add ecx, ds:[edx+0x4]
         // 00401267: mov ss:[esp], ecx
         // 0040126a: mov edi, ds:[ebx+0x8]
         // 0040126d: add edi, ds:[ebx+0xc]
         // 00401270: sub edi, ecx
         // 00401272: mov ss:[esp+0x4], edi
         // 00401276: sub esi, eax
         // 00401278: mov ds:[ebx+0xc], esi
         // 0040127b: mov edx, esp
         // 0040127d: mov eax, ebx
         // 0040127f: call 0x401154
         // 00401284: test b1 al, b1 al
         // 00401286: jnz 0x40128c
      [-]33c0eb0c
         // 00401288: xor eax, eax
         // 0040128a: jmp 0x401298
      [-]b001eb08
         // 0040128c: mov b1 al, b1 0x1
         // 0040128e: jmp 0x401298
      [-]8b1b3bfb7581
         // 00401290: mov ebx, ds:[ebx]
         // 00401292: cmp edi, ebx
         // 00401294: jnz 0x401217
      [-]595a5d5f5e5bc3
         // 00401298: pop ecx
         // 00401299: pop edx
         // 0040129a: pop ebp
         // 0040129b: pop edi
         // 0040129c: pop esi
         // 0040129d: pop ebx
         // 0040129e: retn 
      [-]5356578bda8bf081fe????????7d07
         // 004012a0: push ebx
         // 004012a1: push esi
         // 004012a2: push edi
         // 004012a3: mov ebx, edx
         // 004012a5: mov esi, eax
         // 004012a7: cmp esi, 0x100000
         // 004012ad: jge 0x4012b6
      [-]be????????eb0c
         // 004012af: mov esi, 0x100000
         // 004012b4: jmp 0x4012c2
      [-]81c6????????81e6????????
         // 004012b6: add esi, 0xffff
         // 004012bc: and esi, 0xffffffffffff0000
      [-]8973046a0168????????566a00e8f8fdffff8bf8893b85ff7423
         // 004012c2: mov ds:[ebx+0x4], esi
         // 004012c5: push 0x1
         // 004012c7: push 0x2000
         // 004012cc: push esi
         // 004012cd: push 0x0
         // 004012cf: call VirtualAlloc
         // 004012d4: mov edi, eax
         // 004012d6: mov ds:[ebx], edi
         // 004012d8: test edi, edi
         // 004012da: jz 0x4012ff
      [-]8bd3b8????????e86cfeffff84c07513
         // 004012dc: mov edx, ebx
         // 004012de: mov eax, 0x40a5d4
         // 004012e3: call 0x401154
         // 004012e8: test b1 al, b1 al
         // 004012ea: jnz 0x4012ff
      [-]68????????6a008b0350e8d9fdffff33c08903
         // 004012ec: push 0x8000
         // 004012f1: push 0x0
         // 004012f3: mov eax, ds:[ebx]
         // 004012f5: push eax
         // 004012f6: call VirtualFree
         // 004012fb: xor eax, eax
         // 004012fd: mov ds:[ebx], eax
      [-]5f5e5bc3
         // 004012ff: pop edi
         // 00401300: pop esi
         // 00401301: pop ebx
         // 00401302: retn 
      [-]535657558bd98bf28be8c74304????????6a0468????????68????????55e8a5fdffff8bf8893b85ff751f
         // 00401304: push ebx
         // 00401305: push esi
         // 00401306: push edi
         // 00401307: push ebp
         // 00401308: mov ebx, ecx
         // 0040130a: mov esi, edx
         // 0040130c: mov ebp, eax
         // 0040130e: mov ds:[ebx+0x4], 0x100000
         // 00401315: push 0x4
         // 00401317: push 0x2000
         // 0040131c: push 0x100000
         // 00401321: push ebp
         // 00401322: call VirtualAlloc
         // 00401327: mov edi, eax
         // 00401329: mov ds:[ebx], edi
         // 0040132b: test edi, edi
         // 0040132d: jnz 0x40134e
      [-]81c6????????81e6????????8973046a0468????????5655e880fdffff8903
         // 0040132f: add esi, 0xffff
         // 00401335: and esi, 0xffffffffffff0000
         // 0040133b: mov ds:[ebx+0x4], esi
         // 0040133e: push 0x4
         // 00401340: push 0x2000
         // 00401345: push esi
         // 00401346: push ebp
         // 00401347: call VirtualAlloc
         // 0040134c: mov ds:[ebx], eax
      [-]833b007423
         // 0040134e: cmp ds:[ebx], 0x0
         // 00401351: jz 0x401376
      [-]8bd3b8????????e8f5fdffff84c07513
         // 00401353: mov edx, ebx
         // 00401355: mov eax, 0x40a5d4
         // 0040135a: call 0x401154
         // 0040135f: test b1 al, b1 al
         // 00401361: jnz 0x401376
      [-]68????????6a008b0350e862fdffff33c08903
         // 00401363: push 0x8000
         // 00401368: push 0x0
         // 0040136a: mov eax, ds:[ebx]
         // 0040136c: push eax
         // 0040136d: call VirtualFree
         // 00401372: xor eax, eax
         // 00401374: mov ds:[ebx], eax
      [-]5d5f5e5bc3
         // 00401376: pop ebp
         // 00401377: pop edi
         // 00401378: pop esi
         // 00401379: pop ebx
         // 0040137a: retn 
      [-]5356575583c4ec894c2404891424c7442408????????33d28954240c8be88b042403c5894424108b1d????????eb51
         // 0040137c: push ebx
         // 0040137d: push esi
         // 0040137e: push edi
         // 0040137f: push ebp
         // 00401380: add esp, 0xffffffffffffffec
         // 00401383: mov ss:[esp+0x4], ecx
         // 00401387: mov ss:[esp], edx
         // 0040138a: mov ss:[esp+0x8], 0xffffffffffffffff
         // 00401392: xor edx, edx
         // 00401394: mov ss:[esp+0xc], edx
         // 00401398: mov ebp, eax
         // 0040139a: mov eax, ss:[esp]
         // 0040139d: add eax, ebp
         // 0040139f: mov ss:[esp+0x10], eax
         // 004013a3: mov ebx, ds:[0x40a5d4]
         // 004013a9: jmp 0x4013fc
      [-]8b3b8b73083bee7746
         // 004013ab: mov edi, ds:[ebx]
         // 004013ad: mov esi, ds:[ebx+0x8]
         // 004013b0: cmp ebp, esi
         // 004013b2: ja 0x4013fa
      [-]8bc603430c3b442410773b
         // 004013b4: mov eax, esi
         // 004013b6: add eax, ds:[ebx+0xc]
         // 004013b9: cmp eax, ss:[esp+0x10]
         // 004013bd: ja 0x4013fa
      [-]3b7424087304
         // 004013bf: cmp esi, ss:[esp+0x8]
         // 004013c3: jnb 0x4013c9
      [-]89742408
         // 004013c5: mov ss:[esp+0x8], esi
      [-]8bc603430c3b44240c7604
         // 004013c9: mov eax, esi
         // 004013cb: add eax, ds:[ebx+0xc]
         // 004013ce: cmp eax, ss:[esp+0xc]
         // 004013d2: jbe 0x4013d8
      [-]8944240c
         // 004013d4: mov ss:[esp+0xc], eax
      [-]68????????6a0056e8effcffff85c0750a
         // 004013d8: push 0x8000
         // 004013dd: push 0x0
         // 004013df: push esi
         // 004013e0: call VirtualFree
         // 004013e5: test eax, eax
         // 004013e7: jnz 0x4013f3
      [-]c705????????????????
         // 004013e9: mov ds:[0x40a5b0], 0x1
      [-]8bc3e88afdffff
         // 004013f3: mov eax, ebx
         // 004013f5: call 0x401184
      [-]81fb????????75a7
         // 004013fc: cmp ebx, 0x40a5d4
         // 00401402: jnz 0x4013ab
      [-]8b44240433d28910837c240c007419
         // 00401404: mov eax, ss:[esp+0x4]
         // 00401408: xor edx, edx
         // 0040140a: mov ds:[eax], edx
         // 0040140c: cmp ss:[esp+0xc], 0x0
         // 00401411: jz 0x40142c
      [-]8b4424048b54240889108b44240c2b4424088b542404894204
         // 00401413: mov eax, ss:[esp+0x4]
         // 00401417: mov edx, ss:[esp+0x8]
         // 0040141b: mov ds:[eax], edx
         // 0040141d: mov eax, ss:[esp+0xc]
         // 00401421: sub eax, ss:[esp+0x8]
         // 00401425: mov edx, ss:[esp+0x4]
         // 00401429: mov ds:[edx+0x4], eax
      [-]83c4145d5f5e5bc3
         // 0040142c: add esp, 0x14
         // 0040142f: pop ebp
         // 00401430: pop edi
         // 00401431: pop esi
         // 00401432: pop ebx
         // 00401433: retn 
      [-]5356575583c4f4894c24048914248bd08bea81e5????????03142481c2????????81e2????????895424088b44240489288b4424082bc58b5424048942048b35????????eb3c
         // 00401434: push ebx
         // 00401435: push esi
         // 00401436: push edi
         // 00401437: push ebp
         // 00401438: add esp, 0xfffffffffffffff4
         // 0040143b: mov ss:[esp+0x4], ecx
         // 0040143f: mov ss:[esp], edx
         // 00401442: mov edx, eax
         // 00401444: mov ebp, edx
         // 00401446: and ebp, 0xfffffffffffff000
         // 0040144c: add edx, ss:[esp]
         // 0040144f: add edx, 0xfff
         // 00401455: and edx, 0xfffffffffffff000
         // 0040145b: mov ss:[esp+0x8], edx
         // 0040145f: mov eax, ss:[esp+0x4]
         // 00401463: mov ds:[eax], ebp
         // 00401465: mov eax, ss:[esp+0x8]
         // 00401469: sub eax, ebp
         // 0040146b: mov edx, ss:[esp+0x4]
         // 0040146f: mov ds:[edx+0x4], eax
         // 00401472: mov esi, ds:[0x40a5d4]
         // 00401478: jmp 0x4014b6
      [-]8b5e088b7e0c03fb3beb7602
         // 0040147a: mov ebx, ds:[esi+0x8]
         // 0040147d: mov edi, ds:[esi+0xc]
         // 00401480: add edi, ebx
         // 00401482: cmp ebp, ebx
         // 00401484: jbe 0x401488
      [-]3b7c24087604
         // 00401488: cmp edi, ss:[esp+0x8]
         // 0040148c: jbe 0x401492
      [-]8b7c2408
         // 0040148e: mov edi, ss:[esp+0x8]
      [-]3bfb761e
         // 00401492: cmp edi, ebx
         // 00401494: jbe 0x4014b4
      [-]6a0468????????2bfb5753e826fcffff85c0750a
         // 00401496: push 0x4
         // 00401498: push 0x1000
         // 0040149d: sub edi, ebx
         // 0040149f: push edi
         // 004014a0: push ebx
         // 004014a1: call VirtualAlloc
         // 004014a6: test eax, eax
         // 004014a8: jnz 0x4014b4
      [-]8b44240433d28910eb0a
         // 004014aa: mov eax, ss:[esp+0x4]
         // 004014ae: xor edx, edx
         // 004014b0: mov ds:[eax], edx
         // 004014b2: jmp 0x4014be
      [-]81fe????????75bc
         // 004014b6: cmp esi, 0x40a5d4
         // 004014bc: jnz 0x40147a
      [-]83c40c5d5f5e5bc3
         // 004014be: add esp, 0xc
         // 004014c1: pop ebp
         // 004014c2: pop edi
         // 004014c3: pop esi
         // 004014c4: pop ebx
         // 004014c5: retn 
      [-]53565755518bd88bf381c6????????81e6????????8934248beb03ea81e5????????8b042489018bc52b04248941048b35????????eb38
         // 004014c8: push ebx
         // 004014c9: push esi
         // 004014ca: push edi
         // 004014cb: push ebp
         // 004014cc: push ecx
         // 004014cd: mov ebx, eax
         // 004014cf: mov esi, ebx
         // 004014d1: add esi, 0xfff
         // 004014d7: and esi, 0xfffffffffffff000
         // 004014dd: mov ss:[esp], esi
         // 004014e0: mov ebp, ebx
         // 004014e2: add ebp, edx
         // 004014e4: and ebp, 0xfffffffffffff000
         // 004014ea: mov eax, ss:[esp]
         // 004014ed: mov ds:[ecx], eax
         // 004014ef: mov eax, ebp
         // 004014f1: sub eax, ss:[esp]
         // 004014f4: mov ds:[ecx+0x4], eax
         // 004014f7: mov esi, ds:[0x40a5d4]
         // 004014fd: jmp 0x401537
      [-]8b5e088b7e0c03fb3b1c247303
         // 004014ff: mov ebx, ds:[esi+0x8]
         // 00401502: mov edi, ds:[esi+0xc]
         // 00401505: add edi, ebx
         // 00401507: cmp ebx, ss:[esp]
         // 0040150a: jnb 0x40150f
      [-]3bef7302
         // 0040150f: cmp ebp, edi
         // 00401511: jnb 0x401515
      [-]3bfb761c
         // 00401515: cmp edi, ebx
         // 00401517: jbe 0x401535
      [-]68????????2bfb5753e8adfbffff85c0750a
         // 00401519: push 0x4000
         // 0040151e: sub edi, ebx
         // 00401520: push edi
         // 00401521: push ebx
         // 00401522: call VirtualFree
         // 00401527: test eax, eax
         // 00401529: jnz 0x401535
      [-]c705????????????????
         // 0040152b: mov ds:[0x40a5b0], 0x2
      [-]81fe????????75c0
         // 00401537: cmp esi, 0x40a5d4
         // 0040153d: jnz 0x4014ff
      [-]5a5d5f5e5bc3
         // 0040153f: pop edx
         // 00401540: pop ebp
         // 00401541: pop edi
         // 00401542: pop esi
         // 00401543: pop ebx
         // 00401544: retn 
      [-]5356575583c4f88bf28bf8bd????????81c7????????81e7????????
         // 00401548: push ebx
         // 00401549: push esi
         // 0040154a: push edi
         // 0040154b: push ebp
         // 0040154c: add esp, 0xfffffffffffffff8
         // 0040154f: mov esi, edx
         // 00401551: mov edi, eax
         // 00401553: mov ebp, 0x40a5e4
         // 00401558: add edi, 0x3fff
         // 0040155e: and edi, 0xffffffffffffc000
      [-]8b5d00eb33
         // 00401564: mov ebx, ss:[ebp+0x0]
         // 00401567: jmp 0x40159c
      [-]3b7b0c7f2c
         // 00401569: cmp edi, ds:[ebx+0xc]
         // 0040156c: jg 0x40159a
      [-]8bce8bd78b4308e8bafeffff833e007450
         // 0040156e: mov ecx, esi
         // 00401570: mov edx, edi
         // 00401572: mov eax, ds:[ebx+0x8]
         // 00401575: call 0x401434
         // 0040157a: cmp ds:[esi], 0x0
         // 0040157d: jz 0x4015cf
      [-]8b46040143088b460429430c837b0c00753e
         // 0040157f: mov eax, ds:[esi+0x4]
         // 00401582: add ds:[ebx+0x8], eax
         // 00401585: mov eax, ds:[esi+0x4]
         // 00401588: sub ds:[ebx+0xc], eax
         // 0040158b: cmp ds:[ebx+0xc], 0x0
         // 0040158f: jnz 0x4015cf
      [-]8bc3e8ecfbffffeb35
         // 00401591: mov eax, ebx
         // 00401593: call 0x401184
         // 00401598: jmp 0x4015cf
      [-]3bdd75c9
         // 0040159c: cmp ebx, ebp
         // 0040159e: jnz 0x401569
      [-]8bd68bc7e8f7fcffff833e007421
         // 004015a0: mov edx, esi
         // 004015a2: mov eax, edi
         // 004015a4: call 0x4012a0
         // 004015a9: cmp ds:[esi], 0x0
         // 004015ac: jz 0x4015cf
      [-]8bcc8bd68bc5e8e3fbffff833c240075a5
         // 004015ae: mov ecx, esp
         // 004015b0: mov edx, esi
         // 004015b2: mov eax, ebp
         // 004015b4: call 0x40119c
         // 004015b9: cmp ss:[esp], 0x0
         // 004015bd: jnz 0x401564
      [-]8bcc8b56048b06e8b1fdffff33c08906
         // 004015bf: mov ecx, esp
         // 004015c1: mov edx, ds:[esi+0x4]
         // 004015c4: mov eax, ds:[esi]
         // 004015c6: call 0x40137c
         // 004015cb: xor eax, eax
         // 004015cd: mov ds:[esi], eax
      [-]595a5d5f5e5bc3
         // 004015cf: pop ecx
         // 004015d0: pop edx
         // 004015d1: pop ebp
         // 004015d2: pop edi
         // 004015d3: pop esi
         // 004015d4: pop ebx
         // 004015d5: retn 
      [-]5356575583c4ec890c248bfa8bf0bd????????81c7????????81e7????????
         // 004015d8: push ebx
         // 004015d9: push esi
         // 004015da: push edi
         // 004015db: push ebp
         // 004015dc: add esp, 0xffffffffffffffec
         // 004015df: mov ss:[esp], ecx
         // 004015e2: mov edi, edx
         // 004015e4: mov esi, eax
         // 004015e6: mov ebp, 0x40a5e4
         // 004015eb: add edi, 0x3fff
         // 004015f1: and edi, 0xffffffffffffc000
      [-]8b5d00eb02
         // 004015f7: mov ebx, ss:[ebp+0x0]
         // 004015fa: jmp 0x4015fe
      [-]3bdd7405
         // 004015fe: cmp ebx, ebp
         // 00401600: jz 0x401607
      [-]3b730875f5
         // 00401602: cmp esi, ds:[ebx+0x8]
         // 00401605: jnz 0x4015fc
      [-]3b73087557
         // 00401607: cmp esi, ds:[ebx+0x8]
         // 0040160a: jnz 0x401663
      [-]3b7b0c0f8e96000000
         // 0040160c: cmp edi, ds:[ebx+0xc]
         // 0040160f: jle 0x4016ab
      [-]8d4c24048bd72b530c8b430803430ce8dbfcffff837c2404007433
         // 00401615: lea ecx, ss:[esp+0x4]
         // 00401619: mov edx, edi
         // 0040161b: sub edx, ds:[ebx+0xc]
         // 0040161e: mov eax, ds:[ebx+0x8]
         // 00401621: add eax, ds:[ebx+0xc]
         // 00401624: call 0x401304
         // 00401629: cmp ss:[esp+0x4], 0x0
         // 0040162e: jz 0x401663
      [-]8d4c240c8d5424048bc5e85dfbffff837c240c0075b1
         // 00401630: lea ecx, ss:[esp+0xc]
         // 00401634: lea edx, ss:[esp+0x4]
         // 00401638: mov eax, ebp
         // 0040163a: call 0x40119c
         // 0040163f: cmp ss:[esp+0xc], 0x0
         // 00401644: jnz 0x4015f7
      [-]8d4c240c8b5424088b442404e825fdffff8b042433d28910e990000000
         // 00401646: lea ecx, ss:[esp+0xc]
         // 0040164a: mov edx, ss:[esp+0x8]
         // 0040164e: mov eax, ss:[esp+0x4]
         // 00401652: call 0x40137c
         // 00401657: mov eax, ss:[esp]
         // 0040165a: xor edx, edx
         // 0040165c: mov ds:[eax], edx
         // 0040165e: jmp 0x4016f3
      [-]8d4c24048bd78bc6e894fcffff837c2404007434
         // 00401663: lea ecx, ss:[esp+0x4]
         // 00401667: mov edx, edi
         // 00401669: mov eax, esi
         // 0040166b: call 0x401304
         // 00401670: cmp ss:[esp+0x4], 0x0
         // 00401675: jz 0x4016ab
      [-]8d4c240c8d5424048bc5e816fbffff837c240c000f8566ffffff
         // 00401677: lea ecx, ss:[esp+0xc]
         // 0040167b: lea edx, ss:[esp+0x4]
         // 0040167f: mov eax, ebp
         // 00401681: call 0x40119c
         // 00401686: cmp ss:[esp+0xc], 0x0
         // 0040168b: jnz 0x4015f7
      [-]8d4c240c8b5424088b442404e8dafcffff8b042433d28910eb48
         // 00401691: lea ecx, ss:[esp+0xc]
         // 00401695: mov edx, ss:[esp+0x8]
         // 00401699: mov eax, ss:[esp+0x4]
         // 0040169d: call 0x40137c
         // 004016a2: mov eax, ss:[esp]
         // 004016a5: xor edx, edx
         // 004016a7: mov ds:[eax], edx
         // 004016a9: jmp 0x4016f3
      [-]8b6b083bf5753a
         // 004016ab: mov ebp, ds:[ebx+0x8]
         // 004016ae: cmp esi, ebp
         // 004016b0: jnz 0x4016ec
      [-]3b7b0c7f35
         // 004016b2: cmp edi, ds:[ebx+0xc]
         // 004016b5: jg 0x4016ec
      [-]8b0c248bd78bc5e871fdffff8b04248338007428
         // 004016b7: mov ecx, ss:[esp]
         // 004016ba: mov edx, edi
         // 004016bc: mov eax, ebp
         // 004016be: call 0x401434
         // 004016c3: mov eax, ss:[esp]
         // 004016c6: cmp ds:[eax], 0x0
         // 004016c9: jz 0x4016f3
      [-]8b04248b40040143088b04248b400429430c837b0c007510
         // 004016cb: mov eax, ss:[esp]
         // 004016ce: mov eax, ds:[eax+0x4]
         // 004016d1: add ds:[ebx+0x8], eax
         // 004016d4: mov eax, ss:[esp]
         // 004016d7: mov eax, ds:[eax+0x4]
         // 004016da: sub ds:[ebx+0xc], eax
         // 004016dd: cmp ds:[ebx+0xc], 0x0
         // 004016e1: jnz 0x4016f3
      [-]8bc3e89afaffffeb07
         // 004016e3: mov eax, ebx
         // 004016e5: call 0x401184
         // 004016ea: jmp 0x4016f3
      [-]8b042433d28910
         // 004016ec: mov eax, ss:[esp]
         // 004016ef: xor edx, edx
         // 004016f1: mov ds:[eax], edx
      [-]83c4145d5f5e5bc3
         // 004016f3: add esp, 0x14
         // 004016f6: pop ebp
         // 004016f7: pop edi
         // 004016f8: pop esi
         // 004016f9: pop ebx
         // 004016fa: retn 
      [-]53565783c4ec8bf98914248d98????????81e3????????8b342403f081e6????????3bde735b
         // 004016fc: push ebx
         // 004016fd: push esi
         // 004016fe: push edi
         // 004016ff: add esp, 0xffffffffffffffec
         // 00401702: mov edi, ecx
         // 00401704: mov ss:[esp], edx
         // 00401707: lea ebx, ds:[eax+0x3fff]
         // 0040170d: and ebx, 0xffffffffffffc000
         // 00401713: mov esi, ss:[esp]
         // 00401716: add esi, eax
         // 00401718: and esi, 0xffffffffffffc000
         // 0040171e: cmp ebx, esi
         // 00401720: jnb 0x40177d
      [-]8bcf8bd62bd38bc3e899fdffff8d4c24048bd7b8????????e85dfaffff8b5c240485db741f
         // 00401722: mov ecx, edi
         // 00401724: mov edx, esi
         // 00401726: sub edx, ebx
         // 00401728: mov eax, ebx
         // 0040172a: call 0x4014c8
         // 0040172f: lea ecx, ss:[esp+0x4]
         // 00401733: mov edx, edi
         // 00401735: mov eax, 0x40a5e4
         // 0040173a: call 0x40119c
         // 0040173f: mov ebx, ss:[esp+0x4]
         // 00401743: test ebx, ebx
         // 00401745: jz 0x401766
      [-]8d4c240c8b5424088bc3e826fcffff8b44240c894424048b44241089442408
         // 00401747: lea ecx, ss:[esp+0xc]
         // 0040174b: mov edx, ss:[esp+0x8]
         // 0040174f: mov eax, ebx
         // 00401751: call 0x40137c
         // 00401756: mov eax, ss:[esp+0xc]
         // 0040175a: mov ss:[esp+0x4], eax
         // 0040175e: mov eax, ss:[esp+0x10]
         // 00401762: mov ss:[esp+0x8], eax
      [-]837c2404007414
         // 00401766: cmp ss:[esp+0x4], 0x0
         // 0040176b: jz 0x401781
      [-]8d542404b8????????e891faffffeb04
         // 0040176d: lea edx, ss:[esp+0x4]
         // 00401771: mov eax, 0x40a5e4
         // 00401776: call 0x40120c
         // 0040177b: jmp 0x401781
      [-]33c08907
         // 0040177d: xor eax, eax
         // 0040177f: mov ds:[edi], eax
      [-]83c4145f5e5bc3
         // 00401781: add esp, 0x14
         // 00401784: pop edi
         // 00401785: pop esi
         // 00401786: pop ebx
         // 00401787: retn 
      [-]558bec33d25568????????64ff3264892268b4a54000e839f9ffff803d35a0400000740a
         // 00401788: push ebp
         // 00401789: mov ebp, esp
         // 0040178b: xor edx, edx
         // 0040178d: push ebp
         // 0040178e: push 0x40183e
         // 00401793: push fs:[edx]
         // 00401796: mov fs:[edx], esp
         // 00401799: push CriticalSection.DebugInfo
         // 0040179e: call InitializeCriticalSection
         // 004017a3: cmp b1 ds:[0x40a035], b1 0x0
         // 004017aa: jz 0x4017b6
      [-]68b4a54000e82ef9ffff
         // 004017ac: push CriticalSection.DebugInfo
         // 004017b1: call EnterCriticalSection
      [-]b8????????e88cf9ffffb8????????e882f9ffffb8????????e878f9ffff68????????6a00e8dcf8ffffa3????????833d????????00742f
         // 004017b6: mov eax, 0x40a5d4
         // 004017bb: call 0x40114c
         // 004017c0: mov eax, 0x40a5e4
         // 004017c5: call 0x40114c
         // 004017ca: mov eax, 0x40a610
         // 004017cf: call 0x40114c
         // 004017d4: push 0xff8
         // 004017d9: push 0x0
         // 004017db: call LocalAlloc
         // 004017e0: mov ds:[0x40a60c], eax
         // 004017e5: cmp ds:[0x40a60c], 0x0
         // 004017ec: jz 0x40181d
      [-]b8????????
         // 004017ee: mov eax, 0x3
      [-]8b15????????33c9894c82f4403d????????75ec
         // 004017f3: mov edx, ds:[0x40a60c]
         // 004017f9: xor ecx, ecx
         // 004017fb: mov ds:[edx+eax*0x4], ecx
         // 004017ff: inc eax
         // 00401800: cmp eax, 0x401
         // 00401805: jnz 0x4017f3
      [-]b8????????8940048900a3????????c605aca5400001
         // 00401807: mov eax, 0x40a5f4
         // 0040180c: mov ds:[eax+0x4], eax
         // 0040180f: mov ds:[eax], eax
         // 00401811: mov ds:[0x40a600], eax
         // 00401816: mov b1 ds:[0x40a5ac], b1 0x1
      [-]33c05a595964891068????????803d35a0400000740a
         // 0040181d: xor eax, eax
         // 0040181f: pop edx
         // 00401820: pop ecx
         // 00401821: pop ecx
         // 00401822: mov fs:[eax], edx
         // 00401825: push 0x401845
         // 0040182a: cmp b1 ds:[0x40a035], b1 0x0
         // 00401831: jz 0x40183d
      [-]68b4a54000e8aff8ffff
         // 00401833: push CriticalSection.DebugInfo
         // 00401838: call LeaveCriticalSection
      [-]a0aca540005dc3
         // 00401845: mov b1 al, b1 ds:[0x40a5ac]
         // 0040184a: pop ebp
         // 0040184b: retn 
      [-]558bec53803daca54000000f84cc000000
         // 0040184c: push ebp
         // 0040184d: mov ebp, esp
         // 0040184f: push ebx
         // 00401850: cmp b1 ds:[0x40a5ac], b1 0x0
         // 00401857: jz 0x401929
      [-]33d25568????????64ff32648922803d35a0400000740a
         // 0040185d: xor edx, edx
         // 0040185f: push ebp
         // 00401860: push 0x401922
         // 00401865: push fs:[edx]
         // 00401868: mov fs:[edx], esp
         // 0040186b: cmp b1 ds:[0x40a035], b1 0x0
         // 00401872: jz 0x40187e
      [-]68b4a54000e866f8ffff
         // 00401874: push CriticalSection.DebugInfo
         // 00401879: call EnterCriticalSection
      [-]c605aca5400000a1????????50e834f8ffff33c0a3????????8b1d????????eb12
         // 0040187e: mov b1 ds:[0x40a5ac], b1 0x0
         // 00401885: mov eax, ds:[0x40a60c]
         // 0040188a: push eax
         // 0040188b: call LocalFree
         // 00401890: xor eax, eax
         // 00401892: mov ds:[0x40a60c], eax
         // 00401897: mov ebx, ds:[0x40a5d4]
         // 0040189d: jmp 0x4018b1
      [-]68????????6a008b430850e825f8ffff8b1b
         // 0040189f: push 0x8000
         // 004018a4: push 0x0
         // 004018a6: mov eax, ds:[ebx+0x8]
         // 004018a9: push eax
         // 004018aa: call VirtualFree
         // 004018af: mov ebx, ds:[ebx]
      [-]81fb????????75e6
         // 004018b1: cmp ebx, 0x40a5d4
         // 004018b7: jnz 0x40189f
      [-]b8????????e889f8ffffb8????????e87ff8ffffb8????????e875f8ffffa1????????85c07417
         // 004018b9: mov eax, 0x40a5d4
         // 004018be: call 0x40114c
         // 004018c3: mov eax, 0x40a5e4
         // 004018c8: call 0x40114c
         // 004018cd: mov eax, 0x40a610
         // 004018d2: call 0x40114c
         // 004018d7: mov eax, ds:[0x40a5cc]
         // 004018dc: test eax, eax
         // 004018de: jz 0x4018f7
      [-]8b108915????????50e8d6f7ffffa1????????85c075e9
         // 004018e0: mov edx, ds:[eax]
         // 004018e2: mov ds:[0x40a5cc], edx
         // 004018e8: push eax
         // 004018e9: call LocalFree
         // 004018ee: mov eax, ds:[0x40a5cc]
         // 004018f3: test eax, eax
         // 004018f5: jnz 0x4018e0
      [-]33c05a595964891068????????803d35a0400000740a
         // 004018f7: xor eax, eax
         // 004018f9: pop edx
         // 004018fa: pop ecx
         // 004018fb: pop ecx
         // 004018fc: mov fs:[eax], edx
         // 004018ff: push 0x401929
         // 00401904: cmp b1 ds:[0x40a035], b1 0x0
         // 0040190b: jz 0x401917
      [-]68b4a54000e8d5f7ffff
         // 0040190d: push CriticalSection.DebugInfo
         // 00401912: call LeaveCriticalSection
      [-]68b4a54000e8d3f7ffffc3
         // 00401917: push CriticalSection.DebugInfo
         // 0040191c: call DeleteCriticalSection
         // 00401921: retn 
      [-]533b05????????7509
         // 0040192c: push ebx
         // 0040192d: cmp eax, ds:[0x40a600]
         // 00401933: jnz 0x40193e
      [-]8b50048915????????
         // 00401935: mov edx, ds:[eax+0x4]
         // 00401938: mov ds:[0x40a600], edx
      [-]8b50048b480881f9????????7f38
         // 0040193e: mov edx, ds:[eax+0x4]
         // 00401941: mov ecx, ds:[eax+0x8]
         // 00401944: cmp ecx, 0x1000
         // 0040194a: jg 0x401984
      [-]3bc27517
         // 0040194c: cmp eax, edx
         // 0040194e: jnz 0x401967
      [-]85c97903
         // 00401950: test ecx, ecx
         // 00401952: jns 0x401957
      [-]c1f902a1????????33d2895488f4eb24
         // 00401957: sar ecx, b1 0x2
         // 0040195a: mov eax, ds:[0x40a60c]
         // 0040195f: xor edx, edx
         // 00401961: mov ds:[eax+ecx*0x4], edx
         // 00401965: jmp 0x40198b
      [-]85c97903
         // 00401967: test ecx, ecx
         // 00401969: jns 0x40196e
      [-]c1f9028b1d????????89548bf48b0089028950045bc3
         // 0040196e: sar ecx, b1 0x2
         // 00401971: mov ebx, ds:[0x40a60c]
         // 00401977: mov ds:[ebx+ecx*0x4], edx
         // 0040197b: mov eax, ds:[eax]
         // 0040197d: mov ds:[edx], eax
         // 0040197f: mov ds:[eax+0x4], edx
         // 00401982: pop ebx
         // 00401983: retn 
      [-]8b008902895004
         // 00401984: mov eax, ds:[eax]
         // 00401986: mov ds:[edx], eax
         // 00401988: mov ds:[eax+0x4], edx
      [-]8b15????????eb10
         // 00401990: mov edx, ds:[0x40a610]
         // 00401996: jmp 0x4019a8
      [-]8b4a083bc17207
         // 00401998: mov ecx, ds:[edx+0x8]
         // 0040199b: cmp eax, ecx
         // 0040199d: jb 0x4019a6
      [-]034a0c3bc17216
         // 0040199f: add ecx, ds:[edx+0xc]
         // 004019a2: cmp eax, ecx
         // 004019a4: jb 0x4019bc
      [-]81fa????????75e8
         // 004019a8: cmp edx, 0x40a610
         // 004019ae: jnz 0x401998
      [-]c705????????????????33d2
         // 004019b0: mov ds:[0x40a5b0], 0x3
         // 004019ba: xor edx, edx
      [-]538bca83e9048d1c0183fa107c0f
         // 004019c0: push ebx
         // 004019c1: mov ecx, edx
         // 004019c3: sub ecx, 0x4
         // 004019c6: lea ebx, ds:[ecx+eax]
         // 004019c9: cmp edx, 0x10
         // 004019cc: jl 0x4019dd
      [-]c703????????8bd1e8b90100005bc3
         // 004019ce: mov ds:[ebx], 0xffffffff80000007
         // 004019d4: mov edx, ecx
         // 004019d6: call 0x401b94
         // 004019db: pop ebx
         // 004019dc: retn 
      [-]83fa047c0c
         // 004019dd: cmp edx, 0x4
         // 004019e0: jl 0x4019ee
      [-]8bca81c9????????8908890b
         // 004019e2: mov ecx, edx
         // 004019e4: or ecx, 0xffffffff80000002
         // 004019ea: mov ds:[eax], ecx
         // 004019ec: mov ds:[ebx], ecx
      [-]ff05????????8bd083ea048b1281e2????????83ea040115????????e8f3050000c3
         // 004019f0: inc ds:[0x40a59c]
         // 004019f6: mov edx, eax
         // 004019f8: sub edx, 0x4
         // 004019fb: mov edx, ds:[edx]
         // 004019fd: and edx, 0x7ffffffc
         // 00401a03: sub edx, 0x4
         // 00401a06: add ds:[0x40a5a0], edx
         // 00401a0c: call 0x402004
         // 00401a11: retn 
      [-]83fa0c7c0e
         // 00401a14: cmp edx, 0xc
         // 00401a17: jl 0x401a27
      [-]83ca02891083c004e8caffffffc3
         // 00401a19: or edx, 0x2
         // 00401a1c: mov ds:[eax], edx
         // 00401a1e: add eax, 0x4
         // 00401a21: call 0x4019f0
         // 00401a26: retn 
      [-]83fa047c0a
         // 00401a27: cmp edx, 0x4
         // 00401a2a: jl 0x401a36
      [-]8bca81c9????????8908
         // 00401a2c: mov ecx, edx
         // 00401a2e: or ecx, 0xffffffff80000002
         // 00401a34: mov ds:[eax], ecx
      [-]03c28320fec3
         // 00401a36: add eax, edx
         // 00401a38: and ds:[eax], 0xfffffffffffffffe
         // 00401a3b: retn 
      [-]53568bd083ea048b128bca81e1????????81f9????????740a
         // 00401a3c: push ebx
         // 00401a3d: push esi
         // 00401a3e: mov edx, eax
         // 00401a40: sub edx, 0x4
         // 00401a43: mov edx, ds:[edx]
         // 00401a45: mov ecx, edx
         // 00401a47: and ecx, 0xffffffff80000002
         // 00401a4d: cmp ecx, 0xffffffff80000002
         // 00401a53: jz 0x401a5f
      [-]c705????????????????
         // 00401a55: mov ds:[0x40a5b0], 0x4
      [-]8bda81e3????????2bc38bc83311f7c2????????740a
         // 00401a5f: mov ebx, edx
         // 00401a61: and ebx, 0x7ffffffc
         // 00401a67: sub eax, ebx
         // 00401a69: mov ecx, eax
         // 00401a6b: xor edx, ds:[ecx]
         // 00401a6d: test edx, 0xfffffffffffffffe
         // 00401a73: jz 0x401a7f
      [-]c705????????????????
         // 00401a75: mov ds:[0x40a5b0], 0x5
      [-]f601017420
         // 00401a7f: test b1 ds:[ecx], b1 0x1
         // 00401a82: jz 0x401aa4
      [-]8bd083ea0c8b72082bc63b7008740a
         // 00401a84: mov edx, eax
         // 00401a86: sub edx, 0xc
         // 00401a89: mov esi, ds:[edx+0x8]
         // 00401a8c: sub eax, esi
         // 00401a8e: cmp esi, ds:[eax+0x8]
         // 00401a91: jz 0x401a9d
      [-]c705????????????????
         // 00401a93: mov ds:[0x40a5b0], 0x6
      [-]e88afeffff03de
         // 00401a9d: call 0x40192c
         // 00401aa2: add ebx, esi
      [-]8bc35e5bc3
         // 00401aa4: mov eax, ebx
         // 00401aa6: pop esi
         // 00401aa7: pop ebx
         // 00401aa8: retn 
      [-]5356578bd833ff8b03a9????????740b
         // 00401aac: push ebx
         // 00401aad: push esi
         // 00401aae: push edi
         // 00401aaf: mov ebx, eax
         // 00401ab1: xor edi, edi
         // 00401ab3: mov eax, ds:[ebx]
         // 00401ab5: test eax, 0xffffffff80000000
         // 00401aba: jz 0x401ac7
      [-]25????????03f803d88b03
         // 00401abc: and eax, 0x7ffffffc
         // 00401ac1: add edi, eax
         // 00401ac3: add ebx, eax
         // 00401ac5: mov eax, ds:[ebx]
      [-]a8027513
         // 00401ac7: test b1 al, b1 0x2
         // 00401ac9: jnz 0x401ade
      [-]8bf38bc6e858feffff8b460803f803d88323fe
         // 00401acb: mov esi, ebx
         // 00401acd: mov eax, esi
         // 00401acf: call 0x40192c
         // 00401ad4: mov eax, ds:[esi+0x8]
         // 00401ad7: add edi, eax
         // 00401ad9: add ebx, eax
         // 00401adb: and ds:[ebx], 0xfffffffffffffffe
      [-]8bc75f5e5bc3
         // 00401ade: mov eax, edi
         // 00401ae0: pop edi
         // 00401ae1: pop esi
         // 00401ae2: pop ebx
         // 00401ae3: retn 
      [-]5356575583c4f48bfa8bf0c60424008bc6e896feffff8bd885db0f8482000000
         // 00401ae4: push ebx
         // 00401ae5: push esi
         // 00401ae6: push edi
         // 00401ae7: push ebp
         // 00401ae8: add esp, 0xfffffffffffffff4
         // 00401aeb: mov edi, edx
         // 00401aed: mov esi, eax
         // 00401aef: mov b1 ss:[esp], b1 0x0
         // 00401af3: mov eax, esi
         // 00401af5: call 0x401990
         // 00401afa: mov ebx, eax
         // 00401afc: test ebx, ebx
         // 00401afe: jz 0x401b86
      [-]8b6b088bc503430c8bd08d0c372bd183fa0c7f04
         // 00401b04: mov ebp, ds:[ebx+0x8]
         // 00401b07: mov eax, ebp
         // 00401b09: add eax, ds:[ebx+0xc]
         // 00401b0c: mov edx, eax
         // 00401b0e: lea ecx, ds:[edi+esi]
         // 00401b11: sub edx, ecx
         // 00401b13: cmp edx, 0xc
         // 00401b16: jg 0x401b1c
      [-]8bf82bfe
         // 00401b18: mov edi, eax
         // 00401b1a: sub edi, esi
      [-]8bc62bc583f80c7d14
         // 00401b1c: mov eax, esi
         // 00401b1e: sub eax, ebp
         // 00401b20: cmp eax, 0xc
         // 00401b23: jge 0x401b39
      [-]8d4c24018bd62b530803d78bc5e8c5fbffffeb11
         // 00401b25: lea ecx, ss:[esp+0x1]
         // 00401b29: mov edx, esi
         // 00401b2b: sub edx, ds:[ebx+0x8]
         // 00401b2e: add edx, edi
         // 00401b30: mov eax, ebp
         // 00401b32: call 0x4016fc
         // 00401b37: jmp 0x401b4a
      [-]8d4c24018bd783ea048d4604e8b2fbffff
         // 00401b39: lea ecx, ss:[esp+0x1]
         // 00401b3d: mov edx, edi
         // 00401b3f: sub edx, 0x4
         // 00401b42: lea eax, ds:[esi+0x4]
         // 00401b45: call 0x4016fc
      [-]8b6c240185ed7434
         // 00401b4a: mov ebp, ss:[esp+0x1]
         // 00401b4e: test ebp, ebp
         // 00401b50: jz 0x401b86
      [-]8bd52bd68bc6e863feffff8bc5034424058b530803530c3bc2730a
         // 00401b52: mov edx, ebp
         // 00401b54: sub edx, esi
         // 00401b56: mov eax, esi
         // 00401b58: call 0x4019c0
         // 00401b5d: mov eax, ebp
         // 00401b5f: add eax, ss:[esp+0x5]
         // 00401b63: mov edx, ds:[ebx+0x8]
         // 00401b66: add edx, ds:[ebx+0xc]
         // 00401b69: cmp eax, edx
         // 00401b6b: jnb 0x401b77
      [-]8d14372bd0e89dfeffff
         // 00401b6d: lea edx, ds:[edi+esi]
         // 00401b70: sub edx, eax
         // 00401b72: call 0x401a14
      [-]8d5424018bc3e88af6ffffc6042401
         // 00401b77: lea edx, ss:[esp+0x1]
         // 00401b7b: mov eax, ebx
         // 00401b7d: call 0x40120c
         // 00401b82: mov b1 ss:[esp], b1 0x1
      [-]8a042483c40c5d5f5e5bc3
         // 00401b86: mov b1 al, b1 ss:[esp]
         // 00401b89: add esp, 0xc
         // 00401b8c: pop ebp
         // 00401b8d: pop edi
         // 00401b8e: pop esi
         // 00401b8f: pop ebx
         // 00401b90: retn 
      [-]5356578bf28bf88bdf8973088bc303c683e80c89700881fe????????7f37
         // 00401b94: push ebx
         // 00401b95: push esi
         // 00401b96: push edi
         // 00401b97: mov esi, edx
         // 00401b99: mov edi, eax
         // 00401b9b: mov ebx, edi
         // 00401b9d: mov ds:[ebx+0x8], esi
         // 00401ba0: mov eax, ebx
         // 00401ba2: add eax, esi
         // 00401ba4: sub eax, 0xc
         // 00401ba7: mov ds:[eax+0x8], esi
         // 00401baa: cmp esi, 0x1000
         // 00401bb0: jg 0x401be9
      [-]8bd685d27903
         // 00401bb2: mov edx, esi
         // 00401bb4: test edx, edx
         // 00401bb6: jns 0x401bbb
      [-]c1fa02a1????????8b4490f485c07510
         // 00401bbb: sar edx, b1 0x2
         // 00401bbe: mov eax, ds:[0x40a60c]
         // 00401bc3: mov eax, ds:[eax+edx*0x4]
         // 00401bc7: test eax, eax
         // 00401bc9: jnz 0x401bdb
      [-]a1????????895c90f4895b04891beb3a
         // 00401bcb: mov eax, ds:[0x40a60c]
         // 00401bd0: mov ds:[eax+edx*0x4], ebx
         // 00401bd4: mov ds:[ebx+0x4], ebx
         // 00401bd7: mov ds:[ebx], ebx
         // 00401bd9: jmp 0x401c15
      [-]8b1089430489138918895a04eb2c
         // 00401bdb: mov edx, ds:[eax]
         // 00401bdd: mov ds:[ebx+0x4], eax
         // 00401be0: mov ds:[ebx], edx
         // 00401be2: mov ds:[eax], ebx
         // 00401be4: mov ds:[edx+0x4], ebx
         // 00401be7: jmp 0x401c15
      [-]81fe????????7c0d
         // 00401be9: cmp esi, 0x3c00
         // 00401bef: jl 0x401bfe
      [-]8bd68bc7e8eafeffff84c07517
         // 00401bf1: mov edx, esi
         // 00401bf3: mov eax, edi
         // 00401bf5: call 0x401ae4
         // 00401bfa: test b1 al, b1 al
         // 00401bfc: jnz 0x401c15
      [-]a1????????891d????????8b1089430489138918895a04
         // 00401bfe: mov eax, ds:[0x40a600]
         // 00401c03: mov ds:[0x40a600], ebx
         // 00401c09: mov edx, ds:[eax]
         // 00401c0b: mov ds:[ebx+0x4], eax
         // 00401c0e: mov ds:[ebx], edx
         // 00401c10: mov ds:[eax], ebx
         // 00401c12: mov ds:[edx+0x4], ebx
      [-]5f5e5bc3
         // 00401c15: pop edi
         // 00401c16: pop esi
         // 00401c17: pop ebx
         // 00401c18: retn 
      [-]833d????????007e40
         // 00401c1c: cmp ds:[0x40a604], 0x0
         // 00401c23: jle 0x401c65
      [-]833d????????0c7d0c
         // 00401c25: cmp ds:[0x40a604], 0xc
         // 00401c2c: jge 0x401c3a
      [-]c705????????????????eb2b
         // 00401c2e: mov ds:[0x40a5b0], 0x7
         // 00401c38: jmp 0x401c65
      [-]a1????????83c8028b15????????8902a1????????83c004e899fdffff33c0a3????????33c0a3????????
         // 00401c3a: mov eax, ds:[0x40a604]
         // 00401c3f: or eax, 0x2
         // 00401c42: mov edx, ds:[0x40a608]
         // 00401c48: mov ds:[edx], eax
         // 00401c4a: mov eax, ds:[0x40a608]
         // 00401c4f: add eax, 0x4
         // 00401c52: call 0x4019f0
         // 00401c57: xor eax, eax
         // 00401c59: mov ds:[0x40a608], eax
         // 00401c5e: xor eax, eax
         // 00401c60: mov ds:[0x40a604], eax
      [-]53565783c4f08bf08d3c24a5a58bfce8a0ffffff8d4c24088bd7b8????????e810f5ffff8b5c240885db7504
         // 00401c68: push ebx
         // 00401c69: push esi
         // 00401c6a: push edi
         // 00401c6b: add esp, 0xfffffffffffffff0
         // 00401c6e: mov esi, eax
         // 00401c70: lea edi, ss:[esp]
         // 00401c73: movsdd 
         // 00401c74: movsdd 
         // 00401c75: mov edi, esp
         // 00401c77: call 0x401c1c
         // 00401c7c: lea ecx, ss:[esp+0x8]
         // 00401c80: mov edx, edi
         // 00401c82: mov eax, 0x40a610
         // 00401c87: call 0x40119c
         // 00401c8c: mov ebx, ss:[esp+0x8]
         // 00401c90: test ebx, ebx
         // 00401c92: jnz 0x401c98
      [-]33c0eb52
         // 00401c94: xor eax, eax
         // 00401c96: jmp 0x401cea
      [-]8b073bd8730a
         // 00401c98: mov eax, ds:[edi]
         // 00401c9a: cmp ebx, eax
         // 00401c9c: jnb 0x401ca8
      [-]e899fdffff2907014704
         // 00401c9e: call 0x401a3c
         // 00401ca3: sub ds:[edi], eax
         // 00401ca5: add ds:[edi+0x4], eax
      [-]8b070347048bf30374240c3bc67308
         // 00401ca8: mov eax, ds:[edi]
         // 00401caa: add eax, ds:[edi+0x4]
         // 00401cad: mov esi, ebx
         // 00401caf: add esi, ss:[esp+0xc]
         // 00401cb3: cmp eax, esi
         // 00401cb5: jnb 0x401cbf
      [-]e8f0fdffff014704
         // 00401cb7: call 0x401aac
         // 00401cbc: add ds:[edi+0x4], eax
      [-]8b070347043bf07511
         // 00401cbf: mov eax, ds:[edi]
         // 00401cc1: add eax, ds:[edi+0x4]
         // 00401cc4: cmp esi, eax
         // 00401cc6: jnz 0x401cd9
      [-]83e804ba????????e8ebfcffff836f0404
         // 00401cc8: sub eax, 0x4
         // 00401ccb: mov edx, 0x4
         // 00401cd0: call 0x4019c0
         // 00401cd5: sub ds:[edi+0x4], 0x4
      [-]8b07a3????????8b4704a3????????b001
         // 00401cd9: mov eax, ds:[edi]
         // 00401cdb: mov ds:[0x40a608], eax
         // 00401ce0: mov eax, ds:[edi+0x4]
         // 00401ce3: mov ds:[0x40a604], eax
         // 00401ce8: mov b1 al, b1 0x1
      [-]83c4105f5e5bc3
         // 00401cea: add esp, 0x10
         // 00401ced: pop edi
         // 00401cee: pop esi
         // 00401cef: pop ebx
         // 00401cf0: retn 
      [-]5383c4f88bd88bd48d4304e844f8ffff833c2400740b
         // 00401cf4: push ebx
         // 00401cf5: add esp, 0xfffffffffffffff8
         // 00401cf8: mov ebx, eax
         // 00401cfa: mov edx, esp
         // 00401cfc: lea eax, ds:[ebx+0x4]
         // 00401cff: call 0x401548
         // 00401d04: cmp ss:[esp], 0x0
         // 00401d08: jz 0x401d15
      [-]8bc4e857ffffff84c07504
         // 00401d0a: mov eax, esp
         // 00401d0c: call 0x401c68
         // 00401d11: test b1 al, b1 al
         // 00401d13: jnz 0x401d19
      [-]33c0eb02
         // 00401d15: xor eax, eax
         // 00401d17: jmp 0x401d1b
      [-]595a5bc3
         // 00401d1b: pop ecx
         // 00401d1c: pop edx
         // 00401d1d: pop ebx
         // 00401d1e: retn 
      [-]535683c4f88bf28bd88bcc8d56048bc3e8a3f8ffff833c2400740b
         // 00401d20: push ebx
         // 00401d21: push esi
         // 00401d22: add esp, 0xfffffffffffffff8
         // 00401d25: mov esi, edx
         // 00401d27: mov ebx, eax
         // 00401d29: mov ecx, esp
         // 00401d2b: lea edx, ds:[esi+0x4]
         // 00401d2e: mov eax, ebx
         // 00401d30: call 0x4015d8
         // 00401d35: cmp ss:[esp], 0x0
         // 00401d39: jz 0x401d46
      [-]8bc4e826ffffff84c07504
         // 00401d3b: mov eax, esp
         // 00401d3d: call 0x401c68
         // 00401d42: test b1 al, b1 al
         // 00401d44: jnz 0x401d4a
      [-]33c0eb02
         // 00401d46: xor eax, eax
         // 00401d48: jmp 0x401d4c
      [-]595a5e5bc3
         // 00401d4c: pop ecx
         // 00401d4d: pop edx
         // 00401d4e: pop esi
         // 00401d4f: pop ebx
         // 00401d50: retn 
      [-]33d285c07903
         // 00401d54: xor edx, edx
         // 00401d56: test eax, eax
         // 00401d58: jns 0x401d5d
      [-]c1f8023d????????7f16
         // 00401d5d: sar eax, b1 0x2
         // 00401d60: cmp eax, 0x400
         // 00401d65: jg 0x401d7d
      [-]8b15????????8b5482f485d27508
         // 00401d67: mov edx, ds:[0x40a60c]
         // 00401d6d: mov edx, ds:[edx+eax*0x4]
         // 00401d71: test edx, edx
         // 00401d73: jnz 0x401d7d
      [-]403d????????75ea
         // 00401d75: inc eax
         // 00401d76: cmp eax, 0x401
         // 00401d7b: jnz 0x401d67
      [-]535657558bf0bf????????bd????????
         // 00401d80: push ebx
         // 00401d81: push esi
         // 00401d82: push edi
         // 00401d83: push ebp
         // 00401d84: mov esi, eax
         // 00401d86: mov edi, 0x40a600
         // 00401d8b: mov ebp, 0x40a604
      [-]8b1d????????3b73080f8e84000000
         // 00401d90: mov ebx, ds:[0x40a5f8]
         // 00401d96: cmp esi, ds:[ebx+0x8]
         // 00401d99: jle 0x401e23
      [-]8b1f8b43083bf07e7b
         // 00401d9f: mov ebx, ds:[edi]
         // 00401da1: mov eax, ds:[ebx+0x8]
         // 00401da4: cmp esi, eax
         // 00401da6: jle 0x401e23
      [-]8b5b043b73087ff8
         // 00401dab: mov ebx, ds:[ebx+0x4]
         // 00401dae: cmp esi, ds:[ebx+0x8]
         // 00401db1: jg 0x401dab
      [-]8b178942083b1f7404
         // 00401db3: mov edx, ds:[edi]
         // 00401db5: mov ds:[edx+0x8], eax
         // 00401db8: cmp ebx, ds:[edi]
         // 00401dba: jz 0x401dc0
      [-]891feb63
         // 00401dbc: mov ds:[edi], ebx
         // 00401dbe: jmp 0x401e23
      [-]81fe????????7f0d
         // 00401dc0: cmp esi, 0x1000
         // 00401dc6: jg 0x401dd5
      [-]8bc6e885ffffff8bd885db754e
         // 00401dc8: mov eax, esi
         // 00401dca: call 0x401d54
         // 00401dcf: mov ebx, eax
         // 00401dd1: test ebx, ebx
         // 00401dd3: jnz 0x401e23
      [-]8bc6e818ffffff84c07507
         // 00401dd5: mov eax, esi
         // 00401dd7: call 0x401cf4
         // 00401ddc: test b1 al, b1 al
         // 00401dde: jnz 0x401de7
      [-]33c0e988000000
         // 00401de0: xor eax, eax
         // 00401de2: jmp 0x401e6f
      [-]3b75007fa4
         // 00401de7: cmp esi, ss:[ebp+0x0]
         // 00401dea: jg 0x401d90
      [-]297500837d000c7d08
         // 00401dec: sub ss:[ebp+0x0], esi
         // 00401def: cmp ss:[ebp+0x0], 0xc
         // 00401df3: jge 0x401dfd
      [-]03750033c0894500
         // 00401df5: add esi, ss:[ebp+0x0]
         // 00401df8: xor eax, eax
         // 00401dfa: mov ss:[ebp+0x0], eax
      [-]a1????????0135????????8bd683ca02891083c004ff05????????83ee040135????????eb4c
         // 00401dfd: mov eax, ds:[0x40a608]
         // 00401e02: add ds:[0x40a608], esi
         // 00401e08: mov edx, esi
         // 00401e0a: or edx, 0x2
         // 00401e0d: mov ds:[eax], edx
         // 00401e0f: add eax, 0x4
         // 00401e12: inc ds:[0x40a59c]
         // 00401e18: sub esi, 0x4
         // 00401e1b: add ds:[0x40a5a0], esi
         // 00401e21: jmp 0x401e6f
      [-]8bc3e802fbffff8b53088bc22bc683f80c7c0c
         // 00401e23: mov eax, ebx
         // 00401e25: call 0x40192c
         // 00401e2a: mov edx, ds:[ebx+0x8]
         // 00401e2d: mov eax, edx
         // 00401e2f: sub eax, esi
         // 00401e31: cmp eax, 0xc
         // 00401e34: jl 0x401e42
      [-]8bd303d692e854fdffffeb12
         // 00401e36: mov edx, ebx
         // 00401e38: add edx, esi
         // 00401e3a: xchg eax, edx
         // 00401e3b: call 0x401b94
         // 00401e40: jmp 0x401e54
      [-]8bf23b1f7505
         // 00401e42: mov esi, edx
         // 00401e44: cmp ebx, ds:[edi]
         // 00401e46: jnz 0x401e4d
      [-]8b43048907
         // 00401e48: mov eax, ds:[ebx+0x4]
         // 00401e4b: mov ds:[edi], eax
      [-]8bc303c68320fe
         // 00401e4d: mov eax, ebx
         // 00401e4f: add eax, esi
         // 00401e51: and ds:[eax], 0xfffffffffffffffe
      [-]8bc38bd683ca02891083c004ff05????????83ee040135????????
         // 00401e54: mov eax, ebx
         // 00401e56: mov edx, esi
         // 00401e58: or edx, 0x2
         // 00401e5b: mov ds:[eax], edx
         // 00401e5d: add eax, 0x4
         // 00401e60: inc ds:[0x40a59c]
         // 00401e66: sub esi, 0x4
         // 00401e69: add ds:[0x40a5a0], esi
      [-]5d5f5e5bc3
         // 00401e6f: pop ebp
         // 00401e70: pop edi
         // 00401e71: pop esi
         // 00401e72: pop ebx
         // 00401e73: retn 
      [-]558bec83c4f85356578bd8803daca54000007509
         // 00401e74: push ebp
         // 00401e75: mov ebp, esp
         // 00401e77: add esp, 0xfffffffffffffff8
         // 00401e7a: push ebx
         // 00401e7b: push esi
         // 00401e7c: push edi
         // 00401e7d: mov ebx, eax
         // 00401e7f: cmp b1 ds:[0x40a5ac], b1 0x0
         // 00401e86: jnz 0x401e91
      [-]e8fbf8ffff84c07408
         // 00401e88: call 0x401788
         // 00401e8d: test b1 al, b1 al
         // 00401e8f: jz 0x401e99
      [-]81fb????????7e0a
         // 00401e91: cmp ebx, 0x7ffffff8
         // 00401e97: jle 0x401ea3
      [-]33c08945fce954010000
         // 00401e99: xor eax, eax
         // 00401e9b: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401e9e: jmp 0x401ff7
      [-]33c95568????????64ff31648921803d35a0400000740a
         // 00401ea3: xor ecx, ecx
         // 00401ea5: push ebp
         // 00401ea6: push 0x401ff0
         // 00401eab: push fs:[ecx]
         // 00401eae: mov fs:[ecx], esp
         // 00401eb1: cmp b1 ds:[0x40a035], b1 0x0
         // 00401eb8: jz 0x401ec4
      [-]68b4a54000e820f2ffff
         // 00401eba: push CriticalSection.DebugInfo
         // 00401ebf: call EnterCriticalSection
      [-]83c30783e3fc83fb0c7d05
         // 00401ec4: add ebx, 0x7
         // 00401ec7: and ebx, 0xfffffffffffffffc
         // 00401eca: cmp ebx, 0xc
         // 00401ecd: jge 0x401ed4
      [-]bb????????
         // 00401ecf: mov ebx, 0xc
      [-]81fb????????0f8f93000000
         // 00401ed4: cmp ebx, 0x1000
         // 00401eda: jg 0x401f73
      [-]8bc385c07903
         // 00401ee0: mov eax, ebx
         // 00401ee2: test eax, eax
         // 00401ee4: jns 0x401ee9
      [-]c1f8028b15????????8b5482f485d27479
         // 00401ee9: sar eax, b1 0x2
         // 00401eec: mov edx, ds:[0x40a60c]
         // 00401ef2: mov edx, ds:[edx+eax*0x4]
         // 00401ef6: test edx, edx
         // 00401ef8: jz 0x401f73
      [-]8bf28bc603c38320fe8b42043bd0751a
         // 00401efa: mov esi, edx
         // 00401efc: mov eax, esi
         // 00401efe: add eax, ebx
         // 00401f00: and ds:[eax], 0xfffffffffffffffe
         // 00401f03: mov eax, ds:[edx+0x4]
         // 00401f06: cmp edx, eax
         // 00401f08: jnz 0x401f24
      [-]8bc385c07903
         // 00401f0a: mov eax, ebx
         // 00401f0c: test eax, eax
         // 00401f0e: jns 0x401f13
      [-]c1f8028b0d????????33ff897c81f4eb26
         // 00401f13: sar eax, b1 0x2
         // 00401f16: mov ecx, ds:[0x40a60c]
         // 00401f1c: xor edi, edi
         // 00401f1e: mov ds:[ecx+eax*0x4], edi
         // 00401f22: jmp 0x401f4a
      [-]8bcb85c97903
         // 00401f24: mov ecx, ebx
         // 00401f26: test ecx, ecx
         // 00401f28: jns 0x401f2d
      [-]c1f9028b3d????????89448ff48b0a894df88b4df88941048b4df88908
         // 00401f2d: sar ecx, b1 0x2
         // 00401f30: mov edi, ds:[0x40a60c]
         // 00401f36: mov ds:[edi+ecx*0x4], eax
         // 00401f3a: mov ecx, ds:[edx]
         // 00401f3c: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 00401f3f: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 00401f42: mov ds:[ecx+0x4], eax
         // 00401f45: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 00401f48: mov ds:[eax], ecx
      [-]8bc68b520883ca02891083c0048945fcff05????????83eb04011d????????e87e0c0000e984000000
         // 00401f4a: mov eax, esi
         // 00401f4c: mov edx, ds:[edx+0x8]
         // 00401f4f: or edx, 0x2
         // 00401f52: mov ds:[eax], edx
         // 00401f54: add eax, 0x4
         // 00401f57: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401f5a: inc ds:[0x40a59c]
         // 00401f60: sub ebx, 0x4
         // 00401f63: add ds:[0x40a5a0], ebx
         // 00401f69: call 0x402bec
         // 00401f6e: jmp 0x401ff7
      [-]3b1d????????7f4a
         // 00401f73: cmp ebx, ds:[0x40a604]
         // 00401f79: jg 0x401fc5
      [-]291d????????833d????????0c7d0d
         // 00401f7b: sub ds:[0x40a604], ebx
         // 00401f81: cmp ds:[0x40a604], 0xc
         // 00401f88: jge 0x401f97
      [-]031d????????33c0a3????????
         // 00401f8a: add ebx, ds:[0x40a604]
         // 00401f90: xor eax, eax
         // 00401f92: mov ds:[0x40a604], eax
      [-]a1????????011d????????8bd383ca02891083c0048945fcff05????????83eb04011d????????e8290c0000eb32
         // 00401f97: mov eax, ds:[0x40a608]
         // 00401f9c: add ds:[0x40a608], ebx
         // 00401fa2: mov edx, ebx
         // 00401fa4: or edx, 0x2
         // 00401fa7: mov ds:[eax], edx
         // 00401fa9: add eax, 0x4
         // 00401fac: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401faf: inc ds:[0x40a59c]
         // 00401fb5: sub ebx, 0x4
         // 00401fb8: add ds:[0x40a5a0], ebx
         // 00401fbe: call 0x402bec
         // 00401fc3: jmp 0x401ff7
      [-]8bc3e8b4fdffff8945fc33c05a595964891068????????803d35a0400000740a
         // 00401fc5: mov eax, ebx
         // 00401fc7: call 0x401d80
         // 00401fcc: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401fcf: xor eax, eax
         // 00401fd1: pop edx
         // 00401fd2: pop ecx
         // 00401fd3: pop ecx
         // 00401fd4: mov fs:[eax], edx
         // 00401fd7: push 0x401ff7
         // 00401fdc: cmp b1 ds:[0x40a035], b1 0x0
         // 00401fe3: jz 0x401fef
      [-]68b4a54000e8fdf0ffff
         // 00401fe5: push CriticalSection.DebugInfo
         // 00401fea: call LeaveCriticalSection
      [-]8b45fc5f5e5b59595dc3
         // 00401ff7: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00401ffa: pop edi
         // 00401ffb: pop esi
         // 00401ffc: pop ebx
         // 00401ffd: pop ecx
         // 00401ffe: pop ecx
         // 00401fff: pop ebp
         // 00402000: retn 
      [-]558bec515356578bd833c0a3????????803daca5400000751f
         // 00402004: push ebp
         // 00402005: mov ebp, esp
         // 00402007: push ecx
         // 00402008: push ebx
         // 00402009: push esi
         // 0040200a: push edi
         // 0040200b: mov ebx, eax
         // 0040200d: xor eax, eax
         // 0040200f: mov ds:[0x40a5b0], eax
         // 00402014: cmp b1 ds:[0x40a5ac], b1 0x0
         // 0040201b: jnz 0x40203c
      [-]e866f7ffff84c07516
         // 0040201d: call 0x401788
         // 00402022: test b1 al, b1 al
         // 00402024: jnz 0x40203c
      [-]c705????????????????c745fc????????e961010000
         // 00402026: mov ds:[0x40a5b0], 0x8
         // 00402030: mov ss:[ebp+0xfffffffffffffffc], 0x8
         // 00402037: jmp 0x40219d
      [-]33c95568????????64ff31648921803d35a0400000740a
         // 0040203c: xor ecx, ecx
         // 0040203e: push ebp
         // 0040203f: push 0x402196
         // 00402044: push fs:[ecx]
         // 00402047: mov fs:[ecx], esp
         // 0040204a: cmp b1 ds:[0x40a035], b1 0x0
         // 00402051: jz 0x40205d
      [-]68b4a54000e887f0ffff
         // 00402053: push CriticalSection.DebugInfo
         // 00402058: call EnterCriticalSection
      [-]8bf383ee048b1ef6c302750f
         // 0040205d: mov esi, ebx
         // 0040205f: sub esi, 0x4
         // 00402062: mov ebx, ds:[esi]
         // 00402064: test b1 bl, b1 0x2
         // 00402067: jnz 0x402078
      [-]c705????????????????e9f5000000
         // 00402069: mov ds:[0x40a5b0], 0x9
         // 00402073: jmp 0x40216d
      [-]ff0d????????8bc325????????83e8042905????????f6c3017445
         // 00402078: dec ds:[0x40a59c]
         // 0040207e: mov eax, ebx
         // 00402080: and eax, 0x7ffffffc
         // 00402085: sub eax, 0x4
         // 00402088: sub ds:[0x40a5a0], eax
         // 0040208e: test b1 bl, b1 0x1
         // 00402091: jz 0x4020d8
      [-]8bc683e80c8b500883fa0c7c08
         // 00402093: mov eax, esi
         // 00402095: sub eax, 0xc
         // 00402098: mov edx, ds:[eax+0x8]
         // 0040209b: cmp edx, 0xc
         // 0040209e: jl 0x4020a8
      [-]f7c2????????740f
         // 004020a0: test edx, 0xffffffff80000003
         // 004020a6: jz 0x4020b7
      [-]c705????????????????e9b6000000
         // 004020a8: mov ds:[0x40a5b0], 0xa
         // 004020b2: jmp 0x40216d
      [-]8bc62bc23b5008740f
         // 004020b7: mov eax, esi
         // 004020b9: sub eax, edx
         // 004020bb: cmp edx, ds:[eax+0x8]
         // 004020be: jz 0x4020cf
      [-]c705????????????????e99e000000
         // 004020c0: mov ds:[0x40a5b0], 0xa
         // 004020ca: jmp 0x40216d
      [-]03da8bf0e854f8ffff
         // 004020cf: add ebx, edx
         // 004020d1: mov esi, eax
         // 004020d3: call 0x40192c
      [-]81e3????????8bc603c38bf83b3d????????752c
         // 004020d8: and ebx, 0x7ffffffc
         // 004020de: mov eax, esi
         // 004020e0: add eax, ebx
         // 004020e2: mov edi, eax
         // 004020e4: cmp edi, ds:[0x40a608]
         // 004020ea: jnz 0x402118
      [-]291d????????011d????????813d????????????????7e05
         // 004020ec: sub ds:[0x40a608], ebx
         // 004020f2: add ds:[0x40a604], ebx
         // 004020f8: cmp ds:[0x40a604], 0x3c00
         // 00402102: jle 0x402109
      [-]e813fbffff
         // 00402104: call 0x401c1c
      [-]33c08945fce8d90a0000e985000000
         // 00402109: xor eax, eax
         // 0040210b: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040210e: call 0x402bec
         // 00402113: jmp 0x40219d
      [-]8b10f6c202741c
         // 00402118: mov edx, ds:[eax]
         // 0040211a: test b1 dl, b1 0x2
         // 0040211d: jz 0x40213b
      [-]81e2????????83fa047d0c
         // 0040211f: and edx, 0x7ffffffc
         // 00402125: cmp edx, 0x4
         // 00402128: jge 0x402136
      [-]c705????????????????eb37
         // 0040212a: mov ds:[0x40a5b0], 0xb
         // 00402134: jmp 0x40216d
      [-]830801eb29
         // 00402136: or ds:[eax], 0x1
         // 00402139: jmp 0x402164
      [-]8bc783780400740b
         // 0040213b: mov eax, edi
         // 0040213d: cmp ds:[eax+0x4], 0x0
         // 00402141: jz 0x40214e
      [-]8338007406
         // 00402143: cmp ds:[eax], 0x0
         // 00402146: jz 0x40214e
      [-]8378080c7d0c
         // 00402148: cmp ds:[eax+0x8], 0xc
         // 0040214c: jge 0x40215a
      [-]c705????????????????eb13
         // 0040214e: mov ds:[0x40a5b0], 0xb
         // 00402158: jmp 0x40216d
      [-]8b500803dae8c8f7ffff
         // 0040215a: mov edx, ds:[eax+0x8]
         // 0040215d: add ebx, edx
         // 0040215f: call 0x40192c
      [-]8bd38bc6e827faffff
         // 00402164: mov edx, ebx
         // 00402166: mov eax, esi
         // 00402168: call 0x401b94
      [-]a1????????8945fc33c05a595964891068????????803d35a0400000740a
         // 0040216d: mov eax, ds:[0x40a5b0]
         // 00402172: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00402175: xor eax, eax
         // 00402177: pop edx
         // 00402178: pop ecx
         // 00402179: pop ecx
         // 0040217a: mov fs:[eax], edx
         // 0040217d: push 0x40219d
         // 00402182: cmp b1 ds:[0x40a035], b1 0x0
         // 00402189: jz 0x402195
      [-]68b4a54000e857efffff
         // 0040218b: push CriticalSection.DebugInfo
         // 00402190: call LeaveCriticalSection
      [-]8b45fc5f5e5b595dc3
         // 0040219d: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004021a0: pop edi
         // 004021a1: pop esi
         // 004021a2: pop ebx
         // 004021a3: pop ecx
         // 004021a4: pop ebp
         // 004021a5: retn 
      [-]5356575583c4f88bf283c60783e6fc83fe0c7d05
         // 004021a8: push ebx
         // 004021a9: push esi
         // 004021aa: push edi
         // 004021ab: push ebp
         // 004021ac: add esp, 0xfffffffffffffff8
         // 004021af: mov esi, edx
         // 004021b1: add esi, 0x7
         // 004021b4: and esi, 0xfffffffffffffffc
         // 004021b7: cmp esi, 0xc
         // 004021ba: jge 0x4021c1
      [-]be????????
         // 004021bc: mov esi, 0xc
      [-]8be883ed048b7d0081e7????????8bc503c78bd83bfe7507
         // 004021c1: mov ebp, eax
         // 004021c3: sub ebp, 0x4
         // 004021c6: mov edi, ss:[ebp+0x0]
         // 004021c9: and edi, 0x7ffffffc
         // 004021cf: mov eax, ebp
         // 004021d1: add eax, edi
         // 004021d3: mov ebx, eax
         // 004021d5: cmp edi, esi
         // 004021d7: jnz 0x4021e0
      [-]b001e99b010000
         // 004021d9: mov b1 al, b1 0x1
         // 004021db: jmp 0x40237b
      [-]3bfe0f8e83000000
         // 004021e0: cmp edi, esi
         // 004021e2: jle 0x40226b
      [-]8bd72bd68914243b1d????????7538
         // 004021e8: mov edx, edi
         // 004021ea: sub edx, esi
         // 004021ec: mov ss:[esp], edx
         // 004021ef: cmp ebx, ds:[0x40a608]
         // 004021f5: jnz 0x40222f
      [-]8b04242905????????8b04240105????????833d????????0c0f8d4c010000
         // 004021f7: mov eax, ss:[esp]
         // 004021fa: sub ds:[0x40a608], eax
         // 00402200: mov eax, ss:[esp]
         // 00402203: add ds:[0x40a604], eax
         // 00402209: cmp ds:[0x40a604], 0xc
         // 00402210: jge 0x402362
      [-]8b04240105????????8b04242905????????8bf7e933010000
         // 00402216: mov eax, ss:[esp]
         // 00402219: add ds:[0x40a608], eax
         // 0040221f: mov eax, ss:[esp]
         // 00402222: sub ds:[0x40a604], eax
         // 00402228: mov esi, edi
         // 0040222a: jmp 0x402362
      [-]8bd8f60302750d
         // 0040222f: mov ebx, eax
         // 00402231: test b1 ds:[ebx], b1 0x2
         // 00402234: jnz 0x402243
      [-]8bc38b5008011424e8e9f6ffff
         // 00402236: mov eax, ebx
         // 00402238: mov edx, ds:[eax+0x8]
         // 0040223b: add ss:[esp], edx
         // 0040223e: call 0x40192c
      [-]833c240c7c1b
         // 00402243: cmp ss:[esp], 0xc
         // 00402247: jl 0x402264
      [-]8bdd03de8b042483c80289038bc383c004e891f7ffffe9fe000000
         // 00402249: mov ebx, ebp
         // 0040224b: add ebx, esi
         // 0040224d: mov eax, ss:[esp]
         // 00402250: or eax, 0x2
         // 00402253: mov ds:[ebx], eax
         // 00402255: mov eax, ebx
         // 00402257: add eax, 0x4
         // 0040225a: call 0x4019f0
         // 0040225f: jmp 0x402362
      [-]8bf7e9f7000000
         // 00402264: mov esi, edi
         // 00402266: jmp 0x402362
      [-]8bc62bc7894424043b1d????????7567
         // 0040226b: mov eax, esi
         // 0040226d: sub eax, edi
         // 0040226f: mov ss:[esp+0x4], eax
         // 00402273: cmp ebx, ds:[0x40a608]
         // 00402279: jnz 0x4022e2
      [-]a1????????3b4424047c53
         // 0040227b: mov eax, ds:[0x40a604]
         // 00402280: cmp eax, ss:[esp+0x4]
         // 00402284: jl 0x4022d9
      [-]8b4424042905????????8b4424040105????????833d????????0c7d18
         // 00402286: mov eax, ss:[esp+0x4]
         // 0040228a: sub ds:[0x40a604], eax
         // 00402290: mov eax, ss:[esp+0x4]
         // 00402294: add ds:[0x40a608], eax
         // 0040229a: cmp ds:[0x40a604], 0xc
         // 004022a1: jge 0x4022bb
      [-]a1????????0105????????0335????????33c0a3????????
         // 004022a3: mov eax, ds:[0x40a604]
         // 004022a8: add ds:[0x40a608], eax
         // 004022ae: add esi, ds:[0x40a604]
         // 004022b4: xor eax, eax
         // 004022b6: mov ds:[0x40a604], eax
      [-]8bc62bc70105????????8b450025????????0bf0897500b001e9a2000000
         // 004022bb: mov eax, esi
         // 004022bd: sub eax, edi
         // 004022bf: add ds:[0x40a5a0], eax
         // 004022c5: mov eax, ss:[ebp+0x0]
         // 004022c8: and eax, 0xffffffff80000003
         // 004022cd: or esi, eax
         // 004022cf: mov ss:[ebp+0x0], esi
         // 004022d2: mov b1 al, b1 0x1
         // 004022d4: jmp 0x40237b
      [-]e83ef9ffff8bdd03df
         // 004022d9: call 0x401c1c
         // 004022de: mov ebx, ebp
         // 004022e0: add ebx, edi
      [-]f60302754d
         // 004022e2: test b1 ds:[ebx], b1 0x2
         // 004022e5: jnz 0x402334
      [-]8bd38bc28b4808890c248b0c243b4c24047d0e
         // 004022e7: mov edx, ebx
         // 004022e9: mov eax, edx
         // 004022eb: mov ecx, ds:[eax+0x8]
         // 004022ee: mov ss:[esp], ecx
         // 004022f1: mov ecx, ss:[esp]
         // 004022f4: cmp ecx, ss:[esp+0x4]
         // 004022f8: jge 0x402308
      [-]0314248bda8b042429442404eb2c
         // 004022fa: add edx, ss:[esp]
         // 004022fd: mov ebx, edx
         // 004022ff: mov eax, ss:[esp]
         // 00402302: sub ss:[esp+0x4], eax
         // 00402306: jmp 0x402334
      [-]e81ff6ffff8b442404290424833c240c7c0e
         // 00402308: call 0x40192c
         // 0040230d: mov eax, ss:[esp+0x4]
         // 00402311: sub ss:[esp], eax
         // 00402314: cmp ss:[esp], 0xc
         // 00402318: jl 0x402328
      [-]8bc503c68b1424e86ef8ffffeb3a
         // 0040231a: mov eax, ebp
         // 0040231c: add eax, esi
         // 0040231e: mov edx, ss:[esp]
         // 00402321: call 0x401b94
         // 00402326: jmp 0x402362
      [-]0334248bdd03de8323feeb2e
         // 00402328: add esi, ss:[esp]
         // 0040232b: mov ebx, ebp
         // 0040232d: add ebx, esi
         // 0040232f: and ds:[ebx], 0xfffffffffffffffe
         // 00402332: jmp 0x402362
      [-]8b03a9????????7421
         // 00402334: mov eax, ds:[ebx]
         // 00402336: test eax, 0xffffffff80000000
         // 0040233b: jz 0x40235e
      [-]25????????03c38bd88b5424048bc3e8cff9ffff84c07409
         // 0040233d: and eax, 0x7ffffffc
         // 00402342: add eax, ebx
         // 00402344: mov ebx, eax
         // 00402346: mov edx, ss:[esp+0x4]
         // 0040234a: mov eax, ebx
         // 0040234c: call 0x401d20
         // 00402351: test b1 al, b1 al
         // 00402353: jz 0x40235e
      [-]8bdd03dfe90dffffff
         // 00402355: mov ebx, ebp
         // 00402357: add ebx, edi
         // 00402359: jmp 0x40226b
      [-]33c0eb19
         // 0040235e: xor eax, eax
         // 00402360: jmp 0x40237b
      [-]8bc62bc70105????????8b450025????????0bf0897500b001
         // 00402362: mov eax, esi
         // 00402364: sub eax, edi
         // 00402366: add ds:[0x40a5a0], eax
         // 0040236c: mov eax, ss:[ebp+0x0]
         // 0040236f: and eax, 0xffffffff80000003
         // 00402374: or esi, eax
         // 00402376: mov ss:[ebp+0x0], esi
         // 00402379: mov b1 al, b1 0x1
      [-]595a5d5f5e5bc3
         // 0040237b: pop ecx
         // 0040237c: pop edx
         // 0040237d: pop ebp
         // 0040237e: pop edi
         // 0040237f: pop esi
         // 00402380: pop ebx
         // 00402381: retn 
      [-]558bec515356578bf28bd8803daca54000007513
         // 00402384: push ebp
         // 00402385: mov ebp, esp
         // 00402387: push ecx
         // 00402388: push ebx
         // 00402389: push esi
         // 0040238a: push edi
         // 0040238b: mov esi, edx
         // 0040238d: mov ebx, eax
         // 0040238f: cmp b1 ds:[0x40a5ac], b1 0x0
         // 00402396: jnz 0x4023ab
      [-]e8ebf3ffff84c0750a
         // 00402398: call 0x401788
         // 0040239d: test b1 al, b1 al
         // 0040239f: jnz 0x4023ab
      [-]33c0
         // 004023a1: xor eax, eax
         // 004023a3: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004023a6: jmp 0x40243c

  }
  condition:
    all of them
}
