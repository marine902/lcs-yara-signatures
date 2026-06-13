rule salgorea_10_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec6afe68a8874200685073410064a1????????5083ec10535657a120b542003145f833c5508d45f064a3????????8965e8c745????????ff33ff897dfc57ff15004042008bd83bdf7457
         // 00401000: push ebp
         // 00401001: mov ebp, esp
         // 00401003: push 0xfffffffffffffffe
         // 00401005: push stru_4287A8.GSCookieOffset
         // 0040100a: push __except_handler4
         // 0040100f: mov eax, fs:[0x0]
         // 00401015: push eax
         // 00401016: sub esp, 0x10
         // 00401019: push ebx
         // 0040101a: push esi
         // 0040101b: push edi
         // 0040101c: mov eax, ds:[___security_cookie]
         // 00401021: xor ss:[ebp+0xfffffffffffffff8], eax
         // 00401024: xor eax, ebp
         // 00401026: push eax
         // 00401027: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040102a: mov fs:[0x0], eax
         // 00401030: mov ss:[ebp+0xffffffffffffffe8], esp
         // 00401033: mov ss:[ebp+0xffffffffffffffe4], 0xffffffffffffffff
         // 0040103a: xor edi, edi
         // 0040103c: mov ss:[ebp+0xfffffffffffffffc], edi
         // 0040103f: push edi
         // 00401040: call ds:[GetModuleHandleW]
         // 00401046: mov ebx, eax
         // 00401048: cmp ebx, edi
         // 0040104a: jz 0x4010a3
      [-]8b433c03c38138????????754a
         // 0040104c: mov eax, ds:[ebx+0x3c]
         // 0040104f: add eax, ebx
         // 00401051: cmp ds:[eax], 0x4550
         // 00401057: jnz 0x4010a3
      [-]897de00fb748063bf97d3f
         // 00401059: mov ss:[ebp+0xffffffffffffffe0], edi
         // 0040105c: movzx ecx, b2 ds:[eax+0x6]
         // 00401060: cmp edi, ecx
         // 00401062: jge 0x4010a3
      [-]8d14bf8db4d0f80000008b4e0c03cb8b560803d13955087313
         // 00401064: lea edx, ds:[edi+edi*0x4]
         // 00401067: lea esi, ds:[eax+edx*0x8]
         // 0040106e: mov ecx, ds:[esi+0xc]
         // 00401071: add ecx, ebx
         // 00401073: mov edx, ds:[esi+0x8]
         // 00401076: add edx, ecx
         // 00401078: cmp ss:[ebp+0x8], edx
         // 0040107b: jnb 0x401090
      [-]8b55083bd1720c
         // 0040107d: mov edx, ss:[ebp+0x8]
         // 00401080: cmp edx, ecx
         // 00401082: jb 0x401090
      [-]8b76142bf103f28975e4eb13
         // 00401084: mov esi, ds:[esi+0x14]
         // 00401087: sub esi, ecx
         // 00401089: add esi, edx
         // 0040108b: mov ss:[ebp+0xffffffffffffffe4], esi
         // 0040108e: jmp 0x4010a3
      [-]c745fc????????8b45e48b4df064890d????????595f5e5b8be55dc3
         // 004010a3: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 004010aa: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 004010ad: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004010b0: mov fs:[0x0], ecx
         // 004010b7: pop ecx
         // 004010b8: pop edi
         // 004010b9: pop esi
         // 004010ba: pop ebx
         // 004010bb: mov esp, ebp
         // 004010bd: pop ebp
         // 004010be: retn 
      [-]558bec81ec????????a120b5420033c58945fc535633c9b001578d9b????????
         // 004010c0: push ebp
         // 004010c1: mov ebp, esp
         // 004010c3: sub esp, 0x208
         // 004010c9: mov eax, ds:[___security_cookie]
         // 004010ce: xor eax, ebp
         // 004010d0: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004010d3: push ebx
         // 004010d4: push esi
         // 004010d5: xor ecx, ecx
         // 004010d7: mov b1 al, b1 0x1
         // 004010d9: push edi
         // 004010da: lea ebx, ds:[ebx+0x0]
      [-]0fb6d0888c15fcfeffff8ad080e28088840dfcfdffff41f6da1ad28ad880e21b02db32d332c281f9????????7cd2
         // 004010e0: movzx edx, b1 al
         // 004010e3: mov b1 ss:[ebp+edx+0xfffffffffffffefc], b1 cl
         // 004010ea: mov b1 dl, b1 al
         // 004010ec: and b1 dl, b1 0x80
         // 004010ef: mov b1 ss:[ebp+ecx+0xfffffffffffffdfc], b1 al
         // 004010f6: inc ecx
         // 004010f7: neg b1 dl
         // 004010f9: sbb b1 dl, b1 dl
         // 004010fb: mov b1 bl, b1 al
         // 004010fd: and b1 dl, b1 0x1b
         // 00401100: add b1 bl, b1 bl
         // 00401102: xor b1 dl, b1 bl
         // 00401104: xor b1 al, b1 dl
         // 00401106: cmp ecx, 0x100
         // 0040110c: jl 0x4010e0
      [-]b001b9????????
         // 0040110e: mov b1 al, b1 0x1
         // 00401110: mov ecx, 0x46f380
      [-]0fb6d0c1e21889118ad080e28083c104f6da1ad280e21b02c032c281f9????????7cdd
         // 00401115: movzx edx, b1 al
         // 00401118: shl edx, b1 0x18
         // 0040111b: mov ds:[ecx], edx
         // 0040111d: mov b1 dl, b1 al
         // 0040111f: and b1 dl, b1 0x80
         // 00401122: add ecx, 0x4
         // 00401125: neg b1 dl
         // 00401127: sbb b1 dl, b1 dl
         // 00401129: and b1 dl, b1 0x1b
         // 0040112c: add b1 al, b1 al
         // 0040112e: xor b1 al, b1 dl
         // 00401130: cmp ecx, 0x46f3a8
         // 00401136: jl 0x401115
      [-]c705????????????????c705????????????????ba????????eb0d
         // 00401138: mov ds:[0x46e780], 0x63
         // 00401142: mov ds:[0x47194c], 0x0
         // 0040114c: mov edx, 0x1
         // 00401151: jmp 0x401160
      [-]0fb68415fcfeffff8d8d????????2bc88a098ac1d0c032c8d0c032c8d0c032c8d0c032c134630fb6c0890495????????891485????????4281fa????????7cc0
         // 00401160: movzx eax, b1 ss:[ebp+edx+0xfffffffffffffefc]
         // 00401168: lea ecx, ss:[ebp+0xfffffffffffffefb]
         // 0040116e: sub ecx, eax
         // 00401170: mov b1 cl, b1 ds:[ecx]
         // 00401172: mov b1 al, b1 cl
         // 00401174: rol b1 al, b1 0x1
         // 00401176: xor b1 cl, b1 al
         // 00401178: rol b1 al, b1 0x1
         // 0040117a: xor b1 cl, b1 al
         // 0040117c: rol b1 al, b1 0x1
         // 0040117e: xor b1 cl, b1 al
         // 00401180: rol b1 al, b1 0x1
         // 00401182: xor b1 al, b1 cl
         // 00401184: xor b1 al, b1 0x63
         // 00401186: movzx eax, b1 al
         // 00401189: mov ds:[0x46e780+edx*0x4], eax
         // 00401190: mov ds:[0x4717c0+eax*0x4], edx
         // 00401197: inc edx
         // 00401198: cmp edx, 0x100
         // 0040119e: jl 0x401160
      [-]8a9180e746008ac22480f6d81ac0241b8ada02db32c30fb6f00fb6d28bc6c1e00833c2c1e00833c2c1e00833c633c28981????????c1c8088981????????c1c8088981????????c1c8088981????????8a81c017470084c07473
         // 004011a2: mov b1 dl, b1 ds:[ecx+0x46e780]
         // 004011a8: mov b1 al, b1 dl
         // 004011aa: and b1 al, b1 0x80
         // 004011ac: neg b1 al
         // 004011ae: sbb b1 al, b1 al
         // 004011b0: and b1 al, b1 0x1b
         // 004011b2: mov b1 bl, b1 dl
         // 004011b4: add b1 bl, b1 bl
         // 004011b6: xor b1 al, b1 bl
         // 004011b8: movzx esi, b1 al
         // 004011bb: movzx edx, b1 dl
         // 004011be: mov eax, esi
         // 004011c0: shl eax, b1 0x8
         // 004011c3: xor eax, edx
         // 004011c5: shl eax, b1 0x8
         // 004011c8: xor eax, edx
         // 004011ca: shl eax, b1 0x8
         // 004011cd: xor eax, esi
         // 004011cf: xor eax, edx
         // 004011d1: mov ds:[ecx+0x4713c0], eax
         // 004011d7: ror eax, b1 0x8
         // 004011da: mov ds:[ecx+0x470fc0], eax
         // 004011e0: ror eax, b1 0x8
         // 004011e3: mov ds:[ecx+0x470bc0], eax
         // 004011e9: ror eax, b1 0x8
         // 004011ec: mov ds:[ecx+0x4707c0], eax
         // 004011f2: mov b1 al, b1 ds:[ecx+0x4717c0]
         // 004011f8: test b1 al, b1 al
         // 004011fa: jz 0x40126f
      [-]0fb6d00fb6b415fcfeffff0fb68507ffffff03c699bf????????f7ff0fb68415fcfdffff8985????????0fb68509ffffff03c699f7ff0fb68505ffffff03c60fb69c15fcfdffff99f7ff0fb6850affffff03c6be????????0fb6bc15fcfdffff99f7fe0fb68415fcfdffff8b95????????eb08
         // 004011fc: movzx edx, b1 al
         // 004011ff: movzx esi, b1 ss:[ebp+edx+0xfffffffffffffefc]
         // 00401207: movzx eax, b1 ss:[ebp+0xffffffffffffff07]
         // 0040120e: add eax, esi
         // 00401210: cdq 
         // 00401211: mov edi, 0xff
         // 00401216: idiv edi
         // 00401218: movzx eax, b1 ss:[ebp+edx+0xfffffffffffffdfc]
         // 00401220: mov ss:[ebp+0xfffffffffffffdf8], eax
         // 00401226: movzx eax, b1 ss:[ebp+0xffffffffffffff09]
         // 0040122d: add eax, esi
         // 0040122f: cdq 
         // 00401230: idiv edi
         // 00401232: movzx eax, b1 ss:[ebp+0xffffffffffffff05]
         // 00401239: add eax, esi
         // 0040123b: movzx ebx, b1 ss:[ebp+edx+0xfffffffffffffdfc]
         // 00401243: cdq 
         // 00401244: idiv edi
         // 00401246: movzx eax, b1 ss:[ebp+0xffffffffffffff0a]
         // 0040124d: add eax, esi
         // 0040124f: mov esi, 0xff
         // 00401254: movzx edi, b1 ss:[ebp+edx+0xfffffffffffffdfc]
         // 0040125c: cdq 
         // 0040125d: idiv esi
         // 0040125f: movzx eax, b1 ss:[ebp+edx+0xfffffffffffffdfc]
         // 00401267: mov edx, ss:[ebp+0xfffffffffffffdf8]
         // 0040126d: jmp 0x401277
      [-]33d233db33ff33c0
         // 0040126f: xor edx, edx
         // 00401271: xor ebx, ebx
         // 00401273: xor edi, edi
         // 00401275: xor eax, eax
      [-]c1e00833c7c1e00833c3c1e00833c28981????????c1c8088981????????c1c8088981????????c1c8088981????????83c10481f9????????0f8cecfeffff
         // 00401277: shl eax, b1 0x8
         // 0040127a: xor eax, edi
         // 0040127c: shl eax, b1 0x8
         // 0040127f: xor eax, ebx
         // 00401281: shl eax, b1 0x8
         // 00401284: xor eax, edx
         // 00401286: mov ds:[ecx+0x4703c0], eax
         // 0040128c: ror eax, b1 0x8
         // 0040128f: mov ds:[ecx+0x46ffc0], eax
         // 00401295: ror eax, b1 0x8
         // 00401298: mov ds:[ecx+0x46ef80], eax
         // 0040129e: ror eax, b1 0x8
         // 004012a1: mov ds:[ecx+0x46eb80], eax
         // 004012a7: add ecx, 0x4
         // 004012aa: cmp ecx, 0x400
         // 004012b0: jl 0x4011a2
      [-]8b4dfc5f5e33cd5be8080101008be55dc3
         // 004012b6: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004012b9: pop edi
         // 004012ba: pop esi
         // 004012bb: xor ecx, ebp
         // 004012bd: pop ebx
         // 004012be: call @__security_check_cookie@4
         // 004012c3: mov esp, ebp
         // 004012c5: pop ebp
         // 004012c6: retn 
      [-]558bec833d????????00740f
         // 004012d0: push ebp
         // 004012d1: mov ebp, esp
         // 004012d3: cmp ds:[0x46c42c], 0x0
         // 004012da: jz 0x4012eb
      [-]e8dffdffffc705????????????????
         // 004012dc: call 0x4010c0
         // 004012e1: mov ds:[0x46c42c], 0x0
      [-]8b45088b4d0c535633d2c780????????????????83c10257
         // 004012eb: mov eax, ss:[ebp+0x8]
         // 004012ee: mov ecx, ss:[ebp+0xc]
         // 004012f1: push ebx
         // 004012f2: push esi
         // 004012f3: xor edx, edx
         // 004012f5: mov ds:[eax+0x200], 0xe
         // 004012ff: add ecx, 0x2
         // 00401302: push edi
      [-]0fb671fe0fb679ffc1e6080bf70fb639c1e6080bf70fb67901c1e6080bf78934904283c10483fa087cd6
         // 00401303: movzx esi, b1 ds:[ecx+0xfffffffffffffffe]
         // 00401307: movzx edi, b1 ds:[ecx+0xffffffffffffffff]
         // 0040130b: shl esi, b1 0x8
         // 0040130e: or esi, edi
         // 00401310: movzx edi, b1 ds:[ecx]
         // 00401313: shl esi, b1 0x8
         // 00401316: or esi, edi
         // 00401318: movzx edi, b1 ds:[ecx+0x1]
         // 0040131c: shl esi, b1 0x8
         // 0040131f: or esi, edi
         // 00401321: mov ds:[eax+edx*0x4], esi
         // 00401324: inc edx
         // 00401325: add ecx, 0x4
         // 00401328: cmp edx, 0x8
         // 0040132b: jl 0x401303
      [-]bb????????
         // 0040132d: mov ebx, 0x46f380
      [-]8b701c8bcec1e9100fb6d18b0c95????????c1e1088b780c8bd6c1ea080fb6d2330c95????????0fb6501cc1e108330c95????????8bd6c1e108c1ea18330c95????????8b5004330883c304334bfc83c02033d189088b48e833ca33f989500489480889780c8bcfc1e9188b0c8d????????c1e1088bd7c1ea100fb6d2330c95????????8bd7c1ea08c1e1080fb6d2330c95????????0fb6500cc1e108330c95????????8b50f43348f033d18948108b48f833ca33f189501489481889701c81fb????????0f8c35ffffff
         // 00401332: mov esi, ds:[eax+0x1c]
         // 00401335: mov ecx, esi
         // 00401337: shr ecx, b1 0x10
         // 0040133a: movzx edx, b1 cl
         // 0040133d: mov ecx, ds:[0x46e780+edx*0x4]
         // 00401344: shl ecx, b1 0x8
         // 00401347: mov edi, ds:[eax+0xc]
         // 0040134a: mov edx, esi
         // 0040134c: shr edx, b1 0x8
         // 0040134f: movzx edx, b1 dl
         // 00401352: xor ecx, ds:[0x46e780+edx*0x4]
         // 00401359: movzx edx, b1 ds:[eax+0x1c]
         // 0040135d: shl ecx, b1 0x8
         // 00401360: xor ecx, ds:[0x46e780+edx*0x4]
         // 00401367: mov edx, esi
         // 00401369: shl ecx, b1 0x8
         // 0040136c: shr edx, b1 0x18
         // 0040136f: xor ecx, ds:[0x46e780+edx*0x4]
         // 00401376: mov edx, ds:[eax+0x4]
         // 00401379: xor ecx, ds:[eax]
         // 0040137b: add ebx, 0x4
         // 0040137e: xor ecx, ds:[ebx+0xfffffffffffffffc]
         // 00401381: add eax, 0x20
         // 00401384: xor edx, ecx
         // 00401386: mov ds:[eax], ecx
         // 00401388: mov ecx, ds:[eax+0xffffffffffffffe8]
         // 0040138b: xor ecx, edx
         // 0040138d: xor edi, ecx
         // 0040138f: mov ds:[eax+0x4], edx
         // 00401392: mov ds:[eax+0x8], ecx
         // 00401395: mov ds:[eax+0xc], edi
         // 00401398: mov ecx, edi
         // 0040139a: shr ecx, b1 0x18
         // 0040139d: mov ecx, ds:[0x46e780+ecx*0x4]
         // 004013a4: shl ecx, b1 0x8
         // 004013a7: mov edx, edi
         // 004013a9: shr edx, b1 0x10
         // 004013ac: movzx edx, b1 dl
         // 004013af: xor ecx, ds:[0x46e780+edx*0x4]
         // 004013b6: mov edx, edi
         // 004013b8: shr edx, b1 0x8
         // 004013bb: shl ecx, b1 0x8
         // 004013be: movzx edx, b1 dl
         // 004013c1: xor ecx, ds:[0x46e780+edx*0x4]
         // 004013c8: movzx edx, b1 ds:[eax+0xc]
         // 004013cc: shl ecx, b1 0x8
         // 004013cf: xor ecx, ds:[0x46e780+edx*0x4]
         // 004013d6: mov edx, ds:[eax+0xfffffffffffffff4]
         // 004013d9: xor ecx, ds:[eax+0xfffffffffffffff0]
         // 004013dc: xor edx, ecx
         // 004013de: mov ds:[eax+0x10], ecx
         // 004013e1: mov ecx, ds:[eax+0xfffffffffffffff8]
         // 004013e4: xor ecx, edx
         // 004013e6: xor esi, ecx
         // 004013e8: mov ds:[eax+0x14], edx
         // 004013eb: mov ds:[eax+0x18], ecx
         // 004013ee: mov ds:[eax+0x1c], esi
         // 004013f1: cmp ebx, 0x46f39c
         // 004013f7: jl 0x401332
      [-]833d????????000f8408010000
         // 004013fd: cmp ds:[0x46c48c], 0x0
         // 00401404: jz 0x401512
      [-]33c98d642400
         // 0040140a: xor ecx, ecx
         // 0040140c: lea esp, ss:[esp+0x0]
      [-]8b91????????03d28bb412????????03d289b1????????8bb2????????89b1????????8bb2????????8b92????????8991????????8b91????????03d203d289b1????????8bb2????????89b1????????8bb2????????89b1????????8bb2????????8b92????????8991????????8b91????????03d203d289b1????????8bb2????????89b1????????8bb2????????89b1????????8bb2????????8b92????????8991????????8b91????????03d203d289b1????????8bb2????????89b1????????8bb2????????89b1????????8bb2????????8b92????????89b1????????8991????????83c11081f9????????0f8c08ffffff
         // 00401410: mov edx, ds:[ecx+0x46e780]
         // 00401416: add edx, edx
         // 00401418: mov esi, ds:[edx+edx+0x4703c0]
         // 0040141f: add edx, edx
         // 00401421: mov ds:[ecx+0x46fbc0], esi
         // 00401427: mov esi, ds:[edx+0x46ffc0]
         // 0040142d: mov ds:[ecx+0x46f7c0], esi
         // 00401433: mov esi, ds:[edx+0x46ef80]
         // 00401439: mov edx, ds:[edx+0x46eb80]
         // 0040143f: mov ds:[ecx+0x471bc0], edx
         // 00401445: mov edx, ds:[ecx+0x46e784]
         // 0040144b: add edx, edx
         // 0040144d: add edx, edx
         // 0040144f: mov ds:[ecx+0x46f3c0], esi
         // 00401455: mov esi, ds:[edx+0x4703c0]
         // 0040145b: mov ds:[ecx+0x46fbc4], esi
         // 00401461: mov esi, ds:[edx+0x46ffc0]
         // 00401467: mov ds:[ecx+0x46f7c4], esi
         // 0040146d: mov esi, ds:[edx+0x46ef80]
         // 00401473: mov edx, ds:[edx+0x46eb80]
         // 00401479: mov ds:[ecx+0x471bc4], edx
         // 0040147f: mov edx, ds:[ecx+0x46e788]
         // 00401485: add edx, edx
         // 00401487: add edx, edx
         // 00401489: mov ds:[ecx+0x46f3c4], esi
         // 0040148f: mov esi, ds:[edx+0x4703c0]
         // 00401495: mov ds:[ecx+0x46fbc8], esi
         // 0040149b: mov esi, ds:[edx+0x46ffc0]
         // 004014a1: mov ds:[ecx+0x46f7c8], esi
         // 004014a7: mov esi, ds:[edx+0x46ef80]
         // 004014ad: mov edx, ds:[edx+0x46eb80]
         // 004014b3: mov ds:[ecx+0x471bc8], edx
         // 004014b9: mov edx, ds:[ecx+0x46e78c]
         // 004014bf: add edx, edx
         // 004014c1: add edx, edx
         // 004014c3: mov ds:[ecx+0x46f3c8], esi
         // 004014c9: mov esi, ds:[edx+0x4703c0]
         // 004014cf: mov ds:[ecx+0x46fbcc], esi
         // 004014d5: mov esi, ds:[edx+0x46ffc0]
         // 004014db: mov ds:[ecx+0x46f7cc], esi
         // 004014e1: mov esi, ds:[edx+0x46ef80]
         // 004014e7: mov edx, ds:[edx+0x46eb80]
         // 004014ed: mov ds:[ecx+0x46f3cc], esi
         // 004014f3: mov ds:[ecx+0x471bcc], edx
         // 004014f9: add ecx, 0x10
         // 004014fc: cmp ecx, 0x400
         // 00401502: jl 0x401410
      [-]c705????????????????
         // 00401508: mov ds:[0x46c48c], 0x0
      [-]8b308b550889b2????????8b70048d8a????????8971048b70088971088b700c89710cbf????????83c11083c01039ba????????0f8e05010000
         // 00401512: mov esi, ds:[eax]
         // 00401514: mov edx, ss:[ebp+0x8]
         // 00401517: mov ds:[edx+0x100], esi
         // 0040151d: mov esi, ds:[eax+0x4]
         // 00401520: lea ecx, ds:[edx+0x100]
         // 00401526: mov ds:[ecx+0x4], esi
         // 00401529: mov esi, ds:[eax+0x8]
         // 0040152c: mov ds:[ecx+0x8], esi
         // 0040152f: mov esi, ds:[eax+0xc]
         // 00401532: mov ds:[ecx+0xc], esi
         // 00401535: mov edi, 0x1
         // 0040153a: add ecx, 0x10
         // 0040153d: add eax, 0x10
         // 00401540: cmp ds:[edx+0x200], edi
         // 00401546: jle 0x401651
      [-]8d642400
         // 0040154c: lea esp, ss:[esp+0x0]
      [-]8b70e08bdec1eb100fb6db8bd6c1ea188b1495????????33149d????????8bdec1eb080fb6f33314b5????????0fb670e03314b5????????4789118b70e48bdec1eb100fb6db8bd6c1ea188b1495????????33149d????????8bdec1eb080fb6f33314b5????????0fb670e43314b5????????83c1108951f48b70e88bdec1eb108bd6c1ea188b1495????????0fb6db33149d????????8bdec1eb080fb6f33314b5????????0fb670e83314b5????????83c0f08951f88b70fc8bdec1eb108bd6c1ea188b1495????????0fb6db33149d????????8bdec1eb080fb6f33314b5????????0fb670fc3314b5????????8951fc8b55083bba????????0f8cfffeffff
         // 00401550: mov esi, ds:[eax+0xffffffffffffffe0]
         // 00401553: mov ebx, esi
         // 00401555: shr ebx, b1 0x10
         // 00401558: movzx ebx, b1 bl
         // 0040155b: mov edx, esi
         // 0040155d: shr edx, b1 0x18
         // 00401560: mov edx, ds:[0x46fbc0+edx*0x4]
         // 00401567: xor edx, ds:[0x46f7c0+ebx*0x4]
         // 0040156e: mov ebx, esi
         // 00401570: shr ebx, b1 0x8
         // 00401573: movzx esi, b1 bl
         // 00401576: xor edx, ds:[0x46f3c0+esi*0x4]
         // 0040157d: movzx esi, b1 ds:[eax+0xffffffffffffffe0]
         // 00401581: xor edx, ds:[0x471bc0+esi*0x4]
         // 00401588: inc edi
         // 00401589: mov ds:[ecx], edx
         // 0040158b: mov esi, ds:[eax+0xffffffffffffffe4]
         // 0040158e: mov ebx, esi
         // 00401590: shr ebx, b1 0x10
         // 00401593: movzx ebx, b1 bl
         // 00401596: mov edx, esi
         // 00401598: shr edx, b1 0x18
         // 0040159b: mov edx, ds:[0x46fbc0+edx*0x4]
         // 004015a2: xor edx, ds:[0x46f7c0+ebx*0x4]
         // 004015a9: mov ebx, esi
         // 004015ab: shr ebx, b1 0x8
         // 004015ae: movzx esi, b1 bl
         // 004015b1: xor edx, ds:[0x46f3c0+esi*0x4]
         // 004015b8: movzx esi, b1 ds:[eax+0xffffffffffffffe4]
         // 004015bc: xor edx, ds:[0x471bc0+esi*0x4]
         // 004015c3: add ecx, 0x10
         // 004015c6: mov ds:[ecx+0xfffffffffffffff4], edx
         // 004015c9: mov esi, ds:[eax+0xffffffffffffffe8]
         // 004015cc: mov ebx, esi
         // 004015ce: shr ebx, b1 0x10
         // 004015d1: mov edx, esi
         // 004015d3: shr edx, b1 0x18
         // 004015d6: mov edx, ds:[0x46fbc0+edx*0x4]
         // 004015dd: movzx ebx, b1 bl
         // 004015e0: xor edx, ds:[0x46f7c0+ebx*0x4]
         // 004015e7: mov ebx, esi
         // 004015e9: shr ebx, b1 0x8
         // 004015ec: movzx esi, b1 bl
         // 004015ef: xor edx, ds:[0x46f3c0+esi*0x4]
         // 004015f6: movzx esi, b1 ds:[eax+0xffffffffffffffe8]
         // 004015fa: xor edx, ds:[0x471bc0+esi*0x4]
         // 00401601: add eax, 0xfffffffffffffff0
         // 00401604: mov ds:[ecx+0xfffffffffffffff8], edx
         // 00401607: mov esi, ds:[eax+0xfffffffffffffffc]
         // 0040160a: mov ebx, esi
         // 0040160c: shr ebx, b1 0x10
         // 0040160f: mov edx, esi
         // 00401611: shr edx, b1 0x18
         // 00401614: mov edx, ds:[0x46fbc0+edx*0x4]
         // 0040161b: movzx ebx, b1 bl
         // 0040161e: xor edx, ds:[0x46f7c0+ebx*0x4]
         // 00401625: mov ebx, esi
         // 00401627: shr ebx, b1 0x8
         // 0040162a: movzx esi, b1 bl
         // 0040162d: xor edx, ds:[0x46f3c0+esi*0x4]
         // 00401634: movzx esi, b1 ds:[eax+0xfffffffffffffffc]
         // 00401638: xor edx, ds:[0x471bc0+esi*0x4]
         // 0040163f: mov ds:[ecx+0xfffffffffffffffc], edx
         // 00401642: mov edx, ss:[ebp+0x8]
         // 00401645: cmp edi, ds:[edx+0x200]
         // 0040164b: jl 0x401550
      [-]8b50e089118b50e48951048b50e88951088b40ec5f5e89410c33c05b5dc3
         // 00401651: mov edx, ds:[eax+0xffffffffffffffe0]
         // 00401654: mov ds:[ecx], edx
         // 00401656: mov edx, ds:[eax+0xffffffffffffffe4]
         // 00401659: mov ds:[ecx+0x4], edx
         // 0040165c: mov edx, ds:[eax+0xffffffffffffffe8]
         // 0040165f: mov ds:[ecx+0x8], edx
         // 00401662: mov eax, ds:[eax+0xffffffffffffffec]
         // 00401665: pop edi
         // 00401666: pop esi
         // 00401667: mov ds:[ecx+0xc], eax
         // 0040166a: xor eax, eax
         // 0040166c: pop ebx
         // 0040166d: pop ebp
         // 0040166e: retn 
      [-]558bec83ec1c0fb6080fb65001530fb65805c1e1080bca0fb65002568b7508c1e1080bca0fb65003c1e1080bca330e0fb65004c1e2080bd30fb65806c1e2080bd30fb65807c1e2080bd33356040fb670080fb65809c1e6080bf30fb6580ac1e6080bf30fb6580bc1e6080bf38b5d083373080fb6580d8975ec0fb6700cc1e6080bf30fb6580e0fb6400fc1e6080bf38b5decc1e6080bf08b450833700cc1eb088975e80fb6f38b34b5????????8bdac1eb100fb6db33349d????????8bd9c1eb1833349d????????0fb65de833349d????????8b5de8337010c1eb088975fc0fb6f38b5dec8b34b5????????c1eb100fb6db33349d????????8bdac1eb1833349d????????0fb6d933349d????????3370148975f88b5de8c1eb100fb6f38b34b5????????8b5decc1eb1833349d????????8bd9c1eb080fb6db33349d????????0fb6da33349d????????c1ea08337018c1e9108975f48b75e8c1ee180fb6da8b14b5????????33149d????????8b5df80fb6c933148d????????0fb64dec33148d????????8b4df433501cc1eb100fb6f3c1e9080fb6c98b0c8d????????330cb5????????8b75fcc1ee18330cb5????????0fb6f2330cb5????????8bdac1eb080fb6f38b34b5????????8b5df4c1eb100fb6db33349d????????0fb65dfc8975e88b75f8c1ee188b34b5????????3175e88b75e833349d????????3348203370248bda8975f0c1eb100fb6f38b34b5????????8b5df4c1eb1833349d????????8b5dfc8975e8c1eb080fb6f38b34b5????????3175e80fb65df88b75e833349d????????8b5df8337028c1ea18c1eb088975ec0fb6f38b1495????????3314b5????????8b5dfcc1eb100fb6f33314b5????????0fb675f43314b5????????8b5dec33502cc1eb080fb6f38b34b5????????8b5df0c1eb100fb6db33349d????????8bd9c1eb1833349d????????0fb6da33349d????????8bda337030c1eb088975fc0fb6f38b34b5????????8b5decc1eb100fb6db33349d????????8b5df0c1eb1833349d????????0fb6d933349d????????8bda337034c1eb108975f80fb6f38b34b5????????8b5decc1eb1833349d????????8bd98975e8c1eb080fb6f38b34b5????????3175e80fb65df08b75e833349d????????8b5df0337038c1e9108975f4c1ea188b1495????????c1eb080fb6c90fb6f33314b5????????8b5df833148d????????0fb64dec33148d????????8b4df433503cc1e9080fb6c98b0c8d????????c1eb100fb6f3330cb5????????8b75fcc1ee18330cb5????????0fb6f2330cb5????????8bdac1eb080fb6f38b34b5????????8b5df4c1eb100fb6db33349d????????0fb65dfc8975e88b75f8c1ee188b34b5????????3175e88b75e833349d????????8bda337044c1eb108975f00fb6f38b34b5????????8b5df4c1eb1833349d????????8b5dfcc1eb088975e80fb6f38b34b5????????3175e80fb65df88b75e833349d????????8b5df8337048c1eb088975ec0fb6f38b5dfcc1eb10334840c1ea188b1495????????3314b5????????0fb6f33314b5????????0fb675f43314b5????????8b5dec33504cc1eb080fb6f38b34b5????????8b5df0c1eb100fb6db33349d????????8bd9c1eb1833349d????????0fb6da33349d????????8bda337050c1eb088975fc0fb6f38b5dec8b34b5????????c1eb100fb6db33349d????????8b5df0c1eb1833349d????????0fb6d933349d????????3370548975f88bdac1eb100fb6f38b34b5????????8b5decc1eb1833349d????????8bd98975e8c1eb080fb6f38b34b5????????3175e80fb65df08b75e833349d????????8b5df0337058c1eb088975f40fb6f38b5df8c1e9100fb6c9c1ea188b1495????????3314b5????????c1eb1033148d????????0fb64dec33148d????????8b4df433505c0fb6f3c1e9080fb6c98b0c8d????????330cb5????????8b75fcc1ee18330cb5????????0fb6f2330cb5????????8bdac1eb080fb6f38b34b5????????8b5df4c1eb100fb6db33349d????????0fb65dfc8975e88b75f8c1ee188b34b5????????3175e88b75e833349d????????3348603370648bda8975f0c1eb100fb6f38b34b5????????8b5df4c1eb1833349d????????8b5dfc8975e8c1eb080fb6f38b34b5????????3175e80fb65df88b75e833349d????????337068c1ea188975ec8b1495????????8b5df8c1eb080fb6f33314b5????????8b5dfcc1eb100fb6f33314b5????????0fb675f43314b5????????8b5dec33506cc1eb080fb6f38b34b5????????8b5df0c1eb100fb6db33349d????????8bd9c1eb1833349d????????0fb6da33349d????????8bda337070c1eb088975fc0fb6f38b34b5????????8b5decc1eb100fb6db33349d????????8b5df0c1eb1833349d????????0fb6d933349d????????8bda337074c1eb108975f80fb6f38b34b5????????8b5decc1eb1833349d????????8bd98975e8c1eb080fb6f38b34b5????????3175e80fb65df08b75e833349d????????8b5df0337078c1ea188b1495????????c1eb08c1e9108975f40fb6f33314b5????????8b5df80fb6c933148d????????0fb64dec33148d????????8b4df433507cc1e9080fb6c98b0c8d????????c1eb100fb6f3330cb5????????8b75fcc1ee18330cb5????????0fb6f2330cb5????????8bdac1eb080fb6f38b34b5????????8b5df4c1eb100fb6db33349d????????0fb65dfc8975e88b75f8c1ee188b34b5????????3175e88b75e833349d????????8bda33b0????????c1eb108975f00fb6f38b34b5????????8b5df4c1eb1833349d????????8b5dfcc1eb088975e80fb6f38b34b5????????3175e80fb65df88b75e833349d????????8b5df833b0????????c1eb088975ec0fb6f38b5dfcc1eb103388????????c1ea188b1495????????3314b5????????0fb6f33314b5????????0fb675f43314b5????????8b5dec3390????????c1eb080fb6f38b34b5????????8b5df0c1eb100fb6db33349d????????8bd9c1eb1833349d????????0fb6da33349d????????05????????33308bdac1eb088975fc0fb6f38b5dec8b34b5????????c1eb100fb6db33349d????????8b5df0c1eb1833349d????????0fb6d933349d????????8bda337004c1eb108975f80fb6f38b34b5????????8b5decc1eb1833349d????????8bd98975e8c1eb080fb6f38b34b5????????3175e80fb65df08b75e833349d????????8b5df0337008c1ea188b1495????????c1eb08c1e9108975f40fb6f33314b5????????0fb6c933148d????????0fb64dec33148d????????8b4d088b89????????33500c894de483f90a0f8e02020000
         // 00401670: push ebp
         // 00401671: mov ebp, esp
         // 00401673: sub esp, 0x1c
         // 00401676: movzx ecx, b1 ds:[eax]
         // 00401679: movzx edx, b1 ds:[eax+0x1]
         // 0040167d: push ebx
         // 0040167e: movzx ebx, b1 ds:[eax+0x5]
         // 00401682: shl ecx, b1 0x8
         // 00401685: or ecx, edx
         // 00401687: movzx edx, b1 ds:[eax+0x2]
         // 0040168b: push esi
         // 0040168c: mov esi, ss:[ebp+0x8]
         // 0040168f: shl ecx, b1 0x8
         // 00401692: or ecx, edx
         // 00401694: movzx edx, b1 ds:[eax+0x3]
         // 00401698: shl ecx, b1 0x8
         // 0040169b: or ecx, edx
         // 0040169d: xor ecx, ds:[esi]
         // 0040169f: movzx edx, b1 ds:[eax+0x4]
         // 004016a3: shl edx, b1 0x8
         // 004016a6: or edx, ebx
         // 004016a8: movzx ebx, b1 ds:[eax+0x6]
         // 004016ac: shl edx, b1 0x8
         // 004016af: or edx, ebx
         // 004016b1: movzx ebx, b1 ds:[eax+0x7]
         // 004016b5: shl edx, b1 0x8
         // 004016b8: or edx, ebx
         // 004016ba: xor edx, ds:[esi+0x4]
         // 004016bd: movzx esi, b1 ds:[eax+0x8]
         // 004016c1: movzx ebx, b1 ds:[eax+0x9]
         // 004016c5: shl esi, b1 0x8
         // 004016c8: or esi, ebx
         // 004016ca: movzx ebx, b1 ds:[eax+0xa]
         // 004016ce: shl esi, b1 0x8
         // 004016d1: or esi, ebx
         // 004016d3: movzx ebx, b1 ds:[eax+0xb]
         // 004016d7: shl esi, b1 0x8
         // 004016da: or esi, ebx
         // 004016dc: mov ebx, ss:[ebp+0x8]
         // 004016df: xor esi, ds:[ebx+0x8]
         // 004016e2: movzx ebx, b1 ds:[eax+0xd]
         // 004016e6: mov ss:[ebp+0xffffffffffffffec], esi
         // 004016e9: movzx esi, b1 ds:[eax+0xc]
         // 004016ed: shl esi, b1 0x8
         // 004016f0: or esi, ebx
         // 004016f2: movzx ebx, b1 ds:[eax+0xe]
         // 004016f6: movzx eax, b1 ds:[eax+0xf]
         // 004016fa: shl esi, b1 0x8
         // 004016fd: or esi, ebx
         // 004016ff: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401702: shl esi, b1 0x8
         // 00401705: or esi, eax
         // 00401707: mov eax, ss:[ebp+0x8]
         // 0040170a: xor esi, ds:[eax+0xc]
         // 0040170d: shr ebx, b1 0x8
         // 00401710: mov ss:[ebp+0xffffffffffffffe8], esi
         // 00401713: movzx esi, b1 bl
         // 00401716: mov esi, ds:[0x470bc0+esi*0x4]
         // 0040171d: mov ebx, edx
         // 0040171f: shr ebx, b1 0x10
         // 00401722: movzx ebx, b1 bl
         // 00401725: xor esi, ds:[0x470fc0+ebx*0x4]
         // 0040172c: mov ebx, ecx
         // 0040172e: shr ebx, b1 0x18
         // 00401731: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00401738: movzx ebx, b1 ss:[ebp+0xffffffffffffffe8]
         // 0040173c: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00401743: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 00401746: xor esi, ds:[eax+0x10]
         // 00401749: shr ebx, b1 0x8
         // 0040174c: mov ss:[ebp+0xfffffffffffffffc], esi
         // 0040174f: movzx esi, b1 bl
         // 00401752: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401755: mov esi, ds:[0x470bc0+esi*0x4]
         // 0040175c: shr ebx, b1 0x10
         // 0040175f: movzx ebx, b1 bl
         // 00401762: xor esi, ds:[0x470fc0+ebx*0x4]
         // 00401769: mov ebx, edx
         // 0040176b: shr ebx, b1 0x18
         // 0040176e: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00401775: movzx ebx, b1 cl
         // 00401778: xor esi, ds:[0x4707c0+ebx*0x4]
         // 0040177f: xor esi, ds:[eax+0x14]
         // 00401782: mov ss:[ebp+0xfffffffffffffff8], esi
         // 00401785: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 00401788: shr ebx, b1 0x10
         // 0040178b: movzx esi, b1 bl
         // 0040178e: mov esi, ds:[0x470fc0+esi*0x4]
         // 00401795: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401798: shr ebx, b1 0x18
         // 0040179b: xor esi, ds:[0x4713c0+ebx*0x4]
         // 004017a2: mov ebx, ecx
         // 004017a4: shr ebx, b1 0x8
         // 004017a7: movzx ebx, b1 bl
         // 004017aa: xor esi, ds:[0x470bc0+ebx*0x4]
         // 004017b1: movzx ebx, b1 dl
         // 004017b4: xor esi, ds:[0x4707c0+ebx*0x4]
         // 004017bb: shr edx, b1 0x8
         // 004017be: xor esi, ds:[eax+0x18]
         // 004017c1: shr ecx, b1 0x10
         // 004017c4: mov ss:[ebp+0xfffffffffffffff4], esi
         // 004017c7: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 004017ca: shr esi, b1 0x18
         // 004017cd: movzx ebx, b1 dl
         // 004017d0: mov edx, ds:[0x4713c0+esi*0x4]
         // 004017d7: xor edx, ds:[0x470bc0+ebx*0x4]
         // 004017de: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 004017e1: movzx ecx, b1 cl
         // 004017e4: xor edx, ds:[0x470fc0+ecx*0x4]
         // 004017eb: movzx ecx, b1 ss:[ebp+0xffffffffffffffec]
         // 004017ef: xor edx, ds:[0x4707c0+ecx*0x4]
         // 004017f6: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 004017f9: xor edx, ds:[eax+0x1c]
         // 004017fc: shr ebx, b1 0x10
         // 004017ff: movzx esi, b1 bl
         // 00401802: shr ecx, b1 0x8
         // 00401805: movzx ecx, b1 cl
         // 00401808: mov ecx, ds:[0x470bc0+ecx*0x4]
         // 0040180f: xor ecx, ds:[0x470fc0+esi*0x4]
         // 00401816: mov esi, ss:[ebp+0xfffffffffffffffc]
         // 00401819: shr esi, b1 0x18
         // 0040181c: xor ecx, ds:[0x4713c0+esi*0x4]
         // 00401823: movzx esi, b1 dl
         // 00401826: xor ecx, ds:[0x4707c0+esi*0x4]
         // 0040182d: mov ebx, edx
         // 0040182f: shr ebx, b1 0x8
         // 00401832: movzx esi, b1 bl
         // 00401835: mov esi, ds:[0x470bc0+esi*0x4]
         // 0040183c: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 0040183f: shr ebx, b1 0x10
         // 00401842: movzx ebx, b1 bl
         // 00401845: xor esi, ds:[0x470fc0+ebx*0x4]
         // 0040184c: movzx ebx, b1 ss:[ebp+0xfffffffffffffffc]
         // 00401850: mov ss:[ebp+0xffffffffffffffe8], esi
         // 00401853: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00401856: shr esi, b1 0x18
         // 00401859: mov esi, ds:[0x4713c0+esi*0x4]
         // 00401860: xor ss:[ebp+0xffffffffffffffe8], esi
         // 00401863: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 00401866: xor esi, ds:[0x4707c0+ebx*0x4]
         // 0040186d: xor ecx, ds:[eax+0x20]
         // 00401870: xor esi, ds:[eax+0x24]
         // 00401873: mov ebx, edx
         // 00401875: mov ss:[ebp+0xfffffffffffffff0], esi
         // 00401878: shr ebx, b1 0x10
         // 0040187b: movzx esi, b1 bl
         // 0040187e: mov esi, ds:[0x470fc0+esi*0x4]
         // 00401885: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 00401888: shr ebx, b1 0x18
         // 0040188b: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00401892: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401895: mov ss:[ebp+0xffffffffffffffe8], esi
         // 00401898: shr ebx, b1 0x8
         // 0040189b: movzx esi, b1 bl
         // 0040189e: mov esi, ds:[0x470bc0+esi*0x4]
         // 004018a5: xor ss:[ebp+0xffffffffffffffe8], esi
         // 004018a8: movzx ebx, b1 ss:[ebp+0xfffffffffffffff8]
         // 004018ac: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 004018af: xor esi, ds:[0x4707c0+ebx*0x4]
         // 004018b6: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 004018b9: xor esi, ds:[eax+0x28]
         // 004018bc: shr edx, b1 0x18
         // 004018bf: shr ebx, b1 0x8
         // 004018c2: mov ss:[ebp+0xffffffffffffffec], esi
         // 004018c5: movzx esi, b1 bl
         // 004018c8: mov edx, ds:[0x4713c0+edx*0x4]
         // 004018cf: xor edx, ds:[0x470bc0+esi*0x4]
         // 004018d6: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 004018d9: shr ebx, b1 0x10
         // 004018dc: movzx esi, b1 bl
         // 004018df: xor edx, ds:[0x470fc0+esi*0x4]
         // 004018e6: movzx esi, b1 ss:[ebp+0xfffffffffffffff4]
         // 004018ea: xor edx, ds:[0x4707c0+esi*0x4]
         // 004018f1: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 004018f4: xor edx, ds:[eax+0x2c]
         // 004018f7: shr ebx, b1 0x8
         // 004018fa: movzx esi, b1 bl
         // 004018fd: mov esi, ds:[0x470bc0+esi*0x4]
         // 00401904: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401907: shr ebx, b1 0x10
         // 0040190a: movzx ebx, b1 bl
         // 0040190d: xor esi, ds:[0x470fc0+ebx*0x4]
         // 00401914: mov ebx, ecx
         // 00401916: shr ebx, b1 0x18
         // 00401919: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00401920: movzx ebx, b1 dl
         // 00401923: xor esi, ds:[0x4707c0+ebx*0x4]
         // 0040192a: mov ebx, edx
         // 0040192c: xor esi, ds:[eax+0x30]
         // 0040192f: shr ebx, b1 0x8
         // 00401932: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00401935: movzx esi, b1 bl
         // 00401938: mov esi, ds:[0x470bc0+esi*0x4]
         // 0040193f: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401942: shr ebx, b1 0x10
         // 00401945: movzx ebx, b1 bl
         // 00401948: xor esi, ds:[0x470fc0+ebx*0x4]
         // 0040194f: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401952: shr ebx, b1 0x18
         // 00401955: xor esi, ds:[0x4713c0+ebx*0x4]
         // 0040195c: movzx ebx, b1 cl
         // 0040195f: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00401966: mov ebx, edx
         // 00401968: xor esi, ds:[eax+0x34]
         // 0040196b: shr ebx, b1 0x10
         // 0040196e: mov ss:[ebp+0xfffffffffffffff8], esi
         // 00401971: movzx esi, b1 bl
         // 00401974: mov esi, ds:[0x470fc0+esi*0x4]
         // 0040197b: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 0040197e: shr ebx, b1 0x18
         // 00401981: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00401988: mov ebx, ecx
         // 0040198a: mov ss:[ebp+0xffffffffffffffe8], esi
         // 0040198d: shr ebx, b1 0x8
         // 00401990: movzx esi, b1 bl
         // 00401993: mov esi, ds:[0x470bc0+esi*0x4]
         // 0040199a: xor ss:[ebp+0xffffffffffffffe8], esi
         // 0040199d: movzx ebx, b1 ss:[ebp+0xfffffffffffffff0]
         // 004019a1: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 004019a4: xor esi, ds:[0x4707c0+ebx*0x4]
         // 004019ab: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 004019ae: xor esi, ds:[eax+0x38]
         // 004019b1: shr ecx, b1 0x10
         // 004019b4: mov ss:[ebp+0xfffffffffffffff4], esi
         // 004019b7: shr edx, b1 0x18
         // 004019ba: mov edx, ds:[0x4713c0+edx*0x4]
         // 004019c1: shr ebx, b1 0x8
         // 004019c4: movzx ecx, b1 cl
         // 004019c7: movzx esi, b1 bl
         // 004019ca: xor edx, ds:[0x470bc0+esi*0x4]
         // 004019d1: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 004019d4: xor edx, ds:[0x470fc0+ecx*0x4]
         // 004019db: movzx ecx, b1 ss:[ebp+0xffffffffffffffec]
         // 004019df: xor edx, ds:[0x4707c0+ecx*0x4]
         // 004019e6: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 004019e9: xor edx, ds:[eax+0x3c]
         // 004019ec: shr ecx, b1 0x8
         // 004019ef: movzx ecx, b1 cl
         // 004019f2: mov ecx, ds:[0x470bc0+ecx*0x4]
         // 004019f9: shr ebx, b1 0x10
         // 004019fc: movzx esi, b1 bl
         // 004019ff: xor ecx, ds:[0x470fc0+esi*0x4]
         // 00401a06: mov esi, ss:[ebp+0xfffffffffffffffc]
         // 00401a09: shr esi, b1 0x18
         // 00401a0c: xor ecx, ds:[0x4713c0+esi*0x4]
         // 00401a13: movzx esi, b1 dl
         // 00401a16: xor ecx, ds:[0x4707c0+esi*0x4]
         // 00401a1d: mov ebx, edx
         // 00401a1f: shr ebx, b1 0x8
         // 00401a22: movzx esi, b1 bl
         // 00401a25: mov esi, ds:[0x470bc0+esi*0x4]
         // 00401a2c: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 00401a2f: shr ebx, b1 0x10
         // 00401a32: movzx ebx, b1 bl
         // 00401a35: xor esi, ds:[0x470fc0+ebx*0x4]
         // 00401a3c: movzx ebx, b1 ss:[ebp+0xfffffffffffffffc]
         // 00401a40: mov ss:[ebp+0xffffffffffffffe8], esi
         // 00401a43: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00401a46: shr esi, b1 0x18
         // 00401a49: mov esi, ds:[0x4713c0+esi*0x4]
         // 00401a50: xor ss:[ebp+0xffffffffffffffe8], esi
         // 00401a53: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 00401a56: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00401a5d: mov ebx, edx
         // 00401a5f: xor esi, ds:[eax+0x44]
         // 00401a62: shr ebx, b1 0x10
         // 00401a65: mov ss:[ebp+0xfffffffffffffff0], esi
         // 00401a68: movzx esi, b1 bl
         // 00401a6b: mov esi, ds:[0x470fc0+esi*0x4]
         // 00401a72: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 00401a75: shr ebx, b1 0x18
         // 00401a78: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00401a7f: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401a82: shr ebx, b1 0x8
         // 00401a85: mov ss:[ebp+0xffffffffffffffe8], esi
         // 00401a88: movzx esi, b1 bl
         // 00401a8b: mov esi, ds:[0x470bc0+esi*0x4]
         // 00401a92: xor ss:[ebp+0xffffffffffffffe8], esi
         // 00401a95: movzx ebx, b1 ss:[ebp+0xfffffffffffffff8]
         // 00401a99: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 00401a9c: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00401aa3: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401aa6: xor esi, ds:[eax+0x48]
         // 00401aa9: shr ebx, b1 0x8
         // 00401aac: mov ss:[ebp+0xffffffffffffffec], esi
         // 00401aaf: movzx esi, b1 bl
         // 00401ab2: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401ab5: shr ebx, b1 0x10
         // 00401ab8: xor ecx, ds:[eax+0x40]
         // 00401abb: shr edx, b1 0x18
         // 00401abe: mov edx, ds:[0x4713c0+edx*0x4]
         // 00401ac5: xor edx, ds:[0x470bc0+esi*0x4]
         // 00401acc: movzx esi, b1 bl
         // 00401acf: xor edx, ds:[0x470fc0+esi*0x4]
         // 00401ad6: movzx esi, b1 ss:[ebp+0xfffffffffffffff4]
         // 00401ada: xor edx, ds:[0x4707c0+esi*0x4]
         // 00401ae1: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401ae4: xor edx, ds:[eax+0x4c]
         // 00401ae7: shr ebx, b1 0x8
         // 00401aea: movzx esi, b1 bl
         // 00401aed: mov esi, ds:[0x470bc0+esi*0x4]
         // 00401af4: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401af7: shr ebx, b1 0x10
         // 00401afa: movzx ebx, b1 bl
         // 00401afd: xor esi, ds:[0x470fc0+ebx*0x4]
         // 00401b04: mov ebx, ecx
         // 00401b06: shr ebx, b1 0x18
         // 00401b09: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00401b10: movzx ebx, b1 dl
         // 00401b13: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00401b1a: mov ebx, edx
         // 00401b1c: xor esi, ds:[eax+0x50]
         // 00401b1f: shr ebx, b1 0x8
         // 00401b22: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00401b25: movzx esi, b1 bl
         // 00401b28: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401b2b: mov esi, ds:[0x470bc0+esi*0x4]
         // 00401b32: shr ebx, b1 0x10
         // 00401b35: movzx ebx, b1 bl
         // 00401b38: xor esi, ds:[0x470fc0+ebx*0x4]
         // 00401b3f: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401b42: shr ebx, b1 0x18
         // 00401b45: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00401b4c: movzx ebx, b1 cl
         // 00401b4f: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00401b56: xor esi, ds:[eax+0x54]
         // 00401b59: mov ss:[ebp+0xfffffffffffffff8], esi
         // 00401b5c: mov ebx, edx
         // 00401b5e: shr ebx, b1 0x10
         // 00401b61: movzx esi, b1 bl
         // 00401b64: mov esi, ds:[0x470fc0+esi*0x4]
         // 00401b6b: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401b6e: shr ebx, b1 0x18
         // 00401b71: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00401b78: mov ebx, ecx
         // 00401b7a: mov ss:[ebp+0xffffffffffffffe8], esi
         // 00401b7d: shr ebx, b1 0x8
         // 00401b80: movzx esi, b1 bl
         // 00401b83: mov esi, ds:[0x470bc0+esi*0x4]
         // 00401b8a: xor ss:[ebp+0xffffffffffffffe8], esi
         // 00401b8d: movzx ebx, b1 ss:[ebp+0xfffffffffffffff0]
         // 00401b91: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 00401b94: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00401b9b: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401b9e: xor esi, ds:[eax+0x58]
         // 00401ba1: shr ebx, b1 0x8
         // 00401ba4: mov ss:[ebp+0xfffffffffffffff4], esi
         // 00401ba7: movzx esi, b1 bl
         // 00401baa: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401bad: shr ecx, b1 0x10
         // 00401bb0: movzx ecx, b1 cl
         // 00401bb3: shr edx, b1 0x18
         // 00401bb6: mov edx, ds:[0x4713c0+edx*0x4]
         // 00401bbd: xor edx, ds:[0x470bc0+esi*0x4]
         // 00401bc4: shr ebx, b1 0x10
         // 00401bc7: xor edx, ds:[0x470fc0+ecx*0x4]
         // 00401bce: movzx ecx, b1 ss:[ebp+0xffffffffffffffec]
         // 00401bd2: xor edx, ds:[0x4707c0+ecx*0x4]
         // 00401bd9: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401bdc: xor edx, ds:[eax+0x5c]
         // 00401bdf: movzx esi, b1 bl
         // 00401be2: shr ecx, b1 0x8
         // 00401be5: movzx ecx, b1 cl
         // 00401be8: mov ecx, ds:[0x470bc0+ecx*0x4]
         // 00401bef: xor ecx, ds:[0x470fc0+esi*0x4]
         // 00401bf6: mov esi, ss:[ebp+0xfffffffffffffffc]
         // 00401bf9: shr esi, b1 0x18
         // 00401bfc: xor ecx, ds:[0x4713c0+esi*0x4]
         // 00401c03: movzx esi, b1 dl
         // 00401c06: xor ecx, ds:[0x4707c0+esi*0x4]
         // 00401c0d: mov ebx, edx
         // 00401c0f: shr ebx, b1 0x8
         // 00401c12: movzx esi, b1 bl
         // 00401c15: mov esi, ds:[0x470bc0+esi*0x4]
         // 00401c1c: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 00401c1f: shr ebx, b1 0x10
         // 00401c22: movzx ebx, b1 bl
         // 00401c25: xor esi, ds:[0x470fc0+ebx*0x4]
         // 00401c2c: movzx ebx, b1 ss:[ebp+0xfffffffffffffffc]
         // 00401c30: mov ss:[ebp+0xffffffffffffffe8], esi
         // 00401c33: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00401c36: shr esi, b1 0x18
         // 00401c39: mov esi, ds:[0x4713c0+esi*0x4]
         // 00401c40: xor ss:[ebp+0xffffffffffffffe8], esi
         // 00401c43: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 00401c46: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00401c4d: xor ecx, ds:[eax+0x60]
         // 00401c50: xor esi, ds:[eax+0x64]
         // 00401c53: mov ebx, edx
         // 00401c55: mov ss:[ebp+0xfffffffffffffff0], esi
         // 00401c58: shr ebx, b1 0x10
         // 00401c5b: movzx esi, b1 bl
         // 00401c5e: mov esi, ds:[0x470fc0+esi*0x4]
         // 00401c65: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 00401c68: shr ebx, b1 0x18
         // 00401c6b: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00401c72: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401c75: mov ss:[ebp+0xffffffffffffffe8], esi
         // 00401c78: shr ebx, b1 0x8
         // 00401c7b: movzx esi, b1 bl
         // 00401c7e: mov esi, ds:[0x470bc0+esi*0x4]
         // 00401c85: xor ss:[ebp+0xffffffffffffffe8], esi
         // 00401c88: movzx ebx, b1 ss:[ebp+0xfffffffffffffff8]
         // 00401c8c: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 00401c8f: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00401c96: xor esi, ds:[eax+0x68]
         // 00401c99: shr edx, b1 0x18
         // 00401c9c: mov ss:[ebp+0xffffffffffffffec], esi
         // 00401c9f: mov edx, ds:[0x4713c0+edx*0x4]
         // 00401ca6: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401ca9: shr ebx, b1 0x8
         // 00401cac: movzx esi, b1 bl
         // 00401caf: xor edx, ds:[0x470bc0+esi*0x4]
         // 00401cb6: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401cb9: shr ebx, b1 0x10
         // 00401cbc: movzx esi, b1 bl
         // 00401cbf: xor edx, ds:[0x470fc0+esi*0x4]
         // 00401cc6: movzx esi, b1 ss:[ebp+0xfffffffffffffff4]
         // 00401cca: xor edx, ds:[0x4707c0+esi*0x4]
         // 00401cd1: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401cd4: xor edx, ds:[eax+0x6c]
         // 00401cd7: shr ebx, b1 0x8
         // 00401cda: movzx esi, b1 bl
         // 00401cdd: mov esi, ds:[0x470bc0+esi*0x4]
         // 00401ce4: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401ce7: shr ebx, b1 0x10
         // 00401cea: movzx ebx, b1 bl
         // 00401ced: xor esi, ds:[0x470fc0+ebx*0x4]
         // 00401cf4: mov ebx, ecx
         // 00401cf6: shr ebx, b1 0x18
         // 00401cf9: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00401d00: movzx ebx, b1 dl
         // 00401d03: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00401d0a: mov ebx, edx
         // 00401d0c: xor esi, ds:[eax+0x70]
         // 00401d0f: shr ebx, b1 0x8
         // 00401d12: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00401d15: movzx esi, b1 bl
         // 00401d18: mov esi, ds:[0x470bc0+esi*0x4]
         // 00401d1f: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401d22: shr ebx, b1 0x10
         // 00401d25: movzx ebx, b1 bl
         // 00401d28: xor esi, ds:[0x470fc0+ebx*0x4]
         // 00401d2f: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401d32: shr ebx, b1 0x18
         // 00401d35: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00401d3c: movzx ebx, b1 cl
         // 00401d3f: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00401d46: mov ebx, edx
         // 00401d48: xor esi, ds:[eax+0x74]
         // 00401d4b: shr ebx, b1 0x10
         // 00401d4e: mov ss:[ebp+0xfffffffffffffff8], esi
         // 00401d51: movzx esi, b1 bl
         // 00401d54: mov esi, ds:[0x470fc0+esi*0x4]
         // 00401d5b: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401d5e: shr ebx, b1 0x18
         // 00401d61: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00401d68: mov ebx, ecx
         // 00401d6a: mov ss:[ebp+0xffffffffffffffe8], esi
         // 00401d6d: shr ebx, b1 0x8
         // 00401d70: movzx esi, b1 bl
         // 00401d73: mov esi, ds:[0x470bc0+esi*0x4]
         // 00401d7a: xor ss:[ebp+0xffffffffffffffe8], esi
         // 00401d7d: movzx ebx, b1 ss:[ebp+0xfffffffffffffff0]
         // 00401d81: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 00401d84: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00401d8b: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401d8e: xor esi, ds:[eax+0x78]
         // 00401d91: shr edx, b1 0x18
         // 00401d94: mov edx, ds:[0x4713c0+edx*0x4]
         // 00401d9b: shr ebx, b1 0x8
         // 00401d9e: shr ecx, b1 0x10
         // 00401da1: mov ss:[ebp+0xfffffffffffffff4], esi
         // 00401da4: movzx esi, b1 bl
         // 00401da7: xor edx, ds:[0x470bc0+esi*0x4]
         // 00401dae: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401db1: movzx ecx, b1 cl
         // 00401db4: xor edx, ds:[0x470fc0+ecx*0x4]
         // 00401dbb: movzx ecx, b1 ss:[ebp+0xffffffffffffffec]
         // 00401dbf: xor edx, ds:[0x4707c0+ecx*0x4]
         // 00401dc6: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401dc9: xor edx, ds:[eax+0x7c]
         // 00401dcc: shr ecx, b1 0x8
         // 00401dcf: movzx ecx, b1 cl
         // 00401dd2: mov ecx, ds:[0x470bc0+ecx*0x4]
         // 00401dd9: shr ebx, b1 0x10
         // 00401ddc: movzx esi, b1 bl
         // 00401ddf: xor ecx, ds:[0x470fc0+esi*0x4]
         // 00401de6: mov esi, ss:[ebp+0xfffffffffffffffc]
         // 00401de9: shr esi, b1 0x18
         // 00401dec: xor ecx, ds:[0x4713c0+esi*0x4]
         // 00401df3: movzx esi, b1 dl
         // 00401df6: xor ecx, ds:[0x4707c0+esi*0x4]
         // 00401dfd: mov ebx, edx
         // 00401dff: shr ebx, b1 0x8
         // 00401e02: movzx esi, b1 bl
         // 00401e05: mov esi, ds:[0x470bc0+esi*0x4]
         // 00401e0c: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 00401e0f: shr ebx, b1 0x10
         // 00401e12: movzx ebx, b1 bl
         // 00401e15: xor esi, ds:[0x470fc0+ebx*0x4]
         // 00401e1c: movzx ebx, b1 ss:[ebp+0xfffffffffffffffc]
         // 00401e20: mov ss:[ebp+0xffffffffffffffe8], esi
         // 00401e23: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00401e26: shr esi, b1 0x18
         // 00401e29: mov esi, ds:[0x4713c0+esi*0x4]
         // 00401e30: xor ss:[ebp+0xffffffffffffffe8], esi
         // 00401e33: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 00401e36: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00401e3d: mov ebx, edx
         // 00401e3f: xor esi, ds:[eax+0x84]
         // 00401e45: shr ebx, b1 0x10
         // 00401e48: mov ss:[ebp+0xfffffffffffffff0], esi
         // 00401e4b: movzx esi, b1 bl
         // 00401e4e: mov esi, ds:[0x470fc0+esi*0x4]
         // 00401e55: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 00401e58: shr ebx, b1 0x18
         // 00401e5b: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00401e62: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401e65: shr ebx, b1 0x8
         // 00401e68: mov ss:[ebp+0xffffffffffffffe8], esi
         // 00401e6b: movzx esi, b1 bl
         // 00401e6e: mov esi, ds:[0x470bc0+esi*0x4]
         // 00401e75: xor ss:[ebp+0xffffffffffffffe8], esi
         // 00401e78: movzx ebx, b1 ss:[ebp+0xfffffffffffffff8]
         // 00401e7c: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 00401e7f: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00401e86: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401e89: xor esi, ds:[eax+0x88]
         // 00401e8f: shr ebx, b1 0x8
         // 00401e92: mov ss:[ebp+0xffffffffffffffec], esi
         // 00401e95: movzx esi, b1 bl
         // 00401e98: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401e9b: shr ebx, b1 0x10
         // 00401e9e: xor ecx, ds:[eax+0x80]
         // 00401ea4: shr edx, b1 0x18
         // 00401ea7: mov edx, ds:[0x4713c0+edx*0x4]
         // 00401eae: xor edx, ds:[0x470bc0+esi*0x4]
         // 00401eb5: movzx esi, b1 bl
         // 00401eb8: xor edx, ds:[0x470fc0+esi*0x4]
         // 00401ebf: movzx esi, b1 ss:[ebp+0xfffffffffffffff4]
         // 00401ec3: xor edx, ds:[0x4707c0+esi*0x4]
         // 00401eca: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401ecd: xor edx, ds:[eax+0x8c]
         // 00401ed3: shr ebx, b1 0x8
         // 00401ed6: movzx esi, b1 bl
         // 00401ed9: mov esi, ds:[0x470bc0+esi*0x4]
         // 00401ee0: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401ee3: shr ebx, b1 0x10
         // 00401ee6: movzx ebx, b1 bl
         // 00401ee9: xor esi, ds:[0x470fc0+ebx*0x4]
         // 00401ef0: mov ebx, ecx
         // 00401ef2: shr ebx, b1 0x18
         // 00401ef5: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00401efc: movzx ebx, b1 dl
         // 00401eff: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00401f06: add eax, 0x90
         // 00401f0b: xor esi, ds:[eax]
         // 00401f0d: mov ebx, edx
         // 00401f0f: shr ebx, b1 0x8
         // 00401f12: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00401f15: movzx esi, b1 bl
         // 00401f18: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401f1b: mov esi, ds:[0x470bc0+esi*0x4]
         // 00401f22: shr ebx, b1 0x10
         // 00401f25: movzx ebx, b1 bl
         // 00401f28: xor esi, ds:[0x470fc0+ebx*0x4]
         // 00401f2f: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401f32: shr ebx, b1 0x18
         // 00401f35: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00401f3c: movzx ebx, b1 cl
         // 00401f3f: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00401f46: mov ebx, edx
         // 00401f48: xor esi, ds:[eax+0x4]
         // 00401f4b: shr ebx, b1 0x10
         // 00401f4e: mov ss:[ebp+0xfffffffffffffff8], esi
         // 00401f51: movzx esi, b1 bl
         // 00401f54: mov esi, ds:[0x470fc0+esi*0x4]
         // 00401f5b: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401f5e: shr ebx, b1 0x18
         // 00401f61: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00401f68: mov ebx, ecx
         // 00401f6a: mov ss:[ebp+0xffffffffffffffe8], esi
         // 00401f6d: shr ebx, b1 0x8
         // 00401f70: movzx esi, b1 bl
         // 00401f73: mov esi, ds:[0x470bc0+esi*0x4]
         // 00401f7a: xor ss:[ebp+0xffffffffffffffe8], esi
         // 00401f7d: movzx ebx, b1 ss:[ebp+0xfffffffffffffff0]
         // 00401f81: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 00401f84: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00401f8b: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401f8e: xor esi, ds:[eax+0x8]
         // 00401f91: shr edx, b1 0x18
         // 00401f94: mov edx, ds:[0x4713c0+edx*0x4]
         // 00401f9b: shr ebx, b1 0x8
         // 00401f9e: shr ecx, b1 0x10
         // 00401fa1: mov ss:[ebp+0xfffffffffffffff4], esi
         // 00401fa4: movzx esi, b1 bl
         // 00401fa7: xor edx, ds:[0x470bc0+esi*0x4]
         // 00401fae: movzx ecx, b1 cl
         // 00401fb1: xor edx, ds:[0x470fc0+ecx*0x4]
         // 00401fb8: movzx ecx, b1 ss:[ebp+0xffffffffffffffec]
         // 00401fbc: xor edx, ds:[0x4707c0+ecx*0x4]
         // 00401fc3: mov ecx, ss:[ebp+0x8]
         // 00401fc6: mov ecx, ds:[ecx+0x200]
         // 00401fcc: xor edx, ds:[eax+0xc]
         // 00401fcf: mov ss:[ebp+0xffffffffffffffe4], ecx
         // 00401fd2: cmp ecx, 0xa
         // 00401fd5: jle 0x4021dd
      [-]8b4df48b5df8c1eb10c1e9080fb6f30fb6c98b0c8d????????330cb5????????8b75fcc1ee18330cb5????????0fb6f2330cb5????????8bdac1eb080fb6f38b34b5????????8b5df4c1eb100fb6db33349d????????0fb65dfc8975088b75f8c1ee188b34b5????????3175088b750833349d????????3348103370148bda8975f0c1eb100fb6f38b34b5????????8b5df4c1eb1833349d????????8b5dfc897508c1eb080fb6f38b34b5????????3175080fb675f88b5d08331cb5????????c1ea188b3495????????8b55fc335818894dec8b4df8c1ea10c1e9080fb6d20fb6c933348d????????8b4df0333495????????0fb655f4333495????????8bd333701cc1ea080fb6d28b1495????????8975e8c1e9100fb6f13314b5????????8b4dec8bf1c1ee183314b5????????0fb675e83314b5????????83c02033108955fc8b55e8c1ea080fb6d28b1495????????895d08c1eb100fb6f33314b5????????8b75f08b5d08c1ee183314b5????????0fb6f13314b5????????8bf3335004c1ee188955f88b55e8c1ea100fb6d28b1495????????3314b5????????895dec8bd9c1eb080fb6f33314b5????????0fb675f03314b5????????8b5dec335008c1e9108955f48b55e8c1ea188bf28b55f08b34b5????????c1ea080fb6d2333495????????0fb6c933348d????????8b4de40fb6d3333495????????33700c8bd6
         // 00401fdb: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401fde: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401fe1: shr ebx, b1 0x10
         // 00401fe4: shr ecx, b1 0x8
         // 00401fe7: movzx esi, b1 bl
         // 00401fea: movzx ecx, b1 cl
         // 00401fed: mov ecx, ds:[0x470bc0+ecx*0x4]
         // 00401ff4: xor ecx, ds:[0x470fc0+esi*0x4]
         // 00401ffb: mov esi, ss:[ebp+0xfffffffffffffffc]
         // 00401ffe: shr esi, b1 0x18
         // 00402001: xor ecx, ds:[0x4713c0+esi*0x4]
         // 00402008: movzx esi, b1 dl
         // 0040200b: xor ecx, ds:[0x4707c0+esi*0x4]
         // 00402012: mov ebx, edx
         // 00402014: shr ebx, b1 0x8
         // 00402017: movzx esi, b1 bl
         // 0040201a: mov esi, ds:[0x470bc0+esi*0x4]
         // 00402021: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 00402024: shr ebx, b1 0x10
         // 00402027: movzx ebx, b1 bl
         // 0040202a: xor esi, ds:[0x470fc0+ebx*0x4]
         // 00402031: movzx ebx, b1 ss:[ebp+0xfffffffffffffffc]
         // 00402035: mov ss:[ebp+0x8], esi
         // 00402038: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 0040203b: shr esi, b1 0x18
         // 0040203e: mov esi, ds:[0x4713c0+esi*0x4]
         // 00402045: xor ss:[ebp+0x8], esi
         // 00402048: mov esi, ss:[ebp+0x8]
         // 0040204b: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00402052: xor ecx, ds:[eax+0x10]
         // 00402055: xor esi, ds:[eax+0x14]
         // 00402058: mov ebx, edx
         // 0040205a: mov ss:[ebp+0xfffffffffffffff0], esi
         // 0040205d: shr ebx, b1 0x10
         // 00402060: movzx esi, b1 bl
         // 00402063: mov esi, ds:[0x470fc0+esi*0x4]
         // 0040206a: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 0040206d: shr ebx, b1 0x18
         // 00402070: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00402077: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040207a: mov ss:[ebp+0x8], esi
         // 0040207d: shr ebx, b1 0x8
         // 00402080: movzx esi, b1 bl
         // 00402083: mov esi, ds:[0x470bc0+esi*0x4]
         // 0040208a: xor ss:[ebp+0x8], esi
         // 0040208d: movzx esi, b1 ss:[ebp+0xfffffffffffffff8]
         // 00402091: mov ebx, ss:[ebp+0x8]
         // 00402094: xor ebx, ds:[0x4707c0+esi*0x4]
         // 0040209b: shr edx, b1 0x18
         // 0040209e: mov esi, ds:[0x4713c0+edx*0x4]
         // 004020a5: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 004020a8: xor ebx, ds:[eax+0x18]
         // 004020ab: mov ss:[ebp+0xffffffffffffffec], ecx
         // 004020ae: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 004020b1: shr edx, b1 0x10
         // 004020b4: shr ecx, b1 0x8
         // 004020b7: movzx edx, b1 dl
         // 004020ba: movzx ecx, b1 cl
         // 004020bd: xor esi, ds:[0x470bc0+ecx*0x4]
         // 004020c4: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004020c7: xor esi, ds:[0x470fc0+edx*0x4]
         // 004020ce: movzx edx, b1 ss:[ebp+0xfffffffffffffff4]
         // 004020d2: xor esi, ds:[0x4707c0+edx*0x4]
         // 004020d9: mov edx, ebx
         // 004020db: xor esi, ds:[eax+0x1c]
         // 004020de: shr edx, b1 0x8
         // 004020e1: movzx edx, b1 dl
         // 004020e4: mov edx, ds:[0x470bc0+edx*0x4]
         // 004020eb: mov ss:[ebp+0xffffffffffffffe8], esi
         // 004020ee: shr ecx, b1 0x10
         // 004020f1: movzx esi, b1 cl
         // 004020f4: xor edx, ds:[0x470fc0+esi*0x4]
         // 004020fb: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 004020fe: mov esi, ecx
         // 00402100: shr esi, b1 0x18
         // 00402103: xor edx, ds:[0x4713c0+esi*0x4]
         // 0040210a: movzx esi, b1 ss:[ebp+0xffffffffffffffe8]
         // 0040210e: xor edx, ds:[0x4707c0+esi*0x4]
         // 00402115: add eax, 0x20
         // 00402118: xor edx, ds:[eax]
         // 0040211a: mov ss:[ebp+0xfffffffffffffffc], edx
         // 0040211d: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 00402120: shr edx, b1 0x8
         // 00402123: movzx edx, b1 dl
         // 00402126: mov edx, ds:[0x470bc0+edx*0x4]
         // 0040212d: mov ss:[ebp+0x8], ebx
         // 00402130: shr ebx, b1 0x10
         // 00402133: movzx esi, b1 bl
         // 00402136: xor edx, ds:[0x470fc0+esi*0x4]
         // 0040213d: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00402140: mov ebx, ss:[ebp+0x8]
         // 00402143: shr esi, b1 0x18
         // 00402146: xor edx, ds:[0x4713c0+esi*0x4]
         // 0040214d: movzx esi, b1 cl
         // 00402150: xor edx, ds:[0x4707c0+esi*0x4]
         // 00402157: mov esi, ebx
         // 00402159: xor edx, ds:[eax+0x4]
         // 0040215c: shr esi, b1 0x18
         // 0040215f: mov ss:[ebp+0xfffffffffffffff8], edx
         // 00402162: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 00402165: shr edx, b1 0x10
         // 00402168: movzx edx, b1 dl
         // 0040216b: mov edx, ds:[0x470fc0+edx*0x4]
         // 00402172: xor edx, ds:[0x4713c0+esi*0x4]
         // 00402179: mov ss:[ebp+0xffffffffffffffec], ebx
         // 0040217c: mov ebx, ecx
         // 0040217e: shr ebx, b1 0x8
         // 00402181: movzx esi, b1 bl
         // 00402184: xor edx, ds:[0x470bc0+esi*0x4]
         // 0040218b: movzx esi, b1 ss:[ebp+0xfffffffffffffff0]
         // 0040218f: xor edx, ds:[0x4707c0+esi*0x4]
         // 00402196: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00402199: xor edx, ds:[eax+0x8]
         // 0040219c: shr ecx, b1 0x10
         // 0040219f: mov ss:[ebp+0xfffffffffffffff4], edx
         // 004021a2: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 004021a5: shr edx, b1 0x18
         // 004021a8: mov esi, edx
         // 004021aa: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 004021ad: mov esi, ds:[0x4713c0+esi*0x4]
         // 004021b4: shr edx, b1 0x8
         // 004021b7: movzx edx, b1 dl
         // 004021ba: xor esi, ds:[0x470bc0+edx*0x4]
         // 004021c1: movzx ecx, b1 cl
         // 004021c4: xor esi, ds:[0x470fc0+ecx*0x4]
         // 004021cb: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 004021ce: movzx edx, b1 bl
         // 004021d1: xor esi, ds:[0x4707c0+edx*0x4]
         // 004021d8: xor esi, ds:[eax+0xc]
         // 004021db: mov edx, esi
      [-]83f90c0f8ee9010000
         // 004021dd: cmp ecx, 0xc
         // 004021e0: jle 0x4023cf
      [-]8b4df48b5df8c1eb100fb6f3c1e9080fb6c98b0c8d????????330cb5????????8b75fcc1ee18330cb5????????0fb6f2330cb5????????8bdac1eb080fb6f38b34b5????????8b5df4c1eb100fb6db33349d????????0fb65dfc8975088b75f8c1ee188b34b5????????3175088b750833349d????????8bda337014c1eb108975f00fb6f38b34b5????????8b5df4c1eb1833349d????????8b5dfcc1eb088975080fb6f38b34b5????????3175080fb65df88b750833349d????????8b5df8337018c1eb083348108975ec0fb6f38b5dfcc1eb10c1ea188b1495????????3314b5????????0fb6f33314b5????????0fb675f43314b5????????8b5dec33501cc1eb080fb6f38b5df08b34b5????????c1eb100fb6db33349d????????8bd9c1eb1833349d????????0fb6da33349d????????83c02033308bda8975fcc1eb080fb6f38b34b5????????8b5decc1eb100fb6db33349d????????8b5df0c1eb1833349d????????0fb6d933349d????????8bda337004c1eb108975f80fb6f38b34b5????????8b5decc1eb1833349d????????8bd9c1eb080fb6db33349d????????0fb65df033349d????
         // 004021e6: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 004021e9: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 004021ec: shr ebx, b1 0x10
         // 004021ef: movzx esi, b1 bl
         // 004021f2: shr ecx, b1 0x8
         // 004021f5: movzx ecx, b1 cl
         // 004021f8: mov ecx, ds:[0x470bc0+ecx*0x4]
         // 004021ff: xor ecx, ds:[0x470fc0+esi*0x4]
         // 00402206: mov esi, ss:[ebp+0xfffffffffffffffc]
         // 00402209: shr esi, b1 0x18
         // 0040220c: xor ecx, ds:[0x4713c0+esi*0x4]
         // 00402213: movzx esi, b1 dl
         // 00402216: xor ecx, ds:[0x4707c0+esi*0x4]
         // 0040221d: mov ebx, edx
         // 0040221f: shr ebx, b1 0x8
         // 00402222: movzx esi, b1 bl
         // 00402225: mov esi, ds:[0x470bc0+esi*0x4]
         // 0040222c: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 0040222f: shr ebx, b1 0x10
         // 00402232: movzx ebx, b1 bl
         // 00402235: xor esi, ds:[0x470fc0+ebx*0x4]
         // 0040223c: movzx ebx, b1 ss:[ebp+0xfffffffffffffffc]
         // 00402240: mov ss:[ebp+0x8], esi
         // 00402243: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00402246: shr esi, b1 0x18
         // 00402249: mov esi, ds:[0x4713c0+esi*0x4]
         // 00402250: xor ss:[ebp+0x8], esi
         // 00402253: mov esi, ss:[ebp+0x8]
         // 00402256: xor esi, ds:[0x4707c0+ebx*0x4]
         // 0040225d: mov ebx, edx
         // 0040225f: xor esi, ds:[eax+0x14]
         // 00402262: shr ebx, b1 0x10
         // 00402265: mov ss:[ebp+0xfffffffffffffff0], esi
         // 00402268: movzx esi, b1 bl
         // 0040226b: mov esi, ds:[0x470fc0+esi*0x4]
         // 00402272: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 00402275: shr ebx, b1 0x18
         // 00402278: xor esi, ds:[0x4713c0+ebx*0x4]
         // 0040227f: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00402282: shr ebx, b1 0x8
         // 00402285: mov ss:[ebp+0x8], esi
         // 00402288: movzx esi, b1 bl
         // 0040228b: mov esi, ds:[0x470bc0+esi*0x4]
         // 00402292: xor ss:[ebp+0x8], esi
         // 00402295: movzx ebx, b1 ss:[ebp+0xfffffffffffffff8]
         // 00402299: mov esi, ss:[ebp+0x8]
         // 0040229c: xor esi, ds:[0x4707c0+ebx*0x4]
         // 004022a3: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 004022a6: xor esi, ds:[eax+0x18]
         // 004022a9: shr ebx, b1 0x8
         // 004022ac: xor ecx, ds:[eax+0x10]
         // 004022af: mov ss:[ebp+0xffffffffffffffec], esi
         // 004022b2: movzx esi, b1 bl
         // 004022b5: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 004022b8: shr ebx, b1 0x10
         // 004022bb: shr edx, b1 0x18
         // 004022be: mov edx, ds:[0x4713c0+edx*0x4]
         // 004022c5: xor edx, ds:[0x470bc0+esi*0x4]
         // 004022cc: movzx esi, b1 bl
         // 004022cf: xor edx, ds:[0x470fc0+esi*0x4]
         // 004022d6: movzx esi, b1 ss:[ebp+0xfffffffffffffff4]
         // 004022da: xor edx, ds:[0x4707c0+esi*0x4]
         // 004022e1: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 004022e4: xor edx, ds:[eax+0x1c]
         // 004022e7: shr ebx, b1 0x8
         // 004022ea: movzx esi, b1 bl
         // 004022ed: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 004022f0: mov esi, ds:[0x470bc0+esi*0x4]
         // 004022f7: shr ebx, b1 0x10
         // 004022fa: movzx ebx, b1 bl
         // 004022fd: xor esi, ds:[0x470fc0+ebx*0x4]
         // 00402304: mov ebx, ecx
         // 00402306: shr ebx, b1 0x18
         // 00402309: xor esi, ds:[0x4713c0+ebx*0x4]
         // 00402310: movzx ebx, b1 dl
         // 00402313: xor esi, ds:[0x4707c0+ebx*0x4]
         // 0040231a: add eax, 0x20
         // 0040231d: xor esi, ds:[eax]
         // 0040231f: mov ebx, edx
         // 00402321: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00402324: shr ebx, b1 0x8
         // 00402327: movzx esi, b1 bl
         // 0040232a: mov esi, ds:[0x470bc0+esi*0x4]
         // 00402331: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00402334: shr ebx, b1 0x10
         // 00402337: movzx ebx, b1 bl
         // 0040233a: xor esi, ds:[0x470fc0+ebx*0x4]
         // 00402341: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00402344: shr ebx, b1 0x18
         // 00402347: xor esi, ds:[0x4713c0+ebx*0x4]
         // 0040234e: movzx ebx, b1 cl
         // 00402351: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00402358: mov ebx, edx
         // 0040235a: xor esi, ds:[eax+0x4]
         // 0040235d: shr ebx, b1 0x10
         // 00402360: mov ss:[ebp+0xfffffffffffffff8], esi
         // 00402363: movzx esi, b1 bl
         // 00402366: mov esi, ds:[0x470fc0+esi*0x4]
         // 0040236d: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00402370: shr ebx, b1 0x18
         // 00402373: xor esi, ds:[0x4713c0+ebx*0x4]
         // 0040237a: mov ebx, ecx
         // 0040237c: shr ebx, b1 0x8
         // 0040237f: movzx ebx, b1 bl
         // 00402382: xor esi, ds:[0x470bc0+ebx*0x4]
         // 00402389: movzx ebx, b1 ss:[ebp+0xfffffffffffffff0]
         // 0040238d: xor esi, ds:[0x4707c0+ebx*0x4]
         // 00402394: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00402397: xor esi, ds:[eax+0x8]
         // 0040239a: shr edx, b1 0x18
         // 0040239d: mov edx, ds:[0x4713c0+edx*0x4]
         // 004023a4: shr ebx, b1 0x8
         // 004023a7: mov ss:[ebp+0xfffffffffffffff4], esi
         // 004023aa: shr ecx, b1 0x10
         // 004023ad: movzx esi, b1 bl
         // 004023b0: xor edx, ds:[0x470bc0+esi*0x4]
         // 004023b7: movzx ecx, b1 cl
         // 004023ba: xor edx, ds:[0x470fc0+ecx*0x4]
         // 004023c1: movzx ecx, b1 ss:[ebp+0xffffffffffffffec]
         // 004023c5: xor edx, ds:[0x4707c0+ecx*0x4]
         // 004023cc: xor edx, ds:[eax+0xc]

  }
  condition:
    all of them
}
