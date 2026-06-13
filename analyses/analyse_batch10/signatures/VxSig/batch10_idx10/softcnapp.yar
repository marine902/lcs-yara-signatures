rule softcnapp_10_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         3bf37318
         // 004154be: cmp esi, ebx
         // 004154c0: jnb 0x4154da
      [-]ffffffd7
         // 00416780: call edi
      [-]83c6043bf372ea
         // 00544a29: add esi, 0x4
         // 00544a2c: cmp esi, ebx
         // 00544a2e: jb 0x544a1a
      [-]3bf37318
         // 004154e9: cmp esi, ebx
         // 004154eb: jnb 0x415505
      [-]ffffffd7
         // 004167ab: call edi
      [-]83c6043bf372ea
         // 00544a54: add esi, 0x4
         // 00544a57: cmp esi, ebx
         // 00544a59: jb 0x544a45
      [-]558bec56
         // 0051a330: push ebp
         // 0051a331: mov ebp, esp
         // 0051a333: push esi
      [-]558bec8b5508
         // 00546c70: push ebp
         // 00546c71: mov ebp, esp
         // 00546c73: mov edx, ss:[ebp+0x8]
      [-]8b48180b481c8b30752f
         // 00546c87: mov ecx, ds:[eax+0x18]
         // 00546c8a: or ecx, ds:[eax+0x1c]
         // 00546c8d: mov esi, ds:[eax]
         // 00546c8f: jnz 0x546cc0
      [-]3bd80f44de3bf87513
         // 00546c91: cmp ebx, eax
         // 00546c93: cmovz ebx, esi
         // 00546c96: cmp edi, eax
         // 00546c98: jnz 0x546cad
      [-]00008b550883c404ff4a0ceb
         // 0053de85: mov edx, ss:[ebp+0x8]
         // 0053de88: add esp, 0x4
         // 0053de8b: dec ds:[edx+0xc]
         // 0053de8e: jmp 0x53de92
      [-]5e891a5b
         // 00546cc8: pop esi
         // 00546cc9: mov ds:[edx], ebx
         // 00546ccb: pop ebx
      [-]558bec568b750883be
         // 005470f0: push ebp
         // 005470f1: mov ebp, esp
         // 005470f3: push esi
         // 005470f4: mov esi, ss:[ebp+0x8]
         // 005470f7: cmp ds:[esi+0x348], 0x0
      [-]ffffff83c404
         // 0054710f: add esp, 0x4
      [-]6a026a0256e8
         // 00417ce2: push 0x2
         // 00417ce4: push 0x2
         // 00417ce6: push esi
         // 00417ce7: call 0x4246a0
      [-]e88300000083c414
         // 00417cf8: call 0x417d80
         // 00417cfd: add esp, 0x14
      [-]837d0c00741d
         // 00547147: cmp ss:[ebp+0xc], 0x0
         // 0054714b: jz 0x54716a
      [-]ffff83c404c786
         // 0053e33d: add esp, 0x4
         // 0053e340: mov ds:[esi+0x410], 0x0
      [-]6a026a0256e8
         // 00417d3a: push 0x2
         // 00417d3c: push 0x2
         // 00417d3e: push esi
         // 00417d3f: call 0x4246a0
      [-]837d0c007420
         // 00547177: cmp ss:[ebp+0xc], 0x0
         // 0054717b: jz 0x54719d
      [-]faffff83c404
         // 0053e37a: add esp, 0x4
      [-]6a0256e8
         // 00417d6d: push 0x2
         // 00417d6f: push esi
         // 00417d70: call 0x4246e0
      [-]83c4085e5dc3
         // 00417d75: add esp, 0x8
         // 00417d78: pop esi
         // 00417d79: pop ebp
         // 00417d7a: retn 
      [-]558bec51568b7508
         // 00416ad0: push ebp
         // 00416ad1: mov ebp, esp
         // 00416ad3: push ecx
         // 00416ad4: push esi
         // 00416ad5: mov esi, ss:[ebp+0x8]
      [-]837e0c000f84
         // 005471c7: cmp ds:[esi+0xc], 0x0
         // 005471cb: jz 0x547291
      [-]8b3683c408
         // 004cef11: mov esi, ds:[esi]
         // 004cef13: add esp, 0x8
      [-]5e8be55dc3
         // 00416b83: pop esi
         // 00416b84: mov esp, ebp
         // 00416b86: pop ebp
         // 00416b87: retn 
      [-]5e8be55dc3
         // 00416bac: pop esi
         // 00416bad: mov esp, ebp
         // 00416baf: pop ebp
         // 00416bb0: retn 
      [-]5e8be55dc3
         // 00547293: pop esi
         // 00547294: mov esp, ebp
         // 00547296: pop ebp
         // 00547297: retn 
      [-]558bec8b5508b9
         // 0051a6a0: push ebp
         // 0051a6a1: mov ebp, esp
         // 0051a6a3: mov edx, ss:[ebp+0x8]
         // 0051a6a6: mov ecx, 0x55d6a5
      [-]5356578b4208bf
         // 0051a6ab: push ebx
         // 0051a6ac: push esi
         // 0051a6ad: push edi
         // 0051a6ae: mov eax, ds:[edx+0x8]
         // 0051a6b1: mov edi, 0x55d3f0
      [-]0f45c88b420c
         // 0051a6bd: cmovnz ecx, eax
         // 0051a6c0: mov eax, ds:[edx+0xc]
      [-]0f45f88b42
         // 0051a6c5: cmovnz edi, eax
         // 0051a6c8: mov eax, ds:[edx+0x10]
      [-]80382ebe
         // 00416cda: cmp b1 ds:[eax], b1 0x2e
         // 00416cdd: mov esi, 0x45a5e0
      [-]560f44c15068
         // 00417ef3: push esi
         // 00417ef4: cmovz eax, ecx
         // 00417ef7: push eax
         // 00417ef8: push 0x45b5d4
      [-]83c42c5f5e5b5dc3
         // 00417f02: add esp, 0x2c
         // 00417f05: pop edi
         // 00417f06: pop esi
         // 00417f07: pop ebx
         // 00417f08: pop ebp
         // 00417f09: retn 
      [-]558bec83ec
         // 004185c0: push ebp
         // 004185c1: mov ebp, esp
         // 004185c3: sub esp, 0x50
      [-]0033c58945fc8b4514538b5d10568b750c578b7d088945
         // 004185cb: xor eax, ebp
         // 004185cd: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004185d0: mov eax, ss:[ebp+0x14]
         // 004185d3: push ebx
         // 004185d4: mov ebx, ss:[ebp+0x10]
         // 004185d7: push esi
         // 004185d8: mov esi, ss:[ebp+0xc]
         // 004185db: push edi
         // 004185dc: mov edi, ss:[ebp+0x8]
         // 004185df: mov ss:[ebp+0xffffffffffffffd4], eax
      [-]c700????????8d45
         // 004185e2: mov ds:[eax], 0x0
         // 004185e8: lea eax, ss:[ebp+0xffffffffffffffd8]
      [-]50566a02e8
         // 004185eb: push eax
         // 004185ec: push esi
         // 004185ed: push 0x2
         // 004185ef: call 0x4270a0
      [-]83c40c53
         // 004185f4: add esp, 0xc
         // 004185f7: push ebx
      [-]506a02e8
         // 0051bc40: push eax
         // 0051bc41: push 0x2
         // 0051bc43: call 0x527af0
      [-]83c4105f5e5b8b4dfc33cde8
         // 0051bc48: add esp, 0x10
         // 0051bc4b: pop edi
         // 0051bc4c: pop esi
         // 0051bc4d: pop ebx
         // 0051bc4e: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0051bc51: xor ecx, ebp
         // 0051bc53: call @__security_check_cookie@4
      [-]8be55dc3
         // 0051bc58: mov esp, ebp
         // 0051bc5a: pop ebp
         // 0051bc5b: retn 
      [-]0f57c00f1145
         // 0051bc5f: xorps b16 xmm0, b16 xmm0
         // 0051bc62: movups b16 ss:[ebp+0xffffffffffffffb0], b16 xmm0
      [-]500f1145
         // 0051bc73: push eax
         // 0051bc74: movups b16 ss:[ebp+0xffffffffffffffc0], b16 xmm0
      [-]50535657e8
         // 0051bc87: push eax
         // 0051bc88: push ebx
         // 0051bc89: push esi
         // 0051bc8a: push edi
         // 0051bc8b: call 0x51c090
      [-]04000083c420
         // 0051bc90: add esp, 0x20
      [-]5f5e5bc700????????
         // 004173aa: pop edi
         // 004173ab: pop esi
         // 004173ac: pop ebx
         // 004173ad: mov ds:[eax], 0x1
      [-]8b4dfc33cde8
         // 004173b5: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004173b8: xor ecx, ebp
         // 004173ba: call @__security_check_cookie@4
      [-]8be55dc3
         // 004173bf: mov esp, ebp
         // 004173c1: pop ebp
         // 004173c2: retn 
      [-]50535668
         // 004cf797: push eax
         // 004cf798: push ebx
         // 004cf799: push esi
         // 004cf79a: push 0x669b18
      [-]5f5e5b8b4dfc33cde8
         // 004cf7ab: pop edi
         // 004cf7ac: pop esi
         // 004cf7ad: pop ebx
         // 004cf7ae: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004cf7b1: xor ecx, ebp
         // 004cf7b3: call @__security_check_cookie@4
      [-]8be55dc3
         // 004cf7b8: mov esp, ebp
         // 004cf7ba: pop ebp
         // 004cf7bb: retn 
      [-]8b4dfc8b45
         // 0053a269: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0053a26c: mov eax, ss:[ebp+0xffffffffffffffd0]
      [-]33cd5f5e5be8
         // 0053a26f: xor ecx, ebp
         // 0053a271: pop edi
         // 0053a272: pop esi
         // 0053a273: pop ebx
         // 0053a274: call @__security_check_cookie@4
      [-]8be55dc3
         // 0053a279: mov esp, ebp
         // 0053a27b: pop ebp
         // 0053a27c: retn 
      [-]558bec538b5d08578b038bbb
         // 00417470: push ebp
         // 00417471: mov ebp, esp
         // 00417473: push ebx
         // 00417474: mov ebx, ss:[ebp+0x8]
         // 00417477: push edi
         // 00417478: mov eax, ds:[ebx]
         // 0041747a: mov edi, ds:[ebx+0x3bc]
      [-]8945088b450cc700????????
         // 00417480: mov ss:[ebp+0x8], eax
         // 00417483: mov eax, ss:[ebp+0xc]
         // 00417486: mov ds:[eax], 0x0
      [-]8b4508ffb0
         // 0051bddc: mov eax, ss:[ebp+0x8]
         // 0051bddf: push ds:[eax+0x4b4]
      [-]0f48d08b47
         // 0051be00: cmovs edx, eax
         // 0051be03: mov eax, ds:[edi+0x8]
      [-]518d04118947
         // 00417540: push ecx
         // 00417541: lea eax, ds:[ecx+edx]
         // 00417544: mov ds:[edi+0xc], eax
      [-]5f5b5dc3
         // 00417553: pop edi
         // 00417554: pop ebx
         // 00417555: pop ebp
         // 00417556: retn 
      [-]558bec568b750857
         // 0051af30: push ebp
         // 0051af31: mov ebp, esp
         // 0051af33: push esi
         // 0051af34: mov esi, ss:[ebp+0x8]
         // 0051af37: push edi
      [-]56e85e01000083c404
         // 00547c5c: push esi
         // 00547c5d: call 0x547dc0
         // 00547c62: add esp, 0x4
      [-]00000083c404
         // 004175e3: add esp, 0x4
      [-]5f5e5dc3
         // 00547cdb: pop edi
         // 00547cdc: pop esi
         // 00547cdd: pop ebp
         // 00547cde: retn 
      [-]558bec8b45088b80
         // 00417600: push ebp
         // 00417601: mov ebp, esp
         // 00417603: mov eax, ss:[ebp+0x8]
         // 00417606: mov eax, ds:[eax+0x3bc]
      [-]558bec568b75088b06
         // 00547d70: push ebp
         // 00547d71: mov ebp, esp
         // 00547d73: push esi
         // 00547d74: mov esi, ss:[ebp+0x8]
         // 00547d77: mov eax, ds:[esi]
      [-]ff36ff15
         // 00418954: push ds:[esi]
         // 00418956: call ds:[0x5ffb38]
      [-]6a0056e8
         // 00418982: push 0x0
         // 00418984: push esi
         // 00418985: call _memset
      [-]83c40c5e5dc3
         // 0041898a: add esp, 0xc
         // 0041898d: pop esi
         // 0041898e: pop ebp
         // 0041898f: retn 
      [-]558bec8b4d085651e8
         // 0051b0b0: push ebp
         // 0051b0b1: mov ebp, esp
         // 0051b0b3: mov ecx, ss:[ebp+0x8]
         // 0051b0b6: push esi
         // 0051b0b7: push ecx
         // 0051b0b8: call 0x51afd0
      [-]ff7614ff761051e8
         // 0051b0bf: push ds:[esi+0x14]
         // 0051b0c2: push ds:[esi+0x10]
         // 0051b0c5: push ecx
         // 0051b0c6: call 0x527830
      [-]000083c410c746????????005e5dc3
         // 0051b0cb: add esp, 0x10
         // 0051b0ce: mov ds:[esi+0x14], 0x0
         // 0051b0d5: pop esi
         // 0051b0d6: pop ebp
         // 0051b0d7: retn 
      [-]558bec5356576a486a01ff15
         // 004cfb40: push ebp
         // 004cfb41: mov ebp, esp
         // 004cfb43: push ebx
         // 004cfb44: push esi
         // 004cfb45: push edi
         // 004cfb46: push 0x48
         // 004cfb48: push 0x1
         // 004cfb4a: call ds:[0x7043a4]
      [-]ff75148b4d10
         // 00547eab: push ss:[ebp+0x14]
         // 00547eae: mov ecx, ss:[ebp+0x10]
      [-]51ff750c898e
         // 00547eb4: push ecx
         // 00547eb5: push ss:[ebp+0xc]
         // 00547eb8: mov ds:[esi+0x3ac], ecx
      [-]07????????e8
         // 00547eea: call 0x547f90
      [-]00000083c410
         // 00547eef: add esp, 0x10
      [-]83c4088907
         // 00418b1c: add esp, 0x8
         // 00418b1f: mov ds:[edi], eax
      [-]fdffff83c40453ff15
         // 00547f68: add esp, 0x4
         // 00547f6b: push ebx
         // 00547f6c: call ds:[SetLastError]
      [-]558bec568b75086a
         // 00547f90: push ebp
         // 00547f91: mov ebp, esp
         // 00547f93: push esi
         // 00547f94: mov esi, ss:[ebp+0x8]
         // 00547f97: push 0x38
      [-]83c41089
         // 00547faf: add esp, 0x10
         // 00547fb2: mov ds:[esi], eax
      [-]ff750cc7
         // 00547fbf: push ss:[ebp+0xc]
         // 00547fc2: mov ds:[esi+0x10], 0x0
      [-]83c40489
         // 00547fcf: add esp, 0x4
         // 00547fd2: mov ds:[esi+0x8], eax
      [-]fdffff83c404
         // 00417907: add esp, 0x4
      [-]558bec57ff7514ff7510e8
         // 00418bf0: push ebp
         // 00418bf1: mov ebp, esp
         // 00418bf3: push edi
         // 00418bf4: push ss:[ebp+0x14]
         // 00418bf7: push ss:[ebp+0x10]
         // 00418bfa: call 0x419020
      [-]8a064684c075f9
         // 00548041: mov b1 al, b1 ds:[esi]
         // 00548043: inc esi
         // 00548044: test b1 al, b1 al
         // 00548046: jnz 0x548041
      [-]536a186a012bf1ff15
         // 00418c18: push ebx
         // 00418c19: push 0x18
         // 00418c1b: push 0x1
         // 00418c1d: sub esi, ecx
         // 00418c1f: call ds:[0x5ffb44]
      [-]5b5e5f5dc3
         // 00418c3a: pop ebx
         // 00418c3b: pop esi
         // 00418c3c: pop edi
         // 00418c3d: pop ebp
         // 00418c3e: retn 
      [-]8b450c89038d430850c743
         // 0053a7cf: mov eax, ss:[ebp+0xc]
         // 0053a7d2: mov ds:[ebx], eax
         // 0053a7d4: lea eax, ds:[ebx+0x8]
         // 0053a7d7: push eax
         // 0053a7d8: mov ds:[ebx+0x10], 0x0
      [-]8b430883c4040b430c750a
         // 0053a7e4: mov eax, ds:[ebx+0x8]
         // 0053a7e7: add esp, 0x4
         // 0053a7ea: or eax, ds:[ebx+0xc]
         // 0053a7ed: jnz 0x53a7f9
      [-]c74308????????89430c
         // 0054808f: mov ds:[ebx+0x8], 0x1
         // 00548096: mov ds:[ebx+0xc], eax
      [-]538d4601508b450857ff
         // 00548099: push ebx
         // 0054809a: lea eax, ds:[esi+0x1]
         // 0054809d: push eax
         // 0054809e: mov eax, ss:[ebp+0x8]
         // 005480a1: push edi
         // 005480a2: push ds:[eax]
      [-]ff461057ff15
         // 00418c9a: inc ds:[esi+0x10]
         // 00418c9d: push edi
         // 00418c9e: call ds:[0x5ffb38]
      [-]5b5e5f5dc3
         // 00418ca9: pop ebx
         // 00418caa: pop esi
         // 00418cab: pop edi
         // 00418cac: pop ebp
         // 00418cad: retn 
      [-]0f44c8890d
         // 00418d17: cmovz ecx, eax
         // 00418d1a: mov ds:[0x6009b0], ecx
      [-]0f45c1c3
         // 00418d29: cmovnz eax, ecx
         // 00418d2c: retn 
      [-]558bec83ec08568b750883be
         // 00548130: push ebp
         // 00548131: mov ebp, esp
         // 00548133: sub esp, 0x8
         // 00548136: push esi
         // 00548137: mov esi, ss:[ebp+0x8]
         // 0054813a: cmp ds:[esi+0x264], 0xffffffffffffffff
      [-]6a026a0356e8
         // 00418d4e: push 0x2
         // 00418d50: push 0x3
         // 00418d52: push esi
         // 00418d53: call 0x4246a0
      [-]8d45f850e8
         // 0051c39b: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0051c39e: push eax
         // 0051c39f: call 0x4fb082
      [-]ff75fcff75f8ffb6
         // 0051c3a4: push ss:[ebp+0xfffffffffffffffc]
         // 0051c3a7: push ss:[ebp+0xfffffffffffffff8]
         // 0051c3aa: push ds:[esi+0x264]
      [-]000083c414837e
         // 0051c3b7: add esp, 0x14
         // 0051c3ba: cmp ds:[esi+0x10], 0x0
      [-]6a0356e8
         // 00418d80: push 0x3
         // 00418d82: push esi
         // 00418d83: call 0x4246e0
      [-]5e8be55dc3
         // 0054818b: pop esi
         // 0054818c: mov esp, ebp
         // 0054818e: pop ebp
         // 0054818f: retn 
      [-]558bec8b4d088b410483e8027404
         // 005481d0: push ebp
         // 005481d1: mov ebp, esp
         // 005481d3: mov ecx, ss:[ebp+0x8]
         // 005481d6: mov eax, ds:[ecx+0x4]
         // 005481d9: sub eax, 0x2
         // 005481dc: jz 0x5481e2
      [-]ff75108b4118ff750c83c004506a02e8
         // 00418de2: push ss:[ebp+0x10]
         // 00418de5: mov eax, ds:[ecx+0x18]
         // 00418de8: push ss:[ebp+0xc]
         // 00418deb: add eax, 0x4
         // 00418dee: push eax
         // 00418def: push 0x2
         // 00418df1: call 0x427220
      [-]83c4105dc3
         // 00418df6: add esp, 0x10
         // 00418df9: pop ebp
         // 00418dfa: retn 
      [-]558bec83ec088b45
         // 0051c440: push ebp
         // 0051c441: mov ebp, esp
         // 0051c443: sub esp, 0x8
         // 0051c446: mov eax, ss:[ebp+0x8]
      [-]00????????
      [-]837dfc000f85
         // 005482ae: cmp ss:[ebp+0xfffffffffffffffc], 0x0
         // 005482b2: jnz 0x54837a
      [-]8d45f850ff7510ff750c
         // 00418ec8: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00418ecb: push eax
         // 00418ecc: push ss:[ebp+0x10]
         // 00418ecf: push ss:[ebp+0xc]
      [-]3945f80f84
         // 005482e1: cmp ss:[ebp+0xfffffffffffffff8], eax
         // 005482e4: jz 0x54837a
      [-]8d45fc50
         // 005482ea: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 005482ed: push eax
      [-]ffff83c408
         // 005482f7: add esp, 0x8
      [-]395dfc8b4dfc
         // 0054830d: cmp ss:[ebp+0xfffffffffffffffc], ebx
         // 00548310: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]0f94c38908
         // 00548314: setz b1 bl
         // 00548317: mov ds:[eax], ecx
      [-]5b8be55dc3
         // 0054831c: pop ebx
         // 0054831d: mov esp, ebp
         // 0054831f: pop ebp
         // 00548320: retn 
      [-]6a026a03
         // 00418f27: push 0x2
         // 00418f29: push 0x3
      [-]ffff83c4108945fc83
         // 00418f41: add esp, 0x10
         // 00418f44: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00418f47: cmp ds:[edi+0x10], 0x0
      [-]837dfc0075
         // 00548358: cmp ss:[ebp+0xfffffffffffffffc], 0x0
         // 0054835c: jnz 0x548378
      [-]8b451483c4048b4dfc
         // 00417cb4: mov eax, ss:[ebp+0x14]
         // 00417cb7: add esp, 0x4
         // 00417cba: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]5b8be55dc3
         // 00417cc3: pop ebx
         // 00417cc4: mov esp, ebp
         // 00417cc6: pop ebp
         // 00417cc7: retn 
      [-]8b45148b4dfc
         // 00417cca: mov eax, ss:[ebp+0x14]
         // 00417ccd: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]5b8be55dc3
         // 00417cd6: pop ebx
         // 00417cd7: mov esp, ebp
         // 00417cd9: pop ebp
         // 00417cda: retn 
      [-]558bec837d18008b4514c700????????7d07
         // 00548390: push ebp
         // 00548391: mov ebp, esp
         // 00548393: cmp ss:[ebp+0x18], 0x0
         // 00548397: mov eax, ss:[ebp+0x14]
         // 0054839a: mov ds:[eax], 0x0
         // 005483a0: jge 0x5483a9
      [-]50ff7510ff750cff7508e8
         // 005483a9: push eax
         // 005483aa: push ss:[ebp+0x10]
         // 005483ad: push ss:[ebp+0xc]
         // 005483b0: push ss:[ebp+0x8]
         // 005483b3: call 0x548200
      [-]feffff83c4105dc3
         // 005483b8: add esp, 0x10
         // 005483bb: pop ebp
         // 005483bc: retn 
      [-]558bec568b7508
         // 004d0400: push ebp
         // 004d0401: mov ebp, esp
         // 004d0403: push esi
         // 004d0404: mov esi, ss:[ebp+0x8]
      [-]6a026a0356e8
         // 00418fcd: push 0x2
         // 00418fcf: push 0x3
         // 00418fd1: push esi
         // 00418fd2: call 0x4246a0
      [-]6a0356e8
         // 00419004: push 0x3
         // 00419006: push esi
         // 00419007: call 0x4246e0
      [-]558becff750c
         // 00419020: push ebp
         // 00419021: mov ebp, esp
         // 00419023: push ss:[ebp+0xc]
      [-]558bec568b7508
         // 00548440: push ebp
         // 00548441: mov ebp, esp
         // 00548443: push esi
         // 00548444: mov esi, ss:[ebp+0x8]
      [-]558bec83ec14a1
         // 00419070: push ebp
         // 00419071: mov ebp, esp
         // 00419073: sub esp, 0x14
         // 00419076: mov eax, ds:[___security_cookie]
      [-]0033c58945fc8b450c8b4d088945ec8b45108945f48b45148945f88d45ec68
         // 0041907b: xor eax, ebp
         // 0041907d: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00419080: mov eax, ss:[ebp+0xc]
         // 00419083: mov ecx, ss:[ebp+0x8]
         // 00419086: mov ss:[ebp+0xffffffffffffffec], eax
         // 00419089: mov eax, ss:[ebp+0x10]
         // 0041908c: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0041908f: mov eax, ss:[ebp+0x14]
         // 00419092: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00419095: lea eax, ss:[ebp+0xffffffffffffffec]
         // 00419098: push 0x4190c0
      [-]8b4dfc83c40c33cde8
         // 004190a4: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004190a7: add esp, 0xc
         // 004190aa: xor ecx, ebp
         // 004190ac: call @__security_check_cookie@4
      [-]8be55dc3
         // 004190b1: mov esp, ebp
         // 004190b3: pop ebp
         // 004190b4: retn 
      [-]558bec538b5d1056578b7d0c5357ff7508
         // 0041a9c0: push ebp
         // 0041a9c1: mov ebp, esp
         // 0041a9c3: push ebx
         // 0041a9c4: mov ebx, ss:[ebp+0x10]
         // 0041a9c7: push esi
         // 0041a9c8: push edi
         // 0041a9c9: mov edi, ss:[ebp+0xc]
         // 0041a9cc: push ebx
         // 0041a9cd: push edi
         // 0041a9ce: push ss:[ebp+0x8]
      [-]8b078b88
         // 0054b095: mov eax, ds:[edi]
         // 0054b097: mov ecx, ds:[eax+0x25c]
      [-]39710c75
         // 0054b09d: cmp ds:[ecx+0xc], esi
         // 0054b0a0: jnz 0x54b0e1
      [-]39710c75
         // 0054b0a8: cmp ds:[ecx+0xc], esi
         // 0054b0ab: jnz 0x54b0e1
      [-]ff751450e8
         // 0041aa01: push ss:[ebp+0x14]
         // 0041aa04: push eax
         // 0041aa05: call 0x41d350
      [-]8b45145f
         // 0041aa31: mov eax, ss:[ebp+0x14]
         // 0041aa34: pop edi
      [-]5e5b5dc3
         // 0041aa3d: pop esi
         // 0041aa3e: pop ebx
         // 0041aa3f: pop ebp
         // 0041aa40: retn 
      [-]ffd083c408
         // 0054b23c: call eax
         // 0054b23e: add esp, 0x8
      [-]00006a01ff
         // 0041abd8: push 0x1
         // 0041abda: push ds:[edi+0x260]
      [-]8b7508576a
         // 0054da05: mov esi, ss:[ebp+0x8]
         // 0054da08: push edi
         // 0054da09: push 0x1
      [-]00008b86
         // 0054da15: mov eax, ds:[esi+0x210]
      [-]83c408f6404010
         // 0054da1b: add esp, 0x8
         // 0054da1e: test b1 ds:[eax+0x40], b1 0x10
      [-]558bec8b45088b08
         // 0054db90: push ebp
         // 0054db91: mov ebp, esp
         // 0054db93: mov eax, ss:[ebp+0x8]
         // 0054db96: mov ecx, ds:[eax]
      [-]558bec6a006aff
         // 0041e830: push ebp
         // 0041e831: mov ebp, esp
         // 0041e833: push 0x0
         // 0041e835: push 0xffffffffffffffff
      [-]000083c4
         // 0041e83f: add esp, 0xc
      [-]558bec83ec0c5356578b7d0c
         // 0054df10: push ebp
         // 0054df11: mov ebp, esp
         // 0054df13: sub esp, 0xc
         // 0054df16: push ebx
         // 0054df17: push esi
         // 0054df18: push edi
         // 0054df19: mov edi, ss:[ebp+0xc]
      [-]0f8421010000
         // 0054df1e: jz 0x54e045
      [-]803f000f8418010000
         // 0054df24: cmp b1 ds:[edi], b1 0x0
         // 0054df27: jz 0x54e045
      [-]5b8be55dc3
         // 0054df46: pop ebx
         // 0054df47: mov esp, ebp
         // 0054df49: pop ebp
         // 0054df4a: retn 
      [-]8a034384c075f9
         // 0054df50: mov b1 al, b1 ds:[ebx]
         // 0054df52: inc ebx
         // 0054df53: test b1 al, b1 al
         // 0054df55: jnz 0x54df50
      [-]8b75082bd96a3a56e8
         // 0041eb57: mov esi, ss:[ebp+0x8]
         // 0041eb5a: sub ebx, ecx
         // 0041eb5c: push 0x3a
         // 0041eb5e: push esi
         // 0041eb5f: call _strchr
      [-]2bd6eb0e
         // 0054df6d: sub edx, esi
         // 0054df6f: jmp 0x54df7f
      [-]8a024284c075f9
         // 0054df76: mov b1 al, b1 ds:[edx]
         // 0054df78: inc edx
         // 0054df79: test b1 al, b1 al
         // 0054df7b: jnz 0x54df76
      [-]8955fc8975f8
         // 0054df81: mov ss:[ebp+0xfffffffffffffffc], edx
         // 0054df84: mov ss:[ebp+0xfffffffffffffff8], esi
      [-]0f84b6000000
         // 0054df89: jz 0x54e045
      [-]3bf37320
         // 0054df90: cmp esi, ebx
         // 0054df92: jnb 0x54dfb4
      [-]0fbe043e5068
         // 0041eb94: movsx eax, b1 ds:[esi+edi]
         // 0041eb98: push eax
         // 0041eb99: push 0x45c1c0
      [-]463bf372e5
         // 0054dfaa: inc esi
         // 0054dfab: cmp esi, ebx
         // 0054dfad: jb 0x54df94
      [-]8975f83bf3
         // 0054dfaf: mov ss:[ebp+0xfffffffffffffff8], esi
         // 0054dfb2: cmp esi, ebx
      [-]0f848b000000
         // 0054dfb4: jz 0x54e045
      [-]3bf37321
         // 0054dfbc: cmp esi, ebx
         // 0054dfbe: jnb 0x54dfe1
      [-]0fbe04375068
         // 0041ebc3: movsx eax, b1 ds:[edi+esi]
         // 0041ebc7: push eax
         // 0041ebc8: push 0x45c1c0
      [-]473bfb72e5
         // 0054dfd9: inc edi
         // 0054dfda: cmp edi, ebx
         // 0054dfdc: jb 0x54dfc3
      [-]8b450c8d4e018b55fc803c062e0f45ce
         // 0054dfe1: mov eax, ss:[ebp+0xc]
         // 0054dfe4: lea ecx, ds:[esi+0x1]
         // 0054dfe7: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 0054dfea: cmp b1 ds:[esi+eax], b1 0x2e
         // 0054dfee: cmovnz ecx, esi
      [-]2bf1894df48975f83bf27734
         // 0054dff3: sub esi, ecx
         // 0054dff5: mov ss:[ebp+0xfffffffffffffff4], ecx
         // 0054dff8: mov ss:[ebp+0xfffffffffffffff8], esi
         // 0054dffb: cmp esi, edx
         // 0054dffd: ja 0x54e033
      [-]03c12bf703f20375085650e8
         // 0041ec04: add eax, ecx
         // 0041ec06: sub esi, edi
         // 0041ec08: add esi, edx
         // 0041ec0a: add esi, ss:[ebp+0x8]
         // 0041ec0d: push esi
         // 0041ec0e: push eax
         // 0041ec0f: call 0x424790
      [-]2b45f43b45fc0f8416ffffff
         // 0054e01d: sub eax, ss:[ebp+0xfffffffffffffff4]
         // 0054e020: cmp eax, ss:[ebp+0xfffffffffffffffc]
         // 0054e023: jz 0x54df3f
      [-]807eff2e0f840cffffff
         // 0054e029: cmp b1 ds:[esi+0xffffffffffffffff], b1 0x2e
         // 0054e02d: jz 0x54df3f
      [-]8d77018975f83bf37308
         // 0054e033: lea esi, ds:[edi+0x1]
         // 0054e036: mov ss:[ebp+0xfffffffffffffff8], esi
         // 0054e039: cmp esi, ebx
         // 0054e03b: jnb 0x54e045
      [-]8b7d0ce94bffffff
         // 0054e03d: mov edi, ss:[ebp+0xc]
         // 0054e040: jmp 0x54df90
      [-]5b8be55dc3
         // 0054e049: pop ebx
         // 0054e04a: mov esp, ebp
         // 0054e04c: pop ebp
         // 0054e04d: retn 
      [-]84c075f9
         // 0054e3e3: test b1 al, b1 al
         // 0054e3e5: jnz 0x54e3e0
      [-]b8????????3b
         // 0041dd49: mov eax, 0x100
         // 0041dd4e: cmp ecx, eax
      [-]83c40489
         // 004d47d9: add esp, 0x4
         // 004d47dc: mov ds:[esi+0x90], eax
      [-]83f80174
         // 0054e67e: cmp eax, 0x1
         // 0054e681: jz 0x54e69c
      [-]f6404010
         // 0041f2f9: test b1 ds:[eax+0x40], b1 0x10
      [-]000083c40c
         // 00522972: add esp, 0xc
      [-]53568b400cffd083c40c
         // 00521a63: push ebx
         // 00521a64: push esi
         // 00521a65: mov eax, ds:[eax+0xc]
         // 00521a68: call eax
         // 00521a6a: add esp, 0xc
      [-]6aff6a006a006aff6aff6aff56e8
         // 0041e0c0: push 0xffffffffffffffff
         // 0041e0c2: push 0x0
         // 0041e0c4: push 0x0
         // 0041e0c6: push 0xffffffffffffffff
         // 0041e0c8: push 0xffffffffffffffff
         // 0041e0ca: push 0xffffffffffffffff
         // 0041e0cc: push esi
         // 0041e0cd: call 0x418cb0
      [-]558bec8b4510538b5d08568b35
         // 0041f790: push ebp
         // 0041f791: mov ebp, esp
         // 0041f793: mov eax, ss:[ebp+0x10]
         // 0041f796: push ebx
         // 0041f797: mov ebx, ss:[ebp+0x8]
         // 0041f79a: push esi
         // 0041f79b: mov esi, ds:[0x45be78]
      [-]0f1f440000
         // 0054ebab: nop ds:[eax+eax+0x0]
      [-]50ff36e8
         // 0041f7b0: push eax
         // 0041f7b1: push ds:[esi]
         // 0041f7b3: call 0x424720
      [-]8b463c8583
         // 0054ebce: mov eax, ds:[esi+0x3c]
         // 0054ebd1: test ds:[ebx+0x3d4], eax
      [-]8b450c5f89b0
         // 0041e54a: mov eax, ss:[ebp+0xc]
         // 0041e54d: pop edi
         // 0041e54e: mov ds:[eax+0x214], esi
      [-]5e5b5dc3
         // 0041e55c: pop esi
         // 0041e55d: pop ebx
         // 0041e55e: pop ebp
         // 0041e55f: retn 
      [-]5f5e5b5dc3
         // 0041f817: pop edi
         // 0041f818: pop esi
         // 0041f819: pop ebx
         // 0041f81a: pop ebp
         // 0041f81b: retn 
      [-]558bec568b
         // 0041f760: push ebp
         // 0041f761: mov ebp, esp
         // 0041f763: push esi
         // 0041f764: mov esi, ss:[ebp+0x8]
      [-]ffd183c404
         // 0041f77c: call ecx
         // 0041f77e: add esp, 0x4
      [-]8b403889
         // 0054fe34: mov eax, ds:[eax+0x38]
         // 0054fe37: mov ds:[esi+0x98], eax
      [-]558bec568b75088b86
         // 0054fe60: push ebp
         // 0054fe61: mov ebp, esp
         // 0054fe63: push esi
         // 0054fe64: mov esi, ss:[ebp+0x8]
         // 0054fe67: mov eax, ds:[esi+0x1d0]
      [-]0bc17411
         // 0041f824: or eax, ecx
         // 0041f826: jz 0x41f839
      [-]83c40ceb0f
         // 00420ad4: add esp, 0xc
         // 00420ad7: jmp 0x420ae8
      [-]8d411b5e5dc3
         // 0054ff01: lea eax, ds:[ecx+0x1b]
         // 0054ff04: pop esi
         // 0054ff05: pop ebp
         // 0054ff06: retn 
      [-]558bec538b5d08
         // 004d7200: push ebp
         // 004d7201: mov ebp, esp
         // 004d7203: push ebx
         // 004d7204: mov ebx, ss:[ebp+0x8]
      [-]7d0c008b7e088b0674
         // 0054ff33: cmp ss:[ebp+0xc], 0x0
         // 0054ff37: mov edi, ds:[esi+0x8]
         // 0054ff3a: mov eax, ds:[esi]
         // 0054ff3c: jz 0x54ff48
      [-]6a005653e8
         // 00420b4e: push 0x0
         // 00420b50: push esi
         // 00420b51: push ebx
         // 00420b52: call 0x424a80
      [-]000083c410
         // 00420b57: add esp, 0x10
      [-]558bec8b
         // 0041f8d0: push ebp
         // 0041f8d1: mov ebp, esp
         // 0041f8d3: mov ecx, ss:[ebp+0x8]
      [-]558bec568b75080f57c00f1186
         // 0041fe20: push ebp
         // 0041fe21: mov ebp, esp
         // 0041fe23: push esi
         // 0041fe24: mov esi, ss:[ebp+0x8]
         // 0041fe27: xorps b16 xmm0, b16 xmm0
         // 0041fe2a: movups b16 ds:[esi+0x478], b16 xmm0
      [-]0400000f1186
         // 0041fe31: movups b16 ds:[esi+0x490], b16 xmm0
      [-]040000f20f1186
         // 0041fe38: movsd b8 ds:[esi+0x460], b16 xmm0
      [-]040000f20f1186
         // 0041fe40: movsd b8 ds:[esi+0x4a0], b16 xmm0
      [-]558bec8b55088b0a0f1082
         // 00550f80: push ebp
         // 00550f81: mov ebp, esp
         // 00550f83: mov edx, ss:[ebp+0x8]
         // 00550f86: mov ecx, ds:[edx]
         // 00550f88: movups b16 xmm0, b16 ds:[edx+0x9e]
      [-]0000000f1181
         // 00550f8f: movups b16 ds:[ecx+0x86bc], b16 xmm0
      [-]00000f1082
         // 00550f96: movups b16 xmm0, b16 ds:[edx+0xae]
      [-]0000000f1181
         // 00550f9d: movups b16 ds:[ecx+0x86cc], b16 xmm0
      [-]0000f30f7e82
         // 00550fa4: movq b16 xmm0, b8 ds:[edx+0xbe]
      [-]000000660fd681
         // 00550fac: movq b8 ds:[ecx+0x86dc], b16 xmm0
      [-]00008b82
         // 00550fb4: mov eax, ds:[edx+0xc6]
      [-]000000668981
         // 00550fc7: mov b2 ds:[ecx+0x86e8], b2 ax
      [-]00008b0a0f1082
         // 00550fce: mov ecx, ds:[edx]
         // 00550fd0: movups b16 xmm0, b16 ds:[edx+0xd0]
      [-]0000000f1181
         // 00550fd7: movups b16 ds:[ecx+0x86f0], b16 xmm0
      [-]00000f1082
         // 00550fde: movups b16 xmm0, b16 ds:[edx+0xe0]
      [-]870000f30f7e82
         // 00550fec: movq b16 xmm0, b8 ds:[edx+0xf0]
      [-]660fd681
         // 00550ff4: movq b8 ds:[ecx+0x8710], b16 xmm0
      [-]8700008b82
         // 00550ffc: mov eax, ds:[edx+0xf8]
      [-]8700008b0a8b82
         // 00551016: mov ecx, ds:[edx]
         // 00551018: mov eax, ds:[edx+0xcc]
      [-]8b0a8b82
         // 00551024: mov ecx, ds:[edx]
         // 00551026: mov eax, ds:[edx+0x100]
      [-]558bec83ec08
         // 00524ab0: push ebp
         // 00524ab1: mov ebp, esp
         // 00524ab3: sub esp, 0x8
      [-]578b7d08
         // 00524abf: push edi
         // 00524ac0: mov edi, ss:[ebp+0x8]
      [-]83e801742c
         // 005510da: sub eax, 0x1
         // 005510dd: jz 0x55110b
      [-]83e801741f
         // 005510df: sub eax, 0x1
         // 005510e2: jz 0x551103
      [-]5b8be55dc3
         // 005510f1: pop ebx
         // 005510f2: mov esp, ebp
         // 005510f4: pop ebp
         // 005510f5: retn 
      [-]3bd60f4cf2eb0a
         // 005510fc: cmp edx, esi
         // 005510fe: cmovl esi, edx
         // 00551101: jmp 0x55110d
      [-]8945f88955fc
         // 00421d19: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00421d1c: mov ss:[ebp+0xfffffffffffffffc], edx
      [-]5f5e5b8be55dc3
         // 00524b5c: pop edi
         // 00524b5d: pop esi
         // 00524b5e: pop ebx
         // 00524b5f: mov esp, ebp
         // 00524b61: pop ebp
         // 00524b62: retn 
      [-]558bec568b7508578b7d0c0fb706
         // 004d9240: push ebp
         // 004d9241: mov ebp, esp
         // 004d9243: push esi
         // 004d9244: mov esi, ss:[ebp+0x8]
         // 004d9247: push edi
         // 004d9248: mov edi, ss:[ebp+0xc]
         // 004d924b: movzx eax, b2 ds:[esi]
      [-]6a2e578d4604506a02e8
         // 004222e3: push 0x2e
         // 004222e5: push edi
         // 004222e6: lea eax, ds:[esi+0x4]
         // 004222e9: push eax
         // 004222ea: push 0x2
         // 004222ec: call 0x427220
      [-]000083c410
         // 004222f1: add esp, 0x10
      [-]0fb7460250ff15
         // 004222f8: movzx eax, b2 ds:[esi+0x2]
         // 004222fc: push eax
         // 004222fd: call ds:[ntohs]
      [-]0fb7c88b45105f5e8908
         // 00422303: movzx ecx, b2 ax
         // 00422306: mov eax, ss:[ebp+0x10]
         // 00422309: pop edi
         // 0042230a: pop esi
         // 0042230b: mov ds:[eax], ecx
      [-]8b4510c607005f5ec700????????
         // 00551714: mov eax, ss:[ebp+0x10]
         // 00551717: mov b1 ds:[edi], b1 0x0
         // 0055171a: pop edi
         // 0055171b: pop esi
         // 0055171c: mov ds:[eax], 0x0
      [-]558bec83ec086a006a00c745fc????????c745f8????????ff15
         // 00551ba0: push ebp
         // 00551ba1: mov ebp, esp
         // 00551ba3: sub esp, 0x8
         // 00551ba6: push 0x0
         // 00551ba8: push 0x0
         // 00551baa: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00551bb1: mov ss:[ebp+0xfffffffffffffff8], 0x4
         // 00551bb8: call ds:[SleepEx]
      [-]8d45f8508d45fc5068????????68????????ff7508ff15
         // 00551bbe: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00551bc1: push eax
         // 00551bc2: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00551bc5: push eax
         // 00551bc6: push 0x1007
         // 00551bcb: push 0xffff
         // 00551bd0: push ss:[ebp+0x8]
         // 00551bd3: call ds:[getsockopt]
      [-]3d????????7404
         // 00551bec: cmp eax, 0x2748
         // 00551bf1: jz 0x551bf7
      [-]558bec6a10ff15
         // 00424970: push ebp
         // 00424971: mov ebp, esp
         // 00424973: push 0x10
         // 00424975: call ds:[0x5ffb34]
      [-]ff750852e8
         // 004236e6: push ss:[ebp+0x8]
         // 004236e9: push edx
         // 004236ea: call 0x423860
      [-]000083c408
         // 004236ef: add esp, 0x8
      [-]558bec568b7508
         // 00553d60: push ebp
         // 00553d61: mov ebp, esp
         // 00553d63: push esi
         // 00553d64: mov esi, ss:[ebp+0x8]
      [-]837e0c007618
         // 00553d6b: cmp ds:[esi+0xc], 0x0
         // 00553d6f: jbe 0x553d89
      [-]578b7d0c
         // 00553d71: push edi
         // 00553d72: mov edi, ss:[ebp+0xc]
      [-]57ff760456e8
         // 00553d75: push edi
         // 00553d76: push ds:[esi+0x4]
         // 00553d79: push esi
         // 00553d7a: call 0x553e40
      [-]83c40c837e0c0077ed
         // 00553d7f: add esp, 0xc
         // 00553d82: cmp ds:[esi+0xc], 0x0
         // 00553d86: ja 0x553d75
      [-]558bec6a0cff15
         // 004249e0: push ebp
         // 004249e1: mov ebp, esp
         // 004249e3: push 0xc
         // 004249e5: call ds:[0x5ffb34]
      [-]8b55088b45108901837a0c00751f
         // 00553db6: mov edx, ss:[ebp+0x8]
         // 00553db9: mov eax, ss:[ebp+0x10]
         // 00553dbc: mov ds:[ecx], eax
         // 00553dbe: cmp ds:[edx+0xc], 0x0
         // 00553dc2: jnz 0x553de3
      [-]890ac741????????008b02c740????????00
         // 00553dc4: mov ds:[edx], ecx
         // 00553dc6: mov ds:[ecx+0x4], 0x0
         // 00553dcd: mov eax, ds:[edx]
         // 00553dcf: mov ds:[eax+0x8], 0x0
      [-]ff420c894a045dc3
         // 00553ddb: inc ds:[edx+0xc]
         // 00553dde: mov ds:[edx+0x4], ecx
         // 00553de1: pop ebp
         // 00553de2: retn 
      [-]568b750c8d4608
         // 00553de3: push esi
         // 00553de4: mov esi, ss:[ebp+0xc]
         // 00553de7: lea eax, ds:[esi+0x8]
      [-]8b00894108897104
         // 00553df0: mov eax, ds:[eax]
         // 00553df2: mov ds:[ecx+0x8], eax
         // 00553df5: mov ds:[ecx+0x4], esi
      [-]8b025e894804
         // 00553dfc: mov eax, ds:[edx]
         // 00553dfe: pop esi
         // 00553dff: mov ds:[eax+0x4], ecx
      [-]ff420c890a5dc3
         // 00553e07: inc ds:[edx+0xc]
         // 00553e0a: mov ds:[edx], ecx
         // 00553e0c: pop ebp
         // 00553e0d: retn 
      [-]894e08ff420c5e5dc3
         // 00553e1d: mov ds:[esi+0x8], ecx
         // 00553e20: inc ds:[edx+0xc]
         // 00553e23: pop esi
         // 00553e24: pop ebp
         // 00553e25: retn 
      [-]894e08ff420c5e5dc3
         // 00553e2e: mov ds:[esi+0x8], ecx
         // 00553e31: inc ds:[edx+0xc]
         // 00553e34: pop esi
         // 00553e35: pop ebp
         // 00553e36: retn 
      [-]558bec568b750c57
         // 00553e40: push ebp
         // 00553e41: mov ebp, esp
         // 00553e43: push esi
         // 00553e44: mov esi, ss:[ebp+0xc]
         // 00553e47: push edi
      [-]8b7d08837f0c007461
         // 00553e4c: mov edi, ss:[ebp+0x8]
         // 00553e4f: cmp ds:[edi+0xc], 0x0
         // 00553e53: jz 0x553eb6
      [-]8b46083b377517
         // 00553e55: mov eax, ds:[esi+0x8]
         // 00553e58: cmp esi, ds:[edi]
         // 00553e5a: jnz 0x553e73
      [-]894704eb24
         // 00553e62: mov ds:[edi+0x4], eax
         // 00553e65: jmp 0x553e8b
      [-]8b4608c740????????00eb18
         // 00553e67: mov eax, ds:[esi+0x8]
         // 00553e6a: mov ds:[eax+0x4], 0x0
         // 00553e71: jmp 0x553e8b
      [-]8b4e048941088b4e088b4604
         // 00553e73: mov ecx, ds:[esi+0x4]
         // 00553e76: mov ds:[ecx+0x8], eax
         // 00553e79: mov ecx, ds:[esi+0x8]
         // 00553e7c: mov eax, ds:[esi+0x4]
      [-]894704eb03
         // 00553e83: mov ds:[edi+0x4], eax
         // 00553e86: jmp 0x553e8b
      [-]ff368b4708ff7510ffd056c706????????c746????????00c746????????00ff15
         // 0042382b: push ds:[esi]
         // 0042382d: mov eax, ds:[edi+0x8]
         // 00423830: push ss:[ebp+0x10]
         // 00423833: call eax
         // 00423835: push esi
         // 00423836: mov ds:[esi], 0x0
         // 0042383c: mov ds:[esi+0x4], 0x0
         // 00423843: mov ds:[esi+0x8], 0x0
         // 0042384a: call ds:[0x6077a8]
      [-]83c40cff4f0c
         // 00423850: add esp, 0xc
         // 00423853: dec ds:[edi+0xc]
      [-]558bec8b4d088b450cc741????????00894108c701????????c741????????005dc3
         // 00553ec0: push ebp
         // 00553ec1: mov ebp, esp
         // 00553ec3: mov ecx, ss:[ebp+0x8]
         // 00553ec6: mov eax, ss:[ebp+0xc]
         // 00553ec9: mov ds:[ecx+0xc], 0x0
         // 00553ed0: mov ds:[ecx+0x8], eax
         // 00553ed3: mov ds:[ecx], 0x0
         // 00553ed9: mov ds:[ecx+0x4], 0x0
         // 00553ee0: pop ebp
         // 00553ee1: retn 
      [-]558bec8b450c
         // 004de500: push ebp
         // 004de501: mov ebp, esp
         // 004de503: mov eax, ss:[ebp+0xc]
      [-]53568b7508
         // 004de508: push ebx
         // 004de509: push esi
         // 004de50a: mov esi, ss:[ebp+0x8]
      [-]578b3e394f
         // 00554f40: push edi
         // 00554f41: mov edi, ds:[esi]
         // 00554f43: cmp ds:[edi+0x10], ecx
      [-]6a026a0357e8
         // 00425bb8: push 0x2
         // 00425bba: push 0x3
         // 00425bbc: push edi
         // 00425bbd: call 0x4246a0
      [-]8b451083c40c
         // 00425bc2: mov eax, ss:[ebp+0x10]
         // 00425bc5: add esp, 0xc
      [-]ffff83c41089450c
         // 00425bdb: add esp, 0x10
         // 00425bde: mov ss:[ebp+0xc], eax
      [-]ff7510e8
         // 00425be5: push ss:[ebp+0x10]
         // 00425be8: call 0x424bd0
      [-]6a0357e8
         // 00425bfb: push 0x3
         // 00425bfd: push edi
         // 00425bfe: call 0x4246e0
      [-]8b4d0c5f
         // 00554f96: mov ecx, ss:[ebp+0xc]
         // 00554f99: pop edi
      [-]5e5b5dc3
         // 0042497c: pop esi
         // 0042497d: pop ebx
         // 0042497e: pop ebp
         // 0042497f: retn 
      [-]558bec568b7508578b86
         // 00424990: push ebp
         // 00424991: mov ebp, esp
         // 00424993: push esi
         // 00424994: mov esi, ss:[ebp+0x8]
         // 00424997: push edi
         // 00424998: mov eax, ds:[esi+0x3b0]
      [-]ff750c56e8
         // 005287ff: push ss:[ebp+0xc]
         // 00528802: push esi
         // 00528803: call 0x521c40
      [-]6a0056e8
         // 00425c61: push 0x0
         // 00425c63: push esi
         // 00425c64: call 0x41bd80
      [-]ffff83c408
         // 00425c69: add esp, 0x8
      [-]5f5e5dc3
         // 00554ffe: pop edi
         // 00554fff: pop esi
         // 00555000: pop ebp
         // 00555001: retn 
      [-]558bec5de9
         // 00425c80: push ebp
         // 00425c81: mov ebp, esp
         // 00425c83: pop ebp
         // 00425c84: jmp 0x4185c0
      [-]558bec53568b7508
         // 0055a270: push ebp
         // 0055a271: mov ebp, esp
         // 0055a273: push ebx
         // 0055a274: push esi
         // 0055a275: mov esi, ss:[ebp+0x8]
      [-]0f84c7000000
         // 0055a2b3: jz 0x55a380
      [-]c747????????00
         // 0052c727: mov ds:[edi+0x5c], 0x0
      [-]83f8037534
         // 0055a2e4: cmp eax, 0x3
         // 0055a2e7: jnz 0x55a31d
      [-]8b4f28034f208b472c13472457894b
         // 0055a2e9: mov ecx, ds:[edi+0x28]
         // 0055a2ec: add ecx, ds:[edi+0x20]
         // 0055a2ef: mov eax, ds:[edi+0x2c]
         // 0055a2f2: adc eax, ds:[edi+0x24]
         // 0055a2f5: push edi
         // 0055a2f6: mov ds:[ebx+0x38], ecx
      [-]8b473883c404
         // 0055a301: mov eax, ds:[edi+0x38]
         // 0055a304: add esp, 0x4
      [-]83c404c747????????00eb17
         // 0042aff1: add esp, 0x4
         // 0042aff4: mov ds:[edi+0x38], 0x0
         // 0042affb: jmp 0x42b014
      [-]83f8047512
         // 0055a31d: cmp eax, 0x4
         // 0055a320: jnz 0x55a334
      [-]8b4f28034f208b472c134724894b
         // 0055a322: mov ecx, ds:[edi+0x28]
         // 0055a325: add ecx, ds:[edi+0x20]
         // 0055a328: mov eax, ds:[edi+0x2c]
         // 0055a32b: adc eax, ds:[edi+0x24]
         // 0055a32e: mov ds:[ebx+0x38], ecx
      [-]5f5e5b5dc3
         // 0052c7cb: pop edi
         // 0052c7cc: pop esi
         // 0052c7cd: pop ebx
         // 0052c7ce: pop ebp
         // 0052c7cf: retn 
      [-]5f5e5b5dc3
         // 0055a382: pop edi
         // 0055a383: pop esi
         // 0055a384: pop ebx
         // 0055a385: pop ebp
         // 0055a386: retn 
      [-]558bec568b7508578b7d10
         // 004e0310: push ebp
         // 004e0311: mov ebp, esp
         // 004e0313: push esi
         // 004e0314: mov esi, ss:[ebp+0x8]
         // 004e0317: push edi
         // 004e0318: mov edi, ss:[ebp+0x10]
      [-]f7d08b56083bc273
         // 004e031d: not eax
         // 004e031f: mov edx, ds:[esi+0x8]
         // 004e0322: cmp eax, edx
         // 004e0324: jnb 0x4e0347
      [-]833e0053740b
         // 0055a44f: cmp ds:[esi], 0x0
         // 0055a452: push ebx
         // 0055a453: jz 0x55a460
      [-]8b46048d0c3a483bc876
         // 0055a455: mov eax, ds:[esi+0x4]
         // 0055a458: lea ecx, ds:[edx+edi]
         // 0055a45b: dec eax
         // 0055a45c: cmp ecx, eax
         // 0055a45e: jbe 0x55a4d5
      [-]81ff????????771b
         // 0055a460: cmp edi, 0x7fffffff
         // 0055a466: ja 0x55a483
      [-]81fa????????7713
         // 0055a468: cmp edx, 0x7fffffff
         // 0055a46e: ja 0x55a483
      [-]8d0c3ff7d18d04123bc87207
         // 0055a470: lea ecx, ds:[edi+edi]
         // 0055a473: not ecx
         // 0055a475: lea eax, ds:[edx+edx]
         // 0055a478: cmp ecx, eax
         // 0055a47a: jb 0x55a483
      [-]83c408eb09
         // 00429f04: add esp, 0x8
         // 00429f07: jmp 0x429f12
      [-]8906895e04
         // 0055a4d0: mov ds:[esi], eax
         // 0055a4d2: mov ds:[esi+0x4], ebx
      [-]8b0603460857ff750c50e8
         // 0042b1b5: mov eax, ds:[esi]
         // 0042b1b7: add eax, ds:[esi+0x8]
         // 0042b1ba: push edi
         // 0042b1bb: push ss:[ebp+0xc]
         // 0042b1be: push eax
         // 0042b1bf: call _memmove_0
      [-]017e0883c40c
         // 0042b1c4: add ds:[esi+0x8], edi
         // 0042b1c7: add esp, 0xc
      [-]5b5f5e5dc3
         // 0042b1cc: pop ebx
         // 0042b1cd: pop edi
         // 0042b1ce: pop esi
         // 0042b1cf: pop ebp
         // 0042b1d0: retn 
      [-]558bec83ec0c8b45185356578b
         // 00429f80: push ebp
         // 00429f81: mov ebp, esp
         // 00429f83: sub esp, 0xc
         // 00429f86: mov eax, ss:[ebp+0x18]
         // 00429f89: push ebx
         // 00429f8a: push esi
         // 00429f8b: push edi
         // 00429f8c: mov edi, ss:[ebp+0xc]
      [-]0100008b
         // 00429f96: mov edx, ds:[edi]
      [-]8945fc8b45088b
         // 00429f98: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00429f9b: mov eax, ss:[ebp+0x8]
         // 00429f9e: mov esi, ds:[edx+0x8664]
      [-]8b088b5808
         // 00429fa4: mov ecx, ds:[eax]
         // 00429fa6: mov ebx, ds:[eax+0x8]
      [-]2b45148945f88b
         // 00429fab: sub eax, ss:[ebp+0x14]
         // 00429fae: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00429fb1: mov eax, ds:[edi+0x210]
      [-]894d18f6404001
         // 00429fb7: mov ss:[ebp+0x18], ecx
         // 00429fba: test b1 ds:[eax+0x40], b1 0x1
      [-]0f4745f82b
         // 0042a01c: cmova eax, ss:[ebp+0xfffffffffffffff8]
         // 0042a020: sub ecx, eax
      [-]50ff75188b
         // 0052bb17: push eax
         // 0052bb18: push ss:[ebp+0x18]
         // 0052bb1b: mov eax, ds:[edi]
      [-]6a0250e8
         // 0052bb1d: push 0x2
         // 0052bb1f: push eax
         // 0052bb20: call 0x517830
      [-]506a04ff
         // 0052ca3b: push eax
         // 0052ca3c: push 0x4
         // 0052ca3e: push ds:[edi]
      [-]5b8be55dc3
         // 0055a674: pop ebx
         // 0055a675: mov esp, ebp
         // 0055a677: pop ebp
         // 0055a678: retn 
      [-]8b45f483c4045f5e5b8be55dc3
         // 0042b396: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0042b399: add esp, 0x4
         // 0042b39c: pop edi
         // 0042b39d: pop esi
         // 0042b39e: pop ebx
         // 0042b39f: mov esp, ebp
         // 0042b3a1: pop ebp
         // 0042b3a2: retn 
      [-]558bec56578d451050ff750ce8
         // 0042a140: push ebp
         // 0042a141: mov ebp, esp
         // 0042a143: push esi
         // 0042a144: push edi
         // 0042a145: lea eax, ss:[ebp+0x10]
         // 0042a148: push eax
         // 0042a149: push ss:[ebp+0xc]
         // 0042a14c: call 0x421fc0
      [-]8d510190
         // 0055a6ec: lea edx, ds:[ecx+0x1]
         // 0055a6ef: nop 
      [-]8a014184c075f9
         // 0055a6f0: mov b1 al, b1 ds:[ecx]
         // 0055a6f2: inc ecx
         // 0055a6f3: test b1 al, b1 al
         // 0055a6f5: jnz 0x55a6f0
      [-]2bca5157ff7508e8
         // 0042b3d7: sub ecx, edx
         // 0042b3d9: push ecx
         // 0042b3da: push edi
         // 0042b3db: push ss:[ebp+0x8]
         // 0042b3de: call 0x42b0f0
      [-]fdffff57
         // 0042b3e3: push edi
      [-]5f5e5dc3
         // 0042b3f1: pop edi
         // 0042b3f2: pop esi
         // 0042b3f3: pop ebp
         // 0042b3f4: retn 
      [-]5f5e5dc3
         // 0042b417: pop edi
         // 0042b418: pop esi
         // 0042b419: pop ebp
         // 0042b41a: retn 
      [-]558bec538b5d0c5657
         // 0055a990: push ebp
         // 0055a991: mov ebp, esp
         // 0055a993: push ebx
         // 0055a994: mov ebx, ss:[ebp+0xc]
         // 0055a997: push esi
         // 0055a998: push edi
      [-]8d4f016690
         // 0055a99b: lea ecx, ds:[edi+0x1]
         // 0055a99e: xchg b2 ax, b2 ax
      [-]8a074784c075f9
         // 0055a9a0: mov b1 al, b1 ds:[edi]
         // 0055a9a2: inc edi
         // 0055a9a3: test b1 al, b1 al
         // 0055a9a5: jnz 0x55a9a0
      [-]082bf98b
         // 0042a41a: sub edi, ecx
         // 0042a41c: mov esi, ds:[esi+0x1d8]
      [-]5753ff36e8
         // 0042b696: push edi
         // 0042b697: push ebx
         // 0042b698: push ds:[esi]
         // 0042b69a: call 0x424790
      [-]8b065f5e5b5dc3
         // 0055a9d4: mov eax, ds:[esi]
         // 0055a9d6: pop edi
         // 0055a9d7: pop esi
         // 0055a9d8: pop ebx
         // 0055a9d9: pop ebp
         // 0055a9da: retn 
      [-]558bec8b4d0c56
         // 0055a9e0: push ebp
         // 0055a9e1: mov ebp, esp
         // 0055a9e3: mov ecx, ss:[ebp+0xc]
         // 0055a9e6: push esi
      [-]578d56010f1f00
         // 0055a9e9: push edi
         // 0055a9ea: lea edx, ds:[esi+0x1]
         // 0055a9ed: nop ds:[eax]
      [-]8a064684c075f9
         // 0055a9f0: mov b1 al, b1 ds:[esi]
         // 0055a9f2: inc esi
         // 0055a9f3: test b1 al, b1 al
         // 0055a9f5: jnz 0x55a9f0
      [-]8b7d082bf2565157e8
         // 0042b6d7: mov edi, ss:[ebp+0x8]
         // 0042b6da: sub esi, edx
         // 0042b6dc: push esi
         // 0042b6dd: push ecx
         // 0042b6de: push edi
         // 0042b6df: call 0x424790
      [-]5f5e5dc3
         // 0055aa0b: pop edi
         // 0055aa0c: pop esi
         // 0055aa0d: pop ebp
         // 0055aa0e: retn 
      [-]8a043e03f784c074
         // 0055aa0f: mov b1 al, b1 ds:[esi+edi]
         // 0055aa12: add esi, edi
         // 0055aa14: test b1 al, b1 al
         // 0055aa16: jz 0x55aa38
      [-]0fb6c050e8
         // 0042b700: movzx eax, b1 al
         // 0042b703: push eax
         // 0042b704: call _isspace
      [-]8a46014684c075e8
         // 0055aa30: mov b1 al, b1 ds:[esi+0x1]
         // 0055aa33: inc esi
         // 0055aa34: test b1 al, b1 al
         // 0055aa36: jnz 0x55aa20
      [-]6a0d56e8
         // 0042b718: push 0xd
         // 0042b71a: push esi
         // 0042b71b: call _strchr
      [-]6a0a56e8
         // 0042b729: push 0xa
         // 0042b72b: push esi
         // 0042b72c: call _strchr
      [-]8b4d102bfe53
         // 0055aa66: mov ecx, ss:[ebp+0x10]
         // 0055aa69: sub edi, esi
         // 0055aa6b: push ebx
      [-]8a034384c075f9
         // 0055aa71: mov b1 al, b1 ds:[ebx]
         // 0055aa73: inc ebx
         // 0055aa74: test b1 al, b1 al
         // 0055aa76: jnz 0x55aa71
      [-]2bda3bfb721a
         // 0055aa78: sub ebx, edx
         // 0055aa7a: cmp edi, ebx
         // 0055aa7c: jb 0x55aa98
      [-]535156e8
         // 0042b760: push ebx
         // 0042b761: push ecx
         // 0042b762: push esi
         // 0042b763: call 0x424790
      [-]8b4d104f463bfb73e8
         // 0055aa8f: mov ecx, ss:[ebp+0x10]
         // 0055aa92: dec edi
         // 0055aa93: inc esi
         // 0055aa94: cmp edi, ebx
         // 0055aa96: jnb 0x55aa80
      [-]558bec53568b7508
         // 0042a860: push ebp
         // 0042a861: mov ebp, esp
         // 0042a863: push ebx
         // 0042a864: push esi
         // 0042a865: mov esi, ss:[ebp+0x8]
      [-]578b168955088dba
         // 0042a86a: push edi
         // 0042a86b: mov edx, ds:[esi]
         // 0042a86d: mov ss:[ebp+0x8], edx
         // 0042a870: lea edi, ds:[edx+0x85bc]
      [-]395f047503
         // 0055ae2e: cmp ds:[edi+0x4], ebx
         // 0055ae31: jnz 0x55ae36
      [-]3959047503
         // 0055ae3c: cmp ds:[ecx+0x4], ebx
         // 0055ae3f: jnz 0x55ae44
      [-]6a01ff7510ff750c5156e8
         // 0042a8c7: push 0x1
         // 0042a8c9: push ss:[ebp+0x10]
         // 0042a8cc: push ss:[ebp+0xc]
         // 0042a8cf: push ecx
         // 0042a8d0: push esi
         // 0042a8d1: call 0x42bcd0
      [-]5f5e5b5dc3
         // 0042a923: pop edi
         // 0042a924: pop esi
         // 0042a925: pop ebx
         // 0042a926: pop ebp
         // 0042a927: retn 
      [-]6a00ff7510ff750c5756e8
         // 0042a931: push 0x0
         // 0042a933: push ss:[ebp+0x10]
         // 0042a936: push ss:[ebp+0xc]
         // 0042a939: push edi
         // 0042a93a: push esi
         // 0042a93b: call 0x42bcd0
      [-]000083c414
         // 0042a940: add esp, 0x14
      [-]5f5e5b5dc3
         // 0042a945: pop edi
         // 0042a946: pop esi
         // 0042a947: pop ebx
         // 0042a948: pop ebp
         // 0042a949: retn 
      [-]5f5e5b5dc3
         // 0055aeea: pop edi
         // 0055aeeb: pop esi
         // 0055aeec: pop ebx
         // 0055aeed: pop ebp
         // 0055aeee: retn 
      [-]558bec8b4508538b5d0c568bb0
         // 0042b6d0: push ebp
         // 0042b6d1: mov ebp, esp
         // 0042b6d3: mov eax, ss:[ebp+0x8]
         // 0042b6d6: push ebx
         // 0042b6d7: mov ebx, ss:[ebp+0xc]
         // 0042b6da: push esi
         // 0042b6db: mov esi, ds:[eax+0x274]
      [-]8a084084c975f9
         // 0055bc80: mov b1 cl, b1 ds:[eax]
         // 0055bc82: inc eax
         // 0055bc83: test b1 cl, b1 cl
         // 0055bc85: jnz 0x55bc80
      [-]2bc7505352e8
         // 0042c967: sub eax, edi
         // 0042c969: push eax
         // 0042c96a: push ebx
         // 0042c96b: push edx
         // 0042c96c: call 0x424790
      [-]5f5e5b5dc3
         // 004e1fc4: pop edi
         // 004e1fc5: pop esi
         // 004e1fc8: pop ebx
         // 004e1fc9: pop ebp
         // 004e1fca: retn 
      [-]558bec8b450cff7510ff75088b80
         // 0055bcd0: push ebp
         // 0055bcd1: mov ebp, esp
         // 0055bcd3: mov eax, ss:[ebp+0xc]
         // 0055bcd6: push ss:[ebp+0x10]
         // 0055bcd9: push ss:[ebp+0x8]
         // 0055bcdc: mov eax, ds:[eax+0x210]
      [-]f7403c????????740a
         // 0055bce2: test ds:[eax+0x3c], 0x40000
         // 0055bce9: jz 0x55bcf5
      [-]e81000000083c4085dc3
         // 0055bceb: call 0x55bd00
         // 0055bcf0: add esp, 0x8
         // 0055bcf3: pop ebp
         // 0055bcf4: retn 
      [-]ffffff83c4085dc3
         // 0055bcfa: add esp, 0x8
         // 0055bcfd: pop ebp
         // 0055bcfe: retn 
      [-]558bec6a05ff750c68
         // 0055bd00: push ebp
         // 0055bd01: mov ebp, esp
         // 0055bd03: push 0x5
         // 0055bd05: push ss:[ebp+0xc]
         // 0055bd08: push 0x5b7f5c
      [-]558bec568b7508
         // 0042b860: push ebp
         // 0042b861: mov ebp, esp
         // 0042b863: push esi
         // 0042b864: mov esi, ss:[ebp+0x8]
      [-]000083c408
         // 0042b87a: add esp, 0x8
      [-]ffff83c408
         // 0042cafc: add esp, 0x8
      [-]ffff83c40c
         // 0042cb13: add esp, 0xc
      [-]ff7510e8
         // 0042cb26: push ss:[ebp+0x10]
         // 0042cb29: call 0x42b3b0
      [-]ffff83c408
         // 0042cb2e: add esp, 0x8
      [-]558bec538b5d10568b750c578b7d088b465803c38b8f
         // 0055be70: push ebp
         // 0055be71: mov ebp, esp
         // 0055be73: push ebx
         // 0055be74: mov ebx, ss:[ebp+0x10]
         // 0055be77: push esi
         // 0055be78: mov esi, ss:[ebp+0xc]
         // 0055be7b: push edi
         // 0055be7c: mov edi, ss:[ebp+0x8]
         // 0055be7f: mov eax, ds:[esi+0x58]
         // 0055be82: add eax, ebx
         // 0055be84: mov ecx, ds:[edi+0x538]
      [-]3bc1727d
         // 0055be8a: cmp eax, ecx
         // 0055be8c: jb 0x55bf0b
      [-]3d????????761d
         // 0055be8e: cmp eax, 0x19000
         // 0055be93: jbe 0x55beb2
      [-]68????????68
         // 0042b905: push 0x19000
         // 0042b90a: push 0x45d6b4
      [-]5f5e5b5dc3
         // 0042b91d: pop edi
         // 0042b91e: pop esi
         // 0042b91f: pop ebx
         // 0042b920: pop ebp
         // 0042b921: retn 
      [-]8b56548d0440d1e8
         // 0042cb92: mov edx, ds:[esi+0x54]
         // 0042cb95: lea eax, ds:[eax+eax*0x2]
         // 0042cb98: shr eax, b1 0x1
      [-]3bc10f47c88b87
         // 0042cb9c: cmp eax, ecx
         // 0042cb9e: cmova ecx, eax
         // 0042cba1: mov eax, ds:[edi+0x534]
      [-]512bd0894d0c50895510ff15
         // 0042cba7: push ecx
         // 0042cba8: sub edx, eax
         // 0042cbaa: mov ss:[ebp+0xc], ecx
         // 0042cbad: push eax
         // 0042cbae: mov ss:[ebp+0x10], edx
         // 0042cbb1: call ds:[0x5ffb3c]
      [-]5f5e5b5dc3
         // 0042b961: pop edi
         // 0042b962: pop esi
         // 0042b963: pop ebx
         // 0042b964: pop ebp
         // 0042b965: retn 
      [-]8b4d0c8987
         // 0055bef6: mov ecx, ss:[ebp+0xc]
         // 0055bef9: mov ds:[edi+0x534], eax
      [-]034510898f
         // 0055beff: add eax, ss:[ebp+0x10]
         // 0055bf02: mov ds:[edi+0x538], ecx
      [-]53ff7660ff7654e8
         // 0054e67b: push ebx
         // 0054e67c: push ds:[esi+0x60]
         // 0054e67f: push ds:[esi+0x54]
         // 0054e682: call _memmove_0
      [-]015e5483c40c8b4654015e585f5ec60000
         // 0054e687: add ds:[esi+0x54], ebx
         // 0054e68a: add esp, 0xc
         // 0054e68d: mov eax, ds:[esi+0x54]
         // 0054e690: add ds:[esi+0x58], ebx
         // 0054e693: pop edi
         // 0054e694: pop esi
         // 0054e695: mov b1 ds:[eax], b1 0x0
      [-]558bec83ec088b450853
         // 0042b9a0: push ebp
         // 0042b9a1: mov ebp, esp
         // 0042b9a3: sub esp, 0x8
         // 0042b9a6: mov eax, ss:[ebp+0x8]
         // 0042b9a9: push ebx
      [-]c745f8????????c745fc????????
         // 0042b9b1: mov ss:[ebp+0xfffffffffffffff8], 0x0
         // 0042b9b8: mov ss:[ebp+0xfffffffffffffffc], 0x0
      [-]68????????50e8
         // 0052e3d6: push 0x4001
         // 0052e3db: push eax
         // 0052e3dc: call _snprintf
      [-]8d41018945
         // 0052e3ec: lea eax, ds:[ecx+0x1]
         // 0052e3ef: mov ss:[ebp+0x8], eax
      [-]8a014184c075f9
         // 0055bfa2: mov b1 al, b1 ds:[ecx]
         // 0055bfa4: inc ecx
         // 0055bfa5: test b1 al, b1 al
         // 0055bfa7: jnz 0x55bfa2
      [-]8d45f8508d45fc505152
         // 0055bfac: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0055bfaf: push eax
         // 0055bfb0: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0055bfb3: push eax
         // 0055bfb4: push ecx
         // 0055bfb5: push edx
      [-]5b8be55dc3
         // 0055bfd1: pop ebx
         // 0055bfd2: mov esp, ebp
         // 0055bfd4: pop ebp
         // 0055bfd5: retn 
      [-]5f5e5b8be55dc3
         // 0055c024: pop edi
         // 0055c025: pop esi
         // 0055c026: pop ebx
         // 0055c027: mov esp, ebp
         // 0055c029: pop ebp
         // 0055c02a: retn 
      [-]558bec51538b
         // 004e24a0: push ebp
         // 004e24a1: mov ebp, esp
         // 004e24a3: push ecx
         // 004e24a4: push ebx
         // 004e24a6: mov esi, ss:[ebp+0x8]
      [-]7508578b
         // 004e24a9: push edi
         // 004e24aa: mov edi, ss:[ebp+0xc]
      [-]ffff83c408
         // 0042cfb2: add esp, 0x8
      [-]ffff83c408
         // 0042cfcf: add esp, 0x8
      [-]fcffff83c408
         // 0042cfe4: add esp, 0x8
      [-]5f5e5b8be55dc3
         // 0055c322: pop edi
         // 0055c323: pop esi
         // 0055c324: pop ebx
         // 0055c325: mov esp, ebp
         // 0055c327: pop ebp
         // 0055c328: retn 
      [-]0f44c15068
         // 0052d892: cmovz eax, ecx
         // 0052d895: push eax
         // 0052d896: push 0x6584d4
      [-]0c0f94c0
         // 0052d8a8: cmp ds:[ebx+0xc], eax
         // 0052d8ab: setz b1 al
      [-]5e5b8be55dc3
         // 0052d8b4: pop esi
         // 0052d8b5: pop ebx
         // 0052d8b6: mov esp, ebp
         // 0052d8b8: pop ebp
         // 0052d8b9: retn 
      [-]558bec8b4508
         // 0055c370: push ebp
         // 0055c371: mov ebp, esp
         // 0055c373: mov eax, ss:[ebp+0x8]
      [-]8b08234808f6c1047412
         // 0055c37b: mov ecx, ds:[eax]
         // 0055c37d: and ecx, ds:[eax+0x8]
         // 0055c380: test b1 cl, b1 0x4
         // 0055c383: jz 0x55c397
      [-]c74004????????c740????????00
         // 0055c385: mov ds:[eax+0x4], 0x4
         // 0055c38c: mov ds:[eax+0x8], 0x0
      [-]f6c1027412
         // 0055c397: test b1 cl, b1 0x2
         // 0055c39a: jz 0x55c3ae
      [-]c74004????????c740????????00
         // 0055c39c: mov ds:[eax+0x4], 0x2
         // 0055c3a3: mov ds:[eax+0x8], 0x0
      [-]f6c1087412
         // 0055c3ae: test b1 cl, b1 0x8
         // 0055c3b1: jz 0x55c3c5
      [-]c74004????????c740????????00
         // 0055c3b3: mov ds:[eax+0x4], 0x8
         // 0055c3ba: mov ds:[eax+0x8], 0x0
      [-]f6c1207412
         // 0055c3c5: test b1 cl, b1 0x20
         // 0055c3c8: jz 0x55c3dc
      [-]c74004????????c740????????00
         // 0055c3ca: mov ds:[eax+0x4], 0x20
         // 0055c3d1: mov ds:[eax+0x8], 0x0
      [-]558bec8b4d08
         // 004e27e0: push ebp
         // 004e27e1: mov ebp, esp
         // 004e27e3: mov ecx, ss:[ebp+0x8]
      [-]8b450c8b
         // 0055c4f6: mov eax, ss:[ebp+0xc]
         // 0055c4f9: mov eax, ds:[eax+0x118]
      [-]558bec68
         // 004e28b0: push ebp
         // 004e28b1: mov ebp, esp
         // 004e28b3: push 0x4fa0c0
      [-]ffff8b4d08
         // 004e28bd: mov ecx, ss:[ebp+0x8]
      [-]0f44c15dc3
         // 004e28d1: cmovz eax, ecx
         // 004e28d4: pop ebp
         // 004e28d5: retn 
      [-]558bec568b750883be
         // 0055c5e0: push ebp
         // 0055c5e1: mov ebp, esp
         // 0055c5e3: push esi
         // 0055c5e4: mov esi, ss:[ebp+0x8]
         // 0055c5e7: cmp ds:[esi+0x44c], 0x0
      [-]000f8ca5000000
         // 0055c5ee: jl 0x55c699
      [-]000f8296000000
         // 0055c5fd: jb 0x55c699
      [-]000f8489000000
         // 0055c60a: jz 0x55c699
      [-]ff7510ff750ce8
         // 0042d32d: push ss:[ebp+0x10]
         // 0042d330: push ss:[ebp+0xc]
         // 0042d333: call 0x424b30
      [-]83c41069ca????????2bc8
         // 0042d33e: add esp, 0x10
         // 0042d341: imul ecx, edx, 0x3e8
         // 0042d347: sub ecx, eax
      [-]008b450c8986
         // 0055c6a0: mov eax, ss:[ebp+0xc]
         // 0055c6a3: mov ds:[esi+0x528], eax
      [-]8b45108986
         // 0055c6a9: mov eax, ss:[ebp+0x10]
         // 0055c6ac: mov ds:[esi+0x52c], eax
      [-]558bec8b45080f57c0660fd680
         // 0055c6d0: push ebp
         // 0055c6d1: mov ebp, esp
         // 0055c6d3: mov eax, ss:[ebp+0x8]
         // 0055c6d6: xorps b16 xmm0, b16 xmm0
         // 0055c6d9: movq b8 ds:[eax+0x528], b16 xmm0
      [-]0500005dc3
         // 0055c6e1: pop ebp
         // 0055c6e2: retn 
      [-]558bec83ec0c8b4d085356578b01
         // 0042d520: push ebp
         // 0042d521: mov ebp, esp
         // 0042d523: sub esp, 0xc
         // 0042d526: mov ecx, ss:[ebp+0x8]
         // 0042d529: push ebx
         // 0042d52a: push esi
         // 0042d52b: push edi
         // 0042d52c: mov eax, ds:[ecx]
      [-]8945fc6a078bb8
         // 0042d538: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0042d53b: push 0x7
         // 0042d53d: mov edi, ds:[eax+0x8638]
      [-]8945f48b450c68
         // 0042d546: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0042d549: mov eax, ss:[ebp+0xc]
         // 0042d54c: push 0x45dbc4
      [-]57894df8
         // 0042d551: push edi
         // 0042d552: mov ss:[ebp+0xfffffffffffffff8], ecx
      [-]0f858d000000
         // 0042d5ad: jnz 0x42d640
      [-]6a2f57e8
         // 0052f0bb: push 0x2f
         // 0052f0bd: push edi
         // 0052f0be: call 0x4f2a40
      [-]413819740f
         // 0055db80: inc ecx
         // 0055db81: cmp b1 ds:[ecx], b1 bl
         // 0055db83: jz 0x55db94
      [-]80383a7503
         // 0055db87: cmp b1 ds:[eax], b1 0x3a
         // 0055db8a: jnz 0x55db8f
      [-]40381875f3
         // 0055db8f: inc eax
         // 0055db90: cmp b1 ds:[eax], b1 bl
         // 0055db92: jnz 0x55db87
      [-]8b75085168
         // 0052f0e4: mov esi, ss:[ebp+0x8]
         // 0052f0e7: push ecx
         // 0052f0e8: push 0x658f10
      [-]56ff75f8e8
         // 0052f0ed: push esi
         // 0052f0ee: push ss:[ebp+0xfffffffffffffff8]
         // 0052f0f1: call 0x517cc0
      [-]ff75fce8
         // 0042d624: push ss:[ebp+0xfffffffffffffffc]
         // 0042d627: call 0x420110
      [-]5f5e5b8be55dc3
         // 0042d631: pop edi
         // 0042d632: pop esi
         // 0042d633: pop ebx
         // 0042d634: mov esp, ebp
         // 0042d636: pop ebp
         // 0042d637: retn 
      [-]8b45f4e9
         // 0055dbc8: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0055dbcb: jmp 0x55dd77
      [-]6a3a57e8
         // 0042e8b0: push 0x3a
         // 0042e8b2: push edi
         // 0042e8b3: call _strchr
      [-]476a3a57e8
         // 0042e8c1: inc edi
         // 0042e8c2: push 0x3a
         // 0042e8c4: push edi
         // 0042e8c5: call _strchr
      [-]881e466a3a56e8
         // 0042e8d3: mov b1 ds:[esi], b1 bl
         // 0042e8d5: inc esi
         // 0042e8d6: push 0x3a
         // 0042e8d8: push esi
         // 0042e8d9: call _strchr
      [-]381f7518
         // 0055dc0b: cmp b1 ds:[edi], b1 bl
         // 0055dc0d: jnz 0x55dc27
      [-]8b5dfc68
         // 0042d67f: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 0042d682: push 0x45dbd8
      [-]83c408bf
         // 0042d68d: add esp, 0x8
         // 0042d690: mov edi, 0x45dbf0
      [-]803e007505
         // 0055dc2e: cmp b1 ds:[esi], b1 0x0
         // 0055dc31: jnz 0x55dc38
      [-]57568b750868
         // 0055dc4c: push edi
         // 0055dc4d: push esi
         // 0055dc4e: mov esi, ss:[ebp+0x8]
         // 0055dc51: push 0x5b8504
      [-]56ff75f8e8
         // 0055dc56: push esi
         // 0055dc57: push ss:[ebp+0xfffffffffffffff8]
         // 0055dc5a: call 0x550b60
      [-]57894508
         // 0055dc5f: push edi
         // 0055dc60: mov ss:[ebp+0x8], eax
      [-]8b7d0883c418
         // 0055dc68: mov edi, ss:[ebp+0x8]
         // 0055dc6b: add esp, 0x18
      [-]5f5e5b8be55dc3
         // 0042d6f2: pop edi
         // 0042d6f3: pop esi
         // 0042d6f4: pop ebx
         // 0042d6f5: mov esp, ebp
         // 0042d6f7: pop ebp
         // 0042d6f8: retn 
      [-]6a3a57e8
         // 0052f1e1: push 0x3a
         // 0052f1e3: push edi
         // 0052f1e4: call 0x4f2a40
      [-]476a3a57e8
         // 0042e982: inc edi
         // 0042e983: push 0x3a
         // 0042e985: push edi
         // 0042e986: call _strchr
      [-]881e466a3a56e8
         // 0042e994: mov b1 ds:[esi], b1 bl
         // 0042e996: inc esi
         // 0042e997: push 0x3a
         // 0042e999: push esi
         // 0042e99a: call _strchr
      [-]c60300436a3a53e8
         // 004ea486: mov b1 ds:[ebx], b1 0x0
         // 004ea489: inc ebx
         // 004ea48a: push 0x3a
         // 004ea48c: push ebx
         // 004ea48d: call _strchr
      [-]803f007515
         // 0055dce2: cmp b1 ds:[edi], b1 0x0
         // 0055dce5: jnz 0x55dcfc
      [-]ff75fce8
         // 0042e9cc: push ss:[ebp+0xfffffffffffffffc]
         // 0042e9cf: call 0x421450
      [-]83c408bf
         // 0042e9d4: add esp, 0x8
         // 0042e9d7: mov edi, 0x45ebe8
      [-]803e007505
         // 0055dd00: cmp b1 ds:[esi], b1 0x0
         // 0055dd03: jnz 0x55dd0a
      [-]803b007505
         // 0055dd0e: cmp b1 ds:[ebx], b1 0x0
         // 0055dd11: jnz 0x55dd18
      [-]578b7dfc57e8
         // 0042d788: push edi
         // 0042d789: mov edi, ss:[ebp+0xfffffffffffffffc]
         // 0042d78c: push edi
         // 0042d78d: call 0x42d810
      [-]00000083c40889450c
         // 0042d792: add esp, 0x8
         // 0042d795: mov ss:[ebp+0xc], eax
      [-]5b8be55dc3
         // 0055dd33: pop ebx
         // 0055dd34: mov esp, ebp
         // 0055dd36: pop ebp
         // 0055dd37: retn 
      [-]5053568b750868
         // 0042d7a8: push eax
         // 0042d7a9: push ebx
         // 0042d7aa: push esi
         // 0042d7ab: mov esi, ss:[ebp+0x8]
         // 0042d7ae: push 0x45dbfc
      [-]56ff75f8e8
         // 0042d7b3: push esi
         // 0042d7b4: push ss:[ebp+0xfffffffffffffff8]
         // 0042d7b7: call 0x4204c0
      [-]5f5e5b8be55dc3
         // 0042d7dd: pop edi
         // 0042d7de: pop esi
         // 0042d7df: pop ebx
         // 0042d7e0: mov esp, ebp
         // 0042d7e2: pop ebp
         // 0042d7e3: retn 
      [-]6a006aff506a006aff6aff6a0056e8
         // 0042ea57: push 0x0
         // 0042ea59: push 0xffffffffffffffff
         // 0042ea5b: push eax
         // 0042ea5c: push 0x0
         // 0042ea5e: push 0xffffffffffffffff
         // 0042ea60: push 0xffffffffffffffff
         // 0042ea62: push 0x0
         // 0042ea64: push esi
         // 0042ea65: call 0x419f60
      [-]ff83c420
         // 0042ea6a: add esp, 0x20
      [-]5b8be55dc3
         // 0055dd91: pop ebx
         // 0055dd92: mov esp, ebp
         // 0055dd94: pop ebp
         // 0055dd95: retn 
      [-]568d45fc
         // 0052f2f5: push esi
         // 0052f2f6: lea eax, ss:[ebp+0xfffffffffffffffc]
      [-]5056ff750cff7508e8
         // 0052f2fb: push eax
         // 0052f2fc: push esi
         // 0052f2fd: push ss:[ebp+0xc]
         // 0052f300: push ss:[ebp+0x8]
         // 0052f303: call 0x5390c0
      [-]578d0445????????50
         // 0042d83a: push edi
         // 0042d83b: lea eax, ds:[0x1+eax*0x2]
         // 0042d842: push eax
      [-]80f9207e14
         // 0055ddf0: cmp b1 cl, b1 0x20
         // 0055ddf3: jle 0x55de09
      [-]80f97f740f
         // 0055ddf5: cmp b1 cl, b1 0x7f
         // 0055ddf8: jz 0x55de09
      [-]80f927740a
         // 0055ddfa: cmp b1 cl, b1 0x27
         // 0055ddfd: jz 0x55de09
      [-]80f9227405
         // 0055ddff: cmp b1 cl, b1 0x22
         // 0055de02: jz 0x55de09
      [-]80f95c7505
         // 0055de04: cmp b1 cl, b1 0x5c
         // 0055de07: jnz 0x55de0e
      [-]c604375c46
         // 0055de09: mov b1 ds:[edi+esi], b1 0x5c
         // 0055de0d: inc esi
      [-]880c37468a
         // 0055de0f: mov b1 ds:[edi+esi], b1 cl
         // 0055de12: inc esi
         // 0055de13: mov b1 cl, b1 ds:[eax]
      [-]84c975d7
         // 0055de15: test b1 cl, b1 cl
         // 0055de17: jnz 0x55ddf0
      [-]558bec83ec6ca1
         // 0042d8a0: push ebp
         // 0042d8a1: mov ebp, esp
         // 0042d8a3: sub esp, 0x6c
         // 0042d8a6: mov eax, ds:[___security_cookie]
      [-]0033c58945fc8b450c53
         // 0042d8ab: xor eax, ebp
         // 0042d8ad: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0042d8b0: mov eax, ss:[ebp+0xc]
         // 0042d8b3: push ebx
      [-]000083c404
         // 0042d8e0: add esp, 0x4
      [-]04000083c404
         // 0042eb6a: add esp, 0x4
      [-]5e5b8b4dfc33cde8
         // 00530326: pop esi
         // 00530327: pop ebx
         // 00530328: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0053032b: xor ecx, ebp
         // 0053032d: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 00530332: mov esp, ebp
         // 00530334: pop ebp
         // 00530335: retn 
      [-]83f8ff75
         // 0055dfd0: cmp eax, 0xffffffffffffffff
         // 0055dfd3: jnz 0x55dff8
      [-]5b8b4dfc33cde8
         // 0042f3e9: pop ebx
         // 0042f3ea: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0042f3ed: xor ecx, ebp
         // 0042f3ef: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 0042f3f4: mov esp, ebp
         // 0042f3f6: pop ebp
         // 0042f3f7: retn 
      [-]6af6ff15
         // 004ea797: push 0xfffffffffffffff6
         // 004ea799: call ds:[GetStdHandle]
      [-]94894598ff15
         // 004ea7a6: mov ss:[ebp+0xffffffffffffff98], eax
         // 004ea7a9: call ds:[GetFileType]
      [-]83f80374
         // 004ea7af: cmp eax, 0x3
         // 004ea7b2: jz 0x4ea7c9
      [-]ba????????eb0a
         // 0055e029: mov edx, 0x3e8
         // 0055e02e: jmp 0x55e03a
      [-]526a008d
         // 0055e040: push edx
         // 0055e041: push 0x0
         // 0055e043: lea ecx, ss:[ebp+0xffffffffffffff94]
      [-]83e8000f84
         // 0055e04e: sub eax, 0x0
         // 0055e051: jz 0x55e163
      [-]83e8010f84
         // 0055e057: sub eax, 0x1
         // 0055e05a: jz 0x55e116
      [-]2d????????0f85
         // 0055e060: sub eax, 0x101
         // 0055e065: jnz 0x55e235
      [-]0f1f440000
         // 0055e06b: nop ds:[eax+eax+0x0]
      [-]68????????6a01
         // 0042dae2: push 0x3fff
         // 0042dae7: push 0x1
      [-]83c41081fe????????0f84
         // 0042daee: add esp, 0x10
         // 0042daf1: cmp esi, 0x10000000
         // 0042daf7: jz 0x42db8f
      [-]81fe????????0f84
         // 0055e09d: cmp esi, 0x10000001
         // 0055e0a3: jz 0x55e235
      [-]6a008d45
         // 0055e0b6: push 0x0
         // 0055e0b8: lea eax, ss:[ebp+0xffffffffffffffc0]
      [-]506a006a006a00ff75
         // 0055e0bb: push eax
         // 0055e0bc: push 0x0
         // 0055e0be: push 0x0
         // 0055e0c0: push 0x0
         // 0055e0c2: push ss:[ebp+0xffffffffffffffb0]
      [-]6a008d45
         // 00530519: push 0x0
         // 0053051b: lea eax, ss:[ebp+0xffffffffffffffc0]
      [-]5068????????
         // 0053051e: push eax
         // 0053051f: push 0x4001
      [-]6a008d45
         // 00530556: push 0x0
         // 00530558: lea eax, ss:[ebp+0xffffffffffffffc0]
      [-]5068????????
         // 0053055b: push eax
         // 0053055c: push 0x4001
      [-]e9d2000000
         // 0055e15e: jmp 0x55e235
      [-]8d45d050ff75
         // 0055e163: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 0055e166: push eax
         // 0055e167: push ss:[ebp+0xffffffffffffffb8]
      [-]ff55a083f8ff75
         // 0055e16d: call ss:[ebp+0xffffffffffffffa0]
         // 0055e170: cmp eax, 0xffffffffffffffff
         // 0055e173: jnz 0x55e1a8
      [-]3d????????0f84
         // 0055e17b: cmp eax, 0x2734
         // 0055e180: jz 0x55e235
      [-]e98d000000
         // 005305e3: jmp 0x530675
      [-]f645d00174
         // 0055e1a8: test b1 ss:[ebp+0xffffffffffffffd0], b1 0x1
         // 0055e1ac: jz 0x55e223
      [-]8d459c5068????????
         // 0042ee7e: lea eax, ss:[ebp+0xffffffffffffff9c]
         // 0042ee81: push eax
         // 0042ee82: push 0x3fff
      [-]83c41483fe5174
         // 0042ee93: add esp, 0x14
         // 0042ee96: cmp esi, 0x51
         // 0042ee99: jz 0x42ef05
      [-]83380074
         // 0055e205: cmp ds:[eax], 0x0
         // 0055e208: jz 0x55e223
      [-]8378040075
         // 0055e20a: cmp ds:[eax+0x4], 0x0
         // 0055e20e: jnz 0x55e223
      [-]00008b45
         // 0042eee6: mov eax, ss:[ebp+0xffffffffffffffa8]
      [-]83c404c74004????????
         // 0042eee9: add esp, 0x4
         // 0042eeec: mov ds:[eax+0x4], 0x1
      [-]f645d020
         // 00530663: test b1 ss:[ebp+0xffffffffffffffd0], b1 0x20
      [-]8b4dfc5f
         // 0042efbc: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0042efbf: pop edi
      [-]33cd5be8
         // 0042efc1: xor ecx, ebp
         // 0042efc3: pop ebx
         // 0042efc4: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 0042efc9: mov esp, ebp
         // 0042efcb: pop ebp
         // 0042efcc: retn 
      [-]558bec81ec????????a1
         // 0042ddb0: push ebp
         // 0042ddb1: mov ebp, esp
         // 0042ddb3: sub esp, 0x188
         // 0042ddb9: mov eax, ds:[___security_cookie]
      [-]0033c58945fc8b
         // 0042ddbe: xor eax, ebp
         // 0042ddc0: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0042ddc3: mov eax, ss:[ebp+0x8]
      [-]8d85????????68
         // 0042dde7: lea eax, ss:[ebp+0xfffffffffffffe7c]
         // 0042dded: push 0x45ddf0
      [-]68????????50e8
         // 0042ddf2: push 0x100
         // 0042ddf7: push eax
         // 0042ddf8: call _snprintf
      [-]8d85????????50ffb6
         // 0042ddfd: lea eax, ss:[ebp+0xfffffffffffffe7c]
         // 0042de03: push eax
         // 0042de04: push ds:[esi+0x18a8]
      [-]ff83c418
         // 0042de0f: add esp, 0x18
      [-]ff83c404899e
         // 0042f0a1: add esp, 0x4
         // 0042f0a4: mov ds:[esi+0x18a8], ebx
      [-]8d431b5f5e5b8b4dfc33cde8
         // 0042f0aa: lea eax, ds:[ebx+0x1b]
         // 0042f0ad: pop edi
         // 0042f0ae: pop esi
         // 0042f0af: pop ebx
         // 0042f0b0: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0042f0b3: xor ecx, ebp
         // 0042f0b5: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 0042f0ba: mov esp, ebp
         // 0042f0bc: pop ebp
         // 0042f0bd: retn 
      [-]8d85????????508d85????????5068
         // 0042f0e0: lea eax, ss:[ebp+0xfffffffffffffe7c]
         // 0042f0e6: push eax
         // 0042f0e7: lea eax, ss:[ebp+0xffffffffffffff7c]
         // 0042f0ed: push eax
         // 0042f0ee: push 0x45edf0
      [-]ff83c41083f8020f85
         // 0042f0fa: add esp, 0x10
         // 0042f0fd: cmp eax, 0x2
         // 0042f100: jnz 0x42f20c
      [-]8d85????????68
         // 0042de86: lea eax, ss:[ebp+0xffffffffffffff7c]
         // 0042de8c: push 0x45de10
      [-]6a1f8d85????????508d86??
         // 0053087e: push 0x1f
         // 00530880: lea eax, ss:[ebp+0xfffffffffffffe7c]
         // 00530886: push eax
         // 00530887: lea eax, ds:[esi+0x1808]
      [-]83c40c889e27
         // 00530893: add esp, 0xc
         // 00530896: mov b1 ds:[esi+0x1827], b1 bl
      [-]0000c786????????????????e9
         // 0053089c: mov ds:[esi+0x868], 0x1
         // 005308a6: jmp 0x53092e
      [-]8d85????????68
         // 0042decb: lea eax, ss:[ebp+0xffffffffffffff7c]
         // 0042ded1: push 0x45e314
      [-]6a7f8d85????????508d86??
         // 0042f163: push 0x7f
         // 0042f165: lea eax, ss:[ebp+0xfffffffffffffe7c]
         // 0042f16b: push eax
         // 0042f16c: lea eax, ds:[esi+0x1828]
      [-]83c40c889ea7
         // 0042f178: add esp, 0xc
         // 0042f17b: mov b1 ds:[esi+0x18a7], b1 bl
      [-]0000c786????????????????
         // 0042f181: mov ds:[esi+0x894], 0x1
      [-]8d85????????68
         // 0042df0d: lea eax, ss:[ebp+0xffffffffffffff7c]
         // 0042df13: push 0x45de18
      [-]8d85????????50ffb6
         // 0042f1a5: lea eax, ss:[ebp+0xfffffffffffffe7c]
         // 0042f1ab: push eax
         // 0042f1ac: push ds:[esi+0x18a8]
      [-]ff83c408
         // 0042f1b7: add esp, 0x8
      [-]c786????????????????
         // 0055e4e4: mov ds:[esi+0x8a4], 0x1
      [-]5b8b4dfc33cde8
         // 0052fa3d: pop ebx
         // 0052fa3e: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0052fa41: xor ecx, ebp
         // 0052fa43: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 0052fa48: mov esp, ebp
         // 0052fa4a: pop ebp
         // 0052fa4b: retn 
      [-]ffb5????????e8
         // 0042df7a: push ss:[ebp+0xfffffffffffffe78]
         // 0042df80: call 0x420110
      [-]ffb5????????e8
         // 0042df93: push ss:[ebp+0xfffffffffffffe78]
         // 0042df99: call 0x420110
      [-]ff83c404c786
         // 0042f231: add esp, 0x4
         // 0042f234: mov ds:[esi+0x18a8], 0x0
      [-]5f5e33cd5be8
         // 0052faa3: pop edi
         // 0052faa4: pop esi
         // 0052faa5: xor ecx, ebp
         // 0052faa7: pop ebx
         // 0052faa8: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 0052faad: mov esp, ebp
         // 0052faaf: pop ebp
         // 0052fab0: retn 
      [-]558bec81ec????????a1
         // 0042dfe0: push ebp
         // 0042dfe1: mov ebp, esp
         // 0042dfe3: sub esp, 0x194
         // 0042dfe9: mov eax, ds:[___security_cookie]
      [-]0033c58945fc568b75088d85????????506a02ff15
         // 0042dfee: xor eax, ebp
         // 0042dff0: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0042dff3: push esi
         // 0042dff4: mov esi, ss:[ebp+0x8]
         // 0042dff7: lea eax, ss:[ebp+0xfffffffffffffe6c]
         // 0042dffd: push eax
         // 0042dffe: push 0x2
         // 0042e000: call ds:[WSAStartup]
      [-]5e8b4dfc33cde8
         // 0042e01e: pop esi
         // 0042e01f: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0042e022: xor ecx, ebp
         // 0042e024: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 0042e029: mov esp, ebp
         // 0042e02b: pop ebp
         // 0042e02c: retn 
      [-]8b85????????3c027518
         // 0042f2b3: mov eax, ss:[ebp+0xfffffffffffffe6c]
         // 0042f2b9: cmp b1 al, b1 0x2
         // 0042f2bb: jnz 0x42f2d5
      [-]c1e80884c07511
         // 0055e5dd: shr eax, b1 0x8
         // 0055e5e0: test b1 al, b1 al
         // 0055e5e2: jnz 0x55e5f5
      [-]5e8b4dfc33cde8
         // 0042f2c6: pop esi
         // 0042f2c7: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0042f2ca: xor ecx, ebp
         // 0042f2cc: call @__security_check_cookie@4
      [-]ff8be55dc3
         // 0042f2d1: mov esp, ebp
         // 0042f2d3: pop ebp
         // 0042f2d4: retn 
      [-]8b4dfc83c40833cd
         // 0042e060: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0042e063: add esp, 0x8
         // 0042e066: xor ecx, ebp
      [-]ff8be55dc3
         // 0042e073: mov esp, ebp
         // 0042e075: pop ebp
         // 0042e076: retn 
      [-]558bec68
         // 0042f300: push ebp
         // 0042f301: mov ebp, esp
         // 0042f303: push 0x1ab8
      [-]6a01ff15
         // 0042f308: push 0x1
         // 0042f30a: call ds:[0x5ffb44]
      [-]8b45088b008988
         // 0042e0a0: mov eax, ss:[ebp+0x8]
         // 0042e0a3: mov eax, ds:[eax]
         // 0042e0a5: mov ds:[eax+0x8664], ecx
      [-]c781????????????????c781
         // 0042e0c3: mov ds:[ecx+0x808], 0x1
         // 0042e0cd: mov ds:[ecx+0x814], 0x1
      [-]558bec538b5d085657
         // 004eaf20: push ebp
         // 004eaf21: mov ebp, esp
         // 004eaf23: push ebx
         // 004eaf24: mov ebx, ss:[ebp+0x8]
         // 004eaf27: push esi
         // 004eaf28: push edi
      [-]8b038bb8
         // 004eaf2b: mov eax, ds:[ebx]
         // 004eaf2d: mov edi, ds:[eax+0x114]
      [-]81c7????????0f1f80????????
         // 004eaf33: add edi, 0x1408
         // 004eaf39: nop ds:[eax+0x0]
      [-]83bf????????01750c
         // 0055e6b0: cmp ds:[edi+0xfffffffffffff400], 0x1
         // 0055e6b7: jnz 0x55e6c5
      [-]6a015653e8
         // 0055e6b9: push 0x1
         // 0055e6bb: push esi
         // 0055e6bc: push ebx
         // 0055e6bd: call 0x55ee90
      [-]000083c40c
         // 0055e6c2: add esp, 0xc
      [-]833f01750c
         // 0055e6c5: cmp ds:[edi], 0x1
         // 0055e6c8: jnz 0x55e6d6
      [-]6a015653e8
         // 0055e6ca: push 0x1
         // 0055e6cc: push esi
         // 0055e6cd: push ebx
         // 0055e6ce: call 0x55ef30
      [-]000083c40c
         // 0055e6d3: add esp, 0xc
      [-]4683c70483fe287c
         // 0055e6d6: inc esi
         // 0055e6d7: add edi, 0x4
         // 0055e6da: cmp esi, 0x28
         // 0055e6dd: jl 0x55e6b0
      [-]5f5e5b5dc3
         // 0055e6df: pop edi
         // 0055e6e0: pop esi
         // 0055e6e1: pop ebx
         // 0055e6e2: pop ebp
         // 0055e6e3: retn 
      [-]558bec8b5508
         // 0055e6f0: push ebp
         // 0055e6f1: mov ebp, esp
         // 0055e6f3: mov edx, ss:[ebp+0x8]
      [-]000f84eb000000
         // 0055e6fd: jz 0x55e7ee
      [-]8b4d1081f9????????753c
         // 0055e703: mov ecx, ss:[ebp+0x10]
         // 0055e706: cmp ecx, 0xff
         // 0055e70c: jnz 0x55e74a
      [-]8b4d148d81????????83f813771a
         // 0055e70e: mov ecx, ss:[ebp+0x14]
         // 0055e711: lea eax, ds:[ecx+0xffffffffffffff14]
         // 0055e717: cmp eax, 0x13
         // 0055e71a: ja 0x55e736
      [-]ff750c68
         // 0042f403: push ss:[ebp+0xc]
         // 0042f406: push 0x45ecd8
      [-]83c4105dc3
         // 0042f411: add esp, 0x10
         // 0042f414: pop ebp
         // 0042f415: retn 
      [-]51ff750c68
         // 0042f416: push ecx
         // 0042f417: push ss:[ebp+0xc]
         // 0042f41a: push 0x45ece4
      [-]83c4105dc3
         // 0042f425: add esp, 0x10
         // 0042f428: pop ebp
         // 0042f429: retn 
      [-]5681f9????????7507
         // 0055e74a: push esi
         // 0055e74b: cmp ecx, 0xfb
         // 0055e751: jnz 0x55e75a
      [-]81f9????????7507
         // 0055e75a: cmp ecx, 0xfc
         // 0055e760: jnz 0x55e769
      [-]81f9????????7507
         // 0055e769: cmp ecx, 0xfd
         // 0055e76f: jnz 0x55e778
      [-]81f9????????0f45c6
         // 0042f45f: cmp ecx, 0xfe
         // 0042f465: cmovnz eax, esi
      [-]8b4d1483f9277f21
         // 0055e78c: mov ecx, ss:[ebp+0x14]
         // 0055e78f: cmp ecx, 0x27
         // 0055e792: jg 0x55e7b5
      [-]5150ff750c68
         // 0052fcdf: push ecx
         // 0052fce0: push eax
         // 0052fce1: push ss:[ebp+0xc]
         // 0052fce4: push 0x6590c0
      [-]83c4145e5dc3
         // 0052fcef: add esp, 0x14
         // 0052fcf2: pop esi
         // 0052fcf3: pop ebp
         // 0052fcf4: retn 
      [-]81f9????????75e2
         // 0055e7b5: cmp ecx, 0xff
         // 0055e7bb: jnz 0x55e79f
      [-]5650ff750c68
         // 0042f4a2: push esi
         // 0042f4a3: push eax
         // 0042f4a4: push ss:[ebp+0xc]
         // 0042f4a7: push 0x45ecf8
      [-]83c4145e5dc3
         // 0042f4b2: add esp, 0x14
         // 0042f4b5: pop esi
         // 0042f4b6: pop ebp
         // 0042f4b7: retn 
      [-]ff751451ff750c68
         // 0042f4b8: push ss:[ebp+0x14]
         // 0042f4bb: push ecx
         // 0042f4bc: push ss:[ebp+0xc]
         // 0042f4bf: push 0x45ed10
      [-]83c4145e
         // 0042f4ca: add esp, 0x14
         // 0042f4cd: pop esi
      [-]558bec51568b7508
         // 0042e250: push ebp
         // 0042e251: mov ebp, esp
         // 0042e253: push ecx
         // 0042e254: push esi
         // 0042e255: mov esi, ss:[ebp+0x8]
      [-]8b4d0c5357
         // 0055e809: mov ecx, ss:[ebp+0xc]
         // 0055e80c: push ebx
         // 0055e80d: push edi
      [-]83f93cba
         // 0042f4f6: cmp ecx, 0x3c
         // 0042f4f9: mov edx, 0x45ed38
      [-]0f45c25068
         // 0042f503: cmovnz eax, edx
         // 0042f506: push eax
         // 0042f507: push 0x45ed48
      [-]1483c40c83
         // 0042f515: add esp, 0xc
         // 0042f518: cmp ebx, 0x3
      [-]83c40883
         // 00530cb2: add esp, 0x8
         // 00530cb5: cmp edi, 0x27
      [-]83c40c83f827770e
         // 0042f58d: add esp, 0xc
         // 0042f590: cmp eax, 0x27
         // 0042f593: ja 0x42f5a3
      [-]3d????????720e
         // 0055e8c3: cmp eax, 0xec
         // 0055e8c8: jb 0x55e8d8
      [-]83c40c68
         // 0042f5c4: add esp, 0xc
         // 0042f5c7: push 0x45ed68
      [-]83c4085f5b5e8be55dc3
         // 0042f5f0: add esp, 0x8
         // 0042f5f3: pop edi
         // 0042f5f4: pop ebx
         // 0042f5f5: pop esi
         // 0042f5f6: mov esp, ebp
         // 0042f5f8: pop ebp
         // 0042f5f9: retn 
      [-]80f92777
         // 00530d5f: cmp b1 cl, b1 0x27
         // 00530d62: ja 0x530d95
      [-]3c180f84
         // 0055e99d: cmp b1 al, b1 0x18
         // 0055e99f: jz 0x55ea40
      [-]3c230f84
         // 0055e9a5: cmp b1 al, b1 0x23
         // 0055e9a7: jz 0x55ea40
      [-]3c27742c
         // 0055e9ad: cmp b1 al, b1 0x27
         // 0055e9af: jz 0x55e9dd
      [-]83e800741d
         // 0042e469: sub eax, 0x0
         // 0042e46c: jz 0x42e48b
      [-]83c40ceb15
         // 0042e47f: add esp, 0xc
         // 0042e482: jmp 0x42e499
      [-]837d0c00740e
         // 0055ea56: cmp ss:[ebp+0xc], 0x0
         // 0055ea5a: jz 0x55ea6a
      [-]5e8be55dc3
         // 0055ea6c: pop esi
         // 0055ea6d: mov esp, ebp
         // 0055ea6f: pop ebp
         // 0055ea70: retn 
      [-]558bec56
         // 00530ed0: push ebp
         // 00530ed1: mov ebp, esp
         // 00530ed3: push esi
      [-]8b7d088b078b
         // 00530ed5: mov edi, ss:[ebp+0x8]
         // 00530ed8: mov eax, ds:[edi]
         // 00530eda: mov esi, ds:[eax+0x8664]
      [-]83e80074
         // 004eb39e: sub eax, 0x0
         // 004eb3a1: jz 0x4eb3bc
      [-]08????????89
         // 0055ead4: mov ds:[edx+0x408], eax
      [-]0804000083
         // 0055eaef: sub edx, 0x0
      [-]08????????89
         // 0055eb00: mov ds:[esi+eax*0x4], edx
      [-]08100000
      [-]68????????57e8
         // 0055eb08: push 0xfc
         // 0055eb0d: push edi
         // 0055eb0e: call 0x55ed70
      [-]02000083c40c
         // 0055eb13: add esp, 0xc
      [-]000001
         // 0055eb2d: jnz 0x55eb07

  }
  condition:
    all of them
}
