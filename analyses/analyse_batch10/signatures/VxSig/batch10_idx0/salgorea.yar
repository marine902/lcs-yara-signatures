rule salgorea_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec6afe68
         // 00401000: push ebp
         // 00401001: mov ebp, esp
         // 00401003: push 0xfffffffffffffffe
         // 00401005: push stru_4287A8.GSCookieOffset
      [-]0064a1000000005083ec10535657a1
         // 0040100f: mov eax, fs:[0x0]
         // 00401015: push eax
         // 00401016: sub esp, 0x10
         // 00401019: push ebx
         // 0040101a: push esi
         // 0040101b: push edi
         // 0040101c: mov eax, ds:[___security_cookie]
      [-]003145f833c5508d45f064a3000000008965e8c745e4ffffffff33ff897dfc57ff1500
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
      [-]008bd83bdf7457
         // 00401046: mov ebx, eax
         // 00401048: cmp ebx, edi
         // 0040104a: jz 0x4010a3
      [-]8b433c03c3813850450000754a
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
      [-]c745fcfeffffff8b45e48b4df064890d00000000595f5e5b8be55dc3
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
      [-]c70000000000c7400400000000c7400867e6096ac7400c85ae67bbc7401072f36e3cc740143af54fa5c740187f520e51c7401c8c68059bc74020abd9831fc7402419cde05bc3
         // 00403470: mov ds:[eax], 0x0
         // 00403476: mov ds:[eax+0x4], 0x0
         // 0040347d: mov ds:[eax+0x8], 0x6a09e667
         // 00403484: mov ds:[eax+0xc], 0xffffffffbb67ae85
         // 0040348b: mov ds:[eax+0x10], 0x3c6ef372
         // 00403492: mov ds:[eax+0x14], 0xffffffffa54ff53a
         // 00403499: mov ds:[eax+0x18], 0x510e527f
         // 004034a0: mov ds:[eax+0x1c], 0xffffffff9b05688c
         // 004034a7: mov ds:[eax+0x20], 0x1f83d9ab
         // 004034ae: mov ds:[eax+0x24], 0x5be0cd19
         // 004034b5: retn 
      [-]558bec81ec240100000fb6080fb65001c1e1080bca0fb6500253c1e1080bca0fb65003560fb67005570fb67809c1e1080bca0fb65004c1e2080bd60fb670060fb6580dc1e2080bd60fb67007c1e2080bd60fb67008c1e6080bf70fb6780ac1e6080bf70fb6780bc1e6080bf70fb6780cc1e7080bfb0fb6580ec1e7080bfb0fb6580fc1e7080bfb0fb6581189bde8feffff0fb67810c1e7080bfb0fb65812c1e7080bfb0fb65813c1e7080bfb0fb6581589bdecfeffff0fb67814c1e7080bfb0fb65816c1e7080bfb0fb65817c1e7080bfb0fb6581989bdf0feffff0fb67818c1e7080bfb0fb6581ac1e7080bfb0fb6581bc1e7080bfb89bdf4feffff0fb6781c898ddcfeffff8995e0feffff89b5e4feffffc1e7080fb6581d0bfbc1e7080fb6581e0bfbc1e7080fb6581f0bfb89bdf8feffff0fb67820c1e7080fb658210bfbc1e7080fb658220bfbc1e7080fb658230bfb89bdfcfeffff0fb67824c1e7080fb658250bfb0fb65826c1e7080bfb0fb65827c1e7080bfb89bd00ffffff0fb678280fb65829c1e7080bfb0fb6582ac1e7080bfb0fb6582bc1e7080bfb0fb6582d89bd04ffffff0fb6782cc1e7080bfb0fb6582ec1e7080bfb0fb6582fc1e7080bfb0fb6583189bd08ffffff0fb67830c1e7080bfb0fb65832c1e7080bfb0fb65833c1e7080bfb0fb6583589bd0cffffff0fb67834c1e7080bfb0fb65836c1e7080bfb0fb65837c1e7080bfb0fb6583989bd10ffffff0fb67838c1e7080bfbc1e7080fb6583a0bfb0fb6583bc1e7080bfb0fb6583d89bd14ffffff0fb6783cc1e7080bfb0fb6583e0fb6403fc1e7080bfbc1e7080bf88b45088b581c89bd18ffffff8b7808897de08b780c897de88b7810897dec8b78188b40208945dc8bc7c1c80b895de48bdfc1c30733c38b5d08897df8c1cf0633c70343248b7ddc337de4237df8337ddc03f88d8c0f982f8a428b7de88bc38b401403c1894dfc8b4de08945f08bd9c1cb0d8bc1c1c00a33d88bc1c1c80233d8035dfc8bc70bc12345ec23f98b4df00bc78bf903c38bd9c1cf0bc1c30733fbc1c90633f98b4de4334df8037ddc234df0334de403cf8d9411914437710155ec8955fc8bf8c1cf0d8bd0c1c20a33fa8b55e08bc8c1c90233f9037dfc8bc80bca234de88bd823da8b55ec0bcb03cf8bfac1cf0b8bdac1c30733fbc1ca0633fa037de48b55f83355f08bd82355ec23d93355f803d78b7de88db432cffbc0b503fe8975fc8bf1c1ce0d8bd1c1c20a33f28bd1c1ca0233f20375fc8bd00bd12355e0897de80bd303d68bf7c1ce0b8bdfc1c30733f38b5d08c1cf0633f78b7df0337dec037318237de8337df003fe8bb5e8feffff8db437a5dbb5e90175e08975fc8bfac1cf0d8bf2c1c60a33fe8bf2c1ce0233fe037dfc8bf10bf223f08bd923da0bf303f78975f48b75e08bfec1cf0b8bdec1c30733fbc1ce0633fe037df08b75ec3375e82375e03375ec03f78bbdecfeffff8db43e5bc2563903c68975fc8b75f48bdec1cb0d8bfec1c70a33df8bfec1cf0233df035dfc8bfa0bfe23f9897df88bfa23fe8b75f80bf703f38975f08bf0c1ce0b8bf8c1c70733f78bf8c1cf0633f70375ec8b7de8337de023f8337de803fe8bb5f0feffff8db437f111f15903ce8975fc8b75f08bdec1cb0d8bfec1c70a33df8bfec1cf0233df8b7df40bfe23fa897df88b7df423fe8b75f8035dfc0bf703f38975ec8bf9c1cf0b8bf1c1c60733fe8bf1c1ce0633fe037de88b75e08bd833de23d933de03df8bb5f4feffff8db433a4823f9203d68975fc8b75ec8bdec1cb0d8bfec1c70a33df8bfec1cf0233df8b7df00bfe237df4035dfc897df88b7df023fe8b75f80bf703f38975e88bf2c1ce0b8bfac1c70733f78bfac1cf0633f70375e08bf833f923fa33f803fe8bb5f8feffff8db437d55e1cab0175f48975fc8b75e88bdec1cb0d8bfec1c70a33df8bfec1cf0233df8b7dec035dfc0bfe237df0897df88b7dec23fe8b75f80bf703f38975e08b75f48bfec1cf0b8bdec1c30733fb8bdec1cb0633fb03f88b85fcfeffff8bd933da23de8b75e033d903df8b7de88d840398aa07d80145f08bdec1cb0d8945fc8bc6c1c00a33d88bc6c1c80233d8035dfc8bc723fe0bc62345ec8b75f00bc703c38bfec1cf0b8bdec1c30733fbc1ce0633fe03f98b8d00ffffff8bf23375f48bd82375f033f203f78d8c0e015b8312014dec8b75e0894dfc8bf8c1cf0d8bc8c1c10a33f98bc8c1c90233f9037dfc23de8bc80bce234de88b75ec0bcb03cf8bfec1cf0b8bdec1c30733fbc1ce0633fe8b75f43375f02375ec03fa3375f48b9504ffffff03f78d9416be8531248b75e803f28955fc8bf9c1cf0d8bd1c1c20a33fa8975e88bd1c1ca0233fa037dfc8bd00bd12355e08bd823d90bd303d78bfe8bdec1cf0bc1c30733fbc1ce0633fe037df48b75f03375ec8bd92375e823da3375f003f78bbd08ffffff8db43ec37d0c550175e08975fc8bfac1cf0d8bf2c1c60a33fe8bf2c1ce0233fe037dfc8bf10bf223f00bf303f78975f48b75e08bfe8bdec1cf0bc1c30733fbc1ce0633fe8b75ec3375e8037df02375e03375ec03f78bbd0cffffff8db43e745dbe7203c68975fc8b75f48bdec1cb0d8bfec1c70a33df8bfec1cf0233df035dfc8bfa0bfe23f9897df88bfa23fe8b75f80bf703f38975f08bf0c1ce0b8bf8c1c70733f78bf8c1cf0633f70375ec8b7de8337de023f8337de803fe8bb510ffffff8db437feb1de8003ce8975fc8b75f08bdec1cb0d8bfec1c70a33df8bfec1cf0233df035dfc8b7df40bfe23fa897df88b7df423fe8b75f80bf703f38975ec8bf9c1cf0b8bf1c1c60733fe8bf1c1ce0633fe8b75e0037de88bd833de23d933de8bb514ffffff03df8db433a706dc9b03d68975fc8b75ec8bdec1cb0d8bfec1c70a33df8bfec1cf0233df035dfc8b7df00bfe237df4897df88b7df023fe8b75f80bf703f38975e88bf2c1ce0b8bfac1c70733f78bfac1cf0633f70375e08bf833f923fa33f803fe8bb518ffffff8db43774f19bc10175f48975fc8b75e88bdec1cb0d8bfec1c70a33df8bfec1cf0233df035dfc8b7dec0bfe237df0897df88b7dec23fe8b75f80bf703f38975e08bb514ffffff8bdec1c30f8bfec1c70d33df8bbde0feffffc1ee0a33de039d00ffffff8bf7c1c60ec1cf0733f78bbde0feffffc1ef0333f703f303b5dcfeffff89b51cffffff8b75f48bfec1cf0b8bdec1c30733fb8bdec1cb0633fb8bd903bd1cffffff33da23de8b75e033d903df8d8403c1699be40145f08945fc8b5de823de8bfec1cf0d8bc6c1c00a33f88bc6c1c80233f8037dfc8b45e80bc62345ec0bc303c78945e48b8518ffffff8bd88bf8c1e80ac1c30fc1c70d33df8bbde4feffff33d8039d04ffffff8bc7c1c00ec1cf0733c78bbde4feffffc1ef0333c703c30385e0feffff898520ffffff8b45f08bf88bd8c1cf0bc1c30733fbc1c80633f803bd20ffffff8bc23345f42345f033c203c78b7de48d8c088647beef014dec8bdfc1cb0d8bc7c1c00a33d88bc7c1c80233d88bc70bc62345e823fe03d98b8d1cffffff0bc703c38bd9c1c30f8bf9c1c70d33dfc1e90a33d9039d08ffffff8bbde8feffff8bcfc1c10ec1cf0733cf8bbde8feffffc1ef0333cf03cb038de4feffff898d24ffffff8b4dec8bf9c1cf0b8bd9c1c30733fbc1c90633f903bd24ffffff8b4df4334df08bd8234dec334df403cf8d9411c69dc10f0155e88b7de4c1cb0d8bc8c1c10a33d98bc8c1c90233d903da8b9520ffffff8bcf23f80bc823ce0bcf03cb8bda8bfac1ea0ac1c30fc1c70d33df8bbdecfeffff33da039d0cffffff8bd7c1c20ec1cf0733d78bbdecfeffffc1ef0333d703d30395e8feffff899528ffffff8b55e88bfa8bdac1cf0bc1c30733fbc1ca0633fa8b55f03355ec2355e83355f003bd28ffffff8bd803d78b7df48d943acca10c2403f28955fc23d98bf9c1cf0d8bd1c1c20a33fa8bd1c1ca0233fa037dfc8bd00bd12355e40bd303d78955f48b9524ffffff8bda8bfac1ea0ac1c30fc1c70d33df8bbdf0feffff33da039d10ffffff8bd7c1c20ec1cf0733d78bbdf0feffffc1ef0333d703d30395ecfeffff8bfe89952cffffff8bd6c1ca0bc1c70733d78bfec1cf0633d703952cffffff8b7dec337de823fe337dec03fa8b55f08d94176f2ce92d0155e48955fc8b55f48bdac1cb0d8bfac1c70a33df8bfac1cf0233df035dfc8bf90bfa23f8897df88bf923fa8b55f80bd703d38955f08b9528ffffff8bdac1c30f8bfac1c70d33dfc1ea0a33da039d14ffffff8bbdf4feffff8bd7c1c20ec1cf0733d78bbdf4feffffc1ef0333d703d30395f0feffff899530ffffff8b55e48bfac1cf0b8bdac1c30733fb8bdac1cb0633fb03bd30ffffff8b5de833de23da335de88b55ec03df8d9413aa84744a03c28955fc8b55f08bdac1cb0d8bfac1c70a33df8bfac1cf0233df8b7df4035dfc0bfa23f9897df88b7df423fa8b55f80bd703d38955ec8b952cffffff8bda8bfac1c30fc1c70d33df8bbdf8feffffc1ea0a33da039d18ffffff8bd7c1c20ec1cf0733d78bbdf8feffffc1ef0333d703d30395f4feffff8bf8899534ffffffc1cf0b8bd8c1c30733fb8bd8c1cb0633fb03fa8b5de433de8b55e823d833de03df8d9413dca9b05c03ca8955fc8b55ec8bdac1cb0d8bfac1c70a33df8bfac1cf0233df035dfc8b7df00bfa237df4897df88b7df023fa8b55f80bd703d38955e88b9530ffffff8bdac1c30f8bfac1c70d33df8bbdfcfeffffc1ea0a33da039d1cffffff8bd7c1c20ec1cf0733d78bbdfcfeffffc1ef0333d703d30395f8feffff8bf9899538ffffffc1cf0b8bd1c1c20733fa8bd1c1ca0633fa8b55e403bd38ffffff8bda33d823d933da8b55e803df8db433da88f9760175f48975fc8bfac1cf0d8bf2c1c60a33fe8bf2c1ce0233fe037dfc8b75ec0bf22375f08b5dec23da0bf303f78975e08bb534ffffff8bdec1c30f8bfec1c70d33df8bbd00ffffffc1ee0a33de039d20ffffff8bf7c1c60ec1cf0733f78bbd00ffffffc1ef0333f703f303b5fcfeffff89b53cffffff8b75f48bfec1cf0b8bdec1c30733fb8bdec1cb0633fb03bd3cffffff8bd833d923de8b75e433d803df8db43352513e980175f08975fc8b75e08bdec1cb0d8bfec1c70a33df8bfec1cf0233df035dfc8bfa0bfe237dec897df88bfa23fe8b75f80bf703f38975e48bb538ffffff8bde8bfec1c30fc1c70d33df8bbd04ffffffc1ee0a33de8bf7c1c60e039d24ffffffc1cf0733f78bbd04ffffffc1ef0333f703f303b500ffffff89b540ffffff8b75f08bfec1cf0b8bdec1c30733fbc1ce0633fe03bd40ffffff8bf13375f42375f033f103f78d84066dc631a80145ec8b75e48945fc8b7de08bdec1cb0d8bc6c1c00a33d88bc6c1c80233d8035dfc8bc60bc723c28945f88bc623c78945e48b45f80b45e403c38945f88b853cffffff8bd88bf8c1e80ac1c30fc1c70d33df8bbd08ffffff33d8039d28ffffff8bc7c1c00ec1cf0733c78bbd08ffffffc1ef0333c703c3038504ffffff898544ffffff8b45ec8bf88bd8c1cf0bc1c30733fbc1c80633f88b45f43345f02345ec3345f403bd44ffffff03c78d8c08c82703b08b45f803d1894dfc8bf8c1cf0d8bc8c1c10a33f98bc8c1c90233f9037dfc8bce0bc8234de08bde23d80bcb03cf894ddc8b8d40ffffff8bd98bf9c1e90ac1c30fc1c70d33df8bbd0cffffff33d9039d2cffffff8bcfc1c10ec1cf0733cf8bbd0cffffffc1ef0333cf03cb038d08ffffff8bfa898d48ffffff8bcac1c90bc1c70733cf8bfac1cf0633cf038d48ffffff8b7df0337dec23fa337df003f98b4df48d8c0fc77f59bf014de0894dfc8b4ddc8bd9c1cb0d8bf9c1c70a33df8bf9c1cf0233df035dfc8bf80bf923fe897df88bf823f98b4df80bcf03cb894df48b8d44ffffff8bd9c1c30f8bf9c1c70d33dfc1e90a33d9039d30ffffff8bbd10ffffff8bcfc1c10ec1cf0733cf8bbd10ffffffc1ef0333cf03cb038d0cffffff898d4cffffff8b4de08bf9c1cf0b8bd9c1c30733fb8bd9c1cb0633fb03bd4cffffff8b5dec33da23d9335dec8b4df003df8d8c0bf30be0c603f1894dfc8b4df48bd98bf9c1cb0dc1c70a33df8bf9c1cf0233df8b7ddc035dfc0bf923f8897df88b7ddc23f98b4df80bcf03cb894df08b8d48ffffff8bd98bf9c1c30fc1c70dc1e90a33df8bbd14ffffff33d9039d34ffffff8bcfc1c10ec1cf0733cf8bbd14ffffffc1ef0333cf03cb038d10ffffff8bfe898d50ffffff8bcec1c90bc1c70733cf8bfec1cf0633cf038d50ffffff8bfa337de023fe33fa03f98b4dec8d8c0f4791a7d503c1894dfc8b4df08bd9c1cb0d8bf9c1c70a33df8bf9c1cf0233df035dfc8b7df40bf9237ddc897df88b7df423f98b4df80bcf03cb894dec8b8d4cffffff8bd9c1c30f8bf9c1c70d33df8bbd18ffffffc1e90a33d9039d38ffffff8bcfc1c10ec1cf0733cf8bbd18ffffffc1ef0333cf03cb038d14ffffff8bf8c1cf0b898d54ffffff8bc8c1c10733f98bc8c1c90633f98b4de003bd54ffffff8bde33d923d833d98b4dec03df8d94135163ca060155dc8955fc8bf9c1cf0d8bd1c1c20a33fa8bd1c1ca0233fa037dfc8b55f00bd12355f48b5df023d90bd303d78955e88b9550ffffff8bdac1c30f8bfac1c70d33df8bbd1c
         // 004034c0: push ebp
         // 004034c1: mov ebp, esp
         // 004034c3: sub esp, 0x124
         // 004034c9: movzx ecx, b1 ds:[eax]
         // 004034cc: movzx edx, b1 ds:[eax+0x1]
         // 004034d0: shl ecx, b1 0x8
         // 004034d3: or ecx, edx
         // 004034d5: movzx edx, b1 ds:[eax+0x2]
         // 004034d9: push ebx
         // 004034da: shl ecx, b1 0x8
         // 004034dd: or ecx, edx
         // 004034df: movzx edx, b1 ds:[eax+0x3]
         // 004034e3: push esi
         // 004034e4: movzx esi, b1 ds:[eax+0x5]
         // 004034e8: push edi
         // 004034e9: movzx edi, b1 ds:[eax+0x9]
         // 004034ed: shl ecx, b1 0x8
         // 004034f0: or ecx, edx
         // 004034f2: movzx edx, b1 ds:[eax+0x4]
         // 004034f6: shl edx, b1 0x8
         // 004034f9: or edx, esi
         // 004034fb: movzx esi, b1 ds:[eax+0x6]
         // 004034ff: movzx ebx, b1 ds:[eax+0xd]
         // 00403503: shl edx, b1 0x8
         // 00403506: or edx, esi
         // 00403508: movzx esi, b1 ds:[eax+0x7]
         // 0040350c: shl edx, b1 0x8
         // 0040350f: or edx, esi
         // 00403511: movzx esi, b1 ds:[eax+0x8]
         // 00403515: shl esi, b1 0x8
         // 00403518: or esi, edi
         // 0040351a: movzx edi, b1 ds:[eax+0xa]
         // 0040351e: shl esi, b1 0x8
         // 00403521: or esi, edi
         // 00403523: movzx edi, b1 ds:[eax+0xb]
         // 00403527: shl esi, b1 0x8
         // 0040352a: or esi, edi
         // 0040352c: movzx edi, b1 ds:[eax+0xc]
         // 00403530: shl edi, b1 0x8
         // 00403533: or edi, ebx
         // 00403535: movzx ebx, b1 ds:[eax+0xe]
         // 00403539: shl edi, b1 0x8
         // 0040353c: or edi, ebx
         // 0040353e: movzx ebx, b1 ds:[eax+0xf]
         // 00403542: shl edi, b1 0x8
         // 00403545: or edi, ebx
         // 00403547: movzx ebx, b1 ds:[eax+0x11]
         // 0040354b: mov ss:[ebp+0xfffffffffffffee8], edi
         // 00403551: movzx edi, b1 ds:[eax+0x10]
         // 00403555: shl edi, b1 0x8
         // 00403558: or edi, ebx
         // 0040355a: movzx ebx, b1 ds:[eax+0x12]
         // 0040355e: shl edi, b1 0x8
         // 00403561: or edi, ebx
         // 00403563: movzx ebx, b1 ds:[eax+0x13]
         // 00403567: shl edi, b1 0x8
         // 0040356a: or edi, ebx
         // 0040356c: movzx ebx, b1 ds:[eax+0x15]
         // 00403570: mov ss:[ebp+0xfffffffffffffeec], edi
         // 00403576: movzx edi, b1 ds:[eax+0x14]
         // 0040357a: shl edi, b1 0x8
         // 0040357d: or edi, ebx
         // 0040357f: movzx ebx, b1 ds:[eax+0x16]
         // 00403583: shl edi, b1 0x8
         // 00403586: or edi, ebx
         // 00403588: movzx ebx, b1 ds:[eax+0x17]
         // 0040358c: shl edi, b1 0x8
         // 0040358f: or edi, ebx
         // 00403591: movzx ebx, b1 ds:[eax+0x19]
         // 00403595: mov ss:[ebp+0xfffffffffffffef0], edi
         // 0040359b: movzx edi, b1 ds:[eax+0x18]
         // 0040359f: shl edi, b1 0x8
         // 004035a2: or edi, ebx
         // 004035a4: movzx ebx, b1 ds:[eax+0x1a]
         // 004035a8: shl edi, b1 0x8
         // 004035ab: or edi, ebx
         // 004035ad: movzx ebx, b1 ds:[eax+0x1b]
         // 004035b1: shl edi, b1 0x8
         // 004035b4: or edi, ebx
         // 004035b6: mov ss:[ebp+0xfffffffffffffef4], edi
         // 004035bc: movzx edi, b1 ds:[eax+0x1c]
         // 004035c0: mov ss:[ebp+0xfffffffffffffedc], ecx
         // 004035c6: mov ss:[ebp+0xfffffffffffffee0], edx
         // 004035cc: mov ss:[ebp+0xfffffffffffffee4], esi
         // 004035d2: shl edi, b1 0x8
         // 004035d5: movzx ebx, b1 ds:[eax+0x1d]
         // 004035d9: or edi, ebx
         // 004035db: shl edi, b1 0x8
         // 004035de: movzx ebx, b1 ds:[eax+0x1e]
         // 004035e2: or edi, ebx
         // 004035e4: shl edi, b1 0x8
         // 004035e7: movzx ebx, b1 ds:[eax+0x1f]
         // 004035eb: or edi, ebx
         // 004035ed: mov ss:[ebp+0xfffffffffffffef8], edi
         // 004035f3: movzx edi, b1 ds:[eax+0x20]
         // 004035f7: shl edi, b1 0x8
         // 004035fa: movzx ebx, b1 ds:[eax+0x21]
         // 004035fe: or edi, ebx
         // 00403600: shl edi, b1 0x8
         // 00403603: movzx ebx, b1 ds:[eax+0x22]
         // 00403607: or edi, ebx
         // 00403609: shl edi, b1 0x8
         // 0040360c: movzx ebx, b1 ds:[eax+0x23]
         // 00403610: or edi, ebx
         // 00403612: mov ss:[ebp+0xfffffffffffffefc], edi
         // 00403618: movzx edi, b1 ds:[eax+0x24]
         // 0040361c: shl edi, b1 0x8
         // 0040361f: movzx ebx, b1 ds:[eax+0x25]
         // 00403623: or edi, ebx
         // 00403625: movzx ebx, b1 ds:[eax+0x26]
         // 00403629: shl edi, b1 0x8
         // 0040362c: or edi, ebx
         // 0040362e: movzx ebx, b1 ds:[eax+0x27]
         // 00403632: shl edi, b1 0x8
         // 00403635: or edi, ebx
         // 00403637: mov ss:[ebp+0xffffffffffffff00], edi
         // 0040363d: movzx edi, b1 ds:[eax+0x28]
         // 00403641: movzx ebx, b1 ds:[eax+0x29]
         // 00403645: shl edi, b1 0x8
         // 00403648: or edi, ebx
         // 0040364a: movzx ebx, b1 ds:[eax+0x2a]
         // 0040364e: shl edi, b1 0x8
         // 00403651: or edi, ebx
         // 00403653: movzx ebx, b1 ds:[eax+0x2b]
         // 00403657: shl edi, b1 0x8
         // 0040365a: or edi, ebx
         // 0040365c: movzx ebx, b1 ds:[eax+0x2d]
         // 00403660: mov ss:[ebp+0xffffffffffffff04], edi
         // 00403666: movzx edi, b1 ds:[eax+0x2c]
         // 0040366a: shl edi, b1 0x8
         // 0040366d: or edi, ebx
         // 0040366f: movzx ebx, b1 ds:[eax+0x2e]
         // 00403673: shl edi, b1 0x8
         // 00403676: or edi, ebx
         // 00403678: movzx ebx, b1 ds:[eax+0x2f]
         // 0040367c: shl edi, b1 0x8
         // 0040367f: or edi, ebx
         // 00403681: movzx ebx, b1 ds:[eax+0x31]
         // 00403685: mov ss:[ebp+0xffffffffffffff08], edi
         // 0040368b: movzx edi, b1 ds:[eax+0x30]
         // 0040368f: shl edi, b1 0x8
         // 00403692: or edi, ebx
         // 00403694: movzx ebx, b1 ds:[eax+0x32]
         // 00403698: shl edi, b1 0x8
         // 0040369b: or edi, ebx
         // 0040369d: movzx ebx, b1 ds:[eax+0x33]
         // 004036a1: shl edi, b1 0x8
         // 004036a4: or edi, ebx
         // 004036a6: movzx ebx, b1 ds:[eax+0x35]
         // 004036aa: mov ss:[ebp+0xffffffffffffff0c], edi
         // 004036b0: movzx edi, b1 ds:[eax+0x34]
         // 004036b4: shl edi, b1 0x8
         // 004036b7: or edi, ebx
         // 004036b9: movzx ebx, b1 ds:[eax+0x36]
         // 004036bd: shl edi, b1 0x8
         // 004036c0: or edi, ebx
         // 004036c2: movzx ebx, b1 ds:[eax+0x37]
         // 004036c6: shl edi, b1 0x8
         // 004036c9: or edi, ebx
         // 004036cb: movzx ebx, b1 ds:[eax+0x39]
         // 004036cf: mov ss:[ebp+0xffffffffffffff10], edi
         // 004036d5: movzx edi, b1 ds:[eax+0x38]
         // 004036d9: shl edi, b1 0x8
         // 004036dc: or edi, ebx
         // 004036de: shl edi, b1 0x8
         // 004036e1: movzx ebx, b1 ds:[eax+0x3a]
         // 004036e5: or edi, ebx
         // 004036e7: movzx ebx, b1 ds:[eax+0x3b]
         // 004036eb: shl edi, b1 0x8
         // 004036ee: or edi, ebx
         // 004036f0: movzx ebx, b1 ds:[eax+0x3d]
         // 004036f4: mov ss:[ebp+0xffffffffffffff14], edi
         // 004036fa: movzx edi, b1 ds:[eax+0x3c]
         // 004036fe: shl edi, b1 0x8
         // 00403701: or edi, ebx
         // 00403703: movzx ebx, b1 ds:[eax+0x3e]
         // 00403707: movzx eax, b1 ds:[eax+0x3f]
         // 0040370b: shl edi, b1 0x8
         // 0040370e: or edi, ebx
         // 00403710: shl edi, b1 0x8
         // 00403713: or edi, eax
         // 00403715: mov eax, ss:[ebp+0x8]
         // 00403718: mov ebx, ds:[eax+0x1c]
         // 0040371b: mov ss:[ebp+0xffffffffffffff18], edi
         // 00403721: mov edi, ds:[eax+0x8]
         // 00403724: mov ss:[ebp+0xffffffffffffffe0], edi
         // 00403727: mov edi, ds:[eax+0xc]
         // 0040372a: mov ss:[ebp+0xffffffffffffffe8], edi
         // 0040372d: mov edi, ds:[eax+0x10]
         // 00403730: mov ss:[ebp+0xffffffffffffffec], edi
         // 00403733: mov edi, ds:[eax+0x18]
         // 00403736: mov eax, ds:[eax+0x20]
         // 00403739: mov ss:[ebp+0xffffffffffffffdc], eax
         // 0040373c: mov eax, edi
         // 0040373e: ror eax, b1 0xb
         // 00403741: mov ss:[ebp+0xffffffffffffffe4], ebx
         // 00403744: mov ebx, edi
         // 00403746: rol ebx, b1 0x7
         // 00403749: xor eax, ebx
         // 0040374b: mov ebx, ss:[ebp+0x8]
         // 0040374e: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00403751: ror edi, b1 0x6
         // 00403754: xor eax, edi
         // 00403756: add eax, ds:[ebx+0x24]
         // 00403759: mov edi, ss:[ebp+0xffffffffffffffdc]
         // 0040375c: xor edi, ss:[ebp+0xffffffffffffffe4]
         // 0040375f: and edi, ss:[ebp+0xfffffffffffffff8]
         // 00403762: xor edi, ss:[ebp+0xffffffffffffffdc]
         // 00403765: add edi, eax
         // 00403767: lea ecx, ds:[edi+ecx+0x428a2f98]
         // 0040376e: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 00403771: mov eax, ebx
         // 00403773: mov eax, ds:[eax+0x14]
         // 00403776: add eax, ecx
         // 00403778: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 0040377b: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 0040377e: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00403781: mov ebx, ecx
         // 00403783: ror ebx, b1 0xd
         // 00403786: mov eax, ecx
         // 00403788: rol eax, b1 0xa
         // 0040378b: xor ebx, eax
         // 0040378d: mov eax, ecx
         // 0040378f: ror eax, b1 0x2
         // 00403792: xor ebx, eax
         // 00403794: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00403797: mov eax, edi
         // 00403799: or eax, ecx
         // 0040379b: and eax, ss:[ebp+0xffffffffffffffec]
         // 0040379e: and edi, ecx
         // 004037a0: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004037a3: or eax, edi
         // 004037a5: mov edi, ecx
         // 004037a7: add eax, ebx
         // 004037a9: mov ebx, ecx
         // 004037ab: ror edi, b1 0xb
         // 004037ae: rol ebx, b1 0x7
         // 004037b1: xor edi, ebx
         // 004037b3: ror ecx, b1 0x6
         // 004037b6: xor edi, ecx
         // 004037b8: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 004037bb: xor ecx, ss:[ebp+0xfffffffffffffff8]
         // 004037be: add edi, ss:[ebp+0xffffffffffffffdc]
         // 004037c1: and ecx, ss:[ebp+0xfffffffffffffff0]
         // 004037c4: xor ecx, ss:[ebp+0xffffffffffffffe4]
         // 004037c7: add ecx, edi
         // 004037c9: lea edx, ds:[ecx+edx+0x71374491]
         // 004037d0: add ss:[ebp+0xffffffffffffffec], edx
         // 004037d3: mov ss:[ebp+0xfffffffffffffffc], edx
         // 004037d6: mov edi, eax
         // 004037d8: ror edi, b1 0xd
         // 004037db: mov edx, eax
         // 004037dd: rol edx, b1 0xa
         // 004037e0: xor edi, edx
         // 004037e2: mov edx, ss:[ebp+0xffffffffffffffe0]
         // 004037e5: mov ecx, eax
         // 004037e7: ror ecx, b1 0x2
         // 004037ea: xor edi, ecx
         // 004037ec: add edi, ss:[ebp+0xfffffffffffffffc]
         // 004037ef: mov ecx, eax
         // 004037f1: or ecx, edx
         // 004037f3: and ecx, ss:[ebp+0xffffffffffffffe8]
         // 004037f6: mov ebx, eax
         // 004037f8: and ebx, edx
         // 004037fa: mov edx, ss:[ebp+0xffffffffffffffec]
         // 004037fd: or ecx, ebx
         // 004037ff: add ecx, edi
         // 00403801: mov edi, edx
         // 00403803: ror edi, b1 0xb
         // 00403806: mov ebx, edx
         // 00403808: rol ebx, b1 0x7
         // 0040380b: xor edi, ebx
         // 0040380d: ror edx, b1 0x6
         // 00403810: xor edi, edx
         // 00403812: add edi, ss:[ebp+0xffffffffffffffe4]
         // 00403815: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 00403818: xor edx, ss:[ebp+0xfffffffffffffff0]
         // 0040381b: mov ebx, eax
         // 0040381d: and edx, ss:[ebp+0xffffffffffffffec]
         // 00403820: and ebx, ecx
         // 00403822: xor edx, ss:[ebp+0xfffffffffffffff8]
         // 00403825: add edx, edi
         // 00403827: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 0040382a: lea esi, ds:[edx+esi+0xffffffffb5c0fbcf]
         // 00403831: add edi, esi
         // 00403833: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00403836: mov esi, ecx
         // 00403838: ror esi, b1 0xd
         // 0040383b: mov edx, ecx
         // 0040383d: rol edx, b1 0xa
         // 00403840: xor esi, edx
         // 00403842: mov edx, ecx
         // 00403844: ror edx, b1 0x2
         // 00403847: xor esi, edx
         // 00403849: add esi, ss:[ebp+0xfffffffffffffffc]
         // 0040384c: mov edx, eax
         // 0040384e: or edx, ecx
         // 00403850: and edx, ss:[ebp+0xffffffffffffffe0]
         // 00403853: mov ss:[ebp+0xffffffffffffffe8], edi
         // 00403856: or edx, ebx
         // 00403858: add edx, esi
         // 0040385a: mov esi, edi
         // 0040385c: ror esi, b1 0xb
         // 0040385f: mov ebx, edi
         // 00403861: rol ebx, b1 0x7
         // 00403864: xor esi, ebx
         // 00403866: mov ebx, ss:[ebp+0x8]
         // 00403869: ror edi, b1 0x6
         // 0040386c: xor esi, edi
         // 0040386e: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 00403871: xor edi, ss:[ebp+0xffffffffffffffec]
         // 00403874: add esi, ds:[ebx+0x18]
         // 00403877: and edi, ss:[ebp+0xffffffffffffffe8]
         // 0040387a: xor edi, ss:[ebp+0xfffffffffffffff0]
         // 0040387d: add edi, esi
         // 0040387f: mov esi, ss:[ebp+0xfffffffffffffee8]
         // 00403885: lea esi, ds:[edi+esi+0xffffffffe9b5dba5]
         // 0040388c: add ss:[ebp+0xffffffffffffffe0], esi
         // 0040388f: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00403892: mov edi, edx
         // 00403894: ror edi, b1 0xd
         // 00403897: mov esi, edx
         // 00403899: rol esi, b1 0xa
         // 0040389c: xor edi, esi
         // 0040389e: mov esi, edx
         // 004038a0: ror esi, b1 0x2
         // 004038a3: xor edi, esi
         // 004038a5: add edi, ss:[ebp+0xfffffffffffffffc]
         // 004038a8: mov esi, ecx
         // 004038aa: or esi, edx
         // 004038ac: and esi, eax
         // 004038ae: mov ebx, ecx
         // 004038b0: and ebx, edx
         // 004038b2: or esi, ebx
         // 004038b4: add esi, edi
         // 004038b6: mov ss:[ebp+0xfffffffffffffff4], esi
         // 004038b9: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 004038bc: mov edi, esi
         // 004038be: ror edi, b1 0xb
         // 004038c1: mov ebx, esi
         // 004038c3: rol ebx, b1 0x7
         // 004038c6: xor edi, ebx
         // 004038c8: ror esi, b1 0x6
         // 004038cb: xor edi, esi
         // 004038cd: add edi, ss:[ebp+0xfffffffffffffff0]
         // 004038d0: mov esi, ss:[ebp+0xffffffffffffffec]
         // 004038d3: xor esi, ss:[ebp+0xffffffffffffffe8]
         // 004038d6: and esi, ss:[ebp+0xffffffffffffffe0]
         // 004038d9: xor esi, ss:[ebp+0xffffffffffffffec]
         // 004038dc: add esi, edi
         // 004038de: mov edi, ss:[ebp+0xfffffffffffffeec]
         // 004038e4: lea esi, ds:[esi+edi+0x3956c25b]
         // 004038eb: add eax, esi
         // 004038ed: mov ss:[ebp+0xfffffffffffffffc], esi
         // 004038f0: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 004038f3: mov ebx, esi
         // 004038f5: ror ebx, b1 0xd
         // 004038f8: mov edi, esi
         // 004038fa: rol edi, b1 0xa
         // 004038fd: xor ebx, edi
         // 004038ff: mov edi, esi
         // 00403901: ror edi, b1 0x2
         // 00403904: xor ebx, edi
         // 00403906: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00403909: mov edi, edx
         // 0040390b: or edi, esi
         // 0040390d: and edi, ecx
         // 0040390f: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00403912: mov edi, edx
         // 00403914: and edi, esi
         // 00403916: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00403919: or esi, edi
         // 0040391b: add esi, ebx
         // 0040391d: mov ss:[ebp+0xfffffffffffffff0], esi
         // 00403920: mov esi, eax
         // 00403922: ror esi, b1 0xb
         // 00403925: mov edi, eax
         // 00403927: rol edi, b1 0x7
         // 0040392a: xor esi, edi
         // 0040392c: mov edi, eax
         // 0040392e: ror edi, b1 0x6
         // 00403931: xor esi, edi
         // 00403933: add esi, ss:[ebp+0xffffffffffffffec]
         // 00403936: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 00403939: xor edi, ss:[ebp+0xffffffffffffffe0]
         // 0040393c: and edi, eax
         // 0040393e: xor edi, ss:[ebp+0xffffffffffffffe8]
         // 00403941: add edi, esi
         // 00403943: mov esi, ss:[ebp+0xfffffffffffffef0]
         // 00403949: lea esi, ds:[edi+esi+0x59f111f1]
         // 00403950: add ecx, esi
         // 00403952: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00403955: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00403958: mov ebx, esi
         // 0040395a: ror ebx, b1 0xd
         // 0040395d: mov edi, esi
         // 0040395f: rol edi, b1 0xa
         // 00403962: xor ebx, edi
         // 00403964: mov edi, esi
         // 00403966: ror edi, b1 0x2
         // 00403969: xor ebx, edi
         // 0040396b: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 0040396e: or edi, esi
         // 00403970: and edi, edx
         // 00403972: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00403975: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 00403978: and edi, esi
         // 0040397a: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 0040397d: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00403980: or esi, edi
         // 00403982: add esi, ebx
         // 00403984: mov ss:[ebp+0xffffffffffffffec], esi
         // 00403987: mov edi, ecx
         // 00403989: ror edi, b1 0xb
         // 0040398c: mov esi, ecx
         // 0040398e: rol esi, b1 0x7
         // 00403991: xor edi, esi
         // 00403993: mov esi, ecx
         // 00403995: ror esi, b1 0x6
         // 00403998: xor edi, esi
         // 0040399a: add edi, ss:[ebp+0xffffffffffffffe8]
         // 0040399d: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 004039a0: mov ebx, eax
         // 004039a2: xor ebx, esi
         // 004039a4: and ebx, ecx
         // 004039a6: xor ebx, esi
         // 004039a8: add ebx, edi
         // 004039aa: mov esi, ss:[ebp+0xfffffffffffffef4]
         // 004039b0: lea esi, ds:[ebx+esi+0xffffffff923f82a4]
         // 004039b7: add edx, esi
         // 004039b9: mov ss:[ebp+0xfffffffffffffffc], esi
         // 004039bc: mov esi, ss:[ebp+0xffffffffffffffec]
         // 004039bf: mov ebx, esi
         // 004039c1: ror ebx, b1 0xd
         // 004039c4: mov edi, esi
         // 004039c6: rol edi, b1 0xa
         // 004039c9: xor ebx, edi
         // 004039cb: mov edi, esi
         // 004039cd: ror edi, b1 0x2
         // 004039d0: xor ebx, edi
         // 004039d2: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 004039d5: or edi, esi
         // 004039d7: and edi, ss:[ebp+0xfffffffffffffff4]
         // 004039da: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004039dd: mov ss:[ebp+0xfffffffffffffff8], edi
         // 004039e0: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 004039e3: and edi, esi
         // 004039e5: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 004039e8: or esi, edi
         // 004039ea: add esi, ebx
         // 004039ec: mov ss:[ebp+0xffffffffffffffe8], esi
         // 004039ef: mov esi, edx
         // 004039f1: ror esi, b1 0xb
         // 004039f4: mov edi, edx
         // 004039f6: rol edi, b1 0x7
         // 004039f9: xor esi, edi
         // 004039fb: mov edi, edx
         // 004039fd: ror edi, b1 0x6
         // 00403a00: xor esi, edi
         // 00403a02: add esi, ss:[ebp+0xffffffffffffffe0]
         // 00403a05: mov edi, eax
         // 00403a07: xor edi, ecx
         // 00403a09: and edi, edx
         // 00403a0b: xor edi, eax
         // 00403a0d: add edi, esi
         // 00403a0f: mov esi, ss:[ebp+0xfffffffffffffef8]
         // 00403a15: lea esi, ds:[edi+esi+0xffffffffab1c5ed5]
         // 00403a1c: add ss:[ebp+0xfffffffffffffff4], esi
         // 00403a1f: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00403a22: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 00403a25: mov ebx, esi
         // 00403a27: ror ebx, b1 0xd
         // 00403a2a: mov edi, esi
         // 00403a2c: rol edi, b1 0xa
         // 00403a2f: xor ebx, edi
         // 00403a31: mov edi, esi
         // 00403a33: ror edi, b1 0x2
         // 00403a36: xor ebx, edi
         // 00403a38: mov edi, ss:[ebp+0xffffffffffffffec]
         // 00403a3b: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00403a3e: or edi, esi
         // 00403a40: and edi, ss:[ebp+0xfffffffffffffff0]
         // 00403a43: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00403a46: mov edi, ss:[ebp+0xffffffffffffffec]
         // 00403a49: and edi, esi
         // 00403a4b: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00403a4e: or esi, edi
         // 00403a50: add esi, ebx
         // 00403a52: mov ss:[ebp+0xffffffffffffffe0], esi
         // 00403a55: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 00403a58: mov edi, esi
         // 00403a5a: ror edi, b1 0xb
         // 00403a5d: mov ebx, esi
         // 00403a5f: rol ebx, b1 0x7
         // 00403a62: xor edi, ebx
         // 00403a64: mov ebx, esi
         // 00403a66: ror ebx, b1 0x6
         // 00403a69: xor edi, ebx
         // 00403a6b: add edi, eax
         // 00403a6d: mov eax, ss:[ebp+0xfffffffffffffefc]
         // 00403a73: mov ebx, ecx
         // 00403a75: xor ebx, edx
         // 00403a77: and ebx, esi
         // 00403a79: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 00403a7c: xor ebx, ecx
         // 00403a7e: add ebx, edi
         // 00403a80: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 00403a83: lea eax, ds:[ebx+eax+0xffffffffd807aa98]
         // 00403a8a: add ss:[ebp+0xfffffffffffffff0], eax
         // 00403a8d: mov ebx, esi
         // 00403a8f: ror ebx, b1 0xd
         // 00403a92: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00403a95: mov eax, esi
         // 00403a97: rol eax, b1 0xa
         // 00403a9a: xor ebx, eax
         // 00403a9c: mov eax, esi
         // 00403a9e: ror eax, b1 0x2
         // 00403aa1: xor ebx, eax
         // 00403aa3: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00403aa6: mov eax, edi
         // 00403aa8: and edi, esi
         // 00403aaa: or eax, esi
         // 00403aac: and eax, ss:[ebp+0xffffffffffffffec]
         // 00403aaf: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00403ab2: or eax, edi
         // 00403ab4: add eax, ebx
         // 00403ab6: mov edi, esi
         // 00403ab8: ror edi, b1 0xb
         // 00403abb: mov ebx, esi
         // 00403abd: rol ebx, b1 0x7
         // 00403ac0: xor edi, ebx
         // 00403ac2: ror esi, b1 0x6
         // 00403ac5: xor edi, esi
         // 00403ac7: add edi, ecx
         // 00403ac9: mov ecx, ss:[ebp+0xffffffffffffff00]
         // 00403acf: mov esi, edx
         // 00403ad1: xor esi, ss:[ebp+0xfffffffffffffff4]
         // 00403ad4: mov ebx, eax
         // 00403ad6: and esi, ss:[ebp+0xfffffffffffffff0]
         // 00403ad9: xor esi, edx
         // 00403adb: add esi, edi
         // 00403add: lea ecx, ds:[esi+ecx+0x12835b01]
         // 00403ae4: add ss:[ebp+0xffffffffffffffec], ecx
         // 00403ae7: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 00403aea: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00403aed: mov edi, eax
         // 00403aef: ror edi, b1 0xd
         // 00403af2: mov ecx, eax
         // 00403af4: rol ecx, b1 0xa
         // 00403af7: xor edi, ecx
         // 00403af9: mov ecx, eax
         // 00403afb: ror ecx, b1 0x2
         // 00403afe: xor edi, ecx
         // 00403b00: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00403b03: and ebx, esi
         // 00403b05: mov ecx, eax
         // 00403b07: or ecx, esi
         // 00403b09: and ecx, ss:[ebp+0xffffffffffffffe8]
         // 00403b0c: mov esi, ss:[ebp+0xffffffffffffffec]
         // 00403b0f: or ecx, ebx
         // 00403b11: add ecx, edi
         // 00403b13: mov edi, esi
         // 00403b15: ror edi, b1 0xb
         // 00403b18: mov ebx, esi
         // 00403b1a: rol ebx, b1 0x7
         // 00403b1d: xor edi, ebx
         // 00403b1f: ror esi, b1 0x6
         // 00403b22: xor edi, esi
         // 00403b24: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 00403b27: xor esi, ss:[ebp+0xfffffffffffffff0]
         // 00403b2a: and esi, ss:[ebp+0xffffffffffffffec]
         // 00403b2d: add edi, edx
         // 00403b2f: xor esi, ss:[ebp+0xfffffffffffffff4]
         // 00403b32: mov edx, ss:[ebp+0xffffffffffffff04]
         // 00403b38: add esi, edi
         // 00403b3a: lea edx, ds:[esi+edx+0x243185be]
         // 00403b41: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 00403b44: add esi, edx
         // 00403b46: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00403b49: mov edi, ecx
         // 00403b4b: ror edi, b1 0xd
         // 00403b4e: mov edx, ecx
         // 00403b50: rol edx, b1 0xa
         // 00403b53: xor edi, edx
         // 00403b55: mov ss:[ebp+0xffffffffffffffe8], esi
         // 00403b58: mov edx, ecx
         // 00403b5a: ror edx, b1 0x2
         // 00403b5d: xor edi, edx
         // 00403b5f: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00403b62: mov edx, eax
         // 00403b64: or edx, ecx
         // 00403b66: and edx, ss:[ebp+0xffffffffffffffe0]
         // 00403b69: mov ebx, eax
         // 00403b6b: and ebx, ecx
         // 00403b6d: or edx, ebx
         // 00403b6f: add edx, edi
         // 00403b71: mov edi, esi
         // 00403b73: mov ebx, esi
         // 00403b75: ror edi, b1 0xb
         // 00403b78: rol ebx, b1 0x7
         // 00403b7b: xor edi, ebx
         // 00403b7d: ror esi, b1 0x6
         // 00403b80: xor edi, esi
         // 00403b82: add edi, ss:[ebp+0xfffffffffffffff4]
         // 00403b85: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00403b88: xor esi, ss:[ebp+0xffffffffffffffec]
         // 00403b8b: mov ebx, ecx
         // 00403b8d: and esi, ss:[ebp+0xffffffffffffffe8]
         // 00403b90: and ebx, edx
         // 00403b92: xor esi, ss:[ebp+0xfffffffffffffff0]
         // 00403b95: add esi, edi
         // 00403b97: mov edi, ss:[ebp+0xffffffffffffff08]
         // 00403b9d: lea esi, ds:[esi+edi+0x550c7dc3]
         // 00403ba4: add ss:[ebp+0xffffffffffffffe0], esi
         // 00403ba7: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00403baa: mov edi, edx
         // 00403bac: ror edi, b1 0xd
         // 00403baf: mov esi, edx
         // 00403bb1: rol esi, b1 0xa
         // 00403bb4: xor edi, esi
         // 00403bb6: mov esi, edx
         // 00403bb8: ror esi, b1 0x2
         // 00403bbb: xor edi, esi
         // 00403bbd: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00403bc0: mov esi, ecx
         // 00403bc2: or esi, edx
         // 00403bc4: and esi, eax
         // 00403bc6: or esi, ebx
         // 00403bc8: add esi, edi
         // 00403bca: mov ss:[ebp+0xfffffffffffffff4], esi
         // 00403bcd: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 00403bd0: mov edi, esi
         // 00403bd2: mov ebx, esi
         // 00403bd4: ror edi, b1 0xb
         // 00403bd7: rol ebx, b1 0x7
         // 00403bda: xor edi, ebx
         // 00403bdc: ror esi, b1 0x6
         // 00403bdf: xor edi, esi
         // 00403be1: mov esi, ss:[ebp+0xffffffffffffffec]
         // 00403be4: xor esi, ss:[ebp+0xffffffffffffffe8]
         // 00403be7: add edi, ss:[ebp+0xfffffffffffffff0]
         // 00403bea: and esi, ss:[ebp+0xffffffffffffffe0]
         // 00403bed: xor esi, ss:[ebp+0xffffffffffffffec]
         // 00403bf0: add esi, edi
         // 00403bf2: mov edi, ss:[ebp+0xffffffffffffff0c]
         // 00403bf8: lea esi, ds:[esi+edi+0x72be5d74]
         // 00403bff: add eax, esi
         // 00403c01: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00403c04: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 00403c07: mov ebx, esi
         // 00403c09: ror ebx, b1 0xd
         // 00403c0c: mov edi, esi
         // 00403c0e: rol edi, b1 0xa
         // 00403c11: xor ebx, edi
         // 00403c13: mov edi, esi
         // 00403c15: ror edi, b1 0x2
         // 00403c18: xor ebx, edi
         // 00403c1a: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00403c1d: mov edi, edx
         // 00403c1f: or edi, esi
         // 00403c21: and edi, ecx
         // 00403c23: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00403c26: mov edi, edx
         // 00403c28: and edi, esi
         // 00403c2a: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00403c2d: or esi, edi
         // 00403c2f: add esi, ebx
         // 00403c31: mov ss:[ebp+0xfffffffffffffff0], esi
         // 00403c34: mov esi, eax
         // 00403c36: ror esi, b1 0xb
         // 00403c39: mov edi, eax
         // 00403c3b: rol edi, b1 0x7
         // 00403c3e: xor esi, edi
         // 00403c40: mov edi, eax
         // 00403c42: ror edi, b1 0x6
         // 00403c45: xor esi, edi
         // 00403c47: add esi, ss:[ebp+0xffffffffffffffec]
         // 00403c4a: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 00403c4d: xor edi, ss:[ebp+0xffffffffffffffe0]
         // 00403c50: and edi, eax
         // 00403c52: xor edi, ss:[ebp+0xffffffffffffffe8]
         // 00403c55: add edi, esi
         // 00403c57: mov esi, ss:[ebp+0xffffffffffffff10]
         // 00403c5d: lea esi, ds:[edi+esi+0xffffffff80deb1fe]
         // 00403c64: add ecx, esi
         // 00403c66: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00403c69: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00403c6c: mov ebx, esi
         // 00403c6e: ror ebx, b1 0xd
         // 00403c71: mov edi, esi
         // 00403c73: rol edi, b1 0xa
         // 00403c76: xor ebx, edi
         // 00403c78: mov edi, esi
         // 00403c7a: ror edi, b1 0x2
         // 00403c7d: xor ebx, edi
         // 00403c7f: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00403c82: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 00403c85: or edi, esi
         // 00403c87: and edi, edx
         // 00403c89: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00403c8c: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 00403c8f: and edi, esi
         // 00403c91: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00403c94: or esi, edi
         // 00403c96: add esi, ebx
         // 00403c98: mov ss:[ebp+0xffffffffffffffec], esi
         // 00403c9b: mov edi, ecx
         // 00403c9d: ror edi, b1 0xb
         // 00403ca0: mov esi, ecx
         // 00403ca2: rol esi, b1 0x7
         // 00403ca5: xor edi, esi
         // 00403ca7: mov esi, ecx
         // 00403ca9: ror esi, b1 0x6
         // 00403cac: xor edi, esi
         // 00403cae: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 00403cb1: add edi, ss:[ebp+0xffffffffffffffe8]
         // 00403cb4: mov ebx, eax
         // 00403cb6: xor ebx, esi
         // 00403cb8: and ebx, ecx
         // 00403cba: xor ebx, esi
         // 00403cbc: mov esi, ss:[ebp+0xffffffffffffff14]
         // 00403cc2: add ebx, edi
         // 00403cc4: lea esi, ds:[ebx+esi+0xffffffff9bdc06a7]
         // 00403ccb: add edx, esi
         // 00403ccd: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00403cd0: mov esi, ss:[ebp+0xffffffffffffffec]
         // 00403cd3: mov ebx, esi
         // 00403cd5: ror ebx, b1 0xd
         // 00403cd8: mov edi, esi
         // 00403cda: rol edi, b1 0xa
         // 00403cdd: xor ebx, edi
         // 00403cdf: mov edi, esi
         // 00403ce1: ror edi, b1 0x2
         // 00403ce4: xor ebx, edi
         // 00403ce6: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00403ce9: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 00403cec: or edi, esi
         // 00403cee: and edi, ss:[ebp+0xfffffffffffffff4]
         // 00403cf1: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00403cf4: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 00403cf7: and edi, esi
         // 00403cf9: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00403cfc: or esi, edi
         // 00403cfe: add esi, ebx
         // 00403d00: mov ss:[ebp+0xffffffffffffffe8], esi
         // 00403d03: mov esi, edx
         // 00403d05: ror esi, b1 0xb
         // 00403d08: mov edi, edx
         // 00403d0a: rol edi, b1 0x7
         // 00403d0d: xor esi, edi
         // 00403d0f: mov edi, edx
         // 00403d11: ror edi, b1 0x6
         // 00403d14: xor esi, edi
         // 00403d16: add esi, ss:[ebp+0xffffffffffffffe0]
         // 00403d19: mov edi, eax
         // 00403d1b: xor edi, ecx
         // 00403d1d: and edi, edx
         // 00403d1f: xor edi, eax
         // 00403d21: add edi, esi
         // 00403d23: mov esi, ss:[ebp+0xffffffffffffff18]
         // 00403d29: lea esi, ds:[edi+esi+0xffffffffc19bf174]
         // 00403d30: add ss:[ebp+0xfffffffffffffff4], esi
         // 00403d33: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00403d36: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 00403d39: mov ebx, esi
         // 00403d3b: ror ebx, b1 0xd
         // 00403d3e: mov edi, esi
         // 00403d40: rol edi, b1 0xa
         // 00403d43: xor ebx, edi
         // 00403d45: mov edi, esi
         // 00403d47: ror edi, b1 0x2
         // 00403d4a: xor ebx, edi
         // 00403d4c: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00403d4f: mov edi, ss:[ebp+0xffffffffffffffec]
         // 00403d52: or edi, esi
         // 00403d54: and edi, ss:[ebp+0xfffffffffffffff0]
         // 00403d57: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00403d5a: mov edi, ss:[ebp+0xffffffffffffffec]
         // 00403d5d: and edi, esi
         // 00403d5f: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00403d62: or esi, edi
         // 00403d64: add esi, ebx
         // 00403d66: mov ss:[ebp+0xffffffffffffffe0], esi
         // 00403d69: mov esi, ss:[ebp+0xffffffffffffff14]
         // 00403d6f: mov ebx, esi
         // 00403d71: rol ebx, b1 0xf
         // 00403d74: mov edi, esi
         // 00403d76: rol edi, b1 0xd
         // 00403d79: xor ebx, edi
         // 00403d7b: mov edi, ss:[ebp+0xfffffffffffffee0]
         // 00403d81: shr esi, b1 0xa
         // 00403d84: xor ebx, esi
         // 00403d86: add ebx, ss:[ebp+0xffffffffffffff00]
         // 00403d8c: mov esi, edi
         // 00403d8e: rol esi, b1 0xe
         // 00403d91: ror edi, b1 0x7
         // 00403d94: xor esi, edi
         // 00403d96: mov edi, ss:[ebp+0xfffffffffffffee0]
         // 00403d9c: shr edi, b1 0x3
         // 00403d9f: xor esi, edi
         // 00403da1: add esi, ebx
         // 00403da3: add esi, ss:[ebp+0xfffffffffffffedc]
         // 00403da9: mov ss:[ebp+0xffffffffffffff1c], esi
         // 00403daf: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 00403db2: mov edi, esi
         // 00403db4: ror edi, b1 0xb
         // 00403db7: mov ebx, esi
         // 00403db9: rol ebx, b1 0x7
         // 00403dbc: xor edi, ebx
         // 00403dbe: mov ebx, esi
         // 00403dc0: ror ebx, b1 0x6
         // 00403dc3: xor edi, ebx
         // 00403dc5: mov ebx, ecx
         // 00403dc7: add edi, ss:[ebp+0xffffffffffffff1c]
         // 00403dcd: xor ebx, edx
         // 00403dcf: and ebx, esi
         // 00403dd1: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 00403dd4: xor ebx, ecx
         // 00403dd6: add ebx, edi
         // 00403dd8: lea eax, ds:[ebx+eax+0xffffffffe49b69c1]
         // 00403ddf: add ss:[ebp+0xfffffffffffffff0], eax
         // 00403de2: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00403de5: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 00403de8: and ebx, esi
         // 00403dea: mov edi, esi
         // 00403dec: ror edi, b1 0xd
         // 00403def: mov eax, esi
         // 00403df1: rol eax, b1 0xa
         // 00403df4: xor edi, eax
         // 00403df6: mov eax, esi
         // 00403df8: ror eax, b1 0x2
         // 00403dfb: xor edi, eax
         // 00403dfd: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00403e00: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00403e03: or eax, esi
         // 00403e05: and eax, ss:[ebp+0xffffffffffffffec]
         // 00403e08: or eax, ebx
         // 00403e0a: add eax, edi
         // 00403e0c: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00403e0f: mov eax, ss:[ebp+0xffffffffffffff18]
         // 00403e15: mov ebx, eax
         // 00403e17: mov edi, eax
         // 00403e19: shr eax, b1 0xa
         // 00403e1c: rol ebx, b1 0xf
         // 00403e1f: rol edi, b1 0xd
         // 00403e22: xor ebx, edi
         // 00403e24: mov edi, ss:[ebp+0xfffffffffffffee4]
         // 00403e2a: xor ebx, eax
         // 00403e2c: add ebx, ss:[ebp+0xffffffffffffff04]
         // 00403e32: mov eax, edi
         // 00403e34: rol eax, b1 0xe
         // 00403e37: ror edi, b1 0x7
         // 00403e3a: xor eax, edi
         // 00403e3c: mov edi, ss:[ebp+0xfffffffffffffee4]
         // 00403e42: shr edi, b1 0x3
         // 00403e45: xor eax, edi
         // 00403e47: add eax, ebx
         // 00403e49: add eax, ss:[ebp+0xfffffffffffffee0]
         // 00403e4f: mov ss:[ebp+0xffffffffffffff20], eax
         // 00403e55: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00403e58: mov edi, eax
         // 00403e5a: mov ebx, eax
         // 00403e5c: ror edi, b1 0xb
         // 00403e5f: rol ebx, b1 0x7
         // 00403e62: xor edi, ebx
         // 00403e64: ror eax, b1 0x6
         // 00403e67: xor edi, eax
         // 00403e69: add edi, ss:[ebp+0xffffffffffffff20]
         // 00403e6f: mov eax, edx
         // 00403e71: xor eax, ss:[ebp+0xfffffffffffffff4]
         // 00403e74: and eax, ss:[ebp+0xfffffffffffffff0]
         // 00403e77: xor eax, edx
         // 00403e79: add eax, edi
         // 00403e7b: mov edi, ss:[ebp+0xffffffffffffffe4]
         // 00403e7e: lea ecx, ds:[eax+ecx+0xffffffffefbe4786]
         // 00403e85: add ss:[ebp+0xffffffffffffffec], ecx
         // 00403e88: mov ebx, edi
         // 00403e8a: ror ebx, b1 0xd
         // 00403e8d: mov eax, edi
         // 00403e8f: rol eax, b1 0xa
         // 00403e92: xor ebx, eax
         // 00403e94: mov eax, edi
         // 00403e96: ror eax, b1 0x2
         // 00403e99: xor ebx, eax
         // 00403e9b: mov eax, edi
         // 00403e9d: or eax, esi
         // 00403e9f: and eax, ss:[ebp+0xffffffffffffffe8]
         // 00403ea2: and edi, esi
         // 00403ea4: add ebx, ecx
         // 00403ea6: mov ecx, ss:[ebp+0xffffffffffffff1c]
         // 00403eac: or eax, edi
         // 00403eae: add eax, ebx
         // 00403eb0: mov ebx, ecx
         // 00403eb2: rol ebx, b1 0xf
         // 00403eb5: mov edi, ecx
         // 00403eb7: rol edi, b1 0xd
         // 00403eba: xor ebx, edi
         // 00403ebc: shr ecx, b1 0xa
         // 00403ebf: xor ebx, ecx
         // 00403ec1: add ebx, ss:[ebp+0xffffffffffffff08]
         // 00403ec7: mov edi, ss:[ebp+0xfffffffffffffee8]
         // 00403ecd: mov ecx, edi
         // 00403ecf: rol ecx, b1 0xe
         // 00403ed2: ror edi, b1 0x7
         // 00403ed5: xor ecx, edi
         // 00403ed7: mov edi, ss:[ebp+0xfffffffffffffee8]
         // 00403edd: shr edi, b1 0x3
         // 00403ee0: xor ecx, edi
         // 00403ee2: add ecx, ebx
         // 00403ee4: add ecx, ss:[ebp+0xfffffffffffffee4]
         // 00403eea: mov ss:[ebp+0xffffffffffffff24], ecx
         // 00403ef0: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 00403ef3: mov edi, ecx
         // 00403ef5: ror edi, b1 0xb
         // 00403ef8: mov ebx, ecx
         // 00403efa: rol ebx, b1 0x7
         // 00403efd: xor edi, ebx
         // 00403eff: ror ecx, b1 0x6
         // 00403f02: xor edi, ecx
         // 00403f04: add edi, ss:[ebp+0xffffffffffffff24]
         // 00403f0a: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00403f0d: xor ecx, ss:[ebp+0xfffffffffffffff0]
         // 00403f10: mov ebx, eax
         // 00403f12: and ecx, ss:[ebp+0xffffffffffffffec]
         // 00403f15: xor ecx, ss:[ebp+0xfffffffffffffff4]
         // 00403f18: add ecx, edi
         // 00403f1a: lea edx, ds:[ecx+edx+0xfc19dc6]
         // 00403f21: add ss:[ebp+0xffffffffffffffe8], edx
         // 00403f24: mov edi, ss:[ebp+0xffffffffffffffe4]
         // 00403f27: ror ebx, b1 0xd
         // 00403f2a: mov ecx, eax
         // 00403f2c: rol ecx, b1 0xa
         // 00403f2f: xor ebx, ecx
         // 00403f31: mov ecx, eax
         // 00403f33: ror ecx, b1 0x2
         // 00403f36: xor ebx, ecx
         // 00403f38: add ebx, edx
         // 00403f3a: mov edx, ss:[ebp+0xffffffffffffff20]
         // 00403f40: mov ecx, edi
         // 00403f42: and edi, eax
         // 00403f44: or ecx, eax
         // 00403f46: and ecx, esi
         // 00403f48: or ecx, edi
         // 00403f4a: add ecx, ebx
         // 00403f4c: mov ebx, edx
         // 00403f4e: mov edi, edx
         // 00403f50: shr edx, b1 0xa
         // 00403f53: rol ebx, b1 0xf
         // 00403f56: rol edi, b1 0xd
         // 00403f59: xor ebx, edi
         // 00403f5b: mov edi, ss:[ebp+0xfffffffffffffeec]
         // 00403f61: xor ebx, edx
         // 00403f63: add ebx, ss:[ebp+0xffffffffffffff0c]
         // 00403f69: mov edx, edi
         // 00403f6b: rol edx, b1 0xe
         // 00403f6e: ror edi, b1 0x7
         // 00403f71: xor edx, edi
         // 00403f73: mov edi, ss:[ebp+0xfffffffffffffeec]
         // 00403f79: shr edi, b1 0x3
         // 00403f7c: xor edx, edi
         // 00403f7e: add edx, ebx
         // 00403f80: add edx, ss:[ebp+0xfffffffffffffee8]
         // 00403f86: mov ss:[ebp+0xffffffffffffff28], edx
         // 00403f8c: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 00403f8f: mov edi, edx
         // 00403f91: mov ebx, edx
         // 00403f93: ror edi, b1 0xb
         // 00403f96: rol ebx, b1 0x7
         // 00403f99: xor edi, ebx
         // 00403f9b: ror edx, b1 0x6
         // 00403f9e: xor edi, edx
         // 00403fa0: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 00403fa3: xor edx, ss:[ebp+0xffffffffffffffec]
         // 00403fa6: and edx, ss:[ebp+0xffffffffffffffe8]
         // 00403fa9: xor edx, ss:[ebp+0xfffffffffffffff0]
         // 00403fac: add edi, ss:[ebp+0xffffffffffffff28]
         // 00403fb2: mov ebx, eax
         // 00403fb4: add edx, edi
         // 00403fb6: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 00403fb9: lea edx, ds:[edx+edi+0x240ca1cc]
         // 00403fc0: add esi, edx
         // 00403fc2: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00403fc5: and ebx, ecx
         // 00403fc7: mov edi, ecx
         // 00403fc9: ror edi, b1 0xd
         // 00403fcc: mov edx, ecx
         // 00403fce: rol edx, b1 0xa
         // 00403fd1: xor edi, edx
         // 00403fd3: mov edx, ecx
         // 00403fd5: ror edx, b1 0x2
         // 00403fd8: xor edi, edx
         // 00403fda: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00403fdd: mov edx, eax
         // 00403fdf: or edx, ecx
         // 00403fe1: and edx, ss:[ebp+0xffffffffffffffe4]
         // 00403fe4: or edx, ebx
         // 00403fe6: add edx, edi
         // 00403fe8: mov ss:[ebp+0xfffffffffffffff4], edx
         // 00403feb: mov edx, ss:[ebp+0xffffffffffffff24]
         // 00403ff1: mov ebx, edx
         // 00403ff3: mov edi, edx
         // 00403ff5: shr edx, b1 0xa
         // 00403ff8: rol ebx, b1 0xf
         // 00403ffb: rol edi, b1 0xd
         // 00403ffe: xor ebx, edi
         // 00404000: mov edi, ss:[ebp+0xfffffffffffffef0]
         // 00404006: xor ebx, edx
         // 00404008: add ebx, ss:[ebp+0xffffffffffffff10]
         // 0040400e: mov edx, edi
         // 00404010: rol edx, b1 0xe
         // 00404013: ror edi, b1 0x7
         // 00404016: xor edx, edi
         // 00404018: mov edi, ss:[ebp+0xfffffffffffffef0]
         // 0040401e: shr edi, b1 0x3
         // 00404021: xor edx, edi
         // 00404023: add edx, ebx
         // 00404025: add edx, ss:[ebp+0xfffffffffffffeec]
         // 0040402b: mov edi, esi
         // 0040402d: mov ss:[ebp+0xffffffffffffff2c], edx
         // 00404033: mov edx, esi
         // 00404035: ror edx, b1 0xb
         // 00404038: rol edi, b1 0x7
         // 0040403b: xor edx, edi
         // 0040403d: mov edi, esi
         // 0040403f: ror edi, b1 0x6
         // 00404042: xor edx, edi
         // 00404044: add edx, ss:[ebp+0xffffffffffffff2c]
         // 0040404a: mov edi, ss:[ebp+0xffffffffffffffec]
         // 0040404d: xor edi, ss:[ebp+0xffffffffffffffe8]
         // 00404050: and edi, esi
         // 00404052: xor edi, ss:[ebp+0xffffffffffffffec]
         // 00404055: add edi, edx
         // 00404057: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 0040405a: lea edx, ds:[edi+edx+0x2de92c6f]
         // 00404061: add ss:[ebp+0xffffffffffffffe4], edx
         // 00404064: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00404067: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 0040406a: mov ebx, edx
         // 0040406c: ror ebx, b1 0xd
         // 0040406f: mov edi, edx
         // 00404071: rol edi, b1 0xa
         // 00404074: xor ebx, edi
         // 00404076: mov edi, edx
         // 00404078: ror edi, b1 0x2
         // 0040407b: xor ebx, edi
         // 0040407d: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00404080: mov edi, ecx
         // 00404082: or edi, edx
         // 00404084: and edi, eax
         // 00404086: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00404089: mov edi, ecx
         // 0040408b: and edi, edx
         // 0040408d: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 00404090: or edx, edi
         // 00404092: add edx, ebx
         // 00404094: mov ss:[ebp+0xfffffffffffffff0], edx
         // 00404097: mov edx, ss:[ebp+0xffffffffffffff28]
         // 0040409d: mov ebx, edx
         // 0040409f: rol ebx, b1 0xf
         // 004040a2: mov edi, edx
         // 004040a4: rol edi, b1 0xd
         // 004040a7: xor ebx, edi
         // 004040a9: shr edx, b1 0xa
         // 004040ac: xor ebx, edx
         // 004040ae: add ebx, ss:[ebp+0xffffffffffffff14]
         // 004040b4: mov edi, ss:[ebp+0xfffffffffffffef4]
         // 004040ba: mov edx, edi
         // 004040bc: rol edx, b1 0xe
         // 004040bf: ror edi, b1 0x7
         // 004040c2: xor edx, edi
         // 004040c4: mov edi, ss:[ebp+0xfffffffffffffef4]
         // 004040ca: shr edi, b1 0x3
         // 004040cd: xor edx, edi
         // 004040cf: add edx, ebx
         // 004040d1: add edx, ss:[ebp+0xfffffffffffffef0]
         // 004040d7: mov ss:[ebp+0xffffffffffffff30], edx
         // 004040dd: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 004040e0: mov edi, edx
         // 004040e2: ror edi, b1 0xb
         // 004040e5: mov ebx, edx
         // 004040e7: rol ebx, b1 0x7
         // 004040ea: xor edi, ebx
         // 004040ec: mov ebx, edx
         // 004040ee: ror ebx, b1 0x6
         // 004040f1: xor edi, ebx
         // 004040f3: add edi, ss:[ebp+0xffffffffffffff30]
         // 004040f9: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 004040fc: xor ebx, esi
         // 004040fe: and ebx, edx
         // 00404100: xor ebx, ss:[ebp+0xffffffffffffffe8]
         // 00404103: mov edx, ss:[ebp+0xffffffffffffffec]
         // 00404106: add ebx, edi
         // 00404108: lea edx, ds:[ebx+edx+0x4a7484aa]
         // 0040410f: add eax, edx
         // 00404111: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00404114: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 00404117: mov ebx, edx
         // 00404119: ror ebx, b1 0xd
         // 0040411c: mov edi, edx
         // 0040411e: rol edi, b1 0xa
         // 00404121: xor ebx, edi
         // 00404123: mov edi, edx
         // 00404125: ror edi, b1 0x2
         // 00404128: xor ebx, edi
         // 0040412a: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 0040412d: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00404130: or edi, edx
         // 00404132: and edi, ecx
         // 00404134: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00404137: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 0040413a: and edi, edx
         // 0040413c: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 0040413f: or edx, edi
         // 00404141: add edx, ebx
         // 00404143: mov ss:[ebp+0xffffffffffffffec], edx
         // 00404146: mov edx, ss:[ebp+0xffffffffffffff2c]
         // 0040414c: mov ebx, edx
         // 0040414e: mov edi, edx
         // 00404150: rol ebx, b1 0xf
         // 00404153: rol edi, b1 0xd
         // 00404156: xor ebx, edi
         // 00404158: mov edi, ss:[ebp+0xfffffffffffffef8]
         // 0040415e: shr edx, b1 0xa
         // 00404161: xor ebx, edx
         // 00404163: add ebx, ss:[ebp+0xffffffffffffff18]
         // 00404169: mov edx, edi
         // 0040416b: rol edx, b1 0xe
         // 0040416e: ror edi, b1 0x7
         // 00404171: xor edx, edi
         // 00404173: mov edi, ss:[ebp+0xfffffffffffffef8]
         // 00404179: shr edi, b1 0x3
         // 0040417c: xor edx, edi
         // 0040417e: add edx, ebx
         // 00404180: add edx, ss:[ebp+0xfffffffffffffef4]
         // 00404186: mov edi, eax
         // 00404188: mov ss:[ebp+0xffffffffffffff34], edx
         // 0040418e: ror edi, b1 0xb
         // 00404191: mov ebx, eax
         // 00404193: rol ebx, b1 0x7
         // 00404196: xor edi, ebx
         // 00404198: mov ebx, eax
         // 0040419a: ror ebx, b1 0x6
         // 0040419d: xor edi, ebx
         // 0040419f: add edi, edx
         // 004041a1: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 004041a4: xor ebx, esi
         // 004041a6: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 004041a9: and ebx, eax
         // 004041ab: xor ebx, esi
         // 004041ad: add ebx, edi
         // 004041af: lea edx, ds:[ebx+edx+0x5cb0a9dc]
         // 004041b6: add ecx, edx
         // 004041b8: mov ss:[ebp+0xfffffffffffffffc], edx
         // 004041bb: mov edx, ss:[ebp+0xffffffffffffffec]
         // 004041be: mov ebx, edx
         // 004041c0: ror ebx, b1 0xd
         // 004041c3: mov edi, edx
         // 004041c5: rol edi, b1 0xa
         // 004041c8: xor ebx, edi
         // 004041ca: mov edi, edx
         // 004041cc: ror edi, b1 0x2
         // 004041cf: xor ebx, edi
         // 004041d1: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004041d4: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 004041d7: or edi, edx
         // 004041d9: and edi, ss:[ebp+0xfffffffffffffff4]
         // 004041dc: mov ss:[ebp+0xfffffffffffffff8], edi
         // 004041df: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 004041e2: and edi, edx
         // 004041e4: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 004041e7: or edx, edi
         // 004041e9: add edx, ebx
         // 004041eb: mov ss:[ebp+0xffffffffffffffe8], edx
         // 004041ee: mov edx, ss:[ebp+0xffffffffffffff30]
         // 004041f4: mov ebx, edx
         // 004041f6: rol ebx, b1 0xf
         // 004041f9: mov edi, edx
         // 004041fb: rol edi, b1 0xd
         // 004041fe: xor ebx, edi
         // 00404200: mov edi, ss:[ebp+0xfffffffffffffefc]
         // 00404206: shr edx, b1 0xa
         // 00404209: xor ebx, edx
         // 0040420b: add ebx, ss:[ebp+0xffffffffffffff1c]
         // 00404211: mov edx, edi
         // 00404213: rol edx, b1 0xe
         // 00404216: ror edi, b1 0x7
         // 00404219: xor edx, edi
         // 0040421b: mov edi, ss:[ebp+0xfffffffffffffefc]
         // 00404221: shr edi, b1 0x3
         // 00404224: xor edx, edi
         // 00404226: add edx, ebx
         // 00404228: add edx, ss:[ebp+0xfffffffffffffef8]
         // 0040422e: mov edi, ecx
         // 00404230: mov ss:[ebp+0xffffffffffffff38], edx
         // 00404236: ror edi, b1 0xb
         // 00404239: mov edx, ecx
         // 0040423b: rol edx, b1 0x7
         // 0040423e: xor edi, edx
         // 00404240: mov edx, ecx
         // 00404242: ror edx, b1 0x6
         // 00404245: xor edi, edx
         // 00404247: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 0040424a: add edi, ss:[ebp+0xffffffffffffff38]
         // 00404250: mov ebx, edx
         // 00404252: xor ebx, eax
         // 00404254: and ebx, ecx
         // 00404256: xor ebx, edx
         // 00404258: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 0040425b: add ebx, edi
         // 0040425d: lea esi, ds:[ebx+esi+0x76f988da]
         // 00404264: add ss:[ebp+0xfffffffffffffff4], esi
         // 00404267: mov ss:[ebp+0xfffffffffffffffc], esi
         // 0040426a: mov edi, edx
         // 0040426c: ror edi, b1 0xd
         // 0040426f: mov esi, edx
         // 00404271: rol esi, b1 0xa
         // 00404274: xor edi, esi
         // 00404276: mov esi, edx
         // 00404278: ror esi, b1 0x2
         // 0040427b: xor edi, esi
         // 0040427d: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00404280: mov esi, ss:[ebp+0xffffffffffffffec]
         // 00404283: or esi, edx
         // 00404285: and esi, ss:[ebp+0xfffffffffffffff0]
         // 00404288: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 0040428b: and ebx, edx
         // 0040428d: or esi, ebx
         // 0040428f: add esi, edi
         // 00404291: mov ss:[ebp+0xffffffffffffffe0], esi
         // 00404294: mov esi, ss:[ebp+0xffffffffffffff34]
         // 0040429a: mov ebx, esi
         // 0040429c: rol ebx, b1 0xf
         // 0040429f: mov edi, esi
         // 004042a1: rol edi, b1 0xd
         // 004042a4: xor ebx, edi
         // 004042a6: mov edi, ss:[ebp+0xffffffffffffff00]
         // 004042ac: shr esi, b1 0xa
         // 004042af: xor ebx, esi
         // 004042b1: add ebx, ss:[ebp+0xffffffffffffff20]
         // 004042b7: mov esi, edi
         // 004042b9: rol esi, b1 0xe
         // 004042bc: ror edi, b1 0x7
         // 004042bf: xor esi, edi
         // 004042c1: mov edi, ss:[ebp+0xffffffffffffff00]
         // 004042c7: shr edi, b1 0x3
         // 004042ca: xor esi, edi
         // 004042cc: add esi, ebx
         // 004042ce: add esi, ss:[ebp+0xfffffffffffffefc]
         // 004042d4: mov ss:[ebp+0xffffffffffffff3c], esi
         // 004042da: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 004042dd: mov edi, esi
         // 004042df: ror edi, b1 0xb
         // 004042e2: mov ebx, esi
         // 004042e4: rol ebx, b1 0x7
         // 004042e7: xor edi, ebx
         // 004042e9: mov ebx, esi
         // 004042eb: ror ebx, b1 0x6
         // 004042ee: xor edi, ebx
         // 004042f0: add edi, ss:[ebp+0xffffffffffffff3c]
         // 004042f6: mov ebx, eax
         // 004042f8: xor ebx, ecx
         // 004042fa: and ebx, esi
         // 004042fc: mov esi, ss:[ebp+0xffffffffffffffe4]
         // 004042ff: xor ebx, eax
         // 00404301: add ebx, edi
         // 00404303: lea esi, ds:[ebx+esi+0xffffffff983e5152]
         // 0040430a: add ss:[ebp+0xfffffffffffffff0], esi
         // 0040430d: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00404310: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 00404313: mov ebx, esi
         // 00404315: ror ebx, b1 0xd
         // 00404318: mov edi, esi
         // 0040431a: rol edi, b1 0xa
         // 0040431d: xor ebx, edi
         // 0040431f: mov edi, esi
         // 00404321: ror edi, b1 0x2
         // 00404324: xor ebx, edi
         // 00404326: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00404329: mov edi, edx
         // 0040432b: or edi, esi
         // 0040432d: and edi, ss:[ebp+0xffffffffffffffec]
         // 00404330: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00404333: mov edi, edx
         // 00404335: and edi, esi
         // 00404337: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 0040433a: or esi, edi
         // 0040433c: add esi, ebx
         // 0040433e: mov ss:[ebp+0xffffffffffffffe4], esi
         // 00404341: mov esi, ss:[ebp+0xffffffffffffff38]
         // 00404347: mov ebx, esi
         // 00404349: mov edi, esi
         // 0040434b: rol ebx, b1 0xf
         // 0040434e: rol edi, b1 0xd
         // 00404351: xor ebx, edi
         // 00404353: mov edi, ss:[ebp+0xffffffffffffff04]
         // 00404359: shr esi, b1 0xa
         // 0040435c: xor ebx, esi
         // 0040435e: mov esi, edi
         // 00404360: rol esi, b1 0xe
         // 00404363: add ebx, ss:[ebp+0xffffffffffffff24]
         // 00404369: ror edi, b1 0x7
         // 0040436c: xor esi, edi
         // 0040436e: mov edi, ss:[ebp+0xffffffffffffff04]
         // 00404374: shr edi, b1 0x3
         // 00404377: xor esi, edi
         // 00404379: add esi, ebx
         // 0040437b: add esi, ss:[ebp+0xffffffffffffff00]
         // 00404381: mov ss:[ebp+0xffffffffffffff40], esi
         // 00404387: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 0040438a: mov edi, esi
         // 0040438c: ror edi, b1 0xb
         // 0040438f: mov ebx, esi
         // 00404391: rol ebx, b1 0x7
         // 00404394: xor edi, ebx
         // 00404396: ror esi, b1 0x6
         // 00404399: xor edi, esi
         // 0040439b: add edi, ss:[ebp+0xffffffffffffff40]
         // 004043a1: mov esi, ecx
         // 004043a3: xor esi, ss:[ebp+0xfffffffffffffff4]
         // 004043a6: and esi, ss:[ebp+0xfffffffffffffff0]
         // 004043a9: xor esi, ecx
         // 004043ab: add esi, edi
         // 004043ad: lea eax, ds:[esi+eax+0xffffffffa831c66d]
         // 004043b4: add ss:[ebp+0xffffffffffffffec], eax
         // 004043b7: mov esi, ss:[ebp+0xffffffffffffffe4]
         // 004043ba: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004043bd: mov edi, ss:[ebp+0xffffffffffffffe0]
         // 004043c0: mov ebx, esi
         // 004043c2: ror ebx, b1 0xd
         // 004043c5: mov eax, esi
         // 004043c7: rol eax, b1 0xa
         // 004043ca: xor ebx, eax
         // 004043cc: mov eax, esi
         // 004043ce: ror eax, b1 0x2
         // 004043d1: xor ebx, eax
         // 004043d3: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004043d6: mov eax, esi
         // 004043d8: or eax, edi
         // 004043da: and eax, edx
         // 004043dc: mov ss:[ebp+0xfffffffffffffff8], eax
         // 004043df: mov eax, esi
         // 004043e1: and eax, edi
         // 004043e3: mov ss:[ebp+0xffffffffffffffe4], eax
         // 004043e6: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 004043e9: or eax, ss:[ebp+0xffffffffffffffe4]
         // 004043ec: add eax, ebx
         // 004043ee: mov ss:[ebp+0xfffffffffffffff8], eax
         // 004043f1: mov eax, ss:[ebp+0xffffffffffffff3c]
         // 004043f7: mov ebx, eax
         // 004043f9: mov edi, eax
         // 004043fb: shr eax, b1 0xa
         // 004043fe: rol ebx, b1 0xf
         // 00404401: rol edi, b1 0xd
         // 00404404: xor ebx, edi
         // 00404406: mov edi, ss:[ebp+0xffffffffffffff08]
         // 0040440c: xor ebx, eax
         // 0040440e: add ebx, ss:[ebp+0xffffffffffffff28]
         // 00404414: mov eax, edi
         // 00404416: rol eax, b1 0xe
         // 00404419: ror edi, b1 0x7
         // 0040441c: xor eax, edi
         // 0040441e: mov edi, ss:[ebp+0xffffffffffffff08]
         // 00404424: shr edi, b1 0x3
         // 00404427: xor eax, edi
         // 00404429: add eax, ebx
         // 0040442b: add eax, ss:[ebp+0xffffffffffffff04]
         // 00404431: mov ss:[ebp+0xffffffffffffff44], eax
         // 00404437: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0040443a: mov edi, eax
         // 0040443c: mov ebx, eax
         // 0040443e: ror edi, b1 0xb
         // 00404441: rol ebx, b1 0x7
         // 00404444: xor edi, ebx
         // 00404446: ror eax, b1 0x6
         // 00404449: xor edi, eax
         // 0040444b: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0040444e: xor eax, ss:[ebp+0xfffffffffffffff0]
         // 00404451: and eax, ss:[ebp+0xffffffffffffffec]
         // 00404454: xor eax, ss:[ebp+0xfffffffffffffff4]
         // 00404457: add edi, ss:[ebp+0xffffffffffffff44]
         // 0040445d: add eax, edi
         // 0040445f: lea ecx, ds:[eax+ecx+0xffffffffb00327c8]
         // 00404466: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00404469: add edx, ecx
         // 0040446b: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 0040446e: mov edi, eax
         // 00404470: ror edi, b1 0xd
         // 00404473: mov ecx, eax
         // 00404475: rol ecx, b1 0xa
         // 00404478: xor edi, ecx
         // 0040447a: mov ecx, eax
         // 0040447c: ror ecx, b1 0x2
         // 0040447f: xor edi, ecx
         // 00404481: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00404484: mov ecx, esi
         // 00404486: or ecx, eax
         // 00404488: and ecx, ss:[ebp+0xffffffffffffffe0]
         // 0040448b: mov ebx, esi
         // 0040448d: and ebx, eax
         // 0040448f: or ecx, ebx
         // 00404491: add ecx, edi
         // 00404493: mov ss:[ebp+0xffffffffffffffdc], ecx
         // 00404496: mov ecx, ss:[ebp+0xffffffffffffff40]
         // 0040449c: mov ebx, ecx
         // 0040449e: mov edi, ecx
         // 004044a0: shr ecx, b1 0xa
         // 004044a3: rol ebx, b1 0xf
         // 004044a6: rol edi, b1 0xd
         // 004044a9: xor ebx, edi
         // 004044ab: mov edi, ss:[ebp+0xffffffffffffff0c]
         // 004044b1: xor ebx, ecx
         // 004044b3: add ebx, ss:[ebp+0xffffffffffffff2c]
         // 004044b9: mov ecx, edi
         // 004044bb: rol ecx, b1 0xe
         // 004044be: ror edi, b1 0x7
         // 004044c1: xor ecx, edi
         // 004044c3: mov edi, ss:[ebp+0xffffffffffffff0c]
         // 004044c9: shr edi, b1 0x3
         // 004044cc: xor ecx, edi
         // 004044ce: add ecx, ebx
         // 004044d0: add ecx, ss:[ebp+0xffffffffffffff08]
         // 004044d6: mov edi, edx
         // 004044d8: mov ss:[ebp+0xffffffffffffff48], ecx
         // 004044de: mov ecx, edx
         // 004044e0: ror ecx, b1 0xb
         // 004044e3: rol edi, b1 0x7
         // 004044e6: xor ecx, edi
         // 004044e8: mov edi, edx
         // 004044ea: ror edi, b1 0x6
         // 004044ed: xor ecx, edi
         // 004044ef: add ecx, ss:[ebp+0xffffffffffffff48]
         // 004044f5: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 004044f8: xor edi, ss:[ebp+0xffffffffffffffec]
         // 004044fb: and edi, edx
         // 004044fd: xor edi, ss:[ebp+0xfffffffffffffff0]
         // 00404500: add edi, ecx
         // 00404502: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00404505: lea ecx, ds:[edi+ecx+0xffffffffbf597fc7]
         // 0040450c: add ss:[ebp+0xffffffffffffffe0], ecx
         // 0040450f: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00404512: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 00404515: mov ebx, ecx
         // 00404517: ror ebx, b1 0xd
         // 0040451a: mov edi, ecx
         // 0040451c: rol edi, b1 0xa
         // 0040451f: xor ebx, edi
         // 00404521: mov edi, ecx
         // 00404523: ror edi, b1 0x2
         // 00404526: xor ebx, edi
         // 00404528: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040452b: mov edi, eax
         // 0040452d: or edi, ecx
         // 0040452f: and edi, esi
         // 00404531: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00404534: mov edi, eax
         // 00404536: and edi, ecx
         // 00404538: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 0040453b: or ecx, edi
         // 0040453d: add ecx, ebx
         // 0040453f: mov ss:[ebp+0xfffffffffffffff4], ecx
         // 00404542: mov ecx, ss:[ebp+0xffffffffffffff44]
         // 00404548: mov ebx, ecx
         // 0040454a: rol ebx, b1 0xf
         // 0040454d: mov edi, ecx
         // 0040454f: rol edi, b1 0xd
         // 00404552: xor ebx, edi
         // 00404554: shr ecx, b1 0xa
         // 00404557: xor ebx, ecx
         // 00404559: add ebx, ss:[ebp+0xffffffffffffff30]
         // 0040455f: mov edi, ss:[ebp+0xffffffffffffff10]
         // 00404565: mov ecx, edi
         // 00404567: rol ecx, b1 0xe
         // 0040456a: ror edi, b1 0x7
         // 0040456d: xor ecx, edi
         // 0040456f: mov edi, ss:[ebp+0xffffffffffffff10]
         // 00404575: shr edi, b1 0x3
         // 00404578: xor ecx, edi
         // 0040457a: add ecx, ebx
         // 0040457c: add ecx, ss:[ebp+0xffffffffffffff0c]
         // 00404582: mov ss:[ebp+0xffffffffffffff4c], ecx
         // 00404588: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 0040458b: mov edi, ecx
         // 0040458d: ror edi, b1 0xb
         // 00404590: mov ebx, ecx
         // 00404592: rol ebx, b1 0x7
         // 00404595: xor edi, ebx
         // 00404597: mov ebx, ecx
         // 00404599: ror ebx, b1 0x6
         // 0040459c: xor edi, ebx
         // 0040459e: add edi, ss:[ebp+0xffffffffffffff4c]
         // 004045a4: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 004045a7: xor ebx, edx
         // 004045a9: and ebx, ecx
         // 004045ab: xor ebx, ss:[ebp+0xffffffffffffffec]
         // 004045ae: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004045b1: add ebx, edi
         // 004045b3: lea ecx, ds:[ebx+ecx+0xffffffffc6e00bf3]
         // 004045ba: add esi, ecx
         // 004045bc: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 004045bf: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 004045c2: mov ebx, ecx
         // 004045c4: mov edi, ecx
         // 004045c6: ror ebx, b1 0xd
         // 004045c9: rol edi, b1 0xa
         // 004045cc: xor ebx, edi
         // 004045ce: mov edi, ecx
         // 004045d0: ror edi, b1 0x2
         // 004045d3: xor ebx, edi
         // 004045d5: mov edi, ss:[ebp+0xffffffffffffffdc]
         // 004045d8: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004045db: or edi, ecx
         // 004045dd: and edi, eax
         // 004045df: mov ss:[ebp+0xfffffffffffffff8], edi
         // 004045e2: mov edi, ss:[ebp+0xffffffffffffffdc]
         // 004045e5: and edi, ecx
         // 004045e7: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 004045ea: or ecx, edi
         // 004045ec: add ecx, ebx
         // 004045ee: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 004045f1: mov ecx, ss:[ebp+0xffffffffffffff48]
         // 004045f7: mov ebx, ecx
         // 004045f9: mov edi, ecx
         // 004045fb: rol ebx, b1 0xf
         // 004045fe: rol edi, b1 0xd
         // 00404601: shr ecx, b1 0xa
         // 00404604: xor ebx, edi
         // 00404606: mov edi, ss:[ebp+0xffffffffffffff14]
         // 0040460c: xor ebx, ecx
         // 0040460e: add ebx, ss:[ebp+0xffffffffffffff34]
         // 00404614: mov ecx, edi
         // 00404616: rol ecx, b1 0xe
         // 00404619: ror edi, b1 0x7
         // 0040461c: xor ecx, edi
         // 0040461e: mov edi, ss:[ebp+0xffffffffffffff14]
         // 00404624: shr edi, b1 0x3
         // 00404627: xor ecx, edi
         // 00404629: add ecx, ebx
         // 0040462b: add ecx, ss:[ebp+0xffffffffffffff10]
         // 00404631: mov edi, esi
         // 00404633: mov ss:[ebp+0xffffffffffffff50], ecx
         // 00404639: mov ecx, esi
         // 0040463b: ror ecx, b1 0xb
         // 0040463e: rol edi, b1 0x7
         // 00404641: xor ecx, edi
         // 00404643: mov edi, esi
         // 00404645: ror edi, b1 0x6
         // 00404648: xor ecx, edi
         // 0040464a: add ecx, ss:[ebp+0xffffffffffffff50]
         // 00404650: mov edi, edx
         // 00404652: xor edi, ss:[ebp+0xffffffffffffffe0]
         // 00404655: and edi, esi
         // 00404657: xor edi, edx
         // 00404659: add edi, ecx
         // 0040465b: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 0040465e: lea ecx, ds:[edi+ecx+0xffffffffd5a79147]
         // 00404665: add eax, ecx
         // 00404667: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 0040466a: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040466d: mov ebx, ecx
         // 0040466f: ror ebx, b1 0xd
         // 00404672: mov edi, ecx
         // 00404674: rol edi, b1 0xa
         // 00404677: xor ebx, edi
         // 00404679: mov edi, ecx
         // 0040467b: ror edi, b1 0x2
         // 0040467e: xor ebx, edi
         // 00404680: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00404683: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 00404686: or edi, ecx
         // 00404688: and edi, ss:[ebp+0xffffffffffffffdc]
         // 0040468b: mov ss:[ebp+0xfffffffffffffff8], edi
         // 0040468e: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 00404691: and edi, ecx
         // 00404693: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 00404696: or ecx, edi
         // 00404698: add ecx, ebx
         // 0040469a: mov ss:[ebp+0xffffffffffffffec], ecx
         // 0040469d: mov ecx, ss:[ebp+0xffffffffffffff4c]
         // 004046a3: mov ebx, ecx
         // 004046a5: rol ebx, b1 0xf
         // 004046a8: mov edi, ecx
         // 004046aa: rol edi, b1 0xd
         // 004046ad: xor ebx, edi
         // 004046af: mov edi, ss:[ebp+0xffffffffffffff18]
         // 004046b5: shr ecx, b1 0xa
         // 004046b8: xor ebx, ecx
         // 004046ba: add ebx, ss:[ebp+0xffffffffffffff38]
         // 004046c0: mov ecx, edi
         // 004046c2: rol ecx, b1 0xe
         // 004046c5: ror edi, b1 0x7
         // 004046c8: xor ecx, edi
         // 004046ca: mov edi, ss:[ebp+0xffffffffffffff18]
         // 004046d0: shr edi, b1 0x3
         // 004046d3: xor ecx, edi
         // 004046d5: add ecx, ebx
         // 004046d7: add ecx, ss:[ebp+0xffffffffffffff14]
         // 004046dd: mov edi, eax
         // 004046df: ror edi, b1 0xb
         // 004046e2: mov ss:[ebp+0xffffffffffffff54], ecx
         // 004046e8: mov ecx, eax
         // 004046ea: rol ecx, b1 0x7
         // 004046ed: xor edi, ecx
         // 004046ef: mov ecx, eax
         // 004046f1: ror ecx, b1 0x6
         // 004046f4: xor edi, ecx
         // 004046f6: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 004046f9: add edi, ss:[ebp+0xffffffffffffff54]
         // 004046ff: mov ebx, esi
         // 00404701: xor ebx, ecx
         // 00404703: and ebx, eax
         // 00404705: xor ebx, ecx
         // 00404707: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 0040470a: add ebx, edi
         // 0040470c: lea edx, ds:[ebx+edx+0x6ca6351]
         // 00404713: add ss:[ebp+0xffffffffffffffdc], edx
         // 00404716: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00404719: mov edi, ecx
         // 0040471b: ror edi, b1 0xd
         // 0040471e: mov edx, ecx
         // 00404720: rol edx, b1 0xa
         // 00404723: xor edi, edx
         // 00404725: mov edx, ecx
         // 00404727: ror edx, b1 0x2
         // 0040472a: xor edi, edx
         // 0040472c: add edi, ss:[ebp+0xfffffffffffffffc]
         // 0040472f: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 00404732: or edx, ecx
         // 00404734: and edx, ss:[ebp+0xfffffffffffffff4]
         // 00404737: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 0040473a: and ebx, ecx
         // 0040473c: or edx, ebx
         // 0040473e: add edx, edi
         // 00404740: mov ss:[ebp+0xffffffffffffffe8], edx
         // 00404743: mov edx, ss:[ebp+0xffffffffffffff50]
         // 00404749: mov ebx, edx
         // 0040474b: rol ebx, b1 0xf
         // 0040474e: mov edi, edx
         // 00404750: rol edi, b1 0xd
         // 00404753: xor ebx, edi
         // 00404755: mov edi, ss:[ebp+0xffffffffffffff1c]
         // 0040475b: shr edx, b1 0xa
         // 0040475e: xor ebx, edx
         // 00404760: add ebx, ss:[ebp+0xffffffffffffff3c]
         // 00404766: mov edx, edi
         // 00404768: rol edx, b1 0xe
         // 0040476b: ror edi, b1 0x7
         // 0040476e: xor edx, edi
         // 00404770: mov edi, ss:[ebp+0xffffffffffffff1c]
         // 00404776: shr edi, b1 0x3
         // 00404779: xor edx, edi
         // 0040477b: add edx, ebx
         // 0040477d: add edx, ss:[ebp+0xffffffffffffff18]
         // 00404783: mov ss:[ebp+0xffffffffffffff58], edx
         // 00404789: mov edx, ss:[ebp+0xffffffffffffffdc]
         // 0040478c: mov edi, edx
         // 0040478e: ror edi, b1 0xb
         // 00404791: mov ebx, edx
         // 00404793: rol ebx, b1 0x7
         // 00404796: xor edi, ebx
         // 00404798: mov ebx, edx
         // 0040479a: ror ebx, b1 0x6
         // 0040479d: xor edi, ebx
         // 0040479f: add edi, ss:[ebp+0xffffffffffffff58]
         // 004047a5: mov ebx, esi
         // 004047a7: xor ebx, eax
         // 004047a9: and ebx, edx
         // 004047ab: mov edx, ss:[ebp+0xffffffffffffffe0]
         // 004047ae: xor ebx, esi
         // 004047b0: add ebx, edi
         // 004047b2: lea edx, ds:[ebx+edx+0x14292967]
         // 004047b9: add ss:[ebp+0xfffffffffffffff4], edx
         // 004047bc: mov ss:[ebp+0xfffffffffffffffc], edx
         // 004047bf: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 004047c2: mov ebx, edx
         // 004047c4: ror ebx, b1 0xd
         // 004047c7: mov edi, edx
         // 004047c9: rol edi, b1 0xa
         // 004047cc: xor ebx, edi
         // 004047ce: mov edi, edx
         // 004047d0: ror edi, b1 0x2
         // 004047d3: xor ebx, edi
         // 004047d5: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004047d8: mov edi, ecx
         // 004047da: or edi, edx
         // 004047dc: and edi, ss:[ebp+0xfffffffffffffff0]
         // 004047df: mov ss:[ebp+0xfffffffffffffff8], edi
         // 004047e2: mov edi, ecx
         // 004047e4: and edi, edx
         // 004047e6: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 004047e9: or edx, edi
         // 004047eb: add edx, ebx
         // 004047ed: mov ss:[ebp+0xffffffffffffffe0], edx
         // 004047f0: mov edx, ss:[ebp+0xffffffffffffff54]
         // 004047f6: mov ebx, edx
         // 004047f8: rol ebx, b1 0xf
         // 004047fb: mov edi, edx
         // 004047fd: rol edi, b1 0xd
         // 00404800: xor ebx, edi
         // 00404802: mov edi, ss:[ebp+0xffffffffffffff20]
         // 00404808: shr edx, b1 0xa
         // 0040480b: xor ebx, edx
         // 0040480d: mov edx, edi
         // 0040480f: rol edx, b1 0xe
         // 00404812: ror edi, b1 0x7
         // 00404815: add ebx, ss:[ebp+0xffffffffffffff40]
         // 0040481b: xor edx, edi
         // 0040481d: mov edi, ss:[ebp+0xffffffffffffff20]
         // 00404823: shr edi, b1 0x3
         // 00404826: xor edx, edi
         // 00404828: add edx, ebx
         // 0040482a: add edx, ss:[ebp+0xffffffffffffff1c]
         // 00404830: mov ss:[ebp+0xffffffffffffff5c], edx
         // 00404836: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 00404839: mov edi, edx
         // 0040483b: ror edi, b1 0xb
         // 0040483e: mov ebx, edx
         // 00404840: rol ebx, b1 0x7
         // 00404843: xor edi, ebx
         // 00404845: ror edx, b1 0x6
         // 00404848: xor edi, edx
         // 0040484a: add edi, ss:[ebp+0xffffffffffffff5c]
         // 00404850: mov edx, eax
         // 00404852: xor edx, ss:[ebp+0xffffffffffffffdc]
         // 00404855: and edx, ss:[ebp+0xfffffffffffffff4]
         // 00404858: xor edx, eax
         // 0040485a: add edx, edi
         // 0040485c: lea esi, ds:[edx+esi+0x27b70a85]
         // 00404863: add ss:[ebp+0xfffffffffffffff0], esi
         // 00404866: mov edx, ss:[ebp+0xffffffffffffffe0]
         // 00404869: mov ss:[ebp+0xfffffffffffffffc], esi
         // 0040486c: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 0040486f: mov ebx, edx
         // 00404871: ror ebx, b1 0xd
         // 00404874: mov esi, edx
         // 00404876: rol esi, b1 0xa
         // 00404879: xor ebx, esi
         // 0040487b: mov esi, edx
         // 0040487d: ror esi, b1 0x2
         // 00404880: xor ebx, esi
         // 00404882: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00404885: mov esi, edi
         // 00404887: or esi, edx
         // 00404889: and esi, ecx
         // 0040488b: and edi, edx
         // 0040488d: or esi, edi
         // 0040488f: add esi, ebx
         // 00404891: mov ss:[ebp+0xffffffffffffffe4], esi
         // 00404894: mov esi, ss:[ebp+0xffffffffffffff58]
         // 0040489a: mov ebx, esi
         // 0040489c: mov edi, esi
         // 0040489e: shr esi, b1 0xa
         // 004048a1: rol ebx, b1 0xf
         // 004048a4: rol edi, b1 0xd
         // 004048a7: xor ebx, edi
         // 004048a9: mov edi, ss:[ebp+0xffffffffffffff24]
         // 004048af: xor ebx, esi
         // 004048b1: add ebx, ss:[ebp+0xffffffffffffff44]
         // 004048b7: mov esi, edi
         // 004048b9: rol esi, b1 0xe
         // 004048bc: ror edi, b1 0x7
         // 004048bf: xor esi, edi
         // 004048c1: mov edi, ss:[ebp+0xffffffffffffff24]
         // 004048c7: shr edi, b1 0x3
         // 004048ca: xor esi, edi
         // 004048cc: add esi, ebx
         // 004048ce: add esi, ss:[ebp+0xffffffffffffff20]
         // 004048d4: mov ss:[ebp+0xffffffffffffff60], esi
         // 004048da: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 004048dd: mov edi, esi
         // 004048df: mov ebx, esi
         // 004048e1: ror edi, b1 0xb
         // 004048e4: rol ebx, b1 0x7
         // 004048e7: xor edi, ebx
         // 004048e9: ror esi, b1 0x6
         // 004048ec: xor edi, esi
         // 004048ee: mov esi, ss:[ebp+0xffffffffffffffdc]
         // 004048f1: xor esi, ss:[ebp+0xfffffffffffffff4]
         // 004048f4: add edi, ss:[ebp+0xffffffffffffff60]
         // 004048fa: and esi, ss:[ebp+0xfffffffffffffff0]
         // 004048fd: xor esi, ss:[ebp+0xffffffffffffffdc]
         // 00404900: add esi, edi
         // 00404902: lea eax, ds:[esi+eax+0x2e1b2138]
         // 00404909: mov esi, ss:[ebp+0xffffffffffffffe4]
         // 0040490c: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040490f: add ecx, eax
         // 00404911: mov edi, esi
         // 00404913: ror edi, b1 0xd
         // 00404916: mov eax, esi
         // 00404918: rol eax, b1 0xa
         // 0040491b: xor edi, eax
         // 0040491d: mov eax, esi
         // 0040491f: ror eax, b1 0x2
         // 00404922: xor edi, eax
         // 00404924: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00404927: mov eax, esi
         // 00404929: or eax, edx
         // 0040492b: and eax, ss:[ebp+0xffffffffffffffe8]
         // 0040492e: mov ebx, esi
         // 00404930: and ebx, edx
         // 00404932: or eax, ebx
         // 00404934: add eax, edi
         // 00404936: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00404939: mov eax, ss:[ebp+0xffffffffffffff5c]
         // 0040493f: mov ebx, eax
         // 00404941: mov edi, eax
         // 00404943: shr eax, b1 0xa
         // 00404946: rol ebx, b1 0xf
         // 00404949: rol edi, b1 0xd
         // 0040494c: xor ebx, edi
         // 0040494e: mov edi, ss:[ebp+0xffffffffffffff28]
         // 00404954: xor ebx, eax
         // 00404956: add ebx, ss:[ebp+0xffffffffffffff48]
         // 0040495c: mov eax, edi
         // 0040495e: rol eax, b1 0xe
         // 00404961: ror edi, b1 0x7
         // 00404964: xor eax, edi
         // 00404966: mov edi, ss:[ebp+0xffffffffffffff28]
         // 0040496c: shr edi, b1 0x3
         // 0040496f: xor eax, edi
         // 00404971: add eax, ebx
         // 00404973: add eax, ss:[ebp+0xffffffffffffff24]
         // 00404979: mov edi, ecx
         // 0040497b: mov ss:[ebp+0xffffffffffffff64], eax
         // 00404981: mov eax, ecx
         // 00404983: ror eax, b1 0xb
         // 00404986: rol edi, b1 0x7
         // 00404989: xor eax, edi
         // 0040498b: mov edi, ecx
         // 0040498d: ror edi, b1 0x6
         // 00404990: xor eax, edi
         // 00404992: add eax, ss:[ebp+0xffffffffffffff64]
         // 00404998: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 0040499b: xor edi, ss:[ebp+0xfffffffffffffff0]
         // 0040499e: and edi, ecx
         // 004049a0: xor edi, ss:[ebp+0xfffffffffffffff4]
         // 004049a3: add edi, eax
         // 004049a5: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 004049a8: lea eax, ds:[edi+eax+0x4d2c6dfc]
         // 004049af: add ss:[ebp+0xffffffffffffffe8], eax
         // 004049b2: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004049b5: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 004049b8: mov ebx, eax
         // 004049ba: ror ebx, b1 0xd
         // 004049bd: mov edi, eax
         // 004049bf: rol edi, b1 0xa
         // 004049c2: xor ebx, edi
         // 004049c4: mov edi, eax
         // 004049c6: ror edi, b1 0x2
         // 004049c9: xor ebx, edi
         // 004049cb: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004049ce: mov edi, esi
         // 004049d0: or edi, eax
         // 004049d2: and edi, edx
         // 004049d4: mov ss:[ebp+0xffffffffffffffe4], edi
         // 004049d7: mov edi, esi
         // 004049d9: and edi, eax
         // 004049db: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 004049de: or eax, edi
         // 004049e0: add eax, ebx
         // 004049e2: mov ss:[ebp+0xffffffffffffffdc], eax
         // 004049e5: mov eax, ss:[ebp+0xffffffffffffff60]
         // 004049eb: mov ebx, eax
         // 004049ed: rol ebx, b1 0xf
         // 004049f0: mov edi, eax
         // 004049f2: rol edi, b1 0xd
         // 004049f5: xor ebx, edi
         // 004049f7: shr eax, b1 0xa
         // 004049fa: xor ebx, eax
         // 004049fc: add ebx, ss:[ebp+0xffffffffffffff4c]
         // 00404a02: mov edi, ss:[ebp+0xffffffffffffff2c]
         // 00404a08: mov eax, edi
         // 00404a0a: rol eax, b1 0xe
         // 00404a0d: ror edi, b1 0x7
         // 00404a10: xor eax, edi
         // 00404a12: mov edi, ss:[ebp+0xffffffffffffff2c]
         // 00404a18: shr edi, b1 0x3
         // 00404a1b: xor eax, edi
         // 00404a1d: add eax, ebx
         // 00404a1f: add eax, ss:[ebp+0xffffffffffffff28]
         // 00404a25: mov ss:[ebp+0xffffffffffffff68], eax
         // 00404a2b: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00404a2e: mov edi, eax
         // 00404a30: ror edi, b1 0xb
         // 00404a33: mov ebx, eax
         // 00404a35: rol ebx, b1 0x7
         // 00404a38: xor edi, ebx
         // 00404a3a: mov ebx, eax
         // 00404a3c: ror ebx, b1 0x6
         // 00404a3f: xor edi, ebx
         // 00404a41: add edi, ss:[ebp+0xffffffffffffff68]
         // 00404a47: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00404a4a: xor ebx, ecx
         // 00404a4c: and ebx, eax
         // 00404a4e: xor ebx, ss:[ebp+0xfffffffffffffff0]
         // 00404a51: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00404a54: add ebx, edi
         // 00404a56: lea eax, ds:[ebx+eax+0x53380d13]
         // 00404a5d: add edx, eax
         // 00404a5f: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00404a62: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 00404a65: mov ebx, eax
         // 00404a67: ror ebx, b1 0xd
         // 00404a6a: mov edi, eax
         // 00404a6c: rol edi, b1 0xa
         // 00404a6f: xor ebx, edi
         // 00404a71: mov edi, eax
         // 00404a73: ror edi, b1 0x2
         // 00404a76: xor ebx, edi
         // 00404a78: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00404a7b: mov edi, ss:[ebp+0xfffffffffffffff8]
         // 00404a7e: or edi, eax
         // 00404a80: and edi, esi
         // 00404a82: mov ss:[ebp+0xffffffffffffffe4], edi
         // 00404a85: mov edi, ss:[ebp+0xfffffffffffffff8]
         // 00404a88: and edi, eax
         // 00404a8a: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00404a8d: or eax, edi
         // 00404a8f: add eax, ebx
         // 00404a91: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00404a94: mov eax, ss:[ebp+0xffffffffffffff64]
         // 00404a9a: mov ebx, eax
         // 00404a9c: mov edi, eax
         // 00404a9e: shr eax, b1 0xa
         // 00404aa1: rol ebx, b1 0xf
         // 00404aa4: rol edi, b1 0xd
         // 00404aa7: xor ebx, edi
         // 00404aa9: mov edi, ss:[ebp+0xffffffffffffff30]
         // 00404aaf: xor ebx, eax
         // 00404ab1: add ebx, ss:[ebp+0xffffffffffffff50]
         // 00404ab7: mov eax, edi
         // 00404ab9: rol eax, b1 0xe
         // 00404abc: ror edi, b1 0x7
         // 00404abf: xor eax, edi
         // 00404ac1: mov edi, ss:[ebp+0xffffffffffffff30]
         // 00404ac7: shr edi, b1 0x3
         // 00404aca: xor eax, edi
         // 00404acc: add eax, ebx
         // 00404ace: add eax, ss:[ebp+0xffffffffffffff2c]
         // 00404ad4: mov edi, edx
         // 00404ad6: mov ss:[ebp+0xffffffffffffff6c], eax
         // 00404adc: mov eax, edx
         // 00404ade: ror eax, b1 0xb
         // 00404ae1: rol edi, b1 0x7
         // 00404ae4: xor eax, edi
         // 00404ae6: mov edi, edx
         // 00404ae8: ror edi, b1 0x6
         // 00404aeb: xor eax, edi
         // 00404aed: add eax, ss:[ebp+0xffffffffffffff6c]
         // 00404af3: mov edi, ecx
         // 00404af5: xor edi, ss:[ebp+0xffffffffffffffe8]
         // 00404af8: and edi, edx
         // 00404afa: xor edi, ecx
         // 00404afc: add edi, eax
         // 00404afe: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00404b01: lea eax, ds:[edi+eax+0x650a7354]
         // 00404b08: add esi, eax
         // 00404b0a: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00404b0d: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00404b10: mov ebx, eax
         // 00404b12: ror ebx, b1 0xd
         // 00404b15: mov edi, eax
         // 00404b17: rol edi, b1 0xa
         // 00404b1a: xor ebx, edi
         // 00404b1c: mov edi, eax
         // 00404b1e: ror edi, b1 0x2
         // 00404b21: xor ebx, edi
         // 00404b23: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00404b26: mov edi, ss:[ebp+0xffffffffffffffdc]
         // 00404b29: or edi, eax
         // 00404b2b: and edi, ss:[ebp+0xfffffffffffffff8]
         // 00404b2e: mov ss:[ebp+0xffffffffffffffe4], edi
         // 00404b31: mov edi, ss:[ebp+0xffffffffffffffdc]
         // 00404b34: and edi, eax
         // 00404b36: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00404b39: or eax, edi
         // 00404b3b: add eax, ebx
         // 00404b3d: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00404b40: mov eax, ss:[ebp+0xffffffffffffff68]
         // 00404b46: mov ebx, eax
         // 00404b48: rol ebx, b1 0xf
         // 00404b4b: mov edi, eax
         // 00404b4d: rol edi, b1 0xd
         // 00404b50: xor ebx, edi
         // 00404b52: mov edi, ss:[ebp+0xffffffffffffff34]
         // 00404b58: shr eax, b1 0xa
         // 00404b5b: xor ebx, eax
         // 00404b5d: add ebx, ss:[ebp+0xffffffffffffff54]
         // 00404b63: mov eax, edi
         // 00404b65: rol eax, b1 0xe
         // 00404b68: ror edi, b1 0x7
         // 00404b6b: xor eax, edi
         // 00404b6d: mov edi, ss:[ebp+0xffffffffffffff34]
         // 00404b73: shr edi, b1 0x3
         // 00404b76: xor eax, edi
         // 00404b78: add eax, ebx
         // 00404b7a: add eax, ss:[ebp+0xffffffffffffff30]
         // 00404b80: mov edi, esi
         // 00404b82: ror edi, b1 0xb
         // 00404b85: mov ss:[ebp+0xffffffffffffff70], eax
         // 00404b8b: mov eax, esi
         // 00404b8d: rol eax, b1 0x7
         // 00404b90: xor edi, eax
         // 00404b92: mov eax, esi
         // 00404b94: ror eax, b1 0x6
         // 00404b97: xor edi, eax
         // 00404b99: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00404b9c: add edi, ss:[ebp+0xffffffffffffff70]
         // 00404ba2: mov ebx, eax
         // 00404ba4: xor ebx, edx
         // 00404ba6: and ebx, esi
         // 00404ba8: xor ebx, eax
         // 00404baa: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00404bad: add ebx, edi
         // 00404baf: lea ecx, ds:[ebx+ecx+0x766a0abb]
         // 00404bb6: add ss:[ebp+0xfffffffffffffff8], ecx
         // 00404bb9: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 00404bbc: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00404bbf: mov edi, eax
         // 00404bc1: ror edi, b1 0xd
         // 00404bc4: mov ecx, eax
         // 00404bc6: rol ecx, b1 0xa
         // 00404bc9: xor edi, ecx
         // 00404bcb: mov ecx, eax
         // 00404bcd: ror ecx, b1 0x2
         // 00404bd0: xor edi, ecx
         // 00404bd2: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00404bd5: or ecx, eax
         // 00404bd7: and ecx, ss:[ebp+0xffffffffffffffdc]
         // 00404bda: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00404bdd: and ebx, eax
         // 00404bdf: or ecx, ebx
         // 00404be1: add ecx, edi
         // 00404be3: mov ss:[ebp+0xffffffffffffffec], ecx
         // 00404be6: mov ecx, ss:[ebp+0xffffffffffffff6c]
         // 00404bec: mov ebx, ecx
         // 00404bee: rol ebx, b1 0xf
         // 00404bf1: mov edi, ecx
         // 00404bf3: rol edi, b1 0xd
         // 00404bf6: xor ebx, edi
         // 00404bf8: mov edi, ss:[ebp+0xffffffffffffff38]
         // 00404bfe: shr ecx, b1 0xa
         // 00404c01: xor ebx, ecx
         // 00404c03: add ebx, ss:[ebp+0xffffffffffffff58]
         // 00404c09: mov ecx, edi
         // 00404c0b: rol ecx, b1 0xe
         // 00404c0e: ror edi, b1 0x7
         // 00404c11: xor ecx, edi
         // 00404c13: mov edi, ss:[ebp+0xffffffffffffff38]
         // 00404c19: shr edi, b1 0x3
         // 00404c1c: xor ecx, edi
         // 00404c1e: add ecx, ebx
         // 00404c20: add ecx, ss:[ebp+0xffffffffffffff34]
         // 00404c26: mov ss:[ebp+0xffffffffffffff74], ecx
         // 00404c2c: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 00404c2f: mov edi, ecx
         // 00404c31: ror edi, b1 0xb
         // 00404c34: mov ebx, ecx
         // 00404c36: rol ebx, b1 0x7
         // 00404c39: xor edi, ebx
         // 00404c3b: mov ebx, ecx
         // 00404c3d: ror ebx, b1 0x6
         // 00404c40: xor edi, ebx
         // 00404c42: add edi, ss:[ebp+0xffffffffffffff74]
         // 00404c48: mov ebx, esi
         // 00404c4a: xor ebx, edx
         // 00404c4c: and ebx, ecx
         // 00404c4e: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 00404c51: xor ebx, edx
         // 00404c53: add ebx, edi
         // 00404c55: lea ecx, ds:[ebx+ecx+0xffffffff81c2c92e]
         // 00404c5c: add ss:[ebp+0xffffffffffffffdc], ecx
         // 00404c5f: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00404c62: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 00404c65: mov ebx, ecx
         // 00404c67: ror ebx, b1 0xd
         // 00404c6a: mov edi, ecx
         // 00404c6c: rol edi, b1 0xa
         // 00404c6f: xor ebx, edi
         // 00404c71: mov edi, ecx
         // 00404c73: ror edi, b1 0x2
         // 00404c76: xor ebx, edi
         // 00404c78: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00404c7b: mov edi, eax
         // 00404c7d: or edi, ecx
         // 00404c7f: and edi, ss:[ebp+0xfffffffffffffff4]
         // 00404c82: mov ss:[ebp+0xffffffffffffffe4], edi
         // 00404c85: mov edi, eax
         // 00404c87: and edi, ecx
         // 00404c89: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 00404c8c: or ecx, edi
         // 00404c8e: add ecx, ebx
         // 00404c90: mov ss:[ebp+0xffffffffffffffe8], ecx
         // 00404c93: mov ecx, ss:[ebp+0xffffffffffffff70]
         // 00404c99: mov ebx, ecx
         // 00404c9b: mov edi, ecx
         // 00404c9d: rol ebx, b1 0xf
         // 00404ca0: rol edi, b1 0xd
         // 00404ca3: xor ebx, edi
         // 00404ca5: mov edi, ss:[ebp+0xffffffffffffff3c]
         // 00404cab: shr ecx, b1 0xa
         // 00404cae: xor ebx, ecx
         // 00404cb0: mov ecx, edi
         // 00404cb2: rol ecx, b1 0xe
         // 00404cb5: ror edi, b1 0x7
         // 00404cb8: xor ecx, edi
         // 00404cba: mov edi, ss:[ebp+0xffffffffffffff3c]
         // 00404cc0: shr edi, b1 0x3
         // 00404cc3: xor ecx, edi
         // 00404cc5: add ebx, ss:[ebp+0xffffffffffffff5c]
         // 00404ccb: add ecx, ebx
         // 00404ccd: add ecx, ss:[ebp+0xffffffffffffff38]
         // 00404cd3: mov ss:[ebp+0xffffffffffffff78], ecx
         // 00404cd9: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 00404cdc: mov edi, ecx
         // 00404cde: ror edi, b1 0xb
         // 00404ce1: mov ebx, ecx
         // 00404ce3: rol ebx, b1 0x7
         // 00404ce6: xor edi, ebx
         // 00404ce8: ror ecx, b1 0x6
         // 00404ceb: xor edi, ecx
         // 00404ced: add edi, ss:[ebp+0xffffffffffffff78]
         // 00404cf3: mov ecx, esi
         // 00404cf5: xor ecx, ss:[ebp+0xfffffffffffffff8]
         // 00404cf8: and ecx, ss:[ebp+0xffffffffffffffdc]
         // 00404cfb: xor ecx, esi
         // 00404cfd: add ecx, edi
         // 00404cff: lea edx, ds:[ecx+edx+0xffffffff92722c85]
         // 00404d06: add ss:[ebp+0xfffffffffffffff4], edx
         // 00404d09: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 00404d0c: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00404d0f: mov edi, ss:[ebp+0xffffffffffffffec]
         // 00404d12: mov ebx, ecx
         // 00404d14: ror ebx, b1 0xd
         // 00404d17: mov edx, ecx
         // 00404d19: rol edx, b1 0xa
         // 00404d1c: xor ebx, edx
         // 00404d1e: mov edx, ecx
         // 00404d20: ror edx, b1 0x2
         // 00404d23: xor ebx, edx
         // 00404d25: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00404d28: mov edx, edi
         // 00404d2a: or edx, ecx
         // 00404d2c: and edx, eax
         // 00404d2e: and edi, ecx
         // 00404d30: or edx, edi
         // 00404d32: add edx, ebx
         // 00404d34: mov ss:[ebp+0xffffffffffffffe0], edx
         // 00404d37: mov edx, ss:[ebp+0xffffffffffffff74]
         // 00404d3d: mov ebx, edx
         // 00404d3f: mov edi, edx
         // 00404d41: shr edx, b1 0xa
         // 00404d44: rol ebx, b1 0xf
         // 00404d47: rol edi, b1 0xd
         // 00404d4a: xor ebx, edi
         // 00404d4c: mov edi, ss:[ebp+0xffffffffffffff40]
         // 00404d52: xor ebx, edx
         // 00404d54: add ebx, ss:[ebp+0xffffffffffffff60]
         // 00404d5a: mov edx, edi
         // 00404d5c: rol edx, b1 0xe
         // 00404d5f: ror edi, b1 0x7
         // 00404d62: xor edx, edi
         // 00404d64: mov edi, ss:[ebp+0xffffffffffffff40]
         // 00404d6a: shr edi, b1 0x3
         // 00404d6d: xor edx, edi
         // 00404d6f: add edx, ebx
         // 00404d71: add edx, ss:[ebp+0xffffffffffffff3c]
         // 00404d77: mov ss:[ebp+0xffffffffffffff7c], edx
         // 00404d7d: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 00404d80: mov edi, edx
         // 00404d82: ror edi, b1 0xb
         // 00404d85: mov ebx, edx
         // 00404d87: rol ebx, b1 0x7
         // 00404d8a: xor edi, ebx
         // 00404d8c: ror edx, b1 0x6
         // 00404d8f: xor edi, edx
         // 00404d91: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 00404d94: xor edx, ss:[ebp+0xffffffffffffffdc]
         // 00404d97: add edi, ss:[ebp+0xffffffffffffff7c]
         // 00404d9d: and edx, ss:[ebp+0xfffffffffffffff4]
         // 00404da0: xor edx, ss:[ebp+0xfffffffffffffff8]
         // 00404da3: add edx, edi
         // 00404da5: lea esi, ds:[edx+esi+0xffffffffa2bfe8a1]
         // 00404dac: mov edx, ss:[ebp+0xffffffffffffffe0]
         // 00404daf: add eax, esi
         // 00404db1: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00404db4: mov edi, edx
         // 00404db6: ror edi, b1 0xd
         // 00404db9: mov esi, edx
         // 00404dbb: rol esi, b1 0xa
         // 00404dbe: xor edi, esi
         // 00404dc0: mov esi, edx
         // 00404dc2: ror esi, b1 0x2
         // 00404dc5: xor edi, esi
         // 00404dc7: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00404dca: mov esi, ecx
         // 00404dcc: or esi, edx
         // 00404dce: and esi, ss:[ebp+0xffffffffffffffec]
         // 00404dd1: mov ebx, ecx
         // 00404dd3: and ebx, edx
         // 00404dd5: or esi, ebx
         // 00404dd7: add esi, edi
         // 00404dd9: mov ss:[ebp+0xffffffffffffffe4], esi
         // 00404ddc: mov esi, ss:[ebp+0xffffffffffffff78]
         // 00404de2: mov ebx, esi
         // 00404de4: mov edi, esi
         // 00404de6: shr esi, b1 0xa
         // 00404de9: rol ebx, b1 0xf
         // 00404dec: rol edi, b1 0xd
         // 00404def: xor ebx, edi
         // 00404df1: xor ebx, esi
         // 00404df3: add ebx, ss:[ebp+0xffffffffffffff64]
         // 00404df9: mov edi, ss:[ebp+0xffffffffffffff44]
         // 00404dff: mov esi, edi
         // 00404e01: rol esi, b1 0xe
         // 00404e04: ror edi, b1 0x7
         // 00404e07: xor esi, edi
         // 00404e09: mov edi, ss:[ebp+0xffffffffffffff44]
         // 00404e0f: shr edi, b1 0x3
         // 00404e12: xor esi, edi
         // 00404e14: add esi, ebx
         // 00404e16: add esi, ss:[ebp+0xffffffffffffff40]
         // 00404e1c: mov edi, eax
         // 00404e1e: mov ss:[ebp+0xffffffffffffff80], esi
         // 00404e21: mov esi, eax
         // 00404e23: ror esi, b1 0xb
         // 00404e26: rol edi, b1 0x7
         // 00404e29: xor esi, edi
         // 00404e2b: mov edi, eax
         // 00404e2d: ror edi, b1 0x6
         // 00404e30: xor esi, edi
         // 00404e32: add esi, ss:[ebp+0xffffffffffffff80]
         // 00404e35: mov edi, ss:[ebp+0xffffffffffffffdc]
         // 00404e38: xor edi, ss:[ebp+0xfffffffffffffff4]
         // 00404e3b: and edi, eax
         // 00404e3d: xor edi, ss:[ebp+0xffffffffffffffdc]
         // 00404e40: add edi, esi
         // 00404e42: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00404e45: lea esi, ds:[edi+esi+0xffffffffa81a664b]
         // 00404e4c: add ss:[ebp+0xffffffffffffffec], esi
         // 00404e4f: mov edi, ss:[ebp+0xffffffffffffffe4]
         // 00404e52: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00404e55: mov ebx, edi
         // 00404e57: ror ebx, b1 0xd
         // 00404e5a: mov esi, edi
         // 00404e5c: rol esi, b1 0xa
         // 00404e5f: xor ebx, esi
         // 00404e61: mov esi, edi
         // 00404e63: ror esi, b1 0x2
         // 00404e66: xor ebx, esi
         // 00404e68: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00404e6b: mov esi, edi
         // 00404e6d: or esi, edx
         // 00404e6f: and esi, ecx
         // 00404e71: and edi, edx
         // 00404e73: or esi, edi
         // 00404e75: add esi, ebx
         // 00404e77: mov ss:[ebp+0xfffffffffffffff8], esi
         // 00404e7a: mov esi, ss:[ebp+0xffffffffffffff7c]
         // 00404e80: mov ebx, esi
         // 00404e82: rol ebx, b1 0xf
         // 00404e85: mov edi, esi
         // 00404e87: rol edi, b1 0xd
         // 00404e8a: xor ebx, edi
         // 00404e8c: mov edi, ss:[ebp+0xffffffffffffff48]
         // 00404e92: shr esi, b1 0xa
         // 00404e95: xor ebx, esi
         // 00404e97: mov esi, edi
         // 00404e99: rol esi, b1 0xe
         // 00404e9c: ror edi, b1 0x7
         // 00404e9f: xor esi, edi
         // 00404ea1: mov edi, ss:[ebp+0xffffffffffffff48]
         // 00404ea7: add ebx, ss:[ebp+0xffffffffffffff68]
         // 00404ead: shr edi, b1 0x3
         // 00404eb0: xor esi, edi
         // 00404eb2: add esi, ebx
         // 00404eb4: add esi, ss:[ebp+0xffffffffffffff44]
         // 00404eba: mov ss:[ebp+0xffffffffffffff84], esi
         // 00404ebd: mov esi, ss:[ebp+0xffffffffffffffec]
         // 00404ec0: mov edi, esi
         // 00404ec2: ror edi, b1 0xb
         // 00404ec5: mov ebx, esi
         // 00404ec7: rol ebx, b1 0x7
         // 00404eca: xor edi, ebx
         // 00404ecc: mov ebx, esi
         // 00404ece: ror ebx, b1 0x6
         // 00404ed1: xor edi, ebx
         // 00404ed3: add edi, ss:[ebp+0xffffffffffffff84]
         // 00404ed6: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 00404ed9: xor ebx, eax
         // 00404edb: and ebx, esi
         // 00404edd: xor ebx, ss:[ebp+0xfffffffffffffff4]
         // 00404ee0: mov esi, ss:[ebp+0xffffffffffffffdc]
         // 00404ee3: add ebx, edi
         // 00404ee5: lea esi, ds:[ebx+esi+0xffffffffc24b8b70]
         // 00404eec: add ecx, esi
         // 00404eee: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00404ef1: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00404ef4: mov ebx, esi
         // 00404ef6: mov edi, esi
         // 00404ef8: ror ebx, b1 0xd
         // 00404efb: rol edi, b1 0xa
         // 00404efe: xor ebx, edi
         // 00404f00: mov edi, esi
         // 00404f02: ror edi, b1 0x2
         // 00404f05: xor ebx, edi
         // 00404f07: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00404f0a: mov edi, ss:[ebp+0xffffffffffffffe4]
         // 00404f0d: or edi, esi
         // 00404f0f: and edi, edx
         // 00404f11: mov ss:[ebp+0xffffffffffffffdc], edi
         // 00404f14: mov edi, ss:[ebp+0xffffffffffffffe4]
         // 00404f17: and edi, esi
         // 00404f19: mov esi, ss:[ebp+0xffffffffffffffdc]
         // 00404f1c: or esi, edi
         // 00404f1e: add esi, ebx
         // 00404f20: mov ss:[ebp+0xffffffffffffffdc], esi
         // 00404f23: mov esi, ss:[ebp+0xffffffffffffff80]
         // 00404f26: mov ebx, esi
         // 00404f28: mov edi, esi
         // 00404f2a: shr esi, b1 0xa
         // 00404f2d: rol ebx, b1 0xf
         // 00404f30: rol edi, b1 0xd
         // 00404f33: xor ebx, edi
         // 00404f35: mov edi, ss:[ebp+0xffffffffffffff4c]
         // 00404f3b: xor ebx, esi
         // 00404f3d: add ebx, ss:[ebp+0xffffffffffffff6c]
         // 00404f43: mov esi, edi
         // 00404f45: rol esi, b1 0xe
         // 00404f48: ror edi, b1 0x7
         // 00404f4b: xor esi, edi
         // 00404f4d: mov edi, ss:[ebp+0xffffffffffffff4c]
         // 00404f53: shr edi, b1 0x3
         // 00404f56: xor esi, edi
         // 00404f58: add esi, ebx
         // 00404f5a: add esi, ss:[ebp+0xffffffffffffff48]
         // 00404f60: mov edi, ecx
         // 00404f62: mov ss:[ebp+0xffffffffffffff88], esi
         // 00404f65: mov esi, ecx
         // 00404f67: ror esi, b1 0xb
         // 00404f6a: rol edi, b1 0x7
         // 00404f6d: xor esi, edi
         // 00404f6f: mov edi, ecx
         // 00404f71: ror edi, b1 0x6
         // 00404f74: xor esi, edi
         // 00404f76: add esi, ss:[ebp+0xffffffffffffff88]
         // 00404f79: mov edi, eax
         // 00404f7b: xor edi, ss:[ebp+0xffffffffffffffec]
         // 00404f7e: and edi, ecx
         // 00404f80: xor edi, eax
         // 00404f82: add edi, esi
         // 00404f84: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 00404f87: lea esi, ds:[edi+esi+0xffffffffc76c51a3]
         // 00404f8e: add edx, esi
         // 00404f90: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00404f93: mov esi, ss:[ebp+0xffffffffffffffdc]
         // 00404f96: mov ebx, esi
         // 00404f98: ror ebx, b1 0xd
         // 00404f9b: mov edi, esi
         // 00404f9d: rol edi, b1 0xa
         // 00404fa0: xor ebx, edi
         // 00404fa2: mov edi, esi
         // 00404fa4: ror edi, b1 0x2
         // 00404fa7: xor ebx, edi
         // 00404fa9: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00404fac: mov edi, ss:[ebp+0xfffffffffffffff8]
         // 00404faf: or edi, esi
         // 00404fb1: and edi, ss:[ebp+0xffffffffffffffe4]
         // 00404fb4: mov ss:[ebp+0xffffffffffffffe0], edi
         // 00404fb7: mov edi, ss:[ebp+0xfffffffffffffff8]
         // 00404fba: and edi, esi
         // 00404fbc: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 00404fbf: or esi, edi
         // 00404fc1: add esi, ebx
         // 00404fc3: mov ss:[ebp+0xfffffffffffffff4], esi
         // 00404fc6: mov esi, ss:[ebp+0xffffffffffffff84]
         // 00404fc9: mov ebx, esi
         // 00404fcb: rol ebx, b1 0xf
         // 00404fce: mov edi, esi
         // 00404fd0: rol edi, b1 0xd
         // 00404fd3: xor ebx, edi
         // 00404fd5: mov edi, ss:[ebp+0xffffffffffffff50]
         // 00404fdb: shr esi, b1 0xa
         // 00404fde: xor ebx, esi
         // 00404fe0: add ebx, ss:[ebp+0xffffffffffffff70]
         // 00404fe6: mov esi, edi
         // 00404fe8: rol esi, b1 0xe
         // 00404feb: ror edi, b1 0x7
         // 00404fee: xor esi, edi
         // 00404ff0: mov edi, ss:[ebp+0xffffffffffffff50]
         // 00404ff6: shr edi, b1 0x3
         // 00404ff9: xor esi, edi
         // 00404ffb: add esi, ebx
         // 00404ffd: add esi, ss:[ebp+0xffffffffffffff4c]
         // 00405003: mov edi, edx
         // 00405005: ror edi, b1 0xb
         // 00405008: mov ss:[ebp+0xffffffffffffff8c], esi
         // 0040500b: mov esi, edx
         // 0040500d: rol esi, b1 0x7
         // 00405010: xor edi, esi
         // 00405012: mov esi, edx
         // 00405014: ror esi, b1 0x6
         // 00405017: xor edi, esi
         // 00405019: mov esi, ss:[ebp+0xffffffffffffffec]
         // 0040501c: add edi, ss:[ebp+0xffffffffffffff8c]
         // 0040501f: mov ebx, esi
         // 00405021: xor ebx, ecx
         // 00405023: and ebx, edx
         // 00405025: xor ebx, esi
         // 00405027: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 0040502a: add ebx, edi
         // 0040502c: lea eax, ds:[ebx+eax+0xffffffffd192e819]
         // 00405033: add ss:[ebp+0xffffffffffffffe4], eax
         // 00405036: mov ebx, ss:[ebp+0xffffffffffffffdc]
         // 00405039: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040503c: mov edi, esi
         // 0040503e: ror edi, b1 0xd
         // 00405041: mov eax, esi
         // 00405043: rol eax, b1 0xa
         // 00405046: xor edi, eax
         // 00405048: mov eax, esi
         // 0040504a: ror eax, b1 0x2
         // 0040504d: xor edi, eax
         // 0040504f: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 00405052: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00405055: or eax, esi
         // 00405057: and eax, ss:[ebp+0xfffffffffffffff8]
         // 0040505a: and ebx, esi
         // 0040505c: or eax, ebx
         // 0040505e: add eax, edi
         // 00405060: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00405063: mov eax, ss:[ebp+0xffffffffffffff88]
         // 00405066: mov ebx, eax
         // 00405068: rol ebx, b1 0xf
         // 0040506b: mov edi, eax
         // 0040506d: rol edi, b1 0xd
         // 00405070: xor ebx, edi
         // 00405072: shr eax, b1 0xa
         // 00405075: xor ebx, eax
         // 00405077: add ebx, ss:[ebp+0xffffffffffffff74]
         // 0040507d: mov edi, ss:[ebp+0xffffffffffffff54]
         // 00405083: mov eax, edi
         // 00405085: rol eax, b1 0xe
         // 00405088: ror edi, b1 0x7
         // 0040508b: xor eax, edi
         // 0040508d: mov edi, ss:[ebp+0xffffffffffffff54]
         // 00405093: shr edi, b1 0x3
         // 00405096: xor eax, edi
         // 00405098: add eax, ebx
         // 0040509a: add eax, ss:[ebp+0xffffffffffffff50]
         // 004050a0: mov ss:[ebp+0xffffffffffffff90], eax
         // 004050a3: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 004050a6: mov edi, eax
         // 004050a8: ror edi, b1 0xb
         // 004050ab: mov ebx, eax
         // 004050ad: rol ebx, b1 0x7
         // 004050b0: xor edi, ebx
         // 004050b2: mov ebx, eax
         // 004050b4: ror ebx, b1 0x6
         // 004050b7: xor edi, ebx
         // 004050b9: add edi, ss:[ebp+0xffffffffffffff90]
         // 004050bc: mov ebx, ecx
         // 004050be: xor ebx, edx
         // 004050c0: and ebx, eax
         // 004050c2: mov eax, ss:[ebp+0xffffffffffffffec]
         // 004050c5: xor ebx, ecx
         // 004050c7: add ebx, edi
         // 004050c9: lea eax, ds:[ebx+eax+0xffffffffd6990624]
         // 004050d0: add ss:[ebp+0xfffffffffffffff8], eax
         // 004050d3: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004050d6: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 004050d9: mov ebx, eax
         // 004050db: ror ebx, b1 0xd
         // 004050de: mov edi, eax
         // 004050e0: rol edi, b1 0xa
         // 004050e3: xor ebx, edi
         // 004050e5: mov edi, eax
         // 004050e7: ror edi, b1 0x2
         // 004050ea: xor ebx, edi
         // 004050ec: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004050ef: mov edi, esi
         // 004050f1: or edi, eax
         // 004050f3: and edi, ss:[ebp+0xffffffffffffffdc]
         // 004050f6: mov ss:[ebp+0xffffffffffffffe0], edi
         // 004050f9: mov edi, esi
         // 004050fb: and edi, eax
         // 004050fd: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 00405100: or eax, edi
         // 00405102: add eax, ebx
         // 00405104: mov ss:[ebp+0xffffffffffffffec], eax
         // 00405107: mov eax, ss:[ebp+0xffffffffffffff8c]
         // 0040510a: mov ebx, eax
         // 0040510c: mov edi, eax
         // 0040510e: rol ebx, b1 0xf
         // 00405111: rol edi, b1 0xd
         // 00405114: xor ebx, edi
         // 00405116: mov edi, ss:[ebp+0xffffffffffffff58]
         // 0040511c: shr eax, b1 0xa
         // 0040511f: xor ebx, eax
         // 00405121: add ebx, ss:[ebp+0xffffffffffffff78]
         // 00405127: mov eax, edi
         // 00405129: rol eax, b1 0xe
         // 0040512c: ror edi, b1 0x7
         // 0040512f: xor eax, edi
         // 00405131: mov edi, ss:[ebp+0xffffffffffffff58]
         // 00405137: shr edi, b1 0x3
         // 0040513a: xor eax, edi
         // 0040513c: add eax, ebx
         // 0040513e: add eax, ss:[ebp+0xffffffffffffff54]
         // 00405144: mov ss:[ebp+0xffffffffffffff94], eax
         // 00405147: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 0040514a: mov edi, eax
         // 0040514c: mov ebx, eax
         // 0040514e: ror edi, b1 0xb
         // 00405151: rol ebx, b1 0x7
         // 00405154: xor edi, ebx
         // 00405156: mov ebx, eax
         // 00405158: ror ebx, b1 0x6
         // 0040515b: xor edi, ebx
         // 0040515d: add edi, ss:[ebp+0xffffffffffffff94]
         // 00405160: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 00405163: xor ebx, edx
         // 00405165: and ebx, eax
         // 00405167: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0040516a: xor ebx, edx
         // 0040516c: add ebx, edi
         // 0040516e: lea ecx, ds:[ebx+ecx+0xfffffffff40e3585]
         // 00405175: add ss:[ebp+0xffffffffffffffdc], ecx
         // 00405178: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 0040517b: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 0040517e: mov ebx, eax
         // 00405180: ror ebx, b1 0xd
         // 00405183: mov ecx, eax
         // 00405185: rol ecx, b1 0xa
         // 00405188: xor ebx, ecx
         // 0040518a: mov ecx, eax
         // 0040518c: ror ecx, b1 0x2
         // 0040518f: xor ebx, ecx
         // 00405191: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00405194: mov ecx, edi
         // 00405196: or ecx, eax
         // 00405198: and ecx, esi
         // 0040519a: and edi, eax
         // 0040519c: or ecx, edi
         // 0040519e: add ecx, ebx
         // 004051a0: mov ss:[ebp+0xffffffffffffffe8], ecx
         // 004051a3: mov ecx, ss:[ebp+0xffffffffffffff90]
         // 004051a6: mov ebx, ecx
         // 004051a8: mov edi, ecx
         // 004051aa: shr ecx, b1 0xa
         // 004051ad: rol ebx, b1 0xf
         // 004051b0: rol edi, b1 0xd
         // 004051b3: xor ebx, edi
         // 004051b5: mov edi, ss:[ebp+0xffffffffffffff5c]
         // 004051bb: xor ebx, ecx
         // 004051bd: add ebx, ss:[ebp+0xffffffffffffff7c]
         // 004051c3: mov ecx, edi
         // 004051c5: rol ecx, b1 0xe
         // 004051c8: ror edi, b1 0x7
         // 004051cb: xor ecx, edi
         // 004051cd: mov edi, ss:[ebp+0xffffffffffffff5c]
         // 004051d3: shr edi, b1 0x3
         // 004051d6: xor ecx, edi
         // 004051d8: add ecx, ebx
         // 004051da: add ecx, ss:[ebp+0xffffffffffffff58]
         // 004051e0: mov ss:[ebp+0xffffffffffffff98], ecx
         // 004051e3: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 004051e6: mov edi, ecx
         // 004051e8: ror edi, b1 0xb
         // 004051eb: mov ebx, ecx
         // 004051ed: rol ebx, b1 0x7
         // 004051f0: xor edi, ebx
         // 004051f2: ror ecx, b1 0x6
         // 004051f5: xor edi, ecx
         // 004051f7: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 004051fa: xor ecx, ss:[ebp+0xfffffffffffffff8]
         // 004051fd: add edi, ss:[ebp+0xffffffffffffff98]
         // 00405200: and ecx, ss:[ebp+0xffffffffffffffdc]
         // 00405203: mov ebx, eax
         // 00405205: xor ecx, ss:[ebp+0xffffffffffffffe4]
         // 00405208: add ecx, edi
         // 0040520a: lea edx, ds:[ecx+edx+0x106aa070]
         // 00405211: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 00405214: add esi, edx
         // 00405216: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00405219: mov edi, ecx
         // 0040521b: ror edi, b1 0xd
         // 0040521e: mov edx, ecx
         // 00405220: rol edx, b1 0xa
         // 00405223: xor edi, edx
         // 00405225: mov edx, ecx
         // 00405227: ror edx, b1 0x2
         // 0040522a: xor edi, edx
         // 0040522c: mov edx, eax
         // 0040522e: or edx, ecx
         // 00405230: and edx, ss:[ebp+0xfffffffffffffff0]
         // 00405233: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00405236: and ebx, ecx
         // 00405238: or edx, ebx
         // 0040523a: add edx, edi
         // 0040523c: mov ss:[ebp+0xffffffffffffffe0], edx
         // 0040523f: mov edx, ss:[ebp+0xffffffffffffff94]
         // 00405242: mov ebx, edx
         // 00405244: mov edi, edx
         // 00405246: shr edx, b1 0xa
         // 00405249: rol ebx, b1 0xf
         // 0040524c: rol edi, b1 0xd
         // 0040524f: xor ebx, edi
         // 00405251: xor ebx, edx
         // 00405253: add ebx, ss:[ebp+0xffffffffffffff80]
         // 00405256: mov edi, ss:[ebp+0xffffffffffffff60]
         // 0040525c: mov edx, edi
         // 0040525e: rol edx, b1 0xe
         // 00405261: ror edi, b1 0x7
         // 00405264: xor edx, edi
         // 00405266: mov edi, ss:[ebp+0xffffffffffffff60]
         // 0040526c: shr edi, b1 0x3
         // 0040526f: xor edx, edi
         // 00405271: add edx, ebx
         // 00405273: add edx, ss:[ebp+0xffffffffffffff5c]
         // 00405279: mov edi, esi
         // 0040527b: mov ss:[ebp+0xffffffffffffff9c], edx
         // 0040527e: mov edx, esi
         // 00405280: ror edx, b1 0xb
         // 00405283: rol edi, b1 0x7
         // 00405286: xor edx, edi
         // 00405288: mov edi, esi
         // 0040528a: ror edi, b1 0x6
         // 0040528d: xor edx, edi
         // 0040528f: add edx, ss:[ebp+0xffffffffffffff9c]
         // 00405292: mov edi, ss:[ebp+0xfffffffffffffff8]
         // 00405295: xor edi, ss:[ebp+0xffffffffffffffdc]
         // 00405298: and edi, esi
         // 0040529a: xor edi, ss:[ebp+0xfffffffffffffff8]
         // 0040529d: add edi, edx
         // 0040529f: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 004052a2: lea edx, ds:[edi+edx+0x19a4c116]
         // 004052a9: add ss:[ebp+0xfffffffffffffff0], edx
         // 004052ac: mov ss:[ebp+0xfffffffffffffffc], edx
         // 004052af: mov edx, ss:[ebp+0xffffffffffffffe0]
         // 004052b2: mov ebx, edx
         // 004052b4: ror ebx, b1 0xd
         // 004052b7: mov edi, edx
         // 004052b9: rol edi, b1 0xa
         // 004052bc: xor ebx, edi
         // 004052be: mov edi, edx
         // 004052c0: ror edi, b1 0x2
         // 004052c3: xor ebx, edi
         // 004052c5: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004052c8: mov edi, ecx
         // 004052ca: or edi, edx
         // 004052cc: and edi, eax
         // 004052ce: mov ss:[ebp+0xffffffffffffffe4], edi
         // 004052d1: mov edi, ecx
         // 004052d3: and edi, edx
         // 004052d5: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 004052d8: or edx, edi
         // 004052da: add edx, ebx
         // 004052dc: mov ss:[ebp+0xffffffffffffffe4], edx
         // 004052df: mov edx, ss:[ebp+0xffffffffffffff98]
         // 004052e2: mov ebx, edx
         // 004052e4: mov edi, edx
         // 004052e6: rol ebx, b1 0xf
         // 004052e9: rol edi, b1 0xd
         // 004052ec: xor ebx, edi
         // 004052ee: mov edi, ss:[ebp+0xffffffffffffff64]
         // 004052f4: shr edx, b1 0xa
         // 004052f7: xor ebx, edx
         // 004052f9: add ebx, ss:[ebp+0xffffffffffffff84]
         // 004052fc: mov edx, edi
         // 004052fe: rol edx, b1 0xe
         // 00405301: ror edi, b1 0x7
         // 00405304: xor edx, edi
         // 00405306: mov edi, ss:[ebp+0xffffffffffffff64]
         // 0040530c: shr edi, b1 0x3
         // 0040530f: xor edx, edi
         // 00405311: add edx, ebx
         // 00405313: add edx, ss:[ebp+0xffffffffffffff60]
         // 00405319: mov ss:[ebp+0xffffffffffffffa0], edx
         // 0040531c: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 0040531f: mov edi, edx
         // 00405321: ror edi, b1 0xb
         // 00405324: mov ebx, edx
         // 00405326: rol ebx, b1 0x7
         // 00405329: xor edi, ebx
         // 0040532b: mov ebx, edx
         // 0040532d: ror ebx, b1 0x6
         // 00405330: xor edi, ebx
         // 00405332: add edi, ss:[ebp+0xffffffffffffffa0]
         // 00405335: mov ebx, ss:[ebp+0xffffffffffffffdc]
         // 00405338: xor ebx, esi
         // 0040533a: and ebx, edx
         // 0040533c: xor ebx, ss:[ebp+0xffffffffffffffdc]
         // 0040533f: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 00405342: add ebx, edi
         // 00405344: lea edx, ds:[ebx+edx+0x1e376c08]
         // 0040534b: add eax, edx
         // 0040534d: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00405350: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 00405353: mov ebx, edx
         // 00405355: mov edi, edx
         // 00405357: ror ebx, b1 0xd
         // 0040535a: rol edi, b1 0xa
         // 0040535d: xor ebx, edi
         // 0040535f: mov edi, edx
         // 00405361: ror edi, b1 0x2
         // 00405364: xor ebx, edi
         // 00405366: mov edi, ss:[ebp+0xffffffffffffffe0]
         // 00405369: or edx, edi
         // 0040536b: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040536e: and edx, ecx
         // 00405370: mov ss:[ebp+0xfffffffffffffff8], edx
         // 00405373: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 00405376: and edx, edi
         // 00405378: mov ss:[ebp+0xffffffffffffffe8], edx
         // 0040537b: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 0040537e: or edx, ss:[ebp+0xffffffffffffffe8]
         // 00405381: add edx, ebx
         // 00405383: mov ss:[ebp+0xfffffffffffffff8], edx
         // 00405386: mov edx, ss:[ebp+0xffffffffffffff9c]
         // 00405389: mov ebx, edx
         // 0040538b: mov edi, edx
         // 0040538d: shr edx, b1 0xa
         // 00405390: rol ebx, b1 0xf
         // 00405393: rol edi, b1 0xd
         // 00405396: xor ebx, edi
         // 00405398: mov edi, ss:[ebp+0xffffffffffffff68]
         // 0040539e: xor ebx, edx
         // 004053a0: add ebx, ss:[ebp+0xffffffffffffff88]
         // 004053a3: mov edx, edi
         // 004053a5: rol edx, b1 0xe
         // 004053a8: ror edi, b1 0x7
         // 004053ab: xor edx, edi
         // 004053ad: mov edi, ss:[ebp+0xffffffffffffff68]
         // 004053b3: shr edi, b1 0x3
         // 004053b6: xor edx, edi
         // 004053b8: add edx, ebx
         // 004053ba: add edx, ss:[ebp+0xffffffffffffff64]
         // 004053c0: mov edi, eax
         // 004053c2: mov ss:[ebp+0xffffffffffffffa4], edx
         // 004053c5: mov edx, eax
         // 004053c7: ror edx, b1 0xb
         // 004053ca: rol edi, b1 0x7
         // 004053cd: xor edx, edi
         // 004053cf: mov edi, eax
         // 004053d1: ror edi, b1 0x6
         // 004053d4: xor edx, edi
         // 004053d6: add edx, ss:[ebp+0xffffffffffffffa4]
         // 004053d9: mov edi, esi
         // 004053db: xor edi, ss:[ebp+0xfffffffffffffff0]
         // 004053de: and edi, eax
         // 004053e0: xor edi, esi
         // 004053e2: add edi, edx
         // 004053e4: mov edx, ss:[ebp+0xffffffffffffffdc]
         // 004053e7: lea edx, ds:[edi+edx+0x2748774c]
         // 004053ee: mov ss:[ebp+0xfffffffffffffffc], edx
         // 004053f1: add ecx, edx
         // 004053f3: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 004053f6: mov ebx, edx
         // 004053f8: ror ebx, b1 0xd
         // 004053fb: mov edi, edx
         // 004053fd: rol edi, b1 0xa
         // 00405400: xor ebx, edi
         // 00405402: mov edi, edx
         // 00405404: ror edi, b1 0x2
         // 00405407: xor ebx, edi
         // 00405409: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040540c: mov edi, ss:[ebp+0xffffffffffffffe4]
         // 0040540f: or edi, edx
         // 00405411: and edi, ss:[ebp+0xffffffffffffffe0]
         // 00405414: mov ss:[ebp+0xffffffffffffffdc], edi
         // 00405417: mov edi, ss:[ebp+0xffffffffffffffe4]
         // 0040541a: and edi, edx
         // 0040541c: mov edx, ss:[ebp+0xffffffffffffffdc]
         // 0040541f: or edx, edi
         // 00405421: add edx, ebx
         // 00405423: mov ss:[ebp+0xffffffffffffffdc], edx
         // 00405426: mov edx, ss:[ebp+0xffffffffffffff6c]
         // 0040542c: mov ebx, edx
         // 0040542e: rol ebx, b1 0xe
         // 00405431: mov edi, edx
         // 00405433: ror edi, b1 0x7
         // 00405436: xor ebx, edi
         // 00405438: mov edi, ss:[ebp+0xffffffffffffffa0]
         // 0040543b: shr edx, b1 0x3
         // 0040543e: xor ebx, edx
         // 00405440: add ebx, ss:[ebp+0xffffffffffffff8c]
         // 00405443: mov edx, edi
         // 00405445: rol edx, b1 0xf
         // 00405448: rol edi, b1 0xd
         // 0040544b: xor edx, edi
         // 0040544d: mov edi, ss:[ebp+0xffffffffffffffa0]
         // 00405450: shr edi, b1 0xa
         // 00405453: xor edx, edi
         // 00405455: add edx, ebx
         // 00405457: add edx, ss:[ebp+0xffffffffffffff68]
         // 0040545d: mov edi, ecx
         // 0040545f: ror edi, b1 0xb
         // 00405462: mov ss:[ebp+0xffffffffffffffa8], edx
         // 00405465: mov edx, ecx
         // 00405467: rol edx, b1 0x7
         // 0040546a: xor edi, edx
         // 0040546c: mov edx, ecx
         // 0040546e: ror edx, b1 0x6
         // 00405471: xor edi, edx
         // 00405473: add edi, ss:[ebp+0xffffffffffffffa8]
         // 00405476: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 00405479: mov ebx, edx
         // 0040547b: xor ebx, eax
         // 0040547d: and ebx, ecx
         // 0040547f: xor ebx, edx
         // 00405481: mov edx, ss:[ebp+0xffffffffffffffdc]
         // 00405484: add ebx, edi
         // 00405486: lea esi, ds:[ebx+esi+0x34b0bcb5]
         // 0040548d: add ss:[ebp+0xffffffffffffffe0], esi
         // 00405490: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00405493: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00405496: mov edi, edx
         // 00405498: ror edi, b1 0xd
         // 0040549b: mov esi, edx
         // 0040549d: rol esi, b1 0xa
         // 004054a0: xor edi, esi
         // 004054a2: mov esi, edx
         // 004054a4: ror esi, b1 0x2
         // 004054a7: xor edi, esi
         // 004054a9: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 004054ac: add edi, ss:[ebp+0xfffffffffffffffc]
         // 004054af: or esi, edx
         // 004054b1: and esi, ss:[ebp+0xffffffffffffffe4]
         // 004054b4: and ebx, edx
         // 004054b6: or esi, ebx
         // 004054b8: add esi, edi
         // 004054ba: mov ss:[ebp+0xfffffffffffffff4], esi
         // 004054bd: mov esi, ss:[ebp+0xffffffffffffff70]
         // 004054c3: mov ebx, esi
         // 004054c5: rol ebx, b1 0xe
         // 004054c8: mov edi, esi
         // 004054ca: ror edi, b1 0x7
         // 004054cd: xor ebx, edi
         // 004054cf: shr esi, b1 0x3
         // 004054d2: xor ebx, esi
         // 004054d4: add ebx, ss:[ebp+0xffffffffffffff90]
         // 004054d7: mov edi, ss:[ebp+0xffffffffffffffa4]
         // 004054da: mov esi, edi
         // 004054dc: rol esi, b1 0xf
         // 004054df: rol edi, b1 0xd
         // 004054e2: xor esi, edi
         // 004054e4: mov edi, ss:[ebp+0xffffffffffffffa4]
         // 004054e7: shr edi, b1 0xa
         // 004054ea: xor esi, edi
         // 004054ec: add esi, ebx
         // 004054ee: add esi, ss:[ebp+0xffffffffffffff6c]
         // 004054f4: mov ss:[ebp+0xffffffffffffffac], esi
         // 004054f7: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 004054fa: mov edi, esi
         // 004054fc: ror edi, b1 0xb
         // 004054ff: mov ebx, esi
         // 00405501: rol ebx, b1 0x7
         // 00405504: xor edi, ebx
         // 00405506: mov ebx, esi
         // 00405508: ror ebx, b1 0x6
         // 0040550b: xor edi, ebx
         // 0040550d: add edi, ss:[ebp+0xffffffffffffffac]
         // 00405510: mov ebx, eax
         // 00405512: xor ebx, ecx
         // 00405514: and ebx, esi
         // 00405516: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00405519: xor ebx, eax
         // 0040551b: add ebx, edi
         // 0040551d: lea esi, ds:[ebx+esi+0x391c0cb3]
         // 00405524: add ss:[ebp+0xffffffffffffffe4], esi
         // 00405527: mov ss:[ebp+0xfffffffffffffffc], esi
         // 0040552a: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 0040552d: mov ebx, esi
         // 0040552f: ror ebx, b1 0xd
         // 00405532: mov edi, esi
         // 00405534: rol edi, b1 0xa
         // 00405537: xor ebx, edi
         // 00405539: mov edi, esi
         // 0040553b: ror edi, b1 0x2
         // 0040553e: xor ebx, edi
         // 00405540: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00405543: mov edi, edx
         // 00405545: or edi, esi
         // 00405547: and edi, ss:[ebp+0xfffffffffffffff8]
         // 0040554a: mov ss:[ebp+0xffffffffffffffdc], edi
         // 0040554d: mov edi, edx
         // 0040554f: and edi, esi
         // 00405551: mov esi, ss:[ebp+0xffffffffffffffdc]
         // 00405554: or esi, edi
         // 00405556: add esi, ebx
         // 00405558: mov ss:[ebp+0xfffffffffffffff0], esi
         // 0040555b: mov esi, ss:[ebp+0xffffffffffffff74]
         // 00405561: mov ebx, esi
         // 00405563: rol ebx, b1 0xe
         // 00405566: mov edi, esi
         // 00405568: ror edi, b1 0x7
         // 0040556b: xor ebx, edi
         // 0040556d: mov edi, ss:[ebp+0xffffffffffffffa8]
         // 00405570: shr esi, b1 0x3
         // 00405573: xor ebx, esi
         // 00405575: add ebx, ss:[ebp+0xffffffffffffff94]
         // 00405578: mov esi, edi
         // 0040557a: rol esi, b1 0xf
         // 0040557d: rol edi, b1 0xd
         // 00405580: xor esi, edi
         // 00405582: mov edi, ss:[ebp+0xffffffffffffffa8]
         // 00405585: shr edi, b1 0xa
         // 00405588: xor esi, edi
         // 0040558a: add esi, ebx
         // 0040558c: add esi, ss:[ebp+0xffffffffffffff70]
         // 00405592: mov ss:[ebp+0xffffffffffffffb0], esi
         // 00405595: mov esi, ss:[ebp+0xffffffffffffffe4]
         // 00405598: mov edi, esi
         // 0040559a: ror edi, b1 0xb
         // 0040559d: mov ebx, esi
         // 0040559f: rol ebx, b1 0x7
         // 004055a2: xor edi, ebx
         // 004055a4: ror esi, b1 0x6
         // 004055a7: xor edi, esi
         // 004055a9: add edi, ss:[ebp+0xffffffffffffffb0]
         // 004055ac: mov esi, ecx
         // 004055ae: xor esi, ss:[ebp+0xffffffffffffffe0]
         // 004055b1: and esi, ss:[ebp+0xffffffffffffffe4]
         // 004055b4: xor esi, ecx
         // 004055b6: add esi, edi
         // 004055b8: lea eax, ds:[esi+eax+0x4ed8aa4a]
         // 004055bf: add ss:[ebp+0xfffffffffffffff8], eax
         // 004055c2: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 004055c5: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004055c8: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 004055cb: mov ebx, esi
         // 004055cd: ror ebx, b1 0xd
         // 004055d0: mov eax, esi
         // 004055d2: rol eax, b1 0xa
         // 004055d5: xor ebx, eax
         // 004055d7: mov eax, esi
         // 004055d9: ror eax, b1 0x2
         // 004055dc: xor ebx, eax
         // 004055de: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004055e1: mov eax, edi
         // 004055e3: or eax, esi
         // 004055e5: and eax, edx
         // 004055e7: and edi, esi
         // 004055e9: or eax, edi
         // 004055eb: add eax, ebx
         // 004055ed: mov ss:[ebp+0xffffffffffffffec], eax
         // 004055f0: mov eax, ss:[ebp+0xffffffffffffff78]
         // 004055f6: mov ebx, eax
         // 004055f8: mov edi, eax
         // 004055fa: shr eax, b1 0x3
         // 004055fd: rol ebx, b1 0xe
         // 00405600: ror edi, b1 0x7
         // 00405603: xor ebx, edi
         // 00405605: mov edi, ss:[ebp+0xffffffffffffffac]
         // 00405608: xor ebx, eax
         // 0040560a: add ebx, ss:[ebp+0xffffffffffffff98]
         // 0040560d: mov eax, edi
         // 0040560f: rol eax, b1 0xf
         // 00405612: rol edi, b1 0xd
         // 00405615: xor eax, edi
         // 00405617: mov edi, ss:[ebp+0xffffffffffffffac]
         // 0040561a: shr edi, b1 0xa
         // 0040561d: xor eax, edi
         // 0040561f: add eax, ebx
         // 00405621: add eax, ss:[ebp+0xffffffffffffff74]
         // 00405627: mov ss:[ebp+0xffffffffffffffb4], eax
         // 0040562a: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 0040562d: mov edi, eax
         // 0040562f: ror edi, b1 0xb
         // 00405632: mov ebx, eax
         // 00405634: rol ebx, b1 0x7
         // 00405637: xor edi, ebx
         // 00405639: ror eax, b1 0x6
         // 0040563c: xor edi, eax
         // 0040563e: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00405641: xor eax, ss:[ebp+0xffffffffffffffe0]
         // 00405644: add edi, ss:[ebp+0xffffffffffffffb4]
         // 00405647: and eax, ss:[ebp+0xfffffffffffffff8]
         // 0040564a: mov ebx, esi
         // 0040564c: xor eax, ss:[ebp+0xffffffffffffffe0]
         // 0040564f: add eax, edi
         // 00405651: lea ecx, ds:[eax+ecx+0x5b9cca4f]
         // 00405658: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0040565b: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 0040565e: add edx, ecx
         // 00405660: mov edi, eax
         // 00405662: ror edi, b1 0xd
         // 00405665: mov ecx, eax
         // 00405667: rol ecx, b1 0xa
         // 0040566a: xor edi, ecx
         // 0040566c: mov ecx, eax
         // 0040566e: ror ecx, b1 0x2
         // 00405671: xor edi, ecx
         // 00405673: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00405676: mov ecx, esi
         // 00405678: or ecx, eax
         // 0040567a: and ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040567d: and ebx, eax
         // 0040567f: or ecx, ebx
         // 00405681: add ecx, edi
         // 00405683: mov ss:[ebp+0xffffffffffffffe8], ecx
         // 00405686: mov ecx, ss:[ebp+0xffffffffffffff7c]
         // 0040568c: mov ebx, ecx
         // 0040568e: mov edi, ecx
         // 00405690: shr ecx, b1 0x3
         // 00405693: rol ebx, b1 0xe
         // 00405696: ror edi, b1 0x7
         // 00405699: xor ebx, edi
         // 0040569b: xor ebx, ecx
         // 0040569d: add ebx, ss:[ebp+0xffffffffffffff9c]
         // 004056a0: mov edi, ss:[ebp+0xffffffffffffffb0]
         // 004056a3: mov ecx, edi
         // 004056a5: rol ecx, b1 0xf
         // 004056a8: rol edi, b1 0xd
         // 004056ab: xor ecx, edi
         // 004056ad: mov edi, ss:[ebp+0xffffffffffffffb0]
         // 004056b0: shr edi, b1 0xa
         // 004056b3: xor ecx, edi
         // 004056b5: add ecx, ebx
         // 004056b7: add ecx, ss:[ebp+0xffffffffffffff78]
         // 004056bd: mov edi, edx
         // 004056bf: mov ss:[ebp+0xffffffffffffffb8], ecx
         // 004056c2: mov ecx, edx
         // 004056c4: ror ecx, b1 0xb
         // 004056c7: rol edi, b1 0x7
         // 004056ca: xor ecx, edi
         // 004056cc: mov edi, edx
         // 004056ce: ror edi, b1 0x6
         // 004056d1: xor ecx, edi
         // 004056d3: add ecx, ss:[ebp+0xffffffffffffffb8]
         // 004056d6: mov edi, ss:[ebp+0xffffffffffffffe4]
         // 004056d9: xor edi, ss:[ebp+0xfffffffffffffff8]
         // 004056dc: and edi, edx
         // 004056de: xor edi, ss:[ebp+0xffffffffffffffe4]
         // 004056e1: add edi, ecx
         // 004056e3: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 004056e6: lea ecx, ds:[edi+ecx+0x682e6ff3]
         // 004056ed: add ss:[ebp+0xfffffffffffffff4], ecx
         // 004056f0: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 004056f3: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 004056f6: mov ebx, ecx
         // 004056f8: ror ebx, b1 0xd
         // 004056fb: mov edi, ecx
         // 004056fd: rol edi, b1 0xa
         // 00405700: xor ebx, edi
         // 00405702: mov edi, ecx
         // 00405704: ror edi, b1 0x2
         // 00405707: xor ebx, edi
         // 00405709: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040570c: mov edi, eax
         // 0040570e: or edi, ecx
         // 00405710: and edi, esi
         // 00405712: mov ss:[ebp+0xffffffffffffffdc], edi
         // 00405715: mov edi, eax
         // 00405717: and edi, ecx
         // 00405719: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 0040571c: or ecx, edi
         // 0040571e: add ecx, ebx
         // 00405720: mov ss:[ebp+0xffffffffffffffe0], ecx
         // 00405723: mov ecx, ss:[ebp+0xffffffffffffff80]
         // 00405726: mov ebx, ecx
         // 00405728: mov edi, ecx
         // 0040572a: rol ebx, b1 0xe
         // 0040572d: ror edi, b1 0x7
         // 00405730: xor ebx, edi
         // 00405732: mov edi, ss:[ebp+0xffffffffffffffb4]
         // 00405735: shr ecx, b1 0x3
         // 00405738: xor ebx, ecx
         // 0040573a: add ebx, ss:[ebp+0xffffffffffffffa0]
         // 0040573d: mov ecx, edi
         // 0040573f: rol ecx, b1 0xf
         // 00405742: rol edi, b1 0xd
         // 00405745: xor ecx, edi
         // 00405747: mov edi, ss:[ebp+0xffffffffffffffb4]
         // 0040574a: shr edi, b1 0xa
         // 0040574d: xor ecx, edi
         // 0040574f: add ecx, ebx
         // 00405751: add ecx, ss:[ebp+0xffffffffffffff7c]
         // 00405757: mov ss:[ebp+0xffffffffffffffbc], ecx
         // 0040575a: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040575d: mov edi, ecx
         // 0040575f: ror edi, b1 0xb
         // 00405762: mov ebx, ecx
         // 00405764: rol ebx, b1 0x7
         // 00405767: xor edi, ebx
         // 00405769: mov ebx, ecx
         // 0040576b: ror ebx, b1 0x6
         // 0040576e: xor edi, ebx
         // 00405770: add edi, ss:[ebp+0xffffffffffffffbc]
         // 00405773: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00405776: xor ebx, edx
         // 00405778: and ebx, ecx
         // 0040577a: xor ebx, ss:[ebp+0xfffffffffffffff8]
         // 0040577d: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 00405780: add ebx, edi
         // 00405782: lea ecx, ds:[ebx+ecx+0x748f82ee]
         // 00405789: add esi, ecx
         // 0040578b: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 0040578e: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 00405791: mov ebx, ecx
         // 00405793: mov edi, ecx
         // 00405795: ror ebx, b1 0xd
         // 00405798: rol edi, b1 0xa
         // 0040579b: xor ebx, edi
         // 0040579d: mov edi, ecx
         // 0040579f: ror edi, b1 0x2
         // 004057a2: xor ebx, edi
         // 004057a4: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004057a7: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 004057aa: or edi, ecx
         // 004057ac: and edi, eax
         // 004057ae: mov ss:[ebp+0xffffffffffffffe4], edi
         // 004057b1: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 004057b4: and edi, ecx
         // 004057b6: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 004057b9: or ecx, edi
         // 004057bb: add ecx, ebx
         // 004057bd: mov ss:[ebp+0xffffffffffffffe4], ecx
         // 004057c0: mov ecx, ss:[ebp+0xffffffffffffff84]
         // 004057c3: mov ebx, ecx
         // 004057c5: mov edi, ecx
         // 004057c7: shr ecx, b1 0x3
         // 004057ca: rol ebx, b1 0xe
         // 004057cd: ror edi, b1 0x7
         // 004057d0: xor ebx, edi
         // 004057d2: mov edi, ss:[ebp+0xffffffffffffffb8]
         // 004057d5: xor ebx, ecx
         // 004057d7: add ebx, ss:[ebp+0xffffffffffffffa4]
         // 004057da: mov ecx, edi
         // 004057dc: rol ecx, b1 0xf
         // 004057df: rol edi, b1 0xd
         // 004057e2: xor ecx, edi
         // 004057e4: mov edi, ss:[ebp+0xffffffffffffffb8]
         // 004057e7: shr edi, b1 0xa
         // 004057ea: xor ecx, edi
         // 004057ec: add ecx, ebx
         // 004057ee: add ecx, ss:[ebp+0xffffffffffffff80]
         // 004057f1: mov edi, esi
         // 004057f3: mov ss:[ebp+0xffffffffffffffc0], ecx
         // 004057f6: mov ecx, esi
         // 004057f8: ror ecx, b1 0xb
         // 004057fb: rol edi, b1 0x7
         // 004057fe: xor ecx, edi
         // 00405800: mov edi, esi
         // 00405802: ror edi, b1 0x6
         // 00405805: xor ecx, edi
         // 00405807: add ecx, ss:[ebp+0xffffffffffffffc0]
         // 0040580a: mov edi, edx
         // 0040580c: xor edi, ss:[ebp+0xfffffffffffffff4]
         // 0040580f: and edi, esi
         // 00405811: xor edi, edx
         // 00405813: add edi, ecx
         // 00405815: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 00405818: lea ecx, ds:[edi+ecx+0x78a5636f]
         // 0040581f: add eax, ecx
         // 00405821: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00405824: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 00405827: mov edi, ecx
         // 00405829: ror edi, b1 0xd
         // 0040582c: mov ebx, ecx
         // 0040582e: rol ebx, b1 0xa
         // 00405831: xor edi, ebx
         // 00405833: mov ebx, ecx
         // 00405835: or ecx, ss:[ebp+0xffffffffffffffe0]
         // 00405838: ror ebx, b1 0x2
         // 0040583b: and ecx, ss:[ebp+0xffffffffffffffe8]
         // 0040583e: xor edi, ebx
         // 00405840: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00405843: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 00405846: and ebx, ss:[ebp+0xffffffffffffffe0]
         // 00405849: or ecx, ebx
         // 0040584b: add ecx, edi
         // 0040584d: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 00405850: mov ecx, ss:[ebp+0xffffffffffffff88]
         // 00405853: mov ebx, ecx
         // 00405855: rol ebx, b1 0xe
         // 00405858: mov edi, ecx
         // 0040585a: ror edi, b1 0x7
         // 0040585d: xor ebx, edi
         // 0040585f: mov edi, ss:[ebp+0xffffffffffffffbc]
         // 00405862: shr ecx, b1 0x3
         // 00405865: xor ebx, ecx
         // 00405867: add ebx, ss:[ebp+0xffffffffffffffa8]
         // 0040586a: mov ecx, edi
         // 0040586c: rol ecx, b1 0xf
         // 0040586f: rol edi, b1 0xd
         // 00405872: xor ecx, edi
         // 00405874: mov edi, ss:[ebp+0xffffffffffffffbc]
         // 00405877: shr edi, b1 0xa
         // 0040587a: xor ecx, edi
         // 0040587c: add ecx, ebx
         // 0040587e: add ecx, ss:[ebp+0xffffffffffffff84]
         // 00405881: mov edi, eax
         // 00405883: ror edi, b1 0xb
         // 00405886: mov ss:[ebp+0xffffffffffffffc4], ecx
         // 00405889: mov ecx, eax
         // 0040588b: rol ecx, b1 0x7
         // 0040588e: xor edi, ecx
         // 00405890: mov ecx, eax
         // 00405892: ror ecx, b1 0x6
         // 00405895: xor edi, ecx
         // 00405897: add edi, ss:[ebp+0xffffffffffffffc4]
         // 0040589a: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040589d: mov ebx, ecx
         // 0040589f: xor ebx, esi
         // 004058a1: and ebx, eax
         // 004058a3: xor ebx, ecx
         // 004058a5: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 004058a8: add ebx, edi
         // 004058aa: lea edx, ds:[ebx+edx+0xffffffff84c87814]
         // 004058b1: add ss:[ebp+0xffffffffffffffe8], edx
         // 004058b4: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 004058b7: mov ss:[ebp+0xfffffffffffffffc], edx
         // 004058ba: mov edi, ecx
         // 004058bc: ror edi, b1 0xd
         // 004058bf: mov edx, ecx
         // 004058c1: rol edx, b1 0xa
         // 004058c4: xor edi, edx
         // 004058c6: mov edx, ecx
         // 004058c8: ror edx, b1 0x2
         // 004058cb: xor edi, edx
         // 004058cd: add edi, ss:[ebp+0xfffffffffffffffc]
         // 004058d0: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 004058d3: or edx, ecx
         // 004058d5: and edx, ss:[ebp+0xffffffffffffffe0]
         // 004058d8: and ebx, ecx
         // 004058da: or edx, ebx
         // 004058dc: add edx, edi
         // 004058de: mov ss:[ebp+0xffffffffffffffdc], edx
         // 004058e1: mov edx, ss:[ebp+0xffffffffffffff8c]
         // 004058e4: mov ebx, edx
         // 004058e6: rol ebx, b1 0xe
         // 004058e9: mov edi, edx
         // 004058eb: ror edi, b1 0x7
         // 004058ee: xor ebx, edi
         // 004058f0: mov edi, ss:[ebp+0xffffffffffffffc0]
         // 004058f3: shr edx, b1 0x3
         // 004058f6: xor ebx, edx
         // 004058f8: mov edx, edi
         // 004058fa: rol edx, b1 0xf
         // 004058fd: rol edi, b1 0xd
         // 00405900: xor edx, edi
         // 00405902: mov edi, ss:[ebp+0xffffffffffffffc0]
         // 00405905: add ebx, ss:[ebp+0xffffffffffffffac]
         // 00405908: shr edi, b1 0xa
         // 0040590b: xor edx, edi
         // 0040590d: add edx, ebx
         // 0040590f: add edx, ss:[ebp+0xffffffffffffff88]
         // 00405912: mov ss:[ebp+0xffffffffffffffc8], edx
         // 00405915: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 00405918: mov edi, edx
         // 0040591a: ror edi, b1 0xb
         // 0040591d: mov ebx, edx
         // 0040591f: rol ebx, b1 0x7
         // 00405922: xor edi, ebx
         // 00405924: mov ebx, edx
         // 00405926: ror ebx, b1 0x6
         // 00405929: xor edi, ebx
         // 0040592b: add edi, ss:[ebp+0xffffffffffffffc8]
         // 0040592e: mov ebx, esi
         // 00405930: xor ebx, eax
         // 00405932: and ebx, edx
         // 00405934: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 00405937: xor ebx, esi
         // 00405939: add ebx, edi
         // 0040593b: lea edx, ds:[ebx+edx+0xffffffff8cc70208]
         // 00405942: add ss:[ebp+0xffffffffffffffe0], edx
         // 00405945: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00405948: mov edx, ss:[ebp+0xffffffffffffffdc]
         // 0040594b: mov ebx, edx
         // 0040594d: mov edi, edx
         // 0040594f: ror ebx, b1 0xd
         // 00405952: rol edi, b1 0xa
         // 00405955: xor ebx, edi
         // 00405957: mov edi, edx
         // 00405959: ror edi, b1 0x2
         // 0040595c: xor ebx, edi
         // 0040595e: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00405961: mov edi, ecx
         // 00405963: or edi, edx
         // 00405965: and edi, ss:[ebp+0xffffffffffffffe4]
         // 00405968: mov ss:[ebp+0xfffffffffffffff8], edi
         // 0040596b: mov edi, ecx
         // 0040596d: and edi, edx
         // 0040596f: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 00405972: or edx, edi
         // 00405974: add edx, ebx
         // 00405976: mov ss:[ebp+0xfffffffffffffff4], edx
         // 00405979: mov edx, ss:[ebp+0xffffffffffffff90]
         // 0040597c: mov ebx, edx
         // 0040597e: mov edi, edx
         // 00405980: shr edx, b1 0x3
         // 00405983: rol ebx, b1 0xe
         // 00405986: ror edi, b1 0x7
         // 00405989: xor ebx, edi
         // 0040598b: mov edi, ss:[ebp+0xffffffffffffffc4]
         // 0040598e: xor ebx, edx
         // 00405990: add ebx, ss:[ebp+0xffffffffffffffb0]
         // 00405993: mov edx, edi
         // 00405995: rol edx, b1 0xf
         // 00405998: rol edi, b1 0xd
         // 0040599b: xor edx, edi
         // 0040599d: mov edi, ss:[ebp+0xffffffffffffffc4]
         // 004059a0: shr edi, b1 0xa
         // 004059a3: xor edx, edi
         // 004059a5: add edx, ebx
         // 004059a7: add edx, ss:[ebp+0xffffffffffffff8c]
         // 004059aa: mov ss:[ebp+0xffffffffffffffcc], edx
         // 004059ad: mov edx, ss:[ebp+0xffffffffffffffe0]
         // 004059b0: mov edi, edx
         // 004059b2: mov ebx, edx
         // 004059b4: ror edi, b1 0xb
         // 004059b7: rol ebx, b1 0x7
         // 004059ba: xor edi, ebx
         // 004059bc: ror edx, b1 0x6
         // 004059bf: xor edi, edx
         // 004059c1: add edi, ss:[ebp+0xffffffffffffffcc]
         // 004059c4: mov edx, eax
         // 004059c6: xor edx, ss:[ebp+0xffffffffffffffe8]
         // 004059c9: and edx, ss:[ebp+0xffffffffffffffe0]
         // 004059cc: xor edx, eax
         // 004059ce: add edx, edi
         // 004059d0: lea esi, ds:[edx+esi+0xffffffff90befffa]
         // 004059d7: mov ss:[ebp+0xfffffffffffffffc], esi
         // 004059da: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 004059dd: add edx, esi
         // 004059df: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 004059e2: mov ebx, esi
         // 004059e4: mov edi, esi
         // 004059e6: ror ebx, b1 0xd
         // 004059e9: rol edi, b1 0xa
         // 004059ec: xor ebx, edi
         // 004059ee: mov edi, esi
         // 004059f0: ror edi, b1 0x2
         // 004059f3: xor ebx, edi
         // 004059f5: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004059f8: mov edi, ss:[ebp+0xffffffffffffffdc]
         // 004059fb: or edi, esi
         // 004059fd: and edi, ecx
         // 004059ff: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00405a02: mov edi, ss:[ebp+0xffffffffffffffdc]
         // 00405a05: and edi, esi
         // 00405a07: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00405a0a: or esi, edi
         // 00405a0c: add esi, ebx
         // 00405a0e: mov ss:[ebp+0xfffffffffffffff0], esi
         // 00405a11: mov esi, ss:[ebp+0xffffffffffffff94]
         // 00405a14: mov ebx, esi
         // 00405a16: mov edi, esi
         // 00405a18: shr esi, b1 0x3
         // 00405a1b: rol ebx, b1 0xe
         // 00405a1e: ror edi, b1 0x7
         // 00405a21: xor ebx, edi
         // 00405a23: mov edi, ss:[ebp+0xffffffffffffffc8]
         // 00405a26: xor ebx, esi
         // 00405a28: add ebx, ss:[ebp+0xffffffffffffffb4]
         // 00405a2b: mov esi, edi
         // 00405a2d: rol esi, b1 0xf
         // 00405a30: rol edi, b1 0xd
         // 00405a33: xor esi, edi
         // 00405a35: mov edi, ss:[ebp+0xffffffffffffffc8]
         // 00405a38: shr edi, b1 0xa
         // 00405a3b: xor esi, edi
         // 00405a3d: add esi, ebx
         // 00405a3f: add esi, ss:[ebp+0xffffffffffffff90]
         // 00405a42: mov edi, edx
         // 00405a44: mov ss:[ebp+0xffffffffffffffd0], esi
         // 00405a47: mov esi, edx
         // 00405a49: ror esi, b1 0xb
         // 00405a4c: rol edi, b1 0x7
         // 00405a4f: xor esi, edi
         // 00405a51: mov edi, edx
         // 00405a53: ror edi, b1 0x6
         // 00405a56: xor esi, edi
         // 00405a58: add esi, ss:[ebp+0xffffffffffffffd0]
         // 00405a5b: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 00405a5e: xor edi, ss:[ebp+0xffffffffffffffe0]
         // 00405a61: and edi, edx
         // 00405a63: xor edi, ss:[ebp+0xffffffffffffffe8]
         // 00405a66: add edi, esi
         // 00405a68: lea eax, ds:[edi+eax+0xffffffffa4506ceb]
         // 00405a6f: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 00405a72: add ecx, eax
         // 00405a74: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00405a77: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00405a7a: mov ebx, eax
         // 00405a7c: ror ebx, b1 0xd
         // 00405a7f: mov esi, eax
         // 00405a81: rol esi, b1 0xa
         // 00405a84: xor ebx, esi
         // 00405a86: mov esi, eax
         // 00405a88: ror esi, b1 0x2
         // 00405a8b: xor ebx, esi
         // 00405a8d: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00405a90: mov esi, edi
         // 00405a92: or esi, eax
         // 00405a94: and esi, ss:[ebp+0xffffffffffffffdc]
         // 00405a97: and edi, eax
         // 00405a99: mov eax, ss:[ebp+0xffffffffffffff98]
         // 00405a9c: or esi, edi
         // 00405a9e: add esi, ebx
         // 00405aa0: mov ebx, eax
         // 00405aa2: mov ss:[ebp+0xffffffffffffffec], esi
         // 00405aa5: rol ebx, b1 0xe
         // 00405aa8: mov edi, eax
         // 00405aaa: shr eax, b1 0x3
         // 00405aad: ror edi, b1 0x7
         // 00405ab0: xor ebx, edi
         // 00405ab2: xor ebx, eax
         // 00405ab4: add ebx, ss:[ebp+0xffffffffffffffb8]
         // 00405ab7: mov edi, ss:[ebp+0xffffffffffffffcc]
         // 00405aba: mov eax, edi
         // 00405abc: rol eax, b1 0xf
         // 00405abf: rol edi, b1 0xd
         // 00405ac2: xor eax, edi
         // 00405ac4: mov edi, ss:[ebp+0xffffffffffffffcc]
         // 00405ac7: shr edi, b1 0xa
         // 00405aca: xor eax, edi
         // 00405acc: add eax, ebx
         // 00405ace: add eax, ss:[ebp+0xffffffffffffff94]
         // 00405ad1: mov edi, ecx
         // 00405ad3: mov ss:[ebp+0xffffffffffffffd4], eax
         // 00405ad6: ror edi, b1 0xb
         // 00405ad9: mov eax, ecx
         // 00405adb: rol eax, b1 0x7
         // 00405ade: xor edi, eax
         // 00405ae0: mov eax, ecx
         // 00405ae2: ror eax, b1 0x6
         // 00405ae5: xor edi, eax
         // 00405ae7: add edi, ss:[ebp+0xffffffffffffffd4]
         // 00405aea: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 00405aed: mov ebx, edx
         // 00405aef: xor ebx, eax
         // 00405af1: and ebx, ecx
         // 00405af3: xor ebx, eax
         // 00405af5: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00405af8: add ebx, edi
         // 00405afa: lea eax, ds:[ebx+eax+0xffffffffbef9a3f7]
         // 00405b01: add ss:[ebp+0xffffffffffffffdc], eax
         // 00405b04: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00405b07: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00405b0a: mov edi, esi
         // 00405b0c: ror edi, b1 0xd
         // 00405b0f: mov eax, esi
         // 00405b11: rol eax, b1 0xa
         // 00405b14: xor edi, eax
         // 00405b16: mov eax, esi
         // 00405b18: ror eax, b1 0x2
         // 00405b1b: xor edi, eax
         // 00405b1d: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00405b20: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00405b23: or eax, esi
         // 00405b25: and eax, ss:[ebp+0xfffffffffffffff4]
         // 00405b28: and ebx, esi
         // 00405b2a: or eax, ebx
         // 00405b2c: add eax, edi
         // 00405b2e: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00405b31: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 00405b34: mov esi, eax
         // 00405b36: ror esi, b1 0xb
         // 00405b39: mov edi, eax
         // 00405b3b: rol edi, b1 0x7
         // 00405b3e: xor esi, edi
         // 00405b40: ror eax, b1 0x6
         // 00405b43: xor esi, eax
         // 00405b45: mov eax, ss:[ebp+0xffffffffffffff9c]
         // 00405b48: mov edi, eax
         // 00405b4a: rol edi, b1 0xe
         // 00405b4d: mov ebx, eax
         // 00405b4f: shr eax, b1 0x3
         // 00405b52: ror ebx, b1 0x7
         // 00405b55: xor edi, ebx
         // 00405b57: xor edi, eax
         // 00405b59: mov eax, ss:[ebp+0xffffffffffffffd0]
         // 00405b5c: add esi, edi
         // 00405b5e: mov edi, eax
         // 00405b60: mov ebx, eax
         // 00405b62: rol edi, b1 0xf
         // 00405b65: rol ebx, b1 0xd
         // 00405b68: shr eax, b1 0xa
         // 00405b6b: xor edi, ebx
         // 00405b6d: xor edi, eax
         // 00405b6f: add edi, ss:[ebp+0xffffffffffffffbc]
         // 00405b72: mov eax, edx
         // 00405b74: xor eax, ecx
         // 00405b76: and eax, ss:[ebp+0xffffffffffffffdc]
         // 00405b79: add edi, esi
         // 00405b7b: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 00405b7e: xor eax, edx
         // 00405b80: add eax, edi
         // 00405b82: add eax, ss:[ebp+0xffffffffffffff98]
         // 00405b85: lea eax, ds:[eax+esi+0xffffffffc67178f2]
         // 00405b8c: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 00405b8f: mov edi, esi
         // 00405b91: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00405b94: mov eax, esi
         // 00405b96: ror edi, b1 0xd
         // 00405b99: rol eax, b1 0xa
         // 00405b9c: xor edi, eax
         // 00405b9e: mov eax, esi
         // 00405ba0: ror eax, b1 0x2
         // 00405ba3: xor edi, eax
         // 00405ba5: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00405ba8: mov ebx, eax
         // 00405baa: or ebx, esi
         // 00405bac: and ebx, ss:[ebp+0xfffffffffffffff0]
         // 00405baf: and eax, esi
         // 00405bb1: or ebx, eax
         // 00405bb3: mov eax, ss:[ebp+0x8]
         // 00405bb6: add edi, ds:[eax+0x8]
         // 00405bb9: add ebx, edi
         // 00405bbb: mov edi, ss:[ebp+0xfffffffffffffffc]
         // 00405bbe: add ebx, edi
         // 00405bc0: mov ds:[eax+0x8], ebx
         // 00405bc3: mov ebx, ds:[eax+0xc]
         // 00405bc6: add ebx, esi
         // 00405bc8: mov esi, ds:[eax+0x10]
         // 00405bcb: add esi, ss:[ebp+0xffffffffffffffec]
         // 00405bce: mov ds:[eax+0xc], ebx
         // 00405bd1: mov ds:[eax+0x10], esi
         // 00405bd4: mov esi, ds:[eax+0x14]
         // 00405bd7: add esi, ss:[ebp+0xfffffffffffffff0]
         // 00405bda: mov ds:[eax+0x14], esi
         // 00405bdd: mov esi, ds:[eax+0x18]
         // 00405be0: add esi, edi
         // 00405be2: add esi, ss:[ebp+0xfffffffffffffff4]
         // 00405be5: pop edi
         // 00405be6: mov ds:[eax+0x18], esi
         // 00405be9: mov esi, ds:[eax+0x1c]
         // 00405bec: add esi, ss:[ebp+0xffffffffffffffdc]
         // 00405bef: mov ds:[eax+0x1c], esi
         // 00405bf2: mov esi, ds:[eax+0x20]
         // 00405bf5: add esi, ecx
         // 00405bf7: mov ecx, ds:[eax+0x24]
         // 00405bfa: mov ds:[eax+0x20], esi
         // 00405bfd: add ecx, edx
         // 00405bff: pop esi
         // 00405c00: mov ds:[eax+0x24], ecx
         // 00405c03: pop ebx
         // 00405c04: mov esp, ebp
         // 00405c06: pop ebp
         // 00405c07: retn 

  }
  condition:
    all of them
}
