Return-Path: <kasan-dev+bncBCVLFUWIZIBBBTHYV74AKGQETLEZDCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id BC70121CF73
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jul 2020 08:16:45 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id a24sf8663200oos.10
        for <lists+kasan-dev@lfdr.de>; Sun, 12 Jul 2020 23:16:45 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0TpUu1PhxrocUSfDTapqF0bdtynGyBCNZwx0a2lzG+4=;
        b=OrR/+q+Qfyi+hn7YHeBr8XW6k9TjjpvSmKb8PPZnwE8BCgKrnNdbxsfoi9xBPpeYDM
         86du1S10t++LYaRO0NSrjQfDUNGRDMla81Oa4sQmJpIVpzJRvjVzxX9QmXBsR22PR/Kj
         r5G88LR2lROpLat46Khmsl7DVOw38rPj2NGo+qcOFh16bFMU8OQVQEucc6tHyzlIZdW7
         FKz7tLjodmcQ9sQig0mPaQpLZdyr1VGSfSiRrUlW0cQEH8I65I29wwNgxRm9ABMWjI/9
         ZIsvVgrfBYhzBgEYZ1zEsgyCbmEWbLtbeN9TLIq3haGvYrY0Rj6ssNG4d63oy2yJSlyO
         XDFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0TpUu1PhxrocUSfDTapqF0bdtynGyBCNZwx0a2lzG+4=;
        b=Nghj/Hqr5iE06aLEQ1OvrKNWq8ehP0d/9KGdCvtzluX6B6PIuonDcvpfTNLe9zqquC
         8tm83d3wsJVwHmJRBwSEYyOjy6kAupv4ha4IHt5Bah1zneN9touGtRfJV5MnRFjRbhW2
         28OM1w2MiBTTc/qKF3e4RA5j5xu0WP1ZFMzrv85qZd1YSz1v6Q6nDqrRT2K1TldGP+tD
         EeGYPwjf7t4ZkazakxYqclCgiZuAbQxmMEoXD2mjiAMbjkyUJanOIlRuRXX3VmKwvB3X
         QDl3GXOoGVaTtgd8EQUXDO4PiWN7K0RC2VYsDmuPI1/eWyhdxyOIsA0rKHCYmNCLDukF
         E+KA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Kudzl3sgOUWWJO6i5tuj6ClQuqbo0oQZmDYYq94xlimsKlMYg
	6YYbmqIUvAdXALgth/enHS4=
X-Google-Smtp-Source: ABdhPJw3d8iYSFWtAq5zRyMiMfnOqf2kZWYFTmBg9Ef9jd9z6vsEmOjpLZW/0ufzN6Dm+uvqmYiFxw==
X-Received: by 2002:a9d:6f85:: with SMTP id h5mr23458455otq.81.1594621004664;
        Sun, 12 Jul 2020 23:16:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:3c9:: with SMTP id o9ls3120759oie.6.gmail; Sun, 12
 Jul 2020 23:16:44 -0700 (PDT)
X-Received: by 2002:aca:5693:: with SMTP id k141mr12426826oib.35.1594621004227;
        Sun, 12 Jul 2020 23:16:44 -0700 (PDT)
Date: Sun, 12 Jul 2020 23:16:43 -0700 (PDT)
From: hyouyan@126.com
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <f98a41c3-2748-4dff-970a-fd656c40e0fdo@googlegroups.com>
Subject: Porting kasan for arm v2 to kernel 4.14, appear crash on
 kasan_pte_populate
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_844_204313078.1594621003678"
X-Original-Sender: hyouyan@126.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

------=_Part_844_204313078.1594621003678
Content-Type: multipart/alternative; 
	boundary="----=_Part_845_383446880.1594621003678"

------=_Part_845_383446880.1594621003678
Content-Type: text/plain; charset="UTF-8"

Hi admin:
     I plan to port kasan for arm v2 patch to arm kernel 4.14. But appear 
crash, fellow is the crash log:

     0.000000] c0 kasan: base end 80000000, bffc0000
[    0.000000] c0 kasan: populating shadow for b7000000, bc200000
[    0.000000] c0 kasan:  create_mapping addr b7000000,
[    0.000000] c0 Unable to handle kernel paging request at virtual address 
a86f7000
[    0.000000] c0 pgd = (ptrval)
[    0.000000] c0 [a86f7000] *pgd=00000000
[    0.000000] c0 Internal error: Oops: 5 [#1] PREEMPT SMP ARM
[    0.000000] c0 Modules linked in:
[    0.000000] c0 CPU: 0 PID: 0 Comm: swapper Not tainted 4.14.133+ #83
[    0.000000] c0 Hardware name: Generic DT based system
[    0.000000] c0 task: (ptrval) task.stack: (ptrval)
[    0.000000] c0 PC is at kasan_pte_populate+0x2c/0xcc
[    0.000000] c0 LR is at kasan_init+0x258/0x2b0
[    0.000000] c0 pc : [<c170b8cc>]    lr : [<c170bc7c>]    psr: a00000d3
[    0.000000] c0 sp : c1803d88  ip : c170b8b4  fp : c1803da4
[    0.000000] c0 r10: c14c2354  r9 : b7000000  r8 : c18b3280
[    0.000000] c0 r7 : c18b3e00  r6 : b7000000  r5 : c1545034  r4 : bc200000
[    0.000000] c0 r3 : a86f7000  r2 : ffffffff  r1 : 00000000  r0 : c0006dc0
[    0.000000] c0 Flags: NzCv  IRQs off  FIQs off  Mode SVC_32  ISA ARM  
Segment none
[    0.000000] c0 Control: 10c5383d  Table: 817a4000  DAC: 00000051
[    0.000000] c0 Process swapper (pid: 0, stack limit = 0x(ptrval))
[    0.000000] c0 Stack: (0xc1803d88 to 0xc1804000)
[    0.000000] c0 3d80:                   bc200000 c1545034 c1c60ee0 
c18b3e00 c1803ddc c1803da8
[    0.000000] c0 3da0: c170bc7c c170b8ac c15452ec 8000406a 00000000 
c1790ec0 c1803ec0 c1bc08c0
[    0.000000] c0 3dc0: c1803f40 c179d23c 80008000 c20e43a0 c1803eec 
c1803de0 c1706020 c170ba30
[    0.000000] c0 3de0: 0000006c 10c5383d c1803e0c c1803df8 c01c7a3c 
c01c759c 00000024 b73007c4
[    0.000000] c0 3e00: c1803e44 c1803e10 c01c94f4 c01c7a18 00000001 
00000030 c1803e44 b73007cc
[    0.000000] c0 3e20: 41b58ab3 c14c01b0 c1705990 00040e85 c180b200 
00000000 c1803edc c1803e48
[    0.000000] c0 3e40: c01c89c8 c01c92bc c1803e6c c1803e58 c0f08478 
c0358a94 c1817348 c1856440
[    0.000000] c0 3e60: 41b58ab3 c14c30bd c01c894c c0f08458 00000001 
c18564e0 c1803e9c c1803e88
[    0.000000] c0 3e80: c1803ee4 c03588c4 c1879240 00000005 c1803eec 
c1803ea0 c1803eec c1803ea8
[    0.000000] c0 3ea0: c0275760 c0358b34 c1803eec c1803ec8 c1705578 
c01c895c c1879284 00000000
[    0.000000] c0 3ec0: c1803eec b73007e4 c180b21c c1803fc0 c180b208 
00040e85 c180b200 00000000
[    0.000000] c0 3ee0: c1803ff4 c1803ef0 c1700c18 c170599c 00000000 
00000000 00000000 00000000
[    0.000000] c0 3f00: 00000000 00000000 00000000 00000000 00000000 
00000000 00000000 00000000
[    0.000000] c0 3f20: 41b58ab3 c14bf229 c1700b64 00000000 00000000 
00000000 00000000 00000000
[    0.000000] c0 3f40: c179d23c 00000000 00000000 00000000 00000000 
00000000 00000000 00000000
[    0.000000] c0 3f60: 00000000 00000000 00000000 00000000 00000000 
00000000 00000000 00000000
[    0.000000] c0 3f80: 00000000 00000000 00000000 00000000 00000000 
00000000 00000000 00000000
[    0.000000] c0 3fa0: 00000000 00000000 00000000 00000000 00000000 
00000000 00000000 c170b894
[    0.000000] c0 3fc0: c1bc0ba0 00000000 c179d238 c1bc0ba0 c180b21c 
c179d238 c181c344 8000406a
[    0.000000] c0 3fe0: 410fd034 00000000 00000000 c1803ff8 c0006fc0 
c1700b70 00000000 00000000
[    0.000000] c0 [<c170b8cc>] (kasan_pte_populate) from [<c170bc7c>] 
(kasan_init+0x258/0x2b0)
[    0.000000] c0 [<c170bc7c>] (kasan_init) from [<c1706020>] 
(setup_arch+0x690/0xd64)
[    0.000000] c0 [<c1706020>] (setup_arch) from [<c1700c18>] 
(start_kernel+0xb4/0x514)
[    0.000000] c0 [<c1700c18>] (start_kernel) from [<c0006fc0>] (0xc0006fc0)


Is there any config wrong?


thanks and best regards
youyan
    

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f98a41c3-2748-4dff-970a-fd656c40e0fdo%40googlegroups.com.

------=_Part_845_383446880.1594621003678
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hi admin:<div>=C2=A0 =C2=A0 =C2=A0I plan to port=C2=A0kasa=
n for arm v2 patch to arm=C2=A0kernel 4.14. But appear crash, fellow is the=
 crash log:</div><div><br></div><div><div>=C2=A0 =C2=A0 =C2=A00.000000] c0 =
kasan: base end 80000000, bffc0000</div><div>[=C2=A0 =C2=A0 0.000000] c0 ka=
san: populating shadow for b7000000, bc200000</div><div>[=C2=A0 =C2=A0 0.00=
0000] c0 kasan:=C2=A0 create_mapping addr b7000000,</div><div>[=C2=A0 =C2=
=A0 0.000000] c0 Unable to handle kernel paging request at virtual address =
a86f7000</div><div>[=C2=A0 =C2=A0 0.000000] c0 pgd =3D (ptrval)</div><div>[=
=C2=A0 =C2=A0 0.000000] c0 [a86f7000] *pgd=3D00000000</div><div>[=C2=A0 =C2=
=A0 0.000000] c0 Internal error: Oops: 5 [#1] PREEMPT SMP ARM</div><div>[=
=C2=A0 =C2=A0 0.000000] c0 Modules linked in:</div><div>[=C2=A0 =C2=A0 0.00=
0000] c0 CPU: 0 PID: 0 Comm: swapper Not tainted 4.14.133+ #83</div><div>[=
=C2=A0 =C2=A0 0.000000] c0 Hardware name: Generic DT based system</div><div=
>[=C2=A0 =C2=A0 0.000000] c0 task: (ptrval) task.stack: (ptrval)</div><div>=
[=C2=A0 =C2=A0 0.000000] c0 PC is at kasan_pte_populate+0x2c/0xcc</div><div=
>[=C2=A0 =C2=A0 0.000000] c0 LR is at kasan_init+0x258/0x2b0</div><div>[=C2=
=A0 =C2=A0 0.000000] c0 pc : [&lt;c170b8cc&gt;]=C2=A0 =C2=A0 lr : [&lt;c170=
bc7c&gt;]=C2=A0 =C2=A0 psr: a00000d3</div><div>[=C2=A0 =C2=A0 0.000000] c0 =
sp : c1803d88=C2=A0 ip : c170b8b4=C2=A0 fp : c1803da4</div><div>[=C2=A0 =C2=
=A0 0.000000] c0 r10: c14c2354=C2=A0 r9 : b7000000=C2=A0 r8 : c18b3280</div=
><div>[=C2=A0 =C2=A0 0.000000] c0 r7 : c18b3e00=C2=A0 r6 : b7000000=C2=A0 r=
5 : c1545034=C2=A0 r4 : bc200000</div><div>[=C2=A0 =C2=A0 0.000000] c0 r3 :=
 a86f7000=C2=A0 r2 : ffffffff=C2=A0 r1 : 00000000=C2=A0 r0 : c0006dc0</div>=
<div>[=C2=A0 =C2=A0 0.000000] c0 Flags: NzCv=C2=A0 IRQs off=C2=A0 FIQs off=
=C2=A0 Mode SVC_32=C2=A0 ISA ARM=C2=A0 Segment none</div><div>[=C2=A0 =C2=
=A0 0.000000] c0 Control: 10c5383d=C2=A0 Table: 817a4000=C2=A0 DAC: 0000005=
1</div><div><div>[=C2=A0 =C2=A0 0.000000] c0 Process swapper (pid: 0, stack=
 limit =3D 0x(ptrval))</div><div><div>[=C2=A0 =C2=A0 0.000000] c0 Stack: (0=
xc1803d88 to 0xc1804000)</div><div>[=C2=A0 =C2=A0 0.000000] c0 3d80:=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0bc200000 c154=
5034 c1c60ee0 c18b3e00 c1803ddc c1803da8</div><div>[=C2=A0 =C2=A0 0.000000]=
 c0 3da0: c170bc7c c170b8ac c15452ec 8000406a 00000000 c1790ec0 c1803ec0 c1=
bc08c0</div><div>[=C2=A0 =C2=A0 0.000000] c0 3dc0: c1803f40 c179d23c 800080=
00 c20e43a0 c1803eec c1803de0 c1706020 c170ba30</div><div>[=C2=A0 =C2=A0 0.=
000000] c0 3de0: 0000006c 10c5383d c1803e0c c1803df8 c01c7a3c c01c759c 0000=
0024 b73007c4</div><div>[=C2=A0 =C2=A0 0.000000] c0 3e00: c1803e44 c1803e10=
 c01c94f4 c01c7a18 00000001 00000030 c1803e44 b73007cc</div><div>[=C2=A0 =
=C2=A0 0.000000] c0 3e20: 41b58ab3 c14c01b0 c1705990 00040e85 c180b200 0000=
0000 c1803edc c1803e48</div><div>[=C2=A0 =C2=A0 0.000000] c0 3e40: c01c89c8=
 c01c92bc c1803e6c c1803e58 c0f08478 c0358a94 c1817348 c1856440</div><div>[=
=C2=A0 =C2=A0 0.000000] c0 3e60: 41b58ab3 c14c30bd c01c894c c0f08458 000000=
01 c18564e0 c1803e9c c1803e88</div><div>[=C2=A0 =C2=A0 0.000000] c0 3e80: c=
1803ee4 c03588c4 c1879240 00000005 c1803eec c1803ea0 c1803eec c1803ea8</div=
><div>[=C2=A0 =C2=A0 0.000000] c0 3ea0: c0275760 c0358b34 c1803eec c1803ec8=
 c1705578 c01c895c c1879284 00000000</div><div>[=C2=A0 =C2=A0 0.000000] c0 =
3ec0: c1803eec b73007e4 c180b21c c1803fc0 c180b208 00040e85 c180b200 000000=
00</div><div>[=C2=A0 =C2=A0 0.000000] c0 3ee0: c1803ff4 c1803ef0 c1700c18 c=
170599c 00000000 00000000 00000000 00000000</div><div>[=C2=A0 =C2=A0 0.0000=
00] c0 3f00: 00000000 00000000 00000000 00000000 00000000 00000000 00000000=
 00000000</div><div>[=C2=A0 =C2=A0 0.000000] c0 3f20: 41b58ab3 c14bf229 c17=
00b64 00000000 00000000 00000000 00000000 00000000</div><div>[=C2=A0 =C2=A0=
 0.000000] c0 3f40: c179d23c 00000000 00000000 00000000 00000000 00000000 0=
0000000 00000000</div><div>[=C2=A0 =C2=A0 0.000000] c0 3f60: 00000000 00000=
000 00000000 00000000 00000000 00000000 00000000 00000000</div><div>[=C2=A0=
 =C2=A0 0.000000] c0 3f80: 00000000 00000000 00000000 00000000 00000000 000=
00000 00000000 00000000</div><div>[=C2=A0 =C2=A0 0.000000] c0 3fa0: 0000000=
0 00000000 00000000 00000000 00000000 00000000 00000000 c170b894</div><div>=
[=C2=A0 =C2=A0 0.000000] c0 3fc0: c1bc0ba0 00000000 c179d238 c1bc0ba0 c180b=
21c c179d238 c181c344 8000406a</div><div>[=C2=A0 =C2=A0 0.000000] c0 3fe0: =
410fd034 00000000 00000000 c1803ff8 c0006fc0 c1700b70 00000000 00000000</di=
v><div>[=C2=A0 =C2=A0 0.000000] c0 [&lt;c170b8cc&gt;] (kasan_pte_populate) =
from [&lt;c170bc7c&gt;] (kasan_init+0x258/0x2b0)</div><div>[=C2=A0 =C2=A0 0=
.000000] c0 [&lt;c170bc7c&gt;] (kasan_init) from [&lt;c1706020&gt;] (setup_=
arch+0x690/0xd64)</div><div>[=C2=A0 =C2=A0 0.000000] c0 [&lt;c1706020&gt;] =
(setup_arch) from [&lt;c1700c18&gt;] (start_kernel+0xb4/0x514)</div><div>[=
=C2=A0 =C2=A0 0.000000] c0 [&lt;c1700c18&gt;] (start_kernel) from [&lt;c000=
6fc0&gt;] (0xc0006fc0)</div></div></div><div><br></div><div><br></div><div>=
Is there any config wrong?</div><div><br></div><div><br></div><div>thanks a=
nd best regards</div><div>youyan</div><div>=C2=A0 =C2=A0=C2=A0</div></div><=
/div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/f98a41c3-2748-4dff-970a-fd656c40e0fdo%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/f98a41c3-2748-4dff-970a-fd656c40e0fdo%40googlegroups.com</a>.<b=
r />

------=_Part_845_383446880.1594621003678--

------=_Part_844_204313078.1594621003678--
