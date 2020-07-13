Return-Path: <kasan-dev+bncBCVLFUWIZIBBBP6BWH4AKGQEULVIICQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E4F421D6FE
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jul 2020 15:25:21 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id r62sf6477830oif.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jul 2020 06:25:21 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9NxbTsdVKdoGzfLPlMjPBYTItIbN4QYpq/IdBTIBp3k=;
        b=Z+YxIdmbcYECzAd/xttSjjkrmoiNdjuEber7e82Wl36IkEp+iOBj/zq3H5gJV75F0s
         tlHh+DSs9i0MfUdS+Zy7+UCnEy74DnQoTYZfWpiwoz6njWX7q0CepKF282ji1cpJbcmz
         SuYeDkbOcFwEpwqLZHOUZpRNUdEfICzlK2DV5t7sNhFwwvESjxC6HOtTlJ/RRlMnFdFu
         EULZJLO1W+BQPnHegrjCVTMtp68abB7gVKtFi1VuctjBVsH3jPUt1e6pQZpcLVh+xN9L
         euBF0OBb8uoij/fEOmNxSkGXy8EWAfAV+zN/j/hhaC1S1g6D8pU8gDTIlLQYREXOfEZ+
         o5Zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9NxbTsdVKdoGzfLPlMjPBYTItIbN4QYpq/IdBTIBp3k=;
        b=RQ+xSJeumFH7B3yes+bhGKrw84zE1wmrg8lWoR7mp8DifEbx2qGtmFF+FD3UQBJEQJ
         CZ74FBHwR4CNfhsRglhychXW/i9vSGz99nPPaie2PzHGXGZKD02Ey/WQjPCmgOTPNN1o
         G5sN5S+R4LvLpX48UAWLlrMp5+LSQOeVhkewkSngWUbyU4wkD8C7v5xu+EDJZ6Wmuzt4
         4SY+Q+pDmEn541QQZsi/KANM96iuwJi4YqsmOp9oMHPqauUU5TOh4DU1sDCsB6yg9HyB
         NZQO8f2aHPVk2MF4L7WffwyFCNp8/Q7Q6mSQIRP7VThIF/+Q9A6WdQZW09ClCPAl6MC1
         Tusg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533jr0Ki7XpUJ/KsD4y5otRZ36Nb7Kv43LdKuh6miEI1HuSWr9Gu
	MgRfEKlbxjUvr+HWsA/WAe0=
X-Google-Smtp-Source: ABdhPJzWUYGyqdLlDg1a0Bpw/okjZgBYF6NPG6dGjkHug2OyNCk0XTc6QDTny8qRM2VNC1NttyIxLw==
X-Received: by 2002:a05:6830:1ad5:: with SMTP id r21mr63486111otc.181.1594646719753;
        Mon, 13 Jul 2020 06:25:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:cf03:: with SMTP id l3ls925749oos.8.gmail; Mon, 13 Jul
 2020 06:25:19 -0700 (PDT)
X-Received: by 2002:a4a:a404:: with SMTP id v4mr11141201ool.2.1594646719315;
        Mon, 13 Jul 2020 06:25:19 -0700 (PDT)
Date: Mon, 13 Jul 2020 06:25:18 -0700 (PDT)
From: hyouyan@126.com
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <10459479-d07c-454f-b4be-eb8a44842377o@googlegroups.com>
In-Reply-To: <f98a41c3-2748-4dff-970a-fd656c40e0fdo@googlegroups.com>
References: <f98a41c3-2748-4dff-970a-fd656c40e0fdo@googlegroups.com>
Subject: Re: Porting kasan for arm v2 to kernel 4.14, appear crash on
 kasan_pte_populate
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_893_1004587149.1594646718762"
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

------=_Part_893_1004587149.1594646718762
Content-Type: multipart/alternative; 
	boundary="----=_Part_894_587722476.1594646718763"

------=_Part_894_587722476.1594646718763
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

hi Linus Walleij
I porting v12 to kernel v4.14,report fellow crash log:
    0.000000] c0 CPU: ARMv7 Processor [410fd034] revision 4 (ARMv7),=20
cr=3D10c5383d
[    0.000000] c0 CPU: div instructions available: patching division code
[    0.000000] c0 CPU: PIPT / VIPT nonaliasing data cache, VIPT aliasing=20
instruction cache
[    0.000000] c0 OF: fdt: Machine model: Spreadtrum SL8541E-1H10-32b Board=
=20
DX8000
[    0.000000] c0 earlycon: sprd_serial0 at MMIO 0x70100000 (options=20
'115200n8')
[    0.000000] c0 bootconsole [sprd_serial0] enabled
[    0.000000] c0 Internal error: Oops: 805 [#1] PREEMPT SMP ARM
[    0.000000] c0 Modules linked in:
[    0.000000] c0 CPU: 0 PID: 0 Comm: swapper Not tainted 4.14.133+ #90
[    0.000000] c0 Hardware name: Generic DT based system
[    0.000000] c0 task: (ptrval) task.stack: (ptrval)
[    0.000000] c0 PC is at mmioset+0x30/0xa8
[    0.000000] c0 LR is at 0x0
[    0.000000] c0 pc : [<c1f59830>]    lr : [<00000000>]    psr: 200000d3
[    0.000000] c0 sp : c2a03d58  ip : a86f6000  fp : c2a03d94
[    0.000000] c0 r10: c2a14bc4  r9 : 00000000  r8 : 00000000
[    0.000000] c0 r7 : c0006dc8  r6 : b7200000  r5 : b7000000  r4 : a86f700=
0
[    0.000000] c0 r3 : 00000000  r2 : 00000fc0  r1 : 00000000  r0 : a86f600=
0
[    0.000000] c0 Flags: nzCv  IRQs off  FIQs off  Mode SVC_32  ISA ARM =20
Segment none
[    0.000000] c0 Control: 10c5383d  Table: 828d006a  DAC: 00000051
[    0.000000] c0 Process swapper (pid: 0, stack limit =3D 0x(ptrval))
[    0.000000] c0 Stack: (0xc2a03d58 to 0xc2a04000)
[    0.000000] c0 3d40:                                                   =
=20
   bc200000 c2810998
[    0.000000] c0 3d60: a86f6000 00002dbe c1f90364 b7000000 c25de000=20
c2e5fce0 c2ab3880 c25de034
[    0.000000] c0 3d80: c28ca0b0 c255bc89 c2a03dcc c2a03d98 c2810cf0=20
c2810868 00000007 bc200000
[    0.000000] c0 3da0: c280fb4c c28bad18 c2a1a960 80008000 c2a03ec0=20
c2a03f40 e12fff1e c1f58f78
[    0.000000] c0 3dc0: c2a03eec c2a03dd0 c28090f4 c2810aec 0000006c=20
10c5383d c2a03ee4 00000000
[    0.000000] c0 3de0: 00000001 00000001 c2a03e0c c2a03df8 c028c3f4=20
185407c4 c1fa8300 c2a03ee4
[    0.000000] c0 3e00: c2a03e44 c2a03e10 c028f460 c028c3d0 c2a03e3c=20
c2a03e20 c2a55fb4 b75407cc
[    0.000000] c0 3e20: 41b58ab3 c2559770 c2808584 00040e85 c2a0b200=20
00000000 c2a03edc c2a03e48
[    0.000000] c0 3e40: c028e1b0 c028eed4 c2a17348 c281d9e0 c2a17348=20
c2a55ec0 c2a03e94 c05b6b7c
[    0.000000] c0 3e60: 41b58ab3 c255c9e2 c028e134 c2a55f60 00000002=20
c1ffb16c c2a55fa8 c2a55fa4
[    0.000000] c0 3e80: c2a03ee4 00000000 c2a03eec c2e5bf80 c2e5d480=20
00000000 c2a0b208 00040e85
[    0.000000] c0 3ea0: c2a03ebc c2a03eb0 c05b6b7c c05b7340 c2a03ecc=20
c2a03ec0 c05b7f6c 00000000
[    0.000000] c0 3ec0: c2a03eec b75407e4 c2a0b21c c2a03fc0 c2a0b208=20
00040e85 c2a0b200 00000000
[    0.000000] c0 3ee0: c2a03ff4 c2a03ef0 c280110c c2808590 00000000=20
00000000 00000000 00000000
[    0.000000] c0 3f00: 00000000 00000000 00000000 00000000 00000000=20
00000000 00000000 00000000
[    0.000000] c0 3f20: 41b58ab3 c25587e9 c2801058 00000000 00000000=20
00000000 00000000 00000000
[    0.000000] c0 3f40: c28c923c 00000000 00000000 00000000 00000000=20
00000000 00000000 00000000
[    0.000000] c0 3f60: 00000000 00000000 00000000 00000000 00000000=20
00000000 00000000 00000000
[    0.000000] c0 3f80: 00000000 00000000 00000000 00000000 00000000=20
00000000 00000000 00000000
[    0.000000] c0 3fa0: 00000000 00000000 00000000 c2810ad4 00000000=20
00002dbe 00000000 c2dbfba0
[    0.000000] c0 3fc0: c2a0b21c 00000000 c2a1c324 c2dbfba0 c2a0b21c=20
c28c9238 c2a1c324 8000406a
[    0.000000] c0 3fe0: 410fd034 00000000 00000000 c2a03ff8 c28109fc=20
c2801064 00000000 00000000
[    0.000000] c0 [<c1f59830>] (mmioset) from [<c2810998>]=20
(kasan_pgd_populate+0x13c/0x21c)
[    0.000000] c0 [<c2810998>] (kasan_pgd_populate) from [<c2810cf0>]=20
(kasan_init+0x210/0x260)
[    0.000000] c0 [<c2810cf0>] (kasan_init) from [<c28090f4>]=20
(setup_arch+0xb70/0x1978)
[    0.000000] c0 [<c28090f4>] (setup_arch) from [<c280110c>]=20
(start_kernel+0xb4/0x6e4)
[    0.000000] c0 [<c280110c>] (start_kernel) from [<c28109fc>]=20
(kasan_pgd_populate+0x1a0/0x2

how I can fix it?

thanks and best regards
youyan

=E5=9C=A8 2020=E5=B9=B47=E6=9C=8813=E6=97=A5=E6=98=9F=E6=9C=9F=E4=B8=80 UTC=
+8=E4=B8=8B=E5=8D=882:16:43=EF=BC=8Chyo...@126.com=E5=86=99=E9=81=93=EF=BC=
=9A
>
> Hi admin:
>      I plan to port kasan for arm v2 patch to arm kernel 4.14. But appear=
=20
> crash, fellow is the crash log:
>
>      0.000000] c0 kasan: base end 80000000, bffc0000
> [    0.000000] c0 kasan: populating shadow for b7000000, bc200000
> [    0.000000] c0 kasan:  create_mapping addr b7000000,
> [    0.000000] c0 Unable to handle kernel paging request at virtual=20
> address a86f7000
> [    0.000000] c0 pgd =3D (ptrval)
> [    0.000000] c0 [a86f7000] *pgd=3D00000000
> [    0.000000] c0 Internal error: Oops: 5 [#1] PREEMPT SMP ARM
> [    0.000000] c0 Modules linked in:
> [    0.000000] c0 CPU: 0 PID: 0 Comm: swapper Not tainted 4.14.133+ #83
> [    0.000000] c0 Hardware name: Generic DT based system
> [    0.000000] c0 task: (ptrval) task.stack: (ptrval)
> [    0.000000] c0 PC is at kasan_pte_populate+0x2c/0xcc
> [    0.000000] c0 LR is at kasan_init+0x258/0x2b0
> [    0.000000] c0 pc : [<c170b8cc>]    lr : [<c170bc7c>]    psr: a00000d3
> [    0.000000] c0 sp : c1803d88  ip : c170b8b4  fp : c1803da4
> [    0.000000] c0 r10: c14c2354  r9 : b7000000  r8 : c18b3280
> [    0.000000] c0 r7 : c18b3e00  r6 : b7000000  r5 : c1545034  r4 :=20
> bc200000
> [    0.000000] c0 r3 : a86f7000  r2 : ffffffff  r1 : 00000000  r0 :=20
> c0006dc0
> [    0.000000] c0 Flags: NzCv  IRQs off  FIQs off  Mode SVC_32  ISA ARM =
=20
> Segment none
> [    0.000000] c0 Control: 10c5383d  Table: 817a4000  DAC: 00000051
> [    0.000000] c0 Process swapper (pid: 0, stack limit =3D 0x(ptrval))
> [    0.000000] c0 Stack: (0xc1803d88 to 0xc1804000)
> [    0.000000] c0 3d80:                   bc200000 c1545034 c1c60ee0=20
> c18b3e00 c1803ddc c1803da8
> [    0.000000] c0 3da0: c170bc7c c170b8ac c15452ec 8000406a 00000000=20
> c1790ec0 c1803ec0 c1bc08c0
> [    0.000000] c0 3dc0: c1803f40 c179d23c 80008000 c20e43a0 c1803eec=20
> c1803de0 c1706020 c170ba30
> [    0.000000] c0 3de0: 0000006c 10c5383d c1803e0c c1803df8 c01c7a3c=20
> c01c759c 00000024 b73007c4
> [    0.000000] c0 3e00: c1803e44 c1803e10 c01c94f4 c01c7a18 00000001=20
> 00000030 c1803e44 b73007cc
> [    0.000000] c0 3e20: 41b58ab3 c14c01b0 c1705990 00040e85 c180b200=20
> 00000000 c1803edc c1803e48
> [    0.000000] c0 3e40: c01c89c8 c01c92bc c1803e6c c1803e58 c0f08478=20
> c0358a94 c1817348 c1856440
> [    0.000000] c0 3e60: 41b58ab3 c14c30bd c01c894c c0f08458 00000001=20
> c18564e0 c1803e9c c1803e88
> [    0.000000] c0 3e80: c1803ee4 c03588c4 c1879240 00000005 c1803eec=20
> c1803ea0 c1803eec c1803ea8
> [    0.000000] c0 3ea0: c0275760 c0358b34 c1803eec c1803ec8 c1705578=20
> c01c895c c1879284 00000000
> [    0.000000] c0 3ec0: c1803eec b73007e4 c180b21c c1803fc0 c180b208=20
> 00040e85 c180b200 00000000
> [    0.000000] c0 3ee0: c1803ff4 c1803ef0 c1700c18 c170599c 00000000=20
> 00000000 00000000 00000000
> [    0.000000] c0 3f00: 00000000 00000000 00000000 00000000 00000000=20
> 00000000 00000000 00000000
> [    0.000000] c0 3f20: 41b58ab3 c14bf229 c1700b64 00000000 00000000=20
> 00000000 00000000 00000000
> [    0.000000] c0 3f40: c179d23c 00000000 00000000 00000000 00000000=20
> 00000000 00000000 00000000
> [    0.000000] c0 3f60: 00000000 00000000 00000000 00000000 00000000=20
> 00000000 00000000 00000000
> [    0.000000] c0 3f80: 00000000 00000000 00000000 00000000 00000000=20
> 00000000 00000000 00000000
> [    0.000000] c0 3fa0: 00000000 00000000 00000000 00000000 00000000=20
> 00000000 00000000 c170b894
> [    0.000000] c0 3fc0: c1bc0ba0 00000000 c179d238 c1bc0ba0 c180b21c=20
> c179d238 c181c344 8000406a
> [    0.000000] c0 3fe0: 410fd034 00000000 00000000 c1803ff8 c0006fc0=20
> c1700b70 00000000 00000000
> [    0.000000] c0 [<c170b8cc>] (kasan_pte_populate) from [<c170bc7c>]=20
> (kasan_init+0x258/0x2b0)
> [    0.000000] c0 [<c170bc7c>] (kasan_init) from [<c1706020>]=20
> (setup_arch+0x690/0xd64)
> [    0.000000] c0 [<c1706020>] (setup_arch) from [<c1700c18>]=20
> (start_kernel+0xb4/0x514)
> [    0.000000] c0 [<c1700c18>] (start_kernel) from [<c0006fc0>]=20
> (0xc0006fc0)
>
>
> Is there any config wrong?
>
>
> thanks and best regards
> youyan
>    =20
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/10459479-d07c-454f-b4be-eb8a44842377o%40googlegroups.com.

------=_Part_894_587722476.1594646718763
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">hi Linus Walleij<div>I porting v12 to kernel v4.14,report =
fellow crash log:</div><div><div>=C2=A0 =C2=A0 0.000000] c0 CPU: ARMv7 Proc=
essor [410fd034] revision 4 (ARMv7), cr=3D10c5383d</div><div>[=C2=A0 =C2=A0=
 0.000000] c0 CPU: div instructions available: patching division code</div>=
<div>[=C2=A0 =C2=A0 0.000000] c0 CPU: PIPT / VIPT nonaliasing data cache, V=
IPT aliasing instruction cache</div><div>[=C2=A0 =C2=A0 0.000000] c0 OF: fd=
t: Machine model: Spreadtrum SL8541E-1H10-32b Board DX8000</div><div>[=C2=
=A0 =C2=A0 0.000000] c0 earlycon: sprd_serial0 at MMIO 0x70100000 (options =
&#39;115200n8&#39;)</div><div>[=C2=A0 =C2=A0 0.000000] c0 bootconsole [sprd=
_serial0] enabled</div><div>[=C2=A0 =C2=A0 0.000000] c0 Internal error: Oop=
s: 805 [#1] PREEMPT SMP ARM</div><div>[=C2=A0 =C2=A0 0.000000] c0 Modules l=
inked in:</div><div>[=C2=A0 =C2=A0 0.000000] c0 CPU: 0 PID: 0 Comm: swapper=
 Not tainted 4.14.133+ #90</div><div>[=C2=A0 =C2=A0 0.000000] c0 Hardware n=
ame: Generic DT based system</div><div>[=C2=A0 =C2=A0 0.000000] c0 task: (p=
trval) task.stack: (ptrval)</div><div>[=C2=A0 =C2=A0 0.000000] c0 PC is at =
mmioset+0x30/0xa8</div><div>[=C2=A0 =C2=A0 0.000000] c0 LR is at 0x0</div><=
div>[=C2=A0 =C2=A0 0.000000] c0 pc : [&lt;c1f59830&gt;]=C2=A0 =C2=A0 lr : [=
&lt;00000000&gt;]=C2=A0 =C2=A0 psr: 200000d3</div><div>[=C2=A0 =C2=A0 0.000=
000] c0 sp : c2a03d58=C2=A0 ip : a86f6000=C2=A0 fp : c2a03d94</div><div>[=
=C2=A0 =C2=A0 0.000000] c0 r10: c2a14bc4=C2=A0 r9 : 00000000=C2=A0 r8 : 000=
00000</div><div>[=C2=A0 =C2=A0 0.000000] c0 r7 : c0006dc8=C2=A0 r6 : b72000=
00=C2=A0 r5 : b7000000=C2=A0 r4 : a86f7000</div><div>[=C2=A0 =C2=A0 0.00000=
0] c0 r3 : 00000000=C2=A0 r2 : 00000fc0=C2=A0 r1 : 00000000=C2=A0 r0 : a86f=
6000</div><div>[=C2=A0 =C2=A0 0.000000] c0 Flags: nzCv=C2=A0 IRQs off=C2=A0=
 FIQs off=C2=A0 Mode SVC_32=C2=A0 ISA ARM=C2=A0 Segment none</div><div>[=C2=
=A0 =C2=A0 0.000000] c0 Control: 10c5383d=C2=A0 Table: 828d006a=C2=A0 DAC: =
00000051</div><div>[=C2=A0 =C2=A0 0.000000] c0 Process swapper (pid: 0, sta=
ck limit =3D 0x(ptrval))</div><div>[=C2=A0 =C2=A0 0.000000] c0 Stack: (0xc2=
a03d58 to 0xc2a04000)</div><div>[=C2=A0 =C2=A0 0.000000] c0 3d40:=C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0bc200000 c2810998</div><div>[=C2=A0 =
=C2=A0 0.000000] c0 3d60: a86f6000 00002dbe c1f90364 b7000000 c25de000 c2e5=
fce0 c2ab3880 c25de034</div><div>[=C2=A0 =C2=A0 0.000000] c0 3d80: c28ca0b0=
 c255bc89 c2a03dcc c2a03d98 c2810cf0 c2810868 00000007 bc200000</div><div>[=
=C2=A0 =C2=A0 0.000000] c0 3da0: c280fb4c c28bad18 c2a1a960 80008000 c2a03e=
c0 c2a03f40 e12fff1e c1f58f78</div><div>[=C2=A0 =C2=A0 0.000000] c0 3dc0: c=
2a03eec c2a03dd0 c28090f4 c2810aec 0000006c 10c5383d c2a03ee4 00000000</div=
><div>[=C2=A0 =C2=A0 0.000000] c0 3de0: 00000001 00000001 c2a03e0c c2a03df8=
 c028c3f4 185407c4 c1fa8300 c2a03ee4</div><div>[=C2=A0 =C2=A0 0.000000] c0 =
3e00: c2a03e44 c2a03e10 c028f460 c028c3d0 c2a03e3c c2a03e20 c2a55fb4 b75407=
cc</div><div>[=C2=A0 =C2=A0 0.000000] c0 3e20: 41b58ab3 c2559770 c2808584 0=
0040e85 c2a0b200 00000000 c2a03edc c2a03e48</div><div>[=C2=A0 =C2=A0 0.0000=
00] c0 3e40: c028e1b0 c028eed4 c2a17348 c281d9e0 c2a17348 c2a55ec0 c2a03e94=
 c05b6b7c</div><div>[=C2=A0 =C2=A0 0.000000] c0 3e60: 41b58ab3 c255c9e2 c02=
8e134 c2a55f60 00000002 c1ffb16c c2a55fa8 c2a55fa4</div><div>[=C2=A0 =C2=A0=
 0.000000] c0 3e80: c2a03ee4 00000000 c2a03eec c2e5bf80 c2e5d480 00000000 c=
2a0b208 00040e85</div><div>[=C2=A0 =C2=A0 0.000000] c0 3ea0: c2a03ebc c2a03=
eb0 c05b6b7c c05b7340 c2a03ecc c2a03ec0 c05b7f6c 00000000</div><div>[=C2=A0=
 =C2=A0 0.000000] c0 3ec0: c2a03eec b75407e4 c2a0b21c c2a03fc0 c2a0b208 000=
40e85 c2a0b200 00000000</div><div>[=C2=A0 =C2=A0 0.000000] c0 3ee0: c2a03ff=
4 c2a03ef0 c280110c c2808590 00000000 00000000 00000000 00000000</div><div>=
[=C2=A0 =C2=A0 0.000000] c0 3f00: 00000000 00000000 00000000 00000000 00000=
000 00000000 00000000 00000000</div><div>[=C2=A0 =C2=A0 0.000000] c0 3f20: =
41b58ab3 c25587e9 c2801058 00000000 00000000 00000000 00000000 00000000</di=
v><div>[=C2=A0 =C2=A0 0.000000] c0 3f40: c28c923c 00000000 00000000 0000000=
0 00000000 00000000 00000000 00000000</div><div>[=C2=A0 =C2=A0 0.000000] c0=
 3f60: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000=
000</div><div>[=C2=A0 =C2=A0 0.000000] c0 3f80: 00000000 00000000 00000000 =
00000000 00000000 00000000 00000000 00000000</div><div>[=C2=A0 =C2=A0 0.000=
000] c0 3fa0: 00000000 00000000 00000000 c2810ad4 00000000 00002dbe 0000000=
0 c2dbfba0</div><div>[=C2=A0 =C2=A0 0.000000] c0 3fc0: c2a0b21c 00000000 c2=
a1c324 c2dbfba0 c2a0b21c c28c9238 c2a1c324 8000406a</div><div>[=C2=A0 =C2=
=A0 0.000000] c0 3fe0: 410fd034 00000000 00000000 c2a03ff8 c28109fc c280106=
4 00000000 00000000</div><div>[=C2=A0 =C2=A0 0.000000] c0 [&lt;c1f59830&gt;=
] (mmioset) from [&lt;c2810998&gt;] (kasan_pgd_populate+0x13c/0x21c)</div><=
div>[=C2=A0 =C2=A0 0.000000] c0 [&lt;c2810998&gt;] (kasan_pgd_populate) fro=
m [&lt;c2810cf0&gt;] (kasan_init+0x210/0x260)</div><div>[=C2=A0 =C2=A0 0.00=
0000] c0 [&lt;c2810cf0&gt;] (kasan_init) from [&lt;c28090f4&gt;] (setup_arc=
h+0xb70/0x1978)</div><div>[=C2=A0 =C2=A0 0.000000] c0 [&lt;c28090f4&gt;] (s=
etup_arch) from [&lt;c280110c&gt;] (start_kernel+0xb4/0x6e4)</div><div>[=C2=
=A0 =C2=A0 0.000000] c0 [&lt;c280110c&gt;] (start_kernel) from [&lt;c28109f=
c&gt;] (kasan_pgd_populate+0x1a0/0x2</div><div><br></div><div>how I can fix=
 it?</div><div><br></div><div>thanks and best regards</div><div>youyan</div=
><br>=E5=9C=A8 2020=E5=B9=B47=E6=9C=8813=E6=97=A5=E6=98=9F=E6=9C=9F=E4=B8=
=80 UTC+8=E4=B8=8B=E5=8D=882:16:43=EF=BC=8Chyo...@126.com=E5=86=99=E9=81=93=
=EF=BC=9A<blockquote class=3D"gmail_quote" style=3D"margin: 0;margin-left: =
0.8ex;border-left: 1px #ccc solid;padding-left: 1ex;"><div dir=3D"ltr">Hi a=
dmin:<div>=C2=A0 =C2=A0 =C2=A0I plan to port=C2=A0kasan for arm v2 patch to=
 arm=C2=A0kernel 4.14. But appear crash, fellow is the crash log:</div><div=
><br></div><div><div>=C2=A0 =C2=A0 =C2=A00.000000] c0 kasan: base end 80000=
000, bffc0000</div><div>[=C2=A0 =C2=A0 0.000000] c0 kasan: populating shado=
w for b7000000, bc200000</div><div>[=C2=A0 =C2=A0 0.000000] c0 kasan:=C2=A0=
 create_mapping addr b7000000,</div><div>[=C2=A0 =C2=A0 0.000000] c0 Unable=
 to handle kernel paging request at virtual address a86f7000</div><div>[=C2=
=A0 =C2=A0 0.000000] c0 pgd =3D (ptrval)</div><div>[=C2=A0 =C2=A0 0.000000]=
 c0 [a86f7000] *pgd=3D00000000</div><div>[=C2=A0 =C2=A0 0.000000] c0 Intern=
al error: Oops: 5 [#1] PREEMPT SMP ARM</div><div>[=C2=A0 =C2=A0 0.000000] c=
0 Modules linked in:</div><div>[=C2=A0 =C2=A0 0.000000] c0 CPU: 0 PID: 0 Co=
mm: swapper Not tainted 4.14.133+ #83</div><div>[=C2=A0 =C2=A0 0.000000] c0=
 Hardware name: Generic DT based system</div><div>[=C2=A0 =C2=A0 0.000000] =
c0 task: (ptrval) task.stack: (ptrval)</div><div>[=C2=A0 =C2=A0 0.000000] c=
0 PC is at kasan_pte_populate+0x2c/0xcc</div><div>[=C2=A0 =C2=A0 0.000000] =
c0 LR is at kasan_init+0x258/0x2b0</div><div>[=C2=A0 =C2=A0 0.000000] c0 pc=
 : [&lt;c170b8cc&gt;]=C2=A0 =C2=A0 lr : [&lt;c170bc7c&gt;]=C2=A0 =C2=A0 psr=
: a00000d3</div><div>[=C2=A0 =C2=A0 0.000000] c0 sp : c1803d88=C2=A0 ip : c=
170b8b4=C2=A0 fp : c1803da4</div><div>[=C2=A0 =C2=A0 0.000000] c0 r10: c14c=
2354=C2=A0 r9 : b7000000=C2=A0 r8 : c18b3280</div><div>[=C2=A0 =C2=A0 0.000=
000] c0 r7 : c18b3e00=C2=A0 r6 : b7000000=C2=A0 r5 : c1545034=C2=A0 r4 : bc=
200000</div><div>[=C2=A0 =C2=A0 0.000000] c0 r3 : a86f7000=C2=A0 r2 : fffff=
fff=C2=A0 r1 : 00000000=C2=A0 r0 : c0006dc0</div><div>[=C2=A0 =C2=A0 0.0000=
00] c0 Flags: NzCv=C2=A0 IRQs off=C2=A0 FIQs off=C2=A0 Mode SVC_32=C2=A0 IS=
A ARM=C2=A0 Segment none</div><div>[=C2=A0 =C2=A0 0.000000] c0 Control: 10c=
5383d=C2=A0 Table: 817a4000=C2=A0 DAC: 00000051</div><div><div>[=C2=A0 =C2=
=A0 0.000000] c0 Process swapper (pid: 0, stack limit =3D 0x(ptrval))</div>=
<div><div>[=C2=A0 =C2=A0 0.000000] c0 Stack: (0xc1803d88 to 0xc1804000)</di=
v><div>[=C2=A0 =C2=A0 0.000000] c0 3d80:=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0bc200000 c1545034 c1c60ee0 c18b3e00 c1803=
ddc c1803da8</div><div>[=C2=A0 =C2=A0 0.000000] c0 3da0: c170bc7c c170b8ac =
c15452ec 8000406a 00000000 c1790ec0 c1803ec0 c1bc08c0</div><div>[=C2=A0 =C2=
=A0 0.000000] c0 3dc0: c1803f40 c179d23c 80008000 c20e43a0 c1803eec c1803de=
0 c1706020 c170ba30</div><div>[=C2=A0 =C2=A0 0.000000] c0 3de0: 0000006c 10=
c5383d c1803e0c c1803df8 c01c7a3c c01c759c 00000024 b73007c4</div><div>[=C2=
=A0 =C2=A0 0.000000] c0 3e00: c1803e44 c1803e10 c01c94f4 c01c7a18 00000001 =
00000030 c1803e44 b73007cc</div><div>[=C2=A0 =C2=A0 0.000000] c0 3e20: 41b5=
8ab3 c14c01b0 c1705990 00040e85 c180b200 00000000 c1803edc c1803e48</div><d=
iv>[=C2=A0 =C2=A0 0.000000] c0 3e40: c01c89c8 c01c92bc c1803e6c c1803e58 c0=
f08478 c0358a94 c1817348 c1856440</div><div>[=C2=A0 =C2=A0 0.000000] c0 3e6=
0: 41b58ab3 c14c30bd c01c894c c0f08458 00000001 c18564e0 c1803e9c c1803e88<=
/div><div>[=C2=A0 =C2=A0 0.000000] c0 3e80: c1803ee4 c03588c4 c1879240 0000=
0005 c1803eec c1803ea0 c1803eec c1803ea8</div><div>[=C2=A0 =C2=A0 0.000000]=
 c0 3ea0: c0275760 c0358b34 c1803eec c1803ec8 c1705578 c01c895c c1879284 00=
000000</div><div>[=C2=A0 =C2=A0 0.000000] c0 3ec0: c1803eec b73007e4 c180b2=
1c c1803fc0 c180b208 00040e85 c180b200 00000000</div><div>[=C2=A0 =C2=A0 0.=
000000] c0 3ee0: c1803ff4 c1803ef0 c1700c18 c170599c 00000000 00000000 0000=
0000 00000000</div><div>[=C2=A0 =C2=A0 0.000000] c0 3f00: 00000000 00000000=
 00000000 00000000 00000000 00000000 00000000 00000000</div><div>[=C2=A0 =
=C2=A0 0.000000] c0 3f20: 41b58ab3 c14bf229 c1700b64 00000000 00000000 0000=
0000 00000000 00000000</div><div>[=C2=A0 =C2=A0 0.000000] c0 3f40: c179d23c=
 00000000 00000000 00000000 00000000 00000000 00000000 00000000</div><div>[=
=C2=A0 =C2=A0 0.000000] c0 3f60: 00000000 00000000 00000000 00000000 000000=
00 00000000 00000000 00000000</div><div>[=C2=A0 =C2=A0 0.000000] c0 3f80: 0=
0000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000</div=
><div>[=C2=A0 =C2=A0 0.000000] c0 3fa0: 00000000 00000000 00000000 00000000=
 00000000 00000000 00000000 c170b894</div><div>[=C2=A0 =C2=A0 0.000000] c0 =
3fc0: c1bc0ba0 00000000 c179d238 c1bc0ba0 c180b21c c179d238 c181c344 800040=
6a</div><div>[=C2=A0 =C2=A0 0.000000] c0 3fe0: 410fd034 00000000 00000000 c=
1803ff8 c0006fc0 c1700b70 00000000 00000000</div><div>[=C2=A0 =C2=A0 0.0000=
00] c0 [&lt;c170b8cc&gt;] (kasan_pte_populate) from [&lt;c170bc7c&gt;] (kas=
an_init+0x258/0x2b0)</div><div>[=C2=A0 =C2=A0 0.000000] c0 [&lt;c170bc7c&gt=
;] (kasan_init) from [&lt;c1706020&gt;] (setup_arch+0x690/0xd64)</div><div>=
[=C2=A0 =C2=A0 0.000000] c0 [&lt;c1706020&gt;] (setup_arch) from [&lt;c1700=
c18&gt;] (start_kernel+0xb4/0x514)</div><div>[=C2=A0 =C2=A0 0.000000] c0 [&=
lt;c1700c18&gt;] (start_kernel) from [&lt;c0006fc0&gt;] (0xc0006fc0)</div><=
/div></div><div><br></div><div><br></div><div>Is there any config wrong?</d=
iv><div><br></div><div><br></div><div>thanks and best regards</div><div>you=
yan</div><div>=C2=A0 =C2=A0=C2=A0</div></div></div></blockquote></div></div=
>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/10459479-d07c-454f-b4be-eb8a44842377o%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/10459479-d07c-454f-b4be-eb8a44842377o%40googlegroups.com</a>.<b=
r />

------=_Part_894_587722476.1594646718763--

------=_Part_893_1004587149.1594646718762--
