Return-Path: <kasan-dev+bncBCC5HZGYUYIRBWH2V2AQMGQE6QUZRFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id EAE0131CAA2
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Feb 2021 13:40:58 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id h10sf4003237ooj.11
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Feb 2021 04:40:58 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BxwZZAjcCDGzthrAbpu/YonCuzH5+lruVPVHfEcB1tI=;
        b=oLarMAa6nICrtW/v5jnpF8C/asRScXOiaw9DTP14ahzmFkLQ3adtYLpLzBMDw/mJWS
         8+UPtMRIbVD78GQKrtP43g52WtY+88Ngx7MUFVRx+dMC8GL3t7D5GPd6QaEg3vfHubnD
         8v/Lz7YrzDQ15rzb46SPGG2pYkvrGIQUj8n42enSInBzo7R5d/At1NUdyUwecPiqFHX/
         8vCV6FTXzADBomNbpTZRWzpHqXJrzAbPYdMEUIv162IhkvC4NxIhGHtc/jtbaDAk10Z8
         MHZWHhlCacgBGBNTX2cRBwzAVDQh9izVmP4XuZukG5VfBCmpIyQm2lp0uKN34GyAL76e
         TgDA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:subject:mime-version:x-original-sender
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BxwZZAjcCDGzthrAbpu/YonCuzH5+lruVPVHfEcB1tI=;
        b=dWd0MIsDMrdfMHD5MDnC4XJvdRYMpaed30lrZNU/ZcEuF89sicEq4c+O2ybWN+lqUs
         NmNbdCTgPh8Pnf2/48TJPnRSIWdA/ONZWUSnDWjYH30v9j2D5Ff4SxzFMDKRCgvr53Gy
         Du0ZRug5yUTuBD9k44v4U8ex7ndOlQhYUXASSIm3AfhWlVQkwp5RMo/aegMj2gy+7Axx
         nsPm9QPp4+Quew+LR0/P4VXVVDF6t5vSHySEBcSOVU2uNZS6zEdY2+L0BD0F8yEVC5Kg
         lepzqm2ROb3LB+mr1qUJRJF7xULCu1gausT87cehJlmCvDiyjbXEZtttHTi82RwzMO6i
         skBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BxwZZAjcCDGzthrAbpu/YonCuzH5+lruVPVHfEcB1tI=;
        b=hDuCPTKUMCYOlnF4LUSuvQw2agbeHtEdc6vmXnBC+g4mU/KIcSIFCkV1a7kBUdLCUA
         KGVfw8lxyhNbO5D5ZhCx2DWdHa1CMUGX7dLEzDCgjn3YvNgOlyOeSVHMysgkWg1FmD0c
         qoIp5s3R1U9kvl+yIn02A2k67UkbVbk25eu6xSeJvBdx3ORxKoavyNlxZhP7rttrYoMn
         8XQYjI+sgamXOn6ucPXO4OcR4iXAQuSRbN7ifVdR9nxUjG7fEsa7PzRYX4IqMjmG0HJN
         tAvpGnMpJYAi/xLhIc+B116r7x1Lj77wKvSlN1froR9uEVqdIt8+euqGfPUdr5WOWsfX
         7pJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533JcbtYYLIluQF1fXOqfKj1k41wQt3PeiaT/qmQslGzbZIVQ0KX
	L5bEdyISvDnr68m+1kCbubQ=
X-Google-Smtp-Source: ABdhPJz8PRT01TXLv2eYziZzboNxgVkzjIDGKtjRteQavUluPxwPl0ZvcoeqqMH8IwXOak8cXkoW3A==
X-Received: by 2002:a05:6820:4e:: with SMTP id v14mr14158870oob.52.1613479256631;
        Tue, 16 Feb 2021 04:40:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:7249:: with SMTP id p70ls4668596oic.5.gmail; Tue, 16 Feb
 2021 04:40:56 -0800 (PST)
X-Received: by 2002:a05:6808:8c1:: with SMTP id k1mr1491609oij.48.1613479256145;
        Tue, 16 Feb 2021 04:40:56 -0800 (PST)
Date: Tue, 16 Feb 2021 04:40:55 -0800 (PST)
From: Shahbaz Ali <shbaz.ali@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <745fe86a-17de-4597-8af3-baa306b6dd0cn@googlegroups.com>
Subject: __asan_register_globals with out-of-tree modules
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_7890_766043814.1613479255554"
X-Original-Sender: shbaz.ali@gmail.com
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

------=_Part_7890_766043814.1613479255554
Content-Type: multipart/alternative; 
	boundary="----=_Part_7891_1143810767.1613479255554"

------=_Part_7891_1143810767.1613479255554
Content-Type: text/plain; charset="UTF-8"

Hi,

I am having issues getting kasan working with out-of-tree modules.
Always seem to fail during the asan_register_globals step.

I have seen and tried suggestions mentioning ABI versions; e.g.
https://groups.google.com/g/kasan-dev/c/NkcefkYk3hs/m/74avihf1AwAJ

As per suggestions I have tried ABI versions 3/4/5 with no success:

   - Version 5 (default) produces below stacktrace when loading first out 
   of tree module.
   - Version 4 crashes near start of kernel loading with similar trace.
   - Version 3 produces lots of kernel errors.

I am on arm aarch64; gcc 6.2
Kernel is at patch 4.9.252

Digging a little deeper, the issue is that the address of the globals being 
passed in is expected to be a kernel address, in this case 0xffff xxxx xxxx 
xxxx, however, the global->beg is always 0x0000 xxxx xxxx xxxx.  See top of 
stack trace for example.  If I ignore those addresses, I will then get 
input addresses just under the kernel address range (0xfffe ...).

The 'beg' is the first 'globals' structure member so initial thoughts are 
that the issue shouldn't be due to structure size mismatch due to ABI 
version.

Is it perhaps to do with the way out-of-tree modules are loaded/handled?  
In that the addresses aren't mapped to kernel memory at the point they 
enter?  I do see the 0x0000 xxxx xxxx xxxx addresses which come into 
asan_register_globals as valid addresses of symbols inside the out-of-tree 
module when running `nm`.


Stack trace:

[   12.497676] veea_boot: loading out-of-tree module taints kernel.
[   12.504618] random: fast init done
[   12.516814] WARNING: Skipped kasan_register_global of non-kernel 
address: 0000000000000190
[   12.525947] WARNING: Skipped kasan_register_global of non-kernel 
address: 00000000000001c0
[   12.534254] WARNING: kasan inaddr: fffe4000016a3f08
[   12.539434] WARNING: kasan shadow addr: fffee800002d47e1
[   12.544192] Unable to handle kernel paging request at virtual address 
fffee800002d47e1
[   12.552527] [fffee800002d47e1] address between user and kernel address 
ranges
[   12.559728] Internal error: Oops: 96000044 [#1] PREEMPT SMP
[   12.565299] Modules linked in: veea_boot(O+)
[   12.569586] CPU: 0 PID: 1073 Comm: modprobe Tainted: G           O    
4.9.252-vsys-1.0 #1
[   12.577764] Hardware name: Cavium ThunderX CN81XX board (DT)
[   12.583423] task: ffff8000c7d45a80 task.stack: ffff8000c7de8000
[   12.589351] PC is at __memset+0x4c/0x1d0
[   12.593275] LR is at kasan_poison_shadow+0x7c/0x90
[   12.598064] pc : [<ffff2000085384cc>] lr : [<ffff200008259994>] pstate: 
00000145
[   12.605454] sp : ffff8000c7deb9b0
[   12.608764] x29: ffff8000c7deb9b0 x28: 0000000000000001 
[   12.614083] x27: ffff8000c7debe20 x26: ffff200000b537e0 
[   12.619401] x25: 0000000000000003 x24: ffff200008e659e0 
[   12.624720] x23: fffeffffffffffff x22: 000000000000003d 
[   12.630037] x21: 0000dfffff4ae0e8 x20: fffee800002d47e1 
[   12.635356] x19: ffff04000016a3fe x18: 2000000000000000 
[   12.640675] x17: 0000ffffa67c1650 x16: ffff20000816f020 
[   12.645994] x15: 5400160b13131717 x14: 3030303030303030 
[   12.651312] x13: 3030203a73736572 x12: ffff0400012da103 
[   12.656631] x11: 1fffe400012da102 x10: ffff0400012da102 
[   12.661949] x9 : 0000000000000000 x8 : fffee800002d47e1 
[   12.667267] x7 : fafafafafafafafa x6 : 0000000041b58ab3 
[   12.672585] x5 : 0000000000000003 x4 : 000000000000000f 
[   12.677903] x3 : dfff200000000000 x2 : 00001bffffe95c1d 
[   12.683221] x1 : 00000000000000fa x0 : fffee800002d47e1 
[   12.688537] 
[   12.690027] Process modprobe (pid: 1073, stack limit = 
0xffff8000c7de8020)
[   12.696899] Stack: (0xffff8000c7deb9b0 to 0xffff8000c7dec000)
[   12.702645] b9a0:                                   ffff8000c7deb9f0 
ffff20000825a328
[   12.710476] b9c0: ffff200000b51f18 00000000000000c0 ffff200000b53720 
ffff20000825a310
[   12.718307] b9e0: ffff200000b51f18 000000fa000000c0 ffff8000c7deba40 
ffff200000b50d98
[   12.726139] ba00: ffff200000b54680 0000000000000001 ffff200000b59000 
ffff200000b54950
[   12.733970] ba20: ffff200000b54948 ffff8000c7cfde80 ffff200000b54850 
000000000000000f
[   12.741801] ba40: ffff8000c7deba50 ffff20000816b7c8 ffff8000c7debaa0 
ffff20000816e6b4
[   12.749632] ba60: ffff200000b54680 0000000000000001 ffff8000c7cfe380 
0000000000000038
[   12.757463] ba80: 0000000000000001 000000000000001d ffff200000b548e0 
0000000000000038
[   12.765294] baa0: ffff8000c7debd50 ffff20000816f13c 1ffff00018fbd7b0 
0000000000000000
[   12.773124] bac0: 0000ffffa682f9e0 0000000000000003 0000000080000000 
0000000000000015
[   12.780955] bae0: 0000000000000123 0000000000000111 ffff200008b54000 
ffff8000c7de8000
[   12.788786] bb00: ffff8000c7cfe390 ffff8000c7debe30 1ffff00018fbd782 
ffff200008168bf8
[   12.796618] bb20: ffff200000b546d0 ffff80000000001d ffff200008168d38 
ffff200008b7d240
[   12.804449] bb40: ffff20000bcacdb8 ffff200000b54850 ffff200000b54858 
ffff200000b548c0
[   12.812281] bb60: ffff200000b54688 ffff200000b5613b ffff200000b54818 
ffff200000b54868
[   12.820113] bb80: ffff20000bcad1c0 ffff200000b54808 ffff20000000001d 
ffff200000b548d8
[   12.827944] bba0: ffff200000b54790 ffff200000b54928 ffff200000b54798 
ffff200000b54750
[   12.835776] bbc0: ffff200000b547a0 ffff200000b547b8 ffff200000b54760 
ffff200000b5479c
[   12.843608] bbe0: ffff200000b547c8 ffff200000b54698 ffff200000b54698 
ffff2000090a76e0
[   12.851439] bc00: ffff200000b548f8 ffff20000828f49c 0000000041b58ab3 
ffff200008e5eb18
[   12.859270] bc20: ffff20000816bad8 0000000000000000 ffff8000c7e48680 
ffff8000c7debde0
[   12.867101] bc40: ffff8000c7e486a0 0000000000000003 ffff8000c7debda0 
ffff2000094382b0
[   12.874932] bc60: 0000000041b58ab3 ffff200008e67588 ffff20000828f3d8 
ffff8000c7e60090
[   12.882763] bc80: ffff8000c7debcc0 ffff2000082902e8 0000000000000000 
0000000000000000
[   12.890593] bca0: 0000000000000000 0000000000000000 0000000000000000 
ffff200000000000
[   12.898425] bcc0: ffff8000c7debd10 ffff20000829034c ffff8000c7e48680 
ffff8000c7e48680
[   12.906256] bce0: ffff8000c7debde0 ffff8000c7debda0 00006c656e72656b 
0000000000000000
[   12.914085] bd00: 0000000000000000 0000000000000000 0000000000000000 
0000000000000000
[   12.921915] bd20: 0000000000000000 0000000000000000 0000ffffa682f9e0 
0000000000000003
[   12.929746] bd40: 0000000080000000 0000000000000015 0000000000000000 
ffff200008083180
[   12.937577] bd60: fffffffffffffeee 0000000000000003 ffffffffffffffff 
0000ffffa67c16e4
[   12.945408] bd80: 0000000041b58ab3 ffff200008e5eb60 ffff20000816f020 
ffff200008b43918
[   12.953239] bda0: 0000000000008600 ffff2000082b4f34 0000000000000000 
ffff2000082b4f08
[   12.961070] bdc0: ffff8000c7debe00 ffff2000082a1b74 0000000000000002 
1ffff00018fbd7cc
[   12.968900] bde0: ffff20000bca5000 ffff8000c7e48680 0000000000000000 
0000000000000001
[   12.976731] be00: 0000000000000000 ffff200008083180 fffffffffffffee6 
0000aaaaac35f840
[   12.984562] be20: ffff20000bca5000 0000000000008600 ffff20000bcacec0 
ffff20000bcacdb8
[   12.992393] be40: ffff20000bca9de8 0000000000005000 0000000000005b88 
0000000000000000
[   13.000222] be60: 0000000000000000 00000000000036e0 0000001b0000001a 
0000000000000013
[   13.008053] be80: 000000000000000d ffff20000808ab14 0000000000000000 
ffff200008082ff4
[   13.015884] bea0: ffffffffffffff06 0000ffffa6831e78 0000000000000000 
ffff200008083180
[   13.023714] bec0: 0000000000000003 0000ffffa682f9e0 0000000000000000 
0000000000000000
[   13.031544] bee0: 0000000000000000 0000000000000000 00000000fffffff8 
0000000000000000
[   13.039375] bf00: 0000000000000111 0000000000000076 0000ffffde67f0dc 
000000000000006c
[   13.047205] bf20: 0000ffffde67f0e0 0000000000000018 0000ffffa6831f50 
000000000d39ad3d
[   13.055037] bf40: 0000aaaaac35e468 0000ffffa67c1650 2000000000000000 
0000ffffa682f9e0
[   13.062867] bf60: 0000000000000003 0000ffffa682fac0 0000ffffa6832f60 
0000aaaaac35f000
[   13.070698] bf80: 0000000000000001 0000aaaaac338b57 0000000000000000 
0000000100000601
[   13.078528] bfa0: 0000000000000001 0000ffffde67f500 0000aaaaac29f8d4 
0000ffffde67f500
[   13.086358] bfc0: 0000ffffa67c16e4 0000000080000000 0000000000000003 
0000000000000111
[   13.094187] bfe0: 0000000000000000 0000000000000000 0000000000000000 
0000000000000000
[   13.102011] Call trace:
[   13.104457] Exception stack(0xffff8000c7deb780 to 0xffff8000c7deb8b0)
[   13.110900] b780: ffff04000016a3fe 0000ffffffffffff ffff8000c7deb9b0 
ffff2000085384cc
[   13.118730] b7a0: 0000000000000145 0000000000000025 0000000000000003 
ffff200000b537e0
[   13.126562] b7c0: 0000000041b58ab3 ffff200008e56238 ffff200008080bb0 
ffff200008e659e0
[   13.134392] b7e0: 0000000000000003 ffff200000b537e0 ffff8000c7debe20 
0000000000000001
[   13.142222] b800: dfff200000000000 000000000000003d 0000000000000140 
0000000000000000
[   13.150053] b820: 0000000000000002 ffff200000b537a0 ffff8000c7deb9b0 
ffff8000c7deb9b0
[   13.157884] b840: ffff8000c7deb970 00000000ffffffc8 ffff8000c7deb880 
ffff200008b336a8
[   13.165716] b860: ffff8000c7deb9b0 ffff8000c7deb9b0 ffff8000c7deb970 
00000000ffffffc8
[   13.173547] b880: fffee800002d47e1 00000000000000fa 00001bffffe95c1d 
dfff200000000000
[   13.181374] b8a0: 000000000000000f 0000000000000003
[   13.186256] [<ffff2000085384cc>] __memset+0x4c/0x1d0
[   13.191221] [<ffff20000825a328>] __asan_register_globals+0x80/0xc0
[   13.197420] [<ffff200000b50d98>] 
_GLOBAL__sub_I_65535_1_of_veea_boot_platform_device_match+0x18/0x30 
[veea_boot]
[   13.207595] [<ffff20000816b7c8>] do_init_module+0xf8/0x350
[   13.213081] [<ffff20000816e6b4>] load_module+0x2bdc/0x3320
[   13.218567] [<ffff20000816f13c>] SyS_finit_module+0x11c/0x130
[   13.224314] [<ffff200008083180>] el0_svc_naked+0x30/0x34
[   13.229628] Code: d65f03c0 cb0803e4 f2400c84 54000080 (a9001d07) 
[   13.235720] ---[ end trace 9d1e36cd22878404 ]---
Segmentation fault


Thanks,
Shahbaz

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/745fe86a-17de-4597-8af3-baa306b6dd0cn%40googlegroups.com.

------=_Part_7891_1143810767.1613479255554
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi,<div><br></div><div>I am having issues getting kasan working with out-of=
-tree modules.</div><div>Always seem to fail during the asan_register_globa=
ls step.</div><div><br></div><div><div>I have seen and tried suggestions me=
ntioning ABI versions; e.g.</div><div>https://groups.google.com/g/kasan-dev=
/c/NkcefkYk3hs/m/74avihf1AwAJ</div></div><div><br></div><div>As per suggest=
ions I have tried ABI versions 3/4/5 with no success:</div><div><ul><li>Ver=
sion 5 (default) produces below stacktrace when loading first out of tree m=
odule.</li><li>Version 4 crashes near start of kernel loading with similar =
trace.</li><li>Version 3 produces lots of kernel errors.</li></ul></div><di=
v><div>I am on arm aarch64; gcc 6.2</div><div>Kernel is at patch 4.9.252</d=
iv></div><div><br></div><div>Digging a little deeper, the issue is that the=
 address of the globals being passed in is expected to be a kernel address,=
 in this case 0xffff xxxx xxxx xxxx, however, the global-&gt;beg is always =
0x0000 xxxx xxxx xxxx.&nbsp; See top of stack trace for example.&nbsp; If I=
 ignore those addresses, I will then get input addresses just under the ker=
nel address range (0xfffe ...).</div><div><br></div><div>The 'beg' is the f=
irst 'globals' structure member so initial thoughts are that the issue shou=
ldn't be due to structure size mismatch due to ABI version.</div><div><br><=
/div><div>Is it perhaps to do with the way out-of-tree modules are loaded/h=
andled?&nbsp; In that the addresses aren't mapped to kernel memory at the p=
oint they enter?&nbsp; I do see the 0x0000 xxxx xxxx xxxx addresses which c=
ome into asan_register_globals as valid addresses of symbols inside the out=
-of-tree module when running `nm`.</div><div><br></div><div><br></div><div>=
Stack trace:</div><div><br></div><div><div>[&nbsp; &nbsp;12.497676] veea_bo=
ot: loading out-of-tree module taints kernel.</div><div>[&nbsp; &nbsp;12.50=
4618] random: fast init done</div><div>[&nbsp; &nbsp;12.516814] WARNING: Sk=
ipped kasan_register_global of non-kernel address: 0000000000000190</div><d=
iv>[&nbsp; &nbsp;12.525947] WARNING: Skipped kasan_register_global of non-k=
ernel address: 00000000000001c0</div><div>[&nbsp; &nbsp;12.534254] WARNING:=
 kasan inaddr: fffe4000016a3f08</div><div>[&nbsp; &nbsp;12.539434] WARNING:=
 kasan shadow addr: fffee800002d47e1</div><div>[&nbsp; &nbsp;12.544192] Una=
ble to handle kernel paging request at virtual address fffee800002d47e1</di=
v><div>[&nbsp; &nbsp;12.552527] [fffee800002d47e1] address between user and=
 kernel address ranges</div><div>[&nbsp; &nbsp;12.559728] Internal error: O=
ops: 96000044 [#1] PREEMPT SMP</div><div>[&nbsp; &nbsp;12.565299] Modules l=
inked in: veea_boot(O+)</div><div>[&nbsp; &nbsp;12.569586] CPU: 0 PID: 1073=
 Comm: modprobe Tainted: G&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;O&nbsp; =
&nbsp; 4.9.252-vsys-1.0 #1</div><div>[&nbsp; &nbsp;12.577764] Hardware name=
: Cavium ThunderX CN81XX board (DT)</div><div>[&nbsp; &nbsp;12.583423] task=
: ffff8000c7d45a80 task.stack: ffff8000c7de8000</div><div>[&nbsp; &nbsp;12.=
589351] PC is at __memset+0x4c/0x1d0</div><div>[&nbsp; &nbsp;12.593275] LR =
is at kasan_poison_shadow+0x7c/0x90</div><div>[&nbsp; &nbsp;12.598064] pc :=
 [&lt;ffff2000085384cc&gt;] lr : [&lt;ffff200008259994&gt;] pstate: 0000014=
5</div><div>[&nbsp; &nbsp;12.605454] sp : ffff8000c7deb9b0</div><div>[&nbsp=
; &nbsp;12.608764] x29: ffff8000c7deb9b0 x28: 0000000000000001&nbsp;</div><=
div>[&nbsp; &nbsp;12.614083] x27: ffff8000c7debe20 x26: ffff200000b537e0&nb=
sp;</div><div>[&nbsp; &nbsp;12.619401] x25: 0000000000000003 x24: ffff20000=
8e659e0&nbsp;</div><div>[&nbsp; &nbsp;12.624720] x23: fffeffffffffffff x22:=
 000000000000003d&nbsp;</div><div>[&nbsp; &nbsp;12.630037] x21: 0000dfffff4=
ae0e8 x20: fffee800002d47e1&nbsp;</div><div>[&nbsp; &nbsp;12.635356] x19: f=
fff04000016a3fe x18: 2000000000000000&nbsp;</div><div>[&nbsp; &nbsp;12.6406=
75] x17: 0000ffffa67c1650 x16: ffff20000816f020&nbsp;</div><div>[&nbsp; &nb=
sp;12.645994] x15: 5400160b13131717 x14: 3030303030303030&nbsp;</div><div>[=
&nbsp; &nbsp;12.651312] x13: 3030203a73736572 x12: ffff0400012da103&nbsp;</=
div><div>[&nbsp; &nbsp;12.656631] x11: 1fffe400012da102 x10: ffff0400012da1=
02&nbsp;</div><div>[&nbsp; &nbsp;12.661949] x9 : 0000000000000000 x8 : fffe=
e800002d47e1&nbsp;</div><div>[&nbsp; &nbsp;12.667267] x7 : fafafafafafafafa=
 x6 : 0000000041b58ab3&nbsp;</div><div>[&nbsp; &nbsp;12.672585] x5 : 000000=
0000000003 x4 : 000000000000000f&nbsp;</div><div>[&nbsp; &nbsp;12.677903] x=
3 : dfff200000000000 x2 : 00001bffffe95c1d&nbsp;</div><div>[&nbsp; &nbsp;12=
.683221] x1 : 00000000000000fa x0 : fffee800002d47e1&nbsp;</div><div>[&nbsp=
; &nbsp;12.688537]&nbsp;</div><div>[&nbsp; &nbsp;12.690027] Process modprob=
e (pid: 1073, stack limit =3D 0xffff8000c7de8020)</div><div>[&nbsp; &nbsp;1=
2.696899] Stack: (0xffff8000c7deb9b0 to 0xffff8000c7dec000)</div><div>[&nbs=
p; &nbsp;12.702645] b9a0:&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &=
nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;=
ffff8000c7deb9f0 ffff20000825a328</div><div>[&nbsp; &nbsp;12.710476] b9c0: =
ffff200000b51f18 00000000000000c0 ffff200000b53720 ffff20000825a310</div><d=
iv>[&nbsp; &nbsp;12.718307] b9e0: ffff200000b51f18 000000fa000000c0 ffff800=
0c7deba40 ffff200000b50d98</div><div>[&nbsp; &nbsp;12.726139] ba00: ffff200=
000b54680 0000000000000001 ffff200000b59000 ffff200000b54950</div><div>[&nb=
sp; &nbsp;12.733970] ba20: ffff200000b54948 ffff8000c7cfde80 ffff200000b548=
50 000000000000000f</div><div>[&nbsp; &nbsp;12.741801] ba40: ffff8000c7deba=
50 ffff20000816b7c8 ffff8000c7debaa0 ffff20000816e6b4</div><div>[&nbsp; &nb=
sp;12.749632] ba60: ffff200000b54680 0000000000000001 ffff8000c7cfe380 0000=
000000000038</div><div>[&nbsp; &nbsp;12.757463] ba80: 0000000000000001 0000=
00000000001d ffff200000b548e0 0000000000000038</div><div>[&nbsp; &nbsp;12.7=
65294] baa0: ffff8000c7debd50 ffff20000816f13c 1ffff00018fbd7b0 00000000000=
00000</div><div>[&nbsp; &nbsp;12.773124] bac0: 0000ffffa682f9e0 00000000000=
00003 0000000080000000 0000000000000015</div><div>[&nbsp; &nbsp;12.780955] =
bae0: 0000000000000123 0000000000000111 ffff200008b54000 ffff8000c7de8000</=
div><div>[&nbsp; &nbsp;12.788786] bb00: ffff8000c7cfe390 ffff8000c7debe30 1=
ffff00018fbd782 ffff200008168bf8</div><div>[&nbsp; &nbsp;12.796618] bb20: f=
fff200000b546d0 ffff80000000001d ffff200008168d38 ffff200008b7d240</div><di=
v>[&nbsp; &nbsp;12.804449] bb40: ffff20000bcacdb8 ffff200000b54850 ffff2000=
00b54858 ffff200000b548c0</div><div>[&nbsp; &nbsp;12.812281] bb60: ffff2000=
00b54688 ffff200000b5613b ffff200000b54818 ffff200000b54868</div><div>[&nbs=
p; &nbsp;12.820113] bb80: ffff20000bcad1c0 ffff200000b54808 ffff20000000001=
d ffff200000b548d8</div><div>[&nbsp; &nbsp;12.827944] bba0: ffff200000b5479=
0 ffff200000b54928 ffff200000b54798 ffff200000b54750</div><div>[&nbsp; &nbs=
p;12.835776] bbc0: ffff200000b547a0 ffff200000b547b8 ffff200000b54760 ffff2=
00000b5479c</div><div>[&nbsp; &nbsp;12.843608] bbe0: ffff200000b547c8 ffff2=
00000b54698 ffff200000b54698 ffff2000090a76e0</div><div>[&nbsp; &nbsp;12.85=
1439] bc00: ffff200000b548f8 ffff20000828f49c 0000000041b58ab3 ffff200008e5=
eb18</div><div>[&nbsp; &nbsp;12.859270] bc20: ffff20000816bad8 000000000000=
0000 ffff8000c7e48680 ffff8000c7debde0</div><div>[&nbsp; &nbsp;12.867101] b=
c40: ffff8000c7e486a0 0000000000000003 ffff8000c7debda0 ffff2000094382b0</d=
iv><div>[&nbsp; &nbsp;12.874932] bc60: 0000000041b58ab3 ffff200008e67588 ff=
ff20000828f3d8 ffff8000c7e60090</div><div>[&nbsp; &nbsp;12.882763] bc80: ff=
ff8000c7debcc0 ffff2000082902e8 0000000000000000 0000000000000000</div><div=
>[&nbsp; &nbsp;12.890593] bca0: 0000000000000000 0000000000000000 000000000=
0000000 ffff200000000000</div><div>[&nbsp; &nbsp;12.898425] bcc0: ffff8000c=
7debd10 ffff20000829034c ffff8000c7e48680 ffff8000c7e48680</div><div>[&nbsp=
; &nbsp;12.906256] bce0: ffff8000c7debde0 ffff8000c7debda0 00006c656e72656b=
 0000000000000000</div><div>[&nbsp; &nbsp;12.914085] bd00: 0000000000000000=
 0000000000000000 0000000000000000 0000000000000000</div><div>[&nbsp; &nbsp=
;12.921915] bd20: 0000000000000000 0000000000000000 0000ffffa682f9e0 000000=
0000000003</div><div>[&nbsp; &nbsp;12.929746] bd40: 0000000080000000 000000=
0000000015 0000000000000000 ffff200008083180</div><div>[&nbsp; &nbsp;12.937=
577] bd60: fffffffffffffeee 0000000000000003 ffffffffffffffff 0000ffffa67c1=
6e4</div><div>[&nbsp; &nbsp;12.945408] bd80: 0000000041b58ab3 ffff200008e5e=
b60 ffff20000816f020 ffff200008b43918</div><div>[&nbsp; &nbsp;12.953239] bd=
a0: 0000000000008600 ffff2000082b4f34 0000000000000000 ffff2000082b4f08</di=
v><div>[&nbsp; &nbsp;12.961070] bdc0: ffff8000c7debe00 ffff2000082a1b74 000=
0000000000002 1ffff00018fbd7cc</div><div>[&nbsp; &nbsp;12.968900] bde0: fff=
f20000bca5000 ffff8000c7e48680 0000000000000000 0000000000000001</div><div>=
[&nbsp; &nbsp;12.976731] be00: 0000000000000000 ffff200008083180 ffffffffff=
fffee6 0000aaaaac35f840</div><div>[&nbsp; &nbsp;12.984562] be20: ffff20000b=
ca5000 0000000000008600 ffff20000bcacec0 ffff20000bcacdb8</div><div>[&nbsp;=
 &nbsp;12.992393] be40: ffff20000bca9de8 0000000000005000 0000000000005b88 =
0000000000000000</div><div>[&nbsp; &nbsp;13.000222] be60: 0000000000000000 =
00000000000036e0 0000001b0000001a 0000000000000013</div><div>[&nbsp; &nbsp;=
13.008053] be80: 000000000000000d ffff20000808ab14 0000000000000000 ffff200=
008082ff4</div><div>[&nbsp; &nbsp;13.015884] bea0: ffffffffffffff06 0000fff=
fa6831e78 0000000000000000 ffff200008083180</div><div>[&nbsp; &nbsp;13.0237=
14] bec0: 0000000000000003 0000ffffa682f9e0 0000000000000000 00000000000000=
00</div><div>[&nbsp; &nbsp;13.031544] bee0: 0000000000000000 00000000000000=
00 00000000fffffff8 0000000000000000</div><div>[&nbsp; &nbsp;13.039375] bf0=
0: 0000000000000111 0000000000000076 0000ffffde67f0dc 000000000000006c</div=
><div>[&nbsp; &nbsp;13.047205] bf20: 0000ffffde67f0e0 0000000000000018 0000=
ffffa6831f50 000000000d39ad3d</div><div>[&nbsp; &nbsp;13.055037] bf40: 0000=
aaaaac35e468 0000ffffa67c1650 2000000000000000 0000ffffa682f9e0</div><div>[=
&nbsp; &nbsp;13.062867] bf60: 0000000000000003 0000ffffa682fac0 0000ffffa68=
32f60 0000aaaaac35f000</div><div>[&nbsp; &nbsp;13.070698] bf80: 00000000000=
00001 0000aaaaac338b57 0000000000000000 0000000100000601</div><div>[&nbsp; =
&nbsp;13.078528] bfa0: 0000000000000001 0000ffffde67f500 0000aaaaac29f8d4 0=
000ffffde67f500</div><div>[&nbsp; &nbsp;13.086358] bfc0: 0000ffffa67c16e4 0=
000000080000000 0000000000000003 0000000000000111</div><div>[&nbsp; &nbsp;1=
3.094187] bfe0: 0000000000000000 0000000000000000 0000000000000000 00000000=
00000000</div><div>[&nbsp; &nbsp;13.102011] Call trace:</div><div>[&nbsp; &=
nbsp;13.104457] Exception stack(0xffff8000c7deb780 to 0xffff8000c7deb8b0)</=
div><div>[&nbsp; &nbsp;13.110900] b780: ffff04000016a3fe 0000ffffffffffff f=
fff8000c7deb9b0 ffff2000085384cc</div><div>[&nbsp; &nbsp;13.118730] b7a0: 0=
000000000000145 0000000000000025 0000000000000003 ffff200000b537e0</div><di=
v>[&nbsp; &nbsp;13.126562] b7c0: 0000000041b58ab3 ffff200008e56238 ffff2000=
08080bb0 ffff200008e659e0</div><div>[&nbsp; &nbsp;13.134392] b7e0: 00000000=
00000003 ffff200000b537e0 ffff8000c7debe20 0000000000000001</div><div>[&nbs=
p; &nbsp;13.142222] b800: dfff200000000000 000000000000003d 000000000000014=
0 0000000000000000</div><div>[&nbsp; &nbsp;13.150053] b820: 000000000000000=
2 ffff200000b537a0 ffff8000c7deb9b0 ffff8000c7deb9b0</div><div>[&nbsp; &nbs=
p;13.157884] b840: ffff8000c7deb970 00000000ffffffc8 ffff8000c7deb880 ffff2=
00008b336a8</div><div>[&nbsp; &nbsp;13.165716] b860: ffff8000c7deb9b0 ffff8=
000c7deb9b0 ffff8000c7deb970 00000000ffffffc8</div><div>[&nbsp; &nbsp;13.17=
3547] b880: fffee800002d47e1 00000000000000fa 00001bffffe95c1d dfff20000000=
0000</div><div>[&nbsp; &nbsp;13.181374] b8a0: 000000000000000f 000000000000=
0003</div><div>[&nbsp; &nbsp;13.186256] [&lt;ffff2000085384cc&gt;] __memset=
+0x4c/0x1d0</div><div>[&nbsp; &nbsp;13.191221] [&lt;ffff20000825a328&gt;] _=
_asan_register_globals+0x80/0xc0</div><div>[&nbsp; &nbsp;13.197420] [&lt;ff=
ff200000b50d98&gt;] _GLOBAL__sub_I_65535_1_of_veea_boot_platform_device_mat=
ch+0x18/0x30 [veea_boot]</div><div>[&nbsp; &nbsp;13.207595] [&lt;ffff200008=
16b7c8&gt;] do_init_module+0xf8/0x350</div><div>[&nbsp; &nbsp;13.213081] [&=
lt;ffff20000816e6b4&gt;] load_module+0x2bdc/0x3320</div><div>[&nbsp; &nbsp;=
13.218567] [&lt;ffff20000816f13c&gt;] SyS_finit_module+0x11c/0x130</div><di=
v>[&nbsp; &nbsp;13.224314] [&lt;ffff200008083180&gt;] el0_svc_naked+0x30/0x=
34</div><div>[&nbsp; &nbsp;13.229628] Code: d65f03c0 cb0803e4 f2400c84 5400=
0080 (a9001d07)&nbsp;</div><div>[&nbsp; &nbsp;13.235720] ---[ end trace 9d1=
e36cd22878404 ]---</div><div>Segmentation fault</div></div><div><br></div><=
div><br></div><div>Thanks,</div><div>Shahbaz</div><div><br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/745fe86a-17de-4597-8af3-baa306b6dd0cn%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/745fe86a-17de-4597-8af3-baa306b6dd0cn%40googlegroups.com</a>.<b=
r />

------=_Part_7891_1143810767.1613479255554--

------=_Part_7890_766043814.1613479255554--
