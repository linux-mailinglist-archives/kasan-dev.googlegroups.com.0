Return-Path: <kasan-dev+bncBAABBHGAXKDQMGQEGGGLBSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 299FB3C8005
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 10:28:14 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id k63-20020a37a1420000b02903b4fb67f606sf710496qke.10
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 01:28:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626251293; cv=pass;
        d=google.com; s=arc-20160816;
        b=PTMqWDzHiQwvlsHpQKEu8sYzRqPlI8JaCpSipRDLB0GtHOXmapjp1FNT1FLr/0TUnr
         iYexHPEig/DZB2oSBSD/75XIZ+89qNF1OozW80sIIa/BifX52k2CSiVj57IOX+c7a+7M
         C+yzn40clQ+P7uBlmdJTsqOzMrAucpKWYyMs/t6iqDMo7VFRHWPO404YS26Zu2Pu1N7r
         yXxSwe/K+C7iHseQmEb/TYxJSlSwBnli4UZoD64UeS43/RGx9B7cuy28nxKUZUVMbVVW
         Ipw3bTvPtb1ReCkAG9hl1Zd7hmwSWBzb0+ARtQkg9UOOHnKl9yrwREFUIN19IPlg8SHG
         MyhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PUQecrEyljctXE7YPTPVF+0Tz7vIXeYEx4onAyVoA2s=;
        b=Oe1oFyKBVZ8eXgZw+LJlG5gs+VLOeDiA6zDkD2YajeaS7Ti+bJfdUVBqJrHb2SzHDr
         PUp+/x8Mudvk78kcwzyYtZMEiBpnhRvauZXDgq9h/SyK3YOwP3nvLFYk2aYSu6SAJv8M
         PughheuAkGivyGbR8A+pUa5P1LOo4dC5hS8fLhuySo3llysehmFTIrGHvgL7O5bhym9U
         DZPZu/OX32tV/d/C2+EK8R5J+K4QH6GYD9Xw2CCVTV9vrJulZodznsqD3KtuCFDt9KiP
         HxSOieaf36EZyBZZQlwl1Gqz8ZYTTiNQeD8TGvg9uG5DSHVOG7/grOx0CCzC42+NjUvT
         BD8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PUQecrEyljctXE7YPTPVF+0Tz7vIXeYEx4onAyVoA2s=;
        b=n88k+jG+QAuFoThy/ZASwBZSS7/z23ZgAmdWd+yjghjPxHgY2LAcEvFj+hMeV2hsbW
         U0kuEmCWZ99r4BJMLwybImEw2V9vxEV7FeITYxtZZenmp2OLgvq3mG8DjsTZuwHVSIij
         gAqe+/jXy00ltdw2bnbsdNYTJ0Nl238EP0IvdjDbNG01mwckpHMTLkfNmhY1QYn+4pnl
         NcaK6YYvblaOBl/XDo4WyH7TDOz1WTr2PZx7IjQ15ZlqUMGzbXzYLvHcL4HoJPcEgM3S
         TZ0ZfkhMclUdPGuCEBvKWQrK6YcEHBN7xc/o3QlhLfpCF9Y8/OmIrZnVQrKbJnXDInid
         N1GA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PUQecrEyljctXE7YPTPVF+0Tz7vIXeYEx4onAyVoA2s=;
        b=rUBI4MXbRPTNv82wTgqPw+NGjB0FUp3F/h9v1YDDd8K0dnSM/K46MlRaxYymcRnT87
         n3Pqrrf9NoExYgMiJkBiTTN0m5P3+ylfuoUbosINBjImWJI+4CwRwsQ+M8iaxliYx34m
         KAgjVpUaPLTcbVdo+HeaEjA7hag9YZ9vcxNgXMs5loa5khBfts/EPkRcL5dbPZIEAf0E
         xP9D4bs1NJLoVR2W37obRK6dzRpBwqWdZrgUZ/CpHJzWWAO88nXBRGfq0EkSWBSRi+Kz
         c2Qkn3ZsZjwAowtfErqoXkcPzhWhMUhM41Ehkhl0qraom4r9eIKeYTy0OWQhi0MTiBiU
         dX6Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533D2OQXzdve6+f1CrJ9N4gF9P0thkR9xEmxC4g2oipUF8GADmy8
	JKxFpzMBT8YCwRNG0x+Ums8=
X-Google-Smtp-Source: ABdhPJzyYEWHJrnj3L8UTAY2U6GPwiahoIYIj0FsAjdWCFr9Z/EJj7XenYWgnobDsZp127PJPbJJDQ==
X-Received: by 2002:a05:620a:1926:: with SMTP id bj38mr8783894qkb.87.1626251293013;
        Wed, 14 Jul 2021 01:28:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:20cb:: with SMTP id f11ls1473228qka.3.gmail; Wed,
 14 Jul 2021 01:28:12 -0700 (PDT)
X-Received: by 2002:a37:ac6:: with SMTP id 189mr8627450qkk.204.1626251292598;
        Wed, 14 Jul 2021 01:28:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626251292; cv=none;
        d=google.com; s=arc-20160816;
        b=lmvI6aUzGVG62TYWFoslKzotybV9vouvIugtNeGt0VvCDeOIXiY//spAfhNICoveEc
         FZ4b3A13WM0IsWZ5ukXkLyI/b4YDYATq1D95EvTOk65iVPTKtipBmL4YiXoMaIM+O1pm
         Rp4FYO2gwOfod0NGkvrmLJhv0G4Ix8uDxwbzVlXP+bxOOswRcLD4TkHF5eBVcqaaFdNp
         9XTyc9Mr56PfC8TA/wZbduj1djT2150zYTohAGqWo/AXE2g5EYUBOIj/Sowi2BLz/kth
         R6A2SBYVBRWYz/OFzA91BRsIj6f9WmZEbqFw6sGuFjiWRWNvzYXagO4l28qb8H2XtHSe
         YewQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=1wTYzCjOou2z4pwnmn8LKixfiS7Emcpbuc7r/jtbM5Y=;
        b=kVik6z/ekUvS8Jt+BM+/xtiG32lWPqT+88JXKsFLnXnS+l3SEgN3cI1MPNOotsWqOY
         SYzvst01zO0j32uhUN06L2z23FgAssmYDVNsEEamCPmIgjDfkCiS530aGWaj2lDbq/Bq
         57xluZY6ntcemC8KactXIv/HJmrbYOxBe+D+wQsk2hVAmGMUGeKkPk+CwsWr+VWaADTK
         RNP1dESTWaJanJhaf4QKi3f2b/li9AhBGtb10Zia/XtQrAVoghNXXVWnvvL6vStKrQdi
         1jeIZ6vEt3fqhm5PxUc2vwECmV7QLaF7R1FxTFGghkSCKPNlbsXAOn4eJoaICUWX4rv/
         +S0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id m6si179021qkg.2.2021.07.14.01.28.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 14 Jul 2021 01:28:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggeme765-chm.china.huawei.com (unknown [172.30.72.55])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4GPr892lN0zXrv9;
	Wed, 14 Jul 2021 16:22:01 +0800 (CST)
Received: from DESKTOP-E0KHRBE.china.huawei.com (10.67.103.82) by
 dggeme765-chm.china.huawei.com (10.3.19.111) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256) id
 15.1.2176.2; Wed, 14 Jul 2021 16:27:38 +0800
From: Shaobo Huang <huangshaobo6@huawei.com>
To: <ardb@kernel.org>, <f.fainelli@gmail.com>, <nico@marvell.com>,
	<qbarnes@gmail.com>, <sagar.abhishek@gmail.com>, <ryabinin.a.a@gmail.com>,
	<glider@google.com>, <andreyknvl@gmail.com>, <dvyukov@google.com>,
	<linux@armlinux.org.uk>, <kasan-dev@googlegroups.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>
CC: <wuquanming@huawei.com>, <young.liuyang@huawei.com>,
	<zengweilin@huawei.com>, <chenzefeng2@huawei.com>, <huangshaobo6@huawei.com>,
	<kepler.chenxin@huawei.com>, <liucheng32@huawei.com>,
	<liuwenliang@huawei.com>, <nixiaoming@huawei.com>, <xiaoqian9@huawei.com>
Subject: [PATCH] ARM: fix panic when kasan and kprobe are enabled
Date: Wed, 14 Jul 2021 16:27:38 +0800
Message-ID: <20210714082738.2668-1-huangshaobo6@huawei.com>
X-Mailer: git-send-email 2.21.0.windows.1
In-Reply-To: <20210708041409.34168-1-huangshaobo6@huawei.com>
References: <20210708041409.34168-1-huangshaobo6@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.103.82]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggeme765-chm.china.huawei.com (10.3.19.111)
X-CFilter-Loop: Reflected
X-Original-Sender: huangshaobo6@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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

From: huangshaobo <huangshaobo6@huawei.com>

arm32 uses software to simulate the instruction replaced
by kprobe. some instructions may be simulated by constructing
assembly functions. therefore, before executing instruction
simulation, it is necessary to construct assembly function
execution environment in C language through binding registers.
after kasan is enabled, the register binding relationship will
be destroyed, resulting in instruction simulation errors and
causing kernel panic.

the kprobe emulate instruction function is distributed in three
files: actions-common.c actions-arm.c actions-thumb.c, so disable
KASAN when compiling these files.

for example, use kprobe insert on cap_capable+20 after kasan
enabled, the cap_capable assembly code is as follows:
<cap_capable>:
e92d47f0	push	{r4, r5, r6, r7, r8, r9, sl, lr}
e1a05000	mov	r5, r0
e280006c	add	r0, r0, #108    ; 0x6c
e1a04001	mov	r4, r1
e1a06002	mov	r6, r2
e59fa090	ldr	sl, [pc, #144]  ;
ebfc7bf8	bl	c03aa4b4 <__asan_load4>
e595706c	ldr	r7, [r5, #108]  ; 0x6c
e2859014	add	r9, r5, #20
......
The emulate_ldr assembly code after enabling kasan is as follows:
c06f1384 <emulate_ldr>:
e92d47f0	push	{r4, r5, r6, r7, r8, r9, sl, lr}
e282803c	add	r8, r2, #60     ; 0x3c
e1a05000	mov	r5, r0
e7e37855	ubfx	r7, r5, #16, #4
e1a00008	mov	r0, r8
e1a09001	mov	r9, r1
e1a04002	mov	r4, r2
ebf35462	bl	c03c6530 <__asan_load4>
e357000f	cmp	r7, #15
e7e36655	ubfx	r6, r5, #12, #4
e205a00f	and	sl, r5, #15
0a000001	beq	c06f13bc <emulate_ldr+0x38>
e0840107	add	r0, r4, r7, lsl #2
ebf3545c	bl	c03c6530 <__asan_load4>
e084010a	add	r0, r4, sl, lsl #2
ebf3545a	bl	c03c6530 <__asan_load4>
e2890010	add	r0, r9, #16
ebf35458	bl	c03c6530 <__asan_load4>
e5990010	ldr	r0, [r9, #16]
e12fff30	blx	r0
e356000f	cm	r6, #15
1a000014	bne	c06f1430 <emulate_ldr+0xac>
e1a06000	mov	r6, r0
e2840040	add	r0, r4, #64     ; 0x40
......

when running in emulate_ldr to simulate the ldr instruction, panic
occurred, and the log is as follows:
Unable to handle kernel NULL pointer dereference at virtual address
00000090
pgd = ecb46400
[00000090] *pgd=2e0fa003, *pmd=00000000
Internal error: Oops: 206 [#1] SMP ARM
PC is at cap_capable+0x14/0xb0
LR is at emulate_ldr+0x50/0xc0
psr: 600d0293 sp : ecd63af8  ip : 00000004  fp : c0a7c30c
r10: 00000000  r9 : c30897f4  r8 : ecd63cd4
r7 : 0000000f  r6 : 0000000a  r5 : e59fa090  r4 : ecd63c98
r3 : c06ae294  r2 : 00000000  r1 : b7611300  r0 : bf4ec008
Flags: nZCv  IRQs off  FIQs on  Mode SVC_32  ISA ARM  Segment user
Control: 32c5387d  Table: 2d546400  DAC: 55555555
Process bash (pid: 1643, stack limit = 0xecd60190)
(cap_capable) from (kprobe_handler+0x218/0x340)
(kprobe_handler) from (kprobe_trap_handler+0x24/0x48)
(kprobe_trap_handler) from (do_undefinstr+0x13c/0x364)
(do_undefinstr) from (__und_svc_finish+0x0/0x30)
(__und_svc_finish) from (cap_capable+0x18/0xb0)
(cap_capable) from (cap_vm_enough_memory+0x38/0x48)
(cap_vm_enough_memory) from
(security_vm_enough_memory_mm+0x48/0x6c)
(security_vm_enough_memory_mm) from
(copy_process.constprop.5+0x16b4/0x25c8)
(copy_process.constprop.5) from (_do_fork+0xe8/0x55c)
(_do_fork) from (SyS_clone+0x1c/0x24)
(SyS_clone) from (__sys_trace_return+0x0/0x10)
Code: 0050a0e1 6c0080e2 0140a0e1 0260a0e1 (f801f0e7)

Fixes: 35aa1df43283 ("ARM kprobes: instruction single-stepping support")
Fixes: 421015713b30 ("ARM: 9017/2: Enable KASan for ARM")
Signed-off-by: huangshaobo <huangshaobo6@huawei.com>
Asked-by: Ard Biesheuvel <ardb@kernel.org>
---
 arch/arm/probes/kprobes/Makefile | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/arm/probes/kprobes/Makefile b/arch/arm/probes/kprobes/Makefile
index 14db56f49f0a..6159010dac4a 100644
--- a/arch/arm/probes/kprobes/Makefile
+++ b/arch/arm/probes/kprobes/Makefile
@@ -1,4 +1,7 @@
 # SPDX-License-Identifier: GPL-2.0
+KASAN_SANITIZE_actions-common.o := n
+KASAN_SANITIZE_actions-arm.o := n
+KASAN_SANITIZE_actions-thumb.o := n
 obj-$(CONFIG_KPROBES)		+= core.o actions-common.o checkers-common.o
 obj-$(CONFIG_ARM_KPROBES_TEST)	+= test-kprobes.o
 test-kprobes-objs		:= test-core.o
-- 
2.12.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210714082738.2668-1-huangshaobo6%40huawei.com.
