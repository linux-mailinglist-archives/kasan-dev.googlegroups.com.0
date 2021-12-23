Return-Path: <kasan-dev+bncBCN7B3VUS4CRB3MYSGHAMGQE7ICAOBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 033AE47E130
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Dec 2021 11:16:15 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id d187-20020a6bb4c4000000b00601c0b8532asf2872524iof.23
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Dec 2021 02:16:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640254573; cv=pass;
        d=google.com; s=arc-20160816;
        b=XeLw47GhriWzfxqrPQpSV2F6jsMtjogYrCJJanc3Nx4V6QLcn2gwKBlvkBANBgD+CG
         S0G7SwNWS5f2wwLvcR0qRcY1grFxYm3PyXrFllBFAC3Wwgsqfl+ycouY1pjXw+J3XnIo
         aseaG6Sya64DyEveWXzNZUP5aHmrxeTeSVPy3Y3A5ZTz7iEbYAAeSYnBQKOjCLRJeCfI
         0vCkyjWXyoD0XHUAq9zJRyEfKgv/8TEy67zQ5bZH3kzW6A3+g8U7Fq057R61wPHbiCng
         wyeMCUdGzxeOquSfM29WlBtBvoPLleHdVwiBRKm37Pmpdqj2iVDg8A0/pzFLs4VtfzWg
         afbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ADHHgle9uvzc/NN78fXNVCv6T6o623Cd0C3g1iM2Jgo=;
        b=v9JrTkTwFfmnbE0Hz+CDaGjvL5b+6m0581sVHW/QMFW9HCipgHlDWwyZX0G8sp5I47
         lZ+wgFGpx2U+2q1E3wbJvg29xovW4zlwQpvqYwKAOz3pER86BXZmZgZCxksG4Zi4B5k9
         wFF9a943O1S60YsR7IjMq6HWQiYxMfwRlr4O4AO1YplhbGcyElSy93QS4rnzOBHdDBll
         8VLyj7R8Vr/fKtqs2GZP3Oaj2RjS1AICj3bwl3NHBzbT8M+MDae2TdwxWikVF5xsdWHJ
         2gj2uvt7uWuLIQD250I30JSPccf7wR0lvewUcwGg2/43i9qcQoZoneZX0DzODCA2HjGF
         Doyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ADHHgle9uvzc/NN78fXNVCv6T6o623Cd0C3g1iM2Jgo=;
        b=Sy4KjJTiZ9e6nctKAqJ/XFA4ixDVHXZ5lOk4qePPQf/MK11WPaePjkq9u2sYzSAn9y
         S3E4tAA7rMtvq5hTOCMDOWetbY3ALTimrwfzyYCxcTAxWdrEkpE/aJFDvqNnag1vfOmT
         zhXFenswhh1s6bzS+7D13peDQGj0rcl27pHF3pz5j2RhT2T3Uv8+mbGIToPSF9nkX2Tz
         FzseMDEYqGmlTvfph+YvHwN+1txqCQNb0AOFp4/SrHymK7QVvY8Zze9YOrFhYOobLgQd
         TBbDuqhfjZGC90TFDJEvFJaV+NKLeF5JXXunMjBvhqILTuCWN1/wJlegSiJZB6Gu4prM
         wafg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ADHHgle9uvzc/NN78fXNVCv6T6o623Cd0C3g1iM2Jgo=;
        b=A9DjCrVe890AfxhIfqaUqF9xwrPRBfGOwL2Ib8ItZwAklMa8i5ADaJ49zadirbIsG+
         egfUZOW67bolSf1Ux5PX2UWFEiH59yEgumvRp+ftgWLdu53fM+eXd7F8NrPeqbDx3F5h
         aR0SHsGxBw2BOmb6L2Z32/DPuyeSorr6xW8QbFunW8bEsHk6mZjXjlX0oDOxTNcseE7/
         xGOQxgtArHCssxMMKefKTi7taUBArx3sobPowvWJt+LrjKQS5r7aOdmzD8TQ/EF8vM5O
         InglO5Q+4RgbEaA2tnj57/Vk7A/Bjt0IberBp/n+OwPn/bYNp/7FVQWjgwD+YNuVth1y
         GHlQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530h5TSArYzLyUMQKFRbZ+u9mk5zixYcGagfYGhQh48PTTlJvl/m
	yNbTVqLHLC4YdmAKf6w2UIc=
X-Google-Smtp-Source: ABdhPJygT8paPQMuRjfPdTq7r964A4Tsip96rKIYTt60TdSePbLyH8N3vKRflcPTmbgmwd55OlBO/w==
X-Received: by 2002:a05:6638:3049:: with SMTP id u9mr732356jak.132.1640254573801;
        Thu, 23 Dec 2021 02:16:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8588:: with SMTP id f8ls495955ioj.0.gmail; Thu, 23 Dec
 2021 02:16:13 -0800 (PST)
X-Received: by 2002:a6b:e508:: with SMTP id y8mr715380ioc.177.1640254573404;
        Thu, 23 Dec 2021 02:16:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640254573; cv=none;
        d=google.com; s=arc-20160816;
        b=ApT5TuUipIqzK0h3V54AQSCwkXgTqV/zOXkZA6SwYlq/EUWb0Ad+GnoBWKOMHLzxf4
         3TFPcyk53S3LM2a2EWu7HuTz5e78UEMHP3oCOI5JNVYXnfFnsp4hQ8eJemd1jPfGutSW
         8+XhTa5gXYt2hIxqq20VWTxzdA4+sBd3WIxtp7KN8Jn//hqtkF/QQXzKyudi9XbBgrjT
         qC9DNCaBmVeT1QC00SgJYD00ObbXSgodAEQCjn+DdNfa7vFMGqh04Xz+xK52wmkRbwWh
         cdnkV5SJ9AyH/DZdTJHe5ovAJ/32+m1JqZ+ZfA+m+UKg7m0iHWILTexaePutnbxiPEQ8
         +5Rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=UgmN9z6+KTvIVYIV2AZ+u2OlJBk1BKARN3PX5DhdRQk=;
        b=yDH1ZMoSMOf2ogHDF5aQaOlX3ulJa6paTnonX77VY/gd19zZ6wSDxDLZWPn/ULQszU
         WqJUF2YsQ8xkb8LaMZTzfA0/l7/ob4b2RWVwZAet4ZZRsfexdpSlAv16oNagwwY84zeb
         Rp+l2I3CGQM/LAEWwdLyDf7Yq19ML9J+bLp1N6WXbrxxrt0UMnmwCjb0ZsNWloGJ5xlp
         b0C2Pjrt0x46+Pmi8msEco+2GxNIb6EaKPF2GJwirO9qcgs6BTUOvMdyQZgJGVx1wJV3
         U61+V3GiTW8vCz7ua7QuDVXoSHp4DIHng6lRDD2PQLUk1A1DCfozNqGIV0ExnhFy8K1/
         e4sA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id y12si297712iod.1.2021.12.23.02.16.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Dec 2021 02:16:13 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 34035d3a60f14c2a8063166864cd25a9-20211223
X-UUID: 34035d3a60f14c2a8063166864cd25a9-20211223
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw01.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1937618850; Thu, 23 Dec 2021 18:16:07 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 15.2.792.15; Thu, 23 Dec 2021 18:16:06 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 23 Dec 2021 18:16:05 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>
CC: <linux@armlinux.org.uk>, <ardb@kernel.org>, <liuwenliang@huawei.com>,
	<linus.walleij@linaro.org>, <f.fainelli@gmail.com>, <dvyukov@google.com>,
	<kasan-dev@googlegroups.com>, <yj.chiang@mediatek.com>, Lecopzer Chen
	<lecopzer.chen@mediatek.com>, <stable@vger.kernel.org>
Subject: [PATCH] ARM: module: fix MODULE_PLTS not work for KASAN
Date: Thu, 23 Dec 2021 18:15:51 +0800
Message-ID: <20211223101551.19991-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

When we run out of module space address with ko insertion,
and with MODULE_PLTS, module would turn to try to find memory
from VMALLOC address space.

Unfortunately, with KASAN enabled, VMALLOC doesn't work without
VMALLOC_KASAN which is unimplemented in ARM.

hello: loading out-of-tree module taints kernel.
8<--- cut here ---
 Unable to handle kernel paging request at virtual address bd300860
 [bd300860] *pgd=41cf1811, *pte=41cf26df, *ppte=41cf265f
 Internal error: Oops: 80f [#1] PREEMPT SMP ARM
 Modules linked in: hello(O+)
 CPU: 0 PID: 89 Comm: insmod Tainted: G           O      5.16.0-rc6+ #19
 Hardware name: Generic DT based system
 PC is at mmioset+0x30/0xa8
 LR is at 0x0
 pc : [<c077ed30>]    lr : [<00000000>]    psr: 20000013
 sp : c451fc18  ip : bd300860  fp : c451fc2c
 r10: f18042cc  r9 : f18042d0  r8 : 00000000
 r7 : 00000001  r6 : 00000003  r5 : 01312d00  r4 : f1804300
 r3 : 00000000  r2 : 00262560  r1 : 00000000  r0 : bd300860
 Flags: nzCv  IRQs on  FIQs on  Mode SVC_32  ISA ARM  Segment none
 Control: 10c5387d  Table: 43e9406a  DAC: 00000051
 Register r0 information: non-paged memory
 Register r1 information: NULL pointer
 Register r2 information: non-paged memory
 Register r3 information: NULL pointer
 Register r4 information: 4887-page vmalloc region starting at 0xf1802000 allocated at load_module+0x14f4/0x32a8
 Register r5 information: non-paged memory
 Register r6 information: non-paged memory
 Register r7 information: non-paged memory
 Register r8 information: NULL pointer
 Register r9 information: 4887-page vmalloc region starting at 0xf1802000 allocated at load_module+0x14f4/0x32a8
 Register r10 information: 4887-page vmalloc region starting at 0xf1802000 allocated at load_module+0x14f4/0x32a8
 Register r11 information: non-slab/vmalloc memory
 Register r12 information: non-paged memory
 Process insmod (pid: 89, stack limit = 0xc451c000)
 Stack: (0xc451fc18 to 0xc4520000)
 fc00:                                                       f18041f0 c04803a4
 fc20: c451fc44 c451fc30 c048053c c0480358 f1804030 01312cff c451fc64 c451fc48
 fc40: c047f330 c0480500 f18040c0 c1b52ccc 00000001 c5be7700 c451fc74 c451fc68
 fc60: f1802098 c047f300 c451fcb4 c451fc78 c026106c f180208c c4880004 00000000
 fc80: c451fcb4 bf001000 c044ff48 c451fec0 f18040c0 00000000 c1b54cc4 00000000
 fca0: c451fdf0 f1804268 c451fe64 c451fcb8 c0264e88 c0260d48 ffff8000 00007fff
 fcc0: f18040c0 c025cd00 c451fd14 00000003 0157f008 f1804258 f180425c f1804174
 fce0: f1804154 f180424c f18041f0 f180414c f1804178 f18041c0 bf0025d4 188a3fa8
 fd00: 0000009e f1804170 f2b18000 c451ff10 c0d92e40 f180416c c451feec 00000001
 fd20: 00000000 c451fec8 c451fe20 c451fed0 f18040cc 00000000 f17ea000 c451fdc0
 fd40: 41b58ab3 c1387729 c0261c28 c047fb5c c451fe2c c451fd60 c0525308 c048033c
 fd60: 188a3fb4 c3ccb090 c451fe00 c3ccb080 00000000 00000000 00016920 00000000
 fd80: c02d0388 c047f55c c02d0388 00000000 c451fddc c451fda0 c02d0388 00000000
 fda0: 41b58ab3 c13a72d0 c0524ff0 c1705f48 c451fdfc c451fdc0 c02d0388 c047f55c
 fdc0: 00016920 00000000 00000003 c1bb2384 c451fdfc c3ccb080 c1bb2384 00000000
 fde0: 00000000 00000000 00000000 00000000 c451fe1c c451fe00 c04e9d70 c1705f48
 fe00: c1b54cc4 c1bbc71c c3ccb080 00000000 c3ccb080 00000000 00000003 c451fec0
 fe20: c451fe64 c451fe30 c0525918 c0524ffc c451feb0 c1705f48 00000000 c1b54cc4
 fe40: b78a3fd0 c451ff60 00000000 0157f008 00000003 c451fec0 c451ffa4 c451fe68
 fe60: c0265480 c0261c34 c451feb0 7fffffff 00000000 00000002 00000000 c4880000
 fe80: 41b58ab3 c138777b c02652cc c04803ec 000a0000 c451ff00 ffffff9c b6ac9f60
 fea0: c451fed4 c1705f48 c04a4a90 b78a3fdc f17ea000 ffffff9c b6ac9f60 c0100244
 fec0: f17ea21a f17ea300 f17ea000 00016920 f1800240 f18000ac f17fb7dc 01316000
 fee0: 013161b0 00002590 01316250 00000000 00000000 00000000 00002580 00000029
 ff00: 0000002a 00000013 00000000 0000000c 00000000 00000000 0157f004 c451ffb0
 ff20: c1719be0 aed6f410 c451ff74 c451ff38 c0c4103c c0c407d0 c451ff84 c451ff48
 ff40: 00000805 c02c8658 c1604230 c1719c30 00000805 0157f004 00000005 c451ffb0
 ff60: c1719be0 aed6f410 c451ffac c451ff78 c0122130 c1705f48 c451ffac 0157f008
 ff80: 00000006 0000005f 0000017b c0100244 c4880000 0000017b 00000000 c451ffa8
 ffa0: c0100060 c02652d8 0157f008 00000006 00000003 0157f008 00000000 b6ac9f60
 ffc0: 0157f008 00000006 0000005f 0000017b 00000000 00000000 aed85f74 00000000
 ffe0: b6ac9cd8 b6ac9cc8 00030200 aecf2d60 a0000010 00000003 00000000 00000000
 Backtrace:
 [<c048034c>] (kasan_poison) from [<c048053c>] (kasan_unpoison+0x48/0x5c)
 [<c04804f4>] (kasan_unpoison) from [<c047f330>] (__asan_register_globals+0x3c/0x64)
  r5:01312cff r4:f1804030
 [<c047f2f4>] (__asan_register_globals) from [<f1802098>] (_sub_I_65535_1+0x18/0xf80 [hello])
  r7:c5be7700 r6:00000001 r5:c1b52ccc r4:f18040c0
 [<f1802080>] (_sub_I_65535_1 [hello]) from [<c026106c>] (do_init_module+0x330/0x72c)
 [<c0260d3c>] (do_init_module) from [<c0264e88>] (load_module+0x3260/0x32a8)
  r10:f1804268 r9:c451fdf0 r8:00000000 r7:c1b54cc4 r6:00000000 r5:f18040c0
  r4:c451fec0
 [<c0261c28>] (load_module) from [<c0265480>] (sys_finit_module+0x1b4/0x1e8)
  r10:c451fec0 r9:00000003 r8:0157f008 r7:00000000 r6:c451ff60 r5:b78a3fd0
  r4:c1b54cc4
 [<c02652cc>] (sys_finit_module) from [<c0100060>] (ret_fast_syscall+0x0/0x1c)
 Exception stack(0xc451ffa8 to 0xc451fff0)
 ffa0:                   0157f008 00000006 00000003 0157f008 00000000 b6ac9f60
 ffc0: 0157f008 00000006 0000005f 0000017b 00000000 00000000 aed85f74 00000000
 ffe0: b6ac9cd8 b6ac9cc8 00030200 aecf2d60
  r10:0000017b r9:c4880000 r8:c0100244 r7:0000017b r6:0000005f r5:00000006
  r4:0157f008
 Code: e92d4100 e1a08001 e1a0e003 e2522040 (a8ac410a)
 ---[ end trace df6e12843197b6f5 ]---

Cc: <stable@vger.kernel.org> # 5.10+
Fixes: 421015713b306e47af9 ("ARM: 9017/2: Enable KASan for ARM")
Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 arch/arm/kernel/module.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm/kernel/module.c b/arch/arm/kernel/module.c
index beac45e89ba6..c818aba72f68 100644
--- a/arch/arm/kernel/module.c
+++ b/arch/arm/kernel/module.c
@@ -46,7 +46,7 @@ void *module_alloc(unsigned long size)
 	p = __vmalloc_node_range(size, 1, MODULES_VADDR, MODULES_END,
 				gfp_mask, PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
 				__builtin_return_address(0));
-	if (!IS_ENABLED(CONFIG_ARM_MODULE_PLTS) || p)
+	if (!IS_ENABLED(CONFIG_ARM_MODULE_PLTS) || IS_ENABLED(CONFIG_KASAN) || p)
 		return p;
 	return __vmalloc_node_range(size, 1,  VMALLOC_START, VMALLOC_END,
 				GFP_KERNEL, PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211223101551.19991-1-lecopzer.chen%40mediatek.com.
