Return-Path: <kasan-dev+bncBCN7B3VUS4CRBL6MTWIAMGQEHEOHEWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F3594B33A3
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Feb 2022 08:48:00 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id n13-20020a056602340d00b006361f2312desf7932657ioz.9
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 23:48:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644652079; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZJpksIsNPqJN4U9axE3FiylVrhUtfyjMIroU8+eNfY9igNuvEA0LyZg3weGZcgQMf0
         Cpc9/H3S9gAHal+xGPo/v18lOJqSoQRgtRYnwkI/yVu7r9kKu0PWZh+qwqjPoa4S0X/C
         2fEfr8oiGq3RjYPCABwpfppViiFZHQdYpLTBY38hA/SutuZNhZ1zK8QNr3CaAlT0MVbS
         2Ad/9tXrLSQsnTaiRxKlIXwt2kj1Co2AKhGyqzuuJlun3PL2pdkBGHothExUPlhbCWqY
         cHAR0PdIKsVwBix+/Bb9DFf3nB52YvG9TnjN/1+VNM8WfXpb69lm4W7vUkFTalaYDVqY
         NZPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=LEwc4x60UOm9Y1SMb334PDYlvsg20EHEEL3MUT45NeM=;
        b=TMOYMW9DZPGX7V0pxen9dGGsgA7KFW80TZJv7uXY2b6Gwg/hnTPItq2y7oZtBOM5xj
         y35MVXmqvGew542I/0WM5yUNF6ooPbdkNn7ADI3Yy3MlO2IweP/XAJNTQBRm9e+40yy7
         RdZ5t30FeTvR+7mwaTlB31dYB36rslkisdcuuSAWuMS7o6i8eKOLtxFoKXNAX0V3nGK7
         qL4hqdG2Kjc+MHooJDqYzzMFrJXITEXXBKNhCC+kzmavB1+fSCIz3f/XvmYt228JtjwM
         GHJdfL5LZaJ1eZvul/C503KFJ8mgWnLNamIe4j4CLrP2BofGgfPOKU694wirO1cEc/mh
         IXUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LEwc4x60UOm9Y1SMb334PDYlvsg20EHEEL3MUT45NeM=;
        b=jh69DdEMIdAnwO9+x1vOe43PrHilP4L7OPCbFPrGmZ31IZq8lEGT6YJtO8fVjz9AbB
         R+3ojd/pgPA75PnAWN26g/5w8ALzpOhn5chLdO0WCOtoOhZE+/WC03ScZNXFn2icWX9J
         NvOUrBL0J06nxMg1AGs8KCBSy5pJg8kWQ2OQpeMFeugafaIwISZUtgfE6i4Kzzvv5nrq
         E9tMVR/hGBE/SkYwl6MJW4728CDMwvyRIvr9RYQ4tsjmfH3K8Gsdypefu0I3vSaZWrgO
         4rpQHneZrx2uMWYT5pbtniWvaBhHAzuAN9wVpNw/WtmoV+YQxRCPKqVz1apAF8FcBXLM
         8Uug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LEwc4x60UOm9Y1SMb334PDYlvsg20EHEEL3MUT45NeM=;
        b=DRYHDdn7BJUjL0RhxxmixDM5db0+ENQYqeaamHLwC8byGws2AejPaOxOAwBzkpCmTb
         SM0sNU5w+hXBuHaxK4xvfKK/G+iAYFK4nSZrUtJ1jNFnj97s1HVBWOlFmENjfTTPex/x
         U8Lipw4UGBTEqAMuLQuYZZAaWD3P7obA7IW9VoL1teTqqtsvvvX/AbzgR9lMExk/z+pN
         AWiwj/M9iP1bXtUoUS8Nl52r9rq8Tza3UCcb5UmDwtk/bEfA6qD7ZHK+wMd0IfKga8N5
         L84CwqwkLezJiYEI601cSPTirBAFTfDZI4Nz1hks0Ng1rzoWan99aUz3jNUf211mT8WX
         cn8g==
X-Gm-Message-State: AOAM530kM39wcgM4fZxhN3wCbtBymJYuUoRNeMtsg2WPcTblcN80/Ghz
	WuBCGBK+lizwWFObtJwIHG0=
X-Google-Smtp-Source: ABdhPJz1iLjzsar28GI/gc20yIMEBL14+2eJF19oaW2sdAI8o9CesjJ1QP3Qe647GXxe8RjfTjTURA==
X-Received: by 2002:a5e:dd41:: with SMTP id u1mr2612308iop.217.1644652079263;
        Fri, 11 Feb 2022 23:47:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1ec:: with SMTP id t12ls1996885jaq.10.gmail; Fri,
 11 Feb 2022 23:47:58 -0800 (PST)
X-Received: by 2002:a02:c903:: with SMTP id t3mr2916955jao.156.1644652078851;
        Fri, 11 Feb 2022 23:47:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644652078; cv=none;
        d=google.com; s=arc-20160816;
        b=z/OVE2gAUwaQjWSyj9f3Tac56fws36N6SG22hnEzV0fAi3ry2G0v7I/YLZuVY/AjMm
         0uMuQGyvLY397e16NVG4lIrx08jDpIKnNeVeMZBwPPedrHhKNnWQhowfdLdnCPH2QojM
         euFQVsPsezLGFHejsU/lLANn7LseZQWM5ZDwOgwz6IZFb6FVW8Wgsyyq3Rf7Zx8h/+13
         44YV2sBv47eDlT9gcQvBQ9yko8no1Om9M3NVuuBq0gBs4GhQxOAKfuEJQceCqUxAWOQf
         Vn3glE9A6M619W/jifOWuAjHoBkx3YK1V/HXUiVpRxKszdGMWfP4iBlRZDR/TrUHbUgo
         VTAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=xgpq/ToyYzNTiA9t4Lita5h+XMP36pNEZ0fv9N8tUyM=;
        b=YYsCXban17s6XuNXgblOSYi27UVC1CMjRDOK0ivmSsu3jUpUF/oqhgyCn+YL3Lwqsf
         SU0w92PghVi7m4qVVQQVBGvfgvTDGR8cQvv4S0525s9iamiYD8RKR456fFnsgKmPXURu
         rtkZ1QHtu8+DCFfa+jZI9gLYyR/PEivHtevOSVJPjFfEJONu8cp7xeyrd5VdZdO/Kihc
         XO/ZUbAMM+9BUTWnp+xq1T3LOPxfo75tIqYMz5j+WyiTbYIQR6IDZjzdXWtVG/56AXJP
         E67WvGoseVZcNrdBpxLTg2tYJtW4PdLgDbNu6fARUl0V37H+5owmUNK+NezhkDBzaOMO
         wkjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id q17si970662ilj.3.2022.02.11.23.47.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 11 Feb 2022 23:47:58 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 64064257b6e3476aa952be279817ef89-20220212
X-UUID: 64064257b6e3476aa952be279817ef89-20220212
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw01.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 123026892; Sat, 12 Feb 2022 15:47:54 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sat, 12 Feb 2022 15:47:53 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sat, 12 Feb 2022 15:47:53 +0800
From: "'Lecopzer Chen' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>
CC: <lecopzer.chen@mediatek.com>, <andreyknvl@gmail.com>,
	<anshuman.khandual@arm.com>, <ardb@kernel.org>, <arnd@arndb.de>,
	<dvyukov@google.com>, <geert+renesas@glider.be>, <glider@google.com>,
	<kasan-dev@googlegroups.com>, <linus.walleij@linaro.org>,
	<linux@armlinux.org.uk>, <lukas.bulwahn@gmail.com>, <mark.rutland@arm.com>,
	<masahiroy@kernel.org>, <matthias.bgg@gmail.com>,
	<rmk+kernel@armlinux.org.uk>, <ryabinin.a.a@gmail.com>,
	<yj.chiang@mediatek.com>
Subject: [PATCH v2 2/2] arm: kconfig: fix MODULE_PLTS for KASAN with KASAN_VMALLOC
Date: Sat, 12 Feb 2022 15:47:47 +0800
Message-ID: <20220212074747.10849-3-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20220212074747.10849-1-lecopzer.chen@mediatek.com>
References: <20220212074747.10849-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Lecopzer Chen <lecopzer.chen@mediatek.com>
Reply-To: Lecopzer Chen <lecopzer.chen@mediatek.com>
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
KASAN_VMALLOC, thus select KASAN_VMALLOC by default.

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

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 arch/arm/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index 78250e246cc6..d797a3699959 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -1515,6 +1515,7 @@ config ARCH_WANT_GENERAL_HUGETLB
 config ARM_MODULE_PLTS
 	bool "Use PLTs to allow module memory to spill over into vmalloc area"
 	depends on MODULES
+	select KASAN_VMALLOC if KASAN
 	default y
 	help
 	  Allocate PLTs when loading modules so that jumps and calls whose
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220212074747.10849-3-lecopzer.chen%40mediatek.com.
