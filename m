Return-Path: <kasan-dev+bncBCN7B3VUS4CRBMEYTKHQMGQEGUVV2GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id B97D0492309
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jan 2022 10:45:21 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id f12-20020a056902038c00b006116df1190asf37264939ybs.20
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jan 2022 01:45:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1642499120; cv=pass;
        d=google.com; s=arc-20160816;
        b=aKBf4Vg7FVINp++SwzRME5/YhGsi9uVEhQgvhsfuUTAgdhR5RMrdo+9xK4n0PVLZCU
         rUlALuKw3JA5SexHvFXipcPovqgGoeTag+D+imIe5y3FRGAOUrsIOgfs5VN2aLQRb88/
         mYO0GbV2LF6WZDXUkIJnuSJSTf41egWmPf3FN68NUBBDvEsFBXI2YB4ol4sqBKDT9iZN
         q2SpKp/sPB6YUaR3m8u8om9zv47LeSucnZcmhAZD/ICYraIq0Dt0L82Z+MKoq/9au5mc
         vHc+VUxS6sCy7jZbZBuix4ZtQBUMWIlWSlnj5qXGeLcxe23RsmzfbE2ZM5/YK6oUuQ9F
         eksQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hnu7ip7Br0cXpMWT1/j7yeSoX9hmUxvAeV9BLTzicQA=;
        b=T9Hz7zp1SPWgL/SKyaVRKBLr7VqkB0EVX5Qpze0DPEHIPosHnLUTdsXI9gy0C2d7Fn
         p6FPF6AgWFI5M0E9yAXbEK1dWtjLYOKdx4sLlzGzf3qsgzg1G/rhSdmpR8UKTAShq7BK
         QvG/ysQgEBKuiLf9IedXXN++Zqtse2U4hfJDP1L5indNUpQKc+N8KnX5xE4V0aW9iVR7
         2uofvzp6KxkG9Kr5OWQqUtPOZGKl8PdRpFnnPO0q8raQkPA+aYNDVZ399qrP+EWB21s6
         bUkqMvPJAYBquFLJt8Ne+OcJx4pdvEyxyePCHrJrG6wbOarnqMjxFqpstzV3C1ldm/95
         w52g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hnu7ip7Br0cXpMWT1/j7yeSoX9hmUxvAeV9BLTzicQA=;
        b=YnZ1winF9ykEmwrMnFL7/M5vQgmvag+WscmePfetz0jv1aoz0P3uwiPNGz4vc6uYaX
         dMoKbCxQmfTIZYyOEGqpXQRR47cy7Z1ix09Dd0ga5RoBnvHvD3skiOYNNl7MaUOEjpox
         z+Fy2TZTkMXwO+1QvlzW6iUZv0SnaGEB0nTVRut9LYZr/c2Hi6/kLsw8tzfzWxGKqzPe
         XFYWGSYptw3AHkNuegfz6ZYrfOg8O6X8S55+p30VtxhD+pbPtyTHK/P3mMw8xzEYpl+V
         9m0xqX+Dbo/Xqg87fNQc3/s1EYHJoX+HQboXwmzGFAbE+D9CskzoFaYfDvGRaxjjf4Vz
         b2Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hnu7ip7Br0cXpMWT1/j7yeSoX9hmUxvAeV9BLTzicQA=;
        b=uzZeN+tQTzul2IkFflI3ckwxhJ2HTGKdAiaYFrQedZZOwHzPDzsAvwy5irJzexwsg1
         o3yumd2bj3TPpr+plV4VCB3/JMwLl21AyzTEDZu2miX9wGyYxJWRGacXUBoK1jkLDHL9
         DIp/onNEka+pgNpn7eRTSnHeOdrqcNj5LxR4GHhnL46rVbiaVFzNQTV+qB/oYzKIo7or
         /0qx3soytEJA3BW7Lu2HpjUYsjq7ClXwuOBK+blqgIP1YJPk+BVKbXsc7ohUzll4xLsx
         CZxzh1VBx0HfujlC1Rdyycrl1fixlFCV6Antlx24I+ztURTC4yRu9kpmdJ7oV1yzRWjY
         URfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5323PS6wkz+yewQ4u+kQf0Xl+Rq1vLLE2VlsDJgmXahcr7V4pg2y
	IQ/wZa/hsGcM1HsqGGWFEHk=
X-Google-Smtp-Source: ABdhPJxGTieOrAtOBtaFsk8U9y9o0n4c7Kv2VEmB6vfMJNKSJr1Jccis9rPuNNl1xiOLBHMvE2KlrA==
X-Received: by 2002:a25:b3c2:: with SMTP id x2mr32048662ybf.565.1642499120643;
        Tue, 18 Jan 2022 01:45:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:1a54:: with SMTP id a81ls1675307yba.2.gmail; Tue, 18 Jan
 2022 01:45:20 -0800 (PST)
X-Received: by 2002:a25:bf82:: with SMTP id l2mr33086800ybk.356.1642499120094;
        Tue, 18 Jan 2022 01:45:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1642499120; cv=none;
        d=google.com; s=arc-20160816;
        b=THMYoSzR9vcuPLSEjIs003sxCtc+WTU9rX8UZxEEXKR//gLTRPeblZzhaHgtX/oNpc
         k80VGrOZh8yQpxdeXg0FxODqshi4WExGpVb4WZrYQaGxTJczkG1wQt8nxIu3T6x11eCh
         ND8UEEu6u0vKpV74nHDDFYQ/L0UakylR3xmMpINM1FtUMV02vZewCPrEezk2aFY/MS1J
         fMk4CrJ1eCvhO+d1Zo0EgrDuUx9x4q1oDPuM7Kb+R7vVKLhq0Ahi3Btt+dk8mIMt4NdJ
         DYI5JVoy4obf5+Cwt+qEwn2u+pXBwjOY2YCI24wDF27o47fe08onbBDpe0LXz3vN4gaB
         a6Fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=Vb+w3ikmNiAWvlgfUVHiRwZQoay9m7sUAuvRQD60pfw=;
        b=mEojXrdUQo9LQuOXkfJTSuD5eXl37f7EGOTdDYGDht7ciybMPE6zi+o7ZDnWvxIGCa
         DeXrGJC0X/mv+GiGGtiOsfguoidTZMNSrK/OQRODDPwJIlX7MeNQteDzzI31R4E7jAcv
         chvpxAJVYrcWcSUWIjzGCIUjM80UvpuQOr4XrFz7j3g/N6K1PU5SFjODXhdFOUtJPrv4
         QiItNbtuRje9xP08t+tHt1QghevbdW32LEOgiDrXoEvqIeW8BZHA9Qq0t/tv4aJCUxVl
         TYlsSnVICffh1MTflhiz8nnXiIRTfIzf0b765aIjTeSfeFm28Vs1q15zWGMsy4/P7SHE
         4LDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id y16si1000443ybk.5.2022.01.18.01.45.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Jan 2022 01:45:20 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: e1587ceefc7f4901ab973fa118381a65-20220118
X-UUID: e1587ceefc7f4901ab973fa118381a65-20220118
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 50564287; Tue, 18 Jan 2022 17:45:13 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 15.2.792.15; Tue, 18 Jan 2022 17:45:11 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 18 Jan 2022 17:45:11 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <linux-kernel@vger.kernel.org>
CC: Russell King <linux@armlinux.org.uk>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, "Andrey
 Konovalov" <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>, Arnd Bergmann <arnd@arndb.de>,
	Linus Walleij <linus.walleij@linaro.org>, <rmk+kernel@armlinux.org.uk>,
	"Geert Uytterhoeven" <geert+renesas@glider.be>, Ard Biesheuvel
	<ardb@kernel.org>, Mark Rutland <mark.rutland@arm.com>, Anshuman Khandual
	<anshuman.khandual@arm.com>, Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	<linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
	<yj.chiang@mediatek.com>, Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH 2/2] arm: kconfig: fix MODULE_PLTS for KASAN with KASAN_VMALLOC
Date: Tue, 18 Jan 2022 17:44:50 +0800
Message-ID: <20220118094450.7730-3-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20220118094450.7730-1-lecopzer.chen@mediatek.com>
References: <20220118094450.7730-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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
index f97f2c416be0..d219179d3254 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -1514,6 +1514,7 @@ config ARCH_WANT_GENERAL_HUGETLB
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220118094450.7730-3-lecopzer.chen%40mediatek.com.
