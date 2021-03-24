Return-Path: <kasan-dev+bncBCN7B3VUS4CRBEPV5KBAMGQEYM3DVGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 803D3347059
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 05:05:38 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id v25sf209283oiv.7
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 21:05:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616558737; cv=pass;
        d=google.com; s=arc-20160816;
        b=dJNd57Fnc3VmLt1wXUEJy6A45ppaq/Mr7B+1bEjwJdQtHHbuZds9CHpO64NXWiBX1j
         6u3e1gETHS/27ldWSnZ8ns2k81VN/4VhW3a09n5v1SDuZar0pPEoJdzo1H5OJsmm8ctK
         EXUK64J2hj1wLTcbK/rTZgvAMI1njiRlKZ4Gw4l27F7UeFjmGruPDsrxa6nzua4zn0ok
         s27SW5Gg2sod5tnRW59nf8z3xCTCWyJiOLD1I1Tpoh8oTt7wcqUADPUMO1cPQAD4U8mC
         j79TVZHDs7e3bvGNN0+Dyev0uS5h4fi9wD4ijH91RxNAJI24BIT369dVqKSyar2Eb9X2
         nzaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ovG+wGDXgT2Ip4W9umAa/ch8NH2KhFs9LxmSYYy1ZvE=;
        b=yV0H2I3V+T9KlJICIz8+zkNySlNoTaRaAYeIrWjnBuxTnTJq0XWKLF91kdQPnC/uWe
         PoiXMuDnSpv/CYuU+a93tqD3TCpGQP176CHuGA/c6jlCtwNyFaEgVvrGlibFMGWcSXoz
         sMk0ZSHEyhiJtIUw5F1ca7FiXJ1sMAFxTJEXuCR1V83U+JlnxrIP8jEGfINbYd0RBVsW
         /SaghYSjLCN7SW73Udl9Hy/f/7TxDd5uDvZOp0yHLo/8JOOoayRlWxeRYCExMnUO0sXV
         TxkaaM7J+34wSVrP9N+ohwOA7FHrSyB9eyDt11VVZsMh8yo7GtDymYIidugDXbcJIEji
         x8/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ovG+wGDXgT2Ip4W9umAa/ch8NH2KhFs9LxmSYYy1ZvE=;
        b=LStBRtMIaelRpzSPHthP0BFyi6bb8HplxGtwaIlyh8Z/9hfMqgvoGv2XKOZt9zNEv5
         P2rSa+ASFmkyvaMUbT2nFvLuA1PHOvMjNOU19VTF8owy6qb68tsmLyyU8d50qFax1LvW
         dH2vr1h90Wk1tHuEWD1ON/35aom/xR4vdorlb7no1Q1dfTBCBZk0cEtOcgrWOB82mfF0
         r5Ur6O9ehOLUeM7A85jS2VJ5MwKApOptBFzOHYhT2MxNN06APCRH08Wz/yEOTlrUH0sS
         XcIvKFPb+sJS+gQBU7xzL3ty7MJmJGp5ns4MBKQ6E0H0bg0IGWtyh0FCJ8j5KZOkZ60+
         0/Iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ovG+wGDXgT2Ip4W9umAa/ch8NH2KhFs9LxmSYYy1ZvE=;
        b=bYP4igtQWxzrgFyRD/Ay72lj021hUcM4c3PUyk+4RnshwxzTPFVOqKyP28/lw1+pg/
         QkFZvU0aui3bNgwx8+5xdD9LJ7xcGSoOsL9KYOtIoNsd071NvUflOePA7xb8Gc7Ol5eh
         cQSlftKG/FiQk8KdDyf4T32xLEMfEk6sXKwpHPKmlaaJoGGkQnSqKctn3JZsW4OJ0Icq
         n3oCiDRMeKUTBuO1E+O1+bwasxbKeTWXWeDZUz4qF/s8fEl+vneOBykNftO5QL48fj95
         WreZqq0t+tmVpa1f6gLGEgrlqlikM3OxsqPFvLDnBmvwCbnQFGsxiE+ytqqB287jvbyJ
         +KuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533D4FiYXq9Z/i0YeQD3pjRBmsPHQMh6m84OOeqWw4rl9DF8uxuj
	jQsSckk/hN0jJBXUNx9J8Oc=
X-Google-Smtp-Source: ABdhPJyH/3ttqgfwSmXBzvOX93GJhDYukE89N2ZlNe4Qq/i6kEvXnYlZhJaV/XucBK98wQRy5kXq6Q==
X-Received: by 2002:a9d:2628:: with SMTP id a37mr1436021otb.366.1616558737220;
        Tue, 23 Mar 2021 21:05:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2470:: with SMTP id x48ls257810otr.8.gmail; Tue, 23
 Mar 2021 21:05:36 -0700 (PDT)
X-Received: by 2002:a05:6830:13c8:: with SMTP id e8mr1430165otq.175.1616558736882;
        Tue, 23 Mar 2021 21:05:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616558736; cv=none;
        d=google.com; s=arc-20160816;
        b=NVk5VIC9d8a0JENNhXRro47B8QKiFpz3FZz6U0vwwaqmmGH38gthZZp1K2eCuXWvwD
         2L7Hx9D1u9bFB4eiPbYXeB67ULkMn9NcIm0NtU1Qj+1t8+JpXQ3T2BMKzmkp3tiiKJPu
         7fg5xY7LSaEgG7dOUS1hdc9iHpY4W5zJZKM4m9eh2BvO1Pfy6649NNztfed17mdcqHXa
         NxHSzfdWyxP20tZK8VF+GoBcrHB2DRO3/bZOdCk/2cfgUq0dh9MqX+G1U+OgpjNqbEne
         Ek8v5SkucNiIyCL2sHte53ZrcwqstZqECUELXQfUpVgrPESiQctdpobmsPSnxvqGZq+b
         z/aQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=szCN/GLbc4ZxhhDt3bZg83l5+2ZcsqvPQs3DXjX0Vtk=;
        b=hxG0N4UnU9a7n8DODrHGE98YcdocNkSn/87/WMBiXOn+HHE8dWtQuO/EWREyZhgb0b
         z4+bmWFix+EByOpaFCHppLIA5UuAfaXiPxg67tnlwjh4gCNg5jK8qg2urx31Gg3vhSyh
         qaWi9f0UR0BuHlu6SHWKfeY2XMrwCO3fMo0BarF9gQUfxpj6qnAvAczzCZYTcx/qlQVu
         bmlLRila5XBRwP5iIffm8EVWlLlaRJJa6Q/isGcdh1UgNRzw0i8ZRvECuUil0BRQAotC
         wbfA3BRMxN1qXjZhY0J9vgNP0pkclBqPHj2efelrT8Qx3319Zrg8JJ+NcZpafHm4N59d
         au1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id x143si72794oif.2.2021.03.23.21.05.36
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Mar 2021 21:05:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: b2b597c23d3c4d78a2312729a2fc8dd1-20210324
X-UUID: b2b597c23d3c4d78a2312729a2fc8dd1-20210324
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 337191216; Wed, 24 Mar 2021 12:05:30 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs05n2.mediatek.inc (172.21.101.140) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 24 Mar 2021 12:05:29 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 24 Mar 2021 12:05:29 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <catalin.marinas@arm.com>, <will@kernel.org>
CC: <ryabinin.a.a@gmail.com>, <glider@google.com>, <andreyknvl@gmail.com>,
	<dvyukov@google.com>, <akpm@linux-foundation.org>,
	<tyhicks@linux.microsoft.com>, <maz@kernel.org>, <rppt@kernel.org>,
	<linux@roeck-us.net>, <gustavoars@kernel.org>, <yj.chiang@mediatek.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH v4 1/5] arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
Date: Wed, 24 Mar 2021 12:05:18 +0800
Message-ID: <20210324040522.15548-2-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210324040522.15548-1-lecopzer.chen@mediatek.com>
References: <20210324040522.15548-1-lecopzer.chen@mediatek.com>
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

Linux support KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
("kasan: support backing vmalloc space with real shadow memory")

Like how the MODULES_VADDR does now, just not to early populate
the VMALLOC_START between VMALLOC_END.

Before:

MODULE_VADDR: no mapping, no zero shadow at init
VMALLOC_VADDR: backed with zero shadow at init

After:

MODULE_VADDR: no mapping, no zero shadow at init
VMALLOC_VADDR: no mapping, no zero shadow at init

Thus the mapping will get allocated on demand by the core function
of KASAN_VMALLOC.

  -----------  vmalloc_shadow_start
 |           |
 |           |
 |           | <= non-mapping
 |           |
 |           |
 |-----------|
 |///////////|<- kimage shadow with page table mapping.
 |-----------|
 |           |
 |           | <= non-mapping
 |           |
 ------------- vmalloc_shadow_end
 |00000000000|
 |00000000000| <= Zero shadow
 |00000000000|
 ------------- KASAN_SHADOW_END

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
Acked-by: Andrey Konovalov <andreyknvl@gmail.com>
Tested-by: Andrey Konovalov <andreyknvl@gmail.com>
Tested-by: Ard Biesheuvel <ardb@kernel.org>
---
 arch/arm64/mm/kasan_init.c | 18 +++++++++++++-----
 1 file changed, 13 insertions(+), 5 deletions(-)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index d8e66c78440e..20d06008785f 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -214,6 +214,7 @@ static void __init kasan_init_shadow(void)
 {
 	u64 kimg_shadow_start, kimg_shadow_end;
 	u64 mod_shadow_start, mod_shadow_end;
+	u64 vmalloc_shadow_end;
 	phys_addr_t pa_start, pa_end;
 	u64 i;
 
@@ -223,6 +224,8 @@ static void __init kasan_init_shadow(void)
 	mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
 	mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);
 
+	vmalloc_shadow_end = (u64)kasan_mem_to_shadow((void *)VMALLOC_END);
+
 	/*
 	 * We are going to perform proper setup of shadow memory.
 	 * At first we should unmap early shadow (clear_pgds() call below).
@@ -241,12 +244,17 @@ static void __init kasan_init_shadow(void)
 
 	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)PAGE_END),
 				   (void *)mod_shadow_start);
-	kasan_populate_early_shadow((void *)kimg_shadow_end,
-				   (void *)KASAN_SHADOW_END);
 
-	if (kimg_shadow_start > mod_shadow_end)
-		kasan_populate_early_shadow((void *)mod_shadow_end,
-					    (void *)kimg_shadow_start);
+	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
+		kasan_populate_early_shadow((void *)vmalloc_shadow_end,
+					    (void *)KASAN_SHADOW_END);
+	else {
+		kasan_populate_early_shadow((void *)kimg_shadow_end,
+					    (void *)KASAN_SHADOW_END);
+		if (kimg_shadow_start > mod_shadow_end)
+			kasan_populate_early_shadow((void *)mod_shadow_end,
+						    (void *)kimg_shadow_start);
+	}
 
 	for_each_mem_range(i, &pa_start, &pa_end) {
 		void *start = (void *)__phys_to_virt(pa_start);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324040522.15548-2-lecopzer.chen%40mediatek.com.
