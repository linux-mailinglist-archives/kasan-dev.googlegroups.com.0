Return-Path: <kasan-dev+bncBCN7B3VUS4CRB6VJ7GAAMGQECXONMCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 071A2311C2D
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Feb 2021 09:36:12 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id o3sf6146551pju.6
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Feb 2021 00:36:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612600570; cv=pass;
        d=google.com; s=arc-20160816;
        b=TL47NG4g+shqQrXc0/8b++z6KxgsEYyJkbReZznQkw/92n14a+UZjmdjBTeHxXqysH
         rmL2cEZdDKTvBGqoggcxwT22oOnlsTBeOBieuxuqX57UmGMW6FyVMCV/OSKSRTGYaVuo
         1EWXgF+CITpDBG1fbsRSRGtr63X8advjxMJHqKv+IdY2mQcJ7tIEXNgIeRyX6nSb6Efs
         oCzkDO/wAovzFO47nN3rkdIN+X5IVFAKDPFePId2SCm7P3PhtITEsUqc6YOqDRk+3ByZ
         N6ahSKFuC6VyqYIqxIFGeFt6tRKV860DuwkC6uoxIYvL4Lrn+ly/6f3XwebD+hMBRQfY
         UbUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2/sSc7w7xmxYMF2DGPIB69AY/YXrrtqT4bnnpE0cI7o=;
        b=O/W9Z7UrTZWMHAMmsao4qgdO/500KpGKKmCbdv25qSRUaeV6H+21D1x7CtiuTqtUV7
         ypbsABMEIIoY+9fPeBHrJSyy5Oem6U/x45qBrjhyWfkFEGsAFq0IrQyMqCZfypSmF2ZR
         X6zlWJ1F/ZHVSwjBbg41cA3wEyfnRWPGNCslz7ZR96mcqC1rMed7BVFULrYmt0vyhhqa
         uxftAtIsqejh1LGz94+1pzOoIryW5Wi5rPsRmGvwfPFDVSnQAAqOCq4LUDm7k8A5Yp1t
         DDC1QbFjCAt8Pr4/Auh8OIFPOdjjRRpvu1xCd8zLGt1USNAqQhazt0ZRtc+D1vdGj5YT
         2DnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2/sSc7w7xmxYMF2DGPIB69AY/YXrrtqT4bnnpE0cI7o=;
        b=FSTyNu5upDKY3/6RQj1WXfaVM/+sVgWl6iYp6Btq21dAokjVw8Jws5kzB7cNfUDqQQ
         rqitfq6o2eWVrPKlE+OarlNhLVmN7a0CKGe8BIV32EhiK2boB5++N6f9cmrTSqx6IYKo
         x7LIhWKYXG2iO449KNx4CsFUgmKJ1vsEHqjM6Y2gRwfjjQi6WnLqPbtCq+PhUMwvBFOf
         6lb1K0JdrUn+xLV5SsnJrveq/edIIAas3zCRN2F4brdZAl/+AhS4KEL0gdYzl4yyzbrs
         e091sBQqfT5/QFpchz41Hw72pEGY83qx8a7GUxJ//iTmkoBflUL7XNubHgv57/2Mfa/e
         f9iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2/sSc7w7xmxYMF2DGPIB69AY/YXrrtqT4bnnpE0cI7o=;
        b=hcNLsFl3wXtyaFYkEVeXgxEA0zB2qj1boLrf2UwbwNtH6HhYcy1uE8iXnYCj2LD9IU
         xmhiclCXsi0q1P+xLhgTx3hT5PzHVeFw5tKYG4AKyu0PcwuC5CCc0Zhu2Uf0wIlY491r
         n4soIhDrzfzNqUqRjIJ1p2TEAjU/Oz/vUSZCsD+5a05oCPbjFjo6L0gGxILtfkNcgxdp
         fiL4jrvTedylSolz8d9Mb+Euz4VbXWxW9X2o5NP3sw4qUASN9BAIphWIRZQ9pQMysAam
         d0EogsjTWQU7M+5TaPOlVbJjzBgi1ePNKCGCX/O3VFULgVPyeFfdEjkW9JT7ij+OvlCb
         6Vbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531AdUkK3MhDYJsnLouWIsUGLmVVOhJEgtyHTABND0/sytUcBT3v
	9JsHvZbv9H3iXtDV8ZPC484=
X-Google-Smtp-Source: ABdhPJww5UjiKQZDCvcfyfQiyYxqEksxUsS5VhdQpLIWGSmq4oluT/SRHbaTr5qsvldHMy/M3+x4Gw==
X-Received: by 2002:a63:e30d:: with SMTP id f13mr8451740pgh.39.1612600570359;
        Sat, 06 Feb 2021 00:36:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2dcd:: with SMTP id q13ls5677132pjm.0.gmail; Sat, 06
 Feb 2021 00:36:09 -0800 (PST)
X-Received: by 2002:a17:902:5581:b029:e2:a0b3:130e with SMTP id g1-20020a1709025581b02900e2a0b3130emr8053926pli.18.1612600569678;
        Sat, 06 Feb 2021 00:36:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612600569; cv=none;
        d=google.com; s=arc-20160816;
        b=pkpBimzaZtRz00Cl2aRPXTwPxRsxJFxO1n2oP2Z1CT5QEqSYt3nsRnwELJYNYwBWDm
         /C+m8j2ZUIpRiNPVbC/6wdkSyPDPjS1FNVigI+9q5HQ48sAlskHIYjafQTknN86ldA2V
         raVbDJSPHD3FutPLvjfiYhO0PKdGVAOGPJKWUZD8NbOfXUoDoCwYDYUjEZwhuHDlTYXI
         wixh/7gHxpsqBktrDtS53hpCJhjqeGbOaVDE9c2qyOrS08/NwS3F/rpzXCiRNx0UyU61
         dU9v1mHERiSvZTfAfwFOWjbV4roJBZzJzLRU4eGr3ZYkZH09LTzvK0XUIK+6mAeO9GWD
         Q0IQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=uozNGIa07asqoRreqZ6eCVWme3sikFXLL4XqeUSwYVc=;
        b=gg4YuHY9oRiKaeg/lLHm8qPmTRkFdBb92rWxmkFfCCaDTANB6ePhTRIHlSJu2uC4Vg
         pOdy3Xr3wQ2EG+OvD5wZEGzdKiHOOCf2/LgUjSbrBLX+pAD1rtK+J32vb7ajlmjbPF6a
         phehSRDgZ3ykZN7lyXRpiL+BbK0myCmtML/ynhOits0r1uvTlBmvrgo1zPQe1BeDAoOG
         HjI8LBzcor4jEFbZkxE12vmBDbn92aqoUu/8a1BsL+eUko+SU5i5axDjFbINJSyKIDpp
         4oGdRXDkejipcoDwpv3tegDfDdVUyyEm4H1Ute10dR5ZItaFb3sCdagPHMWf2NBctjAY
         QO6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id l8si530608pgi.0.2021.02.06.00.36.09
        for <kasan-dev@googlegroups.com>;
        Sat, 06 Feb 2021 00:36:09 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 54a4c85ce4454427adab3f6a641998f7-20210206
X-UUID: 54a4c85ce4454427adab3f6a641998f7-20210206
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw01.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 494478168; Sat, 06 Feb 2021 16:36:06 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs08n1.mediatek.inc (172.21.101.55) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sat, 6 Feb 2021 16:36:05 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sat, 6 Feb 2021 16:36:05 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>,
	<kasan-dev@googlegroups.com>, <linux-arm-kernel@lists.infradead.org>,
	<will@kernel.org>
CC: <dan.j.williams@intel.com>, <aryabinin@virtuozzo.com>,
	<glider@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
	<linux-mediatek@lists.infradead.org>, <yj.chiang@mediatek.com>,
	<catalin.marinas@arm.com>, <ardb@kernel.org>, <andreyknvl@google.com>,
	<broonie@kernel.org>, <linux@roeck-us.net>, <rppt@kernel.org>,
	<tyhicks@linux.microsoft.com>, <robin.murphy@arm.com>,
	<vincenzo.frascino@arm.com>, <gustavoars@kernel.org>, <lecopzer@gmail.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH v3 1/5] arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
Date: Sat, 6 Feb 2021 16:35:48 +0800
Message-ID: <20210206083552.24394-2-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210206083552.24394-1-lecopzer.chen@mediatek.com>
References: <20210206083552.24394-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as
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

MODULE_VADDR: no mapping, no zoreo shadow at init
VMALLOC_VADDR: backed with zero shadow at init

After:

MODULE_VADDR: no mapping, no zoreo shadow at init
VMALLOC_VADDR: no mapping, no zoreo shadow at init

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210206083552.24394-2-lecopzer.chen%40mediatek.com.
