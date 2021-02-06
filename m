Return-Path: <kasan-dev+bncBCN7B3VUS4CRB7FJ7GAAMGQELP4PRGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 16411311C2E
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Feb 2021 09:36:14 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id v16sf6867877pgl.23
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Feb 2021 00:36:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612600573; cv=pass;
        d=google.com; s=arc-20160816;
        b=L3BTJwC9tmYo6PeNUVQw4d5V3+1YRaE4vJAVC3rK4Lqyydd4GYFlTxWSKLWi30UR7r
         M9ZycunKuJqlksgKirfxDH9xOmp8O7ImHWmI1u0diI8wQBlMURsuTR2VlXqwDLY0djfO
         W6v7YSEoFj56oQ/Qtw9/PqDWQZ/VcgJXY+f0fWTCHg91cBjb82185Gg+Lc4i/DSY6ot4
         UTvOjWbR839aEPmkQtilir69M07yQY7p3nUZseR/0FI+Fvl95Rg9D0qW8wYVFDAeUruI
         UKTDbRt1e2msh4NB04zQ6xqcYCD7c9UuIIgETwa+LEyBARF03SCjetJ88BuYmn5PpdLp
         fqDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qC53rMZYYteHiiXzzCWwvcODZsX0JiY8iygwGWXmm8Y=;
        b=YGw0aDSgndhwft4/N9yeYEyJLef0o9mTmMjRq/X6QgGEVNdxEla6ySeZnXcveefflL
         laTTxkPosTijv0zRQwq/rR6D/ZbmN+zzzqj5T3t2IY5qHSnyFSYttneMc3idsx/qLzUE
         HQVnPrwiqfMQP0PI1a9gTDtJzIzba+OdfVBstMQ3BfzpkEmxrhklf7H0ukyap1M0jd6+
         q3HlEOhsDRdTWjonssSGp5hORvJPs1kx7jfqL15BGfHtdjQjRzhovPFY0bd0Y5CeLdmh
         ue0D1ufCIKEB+YsfDxrbSIV1o7hv0dLODa6XmUXDzGXwalOjTYUGEiYAtcdshKnAb4r/
         oJJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qC53rMZYYteHiiXzzCWwvcODZsX0JiY8iygwGWXmm8Y=;
        b=puQMff08FhZB4ZdV0p3s8SHotGB3qkbtg5okLHU2oz38pqUaKc9BsuE0r0xsiTFc8u
         smvPL0lIBMaTF2DeF+sNjj3sQF5DC6FGb7j39xVL3jQxzGcAPMx4cEgO6aJUxVEZEwOx
         YSo+1ZWtI8Hgjn2M1GktuSgswaOiUMAY1jd+XgMbirrY/e38K/oVYF8wDeKK6W8Gdx0f
         3/GfQA6ShZ7Xm3v0MHyIGz6fuwp4WKw7YB4T32Qz/OCB8zB9b9iMGMaCvnfv9TJ2UTh6
         WbYAZWutwubaYL+C6+IkYXZS4p/GDkggsm1QARZX7pWhBwskrCKxsu24K4E984vJK2um
         Kn+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qC53rMZYYteHiiXzzCWwvcODZsX0JiY8iygwGWXmm8Y=;
        b=tZ92Q0Lb/GJSWo2odHDejjbv0ri5Avw1brrbPDYKE+g9PiVeQPs6ldP9rUx+xXdDgf
         steoJYrScHxNcHTbYBmuIxS31tTiOP0q3U/F7Orq+GKLjA1iErjQC13/gvzgpIh1HDYk
         npkeaQsjwq/OyI6hsY3BsR4m0UqL0/rRl1NLmjLQyojrcZNnRW3A32qUNecRi7Hgh096
         Xl6BwzKP91iGsHlU7c+tx6onI8c3aroZgDvhfOdYmSMaOI/8DgfHMGKttskM5LsWeiw4
         ioOZa+3MDdaMl3twW+DYNtR57XVu69SO5F0QodHF3GIi0NErxfV6r1eVPQ1I7rr+mZKe
         t8Bg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5332VcLAkHsvaEn/QAvJbAcVCERQToIx7pn36hHQ5TWzDZSWIlbJ
	o5tY+p2dRbhBmy9m4wxkITo=
X-Google-Smtp-Source: ABdhPJwiL48OleN7Rxd749Z0u/w/IkDSUNGj1k+qSeIBAXyTqxEW5bLLy2gWUdYljCaSNfOuX3uXCg==
X-Received: by 2002:a63:574b:: with SMTP id h11mr8399437pgm.25.1612600572895;
        Sat, 06 Feb 2021 00:36:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ba17:: with SMTP id s23ls5669708pjr.3.canary-gmail;
 Sat, 06 Feb 2021 00:36:12 -0800 (PST)
X-Received: by 2002:a17:90a:b782:: with SMTP id m2mr7731180pjr.220.1612600572089;
        Sat, 06 Feb 2021 00:36:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612600572; cv=none;
        d=google.com; s=arc-20160816;
        b=byPKS4nWPFa7i5rvgLNxv6R28gVRmteXkcazIB/3DNKF3f7c7pN/dyt4l0bj6XzuGh
         StIgwNDRUIUw54L64coLPbI3ZOKGPQ0VldHt92VbP1QCwvx9I8+X0BgUuZP5LhQYKCZh
         UnfP8e5zPru/PARb2849Nyj1zl8At87WyEIzi9R5kF5glPlDDtr4B9hzh8IQ1KCYhngK
         Dt+OELtZrcPFjM6JCxCLXqGjjnLqL152fUENdLR7wDSiyjoNBF1KCbLIO3BXQAGU2QLg
         +Fox6ib+Y/hzwnuIrg2b/mVRvGx4Ir0hnT4uxfViKZAxyWsZ9Sub6rQNGVsiGwXuV76R
         zG1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=pv43k7B7fJYItvQYP6dThYrT/X9kK10+dtawSE7VVPA=;
        b=DnYRuiG6YeFICJXzEoVXQhM4oAdD23Iar09MfGAQ2AsVVfM9HoxravCbAexbnR+w3g
         ivNoEcVBdrT2rgYGfsdtJMyuZ310W2rhlc7wyKNPL+sdSDLiSMFNTVy9ACQPQZ25nFmb
         06kcwBnSJw3EsUpcY52PXG9yvEr88MWvRy3ZIImISA69UOQzCBIuZKnhI+Dxf+q0bQEF
         f6H2bnWqU43p84bcLc47NUruIL1DD00GhPDXFy2gRkJ6VhxFVe83ll6ikFtuAOjy4cP3
         wRmXtAxoDHrWXZ49Hkiv8ePHa2vCANh5MxquVyIaYPeIMVAGovLxsDG1/m8ZAdN00sCA
         CPNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id j11si802088pgm.4.2021.02.06.00.36.11
        for <kasan-dev@googlegroups.com>;
        Sat, 06 Feb 2021 00:36:12 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 2ba3e05eeb4643df8f94e133f6404c3d-20210206
X-UUID: 2ba3e05eeb4643df8f94e133f6404c3d-20210206
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 103197405; Sat, 06 Feb 2021 16:36:08 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sat, 6 Feb 2021 16:36:06 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sat, 6 Feb 2021 16:36:06 +0800
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
Subject: [PATCH v3 2/5] arm64: kasan: abstract _text and _end to KERNEL_START/END
Date: Sat, 6 Feb 2021 16:35:49 +0800
Message-ID: <20210206083552.24394-3-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210206083552.24394-1-lecopzer.chen@mediatek.com>
References: <20210206083552.24394-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: CF0202CE0B8FA8FEB182A1174645C4228FB0989FBF8CEF182189BA36F623AC222000:8
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

Arm64 provides defined macro for KERNEL_START and KERNEL_END,
thus replace them by the abstration instead of using _text and _end.

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 arch/arm64/mm/kasan_init.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index 20d06008785f..cd2653b7b174 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -218,8 +218,8 @@ static void __init kasan_init_shadow(void)
 	phys_addr_t pa_start, pa_end;
 	u64 i;
 
-	kimg_shadow_start = (u64)kasan_mem_to_shadow(_text) & PAGE_MASK;
-	kimg_shadow_end = PAGE_ALIGN((u64)kasan_mem_to_shadow(_end));
+	kimg_shadow_start = (u64)kasan_mem_to_shadow(KERNEL_START) & PAGE_MASK;
+	kimg_shadow_end = PAGE_ALIGN((u64)kasan_mem_to_shadow(KERNEL_END));
 
 	mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
 	mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);
@@ -240,7 +240,7 @@ static void __init kasan_init_shadow(void)
 	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
 
 	kasan_map_populate(kimg_shadow_start, kimg_shadow_end,
-			   early_pfn_to_nid(virt_to_pfn(lm_alias(_text))));
+			   early_pfn_to_nid(virt_to_pfn(lm_alias(KERNEL_START))));
 
 	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)PAGE_END),
 				   (void *)mod_shadow_start);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210206083552.24394-3-lecopzer.chen%40mediatek.com.
