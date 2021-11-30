Return-Path: <kasan-dev+bncBAABBS6BTKGQMGQE4K6LPDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 96980464104
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:08:11 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id v1-20020aa7cd41000000b003e80973378asf18182489edw.14
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:08:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638310091; cv=pass;
        d=google.com; s=arc-20160816;
        b=0wUDGEwgNeqrBp84SI/XWl/qMviy1c/MF/6iccLxrASgMOignHEQv6o4bmKx/snzDK
         DuhX0PTCUm8gHcP0GsvxS4uQ5Wl59jwa1gT695VLz3xw21iawsuh34D3vahNXlEfPudA
         rByHyBMrMRHlPxwcMLkTXFmj6mlp7wtSQuJj/B0Qcz0pMe73p7DTDxlJTL5rfm/p8u9b
         q503beY2ZnrOtiAnVS18VjAkXmdTaxKcm+NMQMGlBRfDb0jACn1aMXwAewbdOtFBbfIM
         Kc8kTIvcxsc8DPW1NOFOoHdxXDIGLpUh6/6zjao6zjeu9s+B4biC67iaR4ysMxMkSgSO
         VCBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QROIooCG5A7iQKDso/g4R39FlQjsnmwPPEBS8RtYbFc=;
        b=upIFTNwgvT9fUXOm1nv3cS/YwpjafbIvXGucuImSvPDj4w0pYuc+x14ZYY8z2bCmLu
         8Fs4G/cr+gR1+eblQZnsvq0mWQV9agXLXWMm/qyTuIW/CshVu4lED9zVxprU5Bn8hCg6
         kpu/adJCEe/4VI7FWtLbGYWpQgKnLQlCkz+X1iH/Fs3MGUVxeTm3t4tfB+SFTpNTU9if
         J+aHRva7OHm8Y3YXj9Ks26OAlVcaCMkpG4qgXeSG8cdFpxgjwLsY7GjE2FvjCY64/G25
         17TSEx6v3TdiNDeIf3SHzehX4WM/64xXcMe2ae+YLqHQ8IklF9Cc7Bm/dUmfGEPO0raT
         cqJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Z4Yuz3BR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QROIooCG5A7iQKDso/g4R39FlQjsnmwPPEBS8RtYbFc=;
        b=Dc6TU77ZtxmDqscPt7FFUgkO0q9XHOLNuYNq3SzHYBW2VGDdIFkb/boTunAvXO4v8Z
         TsL63WvsoBOXNvwWKWctDwo+GBSsyqJJL+8vuaIEPhCR07ppqUzlJs8QoOneUgFw+4gw
         gSqQQujkG3oIgJ89AdVKAvGHLQVoBSyfYYaoz9FT+28+85qeJiZdoB5axoNzWuGxIbyF
         yg+4LMWDO8FxKtRZbhZy31Ws6FmUZYe3VarNQYHVLZiO7YSys8GrcxrLspL2MTy0A7RS
         W0BsTaGqzIOA8TZWMvxv0/HLziw0i4xJjkC9/KeknNaJ7oLMwfE35UXnm97Xjv8CQUEB
         cE5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QROIooCG5A7iQKDso/g4R39FlQjsnmwPPEBS8RtYbFc=;
        b=gqJLffmbKG1A32X6qcMBlQ6nfZzyS1f6Z4BfpE09OHFQmuGLTlMPbAzuTi3z0lk7j5
         ABP3nMo/MMbgkACpe0Qj3jvs7swF2BjSi9IDiEFMoQhGcTZCkx0Jk2+e+9Z0Yh+5kkdu
         9UUocglwx2K5Al7Fr/x0LWYV/P/D2lilemZ9WC1H4Gv3OMGL3J40FxhOeF85S5i+aENW
         I56hF14cxx7ng9kd3bo+aF2815rtmswxR5/VcOJDqk6gIKHB1S5M7SWGrF2efmjsqW3f
         s8IqiaJCfWQaYtBLp3uifpNV/iJFk4frT5WFFw4qXOieg8QwwC9dYbZ1Dja3f8XSyn8t
         zMoQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531EYpqzgRSQjuSIHx6uMkiQ11FqVEUSZtpL1SQilKi6aK1Kx074
	aeTQ1guEK5JHPSqN8rggK84=
X-Google-Smtp-Source: ABdhPJzA5SExcxOTniwTC167vZPzgdc5s9UJ4FXsPYmCGSIrC5Vyj8QRnGB9291VYiTNGfxJu4lCRw==
X-Received: by 2002:a17:907:2622:: with SMTP id aq2mr2183331ejc.76.1638310091399;
        Tue, 30 Nov 2021 14:08:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:6da0:: with SMTP id sb32ls31648ejc.8.gmail; Tue, 30
 Nov 2021 14:08:10 -0800 (PST)
X-Received: by 2002:a17:907:7e8e:: with SMTP id qb14mr2075639ejc.562.1638310090708;
        Tue, 30 Nov 2021 14:08:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638310090; cv=none;
        d=google.com; s=arc-20160816;
        b=l7mSuGhVefrBKkaCfmP7EZas/3UlPq/DFAGH/OwON2i4ICaoML3MrSay+N/GrM6LH1
         tBLCQuOeV24cubNpisNKZBGQhkU/8EIaNgXYTiMSev3x2FEUfYj70jC6EipjBKws7dVC
         JMjNEzgmwZezkypsyn+NHr44PreDnjgt86cln+/1oS9CdGiOxhj1QZZQ2uI//SHNoCtl
         eXM1Y6aniDfyDCOk6R4c2EB2Hlnci/4WmFVahqAlYEsIX8w09klgIFmKQnY82BP3c/dB
         73vqGrBnDw+jSCka5rp2VzizgYgc9vGKj+K0ZbxBOYukYGTpexJ9ystY5cSsE68SoSQA
         d6XQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/6qJwit6ITW8lPGUAdTPjRxCn0EQ40SKku7cvq8gPsA=;
        b=GdJdfZTBrKX1o+ctgcPAjErppVcWxmokH1S6zm7EnTiVAWF1C6Q/d7hUjcWBWgp7lr
         9furvYUPLbrq1O8RE9vZWf7seiM5GMVc6mV2iIByWztzauLDj/2FtztKEQ6s468yi0WN
         /LCUgEpRnhBSj57poo+m1JC2dyi/LHx8kACn4zLUCYD3QRJrtgSxPP7Ex8PN+56QhI+f
         ZqKLp89S05WSFR18td66PMpS+Vd3quG+Ir+DHdT6IU1xVmIvc/P0GN8kSsy+WURKqXE1
         7VzIejxcRO3cmqprYjgwG++xBBfM20sem1inQ8IaJldWJjkqWYcBugfQMpQx951CqVl3
         tGTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Z4Yuz3BR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id d5si1367294ede.2.2021.11.30.14.08.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:08:10 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 26/31] kasan, page_alloc: allow skipping unpoisoning for HW_TAGS
Date: Tue, 30 Nov 2021 23:08:08 +0100
Message-Id: <e60cbad6f4f8ee08137671c008c83ab26255e9bf.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Z4Yuz3BR;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

This patch add a new GFP flag __GFP_SKIP_KASAN_UNPOISON that allows
skipping KASAN poisoning for page_alloc allocations. The flag is only
effective with HW_TAGS KASAN.

This flag will be used by vmalloc code for page_alloc allocations
backing vmalloc() mappings in the following patch. The reason to skip
KASAN poisoning for these pages in page_alloc is because vmalloc code
will be poisoning them instead.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/gfp.h | 13 +++++++++----
 mm/page_alloc.c     | 24 +++++++++++++++++-------
 2 files changed, 26 insertions(+), 11 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index dddd7597689f..a4c8ff3fbed1 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -54,9 +54,10 @@ struct vm_area_struct;
 #define ___GFP_THISNODE		0x200000u
 #define ___GFP_ACCOUNT		0x400000u
 #define ___GFP_ZEROTAGS		0x800000u
-#define ___GFP_SKIP_KASAN_POISON	0x1000000u
+#define ___GFP_SKIP_KASAN_UNPOISON	0x1000000u
+#define ___GFP_SKIP_KASAN_POISON	0x2000000u
 #ifdef CONFIG_LOCKDEP
-#define ___GFP_NOLOCKDEP	0x2000000u
+#define ___GFP_NOLOCKDEP	0x4000000u
 #else
 #define ___GFP_NOLOCKDEP	0
 #endif
@@ -235,6 +236,9 @@ struct vm_area_struct;
  * %__GFP_ZEROTAGS zeroes memory tags at allocation time if the memory itself
  * is being zeroed (either via __GFP_ZERO or via init_on_alloc).
  *
+ * %__GFP_SKIP_KASAN_UNPOISON skips KASAN unpoisoning on page allocation.
+ * Currently only has an effect in HW tags mode.
+ *
  * %__GFP_SKIP_KASAN_POISON returns a page which does not need to be poisoned
  * on deallocation. Typically used for userspace pages. Currently only has an
  * effect in HW tags mode.
@@ -243,13 +247,14 @@ struct vm_area_struct;
 #define __GFP_COMP	((__force gfp_t)___GFP_COMP)
 #define __GFP_ZERO	((__force gfp_t)___GFP_ZERO)
 #define __GFP_ZEROTAGS	((__force gfp_t)___GFP_ZEROTAGS)
-#define __GFP_SKIP_KASAN_POISON	((__force gfp_t)___GFP_SKIP_KASAN_POISON)
+#define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPOISON)
+#define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POISON)
 
 /* Disable lockdep for GFP context tracking */
 #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
 
 /* Room for N __GFP_FOO bits */
-#define __GFP_BITS_SHIFT (25 + IS_ENABLED(CONFIG_LOCKDEP))
+#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
 
 /**
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 4eb341351124..3afebc037fcd 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2381,6 +2381,21 @@ static bool check_new_pages(struct page *page, unsigned int order)
 	return false;
 }
 
+static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
+{
+	/* Don't skip if a software KASAN mode is enabled. */
+	if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS))
+		return false;
+
+	/*
+	 * For hardware tag-based KASAN, skip if either:
+	 *
+	 * 1. Memory tags have already been cleared via tag_clear_highpage().
+	 * 2. Skipping has been requested via __GFP_SKIP_KASAN_UNPOISON.
+	 */
+	return init_tags || (flags & __GFP_SKIP_KASAN_UNPOISON);
+}
+
 inline void post_alloc_hook(struct page *page, unsigned int order,
 				gfp_t gfp_flags)
 {
@@ -2420,13 +2435,8 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		/* Note that memory is already initialized by the loop above. */
 		init = false;
 	}
-	/*
-	 * If either a software KASAN mode is enabled, or,
-	 * in the case of hardware tag-based KASAN,
-	 * if memory tags have not been cleared via tag_clear_highpage().
-	 */
-	if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS) || !init_tags) {
-		/* Mark shadow memory or set memory tags. */
+	if (!should_skip_kasan_unpoison(gfp_flags, init_tags)) {
+		/* Unpoison shadow memory or set memory tags. */
 		kasan_unpoison_pages(page, order, init);
 
 		/* Note that memory is already initialized by KASAN. */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e60cbad6f4f8ee08137671c008c83ab26255e9bf.1638308023.git.andreyknvl%40google.com.
