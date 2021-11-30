Return-Path: <kasan-dev+bncBAABBLNVTKGQMGQEJBVFYLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 64DA546406E
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 22:42:06 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id b142-20020a1c8094000000b0033f27b76819sf8251872wmd.4
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 13:42:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638308526; cv=pass;
        d=google.com; s=arc-20160816;
        b=HoWljRzyfLnjWmG9nXxjwC8BFAYMCJMX5H3MnVHFQcZ4zpU84/KcC8g3TttOtNKxf2
         tn6+RbYk/5VUUs+2d2xOv+m45cQi72Bi+NAxRFu3jNRorF7Dscp9HQmb3D/r9d8ma7t0
         ZbGUbnvKEB90ch3Thykdc7SKJa/W4LlXwVf2bDu3MRCERHc7zg58gr22H6pXMJsoANdr
         2jp8IsYAncItvl9hkoifROeb7jXwI9UFlhk+R7NcgAFyj+VENVOM40EwtTJVXalUvTKx
         Z3VFhGSHNHRlzJQtils4bbeRltkfW+zoriDGIRZ29/19uqpuiQL3dbzfz3B+FGfvrdo+
         jhEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wILLjCI54j03kaQ5I+2ih0fxQQn/m6zE4C/4VOj7XOI=;
        b=m6A0ee2fVr9xymgB7dG2sT9mWkVmm1amP+W8DEADZnaYuaMr9NutGdx2pDNZgLVGda
         Bd/+yDuVtaQ+ydO2JtdepQxYbfPuJwIRQwOS3MbOFYu8ZNcrKALMajAHsJ1SAzcZkuFs
         YXM0dNBGpslAVLNH2q3egfyXVuBIw3NuwTl5HzHZUTWdotpctk0fv84Zyce6IUq0vLaj
         20jqcLYiacVSZAwHPilY2aVouXWYCIt8a1HXU4epMVEjU9ZLQ0w1WoGst1lAIFavtjjS
         njd7A9WkV+QGePG1WkjlmRYc7tTKV88DpeYIZf+yHo2MPkgDUWPd5TUio/mjgNRIN/TU
         CSew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rwcQF6Q0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wILLjCI54j03kaQ5I+2ih0fxQQn/m6zE4C/4VOj7XOI=;
        b=p5WM0v5rCZ6pukQKq+bHzz3wTaTrISV3iyTXIHXLU2OST0m4swSjlwyr5Sdd68ltl1
         7Wwt3oGl5piSOed8Z7URYhTmaoNMHRTjkdH+JfwKIAgX4ImgXbXcpNw9XXTfiyOk7FY6
         +rA2/G6hWUnUGgXRNhW5mgtDJXA8m/tJwbemsd0Ekm00Ihd7Kv3HWpMP9JoyyxNO481c
         8pzcILSoKg0Pz2btbm8vVS1QQ+jocRuyzlSa/xUJ/2iilRVqS/N1kiCArITp/bQF9qxb
         nanNG6ajnHX6KS10nWdu2EZ+C3TohSPexUm3zr6l0fpvWth1bisTaAUMU197TlNSF1XJ
         7AIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wILLjCI54j03kaQ5I+2ih0fxQQn/m6zE4C/4VOj7XOI=;
        b=p3A6nH5fTD+1uYID3GRa3ZG/sCaWJZyxQ197uThpyoleh+YQCAAmebFNVsMzcK/oD7
         tDKNK7FHYjgKNubFiQdI9GvilNZxmTba70zWkbKR/DMU6yBn1JxDtgPCFFoWZMeXrDeL
         dRHrZIg/AvZEo7FhU/nfldQhwOIPudvV5gv8rzL7haLTQKZtbk+Uk+W5dv5W1lYv2MkZ
         weKBd5paTb+2NcJd6qTJUIeDQqLR3CHO4cyneplNKzUu9q2W9VtmnqWJ+PesOKV2Ipyp
         U4/aQdNijnMPHLSVqaoGIi78FDgAYJXzBcni6YRzynkregqB1ez53mvoqx1t/W1+2tc2
         Pm4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532+l0mphGv4Oc6+FZUn18wHYlovq7g+BJXJfWAJt2+gNgfWlkt1
	wmw/eFy/+OtWyaWF08zQ+VU=
X-Google-Smtp-Source: ABdhPJwdRpFFAtgc1XluWvC79jtrkc2gTg1Pu3w6ByJXkpCAWYU/k35bXUclqI8yV/W+bpawuFt2Wg==
X-Received: by 2002:a1c:4b07:: with SMTP id y7mr1588322wma.188.1638308526144;
        Tue, 30 Nov 2021 13:42:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls127199wrp.1.gmail; Tue, 30 Nov
 2021 13:42:05 -0800 (PST)
X-Received: by 2002:a5d:54c6:: with SMTP id x6mr1766997wrv.513.1638308525584;
        Tue, 30 Nov 2021 13:42:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638308525; cv=none;
        d=google.com; s=arc-20160816;
        b=nY9QH1IJZFuXcFbZ9Bg/Q4R3FjLPq2CP505g8sX270bzvncgh2kIIPVX8o+6oBxRGD
         TXMDctt1shrw4NYywXUwNfGCmhCFytoxnSHZyCD+SdhEXgnlQr1eLzppqLy1DnEFEzRj
         p11SoHeCiXSOLBQIkcYajrtWu3TUCkd0Xa+R+e+7bEiiyR4bDD9r95VioOW+o+O4VcTz
         qvT5QMI36F7r47+Ajem/QLUL2AXV1wRWSGFCt+riqXPnY1qBcqmbgWPPaiWvkr7TUOzp
         PtCO8X2GKP4zwCJ943ShccAaViAfAZZFpTRme2Ik0PIc8uv9Yq2TUwSkuYJr3KEUZO16
         L9pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=098zVxilZL3/80DAvLC4qpo6yXA1SYFMfUJP4UlD304=;
        b=xpFI2q0cc4wxgqNSlEwzDGp5gQ0F/Nkdn1p5zL4R4/x0wrxXWUvG649/bHZomYWy7P
         I3qjN16AQHnyFQ2yjyBr1jPk8YnH0hkEXmGHkqbiVWp9iG3srtpNXBfU5DZT3M3AxrsS
         0Mfk84WeT76JvauaPU8vczRMEeP8SVjHYVq8dX6TeFr+FKdy03ObP/TZqdOTtGSPITev
         Dn3ZFPNMd9kbVGngMrHpoCwlFILEjTQqugnLeK85OIAXYL+h7QmacjISQP3EbuhLGWjY
         ZDo5b4F1z1YE8Y9uaIetxr4vjm4j46uV3B2Xh/5GVZylTSeL7EonGv5GclrjdOipcVat
         8aMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rwcQF6Q0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id x20si887845wrg.3.2021.11.30.13.42.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 13:42:05 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
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
Subject: [PATCH 09/31] kasan, page_alloc: merge kasan_alloc_pages into post_alloc_hook
Date: Tue, 30 Nov 2021 22:42:03 +0100
Message-Id: <3025e0e482b3e4a213529811e5d4e2861acdba6e.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=rwcQF6Q0;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Currently, the code responsible for initializing and poisoning memory in
post_alloc_hook() is scattered across two locations: kasan_alloc_pages()
hook for HW_TAGS KASAN and post_alloc_hook() itself. This is confusing.

This and a few following patches combine the code from these two
locations. Along the way, these patches do a step-by-step restructure
the many performed checks to make them easier to follow.

This patch replaces the only caller of kasan_alloc_pages() with its
implementation.

As kasan_has_integrated_init() is only true when CONFIG_KASAN_HW_TAGS
is enabled, moving the code does no functional changes.

The patch also moves init and init_tags variables definitions out of
kasan_has_integrated_init() clause in post_alloc_hook(), as they have
the same values regardless of what the if condition evaluates to.

This patch is not useful by itself but makes the simplifications in
the following patches easier to follow.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h |  9 ---------
 mm/kasan/common.c     |  2 +-
 mm/kasan/hw_tags.c    | 22 ----------------------
 mm/page_alloc.c       | 20 +++++++++++++++-----
 4 files changed, 16 insertions(+), 37 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 89a43d8ae4fe..1031070be3f3 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -94,8 +94,6 @@ static inline bool kasan_hw_tags_enabled(void)
 	return kasan_enabled();
 }
 
-void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags);
-
 #else /* CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_enabled(void)
@@ -108,13 +106,6 @@ static inline bool kasan_hw_tags_enabled(void)
 	return false;
 }
 
-static __always_inline void kasan_alloc_pages(struct page *page,
-					      unsigned int order, gfp_t flags)
-{
-	/* Only available for integrated init. */
-	BUILD_BUG();
-}
-
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_has_integrated_init(void)
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 66078cc1b4f0..d7168bfca61a 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -536,7 +536,7 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 		return NULL;
 
 	/*
-	 * The object has already been unpoisoned by kasan_alloc_pages() for
+	 * The object has already been unpoisoned by kasan_unpoison_pages() for
 	 * alloc_pages() or by kasan_krealloc() for krealloc().
 	 */
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index c643740b8599..76cf2b6229c7 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -192,28 +192,6 @@ void __init kasan_init_hw_tags(void)
 		kasan_stack_collection_enabled() ? "on" : "off");
 }
 
-void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
-{
-	/*
-	 * This condition should match the one in post_alloc_hook() in
-	 * page_alloc.c.
-	 */
-	bool init = !want_init_on_free() && want_init_on_alloc(flags);
-	bool init_tags = init && (flags & __GFP_ZEROTAGS);
-
-	if (flags & __GFP_SKIP_KASAN_POISON)
-		SetPageSkipKASanPoison(page);
-
-	if (init_tags) {
-		int i;
-
-		for (i = 0; i != 1 << order; ++i)
-			tag_clear_highpage(page + i);
-	} else {
-		kasan_unpoison_pages(page, order, init);
-	}
-}
-
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 void kasan_enable_tagging_sync(void)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 0561cdafce36..2a85aeb45ec1 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2384,6 +2384,9 @@ static bool check_new_pages(struct page *page, unsigned int order)
 inline void post_alloc_hook(struct page *page, unsigned int order,
 				gfp_t gfp_flags)
 {
+	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
+	bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
+
 	set_page_private(page, 0);
 	set_page_refcounted(page);
 
@@ -2399,15 +2402,22 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 
 	/*
 	 * As memory initialization might be integrated into KASAN,
-	 * kasan_alloc_pages and kernel_init_free_pages must be
+	 * KASAN unpoisoning and memory initializion code must be
 	 * kept together to avoid discrepancies in behavior.
 	 */
 	if (kasan_has_integrated_init()) {
-		kasan_alloc_pages(page, order, gfp_flags);
-	} else {
-		bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
-		bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
+		if (gfp_flags & __GFP_SKIP_KASAN_POISON)
+			SetPageSkipKASanPoison(page);
+
+		if (init_tags) {
+			int i;
 
+			for (i = 0; i != 1 << order; ++i)
+				tag_clear_highpage(page + i);
+		} else {
+			kasan_unpoison_pages(page, order, init);
+		}
+	} else {
 		kasan_unpoison_pages(page, order, init);
 
 		if (init_tags) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3025e0e482b3e4a213529811e5d4e2861acdba6e.1638308023.git.andreyknvl%40google.com.
