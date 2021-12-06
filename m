Return-Path: <kasan-dev+bncBAABBUEIXKGQMGQE7YGOOIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 919A246AAB0
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:44:48 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 144-20020a1c0496000000b003305ac0e03asf182545wme.8
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:44:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827088; cv=pass;
        d=google.com; s=arc-20160816;
        b=ux4JVmTKuwc9OiiguUXccU3+pJRmJtuvHxtJs0D+Xyg8Tj7BQD+KH0dlMva1jErL+T
         3WKFsrY5jjuM0ut5R3vJj5mk+0bLk/moRxKyK9GbD0E9RxLcZGtBONVtrmKlOmN8OpLh
         4vWj2e2ut/cg3Mstlgjj7zY2h1pLjmcu7ctj6Aqtn0R4h6e7TM2hv7DWdskhejRXvTZm
         Es4vxlAFIZ30bRHGiS7IkyMi74J27riEjc5tNpG7GUmCI+4ZCcZ9++R8rHMS2aguf/iF
         MTv9GPuXSELi7dko/3rvb/7THqsFCNIwGxk0VxRn3VLEB7iTsiePwSwHJ94u0jecsCY9
         VyIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Z+HVoz3XqxlzOQtsf//s1O2ZqrSyFb593/F6+GOT1L0=;
        b=XS4/0lhxIIEAcCzT0pLuhyDE24iEBqxZtZ19Ql9z90HujumLfP7mV3+TtmstU0o5Ei
         reJt6ES+0nJtSJwL0d+/AtJaXXfoLKPGkNa84fMC7qjkeujOgii6H42xBtess7DVFemM
         m2ZkxkCyP1VK49QOxXpsujGcvE4COLPlhv84NhBA9NBAaqzG9maDy0SNtUnxB9kHJvbx
         l8qhFTAWOLXQfgyOSgq8LxlAXgr207wW/IJM1D0TPEepC7WN6Sc4L5UwYS++r5dP3a36
         5fKxCN0E7s/cS8t8RdcXoYLSMIyrlmxFPpN2sfLVaTJqfC6fTsiLRmS0A9OnApzC3uhw
         wXGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JcidHI7f;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z+HVoz3XqxlzOQtsf//s1O2ZqrSyFb593/F6+GOT1L0=;
        b=M3HAkiF7GGRkSKtffC0OaHF0VYI0kjfwc+4Ysw9fsGg/qg2Ibn1H3YzH5idRY0/VnG
         rQAq1w1zGIssavoIj7vDlc0NGnT5ZZuoSK/Lz20ZWgtiSxUpYEAIwOSTM12zu3upm2vm
         Tx8zehCvsxwy72RIUDRSd33YqQMOLj5iXMmP9hu9Boy6WOs/4rDBblCHiEFyP0mIJwmg
         jHtFnNIP8uCid4VajUmUbckCRUHa76h3keys/M0vnm2cuOiku26icaqfrGZMgHutT94v
         klzLtJHuwYcW11rFxsEK4yUPmVfYfy6xl9n4ZFJOWk2lSDQ4UNFB7SFQ0Mhr5ynojxfI
         cN1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z+HVoz3XqxlzOQtsf//s1O2ZqrSyFb593/F6+GOT1L0=;
        b=3ipQakTTXKqen6vGvKCwDkLGtdz86mqKFWvUjkig4sQ3370O2U5WlUNlm5gYCRTiv0
         8BssFx22WfbGBfQEzGePhX+jsTy94CHouAnG/sSiXyBrgv+47t+GMsdb69jTfjuatExW
         VCSDgfV0HRvD/jg7m1SL4/3powbd2nk2dTp4WBPQEMnwhvT5hhswJoYGqugyaRjcBS1Q
         INMZHYM3JibFW7uNm2K6Wqa8gwxLfzdFeoc8L+6m+Kwqg5G4k1cvpAwDViBD7RUcYEeW
         IGcDaIPp00oxro7tsEO0rGOYiirKu8swq5KujrJDFhnGXKHtjLcskA1F1mKQ7o3Yn5gV
         WZFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530pWigWGjm7koAeXIXgNkvS60KCtnEgEXtOIKz+1zvVQJRiMt9z
	3jAgDRv0yMbIRUX/F+R0iLk=
X-Google-Smtp-Source: ABdhPJxW0LWkBjJwRpnBZ2sg3oR3Mj33svhMCNYL6jj6v2hKBXLGj7BLL/5l+boO+H5bxJxsavTtEQ==
X-Received: by 2002:a05:600c:1d06:: with SMTP id l6mr1448781wms.97.1638827088309;
        Mon, 06 Dec 2021 13:44:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:770f:: with SMTP id t15ls222452wmi.3.gmail; Mon, 06 Dec
 2021 13:44:47 -0800 (PST)
X-Received: by 2002:a05:600c:a49:: with SMTP id c9mr1518971wmq.172.1638827087628;
        Mon, 06 Dec 2021 13:44:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827087; cv=none;
        d=google.com; s=arc-20160816;
        b=nROl5o9KY6O15QU7pJ4hT1dBMNRBxPTK3AVYZKap4erlSAGCygXHKJOGYgKMisbGaG
         jHddwE71kpgnnOH+gRJJzDGrMLH4txc218932PSrAI6tA3wnIHWs/XcxVclBLC6mwbTS
         fHs3QZRIfqBwNL2C9votr8GdRWYTXf2ArCbv/2Qf+oFpWyUCfgOR1zHkPVsQZu+GB9qM
         UPp/6usGcBU9Z0ZQ6d7ugbAq6RC/axxK/6S9Sc+bPFicuXDcBD0viyulBlpBqV37/TC3
         aDkxAGdBdb06zCnQ8nN1C7brh5pDrdeJaLtQvXi+u3BoZOrs2q0laH5V573npaFYMxCT
         C2Qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=l+PTHzJSTVa8536ReyOZGg3sJjywrvvVxDxQcr48qWw=;
        b=GOPypQSQHE5JiDbRn7UIf6GISbvcC0/aYWSaob+PzJ2CROsGWqAO9icBaAtpWMaGFy
         kF5pLVbV9N9gxvehmQ6TWc+5LHPUV+trn4s7ysCan5ZfobHnWX7zRmmsbAo2HgVVcId6
         gMGD6xfIaWqLumpxqusPmiaZb1+pwlVqYBeo/KJ8yNEa6uvF5cIBbyE0nXvYyhZ7PFIY
         Eh7YIXdF0qdL03rukj/7CvkehNuA0DEi1JNmh4FVao/YlKYZQLkyYBooQan570sGdxrW
         P2B19z/6jCescEdvNTwXxhe4UVVlbNbSCaUTGMO16Hbqjwgjg9uMvCN+4YH9x+sVb6Jl
         0HrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JcidHI7f;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id s138si80241wme.1.2021.12.06.13.44.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:44:47 -0800 (PST)
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
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 10/34] kasan, page_alloc: merge kasan_alloc_pages into post_alloc_hook
Date: Mon,  6 Dec 2021 22:43:47 +0100
Message-Id: <76981f93389088cc08d90801a9754346894bb3b9.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=JcidHI7f;       spf=pass
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
index 507004a54f2f..d33e0b0547be 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2383,6 +2383,9 @@ static bool check_new_pages(struct page *page, unsigned int order)
 inline void post_alloc_hook(struct page *page, unsigned int order,
 				gfp_t gfp_flags)
 {
+	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
+	bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
+
 	set_page_private(page, 0);
 	set_page_refcounted(page);
 
@@ -2398,15 +2401,22 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/76981f93389088cc08d90801a9754346894bb3b9.1638825394.git.andreyknvl%40google.com.
