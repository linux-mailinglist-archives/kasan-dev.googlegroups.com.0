Return-Path: <kasan-dev+bncBAABBW5UTKGQMGQEI2RU6YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id A4DBD464060
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 22:40:43 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id k25-20020a05600c1c9900b00332f798ba1dsf14498771wms.4
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 13:40:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638308443; cv=pass;
        d=google.com; s=arc-20160816;
        b=oq4GoWZ8i+uZ94BGPE2b6mfrayBKstXDBHr/vAcX64pxyIjnZx3lPIjet2449eiI+6
         1hrbPIzKG4gpFw+wll78RWpe42pffG40A1AZJCrwLbfXVPOHIiaKVJAxPWnTMH5Bp3rg
         2zQJNNWPttLjjY0L8WvEpaYj0nkjDH0SUPHA90lLZbUdULOOtMH8yK9eozer0oSWKDYl
         tP5tvoUBpXzqPpY0OxQ226C8ADq3CTzmQrZ/b4mDr30mqxZcoHdG7YmArugDh7mtQf3d
         BCbwjyAB+p5x8ImCdZnRK5UBaTolOiwhZIr1kHQBv6m4p7TNgx3JueuA8nFq1N2JkpO5
         bolQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IVcFENP/Bxgn+aRjMk6WGbdWD75ILKIHajAnGNhsy7c=;
        b=DNV7VnaUTpGLuUljYbjS1aaEx2dAfOa6GqmGjbxHB50KllZdJTBf3OtD7zGeylZkYJ
         hegiuwdI0U7eFbtpvJufIWk7TJI1DoGqZrnj1bal6/xtSpAKHSwDUoLiFieQlyZBaIAj
         ea7SlHvo6TS6bGmFAe/zynmyTEzFRGeNiFRw8Ztz45MJ+8b+/A0pFklTnc8eSLJCRml8
         0PVI7sziTVOeo8jK4ODl9lInhSoDmOevt1vFht+uMvY2vmOyQ9Yw+cIWeS8pcEYNqvA2
         mC829ug0yWOwUwXPbvPNSRf5I+lmOQZfNbEW+Je1zTxLuKc92ZpS2ZYubsAf1+HG3HmV
         HDpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IVcFENP/Bxgn+aRjMk6WGbdWD75ILKIHajAnGNhsy7c=;
        b=SLrLMixozhk/X2TyT2hVtdA0x2Ek7/Rzoa5Ui2qVURrW0TIRwxgiXpIxSgStNFXrYp
         EKuah4q2WLvK6Cpld+fSyowo4vIh6yFS47cmxM6xLW5DHK3GV469H1cIhMUzf4MAzE7H
         5uvGn+R7JTPOOf/MzletNlaXeTJazgQCrVFfX9+k1roKHd7QA5+4LDi6ox0l/nV4c+4T
         1pLdMeTmFw3xHwL5/xOS3MrBG7Nc6+NAnvYf/s4sVQjakfbdKipHNzzRMjxymU3awOY/
         4dRdfa07eWNpHrR3ZQOp38HcgigqxDanh5nT9sTV7bhU4bx+U0tX07w5Fltp51H/qokI
         WJIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IVcFENP/Bxgn+aRjMk6WGbdWD75ILKIHajAnGNhsy7c=;
        b=e68/onYJa4CXzGF0IFxLF3eUQLkT9UWLfPoUxkxR18CvP+qUwpAoLsy+bpAPHKGFeT
         fnuuwRE7JaUSLpkJdwdwvYrSkDOY7gP0T6LTQEbDWmUo6PzmjwNzQ8OpgWBQ0V6q109t
         727Q9LxCChJpAH1zKbnEKAvL5ftL3eXl7jjV6yCVIIvZYUI2cj297FO7ZVPN01Sjg37o
         6GDw97qrf9ZbHcFfdZDgKuMXKZhOdRwqb8S5lXTNxyGTpqeDOFuR7P2pfELDzRQwWlJj
         9Q86wAEsu3lipSh8XLWBsy9Z4F7Tic78HSZGECyRugF0+/LooDayvnPXt6K7rQ2/mU2Y
         UXlw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Nllfs3KLlFaxbLIjKVecQib3uhMgDY047kN5u3r8a7yEakv8E
	Yqj049QBHJasePSqEczJh5Y=
X-Google-Smtp-Source: ABdhPJyxVnONGlDfohAXg0oSZmr7UJFM3HPooQ+VqtJ+VWCZOyXbVUb1s8GtKbeK7fXlrW3n4JxpqA==
X-Received: by 2002:a1c:183:: with SMTP id 125mr1714116wmb.0.1638308443476;
        Tue, 30 Nov 2021 13:40:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls128065wrr.0.gmail; Tue, 30 Nov
 2021 13:40:42 -0800 (PST)
X-Received: by 2002:a5d:5984:: with SMTP id n4mr1744285wri.23.1638308442765;
        Tue, 30 Nov 2021 13:40:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638308442; cv=none;
        d=google.com; s=arc-20160816;
        b=h4DS0/8XXjQObmjTEoNVikOM9mTuQaN/R2sIiUHUEUKztvNKf1XWsP/FQKoH6v+aHS
         RTFt5kLsPkjMnDZRjNiumKNAQNbEuRa4wdSsd49JY1ysqmcwXPjaFsmFkohwFeTs+pns
         PYD/GTlEqAN/lzc/HX4ZNiUXkSOIpSkl4xKRPOgqHChd7u0q48/uof97jkjxFDHW041g
         R53HQ890DxufnMqdt3hDBfUunw2xrQeqkmIYqrzgU0QHKvTZMO21ijPoimjhAT6tGv67
         pFGQ7s80XF6/PCVgXhs64yc3RM+17iv00HPUpzpZLPtE81dAOQNYEkttUHKqPDpcvDu6
         rFBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=/mJDmmnXol/HS2QhrHN5/6xnbpfL2rFkap0DEKY0IOo=;
        b=qQbq9goN7Kg977zGi2WNx28GGScmBynIhrj75KCZfVlbTcEA7kiBT99ifljRT/OU1J
         DnYvcjhtXhiwF/b2bY8LgRYKhUha7PBoNjSpDB5kSTpzbpLBR1QsKOpqlpELhl2hN4mF
         0cA6GGe00ptYi3OlGtcLyRqNa5fWwl82OCx0FlN4lby7KiDPqKyJMTIYZqYRFsycAQTR
         Vcq7YS1lnV2pcm8b3MjZEoYDtRdgZDx9xKugMY2hxnYP6pWZLWubRwYBLlFCPR+NYmAd
         ScXEuiiZOpyZ+XEKZW2MUzSUIU1XBIhkzHqxHPHIb19stzye6naac6Pm8NKI1kxqX79T
         2GNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id r6si1218215wrj.2.2021.11.30.13.40.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 13:40:42 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
Subject: [PATCH 03/31] kasan, page_alloc: merge kasan_free_pages into free_pages_prepare
Date: Tue, 30 Nov 2021 22:39:09 +0100
Message-Id: <64f8b74a4766f886a6df77438e7e098205fd0863.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
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

Currently, the code responsible for initializing and poisoning memory
in free_pages_prepare() is scattered across two locations:
kasan_free_pages() for HW_TAGS KASAN and free_pages_prepare() itself.
This is confusing.

This and a few following patches combine the code from these two
locations. Along the way, these patches also simplify the performed
checks to make them easier to follow.

This patch replaces the only caller of kasan_free_pages() with its
implementation.

As kasan_has_integrated_init() is only true when CONFIG_KASAN_HW_TAGS
is enabled, moving the code does no functional changes.

This patch is not useful by itself but makes the simplifications in
the following patches easier to follow.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h |  8 --------
 mm/kasan/common.c     |  2 +-
 mm/kasan/hw_tags.c    | 11 -----------
 mm/page_alloc.c       |  6 ++++--
 4 files changed, 5 insertions(+), 22 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d8783b682669..89a43d8ae4fe 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -95,7 +95,6 @@ static inline bool kasan_hw_tags_enabled(void)
 }
 
 void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags);
-void kasan_free_pages(struct page *page, unsigned int order);
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
@@ -116,13 +115,6 @@ static __always_inline void kasan_alloc_pages(struct page *page,
 	BUILD_BUG();
 }
 
-static __always_inline void kasan_free_pages(struct page *page,
-					     unsigned int order)
-{
-	/* Only available for integrated init. */
-	BUILD_BUG();
-}
-
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_has_integrated_init(void)
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 8428da2aaf17..66078cc1b4f0 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -387,7 +387,7 @@ static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
 	}
 
 	/*
-	 * The object will be poisoned by kasan_free_pages() or
+	 * The object will be poisoned by kasan_poison_pages() or
 	 * kasan_slab_free_mempool().
 	 */
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 7355cb534e4f..0b8225add2e4 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -213,17 +213,6 @@ void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
 	}
 }
 
-void kasan_free_pages(struct page *page, unsigned int order)
-{
-	/*
-	 * This condition should match the one in free_pages_prepare() in
-	 * page_alloc.c.
-	 */
-	bool init = want_init_on_free();
-
-	kasan_poison_pages(page, order, init);
-}
-
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 void kasan_enable_tagging_sync(void)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 3589333b5b77..3f3ea41f8c64 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1353,15 +1353,17 @@ static __always_inline bool free_pages_prepare(struct page *page,
 
 	/*
 	 * As memory initialization might be integrated into KASAN,
-	 * kasan_free_pages and kernel_init_free_pages must be
+	 * KASAN poisoning and memory initialization code must be
 	 * kept together to avoid discrepancies in behavior.
 	 *
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
 	if (kasan_has_integrated_init()) {
+		bool init = want_init_on_free();
+
 		if (!skip_kasan_poison)
-			kasan_free_pages(page, order);
+			kasan_poison_pages(page, order, init);
 	} else {
 		bool init = want_init_on_free();
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/64f8b74a4766f886a6df77438e7e098205fd0863.1638308023.git.andreyknvl%40google.com.
