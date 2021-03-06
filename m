Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRUTROBAMGQEM7NYZKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 28B0132F727
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Mar 2021 01:16:08 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id q11sf903579plx.22
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 16:16:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614989767; cv=pass;
        d=google.com; s=arc-20160816;
        b=xx2K6Ktc8mDOr7dQghaqN51uDAi4SeY6ui2UQP02FaXMQcBnxhNS0GuP7+zHj5lXLz
         Nqe5kTEuKT2xttJ2Aph9mNZbMyL+54cS8IQMkF0w9oZdLfHRGMiBf6roVQCyHf1Fo12e
         P5M+U/IRoW4yyLU5UXfjKW6rkt62ICrm1XPh1G0HefPjSYcB1zZbYqm9i1tJscdwrhvY
         ZcydISbnx7I9C22Pi0OG8civwRpS3dcSoWZPv162OQ5yd4kW67ARIbrqgk1suxOaxgfj
         m1535XxI3rY7Z52ct1fQ9vFJuAkQFZKxzqOcbSyUHmY1UZPLGdEk6Tgd/zFHMRL7uVdI
         5sVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ZF/5wzK3X871bjmLVpqbyzWBk1EewfBWbimNjvPMsGM=;
        b=BD1V6qZ5UexVA0E+O3esQppV137tHPI2pmGHhfRUFhVMZ7g/TY4etD6s4lRgerFw7B
         yx/6tHJeIo4ya7Kpx3at7qxODYlZaMY1eNuBJ2CBq9qMxGldCk0G7F2k/gu1BdNQWdH7
         P6bGpEshouLNK/jl5tOiBO6jLt8kthmcrhJSTV/9UAaldHZJ5Az4LjBknE/o1QWtlCsa
         3BJ7ZA+wz07232B53y5bRH5yKqR87Ng2XR7Tdn5OLs6Ea3UsocflsMUJ+7O25WMlkpa5
         poCCm8Sff7yA/CQgBdyit/nnr56bUoaV/oFQLP5qE3SKFCxmC80RgmpidhOA/3I+lO4z
         GsGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qpZBzena;
       spf=pass (google.com: domain of 3xclcyaokcwwkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3xclCYAoKCWwKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZF/5wzK3X871bjmLVpqbyzWBk1EewfBWbimNjvPMsGM=;
        b=OkPpvpnX20iW3C4HBTuPsRRV+IJ22e0tYeDBftZGCZC33iFP2TdqsOcSxuHSC+6sD8
         mFJs0eWy8NearyG0yVW1ekN1GC9QTh689kUa0RQSeYwUqOB1EChL+kwg+Ut82loiH8/f
         5NiNQlTvEdCvM2kjjcv+X2r9eP9QimMMLucDtI5Rf+zO1UcHvJtVkrHx6HE5Hy/fnlkz
         Ckw9VNQEVnBRySO7LqHPmi9WlIktXC4wTeaj2kVgSgoDS4QBmHdfc/zb3dHVzZbKVBR7
         y8N2xho6TOrEE3xpTeYTe1N1x1c99PA/5sKQXy7j4pTHgvaMFFPDNbZMdW090On2Lw/P
         aZ0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZF/5wzK3X871bjmLVpqbyzWBk1EewfBWbimNjvPMsGM=;
        b=YgkdVXzsNvcrgM+GQBKAD2fzvmn56sRRjZOmNZv7/CXmX29mYJHhurVXwhLjVxUQjy
         LNSKuhaemIS1t6zwC2YZw2MInopbf+o/4ikBhTky/SevtR9nfqdXDeSS1K9Lk6dGsZxj
         xj8R+nz76nKLFeJHibhDOoMKJbi1Yl9VAsbboP3H8P4FBiq5iM08ZO1u/2+DvYLu5XLd
         PLE7uLI9axGv4D7ovPWljOHy+IJcT/pJlR7+P5Sbn+B0pSnZDGT+iZw8PI8wskDN16/5
         6SS5ZACXZsqwDUYGDEEQWPSSNZYU+EVUxkhC11ErYvAZZ23RK6aGxln9QyGVr0Zgd3tl
         Roww==
X-Gm-Message-State: AOAM5317d6/19JuNxFjtiOEg3xfOi/yBMhS8/VS0Ljgzd/K61TUpu1+p
	6eN+mgIBDjjc5EGJMQt5Yhk=
X-Google-Smtp-Source: ABdhPJw8Wo6Teyb7vcdkmYLcZCMzKUv0FiVzifVA8kpZUO/6fgyNV0SrCw731UjVpo0VxJOIkvHkkw==
X-Received: by 2002:a62:7a52:0:b029:1ee:ee21:50f with SMTP id v79-20020a627a520000b02901eeee21050fmr10866628pfc.14.1614989766714;
        Fri, 05 Mar 2021 16:16:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bd8b:: with SMTP id z11ls6241354pjr.1.gmail; Fri, 05
 Mar 2021 16:16:06 -0800 (PST)
X-Received: by 2002:a17:90a:f489:: with SMTP id bx9mr9063204pjb.80.1614989766224;
        Fri, 05 Mar 2021 16:16:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614989766; cv=none;
        d=google.com; s=arc-20160816;
        b=yNAR2wIO0Y7aQct6jZ+5SOdyl6RHBW5WbcGY0jfYByzB9FDyP9m1ould0eOmGSxtSQ
         tRRhbIq7NV3YxeqjHInV9vdNa05RTKQGMqKlTx4UW8WGIk8o4EMsFd6lRvfL3Duee1P+
         /M06qPaWa0BpO6qD11ZgWmDP7j3G8cRwbEgmVo1RuI2Arub5yftlGVZP/0OfnkdV2/9P
         oVLsWXel9KhwLf0H9kVxU0Grzw+KvmI7aslhSSXeVQFBqkmp218v9IUPrzo4sZj//3qs
         mtabrkM5/6U0bsylxbRO3UVcjAk7c6pfLuKCwKi0P7gUkiMtIE8NcMCgsNc8l+1kTXI2
         ZaXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=JV+4yHKwhA6hS5zl77p78vaE1RmKFL1mwbyUPs8dFiM=;
        b=N/mLuHHJcPHrzQKdSIMczn614W6F8xlOpvqSDz3Ek0euuhkbNXt5ijIDag3REa+Quq
         rYQndiO26uRLlZft15Kb/JtdCY405I2HosxG57Wz8axHeTeTh2c8bqZ4hOzOvHFbx/tN
         JOrex5MtZqcxPr00PRzbg7PyVDd/s9B/RsI6QJ9B5sm2WBL08bovHibiKhXTxEHHbMm9
         bDI/6IpGORMd8LhMwX2nc1EsVGZx4uwAMXCB1ojRKeD8EIQXWu5uxR9PwlckTXKM/bVG
         mt+3SczHFmcGnCH8KgtuMq0MoDYde23OeXP54OaxFLm1iEbbOiANmuL6FSnVDJcyEKoo
         qxrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qpZBzena;
       spf=pass (google.com: domain of 3xclcyaokcwwkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3xclCYAoKCWwKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id e7si255990pfi.1.2021.03.05.16.16.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 16:16:06 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xclcyaokcwwkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id d11so3133399qth.3
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 16:16:06 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:953b:d7cf:2b01:f178])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4471:: with SMTP id
 s17mr11312797qvt.51.1614989765390; Fri, 05 Mar 2021 16:16:05 -0800 (PST)
Date: Sat,  6 Mar 2021 01:15:52 +0100
In-Reply-To: <cover.1614989433.git.andreyknvl@google.com>
Message-Id: <a7f1d687b0550182c7f5b4a47c277a61425af65f.1614989433.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1614989433.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH 3/5] kasan, mm: integrate page_alloc init with HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qpZBzena;       spf=pass
 (google.com: domain of 3xclcyaokcwwkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3xclCYAoKCWwKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This change uses the previously added memory initialization feature
of HW_TAGS KASAN routines for page_alloc memory when init_on_alloc/free
is enabled.

With this change, kernel_init_free_pages() is no longer called when
both HW_TAGS KASAN and init_on_alloc/free are enabled. Instead, memory
is initialized in KASAN runtime.

To avoid discrepancies with which memory gets initialized that can be
caused by future changes, both KASAN and kernel_init_free_pages() hooks
are put together and a warning comment is added.

This patch changes the order in which memory initialization and page
poisoning hooks are called. This doesn't lead to any side-effects, as
whenever page poisoning is enabled, memory initialization gets disabled.

Combining setting allocation tags with memory initialization improves
HW_TAGS KASAN performance when init_on_alloc/free is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 16 ++++++++--------
 mm/kasan/common.c     |  8 ++++----
 mm/mempool.c          |  4 ++--
 mm/page_alloc.c       | 37 ++++++++++++++++++++++++++-----------
 4 files changed, 40 insertions(+), 25 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 1d89b8175027..4c0f414a893b 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -120,20 +120,20 @@ static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
 		__kasan_unpoison_range(addr, size);
 }
 
-void __kasan_alloc_pages(struct page *page, unsigned int order);
+void __kasan_alloc_pages(struct page *page, unsigned int order, bool init);
 static __always_inline void kasan_alloc_pages(struct page *page,
-						unsigned int order)
+						unsigned int order, bool init)
 {
 	if (kasan_enabled())
-		__kasan_alloc_pages(page, order);
+		__kasan_alloc_pages(page, order, init);
 }
 
-void __kasan_free_pages(struct page *page, unsigned int order);
+void __kasan_free_pages(struct page *page, unsigned int order, bool init);
 static __always_inline void kasan_free_pages(struct page *page,
-						unsigned int order)
+						unsigned int order, bool init)
 {
 	if (kasan_enabled())
-		__kasan_free_pages(page, order);
+		__kasan_free_pages(page, order, init);
 }
 
 void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
@@ -282,8 +282,8 @@ static inline slab_flags_t kasan_never_merge(void)
 	return 0;
 }
 static inline void kasan_unpoison_range(const void *address, size_t size) {}
-static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
-static inline void kasan_free_pages(struct page *page, unsigned int order) {}
+static inline void kasan_alloc_pages(struct page *page, unsigned int order, bool init) {}
+static inline void kasan_free_pages(struct page *page, unsigned int order, bool init) {}
 static inline void kasan_cache_create(struct kmem_cache *cache,
 				      unsigned int *size,
 				      slab_flags_t *flags) {}
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 316f7f8cd8e6..6107c795611f 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -97,7 +97,7 @@ slab_flags_t __kasan_never_merge(void)
 	return 0;
 }
 
-void __kasan_alloc_pages(struct page *page, unsigned int order)
+void __kasan_alloc_pages(struct page *page, unsigned int order, bool init)
 {
 	u8 tag;
 	unsigned long i;
@@ -108,14 +108,14 @@ void __kasan_alloc_pages(struct page *page, unsigned int order)
 	tag = kasan_random_tag();
 	for (i = 0; i < (1 << order); i++)
 		page_kasan_tag_set(page + i, tag);
-	kasan_unpoison(page_address(page), PAGE_SIZE << order, false);
+	kasan_unpoison(page_address(page), PAGE_SIZE << order, init);
 }
 
-void __kasan_free_pages(struct page *page, unsigned int order)
+void __kasan_free_pages(struct page *page, unsigned int order, bool init)
 {
 	if (likely(!PageHighMem(page)))
 		kasan_poison(page_address(page), PAGE_SIZE << order,
-			     KASAN_FREE_PAGE, false);
+			     KASAN_FREE_PAGE, init);
 }
 
 /*
diff --git a/mm/mempool.c b/mm/mempool.c
index 79959fac27d7..fe19d290a301 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -106,7 +106,7 @@ static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
 	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
 		kasan_slab_free_mempool(element);
 	else if (pool->alloc == mempool_alloc_pages)
-		kasan_free_pages(element, (unsigned long)pool->pool_data);
+		kasan_free_pages(element, (unsigned long)pool->pool_data, false);
 }
 
 static void kasan_unpoison_element(mempool_t *pool, void *element)
@@ -114,7 +114,7 @@ static void kasan_unpoison_element(mempool_t *pool, void *element)
 	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
 		kasan_unpoison_range(element, __ksize(element));
 	else if (pool->alloc == mempool_alloc_pages)
-		kasan_alloc_pages(element, (unsigned long)pool->pool_data);
+		kasan_alloc_pages(element, (unsigned long)pool->pool_data, false);
 }
 
 static __always_inline void add_element(mempool_t *pool, void *element)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 0efb07b5907c..175bdb36d113 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -396,14 +396,14 @@ static DEFINE_STATIC_KEY_TRUE(deferred_pages);
  * initialization is done, but this is not likely to happen.
  */
 static inline void kasan_free_nondeferred_pages(struct page *page, int order,
-							fpi_t fpi_flags)
+						bool init, fpi_t fpi_flags)
 {
 	if (static_branch_unlikely(&deferred_pages))
 		return;
 	if (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
 			(fpi_flags & FPI_SKIP_KASAN_POISON))
 		return;
-	kasan_free_pages(page, order);
+	kasan_free_pages(page, order, init);
 }
 
 /* Returns true if the struct page for the pfn is uninitialised */
@@ -455,12 +455,12 @@ defer_init(int nid, unsigned long pfn, unsigned long end_pfn)
 }
 #else
 static inline void kasan_free_nondeferred_pages(struct page *page, int order,
-							fpi_t fpi_flags)
+						bool init, fpi_t fpi_flags)
 {
 	if (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
 			(fpi_flags & FPI_SKIP_KASAN_POISON))
 		return;
-	kasan_free_pages(page, order);
+	kasan_free_pages(page, order, init);
 }
 
 static inline bool early_page_uninitialised(unsigned long pfn)
@@ -1242,6 +1242,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 			unsigned int order, bool check_free, fpi_t fpi_flags)
 {
 	int bad = 0;
+	bool init;
 
 	VM_BUG_ON_PAGE(PageTail(page), page);
 
@@ -1299,16 +1300,21 @@ static __always_inline bool free_pages_prepare(struct page *page,
 		debug_check_no_obj_freed(page_address(page),
 					   PAGE_SIZE << order);
 	}
-	if (want_init_on_free())
-		kernel_init_free_pages(page, 1 << order);
 
 	kernel_poison_pages(page, 1 << order);
 
 	/*
+	 * As memory initialization is integrated with hardware tag-based
+	 * KASAN, kasan_free_pages and kernel_init_free_pages must be
+	 * kept together to avoid discrepancies in behavior.
+	 *
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
-	kasan_free_nondeferred_pages(page, order, fpi_flags);
+	init = want_init_on_free();
+	if (init && !IS_ENABLED(CONFIG_KASAN_HW_TAGS))
+		kernel_init_free_pages(page, 1 << order);
+	kasan_free_nondeferred_pages(page, order, init, fpi_flags);
 
 	/*
 	 * arch_free_page() can make the page's contents inaccessible.  s390
@@ -2315,17 +2321,26 @@ static bool check_new_pages(struct page *page, unsigned int order)
 inline void post_alloc_hook(struct page *page, unsigned int order,
 				gfp_t gfp_flags)
 {
+	bool init;
+
 	set_page_private(page, 0);
 	set_page_refcounted(page);
 
 	arch_alloc_page(page, order);
 	debug_pagealloc_map_pages(page, 1 << order);
-	kasan_alloc_pages(page, order);
-	kernel_unpoison_pages(page, 1 << order);
-	set_page_owner(page, order, gfp_flags);
 
-	if (!want_init_on_free() && want_init_on_alloc(gfp_flags))
+	/*
+	 * As memory initialization is integrated with hardware tag-based
+	 * KASAN, kasan_alloc_pages and kernel_init_free_pages must be
+	 * kept together to avoid discrepancies in behavior.
+	 */
+	init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
+	kasan_alloc_pages(page, order, init);
+	if (init && !IS_ENABLED(CONFIG_KASAN_HW_TAGS))
 		kernel_init_free_pages(page, 1 << order);
+
+	kernel_unpoison_pages(page, 1 << order);
+	set_page_owner(page, order, gfp_flags);
 }
 
 static void prep_new_page(struct page *page, unsigned int order, gfp_t gfp_flags,
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a7f1d687b0550182c7f5b4a47c277a61425af65f.1614989433.git.andreyknvl%40google.com.
