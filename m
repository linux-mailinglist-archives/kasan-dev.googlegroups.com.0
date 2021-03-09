Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIHOTWBAMGQEZEGIT4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FAA83326FF
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 14:24:50 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id gv10sf2179891pjb.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 05:24:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615296289; cv=pass;
        d=google.com; s=arc-20160816;
        b=JgiQvWWecyQzuYyG8zY7/OFhRy865Slk5Swkpsv+Mp/G9uDG6bMIc8LYUVJ+3EAV+4
         UA5RiRfn/EphB6QGYKmSEXziJlgQyRI5v3OBz0KQ0oOJFInu0Q94Tq3r4ZBAcigHUHZG
         H2MOWukDbIoQovf6PZTd5mMyLgE2G5If16RApaOVrAX6JPhLX8r/xXOyE+CkgWIvkJgq
         juFYRiL32cAIYtSNt5TNTsP17RtLbRtgmD/6M+Q7gz4Mic/z/MkoDDyTEZDOzWw169yT
         2GVXaDuPIfekqNxh8VtZmgsFB+ALViq3MIa0c1TC2xVEM1gMlMDCRCuiBfS+Yt3j8tgh
         M2RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Hb4fPRNVAgiKckkxt7kK/LN4aC+6pqMnbDvhLuxvvFo=;
        b=i/CG+YHvM6bkd1CmkUUvJZWZ5A+ytOo5ICxYPsPPoDHiIc/dCux0kwB8rFfQh6B7H6
         uWmmmCmQDgC4KnrXsQFQMpogon2Ymuo2QHopR6mzl7aypiCBIchgMMpi8mhRNj7LvKNA
         U4Wet27bzolNuST7+4Gphc0E5bYXz/kv/f96FsC1PA3o8UvAVJmNrdNJ+hMhrbsdrC5F
         Atmbqs0w4TVA/oEyMUGL5SP+5Y+pU4XT9uk/5u37oZdOXEuwND+BgTjmzAfkTcj2B8k6
         ffRruKK7s7smcdZ77Jz/javUnMZhpyvAZ4l+HfYCGnslY3ca4Q0OoSrsaDbrU5sC1Rbi
         Rk/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="GuXS/wW0";
       spf=pass (google.com: domain of 3h3dhyaokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3H3dHYAoKCTQQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Hb4fPRNVAgiKckkxt7kK/LN4aC+6pqMnbDvhLuxvvFo=;
        b=fA2sd2smONibkzGCG8K7v8kuIVcVcVm7J8IVw77w4BT7NR7iovOn2Q5gTH7tqD7781
         Z5XCq38+Oc3ku07UsvT7OLH+I3xBHEUWw1v3xGpEJoPE0TmqffbILBMGUY4I83utdL8Q
         3YZONWmkLbaL37HzHamlxmyz3TKDAPsuvnaSrnhoq2wguh/HndR46QLsqW6qyyPFpurt
         dxd+h3Ju06cw+0fMecRUiVHBXu//mJZ+yx0xZSTzbbOnMfRzVMVtMWW2mTaPZoU1Yflf
         zyReqVL6l36cTShqT4wGjbcpJ3uhRJf0YjLCq1ZGkKv4Qh0I9J8dc4JzZKGYzfnZTcuD
         ENBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hb4fPRNVAgiKckkxt7kK/LN4aC+6pqMnbDvhLuxvvFo=;
        b=Qx4o9kdYUkPv6KziICRU/umtcBQW7SyYWdByzi1lD7g6xCucfuR3Gu5SfJ5UXM0WgF
         RlOsyC5dJ2UC3sif45PZnNTwEquZudpu+Vd4dPY9WTScfMe3xG8vMxtcH0NlNeLO5vDs
         MrQ1FC+1uXrXJeTAEGBsUQyEsgPhze0BuoUYTX1uCx0KJfdCTSCVTnMJeoF1fOgaYAbT
         Mp9pI3r6RTqRdhnNg6hpyrFx/BN7hndJqwsLyXVinhRsFc7nlQV4A9gQ+LkyONHElU4M
         ixOY0txEFmOM3yfQydnhpBA1mTUt00WVDtd7BhjD3ZTNHX+6XtQKe4mXzBEv2vOlXJXf
         Y4tw==
X-Gm-Message-State: AOAM531uGfRn5j5E6nc3H2or9A1ThJxiyE4tiWv83l/4+3vmRg4WfYuq
	fmuZpUrcCLBZNrGVzqoT04c=
X-Google-Smtp-Source: ABdhPJx1rSdbqM2ubbpZ4zyBFDCgUURrNDO1OzWyMUfBcZLN9YblPohRJASE6IaVI1jJCu18eZ3DyQ==
X-Received: by 2002:a17:90a:b903:: with SMTP id p3mr4607603pjr.182.1615296288910;
        Tue, 09 Mar 2021 05:24:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:31cc:: with SMTP id v12ls3177691ple.9.gmail; Tue, 09
 Mar 2021 05:24:48 -0800 (PST)
X-Received: by 2002:a17:90b:508:: with SMTP id r8mr4780459pjz.83.1615296288368;
        Tue, 09 Mar 2021 05:24:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615296288; cv=none;
        d=google.com; s=arc-20160816;
        b=NOzmcOj/BHNNXYSihiutr1f03LLpLhCttEmdoNKx58qShhdltlgCj4x+mjE3u6+W9O
         Iqery/2G0QpC8ZM+lbuZ2bKKVTqLCt1qe8gnAsGLJWkwjQfGJNDTb5VTMriQ4je8TaLx
         DoOK2M+5GEZUWUzsSWxaDLTHwCo9bw3S8ywf+46olhLY+kFYBdZlRw2Qplt7b5CnNOR4
         KMVXzBNHlkREmQ4B4ET2Xc9aIaw+wpnyQRRNpAbUZoZtt67KX3hL97wNL2UvlYMTyaJu
         2H4i6KfVT1gO0oS4y/6uTuWKen7x/h7kKO2L7UJHq3whhgzl2hGtZayrRwm87dALlAO2
         NMAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=juB8DGQdBNYffoVbxywhM+daO8QsN177ObTD+3lbjn4=;
        b=01noG/HVOFrCtKCNZoQGC8mR3oxW7qxyxRrVHdARzmJllPDT2zW3/ygWDF7Uypre9q
         UhB1n4LC9Ujf4mDXwgO6YYIzqgPdcxAAzmA0XXKFoFAzsFmo3O+p0x8PXDtG5nUSaKFR
         M1G6MbwSitYUFzI5loud+wBFB6EG+EctBHYCb1ERX0jEEHiwHpayjKpdBRIBj1k4ZxEb
         w+Mhu3kdTcDvJIckSJlqaUeevPwF88+WgBHyxVX6rXFA6d1TN+RxpSLGv2BB8HGhIRnC
         G2ATB7YZIdXJDaM0mlKRAPuXt4q9S1ZBubeaETaIwgjlTVAVhrX5m3CLLMl8pSo8FY52
         7iOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="GuXS/wW0";
       spf=pass (google.com: domain of 3h3dhyaokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3H3dHYAoKCTQQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id x3si270678pjo.1.2021.03.09.05.24.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Mar 2021 05:24:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 3h3dhyaokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id a11so5413878qtd.4
        for <kasan-dev@googlegroups.com>; Tue, 09 Mar 2021 05:24:48 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:5802:818:ce92:dfef])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5851:: with SMTP id
 de17mr25461053qvb.6.1615296287502; Tue, 09 Mar 2021 05:24:47 -0800 (PST)
Date: Tue,  9 Mar 2021 14:24:36 +0100
In-Reply-To: <cover.1615296150.git.andreyknvl@google.com>
Message-Id: <3054314039fa64510947e674180d675cab1b4c41.1615296150.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1615296150.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH v3 2/5] kasan: init memory in kasan_(un)poison for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="GuXS/wW0";       spf=pass
 (google.com: domain of 3h3dhyaokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3H3dHYAoKCTQQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
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

This change adds an argument to kasan_poison() and kasan_unpoison()
that allows initializing memory along with setting the tags for HW_TAGS.

Combining setting allocation tags with memory initialization will
improve HW_TAGS KASAN performance when init_on_alloc/free is enabled.

This change doesn't integrate memory initialization with KASAN,
this is done is subsequent patches in this series.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c   |  4 ++--
 mm/kasan/common.c  | 28 ++++++++++++++--------------
 mm/kasan/generic.c | 12 ++++++------
 mm/kasan/kasan.h   | 14 ++++++++------
 mm/kasan/shadow.c  | 10 +++++-----
 mm/kasan/sw_tags.c |  2 +-
 6 files changed, 36 insertions(+), 34 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index e5647d147b35..d77c45edc7cd 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -1044,14 +1044,14 @@ static void match_all_mem_tag(struct kunit *test)
 			continue;
 
 		/* Mark the first memory granule with the chosen memory tag. */
-		kasan_poison(ptr, KASAN_GRANULE_SIZE, (u8)tag);
+		kasan_poison(ptr, KASAN_GRANULE_SIZE, (u8)tag, false);
 
 		/* This access must cause a KASAN report. */
 		KUNIT_EXPECT_KASAN_FAIL(test, *ptr = 0);
 	}
 
 	/* Recover the memory tag and free. */
-	kasan_poison(ptr, KASAN_GRANULE_SIZE, get_tag(ptr));
+	kasan_poison(ptr, KASAN_GRANULE_SIZE, get_tag(ptr), false);
 	kfree(ptr);
 }
 
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index b5e08d4cefec..316f7f8cd8e6 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -60,7 +60,7 @@ void kasan_disable_current(void)
 
 void __kasan_unpoison_range(const void *address, size_t size)
 {
-	kasan_unpoison(address, size);
+	kasan_unpoison(address, size, false);
 }
 
 #if CONFIG_KASAN_STACK
@@ -69,7 +69,7 @@ void kasan_unpoison_task_stack(struct task_struct *task)
 {
 	void *base = task_stack_page(task);
 
-	kasan_unpoison(base, THREAD_SIZE);
+	kasan_unpoison(base, THREAD_SIZE, false);
 }
 
 /* Unpoison the stack for the current task beyond a watermark sp value. */
@@ -82,7 +82,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 	 */
 	void *base = (void *)((unsigned long)watermark & ~(THREAD_SIZE - 1));
 
-	kasan_unpoison(base, watermark - base);
+	kasan_unpoison(base, watermark - base, false);
 }
 #endif /* CONFIG_KASAN_STACK */
 
@@ -108,14 +108,14 @@ void __kasan_alloc_pages(struct page *page, unsigned int order)
 	tag = kasan_random_tag();
 	for (i = 0; i < (1 << order); i++)
 		page_kasan_tag_set(page + i, tag);
-	kasan_unpoison(page_address(page), PAGE_SIZE << order);
+	kasan_unpoison(page_address(page), PAGE_SIZE << order, false);
 }
 
 void __kasan_free_pages(struct page *page, unsigned int order)
 {
 	if (likely(!PageHighMem(page)))
 		kasan_poison(page_address(page), PAGE_SIZE << order,
-			     KASAN_FREE_PAGE);
+			     KASAN_FREE_PAGE, false);
 }
 
 /*
@@ -251,18 +251,18 @@ void __kasan_poison_slab(struct page *page)
 	for (i = 0; i < compound_nr(page); i++)
 		page_kasan_tag_reset(page + i);
 	kasan_poison(page_address(page), page_size(page),
-		     KASAN_KMALLOC_REDZONE);
+		     KASAN_KMALLOC_REDZONE, false);
 }
 
 void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
 {
-	kasan_unpoison(object, cache->object_size);
+	kasan_unpoison(object, cache->object_size, false);
 }
 
 void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
 {
 	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
-			KASAN_KMALLOC_REDZONE);
+			KASAN_KMALLOC_REDZONE, false);
 }
 
 /*
@@ -351,7 +351,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache,
 	}
 
 	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
-			KASAN_KMALLOC_FREE);
+			KASAN_KMALLOC_FREE, false);
 
 	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine))
 		return false;
@@ -407,7 +407,7 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 	if (unlikely(!PageSlab(page))) {
 		if (____kasan_kfree_large(ptr, ip))
 			return;
-		kasan_poison(ptr, page_size(page), KASAN_FREE_PAGE);
+		kasan_poison(ptr, page_size(page), KASAN_FREE_PAGE, false);
 	} else {
 		____kasan_slab_free(page->slab_cache, ptr, ip, false);
 	}
@@ -453,7 +453,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 	 * Unpoison the whole object.
 	 * For kmalloc() allocations, kasan_kmalloc() will do precise poisoning.
 	 */
-	kasan_unpoison(tagged_object, cache->object_size);
+	kasan_unpoison(tagged_object, cache->object_size, false);
 
 	/* Save alloc info (if possible) for non-kmalloc() allocations. */
 	if (kasan_stack_collection_enabled())
@@ -496,7 +496,7 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
 	redzone_end = round_up((unsigned long)(object + cache->object_size),
 				KASAN_GRANULE_SIZE);
 	kasan_poison((void *)redzone_start, redzone_end - redzone_start,
-			   KASAN_KMALLOC_REDZONE);
+			   KASAN_KMALLOC_REDZONE, false);
 
 	/*
 	 * Save alloc info (if possible) for kmalloc() allocations.
@@ -546,7 +546,7 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
 				KASAN_GRANULE_SIZE);
 	redzone_end = (unsigned long)ptr + page_size(virt_to_page(ptr));
 	kasan_poison((void *)redzone_start, redzone_end - redzone_start,
-		     KASAN_PAGE_REDZONE);
+		     KASAN_PAGE_REDZONE, false);
 
 	return (void *)ptr;
 }
@@ -563,7 +563,7 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 	 * Part of it might already have been unpoisoned, but it's unknown
 	 * how big that part is.
 	 */
-	kasan_unpoison(object, size);
+	kasan_unpoison(object, size, false);
 
 	page = virt_to_head_page(object);
 
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 2e55e0f82f39..53cbf28859b5 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -208,11 +208,11 @@ static void register_global(struct kasan_global *global)
 {
 	size_t aligned_size = round_up(global->size, KASAN_GRANULE_SIZE);
 
-	kasan_unpoison(global->beg, global->size);
+	kasan_unpoison(global->beg, global->size, false);
 
 	kasan_poison(global->beg + aligned_size,
 		     global->size_with_redzone - aligned_size,
-		     KASAN_GLOBAL_REDZONE);
+		     KASAN_GLOBAL_REDZONE, false);
 }
 
 void __asan_register_globals(struct kasan_global *globals, size_t size)
@@ -292,11 +292,11 @@ void __asan_alloca_poison(unsigned long addr, size_t size)
 	WARN_ON(!IS_ALIGNED(addr, KASAN_ALLOCA_REDZONE_SIZE));
 
 	kasan_unpoison((const void *)(addr + rounded_down_size),
-			size - rounded_down_size);
+			size - rounded_down_size, false);
 	kasan_poison(left_redzone, KASAN_ALLOCA_REDZONE_SIZE,
-		     KASAN_ALLOCA_LEFT);
+		     KASAN_ALLOCA_LEFT, false);
 	kasan_poison(right_redzone, padding_size + KASAN_ALLOCA_REDZONE_SIZE,
-		     KASAN_ALLOCA_RIGHT);
+		     KASAN_ALLOCA_RIGHT, false);
 }
 EXPORT_SYMBOL(__asan_alloca_poison);
 
@@ -306,7 +306,7 @@ void __asan_allocas_unpoison(const void *stack_top, const void *stack_bottom)
 	if (unlikely(!stack_top || stack_top > stack_bottom))
 		return;
 
-	kasan_unpoison(stack_top, stack_bottom - stack_top);
+	kasan_unpoison(stack_top, stack_bottom - stack_top, false);
 }
 EXPORT_SYMBOL(__asan_allocas_unpoison);
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 7fbb32234414..823a90d6a0cd 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -331,7 +331,7 @@ static inline u8 kasan_random_tag(void) { return 0; }
 
 #ifdef CONFIG_KASAN_HW_TAGS
 
-static inline void kasan_poison(const void *addr, size_t size, u8 value)
+static inline void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 {
 	addr = kasan_reset_tag(addr);
 
@@ -344,10 +344,10 @@ static inline void kasan_poison(const void *addr, size_t size, u8 value)
 	if (WARN_ON(size & KASAN_GRANULE_MASK))
 		return;
 
-	hw_set_mem_tag_range((void *)addr, size, value, false);
+	hw_set_mem_tag_range((void *)addr, size, value, init);
 }
 
-static inline void kasan_unpoison(const void *addr, size_t size)
+static inline void kasan_unpoison(const void *addr, size_t size, bool init)
 {
 	u8 tag = get_tag(addr);
 
@@ -361,7 +361,7 @@ static inline void kasan_unpoison(const void *addr, size_t size)
 		return;
 	size = round_up(size, KASAN_GRANULE_SIZE);
 
-	hw_set_mem_tag_range((void *)addr, size, tag, false);
+	hw_set_mem_tag_range((void *)addr, size, tag, init);
 }
 
 static inline bool kasan_byte_accessible(const void *addr)
@@ -380,22 +380,24 @@ static inline bool kasan_byte_accessible(const void *addr)
  * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
  * @size - range size, must be aligned to KASAN_GRANULE_SIZE
  * @value - value that's written to metadata for the range
+ * @init - whether to initialize the memory range (only for hardware tag-based)
  *
  * The size gets aligned to KASAN_GRANULE_SIZE before marking the range.
  */
-void kasan_poison(const void *addr, size_t size, u8 value);
+void kasan_poison(const void *addr, size_t size, u8 value, bool init);
 
 /**
  * kasan_unpoison - mark the memory range as accessible
  * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
  * @size - range size, can be unaligned
+ * @init - whether to initialize the memory range (only for hardware tag-based)
  *
  * For the tag-based modes, the @size gets aligned to KASAN_GRANULE_SIZE before
  * marking the range.
  * For the generic mode, the last granule of the memory range gets partially
  * unpoisoned based on the @size.
  */
-void kasan_unpoison(const void *addr, size_t size);
+void kasan_unpoison(const void *addr, size_t size, bool init);
 
 bool kasan_byte_accessible(const void *addr);
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 63f43443f5d7..727ad4629173 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -69,7 +69,7 @@ void *memcpy(void *dest, const void *src, size_t len)
 	return __memcpy(dest, src, len);
 }
 
-void kasan_poison(const void *addr, size_t size, u8 value)
+void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 {
 	void *shadow_start, *shadow_end;
 
@@ -106,7 +106,7 @@ void kasan_poison_last_granule(const void *addr, size_t size)
 }
 #endif
 
-void kasan_unpoison(const void *addr, size_t size)
+void kasan_unpoison(const void *addr, size_t size, bool init)
 {
 	u8 tag = get_tag(addr);
 
@@ -129,7 +129,7 @@ void kasan_unpoison(const void *addr, size_t size)
 		return;
 
 	/* Unpoison all granules that cover the object. */
-	kasan_poison(addr, round_up(size, KASAN_GRANULE_SIZE), tag);
+	kasan_poison(addr, round_up(size, KASAN_GRANULE_SIZE), tag, false);
 
 	/* Partially poison the last granule for the generic mode. */
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
@@ -344,7 +344,7 @@ void kasan_poison_vmalloc(const void *start, unsigned long size)
 		return;
 
 	size = round_up(size, KASAN_GRANULE_SIZE);
-	kasan_poison(start, size, KASAN_VMALLOC_INVALID);
+	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
 }
 
 void kasan_unpoison_vmalloc(const void *start, unsigned long size)
@@ -352,7 +352,7 @@ void kasan_unpoison_vmalloc(const void *start, unsigned long size)
 	if (!is_vmalloc_or_module_addr(start))
 		return;
 
-	kasan_unpoison(start, size);
+	kasan_unpoison(start, size, false);
 }
 
 static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 94c2d33be333..bd0c64d4e4d9 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -159,7 +159,7 @@ EXPORT_SYMBOL(__hwasan_storeN_noabort);
 
 void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
 {
-	kasan_poison((void *)addr, size, tag);
+	kasan_poison((void *)addr, size, tag, false);
 }
 EXPORT_SYMBOL(__hwasan_tag_memory);
 
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3054314039fa64510947e674180d675cab1b4c41.1615296150.git.andreyknvl%40google.com.
