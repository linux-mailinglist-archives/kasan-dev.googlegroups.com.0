Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRETROBAMGQETP5DLDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id A677832F726
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Mar 2021 01:16:04 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id n17sf1784785wrq.5
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 16:16:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614989764; cv=pass;
        d=google.com; s=arc-20160816;
        b=BdOq/vaS9afT0BfhMAkZUaLUPJMtQBQGpwgcxx9wnhMdb0q+3/4DSdzN08ipjQSALt
         kDUcpQwszo8Yqb+R4/eBntHOicdqe3J8ngmOoNAekAtVw1dwTDi2cfMqIHGQoqmPWqkD
         7hWT6IUX8Zz9RVgptOXVQ3vdPXVNxf2yVdhcrVukvD+z6aWkULY2xAmAVonirw645XYv
         +O+2crIeAfdPgAXt99zgJdeoI6gPy1yxrZvdZFPLCgJ2N1ADXGt8F7PE8Bz6iR8WzdTE
         I/A3UK9BfpKD8cu0yWo0sydWCGnZnF/36Qi/koyOZ2+kuxnhQz9mw3/5pn3nRzKKAV2g
         2tQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=JSkh/sFVMfyZSW1vIk7WbH7c+IQR6Ei0UqInR5EKXQw=;
        b=fFRwofoXxqbVv9oTz+D4NkUGgJV90gCMxv7CSn7LagG1GvPtbzbTEiJL7t/PpGA4qf
         UTZjoei/lOa0FaIleTs4rjok0RBSOIQAfOMeGMDZ7du4SP6oGpBYdc9AjUlN0Ov0aLUz
         QaR0UXYTnw9Pwlh+CJgW3bZ6toqHVG7FwtN4oWhVRG5wBqkc6KxNWYdZSIfCsmEHJFdC
         puja0/WUblrsjoahU7jGstDAIgqxfHPby8cP827ZKEtTsl1VK4K8sqCG5pd2OtTxgcLx
         tZcN/x3YNNZqI1KElXtfsmOo7RD7sIpQJ6FWGY08a/Swz7th7dizR09JBfSGhV/5sx7f
         XtIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=utjuGylv;
       spf=pass (google.com: domain of 3w8lcyaokcwoivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3w8lCYAoKCWoIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JSkh/sFVMfyZSW1vIk7WbH7c+IQR6Ei0UqInR5EKXQw=;
        b=jbtyTNV2QuCmtC+drW4qQXj49OJDIzMPvClEJjFYikT4iCG8GQwNCLi1Ht+pgwk9G/
         sIviQwXA2FTY5sJ5z/Sq7TYbcNUHnoncqow56KECF68ZcbSVU+27KAERWWcyvjtQX+qz
         ZGWY2VzgpluWQ+jsasDSqooUvzGC5MV+F20q7GuKDVc/rCaOwd7lBNI83W1qDzRhgFt2
         dE8dIlETCLXY7vh14oOXAgezZqKuasQqrHqpmbwZmzNWxprQZHnxo9eCurKw3zg5cPi3
         aI9BwHle0BKyMR0jy8BCGMLJMtAepL8h8vb+io04Xaoxt34jV3WtBP713QXFZA5jQyXu
         OGsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JSkh/sFVMfyZSW1vIk7WbH7c+IQR6Ei0UqInR5EKXQw=;
        b=S02Fqs/ZgaMXpyRYC5c1MWeaSFuE8n1/r88gdWvfr2ussz2QEw089FmTG8pmczJlQH
         Ae+K6whGHdje1hlZ9o4Xr75QJ73+f9vSJnQyRLJAJTn+5QMzHDoiHeLGz5XPyKwODTx0
         CbqHQGJPYaowWljkFmbCky928p9yBi5rnigfTnRWap+Ld00Iq9hKSO822ieOj5t25v8L
         VtNPtf1YPZfO1Cm7yAYRJBxt3eXE28aCICfaV5dGb8m2b8AqR0xUhwb4VZn4s8aySSPx
         /4MQ9FumF39Tj8SKM2zqAM+tyigb4BHkp1sZMjkeMBTLZsPqCh9IVl7wJfbpnrLEE8T+
         DWOQ==
X-Gm-Message-State: AOAM531XVwlLKn+mDIk1U7czr+TSyNqpdQhBXKoInIP2eQUjSjVOGaxw
	R6vwuYCjRE441mp8jvdvUcM=
X-Google-Smtp-Source: ABdhPJzyfK0A/JmfKtM2LLMQqez+JGYVT2NdJ1T6CunmnYk2q5JC7+Y2VHd/2vj+fXU0A5WOArZguA==
X-Received: by 2002:adf:a703:: with SMTP id c3mr11445799wrd.379.1614989764489;
        Fri, 05 Mar 2021 16:16:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cc94:: with SMTP id p20ls5506346wma.0.gmail; Fri, 05 Mar
 2021 16:16:03 -0800 (PST)
X-Received: by 2002:a1c:c903:: with SMTP id f3mr11041862wmb.69.1614989763734;
        Fri, 05 Mar 2021 16:16:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614989763; cv=none;
        d=google.com; s=arc-20160816;
        b=dSavKAvFEbUuLNrEhZYDWAQMW3jQos+1Hr1rH2VDZstBT6GP544rF9tBq+9r1NnSYS
         k7NerIlI1RhWHVD4RmkiDQ8UAginMGDIjKg9BtBvPe//oGJaaz7DAb8HH4dCd6s4yTFg
         lVIjSxZjsgQJ4vy9Kz0N+UxufEiH2RtlwL2dQbh8F7k89kN/F4+jaEuWyPDsLnZO9KPS
         1kBPOmwjiRq8fQpE9bz6gwLm/Lpype5Gie4V//+JTG0RFPdOfrT2RrLwJbLmcQwLrale
         OEP7yPuTR8sVzKrWucAwwFLl6pw6QGsh5lxz5ZFoVIpUUyd4pYNuqLagW/Lp41JYDasg
         j9Zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=18BLQkaK7gMwPL1oLiiZwYRw3WPv/homyFWs2XqXDtM=;
        b=vMpXdJGh7cPHnO/znrzya4NoO2e7FaNIWp5Pk4x54HT8m7SYI/bSHMXQYLm5yIiIfW
         gRco/sr1S8EBpfEls1m7um0oImdhzN+3LiyCa81D98o81C/u4GAXvWYE5VeBNljT1rXk
         MVnUnJrJ1dJjlkMXW2tOGi34OIYnRvLd+hutogCWQp3TaXvMoqSQgXh2PNBOR09cEcal
         dqRs81EeTeUCTd4/m9vIN1rcnxYOiwbECqjovLfw6lAFKApBSI/ACsM9zCdzO6BScShO
         2ZuauQk7QASUyR0lwK6FHTqWJVqKAkD1ImdauMI3xNjntsHrqNH+UxKtO7AeG9IKN4wY
         r8gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=utjuGylv;
       spf=pass (google.com: domain of 3w8lcyaokcwoivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3w8lCYAoKCWoIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id k83si184620wma.0.2021.03.05.16.16.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 16:16:03 -0800 (PST)
Received-SPF: pass (google.com: domain of 3w8lcyaokcwoivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id i5so1777934wrp.8
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 16:16:03 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:953b:d7cf:2b01:f178])
 (user=andreyknvl job=sendgmr) by 2002:a1c:e184:: with SMTP id
 y126mr11218086wmg.163.1614989763415; Fri, 05 Mar 2021 16:16:03 -0800 (PST)
Date: Sat,  6 Mar 2021 01:15:51 +0100
In-Reply-To: <cover.1614989433.git.andreyknvl@google.com>
Message-Id: <09ee2b0a0e9578885b2da1c963e9e94154d5d70a.1614989433.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1614989433.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH 2/5] kasan: init memory in kasan_(un)poison for HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=utjuGylv;       spf=pass
 (google.com: domain of 3w8lcyaokcwoivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3w8lCYAoKCWoIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/09ee2b0a0e9578885b2da1c963e9e94154d5d70a.1614989433.git.andreyknvl%40google.com.
