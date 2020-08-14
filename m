Return-Path: <kasan-dev+bncBDX4HWEMTEBRBB4T3P4QKGQES4EOFKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 88D3C244DB8
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:27:35 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id w138sf2162312lff.22
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:27:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426055; cv=pass;
        d=google.com; s=arc-20160816;
        b=CD+xMZVBCc1+wGSNGQsVrwutanSiulUzTgEcvyEXVwP1QV5MRhvaVNsK5jhtoNJM/l
         SEqsstM8aJIhXD7BFckKKy47tiIBENeG4gWkV9tFEAmFCaqJFVE41ktMgw9L/FmzXkL5
         MRh3/ERRfNEBqvOPfzyNHpr8p2xuJgmidXvuc+bYZdgwVnBgPHu8aDEJfskw2xX5/2nm
         GJ+EVLyWAjCFabvhG4xsGPfqjbySzgsBvbUEl6ngeWTttEiFU1XRstW/bK0v/7xuUZgh
         z8qHaVUVQVT8pYOMA2tt1r0WWp3KDO7bL1UOhaA03Evn5CZI0ENXnOd3d2gBS1mRD3ol
         mJuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=mDdzY7aeRCV4/x338kRKLCbZwWAdt/EoTuWpA4rhe88=;
        b=Flgk9xE+jlTmaAa6PrE/K6syc9zPrGYQyc63QBK+pS4jdRExWdhpw7Yki+EM5+3hfx
         07RT9QPs9x7GUWo1YPaEgNdsRKpGvu+VbkhoRH6tSK+WLrEQkm0jD2My0qk6Wic9cy9e
         p7yriEZnyJTcdtOLLp+FpxHLoQmx1R9gxhYfoS6QAWVD7h3OF6Qo1venWbFsrLSDHUlI
         EyWQmAZGfT+sB1njTXCPCg6089Cr8Br1d6RoBYgoQAwXTUg6BdiwDCbUPTKhpuUtecXK
         UDFi7Pqyi7aS5H/9H2PDDC52a0k6i5HhglhqzBT+R84Sw7+GbtAZdihlgtezmsoCz8Vp
         zwzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=En5D1zMD;
       spf=pass (google.com: domain of 3hck2xwokcfiuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3hck2XwoKCfIUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mDdzY7aeRCV4/x338kRKLCbZwWAdt/EoTuWpA4rhe88=;
        b=PUyC27YMN8hZbwCehfEJvjaY1+6m7AgG9Avf8B1j3H170zXN/1O9l2+U/CSE8kps5I
         JYo7+m7oQK9icTHJ9u2e5nOBgb05890crU8X+pSeudooJqqEnGp1lm11UKnwCseYOysi
         tI9gLLtQ1sri0mWIrFIR5N7SSyjbk5VKhQ6JjR/DXefpNZ+1LBjFmoG3ykv+71+QOxBC
         yyB8ltM8hj8fO5rrCxQs0d3prNn5+Ndbzji8MXlxSisT3GOaRwQW4sTpCoM27XAdzYKo
         lbXWfkmRX5NIZAUo2V3sRuOWW62hmvncMsOzAk0L8C+Mm1R/7lPP7i0DF4IVfXlz7KZr
         NVqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mDdzY7aeRCV4/x338kRKLCbZwWAdt/EoTuWpA4rhe88=;
        b=CEk7mhs5CogSrC766oQJ190NHSXDEcfH7VTnubg2WROvyZhavlTNiPvSH4ODNk4Iwc
         +Cjq0ZGf+9kdmM0GKkqVhUwzj19xdZ9PIa4N4zuIVuhTtu30JJL1/ZsvjKMLQO63Z1XP
         gfiN8GYgGC6HOM5zpUL0yeIEf1lgw/c+PZF3Um7FCuooAwhEnDkHBdV0vUS9xj61DHWb
         k2IV/wMePQm86f2D3+R0I0T9gjl+jUKR3vLmNRlAwmS8JqjrcjzNJ36GjFCmTdrXInCy
         TyD8WMgHDBQzRwWG/ggEUB1GLOjXXQXayFys998lDL3SZ8jdZq0Z1Z/9UhkMkdgMKYaa
         3/Rw==
X-Gm-Message-State: AOAM530zdolj1dKUAoJTC0ETDyEVi/FjpU0pCAhuETwl1ASS/K4hj6/o
	Dh9AUG02NGdCWndFQ9yiHyQ=
X-Google-Smtp-Source: ABdhPJzv2VOnydxWyi6U46qkGPqfeYYYWPKCRWS/t+7sLGVaz6golTZvQZcwbxJnEENklTJr4b8SfA==
X-Received: by 2002:a19:c68b:: with SMTP id w133mr1665018lff.189.1597426055053;
        Fri, 14 Aug 2020 10:27:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b4d3:: with SMTP id r19ls169750ljm.3.gmail; Fri, 14 Aug
 2020 10:27:34 -0700 (PDT)
X-Received: by 2002:a2e:b5d6:: with SMTP id g22mr1868274ljn.252.1597426054504;
        Fri, 14 Aug 2020 10:27:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426054; cv=none;
        d=google.com; s=arc-20160816;
        b=O1evOkQzjQQRKLls7PXzt3tNOVGyc9BaJgb6VNniLzHn72TIAnyq2M41iyt2NxshrW
         JPIqlRacuz8JnTDSq0uMKwrTNK4gyfp3aPb+yFM85OyMZBSNXUxg03+KYnnd+VgXjf8O
         8Y14waux8lgwKYp+gJ6QZjj+9/qhtIidJQ0Z/sCKY0OzZ9+9Cxw6FQ6F+R9qD3tMwecw
         mmqC6Ddgam8REdE+/BDYE1DkW9WZNGuymzSvrKFBr6kaYtvA8/tINqmB0yN0E+3g5Z8i
         oBttdg6Z9XQmcB19S+WRjkmPkWcRyd34mO4i/x4FrwIk9lHWsoZyMN+1v0bJxfIt5xNw
         Vkdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ZVI16BufIPnDakH6OwxgwWH/hspWExUAjZIdCIHvDJQ=;
        b=G4r9nG7JBK/G5JOEBuly2PKYlGxckC4WB5YuHKgDfcQAQYYjFPBJ65jJYpyWUFpnov
         3vBjJaL2I4GWFhY4PzXU3rGqQB/uVE9hJ10j+i61+C3c08Qr/9Q95erRhPcinZ/sdKEP
         rdKAdUI2Bovn1H5p5U21Qx30cOXx3WZcnGpLwC2+zl9JKJiSq2ubxmwf5TdV2soPARhN
         yzWHfEhRb/NRacdrN76I3+1SPXA9eAvKP9O+OG9qE9nmVI+W++xoM7bqu9S3I5hM4qT7
         Q+sna3Co4xViJiXYBPZvplBFBg9axwNJchzUJ4Q4HBTYsDuTeZafX5hnCQJDIUktccvJ
         zxyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=En5D1zMD;
       spf=pass (google.com: domain of 3hck2xwokcfiuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3hck2XwoKCfIUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 69si477535lfa.3.2020.08.14.10.27.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:27:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hck2xwokcfiuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id q15so3532489wmj.6
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:27:34 -0700 (PDT)
X-Received: by 2002:a7b:cd93:: with SMTP id y19mr424116wmj.0.1597426053539;
 Fri, 14 Aug 2020 10:27:33 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:26:46 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <eeb851f8f3898640d6e880d9fcabea8b580ee3d8.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 04/35] kasan: rename (un)poison_shadow to (un)poison_memory
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=En5D1zMD;       spf=pass
 (google.com: domain of 3hck2xwokcfiuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3hck2XwoKCfIUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

The new mode won't be using shadow memory, but will reuse the same
functions. Rename kasan_unpoison_shadow to kasan_unpoison_memory,
and kasan_poison_shadow to kasan_poison_memory.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h |  6 +++---
 kernel/fork.c         |  4 ++--
 mm/kasan/common.c     | 38 +++++++++++++++++++-------------------
 mm/kasan/generic.c    | 12 ++++++------
 mm/kasan/kasan.h      |  2 +-
 mm/kasan/tags.c       |  2 +-
 mm/slab_common.c      |  2 +-
 7 files changed, 33 insertions(+), 33 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 44a9aae44138..18617d5c4cd7 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -60,7 +60,7 @@ extern void kasan_enable_current(void);
 /* Disable reporting bugs for current task */
 extern void kasan_disable_current(void);
 
-void kasan_unpoison_shadow(const void *address, size_t size);
+void kasan_unpoison_memory(const void *address, size_t size);
 
 void kasan_unpoison_task_stack(struct task_struct *task);
 
@@ -97,7 +97,7 @@ struct kasan_cache {
 size_t __ksize(const void *);
 static inline void kasan_unpoison_slab(const void *ptr)
 {
-	kasan_unpoison_shadow(ptr, __ksize(ptr));
+	kasan_unpoison_memory(ptr, __ksize(ptr));
 }
 size_t kasan_metadata_size(struct kmem_cache *cache);
 
@@ -106,7 +106,7 @@ void kasan_restore_multi_shot(bool enabled);
 
 #else /* CONFIG_KASAN */
 
-static inline void kasan_unpoison_shadow(const void *address, size_t size) {}
+static inline void kasan_unpoison_memory(const void *address, size_t size) {}
 
 static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
diff --git a/kernel/fork.c b/kernel/fork.c
index c9c76a4d1180..c93e93cfbab8 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -224,8 +224,8 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
 		if (!s)
 			continue;
 
-		/* Clear the KASAN shadow of the stack. */
-		kasan_unpoison_shadow(s->addr, THREAD_SIZE);
+		/* Mark stack accessible for KASAN. */
+		kasan_unpoison_memory(s->addr, THREAD_SIZE);
 
 		/* Clear stale pointers from reused stack. */
 		memset(s->addr, 0, THREAD_SIZE);
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index d1c987f324cd..65933b27df81 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -113,7 +113,7 @@ void *memcpy(void *dest, const void *src, size_t len)
  * Poisons the shadow memory for 'size' bytes starting from 'addr'.
  * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
  */
-void kasan_poison_shadow(const void *address, size_t size, u8 value)
+void kasan_poison_memory(const void *address, size_t size, u8 value)
 {
 	void *shadow_start, *shadow_end;
 
@@ -130,7 +130,7 @@ void kasan_poison_shadow(const void *address, size_t size, u8 value)
 	__memset(shadow_start, value, shadow_end - shadow_start);
 }
 
-void kasan_unpoison_shadow(const void *address, size_t size)
+void kasan_unpoison_memory(const void *address, size_t size)
 {
 	u8 tag = get_tag(address);
 
@@ -141,7 +141,7 @@ void kasan_unpoison_shadow(const void *address, size_t size)
 	 */
 	address = reset_tag(address);
 
-	kasan_poison_shadow(address, size, tag);
+	kasan_poison_memory(address, size, tag);
 
 	if (size & KASAN_SHADOW_MASK) {
 		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
@@ -158,7 +158,7 @@ static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
 	void *base = task_stack_page(task);
 	size_t size = sp - base;
 
-	kasan_unpoison_shadow(base, size);
+	kasan_unpoison_memory(base, size);
 }
 
 /* Unpoison the entire stack for a task. */
@@ -177,7 +177,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 	 */
 	void *base = (void *)((unsigned long)watermark & ~(THREAD_SIZE - 1));
 
-	kasan_unpoison_shadow(base, watermark - base);
+	kasan_unpoison_memory(base, watermark - base);
 }
 
 void kasan_alloc_pages(struct page *page, unsigned int order)
@@ -191,13 +191,13 @@ void kasan_alloc_pages(struct page *page, unsigned int order)
 	tag = random_tag();
 	for (i = 0; i < (1 << order); i++)
 		page_kasan_tag_set(page + i, tag);
-	kasan_unpoison_shadow(page_address(page), PAGE_SIZE << order);
+	kasan_unpoison_memory(page_address(page), PAGE_SIZE << order);
 }
 
 void kasan_free_pages(struct page *page, unsigned int order)
 {
 	if (likely(!PageHighMem(page)))
-		kasan_poison_shadow(page_address(page),
+		kasan_poison_memory(page_address(page),
 				PAGE_SIZE << order,
 				KASAN_FREE_PAGE);
 }
@@ -289,18 +289,18 @@ void kasan_poison_slab(struct page *page)
 
 	for (i = 0; i < compound_nr(page); i++)
 		page_kasan_tag_reset(page + i);
-	kasan_poison_shadow(page_address(page), page_size(page),
+	kasan_poison_memory(page_address(page), page_size(page),
 			KASAN_KMALLOC_REDZONE);
 }
 
 void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
 {
-	kasan_unpoison_shadow(object, cache->object_size);
+	kasan_unpoison_memory(object, cache->object_size);
 }
 
 void kasan_poison_object_data(struct kmem_cache *cache, void *object)
 {
-	kasan_poison_shadow(object,
+	kasan_poison_memory(object,
 			round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE),
 			KASAN_KMALLOC_REDZONE);
 }
@@ -413,7 +413,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	}
 
 	rounded_up_size = round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE);
-	kasan_poison_shadow(object, rounded_up_size, KASAN_KMALLOC_FREE);
+	kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
 
 	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
 			unlikely(!(cache->flags & SLAB_KASAN)))
@@ -453,8 +453,8 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 		tag = assign_tag(cache, object, false, keep_tag);
 
 	/* Tag is ignored in set_tag without CONFIG_KASAN_SW_TAGS */
-	kasan_unpoison_shadow(set_tag(object, tag), size);
-	kasan_poison_shadow((void *)redzone_start, redzone_end - redzone_start,
+	kasan_unpoison_memory(set_tag(object, tag), size);
+	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
 		KASAN_KMALLOC_REDZONE);
 
 	if (cache->flags & SLAB_KASAN)
@@ -494,8 +494,8 @@ void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
 				KASAN_SHADOW_SCALE_SIZE);
 	redzone_end = (unsigned long)ptr + page_size(page);
 
-	kasan_unpoison_shadow(ptr, size);
-	kasan_poison_shadow((void *)redzone_start, redzone_end - redzone_start,
+	kasan_unpoison_memory(ptr, size);
+	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
 		KASAN_PAGE_REDZONE);
 
 	return (void *)ptr;
@@ -528,7 +528,7 @@ void kasan_poison_kfree(void *ptr, unsigned long ip)
 			kasan_report_invalid_free(ptr, ip);
 			return;
 		}
-		kasan_poison_shadow(ptr, page_size(page), KASAN_FREE_PAGE);
+		kasan_poison_memory(ptr, page_size(page), KASAN_FREE_PAGE);
 	} else {
 		__kasan_slab_free(page->slab_cache, ptr, ip, false);
 	}
@@ -714,7 +714,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	 * // vmalloc() allocates memory
 	 * // let a = area->addr
 	 * // we reach kasan_populate_vmalloc
-	 * // and call kasan_unpoison_shadow:
+	 * // and call kasan_unpoison_memory:
 	 * STORE shadow(a), unpoison_val
 	 * ...
 	 * STORE shadow(a+99), unpoison_val	x = LOAD p
@@ -749,7 +749,7 @@ void kasan_poison_vmalloc(const void *start, unsigned long size)
 		return;
 
 	size = round_up(size, KASAN_SHADOW_SCALE_SIZE);
-	kasan_poison_shadow(start, size, KASAN_VMALLOC_INVALID);
+	kasan_poison_memory(start, size, KASAN_VMALLOC_INVALID);
 }
 
 void kasan_unpoison_vmalloc(const void *start, unsigned long size)
@@ -757,7 +757,7 @@ void kasan_unpoison_vmalloc(const void *start, unsigned long size)
 	if (!is_vmalloc_or_module_addr(start))
 		return;
 
-	kasan_unpoison_shadow(start, size);
+	kasan_unpoison_memory(start, size);
 }
 
 static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 248264b9cb76..4b5f905198d8 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -207,9 +207,9 @@ static void register_global(struct kasan_global *global)
 {
 	size_t aligned_size = round_up(global->size, KASAN_SHADOW_SCALE_SIZE);
 
-	kasan_unpoison_shadow(global->beg, global->size);
+	kasan_unpoison_memory(global->beg, global->size);
 
-	kasan_poison_shadow(global->beg + aligned_size,
+	kasan_poison_memory(global->beg + aligned_size,
 		global->size_with_redzone - aligned_size,
 		KASAN_GLOBAL_REDZONE);
 }
@@ -290,11 +290,11 @@ void __asan_alloca_poison(unsigned long addr, size_t size)
 
 	WARN_ON(!IS_ALIGNED(addr, KASAN_ALLOCA_REDZONE_SIZE));
 
-	kasan_unpoison_shadow((const void *)(addr + rounded_down_size),
+	kasan_unpoison_memory((const void *)(addr + rounded_down_size),
 			      size - rounded_down_size);
-	kasan_poison_shadow(left_redzone, KASAN_ALLOCA_REDZONE_SIZE,
+	kasan_poison_memory(left_redzone, KASAN_ALLOCA_REDZONE_SIZE,
 			KASAN_ALLOCA_LEFT);
-	kasan_poison_shadow(right_redzone,
+	kasan_poison_memory(right_redzone,
 			padding_size + KASAN_ALLOCA_REDZONE_SIZE,
 			KASAN_ALLOCA_RIGHT);
 }
@@ -306,7 +306,7 @@ void __asan_allocas_unpoison(const void *stack_top, const void *stack_bottom)
 	if (unlikely(!stack_top || stack_top > stack_bottom))
 		return;
 
-	kasan_unpoison_shadow(stack_top, stack_bottom - stack_top);
+	kasan_unpoison_memory(stack_top, stack_bottom - stack_top);
 }
 EXPORT_SYMBOL(__asan_allocas_unpoison);
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index ac499456740f..03450d3b31f7 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -150,7 +150,7 @@ static inline bool addr_has_shadow(const void *addr)
 	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
 }
 
-void kasan_poison_shadow(const void *address, size_t size, u8 value);
+void kasan_poison_memory(const void *address, size_t size, u8 value);
 
 /**
  * check_memory_region - Check memory region, and report if invalid access.
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index e02a36a51f42..4d5a1fe8251f 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -158,7 +158,7 @@ EXPORT_SYMBOL(__hwasan_storeN_noabort);
 
 void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
 {
-	kasan_poison_shadow((void *)addr, size, tag);
+	kasan_poison_memory((void *)addr, size, tag);
 }
 EXPORT_SYMBOL(__hwasan_tag_memory);
 
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 37d48a56431d..24bbf3704a51 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1772,7 +1772,7 @@ size_t ksize(const void *objp)
 	 * We assume that ksize callers could use whole allocated area,
 	 * so we need to unpoison this area.
 	 */
-	kasan_unpoison_shadow(objp, size);
+	kasan_unpoison_memory(objp, size);
 	return size;
 }
 EXPORT_SYMBOL(ksize);
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/eeb851f8f3898640d6e880d9fcabea8b580ee3d8.1597425745.git.andreyknvl%40google.com.
