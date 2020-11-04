Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6PNRT6QKGQEUSNSETA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B3A42A7115
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:22 +0100 (CET)
Received: by mail-vs1-xe39.google.com with SMTP id g5sf80445vsg.14
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531961; cv=pass;
        d=google.com; s=arc-20160816;
        b=RG/7abQcNMSTuwG71eV8KsOkMfvXNor4lkQ53NPKFuC8IyU9/XSibG1DHkIYITTVKB
         nVgzn85kVq9Yxf1k7Woq4HLSiiiSdwptyDZWWVuUXQNnM/rv7yiDPsHMIAKKQq7/mMGK
         Xj54PTAZfklXnnxGTdqAN5DHrT/YICpPUD2pZypcJAcaK9D6biUmS36Dm8kOgAFToo+E
         8fQeEKOJFelptDgWMQ/x62ZOka8aNQx49LPPQzIHxyf6TN2OQKAY353ej136VLeiOOeB
         p5MXwsmkUsnunpraHGR32nrSCG08yBA27LJ567wJ+PzweIQmUzmRrMNg4+vTFFVNsyOo
         UbMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ID1aOem3FUnwmc/WgQwmF/d3KTLjUiTD5axdxCZWiFE=;
        b=ZSXSffTg90hLPmaNBTEPqcpuvt1Ue9oBd0dAg5A1G1dSunM0y6iV0LPrkWiwD9t1+z
         jwoZFWmMIWQGUed27sHt+D10P9F+KSKQd+vLp6t9r26d+ttO9y8aNG4JWKXb6N++FqL6
         N2oRQ17rrAL5XsCSqLXAZvM7tZF+UrNafgNqa9jPGCLQUYiEt8CcpkXJuZQVXTsNZo+v
         8mVA7kQAv+TLJH7i6ysYW5L8HcYUGuJo/VeIgYzIwyuczXX7ZF8R0hP7Uk2RjFs7iFwA
         CMQ2D4E/PXI7OtDrYIJ9x0bGrzAKkDSRKhOBAkFOzihJuDuEwJrTqqvN6qfbr1ndziXw
         P+Yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FVJR2Wqf;
       spf=pass (google.com: domain of 3-dajxwokcfuxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3-DajXwoKCfUXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ID1aOem3FUnwmc/WgQwmF/d3KTLjUiTD5axdxCZWiFE=;
        b=TvYXvRUllSegOsb6j3j3bY/VR3X8gJZrC/pGO0sIoRyFx1IgiLUOmpRTK2yPOM8bMk
         o1b2ebqFcC6I23r48953vAkv9go5KTvoy+ykURV96I25t8AAy6fq09kb3RqizLCU+BGN
         A3ghFpVpLKHDYobJV2pixw+3pEInFr0H2egK4WT+XGtfjo6D2euqHJtt7/wLjXLm+NOT
         8Y5yAkKknGlfOBHExxpN3sNyyYMIzUAlnDWjVDBaDX4XQYL9FrQr2KtmBpRg5a0gZCPh
         Sh9Ban3vFpmf0tgWoc1PHVkFuej/TEla1m58IKSR2ofejVAgnjROdHPEMq4Mz+9J8fbr
         1E5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ID1aOem3FUnwmc/WgQwmF/d3KTLjUiTD5axdxCZWiFE=;
        b=kla/sUBrn0KdB1ObU+qO6t/e7CwVm0vD+P55RR1H2jZ2ngobBi6uwWJ1Wm/Y+cG2Xw
         19OIuu/fc2dERnj4YPiGJ/Mdqq+I1p0qNJQaEjDCZPI2eTfcQHLcaaBgA9OFbS38f4FG
         Reh0H98F1AfkRQ8u6Vs3PNfgbAsUlGaX8EklAV4S9ywWfm5FTRdGKVHqh6clnE2pOyf2
         SGlyl9rRSZsOQ28nB3LwnQj8jYq2sfg8/wFfDhgPs1t9nBBGN44F8akUE48ebVY//6OW
         ThDT1mKxGyGvv92zdBnBxSQgckqDwVS0TZ6UliA9j8L6TzNxBGADPhq7O0ukefmcAPCk
         NusQ==
X-Gm-Message-State: AOAM533OyFpOW6uvmvhxwP2deFUU2DeR7wQBUVkQYsMIpY0qNuUtwcUz
	HHHkoOtvNsa/cfPj2lFF/Fs=
X-Google-Smtp-Source: ABdhPJzxLZ+GUwfe7Ox/lAkRWRX8rnfpP9hDdUlefGOiMePcZ+rFEqcgCrQuhlnPonqYmuypkjG73A==
X-Received: by 2002:a67:db91:: with SMTP id f17mr125469vsk.41.1604531961400;
        Wed, 04 Nov 2020 15:19:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:874b:: with SMTP id j72ls510870vsd.9.gmail; Wed, 04 Nov
 2020 15:19:20 -0800 (PST)
X-Received: by 2002:a05:6102:7c9:: with SMTP id y9mr326242vsg.49.1604531960891;
        Wed, 04 Nov 2020 15:19:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531960; cv=none;
        d=google.com; s=arc-20160816;
        b=zb2yVov1bHyIikiE4Co0QeCz1Y935tS79xgFxP/PCjSITcPQFrJugnD+RVBVsHMzm3
         xXs4HOP5aU+U0RMammyZ8zbIUSBQ80fhugTGWKNeoIZkcgzh95qHj1EKvXYsWTm80t7m
         gNLL7nwpa3lW4IOhO8OYqofRERtFTLZAkyNlG3lQQWidFZovGtfZeRlPSc+AL7oZq7+1
         Kx+beVBK+tzk45lF8zCDqNWHjIh+8S0KTU+SLBZU1k+R2EQYXk1HWGqiHVrvgleXuyas
         mF/shjlCIeWLzXTt5er2tJUaq9cIQ5P02CaWGs80hTdIuvcNwqbwlRqW/k7o8SlC/Tl2
         CquQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=+iowLgVGeQzDkVT2EtZJP7se5REovGWsQCbGnQ4Vm4k=;
        b=WLIHgpVoP3Zk1V4GYjj8BcfRW5tSczNyryGa0FrdHha0yJ8rnrKQ67YutKWr7yd7i0
         /SXVTW8P+la8Z7Vwf6wYyfDS9APcBjX1AKq+GLl7SeRKj5hMwv6FITpsZ9jGoDOy5jk0
         7QefMfXrrsscXPH2sRdHi8kyyNK5FoOnJJwOwcKcccIMoWf2Y2fl8DjmRKDwVxjAoc2g
         GbBLBe5CaUZbi+MhuVV5EAM+SUvF8T15x+uhdRqy59EG/7qvVH6wR3rF1PBuvwJ6VSn2
         o5J2B0Zi5mW+fa9QEr6jIZa7HY8PwDAxsFp0LMR5cJu3VE3nQKS46C03EUv/yuwr7vOS
         APnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FVJR2Wqf;
       spf=pass (google.com: domain of 3-dajxwokcfuxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3-DajXwoKCfUXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id v18si264055vkn.4.2020.11.04.15.19.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:20 -0800 (PST)
Received-SPF: pass (google.com: domain of 3-dajxwokcfuxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id k12so14452964qkj.18
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:20 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5448:: with SMTP id
 h8mr140120qvt.49.1604531960390; Wed, 04 Nov 2020 15:19:20 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:21 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <8c5c57103083a98975d2af537bf82d178117519b.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 06/43] kasan: rename (un)poison_shadow to (un)poison_memory
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FVJR2Wqf;       spf=pass
 (google.com: domain of 3-dajxwokcfuxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3-DajXwoKCfUXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
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
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: Ia359f32815242c4704e49a5f1639ca2d2f8cba69
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
index 45345dd5cfd6..bfb21d5fd279 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -69,7 +69,7 @@ extern void kasan_enable_current(void);
 /* Disable reporting bugs for current task */
 extern void kasan_disable_current(void);
 
-void kasan_unpoison_shadow(const void *address, size_t size);
+void kasan_unpoison_memory(const void *address, size_t size);
 
 void kasan_unpoison_task_stack(struct task_struct *task);
 
@@ -106,7 +106,7 @@ struct kasan_cache {
 size_t __ksize(const void *);
 static inline void kasan_unpoison_slab(const void *ptr)
 {
-	kasan_unpoison_shadow(ptr, __ksize(ptr));
+	kasan_unpoison_memory(ptr, __ksize(ptr));
 }
 size_t kasan_metadata_size(struct kmem_cache *cache);
 
@@ -115,7 +115,7 @@ void kasan_restore_multi_shot(bool enabled);
 
 #else /* CONFIG_KASAN */
 
-static inline void kasan_unpoison_shadow(const void *address, size_t size) {}
+static inline void kasan_unpoison_memory(const void *address, size_t size) {}
 
 static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
diff --git a/kernel/fork.c b/kernel/fork.c
index 32083db7a2a2..463ef51f2b05 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -225,8 +225,8 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
 		if (!s)
 			continue;
 
-		/* Clear the KASAN shadow of the stack. */
-		kasan_unpoison_shadow(s->addr, THREAD_SIZE);
+		/* Mark stack accessible for KASAN. */
+		kasan_unpoison_memory(s->addr, THREAD_SIZE);
 
 		/* Clear stale pointers from reused stack. */
 		memset(s->addr, 0, THREAD_SIZE);
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 89e5ef9417a7..a4b73fa0dd7e 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -108,7 +108,7 @@ void *memcpy(void *dest, const void *src, size_t len)
  * Poisons the shadow memory for 'size' bytes starting from 'addr'.
  * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
  */
-void kasan_poison_shadow(const void *address, size_t size, u8 value)
+void kasan_poison_memory(const void *address, size_t size, u8 value)
 {
 	void *shadow_start, *shadow_end;
 
@@ -125,7 +125,7 @@ void kasan_poison_shadow(const void *address, size_t size, u8 value)
 	__memset(shadow_start, value, shadow_end - shadow_start);
 }
 
-void kasan_unpoison_shadow(const void *address, size_t size)
+void kasan_unpoison_memory(const void *address, size_t size)
 {
 	u8 tag = get_tag(address);
 
@@ -136,7 +136,7 @@ void kasan_unpoison_shadow(const void *address, size_t size)
 	 */
 	address = reset_tag(address);
 
-	kasan_poison_shadow(address, size, tag);
+	kasan_poison_memory(address, size, tag);
 
 	if (size & KASAN_SHADOW_MASK) {
 		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
@@ -153,7 +153,7 @@ static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
 	void *base = task_stack_page(task);
 	size_t size = sp - base;
 
-	kasan_unpoison_shadow(base, size);
+	kasan_unpoison_memory(base, size);
 }
 
 /* Unpoison the entire stack for a task. */
@@ -172,7 +172,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 	 */
 	void *base = (void *)((unsigned long)watermark & ~(THREAD_SIZE - 1));
 
-	kasan_unpoison_shadow(base, watermark - base);
+	kasan_unpoison_memory(base, watermark - base);
 }
 
 void kasan_alloc_pages(struct page *page, unsigned int order)
@@ -186,13 +186,13 @@ void kasan_alloc_pages(struct page *page, unsigned int order)
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
@@ -284,18 +284,18 @@ void kasan_poison_slab(struct page *page)
 
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
@@ -408,7 +408,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	}
 
 	rounded_up_size = round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE);
-	kasan_poison_shadow(object, rounded_up_size, KASAN_KMALLOC_FREE);
+	kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
 
 	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
 			unlikely(!(cache->flags & SLAB_KASAN)))
@@ -448,8 +448,8 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 		tag = assign_tag(cache, object, false, keep_tag);
 
 	/* Tag is ignored in set_tag without CONFIG_KASAN_SW_TAGS */
-	kasan_unpoison_shadow(set_tag(object, tag), size);
-	kasan_poison_shadow((void *)redzone_start, redzone_end - redzone_start,
+	kasan_unpoison_memory(set_tag(object, tag), size);
+	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
 		KASAN_KMALLOC_REDZONE);
 
 	if (cache->flags & SLAB_KASAN)
@@ -489,8 +489,8 @@ void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
 				KASAN_SHADOW_SCALE_SIZE);
 	redzone_end = (unsigned long)ptr + page_size(page);
 
-	kasan_unpoison_shadow(ptr, size);
-	kasan_poison_shadow((void *)redzone_start, redzone_end - redzone_start,
+	kasan_unpoison_memory(ptr, size);
+	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
 		KASAN_PAGE_REDZONE);
 
 	return (void *)ptr;
@@ -523,7 +523,7 @@ void kasan_poison_kfree(void *ptr, unsigned long ip)
 			kasan_report_invalid_free(ptr, ip);
 			return;
 		}
-		kasan_poison_shadow(ptr, page_size(page), KASAN_FREE_PAGE);
+		kasan_poison_memory(ptr, page_size(page), KASAN_FREE_PAGE);
 	} else {
 		__kasan_slab_free(page->slab_cache, ptr, ip, false);
 	}
@@ -709,7 +709,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	 * // vmalloc() allocates memory
 	 * // let a = area->addr
 	 * // we reach kasan_populate_vmalloc
-	 * // and call kasan_unpoison_shadow:
+	 * // and call kasan_unpoison_memory:
 	 * STORE shadow(a), unpoison_val
 	 * ...
 	 * STORE shadow(a+99), unpoison_val	x = LOAD p
@@ -744,7 +744,7 @@ void kasan_poison_vmalloc(const void *start, unsigned long size)
 		return;
 
 	size = round_up(size, KASAN_SHADOW_SCALE_SIZE);
-	kasan_poison_shadow(start, size, KASAN_VMALLOC_INVALID);
+	kasan_poison_memory(start, size, KASAN_VMALLOC_INVALID);
 }
 
 void kasan_unpoison_vmalloc(const void *start, unsigned long size)
@@ -752,7 +752,7 @@ void kasan_unpoison_vmalloc(const void *start, unsigned long size)
 	if (!is_vmalloc_or_module_addr(start))
 		return;
 
-	kasan_unpoison_shadow(start, size);
+	kasan_unpoison_memory(start, size);
 }
 
 static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 37ccfadd3263..7006157c674b 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -202,9 +202,9 @@ static void register_global(struct kasan_global *global)
 {
 	size_t aligned_size = round_up(global->size, KASAN_SHADOW_SCALE_SIZE);
 
-	kasan_unpoison_shadow(global->beg, global->size);
+	kasan_unpoison_memory(global->beg, global->size);
 
-	kasan_poison_shadow(global->beg + aligned_size,
+	kasan_poison_memory(global->beg + aligned_size,
 		global->size_with_redzone - aligned_size,
 		KASAN_GLOBAL_REDZONE);
 }
@@ -285,11 +285,11 @@ void __asan_alloca_poison(unsigned long addr, size_t size)
 
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
@@ -301,7 +301,7 @@ void __asan_allocas_unpoison(const void *stack_top, const void *stack_bottom)
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
index 5c8b08a25715..4bdd7dbd6647 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -153,7 +153,7 @@ EXPORT_SYMBOL(__hwasan_storeN_noabort);
 
 void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
 {
-	kasan_poison_shadow((void *)addr, size, tag);
+	kasan_poison_memory((void *)addr, size, tag);
 }
 EXPORT_SYMBOL(__hwasan_tag_memory);
 
diff --git a/mm/slab_common.c b/mm/slab_common.c
index f9ccd5dc13f3..53d0f8bb57ea 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1176,7 +1176,7 @@ size_t ksize(const void *objp)
 	 * We assume that ksize callers could use whole allocated area,
 	 * so we need to unpoison this area.
 	 */
-	kasan_unpoison_shadow(objp, size);
+	kasan_unpoison_memory(objp, size);
 	return size;
 }
 EXPORT_SYMBOL(ksize);
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8c5c57103083a98975d2af537bf82d178117519b.1604531793.git.andreyknvl%40google.com.
