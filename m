Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4VO5T6AKGQE57YEGEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FFB129F4F0
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:43 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id 17sf1556325oie.4
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999602; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ic8UrF5cxlKiN+isHex47Wt7/cZUGfiNMawcaSYoy7q52OFcKCB46RvxtbJCmdRaJ3
         puo2DSHwnI5TYn41XTPj49vMiimdAIdLkTTHzpyM7+dg9SVdHoqeQeZkDvLdLI0VVpbN
         cWvFr6l19SBroiuLwgc+9WFb3fdlHq53aqTlRynHdAydRvd0nwH3lmg807H4hZ4oxfne
         nS7s7SP/wY8u4RwduDJ5Fq3niw9cmDNG8Hg6Xmg+lYnqKq5WM253VXwECPnquNyhu91x
         jrJkT6zYIVQDa9yD6Jg3CQVrycyHcSByW2ETnmMd+IYxs8t/THIFkS2/+/oTLp2vDBv8
         F3jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ZLpfUZPg13bjGK6wCati4oNUrvtx70EHsnVisq/WpZQ=;
        b=Ra7C9mj3WohVWeEorkXtDEXN8YV2o9aDDeNPLPodc20EuSQIxnXdKdmkiQ95DetAU+
         axng9l175neWSQRExzQ7QA0O8EEUHuSM5hsHZkjsuebLf+rbvSejv7ZA/JoEuslBkJPl
         0aWj0Q+qV0ryhCj5sZ/K6szmrljiCdeH82ao2jWE36CyE2+fGkhI7JCjP8ve5ctYI/HV
         Aro7WXp5CvbmIhCMGqM7c7A9eCUjUjdxPQfMrIFwDjtjHYTsCngTjzbptekTkodF7x+8
         fKhBrAobgWfwDDkH6bM8I7JdiLnjBip5n9iwDq59sIeXvaGxXnjuvD6LMssaTT2fbTne
         z4Mg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sNL2UsOS;
       spf=pass (google.com: domain of 3crebxwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3cRebXwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZLpfUZPg13bjGK6wCati4oNUrvtx70EHsnVisq/WpZQ=;
        b=OuShITTFHTCfdRtVCcqhs3cQxBUgg83Q0pqYw9B5crqzY5ulMMioI6048PoTy02X8e
         KAk9qrvqWLfLLX/msoMVOhsMoKfPnOn0no/6nsTfgzsPZUI1p4/yVgGAnaKFmcEkzbxL
         cECmgToi3erFvPyK1TeclqML/W+b6pJyvuwVSRzCxG64mI7JAkmnc5ojqckpd8TNfscs
         qsYiSPIle1zp1RdkaeRb9tIshw7b9rLx4PK5aejCe2SZE12VBQ82HcqhCCE9F4fdeBVw
         o5f2w/lE3LRxCy2/O6l+ZihgLRzzL12D3iwWk0PCHJNrLHfa3wmUCfgea5A9cDVa3iJa
         yw1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZLpfUZPg13bjGK6wCati4oNUrvtx70EHsnVisq/WpZQ=;
        b=mC5VhgrxGSd8TG2sueuQvYB5F6MCkARh8OeVph8xX76/HEnHNkSHm1jo2ZqprnuqyA
         cNvvnzAfQVobT8CAH80jgwYciwyCz9fVJAcXnpEOGe3SX+c0UktNeSBwqmV7v614T/bu
         SiTryq1cN6a56yIkMDAdtS4aT5zKmdUik2ciONE3ycTGJlpKrsEdQQF6XL5Mzj9qD/FA
         RTDENr6Gy2bNgWNRZRCe69HYuRkjdfQM0cwOT5YHTmxynsT7Ge11XI5iV9JnMjvu4LxY
         UQqxEPcKwU+0SeGD8QhsN+kK6Dh8dFQuglEXDHYzYFO46uHZbk/6fwly3MS0TarRijdJ
         OG0Q==
X-Gm-Message-State: AOAM5330xoLEI01zvnL9uwpWn3ny+O8ENXZuUBjjRihpkU6AoO1jJ85I
	tIFwEYhAihyeRQDy5moqF80=
X-Google-Smtp-Source: ABdhPJxzaxAITfjQ7eA7ECUsSry0WmqkgoganvmFAR1wbPYf7Xbu9eY2frtRK8DumOVYFwVQrLG8NA==
X-Received: by 2002:a9d:2389:: with SMTP id t9mr4118646otb.329.1603999602554;
        Thu, 29 Oct 2020 12:26:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5283:: with SMTP id g125ls939654oib.9.gmail; Thu, 29 Oct
 2020 12:26:42 -0700 (PDT)
X-Received: by 2002:aca:7255:: with SMTP id p82mr866671oic.95.1603999602187;
        Thu, 29 Oct 2020 12:26:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999602; cv=none;
        d=google.com; s=arc-20160816;
        b=A7O5AhRt2L5GcRkK6uDenlh9aLqeKlIewXaLhhohpLoSA/6BSJ+1PRv/VI7twWxqw8
         o6Iw0ai3XSap1F3TD0iTsurqxP77LAqMdmMRStolpzt032KGPvTYBbLHIvF43Lnp60iw
         qZt9MpH2VoDJpb2rY1/p27qnhqSlhpfSBUGavt7EN9Jq5yc3vjLtyCSdGX/Fw+7ojHhL
         Nh8gaohfqkTL2FDyUGKSiNycslsT38Z+J7dF2MhYDdtMSCgcYUAb4RIvE41DNaroknUr
         r4S19ZVJUNyhH9Ea4iv+FmbzLfk+S6afs38fzgMGmqfB4moyva2haAcGYeq2yJG3kpCq
         8BYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ZuZ67cvqdZ21/eXkLupxFcvMCBQVkvS/k3/Rt8jNsMM=;
        b=IP+Skx6ZdBSl5q9NqZZzgPkd7DSTeXknb+KeZKL4ToHn0ckLiY4qCjFenPhK4sUqQd
         x9B7nxv78uQicDJUCCaaRSk0GZoS9B5KrjTZig9MhaVWyMoXcGhu48O/7Aai0Ps75ZWB
         LpnKnWVoiBh16wI9jBm20pod3bMJ5JcizzsSjpRWS8B1CnJ/lTdQctlfrudfUrYPX1vB
         v2DA9Q8qpAiOvOnnFUxCDd2lU2kbMEhehJJ8mtRioS2eFWjDGxIL77I24qO4mGzbXrFs
         rVurPUSwudlfaf5/DANiPFB+YIOljrq0I6TZ5ubVcOrIy10H7tTOCcWzXqLijotx7F9u
         NwQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sNL2UsOS;
       spf=pass (google.com: domain of 3crebxwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3cRebXwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id w26si258255oih.1.2020.10.29.12.26.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3crebxwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id k12so2416361qkj.18
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:42 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:1192:: with SMTP id
 t18mr5859327qvv.49.1603999601624; Thu, 29 Oct 2020 12:26:41 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:35 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <d9ef0193834f49b059f55eaf7970d63c44be5734.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 14/40] kasan: rename (un)poison_shadow to (un)poison_memory
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sNL2UsOS;       spf=pass
 (google.com: domain of 3crebxwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3cRebXwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
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
index 633f8902e5e2..01b943bd49c8 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d9ef0193834f49b059f55eaf7970d63c44be5734.1603999489.git.andreyknvl%40google.com.
