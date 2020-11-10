Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCFAVT6QKGQERRIYFUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C4C72AE2AC
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:11:22 +0100 (CET)
Received: by mail-vs1-xe3c.google.com with SMTP id g3sf5067635vso.1
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:11:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046281; cv=pass;
        d=google.com; s=arc-20160816;
        b=dfASPPizE1DKEC194p4/840YBwbyN6cdJXIQaLrIVKaK3TkhImldiBC05jQagAfpfC
         s1gyUMm+2zVY/QVhdRUEp4qLFapQtZIzXP7nisZPMIotTX7k05njnrkGanpevAr3tO/Y
         L+C+81XhSYZqnRuzuVUuJPWXnc5O98rCzjrTPc3UH1ab/YDYXG4YriuEmhl/ubaLQqvI
         KF67m/WeKFrHRjMqPt9VEDQmr7ed2wjXpsDG+vvHZNkDvVaoZW4ZMgqb66HIyF8eX4fc
         tAKICuEwcl8blIwJetHfbJUzBBPw3Cbblk5JaxLIHajiW/5SpGD+yHujr5/UlkuAkJ+Z
         heEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=qiyd1Q1aq2NO3/AamkkYec7Un3ueuP/GWIfO6JN022Y=;
        b=E/NL/p3QlYEsVXBnywoCBQeDPaPuR+Jlh/KZ4lhAvFFXxDfTl8aVq8hVrS7u7DFGSa
         I4e+Pvk5n/jXQCgc7dfbo9SbCQg6oj+NZgpKrR17RIZKtXWVGLXvxZSl4wjkDEYds1B5
         ge7ibzPEfTWh0GL+jUwpz/NqLgYnrMPewXRAiEWbpp8fVcR+0c1WYqEgLmCsih2Pb/99
         6r8nPt0ukNv85EdkWA6p1B/h3VZKBPPXODQEI0BT0W5D3sSwi4uLzAtETP10ysC08wGU
         ygolqweELM0Avb0sGMY+KyHVjcJr0NGO68n5h0BGexTRwRshl/StcOEAfXcb4iigmWYp
         whuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vAMGIn8X;
       spf=pass (google.com: domain of 3bxcrxwokcdy2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3BxCrXwoKCdY2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qiyd1Q1aq2NO3/AamkkYec7Un3ueuP/GWIfO6JN022Y=;
        b=gjSQIIW0fxMQJSjdXR91Q6Ei4mKAH5VU+V/gWKAGcAHEx4G/OWU67QyHh4T+bcJ+JR
         rz5QjesCD9Ww0dO5osnMxhDJuo1EpD+HUCJAoANY/Dk22tT3lb5srNCH4njC1xE13lzV
         uTh4YcvnNk6JpYrbWFp48dlqVxsTYEYfTFQcnLTBf28M7433+nTkzgTxCLNIqS9FKBwi
         lgZxvd3kMPETZ9NW60ssybz2I9bWZaefrBbn2NIrLaI9pPA1aZCuZ6t51q0fIAz8TD6Q
         plF2CRLI1YUjM+N6bX2YscRBT9QXbODrpZOZoNt+/B4EHNb1DZEiNmoyzluxRPVumwsO
         mE9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qiyd1Q1aq2NO3/AamkkYec7Un3ueuP/GWIfO6JN022Y=;
        b=ZrE5OvyfEQgnDGrmbG2B6gsmz9OT6m2BnfoyY00YrIrVtaeCYmql51+YoGfJ2EjT5l
         xz5qSHGYYSd1kpl3dwMckidwdp1dWGgWFstHuwtjBT88a0joVGeYEnYUsY/Y+C5oQXFY
         wP03K14TsJq+BlWC+1YTUqLReAwt8yg+pF8QbtUWGlfnyatAsnTvnNTtHkARB1k7NUzs
         TbMRTFu0ybTNZ18lVWmCg0HNR1gLyMi9SOafmdqy60A7g0Sln613AoFGhueCI4zHafVf
         rpp9BMWw2RdDLzpy4szxmFlJovFcRDGlV7xe5Irw7Etq+NkU1352sxyHboeoPwQGIqce
         KzMQ==
X-Gm-Message-State: AOAM531pwDxetiEinaLkcUMqsjKyVP9K+sq6ltj9DKy4q6PmVP5XzMQb
	3/0QzQsfCek0MiZ7Fwc/oMo=
X-Google-Smtp-Source: ABdhPJxRJiNIbUA5NTzNNc7Glqb9s9WnZ5ozBd7vGzsaHlVNF65Emb1BDIKIWbRUjKv8zTHpKEmxjg==
X-Received: by 2002:ab0:31:: with SMTP id 46mr11822005uai.131.1605046281047;
        Tue, 10 Nov 2020 14:11:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:2046:: with SMTP id q6ls1670305vsr.3.gmail; Tue, 10
 Nov 2020 14:11:20 -0800 (PST)
X-Received: by 2002:a67:ce84:: with SMTP id c4mr13636013vse.26.1605046280503;
        Tue, 10 Nov 2020 14:11:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046280; cv=none;
        d=google.com; s=arc-20160816;
        b=d+93iUOhVpVvQiGqhnjyAL7spC7QRxy1P7hvEG+EY0k2fsKXdgf2TKxoe4c0YclOuA
         iqrkI5eJXZ2myo8FP9yINheal99XGJIQW7LMRzB74jzqktA836T6X3BO6QYB6zS+NhGf
         RAyuVfKqDb4no0mGwJPQMagBjKtE0w6a6PdKhEIzlCci9EAQVp0M1GPai6pHr0yVdXou
         IQskowNgDagEPgQgvLSHMFgIl8GAsmtgtlvKh7XUIdey9ndBfc41TWQvD98FUwFyqHKu
         r89tHdQzFmapqc6B76prw+ewXNCuLmjamTPXhb7WCwfwV+M4Pvbq7IvH0oIhjtyLbWQJ
         7gug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=NWvE+SnfL3RmSUtgoxKsMdIo3OVmFhGhpj0hSfapO9M=;
        b=IMNNxx9RNOyUpVwmpLZQLSWAOx6pQAacnRJn91H7ooJoqsd+1xzt4fGG/u31LOElBo
         B2PLX7pfbCgzqxVdBampeU303wkEucCsY5HEAXP9drvcp0jaSeYzAbEq7wt6sIhyIXbo
         KXZta0W9C+06r9YsnpeCdB2fCa+WrhhArg/X24ZoadloZZl/vWZbehxnMc+RApqTEi9T
         gnizpQZ//BdSkwHtyllRijtnRS4TimPiBMtlbH4Ci0NHCTeAtGkToLCDmpH32DzpNTED
         qmUMM+O1xuCeXG7JFdTxwuh3+2QIXID3FVtfn2r3IaO0q5Vtn/fKO0ED6Bp6Onv8c1q3
         /FDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vAMGIn8X;
       spf=pass (google.com: domain of 3bxcrxwokcdy2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3BxCrXwoKCdY2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id b16si16592vkn.5.2020.11.10.14.11.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:20 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bxcrxwokcdy2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id k5so53202qvu.10
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:20 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:80e1:: with SMTP id
 88mr21836794qvb.10.1605046279998; Tue, 10 Nov 2020 14:11:19 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:03 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <f26e54bcfe216118762632ecde260a5f6c605594.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 06/44] kasan: rename (un)poison_shadow to (un)poison_memory
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
 header.i=@google.com header.s=20161025 header.b=vAMGIn8X;       spf=pass
 (google.com: domain of 3bxcrxwokcdy2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3BxCrXwoKCdY2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
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
index 26f2ab92e7ca..f6435b9f889c 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -71,7 +71,7 @@ extern void kasan_enable_current(void);
 /* Disable reporting bugs for current task */
 extern void kasan_disable_current(void);
 
-void kasan_unpoison_shadow(const void *address, size_t size);
+void kasan_unpoison_memory(const void *address, size_t size);
 
 void kasan_unpoison_task_stack(struct task_struct *task);
 
@@ -108,7 +108,7 @@ struct kasan_cache {
 size_t __ksize(const void *);
 static inline void kasan_unpoison_slab(const void *ptr)
 {
-	kasan_unpoison_shadow(ptr, __ksize(ptr));
+	kasan_unpoison_memory(ptr, __ksize(ptr));
 }
 size_t kasan_metadata_size(struct kmem_cache *cache);
 
@@ -117,7 +117,7 @@ void kasan_restore_multi_shot(bool enabled);
 
 #else /* CONFIG_KASAN */
 
-static inline void kasan_unpoison_shadow(const void *address, size_t size) {}
+static inline void kasan_unpoison_memory(const void *address, size_t size) {}
 
 static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
diff --git a/kernel/fork.c b/kernel/fork.c
index 6d266388d380..1c905e4290ab 100644
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f26e54bcfe216118762632ecde260a5f6c605594.1605046192.git.andreyknvl%40google.com.
