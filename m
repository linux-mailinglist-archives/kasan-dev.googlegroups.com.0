Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQFN6D6QKGQEX6OJU2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F8542C153C
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:08:34 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id z130sf13321722pgz.19
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:08:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162112; cv=pass;
        d=google.com; s=arc-20160816;
        b=LXk78+FmQLSYyIb51Y6qZozZT4n/BYCPT15b+UBoUy/n+/osYt03c6j4Gr5rQzdfXf
         tMOLG/C+OVDRZzs4R0lr3ahw8562VnTaoh/5SULKnK3Hg50PhHT7YrU9rs8j5Yfert04
         +xapc2QDczy5Ogw2On+Z1BY3CFn8S4cgjDKeS1xHR+ahr+01Dr3FaXzZO7/UNlMY9uL2
         lleHE0EbnL+GyKgT77eQg8TTBXwZq55Y0dseAoq0Jzel70km/5kWh6RYMLDvoYGftep8
         UxkCvGGWqkVX7/uoSBL7CEh5x/Tg54YP/A6TO76K2Lq+vUHxxXAvQ7Whj9hcpURkGiQL
         y6BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ucNOdzrWtIdM4dzmp9yuhPLIQ8oRH22bLofKx7zSQOM=;
        b=fD6vBGpKUhY0vi8W2AiN44My34Dm6xXifOLUPb2MnW0Pul6UKOZaQVA8BpF58XRNPO
         MzH6RHPo1XX2I3ccZvQ8lKfWw2SiuxmdLj2ABzbf/SotwI2ROd/9YVad+6GbHvWgRAuM
         4oX+FLyB+CFeeW5plPV8ZCdH+ovajHK3ygWcxoTQuGwmSEk2XqYyDvT98MfvLqQU952M
         sPwfnpd3e2V1IGWWtLaPkeuCK8Nzgb7nXwIiHEpmTzOR0c9mfucu97oBb8qREucQCGHI
         5658XMh1W4V8F27ycWgpnt4FRlb9bFyacFqy31s9z3vMHGO0+Rc7jsn8wmH2qPvP72hW
         0LPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="CS4//VJh";
       spf=pass (google.com: domain of 3vxa8xwokceacpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3vxa8XwoKCeACPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ucNOdzrWtIdM4dzmp9yuhPLIQ8oRH22bLofKx7zSQOM=;
        b=AfJFVqcKUhjVOz1Q09G4KRpMUGXSrlWzcwMVA9gvUWlx+4nZdcl7LrV1xCMytSqQE6
         lgKb61osYjMMhmrPIsPPWpK+S4UpZ+7PUN2Fjgmie5RuKPuh5vE3cFxGrCzoOsvrLwQ1
         1nYq+m2GSKbv8UKcINY4loELzhkeePGW/N1SuVhvIXWFBZ8FijcEsSuGdUFhvyEz4Sxm
         pDBbGkUZvRNwuPoxztSkpg1iB3vecJvX+19vYphALyYem7q2oc/WL6muLY0ODX9QWZJw
         UyRtnzk9GFpWnQyCFz1wiETVoolTiwmCbCn4ewEogr+dPUhZHMLgMqHB+LxQMM44o/2u
         xIIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ucNOdzrWtIdM4dzmp9yuhPLIQ8oRH22bLofKx7zSQOM=;
        b=NOyqBavBQR2S4qd+ph83hoO8TxPanCOFSREO3N86mv8oaoYukqPSOlRrmNVTCb0OCo
         62aS4tjngobvcUrgfiosPPRRJIREtPqV7U0jGjFpLtuHTKpYAl8WxHQ5pev7NW8KgYwE
         uaiEzMLGJLxnO0Arj9wVtIk7OiKkbgxwPhp/665/KtXbbO7HNa873s4ck8HCh7PfhtuV
         V4N8ZUbzTglw+16vl15pt3kxjBf7zrY00bxSr9nyhMliSsZaYkO6oeNDoZbTut+7kZtN
         W1BBkdHhvImW3BVvomJGNYczAp8DNBwC6SbPUWGtHtoBn7JO7uutwEJvoxcpaqHw8f8m
         X6sQ==
X-Gm-Message-State: AOAM530yzbOUVlwv30z9bBP6uwqQ/8WTDiGnJB5daJqfE1mazHqjlZMo
	aT6hwAL9/DH5PtaMk06Lj44=
X-Google-Smtp-Source: ABdhPJwelgbLZYH47d+kZVGIWL/BRq/KjzNr/F0Or4Nx9OD3pUfNGxRxUGp4uS1sI3pdl4qHNOxijw==
X-Received: by 2002:a17:902:7486:b029:d9:d4aa:e033 with SMTP id h6-20020a1709027486b02900d9d4aae033mr959848pll.16.1606162112557;
        Mon, 23 Nov 2020 12:08:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:480b:: with SMTP id v11ls1462518pga.2.gmail; Mon, 23 Nov
 2020 12:08:32 -0800 (PST)
X-Received: by 2002:aa7:8817:0:b029:18b:58ce:3c29 with SMTP id c23-20020aa788170000b029018b58ce3c29mr957572pfo.54.1606162111979;
        Mon, 23 Nov 2020 12:08:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162111; cv=none;
        d=google.com; s=arc-20160816;
        b=k0u823PrTjNhesW/lrNsjdv7CE1TnuHx3QPv82acg5IcegD8CMaqDSMCfUKi0rXeO6
         sgfvrhyeEd8rKubhPirii9a1W+32WEAy+pXkojk0a0XTw1SgUgraG+1aiph5PXDOgum2
         UfKCqxpD+pfizGQYiGVoIhBAZHvos7fxWZYl9VyzDG9lJGTigyCco8BC6ck7NGTU41ox
         WipM5BCTCCoDUSDJBdeHMpFeO0DKmhCj+o5cD5UIJLSj3S+rp1q0+ErFIRmsuKjaRoTo
         J/BKLmcKlUPPSPXVPxVHS5nZcW+xyHPbFRNLNwluVHUmIXa/A9QzmAvxjPUlmdQLZ6GX
         VreQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=oHPieWHdViYG32GgdeSm81KitfvarR2p95gDiix5nJo=;
        b=zWgU9LpiCINtEsysEYdtKuXCbnR7l8VO4sCKjrSUV1uoWrdsBEAB13k2LltSCdcNH9
         Rm1W4S7FaI10iZ8/o3hw3EGPEo9uxxZgNfHZudqhUkoX6m+Zr4Bkv3bvW0Q2+Gq60Noj
         7JSqeB64e5ByeMTVN3DYgPnfDPrSnGtmseSn5Fubp+bsHq6Tsf37OnMUYBxULV6M5x4H
         Tc5CAAi/XTc9a1IvzxhNhqqz1Ooo522CIUPW/YM/3z+OLrRJHGaPrAgDnopdeR4h4SX6
         cqHfZ8g+RL2FNv5lAimju+Wr+rA7XQsIm+STb9Lj6V5APxlloCxyoup5IqnQgzTR3dsw
         epWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="CS4//VJh";
       spf=pass (google.com: domain of 3vxa8xwokceacpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3vxa8XwoKCeACPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id ch19si65467pjb.0.2020.11.23.12.08.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:08:31 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vxa8xwokceacpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id i14so14366757qtq.18
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:08:31 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:e50a:: with SMTP id
 l10mr1212845qvm.55.1606162111097; Mon, 23 Nov 2020 12:08:31 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:29 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <fccdcaa13dc6b2211bf363d6c6d499279a54fe3a.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 05/42] kasan: rename (un)poison_shadow to (un)poison_range
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="CS4//VJh";       spf=pass
 (google.com: domain of 3vxa8xwokceacpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3vxa8XwoKCeACPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
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

The new mode won't be using shadow memory. Rename external annotation
kasan_unpoison_shadow() to kasan_unpoison_range(), and introduce internal
functions (un)poison_range() (without kasan_ prefix).

Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: Ia359f32815242c4704e49a5f1639ca2d2f8cba69
---
 include/linux/kasan.h |  6 +++---
 kernel/fork.c         |  4 ++--
 mm/kasan/common.c     | 49 ++++++++++++++++++++++++-------------------
 mm/kasan/generic.c    | 23 ++++++++++----------
 mm/kasan/kasan.h      |  3 ++-
 mm/kasan/tags.c       |  2 +-
 mm/slab_common.c      |  2 +-
 7 files changed, 47 insertions(+), 42 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 26f2ab92e7ca..d237051dca58 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -71,7 +71,7 @@ extern void kasan_enable_current(void);
 /* Disable reporting bugs for current task */
 extern void kasan_disable_current(void);
 
-void kasan_unpoison_shadow(const void *address, size_t size);
+void kasan_unpoison_range(const void *address, size_t size);
 
 void kasan_unpoison_task_stack(struct task_struct *task);
 
@@ -108,7 +108,7 @@ struct kasan_cache {
 size_t __ksize(const void *);
 static inline void kasan_unpoison_slab(const void *ptr)
 {
-	kasan_unpoison_shadow(ptr, __ksize(ptr));
+	kasan_unpoison_range(ptr, __ksize(ptr));
 }
 size_t kasan_metadata_size(struct kmem_cache *cache);
 
@@ -117,7 +117,7 @@ void kasan_restore_multi_shot(bool enabled);
 
 #else /* CONFIG_KASAN */
 
-static inline void kasan_unpoison_shadow(const void *address, size_t size) {}
+static inline void kasan_unpoison_range(const void *address, size_t size) {}
 
 static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
diff --git a/kernel/fork.c b/kernel/fork.c
index c2b3828881fb..3ddd78885a5a 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -225,8 +225,8 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
 		if (!s)
 			continue;
 
-		/* Clear the KASAN shadow of the stack. */
-		kasan_unpoison_shadow(s->addr, THREAD_SIZE);
+		/* Mark stack accessible for KASAN. */
+		kasan_unpoison_range(s->addr, THREAD_SIZE);
 
 		/* Clear stale pointers from reused stack. */
 		memset(s->addr, 0, THREAD_SIZE);
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index f5739be60edc..6adbf5891aff 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -109,7 +109,7 @@ void *memcpy(void *dest, const void *src, size_t len)
  * Poisons the shadow memory for 'size' bytes starting from 'addr'.
  * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
  */
-void kasan_poison_shadow(const void *address, size_t size, u8 value)
+void poison_range(const void *address, size_t size, u8 value)
 {
 	void *shadow_start, *shadow_end;
 
@@ -130,7 +130,7 @@ void kasan_poison_shadow(const void *address, size_t size, u8 value)
 	__memset(shadow_start, value, shadow_end - shadow_start);
 }
 
-void kasan_unpoison_shadow(const void *address, size_t size)
+void unpoison_range(const void *address, size_t size)
 {
 	u8 tag = get_tag(address);
 
@@ -149,7 +149,7 @@ void kasan_unpoison_shadow(const void *address, size_t size)
 	if (is_kfence_address(address))
 		return;
 
-	kasan_poison_shadow(address, size, tag);
+	poison_range(address, size, tag);
 
 	if (size & KASAN_SHADOW_MASK) {
 		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
@@ -161,12 +161,17 @@ void kasan_unpoison_shadow(const void *address, size_t size)
 	}
 }
 
+void kasan_unpoison_range(const void *address, size_t size)
+{
+	unpoison_range(address, size);
+}
+
 static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
 {
 	void *base = task_stack_page(task);
 	size_t size = sp - base;
 
-	kasan_unpoison_shadow(base, size);
+	unpoison_range(base, size);
 }
 
 /* Unpoison the entire stack for a task. */
@@ -185,7 +190,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 	 */
 	void *base = (void *)((unsigned long)watermark & ~(THREAD_SIZE - 1));
 
-	kasan_unpoison_shadow(base, watermark - base);
+	unpoison_range(base, watermark - base);
 }
 
 void kasan_alloc_pages(struct page *page, unsigned int order)
@@ -199,13 +204,13 @@ void kasan_alloc_pages(struct page *page, unsigned int order)
 	tag = random_tag();
 	for (i = 0; i < (1 << order); i++)
 		page_kasan_tag_set(page + i, tag);
-	kasan_unpoison_shadow(page_address(page), PAGE_SIZE << order);
+	unpoison_range(page_address(page), PAGE_SIZE << order);
 }
 
 void kasan_free_pages(struct page *page, unsigned int order)
 {
 	if (likely(!PageHighMem(page)))
-		kasan_poison_shadow(page_address(page),
+		poison_range(page_address(page),
 				PAGE_SIZE << order,
 				KASAN_FREE_PAGE);
 }
@@ -297,18 +302,18 @@ void kasan_poison_slab(struct page *page)
 
 	for (i = 0; i < compound_nr(page); i++)
 		page_kasan_tag_reset(page + i);
-	kasan_poison_shadow(page_address(page), page_size(page),
-			KASAN_KMALLOC_REDZONE);
+	poison_range(page_address(page), page_size(page),
+		     KASAN_KMALLOC_REDZONE);
 }
 
 void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
 {
-	kasan_unpoison_shadow(object, cache->object_size);
+	unpoison_range(object, cache->object_size);
 }
 
 void kasan_poison_object_data(struct kmem_cache *cache, void *object)
 {
-	kasan_poison_shadow(object,
+	poison_range(object,
 			round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE),
 			KASAN_KMALLOC_REDZONE);
 }
@@ -424,7 +429,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	}
 
 	rounded_up_size = round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE);
-	kasan_poison_shadow(object, rounded_up_size, KASAN_KMALLOC_FREE);
+	poison_range(object, rounded_up_size, KASAN_KMALLOC_FREE);
 
 	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
 			unlikely(!(cache->flags & SLAB_KASAN)))
@@ -467,9 +472,9 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 		tag = assign_tag(cache, object, false, keep_tag);
 
 	/* Tag is ignored in set_tag without CONFIG_KASAN_SW_TAGS */
-	kasan_unpoison_shadow(set_tag(object, tag), size);
-	kasan_poison_shadow((void *)redzone_start, redzone_end - redzone_start,
-		KASAN_KMALLOC_REDZONE);
+	unpoison_range(set_tag(object, tag), size);
+	poison_range((void *)redzone_start, redzone_end - redzone_start,
+		     KASAN_KMALLOC_REDZONE);
 
 	if (cache->flags & SLAB_KASAN)
 		kasan_set_track(&get_alloc_info(cache, object)->alloc_track, flags);
@@ -508,9 +513,9 @@ void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
 				KASAN_SHADOW_SCALE_SIZE);
 	redzone_end = (unsigned long)ptr + page_size(page);
 
-	kasan_unpoison_shadow(ptr, size);
-	kasan_poison_shadow((void *)redzone_start, redzone_end - redzone_start,
-		KASAN_PAGE_REDZONE);
+	unpoison_range(ptr, size);
+	poison_range((void *)redzone_start, redzone_end - redzone_start,
+		     KASAN_PAGE_REDZONE);
 
 	return (void *)ptr;
 }
@@ -542,7 +547,7 @@ void kasan_poison_kfree(void *ptr, unsigned long ip)
 			kasan_report_invalid_free(ptr, ip);
 			return;
 		}
-		kasan_poison_shadow(ptr, page_size(page), KASAN_FREE_PAGE);
+		poison_range(ptr, page_size(page), KASAN_FREE_PAGE);
 	} else {
 		__kasan_slab_free(page->slab_cache, ptr, ip, false);
 	}
@@ -728,7 +733,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	 * // vmalloc() allocates memory
 	 * // let a = area->addr
 	 * // we reach kasan_populate_vmalloc
-	 * // and call kasan_unpoison_shadow:
+	 * // and call unpoison_range:
 	 * STORE shadow(a), unpoison_val
 	 * ...
 	 * STORE shadow(a+99), unpoison_val	x = LOAD p
@@ -763,7 +768,7 @@ void kasan_poison_vmalloc(const void *start, unsigned long size)
 		return;
 
 	size = round_up(size, KASAN_SHADOW_SCALE_SIZE);
-	kasan_poison_shadow(start, size, KASAN_VMALLOC_INVALID);
+	poison_range(start, size, KASAN_VMALLOC_INVALID);
 }
 
 void kasan_unpoison_vmalloc(const void *start, unsigned long size)
@@ -771,7 +776,7 @@ void kasan_unpoison_vmalloc(const void *start, unsigned long size)
 	if (!is_vmalloc_or_module_addr(start))
 		return;
 
-	kasan_unpoison_shadow(start, size);
+	unpoison_range(start, size);
 }
 
 static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d6a386255007..cdc2d8112f3e 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -203,11 +203,11 @@ static void register_global(struct kasan_global *global)
 {
 	size_t aligned_size = round_up(global->size, KASAN_SHADOW_SCALE_SIZE);
 
-	kasan_unpoison_shadow(global->beg, global->size);
+	unpoison_range(global->beg, global->size);
 
-	kasan_poison_shadow(global->beg + aligned_size,
-		global->size_with_redzone - aligned_size,
-		KASAN_GLOBAL_REDZONE);
+	poison_range(global->beg + aligned_size,
+		     global->size_with_redzone - aligned_size,
+		     KASAN_GLOBAL_REDZONE);
 }
 
 void __asan_register_globals(struct kasan_global *globals, size_t size)
@@ -286,13 +286,12 @@ void __asan_alloca_poison(unsigned long addr, size_t size)
 
 	WARN_ON(!IS_ALIGNED(addr, KASAN_ALLOCA_REDZONE_SIZE));
 
-	kasan_unpoison_shadow((const void *)(addr + rounded_down_size),
-			      size - rounded_down_size);
-	kasan_poison_shadow(left_redzone, KASAN_ALLOCA_REDZONE_SIZE,
-			KASAN_ALLOCA_LEFT);
-	kasan_poison_shadow(right_redzone,
-			padding_size + KASAN_ALLOCA_REDZONE_SIZE,
-			KASAN_ALLOCA_RIGHT);
+	unpoison_range((const void *)(addr + rounded_down_size),
+		       size - rounded_down_size);
+	poison_range(left_redzone, KASAN_ALLOCA_REDZONE_SIZE,
+		     KASAN_ALLOCA_LEFT);
+	poison_range(right_redzone, padding_size + KASAN_ALLOCA_REDZONE_SIZE,
+		     KASAN_ALLOCA_RIGHT);
 }
 EXPORT_SYMBOL(__asan_alloca_poison);
 
@@ -302,7 +301,7 @@ void __asan_allocas_unpoison(const void *stack_top, const void *stack_bottom)
 	if (unlikely(!stack_top || stack_top > stack_bottom))
 		return;
 
-	kasan_unpoison_shadow(stack_top, stack_bottom - stack_top);
+	unpoison_range(stack_top, stack_bottom - stack_top);
 }
 EXPORT_SYMBOL(__asan_allocas_unpoison);
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index ac499456740f..42ab02c61331 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -150,7 +150,8 @@ static inline bool addr_has_shadow(const void *addr)
 	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
 }
 
-void kasan_poison_shadow(const void *address, size_t size, u8 value);
+void poison_range(const void *address, size_t size, u8 value);
+void unpoison_range(const void *address, size_t size);
 
 /**
  * check_memory_region - Check memory region, and report if invalid access.
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 5c8b08a25715..c0b3f327812b 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -153,7 +153,7 @@ EXPORT_SYMBOL(__hwasan_storeN_noabort);
 
 void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
 {
-	kasan_poison_shadow((void *)addr, size, tag);
+	poison_range((void *)addr, size, tag);
 }
 EXPORT_SYMBOL(__hwasan_tag_memory);
 
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 479d17b90155..0b5ae1819a8b 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1179,7 +1179,7 @@ size_t ksize(const void *objp)
 	 * We assume that ksize callers could use whole allocated area,
 	 * so we need to unpoison this area.
 	 */
-	kasan_unpoison_shadow(objp, size);
+	kasan_unpoison_range(objp, size);
 	return size;
 }
 EXPORT_SYMBOL(ksize);
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fccdcaa13dc6b2211bf363d6c6d499279a54fe3a.1606161801.git.andreyknvl%40google.com.
