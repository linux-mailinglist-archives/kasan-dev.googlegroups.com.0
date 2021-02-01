Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4NT4GAAMGQEVZFLNBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 42C5230B099
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 20:43:46 +0100 (CET)
Received: by mail-ej1-x63d.google.com with SMTP id p1sf8789697ejo.4
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 11:43:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612208626; cv=pass;
        d=google.com; s=arc-20160816;
        b=BjKQ1AIuCnKciC1X57ub99c2STuyRhHmAW2EX6T/3OQ6V6cYRR3QMnev8Zdnvw02fF
         ut+UZlQPlU7Y9YL5lYKLRNQykzY2Eu2iIwjg48pvL9hlnZm+PZ6O8HFg7o2TIAqPU1Ak
         oeBAuPpwO4xoflkA/+VhAoXnsqdXvOMMpviTm2ZbCIJwsXJwp0ciWRjMbuo5gprt77gu
         n9tnW/MkNISpcscpX29TsicYcWiV2HvU+8CZ9uNtwHAHtD70Ff5V96tmE4jBbyzdmvLq
         gSaBncfNgSaMTCz9nJw6I1yAExo1drdAnDiOn0eWibrfOfreF6yo4+IxB6gCrKLkw7zC
         iNYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=EyDBxY6DQ39rmXiL9x1bJjMcDjzXiIZY7lt9l6Q2e8M=;
        b=yUCt9fmlMEwAM/0KOyaQC6M/le5rJkF7utXlDLibqDIkhDIfRJaF2XivKfQBtnyyu3
         gXtfT9WR1QMj8tsOBxPO+Ld3lp1TDmD/pQYALgEPrDb9jhKAfi76mhfc5MDSRCID0JFh
         zpBTke3/uzMGwKtDKBqgYQHQQe6XFwc5z0pn/B1iUtZVwVbP8B32EIAUR8+5iNvHWu8C
         BMHniGgQYiA9ueaxLUkyJizh50FmJqBa7R5ShcFFGCIXNnvbW4+7+NZBvmJHt9Se284j
         NIqx/TR4HCOdTDgVBi7KAvg+apU1hwuIkgrv02rlIpctnEnIcXAVqeCbKudSMU7J8eF/
         llsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p6grNAgN;
       spf=pass (google.com: domain of 38fkyyaokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=38FkYYAoKCQ0n0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EyDBxY6DQ39rmXiL9x1bJjMcDjzXiIZY7lt9l6Q2e8M=;
        b=FewU+6lonAP+bpzVXtlxPEcdNxaBV4J3w/5NF4OlVKMX8lj7ghxPFHpGR0iFZ/QCsG
         T8SrC1CcT7YU58drsOYKL7of+NmpKZelFSslHyppSPOCZT56iPjJhZwdCNfY19oWg7HI
         PE90NMap3TeS/Fl4poj5URZsModbKu6ZW+ZCqieBbR8g8O63zwR0+AeSnTzQUhICIC7g
         sYSRcHC0/R3HTePXPUb/QzFFdAvRUmOGz0cMNC6b+v5PhPWyrflci8ih/3kh1zNA2cKE
         NAdG275G4IBQ2M4vxIIFLjMznHomJ9UEk5FURNMkC6efMq421sk/p2AKXyTzYZ40xFRI
         8v9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EyDBxY6DQ39rmXiL9x1bJjMcDjzXiIZY7lt9l6Q2e8M=;
        b=F/T7e5cF3MQQHFu1fLV4jHL3ddMkr/4uVnFr59pNbHtKbm8tItk3EL6jLTro9TXsEf
         Hjnj7lI5mHMKDgmEuk/1iRVOho94Yr9AyRrRM4G7G1OcWgU1jANreat5kQMi2KA8Kxb7
         BwK4jNO8Q+R8+h9Ka7ENdWa8wrzdJqnIzkQHsnk/GBMrUbmptOsaxTBFG+QVTNaq1uwK
         wastBNHPSbvtMKkS246B6fKkZ/FB9z6bWxtPHnUck/4yYQXxrM8c1bg9hEuS1s3F97G8
         25rjMR7ZxPTgC0E6h2YwKjZWkyAoV9UVmLQLqAvQE23yEgi3MQilSMnr1d2MRueD5HRP
         YufQ==
X-Gm-Message-State: AOAM530/n0hsq71TsfE6W6gd4QIK94avYBoo21xKir7L6Mt+Ou/EJv11
	B3AvQboJnRNttohKFaxv75Y=
X-Google-Smtp-Source: ABdhPJytdUIMeYSNJrTQw7SWGJM+z0Z5LH6gN2ivFQ3VSa7SMSBLYdSR1oPc0pjYzO/lO7e+ffyhEw==
X-Received: by 2002:a17:907:961b:: with SMTP id gb27mr17755298ejc.413.1612208625986;
        Mon, 01 Feb 2021 11:43:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:7641:: with SMTP id kj1ls9355730ejc.4.gmail; Mon, 01
 Feb 2021 11:43:45 -0800 (PST)
X-Received: by 2002:a17:906:cc56:: with SMTP id mm22mr7012170ejb.181.1612208625183;
        Mon, 01 Feb 2021 11:43:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612208625; cv=none;
        d=google.com; s=arc-20160816;
        b=aFsMN/oWOO5xoZdY6lIR9bGx2LzEI+4/ykAKu7kNCMj/9O5duIDr2h+gwHLC5vUUmp
         me7fFeKro6Y4hT26HhIBSkA1Jj6bZPRJuCnaRebEBiGE7xNwZbqtlY58sx3XffPNSVnj
         IrepzFMPMC5Fpax1mYFCcDEvyEhgg/N2JvUiqscx0tsX4v1KqOv9Ng0v6+NrYobXHOC6
         bU41g+km2E96Q/U5YDUSFNigQxUJZje5WPfx4FXo+nCg6XfGlmzlujlQTo/FIggEGu0G
         F8ImRw5M4S3BlBW2xDpuh5GyCE48ZinY2qSCuoWKrVWTvFNt0wkKjdof6FVFD51LlQfh
         Dkbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=gyuOP94GIgUUwGD/R4wbCK1VboClPgYqAgz+f87pwxc=;
        b=og8qC7HNi8fDm7Vdr8sVKbBHDcN+TLSMMisYQQV56InPa4gDMVqje9YnMAU3p7/QFu
         2RKN/ruh2nGtzel2WkwHuSLHYlP2qJ0ebgtEFHOXC8gvW/ZoEbXL8vMq28nX3+5pceoH
         en2ajRc06qEyy9lmJu774iwct4ElIY6KsxzKJtJUgdmRjDiYUhG8IQc+any+5E2HixA3
         WqH3yh7J09kDmwxg0Pm9yxlt8jtm/RK3CwWt9rnpoqj9ma/xepkjb+B8VcWfceg5CKjK
         Fv+i+BVl85NhmqJ2dJ/2Lf2ildGUM9dHH4PZWrw8AFhwBZRqzBSJYecCDZjA6muP5WK6
         by4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p6grNAgN;
       spf=pass (google.com: domain of 38fkyyaokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=38FkYYAoKCQ0n0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id y20si202363edv.3.2021.02.01.11.43.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 11:43:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 38fkyyaokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id n14so11067988wru.6
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 11:43:45 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:2d8a:: with SMTP id
 t132mr377860wmt.119.1612208624836; Mon, 01 Feb 2021 11:43:44 -0800 (PST)
Date: Mon,  1 Feb 2021 20:43:26 +0100
In-Reply-To: <cover.1612208222.git.andreyknvl@google.com>
Message-Id: <b3a02f4f7cda00c87af170c1bf555996a9c6788c.1612208222.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612208222.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH 02/12] kasan, mm: optimize kmalloc poisoning
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=p6grNAgN;       spf=pass
 (google.com: domain of 38fkyyaokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=38FkYYAoKCQ0n0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
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

For allocations from kmalloc caches, kasan_kmalloc() always follows
kasan_slab_alloc(). Currenly, both of them unpoison the whole object,
which is unnecessary.

This patch provides separate implementations for both annotations:
kasan_slab_alloc() unpoisons the whole object, and kasan_kmalloc()
only poisons the redzone.

For generic KASAN, the redzone start might not be aligned to
KASAN_GRANULE_SIZE. Therefore, the poisoning is split in two parts:
kasan_poison_last_granule() poisons the unaligned part, and then
kasan_poison() poisons the rest.

This patch also clarifies alignment guarantees of each of the poisoning
functions and drops the unnecessary round_up() call for redzone_end.

With this change, the early SLUB cache annotation needs to be changed to
kasan_slab_alloc(), as kasan_kmalloc() doesn't unpoison objects now.
The number of poisoned bytes for objects in this cache stays the same, as
kmem_cache_node->object_size is equal to sizeof(struct kmem_cache_node).

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 93 +++++++++++++++++++++++++++++++----------------
 mm/kasan/kasan.h  | 43 +++++++++++++++++++++-
 mm/kasan/shadow.c | 28 +++++++-------
 mm/slub.c         |  3 +-
 4 files changed, 119 insertions(+), 48 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 374049564ea3..128cb330ca73 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -278,21 +278,11 @@ void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
  *    based on objects indexes, so that objects that are next to each other
  *    get different tags.
  */
-static u8 assign_tag(struct kmem_cache *cache, const void *object,
-			bool init, bool keep_tag)
+static u8 assign_tag(struct kmem_cache *cache, const void *object, bool init)
 {
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
 		return 0xff;
 
-	/*
-	 * 1. When an object is kmalloc()'ed, two hooks are called:
-	 *    kasan_slab_alloc() and kasan_kmalloc(). We assign the
-	 *    tag only in the first one.
-	 * 2. We reuse the same tag for krealloc'ed objects.
-	 */
-	if (keep_tag)
-		return get_tag(object);
-
 	/*
 	 * If the cache neither has a constructor nor has SLAB_TYPESAFE_BY_RCU
 	 * set, assign a tag when the object is being allocated (init == false).
@@ -325,7 +315,7 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 	}
 
 	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
-	object = set_tag(object, assign_tag(cache, object, true, false));
+	object = set_tag(object, assign_tag(cache, object, true));
 
 	return (void *)object;
 }
@@ -413,12 +403,46 @@ static void set_alloc_info(struct kmem_cache *cache, void *object,
 		kasan_set_track(&alloc_meta->alloc_track, flags);
 }
 
+void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
+					void *object, gfp_t flags)
+{
+	u8 tag;
+	void *tagged_object;
+
+	if (gfpflags_allow_blocking(flags))
+		kasan_quarantine_reduce();
+
+	if (unlikely(object == NULL))
+		return NULL;
+
+	if (is_kfence_address(object))
+		return (void *)object;
+
+	/*
+	 * Generate and assign random tag for tag-based modes.
+	 * Tag is ignored in set_tag() for the generic mode.
+	 */
+	tag = assign_tag(cache, object, false);
+	tagged_object = set_tag(object, tag);
+
+	/*
+	 * Unpoison the whole object.
+	 * For kmalloc() allocations, kasan_kmalloc() will do precise poisoning.
+	 */
+	kasan_unpoison(tagged_object, cache->object_size);
+
+	/* Save alloc info (if possible) for non-kmalloc() allocations. */
+	if (kasan_stack_collection_enabled())
+		set_alloc_info(cache, (void *)object, flags, false);
+
+	return tagged_object;
+}
+
 static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
-				size_t size, gfp_t flags, bool kmalloc)
+					size_t size, gfp_t flags)
 {
 	unsigned long redzone_start;
 	unsigned long redzone_end;
-	u8 tag;
 
 	if (gfpflags_allow_blocking(flags))
 		kasan_quarantine_reduce();
@@ -429,33 +453,41 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	if (is_kfence_address(kasan_reset_tag(object)))
 		return (void *)object;
 
+	/*
+	 * The object has already been unpoisoned by kasan_slab_alloc() for
+	 * kmalloc() or by ksize() for krealloc().
+	 */
+
+	/*
+	 * The redzone has byte-level precision for the generic mode.
+	 * Partially poison the last object granule to cover the unaligned
+	 * part of the redzone.
+	 */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		kasan_poison_last_granule((void *)object, size);
+
+	/* Poison the aligned part of the redzone. */
 	redzone_start = round_up((unsigned long)(object + size),
 				KASAN_GRANULE_SIZE);
-	redzone_end = round_up((unsigned long)object + cache->object_size,
-				KASAN_GRANULE_SIZE);
-	tag = assign_tag(cache, object, false, kmalloc);
-
-	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
-	kasan_unpoison(set_tag(object, tag), size);
+	redzone_end = (unsigned long)object + cache->object_size;
 	kasan_poison((void *)redzone_start, redzone_end - redzone_start,
 			   KASAN_KMALLOC_REDZONE);
 
+	/*
+	 * Save alloc info (if possible) for kmalloc() allocations.
+	 * This also rewrites the alloc info when called from kasan_krealloc().
+	 */
 	if (kasan_stack_collection_enabled())
-		set_alloc_info(cache, (void *)object, flags, kmalloc);
+		set_alloc_info(cache, (void *)object, flags, true);
 
-	return set_tag(object, tag);
-}
-
-void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
-					void *object, gfp_t flags)
-{
-	return ____kasan_kmalloc(cache, object, cache->object_size, flags, false);
+	/* Keep the tag that was set by kasan_slab_alloc(). */
+	return (void *)object;
 }
 
 void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object,
 					size_t size, gfp_t flags)
 {
-	return ____kasan_kmalloc(cache, object, size, flags, true);
+	return ____kasan_kmalloc(cache, object, size, flags);
 }
 EXPORT_SYMBOL(__kasan_kmalloc);
 
@@ -496,8 +528,7 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 	if (unlikely(!PageSlab(page)))
 		return __kasan_kmalloc_large(object, size, flags);
 	else
-		return ____kasan_kmalloc(page->slab_cache, object, size,
-						flags, true);
+		return ____kasan_kmalloc(page->slab_cache, object, size, flags);
 }
 
 void __kasan_kfree_large(void *ptr, unsigned long ip)
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index dd14e8870023..6a2882997f23 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -358,12 +358,51 @@ static inline bool kasan_byte_accessible(const void *addr)
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
-void kasan_poison(const void *address, size_t size, u8 value);
-void kasan_unpoison(const void *address, size_t size);
+/**
+ * kasan_poison - mark the memory range as unaccessible
+ * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
+ * @size - range size
+ * @value - value that's written to metadata for the range
+ *
+ * The size gets aligned to KASAN_GRANULE_SIZE before marking the range.
+ */
+void kasan_poison(const void *addr, size_t size, u8 value);
+
+/**
+ * kasan_unpoison - mark the memory range as accessible
+ * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
+ * @size - range size
+ *
+ * For the tag-based modes, the @size gets aligned to KASAN_GRANULE_SIZE before
+ * marking the range.
+ * For the generic mode, the last granule of the memory range gets partially
+ * unpoisoned based on the @size.
+ */
+void kasan_unpoison(const void *addr, size_t size);
+
 bool kasan_byte_accessible(const void *addr);
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
+#ifdef CONFIG_KASAN_GENERIC
+
+/**
+ * kasan_poison_last_granule - mark the last granule of the memory range as
+ * unaccessible
+ * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
+ * @size - range size
+ *
+ * This function is only available for the generic mode, as it's the only mode
+ * that has partially poisoned memory granules.
+ */
+void kasan_poison_last_granule(const void *address, size_t size);
+
+#else /* CONFIG_KASAN_GENERIC */
+
+static inline void kasan_poison_last_granule(const void *address, size_t size) { }
+
+#endif /* CONFIG_KASAN_GENERIC */
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 1372a2fc0ca9..1ed7817e4ee6 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -69,10 +69,6 @@ void *memcpy(void *dest, const void *src, size_t len)
 	return __memcpy(dest, src, len);
 }
 
-/*
- * Poisons the shadow memory for 'size' bytes starting from 'addr'.
- * Memory addresses should be aligned to KASAN_GRANULE_SIZE.
- */
 void kasan_poison(const void *address, size_t size, u8 value)
 {
 	void *shadow_start, *shadow_end;
@@ -83,12 +79,12 @@ void kasan_poison(const void *address, size_t size, u8 value)
 	 * addresses to this function.
 	 */
 	address = kasan_reset_tag(address);
-	size = round_up(size, KASAN_GRANULE_SIZE);
 
 	/* Skip KFENCE memory if called explicitly outside of sl*b. */
 	if (is_kfence_address(address))
 		return;
 
+	size = round_up(size, KASAN_GRANULE_SIZE);
 	shadow_start = kasan_mem_to_shadow(address);
 	shadow_end = kasan_mem_to_shadow(address + size);
 
@@ -96,6 +92,16 @@ void kasan_poison(const void *address, size_t size, u8 value)
 }
 EXPORT_SYMBOL(kasan_poison);
 
+#ifdef CONFIG_KASAN_GENERIC
+void kasan_poison_last_granule(const void *address, size_t size)
+{
+	if (size & KASAN_GRANULE_MASK) {
+		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
+		*shadow = size & KASAN_GRANULE_MASK;
+	}
+}
+#endif
+
 void kasan_unpoison(const void *address, size_t size)
 {
 	u8 tag = get_tag(address);
@@ -115,16 +121,12 @@ void kasan_unpoison(const void *address, size_t size)
 	if (is_kfence_address(address))
 		return;
 
+	/* Unpoison round_up(size, KASAN_GRANULE_SIZE) bytes. */
 	kasan_poison(address, size, tag);
 
-	if (size & KASAN_GRANULE_MASK) {
-		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
-
-		if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
-			*shadow = tag;
-		else /* CONFIG_KASAN_GENERIC */
-			*shadow = size & KASAN_GRANULE_MASK;
-	}
+	/* Partially poison the last granule for the generic mode. */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		kasan_poison_last_granule(address, size);
 }
 
 #ifdef CONFIG_MEMORY_HOTPLUG
diff --git a/mm/slub.c b/mm/slub.c
index 176b1cb0d006..e564008c2329 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3565,8 +3565,7 @@ static void early_kmem_cache_node_alloc(int node)
 	init_object(kmem_cache_node, n, SLUB_RED_ACTIVE);
 	init_tracking(kmem_cache_node, n);
 #endif
-	n = kasan_kmalloc(kmem_cache_node, n, sizeof(struct kmem_cache_node),
-		      GFP_KERNEL);
+	n = kasan_slab_alloc(kmem_cache_node, n, GFP_KERNEL);
 	page->freelist = get_freepointer(kmem_cache_node, n);
 	page->inuse = 1;
 	page->frozen = 0;
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b3a02f4f7cda00c87af170c1bf555996a9c6788c.1612208222.git.andreyknvl%40google.com.
