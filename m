Return-Path: <kasan-dev+bncBDX4HWEMTEBRBK6N6WAAMGQEJFNDRBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CE92310D3A
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 16:39:24 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id x12sf5551505wrw.21
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 07:39:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612539564; cv=pass;
        d=google.com; s=arc-20160816;
        b=zSRHLzGm1iqbW8UbbVzpp/y1HwBqDUWfhaTKOdVtjzViHMzVvANeHx4Q6LbLmsO6Jv
         rNLkcf6PC9Y6B49L5VssuzV0FCsmjso/KLEqlMr3D3sauXDPvwAWGgKRVBczdcs7mGFF
         ODdg+mDMDcQvWnlKIGYR2EGX3IoIRL3Jm/qHNeV51oqUvYYxrRfSf6YYi4ENl1NNc+hg
         Z64O0ChlowxC+2soBhi+vr7R+EXPjlS25G9DKXVMKXo/+f2a6+wzkNPnPE2PLU8vLIMU
         ucc14Kih+VOgbLGfDyXdffZrbpptbwVukHzAbUupaZgGYlxrlrre3s824ZpfTdzmngVX
         lZew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=jWj1rTK/lv6eEkNtSG7F68UIu94NpL8PA46+RHPs9uQ=;
        b=QVlNLkfWNZNHNrlT8DHywyP5WbFRiH1uz0P032MAP/I7tbo+4m97PqDYeSaCmKzmeC
         IJ3do+AsAWmvlTsDyCsjZEn9pI5hAnVrcGy1HNIqHJXM4ETLOUM4Q+cHDvGw2bL128WX
         gjOkZQN1LyQjLtsqpxOO4uXLfeIwa2HXT6I4Ke7Cslk6j83fo9ARgLrhCMwph+gCEp7l
         SuLlQi7wUp4wlzPYh0+PBZdggdskGJTRuJIgRsq3StqIW9iGSG6nuo3w4M8avQ9vwj0K
         cFIU1s/ZqDyn2CxuiA/5o/74HHZliwWJCfGVeUntptI3LgUFPFuVGVj//u8WZPSzVg38
         pGqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eyyQwZSW;
       spf=pass (google.com: domain of 3qmydyaokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3qmYdYAoKCfMViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jWj1rTK/lv6eEkNtSG7F68UIu94NpL8PA46+RHPs9uQ=;
        b=h1GXbKhU6Zu/KfDY6pp/k01n4XdXpZYIwpJJqa9d2zmsa3NDUVWZ8Rlm4CcBV2w2ma
         7XlL1qm8D0x9H0Swx8uasV5uidJ6B1CWmrNiqkFTTkd+lLvopN5zLA2i5AvI4NiIzZoJ
         rUfFun9RiGKJv0+qNZ3CGdT31IIuEMPrRANu+ncHA9D3mRissEtTbWbmDH7Xa2qFxlot
         IBWfz1dDBQ6xk466BWzJ9MBGHDN0spBkZnnhkmBfQkrkVh8MrEKmEx+cI9S8eZOSOH0a
         o2tzzLHRCRsFLAzBOxuSYBd1Jm5aYvMyAoZl40JeeGE0cap8a3Yj7bgdEwEKgIkbf0VM
         dPBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jWj1rTK/lv6eEkNtSG7F68UIu94NpL8PA46+RHPs9uQ=;
        b=KiwYhhvQomqIb6rjC+AbHCdnlldN/Q1Jc3DD2W6PPo4GZGmFXR3x5wHIKlM1cigb15
         hj0pek5n8kZGJV3mmxYezrFplzqVcxM+r025SrrkDBgA65iS7ILaXU7IS/cHpvMBjAKc
         +at1ZgiuOQ/BAptxtWFhctPtcp5Po8sLD96/CQeymSWDd6hMX7i2shkB57xh8PpeJY0n
         893pGj1V04WcSNwzh2wwXQuuUv0+2PG1X/UKmbRg6pbW8IA/rnvNSV5ijYq9hRZe9k29
         G33j0mzRayeIunieQQtyGAu+zeGfxC5boaI9UA2Bb8uZM+ram2n6u1GiwWgrbXMk26xo
         NjEw==
X-Gm-Message-State: AOAM530W6r1TxlIrCrfjR26sY4yW053bGZVk78Q0XBEpll4ZmFymV5hk
	ufJFpy6REAbNHuuAVG7soaQ=
X-Google-Smtp-Source: ABdhPJwMcOWhe15ER1RYBkY6ILCZdMLBnQmJcqcj3TquC2beCnciEMMrFjJoMx1zNF/4laCPE2k02g==
X-Received: by 2002:a1c:1f4d:: with SMTP id f74mr4155512wmf.133.1612539563901;
        Fri, 05 Feb 2021 07:39:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4485:: with SMTP id j5ls836782wrq.1.gmail; Fri, 05 Feb
 2021 07:39:23 -0800 (PST)
X-Received: by 2002:adf:ce89:: with SMTP id r9mr5757442wrn.345.1612539563167;
        Fri, 05 Feb 2021 07:39:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612539563; cv=none;
        d=google.com; s=arc-20160816;
        b=pNBEnwrlzAulf4PAlR4yBx2HwLWoAWNdqKr4mk0SzI7bdyeeEksjk8sVqN5dsdinSI
         FWazyGXgT5fxu28Ivy+4NHgmW7yUgH1M/tQIldb6g080IivKPkbQ2I+u/m+gFTaUEI0u
         wPA9nLjsCj0nU6gAfd9ZTvz+0jxhpJsz/M2HvtbCoNQ3e77JhkwShSWXWgzXiVFiLNNv
         ldOHRamliSycJ/M5P1NUCPWDHN8SQFSUMQX3/3T6ca+mFTJw/cMlxU2aM3Ozlut7KZQN
         nzkAzY5b6RlZ4gALP+Blpcbfp2AffHUvAxxvdDHmnLbR2eQBNuOkDjRxE42Ldiqg6xu5
         CKMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Ba9zMe8veYMITkXBVAbBRm/Mh4dw6QKopCfTTr6LLO8=;
        b=km/routBDF6WmBytZOuEhpDXTzYyyrBIjqNr+11zClo6Oi8u0XJWXESpvgxH0arQxl
         JLOQqWTsuIblowIfkClxeazPG+PVKrxNtPugvd/xX6JovWYyqQzRqrL0KSrwUthowG55
         7ibpbDsD3Pn1uLYKmPZozG8Fq22yBADSeiorwCSt/F4sHIhVPXL9Bf27B6H8z64lR7Q+
         XLCUQcNRb1AfgpVBOs+BSyGhrLGl3YW0E9EFB/9jtJtq8tEU3xFKg2Q65c5ImfVSMkc3
         /iUu3ajc7tLaVl6wGsBUlPrDBiesQtim2Rbe6UQZ91OKGwRlgRSiorMPgaRBI1lIqCLi
         mQag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eyyQwZSW;
       spf=pass (google.com: domain of 3qmydyaokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3qmYdYAoKCfMViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id w11si647537wrv.0.2021.02.05.07.39.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 07:39:23 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qmydyaokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id d7so5581507wri.23
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 07:39:23 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:ce:: with SMTP id
 u14mr4141612wmm.10.1612539562830; Fri, 05 Feb 2021 07:39:22 -0800 (PST)
Date: Fri,  5 Feb 2021 16:39:03 +0100
In-Reply-To: <cover.1612538932.git.andreyknvl@google.com>
Message-Id: <708de0add7fc6a762e66452afd3d357a9cd5420a.1612538932.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612538932.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v2 02/12] kasan, mm: optimize kmalloc poisoning
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eyyQwZSW;       spf=pass
 (google.com: domain of 3qmydyaokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3qmYdYAoKCfMViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
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

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 93 +++++++++++++++++++++++++++++++----------------
 mm/kasan/kasan.h  | 43 +++++++++++++++++++++-
 mm/kasan/shadow.c | 28 +++++++-------
 mm/slub.c         |  3 +-
 4 files changed, 119 insertions(+), 48 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index bfdf5464f4ef..00edbc3eb32e 100644
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
-				size_t size, gfp_t flags, bool is_kmalloc)
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
-	tag = assign_tag(cache, object, false, is_kmalloc);
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
-		set_alloc_info(cache, (void *)object, flags, is_kmalloc);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/708de0add7fc6a762e66452afd3d357a9cd5420a.1612538932.git.andreyknvl%40google.com.
