Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWVEVT6QKGQETXG3KFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 882792AE33D
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:21:14 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id h2sf1879502wmm.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:21:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046874; cv=pass;
        d=google.com; s=arc-20160816;
        b=zpqcLAd4ializc6PsxQqi0Nr9+26lHBAInal11zIRKI5HakEgfk5kYzePLoR0DQxGe
         p2Sq2W99EAAdPvbFGyp0do/NII7BoKvAHw3yAb2f/iGsqKYkVVTwdPKzwLDxI5t2sBrA
         4zgj6KVmzGEhN+0A0AyBWfwojvEh8bW+DagpQmUYT9kO1SW0jPIAr3uEyRe3x1gtMjNQ
         raYSPsM5Gma7+G8rqpSGOg7GaISlP3nc2BaERZ9lRQCVYzufvrmzAXSdFVOHVBA4LLNR
         0h0SbLOOmMDUPryobWm5/NZ3ZfUB8Od04z2WXib8BTXVEe+G5zth4VaCM1l20ccO76tO
         JRJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=zmOtycDAfmk7MM+Wr0Di9DU34zFuTq4XOH8RDl+EipQ=;
        b=oImQdIAaTPQVbsMIcDdLlx/SpKvRSoWGKKfyW3LM292MH6/MBJ23e+EN7v//ZSPTZ6
         b1K90Hea+a9w81oLfHsRr6SCZLJE6hjSiqqH4AsBNud+L/tkXthtUbhg/Asnue8wtgjt
         SYTRudNiMaUGhaKN1UAi0XjpjmpxNW04XOsWRqIqnVKZASO0TfcpmSOZRm0YNtaJb/Mv
         7bEWtwhfF+zda7OMTSfGW5G4e0JhAYndeIgROM17DRUfg8kO4EqyP1EthYw289tmmMtY
         yXcgiRg+Ir5t8HZfrbuEZwR7/eI7jEZ53w50nQXAIStsPihOq8nD6xy0zGeRBrdxY9hp
         7LtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FOzDKlnS;
       spf=pass (google.com: domain of 3wbkrxwokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3WBKrXwoKCS0JWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zmOtycDAfmk7MM+Wr0Di9DU34zFuTq4XOH8RDl+EipQ=;
        b=Ly5jxx14tn1Isj4bF7dWOHoNsGES49oF3y2IwxPV6uTjKmRLXQyrhE+9NbVROjBN8K
         GThj37SQbbU4FIvsTie4nSkQo1Wby+sEG6m6Qy9DJccdto7NHYGiT6uQ9jeoL0NPZJFJ
         /Ya0C+8TgLsDcF2y+pzBzgVsXpXzRxJjpwewt+UizUCWwSMKWpPuwSNzxemPXUjy9Ogp
         Uzkl8YiJ04OlekY6uyhn52fXlmfnP1Z/VbKIjXeXOwwDgffpODjF1iqe1AR1n4tJWAhp
         5dYr/stkDZtYTAuexhQwoFuQO2G/vKg5flx3N64kyQqjAXFJpE8vAUXBvLj2X4A8lggB
         gQWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zmOtycDAfmk7MM+Wr0Di9DU34zFuTq4XOH8RDl+EipQ=;
        b=mECajjdAAzNYbOYjrrU/0JpUYMyv2v3jfjA8utaKHNtwVtrnStkfQ0B5dFLujHjqZw
         DlOEQPj+lBm9g7idQR7NBEs8Q83sfZCXz/B1H2M8scT0zeJjUdTiktP/9vZ0fBNR854F
         kT1A46efThSR6cERJMOTQCNZY16K6Sfjlmqk2pLwi4PfxFRqqGCCW+gnKSsNDaf3nz/m
         l1Srqfs8qHgWqpEftZhWDaqrIr1svwtv28tfKx1bqfOpXey9eSfcntpnrVgjxP/zuJRm
         Zn1crCjt+4Z5LI821ANImdzD4Cxv1czWdeZnjc4rj5GEIWuwftImQ0wUItCTtpo8BE4r
         navA==
X-Gm-Message-State: AOAM530doh+4eFN1PJgngvc10PUPaeYX2fC3E4ciicls7nzNFNWtNAr3
	6QbiBq1fT1JKOJNK24cSkus=
X-Google-Smtp-Source: ABdhPJxXQfenOk+riyKBv8u+0msUdKQ45zQy/a8Td1pIViBJ+oZNXT5zIisOEvQ2gk3mGhFgwkCKAw==
X-Received: by 2002:a05:600c:2319:: with SMTP id 25mr311333wmo.102.1605046874298;
        Tue, 10 Nov 2020 14:21:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:aa87:: with SMTP id h7ls476330wrc.2.gmail; Tue, 10 Nov
 2020 14:21:13 -0800 (PST)
X-Received: by 2002:a5d:4104:: with SMTP id l4mr26276936wrp.276.1605046873403;
        Tue, 10 Nov 2020 14:21:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046873; cv=none;
        d=google.com; s=arc-20160816;
        b=u3nJC3OvlZlgwcidJ1J4B0/BcCiKLXflvWRxj5WjLjnDL5MLCVkv9evmpYKFygOdhH
         b14qyr+YCsPL68Mdj/QHCRFSq9J3dfiYAwB44/DMxlS+QJKXc++Itdr6DLtSyILLsFkW
         BvOrJHj/OI/1A7qLDSvsW9nujlZuJGCdIKuMP4wgYoAQGiiSHjXHOW5SDZJT5r/sVcXH
         0ATfo9E4bqVdfY47Q7HhB7YfdknO3t7NxCG+G+h3HalhyoKZICTn0oW9pYj2+tKdxBXk
         0EtrLGJsADXHaewSQ9O5UQ3rjXWwT+GcBL7VMWA5jRaCZi7cXuySCgk9Q2+rA1kDnEmk
         UJKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=2zUWPQplFymp9Hmc6hlFXFyiGUCdCRWGOE8USzzNHUI=;
        b=PPzv0YxPqzQ/6m3boahxLau3/TKSzFXR9xLiHedMGqO7BMrbouXfXASpQUc1jpBuKV
         Wgu60D1D8Ui/6mQ+W6y1T+B0pvGyLGX5K3bQuZ2fub2D9tS67DQfwpgm2yfEqcdU0RI+
         eF+jGNELTN9CJle31ZShwuQyt3ef0PSso10II1fHpyFMynqc9i2DsrGmHQAwUtIpMZyb
         IOQRUBzuawrTqZtz7udGb9kaNo17fsUHpgOWq7o7WDbP1T8ViTbCjNaGEyAIPCEChb0U
         Uql/0lsdbNHR2DqkVYe9k4V8/AFgsnM/mbOxY+utW86+FA2nEG9zRwp5zjNwOkCiO/E3
         xuow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FOzDKlnS;
       spf=pass (google.com: domain of 3wbkrxwokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3WBKrXwoKCS0JWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id m5si6466wmc.0.2020.11.10.14.21.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:21:13 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wbkrxwokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id e18so6187361wrs.23
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:21:13 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:6310:: with SMTP id
 i16mr26060595wru.284.1605046872700; Tue, 10 Nov 2020 14:21:12 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:22 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <fe30e8ab5535e14f86fbe7876e134a76374403bf.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 18/20] kasan: clean up metadata allocation and usage
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FOzDKlnS;       spf=pass
 (google.com: domain of 3wbkrxwokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3WBKrXwoKCS0JWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
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

KASAN marks caches that are sanitized with the SLAB_KASAN cache flag.
Currently if the metadata that is appended after the object (stores e.g.
stack trace ids) doesn't fit into KMALLOC_MAX_SIZE (can only happen with
SLAB, see the comment in the patch), KASAN turns off sanitization
completely.

With this change sanitization of the object data is always enabled.
However the metadata is only stored when it fits. Instead of checking for
SLAB_KASAN flag accross the code to find out whether the metadata is
there, use cache->kasan_info.alloc/free_meta_offset. As 0 can be a valid
value for free_meta_offset, introduce KASAN_NO_FREE_META as an indicator
that the free metadata is missing.

Along the way rework __kasan_cache_create() and add claryfying comments.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Icd947e2bea054cb5cfbdc6cf6652227d97032dcb
---
 mm/kasan/common.c         | 112 +++++++++++++++++++++++++-------------
 mm/kasan/generic.c        |  15 ++---
 mm/kasan/hw_tags.c        |   6 +-
 mm/kasan/kasan.h          |  13 ++++-
 mm/kasan/quarantine.c     |   8 +++
 mm/kasan/report.c         |  43 ++++++++-------
 mm/kasan/report_sw_tags.c |   7 ++-
 mm/kasan/sw_tags.c        |   4 ++
 8 files changed, 138 insertions(+), 70 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 4360292ad7f3..940b42231069 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -109,9 +109,6 @@ void __kasan_free_pages(struct page *page, unsigned int order)
  */
 static inline unsigned int optimal_redzone(unsigned int object_size)
 {
-	if (!IS_ENABLED(CONFIG_KASAN_GENERIC))
-		return 0;
-
 	return
 		object_size <= 64        - 16   ? 16 :
 		object_size <= 128       - 32   ? 32 :
@@ -125,47 +122,79 @@ static inline unsigned int optimal_redzone(unsigned int object_size)
 void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 			  slab_flags_t *flags)
 {
-	unsigned int orig_size = *size;
+	unsigned int ok_size;
 	unsigned int redzone_size;
-	int redzone_adjust;
+	unsigned int optimal_size;
+
+	/*
+	 * SLAB_KASAN is used to mark caches as ones that are sanitized by
+	 * KASAN. Currently this is used in two places:
+	 * 1. In slab_ksize() when calculating the size of the accessible
+	 *    memory within the object.
+	 * 2. In slab_common.c to prevent merging of sanitized caches.
+	 */
+	*flags |= SLAB_KASAN;
 
-	if (!kasan_stack_collection_enabled()) {
-		*flags |= SLAB_KASAN;
+	if (!kasan_stack_collection_enabled())
 		return;
-	}
 
-	/* Add alloc meta. */
+	ok_size = *size;
+
+	/* Add alloc meta into redzone. */
 	cache->kasan_info.alloc_meta_offset = *size;
 	*size += sizeof(struct kasan_alloc_meta);
 
-	/* Add free meta. */
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC) &&
-	    (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
-	     cache->object_size < sizeof(struct kasan_free_meta))) {
-		cache->kasan_info.free_meta_offset = *size;
-		*size += sizeof(struct kasan_free_meta);
+	/*
+	 * If alloc meta doesn't fit, don't add it.
+	 * This can only happen with SLAB, as it has KMALLOC_MAX_SIZE equal
+	 * to KMALLOC_MAX_CACHE_SIZE and doesn't fall back to page_alloc for
+	 * larger sizes.
+	*/
+	if (*size > KMALLOC_MAX_SIZE) {
+		cache->kasan_info.alloc_meta_offset = 0;
+		*size = ok_size;
+		/* Continue, since free meta might still fit. */
 	}
 
-	redzone_size = optimal_redzone(cache->object_size);
-	redzone_adjust = redzone_size -	(*size - cache->object_size);
-	if (redzone_adjust > 0)
-		*size += redzone_adjust;
-
-	*size = min_t(unsigned int, KMALLOC_MAX_SIZE,
-			max(*size, cache->object_size + redzone_size));
+	/* Only the generic mode uses free meta or flexible redzones. */
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
+		return;
+	}
 
 	/*
-	 * If the metadata doesn't fit, don't enable KASAN at all.
+	 * Add free meta into redzone when it's not possible to store
+	 * it in the object. This is the case when:
+	 * 1. Object is SLAB_TYPESAFE_BY_RCU, which means that is can
+	 *    be touched after it was freed, or
+	 * 2. Object has a constructor, which means it's expected to
+	 *    retain its content until the next allocation, or
+	 * 3. Object is too small.
+	 * Otherwise cache->kasan_info.free_meta_offset = 0 is implied.
 	 */
-	if (*size <= cache->kasan_info.alloc_meta_offset ||
-			*size <= cache->kasan_info.free_meta_offset) {
-		cache->kasan_info.alloc_meta_offset = 0;
-		cache->kasan_info.free_meta_offset = 0;
-		*size = orig_size;
-		return;
+	if (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
+	    cache->object_size < sizeof(struct kasan_free_meta)) {
+		ok_size = *size;
+
+		cache->kasan_info.free_meta_offset = *size;
+		*size += sizeof(struct kasan_free_meta);
+
+		/* If free meta doesn't fit, don't add it. */
+		if (*size > KMALLOC_MAX_SIZE) {
+			cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
+			*size = ok_size;
+		}
 	}
 
-	*flags |= SLAB_KASAN;
+	redzone_size = optimal_redzone(cache->object_size);
+	/* Calculate size with optimal redzone. */
+	optimal_size = cache->object_size + redzone_size;
+	/* Limit it with KMALLOC_MAX_SIZE (relevant for SLAB only). */
+	if (optimal_size > KMALLOC_MAX_SIZE)
+		optimal_size = KMALLOC_MAX_SIZE;
+	/* Use optimal size if the size with added metas is not large enough. */
+	if (*size < optimal_size)
+		*size = optimal_size;
 }
 
 size_t __kasan_metadata_size(struct kmem_cache *cache)
@@ -181,15 +210,21 @@ size_t __kasan_metadata_size(struct kmem_cache *cache)
 struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
 					      const void *object)
 {
+	if (!cache->kasan_info.alloc_meta_offset)
+		return NULL;
 	return kasan_reset_tag(object) + cache->kasan_info.alloc_meta_offset;
 }
 
+#ifdef CONFIG_KASAN_GENERIC
 struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 					    const void *object)
 {
 	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
+	if (cache->kasan_info.free_meta_offset == KASAN_NO_FREE_META)
+		return NULL;
 	return kasan_reset_tag(object) + cache->kasan_info.free_meta_offset;
 }
+#endif
 
 void __kasan_unpoison_data(const void *addr, size_t size)
 {
@@ -276,11 +311,9 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 	struct kasan_alloc_meta *alloc_meta;
 
 	if (kasan_stack_collection_enabled()) {
-		if (!(cache->flags & SLAB_KASAN))
-			return (void *)object;
-
 		alloc_meta = kasan_get_alloc_meta(cache, object);
-		__memset(alloc_meta, 0, sizeof(*alloc_meta));
+		if (alloc_meta)
+			__memset(alloc_meta, 0, sizeof(*alloc_meta));
 	}
 
 	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
@@ -319,8 +352,7 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (!kasan_stack_collection_enabled())
 		return false;
 
-	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
-			unlikely(!(cache->flags & SLAB_KASAN)))
+	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine))
 		return false;
 
 	kasan_set_free_info(cache, object, tag);
@@ -345,7 +377,11 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 
 static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 {
-	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (alloc_meta)
+		kasan_set_track(&alloc_meta->alloc_track, flags);
 }
 
 static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
@@ -372,7 +408,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
 		KASAN_KMALLOC_REDZONE);
 
-	if (kasan_stack_collection_enabled() && (cache->flags & SLAB_KASAN))
+	if (kasan_stack_collection_enabled())
 		set_alloc_info(cache, (void *)object, flags);
 
 	return set_tag(object, tag);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d259e4c3aefd..97e39516f8fe 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -338,10 +338,10 @@ void kasan_record_aux_stack(void *addr)
 	cache = page->slab_cache;
 	object = nearest_obj(cache, page, addr);
 	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (!alloc_meta)
+		return;
 
-	/*
-	 * record the last two call_rcu() call stacks.
-	 */
+	/* Record the last two call_rcu() call stacks. */
 	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
 	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
 }
@@ -352,11 +352,11 @@ void kasan_set_free_info(struct kmem_cache *cache,
 	struct kasan_free_meta *free_meta;
 
 	free_meta = kasan_get_free_meta(cache, object);
-	kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
+	if (!free_meta)
+		return;
 
-	/*
-	 *  the object was freed and has free track set
-	 */
+	kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
+	/* The object was freed and has free track set. */
 	*(u8 *)kasan_mem_to_shadow(object) = KASAN_KMALLOC_FREETRACK;
 }
 
@@ -365,5 +365,6 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 {
 	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_KMALLOC_FREETRACK)
 		return NULL;
+	/* Free meta must be present with KASAN_KMALLOC_FREETRACK. */
 	return &kasan_get_free_meta(cache, object)->free_track;
 }
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 2f6f0261af8c..c3d2a21d925d 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -188,7 +188,8 @@ void kasan_set_free_info(struct kmem_cache *cache,
 	struct kasan_alloc_meta *alloc_meta;
 
 	alloc_meta = kasan_get_alloc_meta(cache, object);
-	kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
+	if (alloc_meta)
+		kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
 }
 
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
@@ -197,5 +198,8 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 	struct kasan_alloc_meta *alloc_meta;
 
 	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (!alloc_meta)
+		return NULL;
+
 	return &alloc_meta->free_track[0];
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 5eff3d9f624e..88892c05eb7d 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -154,20 +154,31 @@ struct kasan_alloc_meta {
 struct qlist_node {
 	struct qlist_node *next;
 };
+
+/*
+ * Generic mode either stores free meta in the object itself or in the redzone
+ * after the object. In the former case free meta offset is 0, in the latter
+ * case it has some sane value smaller than INT_MAX. Use INT_MAX as free meta
+ * offset when free meta isn't present.
+ */
+#define KASAN_NO_FREE_META (INT_MAX)
+
 struct kasan_free_meta {
+#ifdef CONFIG_KASAN_GENERIC
 	/* This field is used while the object is in the quarantine.
 	 * Otherwise it might be used for the allocator freelist.
 	 */
 	struct qlist_node quarantine_link;
-#ifdef CONFIG_KASAN_GENERIC
 	struct kasan_track free_track;
 #endif
 };
 
 struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
 						const void *object);
+#ifdef CONFIG_KASAN_GENERIC
 struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 						const void *object);
+#endif
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 0da3d37e1589..23f6bfb1e73f 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -135,7 +135,12 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
 	if (IS_ENABLED(CONFIG_SLAB))
 		local_irq_save(flags);
 
+	/*
+	 * As the object now gets freed from the quaratine, assume that its
+	 * free track is now longer valid.
+	 */
 	*(u8 *)kasan_mem_to_shadow(object) = KASAN_KMALLOC_FREE;
+
 	___cache_free(cache, object, _THIS_IP_);
 
 	if (IS_ENABLED(CONFIG_SLAB))
@@ -168,6 +173,9 @@ void quarantine_put(struct kmem_cache *cache, void *object)
 	struct qlist_head temp = QLIST_INIT;
 	struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
 
+	if (!meta)
+		return;
+
 	/*
 	 * Note: irq must be disabled until after we move the batch to the
 	 * global quarantine. Otherwise quarantine_remove_cache() can miss
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 7d86af340148..6a95ad2dee91 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -168,32 +168,35 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
 static void describe_object_stacks(struct kmem_cache *cache, void *object,
 					const void *addr, u8 tag)
 {
-	struct kasan_alloc_meta *alloc_meta = kasan_get_alloc_meta(cache, object);
-
-	if (cache->flags & SLAB_KASAN) {
-		struct kasan_track *free_track;
+	struct kasan_alloc_meta *alloc_meta;
+	struct kasan_track *free_track;
 
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (alloc_meta) {
 		print_track(&alloc_meta->alloc_track, "Allocated");
 		pr_err("\n");
-		free_track = kasan_get_free_track(cache, object, tag);
-		if (free_track) {
-			print_track(free_track, "Freed");
-			pr_err("\n");
-		}
+	}
+
+	free_track = kasan_get_free_track(cache, object, tag);
+	if (free_track) {
+		print_track(free_track, "Freed");
+		pr_err("\n");
+	}
 
 #ifdef CONFIG_KASAN_GENERIC
-		if (alloc_meta->aux_stack[0]) {
-			pr_err("Last call_rcu():\n");
-			print_stack(alloc_meta->aux_stack[0]);
-			pr_err("\n");
-		}
-		if (alloc_meta->aux_stack[1]) {
-			pr_err("Second to last call_rcu():\n");
-			print_stack(alloc_meta->aux_stack[1]);
-			pr_err("\n");
-		}
-#endif
+	if (!alloc_meta)
+		return;
+	if (alloc_meta->aux_stack[0]) {
+		pr_err("Last call_rcu():\n");
+		print_stack(alloc_meta->aux_stack[0]);
+		pr_err("\n");
 	}
+	if (alloc_meta->aux_stack[1]) {
+		pr_err("Second to last call_rcu():\n");
+		print_stack(alloc_meta->aux_stack[1]);
+		pr_err("\n");
+	}
+#endif
 }
 
 static void describe_object(struct kmem_cache *cache, void *object,
diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
index 7604b46239d4..11dc8739e500 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -48,9 +48,10 @@ const char *get_bug_type(struct kasan_access_info *info)
 		object = nearest_obj(cache, page, (void *)addr);
 		alloc_meta = kasan_get_alloc_meta(cache, object);
 
-		for (i = 0; i < KASAN_NR_FREE_STACKS; i++)
-			if (alloc_meta->free_pointer_tag[i] == tag)
-				return "use-after-free";
+		if (alloc_meta)
+			for (i = 0; i < KASAN_NR_FREE_STACKS; i++)
+				if (alloc_meta->free_pointer_tag[i] == tag)
+					return "use-after-free";
 		return "out-of-bounds";
 	}
 
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index d1af6f6c6d12..be10d16bd129 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -170,6 +170,8 @@ void kasan_set_free_info(struct kmem_cache *cache,
 	u8 idx = 0;
 
 	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (!alloc_meta)
+		return;
 
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 	idx = alloc_meta->free_track_idx;
@@ -187,6 +189,8 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 	int i = 0;
 
 	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (!alloc_meta)
+		return NULL;
 
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 	for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fe30e8ab5535e14f86fbe7876e134a76374403bf.1605046662.git.andreyknvl%40google.com.
