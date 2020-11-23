Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZVQ6D6QKGQECTXCVDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 386612C157A
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:15:36 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id c9sf24505449ybs.8
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:15:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162535; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hs+RP6j0JEaSKR1GRhhjHo+LFKptneqCSO41WeQEzdo5ZnnvXp7/E1lM2Td7ALSksL
         bLzt6fFkGG1VpaEz3KGqabeJYzCfebkrzDnLy3J5IDoN3qbcv5iubHxIUkhtwpj8I8u9
         4UPtX+vYCx5YC5KkRey9CMsBVACZlJjDZw1MhS80iYJSRyljrKzy/W1rFcw/cdoHMEzL
         ZTVvL1VsuKHF7UJ10UgCrx+r/IDvHBEPl1i0aOR9rnL3SMxp6YKmBY5Zkq7mhhxHHCTN
         vqne1KFW3Au7qpCgzpneQLYx2k3cDCXSfCPViID7b7yMGztqYt/rJQsBlNYYwXi4FIfP
         w/zQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=6w4Fj6JJuri8ZDANgNiZOIvKsX4as08HLs5QZErtjF0=;
        b=Fop72tk/9h4ef7hZEjpGI0QjyFzgbSvZXv+MO/gkPpeok0l1Zqms8piP94MopI1O8N
         1/jTUjgM27/Q3GBaL6huKncC9R1jkBVzrAY3BfaGARaXtEJF/KREm8vmFtULmaUojb39
         rA9nhlC9dvYrx7RMhytFLkZhsKmOlQC2Mqt3emcdVk7RQeJItbBnms0VhOPRGJaD+Wq0
         I/ZY1PPHzAZUzbSoGriFHKSwSJE8ev4mqmdRcX21qdHY+yzqnIcjOWt+4XcIMwC+gwUv
         IsH0v51CJ9tLywB93UKU8uc2Fc0avivgCf2/5ecyP43PWwrJhw4LyFCTZ/v0AQTC+o7z
         oAUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vb3tnn8k;
       spf=pass (google.com: domain of 3zri8xwokcyoo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3ZRi8XwoKCYoo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6w4Fj6JJuri8ZDANgNiZOIvKsX4as08HLs5QZErtjF0=;
        b=f9I4gGrXhrzsS1/izRCScDVsasIxwVMIftyJmRrSzlbRSeBTI31pYopC88fxxfiQBu
         CMhh//T9RpTWz5nsju3cjYtvE81cHX3myGLNhHaXCkiF4IvcKmqTBSnyGCxzGCuNHvDJ
         U4AOar8pCB9NK4wgi6gTs8I4UlzZvDVy0BJgE/qzD81IAV2fddjj76PDskwEdGGZumMv
         foWQapE6h745zEipBtRiyO847mhXJHYHAEdDflwEJqD90cs2q/Ks44bKHL6TxgfN3d42
         WNH7et3JYZrJo37CcGoLp8xqUU16SlG75rGRZtNOlcC9bbI4KZjF6TOAImgiwEBX38cA
         pN6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6w4Fj6JJuri8ZDANgNiZOIvKsX4as08HLs5QZErtjF0=;
        b=KtpYFDAYCq/X2VyzcXyFMjsfIiTVvTN+dJTEGZOxWCR4vcEmstesCorkU33AZB3pB+
         CG9NozVhcVUAg4s6LANoLS2EMEr8yL+OVROIyJQDJMFVMsO2A9ErgwsHqbFkY5YSYcdW
         /c7qMJ+av1hoHSGFUfyraNH5uSrSOgT5u21eH5fhla1AYgMtpzVLxiEb0gmiPd5IUDfc
         brSLs+dIiNyrQYOVCu25tprOLeX/jH5xjWET/VFEb8d2rEH211N/THJ9CoXWf/mGFY8c
         sQhjNPtVO57uhTBDsLruJEV6s5GSi6PzaUyzh0geYnuPjlbXEqdmX38Py21Ja8FEwD60
         x/8w==
X-Gm-Message-State: AOAM533G+nIY9qzhiPQWlyZkAkJ3NnxBvkP/adRm278g/44BrCaja1hW
	blayPV3C85fOWCxTfABGJDE=
X-Google-Smtp-Source: ABdhPJz/JAMMU7YDaGk5BOtlzdU35kKolM0SvzM8x9eH0EdFtYeyyAwM45U+0dncaTper2U25p5Plg==
X-Received: by 2002:a25:d0c5:: with SMTP id h188mr1428893ybg.13.1606162535091;
        Mon, 23 Nov 2020 12:15:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:19c3:: with SMTP id 186ls565411ybz.7.gmail; Mon, 23 Nov
 2020 12:15:34 -0800 (PST)
X-Received: by 2002:a25:76c3:: with SMTP id r186mr1928700ybc.101.1606162534454;
        Mon, 23 Nov 2020 12:15:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162534; cv=none;
        d=google.com; s=arc-20160816;
        b=Rm6MVed9m9Mn/n8HD71tbY1FjcJSfDKGrRrLCMq01RLOgvfVkgEiJ9zhMzjId6RB82
         5p392UqaFv8p9uI7a79Z1dPHumVsCUNdEsmhDBulMZ6foLRe0Wn2pC9u9Ao5wjEqxV7Y
         EJpV5LroR+QUvj/bIOxl1Ek7Ayeen1/VSQ5QMViVSv+k0pE6piWsbIniIxoUjf9d0bpt
         OXYyxkEiqQQoFwwarzax/HTUHSFwxJaLLPlA5pk3xgjsIEE5qi9OO3bsRJOtfDzDliSk
         p9Sn+JC248M53oGib3B/8GXkLGpNIB3MQy4ZJ1zY6azx6zuT4zpFYhhfXVR6IPflanvu
         CkEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ynP119GCVFCNEeKVEPVj7pM+QyD/hOvaLJsj/XDDQFw=;
        b=Pxl20vdDUo/D1mGTGt1sBBZKDNFRpezHrbtwOrWt/CCZrmZn8YUBWRr8MmVeX+3iIY
         BcC1CvI9Z44uPIy8QwE83tCPomKOVgUFBNlwPhjOPLa9QdpF/SCEwB6t5/HHFxQ6LelR
         ZFvP+HQsFW9Mc3dDbnbVRLIfOIkFtSdFWsVYuQYLFjL4Z5j23A7U8NhOpXMDO4iArN2P
         Mttt8B37ursVXKRp0pBcdyfCXHOLPZ7Oq/8cqJUN1WzTgKBNCvSBfP9JYh/GZCFS14Ra
         w1pn7GFJ0tauwvvzMejo61wPy6keWNJaPbjhtuE4spiBmOVlSbdRBaUk3bPstkwI/e4g
         8nMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vb3tnn8k;
       spf=pass (google.com: domain of 3zri8xwokcyoo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3ZRi8XwoKCYoo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id n185si755699yba.3.2020.11.23.12.15.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:15:34 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zri8xwokcyoo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id v1so13718014qvf.11
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:15:34 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:ab07:: with SMTP id
 h7mr1353179qvb.34.1606162533975; Mon, 23 Nov 2020 12:15:33 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:47 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <aee34b87a5e4afe586c2ac6a0b32db8dc4dcc2dc.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 17/19] kasan: sanitize objects when metadata doesn't fit
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Vincenzo Frascino <Vincenzo.Frascino@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vb3tnn8k;       spf=pass
 (google.com: domain of 3zri8xwokcyoo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3ZRi8XwoKCYoo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
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

Without this change all sanitized KASAN objects would be put into
quarantine with generic KASAN. With this change, only the objects that
have metadata (i.e. when it fits) are put into quarantine, the rest is
freed right away.

Along the way rework __kasan_cache_create() and add claryfying comments.

Co-developed-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
Signed-off-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/Icd947e2bea054cb5cfbdc6cf6652227d97032dcb
---
 mm/kasan/common.c         | 116 ++++++++++++++++++++++++--------------
 mm/kasan/generic.c        |  15 ++---
 mm/kasan/hw_tags.c        |   6 +-
 mm/kasan/kasan.h          |  17 +++++-
 mm/kasan/quarantine.c     |  16 +++++-
 mm/kasan/report.c         |  43 +++++++-------
 mm/kasan/report_sw_tags.c |   9 ++-
 mm/kasan/sw_tags.c        |   4 ++
 8 files changed, 149 insertions(+), 77 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 42ba64fce8a3..249ccba1ecf5 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -115,9 +115,6 @@ void __kasan_free_pages(struct page *page, unsigned int order)
  */
 static inline unsigned int optimal_redzone(unsigned int object_size)
 {
-	if (!IS_ENABLED(CONFIG_KASAN_GENERIC))
-		return 0;
-
 	return
 		object_size <= 64        - 16   ? 16 :
 		object_size <= 128       - 32   ? 32 :
@@ -131,47 +128,77 @@ static inline unsigned int optimal_redzone(unsigned int object_size)
 void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 			  slab_flags_t *flags)
 {
-	unsigned int orig_size = *size;
-	unsigned int redzone_size;
-	int redzone_adjust;
+	unsigned int ok_size;
+	unsigned int optimal_size;
+
+	/*
+	 * SLAB_KASAN is used to mark caches as ones that are sanitized by
+	 * KASAN. Currently this flag is used in two places:
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
+	 */
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
+	 * 1. Object is SLAB_TYPESAFE_BY_RCU, which means that it can
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
+	if ((cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor ||
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
+	/* Calculate size with optimal redzone. */
+	optimal_size = cache->object_size + optimal_redzone(cache->object_size);
+	/* Limit it with KMALLOC_MAX_SIZE (relevant for SLAB only). */
+	if (optimal_size > KMALLOC_MAX_SIZE)
+		optimal_size = KMALLOC_MAX_SIZE;
+	/* Use optimal size if the size with added metas is not large enough. */
+	if (*size < optimal_size)
+		*size = optimal_size;
 }
 
 size_t __kasan_metadata_size(struct kmem_cache *cache)
@@ -187,15 +214,21 @@ size_t __kasan_metadata_size(struct kmem_cache *cache)
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
 
 void __kasan_poison_slab(struct page *page)
 {
@@ -272,11 +305,9 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
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
@@ -318,15 +349,12 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (!kasan_stack_collection_enabled())
 		return false;
 
-	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
-			unlikely(!(cache->flags & SLAB_KASAN)))
+	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine))
 		return false;
 
 	kasan_set_free_info(cache, object, tag);
 
-	quarantine_put(cache, object);
-
-	return IS_ENABLED(CONFIG_KASAN_GENERIC);
+	return quarantine_put(cache, object);
 }
 
 bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
@@ -359,7 +387,11 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 
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
@@ -389,7 +421,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	poison_range((void *)redzone_start, redzone_end - redzone_start,
 		     KASAN_KMALLOC_REDZONE);
 
-	if (kasan_stack_collection_enabled() && (cache->flags & SLAB_KASAN))
+	if (kasan_stack_collection_enabled())
 		set_alloc_info(cache, (void *)object, flags);
 
 	return set_tag(object, tag);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 9c6b77f8c4a4..157df6c762a4 100644
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
index 30ce88935e9d..c91f2c06ecb5 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -187,7 +187,8 @@ void kasan_set_free_info(struct kmem_cache *cache,
 	struct kasan_alloc_meta *alloc_meta;
 
 	alloc_meta = kasan_get_alloc_meta(cache, object);
-	kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
+	if (alloc_meta)
+		kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
 }
 
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
@@ -196,5 +197,8 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 	struct kasan_alloc_meta *alloc_meta;
 
 	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (!alloc_meta)
+		return NULL;
+
 	return &alloc_meta->free_track[0];
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index d01a5ac34f70..725a472e8ea7 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -156,20 +156,31 @@ struct kasan_alloc_meta {
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
+#define KASAN_NO_FREE_META INT_MAX
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
 
@@ -234,11 +245,11 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 
 #if defined(CONFIG_KASAN_GENERIC) && \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
-void quarantine_put(struct kmem_cache *cache, void *object);
+bool quarantine_put(struct kmem_cache *cache, void *object);
 void quarantine_reduce(void);
 void quarantine_remove_cache(struct kmem_cache *cache);
 #else
-static inline void quarantine_put(struct kmem_cache *cache, void *object) { }
+static inline bool quarantine_put(struct kmem_cache *cache, void *object) { return false; }
 static inline void quarantine_reduce(void) { }
 static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
 #endif
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 0da3d37e1589..a598c3514e1a 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -135,7 +135,12 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
 	if (IS_ENABLED(CONFIG_SLAB))
 		local_irq_save(flags);
 
+	/*
+	 * As the object now gets freed from the quaratine, assume that its
+	 * free track is no longer valid.
+	 */
 	*(u8 *)kasan_mem_to_shadow(object) = KASAN_KMALLOC_FREE;
+
 	___cache_free(cache, object, _THIS_IP_);
 
 	if (IS_ENABLED(CONFIG_SLAB))
@@ -161,13 +166,20 @@ static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cache)
 	qlist_init(q);
 }
 
-void quarantine_put(struct kmem_cache *cache, void *object)
+bool quarantine_put(struct kmem_cache *cache, void *object)
 {
 	unsigned long flags;
 	struct qlist_head *q;
 	struct qlist_head temp = QLIST_INIT;
 	struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
 
+	/*
+	 * If there's no metadata for this object, don't put it into
+	 * quarantine.
+	 */
+	if (!meta)
+		return false;
+
 	/*
 	 * Note: irq must be disabled until after we move the batch to the
 	 * global quarantine. Otherwise quarantine_remove_cache() can miss
@@ -200,6 +212,8 @@ void quarantine_put(struct kmem_cache *cache, void *object)
 	}
 
 	local_irq_restore(flags);
+
+	return true;
 }
 
 void quarantine_reduce(void)
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index ffa6076b1710..8b6656d47983 100644
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
index 7604b46239d4..1b026793ad57 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -48,9 +48,12 @@ const char *get_bug_type(struct kasan_access_info *info)
 		object = nearest_obj(cache, page, (void *)addr);
 		alloc_meta = kasan_get_alloc_meta(cache, object);
 
-		for (i = 0; i < KASAN_NR_FREE_STACKS; i++)
-			if (alloc_meta->free_pointer_tag[i] == tag)
-				return "use-after-free";
+		if (alloc_meta) {
+			for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
+				if (alloc_meta->free_pointer_tag[i] == tag)
+					return "use-after-free";
+			}
+		}
 		return "out-of-bounds";
 	}
 
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index e17de2619bbf..5dcd830805b2 100644
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/aee34b87a5e4afe586c2ac6a0b32db8dc4dcc2dc.1606162397.git.andreyknvl%40google.com.
