Return-Path: <kasan-dev+bncBAABBKH6VKJQMGQEFUFQH2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E65A5139A3
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 18:22:01 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id ay39-20020a05600c1e2700b0038ff4f1014fsf2133967wmb.7
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 09:22:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651162921; cv=pass;
        d=google.com; s=arc-20160816;
        b=KJWTQtGuzqta0wWOT5eA85PuZc//XNndsH0hozZ0fA2B+VSxaRsZN6TUSyRH35PoAd
         qGMPo5aCzoWbL2SCsnd4BEaDxyMdCZE/Qo2pV6/STki/s1QNVbu0lO+fRPi3puRvSXyK
         B5R7IG9q0hyIj37Y40PKQU0nRLbOBKkVkI0TnVAgHbsfB9y7QBKwl2IQL12L4EwaAP+H
         LJrj4/ObHwW6XEYcTYXf/yKwq2JvMfkthS8U5Hbsb8tdv786+108g66yhYQ1PLV4sG5b
         pzQxtOUZN1HmkSPAnImd4sy6BV4AMsB2fhMWrupxv73vPwfBMFBrzCdxRwuj1lZjpqNi
         htFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1wMgJUPr6JBJ5JH/3Gmp8J2It4JzXnUbDdHXuuU/Nf0=;
        b=AC7md3Y7UnxPiwFEBDjrS+G7L51kxyO1M8nrBljd+QGPoAdqtoDbg4SlsgvFSfIjKd
         To3m8Okom0FQN16STHpd/zp3GGmNfiZdBLHlKenRuElWE3OJYD94Q39Yi5UFC3ecSQte
         kf0GL3iYz4koRWCJl69sr1ocj2zb9oeOtXWyo6zafy9YoD+UzbgPNPYJ5WFrwPfAw4oy
         iBA80Hyr7VBh6FPGJN4Ypy9RkM4BANYxa5vNHC8EaGwyn/EQSlVyK+NjWOrBzAldegjb
         kwcWZ+tg4h9DMc1uVPLVUb3UAZbYOnT3tIVARAXTbq/jdBwb5mmteyC8qio7b9rvHUiy
         Q8zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fVu2K6g4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1wMgJUPr6JBJ5JH/3Gmp8J2It4JzXnUbDdHXuuU/Nf0=;
        b=LR9Q1KbkegNJTm2dABxr9W4dmFQSjHVYvgb8K8IkNcSVV+8zOmGp8gZBJ0pbNSwHW+
         Arb2/kwLICC/sqTRVUeXBkBHChQwnb7JsKPcUobaVUkwpb7+A0ku3f4qvoyMIWe+eBar
         Y34cT1s4UTFIi91noupiURvHrwdVq66SYCcPjT7lQu/0hsXAfBGB7lg4sUuTnO65yrAY
         r0zsY8nbssCRzLXwPTzLEnY9LUzbtYWwpZwoxexMw7AEunB1LNvSweiHTmoFLtzLTxgw
         Up5p9HD8tHWxB6oqs1DnT5jW0t6yqWZKNOBwuE14aPm4Vu6YXX/RXHIAp8D0rwV1GCeA
         WrLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1wMgJUPr6JBJ5JH/3Gmp8J2It4JzXnUbDdHXuuU/Nf0=;
        b=pGrFWN5WpLSeUFZItMI3dkyigyv06T/Qz/fluzGmg6+ag5Yx+tPn/3reaCJDNV4Y5j
         NBX6U6L2k10oxmwXaxdX4tHvQ6ioKj7rpkxG8Yanvun3chU/fuc1+AL1O1suM5ixfV+F
         8NTRN0/UtZ44joHWxWDaIVhsVt6fNqrBJqE0rFC+0RLXyvqqLavi4IcHLDW0ja0M6a60
         Jdrue+2eMlUYq64sZpGYUrADV6MZ/8/QDQ9Cv+42J42BxYj4ywJjUI+2ptPPMwXhZ50m
         ASmMi7pRHQaHi4MPaR9/IAHoidPn77ki9B0yFUqbtyUBJ+QQVdDP2kARmDa4j44HDX0f
         39UQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531323l4dPML2DnLZzsLjT7oG41zH6SVaGar8dOIBicofKeAY5SV
	IWXuGgMQp0SMjsk/1Ftqmw4=
X-Google-Smtp-Source: ABdhPJw2ricjXvezDh/FkCi+geyP2y+/WvQLJ6wAvAVVAmfQbV/YNU8Q7JKoUL4MlxHH48DWXQHfDg==
X-Received: by 2002:adf:fd45:0:b0:20a:d0fa:1342 with SMTP id h5-20020adffd45000000b0020ad0fa1342mr22771948wrs.595.1651162921059;
        Thu, 28 Apr 2022 09:22:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f950:0:b0:205:dbf5:72d8 with SMTP id q16-20020adff950000000b00205dbf572d8ls718948wrr.0.gmail;
 Thu, 28 Apr 2022 09:22:00 -0700 (PDT)
X-Received: by 2002:a5d:4fca:0:b0:20a:cf56:a894 with SMTP id h10-20020a5d4fca000000b0020acf56a894mr23198322wrw.528.1651162920372;
        Thu, 28 Apr 2022 09:22:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651162920; cv=none;
        d=google.com; s=arc-20160816;
        b=xcOIt2sN5Zf2/C/v5zcvT3xz675H1fG+LwDU2C5fJ0Od+upalXbdKAYfGqwxLvhFa/
         +B2dO4dvM0pIiJJE/dFO41MSuAtuTe7XIbCbyBkkkYt1ExgSFrlVL0oufa5Vjb03pb91
         j5Ff6Bpi/Mgw5LJ1fc7Bm/QEBw3nyBUsN2SxXnLvYOxfrdkl3Jz6NcCFmoyCKj1xudi+
         Zd06hcrETtd1G7kgTwaKrd9jcd3QvfBHwOo34rwAZhr1gDCOFJq5Qco5yqCxtZnxNJc3
         JXb0rYCX4A4/zkl/UdPKQOFyqM2BcIgzIL/9Q4uqfw6nexfLtSd+YynpM7Qf88aR81Uj
         DmIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BH942fTrVXtBdrYiEmF6IffforHv8CYbMy+kTtVqBFE=;
        b=aoioCgga4c6HL3NSimLsQiYb+5NDqe5M2lVmM6gSIDjqWaq3IF+jdGmLN2EarGKH6M
         WhLZ+usf+vml/04cfJkkGUzMRdZeNV1NcBjkT7oQvhOcOc8sB0kF0TrIEAqckslL1LO+
         +v9pvrGjUKjV/27TBH69fXA0mdqcltFEGFbzo9feHpWJAikWWT1mLempuHb/lXruRtKx
         ijT5Nzdi6NSpvXXsg7Gg1vVXeWQCeIk9jp2fLKWOgRhxAOmNamdUDormz7T0p20D7GNI
         /9nRRTqT9OE7hRLzgrQbXhJ5tOC3SMTeEfY+USwQf5hlhEOnkHb0q24QVqMkNUf6Iuez
         RHxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fVu2K6g4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id f7-20020adff987000000b001f1f8f0f76csi264092wrr.3.2022.04.28.09.22.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 28 Apr 2022 09:22:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 3/3] kasan: give better names to shadow values
Date: Thu, 28 Apr 2022 18:21:52 +0200
Message-Id: <c4105419650a2a8d9f153f55b5e76f4daa428297.1651162840.git.andreyknvl@google.com>
In-Reply-To: <3167cbec7a82704c1ed2c6bfe85b77534a836fdc.1651162840.git.andreyknvl@google.com>
References: <3167cbec7a82704c1ed2c6bfe85b77534a836fdc.1651162840.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=fVu2K6g4;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Rename KASAN_KMALLOC_* shadow values to KASAN_SLAB_*, as they are used
for all slab allocations, not only for kmalloc.

Also rename KASAN_FREE_PAGE to KASAN_PAGE_FREE to be consistent with
KASAN_PAGE_REDZONE and KASAN_SLAB_FREE.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c         | 12 ++++++------
 mm/kasan/generic.c        |  6 +++---
 mm/kasan/kasan.h          | 14 +++++++-------
 mm/kasan/quarantine.c     |  2 +-
 mm/kasan/report_generic.c |  8 ++++----
 5 files changed, 21 insertions(+), 21 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index d9079ec11f31..c40c0e7b3b5f 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -117,7 +117,7 @@ void __kasan_poison_pages(struct page *page, unsigned int order, bool init)
 {
 	if (likely(!PageHighMem(page)))
 		kasan_poison(page_address(page), PAGE_SIZE << order,
-			     KASAN_FREE_PAGE, init);
+			     KASAN_PAGE_FREE, init);
 }
 
 /*
@@ -254,7 +254,7 @@ void __kasan_poison_slab(struct slab *slab)
 	for (i = 0; i < compound_nr(page); i++)
 		page_kasan_tag_reset(page + i);
 	kasan_poison(page_address(page), page_size(page),
-		     KASAN_KMALLOC_REDZONE, false);
+		     KASAN_SLAB_REDZONE, false);
 }
 
 void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
@@ -265,7 +265,7 @@ void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
 void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
 {
 	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
-			KASAN_KMALLOC_REDZONE, false);
+			KASAN_SLAB_REDZONE, false);
 }
 
 /*
@@ -357,7 +357,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 	}
 
 	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
-			KASAN_KMALLOC_FREE, init);
+			KASAN_SLAB_FREE, init);
 
 	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine))
 		return false;
@@ -414,7 +414,7 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 	if (unlikely(!folio_test_slab(folio))) {
 		if (____kasan_kfree_large(ptr, ip))
 			return;
-		kasan_poison(ptr, folio_size(folio), KASAN_FREE_PAGE, false);
+		kasan_poison(ptr, folio_size(folio), KASAN_PAGE_FREE, false);
 	} else {
 		struct slab *slab = folio_slab(folio);
 
@@ -505,7 +505,7 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
 	redzone_end = round_up((unsigned long)(object + cache->object_size),
 				KASAN_GRANULE_SIZE);
 	kasan_poison((void *)redzone_start, redzone_end - redzone_start,
-			   KASAN_KMALLOC_REDZONE, false);
+			   KASAN_SLAB_REDZONE, false);
 
 	/*
 	 * Save alloc info (if possible) for kmalloc() allocations.
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index a25ad4090615..437fcc7e77cf 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -369,14 +369,14 @@ void kasan_set_free_info(struct kmem_cache *cache,
 
 	kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
 	/* The object was freed and has free track set. */
-	*(u8 *)kasan_mem_to_shadow(object) = KASAN_KMALLOC_FREETRACK;
+	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREETRACK;
 }
 
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
-	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_KMALLOC_FREETRACK)
+	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREETRACK)
 		return NULL;
-	/* Free meta must be present with KASAN_KMALLOC_FREETRACK. */
+	/* Free meta must be present with KASAN_SLAB_FREETRACK. */
 	return &kasan_get_free_meta(cache, object)->free_track;
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 06fdea41ca4a..41681d3c551d 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -74,22 +74,22 @@ static inline bool kasan_sync_fault_possible(void)
 #define KASAN_MEMORY_PER_SHADOW_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
 
 #ifdef CONFIG_KASAN_GENERIC
-#define KASAN_FREE_PAGE		0xFF  /* freed page */
+#define KASAN_PAGE_FREE		0xFF  /* freed page */
 #define KASAN_PAGE_REDZONE	0xFE  /* redzone for kmalloc_large allocation */
-#define KASAN_KMALLOC_REDZONE	0xFC  /* redzone for slab object */
-#define KASAN_KMALLOC_FREE	0xFB  /* freed slab object */
+#define KASAN_SLAB_REDZONE	0xFC  /* redzone for slab object */
+#define KASAN_SLAB_FREE		0xFB  /* freed slab object */
 #define KASAN_VMALLOC_INVALID	0xF8  /* inaccessible space in vmap area */
 #else
-#define KASAN_FREE_PAGE		KASAN_TAG_INVALID
+#define KASAN_PAGE_FREE		KASAN_TAG_INVALID
 #define KASAN_PAGE_REDZONE	KASAN_TAG_INVALID
-#define KASAN_KMALLOC_REDZONE	KASAN_TAG_INVALID
-#define KASAN_KMALLOC_FREE	KASAN_TAG_INVALID
+#define KASAN_SLAB_REDZONE	KASAN_TAG_INVALID
+#define KASAN_SLAB_FREE		KASAN_TAG_INVALID
 #define KASAN_VMALLOC_INVALID	KASAN_TAG_INVALID /* only used for SW_TAGS */
 #endif
 
 #ifdef CONFIG_KASAN_GENERIC
 
-#define KASAN_KMALLOC_FREETRACK	0xFA  /* freed slab object with free track */
+#define KASAN_SLAB_FREETRACK	0xFA  /* freed slab object with free track */
 #define KASAN_GLOBAL_REDZONE	0xF9  /* redzone for global variable */
 
 /* Stack redzone shadow values. Compiler's ABI, do not change. */
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 0a9def8ce5e8..fac4befb9ef2 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -152,7 +152,7 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
 	 * As the object now gets freed from the quarantine, assume that its
 	 * free track is no longer valid.
 	 */
-	*(u8 *)kasan_mem_to_shadow(object) = KASAN_KMALLOC_FREE;
+	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREE;
 
 	___cache_free(cache, object, _THIS_IP_);
 
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index efc5e79a103f..6689fb9a919b 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -66,7 +66,7 @@ static const char *get_shadow_bug_type(struct kasan_report_info *info)
 		bug_type = "out-of-bounds";
 		break;
 	case KASAN_PAGE_REDZONE:
-	case KASAN_KMALLOC_REDZONE:
+	case KASAN_SLAB_REDZONE:
 		bug_type = "slab-out-of-bounds";
 		break;
 	case KASAN_GLOBAL_REDZONE:
@@ -78,9 +78,9 @@ static const char *get_shadow_bug_type(struct kasan_report_info *info)
 	case KASAN_STACK_PARTIAL:
 		bug_type = "stack-out-of-bounds";
 		break;
-	case KASAN_FREE_PAGE:
-	case KASAN_KMALLOC_FREE:
-	case KASAN_KMALLOC_FREETRACK:
+	case KASAN_PAGE_FREE:
+	case KASAN_SLAB_FREE:
+	case KASAN_SLAB_FREETRACK:
 		bug_type = "use-after-free";
 		break;
 	case KASAN_ALLOCA_LEFT:
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c4105419650a2a8d9f153f55b5e76f4daa428297.1651162840.git.andreyknvl%40google.com.
