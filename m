Return-Path: <kasan-dev+bncBAABBEHR4SJQMGQENOAV57I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id AEE1A5201A0
	for <lists+kasan-dev@lfdr.de>; Mon,  9 May 2022 17:51:44 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id s16-20020adfeb10000000b0020cc4e5e683sf1662070wrn.6
        for <lists+kasan-dev@lfdr.de>; Mon, 09 May 2022 08:51:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652111504; cv=pass;
        d=google.com; s=arc-20160816;
        b=ACHA4syAVCqapYxO1aPWtPv5iceQGGSgDD8cMWbczxUFHhixrmgIcsH4wzrFBWrUXz
         nZ/zAPXLI1ej8oou0By0MwbWXGgiG+AjEbjX4Y7Y8hUzSLmyBugROOTNHlXlOIZDDEaz
         NhGaENQZEkKcSHQPOFB5p59KxJ9x9S+iUqB81xCZiI4ScyC7dhygd8yQVTTWQDckhLUF
         qglhVIOxmzKE6NJh6t22ghrCihESXDGahC7IdqFlLcZSbLSwcsv2iMvqTpCFoE797mAM
         bzW3sz1GBywogTPabiokzp6YK+GjyXl3JvqFBKeRcfEt8ovp8wXf7aEDzJeINSkLkWdH
         Sd8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1PHXbY/4oBjmMxudmj3QFp01uCG7GwWyy0w7sA0wr8o=;
        b=rfXzjpKJkEMK6fJwT/4QcF22KMVrD/aS3HDK6jCypCyefeCWKB5lwrg9kSVjuZ08TY
         M8GJYxoXdDkG2M8CkF/wqFa/H2BiBzr/mZJ3EICvQ+cXmV1aHOY1q86gWASl2DWXOzeH
         3Mv8KyktQ5od4IOn51JruTGAKUrbPRW3dbSb0i1GqBjpHJjsXUFjeMLBmufrd+x2PMPK
         4hAjY4hPpRY3Z9IBebZZRePadi/csyIbD8fy7i8pwoIgQ+EOOW9dWo2jUfBH5r28k0Bx
         ERtjUNVyHak3f153BwiZ3e+fdJVtlmAfMWfFYXTcTMrZfkIUqW3evqdAmdlsOREw40/x
         i2Kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=r755JKWN;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1PHXbY/4oBjmMxudmj3QFp01uCG7GwWyy0w7sA0wr8o=;
        b=pEGZEN0OI318Qgxl9m32cwsBfqmzTguNu5pPfy4FeX0C1ggWVjFLqYvGjqvOqvY/+Y
         9azsJg0PMhjcAC0EARFKSQR7R/kKLLqZ5CdKvyeMjryOVTJOjk1gLkVAKp94ltN5gXH4
         5Bs8Oo+aSUiqfYjV1/UexxIw95U6V5x/pTn2oFTOLqjbMehtf6y8gspDLzo+1MSWiktw
         3yXxoa6OT02riSFw/nbfjrp8DZSX3H1YJUOiIeIoDsFRNciBCwMygX3P5dfUX06bqmYh
         yEcGO1L/sw/p8xUIvUBBIkpUXGLeCMWIj7zSMWHNBn1kjZ9u8RsN+CeoqQUQTTuwRR3E
         cnWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1PHXbY/4oBjmMxudmj3QFp01uCG7GwWyy0w7sA0wr8o=;
        b=exwsRcwqMiq4S8bfLzyqoUP1PC6q5JQ13sfsdcmR+0KoBsbafJs6B2WArHPc+W42M1
         FPH+5E63cn5V9uDGWgAzApJKlJRBY2LefNNMkNysHL1JOvLERMqy7bnBYdDuWAnRLnl6
         kIUVWB97tGhi0hv+9ELQ322EEViT+KWFpTiVx3+sD5/57tovPxuqE/nvYkrxGOxygTWi
         6DfazVjDxt0eD3HTsWswimavUumaSQaVlVKjna7owaJEeFdH12GXPvBsJneZsNQwlp8b
         26id71HQxgW4zXYf9N+HhAnqfHSTWPWkVhlVkb/IZhIvmzB98onopwqUEbju4CCHHjzZ
         VTCA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HGu4HszXoJzzbSCPyGss70xZmUL9xJi34pgVBWznN+GcueLG1
	UNRgIvNyzMjSngqbWcSBdwo=
X-Google-Smtp-Source: ABdhPJzKopDqFCKOjJhR1pF4c5WTxqYC1A0WqVy+Z6lqKMgm4o4Cs0uSHGS77Qo3kFki6AnY2+5EMA==
X-Received: by 2002:a5d:6552:0:b0:20c:7a44:d8c9 with SMTP id z18-20020a5d6552000000b0020c7a44d8c9mr14684996wrv.389.1652111504309;
        Mon, 09 May 2022 08:51:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d96:b0:394:86e0:4174 with SMTP id
 p22-20020a05600c1d9600b0039486e04174ls2479689wms.3.gmail; Mon, 09 May 2022
 08:51:43 -0700 (PDT)
X-Received: by 2002:a05:600c:3041:b0:394:8835:2223 with SMTP id n1-20020a05600c304100b0039488352223mr9506844wmh.160.1652111503649;
        Mon, 09 May 2022 08:51:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652111503; cv=none;
        d=google.com; s=arc-20160816;
        b=rWbibDI/GuyHtCxiV8QqMIXTuX7lBbh1qprxhMSXZyZmHW++sVDWlxxDQyJrL1b2Zb
         v+akiT5vVLHj+G3aUWx3EzDD67hXoNJerc7lu50Im4e1YMCG5pZ+z2SfwkI9V3COYR8n
         d/aLdAfTrqKKVDBiZO5WmoauEIGacs1GS7ya4y+lRyWrVhldrDwvtf9OZL6YP00nTtCW
         ssMWgD/0y1i0o2gNyADVYPfHa5Bb0hJTW7q0q6GStpSvmZFgnX2NtzMiro5k8YAJl+KJ
         OVagcIUVkrhKjfcJemlZ+OAnmW1PKnKHpFgTlz3Mqjc0F+qjp3OrBlMQRpDigCpR5x/x
         cYwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=cdChAqh9Z1Z7THY7s/iFk3WWip4uaed5XjcYAp3h5fU=;
        b=apKBvnRYBPY5ojnK4GEehS2ow615ZFszEZq4ktcLEJ/NIxhcHS39CCcco8+F2HBriJ
         KjC/7cslGCehYEEOIUF4QsgqPWMlSVkIpBjCvH+5LzwtDTZkjrX0gTjkFW2ChVHG0/0c
         3BtanEVAKUjy5n+M+3Z09bZi/cv/biLiuZgttxNp+xQjXk8ZaUm55TyZptFQ790Fy5LV
         OSCDW2So6G+sBs13ov76eDGRapxkAXr3+L5eD8mQmiGCXRfFbxCab7rZ6ZlSC4Q4pfTM
         huEGX6UA97gH88ywHe+QyzxD+R1U4vu+KGcabDOrgpTwBdAWsPw6sC5J/8qq/lYnn6+p
         Wnjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=r755JKWN;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id b5-20020adff245000000b0020c7b2af134si540201wrp.0.2022.05.09.08.51.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 09 May 2022 08:51:43 -0700 (PDT)
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
Subject: [PATCH v2 3/3] kasan: give better names to shadow values
Date: Mon,  9 May 2022 17:51:36 +0200
Message-Id: <bebcaf4eafdb0cabae0401a69c0af956aa87fcaa.1652111464.git.andreyknvl@google.com>
In-Reply-To: <a0680ff30035b56cb7bdd5f59fd400e71712ceb5.1652111464.git.andreyknvl@google.com>
References: <a0680ff30035b56cb7bdd5f59fd400e71712ceb5.1652111464.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=r755JKWN;       spf=pass
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

Reviewed-by: Alexander Potapenko <glider@google.com>
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
index a60ed636e899..610d60d6e5b8 100644
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
 
 /* Stack redzone shadow values. Compiler ABI, do not change. */
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bebcaf4eafdb0cabae0401a69c0af956aa87fcaa.1652111464.git.andreyknvl%40google.com.
