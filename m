Return-Path: <kasan-dev+bncBAABBM6K3GMAMGQEULRRTDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F2555ADA9F
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:08:04 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id v15-20020adf8b4f000000b002285ec61b3asf998498wra.6
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:08:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412084; cv=pass;
        d=google.com; s=arc-20160816;
        b=qM2HihE2HDg6WDIM15xJBB3mMv/WJfVPp4UJUgJc14RMzM3JAhh/RVyaAuLyESvTF6
         eTfWJ7Um2ckb4DQFeMOi4yKfcMDgJT1N13d0POljWpjWk07FEXnfzJVJuGnXz7Cc8umP
         KKgl4BObAVNSy27xXcLfZRvNnymZxQ1OOnEzw0qy5IjD21SXKdUC4SB0uaQyu7yUi/5p
         W1DSQ3lF1HrD/svd00rwZ/v29kgj8a7E9fYqMlg5EGUVeGHeeFfnzVEMqERI7B8Mdlrd
         X+q03hnpqeQmy/2v0jOpTZWAUjDGBsI1ztF298Zq/2WsBAMjQzTsB601GoEOTR595bl2
         MYvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NWUzZzNu0DO9rs+ARn80cAueVDZaQIRm0fvCiD+wcsI=;
        b=0+qn1tRaVkRU4gTTrbKJdwnMQnhLtY6bbhEwdyZX3cCqjgGIuNF4cjW5uEpMLkOc8n
         l97VledEew1ONilvEeVtIgp3nPrQpPY5U+96TfPQGRV3o5eFK/Iw0t+IOObULTirTsnB
         5otvxEEF3fUPLdYAQsFIhEX+ID2BCgjgOXTG2zTEgIMBKTh5njJ8KFd3R1LoaRqtiPne
         9N2Mtn30NvJUaVGZU4vsBPM4ksx9LySZmiXh3hr4kKgHMIy1+XLScIQMorJTDIHykS1n
         tU087n18XIl4OhT64krsBxArOnXHgQwh2cm4yRv7CK4C7pIEv8NbjK5wdxMul7Zmoi1p
         2JHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VQKavR6q;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=NWUzZzNu0DO9rs+ARn80cAueVDZaQIRm0fvCiD+wcsI=;
        b=W+0yumhflgn8OXx8zhirtMKYXu1/5353s4S/jx/ZexUnV/Cr6h9r0i6T4on8HtsaXL
         Wb0Y1Q5KjVK+OseoYMw+18Q/GqePDcDF193t1D5SKqUGpWWsfd55gIMtK95ETjOE385T
         6Jsmn+XUJXYqKeCPSK+y4j3RByhui6bMVhEQt8b+vEdBsFlvGkH9NaMBaC+qh6PtW8BF
         CcTcQcUqltLrpKw2G7uXuf52oTEM98LW/Mtw31qDcUDI/nRLNNw9uUxRX/NNK0I5O0//
         ecXGNUncq3warZo1R1S93Pdx3103ot3so92s+C6o9fJTMWiJEgF0NBJn/7NQ3J5DkvvU
         GsXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=NWUzZzNu0DO9rs+ARn80cAueVDZaQIRm0fvCiD+wcsI=;
        b=y5VmmHPLx/cO72WNiB/muV4OIILsc0MnKhZCJa+iIvnCBDzmeEMkrt1/mKVBVpUr5q
         uU3G0QbdbdHwbR1KkCODpRwJ+xEviCXsNLJk2+iS8kXq8JdbgF0oVhgzLMR/TCXu6hS1
         S1xFyhdIE7u6CoJ8hFPopV9z5oC0l6GKfRzw4shcV3osPT32ZqtqudeThVHiycJbDJaB
         CKpvszVZs7VvawkKXd/vUOEMuml7hwLexmGwYUdTCdMx8cXLnpBpx/YY6p//7rHdlcql
         Ri/2ErC4aRJvjZXgX2TksyfTEN2nmY4ADosFcO1uPoBonBshMg1OCICrXCO0QkPLiXGa
         1ulQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2jBzl9axxCPPHoLzBFfFRu+L3lxvVN/CLBtD5A4+LMbU+oVKj5
	yLxFiB3Yd1nZ6XrXEG15bCA=
X-Google-Smtp-Source: AA6agR4joCpCfH0kQaVsWmVwVqLjwdIC3Y5oODqdOe5KheODVgFO91ioybWanelEFx3j2OiiTcBqzA==
X-Received: by 2002:adf:e9c2:0:b0:228:62a5:a59b with SMTP id l2-20020adfe9c2000000b0022862a5a59bmr6051941wrn.47.1662412084072;
        Mon, 05 Sep 2022 14:08:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:60c7:0:b0:228:c8fc:9de8 with SMTP id x7-20020a5d60c7000000b00228c8fc9de8ls196446wrt.1.-pod-prod-gmail;
 Mon, 05 Sep 2022 14:08:03 -0700 (PDT)
X-Received: by 2002:a5d:5143:0:b0:226:de76:be7b with SMTP id u3-20020a5d5143000000b00226de76be7bmr20595287wrt.308.1662412083498;
        Mon, 05 Sep 2022 14:08:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412083; cv=none;
        d=google.com; s=arc-20160816;
        b=GGBDbnfo2gnRiQissYkA3e7lQu6OZpmmH6N/l2tNi4CvIRU6EBHMq5kWfauf62bJnd
         mu10WfwWVei8s6edpq8QU0utg/ufmCSKQyLVo3yYDmBWekjKNV4E0+13pDrsjSsk7QwV
         AyhFivssM97Y1aDNamU+sXq7lS+rUs0a6Pb3AGE32PGZRjl0UBrmQbwPGFzJliYpItHl
         UPN1z6j09Vr2C9mD8m9kgJqB0MMhBC1y2zdjBP4Ev9Yc7KsVP8yf3J4p596mqNpNZH1j
         FLpEZea/nU/15MQjATquos1STALtNDIfBU27bKFN1vq7cXiuAiCR+40OBOs9qvVQ7+yX
         jKFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ktaPg/Sgb2yHeQQ5jl4nDpOoogpUy9NM3vqMJDUqfT8=;
        b=uxNlzR3WkBsa35xEThz++8ajyIskT+Pz28oYo75RhlP31ea44WRKWdePoc4cfvdu5C
         YFSB7MD5mRTcbrjYIDlysORCov1uqHdhqtVKlOHcLR4EtaY2CV/je7bcgy4ugDV4J03p
         zyl7veUIyrX6ccTdrF0GFjt2a0XAvMvZVobuEKMC5yffInEGQA2t/31+4ytxQpKO7or9
         O8+uxRTc91LpLXuvKmQXRl7Tfs+jdASBnSvb5jHz+XeZ43+pMNPpkt9AXNSJ7GmsIRC2
         nOBM44zlVrM3+Q2rh3M0KYy5UqZfGgjzUTTBPO08mwMYqb2dtGnecPFLiB8CXzoDIysv
         3jSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VQKavR6q;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id c7-20020a05600c0ac700b003a83f11cec0si605862wmr.2.2022.09.05.14.08.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:08:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 12/34] kasan: introduce kasan_init_cache_meta
Date: Mon,  5 Sep 2022 23:05:27 +0200
Message-Id: <a6d7ea01876eb36472c9879f7b23f1b24766276e.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=VQKavR6q;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Add a kasan_init_cache_meta() helper that initializes metadata-related
cache parameters and use this helper in the common KASAN code.

Put the implementation of this new helper into generic.c, as only the
Generic mode uses per-object metadata.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c  | 80 ++--------------------------------------------
 mm/kasan/generic.c | 79 +++++++++++++++++++++++++++++++++++++++++++++
 mm/kasan/kasan.h   |  2 ++
 3 files changed, 83 insertions(+), 78 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index d0300954d76b..b6a74fe5e740 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -118,28 +118,9 @@ void __kasan_poison_pages(struct page *page, unsigned int order, bool init)
 			     KASAN_PAGE_FREE, init);
 }
 
-/*
- * Adaptive redzone policy taken from the userspace AddressSanitizer runtime.
- * For larger allocations larger redzones are used.
- */
-static inline unsigned int optimal_redzone(unsigned int object_size)
-{
-	return
-		object_size <= 64        - 16   ? 16 :
-		object_size <= 128       - 32   ? 32 :
-		object_size <= 512       - 64   ? 64 :
-		object_size <= 4096      - 128  ? 128 :
-		object_size <= (1 << 14) - 256  ? 256 :
-		object_size <= (1 << 15) - 512  ? 512 :
-		object_size <= (1 << 16) - 1024 ? 1024 : 2048;
-}
-
 void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 			  slab_flags_t *flags)
 {
-	unsigned int ok_size;
-	unsigned int optimal_size;
-
 	/*
 	 * SLAB_KASAN is used to mark caches as ones that are sanitized by
 	 * KASAN. Currently this flag is used in two places:
@@ -149,65 +130,8 @@ void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	 */
 	*flags |= SLAB_KASAN;
 
-	if (!kasan_requires_meta())
-		return;
-
-	ok_size = *size;
-
-	/* Add alloc meta into redzone. */
-	cache->kasan_info.alloc_meta_offset = *size;
-	*size += sizeof(struct kasan_alloc_meta);
-
-	/*
-	 * If alloc meta doesn't fit, don't add it.
-	 * This can only happen with SLAB, as it has KMALLOC_MAX_SIZE equal
-	 * to KMALLOC_MAX_CACHE_SIZE and doesn't fall back to page_alloc for
-	 * larger sizes.
-	 */
-	if (*size > KMALLOC_MAX_SIZE) {
-		cache->kasan_info.alloc_meta_offset = 0;
-		*size = ok_size;
-		/* Continue, since free meta might still fit. */
-	}
-
-	/* Only the generic mode uses free meta or flexible redzones. */
-	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
-		cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
-		return;
-	}
-
-	/*
-	 * Add free meta into redzone when it's not possible to store
-	 * it in the object. This is the case when:
-	 * 1. Object is SLAB_TYPESAFE_BY_RCU, which means that it can
-	 *    be touched after it was freed, or
-	 * 2. Object has a constructor, which means it's expected to
-	 *    retain its content until the next allocation, or
-	 * 3. Object is too small.
-	 * Otherwise cache->kasan_info.free_meta_offset = 0 is implied.
-	 */
-	if ((cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor ||
-	    cache->object_size < sizeof(struct kasan_free_meta)) {
-		ok_size = *size;
-
-		cache->kasan_info.free_meta_offset = *size;
-		*size += sizeof(struct kasan_free_meta);
-
-		/* If free meta doesn't fit, don't add it. */
-		if (*size > KMALLOC_MAX_SIZE) {
-			cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
-			*size = ok_size;
-		}
-	}
-
-	/* Calculate size with optimal redzone. */
-	optimal_size = cache->object_size + optimal_redzone(cache->object_size);
-	/* Limit it with KMALLOC_MAX_SIZE (relevant for SLAB only). */
-	if (optimal_size > KMALLOC_MAX_SIZE)
-		optimal_size = KMALLOC_MAX_SIZE;
-	/* Use optimal size if the size with added metas is not large enough. */
-	if (*size < optimal_size)
-		*size = optimal_size;
+	if (kasan_requires_meta())
+		kasan_init_cache_meta(cache, size);
 }
 
 void __kasan_cache_create_kmalloc(struct kmem_cache *cache)
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index fa654cb96a0d..73aea784040a 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -328,6 +328,85 @@ DEFINE_ASAN_SET_SHADOW(f3);
 DEFINE_ASAN_SET_SHADOW(f5);
 DEFINE_ASAN_SET_SHADOW(f8);
 
+/*
+ * Adaptive redzone policy taken from the userspace AddressSanitizer runtime.
+ * For larger allocations larger redzones are used.
+ */
+static inline unsigned int optimal_redzone(unsigned int object_size)
+{
+	return
+		object_size <= 64        - 16   ? 16 :
+		object_size <= 128       - 32   ? 32 :
+		object_size <= 512       - 64   ? 64 :
+		object_size <= 4096      - 128  ? 128 :
+		object_size <= (1 << 14) - 256  ? 256 :
+		object_size <= (1 << 15) - 512  ? 512 :
+		object_size <= (1 << 16) - 1024 ? 1024 : 2048;
+}
+
+void kasan_init_cache_meta(struct kmem_cache *cache, unsigned int *size)
+{
+	unsigned int ok_size;
+	unsigned int optimal_size;
+
+	ok_size = *size;
+
+	/* Add alloc meta into redzone. */
+	cache->kasan_info.alloc_meta_offset = *size;
+	*size += sizeof(struct kasan_alloc_meta);
+
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
+	}
+
+	/* Only the generic mode uses free meta or flexible redzones. */
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
+		return;
+	}
+
+	/*
+	 * Add free meta into redzone when it's not possible to store
+	 * it in the object. This is the case when:
+	 * 1. Object is SLAB_TYPESAFE_BY_RCU, which means that it can
+	 *    be touched after it was freed, or
+	 * 2. Object has a constructor, which means it's expected to
+	 *    retain its content until the next allocation, or
+	 * 3. Object is too small.
+	 * Otherwise cache->kasan_info.free_meta_offset = 0 is implied.
+	 */
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
+	}
+
+	/* Calculate size with optimal redzone. */
+	optimal_size = cache->object_size + optimal_redzone(cache->object_size);
+	/* Limit it with KMALLOC_MAX_SIZE (relevant for SLAB only). */
+	if (optimal_size > KMALLOC_MAX_SIZE)
+		optimal_size = KMALLOC_MAX_SIZE;
+	/* Use optimal size if the size with added metas is not large enough. */
+	if (*size < optimal_size)
+		*size = optimal_size;
+}
+
 struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
 					      const void *object)
 {
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 1736abd661b6..6da35370ba37 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -297,12 +297,14 @@ struct page *kasan_addr_to_page(const void *addr);
 struct slab *kasan_addr_to_slab(const void *addr);
 
 #ifdef CONFIG_KASAN_GENERIC
+void kasan_init_cache_meta(struct kmem_cache *cache, unsigned int *size);
 void kasan_init_object_meta(struct kmem_cache *cache, const void *object);
 struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
 						const void *object);
 struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 						const void *object);
 #else
+static inline void kasan_init_cache_meta(struct kmem_cache *cache, unsigned int *size) { }
 static inline void kasan_init_object_meta(struct kmem_cache *cache, const void *object) { }
 #endif
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a6d7ea01876eb36472c9879f7b23f1b24766276e.1662411799.git.andreyknvl%40google.com.
