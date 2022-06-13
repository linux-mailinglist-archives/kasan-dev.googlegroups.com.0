Return-Path: <kasan-dev+bncBAABBXNWT2KQMGQEALX5FII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F3E6549ECC
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:17:34 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id k15-20020a7bc40f000000b0039c4b7f7d09sf3726178wmi.8
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:17:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151454; cv=pass;
        d=google.com; s=arc-20160816;
        b=w44c6QJNehPkZkrJY/GmDiPOanBkjciaEwgvsginr468X3MPjRAkuyqyIwJy3nVDzD
         gZlwzmb2bdvfe0JRp1kEcJ9NTLujqnQkYed2h04zy0FYGNJj1NGV08UnxOcqOXrh19Ar
         MexNRclAQkdWhZIyU52qjYhsH3ESlDVRJYIPqvOt+4c9r6QM1BFpsB4GHNsP5LcCTRYi
         kzSvre+zwE5nReWCc918Lr707VWtm/Z17usNrjg2AL/HPI/PAwr3TNDCJR2T5BUFuCyY
         xDGlj4OqFmyx1+r4iGvJBn1dka0DIcG7yLN1dv1gDzWpjiXk3YmkBeP6LQuzPZtcbcJX
         hV6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NgiBu7MifKAXkI/n/adyEoWh9oEnTxhPAbspJl6v0Rc=;
        b=rXrXTAjpjC5Ti2MLLEewRJYM+fvl0HJbhVr/QH11rOVnnK4z2UXM4hUW6W+Q4bngV8
         sRGL0LQah+elYScR5XkZWLMKjBvcpcnkCPd/mDpz9Cmubxr917c1Y84EITqM0QOGOex+
         plrv1J4t2miqysL27vl7bl/I7f3RYQ/GS/SfYudMDXKso5DV0wK2SoGzuxF5knznGHKH
         xRhp4jwxhc89b5zz7Cmy36dX3CxhkpJ0Gsj1YdV+blO8AVXjRNs9N50KsjR+L2h9GlWn
         eWQaHQSyuLh/B95oAWaWmUHw4Iabsd08AxLwOP++6dzincIzlOXDjs8UxL5qFJNtePTs
         kmoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=RPTEnN3Q;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NgiBu7MifKAXkI/n/adyEoWh9oEnTxhPAbspJl6v0Rc=;
        b=O9xcvwOD19jOi1kxs4KjdxlbYc7fGs5vtmuyK9FOL/WJrD6O0myKhjGXfFai0IdA77
         r7tKJcQDlZIaBVwcms2GYr8nts2eiz3ZlHqTCH6XyUppPIpAQMzMUOffgvH4eNJ1C1Qy
         8NjAV02MQB/4STFBswdQbCvsEUOWD8+N5DZqaF1b0laAYr04RHBkBvnr3yMIlq4mxa/F
         sK74spt32VyugZPLRTxt4R9e2g20eh95ySCHPQkUjoieWsrDWoID2fwe0GczhdMim6Dq
         1Na7DXHlln74opEvz6UArhDmquCZiGILBDacwXtYrrSAJVy1ne0cz5xCWGBkQPnEiqm6
         aGHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NgiBu7MifKAXkI/n/adyEoWh9oEnTxhPAbspJl6v0Rc=;
        b=ElSb6Cyyh0G+iOJEcYaOpJJS6v1dsFu188m6MzU2HLEuLrYBwjHk+35DorBXgvDF++
         efBFk1l7M5FK+Z4Jpvhl4VLWJicMYZ4mAjC3+uZgae4WKQvI6oIT0MNmNCGOvtjTnf4k
         OyVRtfH2Fibi9SyEpUQNSWOgUTFSXqQuKbYqwpzjVxlwZ+VINZ6YeZNDEtyx2SS3y5f4
         0RNjdChLgvzXZrw0XHkdJUWsKoAHJWH/NWEaAuXowXvyTGMVq+H04j3h4XlLBuBbgrlo
         6wAszSksA7Zj/s3aNES5XDju/rmWAMgrk/nqhSu+qNyxLZLTvB8/1ApzPZ+cSG/qYLLU
         EiuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/WMufl9wTJQe3JcArQN0DpPI4LZrrQSgngRuE8Wvfgz1gVCPy/
	Acqgc3B73F5jFpm1Gm9BCOs=
X-Google-Smtp-Source: AGRyM1tGfptUcB9uDEAnGePmYahrZ0avbDElS9xI7FQKL7Tvd+Z4tmBg5CL/Ys/9T1cRSDRk6WTLiA==
X-Received: by 2002:adf:fd0f:0:b0:210:32d7:4cb5 with SMTP id e15-20020adffd0f000000b0021032d74cb5mr1384481wrr.565.1655151453891;
        Mon, 13 Jun 2022 13:17:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5848:0:b0:219:b7ea:18e1 with SMTP id i8-20020a5d5848000000b00219b7ea18e1ls334046wrf.2.gmail;
 Mon, 13 Jun 2022 13:17:33 -0700 (PDT)
X-Received: by 2002:a5d:5686:0:b0:217:7da8:8c5a with SMTP id f6-20020a5d5686000000b002177da88c5amr1341223wrv.3.1655151453118;
        Mon, 13 Jun 2022 13:17:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151453; cv=none;
        d=google.com; s=arc-20160816;
        b=qwsYstQnx0PXpFb+13wcVH9HdD/V3cpg50PbSKo48iKT0DH6oyTOL1gb/8fkM29HIr
         1xMm7CZjGj3Rjvj4eCDMWTAuOeyK6sdF7/1qJP9Sc8clTPUriXVHUWh566IdVdIXGoz9
         xBLEahbpZJ6B0PBmZJCXaG+UlkepFkENhIQ++BNCtpxyJ+BejuRlOyo4JfiTdMowyJjF
         zpx5++6NmvvK3H5QsVXZWPIcgCeK0P0poioY5niF2TF+bVX/nxiJ2QAV/E9ywGVZMtai
         +UZLNFEWS9wF/Xj6z7zsSMvGrX/EKm3ZDHnjEqqv8Zsmto6b3FopBkmfaNM9xYpyJ+9r
         S3uQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=juoeL9iVysZjLYrCYEKOizkTpbFJJdb8UyU7Sz7zXtQ=;
        b=xfE1cVtBa9w1qE2UFomSTqqDaVWJ0o2/wf9vOFOoEjg5jhmEwwfOBSd964phfvLNEt
         5RHmPd2MVIH+lFeGGrMrwvjndsKjG9G4dnlSPYcej76nuoCdDm2PY1ZIgT7fq19vO6Ke
         0oweWGzxkDoRqt9NMrDGj4Urty6/XRkmZ9LDmAywKIfdDz8weql8mNiOSWw7JJcRI6bx
         vV81u3gPyGasYJWMhqGnALqrFEIufRdwo9dwM9f9Qq3tWK4AYycnnnZ6Q41sTV+iaoE8
         1FVNr+vms3v5VGpFMtuxrqOZhTxh1/oGHKTwZtLqYejj44A8Mi+9kUfJKAJNlpwjBjYC
         hu3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=RPTEnN3Q;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id p17-20020a5d4591000000b00219adf145aesi231966wrq.6.2022.06.13.13.17.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:17:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 12/32] kasan: introduce kasan_init_cache_meta
Date: Mon, 13 Jun 2022 22:14:03 +0200
Message-Id: <d86bbe1cc39eacb71bfaf05961d2e62109e9b0d9.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=RPTEnN3Q;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c  | 80 ++--------------------------------------------
 mm/kasan/generic.c | 79 +++++++++++++++++++++++++++++++++++++++++++++
 mm/kasan/kasan.h   |  2 ++
 3 files changed, 83 insertions(+), 78 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a3dee7cead89..8a83ca9ad738 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -117,28 +117,9 @@ void __kasan_poison_pages(struct page *page, unsigned int order, bool init)
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
@@ -148,65 +129,8 @@ void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
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
index cf123d99f2fe..ab2cd3ff10f3 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -296,12 +296,14 @@ struct page *kasan_addr_to_page(const void *addr);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d86bbe1cc39eacb71bfaf05961d2e62109e9b0d9.1655150842.git.andreyknvl%40google.com.
