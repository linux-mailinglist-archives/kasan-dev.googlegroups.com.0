Return-Path: <kasan-dev+bncBAABB3PN26LAMGQEDBALBEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F3F1578ED8
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:12:30 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id h189-20020a1c21c6000000b003a2fdf9bd2asf6051486wmh.8
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:12:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189549; cv=pass;
        d=google.com; s=arc-20160816;
        b=oOykr1fffr0Zy/auxXBNw0c8v9X9LXmWs+534EAc+oa9cF0bwXVODmsulow9wnMifX
         bEDWyYlXjaxbkXI87xwA61qWBPl7Z8J7x/d55cFmXlzQK07c4ccCDsnHt7FuorOUUHpR
         G2/b/jftfOkX35e82ksBFxSIUUn3I//Vu7/CBrJx3CXsE9SVctkjieBhVaarhr/y0816
         PdMPTbZDdK4ro+SEWXunGMwJV9oNsrtGb2VMrlxuOxeXyHfLdqUlOZ795FSxy2B2Qdg8
         N3LozD3fJ2ZqARAYmtPFYyjAd9+qDD1n15fhbsT9YNwv134cVaIwmIKHsbvr9BVnzCta
         DlRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ssy1pz+p8fvMUk0Ftm9n4jKm9pxCixxGbiX50xpEKtw=;
        b=A0WcaxHmy2k2tNkqv1lDBTlYBuyTGTfFaEuaokpMSkzWFgWCV2UcQfCYHmzmiHjBpF
         qx0UfuWV79XKD9v12cDD+fuW/ZeO4Mf/L6fZglL829rNCqxALejO6GDCs40s7Ey/yzQa
         TDCX4DFz+9hbCjoeZ00EjxYbD+zzT6UCaEE7fQ1fnyXoSTlgZQeqna8t0OP1XSbAMNQG
         F2CGtsVFrqkulu6bNAmrMVB9+0ku2wNuW211O5vEOM60lgTp9rTh/qS3meu9qhXjA6j5
         JfXsU7xlh8mu1HcRGhE7iw53RZi3aq7wdOf4N2hGxJOjtJrvCRTscgXPQTICQ4Hl8kwo
         9TWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=F2BbZXMf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ssy1pz+p8fvMUk0Ftm9n4jKm9pxCixxGbiX50xpEKtw=;
        b=HY2B5i737Rl0vgc+oT/EFJoy87nC6eU2uhIRVd7nPJVjonN3yP1BHjZfDsg0pu4Xxv
         QJ/i7jgQXasH+lPVxpmwLl6HBlmL3FiFxvuGW0S7gV69A+MMx/tMEi+kY8gzTO7kLKZa
         fBXmdssV1Z5zp+e3stNbNjcfU02BbVcqG6MevLr48utTTOeXBxbu2Bbq31ZLaBdXjRJw
         ZmAW2FTdiPjadFP72XPhupYOFoaKGGFS8x2lkW8bmQDAnHD2G6oFpsZmgQyAift1byGa
         sMEqr04x3YCZDaUANWegzjt81LCpwfKkPfwWWoPd9EoJUVQGxjZ1tewX7AnNRK3EIGDI
         X2uA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ssy1pz+p8fvMUk0Ftm9n4jKm9pxCixxGbiX50xpEKtw=;
        b=cxon6ogL0mqRHmcmH81+7vz9fK97PLQcwAOJWTItFHXz+0y6bi0v6pMdh/BGV4Gx78
         cD/SWZIywxRqzaJrpYkrvHRACdMntZSnUL33SvAaSaogLhWxxS+AK3eMQlM16mduV0dh
         OCPWHUxPCLXytCDtyajkdUqQ5Lk5TRVaZRJyDSpwsffpuK5dbcDa5JFdhkmSkwkFJiX4
         k0HJuUiKCHMpfvaR9dXPSsDzaSZA/6ulyZDr4jYQnLyPtXxVnH4iaHm0AflGi+ocKEFM
         wWHrjQTP1HPIydBhGEWnGRr8pHN95ER/7R957oPDkaneODwMRGfgdiL6qQp+Nx9MX1OJ
         Ft9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+kVVt/OUwuoAJTWqEXo8lOUJt2qio4TNDlFfBERjci4pmupS4c
	XQ0X2h8Q23AudymzmdJ8Z4g=
X-Google-Smtp-Source: AGRyM1tva6cpJ4hvq3xNvOJ8bAB4QfnZ5SciV2Sfhs3GJGYJVb4W27jiBzoWuBYICcXAVV/nN0/pnw==
X-Received: by 2002:a5d:4bc4:0:b0:21d:918c:b945 with SMTP id l4-20020a5d4bc4000000b0021d918cb945mr24534204wrt.287.1658189549657;
        Mon, 18 Jul 2022 17:12:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:284a:b0:3a3:7eb:364e with SMTP id
 r10-20020a05600c284a00b003a307eb364els41378wmb.0.-pod-prod-gmail; Mon, 18 Jul
 2022 17:12:29 -0700 (PDT)
X-Received: by 2002:a05:600c:1da1:b0:3a3:1a45:5158 with SMTP id p33-20020a05600c1da100b003a31a455158mr7459600wms.87.1658189549015;
        Mon, 18 Jul 2022 17:12:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189549; cv=none;
        d=google.com; s=arc-20160816;
        b=BMA+am3bObDFKsfXFtG7d1kHc3lcUSi9VSIiJwKPFGtUI0k8GAE1ceyd5O2ZyvPiSf
         Oi2jTf7NhCcRp3HK5hdm0TTulzpbfdbsKqKyIU0eSsscA5IXxZAVqc4K8qVI1604x0ah
         c/pDR/fI7cmQ+/XjiOjPWd6PLW65up/uxk/MYs7ihFaYY9V1xo9RRLmpWxeaOMPlxWqU
         tgOvoPL6lTFaF4GDTyWQFhcJen9HQEUvljIhfGiSB1fQHaHrp8xacezJOC8HklPLR/07
         zur0zDGJXp7thga1PGFiXkwGLjZDoOs+Yji5UgvdqhaxlGiKPeJJ+ZT+gbnQW35+vZWv
         nJgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6/KgfSVlFPREjjOqLt7SNNIjNmfJdkE37gqLUEf+qEc=;
        b=TrwPzsgRF5jn/MnqlzRPbyXtjMZZjQUhDGOfZrWEmVJQa7wFuydwAz1WHEQHHk25on
         4kNDI/FeDzp6d0Hu+inhOrvaJMrE9x+GXacU7kN4ppFdbwmh7Pb3X8jmDJb/OfR3iI7K
         lpzfU/xGnKGaAlE281XTAy1zoIJiziUVHyKwhLXAPuh8AabOTaBx7NeWFOUQQdDKx0cQ
         e0vv2Y+1jeBay2Z654uTqz4HKpYQkP8nJelFQFvZuOmg8+RRqrY3qckgrOuIkzRX1SG4
         7NqGIcI5pI9uPO5p+xjkvEIx3SiPz0SFhP6GRvpBuC51Pw3NGXNMpBdhkRDKclgD7kFR
         e7SA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=F2BbZXMf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id n25-20020a7bc5d9000000b003a2e84a9f74si413588wmk.0.2022.07.18.17.12.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:12:29 -0700 (PDT)
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
Subject: [PATCH mm v2 12/33] kasan: introduce kasan_init_cache_meta
Date: Tue, 19 Jul 2022 02:09:52 +0200
Message-Id: <7ae0695bcf60921a040f6bc295876444f5c3cef1.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=F2BbZXMf;       spf=pass
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
index d2ec4e6af675..83a04834746f 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7ae0695bcf60921a040f6bc295876444f5c3cef1.1658189199.git.andreyknvl%40google.com.
