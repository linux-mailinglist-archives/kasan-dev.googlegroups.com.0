Return-Path: <kasan-dev+bncBAABBIFWT2KQMGQEEEC7DDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 75F05549EC0
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:16:32 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id j4-20020aa7ca44000000b0042dd12a7bc5sf4592225edt.13
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:16:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151392; cv=pass;
        d=google.com; s=arc-20160816;
        b=KYn+u400wXk0v5OnK538fu/Z0qEreqEN3eviV/DrefpxM7QJs5Y9UtEDqLanbiqX1s
         nZYqVz73IFEr/XCA1BQIjrE83IZGofUsPUxP0OHgaoM+2AShqMurtiR3BRxP73qZrUjF
         73MQB6T/whpnblnBT/vf9DxZpvdeqGjb628dIj4WxlPwFrLwpBmmy5b6BYzK41Gr92HI
         8wNiWCOyn8US4N/+mZKcDggSGupJ1rbxQum44egv4omvfYJeOmzd6fjq9woNxP0uTik6
         x3QbqvpuX3JNe2gIeaGc2qqHLzBQauw0iRLlTE8xcizW4cUvec5RDHJ76LvBkXWzlDhm
         NhXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=H2K5zmi3tzPVCqPBbBckE//hd9DLhAv33aFoFkHGrSQ=;
        b=HxN+Xejo07zomwJSu0JJWlFdWUgztMr9UGQhplKQh7Gm3VXUwb1cXQQMh5QF8TI+pV
         vJTTOv1N4eT02mUTnbc6rbKhSJlPI0/xC+9nlE2L2jU2in6EED0n3ZyBTkPhBVU9ZsPt
         QgUQ5cYVdJ4NkCv75xhbvN9JjEtWCZDaGmmmJPu59UBfvjJt/2eXFkdGxx9PJld4d1cw
         U+uNAmHVlD/qj/f9pdcxPSDtZcOCJA8MvKVIM83tnP8NM07XdzMt0QYjIsa2pnMKKDxn
         DRHJXL6DeoUVTAcCZRSdtIRbyQLAK2Ix0FQHfk4FNDSh5n9qJ3j3LsfycCIWWYJcyXb8
         xvSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mIrxUO6y;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H2K5zmi3tzPVCqPBbBckE//hd9DLhAv33aFoFkHGrSQ=;
        b=C3j6FsgArL8ZZk9vRvZoONsb+2+IJisIOSZMDndnsAJ0ANZ4FKH72dU7vRnYtg8GQe
         ciTSo8kSKYGvEIA+0SyKn0jbOrL6e8efJia1JeLM90D5V8NX6ArjUisEP7L1m5aEHNJt
         48wonkmSFbIXW/Sxs7xO+UpJpJSAo06LhUHWNxhrzjerA58gYksMzNkViRnPNfrWFtoM
         /YCPSicxQUylG2ToZT1E1rzBkb6eTwgydHiAeEIJERGcHZhFfNyn6ZX3A1J3+SaZh3eI
         ywSHrXrj3erXa/OZKnf9OfPtf8sX7WfxGl9hf70IYcoN/w0R+9StoWyk/gAzaONYFfEX
         RWJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H2K5zmi3tzPVCqPBbBckE//hd9DLhAv33aFoFkHGrSQ=;
        b=hgjtdI5wJb+R9mTH3UZEj8VoDu6z7PAkEOrTDXPzZXd8+qkTpQ9tehl9NvqxYCYsm9
         BJe0rY2cBC5JglXKoSon/a4iK7uKuV/xJJnw8DLlYv1tLXz1TMmnSoGxOVSkjQ1f74g9
         /kx76TOpQ1IAXVAXQCxWKgq7CTQEMpsiTEgR8v/w4JXGncZPmcqt0xH9yOWzRkDaURS1
         Fi2ZWPPaK+PFHM65+n74PzZjjsiMeb2HKsQIdDlUuhp8mLP8t1vJduQlbOdt3wBe38tT
         xV3se+FeSSUHgZCXtdP88QSr7vWRew5N7SCZ2Lor2XADcDXXcvbbJFX0McQoBnYsQIQm
         e0gw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/WcYILvEAvoXp7td7OwOpSe8HsElulw1oOLN8azjaXjIEWX/Ca
	Tx/q9weKGRfp89Y1JkGgYGU=
X-Google-Smtp-Source: AGRyM1uHyzs8YvbMeSQAIM0QGSXcJ/2F4Jjr69vWkF5dZTwcDJfDVoAQEd06n95vNvBUfbJvYy5/oA==
X-Received: by 2002:a05:6402:35c4:b0:42f:b0f8:6a69 with SMTP id z4-20020a05640235c400b0042fb0f86a69mr1758748edc.180.1655151392238;
        Mon, 13 Jun 2022 13:16:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:5ac1:b0:6ff:ab8:e8f with SMTP id x1-20020a1709065ac100b006ff0ab80e8fls143309ejs.6.gmail;
 Mon, 13 Jun 2022 13:16:31 -0700 (PDT)
X-Received: by 2002:a17:906:af71:b0:70b:cc0b:1f14 with SMTP id os17-20020a170906af7100b0070bcc0b1f14mr1250242ejb.669.1655151391627;
        Mon, 13 Jun 2022 13:16:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151391; cv=none;
        d=google.com; s=arc-20160816;
        b=EqMFPAnOsMYP7IUwb+rCr40aRFUov+UppnAEXllS7KK0BxMnZKP2wekNziaJHHAqq/
         JYazN0uOFblRF2O2x8fsB7DrnW41wx437DMRHnk1B4lyToEE9Yy94xMu7Qnj8n51GW8y
         DIiOJR1edGQRUyDsID6EDH7gzCnpSK4cQkLxAJNEsb80Nfb7j9ip8P60gNlhBO573Uwr
         me+laza1KdjyCc/5pkFpzwf++URovwUGof10bpOcJpodrNk/MTQP0ND3TvqMdjy5OE40
         purFcH+ofO6sSMIK6DFSA8NmcdoP5WoG4o3onjQJgQ2kwWQjAh4t9KoEGgf4OGIMe0c5
         /A/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AqRJE5kHmUhU9DFMHo/l5MzOgI3EbkZf7j3BisUrZdo=;
        b=vMqzHrtppAGJMil7+W/IeP9RhXG3+o3cA++K+0Gu5raisk/VkSSZReldGNwQ+PXYKe
         rDUFzLT3TCR4fXeipaleNMqubRnLZtCWLj8r/TrdXXJ/fIzcBcU+Zp0/3XeEb5+1/9PY
         KAhpSp/tDonirxktFvFx8VBkwKnB7S9UDdWmOg0K5gPMyZONfaeByIGOtlvA6U+018zc
         tMjlntPpmnkyBzhkDikLutI0Is6P0dDtm7MpOdSqn1EqUOGro86DvHwsaJeNuUnsqC5u
         0+lMCdjyUCM47Q3wZeMmPeTSeSznoJ++SQsRK+lw+OBtG5/cfvJ3y9CJDSg64YpxGgl1
         TA1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mIrxUO6y;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id q24-20020aa7d458000000b0042d687c85d2si344150edr.0.2022.06.13.13.16.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:16:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
Subject: [PATCH 11/32] kasan: introduce kasan_requires_meta
Date: Mon, 13 Jun 2022 22:14:02 +0200
Message-Id: <4201bc563d9553bca0278124e5ee4f1fe9a84ba6.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=mIrxUO6y;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
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

Add a kasan_requires_meta() helper that indicates whether the enabled
KASAN mode requires per-object metadata and use this helper in the common
code.

Also hide kasan_init_object_meta() under CONFIG_KASAN_GENERIC ifdef check,
as Generic is the only mode that uses per-object metadata.

To allow for a potential future change that makes Generic KASAN support
the kasan.stacktrace command-line parameter, let kasan_requires_meta()
return kasan_stack_collection_enabled() instead of simply returning true.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 13 +++++--------
 mm/kasan/kasan.h  | 33 +++++++++++++++++++++++++++++----
 mm/kasan/tags.c   |  4 ----
 3 files changed, 34 insertions(+), 16 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 226eaa714da2..a3dee7cead89 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -88,13 +88,10 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 }
 #endif /* CONFIG_KASAN_STACK */
 
-/*
- * Only allow cache merging when stack collection is disabled and no metadata
- * is present.
- */
+/* Only allow cache merging when no per-object metadata is present. */
 slab_flags_t __kasan_never_merge(void)
 {
-	if (kasan_stack_collection_enabled())
+	if (kasan_requires_meta())
 		return SLAB_KASAN;
 	return 0;
 }
@@ -151,7 +148,7 @@ void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	 */
 	*flags |= SLAB_KASAN;
 
-	if (!kasan_stack_collection_enabled())
+	if (!kasan_requires_meta())
 		return;
 
 	ok_size = *size;
@@ -219,7 +216,7 @@ void __kasan_cache_create_kmalloc(struct kmem_cache *cache)
 
 size_t __kasan_metadata_size(struct kmem_cache *cache)
 {
-	if (!kasan_stack_collection_enabled())
+	if (!kasan_requires_meta())
 		return 0;
 	return (cache->kasan_info.alloc_meta_offset ?
 		sizeof(struct kasan_alloc_meta) : 0) +
@@ -294,7 +291,7 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 						const void *object)
 {
 	/* Initialize per-object metadata if it is present. */
-	if (kasan_stack_collection_enabled())
+	if (kasan_requires_meta())
 		kasan_init_object_meta(cache, object);
 
 	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index ff7a1597aa51..cf123d99f2fe 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -43,7 +43,7 @@ static inline bool kasan_sync_fault_possible(void)
 	return kasan_mode == KASAN_MODE_SYNC || kasan_mode == KASAN_MODE_ASYMM;
 }
 
-#else
+#else /* CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_stack_collection_enabled(void)
 {
@@ -60,7 +60,31 @@ static inline bool kasan_sync_fault_possible(void)
 	return true;
 }
 
-#endif
+#endif /* CONFIG_KASAN_HW_TAGS */
+
+#ifdef CONFIG_KASAN_GENERIC
+
+/* Generic KASAN uses per-object metadata to store stack traces. */
+static inline bool kasan_requires_meta(void)
+{
+	/*
+	 * Technically, Generic KASAN always collects stack traces right now.
+	 * However, let's use kasan_stack_collection_enabled() in case the
+	 * kasan.stacktrace command-line argument is changed to affect
+	 * Generic KASAN.
+	 */
+	return kasan_stack_collection_enabled();
+}
+
+#else /* CONFIG_KASAN_GENERIC */
+
+/* Tag-based KASAN modes do not use per-object metadata. */
+static inline bool kasan_requires_meta(void)
+{
+	return false;
+}
+
+#endif /* CONFIG_KASAN_GENERIC */
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
@@ -271,13 +295,14 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
 struct page *kasan_addr_to_page(const void *addr);
 struct slab *kasan_addr_to_slab(const void *addr);
 
-void kasan_init_object_meta(struct kmem_cache *cache, const void *object);
-
 #ifdef CONFIG_KASAN_GENERIC
+void kasan_init_object_meta(struct kmem_cache *cache, const void *object);
 struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
 						const void *object);
 struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 						const void *object);
+#else
+static inline void kasan_init_object_meta(struct kmem_cache *cache, const void *object) { }
 #endif
 
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index f11c89505c77..4f24669085e9 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -17,10 +17,6 @@
 
 #include "kasan.h"
 
-void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
-{
-}
-
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 {
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4201bc563d9553bca0278124e5ee4f1fe9a84ba6.1655150842.git.andreyknvl%40google.com.
