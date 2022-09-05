Return-Path: <kasan-dev+bncBAABB5OK3GMAMGQEIFENIQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A2B35ADAAA
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:09:10 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id r17-20020adfbb11000000b00228663f217fsf858816wrg.20
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:09:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412149; cv=pass;
        d=google.com; s=arc-20160816;
        b=VcPSIFtmuIsbPdJE5SsPVBYgb0PQ9haDoLT/2x1Ruy30dHAdcnWm2ogY5TbRaTHSdW
         lu/sWLODlbg8U67K+yWpiinVWdqregT24zhOHVS9gE6SvTlnQ+zzOI1EMGEVjBsn/sTM
         2509chxpTXF9gtW6p3ET3sjHqFUghzFrE1cGbpFy04KXM/i/pr074BeWgGcmNxBPvb0q
         8maYGh5yPRs/BksJBGdrk7Mlejh+Rdrkz+MAS2M4z6XuwbJI0Mhbo3hV1oe65DaPOvgs
         rUK9EE6zEKWJpD0pOb3bu4s3aTnIr7Vvw2gR0PJPkRU9piJCfucs1D2uPzVLF7z3SvZJ
         TtSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=m83v1ubLOjg2OhnwPhXNv5dQhoRwBqhO0LQpu4WDcLE=;
        b=tjW/S6vwlyLlK4aTfq5TPIWVUAjjzLvXUFM/9k+TbKWxpnJ0rN6buRD0nH99AqtWgV
         SUsKYLhumbNoUGl06IAwvcYV+RE8Ius0hf8JtTq2gnWKp/x50stbOuUg0XEI+0eogwWn
         I1SkbmZOeUT7dOBj3k8CsBJ+mmi7w5vmHm8aISiJtGPJqQcrcTigk0gn+KNkhCmtKzft
         txaThBhOl4i5g7SKpMztb8OhluKGdPNGppMhl6IZMbucGtEerWNFxAGD+n88a37EE6eg
         NIrsLvWNVKtPuB4H6hF82WiKxqO70AKu5NclRviug4XkgERZJ0aB15AQtOtsET5wUr12
         ESSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=PL+hF7kc;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=m83v1ubLOjg2OhnwPhXNv5dQhoRwBqhO0LQpu4WDcLE=;
        b=jM3SlnQdw33JfQ+stJmc1PQu31fvN1uXgaXfw+4XPTe3J3vyfu/86uVGIsQGcNtfoe
         hno/Br+MuNfOFFmUM/SFlN+hJa5NPm/VOKvqWO2NfJGzDwL6HhGwFDbiGffTSJmYznCr
         jAvi04J2uULJZUMMKZzmRmDqLjsodL7s1YT3bxXstp7VH9gzu790VMac2jg9IOupVrIr
         xXW01AgLm3rnNPFM6182PnPTyizwuXaebsLnsHmKy6dAR0Rc9yAwr/tduB7XR7Wn823U
         hgGMdjp021cxrZnYMyzI8v3vluuad2IyBbNeLfGpAqbRzSb3a37pe3j2+lDECrXsisV7
         H0Sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=m83v1ubLOjg2OhnwPhXNv5dQhoRwBqhO0LQpu4WDcLE=;
        b=Z7tL2oBLR01IVKjMxKqoY7BcSdEP/63IdGttMpmCXkGSlSlbvEPXbPVsJqlEUFMB+j
         VXZmLxTPz4sqB5nnhyZb4k5Q8WRLxla2kuC4/4AKQ+W/xaWLratligJ1NtS4V5DZi6f3
         YKn/2WRaMfYR61P71VuG/etQezPMSSBbSjmi6cy7ixfWtmniiET/XqLP7ZtQWxuim0JF
         SNm0FCrDcMaSsx7aF8iOyyDgh5PWbh9g3MJIJbOagIG3RzDj155UKTXTXOANHNzOEgaY
         hJtilSYFj7featyAM1nXl7QyHZV57H4/FKJK48sL7+HwWGKLbfDj8ps9sB8D4I76tEMw
         68xg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1Wpk4AKxT++OJLcGfCLshpUVCFjuNZkpIWTl0y0O5rpNpGPduH
	DyfX+V/ZaD7rsaEtcdRW3+U=
X-Google-Smtp-Source: AA6agR4H/3RHJ6eejsuwpjlNUBKy8am8BEZAdD9xZCxAtdE97qFxVNtBw7oGX4D5QTz5CMSkc31HBQ==
X-Received: by 2002:a05:6000:1881:b0:222:c899:cac6 with SMTP id a1-20020a056000188100b00222c899cac6mr24339426wri.283.1662412149823;
        Mon, 05 Sep 2022 14:09:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:220b:b0:3a8:583c:54ed with SMTP id
 z11-20020a05600c220b00b003a8583c54edls4135691wml.2.-pod-prod-gmail; Mon, 05
 Sep 2022 14:09:09 -0700 (PDT)
X-Received: by 2002:a05:600c:214d:b0:3a5:ce18:bb71 with SMTP id v13-20020a05600c214d00b003a5ce18bb71mr12258707wml.1.1662412148953;
        Mon, 05 Sep 2022 14:09:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412148; cv=none;
        d=google.com; s=arc-20160816;
        b=xA9PAry5w37Pani76GlGgKO5JhWNnEojkS6LC7WIEnDP8JXyNeoaBX5QsSArReUS1z
         CLrpdUQhnVe4IV3dZjGilCyV5kHHtZwa5ke1KOcsfTkozUINehVyjO72OZERm0YK5Nm0
         wKKa+5XT6NTrO52exHfT2NB0/PE6aSKQxSDVibEBP2B8aoZZJi1CguLcY85DbHXKvz5H
         3tNPgCCzYJPMxAaEkzMd6LwA9olmQ1pVIHWffIAncC3b77X4Q8wg71oVQoxNG7h8hWU2
         wS3UJyzWqAGyXVXA35Q9Gx1lk/h7InSnU1Lb2gKpnZj5FduBJXavN6dRaLKDtjo00oQI
         go/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Oe1I5rgVNwQpGV6INl9iERGx4SyKKLbT68poGoo1Dv4=;
        b=JG+Y82qGM2/i/V0+DszZ723BzkGRJhQilBS66PK9wLh4Q138KANbkQxL0wl3hYZR/q
         cD3lmJGVIIxaWq3J21rfQvlcFEfO2i6/t0PyDj5SbKxJT8oxuRspFGu9DAdV/H1yFy8w
         gKWDO+S2RH0vLEcTQWBbiSGDYbSD+pJj7lFSgH2V/PNMxr/BlSvrxWZdRT79tRnDtXa+
         V5OHGmMuzdI5f7NPrjf++cfm9UUW1ni//kS/eOb37mhj+ywT+JnCJ9eu06YKKzIxe+ov
         kiCRWBpuEHAR8QeLHE3Rk94iTAWCcTEGDfauzBv2bppbC9SBxwewj7l9W3BkCvSEWiaW
         faZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=PL+hF7kc;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id r3-20020a1c2b03000000b003a972d2d4a4si529182wmr.1.2022.09.05.14.09.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:09:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH mm v3 18/34] kasan: only define kasan_cache_create for Generic mode
Date: Mon,  5 Sep 2022 23:05:33 +0200
Message-Id: <61faa2aa1906e2d02c97d00ddf99ce8911dda095.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=PL+hF7kc;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Right now, kasan_cache_create() assigns SLAB_KASAN for all KASAN modes
and then sets up metadata-related cache parameters for the Generic mode.

SLAB_KASAN is used in two places:

1. In slab_ksize() to account for per-object metadata when
   calculating the size of the accessible memory within the object.
2. In slab_common.c via kasan_never_merge() to prevent merging of
   caches with per-object metadata.

Both cases are only relevant when per-object metadata is present, which
is only the case with the Generic mode.

Thus, assign SLAB_KASAN and define kasan_cache_create() only for the
Generic mode.

Also update the SLAB_KASAN-related comment.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 18 ++++++------------
 include/linux/slab.h  |  2 +-
 mm/kasan/common.c     | 16 ----------------
 mm/kasan/generic.c    | 17 ++++++++++++++++-
 4 files changed, 23 insertions(+), 30 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index a212c2e3f32d..d811b3d7d2a1 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -128,15 +128,6 @@ static __always_inline void kasan_unpoison_pages(struct page *page,
 		__kasan_unpoison_pages(page, order, init);
 }
 
-void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
-				slab_flags_t *flags);
-static __always_inline void kasan_cache_create(struct kmem_cache *cache,
-				unsigned int *size, slab_flags_t *flags)
-{
-	if (kasan_enabled())
-		__kasan_cache_create(cache, size, flags);
-}
-
 void __kasan_cache_create_kmalloc(struct kmem_cache *cache);
 static __always_inline void kasan_cache_create_kmalloc(struct kmem_cache *cache)
 {
@@ -260,9 +251,6 @@ static inline void kasan_poison_pages(struct page *page, unsigned int order,
 				      bool init) {}
 static inline void kasan_unpoison_pages(struct page *page, unsigned int order,
 					bool init) {}
-static inline void kasan_cache_create(struct kmem_cache *cache,
-				      unsigned int *size,
-				      slab_flags_t *flags) {}
 static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
 static inline void kasan_poison_slab(struct slab *slab) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
@@ -316,6 +304,8 @@ static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
 size_t kasan_metadata_size(struct kmem_cache *cache);
 slab_flags_t kasan_never_merge(void);
+void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
+			slab_flags_t *flags);
 
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
@@ -334,6 +324,10 @@ static inline slab_flags_t kasan_never_merge(void)
 {
 	return 0;
 }
+/* And no cache-related metadata initialization is required. */
+static inline void kasan_cache_create(struct kmem_cache *cache,
+				      unsigned int *size,
+				      slab_flags_t *flags) {}
 
 static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
 static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
diff --git a/include/linux/slab.h b/include/linux/slab.h
index 0fefdf528e0d..1c6b7362e82b 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -106,7 +106,7 @@
 # define SLAB_ACCOUNT		0
 #endif
 
-#ifdef CONFIG_KASAN
+#ifdef CONFIG_KASAN_GENERIC
 #define SLAB_KASAN		((slab_flags_t __force)0x08000000U)
 #else
 #define SLAB_KASAN		0
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index c2690e938030..8efa63190951 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -110,22 +110,6 @@ void __kasan_poison_pages(struct page *page, unsigned int order, bool init)
 			     KASAN_PAGE_FREE, init);
 }
 
-void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
-			  slab_flags_t *flags)
-{
-	/*
-	 * SLAB_KASAN is used to mark caches as ones that are sanitized by
-	 * KASAN. Currently this flag is used in two places:
-	 * 1. In slab_ksize() when calculating the size of the accessible
-	 *    memory within the object.
-	 * 2. In slab_common.c to prevent merging of sanitized caches.
-	 */
-	*flags |= SLAB_KASAN;
-
-	if (kasan_requires_meta())
-		kasan_init_cache_meta(cache, size);
-}
-
 void __kasan_cache_create_kmalloc(struct kmem_cache *cache)
 {
 	cache->kasan_info.is_kmalloc = true;
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 25333bf3c99f..f6bef347de87 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -352,11 +352,26 @@ static inline unsigned int optimal_redzone(unsigned int object_size)
 		object_size <= (1 << 16) - 1024 ? 1024 : 2048;
 }
 
-void kasan_init_cache_meta(struct kmem_cache *cache, unsigned int *size)
+void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
+			  slab_flags_t *flags)
 {
 	unsigned int ok_size;
 	unsigned int optimal_size;
 
+	if (!kasan_requires_meta())
+		return;
+
+	/*
+	 * SLAB_KASAN is used to mark caches that are sanitized by KASAN
+	 * and that thus have per-object metadata.
+	 * Currently this flag is used in two places:
+	 * 1. In slab_ksize() to account for per-object metadata when
+	 *    calculating the size of the accessible memory within the object.
+	 * 2. In slab_common.c via kasan_never_merge() to prevent merging of
+	 *    caches with per-object metadata.
+	 */
+	*flags |= SLAB_KASAN;
+
 	ok_size = *size;
 
 	/* Add alloc meta into redzone. */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/61faa2aa1906e2d02c97d00ddf99ce8911dda095.1662411799.git.andreyknvl%40google.com.
