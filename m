Return-Path: <kasan-dev+bncBAABBL7O26LAMGQE2VLDJSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 492DB578EE8
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:13:36 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id y8-20020ac24208000000b0047f9fc8f632sf4748485lfh.11
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:13:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189615; cv=pass;
        d=google.com; s=arc-20160816;
        b=ICEM5l7JsWHbS/WBOIU5LG6TF88CK0epR+dOGQqv5X3IwDmLQN9xVe1b6XngtcOHP3
         zQHF4W4MGsidFLhNgSunBvT4TjpYdkpq2Ie67xYGwj5drGGqJN5um1Hj2amnRD4F976c
         PNYonIRL0HS3PTjRLWodXfCN/LRVgdRFO8zQbgeSibxHNk5Ms0AgTMhyDVBKv0ps9yDY
         VrDwgrF/769guYuofUH4cpVTBrFrppHatJNjfbnteTe+9OHyRmDWNBLUQXKxwPG8Vrt3
         feyL1/1Opp+lBEDGWmw/ntypVU3ex0QLz9gAlUvBwfhfHJSmE38ITk36KtyUkb9jaKzg
         T6zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=crLZz0pVMRibzLGItucUMLeOHkUWz18CHVHqtKJSTzQ=;
        b=0Ac5TpdXxiZmxQxb5iA8gD2u4Ok6E+N6OICcEvJIcp+Nma5hPs/rcTpBOdz/gS336o
         YygPRDlQpE8Fyv8FSW+r1/SlwxRJlmDK+kpucZZbafoxZwbw/rk94t0deyVoy7QTi1O6
         sK1I8wcq0hS5IxxUzbF+PTZINVp9id94rMlgGkF2eR9oDjeNEvkANWOF9HRNGn7SV8wQ
         QylcFwA+8Q5LPlYN5B5gadk3n0mppnqVcq2xcTSW5ORiUD/5KB5dMcwtPFS5pPWLM0qd
         a1UT6dtY8FXDlUmRL/E5WwOP2oSwbBeMfIPKwwQ8LsQvEm6e1nd+PUmzsphd1Ztl8BP0
         1WoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TyBXMwhO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=crLZz0pVMRibzLGItucUMLeOHkUWz18CHVHqtKJSTzQ=;
        b=RgTxpt90g3ibmVQZEi5skUycq1/3ftK9V50f1nJJ6vnK14SywAUDpEfzPukNatLPEm
         FLmcKjgVC2XQTgXDnSi0t1X46UQ0rstThykHcurjWnJJsfNZihivFOYH/CWeIVH8qQJr
         3SR2nnw1PdvYYWcTZ/31w7bWldm78VGE5p69JqCDX1itrrLfdXpha0+GdmIme38S8cSC
         HUAyV72mqmLLZAb1XQNwgFR4khEJ5nYf0cWCglHbOA0Ki9SQYiw2GXuJm5rc0Q4xyQvs
         FGvTiV1+NUzJ1ipwNRw9Ep8Ov8Evx7c4FJFQsVAA5NXdtArdZNwAWpNXUChwVxBpLx3V
         lLsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=crLZz0pVMRibzLGItucUMLeOHkUWz18CHVHqtKJSTzQ=;
        b=cCP1tg5tbrMstIjdiS6EpAw3gMjgSdE2e4s1pNLTVvowiMmJ0yNjrJLmjuOawu/tNw
         tZC9aq6GAHj6CpBYjpoqXDJeTQ1ETm19aosPbnvbMjBqDV2EIrP0aff+cDhY9Kvxcdia
         lw5zNdRsD401purOCzKuWBUu52NMc0d/nOyFQwrQfaNSb9K1mh+HHVf3fETdePa/YwnC
         M9km7Sm5FQTOxujRigb7MExQZsjrM2lvZoB69Fuz2kjRggFpsVLlOjH9oD/kJdH7prVb
         9E9TEgjohqwmWwCq7cTuCHg7o/eWEl8tHLZGiTyegrQBRMIOKIoSMim7HxpqD6XjCqk5
         DtZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/tQuJB4Znus+Bz77VubZrtxukF4h1RpblUA531ksD8Dy3KgDpl
	6vdzT+I2kFzb495IW6pK2tk=
X-Google-Smtp-Source: AGRyM1t1fNbLmVhJiJ1tRgsrhkQyzTzVm4Qx2mZkbdAz8WDfCKHbc8CDKlJ4VAscCZKjYkt2HlBqqQ==
X-Received: by 2002:a05:6512:3b9f:b0:489:e009:ae0c with SMTP id g31-20020a0565123b9f00b00489e009ae0cmr17501741lfv.213.1658189615555;
        Mon, 18 Jul 2022 17:13:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f78:0:b0:488:e60f:2057 with SMTP id c24-20020ac25f78000000b00488e60f2057ls17020lfc.2.-pod-prod-gmail;
 Mon, 18 Jul 2022 17:13:34 -0700 (PDT)
X-Received: by 2002:a05:6512:2290:b0:489:d433:605d with SMTP id f16-20020a056512229000b00489d433605dmr15365861lfu.629.1658189614822;
        Mon, 18 Jul 2022 17:13:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189614; cv=none;
        d=google.com; s=arc-20160816;
        b=lptNY/jiiwLh13QcmPIVUxHZrjhuZN7FKakQvJNroLMMaWYnndZAAjAZ0cDhtKt96a
         ntAxvIexBuWM/wIbLwWgmZt8xqB8nneKCHafW7s1Z+1hPHseVzuHBiE5Y/PV23K7v+dE
         fjBqC3Ye8c19Xwh+7v7hEPT6bOchbzn9kYoVpxHIME8hhwQKVz/f/CdBdx4kXKptBneU
         F0NsELrLoW95WqemChqeE9ZSrEWUXY7inxfKlTDH2akzlUb7Cw1kak4cH/cQ5FYgOerj
         efragkg6svhicv3MccwA+sibS1Qm5WzMndDVTwe5mswYKW3vNkg6izm1Qn9JHvwDo0iC
         SX1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fcQYVitXIA53g4L8evccpvyk9umTBZJhPZwjoWFoPS0=;
        b=GBj/6cOpf55fR+tYSPOEsnCgvUhtanWknA6rZ46s0aRllCk+9fdrZYS0c1kz6iC0tn
         WGmaQWl24rrVItx6aRjx06alZNRbMoTPgO0YTz/XVNmpwwPgWPtu2UIG2EnMQ7Bw8r+A
         AcXb/t0Z9KZsUcI9rsgu5Xcv/RAX3jNScmP0D6T0CKiPHvGqoDIXcCBTP35vm03lI/KO
         e3HgrX3qveeA7x7QocACAUi5txTBYUYrBvbK9ok0uTS9gSeApnmx3xbSDh3ZLUhH2jqt
         9VZiiVrjPDppDIVv9R7VlBG1nJ9Te2/1/DPy2sX1FGmQbD2+W37Wu5x4hJhI1DFHYbEZ
         5KWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TyBXMwhO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id e1-20020a05651236c100b00489f4f3f541si325427lfs.12.2022.07.18.17.13.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:13:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH mm v2 18/33] kasan: only define kasan_cache_create for Generic mode
Date: Tue, 19 Jul 2022 02:09:58 +0200
Message-Id: <d0e45e36734660186990368cedb9b8574c664399.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=TyBXMwhO;       spf=pass
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
index e4ff0e4e7a9d..89aa97af876e 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -109,22 +109,6 @@ void __kasan_poison_pages(struct page *page, unsigned int order, bool init)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d0e45e36734660186990368cedb9b8574c664399.1658189199.git.andreyknvl%40google.com.
