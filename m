Return-Path: <kasan-dev+bncBAABBH5XT2KQMGQEJDQWFFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id C93F5549ED8
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:18:39 +0200 (CEST)
Received: by mail-ej1-x637.google.com with SMTP id lv2-20020a170906bc8200b0070e0d6bcec0sf2184317ejb.6
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:18:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151519; cv=pass;
        d=google.com; s=arc-20160816;
        b=rA0RshcFBiY+Hmkx958Yf4U2DVUHglGmgN6q5V42Uwnkc+gZqYcriYymxQBtkfLUZ6
         fVdVNRQHhxbQhq7i9LhF/ebalXpTS/tXyR5p5nVLec9eZPruGiFfOtsh22XpLIlGopi4
         pLdM0uequYsxCG892IneAXcFJ87qfN3+P+P0VlB4jzxgj5pBVAZUcY21hvhxkVt98R8Y
         huGkf7+i4fLwq5ra90K9BCCTN7z9JzHtVbMg+aJBiwVBXRjaRZf8GhT9wR6YqruEkOMC
         el9SL0KxJ9/10xJNOB9evvz1odfT9NA8/alO/IGGwqlp+6DMsR6rvE1FBaGs4iP3VMVR
         +9VQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=BI71JFI90EcaNEiwsLmRYZ63Uw6RmGBo4TwptGZqruQ=;
        b=ttZTx3EOKDkvWs24WToenffeb2Xa/ZAP/lhGwMl1VQ9sPUGRu3uCBfmnjK8MWEAaCH
         SwGU6NkKOMPoD9WvnaE3alcjm9rJ5xvOmOvUw5ogqz9n+KTyeM7lXV0ZkhabPWpoyRBB
         DKnGMJtljXlRau071OkN55ygt3Z4nsHdxlVcGwJkDh1RdHutGqfTXFdgKyP0RYROnzKj
         lVehrfIemaNsp+Bu/56pLRQ8jtr5rJTnCvcx8HZOhvo00yXQWEmdcSl/ksYtIseKtMOX
         XuPGGyiMCMkEaPoz4tYXmX1xrY9igmte3KxXYOn6yYdW8ufeaDMwmZuoCJiTBzVXhX1G
         MYWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=SiOziBQo;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BI71JFI90EcaNEiwsLmRYZ63Uw6RmGBo4TwptGZqruQ=;
        b=OHgGprdHg8ZHqv2VfWZwU/gRawilq4Tnr1ZhQeIfQaCE8mBRDZ1XVJO5rKAnVGYJaY
         BR1iarYg3Nwq539npwfHi5nYsmdIqdZK1l2HNlMlCBqTwDhEk+7GEFuPpPs/C7bMYEwe
         BQZv0NvidHcfBxt8RkhKbeEXHUmozCvgrnGePH/EmSezBE1H9FUehzX5jJu6cK39E1B5
         audsM1FRVX8dssY8nUKvyAjujIJVx1xVO9Wq/CzfPfmCVWEdeAHOvn/PFIayZCslj5Vf
         Vj29g2CtnXLjcnWnRcJFZ3bQ/k0DTKIiuIdoHYBZcR4wc9ZMTBDfqFLCdCd6QfmuQzJG
         Kp7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BI71JFI90EcaNEiwsLmRYZ63Uw6RmGBo4TwptGZqruQ=;
        b=R7JyZAyEF98bKf5uXzDToWUu0a3O5CUZeZP2Mjh3NPXb/hf4nhqi4rSD6cdjVg1fzx
         wep13z6R9ArarMXD8/EkWlSoI7cj1a0w6721xfFo1dVvlzvD3PDtxaKPDmERtDY5Inyw
         /YgavggkrTEi+WNoO3Trcm52EJIcuZzsytwFKRThN5fOpY7PcfFOouck/Ahupue35D56
         iJANuwYuY2T60zpTnn6jRzP44AAvpUGIwZQ2W+/yv0/BoP7QU01xTFPSBxodmGGURSHb
         bBmJET632UTsza7YE63lWV55j7xi/djBOrvHUNJAFS4fyvpYwzex5NHkdIxut/T6oe2F
         c2tw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8PPRLtsKdJQdef2C1oz/Dg0U3r3y6HPP8YSMKErzY+FjEvTyDO
	S1leIYwiOMH9OPyzM9he8oA=
X-Google-Smtp-Source: ABdhPJzCJE512tnGimt2UR2se/m/BAJPWSVhIjKYuzBBKJFjAOtp6xP6RkSyHTwJY6iVVPBbuyhYUg==
X-Received: by 2002:a50:ec89:0:b0:42d:cc7f:abbe with SMTP id e9-20020a50ec89000000b0042dcc7fabbemr1642245edr.381.1655151519415;
        Mon, 13 Jun 2022 13:18:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:70cf:b0:6fe:d027:3c1f with SMTP id
 g15-20020a17090670cf00b006fed0273c1fls145047ejk.2.gmail; Mon, 13 Jun 2022
 13:18:38 -0700 (PDT)
X-Received: by 2002:a17:906:c155:b0:708:21b1:dcf6 with SMTP id dp21-20020a170906c15500b0070821b1dcf6mr1283206ejc.661.1655151518648;
        Mon, 13 Jun 2022 13:18:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151518; cv=none;
        d=google.com; s=arc-20160816;
        b=gueLauF1AaUrmtkwKQKxBr62ztXh5TQ/jeoPUYcgUKkWX0fIdwOuga6wjW+VPRCHye
         9B5Qpg0eaEzXr3lo2KXl7AgObdluVmt1KFhCULtWl/7hOZ9R4uiJ8sUt3gNZ2uswkiWE
         w6uIFt44Pq9ofR44bjiZ1u7bppy5BNHiNG3MPpvDfFtUD8V34EUUWSI5FU05tj5XJgoa
         dFK+extnAsU+252xLwQR87AN6/GFcHN5vqUjDnnxQNIf4q/k+DwoE3r7Na5RT8skaheZ
         wTkH7XG6ZUUbHeCUHICY6zf/KWn8RkAKDwQ+e/D1hwh6+a2QNge7JMKAFb/1CxFXaMaM
         VvVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=krlQc9a+2od73hH5OepUxMqNSDz17Dvev41TaF/lT74=;
        b=SecV4yU9hRxgX/t24FVllLqwCQwplI0T923UOPAvwXxe3ZJNgwEfi6z5wVLJOiTv92
         gjaiHUoHbaqzKSdiNhKlbNOQAFjvDwmb9XhVtJvK6v+hT9ZNBbbgseFLuwlTsipz/Hzo
         1oWRJfq/4+IVLFIl9E/YW+EN6MJyz1jn3126dYYlgXo+vc//oGKyBjpzW/U0HqIsGEM4
         7gpI712+OdNRaaYl+TOwdi/Y7hPp6WJbFJdGXdu+k8B8J2s3wbslVgKdADI5i6M+GETD
         jgTuUfLdRCVmv5i7ftVMB2ZYuFiaZnH1xYlOrSeNTkEFtNJG6uox8GFm9dttwd9BVsPc
         BDMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=SiOziBQo;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id j8-20020a170906430800b00711d2027db1si310617ejm.0.2022.06.13.13.18.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:18:38 -0700 (PDT)
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
Subject: [PATCH 18/32] kasan: only define kasan_cache_create for Generic mode
Date: Mon, 13 Jun 2022 22:14:09 +0200
Message-Id: <202a0b87b16b683e32a68cf3d71d369268904829.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=SiOziBQo;       spf=pass
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
index f8ef40fa31e3..f937b6c9e86a 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202a0b87b16b683e32a68cf3d71d369268904829.1655150842.git.andreyknvl%40google.com.
