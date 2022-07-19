Return-Path: <kasan-dev+bncBAABB37N26LAMGQESVFFDZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 697AF578EDA
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:12:32 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id z1-20020a195041000000b00489cc321e11sf4799870lfj.23
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:12:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189552; cv=pass;
        d=google.com; s=arc-20160816;
        b=tCqgB1SLiBDSly8qDSRUNGCmJV+eQoTn/BvUu6sTh+M8Rt2hpslkf5ZThXRylmmn6x
         QGwstqk1YQz9JH+0Iy1Aqg7fMDb1z0vVDOJbhLLuUl7PseDkCp5TGXAhXV78LZkWsp2z
         JqFbRNDrHOPMMrNIJn26mi2a7NNfgR6ynx3yEsHfu/+bFeKcJKBWXkswe95snprOzhxt
         NGo8n3vQI3xO0l8aPi7Nbwl1A6rVm9mkZIcNZV9QTnFEWgtFKXA9JAitl087oVsmQ5q+
         1mDVBYXg3qyGT1+KkonVIzEDZvWNF0nPiCPai2+xBSX6wf/xay8qAIEgcVUtbRpBkYO8
         O3gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Aq/FnQGouRcuFY40Nv3pBFuWa3qSqUTeHf5NO6IhiYM=;
        b=rWw3RP4a9hfGK1wbU8fMulR6xwm60xX1f0w6brrQszXMFhtHbuANZbW8+ZYH0ogW9G
         n88XSx4fPC+lshnFwQqpLek0c3A4ZGFFP7N8jSpROLSF9Re0Dzaaq93iMb0TPpkT1VSA
         V14mZsDdS4zsbSuAGN4XBLNm1R7f7B/t1u47pB0JCjxmhJy8cuzte9dQvXI3/0eRnMGp
         pLL06G9V5QlX0sL2B+mRuXzqpIshKsDdk/aOaVDKKWoY2odGSf7QC7dKWbxduIADBi8e
         HOHS63URXSh1Z26N2uagoC1wgTVZ3t991KBKq5vZNmiYnAScUVfspNqKL8FEvh5eF8Ca
         8Scg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=e6TbVslU;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Aq/FnQGouRcuFY40Nv3pBFuWa3qSqUTeHf5NO6IhiYM=;
        b=CHza5Ta5a7vcpT0pcv1VZ9Mt0cB2KPRIhqMzsU4984Gk5W5qVrBUaLX94aF7MDoXS2
         VXCVqa3DzQqexR3j2uzVizmRcx5qmv1803hVlIEe2zAIN1fORycBnQ1uK7+eXVL2Up24
         nuzSfX/oAwpo6/0p2rE9y+heQKxfYqyH/ugnUxRm8XNw0JR5ltNZ38fS2BrwGdzSEYZV
         HcdsR7pk4DfbpnN22WXF04EtQFkn+FgZyj6Ie6lxovqr2FFw2Mp21PrmnZlNyuGT26I3
         1dMmcWFZ0cSzjFtAdjHhLMhJq4xKXuW44XCM8wWtn+sMF06ED9IQvgth77sMCFuTGuoz
         vJTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Aq/FnQGouRcuFY40Nv3pBFuWa3qSqUTeHf5NO6IhiYM=;
        b=KwZN7BzisfWU7Q70HTKqG+QKe081d0UsSYushCdN1uxBfAPB3HEotJvt8cYGKTD+hn
         hAQsoPnXv4sPxEME1FN8R/6WFp9e80WEQCzDldQ1xjWCS1YKaUhkHalHMeBptEnzUVbp
         viORGwVWYFIxq2JRwxQbY0aJs1Jg80TkUxwQg0qhFMfiKJlIh9CXixgZjqEjH18W5V4B
         bJehR1IqhApEdzil7P309b9ejUHdx49bJhyXdMTv8i5f2iSj1QWZUL+0mv4qCRHdBcoB
         7JrA2Z2BqHi+7rVBbxyd8NDFjylRR9/PnUu3mnA6MiIsyV2mXO4v1GIo2fltnUFXi9Qf
         E7XA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+6CA6Y9sV2/uqCA7wyxCLcBC9nTd7OrsxH4ZVRIzkjbyKIpRlE
	jnS2JojsSZxBd8LTJDUdVUM=
X-Google-Smtp-Source: AGRyM1v7RK1uRcxtP3w+nLb47I3MGck0u3EVW1/Luys5l1QAEoPZyEWOHUesNgIdp+T6pzPUyBPvIA==
X-Received: by 2002:a05:6512:23aa:b0:489:ddb4:6f84 with SMTP id c42-20020a05651223aa00b00489ddb46f84mr15675956lfv.683.1658189551964;
        Mon, 18 Jul 2022 17:12:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f78:0:b0:488:e60f:2057 with SMTP id c24-20020ac25f78000000b00488e60f2057ls16524lfc.2.-pod-prod-gmail;
 Mon, 18 Jul 2022 17:12:31 -0700 (PDT)
X-Received: by 2002:a05:6512:1083:b0:48a:ef0:5a2d with SMTP id j3-20020a056512108300b0048a0ef05a2dmr14517498lfg.400.1658189551291;
        Mon, 18 Jul 2022 17:12:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189551; cv=none;
        d=google.com; s=arc-20160816;
        b=aWaK48co2VFgm3ArOe1dchV6SXa5BrANQG39ebPIYhnXSpBxDXMzkEpeN0UFOAcurm
         pPNdslO8gY26OUL5xcOkCtIlHAbh1uD6JANg2yXSMetqhPBw8mR+4fYvEZTUFYg2S0oL
         Q5AbB2Z+/rIxtoQ+TnW5+tQRMChLa+grEte85uuNF9Q0+RovJ04RSV2mZLNsnev+JCg+
         QcXCItnaNaOChnOeWq7TA8qlhuooNki0C52PRLS3iFcJyOdkCViUGQb7fhowWY5Lqop6
         plr1kWmXyvO3NrIQBPwPRPrDLXJbHZf3DffSJtmLHURxYMfuXtZcHDGSECWL6MAr/EA7
         UYpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=51fcsYmho6J8ZJUQBvChW6NiCMPna0Hu4OlobGKbOIM=;
        b=pSyZcSG9FDXh2wyRKZOaRDem3Aah4H8C48RFIUR/4iSWHu3oo8KTPzlAH+fI6R1056
         GB+y6qKPzZ6QKWMqrFVtUq9AUM93uumiLXHeP2qSRVhC+FAqcRq33DlWhrxzSJI5GkJD
         P3U/qezJ4zHWepAe7vGw5GIp+Ljp9x4qJkLY8X5Py54fzf4CNR6rMsyyVnTZVHc3IqlT
         fBvM+ryHgFqpItdk8g3Ww866PnmSl2ezZKchj03E9qxUIoKbUKQXNceJobt4r8QgEcdL
         hASFGtmjAfQuzG09YmD8EtX/EDrUFX8zVNZ1xbsVqiy6pOx2NcAh0qrFHhF2eRTcQlgk
         yHBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=e6TbVslU;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id k7-20020a2eb747000000b0025d5ccbc5c7si481845ljo.1.2022.07.18.17.12.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:12:31 -0700 (PDT)
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
Subject: [PATCH mm v2 14/33] kasan: only define kasan_metadata_size for Generic mode
Date: Tue, 19 Jul 2022 02:09:54 +0200
Message-Id: <fc6a4d6f017b764e4923c2021db25d58cb8a51e0.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=e6TbVslU;       spf=pass
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

KASAN provides a helper for calculating the size of per-object metadata
stored in the redzone.

As now only the Generic mode uses per-object metadata, only define
kasan_metadata_size() for this mode.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 17 ++++++++---------
 mm/kasan/common.c     | 11 -----------
 mm/kasan/generic.c    | 11 +++++++++++
 3 files changed, 19 insertions(+), 20 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b092277bf48d..027df7599573 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -150,14 +150,6 @@ static __always_inline void kasan_cache_create_kmalloc(struct kmem_cache *cache)
 		__kasan_cache_create_kmalloc(cache);
 }
 
-size_t __kasan_metadata_size(struct kmem_cache *cache);
-static __always_inline size_t kasan_metadata_size(struct kmem_cache *cache)
-{
-	if (kasan_enabled())
-		return __kasan_metadata_size(cache);
-	return 0;
-}
-
 void __kasan_poison_slab(struct slab *slab);
 static __always_inline void kasan_poison_slab(struct slab *slab)
 {
@@ -282,7 +274,6 @@ static inline void kasan_cache_create(struct kmem_cache *cache,
 				      unsigned int *size,
 				      slab_flags_t *flags) {}
 static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
-static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 static inline void kasan_poison_slab(struct slab *slab) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
 					void *object) {}
@@ -333,6 +324,8 @@ static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
 #ifdef CONFIG_KASAN_GENERIC
 
+size_t kasan_metadata_size(struct kmem_cache *cache);
+
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
@@ -340,6 +333,12 @@ void kasan_record_aux_stack_noalloc(void *ptr);
 
 #else /* CONFIG_KASAN_GENERIC */
 
+/* Tag-based KASAN modes do not use per-object metadata. */
+static inline size_t kasan_metadata_size(struct kmem_cache *cache)
+{
+	return 0;
+}
+
 static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
 static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
 static inline void kasan_record_aux_stack(void *ptr) {}
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 83a04834746f..0cef41f8a60d 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -138,17 +138,6 @@ void __kasan_cache_create_kmalloc(struct kmem_cache *cache)
 	cache->kasan_info.is_kmalloc = true;
 }
 
-size_t __kasan_metadata_size(struct kmem_cache *cache)
-{
-	if (!kasan_requires_meta())
-		return 0;
-	return (cache->kasan_info.alloc_meta_offset ?
-		sizeof(struct kasan_alloc_meta) : 0) +
-		((cache->kasan_info.free_meta_offset &&
-		  cache->kasan_info.free_meta_offset != KASAN_NO_FREE_META) ?
-		 sizeof(struct kasan_free_meta) : 0);
-}
-
 void __kasan_poison_slab(struct slab *slab)
 {
 	struct page *page = slab_page(slab);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 5125fad76f70..806ab92032c3 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -427,6 +427,17 @@ void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
 		__memset(alloc_meta, 0, sizeof(*alloc_meta));
 }
 
+size_t kasan_metadata_size(struct kmem_cache *cache)
+{
+	if (!kasan_requires_meta())
+		return 0;
+	return (cache->kasan_info.alloc_meta_offset ?
+		sizeof(struct kasan_alloc_meta) : 0) +
+		((cache->kasan_info.free_meta_offset &&
+		  cache->kasan_info.free_meta_offset != KASAN_NO_FREE_META) ?
+		 sizeof(struct kasan_free_meta) : 0);
+}
+
 static void __kasan_record_aux_stack(void *addr, bool can_alloc)
 {
 	struct slab *slab = kasan_addr_to_slab(addr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fc6a4d6f017b764e4923c2021db25d58cb8a51e0.1658189199.git.andreyknvl%40google.com.
