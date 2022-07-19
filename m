Return-Path: <kasan-dev+bncBAABBMHN26LAMGQEJOJA7OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id DA719578ECF
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:11:28 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id m9-20020a056512358900b0048a16de8aa7sf4690327lfr.5
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:11:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189488; cv=pass;
        d=google.com; s=arc-20160816;
        b=O+Qin39wwi/r6xqwsrtEeUznTAcgYPusnZK4KtzrZHkSw7dLAZ65gcTJjnxz8xrKXi
         BxF3LRhj/TliE4QxUGB/irGKNYNjSqPbab3hWWkJ4P856tQ6Hr1g7zdVZ+GF0OZmdwGK
         Yv4xxzUQGD/W2pokylcxh/DRONksKDCWJwacXms/heK8kFraUZChhRLNkVP6VlUSX3ig
         feOV88Zs7yL4Okw1OucqGyewy9D8tOedkMBKZ4olbN8SJtd00/8+bl6jDAeQ0W2nA+RV
         KvSRvyuYoZOL6HTF0RXq1RbBFOuj184zq2+Xd0Bdc5nNdCsTF9MXpJ4F5yW3tEWAALqU
         yovw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=owo7PIx37qTh/wynCRmJahaVIXdQsPm77zqKN8Uavyg=;
        b=y8WRec1osmfKbUyNWZeBwck/OFSzBGiMN0zkbtWmSwaY2L1XxyqZq5HeKmJSdw5X5/
         cYJU04Ie3QpS5P2B5tN2ckMb/O+437mRhFXllPKvkpSUpBsQmQVpP3FjCyzugfHFEWAp
         7PZiRpVhjKGZyqFb9hHLlSDqKC5rKNGkks7lQuvwRbOD5JoSHqlNMkokOljrKJX8PbJn
         yYA/iRB6UfCFBCpoJ6NFpHd1RPh6e6C1FJ1oDYh5LLNF49b6BXB/v0tB1nzPnppkl4FQ
         e3y4MTtBlZbwoueR6+rKldN45wFlEalB3kFIUaHrSJj9SQrbDUj/OvPYmyl1XclPdyF4
         hnFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Dgr8rg8W;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=owo7PIx37qTh/wynCRmJahaVIXdQsPm77zqKN8Uavyg=;
        b=grdyV2d6BDlKT7bNw6dGw8fTJQ7YqQXoU65Kv3k0u2SJfAi/yqKCTDS4rVltjBEtTK
         6LeW4IcjvjxFvI8v/8nRGVQL/xwlZNK15Lat32ReKQi06lQ3GDgyKsHVhaKjyn6BFvoB
         I/yE81fdc5k74PwkpRguWJGGHa8oexgHBjh0W1Lrwl3Ir/JPKobP44lwrOytL+81nPPj
         hIm7iITHDeb2a8Gcy435faGj0UBA/zbDCD8ZvUmoPywZDVMkffsC2UWEZLMOPR3Ew23o
         +LJYw1pfqXOjg23CyinmBXOMj8gX5rBGe79fe4dihXYs4cgR7GfvqTj1q9tNtn1s/zeq
         eYaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=owo7PIx37qTh/wynCRmJahaVIXdQsPm77zqKN8Uavyg=;
        b=bTEk2TslQ66dt81WzHNcfXrap0aVI197avUYyRnoulmmUD82FDiTixMRwOUYwlV4ER
         5DMEf8aCR5spH1vaa7Sf0nnbT5uXBld3KGi01T0GSuKhphshGx2xX0TCC9gT3Vgmvd+n
         4QX9CO8utMfNx2k+NCFJfqKbkNFAveaw8wzdcvUkOG2Jj/NL5JQnnUDsSpqmn/Qmz9WQ
         9USc9yl/NpaO03tZ+M5qnMaMd6R+rABxq22KTGoUqh6L9vzzjYwTuf9QNzDysiN7ZoDK
         gVWPqKWUNFCgY9to/Uv3UFJL09L5Fek0egD0nmlz6fkLe8L0j8LgjA9+LPLKxvc2P+Sj
         K7Ng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/LMyrgEavhLaf0CwdMw2RkMehyJecicVSPFF7AcSijnqyr1rb6
	+jxnKllAALP+veP63cyNacM=
X-Google-Smtp-Source: AGRyM1vbct0nNaGjb6PlL9xopk0fzqhJpGPCgnqysFp033u9wGbDmnP3tUvT+sIXUnuysRRxpSQtTQ==
X-Received: by 2002:a05:6512:3250:b0:489:da92:77a6 with SMTP id c16-20020a056512325000b00489da9277a6mr15651861lfr.17.1658189488264;
        Mon, 18 Jul 2022 17:11:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4da6:0:b0:48a:15f0:80b2 with SMTP id h6-20020ac24da6000000b0048a15f080b2ls1663644lfe.3.gmail;
 Mon, 18 Jul 2022 17:11:27 -0700 (PDT)
X-Received: by 2002:a05:6512:118d:b0:489:f36c:5118 with SMTP id g13-20020a056512118d00b00489f36c5118mr16969736lfr.39.1658189487464;
        Mon, 18 Jul 2022 17:11:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189487; cv=none;
        d=google.com; s=arc-20160816;
        b=kgR4vMxZvTK69qH7S2gIrb5hGMNX+84X00tdGsuQ9+4hlbi7asygVM6deDlca0sV3p
         GquoD5rL+fdRXEglbT2Zcm4HYO2gZTwr+VRQGmRKz3d+pNPFTM2OvupeMJDwW/aXp3O9
         fppJztltXgviGTRJTAtCsrwXZSQQl+brdQWng3g45oICNkZJig6SIY0kKGKH/OEnwsD6
         2ukMK0xj+J8T1v6wsO81/Mp1tpJoT3b/ej1G5vjNh7FtxLZNt2d6QxzyDPUY5G6lYG1V
         sWMg4ZwRTPaVW7Ln93EoleEAE2wlMtXZHzGadkHoyTDCSYr4WZd51Hezh7/LdoP2S35N
         YlWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rlDhQ93GQxymrct+XncFBhhuVBx6ex2JMh1zy3E0kDY=;
        b=vLdehtmaXiTfVkpSZPKDfRaS0UJf5KBZ+7pEnLkP5KqvuTb3I27+cMk5ZDJdu6M7CC
         F1ykgBd9td+nVjPeZDkRedwrscoSlzV2b4K2laIDv8u0fdiY8lrBfmqKJOeVOeOaN4iJ
         MORjxFjgG6wiiDSxyDbrFCVZGCqMQ0ZxsQJwAOxI6f9jpr/2N2XFyO6K0RNnAVOMPXi5
         NrE12cWk1P8lq1VpX7OGcm7HGzEjJp6cmPkXJIEZXZjTj/4GTwaWblIhyAgVCSFBsijc
         AtiIZfLWYs+qexF2CXOFcuPLYIXq596XQWiWozIQkzNckW2CgDVVlgJE9ITFDPP0UIue
         fJFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Dgr8rg8W;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id t12-20020a19dc0c000000b00482b3534361si368982lfg.6.2022.07.18.17.11.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:11:27 -0700 (PDT)
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
Subject: [PATCH mm v2 11/33] kasan: introduce kasan_requires_meta
Date: Tue, 19 Jul 2022 02:09:51 +0200
Message-Id: <54b97ba71189b557b4b70e9cdcc821ca4349abfb.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Dgr8rg8W;       spf=pass
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
index d46bb2b351ff..d2ec4e6af675 100644
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
index fdd577f3eb9d..1736abd661b6 100644
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
@@ -272,13 +296,14 @@ void kasan_report_invalid_free(void *object, unsigned long ip, enum kasan_report
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/54b97ba71189b557b4b70e9cdcc821ca4349abfb.1658189199.git.andreyknvl%40google.com.
