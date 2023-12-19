Return-Path: <kasan-dev+bncBAABBOVSRCWAMGQENQQCPJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E5A381937E
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:29:15 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-40d31116cffsf2079055e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:29:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703024955; cv=pass;
        d=google.com; s=arc-20160816;
        b=0Vr2gwqgt1tGY+Gad7RKnVDXRB1EwEdPna6ip8FFdEKFihvdHOio4uhtqRuj/7rRzV
         Sq/Fanxd0az24sls8+KZFCje9QXCoC2gl8U5I3X8WikEz+rjXtpPt5wWVpmCu631++sb
         ZXfKBtB/aw0KMBGpetWqgz0TeSDj8Lp7MDYgW8b4lvnfBLPv6XIQr7hjh50agxNr798U
         7V90W1hGq/wTHhZ3Vht1mzcc7uQ6Oh++esbKIWtO4gouGig3qHUUHDnjmfSBdvnjEcED
         A347wmC4oBlX8v2Wcda2wsK84rAconUGYc633WeyMPD4Wsl1bd2W9pMbZfH2bblSTj9B
         ApgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+seAK0MEy2GuQ/18uMK4RJZ2pk3Tmgw6F6L+HCAb8ak=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=pT17923R3grglTjBeo2a5/gzgBHN8TnboU+kxm0YvK4iPukTiPnNeynW5aIsdsCNo6
         fdnfxFo8NCA1vHcX90ATNV6FivHsoQAu4TpQyfMPelTug2VqnEnFmi1HpALce2Xn2pqH
         Qv990+wDN01Yocco1b8ainFxo4PwZSYuyH94xQbOTUXOZsY4R3qJtiRKsNsZT5Wbegpv
         rLohmECw/H1Fcpjd7fIPcwxHOQrQhZ8yj4o71G5R6b8+KU8F9JxTXd3hks4sWZtNSwau
         XOVxWUmS0zQc1Fru5f5PvtpmGOsrnjGq/H2M24+7QJ2Ay1pf/7g4OlWz89PpEaa99gUh
         gfEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qtqOsejh;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.181 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703024955; x=1703629755; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+seAK0MEy2GuQ/18uMK4RJZ2pk3Tmgw6F6L+HCAb8ak=;
        b=jOgYdTdhz+SP5AkctNUWSWuSZBhlR3MqqYNLKYh3j3nmsTXnfmc2DBHxivZD+e7kI/
         Rf7gq73itvMHIT4YLd0Xs+th0EI/Zui6uLSEo/hyLx5kURLlle3z6unwRxZxXPZ3z54N
         TdsDK6J77xAETxn4gYOLaaEki+wu8MqGavA69zNEHRrlwCrXMAyoZod0hadh5mPB0pcy
         WzTNedJ0FtefEdtGeSjWXA7t9KVn5ExBu8P64F/O2gBfCSYYsFcxFfivMqKSFiEO/UCb
         8V1Hp0OfOaNyniWbMdD/KRlTjxoXXa9YBdy9ocyiOMbqNquw/LAT2Mdb2IEFqLuEOfHp
         xGcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703024955; x=1703629755;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+seAK0MEy2GuQ/18uMK4RJZ2pk3Tmgw6F6L+HCAb8ak=;
        b=jlEwD0tZMDQqacM85zmCgX+0t3BZMj9Bdu8JLtH6KcOJpKN97UQy5bz/elH4p1KUgj
         76CiPmYp4BRfg9g6ji6q7qVB+SLrycyBwgMbrEqwedOyEz2L3I5WUiDKzAQEJv7m9tI3
         BnAuKUXQ2bfpdR0yEp/3h3r2aRx9daYFc6vbjocO6VMaqiovnV4giUTs7Um7G+Hh9kYT
         c6ZZGvE4lmymLwSRbPjCQxhaSwxovQA4aUtJxi+SfmW/h6CpZaf8OkARsoQdwVFW+NeK
         xbLv+kdl/QN8MExH1rTNbzHYNeVsoRjUQskeBgKfXeT8ReaIYB+0/lGzbdZoh0V+1Xit
         OTVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzX5SQvmowvnyPFMdov26/XFwhbXGReTR0Hwme2tMV6P49iZEqw
	oycTAT4t7YYhxmfZbbOwvP4=
X-Google-Smtp-Source: AGHT+IHT6V+0+3I4ZyQjJ0NSnTs298XVD8OiKsZAG4HEKL8oTmwDcOy38Sf2BeAStWcTaUlSPoMHbA==
X-Received: by 2002:a05:600c:1da3:b0:40d:22d1:668a with SMTP id p35-20020a05600c1da300b0040d22d1668amr923816wms.37.1703024954249;
        Tue, 19 Dec 2023 14:29:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f43:b0:40c:61a7:cf0a with SMTP id
 m3-20020a05600c4f4300b0040c61a7cf0als1744941wmq.2.-pod-prod-09-eu; Tue, 19
 Dec 2023 14:29:13 -0800 (PST)
X-Received: by 2002:a05:600c:4e44:b0:40d:28ce:bb8a with SMTP id e4-20020a05600c4e4400b0040d28cebb8amr879117wmq.35.1703024952776;
        Tue, 19 Dec 2023 14:29:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703024952; cv=none;
        d=google.com; s=arc-20160816;
        b=ZWCtHrg5CJPNd8QfxGEo3Tje0sLeVO9mjZ6UxtJ6VYwa/LZERXtjyf232+EsDwyWf+
         z1GvbSqkuU8Hi0lXAycCRs9u8F3+XMf9NZnqdR9sz/aEzIZxJt7bSFWc8WXkCWwbOJAo
         Gc+UoJc0vQwTUVLmOJYkLZ5RO+Nil3jnaa5v1bcYZbhA7puteYka3C9wL5uq5mNpF842
         dececD0vy33ftf5fleuWOxaBVTHn4Se6J6JgY7bJ+VlfXu7gJeYF+QVYeCavquRAmLPI
         ObR/suPaLjBi0W7WR+ncm4F4LLgCm2uJpKuN+xX7h1bBkJ4YWMxLQldLhUEkiIIOp4IQ
         A+og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=65Nj55va0LyidH/qJFPAhjUaSN3kZxL0lL8iCsNvyX4=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=lg5BazPgLnxbNNo55t9zC8MK94rNfmquzNXeUwqYHYya63ESMTy5ribp/xQqvdQTrp
         AmgoPgXjKXdQ4EXTkTwPqCp2iO/5jN54dGLUvn/fNqKC72KykcKSP59AMdsABkJkgbBW
         v1kxLb32P8m8Fpvs8hXvM7cZfVqe1s8Cu9LOIfdQm7HBGMVaMK0mRNrrS7Owi5OFN5Id
         v7+fzCOaJH8W5R76OSKfsg6Xol/Tr3VWnuKcVmEWbqNvM4paQAJG23RC1ztlI8uC3tEW
         uvdejxrb2Ptw9qqOmQPj3QF/G34d9dltc3mWUKaJED1JS0KDIg3+e/bYui0PfdFE2767
         tJ/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qtqOsejh;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.181 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-181.mta1.migadu.com (out-181.mta1.migadu.com. [95.215.58.181])
        by gmr-mx.google.com with ESMTPS id 17-20020a05600c021100b0040d2dbeb249si65610wmi.0.2023.12.19.14.29.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:29:12 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.181 as permitted sender) client-ip=95.215.58.181;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Breno Leitao <leitao@debian.org>,
	Alexander Lobakin <alobakin@pm.me>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 01/21] kasan: rename kasan_slab_free_mempool to kasan_mempool_poison_object
Date: Tue, 19 Dec 2023 23:28:45 +0100
Message-Id: <c5618685abb7cdbf9fb4897f565e7759f601da84.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=qtqOsejh;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.181 as
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

Rename kasan_slab_free_mempool to kasan_mempool_poison_object.

kasan_slab_free_mempool is a slightly confusing name: it is unclear
whether this function poisons the object when it is freed into mempool
or does something when the object is freed from mempool to the underlying
allocator.

The new name also aligns with other mempool-related KASAN hooks added in
the following patches in this series.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h  | 8 ++++----
 io_uring/alloc_cache.h | 3 +--
 mm/kasan/common.c      | 4 ++--
 mm/mempool.c           | 2 +-
 4 files changed, 8 insertions(+), 9 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 72cb693b075b..6310435f528b 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -172,11 +172,11 @@ static __always_inline void kasan_kfree_large(void *ptr)
 		__kasan_kfree_large(ptr, _RET_IP_);
 }
 
-void __kasan_slab_free_mempool(void *ptr, unsigned long ip);
-static __always_inline void kasan_slab_free_mempool(void *ptr)
+void __kasan_mempool_poison_object(void *ptr, unsigned long ip);
+static __always_inline void kasan_mempool_poison_object(void *ptr)
 {
 	if (kasan_enabled())
-		__kasan_slab_free_mempool(ptr, _RET_IP_);
+		__kasan_mempool_poison_object(ptr, _RET_IP_);
 }
 
 void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
@@ -256,7 +256,7 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object, bool init
 	return false;
 }
 static inline void kasan_kfree_large(void *ptr) {}
-static inline void kasan_slab_free_mempool(void *ptr) {}
+static inline void kasan_mempool_poison_object(void *ptr) {}
 static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
 				   gfp_t flags, bool init)
 {
diff --git a/io_uring/alloc_cache.h b/io_uring/alloc_cache.h
index 241245cb54a6..8de0414e8efe 100644
--- a/io_uring/alloc_cache.h
+++ b/io_uring/alloc_cache.h
@@ -16,8 +16,7 @@ static inline bool io_alloc_cache_put(struct io_alloc_cache *cache,
 	if (cache->nr_cached < cache->max_cached) {
 		cache->nr_cached++;
 		wq_stack_add_head(&entry->node, &cache->list);
-		/* KASAN poisons object */
-		kasan_slab_free_mempool(entry);
+		kasan_mempool_poison_object(entry);
 		return true;
 	}
 	return false;
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index fe6c4b43ad9f..e0394d0ee7f1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -271,7 +271,7 @@ static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
 
 	/*
 	 * The object will be poisoned by kasan_poison_pages() or
-	 * kasan_slab_free_mempool().
+	 * kasan_mempool_poison_object().
 	 */
 
 	return false;
@@ -282,7 +282,7 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
 	____kasan_kfree_large(ptr, ip);
 }
 
-void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
+void __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 {
 	struct folio *folio;
 
diff --git a/mm/mempool.c b/mm/mempool.c
index b3d2084fd989..7e1c729f292b 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -107,7 +107,7 @@ static inline void poison_element(mempool_t *pool, void *element)
 static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
 {
 	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
-		kasan_slab_free_mempool(element);
+		kasan_mempool_poison_object(element);
 	else if (pool->alloc == mempool_alloc_pages)
 		kasan_poison_pages(element, (unsigned long)pool->pool_data,
 				   false);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c5618685abb7cdbf9fb4897f565e7759f601da84.1703024586.git.andreyknvl%40google.com.
