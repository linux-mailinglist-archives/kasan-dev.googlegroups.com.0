Return-Path: <kasan-dev+bncBAABBPEQUWVAMGQEZID7E7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D4F57E2DBA
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:10:38 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2c563a2a4f0sf53492231fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:10:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301438; cv=pass;
        d=google.com; s=arc-20160816;
        b=LUxDar8nYjn0ofvi3ZE1prwP1al1ZumYB7eABNW1V+vvkIA/sUJ1uDmHQprHw7Kl7B
         HqI4/VbzF835MyeAAkYy9pSvQG7MnHgGnhMHo8BDvQuU+NdBN1mFVaBekQFmx6n8iTdt
         aDEPUDJd12PWCcB5DBD/lcGtB1wpCS6woHEh2Po0ev/2TMVrrwCJkn0jdClnlu9+0BMf
         M2yQPcKw9K6hGiWvoN1am4FLYFxjL+hvOOEv+u0Wwwc8LrPx4GFORCWs+RRLfak/iOz2
         NF5SUUX3QNH9/2hek0uv7xtJDxJRVEPsEgG1fP65PWJNkuUuK9wu5y52WvUVga/EvQCI
         rxAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=CgPCGlPhJm8LXuMaBUmjOZle4zHZH7xohCls3XaDn4g=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=ZG+kOUCYnZyglPev6+gmKvttcX/I/phGbySmA2baqMneRIz7rWGvz1Hkcf8SQuUEX+
         zLTzTM7C138ifRbnoSNDStp3qwBeFfiTR0Q4sTTBosGzVcyyWSf6SlvIk422zoBVysM/
         mIHKLQf2/gVnHad4TZDTswSCys9qr7XT9bnMTiTzbkH/3WrSn8Niq1Qcmu0FvuJUyzjn
         67EGkUcySRmzKFzWDiikyYSJ6+cBFGbDptqGB+chbumhWYHx6MY38c6byW+ArCUGtFe6
         ayCbDtdZNsPI2YclojvWkxLmTxN9HP5uNZ8Wr5C2Uhz54eWkMCDDmn527MKcaRL/waFO
         QOuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=L3cpdQsl;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.174 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301438; x=1699906238; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CgPCGlPhJm8LXuMaBUmjOZle4zHZH7xohCls3XaDn4g=;
        b=g5hweifeYie1kDVLuZNvb8/Mmg22RNBgD1RxCus7zlWpEmYbkpTM0eSENX6hwjFO9y
         Xsy7hE7oqYd8qtYkuSwS+GTCUu8+8gO915bx+8y34RJNazLy65KUM1MOnMtHrzpHXLf1
         62/Lc+09zcxwUSrVRluKpIapkLP0hG9drOz5JFSLhyFPy76UEwccn0Sq5N8RSm/oesXs
         vLOGYqFnEMtSK/vxELXFX6wd8amDW8llR3+EJxz/lakgFWN1rTTgUgNdIEgavqlvLEHi
         Ll1anoa89KB6EiB7kw4EQBHF7BVyTbL6KHFA07fGbM8u/fKIYyc1/N5oCnQnqms8UZAG
         HoWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301438; x=1699906238;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CgPCGlPhJm8LXuMaBUmjOZle4zHZH7xohCls3XaDn4g=;
        b=Mb2EZlHhvTUhX8SbFw7ePlyv/QeSXqz7NsyjbGllicwki/D/GCtP5MzLa7auCd79W5
         16F1dCAzbduk2lOZvJUV6AdZ+kVqWVynk+rPtehElmpSZgiynigmJtK3km08B8uL15La
         TtwAKe4+Pyoz91MJjoa4oU+WJ1HYO4ZJXgD4lbVc3sAjIoIkK573vtllJTcuYVZJX+wF
         k/eGIo0y7+sxtSEGoHKh2yFA7BIev3RaReiPM1hxDyrSrd77abDL6WsA0B1zeQez6+WI
         fnmnzbP7jD/3A0FxIgS/CBslJ5a6LQ5+Vrf2RAXA1MtVou+pFAkFZSEGqP5yPiElR1hy
         O1Jg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw9tsi3tB4ZURCMHsBN5b+U64MktCZHM02v3nVwoX/QDS8UXAkk
	UAj7PPjlwUdxmq97yQ5SWz0=
X-Google-Smtp-Source: AGHT+IGUF3jhBVjy1p1xhi3Oi3pEVhLnFEnGo7IiQjpQzIdb1N+Wm60djVEayzOx8+Z5PRxVvx5Bmg==
X-Received: by 2002:a2e:a4ac:0:b0:2c5:27ca:4784 with SMTP id g12-20020a2ea4ac000000b002c527ca4784mr20088661ljm.4.1699301436489;
        Mon, 06 Nov 2023 12:10:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d29:b0:406:3e39:f334 with SMTP id
 l41-20020a05600c1d2900b004063e39f334ls344834wms.1.-pod-prod-06-eu; Mon, 06
 Nov 2023 12:10:35 -0800 (PST)
X-Received: by 2002:a05:600c:a45:b0:404:fc52:a3c6 with SMTP id c5-20020a05600c0a4500b00404fc52a3c6mr603914wmq.25.1699301434760;
        Mon, 06 Nov 2023 12:10:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301434; cv=none;
        d=google.com; s=arc-20160816;
        b=M0h1+XDBrROJmZKMJv50zcWDo+S+Wg1bT6XzKaPfj0q/PK4CROV/Yth2eINdFXpYc4
         ncZm9hfCMs8NsEXG0p7jGfw98cXS6SAIadhlouFsC3XKmouZE5pRM0LeNw+G9/Jwm0qQ
         j11dq/0uq4Hx6Mp2eleDlQuPnyq2sY+6yJxbbD2w3jdyB/XfJoCUNCqkxRqSXE1HEcpe
         yMj92tWT8YnljsYLrfllsGHQ7TTSMj5chO4zHg9k9YWNbDXN82fOD4/vkBKh6xmwjB1X
         svoKLgiTHh49eqbUVCHO2g8rmzvB9p0y+0U2npZULlyklUKERR0eJ/q2BASjY5nnqYQr
         vkNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5zUveeaHubKwNWv/mUHyod8asGDxf8HEl2nDgxq3m5s=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=g4OglARVGqfTblcWK8PMCHc5QuMQchJ0adPny8+AopvtM9Mfrm3DzmuLfXCZnFgWZk
         v700ySoQO4bpDqncmwV20RnnMwuKA1XsBEa4SCfvTPp7gBkipijCAcHApU7+pzD7yrXM
         fUq43r8lyjLSqMq7lN1AziJ+oYqxlurDpf1cA8OzV/EhZC9JiwqnT4rSf+bMgUjfA5PR
         iVKWtSBk1Nc2EWZYkMy35Bs2GXjOdffEQS4CX0IuwD0r7PAVjxDY0XQ6JuTBRv2OfISf
         chyXFo6KUU2JMBukzlzR6w3OKtbnJFb1XBircb73mhfAqg9Tto3TZuBluiSZThOS8D/r
         XR0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=L3cpdQsl;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.174 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-174.mta1.migadu.com (out-174.mta1.migadu.com. [95.215.58.174])
        by gmr-mx.google.com with ESMTPS id s17-20020a05600c45d100b00401df7502b6si735061wmo.1.2023.11.06.12.10.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:10:34 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.174 as permitted sender) client-ip=95.215.58.174;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH RFC 01/20] kasan: rename kasan_slab_free_mempool to kasan_mempool_poison_object
Date: Mon,  6 Nov 2023 21:10:10 +0100
Message-Id: <bc70b448d766ef7f78a631d1fb6b98919f12b197.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=L3cpdQsl;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.174 as
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
index 256930da578a..e42d6f349ae2 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -261,7 +261,7 @@ static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
 
 	/*
 	 * The object will be poisoned by kasan_poison_pages() or
-	 * kasan_slab_free_mempool().
+	 * kasan_mempool_poison_object().
 	 */
 
 	return false;
@@ -272,7 +272,7 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
 	____kasan_kfree_large(ptr, ip);
 }
 
-void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
+void __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 {
 	struct folio *folio;
 
diff --git a/mm/mempool.c b/mm/mempool.c
index 734bcf5afbb7..768cb39dc5e2 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bc70b448d766ef7f78a631d1fb6b98919f12b197.1699297309.git.andreyknvl%40google.com.
