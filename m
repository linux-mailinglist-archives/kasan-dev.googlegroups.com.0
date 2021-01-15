Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGFNQ6AAMGQEQ4VYNGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id BAE182F82FF
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:53:28 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id i7sf3362973lfi.4
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:53:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610733208; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rvt9VDh1nwcABpIYBQD5mAJMp3tYY6nHh6CjZQVP3hnaKLYK9mzhyRp+dnlmsc8RvO
         3rGreRA51sm40uR89HzU3emHptS/28WYz4GvJ7Ep5PZoitCGuzfqFEu2Re/ovapAzKBX
         F379Fyt7vKyZSnliZBlRphhD9wzKnAcbYayLfwKGtRTPCT+GKAtjg8gKrNOLluP0fPcs
         01TE+CdW/+4ZrJ+Lp+9rI2V+qAjct7KyF8MzRqWYQ7el++zj23HMVM5+MEocfySir1p2
         osNoySvHQ/sw0d+u5BJXLeoyQQ92/Y3iEOwgVs9uxFqj4X3NkQfM/8rKX9iFK04tRP8S
         fQWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=npm48cDYXD+T8yV9Yj4vh9dwYYmd4Wp8cgSfMTJyt+Y=;
        b=qGCuRKJGaJSExR7iIR5fMS8hCei0JVv77obABg3zHJPCDEgERKicVO58W3MeBZAO7I
         ciT0EKwp1Y1JOzFkRQX+YZl1J0qSB5Kkr8iPUjT8jkL0NqvXPuov1Wn/rYW5Wc/dqz4z
         xfjf112+pGm/NXTF0RxJnAQ5DzHDcmm50sN1HDhHnM+HoIXikx+lDxT+OY4Rxr3haYZ2
         Ypy0AqL1IIPkpQwl4drOATjdNOzcvmozzgZg/MYSNr7oVHpVk4SkIJqUZM5pzB/QuzQd
         R/t469obapv4ou6pTSJ32krua3bZxybRGACNLEjiIsfbg/AlladEvm+lSwQ4XXvqvoQb
         2d2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=O2+V2Kgu;
       spf=pass (google.com: domain of 3ltybyaokcvet6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3ltYBYAoKCVEt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=npm48cDYXD+T8yV9Yj4vh9dwYYmd4Wp8cgSfMTJyt+Y=;
        b=j3yNXPgUpyXK2BN0pC4CcrmF69vEO4laNLyFSr/6+1+NR3pt0e1LpiTCKwagh8B5mh
         LmDDDRYROu68FxnGMiXATLekwglw5MoJPX5QymySofIc1vUImnaupjRRS/jyii/EvbDz
         5R054YPsRC+MSLLtxKyYdOSzBNv7LnriqPE4/Rvj4aJ2RpUxbgZDOFNlxt5+oYzM5qSU
         WcX2B34y0usFhrFHpioVXyoJLqZMJpvXT2LZJ4Z20iNicza4OQ4v4KvoQvqcHfXK3mbm
         LXdZxN7c08zM6U2bHiub87bLVbulGYCoK4qhRsqwH4KmjSlnAE3E21o0iom9zvgI98bN
         JsMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=npm48cDYXD+T8yV9Yj4vh9dwYYmd4Wp8cgSfMTJyt+Y=;
        b=CwxUoLTydNjP+nMLp41S+hqQ4ZZ38HkgOhSR6FDBihoIUEbs03Ox4vmVhXmqMIJc1G
         nwPmzplo+QRlzxLoMiifXK+R4kkoFjelVOKJl482qf8qotA4x3qZKLTuHdjEckHZrLok
         8wuBxQI+MLz9mbBA8Oh42yg9H6/RBKDz4b0UD2BsGTYYHsrFWUXv/pOflTsb4ckeFPIb
         m86Xz8bL+0seDJcpKGDKD58Q1xewmGdA1YOKn9FeLB4hSKfHrhW6voGXkqhHRYCOKNrI
         k2xtmlzTdhnMR0m5geM+OJ/JOu+l1RZccaeBQAcRprA3o0rCsMprGji5/AHlHpA9X3Mt
         UzPw==
X-Gm-Message-State: AOAM5305M7SyOWdtSiVxaOzR/iEM1MZ1y+fbXemZ0q6M4pBTMfzOt7TV
	xsdZmWDC3jOe1lvZqgLk0lo=
X-Google-Smtp-Source: ABdhPJzXxywI5vxzZktBXX7BD13B/AgCLyTlWxFij/YcSGg3IJosqBLzffvybIFoUD4hLWN8VtssAg==
X-Received: by 2002:a19:e215:: with SMTP id z21mr5768528lfg.620.1610733208337;
        Fri, 15 Jan 2021 09:53:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b549:: with SMTP id a9ls1703127ljn.1.gmail; Fri, 15 Jan
 2021 09:53:27 -0800 (PST)
X-Received: by 2002:a2e:b001:: with SMTP id y1mr5930205ljk.257.1610733207329;
        Fri, 15 Jan 2021 09:53:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610733207; cv=none;
        d=google.com; s=arc-20160816;
        b=gtMnX1GxVNx4dt/iNeXAOgJLWU34/PvX/h+5tRtZ7UpBpXBo0lgc9nYtqx8gcgp3aN
         oeMs9CtGtHbYChFNU54sPaiwoOd2TsJYIDrqJd+Nbb7chuRSg0ScYGVfkkhb0akVlD9c
         x/BhnFmj3ZhQlu0vzZ2n1HnTY8NrpFkLkZlzGqf4tNOdovMBnm3XfkAtjidB/Tduuf4a
         Dan5Hkh1JXfTG1g0TTF8536/M/XYmZVjE5Q3OWJjabWYI0l4jZntEva9gzKBx5wwu8M1
         q5PL25Tmno1xMWzfGLtlvU+cZrlm/vwrRPE65UF7zaTI0miTVi3bLqLqqafPOlkNJ2BB
         OHqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=s9iTK42qkuuD6lYECtRWQxjMOH1zhUNQbPwL/2iO3lo=;
        b=N1hlMyQ+VVtg1gh45zu9jEV4nv8NwQ40FF13asRp0i9pH0nrd3ZdL9dxHcXn8pBTw/
         S6vcZP/bCrnFixfcUMlK+oWJ8m14sGoUCuKZm21eF6kp5VVDRmfDbgQL+SaUVhu5wObD
         9gjxi/sxM9dEUHmMBCWBNrSh027OQIzCQ0W85Kyp8SrIXqgIBH00j7ED6hGpxhHukvyn
         osuF32MDfZfh+9YXgM5pRcS+5sNJI4Xk5NxvBTgRJMiWmRAsUTstdXH8Rq8SD6WBGzN4
         S+bhSRHMmHOMYThDc0mDLCaEhYZCXJhUVYvM5OpfQCrAxguhENp32ULVoupEOhAUireX
         6Vjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=O2+V2Kgu;
       spf=pass (google.com: domain of 3ltybyaokcvet6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3ltYBYAoKCVEt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id r26si423441lfe.8.2021.01.15.09.53.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:53:27 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ltybyaokcvet6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id h4so3904705eja.12
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:53:27 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:907:d8e:: with SMTP id
 go14mr9789602ejc.472.1610733206643; Fri, 15 Jan 2021 09:53:26 -0800 (PST)
Date: Fri, 15 Jan 2021 18:52:48 +0100
In-Reply-To: <cover.1610733117.git.andreyknvl@google.com>
Message-Id: <5c1490eddf20b436b8c4eeea83fce47687d5e4a4.1610733117.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610733117.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v4 11/15] kasan: move _RET_IP_ to inline wrappers
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=O2+V2Kgu;       spf=pass
 (google.com: domain of 3ltybyaokcvet6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3ltYBYAoKCVEt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Generic mm functions that call KASAN annotations that might report a bug
pass _RET_IP_ to them as an argument. This allows KASAN to include the
name of the function that called the mm function in its report's header.

Now that KASAN has inline wrappers for all of its annotations, move
_RET_IP_ to those wrappers to simplify annotation call sites.

Link: https://linux-review.googlesource.com/id/I8fb3c06d49671305ee184175a39591bc26647a67
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 20 +++++++++-----------
 mm/mempool.c          |  2 +-
 mm/slab.c             |  2 +-
 mm/slub.c             |  4 ++--
 4 files changed, 13 insertions(+), 15 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 5e0655fb2a6f..bba1637827c3 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -181,19 +181,18 @@ static __always_inline void * __must_check kasan_init_slab_obj(
 }
 
 bool __kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
-static __always_inline bool kasan_slab_free(struct kmem_cache *s, void *object,
-						unsigned long ip)
+static __always_inline bool kasan_slab_free(struct kmem_cache *s, void *object)
 {
 	if (kasan_enabled())
-		return __kasan_slab_free(s, object, ip);
+		return __kasan_slab_free(s, object, _RET_IP_);
 	return false;
 }
 
 void __kasan_slab_free_mempool(void *ptr, unsigned long ip);
-static __always_inline void kasan_slab_free_mempool(void *ptr, unsigned long ip)
+static __always_inline void kasan_slab_free_mempool(void *ptr)
 {
 	if (kasan_enabled())
-		__kasan_slab_free_mempool(ptr, ip);
+		__kasan_slab_free_mempool(ptr, _RET_IP_);
 }
 
 void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
@@ -237,10 +236,10 @@ static __always_inline void * __must_check kasan_krealloc(const void *object,
 }
 
 void __kasan_kfree_large(void *ptr, unsigned long ip);
-static __always_inline void kasan_kfree_large(void *ptr, unsigned long ip)
+static __always_inline void kasan_kfree_large(void *ptr)
 {
 	if (kasan_enabled())
-		__kasan_kfree_large(ptr, ip);
+		__kasan_kfree_large(ptr, _RET_IP_);
 }
 
 bool kasan_save_enable_multi_shot(void);
@@ -273,12 +272,11 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
 {
 	return (void *)object;
 }
-static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
-				   unsigned long ip)
+static inline bool kasan_slab_free(struct kmem_cache *s, void *object)
 {
 	return false;
 }
-static inline void kasan_slab_free_mempool(void *ptr, unsigned long ip) {}
+static inline void kasan_slab_free_mempool(void *ptr) {}
 static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
 				   gfp_t flags)
 {
@@ -298,7 +296,7 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
 {
 	return (void *)object;
 }
-static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
+static inline void kasan_kfree_large(void *ptr) {}
 
 #endif /* CONFIG_KASAN */
 
diff --git a/mm/mempool.c b/mm/mempool.c
index 624ed51b060f..79959fac27d7 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -104,7 +104,7 @@ static inline void poison_element(mempool_t *pool, void *element)
 static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
 {
 	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
-		kasan_slab_free_mempool(element, _RET_IP_);
+		kasan_slab_free_mempool(element);
 	else if (pool->alloc == mempool_alloc_pages)
 		kasan_free_pages(element, (unsigned long)pool->pool_data);
 }
diff --git a/mm/slab.c b/mm/slab.c
index d7c8da9319c7..afeb6191fb1e 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3421,7 +3421,7 @@ static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
 		memset(objp, 0, cachep->object_size);
 
 	/* Put the object into the quarantine, don't touch it for now. */
-	if (kasan_slab_free(cachep, objp, _RET_IP_))
+	if (kasan_slab_free(cachep, objp))
 		return;
 
 	/* Use KCSAN to help debug racy use-after-free. */
diff --git a/mm/slub.c b/mm/slub.c
index 75fb097d990d..0afb53488238 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1514,7 +1514,7 @@ static inline void *kmalloc_large_node_hook(void *ptr, size_t size, gfp_t flags)
 static __always_inline void kfree_hook(void *x)
 {
 	kmemleak_free(x);
-	kasan_kfree_large(x, _RET_IP_);
+	kasan_kfree_large(x);
 }
 
 static __always_inline bool slab_free_hook(struct kmem_cache *s, void *x)
@@ -1544,7 +1544,7 @@ static __always_inline bool slab_free_hook(struct kmem_cache *s, void *x)
 				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
 
 	/* KASAN might put x into memory quarantine, delaying its reuse */
-	return kasan_slab_free(s, x, _RET_IP_);
+	return kasan_slab_free(s, x);
 }
 
 static inline bool slab_free_freelist_hook(struct kmem_cache *s,
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5c1490eddf20b436b8c4eeea83fce47687d5e4a4.1610733117.git.andreyknvl%40google.com.
