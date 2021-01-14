Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXN2QKAAMGQECNHUYLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 40EF32F6B21
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:37:02 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id a2sf10293361iod.13
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:37:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610653021; cv=pass;
        d=google.com; s=arc-20160816;
        b=fO2y9NBFbEjEeiw84R9ne0mA80QXeeEsObJcpwps+9gLEnPWeog6S+6QOSS1xiSgSE
         SGXZxSw4ow1NZxnWG3+kW9uDIP8ED21q0ugusodIdSafbZlaL75tVz00eeq/7JRAHfFq
         LvdnCP00bd4DPe+z7YBWIB3TtWcZY2p31zHvzkLmGHztXpH/F03q+bPpRSn6Ouj6pwe2
         XKa278L5gse4JReTjCcTQ1fQxjouM+Y4W2lWcsZIW6TlqCVqxO4I6FksTJjMffF9vCER
         nfMKMUymmt1GyE4seyUvJKVUhGjd8EjqwZ9aoIwHxluQmaUl6dr/R3viLBv05jHTnFp0
         gpbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=BfRdZ9RfMB98yAMIRvaXgnSnsiGhzQ0Ejp7A3K+gtm4=;
        b=gBeABLojdzUeiqRN1oV+RVN67Y4wGQMLH5/UU5JBO6xRlkResjmRpb6DqTJ+PLAcJG
         KRE9Dn1ToPzHGNSK7d0gJ7ekFXapjRWRRDoEbBRgAAEGgGHuWjPYiBeCERaw9+lM6fwt
         pa0Av4/DwVEeUvOtvGDxTt0k3NvWGBWQR7RSkr56biGRBHOkhS75NQUvSGolGMA7SOJp
         VLoyQeSv7T6Dd7UFBSamkHMF1pbAdwXUhQb6mA/SE/hUeoWbzNoUM/xE/hlMt2n2BqHD
         xZyiyOIeVwEczkjy4jx+izZt1DCDeNAkDPtbxNbRc3GzO9eUdTcs4Xrc1RdkDs2/FlEP
         mf6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fSQSLNHo;
       spf=pass (google.com: domain of 3xj0ayaokcz89mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3XJ0AYAoKCZ89MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BfRdZ9RfMB98yAMIRvaXgnSnsiGhzQ0Ejp7A3K+gtm4=;
        b=daTrDNmLQlfQJWcSlzcftct2BPtMpDaXVyTfau2sOQpo+azPmDPVi8HCc9q8vQVsFU
         5RpaNU361LHwhX1MH8Zdrm2sLlcnyJnfg7J3w9Ki+Fii40fZlnHAXT2zSmyaoeqXUXKR
         mvvjHWiGKsiQK1MMwoB3ShLoNrvpB8wPaXIJ4h+vdKfXsPHlns4BcvEEtVEwiYJJkUaQ
         zivpd1m6rdhYTLwWd08r1bVjnxmmfASFXfePeG4ygd1ts0WQo0H/EO8JZyElrYixVmMK
         UMYvDWAxIAz87a/Y4dyUK+ATnrKv7PM57DOWUFyUjqnHyOj9YQ83qR2SOo0cKU8O+uzq
         8fag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BfRdZ9RfMB98yAMIRvaXgnSnsiGhzQ0Ejp7A3K+gtm4=;
        b=DbvdcMpNc8sFovOkZ0tMIVFl3RXqrNC6BoJ3kOFi46X76/a7HIFMtq9Dkg4vWAB5V2
         Vf08IceC2z9m5VhGw/gdsH+SpNbo9k/ixXWcBMFOLi40912/HlSzK89kEn00D9XsFfYv
         aLw7vWnDZ7BQPRCOdikm8nbnwP2AOnKCTMZhCBGkYOg2bkeyw28nAfz8l6NVDxM/+wn3
         gng+b0nqCznk5CyepMhd2fYdVMTgaWtV6WeR9U47p3I92/uFMT7sZgcKNS9KlWTWKqyC
         K5dYdCHzBVwap7rU0tEydF/Hy432kpE6aCW7ItwXFIYQL0j503Xbln7NnCLA6h/epuZr
         NK8g==
X-Gm-Message-State: AOAM531GFxvfRpzcsnNOA/dlauwHf+j66wg4t/nGEKZf6trqTZgkLR7R
	NlaLdNWK5Ra8jQpZZUAnIjY=
X-Google-Smtp-Source: ABdhPJwASPxNtrWC2LhuyEDroGkdL4qHOR1cq0kyvnCHIyUu/P9F0caudfyZz8iNQEXvv14RdzIedQ==
X-Received: by 2002:a02:cf30:: with SMTP id s16mr7571231jar.144.1610653021209;
        Thu, 14 Jan 2021 11:37:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:97d8:: with SMTP id k24ls1033866ios.6.gmail; Thu, 14 Jan
 2021 11:37:00 -0800 (PST)
X-Received: by 2002:a5e:c00e:: with SMTP id u14mr6223590iol.194.1610653020698;
        Thu, 14 Jan 2021 11:37:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610653020; cv=none;
        d=google.com; s=arc-20160816;
        b=dJ5csXmPNaHF+CdEOy1xIO711EZWKYGGSnZVCFrwbLmQ16L0Xsh3zmlJ5Y+X5UpQd1
         GBHuniY4Axz/Fn4xNHfoce+QEv51lNOdOe2YuPee0wP0yvsCg5eBOo5290ASoqcW4Gm1
         z+VWJsOA1su8XPqDALGqpVV6Hx0Ezl4lRzp0DDEGd7CTkj1zHa8Xa48I0pEJcnNe/mpL
         Jrs/gwV4uzQ5J2CVU3HaXsjxV6QHhmTmauQSjKxWY6+KeDPIGyxZUIdY37rzMDN5GHcf
         Tx0scJctDFLbCpK4LgY2ytYnfwDSiOHeP6y3dYLBqZT9Sbc/zR3tCW6fgFwkvxB7qqrJ
         MfCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=40xb9lbPD7zjMi02902hc3827F2UNMsjtXT9ahxodwY=;
        b=tR0iws7klWE1mo1j0qWtIJ8Of6qem9wqqeRC5UVfj1tUnjRN6C2CoOSiNk5b1bDxfq
         MFs4+molSIVPEKvSW67CcH62qZ2goOXas2/9S+de3yfTXm/iSz0uF4i8mfKy2mqbX6TZ
         MAeARz2D4AoYFD27VdmkRgs+GCEb+16LW24e9i68m241t0ly36V4ejg+Yz1kJeFoLE5H
         XV9zfh7vZZcPPllcLZEFA6CsYmIr+PpFouZLSJYFFoiXzaZqeI4pfviK052dEAIu6BJv
         xSZD2Cu3uD9MVP1GFzQnuZhpEubBgT8z1DjWmITI/aD9sqUVA1ur3TbWLtF976+ZK4U+
         +1gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fSQSLNHo;
       spf=pass (google.com: domain of 3xj0ayaokcz89mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3XJ0AYAoKCZ89MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id b8si822843ile.1.2021.01.14.11.37.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:37:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xj0ayaokcz89mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id l6so5334378qtr.9
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:37:00 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:99c8:: with SMTP id
 y8mr8427012qve.35.1610653020179; Thu, 14 Jan 2021 11:37:00 -0800 (PST)
Date: Thu, 14 Jan 2021 20:36:27 +0100
In-Reply-To: <cover.1610652890.git.andreyknvl@google.com>
Message-Id: <03fae8b66a7f4b85abadc80a2d216ac4db815444.1610652890.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v3 11/15] kasan: move _RET_IP_ to inline wrappers
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
 header.i=@google.com header.s=20161025 header.b=fSQSLNHo;       spf=pass
 (google.com: domain of 3xj0ayaokcz89mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3XJ0AYAoKCZ89MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/03fae8b66a7f4b85abadc80a2d216ac4db815444.1610652890.git.andreyknvl%40google.com.
