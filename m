Return-Path: <kasan-dev+bncBDX4HWEMTEBRB5ERTGBAMGQEW2JOIUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 926243312A3
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 16:55:32 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id x9sf4967840wro.9
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 07:55:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615218932; cv=pass;
        d=google.com; s=arc-20160816;
        b=A7xaB2DGJlt/9hDkNYEO7BuCfw6kGk5gLVsQKP+KGeA5RA3694cfhsMmlmvDFdo/PO
         hRMudAsnjj+wvwXqJZgSSA0FqGov8cNlfzYaAli3lvyLSokEXTccgRlC4CTvzdKFRxbo
         /nkr1IvVUR4lpkGNR6nJGtnEbcz//XdRw9AnlEjBdVC1GAuR2/W7e500Cm6Gfnl7vhM9
         gQgMDwAN/hoB3eToCw15zvMZq8cPdF1BjqbXegUuZSwi9nyI7jjocHyvJSzXn7Dm4s1D
         H8s4qm0QZBasrYmSD2Kt0PY2+hCNfMVvqjw6zRFcBcDhErjQobfASuDIc5TljvXUm/GF
         e4BA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=wnj29isaxbsfmjf71VXXTskoZ/rfn3xpGTWW6uzKbKQ=;
        b=Keld4GFeBCRezAbO4qYgTJj7d/Nj3Y78Y4DIy8t3aS5GoTMqwB/PTUch0ZHZBxCQhJ
         aj3YIVZ2LtuB4U3izJAhO6eGgwsc1tORVyIcWQY/uQ72JDDDYnLQIeWrUhu1e6fqWhdL
         mewIngdJUNH9fNFr8Q8Dt6/C+SucU1Hy0KQVc+xqVddxdAAc8clSx0Xc81bGhUVK+CHE
         SBrkhx5zbNNPztX20YJX0wwMKzJ3FcIsOvj9GQhDsoFR88GxKJzCs0lemEYC1E2GgVkz
         QTy3wgUxTZZSBwCBG8zXgsuNMzQBtwJkKppSmqyZcQo023Hftrrp0Y/anbQI/7U2SCre
         0EfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p0fnPCb6;
       spf=pass (google.com: domain of 380hgyaokcaygtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=380hGYAoKCaYGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wnj29isaxbsfmjf71VXXTskoZ/rfn3xpGTWW6uzKbKQ=;
        b=oHhyUXx6SYGrQZfWgh1NHYPoQ6c9JMf+iQ5wevRUtGXUeO+UmrmGAP3wEDBTs9KcgR
         fbPQKZSLBjNcpizvcIjT1we7s4JfEZrr6rIFfJLottUewziKfujRclE2qLgq1l67qDWF
         1EvaIOvluYOHvicmWgRr1xYUFdZV0tjSPZaJQwZYgi6mbuL82NAa4w+kCM4JdAgbcV3H
         +cWScdcEQ4eey8aGiupGTpaLXOviVvJtb5WchRPmGVCWHd5t7ZJK59h7f1Q609CLNGot
         KrZWDKsMJGiirA6nznO4JMGhq8iPKhXyQIB5LkkC3Mxmh3CBlvZ35D1+I0XWKSEHAr4r
         p5zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wnj29isaxbsfmjf71VXXTskoZ/rfn3xpGTWW6uzKbKQ=;
        b=LFjrN2q9Dru7PDBNU41eCcID4JyJrzLx88CxBd8be3/FhGysx5dSyA/x7fzB4chj1B
         c7JNG6RI42Oim5YfNoriO6f2RaPxlOVjwNJad3oHb3EhLfdWB0Fvt5Vf0CTdO9Z1u8K5
         R6z6XjDmG6ZyK5q3VzhXEGym9Emk9gAfJN2OT1j0aB/PZXlGdu8p+NQ8SoUOzDf7eGFB
         i87ys4PCbZpLVpbhMOL5PUTqm9Bn72m4ucQvW3/p6qXQu1O91Ezco32YW/fgKc20BTl2
         6TSmgxk6EECKjujnLlEMuuqtgjBdYBwlJ5oWLgeXnol0F0JYTJLO3l4aX5mYqmwoze67
         OTFg==
X-Gm-Message-State: AOAM531g10AZC1F1VW0KX54HWISaDK1GAxe2pZy41PUYiaLlHrNn8SVO
	Lkap4WOl03n6YsqoXvpIyBM=
X-Google-Smtp-Source: ABdhPJw5QG9YQ3HV4rfQKUWZ2SIj8FxAey+6N8mI2c9EOhw3b2/fYHrxquHHR960D+OWR+aKbbQn4A==
X-Received: by 2002:a5d:5105:: with SMTP id s5mr24555317wrt.140.1615218932412;
        Mon, 08 Mar 2021 07:55:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1981:: with SMTP id 123ls8771595wmz.3.gmail; Mon, 08 Mar
 2021 07:55:31 -0800 (PST)
X-Received: by 2002:a05:600c:1992:: with SMTP id t18mr2633806wmq.125.1615218931604;
        Mon, 08 Mar 2021 07:55:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615218931; cv=none;
        d=google.com; s=arc-20160816;
        b=HsdZ/y24LhPt+JWg4SubgpiQZ8qkOs2Bx3zzkQve1awWduqw9yzGCbMV7eWvnpprat
         EdXKFm4dsmjVWPRLQiOsT1CtBVR/BAs9Ln9htr0qca+XEiVyx9f2GGrU9JckeULBs2m7
         kc8dFrqVfcqpcrH/CejP8oGcEvPyHKiPCIeDJhA+/CaMsf1EQpAkn1f7ybucfFwTCgFe
         1WF2Ho06Z/jKtmpjmTmzM5h+ywG6r7UjGm+9fHe9CahfLayEUUy65fEDPwrJBfvG3FX7
         vjXpRZXcQHObyFmFsLUw8PqW4tYaftiMJELPiBAow+b+pLdnCGio6+37wCrrkN89S3xb
         0tLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=cj8pJM6lbqCmIdH87Nb+h0eI2YGmNtFfaVebFrb26/U=;
        b=Xv+vcgnIS/VJXnU74PQDO7FzLYM1paHzUJZ/LJnY0BQZWUBto9EtXfHMOacWixf6+2
         RtyPovq5hP8nGLyqu6C4eiObM8Wa+IdUChuvdOUxNSY1p2KV7Bpy7ftiVxMPs7sotfQZ
         iOSUEyLpByf3XsConMxU3v3Q2o+wVJ9UvMPNRjOKq0JhWRZl890UqBzfBAYxsXbEF2ZB
         6dw8VbJ/Ny0NGW5CX3bPgdrQy0y+EaV1KCI9FrYsFm/VPq8oEC1982gNBUTfp3NHPcI7
         87C0JyfWQzmuprjDVuAe+lGjIxE7D7MlU+nKtCF77qEgQyySWdk1zuU48aKI/JtA/qlZ
         m5TA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p0fnPCb6;
       spf=pass (google.com: domain of 380hgyaokcaygtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=380hGYAoKCaYGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id v16si9922wmh.1.2021.03.08.07.55.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 07:55:31 -0800 (PST)
Received-SPF: pass (google.com: domain of 380hgyaokcaygtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id mj6so4275769ejb.11
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 07:55:31 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:85fb:aac9:69ed:e574])
 (user=andreyknvl job=sendgmr) by 2002:aa7:c916:: with SMTP id
 b22mr23222244edt.299.1615218931206; Mon, 08 Mar 2021 07:55:31 -0800 (PST)
Date: Mon,  8 Mar 2021 16:55:17 +0100
In-Reply-To: <cover.1615218180.git.andreyknvl@google.com>
Message-Id: <027a5988eb8de20cee1595e65a754072fdfcdb1c.1615218180.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1615218180.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH v2 4/5] kasan, mm: integrate slab init_on_alloc with HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=p0fnPCb6;       spf=pass
 (google.com: domain of 380hgyaokcaygtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=380hGYAoKCaYGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
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

This change uses the previously added memory initialization feature
of HW_TAGS KASAN routines for slab memory when init_on_alloc is enabled.

With this change, memory initialization memset() is no longer called
when both HW_TAGS KASAN and init_on_alloc are enabled. Instead, memory
is initialized in KASAN runtime.

The memory initialization memset() is moved into slab_post_alloc_hook()
that currently directly follows the initialization loop. A new argument
is added to slab_post_alloc_hook() that indicates whether to initialize
the memory or not.

To avoid discrepancies with which memory gets initialized that can be
caused by future changes, both KASAN hook and initialization memset()
are put together and a warning comment is added.

Combining setting allocation tags with memory initialization improves
HW_TAGS KASAN performance when init_on_alloc is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h |  8 ++++----
 mm/kasan/common.c     |  4 ++--
 mm/slab.c             | 28 +++++++++++++---------------
 mm/slab.h             | 17 +++++++++++++----
 mm/slub.c             | 27 +++++++++++----------------
 5 files changed, 43 insertions(+), 41 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index c89613caa8cf..85f2a8786606 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -226,12 +226,12 @@ static __always_inline void kasan_slab_free_mempool(void *ptr)
 }
 
 void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
-				       void *object, gfp_t flags);
+				       void *object, gfp_t flags, bool init);
 static __always_inline void * __must_check kasan_slab_alloc(
-				struct kmem_cache *s, void *object, gfp_t flags)
+		struct kmem_cache *s, void *object, gfp_t flags, bool init)
 {
 	if (kasan_enabled())
-		return __kasan_slab_alloc(s, object, flags);
+		return __kasan_slab_alloc(s, object, flags, init);
 	return object;
 }
 
@@ -320,7 +320,7 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object)
 static inline void kasan_kfree_large(void *ptr) {}
 static inline void kasan_slab_free_mempool(void *ptr) {}
 static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
-				   gfp_t flags)
+				   gfp_t flags, bool init)
 {
 	return object;
 }
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6107c795611f..7ea747b18c26 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -428,7 +428,7 @@ static void set_alloc_info(struct kmem_cache *cache, void *object,
 }
 
 void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
-					void *object, gfp_t flags)
+					void *object, gfp_t flags, bool init)
 {
 	u8 tag;
 	void *tagged_object;
@@ -453,7 +453,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 	 * Unpoison the whole object.
 	 * For kmalloc() allocations, kasan_kmalloc() will do precise poisoning.
 	 */
-	kasan_unpoison(tagged_object, cache->object_size, false);
+	kasan_unpoison(tagged_object, cache->object_size, init);
 
 	/* Save alloc info (if possible) for non-kmalloc() allocations. */
 	if (kasan_stack_collection_enabled())
diff --git a/mm/slab.c b/mm/slab.c
index 51fd424e0d6d..936dd686dec9 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3216,6 +3216,7 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid, size_t orig_
 	void *ptr;
 	int slab_node = numa_mem_id();
 	struct obj_cgroup *objcg = NULL;
+	bool init = false;
 
 	flags &= gfp_allowed_mask;
 	cachep = slab_pre_alloc_hook(cachep, &objcg, 1, flags);
@@ -3254,12 +3255,10 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid, size_t orig_
   out:
 	local_irq_restore(save_flags);
 	ptr = cache_alloc_debugcheck_after(cachep, flags, ptr, caller);
-
-	if (unlikely(slab_want_init_on_alloc(flags, cachep)) && ptr)
-		memset(ptr, 0, cachep->object_size);
+	init = slab_want_init_on_alloc(flags, cachep);
 
 out_hooks:
-	slab_post_alloc_hook(cachep, objcg, flags, 1, &ptr);
+	slab_post_alloc_hook(cachep, objcg, flags, 1, &ptr, init);
 	return ptr;
 }
 
@@ -3301,6 +3300,7 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, size_t orig_size, unsigned lo
 	unsigned long save_flags;
 	void *objp;
 	struct obj_cgroup *objcg = NULL;
+	bool init = false;
 
 	flags &= gfp_allowed_mask;
 	cachep = slab_pre_alloc_hook(cachep, &objcg, 1, flags);
@@ -3317,12 +3317,10 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, size_t orig_size, unsigned lo
 	local_irq_restore(save_flags);
 	objp = cache_alloc_debugcheck_after(cachep, flags, objp, caller);
 	prefetchw(objp);
-
-	if (unlikely(slab_want_init_on_alloc(flags, cachep)) && objp)
-		memset(objp, 0, cachep->object_size);
+	init = slab_want_init_on_alloc(flags, cachep);
 
 out:
-	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp);
+	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init);
 	return objp;
 }
 
@@ -3542,18 +3540,18 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 
 	cache_alloc_debugcheck_after_bulk(s, flags, size, p, _RET_IP_);
 
-	/* Clear memory outside IRQ disabled section */
-	if (unlikely(slab_want_init_on_alloc(flags, s)))
-		for (i = 0; i < size; i++)
-			memset(p[i], 0, s->object_size);
-
-	slab_post_alloc_hook(s, objcg, flags, size, p);
+	/*
+	 * memcg and kmem_cache debug support and memory initialization.
+	 * Done outside of the IRQ disabled section.
+	 */
+	slab_post_alloc_hook(s, objcg, flags, size, p,
+				slab_want_init_on_alloc(flags, s));
 	/* FIXME: Trace call missing. Christoph would like a bulk variant */
 	return size;
 error:
 	local_irq_enable();
 	cache_alloc_debugcheck_after_bulk(s, flags, i, p, _RET_IP_);
-	slab_post_alloc_hook(s, objcg, flags, i, p);
+	slab_post_alloc_hook(s, objcg, flags, i, p, false);
 	__kmem_cache_free_bulk(s, i, p);
 	return 0;
 }
diff --git a/mm/slab.h b/mm/slab.h
index 076582f58f68..c6f0e55a674a 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -506,15 +506,24 @@ static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
 }
 
 static inline void slab_post_alloc_hook(struct kmem_cache *s,
-					struct obj_cgroup *objcg,
-					gfp_t flags, size_t size, void **p)
+					struct obj_cgroup *objcg, gfp_t flags,
+					size_t size, void **p, bool init)
 {
 	size_t i;
 
 	flags &= gfp_allowed_mask;
+
+	/*
+	 * As memory initialization might be integrated into KASAN,
+	 * kasan_slab_alloc and initialization memset must be
+	 * kept together to avoid discrepancies in behavior.
+	 *
+	 * As p[i] might get tagged, memset and kmemleak hook come after KASAN.
+	 */
 	for (i = 0; i < size; i++) {
-		p[i] = kasan_slab_alloc(s, p[i], flags);
-		/* As p[i] might get tagged, call kmemleak hook after KASAN. */
+		p[i] = kasan_slab_alloc(s, p[i], flags, init);
+		if (p[i] && init && !kasan_has_integrated_init())
+			memset(p[i], 0, s->object_size);
 		kmemleak_alloc_recursive(p[i], s->object_size, 1,
 					 s->flags, flags);
 	}
diff --git a/mm/slub.c b/mm/slub.c
index e26c274b4657..f53df23760e3 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2822,6 +2822,7 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
 	struct page *page;
 	unsigned long tid;
 	struct obj_cgroup *objcg = NULL;
+	bool init = false;
 
 	s = slab_pre_alloc_hook(s, &objcg, 1, gfpflags);
 	if (!s)
@@ -2899,12 +2900,10 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
 	}
 
 	maybe_wipe_obj_freeptr(s, object);
-
-	if (unlikely(slab_want_init_on_alloc(gfpflags, s)) && object)
-		memset(kasan_reset_tag(object), 0, s->object_size);
+	init = slab_want_init_on_alloc(gfpflags, s);
 
 out:
-	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object);
+	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init);
 
 	return object;
 }
@@ -3356,20 +3355,16 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	c->tid = next_tid(c->tid);
 	local_irq_enable();
 
-	/* Clear memory outside IRQ disabled fastpath loop */
-	if (unlikely(slab_want_init_on_alloc(flags, s))) {
-		int j;
-
-		for (j = 0; j < i; j++)
-			memset(kasan_reset_tag(p[j]), 0, s->object_size);
-	}
-
-	/* memcg and kmem_cache debug support */
-	slab_post_alloc_hook(s, objcg, flags, size, p);
+	/*
+	 * memcg and kmem_cache debug support and memory initialization.
+	 * Done outside of the IRQ disabled fastpath loop.
+	 */
+	slab_post_alloc_hook(s, objcg, flags, size, p,
+				slab_want_init_on_alloc(flags, s));
 	return i;
 error:
 	local_irq_enable();
-	slab_post_alloc_hook(s, objcg, flags, i, p);
+	slab_post_alloc_hook(s, objcg, flags, i, p, false);
 	__kmem_cache_free_bulk(s, i, p);
 	return 0;
 }
@@ -3579,7 +3574,7 @@ static void early_kmem_cache_node_alloc(int node)
 	init_object(kmem_cache_node, n, SLUB_RED_ACTIVE);
 	init_tracking(kmem_cache_node, n);
 #endif
-	n = kasan_slab_alloc(kmem_cache_node, n, GFP_KERNEL);
+	n = kasan_slab_alloc(kmem_cache_node, n, GFP_KERNEL, false);
 	page->freelist = get_freepointer(kmem_cache_node, n);
 	page->inuse = 1;
 	page->frozen = 0;
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/027a5988eb8de20cee1595e65a754072fdfcdb1c.1615218180.git.andreyknvl%40google.com.
