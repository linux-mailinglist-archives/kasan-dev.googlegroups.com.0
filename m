Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJPOTWBAMGQEF5NIANY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 31272332701
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 14:24:54 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id m17sf431350wml.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 05:24:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615296294; cv=pass;
        d=google.com; s=arc-20160816;
        b=jGzCS5cYmNEaXlC37moo5RA4QCo5k1FY28xvjuBGzKD/2aF6Z42IViywXWdE6WgDhn
         rwz3fAFmuzVuUwnfSa5lzG465svF3vVZwtJbb1Cd+3M2Ee2Kt16fpaCnNoWmFiWcH6Ug
         97b9WLIgxeseyr9TgrJSIb9A4oAl+f6JJrn8W5bm8+4a2pSTo24+F2pkCrhGVWLaBjOQ
         uU29+vKguLnn6tdy3oUQN7oaN3uAvvYQdd4YOjLJ+SH8MbNvLl7KDDByoYjXrYidIr9a
         9ZAad5xDnLld/iufpKI7iuq+WesWYKe6ywsNToN3Bs9G8ONIBMUV088Pzx6czDHCgJZp
         d0kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=tU7aFYxeDLtwo1xPPwcL6olOXhAwtg0wUBHj6yjKf2Y=;
        b=E0PsVySvd5cXyZkLnX0ZamtHkD2xl0eE5SDpja5VbPiT6LBOvZmU2U9YM7CgDrw9GN
         OuCI+7/YFSb0uPu8FQ087ijnWzXoDTfMZxSLwYFzmM6W4Vpfpoa+QM44ChaCminEGyN/
         S8KWMCtKQZuQE0EtFiOeE43t73xMR3fk70ZNeayPfDVTKotTbG9j+XpOZfOUOb8VJYkb
         40hmH7pPh33fT07zjgj9kT+VzDqYEShqj7a7amY2NBLkEx5fk4B9hVyPpG63sHPEUKLJ
         9uKw2KsmomWcD1FMy1R3vdQFyZLzSwViIJERJlwfBwkn4ONZv6w7kFuPXRnx5JZj7TOV
         yFzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="LKXhZ/r7";
       spf=pass (google.com: domain of 3jhdhyaokctkviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3JHdHYAoKCTkViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tU7aFYxeDLtwo1xPPwcL6olOXhAwtg0wUBHj6yjKf2Y=;
        b=M2sbn4bx8ugOA1Lrl6xP3ym9sDtz4G6RP35zbxw9HUnOJ0frLwEFkLSz1QrGqhRrhW
         gpyOVwe4mTBOx4aZfMwyqetyPSclKm9iVV5SGj3rue+frFOMUpuOUsA7wg8JUhAocgLU
         bvvkCrr95Mt9+7zFLja4M3v5G61oiLh8L7yVDndAczWaNjVT9hbuG1mnV1gsLTxmtuHX
         HGgHW1YIBTVrC2mHAvsJkogEevj053QjCGraqkl7nbvSEoqMUJ+WM7tXR46Q6kL8ulhN
         qGGHF8wp1jdfJjHH0cN+cn6orDpmE6vfL5H9BjT42gm97m3DthWjIuMgtRtGmUdiB4n9
         vHsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tU7aFYxeDLtwo1xPPwcL6olOXhAwtg0wUBHj6yjKf2Y=;
        b=HwAbjOLI/ZbNzyDmuf7VtL07jZfjTemb+FRyIb+Pdvyr4YNP3dmM749o1vIz5VTuMS
         nXBzxHdWSEbZGjmbsRLsDg3I8c9phyUAv8yFRllT1rAhwiBDj97uTEiZHuZA49agUjDa
         vWGLHoEPJ7tRm5Y3kuf6cBLQOqjP15JN+WR54aCLDoliTfn/uMS7vmfBw6q9PoBpcOpG
         qA1A7PHo2mP8cpPYet05HA+V2wSsb80xH0p+95xdLj3HFb2m/u7ktOYvnMLzFWkcqkjZ
         hwUPlMOsLo5wPM7VL2fvt+RG1GerwHqWQbf62KqUUNf9SuKwNhBnAtGdU4PLhJzcCyOE
         mhDw==
X-Gm-Message-State: AOAM533SJ/IgNPntamp0S28EVzXPF1x5fMnC+gZYhlrBTgJkxd/9Kpw2
	p2w/j2XwamMlxnih2FCZfds=
X-Google-Smtp-Source: ABdhPJzuplYBLPA20AOmf3UG1QlXQD4jF88dGJKq+CGba1Owk/XqkojuQySpKtCpGEVx7El1w0IRFA==
X-Received: by 2002:a1c:9817:: with SMTP id a23mr3957920wme.57.1615296293931;
        Tue, 09 Mar 2021 05:24:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1981:: with SMTP id 123ls1459883wmz.3.gmail; Tue, 09 Mar
 2021 05:24:53 -0800 (PST)
X-Received: by 2002:a1c:1dd4:: with SMTP id d203mr3964935wmd.83.1615296293108;
        Tue, 09 Mar 2021 05:24:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615296293; cv=none;
        d=google.com; s=arc-20160816;
        b=PvyBYoRa1y8L5DYfh11tbVGD4Xz2eJ7NqTDqBHEDxW+d3JpRm75oprLQmSqwVc2Dkf
         8G+R5E97kPwCLh5mcc9CTTmLP0A2PHJ5imp4jhzSIYPWwtvwf4Y42LenLmLdzfSNzai8
         aQPP0lvBXlJ7t8QvczcTprK3OiusdyEAyNoCeMXOB7w5QGVaKmhXiwOTs1ozdG8xVt1T
         YiGBHitAaY8JMTmYY63bw9RXNSlnQFF6m89m6DaXRCkZQIhqf4/b0txRZCpovCNAxPmX
         WnPoM5ikblOhyDjj7nmrhbJmW31liI0AVAXVOaRlFx0Is9OVCUHQ1fYyGQpLjFr29PI8
         Iuxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=uDCq4UxGr+f+5TaIXWTYNeAihwfp2JNx0hDszCVrvYs=;
        b=w+NcKELRhkI2r84scmxPWi3pO/iuBXVf0ZgA1SPpxuna9aFjOwMT0rYEaklsZUPJiW
         LnKrjz0+iSd0azJvLy2qhTuYbqQHdRf5xPlYYc6/YfILa/uoCS0KiuNXCJra4yG9xmhz
         csw+4bVc49FOMO9llbdml2JYUrC5q5cgib2pQbgjpSC/cCwBw90owiMO4bp2bxjA37mo
         fX8AfUhBGuWVAHKY7qgtw2J9ygfkJdKIWqMVY4Znz/IJVb12Iol0z4yUo406sssDTy6+
         r+iw4u/+I5WQFI2VXG8y9dsPOsZKAOKast3MdFQWTuOUmwYiuT48mPCEdBwuTVNI/bWH
         AY/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="LKXhZ/r7";
       spf=pass (google.com: domain of 3jhdhyaokctkviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3JHdHYAoKCTkViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id t124si91746wmb.3.2021.03.09.05.24.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Mar 2021 05:24:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jhdhyaokctkviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id v13so6422263wrs.21
        for <kasan-dev@googlegroups.com>; Tue, 09 Mar 2021 05:24:53 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:5802:818:ce92:dfef])
 (user=andreyknvl job=sendgmr) by 2002:adf:bc01:: with SMTP id
 s1mr28458737wrg.240.1615296292758; Tue, 09 Mar 2021 05:24:52 -0800 (PST)
Date: Tue,  9 Mar 2021 14:24:38 +0100
In-Reply-To: <cover.1615296150.git.andreyknvl@google.com>
Message-Id: <c1292aeb5d519da221ec74a0684a949b027d7720.1615296150.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1615296150.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH v3 4/5] kasan, mm: integrate slab init_on_alloc with HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="LKXhZ/r7";       spf=pass
 (google.com: domain of 3jhdhyaokctkviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3JHdHYAoKCTkViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
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

Reviewed-by: Marco Elver <elver@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c1292aeb5d519da221ec74a0684a949b027d7720.1615296150.git.andreyknvl%40google.com.
