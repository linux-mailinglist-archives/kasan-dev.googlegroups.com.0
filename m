Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF6UUL5QKGQEBUUYYCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id BBAFD272562
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 15:26:48 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id v128sf2463851lfa.5
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 06:26:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600694808; cv=pass;
        d=google.com; s=arc-20160816;
        b=h4x0UKYyEkPr+zh+8YvbAD96qokLITpQiUHOMSaUJlh5cTfj/xdVOxEnohi9GaUvMK
         Mq9HAroUNVuZ8ZTDB+RGd4PChsoOJAeEu/W3iAKDluRmXovsgMnOp78NoaJbf3yJJmul
         ITn6RBScO/mTmCe3k2Xxb4iPrl1vWGODB2DrrB83bIC5l1ssghKgWOcHTqb8H0ewtG0/
         IahxnClcBgSByBZzwthPzDx7ASpbyxIri8og7eMe5xRtYNeSlVC0Mn+t2YiGzhRPKAXm
         mjUW+AbRSX6hK1eNVweR2UkDB2wpkssefxHhGECtCxW1iPMDApRx+VUVZbpDrLO+g8Sy
         nDXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=tAho4EdkhHC3Vev+LvzQYb0HpXcJBDClOk2uqHMn1ek=;
        b=vQe2SnyoCwiTZeqZLQkXLmgOCmsHVK64zrqAlPqi/PvPRSv5IaXt3GYjmmGdWUczeb
         cCjyZXsTlVGLBABzcgLrYj8olLj8VfUQB/BG4cjCD4mH11MhuoJgrNbT7gx/MNTi5P34
         IaN59HaaDeESga4KsTBg/XvJSGbp/vliQ+Yg5+rjUB8/JpXvmgzjCY6toqR9y/V6gXm3
         Fnbg05cb/AendZ8s3wi2xNg7OsViYqapvesg81BIttqhSBOzH3Ade/ZtJgU7KitoxYqJ
         bLhdx6n4LPgBpSQcqyYhCx6YH/qKC5CS41yLxIZb1UYSOndElgHPb+vx4VRa2FRu7XG6
         y1fQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LQuPh8rZ;
       spf=pass (google.com: domain of 3fqpoxwukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3FqpoXwUKCQ8t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tAho4EdkhHC3Vev+LvzQYb0HpXcJBDClOk2uqHMn1ek=;
        b=g1vnqOBOKBTkkGOAzJumYCl0/BuFgOeX1GV2aNdUNrjbjKsyWJtSBuu+xG0qXWQV2E
         tHlGD3e22GdZtvEvIKcNmpvMQxChXRISD6HXhkx6Fyvu8lvmbFG4e9ZGw+gH6fZf9HGZ
         tK/lWFi91NHbf1SOkuQ2P1axsHJyK5SyuAskTbONx0zBr6fYbGhHwJSnoecBlROyVfPU
         pbRCI/HTOMMdhonWGMrGzdV54Lhfv3R7D6iWg57Lqc21+G+wCd0y22p3HMtEJzBLnVEG
         hZjCQVgb9aMld1z9+cTHo3ot6O2N0iKkJoOctOFlq3ew7k940ga//64KSaGpAgQYdwmh
         OdYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tAho4EdkhHC3Vev+LvzQYb0HpXcJBDClOk2uqHMn1ek=;
        b=snmI1mOdJ45HLxRBi4b3SlqlxX4idkYry2eh6wx0go9tPMmG4k3BWhXB6TDcnnxtAX
         sAZh271EuWyY4ADaPseCQ70hJFfJurK3SCBAzDiRfa4N9AmqigXqv/Zy+oak7985NTmq
         x11TBgM55FzG1zxrAEHiKI2P+ofxi+xAF6STtSLTFk+u+eEWH6mp8pmhdOvompqYZvGQ
         ctoJCdgiYzP5iPNwroV/aEje2OY7do7WyIStFTUx2Jvr6qfv00d+Dy3sOWHYJMsTX3nq
         GV9e3PoEzQXl3d2SALV0b7sGHTBL4P1yibmI9qPbwr3I0N0CAHQv2cvK9kvB+oYtrD33
         gWyA==
X-Gm-Message-State: AOAM530epvRyKnMLHR3sxIJaYdN6gJsi3nUPu95IvUZ2JmrXkzrwQCYX
	h5tPk/DT1sRAQ/pRfFvVBOA=
X-Google-Smtp-Source: ABdhPJwpewhCa/EbY1GYqx8HwaGGleTU2Uzw5CnhdfXnE1XqC2FlJrbZ+VL0HISWGYM+SpDLJimg3A==
X-Received: by 2002:a05:651c:50c:: with SMTP id o12mr17553286ljp.40.1600694808189;
        Mon, 21 Sep 2020 06:26:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:554:: with SMTP id 81ls158323lff.1.gmail; Mon, 21 Sep
 2020 06:26:47 -0700 (PDT)
X-Received: by 2002:a05:6512:1dd:: with SMTP id f29mr14431082lfp.311.1600694807007;
        Mon, 21 Sep 2020 06:26:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600694807; cv=none;
        d=google.com; s=arc-20160816;
        b=nyKqgO7LSt5CWOOp0bjStNIfCEGYaZM6V7QpbnpnmaQoivXdfZ/XOwNlla+YlHUmrR
         kJcuWZGuhbXKmMzcmaMvFm1WmXzZUkWkjpL6jvOGvU0HtS3l3lYk9K2zkwOp4X3QQ9sK
         7NfD19bJlKzRltzpfH5D7ot3ujOgk3WGPlC7dnyNy10ufx9/k+t7YfrUl2MWGkXUukfz
         kEzpUjvZCjuL/l4ipfcHCPaXXKDetZnBb2lEc8cngg+ijyFtx7m55tbx68Pd0ReieanJ
         dNR5VXm4mq5jO4w8FSSddu8fo/rIgZKMBcTmim/Iqcq2AGhlVRhgZF89gTsCHOwxhQZU
         4f4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=YUr1bmlWANV2b/dG0X2XD3v8dg8UYcKH+3szEZKa0xQ=;
        b=aXSUvsyBvh+42Wl0oTkfReV8QA3OlZTo6UiHehmdwzJVQqikd9iqQpbTutTFFX69/r
         JeK0plAWhytDGWJzvrTkf6Ag384T9Stb1A5aky+FGK0Fhp+ioLybYkqy4QDZ0fh75Tkk
         1JIHxx9UX87rEzc9WUuVydTppL+cY0ZIVp0eXH0j5UwGXGwXk74ilhabkqtIi5hibfTJ
         ZxltPhNCf50HcaLTSC+8wPwQR6Q5ecgxWM96Ed2sBY//OJVaL/x7ZPwQ6kiu78yktMOB
         pA0I97pSmFemmcckw+42YcVJaj/iH/mPCELL1Qk8O3nKM7VQ4gEkD0Msg47vy+opJLuA
         S0fg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LQuPh8rZ;
       spf=pass (google.com: domain of 3fqpoxwukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3FqpoXwUKCQ8t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id p25si382820lji.8.2020.09.21.06.26.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Sep 2020 06:26:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fqpoxwukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id y3so5856774wrl.21
        for <kasan-dev@googlegroups.com>; Mon, 21 Sep 2020 06:26:46 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a1c:59c2:: with SMTP id n185mr29928677wmb.43.1600694806274;
 Mon, 21 Sep 2020 06:26:46 -0700 (PDT)
Date: Mon, 21 Sep 2020 15:26:05 +0200
In-Reply-To: <20200921132611.1700350-1-elver@google.com>
Message-Id: <20200921132611.1700350-5-elver@google.com>
Mime-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 04/10] mm, kfence: insert KFENCE hooks for SLAB
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, keescook@chromium.org, mark.rutland@arm.com, 
	penberg@kernel.org, peterz@infradead.org, sjpark@amazon.com, 
	tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LQuPh8rZ;       spf=pass
 (google.com: domain of 3fqpoxwukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3FqpoXwUKCQ8t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

From: Alexander Potapenko <glider@google.com>

Inserts KFENCE hooks into the SLAB allocator.

To pass the originally requested size to KFENCE, add an argument
'orig_size' to slab_alloc*(). The additional argument is required to
preserve the requested original size for kmalloc() allocations, which
uses size classes (e.g. an allocation of 272 bytes will return an object
of size 512). Therefore, kmem_cache::size does not represent the
kmalloc-caller's requested size, and we must introduce the argument
'orig_size' to propagate the originally requested size to KFENCE.

Without the originally requested size, we would not be able to detect
out-of-bounds accesses for objects placed at the end of a KFENCE object
page if that object is not equal to the kmalloc-size class it was
bucketed into.

When KFENCE is disabled, there is no additional overhead, since
slab_alloc*() functions are __always_inline.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
v3:
* Rewrite patch description to clarify need for 'orig_size'
  [reported by Christopher Lameter].
---
 mm/slab.c        | 46 ++++++++++++++++++++++++++++++++++------------
 mm/slab_common.c |  6 +++++-
 2 files changed, 39 insertions(+), 13 deletions(-)

diff --git a/mm/slab.c b/mm/slab.c
index 3160dff6fd76..30aba06ae02b 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -100,6 +100,7 @@
 #include	<linux/seq_file.h>
 #include	<linux/notifier.h>
 #include	<linux/kallsyms.h>
+#include	<linux/kfence.h>
 #include	<linux/cpu.h>
 #include	<linux/sysctl.h>
 #include	<linux/module.h>
@@ -3206,7 +3207,7 @@ static void *____cache_alloc_node(struct kmem_cache *cachep, gfp_t flags,
 }
 
 static __always_inline void *
-slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
+slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid, size_t orig_size,
 		   unsigned long caller)
 {
 	unsigned long save_flags;
@@ -3219,6 +3220,10 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
 	if (unlikely(!cachep))
 		return NULL;
 
+	ptr = kfence_alloc(cachep, orig_size, flags);
+	if (unlikely(ptr))
+		goto out_hooks;
+
 	cache_alloc_debugcheck_before(cachep, flags);
 	local_irq_save(save_flags);
 
@@ -3251,6 +3256,7 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
 	if (unlikely(slab_want_init_on_alloc(flags, cachep)) && ptr)
 		memset(ptr, 0, cachep->object_size);
 
+out_hooks:
 	slab_post_alloc_hook(cachep, objcg, flags, 1, &ptr);
 	return ptr;
 }
@@ -3288,7 +3294,7 @@ __do_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
 #endif /* CONFIG_NUMA */
 
 static __always_inline void *
-slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
+slab_alloc(struct kmem_cache *cachep, gfp_t flags, size_t orig_size, unsigned long caller)
 {
 	unsigned long save_flags;
 	void *objp;
@@ -3299,6 +3305,10 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
 	if (unlikely(!cachep))
 		return NULL;
 
+	objp = kfence_alloc(cachep, orig_size, flags);
+	if (unlikely(objp))
+		goto leave;
+
 	cache_alloc_debugcheck_before(cachep, flags);
 	local_irq_save(save_flags);
 	objp = __do_cache_alloc(cachep, flags);
@@ -3309,6 +3319,7 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
 	if (unlikely(slab_want_init_on_alloc(flags, cachep)) && objp)
 		memset(objp, 0, cachep->object_size);
 
+leave:
 	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp);
 	return objp;
 }
@@ -3414,6 +3425,11 @@ static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
 static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
 					 unsigned long caller)
 {
+	if (kfence_free(objp)) {
+		kmemleak_free_recursive(objp, cachep->flags);
+		return;
+	}
+
 	/* Put the object into the quarantine, don't touch it for now. */
 	if (kasan_slab_free(cachep, objp, _RET_IP_))
 		return;
@@ -3479,7 +3495,7 @@ void ___cache_free(struct kmem_cache *cachep, void *objp,
  */
 void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
 {
-	void *ret = slab_alloc(cachep, flags, _RET_IP_);
+	void *ret = slab_alloc(cachep, flags, cachep->object_size, _RET_IP_);
 
 	trace_kmem_cache_alloc(_RET_IP_, ret,
 			       cachep->object_size, cachep->size, flags);
@@ -3512,7 +3528,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 
 	local_irq_disable();
 	for (i = 0; i < size; i++) {
-		void *objp = __do_cache_alloc(s, flags);
+		void *objp = kfence_alloc(s, s->object_size, flags) ?: __do_cache_alloc(s, flags);
 
 		if (unlikely(!objp))
 			goto error;
@@ -3545,7 +3561,7 @@ kmem_cache_alloc_trace(struct kmem_cache *cachep, gfp_t flags, size_t size)
 {
 	void *ret;
 
-	ret = slab_alloc(cachep, flags, _RET_IP_);
+	ret = slab_alloc(cachep, flags, size, _RET_IP_);
 
 	ret = kasan_kmalloc(cachep, ret, size, flags);
 	trace_kmalloc(_RET_IP_, ret,
@@ -3571,7 +3587,7 @@ EXPORT_SYMBOL(kmem_cache_alloc_trace);
  */
 void *kmem_cache_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid)
 {
-	void *ret = slab_alloc_node(cachep, flags, nodeid, _RET_IP_);
+	void *ret = slab_alloc_node(cachep, flags, nodeid, cachep->object_size, _RET_IP_);
 
 	trace_kmem_cache_alloc_node(_RET_IP_, ret,
 				    cachep->object_size, cachep->size,
@@ -3589,7 +3605,7 @@ void *kmem_cache_alloc_node_trace(struct kmem_cache *cachep,
 {
 	void *ret;
 
-	ret = slab_alloc_node(cachep, flags, nodeid, _RET_IP_);
+	ret = slab_alloc_node(cachep, flags, nodeid, size, _RET_IP_);
 
 	ret = kasan_kmalloc(cachep, ret, size, flags);
 	trace_kmalloc_node(_RET_IP_, ret,
@@ -3650,7 +3666,7 @@ static __always_inline void *__do_kmalloc(size_t size, gfp_t flags,
 	cachep = kmalloc_slab(size, flags);
 	if (unlikely(ZERO_OR_NULL_PTR(cachep)))
 		return cachep;
-	ret = slab_alloc(cachep, flags, caller);
+	ret = slab_alloc(cachep, flags, size, caller);
 
 	ret = kasan_kmalloc(cachep, ret, size, flags);
 	trace_kmalloc(caller, ret,
@@ -4138,18 +4154,24 @@ void __check_heap_object(const void *ptr, unsigned long n, struct page *page,
 			 bool to_user)
 {
 	struct kmem_cache *cachep;
-	unsigned int objnr;
+	unsigned int objnr = 0;
 	unsigned long offset;
+	bool is_kfence = is_kfence_address(ptr);
 
 	ptr = kasan_reset_tag(ptr);
 
 	/* Find and validate object. */
 	cachep = page->slab_cache;
-	objnr = obj_to_index(cachep, page, (void *)ptr);
-	BUG_ON(objnr >= cachep->num);
+	if (!is_kfence) {
+		objnr = obj_to_index(cachep, page, (void *)ptr);
+		BUG_ON(objnr >= cachep->num);
+	}
 
 	/* Find offset within object. */
-	offset = ptr - index_to_obj(cachep, page, objnr) - obj_offset(cachep);
+	if (is_kfence_address(ptr))
+		offset = ptr - kfence_object_start(ptr);
+	else
+		offset = ptr - index_to_obj(cachep, page, objnr) - obj_offset(cachep);
 
 	/* Allow address range falling entirely within usercopy region. */
 	if (offset >= cachep->useroffset &&
diff --git a/mm/slab_common.c b/mm/slab_common.c
index f9ccd5dc13f3..6e35e273681a 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -12,6 +12,7 @@
 #include <linux/memory.h>
 #include <linux/cache.h>
 #include <linux/compiler.h>
+#include <linux/kfence.h>
 #include <linux/module.h>
 #include <linux/cpu.h>
 #include <linux/uaccess.h>
@@ -448,6 +449,9 @@ static int shutdown_cache(struct kmem_cache *s)
 	/* free asan quarantined objects */
 	kasan_cache_shutdown(s);
 
+	if (!kfence_shutdown_cache(s))
+		return -EBUSY;
+
 	if (__kmem_cache_shutdown(s) != 0)
 		return -EBUSY;
 
@@ -1171,7 +1175,7 @@ size_t ksize(const void *objp)
 	if (unlikely(ZERO_OR_NULL_PTR(objp)) || !__kasan_check_read(objp, 1))
 		return 0;
 
-	size = __ksize(objp);
+	size = kfence_ksize(objp) ?: __ksize(objp);
 	/*
 	 * We assume that ksize callers could use whole allocated area,
 	 * so we need to unpoison this area.
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200921132611.1700350-5-elver%40google.com.
