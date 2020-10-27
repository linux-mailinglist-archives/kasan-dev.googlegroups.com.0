Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUOX4D6AKGQE2YL5KXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id BE68729B021
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 15:16:50 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id v7sf412990ots.19
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 07:16:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603808209; cv=pass;
        d=google.com; s=arc-20160816;
        b=rpOl6UQZI5FO5Ea5lpNACA82bc0WlWyJTkr6jrO2ZSAn1umrrUJkLQNEhzLz8p7BcL
         cB0EsETcIKny9zt0KkxKLAbeslvgJvJlU03jz6nnRbe1+aDQ8dwh77ROHcPMBS5urDqp
         yDqlCZAIrv64knj19rQbQfJpkfVNRBT1nIhHT8Jw9UiLNbal5ZPumTLzARPVyUZdEQgV
         2ZiYS2Terdh4lvcXs/TNwvxdqY27BbO9c/5s58pt5e6CK17DWdGq3p0dXs/CHKMUBW0O
         Zf1myWK++qd2ADvBYE01zdp2CiPHGehr8cxyA3XHPJw1pFPBGs45PAXDNIWGEQZmCLMR
         J26A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=hJOG/OMbR6vSzc4ppZtZmws0AjSudZiTkSTdqaV3qQY=;
        b=ixaWjb8Vza0hFqeTnN7JWFNbdGTrKOT3pkO4HTUHynxzcy7oVq9Q4PhhQcfnkVXmOd
         WihvBJlZB8qAWcSVn35W9wRwOQPT1Dam60FBOdfB4NNd9lTOUKgDlcpS4NuBD9AzrOJN
         0t6QgwPxuYCxkfq1MgYCVOJIOISomTfZVSDnCsEmpDUlLOuSKvOwSe6eyOfi/PYuwpF4
         06bQI7GaWZaD9/fvCyqoG4Yp5+i9JsZbEJnTfjDcBUkaHG9GrWloQcej5hZLYk9pSKah
         VcXoCAGXZXFQRwrx9+M4uf+NifaF6kdshbuPd34Da358MdHIAWtJ+ZoaNwbz2tiuE+l8
         Drdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vqOuO8aD;
       spf=pass (google.com: domain of 30cuyxwukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=30CuYXwUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hJOG/OMbR6vSzc4ppZtZmws0AjSudZiTkSTdqaV3qQY=;
        b=RGYtVPyLpvbHf5NqReVZlHMH3XQ1UJr4VN7C5hJNzyiPaqXUFH3GqhSvf9kknNz8RQ
         kbvT3wrd/BDaUQlG1lWJdtNTOcVBS2AxHqejPDd0rEk5pHIM1WsGtUStTYtlczXDM+bP
         MJ3v2cfC4LVGtMcASxb4i3Dl0IW5hVcLWr6H2X1+FMQ6Upj+6XzDWL33ySF0WgEPvfPH
         UhkdBRWACg+BYIcJInwihBOp5fcYLVrK8mjuiLY1ASaE9p+E+FW1+LSqw48QSCZk3a9G
         0WUmeBAfY6vgadrdoH3rkYIgr7jo+WY7tTDmxZ3+xRTAi6WKJimTgJzVQs/+RV41Y4iu
         aSUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hJOG/OMbR6vSzc4ppZtZmws0AjSudZiTkSTdqaV3qQY=;
        b=QBCahZU0bOYtvYSvSIawUKX/LLBaj+Hi0/4EPQfv1eMEHeBAKDTPmkwCbiG4LpTuf8
         D+BqtE6pf3/bvJ6JtoPHmgLDBwQXin2qstK61xSU4+F4/sp2yF9rl1eDy6HzgEf5dWSI
         LBQv1waYTS0qqh5XHO2Xk0QX7sL9tjGAAnb1gGMyXJ5gkC96LD7XqvI/EG7MopSWG3By
         XnbccbvrDhJKEV2UAvgdmtR11DefuDP5vrgojhvy1fceSor7cd1HbMAa1ALMpK2ZlsCJ
         mZCtrxjvxt2Xt5/N4Gksf736rlLGcXoe35jh1pJMEa0TZHVHpsjU44GVf8QEyGB053O6
         1dZw==
X-Gm-Message-State: AOAM532hHsYFJhs16LvqfRBkCAQcYauD/eV38opSupwo/Rm3L4gZKLYd
	q++6DZ0Ru7jXsKHkELyWhzU=
X-Google-Smtp-Source: ABdhPJwyukVlw44uQm5KwQ92QxiXd00IztyyjOHffCDYpfoZb0dJQHjUcHMajdJ2dP+Hs7SqoDOsUg==
X-Received: by 2002:a9d:7315:: with SMTP id e21mr1579430otk.372.1603808209655;
        Tue, 27 Oct 2020 07:16:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:1a84:: with SMTP id 126ls128006oof.11.gmail; Tue, 27 Oct
 2020 07:16:49 -0700 (PDT)
X-Received: by 2002:a4a:ce90:: with SMTP id f16mr2002930oos.55.1603808209210;
        Tue, 27 Oct 2020 07:16:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603808209; cv=none;
        d=google.com; s=arc-20160816;
        b=p/zmsbRzLvCnHpoJMniYnETOD3RzVNAFP+4SEtIXIENEUWXaEBsD29K73fvamSjW40
         k/LGzfvs+/aWFhHOMxorgMC3MvnUBKjM1wKIANq2Xs53ngTyK35tgNQpGO+J2qpxrBqS
         Nj38R7M/mPt3H0b+7h2AidKSNxX7WRwXGyKKvFKuGk2g8sGlA0Y75hmRru9dnjScqOM+
         8YkHkpD/sFSfhy4v7jh54bJXN7jF+c0b79gZ7GELebWflqx2jx5ogxSc/OIvSpSaOxD1
         ih3eeFIl22cKXO3LxZQeq3PdnUNlcg5M/iER0vlNRpraCdSLg9Q9fxA3DF+ytuEADuee
         E68w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=7tx/2NwkmA7HngJZAgicLC4Vz3Ng4DwtJMUF/25pVtg=;
        b=R+focOa8XhPyhORnu5WKrWK9BTyk8/B9KGzdU1bVoL/5HfRZmd5ew4QYaKXkr6zycX
         WjV9kKzNtIIUAmtM5QNFU1eNoMq2FbJzDEZNwV/g4kJFyGSyn97kDQBp79oVtVctWHJo
         Mxr9UWXeOXRfZC8pzoZZj3w/gS2MmidAUE2kebF2OAIGbvc0mKAP8vBrFiY3CaXRMkNo
         mn2b9qCLZhDOqXhVNV7KW30J+JgcnBn7K5J/LARyEnf0sJ1QAGl0NNGJ1g361vDIHYkk
         0X78iNuaZTrWDzAC+B4xcsvZ6L5ovvVsC2M8TA7QNBIKC8ZE54/+Ih97ryNE+6NnFWKA
         pkzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vqOuO8aD;
       spf=pass (google.com: domain of 30cuyxwukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=30CuYXwUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id v11si60413oiv.0.2020.10.27.07.16.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Oct 2020 07:16:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30cuyxwukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id x34so885867qvx.7
        for <kasan-dev@googlegroups.com>; Tue, 27 Oct 2020 07:16:49 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a0c:b5e1:: with SMTP id o33mr2420189qvf.17.1603808208488;
 Tue, 27 Oct 2020 07:16:48 -0700 (PDT)
Date: Tue, 27 Oct 2020 15:16:02 +0100
In-Reply-To: <20201027141606.426816-1-elver@google.com>
Message-Id: <20201027141606.426816-6-elver@google.com>
Mime-Version: 1.0
References: <20201027141606.426816-1-elver@google.com>
X-Mailer: git-send-email 2.29.0.rc2.309.g374f81d7ae-goog
Subject: [PATCH v5 5/9] mm, kfence: insert KFENCE hooks for SLUB
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, joern@purestorage.com, keescook@chromium.org, 
	mark.rutland@arm.com, penberg@kernel.org, peterz@infradead.org, 
	sjpark@amazon.com, tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, 
	x86@kernel.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vqOuO8aD;       spf=pass
 (google.com: domain of 30cuyxwukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=30CuYXwUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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

Inserts KFENCE hooks into the SLUB allocator.

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
v5:
* Fix obj_to_index for kfence objects.

v3:
* Rewrite patch description to clarify need for 'orig_size'
  [reported by Christopher Lameter].
---
 include/linux/slub_def.h |  3 ++
 mm/slub.c                | 72 +++++++++++++++++++++++++++++-----------
 2 files changed, 56 insertions(+), 19 deletions(-)

diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
index 1be0ed5befa1..dcde82a4434c 100644
--- a/include/linux/slub_def.h
+++ b/include/linux/slub_def.h
@@ -7,6 +7,7 @@
  *
  * (C) 2007 SGI, Christoph Lameter
  */
+#include <linux/kfence.h>
 #include <linux/kobject.h>
 #include <linux/reciprocal_div.h>
 
@@ -185,6 +186,8 @@ static inline unsigned int __obj_to_index(const struct kmem_cache *cache,
 static inline unsigned int obj_to_index(const struct kmem_cache *cache,
 					const struct page *page, void *obj)
 {
+	if (is_kfence_address(obj))
+		return 0;
 	return __obj_to_index(cache, page_address(page), obj);
 }
 
diff --git a/mm/slub.c b/mm/slub.c
index b30be2385d1c..95d9e2a45707 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -27,6 +27,7 @@
 #include <linux/ctype.h>
 #include <linux/debugobjects.h>
 #include <linux/kallsyms.h>
+#include <linux/kfence.h>
 #include <linux/memory.h>
 #include <linux/math64.h>
 #include <linux/fault-inject.h>
@@ -1553,6 +1554,11 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 	void *old_tail = *tail ? *tail : *head;
 	int rsize;
 
+	if (is_kfence_address(next)) {
+		slab_free_hook(s, next);
+		return true;
+	}
+
 	/* Head and tail of the reconstructed freelist */
 	*head = NULL;
 	*tail = NULL;
@@ -2658,7 +2664,8 @@ static inline void *get_freelist(struct kmem_cache *s, struct page *page)
  * already disabled (which is the case for bulk allocation).
  */
 static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
-			  unsigned long addr, struct kmem_cache_cpu *c)
+			  unsigned long addr, struct kmem_cache_cpu *c,
+			  size_t orig_size)
 {
 	void *freelist;
 	struct page *page;
@@ -2763,7 +2770,8 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
  * cpu changes by refetching the per cpu area pointer.
  */
 static void *__slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
-			  unsigned long addr, struct kmem_cache_cpu *c)
+			  unsigned long addr, struct kmem_cache_cpu *c,
+			  size_t orig_size)
 {
 	void *p;
 	unsigned long flags;
@@ -2778,7 +2786,7 @@ static void *__slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
 	c = this_cpu_ptr(s->cpu_slab);
 #endif
 
-	p = ___slab_alloc(s, gfpflags, node, addr, c);
+	p = ___slab_alloc(s, gfpflags, node, addr, c, orig_size);
 	local_irq_restore(flags);
 	return p;
 }
@@ -2805,7 +2813,7 @@ static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
  * Otherwise we can simply pick the next object from the lockless free list.
  */
 static __always_inline void *slab_alloc_node(struct kmem_cache *s,
-		gfp_t gfpflags, int node, unsigned long addr)
+		gfp_t gfpflags, int node, unsigned long addr, size_t orig_size)
 {
 	void *object;
 	struct kmem_cache_cpu *c;
@@ -2816,6 +2824,11 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
 	s = slab_pre_alloc_hook(s, &objcg, 1, gfpflags);
 	if (!s)
 		return NULL;
+
+	object = kfence_alloc(s, orig_size, gfpflags);
+	if (unlikely(object))
+		goto out;
+
 redo:
 	/*
 	 * Must read kmem_cache cpu data via this cpu ptr. Preemption is
@@ -2853,7 +2866,7 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
 	object = c->freelist;
 	page = c->page;
 	if (unlikely(!object || !node_match(page, node))) {
-		object = __slab_alloc(s, gfpflags, node, addr, c);
+		object = __slab_alloc(s, gfpflags, node, addr, c, orig_size);
 	} else {
 		void *next_object = get_freepointer_safe(s, object);
 
@@ -2888,20 +2901,21 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
 	if (unlikely(slab_want_init_on_alloc(gfpflags, s)) && object)
 		memset(object, 0, s->object_size);
 
+out:
 	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object);
 
 	return object;
 }
 
 static __always_inline void *slab_alloc(struct kmem_cache *s,
-		gfp_t gfpflags, unsigned long addr)
+		gfp_t gfpflags, unsigned long addr, size_t orig_size)
 {
-	return slab_alloc_node(s, gfpflags, NUMA_NO_NODE, addr);
+	return slab_alloc_node(s, gfpflags, NUMA_NO_NODE, addr, orig_size);
 }
 
 void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
 {
-	void *ret = slab_alloc(s, gfpflags, _RET_IP_);
+	void *ret = slab_alloc(s, gfpflags, _RET_IP_, s->object_size);
 
 	trace_kmem_cache_alloc(_RET_IP_, ret, s->object_size,
 				s->size, gfpflags);
@@ -2913,7 +2927,7 @@ EXPORT_SYMBOL(kmem_cache_alloc);
 #ifdef CONFIG_TRACING
 void *kmem_cache_alloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
 {
-	void *ret = slab_alloc(s, gfpflags, _RET_IP_);
+	void *ret = slab_alloc(s, gfpflags, _RET_IP_, size);
 	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags);
 	ret = kasan_kmalloc(s, ret, size, gfpflags);
 	return ret;
@@ -2924,7 +2938,7 @@ EXPORT_SYMBOL(kmem_cache_alloc_trace);
 #ifdef CONFIG_NUMA
 void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
 {
-	void *ret = slab_alloc_node(s, gfpflags, node, _RET_IP_);
+	void *ret = slab_alloc_node(s, gfpflags, node, _RET_IP_, s->object_size);
 
 	trace_kmem_cache_alloc_node(_RET_IP_, ret,
 				    s->object_size, s->size, gfpflags, node);
@@ -2938,7 +2952,7 @@ void *kmem_cache_alloc_node_trace(struct kmem_cache *s,
 				    gfp_t gfpflags,
 				    int node, size_t size)
 {
-	void *ret = slab_alloc_node(s, gfpflags, node, _RET_IP_);
+	void *ret = slab_alloc_node(s, gfpflags, node, _RET_IP_, size);
 
 	trace_kmalloc_node(_RET_IP_, ret,
 			   size, s->size, gfpflags, node);
@@ -2972,6 +2986,9 @@ static void __slab_free(struct kmem_cache *s, struct page *page,
 
 	stat(s, FREE_SLOWPATH);
 
+	if (kfence_free(head))
+		return;
+
 	if (kmem_cache_debug(s) &&
 	    !free_debug_processing(s, page, head, tail, cnt, addr))
 		return;
@@ -3216,6 +3233,13 @@ int build_detached_freelist(struct kmem_cache *s, size_t size,
 		df->s = cache_from_obj(s, object); /* Support for memcg */
 	}
 
+	if (is_kfence_address(object)) {
+		slab_free_hook(df->s, object);
+		WARN_ON(!kfence_free(object));
+		p[size] = NULL; /* mark object processed */
+		return size;
+	}
+
 	/* Start new detached freelist */
 	df->page = page;
 	set_freepointer(df->s, object, NULL);
@@ -3291,8 +3315,14 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	c = this_cpu_ptr(s->cpu_slab);
 
 	for (i = 0; i < size; i++) {
-		void *object = c->freelist;
+		void *object = kfence_alloc(s, s->object_size, flags);
 
+		if (unlikely(object)) {
+			p[i] = object;
+			continue;
+		}
+
+		object = c->freelist;
 		if (unlikely(!object)) {
 			/*
 			 * We may have removed an object from c->freelist using
@@ -3308,7 +3338,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 			 * of re-populating per CPU c->freelist
 			 */
 			p[i] = ___slab_alloc(s, flags, NUMA_NO_NODE,
-					    _RET_IP_, c);
+					    _RET_IP_, c, size);
 			if (unlikely(!p[i]))
 				goto error;
 
@@ -3963,7 +3993,7 @@ void *__kmalloc(size_t size, gfp_t flags)
 	if (unlikely(ZERO_OR_NULL_PTR(s)))
 		return s;
 
-	ret = slab_alloc(s, flags, _RET_IP_);
+	ret = slab_alloc(s, flags, _RET_IP_, size);
 
 	trace_kmalloc(_RET_IP_, ret, size, s->size, flags);
 
@@ -4011,7 +4041,7 @@ void *__kmalloc_node(size_t size, gfp_t flags, int node)
 	if (unlikely(ZERO_OR_NULL_PTR(s)))
 		return s;
 
-	ret = slab_alloc_node(s, flags, node, _RET_IP_);
+	ret = slab_alloc_node(s, flags, node, _RET_IP_, size);
 
 	trace_kmalloc_node(_RET_IP_, ret, size, s->size, flags, node);
 
@@ -4037,6 +4067,7 @@ void __check_heap_object(const void *ptr, unsigned long n, struct page *page,
 	struct kmem_cache *s;
 	unsigned int offset;
 	size_t object_size;
+	bool is_kfence = is_kfence_address(ptr);
 
 	ptr = kasan_reset_tag(ptr);
 
@@ -4049,10 +4080,13 @@ void __check_heap_object(const void *ptr, unsigned long n, struct page *page,
 			       to_user, 0, n);
 
 	/* Find offset within object. */
-	offset = (ptr - page_address(page)) % s->size;
+	if (is_kfence)
+		offset = ptr - kfence_object_start(ptr);
+	else
+		offset = (ptr - page_address(page)) % s->size;
 
 	/* Adjust for redzone and reject if within the redzone. */
-	if (kmem_cache_debug_flags(s, SLAB_RED_ZONE)) {
+	if (!is_kfence && kmem_cache_debug_flags(s, SLAB_RED_ZONE)) {
 		if (offset < s->red_left_pad)
 			usercopy_abort("SLUB object in left red zone",
 				       s->name, to_user, offset, n);
@@ -4461,7 +4495,7 @@ void *__kmalloc_track_caller(size_t size, gfp_t gfpflags, unsigned long caller)
 	if (unlikely(ZERO_OR_NULL_PTR(s)))
 		return s;
 
-	ret = slab_alloc(s, gfpflags, caller);
+	ret = slab_alloc(s, gfpflags, caller, size);
 
 	/* Honor the call site pointer we received. */
 	trace_kmalloc(caller, ret, size, s->size, gfpflags);
@@ -4492,7 +4526,7 @@ void *__kmalloc_node_track_caller(size_t size, gfp_t gfpflags,
 	if (unlikely(ZERO_OR_NULL_PTR(s)))
 		return s;
 
-	ret = slab_alloc_node(s, gfpflags, node, caller);
+	ret = slab_alloc_node(s, gfpflags, node, caller, size);
 
 	/* Honor the call site pointer we received. */
 	trace_kmalloc_node(caller, ret, size, s->size, gfpflags, node);
-- 
2.29.0.rc2.309.g374f81d7ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201027141606.426816-6-elver%40google.com.
