Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4HRZT5QKGQEM3MQ5MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 484E527CF5B
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 15:38:57 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id n133sf3104806lfd.8
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 06:38:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601386736; cv=pass;
        d=google.com; s=arc-20160816;
        b=lxMUOz/VqA3ChP6KcZNSeZ1DFz0ZQqgYkdOVVFJ6BT5zes6fIiJd9ZeDVhtpNXDk5a
         kB+ErB4q9jO/LBK2hVSBbjw7O3XjWCtiqYFH638vjpOHvCnU9ZsSTNWbcNa/NTK8h2v2
         lQiady9NW6/p2XuhBIDUOfNH2Jl99Fy3qEhRpn0XjhH576zRTxAOPbafzhy1dA07i0v3
         MGq0maj8KuRhmqMkm6RgmODVtaYJDza+fEOWMCmM9Km5uHygmbKssrB3F3faMOfWD2m6
         4ZtgFuDlRJkayLWOJDnmAzuh23oenvy5wfQrcGEjNHyy9tHn84RT81geEW9bAgMTJ7XO
         q7cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=z6lQdc52nhUK2rqrTI/q1EUUaziH1ss54lPlDuffK80=;
        b=amCHKlr7XLxMZ7ao0GDkpZGYxDZivupXLxW1b7RIVfA0cnHdsdW6C6PUPAEeP7vCxW
         S4tWXLa6PfRjAZqu5t9tvCIh1GhjYihaQesgO7diIZQ/AuIUbbLBSBi0xJwTVnD8IJbP
         eyBpZ5zMEoShQr8tOX4lZwVbUrTYVNEK1C6OWFHH4WgTiXBM2snVkvmrftyRkI/WvxWI
         45indrSFj45eGQ+nFU5ihy9QigSMii/Fy0/CDRlpp4kHbWzEtpoCBsmBdGbhjQLQQtJF
         p8BfB+GrWdh0BymCEsNaOyl2Ft8ikT5iSuCYAwYfacfi1DmBpcfu6V1d6dXVbQ2Jdm9o
         vVxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=m3ciNFIc;
       spf=pass (google.com: domain of 37jhzxwukcs8pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=37jhzXwUKCS8PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=z6lQdc52nhUK2rqrTI/q1EUUaziH1ss54lPlDuffK80=;
        b=Cd9cegnm1wAhOgGNuyx6pWAzUaz++XWP6xe8mVFok9ADU/cUi9KKzJ3VeKbRsDVh80
         HqHeTDMnEAyBJmtNioq7FLjjml+W6xBW8yGod4dqFvCpCzFHZdmTlkfWVj058Vv0AGZm
         h35yxYDhN3b7s9ada8ICECfNTDDczDS9GWuRR3/B9RS0ln4FPSaN0ieV6RLfyN57XTZm
         g5eEzbOpd7j7SLHbcung+6W5R94uy/ws2htYmFXWPoVDCez6Z8inP/FCSH+m7CCdhZqy
         qnSY8gOa19CZVEUa6WpBqvFLwyLORl62LeUisdXbvPJZG1kB0HsjDOHXkt3NFpaAs1+T
         QH5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z6lQdc52nhUK2rqrTI/q1EUUaziH1ss54lPlDuffK80=;
        b=AujUSUfOrboj9i/8w+t2gjAcufUrX1T2kyZCHsb7zXf6DtJ4fu2Uy4r2oQYi9RSena
         lJH4eYoFeXSMKNa7GOoi/eIubrBhttVkUNJGl2ZvHBt25ZupmImsWHSQIreD70VVmwhf
         kgSb01Z0tZj6GRZZfD4VgCFay+7Im4v5ve6P1TRWpjc0WpujzAKWu9G6P2n7npqRyBNA
         XnuN3csAW4DN8l5KH/igedrV9Rnqc/hZT39PYlF5hyRB/PhhDcyOnaBdGeNXshbPflLE
         yss1oaTxvvod4WB0OMhhiX0rpFhfZYi+9FqelWiI1ff0DIacg/8JCUrcIhiW0LA9LWFv
         jjuA==
X-Gm-Message-State: AOAM533NxWSRlpVRkBqUupSGN95wpiTMRwcVv/sb5B+I6xp1BJDmX3Rj
	+fXN/B1ER7fkMWkmUr6G+FQ=
X-Google-Smtp-Source: ABdhPJyQ9PTdRBikY1S++MffOFxy5FsQI+zjcaPYhYnA2IpV0HyIC1BztRhFIulTi8nvDYbeVj8tGA==
X-Received: by 2002:a2e:89d6:: with SMTP id c22mr1320735ljk.242.1601386736784;
        Tue, 29 Sep 2020 06:38:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5c44:: with SMTP id s4ls714600lfp.3.gmail; Tue, 29 Sep
 2020 06:38:55 -0700 (PDT)
X-Received: by 2002:ac2:544f:: with SMTP id d15mr1293993lfn.368.1601386735605;
        Tue, 29 Sep 2020 06:38:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601386735; cv=none;
        d=google.com; s=arc-20160816;
        b=sO2Aj0XPyi4cOS74FBMzDGm7CQEjGYqELt4ekZ202FpAWBNe3UOW4RbOSc0FGeuN6L
         Ky3W50fKr/Gx2TacxEs00ifExkerD496OotR+4SlPydzF13Ij5TOQwyveg0bR7FdziD1
         6BxR03MgZQaO4ftyHzrS0711ho3hpMJ9sWVNiWQ+hQW27uV3jB6tf7SBSYe3iEsyRQtM
         08t0EqT85UDr0Ofg5oNqa4SqkfD8NfC4Nj/0j4NFPDhmYHaC2fvjzJ9tpyTn+vCR40Ld
         PPBiWS9UvbQG4zaeSmbHnFey+uw4lJxkqzMwYGheoQfTKbSO5c4wcppc+aOgMcUuUmO3
         /Lfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=TcPFKG27AKWC24GfjbdRwfCqEVji/eGlkYn6VN42bOA=;
        b=NaF8gUExVjxvT89XFCdm7wiUhaIgkKP/2t5MKH11EeF0Qux6y+nqPduX5+piNvNYZ3
         SKW1RmPU6tvah1UVgyqy+U6Cu2r0ZZ7tAqmLeXfx7lqN6lu6G4hs4+De3a2sHkzButUY
         BkBZwG9ah0JkF0ASjesIdnOOJQueL+RfyBBf6QVVHQdGoC9EjHHeUIKF2AKEG2VHyLKn
         iCZEqxX9Ffu7BHTVsfAyM87/odUn54K5027oT01MZgGykVsdisO5uEaXPprHuaKE3siE
         JOtIyGTBJAITz6kOF/8ZM1H1f+N4XLmHrmX9gqVq555Rt+346Hy1Ggted9c0fMx/GCqN
         cWow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=m3ciNFIc;
       spf=pass (google.com: domain of 37jhzxwukcs8pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=37jhzXwUKCS8PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id b5si127494lfa.0.2020.09.29.06.38.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 06:38:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37jhzxwukcs8pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id d13so1750332wrr.23
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 06:38:55 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a5d:55c8:: with SMTP id i8mr4470523wrw.331.1601386734786;
 Tue, 29 Sep 2020 06:38:54 -0700 (PDT)
Date: Tue, 29 Sep 2020 15:38:08 +0200
In-Reply-To: <20200929133814.2834621-1-elver@google.com>
Message-Id: <20200929133814.2834621-6-elver@google.com>
Mime-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 05/11] mm, kfence: insert KFENCE hooks for SLUB
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
 header.i=@google.com header.s=20161025 header.b=m3ciNFIc;       spf=pass
 (google.com: domain of 37jhzxwukcs8pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=37jhzXwUKCS8PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
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
v3:
* Rewrite patch description to clarify need for 'orig_size'
  [reported by Christopher Lameter].
---
 mm/slub.c | 72 ++++++++++++++++++++++++++++++++++++++++---------------
 1 file changed, 53 insertions(+), 19 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index d4177aecedf6..5c5a13a7857c 100644
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
@@ -1557,6 +1558,11 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
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
@@ -2660,7 +2666,8 @@ static inline void *get_freelist(struct kmem_cache *s, struct page *page)
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
 		stat(s, ALLOC_SLOWPATH);
 	} else {
 		void *next_object = get_freepointer_safe(s, object);
@@ -2889,20 +2902,21 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
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
@@ -2914,7 +2928,7 @@ EXPORT_SYMBOL(kmem_cache_alloc);
 #ifdef CONFIG_TRACING
 void *kmem_cache_alloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
 {
-	void *ret = slab_alloc(s, gfpflags, _RET_IP_);
+	void *ret = slab_alloc(s, gfpflags, _RET_IP_, size);
 	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags);
 	ret = kasan_kmalloc(s, ret, size, gfpflags);
 	return ret;
@@ -2925,7 +2939,7 @@ EXPORT_SYMBOL(kmem_cache_alloc_trace);
 #ifdef CONFIG_NUMA
 void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
 {
-	void *ret = slab_alloc_node(s, gfpflags, node, _RET_IP_);
+	void *ret = slab_alloc_node(s, gfpflags, node, _RET_IP_, s->object_size);
 
 	trace_kmem_cache_alloc_node(_RET_IP_, ret,
 				    s->object_size, s->size, gfpflags, node);
@@ -2939,7 +2953,7 @@ void *kmem_cache_alloc_node_trace(struct kmem_cache *s,
 				    gfp_t gfpflags,
 				    int node, size_t size)
 {
-	void *ret = slab_alloc_node(s, gfpflags, node, _RET_IP_);
+	void *ret = slab_alloc_node(s, gfpflags, node, _RET_IP_, size);
 
 	trace_kmalloc_node(_RET_IP_, ret,
 			   size, s->size, gfpflags, node);
@@ -2973,6 +2987,9 @@ static void __slab_free(struct kmem_cache *s, struct page *page,
 
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
@@ -3290,8 +3314,14 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
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
@@ -3307,7 +3337,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 			 * of re-populating per CPU c->freelist
 			 */
 			p[i] = ___slab_alloc(s, flags, NUMA_NO_NODE,
-					    _RET_IP_, c);
+					    _RET_IP_, c, size);
 			if (unlikely(!p[i]))
 				goto error;
 
@@ -3962,7 +3992,7 @@ void *__kmalloc(size_t size, gfp_t flags)
 	if (unlikely(ZERO_OR_NULL_PTR(s)))
 		return s;
 
-	ret = slab_alloc(s, flags, _RET_IP_);
+	ret = slab_alloc(s, flags, _RET_IP_, size);
 
 	trace_kmalloc(_RET_IP_, ret, size, s->size, flags);
 
@@ -4010,7 +4040,7 @@ void *__kmalloc_node(size_t size, gfp_t flags, int node)
 	if (unlikely(ZERO_OR_NULL_PTR(s)))
 		return s;
 
-	ret = slab_alloc_node(s, flags, node, _RET_IP_);
+	ret = slab_alloc_node(s, flags, node, _RET_IP_, size);
 
 	trace_kmalloc_node(_RET_IP_, ret, size, s->size, flags, node);
 
@@ -4036,6 +4066,7 @@ void __check_heap_object(const void *ptr, unsigned long n, struct page *page,
 	struct kmem_cache *s;
 	unsigned int offset;
 	size_t object_size;
+	bool is_kfence = is_kfence_address(ptr);
 
 	ptr = kasan_reset_tag(ptr);
 
@@ -4048,10 +4079,13 @@ void __check_heap_object(const void *ptr, unsigned long n, struct page *page,
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
@@ -4460,7 +4494,7 @@ void *__kmalloc_track_caller(size_t size, gfp_t gfpflags, unsigned long caller)
 	if (unlikely(ZERO_OR_NULL_PTR(s)))
 		return s;
 
-	ret = slab_alloc(s, gfpflags, caller);
+	ret = slab_alloc(s, gfpflags, caller, size);
 
 	/* Honor the call site pointer we received. */
 	trace_kmalloc(caller, ret, size, s->size, gfpflags);
@@ -4491,7 +4525,7 @@ void *__kmalloc_node_track_caller(size_t size, gfp_t gfpflags,
 	if (unlikely(ZERO_OR_NULL_PTR(s)))
 		return s;
 
-	ret = slab_alloc_node(s, gfpflags, node, caller);
+	ret = slab_alloc_node(s, gfpflags, node, caller, size);
 
 	/* Honor the call site pointer we received. */
 	trace_kmalloc_node(caller, ret, size, s->size, gfpflags, node);
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929133814.2834621-6-elver%40google.com.
