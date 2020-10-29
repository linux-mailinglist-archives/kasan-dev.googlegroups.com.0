Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWEB5P6AKGQE3E6TOBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id BAC9329ECA0
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 14:17:12 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id x16sf1267480wrg.7
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 06:17:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603977432; cv=pass;
        d=google.com; s=arc-20160816;
        b=JWUkniC/ACNym8+2XcCacVv8IMTQz5E56LYlXrtaLdHP97qGTucrIU/mwiltPJ/mBQ
         xK870RyKowIOjSeStQKCalWLX8PqVV4EcdTnmDU/CVcHzkyCDtpK04VOmG3QB59LA6ua
         719VcbVA/tPeeeiPTMhu8UoZJBQV6TOW/blhJ6egxuaGW5N/VPlRchnyUXcSuOwsXiPZ
         v+dS3054230lr07Kjvxk3w7xUY1D0Wg8EmFGUtzPQGZhrfhcXZpKJyHvN11Sx3q1q2ac
         hxvErGqMC5UpsWSSxmuqRUrhaxM3yMYw5qthch8+GXZqpERCnJoEUa0FCT0YfV1lJ78U
         x0yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=nXu9qNOXMP/KKN1QJoE8QL0pa5sDzrPgvxwchC57YXM=;
        b=ZPNrg8YPpTEvzTQT3Z8d/8SECxXh3ufsYwbcZaVafX1VVDD/1Lfr6yQQBZie1TjYnX
         A2m0n5Dmo6yye55eEgGbr240qOTaCWvdfTYCEWoYeM6dMGQDgmvZkltBUSm3b+4ZZO39
         XwKEEHbvgkc6an+eqs6i6LrsdWc/EV4MWt77sVLbcZ24qVjIQ6y3aOGlQONRZhC9wYbm
         4wRA6+cduDmS2D8S/9fkTNKj/FITVMHuGohw68wyDF56kSuwRclvHH8ZqZZ6vpjKiP/4
         AdAPesNmxsPBi7f9Roa/0aW1zYy1vXH1iOIaHBh1Rk09hGouQ5cRL91ZgR23Fyz7eKNJ
         5utQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HINz8UJb;
       spf=pass (google.com: domain of 31scaxwukccupw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=31sCaXwUKCcUpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nXu9qNOXMP/KKN1QJoE8QL0pa5sDzrPgvxwchC57YXM=;
        b=M3zdEG/a9S2m4wp1Us0puq1M5/Roq26W7b+3C4NU3mDqgMWDKrCa4kUfQ5FBywCe6e
         9alP9bi0qtPeoOT8rg7TKf+72+TrGweoapSjV4m2Qhc1MiVfa0xHn9H6OXvxnU3+gRTd
         T+RxDyAEfj90YJf2sCE8NWBAna1fZcH8+YmecfRve9yykmK71NV7xMdpqqJF+G/g/f3n
         TX8XmbUah9rxf1IwyXvrKWmh5aNnXIzjQQeXEut2+l2q/+CyAsPeV2VLbWjMpJlNaXfQ
         IhLQ1JJ/uTWtt47oFYrY+kp6jmdZp2oGP89WfE5y3lO+1Zi2ISi98XDNElAYKM0eHEpT
         xqHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nXu9qNOXMP/KKN1QJoE8QL0pa5sDzrPgvxwchC57YXM=;
        b=MABAhLUbbnOpUSNrpkVK3hXnPK3hG9Sbx8WixAxomj586cXWa9OOvpXdl4rYvEMVWT
         yPcjISheM/J55FNV0QQUQ2LiIRMdWy6+rF2nv0iQUGlkk3OJEM9ApbhrJQZ59XE2N3bj
         +WKODos0RUla5WOV+kVHfXMLnIqGHgpPGEIMQDAHnwWQEGWDuDBkcFF2vCmCt5CF/Hwn
         vHMC4S/uHxk30NztMMSqCPHpuSp5/nnyMhgIz3QUyc8cTBdK1sI6q7Ki7Fr2bGBPmltM
         TinR3fCL07ErC++fw9xkoGhRdPNN9fVVjALkktmiZBeso2BId50K8UdWQvkj5gtJDiOh
         6zgw==
X-Gm-Message-State: AOAM531TLhsG+h+CpI6v2cfyIW6/B3IDlDxkEoMUI4l/akYGa7m6r1ZV
	qsxBy/VwnVwsM+yxSUn7P2M=
X-Google-Smtp-Source: ABdhPJwFPgrfqeP+uqZe3+aF425DrbOr2d51UYdZdW980tZExqlXtmLL8vtN+VhoRZAK1MzcFeGSgQ==
X-Received: by 2002:adf:a557:: with SMTP id j23mr5887739wrb.95.1603977432511;
        Thu, 29 Oct 2020 06:17:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:cd8c:: with SMTP id q12ls1159575wrj.0.gmail; Thu, 29 Oct
 2020 06:17:11 -0700 (PDT)
X-Received: by 2002:adf:f48c:: with SMTP id l12mr5922752wro.77.1603977431548;
        Thu, 29 Oct 2020 06:17:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603977431; cv=none;
        d=google.com; s=arc-20160816;
        b=uFyRv1LnyPgccZYnwnuFUmxsn0g3u4RmBOPSrazaH8Mn3TkmhkpI37uwsnhdrGA53M
         RgMEwzLggt4+PaZMdylrm08WaIfXa1fyNMtj+mTk1IWs7L/uSnKaLImLkgfMXswgEGes
         Xe58TOvkKXjAo0ZKRUWBUjQ2K8iZ7oSnt40DSKUNCnUp7y0dRIgvqvMo288q1epew7S9
         sQn0nAM+MPEabRrZzzEGbm4D2wm52UaI/04xlQVnFy0h75tbWr0UL9/nqVnKr6DGLpda
         cKYf1cQFYecZp40Y8LhiqxWwQYv14ToHtGSQg3kifcc+Lh75bf7eKdhXW0OgBoTyroy7
         z/Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ZBmbCevgd8bWbMbBJPZrjV9agh6awCGyrsWIFX9Y3FQ=;
        b=XaF8bRAax8GfQBnGgazjCp2PzBbVjA3rPloP6cZdeuwQ/aOiHA/X5aSSd2oswczHLH
         EsbeRQ/X2eFO3S26b1642UsHmYQ2bQKEvG8B78obrnbHghMZYzZjtqZTFhOZW6qwRsIg
         3sPvQN5d8/UWONMGoBsogdGxz/ees0DxV+uL0sww63VibrI3j7CdDaNeHX9OALFSnTRI
         Sy9eLkRHuKgS0p3lv2etKmAketwDJH0ctwlgg41dsh1ri5lZGNjq+XBusHi8fOQwHgbm
         KmaCqf4GcsivxV97mA/u04kk4nrsnbRMYDgVt2gdLgq48ON5sEyUXO3ig2J5YD+A1Pm3
         dy6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HINz8UJb;
       spf=pass (google.com: domain of 31scaxwukccupw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=31sCaXwUKCcUpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id f198si71381wme.2.2020.10.29.06.17.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 06:17:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31scaxwukccupw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id 11so161668wrc.3
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 06:17:11 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a1c:b783:: with SMTP id h125mr2098392wmf.108.1603977430681;
 Thu, 29 Oct 2020 06:17:10 -0700 (PDT)
Date: Thu, 29 Oct 2020 14:16:45 +0100
In-Reply-To: <20201029131649.182037-1-elver@google.com>
Message-Id: <20201029131649.182037-6-elver@google.com>
Mime-Version: 1.0
References: <20201029131649.182037-1-elver@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 5/9] mm, kfence: insert KFENCE hooks for SLUB
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
 header.i=@google.com header.s=20161025 header.b=HINz8UJb;       spf=pass
 (google.com: domain of 31scaxwukccupw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=31sCaXwUKCcUpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201029131649.182037-6-elver%40google.com.
