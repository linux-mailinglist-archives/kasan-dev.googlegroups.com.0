Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGWUUL5QKGQEXN3EVNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id E8B6A272569
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 15:26:55 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id p11sf7949714pjv.2
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 06:26:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600694814; cv=pass;
        d=google.com; s=arc-20160816;
        b=uW8tswoR9cOHJDjgl1E1jlIxVKNanpkhO7kNpOohzPBar/Em6OHj3xh2/gnslhxlsm
         TLNsBdaPsWBnJ8KUTXucoVjREOP5b93aa+0CYpylg1SsZsCfm3BD6TKjlPszNShI5Yb5
         dKeqMOsDj3BdD5i8K+Zyef40Ml51NBJnRCOeZnyQK6L5Q9tMhBBRLL0C7CmEOUur0vJp
         YDqpi3kp+nfnGJRfOKv3npQysdaLX0SwuxWxBz2WlW7Xu4byHS3dLS/hoFEKrUolTgkY
         wHIN+Y1293Vt1GWFfclR9D+SMHrUwuBigOIFtOU+WUHITVuMEI3hmuihNPN2dQ2Oykpp
         6pag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=12ccZGVoxO2uT63aa9WBm4bNnNhVn2t/L5Y86fonE6k=;
        b=YiOoXIUCyEb8Ct8bh5W1i0LyPUu4r4v+uSDuUrtSOp27c2iuZRu6hqRTmnt1nSqTPi
         urDxHGWFdwtqnAaO4mqTqxZXe6StXet1MtabfMOmuE1y/Wr1ZBlREWksTotbUrqqulV9
         GS6dXkdldUdb00kxMUMB3KU3VL8puO9mE0hktbfHhSXdUnWlGfMvfBu7AWyoXA6ozv1F
         sCu26vVtrv7YzPmsFvbjsa+Mk2UA5N8Sk6izb9A7Ph+rrhTfKG6dGeWs9TMa89F8oSVF
         OUeCKmjSD8LU/4yGgzrCrW9u9m7o62F50XwCkQdaGtkySoMzuRYxTAXd/dWHNXqVnn1G
         1yVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hylJXImg;
       spf=pass (google.com: domain of 3gkpoxwukcrev2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3GKpoXwUKCREv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=12ccZGVoxO2uT63aa9WBm4bNnNhVn2t/L5Y86fonE6k=;
        b=oRIrMHMpg79/DsbU1KbZKgB0MOFs6tOVVqAd3F+oOb536vmfuaprmvYlOSnzojNGbQ
         AxB/6M5x6vYeCGGKwjGHgdDRKguTJiP91SmB9/Ow7q41+7g+IfDqRCxfD0/zeAgvOECP
         ZR0j9zjgOsbP0f856am4R5JOgH7lGDpW1IQcNUo92tsEdQ7wUicKFrAcoGMVFIIUatGp
         EdgOlKlLHm5AEqbxP4Qte4C+K6hkZjDC19xv/oHaI+2wlOEZEDuxVR9a7kRgbi8E3M+E
         cxRIgBJg9ctUaDJPN6BzbQrvAzDq5F/pHo4zrQwnLqPD5h7o1iW/JjljT3BgNvPg1FAv
         3jDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=12ccZGVoxO2uT63aa9WBm4bNnNhVn2t/L5Y86fonE6k=;
        b=eB6AW3lq5uzsdcbCDlw4ezFd5kBAegTgJ83dfJ2Duk4IDfNnC3kT5uK8FnaL5tW8wz
         Uf23FTLeD97fnQdYMO8EBQtZldZYuC0hBSXGtjOCwrmy2EZPNEngvsw3nRIG5g21Mp7n
         u9TaCDCUgdPzuZyw7882V+aIpLUj1KzC64Ln0flM46bXv+k9FHYtDLa/NwOMjs8W12sq
         6i37me7KqXG3S7VCIltKm6U1jGU3wiwABBzXuQPCwzwvnRq2FgO9qJ+ea5vOpDPhReNJ
         1QlMXp64bhmeNoqHYoLkeJL86zHXTBwXkDFyh7HE45v9ri9FtNk9NEaUYvFg7V0Sr6/l
         mN0A==
X-Gm-Message-State: AOAM530snsEOyP0U8wguDdiKzAYubJTCMjcA6SebennO1GX4mBY6aH3s
	u/0bIBtzQdyJQYlCnDPoo0Q=
X-Google-Smtp-Source: ABdhPJyyUVWz2u9w1c93AZ9A3dfo/bcTUSDG99NEtS0/+WpCN2PMWJo9quT1VHjBXGe61d3TDibYNg==
X-Received: by 2002:a17:902:7:b029:d1:e5e7:be08 with SMTP id 7-20020a1709020007b02900d1e5e7be08mr28127432pla.59.1600694811004;
        Mon, 21 Sep 2020 06:26:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:70cc:: with SMTP id l12ls1789490plt.1.gmail; Mon, 21
 Sep 2020 06:26:50 -0700 (PDT)
X-Received: by 2002:a17:902:6bc1:b029:d0:cbe1:e706 with SMTP id m1-20020a1709026bc1b02900d0cbe1e706mr8905plt.20.1600694810369;
        Mon, 21 Sep 2020 06:26:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600694810; cv=none;
        d=google.com; s=arc-20160816;
        b=lHn5cF45sYRuDcDedtCx7+0xLatjLSxbIr3pA9/mcAEun7yVQANiskDhNqqSitB5Jg
         1ephgPJySiUkdg5o8d1iGuL8wa9aJ0OfrZCMuyrzkU2FXNkQTHBQ2qBBSHBF58FMLtDU
         6wV8BbUe1565+Bt1Ujed5WB5zlUjndKSzlIUu/fHacClgRacZ1SoGYk4CIo+pw7qv61+
         FFFj3LhzWntk0GwG9yQh0+0qJ4NEiaszGXZ8d98iw+XkugKFQ5RWRTENEliFjX371V5s
         SGpawafPNt+J8NIfp/Z/u45jqsmwB5qy50RZsPDrI+FIms/8FdJi1O6pB2KKtylRrADM
         ggaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=nx7aUN0/yJCS5xZtnIlKbyXxp8Cu5NaBFGXr6KIFiV8=;
        b=rtWfwq4pOdN+JW/HwNnTd5eZm/GAOe/UPZK0ZmYzyJj9wVIsfYO1kF19+EsN9nqWl8
         GXhDDRoLxqr4IhPyf5uO3wxweggyk5CCZhgrHj9mil6sM95SddL0VzjJwmXV1o8QGD2Y
         bHMdzhGbCY6eoCP3bKbyRFtDR6cR0zcPGLt9b0p6pvoptVpOo3FjrXtDBYHX7Naj39gf
         I7gPNQfIvNZNhWr/FtRFMHp6+6N8bbuTf7Dh8UoTI2PaEi7l+pQUlJi7z6JU3F8gn8QV
         Y9xlc5aaY49oxHF0iIDQzOeyBDtuOQB5uKEjBCKSOFzsmfleAhTM1qk6eb2UUuM8ooFB
         eJRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hylJXImg;
       spf=pass (google.com: domain of 3gkpoxwukcrev2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3GKpoXwUKCREv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id n8si688265pfd.4.2020.09.21.06.26.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Sep 2020 06:26:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gkpoxwukcrev2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id y53so12889100qth.2
        for <kasan-dev@googlegroups.com>; Mon, 21 Sep 2020 06:26:50 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:ad4:5565:: with SMTP id w5mr45433176qvy.24.1600694808773;
 Mon, 21 Sep 2020 06:26:48 -0700 (PDT)
Date: Mon, 21 Sep 2020 15:26:06 +0200
In-Reply-To: <20200921132611.1700350-1-elver@google.com>
Message-Id: <20200921132611.1700350-6-elver@google.com>
Mime-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 05/10] mm, kfence: insert KFENCE hooks for SLUB
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
 header.i=@google.com header.s=20161025 header.b=hylJXImg;       spf=pass
 (google.com: domain of 3gkpoxwukcrev2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3GKpoXwUKCREv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200921132611.1700350-6-elver%40google.com.
