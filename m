Return-Path: <kasan-dev+bncBC7OBJGL2MHBB25UQ36QKGQEWQYLRKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id BF7972A4DA6
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Nov 2020 18:59:07 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id bs10sf7745689edb.22
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Nov 2020 09:59:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604426347; cv=pass;
        d=google.com; s=arc-20160816;
        b=1EprndS/A0w1iL5ZcHiv+puCCbFElNL3HGzIv4XrbYBT0iT1G7IGXurXKoYyFp+wQ5
         vSphAvlWDotzyAPaVwcEz9JcgEVDFjMLXiG/F9kWWQcN6IoHp99cMbgAZchYv+luT4Iw
         ZBwcjkQAWeUEDSnPm5CjkpKsh7QRjL8tmu/xtOqG0vHYDuYhP/ECSHIJSJUjIJK1C5D+
         yUVt2p4NGmz9qYDJqkh76EhUOfxCOEsP4T7GDa6EZalbd6idLd4uYlPR3FeV/N0NBDl1
         g89NIeMaBtA1O2RPmubhhaPYkW78bEEs2gMfxOCSL2Pmy4umxu5pKJe9xZlinZqHUz27
         ElBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=0+qDQv4TknmVI2OEtwDdl7km4wUb3enAfDD19Nr+b0A=;
        b=Xk1C28UGWuy3w3Kqv3CCdpY809PScqziFR1mhOB39Xr5+4nD0ZfTrWTHi4jFevKtB3
         ZkE2m8tvo5avoMfNo9SysyB4sFSqAC4fzJn257oB8UxkCT6XUcNoY2CTQZkTYLH3LPqI
         fMlgfgJdJn0qmOP68GCThjIymW/vsQ3Nx3jXXfALb5nWv5CD+KaxEBZYlU71tg7PbHny
         0os15FIC0zvUza5VyIepciYuF+k+qebBn8YeqqFyq6rWZBd3cEN9fn29FrZN7morYplN
         Nr7Hc0UAfMuaiNTzYlauiTvf8VTWdu2Wer6j/2egiU6wbG8Xo/VCSXF4zsTji9b92AqP
         CGDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="M/AwsFi3";
       spf=pass (google.com: domain of 3azqhxwukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3aZqhXwUKCSgIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0+qDQv4TknmVI2OEtwDdl7km4wUb3enAfDD19Nr+b0A=;
        b=Or881WK9/VED+YZ6QjLd6BJHOlbmSzQXBrEnn93TD1JJKQRDRliJnBlt+h5ZbWKf+K
         AyfuxVVGhKtxzCqkyGtnCYxEg46jGSg8pC05QI6GGDl1LJinO0FL7V8r9zHgECmUlFY/
         IBR/fXbHhLgSeGK1UYrv2NexBsIo/c9vJJkM6c4oNXlAWantsmu4ib7LdjgrlDDZVWC8
         ugvUbvKzcreoJXuyPnOWo9wv471dLEgkyRnrh39PjsssPs0WKejoNIn5+Pdy3Ayz1ouJ
         rFwmFGqX6NnBDFKBtsDoipnpQ/NCowUwkOJJtIR29MxJykoQ99LN7ph0gm0awsQ9a6mh
         kUcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0+qDQv4TknmVI2OEtwDdl7km4wUb3enAfDD19Nr+b0A=;
        b=EVwNdrj8bffl3vhquoozVSeAy98AGl1oLrbizpLBmeyK32mR7Y5xAsrCDP2QvwiM3+
         26YiPp/iqEt59bFEcnmWn4fI1JBnVV/d4URrmwzZiSUHxa5ZANJa48oTBKuj6NlFrL3p
         e78TdjL8WibID5r9Ix79/hNhNonAS55KPNnZpNBq/2qOuUaTe0Fu+mnQ15sLOUbfEcnF
         0R7eA97hEAPuOrTBK9HEsJb3sblXeFmDx5w+K+51fcoQVoh5PWfuC2tX9t1mVMNL0ktI
         MvRq9dU1EdzfyMhlY3i6j17pwIfiTkaN20e4fBKlizgf33NMoR3tnZhnBm+P6TFyFw9U
         QXhg==
X-Gm-Message-State: AOAM532dwoyUJX6eyn6Cd+xttMTO3gcePI3AqDQD6nMzXn3TQhfUAxDH
	09bOw6WX8J6oS+v8fTJFQpI=
X-Google-Smtp-Source: ABdhPJyUeRfHxYrN6V3FCq3tUA5wSEijYbCcsDTeI9Vupmk/KGhzJA6QwzPrv0FY8Pc/q+GCovWYEQ==
X-Received: by 2002:a17:906:1a14:: with SMTP id i20mr16996838ejf.422.1604426347491;
        Tue, 03 Nov 2020 09:59:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d4c3:: with SMTP id t3ls3062172edr.0.gmail; Tue, 03 Nov
 2020 09:59:06 -0800 (PST)
X-Received: by 2002:aa7:d5d8:: with SMTP id d24mr24065892eds.8.1604426346418;
        Tue, 03 Nov 2020 09:59:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604426346; cv=none;
        d=google.com; s=arc-20160816;
        b=oVKh02Bsjmzn3hMME2Vu5ZVUHsd/F4e7MlQj/olt135+xG7YO9fO0UtrXHGZAUwBkq
         FmA53s3AaGW+xpC35NJ+KdzNZMsQSDJFSwyblO7HtIOu1GXiVTQDBAxcEusQhFcRrsbr
         q8/3INaYYfP2u5HL5WjeAfYw9yYN8cA4RP+mGKWoE3hLnvs5gIZaZKsh7Nxe/23i7U0m
         J5lUxqMV9hMGmzzNbW1Y9oP4uqbwVifexF6nJpU5sp86ZpgPDRG7e+qC/ceC8tNp5OLm
         hFwS+JXzRRyBYeX7nP/DfOCNgZ8p4xyhy9EAg9wYUwuzhPm0o3/agJCgHOjmjXDdMibQ
         Cg1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=f54NMbGpMSq/iIHeUCAr1FoCQza8wHra8DmMf8c0R2Y=;
        b=kyLpUdZZIXZoqatPOokFkL0DkiU/54aFk+j7iTOf9csDChiSHjY7mjqTYskjwrkAsB
         u7Pap/rTKvgQm1SVfHabvS+9+z45DlZd+HJmeBcdnpOxP4g2Otv3sukoSvtWRJQD//y9
         aSsJmioVKhKAVK5vhBA7V8eQtwbTWWy7X4G8jBia5q1ZV+VxCnJ+xycI1PxuYzIOstMB
         hU1heFRcCgek6Uu5lGiXbKTXc6KI3r/SEj+w56DfRDga/Xr0Br9rlb4K/EF4ujy5RuBe
         /PHIhTM0rbWmYRtDVgBfaqY976otAscRKel73wa1rKhw4Tg9ON5oOsiQDuMZ8Cr8Wil+
         BRww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="M/AwsFi3";
       spf=pass (google.com: domain of 3azqhxwukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3aZqhXwUKCSgIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id g4si425015edt.2.2020.11.03.09.59.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Nov 2020 09:59:06 -0800 (PST)
Received-SPF: pass (google.com: domain of 3azqhxwukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id t201so76834wmt.1
        for <kasan-dev@googlegroups.com>; Tue, 03 Nov 2020 09:59:06 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a1c:6a0d:: with SMTP id f13mr347027wmc.172.1604426345701;
 Tue, 03 Nov 2020 09:59:05 -0800 (PST)
Date: Tue,  3 Nov 2020 18:58:36 +0100
In-Reply-To: <20201103175841.3495947-1-elver@google.com>
Message-Id: <20201103175841.3495947-5-elver@google.com>
Mime-Version: 1.0
References: <20201103175841.3495947-1-elver@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 4/9] mm, kfence: insert KFENCE hooks for SLAB
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
 header.i=@google.com header.s=20161025 header.b="M/AwsFi3";       spf=pass
 (google.com: domain of 3azqhxwukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3aZqhXwUKCSgIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
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
v7:
* Move kmemleak_free_recursive() before kfence_free() for KFENCE
  objects. kmemleak_free_recursive() should be before releasing the
  object, to avoid a potential race where the object may immediately be
  reused [reported by Jann Horn].
* Re-add SLAB-specific code setting page->s_mem.

v5:
* New kfence_shutdown_cache(): we need to defer kfence_shutdown_cache()
  to before the cache is actually freed. In case of SLAB_TYPESAFE_BY_RCU,
  the objects may still legally be used until the next RCU grace period.
* Fix objs_per_slab_page for kfence objects.
* Revert and use fixed obj_to_index() in __check_heap_object().

v3:
* Rewrite patch description to clarify need for 'orig_size'
  [reported by Christopher Lameter].
---
 include/linux/slab_def.h |  3 +++
 mm/kfence/core.c         |  2 ++
 mm/slab.c                | 38 +++++++++++++++++++++++++++++---------
 mm/slab_common.c         |  5 ++++-
 4 files changed, 38 insertions(+), 10 deletions(-)

diff --git a/include/linux/slab_def.h b/include/linux/slab_def.h
index 9eb430c163c2..3aa5e1e73ab6 100644
--- a/include/linux/slab_def.h
+++ b/include/linux/slab_def.h
@@ -2,6 +2,7 @@
 #ifndef _LINUX_SLAB_DEF_H
 #define	_LINUX_SLAB_DEF_H
 
+#include <linux/kfence.h>
 #include <linux/reciprocal_div.h>
 
 /*
@@ -114,6 +115,8 @@ static inline unsigned int obj_to_index(const struct kmem_cache *cache,
 static inline int objs_per_slab_page(const struct kmem_cache *cache,
 				     const struct page *page)
 {
+	if (is_kfence_address(page_address(page)))
+		return 1;
 	return cache->num;
 }
 
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 64f33b93223b..721fd6318c91 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -313,6 +313,8 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	/* Set required struct page fields. */
 	page = virt_to_page(meta->addr);
 	page->slab_cache = cache;
+	if (IS_ENABLED(CONFIG_SLAB))
+		page->s_mem = addr;
 
 	raw_spin_unlock_irqrestore(&meta->lock, flags);
 
diff --git a/mm/slab.c b/mm/slab.c
index b1113561b98b..a1c2809731c6 100644
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
@@ -3208,7 +3209,7 @@ static void *____cache_alloc_node(struct kmem_cache *cachep, gfp_t flags,
 }
 
 static __always_inline void *
-slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
+slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid, size_t orig_size,
 		   unsigned long caller)
 {
 	unsigned long save_flags;
@@ -3221,6 +3222,10 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
 	if (unlikely(!cachep))
 		return NULL;
 
+	ptr = kfence_alloc(cachep, orig_size, flags);
+	if (unlikely(ptr))
+		goto out_hooks;
+
 	cache_alloc_debugcheck_before(cachep, flags);
 	local_irq_save(save_flags);
 
@@ -3253,6 +3258,7 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
 	if (unlikely(slab_want_init_on_alloc(flags, cachep)) && ptr)
 		memset(ptr, 0, cachep->object_size);
 
+out_hooks:
 	slab_post_alloc_hook(cachep, objcg, flags, 1, &ptr);
 	return ptr;
 }
@@ -3290,7 +3296,7 @@ __do_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
 #endif /* CONFIG_NUMA */
 
 static __always_inline void *
-slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
+slab_alloc(struct kmem_cache *cachep, gfp_t flags, size_t orig_size, unsigned long caller)
 {
 	unsigned long save_flags;
 	void *objp;
@@ -3301,6 +3307,10 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
 	if (unlikely(!cachep))
 		return NULL;
 
+	objp = kfence_alloc(cachep, orig_size, flags);
+	if (unlikely(objp))
+		goto out;
+
 	cache_alloc_debugcheck_before(cachep, flags);
 	local_irq_save(save_flags);
 	objp = __do_cache_alloc(cachep, flags);
@@ -3311,6 +3321,7 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
 	if (unlikely(slab_want_init_on_alloc(flags, cachep)) && objp)
 		memset(objp, 0, cachep->object_size);
 
+out:
 	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp);
 	return objp;
 }
@@ -3416,6 +3427,12 @@ static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
 static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
 					 unsigned long caller)
 {
+	if (is_kfence_address(objp)) {
+		kmemleak_free_recursive(objp, cachep->flags);
+		__kfence_free(objp);
+		return;
+	}
+
 	/* Put the object into the quarantine, don't touch it for now. */
 	if (kasan_slab_free(cachep, objp, _RET_IP_))
 		return;
@@ -3481,7 +3498,7 @@ void ___cache_free(struct kmem_cache *cachep, void *objp,
  */
 void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
 {
-	void *ret = slab_alloc(cachep, flags, _RET_IP_);
+	void *ret = slab_alloc(cachep, flags, cachep->object_size, _RET_IP_);
 
 	trace_kmem_cache_alloc(_RET_IP_, ret,
 			       cachep->object_size, cachep->size, flags);
@@ -3514,7 +3531,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 
 	local_irq_disable();
 	for (i = 0; i < size; i++) {
-		void *objp = __do_cache_alloc(s, flags);
+		void *objp = kfence_alloc(s, s->object_size, flags) ?: __do_cache_alloc(s, flags);
 
 		if (unlikely(!objp))
 			goto error;
@@ -3547,7 +3564,7 @@ kmem_cache_alloc_trace(struct kmem_cache *cachep, gfp_t flags, size_t size)
 {
 	void *ret;
 
-	ret = slab_alloc(cachep, flags, _RET_IP_);
+	ret = slab_alloc(cachep, flags, size, _RET_IP_);
 
 	ret = kasan_kmalloc(cachep, ret, size, flags);
 	trace_kmalloc(_RET_IP_, ret,
@@ -3573,7 +3590,7 @@ EXPORT_SYMBOL(kmem_cache_alloc_trace);
  */
 void *kmem_cache_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid)
 {
-	void *ret = slab_alloc_node(cachep, flags, nodeid, _RET_IP_);
+	void *ret = slab_alloc_node(cachep, flags, nodeid, cachep->object_size, _RET_IP_);
 
 	trace_kmem_cache_alloc_node(_RET_IP_, ret,
 				    cachep->object_size, cachep->size,
@@ -3591,7 +3608,7 @@ void *kmem_cache_alloc_node_trace(struct kmem_cache *cachep,
 {
 	void *ret;
 
-	ret = slab_alloc_node(cachep, flags, nodeid, _RET_IP_);
+	ret = slab_alloc_node(cachep, flags, nodeid, size, _RET_IP_);
 
 	ret = kasan_kmalloc(cachep, ret, size, flags);
 	trace_kmalloc_node(_RET_IP_, ret,
@@ -3652,7 +3669,7 @@ static __always_inline void *__do_kmalloc(size_t size, gfp_t flags,
 	cachep = kmalloc_slab(size, flags);
 	if (unlikely(ZERO_OR_NULL_PTR(cachep)))
 		return cachep;
-	ret = slab_alloc(cachep, flags, caller);
+	ret = slab_alloc(cachep, flags, size, caller);
 
 	ret = kasan_kmalloc(cachep, ret, size, flags);
 	trace_kmalloc(caller, ret,
@@ -4151,7 +4168,10 @@ void __check_heap_object(const void *ptr, unsigned long n, struct page *page,
 	BUG_ON(objnr >= cachep->num);
 
 	/* Find offset within object. */
-	offset = ptr - index_to_obj(cachep, page, objnr) - obj_offset(cachep);
+	if (is_kfence_address(ptr))
+		offset = ptr - kfence_object_start(ptr);
+	else
+		offset = ptr - index_to_obj(cachep, page, objnr) - obj_offset(cachep);
 
 	/* Allow address range falling entirely within usercopy region. */
 	if (offset >= cachep->useroffset &&
diff --git a/mm/slab_common.c b/mm/slab_common.c
index f9ccd5dc13f3..13125773dae2 100644
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
@@ -435,6 +436,7 @@ static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work)
 	rcu_barrier();
 
 	list_for_each_entry_safe(s, s2, &to_destroy, list) {
+		kfence_shutdown_cache(s);
 #ifdef SLAB_SUPPORTS_SYSFS
 		sysfs_slab_release(s);
 #else
@@ -460,6 +462,7 @@ static int shutdown_cache(struct kmem_cache *s)
 		list_add_tail(&s->list, &slab_caches_to_rcu_destroy);
 		schedule_work(&slab_caches_to_rcu_destroy_work);
 	} else {
+		kfence_shutdown_cache(s);
 #ifdef SLAB_SUPPORTS_SYSFS
 		sysfs_slab_unlink(s);
 		sysfs_slab_release(s);
@@ -1171,7 +1174,7 @@ size_t ksize(const void *objp)
 	if (unlikely(ZERO_OR_NULL_PTR(objp)) || !__kasan_check_read(objp, 1))
 		return 0;
 
-	size = __ksize(objp);
+	size = kfence_ksize(objp) ?: __ksize(objp);
 	/*
 	 * We assume that ksize callers could use whole allocated area,
 	 * so we need to unpoison this area.
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201103175841.3495947-5-elver%40google.com.
