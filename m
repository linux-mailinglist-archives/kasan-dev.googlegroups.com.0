Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRP7QL5QKGQEI4WWQ2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AFF826A629
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 15:21:10 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id l26sf1159037wmg.7
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 06:21:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600176070; cv=pass;
        d=google.com; s=arc-20160816;
        b=E77BRBkqr1gHYN4uxEBscQSDrlQPMuOmgT+QPlbW58O5BAL2kfueQSwFBTtlcFDJQf
         L2NOTVDPdtFE/uBfqngjM/BqFL06/8MnxNZzYpGTf9a4u/MT4IoACBBBDADiOHxksVGT
         EfhnszlvLfjxj0AAlQz1par2hsJvdLQBEsUS2QsOZi0VvpoqDRwOsWSGTXxA6hqOlREw
         72dUxPr/9GbUwPg0AZt1/ZzIqDqnnuOKAPIWVzBcRISB0nukbIoSWSnbalg1cl/Tk7YA
         dsf0/v6P9DaK8wM6J3i2/soQcluRYVg1YvHNiwppG+BguieCc24bJv5Kf4hho2MnJmnz
         t2aA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=pkN9hYPccxbVWZ/yL/iQJmfXKdxKuvzVlBq3WcdkrJM=;
        b=byXNG2e5EPKIBfFFv4hLx8KNErr3h7MhIIpm9t8BlB0E9trNc9qTjvtzgetN1L4Nuh
         viC99UjoYaZEtDtj6rCsC/IsCNRaPZBBtQoNW5CrxIAJHDK8x4V4L3DjgTA/XPC5xAI8
         WQ8jlNJkJRrqO4NIhSGrFIGz63IvxGs/dKwr/LW4s78GSt306u1ZvZfpQQS/1RDgFI3x
         ltCWNJYFJ+iS0jAQ9VwnYnkdKA/hkXltUuyKOWcY9hF2cezeJmQYa0IM6K3LlYqV3dPh
         69WeiV3etjzSYhBBdgGs2pejO9u46+D/bqRDYikGok7SjTJlPD78HT/6hbig8Eggg2qV
         D4hw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NpaUC7cf;
       spf=pass (google.com: domain of 3xl9gxwukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3xL9gXwUKCccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pkN9hYPccxbVWZ/yL/iQJmfXKdxKuvzVlBq3WcdkrJM=;
        b=H3btHN0Sg43US/g1+t3tuVfrn2c/ZvbH9L7ctMmjGD8VUkUW593k5ruJgzCLZXNc4E
         aDRuHWh/J9CnUhBM3nBWSIWKcLi2AaP0XDKzY+WGadllh0Rq6WJ9OxzLWdFz7MrX8TYt
         EuTvvy6SUYm4XcF3avyb3Qo55HMqwjlen5SLKWSWiUvU40uTxGdjRiLrykUF8sva3UJd
         WDHggbWfN6/w3kBiluDB1kdHHrL/yayavuqos24xr+7RETLZdL8RG8tKWDfBA+xjuKk6
         4QgMoFBjz4U9BmxnllVAgWnd5m0llg185+Y2W1WRCT+cE6etiMVI8BwYyeXEZqfsP9pI
         E7hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pkN9hYPccxbVWZ/yL/iQJmfXKdxKuvzVlBq3WcdkrJM=;
        b=GKitN4WIs+X8jnUbkBG3BqT56AGYviQT02eyLn9jCixZd0mChjJgTjJ1DnJJwXZoKC
         Xzs5kTk7KWqLzNTnlUdpSJDvdw5baAekYiNh5gQHoEny2VVaVMOb0SGO2lMym+FteHqc
         h6rSqGCKHyyEauEB5J7dGKw6tDmL74KuknpfdkIAMJm03bKqqEC6PzC3dvH1GID/V6Kq
         pWSErozfUoUZTdIRWYWq3qvZqjPrtewmSbYa9GiatXLXlXt43ed3Aq/9T0LKhiCLUVmA
         QKzcVoKsOVZ7Il4c/Ww0wgMkFJXYVBapelz6WqJhzdXilNsnHdKc19XTiEiDyluxLSkI
         q7Dg==
X-Gm-Message-State: AOAM5320hNb0gPw3NwoC6naZLeGFQwL9dgcPqEOl3I/OjPxafm8gnbJ5
	Z1G/jzFQmamT2e0iRm3Ek38=
X-Google-Smtp-Source: ABdhPJz07MfGFgzndwdgrQvxROVppcnVwS82rDemf6QKcMxCBZPrKBV9xiiDNUx0b1ZiMiw1H+If+g==
X-Received: by 2002:a1c:4885:: with SMTP id v127mr5022657wma.129.1600176069906;
        Tue, 15 Sep 2020 06:21:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:428e:: with SMTP id k14ls1820610wrq.0.gmail; Tue, 15 Sep
 2020 06:21:09 -0700 (PDT)
X-Received: by 2002:adf:ded0:: with SMTP id i16mr22793502wrn.372.1600176068907;
        Tue, 15 Sep 2020 06:21:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600176068; cv=none;
        d=google.com; s=arc-20160816;
        b=C3WfJUUtRADeADRs7nB8WQaBAXPJuIfT/sMM3oSDJP+M4tJvZ84hIEAfO/nVpUWodU
         gr7EfMT6YKqcNrap3Wa3Rr4LFkrxYiZKib/ymhLM0apLFs5UXpz5sc+7UxCtJX+AsS7x
         1vl/+2YkHJR/eWXMVj0Z/605hsiiHkTDuLjMy78lFXkHZXAS4xynGM5PI02e999kA2xd
         h/mYRWYJiR7z/z5yg6u1fbIQgYvzKh9LfgF42Su0dwYDcswIM2V6AsXb+fgNDXSCO7oA
         cVXa/ZVnE1efLvGzi8UnPF7V4zCT1g9sw9curb7XL9Ltsd9Yj7G9U6iEixMkpIi6tIm9
         ErAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=xuqVHa2SvjiSIGMIomiVLdoP1dWqddUAsUtVImDYYgU=;
        b=rwhPQFoTm5SMaLpbRHvTE8AAME2Ay5rbFMSYivT4pKOX4HUjD5h/p8dAi98ts6oxvX
         1EQE6vacAGkof8lS6E6eI2qJL4sLxv/ajf8DZ2cISGZk031gmSQl8qU+Arp0tb+4mA1E
         XdQpQkgMcTRLM1m+3UaHmha9+ZN2u3Q/ORZJARGSZUT8IP/MqyrmjCBt+64BL33kAx6h
         tOzSHkr201ahyJq82ixFM02gDQV78FAzYdXSkJ+NKoyQzKCwnzksCtr/38AvDmAb0jcV
         GrcSuL2JdMG165y8uGxTJNiiqx7c5RaTl+TTseGa+MkwoZ5F1xPfAukfbloTnMOL6QKP
         ZLBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NpaUC7cf;
       spf=pass (google.com: domain of 3xl9gxwukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3xL9gXwUKCccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id z17si321717wrm.2.2020.09.15.06.21.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 06:21:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xl9gxwukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id a7so899079wmc.2
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 06:21:08 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a7b:c958:: with SMTP id i24mr4957022wml.50.1600176068261;
 Tue, 15 Sep 2020 06:21:08 -0700 (PDT)
Date: Tue, 15 Sep 2020 15:20:40 +0200
In-Reply-To: <20200915132046.3332537-1-elver@google.com>
Message-Id: <20200915132046.3332537-5-elver@google.com>
Mime-Version: 1.0
References: <20200915132046.3332537-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 04/10] mm, kfence: insert KFENCE hooks for SLAB
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, mingo@redhat.com, jannh@google.com, 
	Jonathan.Cameron@huawei.com, corbet@lwn.net, iamjoonsoo.kim@lge.com, 
	keescook@chromium.org, mark.rutland@arm.com, penberg@kernel.org, 
	peterz@infradead.org, cai@lca.pw, tglx@linutronix.de, vbabka@suse.cz, 
	will@kernel.org, x86@kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NpaUC7cf;       spf=pass
 (google.com: domain of 3xl9gxwukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3xL9gXwUKCccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
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

We note the addition of the 'orig_size' argument to slab_alloc*()
functions, to be able to pass the originally requested size to KFENCE.
When KFENCE is disabled, there is no additional overhead, since these
functions are __always_inline.

Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
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
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200915132046.3332537-5-elver%40google.com.
