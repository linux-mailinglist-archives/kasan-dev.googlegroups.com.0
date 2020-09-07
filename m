Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAHR3D5AKGQEPCO4C3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id E7A7125FB8F
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Sep 2020 15:41:20 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id l15sf5717108wro.10
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Sep 2020 06:41:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599486080; cv=pass;
        d=google.com; s=arc-20160816;
        b=0cixjgMc+LhvLkj61EJi8g2lfILDBuEJ6j58nUnTYw/Ucn+dMOMbBfF0/nKLP7RiqH
         v84g9y6qpd1lnPAUDtg3xDUhkTsg7TgXFNJBu2xv37Ja+2USZoWGyTv5yY0BSVWXJ1a+
         41uAWfFqSLM0jG9lcaVsOVnGcrrEPGO+BgWPKcTRXOuWbWgLY1oyZDjmMDJp84yzARUN
         WGTFgLvRzKX9NTdTJ6G1F23CS+KTpjor0LH0D42SOXIEX6xJPHyBqkqdS6pFe7MCP9yA
         eCMqbWQ4wk61NwSqVUD+/lj7ZS3w7ycWRQJORuFLrlcqwRWXENvrVFEr2NJVu1Hlpwfa
         CcBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=yCwktGTv5HTKVAJzqhd8yhNTDa+vB8winqD1hmWTWuk=;
        b=SbrOteZEl2CW2c1qLjjcZsSKHcSLpaQXeFuzGOslb8UVEDGnY0zj0+FA0vaY5u1rzE
         aLH+J4DKmmj1AY3nVfU/Ar5DINlt70xV3qrUa5W7pQLjyOtk4fiCSuMrLizLjDbx4Cvd
         CIfekzC3rFSgSLnRq70DMugETmvy1IjvEYSQjEcPQndnj9KPT3J05GycoMrn0rM0JSeB
         TfvY+X8YKkKTBhBMK+TRdbYFuw7hC4cOMyta4cO8h1f6ATXpnRnaHWuw0zeTxbdAXFlB
         ZyVNX+FOk877NYd5LIecPo3nQ0g7QT4jtrk2pt+ey1nCZ0XRCBqToW/FlGIUu3YUPG9d
         NbYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dfD49eVp;
       spf=pass (google.com: domain of 3fzhwxwukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3fzhWXwUKCUoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yCwktGTv5HTKVAJzqhd8yhNTDa+vB8winqD1hmWTWuk=;
        b=ZCNIf0AjqNNWqY7rnmFO+WGOHyt9lmJgi6Vm7fWU/y9FdrjIUJhSoqRReVSeWAxfQm
         4gvdjM5xbi/Ss2uAVrSK6GgfuVZs6oxz6DS72ktaMWUWvWKq9NjR0xiPOBFlzNmxFCYZ
         87AH30DSP8HbxBtBYf83yqyv1Eiu2LMGGJ6VrRUS+5mhnYaGm5e02TT58zVqGNcqfOJL
         FlKZuhv4AkbLlCteSErOTzkAJkOO1ZHyolpczZ0USXilYHZqu1mqhDxfqcC1hKZiRzcW
         P9S8zsittiSqxXgbQuQlax2Ojmyu65k817YwWpl2cNkcQ0ofcNsa8H0gztlI7RD0HIlA
         T9IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yCwktGTv5HTKVAJzqhd8yhNTDa+vB8winqD1hmWTWuk=;
        b=delwY8iwqRB/62V6440ieEwyxZwJSkRthU9eLNENKd2WmLfKCQzpPj5g9+220itm1G
         wo1WivK3rmGL9V1bWAJTWSg7tFdlQUNWt3QZDMb9Q961xXAfliYkh4Si0TzYzSBPd+Wu
         JXUAPpJjnafijB1DQZdyjRu5jfr05DLQLpvBcgCJrcxROQCrc/YdlevArb4sv5TTs49V
         9Qbjc4VZlL6tOpFtotLrR2MGSI+BfCkXpQxyjlCULyLDGWVp8MSN5xCIuheEXXuLTXXd
         SdsGTN0hwaVBMby6p7QvplmFbIGOtTqn5SyGZGrCORmI8xA4FFyTA5xHeICudItGXnr4
         5CpQ==
X-Gm-Message-State: AOAM530mzSrzOC657FdBuZNQ+YzTZslmVZNmJttgIRVzmmcafHp1cgrt
	GIhFgtHdPGHxWRz+vqIQQYs=
X-Google-Smtp-Source: ABdhPJwRlix73aOSyaG/MI+gRtbzPy4zyPncsScrAcAX9eqLQihHWKgP04tfedq6MRrv9vzZnnXPew==
X-Received: by 2002:a05:600c:20c:: with SMTP id 12mr21990992wmi.40.1599486080656;
        Mon, 07 Sep 2020 06:41:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:8288:: with SMTP id 8ls9976617wrc.0.gmail; Mon, 07 Sep
 2020 06:41:20 -0700 (PDT)
X-Received: by 2002:adf:82d5:: with SMTP id 79mr17788968wrc.60.1599486079958;
        Mon, 07 Sep 2020 06:41:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599486079; cv=none;
        d=google.com; s=arc-20160816;
        b=skJUCW/rjuKpjYahijglsS6k2sI56R+gg0oHqntAULKcQJzfJI/d0WGVGlu4y9vJJG
         ir+51mVTBOhXjBl4ojqIUUNgbt+MDfGtycULMthWCUK9CBCYVZFW2wzCGyUF2hvCT4hU
         Lkk9PWOMD7ujv/3gb4To3s4GzrBBINnOEur+sbrqrfDNFPmrRbXVlJrOvZtxsdn9jUif
         y7HosPJlGbVDQJzsyC4pkPMtuPIdMbBJRMgFlcqchhw6eIocZOOM4/hMDYaKbwARJQwd
         owOceGLnk2LX+6wLMlyB+RBQ/VMxX+0ej3U0DHtuhKWA7kGxLqe0zmflLJAvqKlv1GfT
         Q7Sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=x+CjtF59NZE8bZw9mYHQnFyw/O2zIlLpBZPgIBAJqdU=;
        b=EMjlPgE9k0GpfQud8MBCUtWbJjYcYteT3GRLwGaMWZli0f7QqM62JoQo96TxODjjyb
         QVOK4KwJylGtSx5jU6tvw4iMA+G5KnEZ6FW9WsiNlyu/aEz5l+lUxCKuMR5fPbDv3vwr
         l0/swEG4irln9h5LavvVdBwepkruQDa8vDGDci7IPlrAAxbINrplu2bU7BApr7lgGkkE
         1K7FINLXIuKF/9/FXRf2cLKA41Jd1W1FUFltg2aZ3aLUBdj1IL4BMisC4VvOxGFP0fi+
         DWZ3PJiS8XluYr49GiSdSnqHZfIzMIXx2WYYcAg6T6opuHg9XHpMGdaF9/IMSR5cYi+/
         Iweg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dfD49eVp;
       spf=pass (google.com: domain of 3fzhwxwukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3fzhWXwUKCUoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id z62si144328wmb.0.2020.09.07.06.41.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Sep 2020 06:41:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fzhwxwukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id d5so2868226wmb.2
        for <kasan-dev@googlegroups.com>; Mon, 07 Sep 2020 06:41:19 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a1c:2b43:: with SMTP id r64mr20462623wmr.105.1599486079475;
 Mon, 07 Sep 2020 06:41:19 -0700 (PDT)
Date: Mon,  7 Sep 2020 15:40:49 +0200
In-Reply-To: <20200907134055.2878499-1-elver@google.com>
Message-Id: <20200907134055.2878499-5-elver@google.com>
Mime-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.526.ge36021eeef-goog
Subject: [PATCH RFC 04/10] mm, kfence: insert KFENCE hooks for SLAB
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, glider@google.com, akpm@linux-foundation.org, 
	catalin.marinas@arm.com, cl@linux.com, rientjes@google.com, 
	iamjoonsoo.kim@lge.com, mark.rutland@arm.com, penberg@kernel.org
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	dave.hansen@linux.intel.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, mingo@redhat.com, jannh@google.com, 
	corbet@lwn.net, keescook@chromium.org, peterz@infradead.org, cai@lca.pw, 
	tglx@linutronix.de, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dfD49eVp;       spf=pass
 (google.com: domain of 3fzhwxwukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3fzhWXwUKCUoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
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
2.28.0.526.ge36021eeef-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200907134055.2878499-5-elver%40google.com.
