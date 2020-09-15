Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR77QL5QKGQEI2THIKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id BC27726A62B
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 15:21:12 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id h20sf1447661oou.8
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 06:21:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600176071; cv=pass;
        d=google.com; s=arc-20160816;
        b=m0bwc6NTeuTDboxhIpXMJLAmzL2qs8YPhSIJ7neGAvS2xBemVEU9b2zW0ANo03zudN
         ITDEbwhX8FEw3C9FME8o+DzteRFnKiqUKrH8hoMpXFcvSfJi6NKAsuZ+BbCh2Vec8mBb
         O7ErvEW3pVJRqSl3buUEwG+5FqP+W6ERBENeRXolg3nR0Ql69iaMkHGpFS/Dgl5vtBmG
         G2R+w4ea7qmVL3kWdHNLZ4Lkhxylo0JjDJL8jePxyMyTEaAJNylYb+4yJYOGshnnamsJ
         rKcFZkImI/ZJqTljn60G+/6qO+k3U236PgiHHunq3jrJjAIQziSgWITWpxFhPUl5+A19
         dOtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=6AgOM+p6QLneDkg+7mtXWH2ll1dpjhq0zzNBBBv11Vs=;
        b=Wr9b7jNd+A81SPp42Hor2gzmAKn+Xqp8Px9tTZhlinzZq3eF6ITn4pgIM/A6g3e8+o
         Saqj7B2vLXdMQ+kkEZ/xx8gqv8QHQLMXe5KHIWKq/Tuys9OuvYZWji6KYo4Shw6zj5ZE
         AUDuUscTVGOq7fgmBshxNT7kFlv7a9YOaOvVjBMpp0NuVs1Dib2yQj4Yq9xLROYs+4rQ
         Qj97PIeWU1LDYko2CSQozOYVvVoavD1ISISOoYrlB6iU5H4J+GQ+jC0zx9qDjB20W1Go
         P8qMSDOpFTj6k2qJJGGnQ13G3D0X5nPklxmFBBpIom1MUAgo/K29yi41vK5C/FgynMQN
         K+Yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VVoCZeGx;
       spf=pass (google.com: domain of 3xr9gxwukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3xr9gXwUKCckt0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6AgOM+p6QLneDkg+7mtXWH2ll1dpjhq0zzNBBBv11Vs=;
        b=Yg5pwmpDs90vvqjjqKUYRY3StZLjFSMU6Pg3xgOePTdl6jZTw27fiLAASu4uA/5vps
         pOzhpY0bINo0WyyzFSPB3/LlSSd7BGwKeO2ZfRThUhnnxpSRQe650oJczNXOpohvIr73
         6I8bNZVhqkmxdlAV5lEpm8G38frd7DNt9qJKEOWQL6CY8h5CRMA+XY55KD0J+mdFiW9S
         MO5MnUqfUI+WzYvFHwbZKYZUMD907simAgvSmgY6oNk/6E9/dZ/4y1y0HjDHltwp/HSc
         yoLucawcmkxTl5LXSAh3ROSP9IRHOStYRLUJLmDVKHYXsVx6WI0dbZC1dNaHK1GRsEBV
         9rUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6AgOM+p6QLneDkg+7mtXWH2ll1dpjhq0zzNBBBv11Vs=;
        b=tfUn/iiv3aRTXYvPwHij68GCNK5RpuAc6cMTAp/c543dNEjA3BdiKo1hZncB6a0ZdJ
         8JAGpodepVd6eYTLxR2qqIE1gTzi81DvAdILsasxS9dkmF9fi1xrJh9YF/MqFz4wjoZy
         U4RMJprD03uxkBOg/looxIZfVoGmcu8digWc3S1fLEBCx5GAYWEcjVAw+8WJmDuAaDPA
         nU3gK6+aNX5iTrFg7nLTI5tfTx/Lu2eUGTdzl+9tlnZsl7ydhSYYUArJjhPOUPQaLyzU
         EKfNI7+hTVVadfMB8NxhQEsZX3NCjKxTPCT2lTcKZjVJ8WaUe5aDErIZUB2a6ld29xjb
         7Uww==
X-Gm-Message-State: AOAM5333bXVEaOyclJCRC9ondJ/43GxlIjCjHpTSXlC132DjyOGFFP8L
	cwhwXvJ5Oqm5+YEOFDfCEpw=
X-Google-Smtp-Source: ABdhPJy4i6BM+Ip/iSCdnjGgPbLmjnCwwgwVsjoxXObI8+2ks3fzfn/G84ZZ7f9pZwaJLTjD+QZjzg==
X-Received: by 2002:a9d:7dd8:: with SMTP id k24mr13333348otn.160.1600176071723;
        Tue, 15 Sep 2020 06:21:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9413:: with SMTP id h19ls761388ooi.2.gmail; Tue, 15 Sep
 2020 06:21:11 -0700 (PDT)
X-Received: by 2002:a4a:c909:: with SMTP id v9mr13981720ooq.43.1600176071343;
        Tue, 15 Sep 2020 06:21:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600176071; cv=none;
        d=google.com; s=arc-20160816;
        b=UlKUBiHY4T8VwxPhQgm70Besyfc3AiOeOJjAsIkLbcyz7CcnCYFQpKToNZ4D+7XvVX
         jgJO72lU09wdIc0S9czf21u/2g9VzKxiXjgGxIWXQASRh3reYlWoDIaLTTpbbq5oCteo
         02v555pUU+G/NLnF7pohrQsf5zH9GvUGSkbV8B5HvD5FixgEdcKZS0Tz3U/nY6PWQOcl
         d1q6g1iFNFjzalYiooS8Vi4Bi8Wp8TAM2I1CU3jCYeSNH/l/Hp0KwRU3s8HmDGAhnX+t
         kfe8v45K+fM3aBXpAQNfh/KvrHJBTScvR1jrmM4p1NvK0ZbG7pcxoyxNudkbS8jmk82J
         p30g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=fU9Sjzqs02icRSCqZS/ebIy9db/XO0okTCR+PIM2AsY=;
        b=CoNDYMq1AR6oEmZogkg++A3rHh9X8MDV92XzgepB835pInhNO3ZzZYj8YuhhUXJU4o
         XKFGeJR77LF312SFmp+iUcUcS01hO5rcAju66XdpE4tl0NkZ025RAVioGVj3zl9PGleL
         chrmYQ1H7e76hH6xyQ4uM83dFZiLFWh2UOE5U7jVR9XZz5mlrjgY+fgHQPc8jlAFu9gl
         qbJaKmOwfFPBLh6QlftTfTrB/BP3qiZBNEq8/D3HXzf9u7Uhy0zxzh+NowGj50R/CxL8
         qg7U966eeQuYJJrPP3zqoX70TswY8+jy+/igfAOPHQMEhCDzw8/7CiSMUT5gN4s7KPYg
         H4sg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VVoCZeGx;
       spf=pass (google.com: domain of 3xr9gxwukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3xr9gXwUKCckt0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id t74si969977oot.1.2020.09.15.06.21.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 06:21:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xr9gxwukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id p13so1683910ybe.4
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 06:21:11 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a25:e643:: with SMTP id d64mr26403934ybh.431.1600176070730;
 Tue, 15 Sep 2020 06:21:10 -0700 (PDT)
Date: Tue, 15 Sep 2020 15:20:41 +0200
In-Reply-To: <20200915132046.3332537-1-elver@google.com>
Message-Id: <20200915132046.3332537-6-elver@google.com>
Mime-Version: 1.0
References: <20200915132046.3332537-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 05/10] mm, kfence: insert KFENCE hooks for SLUB
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
 header.i=@google.com header.s=20161025 header.b=VVoCZeGx;       spf=pass
 (google.com: domain of 3xr9gxwukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3xr9gXwUKCckt0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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

We note the addition of the 'orig_size' argument to slab_alloc*()
functions, to be able to pass the originally requested size to KFENCE.
When KFENCE is disabled, there is no additional overhead, since these
functions are __always_inline.

Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
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
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200915132046.3332537-6-elver%40google.com.
