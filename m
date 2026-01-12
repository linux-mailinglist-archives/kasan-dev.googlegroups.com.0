Return-Path: <kasan-dev+bncBDXYDPH3S4OBB5VASTFQMGQEQX3X6ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 998FAD138E6
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:11 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-430fd96b440sf3318729f8f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231031; cv=pass;
        d=google.com; s=arc-20240605;
        b=fwQIzN2ImoK9uzGyfoBagfIsKQf0rbhSumtUZyWfLAbSYKo3EqzRlYZ0dzXb6czG2H
         yYRzpsjuvu7jX9chavFVvxYbsdjODgqO9OBdN2RstyWLgO9WaReCFInmFePtUWo0pi/4
         CfwyW5QKJvxVWQf+JJhrHlNIwClQfh/Rp6O5H4/v+D0wj4qVjcY8uhuqg9Vq60p35un8
         hcy1u4mnv9hDD69kVD9P3Be1bjCif4fgqge2BOQRKgKGH7V6KDxSWytgOwZBnSXVWVlX
         bs8ITnDsz1vGFe0spPIpKv1LdGOh3FnGegRpr6nk4iIvapBMH3XvnEQU1moS/wzud7Og
         lNoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=vcKGvlzwr2zy4ALwLKEvU8MiGuLD6ArV69VQb7/47to=;
        fh=/Rw9yO/RCOR8WCtYrE5TUZN9aFeVWK4OPfUXyH+NQ3s=;
        b=jBH2A7V1w4AjaQHUUbNOj/ZMOp6oC1aCprSUygd52hxCrSDHo26yOw8l1iKwweWdvW
         1nUatyXeHbRzb0H1A8om+PVaeFu367CQw9QE1RNS6YzLR9ulEAvOkhdJyXAJH8TU1iYX
         +uV7RllGgFoMT3upsB7M5joNzQoJGLU81KEixIMoU9f26ccoNGatZMgRYacKFPCxM+lj
         fv1cx2G4f6A9xupLk/aH5lWUGkmUu3yOUbyNVZQQGbteGlBYzSta80FRxjDeL2OGbH0K
         mThvjQ1mYoEWDqQ7Lwjkl0DVavtJMLMK6tWu8DQAHRNY8GZBYQoOuwidsn6aDYWnBW5x
         G/GA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231031; x=1768835831; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vcKGvlzwr2zy4ALwLKEvU8MiGuLD6ArV69VQb7/47to=;
        b=XLiB+9YpWYhAVbVSKVg0XvfMRfCYf3a9axz1TE6fsnE5U5/Hl+PNOE+YArzqRCVeSS
         YwT9g+uX/XYSvAK1Hba9snShwEDAG7UezLmgJBbTsIbVnwkxoe+ZXBy3hxxugrpyR5Gc
         aaKQgiONamTYhCg9Jt41AXwofigZpGwwRZjXMrbaV2L8y7WMyUXardXbUuO8xoMAARVB
         pYqMJdZPzk46NVjrTBpEoY+1JXSYntlILa5d4q5dQPIBt2iolM+bsMV2CjPh0ZyMCTOS
         wXqBOfd37TT9GTr7tpqmBWYRywLDuGS5U8dT8obM0aJZgoifmwVqNgw1L4n01MVc8jYi
         xGBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231031; x=1768835831;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vcKGvlzwr2zy4ALwLKEvU8MiGuLD6ArV69VQb7/47to=;
        b=Wrt2v6pdz0wV5Lh0IVSVVLPB4Gm2+2QU+XASseVoMhP8NudKXvgPs/eW0XTwogycG2
         tUeGURIXCYbyM2WY4nIiTWzXE033rwh8SNen1KpDlDySVTbzaqS6+DD9+BEdp4X1boe6
         +er1ENVi+MRDa8bOC8Es1ccWCkfkMkoaM8y9bdWi+tqnnk5TucDWNG5eF6+fblujQraU
         DQEetODssaMs45Nr0WWE3P7+W029uB7dz8vDD9RLk8yQlMWDHoc6MsMvuJItx51WNtJR
         liu/zF1YuhOEIOQlHhYx6P9wYIJzjMXQYs9aLqOrpAD2xXHOPa9MMfuJh3YlFfcyNYRs
         cxvg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWua9teYVd0mwTNtEcP/dhrKjMZWgfN/jeUApjZNoGfx5nmhiY20Oa2EurxcP/PUnWvPDw6oQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyat8YeOrfvMWWTbD4SZiTOO8EPYFT+0VH6BHMkIe+gy3EzGo2+
	XSFzGy3lEu0bovN+n4SL8uY1sBY6+kxWuSOWbMxVaWqzdfr5Zoz03mvC
X-Google-Smtp-Source: AGHT+IE+lJNFldPVK82UHX9Dod8KPQasjVt6l5LC39CEcOW8ciUNqAisp2zlzJK73t688z74sXPKCg==
X-Received: by 2002:a5d:5f44:0:b0:430:f6c0:6c5e with SMTP id ffacd0b85a97d-432c364491dmr23229494f8f.28.1768231030648;
        Mon, 12 Jan 2026 07:17:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EiAHNjuexPSmMF+kvqlvDS08GJuv+YMY53ymYM/Syg0g=="
Received: by 2002:a05:6000:220e:b0:432:a9ed:a3f7 with SMTP id
 ffacd0b85a97d-432bc91897dls4720837f8f.1.-pod-prod-04-eu; Mon, 12 Jan 2026
 07:17:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWbihNk/pHjIVDlwimBe+AZ2Vp3/FhmaDDxfq50z+lzR6Kw4shoCmFUxxCLD1ajT4U8TGxFihABUBI=@googlegroups.com
X-Received: by 2002:a05:6000:25c4:b0:430:f463:b6ae with SMTP id ffacd0b85a97d-432c3765660mr23791354f8f.53.1768231028232;
        Mon, 12 Jan 2026 07:17:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231028; cv=none;
        d=google.com; s=arc-20240605;
        b=RapJ8+WJ798Jqq+N8nlH8Wty7sBjl+MHOlmpJpbLyg9JJyJbUdFBjzpPp9CqdCVJZf
         2eDE+c1oLcKTXQ9Vcx+zQ7kECX0hy298g9vnBybh9ma9CLIW5yur0+RHoXRjfVkSVtoG
         oZbXITk+r8Bw74JoyV8eW9r8BowC09TqPJflB4qdurRyVwu+JqwLxScLcWjm+/VxUpFf
         JJJM/fY+2FncN1MDXzhd6tnkW7nMNQRJ/DHmVW3R8BqNomWVaMGLHoPAfNcIjTgSHfbk
         XhqWXr4HhMpPx6UdANOtXWmJqgJbGQMgm3XGDgV+zPqz95CMZ2EJN/0m0D3fNsJ0W8cf
         6z5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=OQQWFCCqLJYSi9mdAmkwY3nVbna00VNAu91kGrXYEgA=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=cHwJP2GC1W6r8/CdsNOO9t1Kf+xWZfIz4Gimv9tDUCsSkbkNqNWXu/N8cfKFX3qOqO
         tvItbN83F5R1o70xR+bSezDy86LiyvOpgoZpWg0VJSdKEq9zUPD0C3ilbDc4TSCg05nJ
         I+Nw2GGtw9PByYC9ywNtiHquqpRFSOYjvJvCQ55ApT0osiLBB0QNSd20X1FxobcGRg5Z
         4GR7WXYawsic3WDeg0dDCNVAMe7rfWZx/OoUgdzKcyLWKfZoc4fAO7UJ1xQ32WxBGQhB
         sLg3bFN3OYKYJGuFcrA6GAYcz5+V8iQRu1dN0YetcpPWMOjtxmyukJmqb7X2nl3g1Pxg
         +Slw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-432c1a50ad8si286757f8f.2.2026.01.12.07.17.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:17:08 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id F33715BCD0;
	Mon, 12 Jan 2026 15:16:57 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id D5D803EA63;
	Mon, 12 Jan 2026 15:16:57 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 0Em3M2kQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:57 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 12 Jan 2026 16:16:59 +0100
Subject: [PATCH RFC v2 05/20] slab: introduce percpu sheaves bootstrap
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260112-sheaves-for-all-v2-5-98225cfb50cf@suse.cz>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
In-Reply-To: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
To: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>
Cc: Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
 Uladzislau Rezki <urezki@gmail.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, 
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
 bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.3
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Spam-Score: -4.00
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: F33715BCD0
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Level: 
X-Spamd-Result: default: False [-4.00 / 50.00];
	REPLY(-4.00)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

Until now, kmem_cache->cpu_sheaves was !NULL only for caches with
sheaves enabled. Since we want to enable them for almost all caches,
it's suboptimal to test the pointer in the fast paths, so instead
allocate it for all caches in do_kmem_cache_create(). Instead of testing
the cpu_sheaves pointer to recognize caches (yet) without sheaves, test
kmem_cache->sheaf_capacity for being 0, where needed.

However, for the fast paths sake we also assume that the main sheaf
always exists (pcs->main is !NULL), and during bootstrap we cannot
allocate sheaves yet.

Solve this by introducing a single static bootstrap_sheaf that's
assigned as pcs->main during bootstrap. It has a size of 0, so during
allocations, the fast path will find it's empty. Since the size of 0
matches sheaf_capacity of 0, the freeing fast paths will find it's
"full". In the slow path handlers, we check sheaf_capacity to recognize
that the cache doesn't (yet) have real sheaves, and fall back. Thus
sharing the single bootstrap sheaf like this for multiple caches and
cpus is safe.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 93 ++++++++++++++++++++++++++++++++++++++++++++++-----------------
 1 file changed, 69 insertions(+), 24 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 6e05e3cc5c49..06d5cf794403 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2855,6 +2855,10 @@ static void pcs_destroy(struct kmem_cache *s)
 		if (!pcs->main)
 			continue;
 
+		/* bootstrap or debug caches, it's the bootstrap_sheaf */
+		if (!pcs->main->cache)
+			continue;
+
 		/*
 		 * We have already passed __kmem_cache_shutdown() so everything
 		 * was flushed and there should be no objects allocated from
@@ -4052,7 +4056,7 @@ static void flush_cpu_slab(struct work_struct *w)
 
 	s = sfw->s;
 
-	if (s->cpu_sheaves)
+	if (s->sheaf_capacity)
 		pcs_flush_all(s);
 
 	flush_this_cpu_slab(s);
@@ -4179,7 +4183,7 @@ static int slub_cpu_dead(unsigned int cpu)
 	mutex_lock(&slab_mutex);
 	list_for_each_entry(s, &slab_caches, list) {
 		__flush_cpu_slab(s, cpu);
-		if (s->cpu_sheaves)
+		if (s->sheaf_capacity)
 			__pcs_flush_all_cpu(s, cpu);
 	}
 	mutex_unlock(&slab_mutex);
@@ -4979,6 +4983,12 @@ __pcs_replace_empty_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
 
 	lockdep_assert_held(this_cpu_ptr(&s->cpu_sheaves->lock));
 
+	/* Bootstrap or debug cache, back off */
+	if (unlikely(!s->sheaf_capacity)) {
+		local_unlock(&s->cpu_sheaves->lock);
+		return NULL;
+	}
+
 	if (pcs->spare && pcs->spare->size > 0) {
 		swap(pcs->main, pcs->spare);
 		return pcs;
@@ -5165,6 +5175,11 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 		struct slab_sheaf *full;
 		struct node_barn *barn;
 
+		if (unlikely(!s->sheaf_capacity)) {
+			local_unlock(&s->cpu_sheaves->lock);
+			return allocated;
+		}
+
 		if (pcs->spare && pcs->spare->size > 0) {
 			swap(pcs->main, pcs->spare);
 			goto do_alloc;
@@ -5244,8 +5259,7 @@ static __fastpath_inline void *slab_alloc_node(struct kmem_cache *s, struct list
 	if (unlikely(object))
 		goto out;
 
-	if (s->cpu_sheaves)
-		object = alloc_from_pcs(s, gfpflags, node);
+	object = alloc_from_pcs(s, gfpflags, node);
 
 	if (!object)
 		object = __slab_alloc_node(s, gfpflags, node, addr, orig_size);
@@ -6078,6 +6092,12 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
 restart:
 	lockdep_assert_held(this_cpu_ptr(&s->cpu_sheaves->lock));
 
+	/* Bootstrap or debug cache, back off */
+	if (unlikely(!s->sheaf_capacity)) {
+		local_unlock(&s->cpu_sheaves->lock);
+		return NULL;
+	}
+
 	barn = get_barn(s);
 	if (!barn) {
 		local_unlock(&s->cpu_sheaves->lock);
@@ -6276,6 +6296,12 @@ bool __kfree_rcu_sheaf(struct kmem_cache *s, void *obj)
 		struct slab_sheaf *empty;
 		struct node_barn *barn;
 
+		/* Bootstrap or debug cache, fall back */
+		if (!unlikely(s->sheaf_capacity)) {
+			local_unlock(&s->cpu_sheaves->lock);
+			goto fail;
+		}
+
 		if (pcs->spare && pcs->spare->size == 0) {
 			pcs->rcu_free = pcs->spare;
 			pcs->spare = NULL;
@@ -6401,6 +6427,9 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
 	if (likely(pcs->main->size < s->sheaf_capacity))
 		goto do_free;
 
+	if (unlikely(!s->sheaf_capacity))
+		goto no_empty;
+
 	barn = get_barn(s);
 	if (!barn)
 		goto no_empty;
@@ -6668,9 +6697,8 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
 	if (unlikely(!slab_free_hook(s, object, slab_want_init_on_free(s), false)))
 		return;
 
-	if (s->cpu_sheaves && likely(!IS_ENABLED(CONFIG_NUMA) ||
-				     slab_nid(slab) == numa_mem_id())
-			   && likely(!slab_test_pfmemalloc(slab))) {
+	if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) == numa_mem_id())
+	    && likely(!slab_test_pfmemalloc(slab))) {
 		if (likely(free_to_pcs(s, object)))
 			return;
 	}
@@ -7484,8 +7512,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
 		size--;
 	}
 
-	if (s->cpu_sheaves)
-		i = alloc_from_pcs_bulk(s, size, p);
+	i = alloc_from_pcs_bulk(s, size, p);
 
 	if (i < size) {
 		/*
@@ -7696,6 +7723,7 @@ static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
 
 static int init_percpu_sheaves(struct kmem_cache *s)
 {
+	static struct slab_sheaf bootstrap_sheaf = {};
 	int cpu;
 
 	for_each_possible_cpu(cpu) {
@@ -7705,7 +7733,28 @@ static int init_percpu_sheaves(struct kmem_cache *s)
 
 		local_trylock_init(&pcs->lock);
 
-		pcs->main = alloc_empty_sheaf(s, GFP_KERNEL);
+		/*
+		 * Bootstrap sheaf has zero size so fast-path allocation fails.
+		 * It has also size == s->sheaf_capacity, so fast-path free
+		 * fails. In the slow paths we recognize the situation by
+		 * checking s->sheaf_capacity. This allows fast paths to assume
+		 * s->pcs_sheaves and pcs->main always exists and is valid.
+		 * It's also safe to share the single static bootstrap_sheaf
+		 * with zero-sized objects array as it's never modified.
+		 *
+		 * bootstrap_sheaf also has NULL pointer to kmem_cache so we
+		 * recognize it and not attempt to free it when destroying the
+		 * cache
+		 *
+		 * We keep bootstrap_sheaf for kmem_cache and kmem_cache_node,
+		 * caches with debug enabled, and all caches with SLUB_TINY.
+		 * For kmalloc caches it's used temporarily during the initial
+		 * bootstrap.
+		 */
+		if (!s->sheaf_capacity)
+			pcs->main = &bootstrap_sheaf;
+		else
+			pcs->main = alloc_empty_sheaf(s, GFP_KERNEL);
 
 		if (!pcs->main)
 			return -ENOMEM;
@@ -7803,7 +7852,7 @@ static int init_kmem_cache_nodes(struct kmem_cache *s)
 			continue;
 		}
 
-		if (s->cpu_sheaves) {
+		if (s->sheaf_capacity) {
 			barn = kmalloc_node(sizeof(*barn), GFP_KERNEL, node);
 
 			if (!barn)
@@ -8121,7 +8170,7 @@ int __kmem_cache_shutdown(struct kmem_cache *s)
 	flush_all_cpus_locked(s);
 
 	/* we might have rcu sheaves in flight */
-	if (s->cpu_sheaves)
+	if (s->sheaf_capacity)
 		rcu_barrier();
 
 	/* Attempt to free all objects */
@@ -8433,7 +8482,7 @@ static int slab_mem_going_online_callback(int nid)
 		if (get_node(s, nid))
 			continue;
 
-		if (s->cpu_sheaves) {
+		if (s->sheaf_capacity) {
 			barn = kmalloc_node(sizeof(*barn), GFP_KERNEL, nid);
 
 			if (!barn) {
@@ -8641,12 +8690,10 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
 
 	set_cpu_partial(s);
 
-	if (s->sheaf_capacity) {
-		s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
-		if (!s->cpu_sheaves) {
-			err = -ENOMEM;
-			goto out;
-		}
+	s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
+	if (!s->cpu_sheaves) {
+		err = -ENOMEM;
+		goto out;
 	}
 
 #ifdef CONFIG_NUMA
@@ -8665,11 +8712,9 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
 	if (!alloc_kmem_cache_cpus(s))
 		goto out;
 
-	if (s->cpu_sheaves) {
-		err = init_percpu_sheaves(s);
-		if (err)
-			goto out;
-	}
+	err = init_percpu_sheaves(s);
+	if (err)
+		goto out;
 
 	err = 0;
 

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-5-98225cfb50cf%40suse.cz.
