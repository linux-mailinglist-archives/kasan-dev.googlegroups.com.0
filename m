Return-Path: <kasan-dev+bncBAABB276TDFQMGQE4EUWS6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id E62B1D18E92
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 13:49:48 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-430fdaba167sf3785705f8f.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 04:49:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768308588; cv=pass;
        d=google.com; s=arc-20240605;
        b=eJ+mG8scTnfc0QGlktClFeRVQoVzFRH5Cm+1A4lkt49rMm8xOc5Lf1oWEOTaLhi1Jj
         JRSb/Q36v49wHLwTwJ2+K9auZu+kSBu7683aR75QaAW8ONsC78yP5bzeRPK4wNX4BOI8
         /ERqiZXiLNdUYN74zEPQDWKeNuTRtU1hxhL8m5RPK+uVGnjMhrCgx21dO54DsjI4E8OG
         dtwk8Hcy4wC82Hgr6Nvt1RqVMbW5HiiEZYU1TJTwbQm9QQnq50mMSZM3QT8iHdRMJQBs
         TX9qhTw5fegyXIeyeo3cOUfOa2DjfiMB/RZBJAxpAarncoWYRaCF5ilzEwy41fGGBso/
         qfIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6cnLGjYveb7hTFMXbE0Hji28hA9brZ+ep1Z4/gpQvlg=;
        fh=68cRHvcfaiHUARDddymK6dVljq7epUnuZ9hc8G0fT8k=;
        b=KMNDV0ZNqpel7JOdoaOWL9ALVem9Rkxu9jDoEyE+HpEIIyvkbc+8PCpW55n8ym45aW
         dnprQM66wEPoGdbiJfGESst7KcK9PaNzTF8qYs2mBQuZUTqMpKVk6xG3B4cA3/zfnH96
         IJ6cswtEUSA5SoXPv7GhAAft9R70nwfP7MBrrdxO74BHxFKReRgL8EJ3szHWN7lIVINW
         cr8RC1SUQb25zgFSPmfmhBgQdbJSvdAigXh1pQpEoamJzOjCl4RNTbQeStwkjFXEqqgg
         tsAypaf4XV04GtVZbGUthYQcunLx+PaazjfNGuADpLuwJlBpq5csd6jRG/IZjp8JFXAw
         knTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jLU6Ree+;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::ba as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768308588; x=1768913388; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6cnLGjYveb7hTFMXbE0Hji28hA9brZ+ep1Z4/gpQvlg=;
        b=RQbLyFPftgjEGdtxd/7gshYo8lgwiDkI8OLbQ0GbAgIvknnmIJjTDdlV5jivfq0id/
         fib7uJ1yeZgxsY+y6hgLdjj/rbROCGyjHODEEx/cNCR9jlMwcPKFvR6p3NODUYlZlsCm
         DvqGYC60FMB0wrXtijBU5aHcC+l2+L4Br0DOzC5RSFJDDe9rBfXymypwN/+KcKlLqaoi
         K52BfuvwJmXjR2MVkGtsZ2qeFx7nGGXNXT683RgyNMVt3yuXqxRk98ELiS6kW7iaTPmi
         NYCoqXm2t1vBDenze0q0Ckw6BK0PAfJjSBoF6sJeH0T6+GOTi5ZEkKR/jSqea8lvx+HH
         WvLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768308588; x=1768913388;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6cnLGjYveb7hTFMXbE0Hji28hA9brZ+ep1Z4/gpQvlg=;
        b=afSLH12xE6rOkTYN12InvT5Jj1h7OBUQl+Q7PvCKVFd/ixD4smeHOFV840PeH4LFDJ
         Ag34hrMMEhJVWIDwpaY/xDZFc00J9NlNueGUS7JzoWywI4EpwhL87s2NM+Mg0Zb5Lmzy
         GgYmrolchtIP2UN+i6aKYhv2P0L7iHZvUBekrDbNo34WQ22DGfX+jydCo+5y4IoVAd56
         ywyEHOnZr8OZvAhakR8pniy8DRPy8a8weCmVRY5w9DfUeOUyzHD8L0i3LunZmtS1m6CB
         qMwJ7zEa2CQVVEoWgIXaH5HbrZg++z3WJ29+QPsZ+/LYeSJBWelMUXXPPpdyX8+rckpd
         Fl/g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXFJrDIhB1Xj4TWA85oJSyE5pXU+nY8oiLA0owaPMmCe0Yeet/zivMye3y3Rg0keHdRsl4xLg==@lfdr.de
X-Gm-Message-State: AOJu0Yxt0/I4tCDE0F+rO76dIRV/S7IXpxDnOOfoHGTOKfFNmaOTq/ib
	zXcB+AeLKi/EmO20zkA5QomS2PwENmYZP/sLbS3Vezo4rjqZIeqHITAj
X-Google-Smtp-Source: AGHT+IH3D1eds1ZLQ11DZnzKxPetPFqHhF1iSJIAUuKtqMpEjb/Xvn1/bBRNzZ+tvZzxd7ublOjdxw==
X-Received: by 2002:a05:600c:a10a:b0:47d:92bb:2723 with SMTP id 5b1f17b1804b1-47d92bb28a9mr122455215e9.3.1768308588239;
        Tue, 13 Jan 2026 04:49:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F6WhSz/yUPWy98SxgM5dVGjJoin86HOhr1HzFl7C2uJw=="
Received: by 2002:a05:600c:1f16:b0:477:a036:8e7b with SMTP id
 5b1f17b1804b1-47d7eab68a0ls47836555e9.0.-pod-prod-01-eu; Tue, 13 Jan 2026
 04:49:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXgHx4nVj5GrfBT//SvAr4U8R4eVyGUobhCb5OagdDg9zq7oTSghJ0OAtE/6CNHTnafU+2KOj8HnVQ=@googlegroups.com
X-Received: by 2002:a05:600c:450f:b0:479:3a89:121e with SMTP id 5b1f17b1804b1-47d84b614c6mr222934315e9.37.1768308586164;
        Tue, 13 Jan 2026 04:49:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768308586; cv=none;
        d=google.com; s=arc-20240605;
        b=K+XXZK2hkrTKLPHX4uGErDyY+nMtc3yiDsvYdpJV2UdA3gtx38QE9lEEpn8aCGkN44
         VQhxVoeS1tIhmMzagIL3K0BH7tYDJsu64hIMN6fG8E06swbQkOF+UyNvZOgnC6wtTEpI
         VWiZPnVR44WJ8UfZMhEy9NJbmTxBbohd9AeXVi/k8J9YYEB/kk1EoahaL9uHwu1oVNeg
         GT+EjVbk9cCgKShqFXp5SVQXGSbomCnkH3o5HHviitvG0mcGFKzToE4tkpGiCjjDBp3f
         5bRnnccFqcoshvxFYsEvhVimZDqrSpwYU+OlaeIhxkIb0Imnc2BqgmyPhy+sa1aXpCv4
         F4OA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=sXIxaaUrGFoA3E6hwhyauqFe+XDhkHXUkgt2L3qneUY=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=kdMDJzIvTCo7qZM2f/jfRBBwnxHpefbTDQXZn+TbvvIzuJN1GanjAGWFxyO+FWcd9n
         QQW3HVSQLhoA27JrN51petIm7ISJKGqD67n2mFsGlqphotpanSWDx1AJ40O1eWI5E9Zl
         HfrXXRwvP+0d/gEKjLt+Pq+EqAflvELSKKuwUui8akwQIObNlxjBFBvyDXvSl9T55wT0
         dzdNJhCXje9pf4dbgQlbuEB98ZkOQynfVWpcVkBtOdswQznrWS+EbEB3UJeiwM/cENK/
         KbwVgX6zx80YdP4N+Ol9guBHXQ6zG7yOsO4HwLU+NBPW9uv8UqtBc+VZwl+HmwVUdBiK
         tKsA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jLU6Ree+;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::ba as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-186.mta0.migadu.com (out-186.mta0.migadu.com. [2001:41d0:1004:224b::ba])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47ee0b488e1si535e9.0.2026.01.13.04.49.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 04:49:46 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::ba as permitted sender) client-ip=2001:41d0:1004:224b::ba;
Date: Tue, 13 Jan 2026 20:49:33 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH RFC v2 05/20] slab: introduce percpu sheaves bootstrap
Message-ID: <leaboap7yhlnvuxnxvqtl5kazbseimfq3efwfhaon74glfmmc3@paib6qlfee3i>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-5-98225cfb50cf@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260112-sheaves-for-all-v2-5-98225cfb50cf@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=jLU6Ree+;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::ba as
 permitted sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=linux.dev
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

On Mon, Jan 12, 2026 at 04:16:59PM +0100, Vlastimil Babka wrote:
> Until now, kmem_cache->cpu_sheaves was !NULL only for caches with
> sheaves enabled. Since we want to enable them for almost all caches,
> it's suboptimal to test the pointer in the fast paths, so instead
> allocate it for all caches in do_kmem_cache_create(). Instead of testing
> the cpu_sheaves pointer to recognize caches (yet) without sheaves, test
> kmem_cache->sheaf_capacity for being 0, where needed.
> 
> However, for the fast paths sake we also assume that the main sheaf
> always exists (pcs->main is !NULL), and during bootstrap we cannot
> allocate sheaves yet.
> 
> Solve this by introducing a single static bootstrap_sheaf that's
> assigned as pcs->main during bootstrap. It has a size of 0, so during
> allocations, the fast path will find it's empty. Since the size of 0
> matches sheaf_capacity of 0, the freeing fast paths will find it's
> "full". In the slow path handlers, we check sheaf_capacity to recognize
> that the cache doesn't (yet) have real sheaves, and fall back. Thus
> sharing the single bootstrap sheaf like this for multiple caches and
> cpus is safe.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 93 ++++++++++++++++++++++++++++++++++++++++++++++-----------------
>  1 file changed, 69 insertions(+), 24 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 6e05e3cc5c49..06d5cf794403 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2855,6 +2855,10 @@ static void pcs_destroy(struct kmem_cache *s)
>  		if (!pcs->main)
>  			continue;
>  
> +		/* bootstrap or debug caches, it's the bootstrap_sheaf */
> +		if (!pcs->main->cache)
> +			continue;
> +
>  		/*
>  		 * We have already passed __kmem_cache_shutdown() so everything
>  		 * was flushed and there should be no objects allocated from
> @@ -4052,7 +4056,7 @@ static void flush_cpu_slab(struct work_struct *w)
>  
>  	s = sfw->s;
>  
> -	if (s->cpu_sheaves)
> +	if (s->sheaf_capacity)
>  		pcs_flush_all(s);
>  
>  	flush_this_cpu_slab(s);
> @@ -4179,7 +4183,7 @@ static int slub_cpu_dead(unsigned int cpu)
>  	mutex_lock(&slab_mutex);
>  	list_for_each_entry(s, &slab_caches, list) {
>  		__flush_cpu_slab(s, cpu);
> -		if (s->cpu_sheaves)
> +		if (s->sheaf_capacity)
>  			__pcs_flush_all_cpu(s, cpu);
>  	}
>  	mutex_unlock(&slab_mutex);
> @@ -4979,6 +4983,12 @@ __pcs_replace_empty_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
>  
>  	lockdep_assert_held(this_cpu_ptr(&s->cpu_sheaves->lock));
>  
> +	/* Bootstrap or debug cache, back off */
> +	if (unlikely(!s->sheaf_capacity)) {
> +		local_unlock(&s->cpu_sheaves->lock);
> +		return NULL;
> +	}
> +
>  	if (pcs->spare && pcs->spare->size > 0) {
>  		swap(pcs->main, pcs->spare);
>  		return pcs;
> @@ -5165,6 +5175,11 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
>  		struct slab_sheaf *full;
>  		struct node_barn *barn;
>  
> +		if (unlikely(!s->sheaf_capacity)) {
> +			local_unlock(&s->cpu_sheaves->lock);
> +			return allocated;
> +		}
> +
>  		if (pcs->spare && pcs->spare->size > 0) {
>  			swap(pcs->main, pcs->spare);
>  			goto do_alloc;
> @@ -5244,8 +5259,7 @@ static __fastpath_inline void *slab_alloc_node(struct kmem_cache *s, struct list
>  	if (unlikely(object))
>  		goto out;
>  
> -	if (s->cpu_sheaves)
> -		object = alloc_from_pcs(s, gfpflags, node);
> +	object = alloc_from_pcs(s, gfpflags, node);
>  
>  	if (!object)
>  		object = __slab_alloc_node(s, gfpflags, node, addr, orig_size);
> @@ -6078,6 +6092,12 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>  restart:
>  	lockdep_assert_held(this_cpu_ptr(&s->cpu_sheaves->lock));
>  
> +	/* Bootstrap or debug cache, back off */
> +	if (unlikely(!s->sheaf_capacity)) {
> +		local_unlock(&s->cpu_sheaves->lock);
> +		return NULL;
> +	}
> +
>  	barn = get_barn(s);
>  	if (!barn) {
>  		local_unlock(&s->cpu_sheaves->lock);
> @@ -6276,6 +6296,12 @@ bool __kfree_rcu_sheaf(struct kmem_cache *s, void *obj)
>  		struct slab_sheaf *empty;
>  		struct node_barn *barn;
>  
> +		/* Bootstrap or debug cache, fall back */
> +		if (!unlikely(s->sheaf_capacity)) {
> +			local_unlock(&s->cpu_sheaves->lock);
> +			goto fail;
> +		}
> +
>  		if (pcs->spare && pcs->spare->size == 0) {
>  			pcs->rcu_free = pcs->spare;
>  			pcs->spare = NULL;
> @@ -6401,6 +6427,9 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
>  	if (likely(pcs->main->size < s->sheaf_capacity))
>  		goto do_free;
>  
> +	if (unlikely(!s->sheaf_capacity))
> +		goto no_empty;
> +
>  	barn = get_barn(s);
>  	if (!barn)
>  		goto no_empty;
> @@ -6668,9 +6697,8 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
>  	if (unlikely(!slab_free_hook(s, object, slab_want_init_on_free(s), false)))
>  		return;
>  
> -	if (s->cpu_sheaves && likely(!IS_ENABLED(CONFIG_NUMA) ||
> -				     slab_nid(slab) == numa_mem_id())
> -			   && likely(!slab_test_pfmemalloc(slab))) {
> +	if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) == numa_mem_id())
> +	    && likely(!slab_test_pfmemalloc(slab))) {
>  		if (likely(free_to_pcs(s, object)))
>  			return;
>  	}
> @@ -7484,8 +7512,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
>  		size--;
>  	}
>  
> -	if (s->cpu_sheaves)
> -		i = alloc_from_pcs_bulk(s, size, p);
> +	i = alloc_from_pcs_bulk(s, size, p);
>  
>  	if (i < size) {
>  		/*
> @@ -7696,6 +7723,7 @@ static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
>  
>  static int init_percpu_sheaves(struct kmem_cache *s)
>  {
> +	static struct slab_sheaf bootstrap_sheaf = {};
>  	int cpu;
>  
>  	for_each_possible_cpu(cpu) {
> @@ -7705,7 +7733,28 @@ static int init_percpu_sheaves(struct kmem_cache *s)
>  
>  		local_trylock_init(&pcs->lock);
>  
> -		pcs->main = alloc_empty_sheaf(s, GFP_KERNEL);
> +		/*
> +		 * Bootstrap sheaf has zero size so fast-path allocation fails.
> +		 * It has also size == s->sheaf_capacity, so fast-path free
> +		 * fails. In the slow paths we recognize the situation by
> +		 * checking s->sheaf_capacity. This allows fast paths to assume
> +		 * s->pcs_sheaves and pcs->main always exists and is valid.
> +		 * It's also safe to share the single static bootstrap_sheaf
> +		 * with zero-sized objects array as it's never modified.
> +		 *
> +		 * bootstrap_sheaf also has NULL pointer to kmem_cache so we
> +		 * recognize it and not attempt to free it when destroying the
> +		 * cache
> +		 *
> +		 * We keep bootstrap_sheaf for kmem_cache and kmem_cache_node,
> +		 * caches with debug enabled, and all caches with SLUB_TINY.
> +		 * For kmalloc caches it's used temporarily during the initial
> +		 * bootstrap.
> +		 */
> +		if (!s->sheaf_capacity)
> +			pcs->main = &bootstrap_sheaf;
> +		else
> +			pcs->main = alloc_empty_sheaf(s, GFP_KERNEL);
>  
>  		if (!pcs->main)
>  			return -ENOMEM;
> @@ -7803,7 +7852,7 @@ static int init_kmem_cache_nodes(struct kmem_cache *s)
>  			continue;
>  		}
>  
> -		if (s->cpu_sheaves) {
> +		if (s->sheaf_capacity) {
>  			barn = kmalloc_node(sizeof(*barn), GFP_KERNEL, node);
>  
>  			if (!barn)
> @@ -8121,7 +8170,7 @@ int __kmem_cache_shutdown(struct kmem_cache *s)
>  	flush_all_cpus_locked(s);
>  
>  	/* we might have rcu sheaves in flight */
> -	if (s->cpu_sheaves)
> +	if (s->sheaf_capacity)
>  		rcu_barrier();
>  
>  	/* Attempt to free all objects */
> @@ -8433,7 +8482,7 @@ static int slab_mem_going_online_callback(int nid)
>  		if (get_node(s, nid))
>  			continue;
>  
> -		if (s->cpu_sheaves) {
> +		if (s->sheaf_capacity) {
>  			barn = kmalloc_node(sizeof(*barn), GFP_KERNEL, nid);
>  
>  			if (!barn) {
> @@ -8641,12 +8690,10 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
>  
>  	set_cpu_partial(s);
>  
> -	if (s->sheaf_capacity) {
> -		s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
> -		if (!s->cpu_sheaves) {
> -			err = -ENOMEM;
> -			goto out;
> -		}
> +	s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);

Since we allocate cpu_sheaves for all SLUB caches, the "if (!s->cpu_sheaves)"
condition in has_pcs_used() should be always false in practice (unless I'm
misunderstanding something). Would it make sense to change it to "if
(!s->sheaf_capacity)" instead?

Also, while trying to understand the difference between checking s->cpu_sheaves
vs s->sheaf_capacity, I noticed that most occurrences of "if (s->cpu_sheaves)"
(except the one in __kmem_cache_release) could be expressed as "if
(s->sheaf_capacity)" as well.

And Perhaps we could introduce a small helper around "if (s->sheaf_capacity)" to
make the intent a bit more explicit.

-- 
Thanks,
Hao

> +	if (!s->cpu_sheaves) {
> +		err = -ENOMEM;
> +		goto out;
>  	}
>  
>  #ifdef CONFIG_NUMA
> @@ -8665,11 +8712,9 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
>  	if (!alloc_kmem_cache_cpus(s))
>  		goto out;
>  
> -	if (s->cpu_sheaves) {
> -		err = init_percpu_sheaves(s);
> -		if (err)
> -			goto out;
> -	}
> +	err = init_percpu_sheaves(s);
> +	if (err)
> +		goto out;
>  
>  	err = 0;
>  
> 
> -- 
> 2.52.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/leaboap7yhlnvuxnxvqtl5kazbseimfq3efwfhaon74glfmmc3%40paib6qlfee3i.
