Return-Path: <kasan-dev+bncBAABBAPZ77EQMGQEJLDFDLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id A334ACBDC07
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 13:18:10 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-47788165c97sf4682885e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 04:18:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765801090; cv=pass;
        d=google.com; s=arc-20240605;
        b=VDGu5wZr/sDQEv+g6URiscmtqlyZuezuc3RgVnxxx//rlbyBnVjLlo792AIVZMIbJy
         z7OI+aVzHqCnK4JORiGGn4EETQTh7ls5qr6WiUuWU3kV1ZUziPPPLFtWDORLz1R+LU4l
         2XzEcN5JCgdMObgsAMrv2UASxWPfiszgVkSIabbhwb1IGXLLQ46kqgjaMFdiSVv5IS7Q
         v71OGp3SkPOAHqQ+0jvSlHVkYZzmL+V1/oYCqOyisjGaIV8qND2+rEPhl7V4ju9zp/KF
         NjoAvQ2BBJ7MR/pR9Gx7HSIe7Gvr1C15YMnU9rvsEafoYdvAG5nFD3Kbae3CYLLTxi3O
         rYqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=jHb1f3icJjQMFPuvVPZQp87FSmdhPidOyjz1bAxWk/Q=;
        fh=KBpluoSsyA85InmmXi/SbrLwVyWOktfg1Ph70BE0D3Q=;
        b=I9V63n1gRn8UaMXFW/YcpPcTm/Yhdr07RthHXm2ADIj31p87DXISsv5FEaWelT34my
         nB5nyvHFenPzSj5kdW5Hm3RnHXKHUBF8lUWqY2AcSNyYVbrH9BnkV6FaxytZXkSD9KwL
         35jNzP3P8F2NbnN9/VCKgtFSrMix4XmYbK2uFzPd8a5ry8Jxi7QWzKHhg5ddIHaipC+3
         oepQv+/N+HJ/3NtcdhoyunyPpuKD9UsYF6EVjrCxvGrLuKS82FJ9LBDkwOmQTXur89PE
         5/B6SBr/VjL+byexWjMT/oO4vWfVKXe3LyPNfREc4KV0JvbQAeyXC6lxOlXiXkihTh41
         VGHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=OpOHNmeb;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::b3 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765801090; x=1766405890; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jHb1f3icJjQMFPuvVPZQp87FSmdhPidOyjz1bAxWk/Q=;
        b=dKJ1T1Mxl93bRR58IFa2vKN60IYVZFaMyHt6ldZGcDmP3OmGkVInsqjOpI5ZX9gNSf
         jD5R8tGZy+m+G+bNTAqf6R4A1gQ9dFkifTCnCtDoqUQzE4EtgMzK91zeKUjZiRDpyZoM
         aKnJOjX9kXidqx/UDnFipN0cFFeGiuYoLXpmGx10Rx0wYN4shwD10N2TYE6+jUniq/yy
         qK8lDFiYdgKo2sfGpHaqvEFerq1rMIvp43f0UvdZ3SkjGe84iWiOT3yGTzZt73RkaxQr
         5sCTIeo6eSTGTo/vbbbLP6xQXF01zE324rckHB3P/BpjA2oHLhETsuPk22BjUSgwHQ57
         GJkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765801090; x=1766405890;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jHb1f3icJjQMFPuvVPZQp87FSmdhPidOyjz1bAxWk/Q=;
        b=nBuzHv655g66r3QAXYs5rtbDusHAgsZ+44QODpwqr9iPLnsDxE8XfWojbJDSnkCk8F
         Sw1W2h7rRr3Et7PjXPJ6juCUlGJ1wB/17obi9OiPNlxQ6zbUonp8yVfNVQH8jvxweojW
         epk74Xx5BkJyPAzKYzbq1OXFJjQ6NQ2YJyD+eEFKltTCNe+vpdG5/1qg8lXPLQP8dMZZ
         BP730NvR6ISGmWSvomkPxTam+BoCTlGz8/fD1JjJukAhrgyEybN3mCu2dT3P6CveUTmx
         NqISesGmgM/E1Nx9lV9fdF58tHI0Udk/xxsG3NklUhejMetl6P9sh+k/CHtiTh8Qww6n
         IBJw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWmFRzpkmaNxetS4zMQHXccnLRQXhAbZPiHn9/bou+eoGDYGD0fcIdiI2k9mmQ6QXStlTpzzg==@lfdr.de
X-Gm-Message-State: AOJu0YwmK406UPr6J7/vWODB/q3iAiDq0vv3KOB7AMr9wO4rFAjYMKXU
	pQyEFR7PHKnquGqKj1EeWKTrKFE8KPnoZPRLrTUDGc8cVeWGRx7XH74L
X-Google-Smtp-Source: AGHT+IEbSJvdAuw8ntLCUQkR3vkzH0CPHa27VIs41vmN6RL7cFd6c46ljP6tYnA8Gsg81/OumRKo+g==
X-Received: by 2002:a05:600c:350c:b0:471:9da:524c with SMTP id 5b1f17b1804b1-47a8f8c15c1mr115596375e9.12.1765801089715;
        Mon, 15 Dec 2025 04:18:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbgac/YSNKCOCNvUlyBAKZsLtUeNcZHeEEgTQFcIPiJKg=="
Received: by 2002:a05:600c:1c15:b0:477:59d9:8ccf with SMTP id
 5b1f17b1804b1-47a8ea5b24bls27653145e9.1.-pod-prod-01-eu; Mon, 15 Dec 2025
 04:18:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWBRgrsPM4DwcH6NWGC0RYIIfMjOQBINGnLOAr9UDXvoJ2/AYuI9BjwGPmc+Kn/c/lY8jodb5fbkps=@googlegroups.com
X-Received: by 2002:a05:600c:444a:b0:479:3876:22a8 with SMTP id 5b1f17b1804b1-47a8f8c2e5cmr123893775e9.16.1765801087548;
        Mon, 15 Dec 2025 04:18:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765801087; cv=none;
        d=google.com; s=arc-20240605;
        b=h35pNNgv7dEQGrJMFXdXbhruHAhSMmqaSB/LCoIH8EcALD+NH9s0f59+VBRJTW0iuN
         LDFIDQqNSe9QYBC8gIIQ7/Md1KWcB9ei6jmS4dEWQ/BQEVFEwRedF9vnOZR3KNRh1Kq7
         N44TLc/FOSUmy/iUmscLFjHEfitXGqHTyFs24Yvy4+B2KFk4xS6HYhKtLQ98ya9SrsmZ
         EmEKsshqPTbtSTaAEbNojROgmMmXEWQLegySnQntR+yOldJfZPKsSgJmokY+9z/LliJr
         IsU4cBVf6MjqmVZ1fTVRKHwWdedLXRRgUtT62q8+DK1kW4WOarOj7ooyD7gFfAjv+2te
         bRNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=hQyowvHu09ybpNC76sRIKOM8wjKkC+jHN9wA1E3FUh4=;
        fh=UxK0f7Sg+Kvncwz8/Gj/XfKMLaSYI6WylwLy90nXgxM=;
        b=TlMtp1aJjsFlEsCxpLm2DvpE2pazvRwmUr5/iT7aGcd3f1KDCcwftAKq7zobAVVb5Z
         jxWFzL0bYx9yOOEaY+pvj9VSGVaQGo8NfsS3X+zrQSIJGs/0xZ9+tB/rbBb2Lo4wX8cx
         HcBA1HdRHi/US9fs4+CbwPTK9ZgS80bRc+z39dGIIntq9dQ0mguZ5SFQspR464aRgQ7z
         OnWbOV3MHBBBrkJ9Nh79G8SttW1YyDKImPJuIeNJCsiUisiCe2cm5P7ZwEPHOl5kWzac
         EmRswWleEBxKwdMFFW8Ko0NF2liBZXi/K4YF39Aicw+qh9JfLhq1coVRA+Y7ELD2q51S
         /yCA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=OpOHNmeb;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::b3 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-179.mta1.migadu.com (out-179.mta1.migadu.com. [2001:41d0:203:375::b3])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47a8f4d0635si1615185e9.2.2025.12.15.04.18.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 04:18:07 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::b3 as permitted sender) client-ip=2001:41d0:203:375::b3;
Date: Mon, 15 Dec 2025 20:17:10 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH RFC 06/19] slab: introduce percpu sheaves bootstrap
Message-ID: <ct5pjdx3k4sxw5qjuzs7rsblkxpkah3qdx6kbhe2oeuaontaii@fwgb6ovi36zj>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-6-6ffa2c9941c0@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251023-sheaves-for-all-v1-6-6ffa2c9941c0@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=OpOHNmeb;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::b3 as
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

On Thu, Oct 23, 2025 at 03:52:28PM +0200, Vlastimil Babka wrote:
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
>  mm/slub.c | 96 ++++++++++++++++++++++++++++++++++++++++++++++-----------------
>  1 file changed, 70 insertions(+), 26 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index a6e58d3708f4..ecb10ed5acfe 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2850,6 +2850,10 @@ static void pcs_destroy(struct kmem_cache *s)
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
> @@ -4054,7 +4058,7 @@ static void flush_cpu_slab(struct work_struct *w)
>  
>  	s = sfw->s;
>  
> -	if (s->cpu_sheaves)
> +	if (s->sheaf_capacity)
>  		pcs_flush_all(s);
>  
>  	flush_this_cpu_slab(s);
> @@ -4176,7 +4180,7 @@ static int slub_cpu_dead(unsigned int cpu)
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
> @@ -5162,6 +5172,11 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
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
> @@ -5241,8 +5256,7 @@ static __fastpath_inline void *slab_alloc_node(struct kmem_cache *s, struct list
>  	if (unlikely(object))
>  		goto out;
>  
> -	if (s->cpu_sheaves)
> -		object = alloc_from_pcs(s, gfpflags, node);
> +	object = alloc_from_pcs(s, gfpflags, node);
>  
>  	if (!object)
>  		object = __slab_alloc_node(s, gfpflags, node, addr, orig_size);
> @@ -6042,6 +6056,12 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
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
> @@ -6240,6 +6260,12 @@ bool __kfree_rcu_sheaf(struct kmem_cache *s, void *obj)
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
> @@ -6364,6 +6390,9 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
>  	if (likely(pcs->main->size < s->sheaf_capacity))
>  		goto do_free;
>  
> +	if (unlikely(!s->sheaf_capacity))
> +		goto no_empty;
> +
>  	barn = get_barn(s);
>  	if (!barn)
>  		goto no_empty;
> @@ -6628,9 +6657,8 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
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
> @@ -7437,8 +7465,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
>  		size--;
>  	}
>  
> -	if (s->cpu_sheaves)
> -		i = alloc_from_pcs_bulk(s, size, p);
> +	i = alloc_from_pcs_bulk(s, size, p);
>  
>  	if (i < size) {
>  		/*
> @@ -7649,6 +7676,7 @@ static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
>  
>  static int init_percpu_sheaves(struct kmem_cache *s)
>  {
> +	static struct slab_sheaf bootstrap_sheaf = {};
>  	int cpu;
>  
>  	for_each_possible_cpu(cpu) {
> @@ -7658,7 +7686,28 @@ static int init_percpu_sheaves(struct kmem_cache *s)
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
> @@ -7733,8 +7782,7 @@ static void free_kmem_cache_nodes(struct kmem_cache *s)
>  void __kmem_cache_release(struct kmem_cache *s)
>  {
>  	cache_random_seq_destroy(s);
> -	if (s->cpu_sheaves)
> -		pcs_destroy(s);
> +	pcs_destroy(s);
>  #ifdef CONFIG_PREEMPT_RT
>  	if (s->cpu_slab)
>  		lockdep_unregister_key(&s->lock_key);
> @@ -7756,7 +7804,7 @@ static int init_kmem_cache_nodes(struct kmem_cache *s)
>  			continue;
>  		}
>  
> -		if (s->cpu_sheaves) {
> +		if (s->sheaf_capacity) {
>  			barn = kmalloc_node(sizeof(*barn), GFP_KERNEL, node);
>  
>  			if (!barn)
> @@ -8074,7 +8122,7 @@ int __kmem_cache_shutdown(struct kmem_cache *s)
>  	flush_all_cpus_locked(s);
>  
>  	/* we might have rcu sheaves in flight */
> -	if (s->cpu_sheaves)
> +	if (s->sheaf_capacity)
>  		rcu_barrier();
>  
>  	/* Attempt to free all objects */
> @@ -8375,7 +8423,7 @@ static int slab_mem_going_online_callback(int nid)
>  		if (get_node(s, nid))
>  			continue;
>  
> -		if (s->cpu_sheaves) {
> +		if (s->sheaf_capacity) {
>  			barn = kmalloc_node(sizeof(*barn), GFP_KERNEL, nid);
>  
>  			if (!barn) {
> @@ -8608,12 +8656,10 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
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

After this change, all SLUB caches enable cpu_sheaves; therefore,
slab_unmergeable() will always return 1.

int slab_unmergeable(struct kmem_cache *s)
{
...
	if (s->cpu_sheaves)
		return 1;
...
}

Maybe we need to update slab_unmergeable() accordingly..

> +	if (!s->cpu_sheaves) {
> +		err = -ENOMEM;
> +		goto out;
>  	}
>  
>  #ifdef CONFIG_NUMA
> @@ -8632,11 +8678,9 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
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
> 2.51.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ct5pjdx3k4sxw5qjuzs7rsblkxpkah3qdx6kbhe2oeuaontaii%40fwgb6ovi36zj.
