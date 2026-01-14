Return-Path: <kasan-dev+bncBAABBQHFTTFQMGQERL4YNII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id A395ED1CA25
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 07:08:02 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-59b6f3890e4sf6529120e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 22:08:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768370882; cv=pass;
        d=google.com; s=arc-20240605;
        b=dSwJsBkUF9uXcMC3hR2dWy/pJSUh9j9oZ3bEXyYHW8l8tqT8WX0/LJC3JOeSKACEFN
         giXOQcEwh32dxtPjoItKaLXPdpng2TnPpJpDrLL4YlaIUfkuElQtMHi+pcq9GGAxyJIi
         KTTWbKG1JI3XB0KFC+AiP+ffQeq3ZvGzA9mWuJU9phNFQ7CtU9krXIJeavV8Ul70gIL9
         tMDAmA+IZn9VzLR8ev2+ZcEiVzz4XfrEmgt/03ceTQu3qV743ZHK0dA1vU3JJLbZIfM0
         83FnNtEFRWv5BtnGR/nmdmmCRSuPmGrY6RpFgAUsnb6LAm2Xr+K5aXrercHPEmhUZJdb
         6MdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=FqooFhttAkqHcWqOKLsEII9sHRemlnM574mw8KNTnKU=;
        fh=vlXP0GNSxYZAgfv3PxRKJ4qmPojOkuFuQRoQYEBQ1H0=;
        b=kNY5Zkx51kvG/3wVkx+a0poxUK4oZ7JPD+DA36Ry6h3L7Huh0G7U0D+i5yNndnfU8Z
         DKWbbAFPCYbFWr8GM6h79/DYPrLJ4epDgR2PS83dUoWcJYwwQaaK2nekqk6IfN2fGu2k
         Dy3Sg4ZiOP4gU21RvJc6e6SYkzmVyBUFuQfexd9J9crFgs4R6ZDboLFPYbs4dwgdLh7X
         G2y4EdiGN61VD4wdm6p04VH2Y3TMJMCdyQC9i1QJ4+eddthI7S2lR/EBqr3XOhs/jnkG
         6sRh23L1bb64znPiVkjhfiM8C5Be2Vc/fF7ZijrgeYd4f/9bLPpfI+xfr4u6c+CScTv3
         rpAw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=aocnKVEZ;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768370882; x=1768975682; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FqooFhttAkqHcWqOKLsEII9sHRemlnM574mw8KNTnKU=;
        b=NORPJ4xvvOF6t4M895Sp0dWeAQvMZpRdZwHbVkNXgAAZIoO2AlgWxXzEgXA4PebqQe
         ODmawRW0QbD8XllWyJNqfsjkvSXQ5Yic6dqaPg1LGHOl3xPcQE+pcffNyXyy/RHxNaQg
         VH38sN5JZaCOUDNfW/RFCsdZfp61PlPJZNBFcG0zYlYeWLtcj1OTTT4mTBLmQt6okmQV
         Y+A8aqkU712RFWIzJEvl+Q5UGwvyVZLptZqaNoWpJYpw9nRwZz/ehoXM1IeyCfV3An3D
         ZeCXZcZQ5GY2/n8Oc/SpFG/+VTK78XnCxY1RFBCCSvfk15XaHAGKCsZCSbGOxj/RdGIP
         SD1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768370882; x=1768975682;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FqooFhttAkqHcWqOKLsEII9sHRemlnM574mw8KNTnKU=;
        b=Qo0CiuHu0SyNRI98Qbf1fPMIbmBxCR/zXoth0w5P6hWkJfDRbCQZ3WROMdWrANvwuK
         aYsSi+mKsdU/yteYnkZ4/D6Ri6u19Zpz24liLIXlBLBN9Pge9SCDTmlQKkB6R4VLXT8V
         +3HwxR4euN1+0hcuf87U4Vm4Ar34koGIm0ooUWiK1ar7awZy+5Nnk+FqgTU5I9VX2Tpj
         W2qouzZRduTlS35trCzPMNYVplr7dANmZZ8xShsAF0w1ATpcvB+ilH4mEhlWwkyAPzbh
         5fJhyrh2EO3EoIVYVmXD2skTNDTmm7w/MTz+uPwCBJm8jWJz2vmsUjlf3hhFGgeD9lru
         mGMw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVcxu6c+CSZ0odrL7UQvH+NJbMfTurGAcITycjtcJoyvB9C0LnlyhMbyZkX12qn2ueWFCPE0A==@lfdr.de
X-Gm-Message-State: AOJu0Yz2YoGEf+S9shLIlKqQeadinSbzA8EWgC3rjTIY8eTjjx0vBDQS
	oRvRA8U5GQm+tk1H4qDQikNIJ4yl514A38S/k0AAxZdUIRL8jjGL7bEN
X-Received: by 2002:a05:6512:3d29:b0:598:ee60:8af1 with SMTP id 2adb3069b0e04-59ba0f65265mr409100e87.15.1768370881555;
        Tue, 13 Jan 2026 22:08:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FqUsEhyY7XGFBJ/X+gWNWzdFMMufu0+/2+SN9fzwXSbw=="
Received: by 2002:a05:6512:110b:b0:59b:7324:a12c with SMTP id
 2adb3069b0e04-59b7324a13fls1653792e87.2.-pod-prod-07-eu; Tue, 13 Jan 2026
 22:07:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXGbhSHBxAu8wB2GxwA0r879wW4/S+CShAXipHxCPx+znMaQ3RxK09BijFMfO80QhDh1T3/6qAkay0=@googlegroups.com
X-Received: by 2002:a05:6512:239a:b0:59b:7942:227a with SMTP id 2adb3069b0e04-59ba0f7ea9dmr396150e87.24.1768370879301;
        Tue, 13 Jan 2026 22:07:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768370879; cv=none;
        d=google.com; s=arc-20240605;
        b=MOqNnnMQkrkQpR2BsgXdkMd774Lo3Kx4W4w7zWum44Ysx2J9qOeyp/ICETaAYHqz2O
         3J04d7c/cQIHwzmRQwc+BkUCh64ksq9fHNsRmMMKy8v3D/z+1uDeFhPaldBxqALzp4iB
         OyfXY5Ch7ZqYt2f8I3kRGpoXsxREikSBMOexRjoMGZCmGPEDrz+PdJ5JM3uMyd9reGZL
         1JlHdIkChPFRrRN/barEhy+kgK6oHW4wmMgkjb2DXo4V0LIHVyoRjwGDi+YLZLVrzGKl
         UuCXWWGcMTWriCdja6MJeGhjxrNxkRunbi6pKaLwd9jDifeMlPJfOezOuVrKmxCf8pb6
         otRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=n08rQGqpj11nHUCAMi/f22AsHiR2vC2VJqIQFlhq3C0=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=Hne4QEKAqGZ8OYVXwyHCR7REETFZXtKb1NHCXN1bBso32bRiTGfP4rwUlZFujqCeFz
         HdxuI/wpA2w6WiW6fXnXxWwo7SvQBECLQquD5vBA+cF7BBVLDWPd77Fn/0DXZ187jo1P
         MigGWob69QprOwt8+fAQGtrpC4rtmiRv365ukM/olcGaIazXk4LibKLQT2MgxUKyQrV4
         rUHMC3fKjR7S+v48vLSJp6f/c88Lljjaqk7TKiL2rvCgArl7KaOOklPgeAJX7MHMs9Eh
         gTxJ4az7svBBl6n91CIuHgG7MMoOzz8QSOcqQWep8UpSOExNT2VMKv/MhFgKjuicLvmv
         tm1g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=aocnKVEZ;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-179.mta0.migadu.com (out-179.mta0.migadu.com. [2001:41d0:1004:224b::b3])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59ba102f6a1si19205e87.4.2026.01.13.22.07.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 22:07:58 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) client-ip=2001:41d0:1004:224b::b3;
Date: Wed, 14 Jan 2026 14:07:40 +0800
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
Subject: Re: [PATCH RFC v2 09/20] slab: remove cpu (partial) slabs usage from
 allocation paths
Message-ID: <3k4wy7gavxczpqn63jt66423fqa3wvdztigvbmejbvcpbr7ld2@fbylldpeuvgi>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-9-98225cfb50cf@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260112-sheaves-for-all-v2-9-98225cfb50cf@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=aocnKVEZ;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b3 as
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

On Mon, Jan 12, 2026 at 04:17:03PM +0100, Vlastimil Babka wrote:
> We now rely on sheaves as the percpu caching layer and can refill them
> directly from partial or newly allocated slabs. Start removing the cpu
> (partial) slabs code, first from allocation paths.
> 
> This means that any allocation not satisfied from percpu sheaves will
> end up in ___slab_alloc(), where we remove the usage of cpu (partial)
> slabs, so it will only perform get_partial() or new_slab().
> 
> In get_partial_node() we used to return a slab for freezing as the cpu
> slab and to refill the partial slab. Now we only want to return a single
> object and leave the slab on the list (unless it became full). We can't
> simply reuse alloc_single_from_partial() as that assumes freeing uses
> free_to_partial_list(). Instead we need to use __slab_update_freelist()
> to work properly against a racing __slab_free().
> 
> The rest of the changes is removing functions that no longer have any
> callers.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 611 ++++++++------------------------------------------------------
>  1 file changed, 78 insertions(+), 533 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index b568801edec2..7173f6716382 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -245,7 +245,6 @@ static DEFINE_STATIC_KEY_FALSE(strict_numa);
>  struct partial_context {
>  	gfp_t flags;
>  	unsigned int orig_size;
> -	void *object;
>  	unsigned int min_objects;
>  	unsigned int max_objects;
>  	struct list_head slabs;
> @@ -599,36 +598,6 @@ static inline void *get_freepointer(struct kmem_cache *s, void *object)
>  	return freelist_ptr_decode(s, p, ptr_addr);
>  }
>  
> -static void prefetch_freepointer(const struct kmem_cache *s, void *object)
> -{
> -	prefetchw(object + s->offset);
> -}
> -
> -/*
> - * When running under KMSAN, get_freepointer_safe() may return an uninitialized
> - * pointer value in the case the current thread loses the race for the next
> - * memory chunk in the freelist. In that case this_cpu_cmpxchg_double() in
> - * slab_alloc_node() will fail, so the uninitialized value won't be used, but
> - * KMSAN will still check all arguments of cmpxchg because of imperfect
> - * handling of inline assembly.
> - * To work around this problem, we apply __no_kmsan_checks to ensure that
> - * get_freepointer_safe() returns initialized memory.
> - */
> -__no_kmsan_checks
> -static inline void *get_freepointer_safe(struct kmem_cache *s, void *object)
> -{
> -	unsigned long freepointer_addr;
> -	freeptr_t p;
> -
> -	if (!debug_pagealloc_enabled_static())
> -		return get_freepointer(s, object);
> -
> -	object = kasan_reset_tag(object);
> -	freepointer_addr = (unsigned long)object + s->offset;
> -	copy_from_kernel_nofault(&p, (freeptr_t *)freepointer_addr, sizeof(p));
> -	return freelist_ptr_decode(s, p, freepointer_addr);
> -}
> -
>  static inline void set_freepointer(struct kmem_cache *s, void *object, void *fp)
>  {
>  	unsigned long freeptr_addr = (unsigned long)object + s->offset;
> @@ -708,23 +677,11 @@ static void slub_set_cpu_partial(struct kmem_cache *s, unsigned int nr_objects)
>  	nr_slabs = DIV_ROUND_UP(nr_objects * 2, oo_objects(s->oo));
>  	s->cpu_partial_slabs = nr_slabs;
>  }
> -
> -static inline unsigned int slub_get_cpu_partial(struct kmem_cache *s)
> -{
> -	return s->cpu_partial_slabs;
> -}
> -#else
> -#ifdef SLAB_SUPPORTS_SYSFS
> +#elif defined(SLAB_SUPPORTS_SYSFS)
>  static inline void
>  slub_set_cpu_partial(struct kmem_cache *s, unsigned int nr_objects)
>  {
>  }
> -#endif
> -
> -static inline unsigned int slub_get_cpu_partial(struct kmem_cache *s)
> -{
> -	return 0;
> -}
>  #endif /* CONFIG_SLUB_CPU_PARTIAL */
>  
>  /*
> @@ -1065,7 +1022,7 @@ static void set_track_update(struct kmem_cache *s, void *object,
>  	p->handle = handle;
>  #endif
>  	p->addr = addr;
> -	p->cpu = smp_processor_id();
> +	p->cpu = raw_smp_processor_id();
>  	p->pid = current->pid;
>  	p->when = jiffies;
>  }
> @@ -3571,15 +3528,15 @@ static bool get_partial_node_bulk(struct kmem_cache *s,
>  }
>  
>  /*
> - * Try to allocate a partial slab from a specific node.
> + * Try to allocate object from a partial slab on a specific node.
>   */
> -static struct slab *get_partial_node(struct kmem_cache *s,
> -				     struct kmem_cache_node *n,
> -				     struct partial_context *pc)
> +static void *get_partial_node(struct kmem_cache *s,
> +			      struct kmem_cache_node *n,
> +			      struct partial_context *pc)
>  {
> -	struct slab *slab, *slab2, *partial = NULL;
> +	struct slab *slab, *slab2;
>  	unsigned long flags;
> -	unsigned int partial_slabs = 0;
> +	void *object = NULL;
>  
>  	/*
>  	 * Racy check. If we mistakenly see no partial slabs then we
> @@ -3595,54 +3552,55 @@ static struct slab *get_partial_node(struct kmem_cache *s,
>  	else if (!spin_trylock_irqsave(&n->list_lock, flags))
>  		return NULL;
>  	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
> +
> +		struct freelist_counters old, new;
> +
>  		if (!pfmemalloc_match(slab, pc->flags))
>  			continue;
>  
>  		if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
> -			void *object = alloc_single_from_partial(s, n, slab,
> +			object = alloc_single_from_partial(s, n, slab,
>  							pc->orig_size);
> -			if (object) {
> -				partial = slab;
> -				pc->object = object;
> +			if (object)
>  				break;
> -			}
>  			continue;
>  		}
>  
> -		remove_partial(n, slab);
> +		/*
> +		 * get a single object from the slab. This might race against
> +		 * __slab_free(), which however has to take the list_lock if
> +		 * it's about to make the slab fully free.
> +		 */
> +		do {
> +			old.freelist = slab->freelist;
> +			old.counters = slab->counters;
>  
> -		if (!partial) {
> -			partial = slab;
> -			stat(s, ALLOC_FROM_PARTIAL);
> +			new.freelist = get_freepointer(s, old.freelist);
> +			new.counters = old.counters;
> +			new.inuse++;
>  
> -			if ((slub_get_cpu_partial(s) == 0)) {
> -				break;
> -			}
> -		} else {
> -			put_cpu_partial(s, slab, 0);
> -			stat(s, CPU_PARTIAL_NODE);
> +		} while (!__slab_update_freelist(s, slab, &old, &new, "get_partial_node"));
>  
> -			if (++partial_slabs > slub_get_cpu_partial(s) / 2) {
> -				break;
> -			}
> -		}
> +		object = old.freelist;
> +		if (!new.freelist)
> +			remove_partial(n, slab);
> +
> +		break;
>  	}
>  	spin_unlock_irqrestore(&n->list_lock, flags);
> -	return partial;
> +	return object;
>  }
>  
>  /*
> - * Get a slab from somewhere. Search in increasing NUMA distances.
> + * Get an object from somewhere. Search in increasing NUMA distances.
>   */
> -static struct slab *get_any_partial(struct kmem_cache *s,
> -				    struct partial_context *pc)
> +static void *get_any_partial(struct kmem_cache *s, struct partial_context *pc)
>  {
>  #ifdef CONFIG_NUMA
>  	struct zonelist *zonelist;
>  	struct zoneref *z;
>  	struct zone *zone;
>  	enum zone_type highest_zoneidx = gfp_zone(pc->flags);
> -	struct slab *slab;
>  	unsigned int cpuset_mems_cookie;
>  
>  	/*
> @@ -3677,8 +3635,8 @@ static struct slab *get_any_partial(struct kmem_cache *s,
>  
>  			if (n && cpuset_zone_allowed(zone, pc->flags) &&
>  					n->nr_partial > s->min_partial) {
> -				slab = get_partial_node(s, n, pc);
> -				if (slab) {
> +				void *object = get_partial_node(s, n, pc);
> +				if (object) {
>  					/*
>  					 * Don't check read_mems_allowed_retry()
>  					 * here - if mems_allowed was updated in
> @@ -3686,7 +3644,7 @@ static struct slab *get_any_partial(struct kmem_cache *s,
>  					 * between allocation and the cpuset
>  					 * update
>  					 */
> -					return slab;
> +					return object;
>  				}
>  			}
>  		}
> @@ -3696,20 +3654,20 @@ static struct slab *get_any_partial(struct kmem_cache *s,
>  }
>  
>  /*
> - * Get a partial slab, lock it and return it.
> + * Get an object from a partial slab
>   */
> -static struct slab *get_partial(struct kmem_cache *s, int node,
> -				struct partial_context *pc)
> +static void *get_partial(struct kmem_cache *s, int node,
> +			 struct partial_context *pc)
>  {
> -	struct slab *slab;
>  	int searchnode = node;
> +	void *object;
>  
>  	if (node == NUMA_NO_NODE)
>  		searchnode = numa_mem_id();
>  
> -	slab = get_partial_node(s, get_node(s, searchnode), pc);
> -	if (slab || (node != NUMA_NO_NODE && (pc->flags & __GFP_THISNODE)))
> -		return slab;
> +	object = get_partial_node(s, get_node(s, searchnode), pc);
> +	if (object || (node != NUMA_NO_NODE && (pc->flags & __GFP_THISNODE)))
> +		return object;
>  
>  	return get_any_partial(s, pc);
>  }
> @@ -4269,19 +4227,6 @@ static int slub_cpu_dead(unsigned int cpu)
>  	return 0;
>  }
>  
> -/*
> - * Check if the objects in a per cpu structure fit numa
> - * locality expectations.
> - */
> -static inline int node_match(struct slab *slab, int node)
> -{
> -#ifdef CONFIG_NUMA
> -	if (node != NUMA_NO_NODE && slab_nid(slab) != node)
> -		return 0;
> -#endif
> -	return 1;
> -}
> -
>  #ifdef CONFIG_SLUB_DEBUG
>  static int count_free(struct slab *slab)
>  {
> @@ -4466,36 +4411,6 @@ __update_cpu_freelist_fast(struct kmem_cache *s,
>  					     &old.freelist_tid, new.freelist_tid);
>  }
>  
> -/*
> - * Check the slab->freelist and either transfer the freelist to the
> - * per cpu freelist or deactivate the slab.
> - *
> - * The slab is still frozen if the return value is not NULL.
> - *
> - * If this function returns NULL then the slab has been unfrozen.
> - */
> -static inline void *get_freelist(struct kmem_cache *s, struct slab *slab)
> -{
> -	struct freelist_counters old, new;
> -
> -	lockdep_assert_held(this_cpu_ptr(&s->cpu_slab->lock));
> -
> -	do {
> -		old.freelist = slab->freelist;
> -		old.counters = slab->counters;
> -
> -		new.freelist = NULL;
> -		new.counters = old.counters;
> -
> -		new.inuse = old.objects;
> -		new.frozen = old.freelist != NULL;
> -
> -
> -	} while (!__slab_update_freelist(s, slab, &old, &new, "get_freelist"));
> -
> -	return old.freelist;
> -}
> -
>  /*
>   * Get the slab's freelist and do not freeze it.
>   *
> @@ -4523,29 +4438,6 @@ static inline void *get_freelist_nofreeze(struct kmem_cache *s, struct slab *sla
>  	return old.freelist;
>  }
>  
> -/*
> - * Freeze the partial slab and return the pointer to the freelist.
> - */
> -static inline void *freeze_slab(struct kmem_cache *s, struct slab *slab)
> -{
> -	struct freelist_counters old, new;
> -
> -	do {
> -		old.freelist = slab->freelist;
> -		old.counters = slab->counters;
> -
> -		new.freelist = NULL;
> -		new.counters = old.counters;
> -		VM_BUG_ON(new.frozen);
> -
> -		new.inuse = old.objects;
> -		new.frozen = 1;
> -
> -	} while (!slab_update_freelist(s, slab, &old, &new, "freeze_slab"));
> -
> -	return old.freelist;
> -}
> -
>  /*
>   * If the object has been wiped upon free, make sure it's fully initialized by
>   * zeroing out freelist pointer.
> @@ -4603,172 +4495,24 @@ static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
>  
>  	return allocated;
>  }
> -
>  /*
> - * Slow path. The lockless freelist is empty or we need to perform
> - * debugging duties.
> - *
> - * Processing is still very fast if new objects have been freed to the
> - * regular freelist. In that case we simply take over the regular freelist
> - * as the lockless freelist and zap the regular freelist.
> - *
> - * If that is not working then we fall back to the partial lists. We take the
> - * first element of the freelist as the object to allocate now and move the
> - * rest of the freelist to the lockless freelist.
> - *
> - * And if we were unable to get a new slab from the partial slab lists then
> - * we need to allocate a new slab. This is the slowest path since it involves
> - * a call to the page allocator and the setup of a new slab.
> + * Slow path. We failed to allocate via percpu sheaves or they are not available
> + * due to bootstrap or debugging enabled or SLUB_TINY.
>   *
> - * Version of __slab_alloc to use when we know that preemption is
> - * already disabled (which is the case for bulk allocation).
> + * We try to allocate from partial slab lists and fall back to allocating a new
> + * slab.
>   */
>  static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
> -			  unsigned long addr, struct kmem_cache_cpu *c, unsigned int orig_size)
> +			   unsigned long addr, unsigned int orig_size)
>  {
>  	bool allow_spin = gfpflags_allow_spinning(gfpflags);
>  	void *freelist;
>  	struct slab *slab;
> -	unsigned long flags;
>  	struct partial_context pc;
>  	bool try_thisnode = true;
>  
>  	stat(s, ALLOC_SLOWPATH);
>  
> -reread_slab:
> -
> -	slab = READ_ONCE(c->slab);
> -	if (!slab) {
> -		/*
> -		 * if the node is not online or has no normal memory, just
> -		 * ignore the node constraint
> -		 */
> -		if (unlikely(node != NUMA_NO_NODE &&
> -			     !node_isset(node, slab_nodes)))
> -			node = NUMA_NO_NODE;
> -		goto new_slab;
> -	}
> -
> -	if (unlikely(!node_match(slab, node))) {
> -		/*
> -		 * same as above but node_match() being false already
> -		 * implies node != NUMA_NO_NODE.
> -		 *
> -		 * We don't strictly honor pfmemalloc and NUMA preferences
> -		 * when !allow_spin because:
> -		 *
> -		 * 1. Most kmalloc() users allocate objects on the local node,
> -		 *    so kmalloc_nolock() tries not to interfere with them by
> -		 *    deactivating the cpu slab.
> -		 *
> -		 * 2. Deactivating due to NUMA or pfmemalloc mismatch may cause
> -		 *    unnecessary slab allocations even when n->partial list
> -		 *    is not empty.
> -		 */
> -		if (!node_isset(node, slab_nodes) ||
> -		    !allow_spin) {
> -			node = NUMA_NO_NODE;
> -		} else {
> -			stat(s, ALLOC_NODE_MISMATCH);
> -			goto deactivate_slab;
> -		}
> -	}
> -
> -	/*
> -	 * By rights, we should be searching for a slab page that was
> -	 * PFMEMALLOC but right now, we are losing the pfmemalloc
> -	 * information when the page leaves the per-cpu allocator
> -	 */
> -	if (unlikely(!pfmemalloc_match(slab, gfpflags) && allow_spin))
> -		goto deactivate_slab;
> -
> -	/* must check again c->slab in case we got preempted and it changed */
> -	local_lock_cpu_slab(s, flags);
> -
> -	if (unlikely(slab != c->slab)) {
> -		local_unlock_cpu_slab(s, flags);
> -		goto reread_slab;
> -	}
> -	freelist = c->freelist;
> -	if (freelist)
> -		goto load_freelist;
> -
> -	freelist = get_freelist(s, slab);
> -
> -	if (!freelist) {
> -		c->slab = NULL;
> -		c->tid = next_tid(c->tid);
> -		local_unlock_cpu_slab(s, flags);
> -		stat(s, DEACTIVATE_BYPASS);
> -		goto new_slab;
> -	}
> -
> -	stat(s, ALLOC_REFILL);
> -
> -load_freelist:
> -
> -	lockdep_assert_held(this_cpu_ptr(&s->cpu_slab->lock));
> -
> -	/*
> -	 * freelist is pointing to the list of objects to be used.
> -	 * slab is pointing to the slab from which the objects are obtained.
> -	 * That slab must be frozen for per cpu allocations to work.
> -	 */
> -	VM_BUG_ON(!c->slab->frozen);
> -	c->freelist = get_freepointer(s, freelist);
> -	c->tid = next_tid(c->tid);
> -	local_unlock_cpu_slab(s, flags);
> -	return freelist;
> -
> -deactivate_slab:
> -
> -	local_lock_cpu_slab(s, flags);
> -	if (slab != c->slab) {
> -		local_unlock_cpu_slab(s, flags);
> -		goto reread_slab;
> -	}
> -	freelist = c->freelist;
> -	c->slab = NULL;
> -	c->freelist = NULL;
> -	c->tid = next_tid(c->tid);
> -	local_unlock_cpu_slab(s, flags);
> -	deactivate_slab(s, slab, freelist);
> -
> -new_slab:
> -
> -#ifdef CONFIG_SLUB_CPU_PARTIAL
> -	while (slub_percpu_partial(c)) {
> -		local_lock_cpu_slab(s, flags);
> -		if (unlikely(c->slab)) {
> -			local_unlock_cpu_slab(s, flags);
> -			goto reread_slab;
> -		}
> -		if (unlikely(!slub_percpu_partial(c))) {
> -			local_unlock_cpu_slab(s, flags);
> -			/* we were preempted and partial list got empty */
> -			goto new_objects;
> -		}
> -
> -		slab = slub_percpu_partial(c);
> -		slub_set_percpu_partial(c, slab);
> -
> -		if (likely(node_match(slab, node) &&
> -			   pfmemalloc_match(slab, gfpflags)) ||
> -		    !allow_spin) {
> -			c->slab = slab;
> -			freelist = get_freelist(s, slab);
> -			VM_BUG_ON(!freelist);
> -			stat(s, CPU_PARTIAL_ALLOC);
> -			goto load_freelist;
> -		}
> -
> -		local_unlock_cpu_slab(s, flags);
> -
> -		slab->next = NULL;
> -		__put_partials(s, slab);
> -	}
> -#endif
> -
>  new_objects:
>  
>  	pc.flags = gfpflags;
> @@ -4793,33 +4537,11 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
>  	}
>  
>  	pc.orig_size = orig_size;
> -	slab = get_partial(s, node, &pc);
> -	if (slab) {
> -		if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
> -			freelist = pc.object;
> -			/*
> -			 * For debug caches here we had to go through
> -			 * alloc_single_from_partial() so just store the
> -			 * tracking info and return the object.
> -			 *
> -			 * Due to disabled preemption we need to disallow
> -			 * blocking. The flags are further adjusted by
> -			 * gfp_nested_mask() in stack_depot itself.
> -			 */
> -			if (s->flags & SLAB_STORE_USER)
> -				set_track(s, freelist, TRACK_ALLOC, addr,
> -					  gfpflags & ~(__GFP_DIRECT_RECLAIM));
> -
> -			return freelist;
> -		}
> -
> -		freelist = freeze_slab(s, slab);
> -		goto retry_load_slab;
> -	}
> +	freelist = get_partial(s, node, &pc);
> +	if (freelist)
> +		goto success;
>  
> -	slub_put_cpu_ptr(s->cpu_slab);
>  	slab = new_slab(s, pc.flags, node);
> -	c = slub_get_cpu_ptr(s->cpu_slab);
>  
>  	if (unlikely(!slab)) {
>  		if (node != NUMA_NO_NODE && !(gfpflags & __GFP_THISNODE)
> @@ -4836,68 +4558,31 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
>  	if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
>  		freelist = alloc_single_from_new_slab(s, slab, orig_size, gfpflags);
>  
> -		if (unlikely(!freelist)) {
> -			/* This could cause an endless loop. Fail instead. */
> -			if (!allow_spin)
> -				return NULL;
> -			goto new_objects;
> +		if (likely(freelist)) {
> +			goto success;
>  		}
> +	} else {
> +		alloc_from_new_slab(s, slab, &freelist, 1, allow_spin);

IIUC, when CONFIG_SLUB_DEBUG is enabled, each successful new_slab() call
should have a matching inc_slabs_node(), since __kmem_cache_shutdown()
rely on the accounting done by inc_slabs_node(). Here
alloc_single_from_new_slab() does call inc_slabs_node(), but
alloc_from_new_slab() doesn't. Could this mismatch cause any issues?

>  
> -		if (s->flags & SLAB_STORE_USER)
> -			set_track(s, freelist, TRACK_ALLOC, addr,
> -				  gfpflags & ~(__GFP_DIRECT_RECLAIM));
> -
> -		return freelist;
> -	}
> -
> -	/*
> -	 * No other reference to the slab yet so we can
> -	 * muck around with it freely without cmpxchg
> -	 */
> -	freelist = slab->freelist;
> -	slab->freelist = NULL;
> -	slab->inuse = slab->objects;
> -	slab->frozen = 1;
> -
> -	inc_slabs_node(s, slab_nid(slab), slab->objects);
> -
> -	if (unlikely(!pfmemalloc_match(slab, gfpflags) && allow_spin)) {
> -		/*
> -		 * For !pfmemalloc_match() case we don't load freelist so that
> -		 * we don't make further mismatched allocations easier.
> -		 */
> -		deactivate_slab(s, slab, get_freepointer(s, freelist));
> -		return freelist;
> +		/* we don't need to check SLAB_STORE_USER here */
> +		if (likely(freelist)) {
> +			return freelist;
> +		}
>  	}
>  
> -retry_load_slab:
> -
> -	local_lock_cpu_slab(s, flags);
> -	if (unlikely(c->slab)) {
> -		void *flush_freelist = c->freelist;
> -		struct slab *flush_slab = c->slab;
> -
> -		c->slab = NULL;
> -		c->freelist = NULL;
> -		c->tid = next_tid(c->tid);
> -
> -		local_unlock_cpu_slab(s, flags);
> -
> -		if (unlikely(!allow_spin)) {
> -			/* Reentrant slub cannot take locks, defer */
> -			defer_deactivate_slab(flush_slab, flush_freelist);
> -		} else {
> -			deactivate_slab(s, flush_slab, flush_freelist);
> -		}
> +	if (allow_spin)
> +		goto new_objects;
>  
> -		stat(s, CPUSLAB_FLUSH);
> +	/* This could cause an endless loop. Fail instead. */
> +	return NULL;
>  
> -		goto retry_load_slab;
> -	}
> -	c->slab = slab;
> +success:
> +	if (kmem_cache_debug_flags(s, SLAB_STORE_USER))
> +		set_track(s, freelist, TRACK_ALLOC, addr, gfpflags);
>  
> -	goto load_freelist;
> +	return freelist;
>  }
> +
>  /*
>   * We disallow kprobes in ___slab_alloc() to prevent reentrance
>   *
> @@ -4912,87 +4597,11 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
>   */
>  NOKPROBE_SYMBOL(___slab_alloc);
>  
> -/*
> - * A wrapper for ___slab_alloc() for contexts where preemption is not yet
> - * disabled. Compensates for possible cpu changes by refetching the per cpu area
> - * pointer.
> - */
> -static void *__slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
> -			  unsigned long addr, struct kmem_cache_cpu *c, unsigned int orig_size)
> -{
> -	void *p;
> -
> -#ifdef CONFIG_PREEMPT_COUNT
> -	/*
> -	 * We may have been preempted and rescheduled on a different
> -	 * cpu before disabling preemption. Need to reload cpu area
> -	 * pointer.
> -	 */
> -	c = slub_get_cpu_ptr(s->cpu_slab);
> -#endif
> -	if (unlikely(!gfpflags_allow_spinning(gfpflags))) {
> -		if (local_lock_is_locked(&s->cpu_slab->lock)) {
> -			/*
> -			 * EBUSY is an internal signal to kmalloc_nolock() to
> -			 * retry a different bucket. It's not propagated
> -			 * to the caller.
> -			 */
> -			p = ERR_PTR(-EBUSY);
> -			goto out;
> -		}
> -	}
> -	p = ___slab_alloc(s, gfpflags, node, addr, c, orig_size);
> -out:
> -#ifdef CONFIG_PREEMPT_COUNT
> -	slub_put_cpu_ptr(s->cpu_slab);
> -#endif
> -	return p;
> -}
> -
>  static __always_inline void *__slab_alloc_node(struct kmem_cache *s,
>  		gfp_t gfpflags, int node, unsigned long addr, size_t orig_size)
>  {
> -	struct kmem_cache_cpu *c;
> -	struct slab *slab;
> -	unsigned long tid;
>  	void *object;
>  
> -redo:
> -	/*
> -	 * Must read kmem_cache cpu data via this cpu ptr. Preemption is
> -	 * enabled. We may switch back and forth between cpus while
> -	 * reading from one cpu area. That does not matter as long
> -	 * as we end up on the original cpu again when doing the cmpxchg.
> -	 *
> -	 * We must guarantee that tid and kmem_cache_cpu are retrieved on the
> -	 * same cpu. We read first the kmem_cache_cpu pointer and use it to read
> -	 * the tid. If we are preempted and switched to another cpu between the
> -	 * two reads, it's OK as the two are still associated with the same cpu
> -	 * and cmpxchg later will validate the cpu.
> -	 */
> -	c = raw_cpu_ptr(s->cpu_slab);
> -	tid = READ_ONCE(c->tid);
> -
> -	/*
> -	 * Irqless object alloc/free algorithm used here depends on sequence
> -	 * of fetching cpu_slab's data. tid should be fetched before anything
> -	 * on c to guarantee that object and slab associated with previous tid
> -	 * won't be used with current tid. If we fetch tid first, object and
> -	 * slab could be one associated with next tid and our alloc/free
> -	 * request will be failed. In this case, we will retry. So, no problem.
> -	 */
> -	barrier();
> -
> -	/*
> -	 * The transaction ids are globally unique per cpu and per operation on
> -	 * a per cpu queue. Thus they can be guarantee that the cmpxchg_double
> -	 * occurs on the right processor and that there was no operation on the
> -	 * linked list in between.
> -	 */
> -
> -	object = c->freelist;
> -	slab = c->slab;
> -
>  #ifdef CONFIG_NUMA
>  	if (static_branch_unlikely(&strict_numa) &&
>  			node == NUMA_NO_NODE) {
> @@ -5001,47 +4610,20 @@ static __always_inline void *__slab_alloc_node(struct kmem_cache *s,
>  
>  		if (mpol) {
>  			/*
> -			 * Special BIND rule support. If existing slab
> +			 * Special BIND rule support. If the local node
>  			 * is in permitted set then do not redirect
>  			 * to a particular node.
>  			 * Otherwise we apply the memory policy to get
>  			 * the node we need to allocate on.
>  			 */
> -			if (mpol->mode != MPOL_BIND || !slab ||
> -					!node_isset(slab_nid(slab), mpol->nodes))
> -
> +			if (mpol->mode != MPOL_BIND ||
> +					!node_isset(numa_mem_id(), mpol->nodes))
>  				node = mempolicy_slab_node();
>  		}
>  	}
>  #endif
>  
> -	if (!USE_LOCKLESS_FAST_PATH() ||
> -	    unlikely(!object || !slab || !node_match(slab, node))) {
> -		object = __slab_alloc(s, gfpflags, node, addr, c, orig_size);
> -	} else {
> -		void *next_object = get_freepointer_safe(s, object);
> -
> -		/*
> -		 * The cmpxchg will only match if there was no additional
> -		 * operation and if we are on the right processor.
> -		 *
> -		 * The cmpxchg does the following atomically (without lock
> -		 * semantics!)
> -		 * 1. Relocate first pointer to the current per cpu area.
> -		 * 2. Verify that tid and freelist have not been changed
> -		 * 3. If they were not changed replace tid and freelist
> -		 *
> -		 * Since this is without lock semantics the protection is only
> -		 * against code executing on this cpu *not* from access by
> -		 * other cpus.
> -		 */
> -		if (unlikely(!__update_cpu_freelist_fast(s, object, next_object, tid))) {
> -			note_cmpxchg_failure("slab_alloc", s, tid);
> -			goto redo;
> -		}
> -		prefetch_freepointer(s, next_object);
> -		stat(s, ALLOC_FASTPATH);
> -	}
> +	object = ___slab_alloc(s, gfpflags, node, addr, orig_size);
>  
>  	return object;
>  }
> @@ -7709,62 +7291,25 @@ static inline
>  int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  			    void **p)
>  {
> -	struct kmem_cache_cpu *c;
> -	unsigned long irqflags;
>  	int i;
>  
>  	/*
> -	 * Drain objects in the per cpu slab, while disabling local
> -	 * IRQs, which protects against PREEMPT and interrupts
> -	 * handlers invoking normal fastpath.
> +	 * TODO: this might be more efficient (if necessary) by reusing
> +	 * __refill_objects()
>  	 */
> -	c = slub_get_cpu_ptr(s->cpu_slab);
> -	local_lock_irqsave(&s->cpu_slab->lock, irqflags);
> -
>  	for (i = 0; i < size; i++) {
> -		void *object = c->freelist;
>  
> -		if (unlikely(!object)) {
> -			/*
> -			 * We may have removed an object from c->freelist using
> -			 * the fastpath in the previous iteration; in that case,
> -			 * c->tid has not been bumped yet.
> -			 * Since ___slab_alloc() may reenable interrupts while
> -			 * allocating memory, we should bump c->tid now.
> -			 */
> -			c->tid = next_tid(c->tid);
> +		p[i] = ___slab_alloc(s, flags, NUMA_NO_NODE, _RET_IP_,
> +				     s->object_size);
> +		if (unlikely(!p[i]))
> +			goto error;
>  
> -			local_unlock_irqrestore(&s->cpu_slab->lock, irqflags);
> -
> -			/*
> -			 * Invoking slow path likely have side-effect
> -			 * of re-populating per CPU c->freelist
> -			 */
> -			p[i] = ___slab_alloc(s, flags, NUMA_NO_NODE,
> -					    _RET_IP_, c, s->object_size);
> -			if (unlikely(!p[i]))
> -				goto error;
> -
> -			c = this_cpu_ptr(s->cpu_slab);
> -			maybe_wipe_obj_freeptr(s, p[i]);
> -
> -			local_lock_irqsave(&s->cpu_slab->lock, irqflags);
> -
> -			continue; /* goto for-loop */
> -		}
> -		c->freelist = get_freepointer(s, object);
> -		p[i] = object;
>  		maybe_wipe_obj_freeptr(s, p[i]);
> -		stat(s, ALLOC_FASTPATH);
>  	}
> -	c->tid = next_tid(c->tid);
> -	local_unlock_irqrestore(&s->cpu_slab->lock, irqflags);
> -	slub_put_cpu_ptr(s->cpu_slab);
>  
>  	return i;
>  
>  error:
> -	slub_put_cpu_ptr(s->cpu_slab);
>  	__kmem_cache_free_bulk(s, i, p);
>  	return 0;
>  
> 
> -- 
> 2.52.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3k4wy7gavxczpqn63jt66423fqa3wvdztigvbmejbvcpbr7ld2%40fbylldpeuvgi.
