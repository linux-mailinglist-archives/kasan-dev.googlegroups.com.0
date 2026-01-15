Return-Path: <kasan-dev+bncBAABBIPKUPFQMGQEXFI6I2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 214F5D24E14
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 15:09:39 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-59b6a320b35sf913990e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 06:09:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768486178; cv=pass;
        d=google.com; s=arc-20240605;
        b=BcXC/2q7ylNp/LfCwYeZtgkShOFJm+ugUR9UMPn3Twmr9sI/Ix47VOpXyjDWzBqmPf
         rUZhkcVZLhdJOFJ0/zOLwaZjBI1gcBCHnERsWiIkv2LR2eMFZsCjqLGrNpII7TQDPS8Q
         4+ZiozwmQj779xxeO2DAiddHzzJImMpFAeMkDtuioJRp0baZxnU+PiFnvEwIDlOaK2Qw
         JkVJwRLFlAyNiTv81ewHTsQSoE010W0RL5dfNUPNc1G6jfW8gJIKOi10rlKHr1xXaLiE
         5EBqfTMV9JnS6lRL0nmeyKkks6/D+yX+eO+41DxwK6QYZq/iTFDIiRTpYWtIUyJIGAcC
         vqPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/j5ElUHZdaf6BKW5MP5H7XGbh4b9LyAm7aFAaHOaJ/8=;
        fh=2K/VHW4xSSNu9QI+ie2zDg44Jz4Rlt9PhRCEa3qc4zQ=;
        b=gTdT95a8hjj4MzHOg3Lh/JhPX1nEKWpfxRYRI8WKWTF4kcoPS9TlfkF7IyoyWEPBD1
         HgrHOGg2dnqqcPdJSGpL2MGW7XADHiKcQDABwqttOaCxOQQZ5txxwCYOdkG0B13Kw27S
         QTx89lur/cSENGm14iYB0IM7Xk0OYTXZn0JdmMT6uxurzD5ZfZG+w7n2J2dKmngMFpGG
         BflGgXFX0Jw9tx6oqVStxxh0GdZ8bu7pCbphfsUnAtM21tRmU565bxa82/yieEA0aKdx
         /xWgHCWnGyFj5B7oDl5jc2FTa6QEF5uVpH08Dh+cTq0xwnmw+ECJ19t4L2Z3PLczEQwq
         wdvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VN8umt9L;
       spf=pass (google.com: domain of hao.li@linux.dev designates 91.218.175.173 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768486178; x=1769090978; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/j5ElUHZdaf6BKW5MP5H7XGbh4b9LyAm7aFAaHOaJ/8=;
        b=BgS8GOy4hAF6kfdIWe/JQMBSXeeQd8MLFc/f64nl5MrBoNstIKxG6RcvPge5qBsCaX
         fZUvZKZ3/pyAzQKe287dIDqpNKIokH7WGsHZ/WGHdHKp24hQ7RjjLl0kpCMi/fdh8Jap
         eXF/pTRgZ8l2WTgH7BUH8XQXwk9cWEjG2iUU2bENfZDVAMmtQ0bLSzZRkOdsgE23ai59
         EiCbaHO+mHomLyRwdOHTHvc8Bn0c+WinL6veCWUjkUPA68sCPO5obXEytFqhU+fy+aRC
         hS5p+qMg3+NOReT2J+yB59A8bMaoRMlvs93j8o8VVUPdLZEtMfm0Rhq0f9G22urzvNDs
         Vb5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768486178; x=1769090978;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/j5ElUHZdaf6BKW5MP5H7XGbh4b9LyAm7aFAaHOaJ/8=;
        b=WqSnNfhpFM2gNNP6gNWju7tW61Q7rKSwC4luzwhEeO6CzvTJqz10nzOqu62cIncm2d
         wqZc7YGBV6QBH/7vcHGhlL8rhUwWul8r0grm39ARAFiSgyqeLxg2tBTIUmAyuxwla9Kw
         DjsOs3d0XSIoV6TM5k3eDZZn6JxEe2815bQL4mIVQqMf5GOcFLUUu4k4+EEsUDz5l4tP
         5GeMwERpeRMxiWI3kWeO+gExP64Sgshmf7S6TaG258k6dpt8WUnkLP7QFtxZHblT2cgP
         sGfgF+/JL7wsWo9nCi5YGkjGg78Rc+NjnDIe2DdissjGzeUL2NeIFfBzMgxuZU0591xs
         AfdA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWtnuZ3RizhecfiLyuyC+Ke0OWe5j7RQBcDHjNWvgUgDqUYsr8HAveZT0UI4M9QDb6yP9F1dQ==@lfdr.de
X-Gm-Message-State: AOJu0YwZO1sT5XlF1Mpz1RSKzvh6qnaRYgZtHVY2vIwZdK05mz3fCJHZ
	pU57sVGZDTfi+x+iRuU5MT1XP96IWi468ayWXOjqfqq66NM4j/VK0Rsg
X-Received: by 2002:ac2:4bd1:0:b0:59b:a8d0:df9f with SMTP id 2adb3069b0e04-59ba8d0dfe6mr1226308e87.1.1768486178150;
        Thu, 15 Jan 2026 06:09:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E+IQfkXjOdzxHQ2NfpL6V/SAY5MRFDQJymHHpnWEwRjg=="
Received: by 2002:a05:6512:68:b0:59a:109d:9953 with SMTP id
 2adb3069b0e04-59ba05e50ddls184752e87.2.-pod-prod-00-eu-canary; Thu, 15 Jan
 2026 06:09:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW8Ihc/AdxXU2oxC07pHJy8o44fJbvL46hXrNQHBjGsrzhtFiMPBt+HkrZB2JG6ktcr0M+alHlEB3c=@googlegroups.com
X-Received: by 2002:a05:651c:31ca:10b0:382:4d10:5dda with SMTP id 38308e7fff4ca-3836f0daae0mr9012711fa.21.1768486175754;
        Thu, 15 Jan 2026 06:09:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768486175; cv=none;
        d=google.com; s=arc-20240605;
        b=a6o1EdqGF/nsszOFryyCfwuywAfYVDFH3WGU1Th5440e5TcjeGtodBJpuHCqa7UsW6
         L4SmlnFCwJT4SKAEHLDFYiWNZTVti9GQytnzVNgde5Rg7dNXjk0LQSU8EEXQNVwIlbDU
         CkNSrqxHcuPD3dFn/O/96HDozC5P8x3e5TzUzC5SrOmFNmNPT8Vi8gt+MC06u9fQgJrk
         n8EaaC6ISHzQW/G7Yvo59fa5hDLFRxwyBq5pV0QuGBI5+r3pjZSonSLPbRSsvSjFRQZj
         QyN1yJRf80/i4DsXS2doW5/s/QhdGrxt7ZeICgfJediaFZgzR6tWX3I6IqNiGl5mUuWN
         1NTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=MIpAv8VZm1fyBvDsuUrYNffY2jlmWo53T8xLzmAajew=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=OmBhpzTGBRudlyjwXAxJdhP/C2BPaz0WboEyvRSU4DzvW0A4Mc3GmroYcxUM/tQwtL
         f4xKqF2kXsFeYMYaV64w3blTjFSISHXENJMxHUw63iNMs0PLtchbpHTVWl/+oMbqy7PV
         oFuP3Eo74IppPKaH/qAk1qykuTRzwHJL3vwvjaMoOxIfBc2jqVn4YZFEvUZ1f2yrLC30
         HbLmbzDk1K+8wp4kY+TwsDi3SwBlp/fLYxIzVEvu3InT+a3uQgyL7k89cyejQD7w2xYN
         aSXL+WUkqCjj4XRmg1ek7eNhx3oGA7fxqkBPXKPe1QC7TS0MBcCsvT48fLDx//7tvblU
         xjdQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VN8umt9L;
       spf=pass (google.com: domain of hao.li@linux.dev designates 91.218.175.173 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-173.mta0.migadu.com (out-173.mta0.migadu.com. [91.218.175.173])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38312397ff7si3479811fa.2.2026.01.15.06.09.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jan 2026 06:09:34 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 91.218.175.173 as permitted sender) client-ip=91.218.175.173;
Date: Thu, 15 Jan 2026 22:09:17 +0800
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
Subject: Re: [PATCH RFC v2 12/20] slab: remove defer_deactivate_slab()
Message-ID: <sofeahffu5jj5xbre422lelbisfclwdul2i42j7odth3j4yzil@nyxfavdhwmuz>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-12-98225cfb50cf@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260112-sheaves-for-all-v2-12-98225cfb50cf@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=VN8umt9L;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 91.218.175.173 as
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

On Mon, Jan 12, 2026 at 04:17:06PM +0100, Vlastimil Babka wrote:
> There are no more cpu slabs so we don't need their deferred
> deactivation. The function is now only used from places where we
> allocate a new slab but then can't spin on node list_lock to put it on
> the partial list. Instead of the deferred action we can free it directly
> via __free_slab(), we just need to tell it to use _nolock() freeing of
> the underlying pages and take care of the accounting.
> 
> Since free_frozen_pages_nolock() variant does not yet exist for code
> outside of the page allocator, create it as a trivial wrapper for
> __free_frozen_pages(..., FPI_TRYLOCK).
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/internal.h   |  1 +
>  mm/page_alloc.c |  5 +++++
>  mm/slab.h       |  8 +-------
>  mm/slub.c       | 51 ++++++++++++++++-----------------------------------
>  4 files changed, 23 insertions(+), 42 deletions(-)
> 
> diff --git a/mm/internal.h b/mm/internal.h
> index e430da900430..1f44ccb4badf 100644
> --- a/mm/internal.h
> +++ b/mm/internal.h
> @@ -846,6 +846,7 @@ static inline struct page *alloc_frozen_pages_noprof(gfp_t gfp, unsigned int ord
>  struct page *alloc_frozen_pages_nolock_noprof(gfp_t gfp_flags, int nid, unsigned int order);
>  #define alloc_frozen_pages_nolock(...) \
>  	alloc_hooks(alloc_frozen_pages_nolock_noprof(__VA_ARGS__))
> +void free_frozen_pages_nolock(struct page *page, unsigned int order);
>  
>  extern void zone_pcp_reset(struct zone *zone);
>  extern void zone_pcp_disable(struct zone *zone);
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index 822e05f1a964..8a288ecfdd93 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -2981,6 +2981,11 @@ void free_frozen_pages(struct page *page, unsigned int order)
>  	__free_frozen_pages(page, order, FPI_NONE);
>  }
>  
> +void free_frozen_pages_nolock(struct page *page, unsigned int order)
> +{
> +	__free_frozen_pages(page, order, FPI_TRYLOCK);
> +}
> +
>  /*
>   * Free a batch of folios
>   */
> diff --git a/mm/slab.h b/mm/slab.h
> index e77260720994..4efec41b6445 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -71,13 +71,7 @@ struct slab {
>  	struct kmem_cache *slab_cache;
>  	union {
>  		struct {
> -			union {
> -				struct list_head slab_list;
> -				struct { /* For deferred deactivate_slab() */
> -					struct llist_node llnode;
> -					void *flush_freelist;
> -				};
> -			};
> +			struct list_head slab_list;
>  			/* Double-word boundary */
>  			struct freelist_counters;
>  		};
> diff --git a/mm/slub.c b/mm/slub.c
> index 522a7e671a26..0effeb3b9552 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3248,7 +3248,7 @@ static struct slab *new_slab(struct kmem_cache *s, gfp_t flags, int node)
>  		flags & (GFP_RECLAIM_MASK | GFP_CONSTRAINT_MASK), node);
>  }
>  
> -static void __free_slab(struct kmem_cache *s, struct slab *slab)
> +static void __free_slab(struct kmem_cache *s, struct slab *slab, bool allow_spin)
>  {
>  	struct page *page = slab_page(slab);
>  	int order = compound_order(page);
> @@ -3262,11 +3262,20 @@ static void __free_slab(struct kmem_cache *s, struct slab *slab)
>  	free_frozen_pages(page, order);

Here we missed using the newly added allow_spin.
It should call free_frozen_pages_nolock() when !allow_spin.

-- 
Thanks,
Hao

>  }
>  
> +static void free_new_slab_nolock(struct kmem_cache *s, struct slab *slab)
> +{
> +	/*
> +	 * Since it was just allocated, we can skip the actions in
> +	 * discard_slab() and free_slab().
> +	 */
> +	__free_slab(s, slab, false);
> +}
> +
>  static void rcu_free_slab(struct rcu_head *h)
>  {
>  	struct slab *slab = container_of(h, struct slab, rcu_head);
>  
> -	__free_slab(slab->slab_cache, slab);
> +	__free_slab(slab->slab_cache, slab, true);
>  }
>  
>  static void free_slab(struct kmem_cache *s, struct slab *slab)
> @@ -3282,7 +3291,7 @@ static void free_slab(struct kmem_cache *s, struct slab *slab)
>  	if (unlikely(s->flags & SLAB_TYPESAFE_BY_RCU))
>  		call_rcu(&slab->rcu_head, rcu_free_slab);
>  	else
> -		__free_slab(s, slab);
> +		__free_slab(s, slab, true);
>  }
>  
>  static void discard_slab(struct kmem_cache *s, struct slab *slab)
> @@ -3375,8 +3384,6 @@ static void *alloc_single_from_partial(struct kmem_cache *s,
>  	return object;
>  }
>  
> -static void defer_deactivate_slab(struct slab *slab, void *flush_freelist);
> -
>  /*
>   * Called only for kmem_cache_debug() caches to allocate from a freshly
>   * allocated slab. Allocate a single object instead of whole freelist
> @@ -3392,8 +3399,8 @@ static void *alloc_single_from_new_slab(struct kmem_cache *s, struct slab *slab,
>  	void *object;
>  
>  	if (!allow_spin && !spin_trylock_irqsave(&n->list_lock, flags)) {
> -		/* Unlucky, discard newly allocated slab */
> -		defer_deactivate_slab(slab, NULL);
> +		/* Unlucky, discard newly allocated slab. */
> +		free_new_slab_nolock(s, slab);
>  		return NULL;
>  	}
>  
> @@ -4262,7 +4269,7 @@ static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
>  
>  		if (!spin_trylock_irqsave(&n->list_lock, flags)) {
>  			/* Unlucky, discard newly allocated slab */
> -			defer_deactivate_slab(slab, NULL);
> +			free_new_slab_nolock(s, slab);
>  			return 0;
>  		}
>  	}
> @@ -6031,7 +6038,6 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
>  
>  struct defer_free {
>  	struct llist_head objects;
> -	struct llist_head slabs;
>  	struct irq_work work;
>  };
>  
> @@ -6039,7 +6045,6 @@ static void free_deferred_objects(struct irq_work *work);
>  
>  static DEFINE_PER_CPU(struct defer_free, defer_free_objects) = {
>  	.objects = LLIST_HEAD_INIT(objects),
> -	.slabs = LLIST_HEAD_INIT(slabs),
>  	.work = IRQ_WORK_INIT(free_deferred_objects),
>  };
>  
> @@ -6052,10 +6057,9 @@ static void free_deferred_objects(struct irq_work *work)
>  {
>  	struct defer_free *df = container_of(work, struct defer_free, work);
>  	struct llist_head *objs = &df->objects;
> -	struct llist_head *slabs = &df->slabs;
>  	struct llist_node *llnode, *pos, *t;
>  
> -	if (llist_empty(objs) && llist_empty(slabs))
> +	if (llist_empty(objs))
>  		return;
>  
>  	llnode = llist_del_all(objs);
> @@ -6079,16 +6083,6 @@ static void free_deferred_objects(struct irq_work *work)
>  
>  		__slab_free(s, slab, x, x, 1, _THIS_IP_);
>  	}
> -
> -	llnode = llist_del_all(slabs);
> -	llist_for_each_safe(pos, t, llnode) {
> -		struct slab *slab = container_of(pos, struct slab, llnode);
> -
> -		if (slab->frozen)
> -			deactivate_slab(slab->slab_cache, slab, slab->flush_freelist);
> -		else
> -			free_slab(slab->slab_cache, slab);
> -	}
>  }
>  
>  static void defer_free(struct kmem_cache *s, void *head)
> @@ -6102,19 +6096,6 @@ static void defer_free(struct kmem_cache *s, void *head)
>  		irq_work_queue(&df->work);
>  }
>  
> -static void defer_deactivate_slab(struct slab *slab, void *flush_freelist)
> -{
> -	struct defer_free *df;
> -
> -	slab->flush_freelist = flush_freelist;
> -
> -	guard(preempt)();
> -
> -	df = this_cpu_ptr(&defer_free_objects);
> -	if (llist_add(&slab->llnode, &df->slabs))
> -		irq_work_queue(&df->work);
> -}
> -
>  void defer_free_barrier(void)
>  {
>  	int cpu;
> 
> -- 
> 2.52.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/sofeahffu5jj5xbre422lelbisfclwdul2i42j7odth3j4yzil%40nyxfavdhwmuz.
