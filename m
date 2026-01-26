Return-Path: <kasan-dev+bncBAABBUFH3TFQMGQERKQBTXA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id NM2lKtMTd2mHbwEAu9opvQ
	(envelope-from <kasan-dev+bncBAABBUFH3TFQMGQERKQBTXA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 08:12:19 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3879A84AFD
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 08:12:19 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-59df9fc83a0sf147369e87.0
        for <lists+kasan-dev@lfdr.de>; Sun, 25 Jan 2026 23:12:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769411538; cv=pass;
        d=google.com; s=arc-20240605;
        b=FKHyt88KJqDAMjGLxvI277D9jnhnugHs7MevN5L3BecgEg010FLG8m4fsSj6Ua8RZ9
         0YMWt22+13yNHMe5/tIbD+Tag+hb/HACzsMP9IPcrJM1NQriGsijjMrQ/o3px2goobFU
         rfHgnJLtz387JQa643M9BrDfEZ0mDy1xaxVHn0z8/i2HK3bwJ2pC52eD5SiHUY9XHG53
         NJVlY+/OfyeOJ3uQ5Vo6xyuZ1APrSKdEozZ+8aY9ojwY+36m8rOCKRVd9WEA32GD2iN2
         EjVSLpeCFHueYrt+Qj0BOagiNsB2CcEWIRjEn5skXaUzT+AAKXzy/j02i7+dJKVpRihb
         nnjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gFHbWE6cI3KMdGmJ1uf32FBiGnlvZZmamA33MIG2vKU=;
        fh=6WrmJogk+9lP64mPUhFf/9jetlbyyyP2Isw75pzg3KA=;
        b=HxEFf21zR2kZ+anb90WO6b/3PjXX6gzA01pWGp4f6zeSLH86qXSmOhJ3AL0CA25KQF
         FTsITGyISM6JnBI1OnoBdfcvtoe8Jq4TYHwPbTdlQsnIq/E88+UgrMNPucI6i95hBk61
         1tPC9WyQjVm4o5eyl5rrVV2vxnDTlk/ml5WGbQjdoV8tBkkdiVnNMfl5zzOa6Vl1K1T4
         DocEkxvRW8x/fr8MJBtuO43qF4of9OS6dZz3E9rmNbAK6jt+/3A4wI0zm/07zK/Ai57+
         72nDXCz3FVkfVix4hpknDd+Wg4n3O9ubRtQIay5FEspGBwsleW2Q1GLmyqegp5lxU1+2
         Ie0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Gwzs01lv;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b2 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769411538; x=1770016338; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gFHbWE6cI3KMdGmJ1uf32FBiGnlvZZmamA33MIG2vKU=;
        b=gJRxai+aa0yIvYToNXDBNNVFBcBx4aRPzZrKN6eUJEgzWpEBYhHMK/NTST1jkk7tDf
         2KmicdYVuWIlfLIKGmXmXefvk+hIKbT6ZQWgfTE4a3yUSBEKcuqeTXluKrxxIQU9Sidx
         ptOr3pfoiMzmm8c93yEZGQaZ0SE4Gp7tsHy6TsRZAr1/9q9QwLTYpakZumUHNm8wNJ1E
         516k8kFFe+3JpD447EEpiRIrLmB24LVYbLgf3d8ZlQ+YKU172xGQU1gISqlmES7Ekuy7
         JLT4DBy6pL8jlGAV7CRFB7KxvzezqZqaRQYeiXlCk+12QcmllfhvJnd6olYBUY/pbqPN
         ZNgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769411538; x=1770016338;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gFHbWE6cI3KMdGmJ1uf32FBiGnlvZZmamA33MIG2vKU=;
        b=PDBKtuYr/u+HV5naekm+5i1LhH/ZHLxLssE5vApY/ZoCGKRRPRdqDAigS7YY0XN6ZT
         WhVEVEhFKU3bGU2VxWKctbOZY/qj5jIkOEhsI4vqApnArQPMmvfCAXn5DJySR/73I/r5
         aSDz/jq5xoz9HLUT/UBEpTgpZdeUqGlkLxZaEmhSSrkQ88OeElGl8pxh5G8tnfu0kSSl
         edeI6K0DbibibOnbF7+YaSp3Cbm5+NA/ChAPrJ1bjBWTHJxxi2pwSCBipOZvcU6coelU
         qfHh5tQu0RwwGRfTVNWkaQCMqb15VBUYkeqMzqneHJRwou4ThySxc1VYDeb1Svz5Y2dC
         rvDg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVCCUg4Kx27gNocxh4T1GrXrCSGifCQ5SxO8xWrzmMYcuQdPVqpMrr1q1ozCDlRE3oQA2EfkQ==@lfdr.de
X-Gm-Message-State: AOJu0YwebphQwQupAxZN/ERg/Y2J75Ed74E9W+dktcG92T8aZHw9Aq6y
	gEXvXB90Cwe1UGsFlTiGOfkZ3FPHTJr/SkV3Nm1m4//0zWp9zC+qTRn8
X-Received: by 2002:a05:6512:304e:b0:59d:f71d:9d51 with SMTP id 2adb3069b0e04-59df71d9d58mr763626e87.27.1769411537593;
        Sun, 25 Jan 2026 23:12:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EsNbeDZe6fJ7l9vjmjG0Gxv6xHTNVySDG8fBUIqd9TUg=="
Received: by 2002:a05:651c:31d1:b0:37f:ab54:159c with SMTP id
 38308e7fff4ca-385c2522ffbls6715231fa.1.-pod-prod-01-eu; Sun, 25 Jan 2026
 23:12:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXxptw7GrU35FDPoPolG2kfXUSezEkXyp0JzX8hOfI135IbFC3ALemZEtUrIrPCZlm/FsZPSwZvviY=@googlegroups.com
X-Received: by 2002:a2e:a581:0:b0:383:5ea:e9c1 with SMTP id 38308e7fff4ca-385f9efe6aamr9700431fa.2.1769411535394;
        Sun, 25 Jan 2026 23:12:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769411535; cv=none;
        d=google.com; s=arc-20240605;
        b=T80OZ5Ueom2z0dI9D2l/LofUdV1HCrXcHzTP3I6TIukFjqqlghBYJfKI9nsK2tAdFf
         k5+y+IdII8iDWc4OUAX3iLHBKnF8MY8QJi3hsQpW0jDD++AnQ7wcH5hvSoDgNaTHd9aF
         ieEW9JgVk+e7j/Chzan2FxYz6XbLdkpRD5vxZEvuZik5lMeepntm4O+2qG4Lela6Mpzk
         zT3N11UzVgudRCej6vwlHgm2NpwiCNufU+ppCqzW4e1vEo9cbF6Wxl/jbgnN/6bXZMDl
         ao56sI9UpgQa1leRQlKmg2qJbGe8TKGjbqUsCUEu4FmkySFTS0UzsF84bOJYFggdpYNJ
         R+pA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=0tQJFz7jcAPVzYMIAq76r5MfF6/thKPhJ3/J6Pp98fQ=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=ZoocTiF/Pj9heGdYNwoX9lrpegC7/Y95bifDg67H5Y5yzu8X8+D4g0+7wHIBrtY0iy
         6L104VbG5NuhbMDVqWMaPVn8BroPR9PzOaAsi6EftHILPHXmd9/byg6elSZqcZvMQ9IF
         t6Zh0CKUUXYyPn3mP8qrN6unLn67NsF8r3IpT/JW7g4AvekWWB/Seg4zZ5Tgny6opSXD
         tnNV/S+0sMGZDrc6NMoq/S6di6fqYtXWwR4UfRFLpVxERY3po22ETqJbBoMehBpvhRoB
         JnEGJjIzwEDdqAP/gZAeYzVR9eHno0TQEiGFUGCMwe3lAjptzHrQiXg/unq+has/ygHy
         I4sg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Gwzs01lv;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b2 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-178.mta0.migadu.com (out-178.mta0.migadu.com. [2001:41d0:1004:224b::b2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-385da0e9ef2si1877791fa.5.2026.01.25.23.12.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 25 Jan 2026 23:12:15 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b2 as permitted sender) client-ip=2001:41d0:1004:224b::b2;
Date: Mon, 26 Jan 2026 15:12:03 +0800
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
Subject: Re: [PATCH v4 10/22] slab: add optimized sheaf refill from partial
 list
Message-ID: <jgmmllqopl4rpihfe4jdnuifzexlffef5gehsocdcdu2xdj62j@xuz56etxseza>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-10-041323d506f7@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260123-sheaves-for-all-v4-10-041323d506f7@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Gwzs01lv;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b2 as
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.11 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_RHS_NOT_FQDN(0.50)[];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[linux.dev : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_COUNT_THREE(0.00)[3];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBAABBUFH3TFQMGQERKQBTXA];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_NEQ_ENVFROM(0.00)[hao.li@linux.dev,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,linux.dev:email,mail-lf1-x13c.google.com:helo,mail-lf1-x13c.google.com:rdns,suse.cz:email]
X-Rspamd-Queue-Id: 3879A84AFD
X-Rspamd-Action: no action

On Fri, Jan 23, 2026 at 07:52:48AM +0100, Vlastimil Babka wrote:
> At this point we have sheaves enabled for all caches, but their refill
> is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
> slabs - now a redundant caching layer that we are about to remove.
> 
> The refill will thus be done from slabs on the node partial list.
> Introduce new functions that can do that in an optimized way as it's
> easier than modifying the __kmem_cache_alloc_bulk() call chain.
> 
> Introduce struct partial_bulk_context, a variant of struct
> partial_context that can return a list of slabs from the partial list
> with the sum of free objects in them within the requested min and max.
> 
> Introduce get_partial_node_bulk() that removes the slabs from freelist
> and returns them in the list. There is a racy read of slab->counters
> so make sure the non-atomic write in __update_freelist_slow() is not
> tearing.
> 
> Introduce get_freelist_nofreeze() which grabs the freelist without
> freezing the slab.
> 
> Introduce alloc_from_new_slab() which can allocate multiple objects from
> a newly allocated slab where we don't need to synchronize with freeing.
> In some aspects it's similar to alloc_single_from_new_slab() but assumes
> the cache is a non-debug one so it can avoid some actions. It supports
> the allow_spin parameter, which we always set true here, but the
> followup change will reuse the function in a context where it may be
> false.
> 
> Introduce __refill_objects() that uses the functions above to fill an
> array of objects. It has to handle the possibility that the slabs will
> contain more objects that were requested, due to concurrent freeing of
> objects to those slabs. When no more slabs on partial lists are
> available, it will allocate new slabs. It is intended to be only used
> in context where spinning is allowed, so add a WARN_ON_ONCE check there.
> 
> Finally, switch refill_sheaf() to use __refill_objects(). Sheaves are
> only refilled from contexts that allow spinning, or even blocking.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 293 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++-----
>  1 file changed, 272 insertions(+), 21 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 22acc249f9c0..142a1099bbc1 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -248,6 +248,14 @@ struct partial_context {
>  	void *object;
>  };
>  
> +/* Structure holding parameters for get_partial_node_bulk() */
> +struct partial_bulk_context {
> +	gfp_t flags;
> +	unsigned int min_objects;
> +	unsigned int max_objects;
> +	struct list_head slabs;
> +};
> +
>  static inline bool kmem_cache_debug(struct kmem_cache *s)
>  {
>  	return kmem_cache_debug_flags(s, SLAB_DEBUG_FLAGS);
> @@ -778,7 +786,8 @@ __update_freelist_slow(struct slab *slab, struct freelist_counters *old,
>  	slab_lock(slab);
>  	if (slab->freelist == old->freelist &&
>  	    slab->counters == old->counters) {
> -		slab->freelist = new->freelist;
> +		/* prevent tearing for the read in get_partial_node_bulk() */
> +		WRITE_ONCE(slab->freelist, new->freelist);

Should this perhaps be WRITE_ONCE(slab->counters, new->counters) here?

Everything else looks good to me.

Reviewed-by: Hao Li <hao.li@linux.dev>

-- 
Thanks,
Hao

>  		slab->counters = new->counters;
>  		ret = true;
>  	}
> @@ -2638,9 +2647,9 @@ static void free_empty_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf)
>  	stat(s, SHEAF_FREE);
>  }
>  
> -static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
> -				   size_t size, void **p);
> -
> +static unsigned int
> +__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
> +		 unsigned int max);
>  
>  static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
>  			 gfp_t gfp)
> @@ -2651,8 +2660,8 @@ static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
>  	if (!to_fill)
>  		return 0;
>  
> -	filled = __kmem_cache_alloc_bulk(s, gfp, to_fill,
> -					 &sheaf->objects[sheaf->size]);
> +	filled = __refill_objects(s, &sheaf->objects[sheaf->size], gfp,
> +			to_fill, to_fill);
>  
>  	sheaf->size += filled;
>  
> @@ -3518,6 +3527,57 @@ static inline void put_cpu_partial(struct kmem_cache *s, struct slab *slab,
>  #endif
>  static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags);
>  
> +static bool get_partial_node_bulk(struct kmem_cache *s,
> +				  struct kmem_cache_node *n,
> +				  struct partial_bulk_context *pc)
> +{
> +	struct slab *slab, *slab2;
> +	unsigned int total_free = 0;
> +	unsigned long flags;
> +
> +	/* Racy check to avoid taking the lock unnecessarily. */
> +	if (!n || data_race(!n->nr_partial))
> +		return false;
> +
> +	INIT_LIST_HEAD(&pc->slabs);
> +
> +	spin_lock_irqsave(&n->list_lock, flags);
> +
> +	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
> +		struct freelist_counters flc;
> +		unsigned int slab_free;
> +
> +		if (!pfmemalloc_match(slab, pc->flags))
> +			continue;
> +
> +		/*
> +		 * determine the number of free objects in the slab racily
> +		 *
> +		 * slab_free is a lower bound due to possible subsequent
> +		 * concurrent freeing, so the caller may get more objects than
> +		 * requested and must handle that
> +		 */
> +		flc.counters = data_race(READ_ONCE(slab->counters));
> +		slab_free = flc.objects - flc.inuse;
> +
> +		/* we have already min and this would get us over the max */
> +		if (total_free >= pc->min_objects
> +		    && total_free + slab_free > pc->max_objects)
> +			break;
> +
> +		remove_partial(n, slab);
> +
> +		list_add(&slab->slab_list, &pc->slabs);
> +
> +		total_free += slab_free;
> +		if (total_free >= pc->max_objects)
> +			break;
> +	}
> +
> +	spin_unlock_irqrestore(&n->list_lock, flags);
> +	return total_free > 0;
> +}
> +
>  /*
>   * Try to allocate a partial slab from a specific node.
>   */
> @@ -4444,6 +4504,33 @@ static inline void *get_freelist(struct kmem_cache *s, struct slab *slab)
>  	return old.freelist;
>  }
>  
> +/*
> + * Get the slab's freelist and do not freeze it.
> + *
> + * Assumes the slab is isolated from node partial list and not frozen.
> + *
> + * Assumes this is performed only for caches without debugging so we
> + * don't need to worry about adding the slab to the full list.
> + */
> +static inline void *get_freelist_nofreeze(struct kmem_cache *s, struct slab *slab)
> +{
> +	struct freelist_counters old, new;
> +
> +	do {
> +		old.freelist = slab->freelist;
> +		old.counters = slab->counters;
> +
> +		new.freelist = NULL;
> +		new.counters = old.counters;
> +		VM_WARN_ON_ONCE(new.frozen);
> +
> +		new.inuse = old.objects;
> +
> +	} while (!slab_update_freelist(s, slab, &old, &new, "get_freelist_nofreeze"));
> +
> +	return old.freelist;
> +}
> +
>  /*
>   * Freeze the partial slab and return the pointer to the freelist.
>   */
> @@ -4467,6 +4554,72 @@ static inline void *freeze_slab(struct kmem_cache *s, struct slab *slab)
>  	return old.freelist;
>  }
>  
> +/*
> + * If the object has been wiped upon free, make sure it's fully initialized by
> + * zeroing out freelist pointer.
> + *
> + * Note that we also wipe custom freelist pointers.
> + */
> +static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
> +						   void *obj)
> +{
> +	if (unlikely(slab_want_init_on_free(s)) && obj &&
> +	    !freeptr_outside_object(s))
> +		memset((void *)((char *)kasan_reset_tag(obj) + s->offset),
> +			0, sizeof(void *));
> +}
> +
> +static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
> +		void **p, unsigned int count, bool allow_spin)
> +{
> +	unsigned int allocated = 0;
> +	struct kmem_cache_node *n;
> +	bool needs_add_partial;
> +	unsigned long flags;
> +	void *object;
> +
> +	/*
> +	 * Are we going to put the slab on the partial list?
> +	 * Note slab->inuse is 0 on a new slab.
> +	 */
> +	needs_add_partial = (slab->objects > count);
> +
> +	if (!allow_spin && needs_add_partial) {
> +
> +		n = get_node(s, slab_nid(slab));
> +
> +		if (!spin_trylock_irqsave(&n->list_lock, flags)) {
> +			/* Unlucky, discard newly allocated slab */
> +			defer_deactivate_slab(slab, NULL);
> +			return 0;
> +		}
> +	}
> +
> +	object = slab->freelist;
> +	while (object && allocated < count) {
> +		p[allocated] = object;
> +		object = get_freepointer(s, object);
> +		maybe_wipe_obj_freeptr(s, p[allocated]);
> +
> +		slab->inuse++;
> +		allocated++;
> +	}
> +	slab->freelist = object;
> +
> +	if (needs_add_partial) {
> +
> +		if (allow_spin) {
> +			n = get_node(s, slab_nid(slab));
> +			spin_lock_irqsave(&n->list_lock, flags);
> +		}
> +		add_partial(n, slab, DEACTIVATE_TO_HEAD);
> +		spin_unlock_irqrestore(&n->list_lock, flags);
> +	}
> +
> +	inc_slabs_node(s, slab_nid(slab), slab->objects);
> +	return allocated;
> +}
> +
>  /*
>   * Slow path. The lockless freelist is empty or we need to perform
>   * debugging duties.
> @@ -4909,21 +5062,6 @@ static __always_inline void *__slab_alloc_node(struct kmem_cache *s,
>  	return object;
>  }
>  
> -/*
> - * If the object has been wiped upon free, make sure it's fully initialized by
> - * zeroing out freelist pointer.
> - *
> - * Note that we also wipe custom freelist pointers.
> - */
> -static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
> -						   void *obj)
> -{
> -	if (unlikely(slab_want_init_on_free(s)) && obj &&
> -	    !freeptr_outside_object(s))
> -		memset((void *)((char *)kasan_reset_tag(obj) + s->offset),
> -			0, sizeof(void *));
> -}
> -
>  static __fastpath_inline
>  struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s, gfp_t flags)
>  {
> @@ -5384,6 +5522,9 @@ static int __prefill_sheaf_pfmemalloc(struct kmem_cache *s,
>  	return ret;
>  }
>  
> +static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
> +				   size_t size, void **p);
> +
>  /*
>   * returns a sheaf that has at least the requested size
>   * when prefilling is needed, do so with given gfp flags
> @@ -7484,6 +7625,116 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
>  }
>  EXPORT_SYMBOL(kmem_cache_free_bulk);
>  
> +static unsigned int
> +__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
> +		 unsigned int max)
> +{
> +	struct partial_bulk_context pc;
> +	struct slab *slab, *slab2;
> +	unsigned int refilled = 0;
> +	unsigned long flags;
> +	void *object;
> +	int node;
> +
> +	pc.flags = gfp;
> +	pc.min_objects = min;
> +	pc.max_objects = max;
> +
> +	node = numa_mem_id();
> +
> +	if (WARN_ON_ONCE(!gfpflags_allow_spinning(gfp)))
> +		return 0;
> +
> +	/* TODO: consider also other nodes? */
> +	if (!get_partial_node_bulk(s, get_node(s, node), &pc))
> +		goto new_slab;
> +
> +	list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
> +
> +		list_del(&slab->slab_list);
> +
> +		object = get_freelist_nofreeze(s, slab);
> +
> +		while (object && refilled < max) {
> +			p[refilled] = object;
> +			object = get_freepointer(s, object);
> +			maybe_wipe_obj_freeptr(s, p[refilled]);
> +
> +			refilled++;
> +		}
> +
> +		/*
> +		 * Freelist had more objects than we can accommodate, we need to
> +		 * free them back. We can treat it like a detached freelist, just
> +		 * need to find the tail object.
> +		 */
> +		if (unlikely(object)) {
> +			void *head = object;
> +			void *tail;
> +			int cnt = 0;
> +
> +			do {
> +				tail = object;
> +				cnt++;
> +				object = get_freepointer(s, object);
> +			} while (object);
> +			do_slab_free(s, slab, head, tail, cnt, _RET_IP_);
> +		}
> +
> +		if (refilled >= max)
> +			break;
> +	}
> +
> +	if (unlikely(!list_empty(&pc.slabs))) {
> +		struct kmem_cache_node *n = get_node(s, node);
> +
> +		spin_lock_irqsave(&n->list_lock, flags);
> +
> +		list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
> +
> +			if (unlikely(!slab->inuse && n->nr_partial >= s->min_partial))
> +				continue;
> +
> +			list_del(&slab->slab_list);
> +			add_partial(n, slab, DEACTIVATE_TO_HEAD);
> +		}
> +
> +		spin_unlock_irqrestore(&n->list_lock, flags);
> +
> +		/* any slabs left are completely free and for discard */
> +		list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
> +
> +			list_del(&slab->slab_list);
> +			discard_slab(s, slab);
> +		}
> +	}
> +
> +
> +	if (likely(refilled >= min))
> +		goto out;
> +
> +new_slab:
> +
> +	slab = new_slab(s, pc.flags, node);
> +	if (!slab)
> +		goto out;
> +
> +	stat(s, ALLOC_SLAB);
> +
> +	/*
> +	 * TODO: possible optimization - if we know we will consume the whole
> +	 * slab we might skip creating the freelist?
> +	 */
> +	refilled += alloc_from_new_slab(s, slab, p + refilled, max - refilled,
> +					/* allow_spin = */ true);
> +
> +	if (refilled < min)
> +		goto new_slab;
> +out:
> +
> +	return refilled;
> +}
> +
>  static inline
>  int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  			    void **p)
> 
> -- 
> 2.52.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/jgmmllqopl4rpihfe4jdnuifzexlffef5gehsocdcdu2xdj62j%40xuz56etxseza.
