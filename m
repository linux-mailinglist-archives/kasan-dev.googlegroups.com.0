Return-Path: <kasan-dev+bncBAABBHG5Y3FQMGQEHYEIGNA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id gI7fJZ6ucWlmLQAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBHG5Y3FQMGQEHYEIGNA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 05:59:10 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 118D961D9A
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 05:59:10 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-385c73b50dbsf1439571fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 20:59:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769057949; cv=pass;
        d=google.com; s=arc-20240605;
        b=HreE9fjdOUNc1uQOzkCzLDTHd3sioutykzBzxrIHFetWOhbKyU+Hoe2OXlxckuzgoJ
         xz5j2joEexu+bcVhX5scS3hhLAf9XXimkzUBFNzlIsaJKpbdpXtIeMxMNQYdevVLPPl7
         JpLqfYy92MjbraQ1ARvTfEcvkCLNpDrX0dihp3RWm9eqWRCkma12/SmrEk1sPwkEb++U
         Fz3fg/LffRLjTaz3nfquxf0Cb03eZD8G9KWMIx7Vo3rcLahw+jnIl2qyJoCwk9dr9ja3
         g3SNn8ZWohF3oc48BSZ8Acb7ttGgikTmr33ceZWCCY75K4A1dAZxKCnidIbNJnRH4bvr
         Ch7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6ljjaon6wreA+oYL7GdspKQsd2hzc8e3Quum3Bxbly4=;
        fh=5OdZu/aEBjc1tFEmInwgciUtzwgZz/3d1ydmIm+ZsdM=;
        b=FxhrScl4PYCYek9MdOrp2RFJbmXfFl45v5D6FHYr0hhfiVnpUteE/XiTQY5nH9ykYo
         q2V5DO4S0vQaNthxw1doEPW3Bt2E/DUx0A3W2pUSFYbfDwkzTdtD1+P1bVne2EVe8UWb
         1+F0ezRcDvX8npHv5j7EoFZ5qcodVuUTv/BSANeOzTjIbKmvVTzdurxDG1RzOndpsIAh
         hXevDxzhJjhAZ/CW/EnYttYA1yItGmcCVDpMSAeY1lPLicaxN4KBRSIgHlYsnnUtoGYj
         tE/48a9uzO5hi/9buGQVJ34/83LoSEy8W7/gUEmNE6cRY0KFKDi6PdpnGh5B5XYqLPFA
         rNJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ibmzka49;
       spf=pass (google.com: domain of hao.li@linux.dev designates 91.218.175.178 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769057949; x=1769662749; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6ljjaon6wreA+oYL7GdspKQsd2hzc8e3Quum3Bxbly4=;
        b=kWKV0FbCetZ9cKx3Y9sflDFOM4U+bKN0BMZbc8QUo8ADD3ywQYOT9Rw2xI2gquhNUJ
         /SJJUMBhNyvwjGABYGGwlRSE1//eXfcn2QJ3HoboRUYS3XjFHhA48QW4TeIU02Ci/qRw
         bcFzY61FaFX/FElipoqAjT66rirc3+sMboDo5lFpBdUBt0WZM0WNRnWTfgHr0DfFkLek
         u+ofcPHHxRi75mTsb9mddFjZevwE1X7O1WyaWbGR2chXoQqDwNfV9y9hD/fUJBx8D6S3
         nI209tAh8Bk5EZlaaVEFciWDGc62ayn/3yh73g9mAlCSxrb/IWBah2xEsCECviAIpcBJ
         KR+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769057949; x=1769662749;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6ljjaon6wreA+oYL7GdspKQsd2hzc8e3Quum3Bxbly4=;
        b=n62x7STb15mFz+jisls+8T7F1OLN/VKsaAETUbF3c3+4E5R4FgTSOc35DKDLs4alji
         H9ciJ21m3+CbYWF2UsWWdIw0BsWIut3UvAK/ozJiysyvs29jKnzNYHZt2AsZOwGXM9/E
         TP3F8zE7d+szcNqoZJtn6WQAYPdEIvePZg2QU+dpoFf7UpWdb/NAjqpv62/dSNfH0InW
         f1qfALLpbvW+bne64Q5GKRuzO9N1IFZO87CDur0wiD6VGyaVu3BU8T7OPuAN6g3AYb9J
         QpzJl8iOsTDHri8bfTXudQPp3SKu83U707xYCGqe2aujsQaSYw3Mzt5B+SvPvtRPQMPt
         vVBg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW2+k+Apj1NzJV5tfw+AcoVTW6Finb4TfJBHiXYlT3Nyi+mtwVmdsClpJf33YeB2Kvq6hPOhA==@lfdr.de
X-Gm-Message-State: AOJu0YzY3RmIoeN/b2dAjoFbkLhZzdCVGvuflFBcyNQy5q90CJg9QMZS
	M+bOyATGtS2mffZQSSWDyQRiidjivzEicOFJo+26rHLIAjG1fwmkaEK3
X-Received: by 2002:a05:651c:2228:b0:383:160f:c230 with SMTP id 38308e7fff4ca-385c2aa58camr6455411fa.6.1769057948863;
        Wed, 21 Jan 2026 20:59:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ExuQ8XGQrV8bjbyPE2UXtCH8ge87HF3MyW2ItjZVj4PQ=="
Received: by 2002:a05:651c:255a:10b0:378:dd6c:719 with SMTP id
 38308e7fff4ca-385aef27951ls647911fa.1.-pod-prod-00-eu-canary; Wed, 21 Jan
 2026 20:59:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUlUgo2Qo64NtENZ5+W/kyThEvK28FiR7MHOke9Zg+Ba5axk7tcO2NMQABhjcs0Zuif4RcJijVQX+Y=@googlegroups.com
X-Received: by 2002:a2e:3509:0:b0:383:1bcc:119b with SMTP id 38308e7fff4ca-385c2b79cc6mr4153051fa.13.1769057946787;
        Wed, 21 Jan 2026 20:59:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769057946; cv=none;
        d=google.com; s=arc-20240605;
        b=ZY6cQT3RzmCWH2vJlEuiIFMzSJBlTE3jQHCzhfbmeQMoYy3d58H+2wzRZHqDxfgmQT
         pAY8xnBQZcFkGjEgyRLeA1ecCn4gi9IIHYN08O6nizMzkzLAclyTsn6VBQGPv3sN5Dcn
         2zVMIRIINFcNJ0Q335J4IDh1ffF4R+bPUc+HQCbSQbSUXuGakUUQXuz5W+zlXYopoEhs
         6W5OqTcrp3LNP0vrmNx6zGDy6rrwu2brUAjugZjDq3+NqHYrNffkMFLyYjusX22GaGGO
         QMvm9tfzcfAOPbspRBOjhbNrGGOJ4R/nUUoKxgK4vhOOK/emf0GtiEVn5Xc0Q+kov949
         Xsyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=MdpaA1zGTiovVE63EwimqyFpitVdOAF+4rwOeZdtVJc=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=GmSrkuh2wgolm2lyHXvo4gF8kzCdDqFTllHHqrgbQPFO13cA7jKyzI1zNb+CDacf66
         knN636h+k1xSCsF7fbTX3aEU1U+89bXuOu7Z4A/2rpr2WQ/WGubtCJ2Nmg0D3CDpbUnG
         Hn/f4MP+v2p6fiAt+ToLKHBi6HQLQ1VQ34FtUG9SNWbwiz8IEl4KWz+cS8xoK64DooIR
         jzqNPo8/MLxfnJSJ/1c9EkhlJTdVT5q1zqZqdqkA3h8kYfb3IS/vzZq17YczFngoNbB2
         0aqq9ZfJup6sB06lH3osDN20mWHCX1z4E0Fvp2WuNCgIxRDIV6b2l6AAtKFEr7L9syMP
         rUeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ibmzka49;
       spf=pass (google.com: domain of hao.li@linux.dev designates 91.218.175.178 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-178.mta0.migadu.com (out-178.mta0.migadu.com. [91.218.175.178])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384e27d7bsi2915411fa.4.2026.01.21.20.59.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 20:59:06 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 91.218.175.178 as permitted sender) client-ip=91.218.175.178;
Date: Thu, 22 Jan 2026 12:58:54 +0800
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
Subject: Re: [PATCH v3 17/21] slab: refill sheaves from all nodes
Message-ID: <gmpxnzifhxamwnngr6holbcfdd42fvuq2xtqrqvdz75zv6fb57@hxbmcgfxtuko>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-17-5595cb000772@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-17-5595cb000772@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ibmzka49;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 91.218.175.178 as
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
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[linux.dev : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_COUNT_THREE(0.00)[3];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	RCVD_TLS_LAST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_NEQ_ENVFROM(0.00)[hao.li@linux.dev,kasan-dev@googlegroups.com];
	TAGGED_FROM(0.00)[bncBAABBHG5Y3FQMGQEHYEIGNA];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,linux.dev:email,suse.cz:email]
X-Rspamd-Queue-Id: 118D961D9A
X-Rspamd-Action: no action

On Fri, Jan 16, 2026 at 03:40:37PM +0100, Vlastimil Babka wrote:
> __refill_objects() currently only attempts to get partial slabs from the
> local node and then allocates new slab(s). Expand it to trying also
> other nodes while observing the remote node defrag ratio, similarly to
> get_any_partial().
> 
> This will prevent allocating new slabs on a node while other nodes have
> many free slabs. It does mean sheaves will contain non-local objects in
> that case. Allocations that care about specific node will still be
> served appropriately, but might get a slowpath allocation.
> 
> Like get_any_partial() we do observe cpuset_zone_allowed(), although we
> might be refilling a sheaf that will be then used from a different
> allocation context.
> 
> We can also use the resulting refill_objects() in
> __kmem_cache_alloc_bulk() for non-debug caches. This means
> kmem_cache_alloc_bulk() will get better performance when sheaves are
> exhausted. kmem_cache_alloc_bulk() cannot indicate a preferred node so
> it's compatible with sheaves refill in preferring the local node.
> Its users also have gfp flags that allow spinning, so document that
> as a requirement.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 137 ++++++++++++++++++++++++++++++++++++++++++++++++--------------
>  1 file changed, 106 insertions(+), 31 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index d52de6e3c2d5..2c522d2bf547 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2518,8 +2518,8 @@ static void free_empty_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf)
>  }
>  
>  static unsigned int
> -__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
> -		 unsigned int max);
> +refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
> +	       unsigned int max);
>  
>  static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
>  			 gfp_t gfp)
> @@ -2530,8 +2530,8 @@ static int refill_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf,
>  	if (!to_fill)
>  		return 0;
>  
> -	filled = __refill_objects(s, &sheaf->objects[sheaf->size], gfp,
> -			to_fill, to_fill);
> +	filled = refill_objects(s, &sheaf->objects[sheaf->size], gfp, to_fill,
> +				to_fill);
>  
>  	sheaf->size += filled;
>  
> @@ -6522,29 +6522,22 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
>  EXPORT_SYMBOL(kmem_cache_free_bulk);
>  
>  static unsigned int
> -__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
> -		 unsigned int max)
> +__refill_objects_node(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
> +		      unsigned int max, struct kmem_cache_node *n)
>  {
>  	struct slab *slab, *slab2;
>  	struct partial_context pc;
>  	unsigned int refilled = 0;
>  	unsigned long flags;
>  	void *object;
> -	int node;
>  
>  	pc.flags = gfp;
>  	pc.min_objects = min;
>  	pc.max_objects = max;
>  
> -	node = numa_mem_id();
> -
> -	if (WARN_ON_ONCE(!gfpflags_allow_spinning(gfp)))
> +	if (!get_partial_node_bulk(s, n, &pc))
>  		return 0;
>  
> -	/* TODO: consider also other nodes? */
> -	if (!get_partial_node_bulk(s, get_node(s, node), &pc))
> -		goto new_slab;
> -
>  	list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
>  
>  		list_del(&slab->slab_list);
> @@ -6582,8 +6575,6 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
>  	}
>  
>  	if (unlikely(!list_empty(&pc.slabs))) {
> -		struct kmem_cache_node *n = get_node(s, node);
> -
>  		spin_lock_irqsave(&n->list_lock, flags);
>  
>  		list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
> @@ -6605,13 +6596,92 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
>  		}
>  	}
>  
> +	return refilled;
> +}
>  
> -	if (likely(refilled >= min))
> -		goto out;
> +#ifdef CONFIG_NUMA
> +static unsigned int
> +__refill_objects_any(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
> +		     unsigned int max, int local_node)


Just a small note: I noticed that the local_node variable is unused. It seems
the intention was to skip local_node in __refill_objects_any(), since it had
already been attempted in __refill_objects_node().

Everything else looks good.

Reviewed-by: Hao Li <hao.li@linux.dev>

> +{
> +	struct zonelist *zonelist;
> +	struct zoneref *z;
> +	struct zone *zone;
> +	enum zone_type highest_zoneidx = gfp_zone(gfp);
> +	unsigned int cpuset_mems_cookie;
> +	unsigned int refilled = 0;
> +
> +	/* see get_any_partial() for the defrag ratio description */
> +	if (!s->remote_node_defrag_ratio ||
> +			get_cycles() % 1024 > s->remote_node_defrag_ratio)
> +		return 0;
> +
> +	do {
> +		cpuset_mems_cookie = read_mems_allowed_begin();
> +		zonelist = node_zonelist(mempolicy_slab_node(), gfp);
> +		for_each_zone_zonelist(zone, z, zonelist, highest_zoneidx) {
> +			struct kmem_cache_node *n;
> +			unsigned int r;
> +
> +			n = get_node(s, zone_to_nid(zone));
> +
> +			if (!n || !cpuset_zone_allowed(zone, gfp) ||
> +					n->nr_partial <= s->min_partial)
> +				continue;
> +
> +			r = __refill_objects_node(s, p, gfp, min, max, n);
> +			refilled += r;
> +
> +			if (r >= min) {
> +				/*
> +				 * Don't check read_mems_allowed_retry() here -
> +				 * if mems_allowed was updated in parallel, that
> +				 * was a harmless race between allocation and
> +				 * the cpuset update
> +				 */
> +				return refilled;
> +			}
> +			p += r;
> +			min -= r;
> +			max -= r;
> +		}
> +	} while (read_mems_allowed_retry(cpuset_mems_cookie));
> +
> +	return refilled;
> +}
> +#else
> +static inline unsigned int
> +__refill_objects_any(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
> +		     unsigned int max, int local_node)
> +{
> +	return 0;
> +}
> +#endif
> +
> +static unsigned int
> +refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
> +	       unsigned int max)
> +{
> +	int local_node = numa_mem_id();
> +	unsigned int refilled;
> +	struct slab *slab;
> +
> +	if (WARN_ON_ONCE(!gfpflags_allow_spinning(gfp)))
> +		return 0;
> +
> +	refilled = __refill_objects_node(s, p, gfp, min, max,
> +					 get_node(s, local_node));
> +	if (refilled >= min)
> +		return refilled;
> +
> +	refilled += __refill_objects_any(s, p + refilled, gfp, min - refilled,
> +					 max - refilled, local_node);
> +	if (refilled >= min)
> +		return refilled;
>  
>  new_slab:
>  
> -	slab = new_slab(s, pc.flags, node);
> +	slab = new_slab(s, gfp, local_node);
>  	if (!slab)
>  		goto out;
>  
> @@ -6626,8 +6696,8 @@ __refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
>  
>  	if (refilled < min)
>  		goto new_slab;
> -out:
>  
> +out:
>  	return refilled;
>  }
>  
> @@ -6637,18 +6707,20 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  {
>  	int i;
>  
> -	/*
> -	 * TODO: this might be more efficient (if necessary) by reusing
> -	 * __refill_objects()
> -	 */
> -	for (i = 0; i < size; i++) {
> +	if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
> +		for (i = 0; i < size; i++) {
>  
> -		p[i] = ___slab_alloc(s, flags, NUMA_NO_NODE, _RET_IP_,
> -				     s->object_size);
> -		if (unlikely(!p[i]))
> -			goto error;
> +			p[i] = ___slab_alloc(s, flags, NUMA_NO_NODE, _RET_IP_,
> +					     s->object_size);
> +			if (unlikely(!p[i]))
> +				goto error;
>  
> -		maybe_wipe_obj_freeptr(s, p[i]);
> +			maybe_wipe_obj_freeptr(s, p[i]);
> +		}
> +	} else {
> +		i = refill_objects(s, p, flags, size, size);
> +		if (i < size)
> +			goto error;
>  	}
>  
>  	return i;
> @@ -6659,7 +6731,10 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  
>  }
>  
> -/* Note that interrupts must be enabled when calling this function. */
> +/*
> + * Note that interrupts must be enabled when calling this function and gfp
> + * flags must allow spinning.
> + */
>  int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
>  				 void **p)
>  {
> 
> -- 
> 2.52.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/gmpxnzifhxamwnngr6holbcfdd42fvuq2xtqrqvdz75zv6fb57%40hxbmcgfxtuko.
