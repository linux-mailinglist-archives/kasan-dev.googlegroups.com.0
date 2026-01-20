Return-Path: <kasan-dev+bncBAABB2HPXXFQMGQEOYRQVDY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id yBGiGrizb2nHMAAAu9opvQ
	(envelope-from <kasan-dev+bncBAABB2HPXXFQMGQEOYRQVDY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:56:24 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DE06480FD
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:56:24 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-43101a351c7sf5120263f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 08:56:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768928183; cv=pass;
        d=google.com; s=arc-20240605;
        b=TXicaEga7CrHFhPoL0U3kM/xDOyCIxqHqF/nuSPSjWPIIm3InaQPYBjSxuTTKNWLjF
         /yO1eBuqb7DFWOeqYdLQqzmrTwMHzDBZ8wELmzc6ZDygpZtMixTQIKEp4loeNsG8Jrab
         UId/URdePSgV4v5I6pqHLkriVFC4/g/r0BQ/ZOdlXkevNU6SGef/8MJG5+TOCYnJ0V5U
         bQqWyRlJsEl6YE9OUSUWgi7W691CvWZG58qkRKRs8KOAg9ifYduPncAhODtLFoUCziUg
         ZX1/o4Ag+DiFoUOLpBnt3fk826L+R/x3/3iMpT4x8FzpwNFGEJY4nZasxFDa+yfHpBhP
         oV5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=SwENxqIcQFJ7ZQPOM/zRzbUpLUnsjxipsKer7zF3iEU=;
        fh=NTLDUoM3wQXXJLkHE65G5cdJwdMxdvZ3pyBVmduIk7g=;
        b=S6P8qM8yadqAQsAYzdCs6/WePhmluRtJ8N7kEjrVXhocrV85fMD+8jfBYivMPv0ECo
         nj+atb9gkLxPuWuXeLfAXpml6w+c/6uNt95QzpyD3Cg9E5Azqc5X9gvVS/o0h7rVXskF
         52P0TYTVELsGb4MePKjsCJmOxrf/l24CZmN48biEv+DHnBWtddQ92jZi6O08RkB8ds48
         VCkdYNcdJzMGCcQe9IuohB1phWNzc1HrUPgflYnA9cAN+WB8E+1p6f7hMMZU+9vK9sUU
         iiUGGMtpTj1MMuiZ0vjvrbcs+evMbpCmSvQ21S/856E02NpB2Ny3GbDsllfw3Z3LaXof
         P4Tw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="r8EHeJ3/";
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b8 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768928183; x=1769532983; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SwENxqIcQFJ7ZQPOM/zRzbUpLUnsjxipsKer7zF3iEU=;
        b=jPp2ri0W4cpwMxV5ki5YFY/IjXYA0F2T151+m1PHqsGGeCe6pFmLjW2fi8BWLCR0JA
         EuwgaeenGitDzmFOz7l8LCUWe6Ree8ciRzL84546AiTNxjnNxrX+UiUAWnDhBSiss8Gk
         81vH7FUBCTPbluLnDWAallhrYS331m5T3FL9AtAJflywRlUG4EK8kyFXnE/Fs86ImTxF
         5L7tTeZ+yvI9I0fILcSq0kGi5BpzmGh1FBpM9/pdjl7Qz5fpx3cuBUzQ2D8twwveVuBV
         1DW/RIaaacBBTwBj58f9pqmf3y2Yy0DXydlE+K/FpUzRc/KZMhIaFRmBS/37xWOicqDr
         PUtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768928183; x=1769532983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SwENxqIcQFJ7ZQPOM/zRzbUpLUnsjxipsKer7zF3iEU=;
        b=OWvdqZfY4CEUg5faWRvGN5pSpVR5Dl/+U3Ze/DSfzG0jb8M9QM6aUHW7ge2WFAWL7j
         KMh2T20CY6wbn820tkFlGBbg1MINFUnR/wSTOIq9nytAjUOA4ZfRgwTaWrBud5r1B8Jx
         K3bwN7+n/n3klwaElOhTOnIEf3gt3R+Jk92CxJdrLZyH+6MOBGYryrdWHLCs2f7wAO9e
         7hZvddwsuW15LGw35fBhF70y5UIWl3t5et7tmb/URb2r5JNIb8SBaDu3guyOVPIu9wPt
         Dz6U4JmQ5AMGuUM+RTYfjafEGx1afU/G9evDcGo/yqG4yuY3n8kyq+oWAT7BVPFaSc84
         SNcQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW+HJWBvfpJlEly437EjFoJm+xOSvFirlUIzF8Cg0FDpYlCgUxCDPdf7qcjscnl1Uo+GS8xGg==@lfdr.de
X-Gm-Message-State: AOJu0YzR7Fw4WLDEKiO3INpT6Lb8HRstQQBkWkv+LbqYdfpbR5buancU
	VJf4FBynj2L1OCg136GVk3T1IztC3xvl0B8RUO0EkrL1Q/XX0kZiMfly
X-Received: by 2002:a05:600c:1c13:b0:47e:e414:b915 with SMTP id 5b1f17b1804b1-48028a65fb7mr129476805e9.2.1768912872586;
        Tue, 20 Jan 2026 04:41:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Hcq5V2DlPBtZsPBNPWJictc3wH95B7FwV6e10PpgPehA=="
Received: by 2002:a05:600c:3510:b0:47a:74d9:db with SMTP id
 5b1f17b1804b1-47fb730a4a5ls31331945e9.1.-pod-prod-02-eu; Tue, 20 Jan 2026
 04:41:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVJ7fZklD6FnYHsVMe+W4YEa6h41AgtpY0AUgBjF//YaWHvLufyVDveBLlBK30ab1Lx8hs0fEPjAME=@googlegroups.com
X-Received: by 2002:a05:600d:644f:10b0:47b:da85:b9ef with SMTP id 5b1f17b1804b1-4801e2fef40mr162099765e9.16.1768912870561;
        Tue, 20 Jan 2026 04:41:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768912870; cv=none;
        d=google.com; s=arc-20240605;
        b=EevpsRLGNhb1hZL3q3xZRdWG9JpTNd84GDjfhf/hvv+fDiMMPzgI1V2/8HeMe6NmxD
         gHR+Lx2DDCfDLyc4Os//X9RBdQ04bE04DwkTcWMKogUPtr9p0fQWXSDyEgouzrc+VJon
         SY/DTPdOrv/Vi6kFGOQgW7jl/hKY/HOhOCUirfmL5kqzN1myaalPtd5mtlOSmabncNcA
         TAtyEHS2+tQk+GFyJpk4wju2mWoLHiZVURv32S01hxnLmPhRvqCYpEbW8rwXW65opRXB
         LgFfwljIOyiTqbuIoBUetftAifGhXC7hEZqJEalI65zq3OxOdBpkS4MCosJ5sSI19ieK
         TIBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=SXI4I+Ibj/Ldc6/+dbWsvhs8PZ/UM4pm3iJ+tzviRtk=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=YFM85yOlouJqR3xACIQM6Y5AWuroEf3xABSVrv6j+tC3x0u/5HVdE1DPQ6+KLndpYO
         Jhght9QTxpvynIhfgw54j9Pkd8MjFqUAzGvS6t1z5hh5wRmbs3IQGMEboJvrXkkpA7kx
         33x4LEWtjuN9Py4RzrKVEG21g+6DVoWkFF98J6SjzZHPcWMxpJxoTviaswvO1325HnJX
         wVH8C/tRhwrQVLzgxwWX714vZ7Ms79bF8XskWhRjtX19e0lVaFLrMJZFDen96J2KM2og
         Pbe+DKH9078ZX4GacegUEob9zKVvsTVeQgXBW8ykqGoEVS5gDqYFMOdQCuAfgFn4+nwm
         FGrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="r8EHeJ3/";
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b8 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-184.mta0.migadu.com (out-184.mta0.migadu.com. [2001:41d0:1004:224b::b8])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4358dd61998si42517f8f.9.2026.01.20.04.41.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 04:41:10 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b8 as permitted sender) client-ip=2001:41d0:1004:224b::b8;
Date: Tue, 20 Jan 2026 20:40:39 +0800
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
Subject: Re: [PATCH v3 15/21] slab: remove struct kmem_cache_cpu
Message-ID: <dxrm4m545d4pzxmxjve34qwxwlw4kbmuz3xwdhvjheyeosa6y7@2zezo6xejama>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-15-5595cb000772@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-15-5595cb000772@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="r8EHeJ3/";       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b8 as
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
	TAGGED_FROM(0.00)[bncBAABB2HPXXFQMGQEOYRQVDY];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,linux.dev:email,mail-wr1-x440.google.com:rdns,mail-wr1-x440.google.com:helo,suse.cz:email]
X-Rspamd-Queue-Id: 0DE06480FD
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Fri, Jan 16, 2026 at 03:40:35PM +0100, Vlastimil Babka wrote:
> The cpu slab is not used anymore for allocation or freeing, the
> remaining code is for flushing, but it's effectively dead.  Remove the
> whole struct kmem_cache_cpu, the flushing code and other orphaned
> functions.
> 
> The remaining used field of kmem_cache_cpu is the stat array with
> CONFIG_SLUB_STATS. Put it instead in a new struct kmem_cache_stats.
> In struct kmem_cache, the field is cpu_stats and placed near the
> end of the struct.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slab.h |   7 +-
>  mm/slub.c | 298 +++++---------------------------------------------------------
>  2 files changed, 24 insertions(+), 281 deletions(-)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index e9a0738133ed..87faeb6143f2 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -21,14 +21,12 @@
>  # define system_has_freelist_aba()	system_has_cmpxchg128()
>  # define try_cmpxchg_freelist		try_cmpxchg128
>  # endif
> -#define this_cpu_try_cmpxchg_freelist	this_cpu_try_cmpxchg128
>  typedef u128 freelist_full_t;
>  #else /* CONFIG_64BIT */
>  # ifdef system_has_cmpxchg64
>  # define system_has_freelist_aba()	system_has_cmpxchg64()
>  # define try_cmpxchg_freelist		try_cmpxchg64
>  # endif
> -#define this_cpu_try_cmpxchg_freelist	this_cpu_try_cmpxchg64
>  typedef u64 freelist_full_t;
>  #endif /* CONFIG_64BIT */
>  
> @@ -189,7 +187,6 @@ struct kmem_cache_order_objects {
>   * Slab cache management.
>   */
>  struct kmem_cache {
> -	struct kmem_cache_cpu __percpu *cpu_slab;
>  	struct slub_percpu_sheaves __percpu *cpu_sheaves;
>  	/* Used for retrieving partial slabs, etc. */
>  	slab_flags_t flags;
> @@ -238,6 +235,10 @@ struct kmem_cache {
>  	unsigned int usersize;		/* Usercopy region size */
>  #endif
>  
> +#ifdef CONFIG_SLUB_STATS
> +	struct kmem_cache_stats __percpu *cpu_stats;
> +#endif
> +
>  	struct kmem_cache_node *node[MAX_NUMNODES];
>  };
>  
> diff --git a/mm/slub.c b/mm/slub.c
> index 8746d9d3f3a3..bb72cfa2d7ec 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -400,28 +400,11 @@ enum stat_item {
>  	NR_SLUB_STAT_ITEMS
>  };
>  
> -struct freelist_tid {
> -	union {
> -		struct {
> -			void *freelist;		/* Pointer to next available object */
> -			unsigned long tid;	/* Globally unique transaction id */
> -		};
> -		freelist_full_t freelist_tid;
> -	};
> -};
> -
> -/*
> - * When changing the layout, make sure freelist and tid are still compatible
> - * with this_cpu_cmpxchg_double() alignment requirements.
> - */
> -struct kmem_cache_cpu {
> -	struct freelist_tid;
> -	struct slab *slab;	/* The slab from which we are allocating */
> -	local_trylock_t lock;	/* Protects the fields above */
>  #ifdef CONFIG_SLUB_STATS
> +struct kmem_cache_stats {
>  	unsigned int stat[NR_SLUB_STAT_ITEMS];
> -#endif
>  };
> +#endif
>  
>  static inline void stat(const struct kmem_cache *s, enum stat_item si)
>  {
> @@ -430,7 +413,7 @@ static inline void stat(const struct kmem_cache *s, enum stat_item si)
>  	 * The rmw is racy on a preemptible kernel but this is acceptable, so
>  	 * avoid this_cpu_add()'s irq-disable overhead.
>  	 */
> -	raw_cpu_inc(s->cpu_slab->stat[si]);
> +	raw_cpu_inc(s->cpu_stats->stat[si]);
>  #endif
>  }
>  
> @@ -438,7 +421,7 @@ static inline
>  void stat_add(const struct kmem_cache *s, enum stat_item si, int v)
>  {
>  #ifdef CONFIG_SLUB_STATS
> -	raw_cpu_add(s->cpu_slab->stat[si], v);
> +	raw_cpu_add(s->cpu_stats->stat[si], v);
>  #endif
>  }
>  
> @@ -1160,20 +1143,6 @@ static void object_err(struct kmem_cache *s, struct slab *slab,
>  	WARN_ON(1);
>  }
>  
> -static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
> -			       void **freelist, void *nextfree)
> -{
> -	if ((s->flags & SLAB_CONSISTENCY_CHECKS) &&
> -	    !check_valid_pointer(s, slab, nextfree) && freelist) {
> -		object_err(s, slab, *freelist, "Freechain corrupt");
> -		*freelist = NULL;
> -		slab_fix(s, "Isolate corrupted freechain");
> -		return true;
> -	}
> -
> -	return false;
> -}
> -
>  static void __slab_err(struct slab *slab)
>  {
>  	if (slab_in_kunit_test())
> @@ -1955,11 +1924,6 @@ static inline void inc_slabs_node(struct kmem_cache *s, int node,
>  							int objects) {}
>  static inline void dec_slabs_node(struct kmem_cache *s, int node,
>  							int objects) {}
> -static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
> -			       void **freelist, void *nextfree)
> -{
> -	return false;
> -}
>  #endif /* CONFIG_SLUB_DEBUG */
>  
>  /*
> @@ -3655,191 +3619,6 @@ static void *get_partial(struct kmem_cache *s, int node,
>  	return get_any_partial(s, pc);
>  }
>  
> -#ifdef CONFIG_PREEMPTION
> -/*
> - * Calculate the next globally unique transaction for disambiguation
> - * during cmpxchg. The transactions start with the cpu number and are then
> - * incremented by CONFIG_NR_CPUS.
> - */
> -#define TID_STEP  roundup_pow_of_two(CONFIG_NR_CPUS)
> -#else
> -/*
> - * No preemption supported therefore also no need to check for
> - * different cpus.
> - */
> -#define TID_STEP 1
> -#endif /* CONFIG_PREEMPTION */
> -
> -static inline unsigned long next_tid(unsigned long tid)
> -{
> -	return tid + TID_STEP;
> -}
> -
> -#ifdef SLUB_DEBUG_CMPXCHG
> -static inline unsigned int tid_to_cpu(unsigned long tid)
> -{
> -	return tid % TID_STEP;
> -}
> -
> -static inline unsigned long tid_to_event(unsigned long tid)
> -{
> -	return tid / TID_STEP;
> -}
> -#endif
> -
> -static inline unsigned int init_tid(int cpu)
> -{
> -	return cpu;
> -}
> -
> -static void init_kmem_cache_cpus(struct kmem_cache *s)
> -{
> -	int cpu;
> -	struct kmem_cache_cpu *c;
> -
> -	for_each_possible_cpu(cpu) {
> -		c = per_cpu_ptr(s->cpu_slab, cpu);
> -		local_trylock_init(&c->lock);
> -		c->tid = init_tid(cpu);
> -	}
> -}
> -
> -/*
> - * Finishes removing the cpu slab. Merges cpu's freelist with slab's freelist,
> - * unfreezes the slabs and puts it on the proper list.
> - * Assumes the slab has been already safely taken away from kmem_cache_cpu
> - * by the caller.
> - */
> -static void deactivate_slab(struct kmem_cache *s, struct slab *slab,
> -			    void *freelist)
> -{
> -	struct kmem_cache_node *n = get_node(s, slab_nid(slab));
> -	int free_delta = 0;
> -	void *nextfree, *freelist_iter, *freelist_tail;
> -	int tail = DEACTIVATE_TO_HEAD;
> -	unsigned long flags = 0;
> -	struct freelist_counters old, new;
> -
> -	if (READ_ONCE(slab->freelist)) {
> -		stat(s, DEACTIVATE_REMOTE_FREES);
> -		tail = DEACTIVATE_TO_TAIL;
> -	}
> -
> -	/*
> -	 * Stage one: Count the objects on cpu's freelist as free_delta and
> -	 * remember the last object in freelist_tail for later splicing.
> -	 */
> -	freelist_tail = NULL;
> -	freelist_iter = freelist;
> -	while (freelist_iter) {
> -		nextfree = get_freepointer(s, freelist_iter);
> -
> -		/*
> -		 * If 'nextfree' is invalid, it is possible that the object at
> -		 * 'freelist_iter' is already corrupted.  So isolate all objects
> -		 * starting at 'freelist_iter' by skipping them.
> -		 */
> -		if (freelist_corrupted(s, slab, &freelist_iter, nextfree))
> -			break;
> -
> -		freelist_tail = freelist_iter;
> -		free_delta++;
> -
> -		freelist_iter = nextfree;
> -	}
> -
> -	/*
> -	 * Stage two: Unfreeze the slab while splicing the per-cpu
> -	 * freelist to the head of slab's freelist.
> -	 */
> -	do {
> -		old.freelist = READ_ONCE(slab->freelist);
> -		old.counters = READ_ONCE(slab->counters);
> -		VM_BUG_ON(!old.frozen);
> -
> -		/* Determine target state of the slab */
> -		new.counters = old.counters;
> -		new.frozen = 0;
> -		if (freelist_tail) {
> -			new.inuse -= free_delta;
> -			set_freepointer(s, freelist_tail, old.freelist);
> -			new.freelist = freelist;
> -		} else {
> -			new.freelist = old.freelist;
> -		}
> -	} while (!slab_update_freelist(s, slab, &old, &new, "unfreezing slab"));
> -
> -	/*
> -	 * Stage three: Manipulate the slab list based on the updated state.
> -	 */
> -	if (!new.inuse && n->nr_partial >= s->min_partial) {
> -		stat(s, DEACTIVATE_EMPTY);
> -		discard_slab(s, slab);
> -		stat(s, FREE_SLAB);
> -	} else if (new.freelist) {
> -		spin_lock_irqsave(&n->list_lock, flags);
> -		add_partial(n, slab, tail);
> -		spin_unlock_irqrestore(&n->list_lock, flags);
> -		stat(s, tail);
> -	} else {
> -		stat(s, DEACTIVATE_FULL);
> -	}
> -}
> -
> -static inline void flush_slab(struct kmem_cache *s, struct kmem_cache_cpu *c)
> -{
> -	unsigned long flags;
> -	struct slab *slab;
> -	void *freelist;
> -
> -	local_lock_irqsave(&s->cpu_slab->lock, flags);
> -
> -	slab = c->slab;
> -	freelist = c->freelist;
> -
> -	c->slab = NULL;
> -	c->freelist = NULL;
> -	c->tid = next_tid(c->tid);
> -
> -	local_unlock_irqrestore(&s->cpu_slab->lock, flags);
> -
> -	if (slab) {
> -		deactivate_slab(s, slab, freelist);
> -		stat(s, CPUSLAB_FLUSH);
> -	}
> -}
> -
> -static inline void __flush_cpu_slab(struct kmem_cache *s, int cpu)
> -{
> -	struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab, cpu);
> -	void *freelist = c->freelist;
> -	struct slab *slab = c->slab;
> -
> -	c->slab = NULL;
> -	c->freelist = NULL;
> -	c->tid = next_tid(c->tid);
> -
> -	if (slab) {
> -		deactivate_slab(s, slab, freelist);
> -		stat(s, CPUSLAB_FLUSH);
> -	}
> -}
> -
> -static inline void flush_this_cpu_slab(struct kmem_cache *s)
> -{
> -	struct kmem_cache_cpu *c = this_cpu_ptr(s->cpu_slab);
> -
> -	if (c->slab)
> -		flush_slab(s, c);
> -}
> -
> -static bool has_cpu_slab(int cpu, struct kmem_cache *s)
> -{
> -	struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab, cpu);
> -
> -	return c->slab;
> -}
> -
>  static bool has_pcs_used(int cpu, struct kmem_cache *s)
>  {
>  	struct slub_percpu_sheaves *pcs;
> @@ -3853,7 +3632,7 @@ static bool has_pcs_used(int cpu, struct kmem_cache *s)
>  }
>  
>  /*
> - * Flush cpu slab.
> + * Flush percpu sheaves
>   *
>   * Called from CPU work handler with migration disabled.
>   */
> @@ -3868,8 +3647,6 @@ static void flush_cpu_slab(struct work_struct *w)

Nit: Would it make sense to rename flush_cpu_slab to flush_cpu_sheaf for better
clarity?

Other than that, looks good to me. Thanks.

Reviewed-by: Hao Li <hao.li@linux.dev>

-- 
Thanks,
Hao

>  
>  	if (cache_has_sheaves(s))
>  		pcs_flush_all(s);
> -
> -	flush_this_cpu_slab(s);
>  }
>  
>  static void flush_all_cpus_locked(struct kmem_cache *s)
> @@ -3882,7 +3659,7 @@ static void flush_all_cpus_locked(struct kmem_cache *s)
>  
>  	for_each_online_cpu(cpu) {
>  		sfw = &per_cpu(slub_flush, cpu);
> -		if (!has_cpu_slab(cpu, s) && !has_pcs_used(cpu, s)) {
> +		if (!has_pcs_used(cpu, s)) {
>  			sfw->skip = true;
>  			continue;
>  		}
> @@ -3992,7 +3769,6 @@ static int slub_cpu_dead(unsigned int cpu)
>  
>  	mutex_lock(&slab_mutex);
>  	list_for_each_entry(s, &slab_caches, list) {
> -		__flush_cpu_slab(s, cpu);
>  		if (cache_has_sheaves(s))
>  			__pcs_flush_all_cpu(s, cpu);
>  	}
> @@ -7121,26 +6897,21 @@ init_kmem_cache_node(struct kmem_cache_node *n, struct node_barn *barn)
>  		barn_init(barn);
>  }
>  
> -static inline int alloc_kmem_cache_cpus(struct kmem_cache *s)
> +#ifdef CONFIG_SLUB_STATS
> +static inline int alloc_kmem_cache_stats(struct kmem_cache *s)
>  {
>  	BUILD_BUG_ON(PERCPU_DYNAMIC_EARLY_SIZE <
>  			NR_KMALLOC_TYPES * KMALLOC_SHIFT_HIGH *
> -			sizeof(struct kmem_cache_cpu));
> +			sizeof(struct kmem_cache_stats));
>  
> -	/*
> -	 * Must align to double word boundary for the double cmpxchg
> -	 * instructions to work; see __pcpu_double_call_return_bool().
> -	 */
> -	s->cpu_slab = __alloc_percpu(sizeof(struct kmem_cache_cpu),
> -				     2 * sizeof(void *));
> +	s->cpu_stats = alloc_percpu(struct kmem_cache_stats);
>  
> -	if (!s->cpu_slab)
> +	if (!s->cpu_stats)
>  		return 0;
>  
> -	init_kmem_cache_cpus(s);
> -
>  	return 1;
>  }
> +#endif
>  
>  static int init_percpu_sheaves(struct kmem_cache *s)
>  {
> @@ -7252,7 +7023,9 @@ void __kmem_cache_release(struct kmem_cache *s)
>  	cache_random_seq_destroy(s);
>  	if (s->cpu_sheaves)
>  		pcs_destroy(s);
> -	free_percpu(s->cpu_slab);
> +#ifdef CONFIG_SLUB_STATS
> +	free_percpu(s->cpu_stats);
> +#endif
>  	free_kmem_cache_nodes(s);
>  }
>  
> @@ -7944,12 +7717,6 @@ static struct kmem_cache * __init bootstrap(struct kmem_cache *static_cache)
>  
>  	memcpy(s, static_cache, kmem_cache->object_size);
>  
> -	/*
> -	 * This runs very early, and only the boot processor is supposed to be
> -	 * up.  Even if it weren't true, IRQs are not up so we couldn't fire
> -	 * IPIs around.
> -	 */
> -	__flush_cpu_slab(s, smp_processor_id());
>  	for_each_kmem_cache_node(s, node, n) {
>  		struct slab *p;
>  
> @@ -8164,8 +7931,10 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
>  	if (!init_kmem_cache_nodes(s))
>  		goto out;
>  
> -	if (!alloc_kmem_cache_cpus(s))
> +#ifdef CONFIG_SLUB_STATS
> +	if (!alloc_kmem_cache_stats(s))
>  		goto out;
> +#endif
>  
>  	err = init_percpu_sheaves(s);
>  	if (err)
> @@ -8484,33 +8253,6 @@ static ssize_t show_slab_objects(struct kmem_cache *s,
>  	if (!nodes)
>  		return -ENOMEM;
>  
> -	if (flags & SO_CPU) {
> -		int cpu;
> -
> -		for_each_possible_cpu(cpu) {
> -			struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab,
> -							       cpu);
> -			int node;
> -			struct slab *slab;
> -
> -			slab = READ_ONCE(c->slab);
> -			if (!slab)
> -				continue;
> -
> -			node = slab_nid(slab);
> -			if (flags & SO_TOTAL)
> -				x = slab->objects;
> -			else if (flags & SO_OBJECTS)
> -				x = slab->inuse;
> -			else
> -				x = 1;
> -
> -			total += x;
> -			nodes[node] += x;
> -
> -		}
> -	}
> -
>  	/*
>  	 * It is impossible to take "mem_hotplug_lock" here with "kernfs_mutex"
>  	 * already held which will conflict with an existing lock order:
> @@ -8881,7 +8623,7 @@ static int show_stat(struct kmem_cache *s, char *buf, enum stat_item si)
>  		return -ENOMEM;
>  
>  	for_each_online_cpu(cpu) {
> -		unsigned x = per_cpu_ptr(s->cpu_slab, cpu)->stat[si];
> +		unsigned int x = per_cpu_ptr(s->cpu_stats, cpu)->stat[si];
>  
>  		data[cpu] = x;
>  		sum += x;
> @@ -8907,7 +8649,7 @@ static void clear_stat(struct kmem_cache *s, enum stat_item si)
>  	int cpu;
>  
>  	for_each_online_cpu(cpu)
> -		per_cpu_ptr(s->cpu_slab, cpu)->stat[si] = 0;
> +		per_cpu_ptr(s->cpu_stats, cpu)->stat[si] = 0;
>  }
>  
>  #define STAT_ATTR(si, text) 					\
> 
> -- 
> 2.52.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/dxrm4m545d4pzxmxjve34qwxwlw4kbmuz3xwdhvjheyeosa6y7%402zezo6xejama.
