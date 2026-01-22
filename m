Return-Path: <kasan-dev+bncBAABBPPWY3FQMGQESCD6JQQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id IKbdMz67cWkNLwAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBPPWY3FQMGQESCD6JQQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 06:53:02 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D15E62134
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 06:53:02 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-385bb7f429csf2415471fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 21:53:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769061182; cv=pass;
        d=google.com; s=arc-20240605;
        b=iq8zqIlIqogJHBGrii7tJsGyjeB9l++e7xLj05vGdGSaHERh/WMsb5wc5K6bK+plVL
         PpdBluflULOLf4yYZsWtuCnF4yC0d/noeMgwKQo59d45TwdCQaI7W0nCV9iZTtNQvNIU
         /OQGuG4erGePFKGgslB5gfgbpK4C20ZO/7/Gj+FE0BsuTn20+wo8zn6VdY/2kOw/bpZZ
         ArjKrJkdmS43bGpD5yb9FD+A1KViVXUYa6Zub7NvBXAt/JV3rHP6GQvtQDszw79+jss1
         DdJkerz3MaUToRrqbxz3GfVHEgMLWYODTl97m/oi0wyb7/9W3l+cHaNrVXWW6UzZtxMa
         ytmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=J1Vbwo7cwaTYiOJ3oIgCjUOGnuubimcuRKquRPJ7ieE=;
        fh=lo7Pd6iNfHe3ivQdnlAgBtw7QwEPRo2R2s9ZoLwAIbo=;
        b=Y1EaHwH/KvcmOrRt/UZB9UQc9dOgfau9YSWmPD2gGvS9y/K7ELNkZaJgfsWQ3U24wP
         MkAhZ7qrooSgyaOvOSHj0Iw5j/6agDRmGLaCMQEmbBl/kIAWkkbZhp9mKIK6I8wKWfGl
         0U3jQ3CL/08r60eaL90pggeFiBGtzGUiogK1Ug2wNXQMO760AK5E8LRMMRriTDPM5SwN
         9mrsC3ExKm6f/vMYhvacYcFnMXqOLcgVkUwrY5PQhdxLYXG9/9BXjP7RlZAQm6XDKCdm
         mnvQPMVVULSruWURATHJvxfyuSN4JHlDO3F8i/XCm0QcYoEZ2PQNamG6k1t9rpHh+Jyo
         gB7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=L2h4ihHa;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::bd as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769061182; x=1769665982; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=J1Vbwo7cwaTYiOJ3oIgCjUOGnuubimcuRKquRPJ7ieE=;
        b=RNxCivGsdjGasU7oLLwAA0KbXl1J6C/J041J8OuMXhnLbqtpIIkdbdIb6hlXAIsshS
         XcVtyAgO/G0Ush43FtQ1XgAtWCR6cW2qFv1EU89nEyetCjPWGUhi054LApNJS10LgrPU
         WYG0NxgG1VrrCm9I4iIR4cnRZdz+sk9KNoxrIsMhHZMl8ujWlwpS9JAAWfuFEPDFPCOo
         lymDTgfxxWSBupdm2uiBdVtEHtfG/dm+E/Jl1Zf5BM0Y6/ZJSvjgQPdB224a1M9AFvP/
         AjW1Of11QnIEqurqi+kqs0ag7J76GarMojXVDxOKSTGgIj1Sf+Ex15D0G16QOCRlMG3E
         76QQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769061182; x=1769665982;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=J1Vbwo7cwaTYiOJ3oIgCjUOGnuubimcuRKquRPJ7ieE=;
        b=OG7gmmaIEKy04fY0hDZMAywmXWYdKNyXJSn/WipGycsKkZCMfOEmOg8DIHwNq+eXXg
         YUTjjBOfSgsmUiO6nc2ZrCqdyhASbN2lMcwHZPM/l13+moLw5HfJLl9+bxTtqVdgxdIf
         r/ot/fQ96ZXK2iK71LmnxnHgRjxw6ddcmEox1AFOFvMLVNVPYW/5LXcdH6gWjZI8Xa13
         lwCLQuH3/Di64POYaMXxlHAsyF+IVcmpzMOvhyMXtcExgQ7pXFxC9/5qOjbEixkAaoYc
         2IZyRf4eBOjqBbfwMWSI4kc8Xu0keg2eVPFLHrBZZqm+S9QBRw/vFj1Op1H7BWzQTT76
         4wAw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUJT0d8pgQs1Uqyx0lByqZucMlzHjBYsCY8UhIk4Wa0n8u31pQE7qXbvmGCEtQ5Uo+bFEZzvA==@lfdr.de
X-Gm-Message-State: AOJu0YxlS7sfMhSCbo714AqYvT61Ao0Yrihh/1eeflNS0VcsBLQNprBS
	KoK11+5n2Z0PtDKYzBPeMtGXKSwdJBncDEhu1bO7KS0LjN6StmbAvDen
X-Received: by 2002:a05:6512:aca:b0:59b:7d3a:2a26 with SMTP id 2adb3069b0e04-59baef00dfdmr7100822e87.44.1769061181604;
        Wed, 21 Jan 2026 21:53:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HUXwbdBAnXHHxDgaFMZrTnylGn/qdtxs3Fc7+Xzfeb5Q=="
Received: by 2002:a05:6512:3e1f:b0:59b:6d6e:9887 with SMTP id
 2adb3069b0e04-59dd783f24bls169203e87.0.-pod-prod-02-eu; Wed, 21 Jan 2026
 21:52:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU+34FpDppwE1nsex4GloaUUNIWR3Qpdw37hHjdloRkJvS1jSWUpLcjkIP0rIGfRUJgmTEdalmlwr8=@googlegroups.com
X-Received: by 2002:a2e:be08:0:b0:385:c42a:1d3e with SMTP id 38308e7fff4ca-385c42a2046mr5082321fa.7.1769061179412;
        Wed, 21 Jan 2026 21:52:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769061179; cv=none;
        d=google.com; s=arc-20240605;
        b=La2Byu7MagKcAq1lMm3qLSpzMXEY5c6isGH4NSnpmtfBBaMEYby+8UwjduMwO/xbyo
         n+rDZKQys4W1gYAj+pbVw3sztz2aG9LAJeHbFe1E8RvZFH4BB0xtl7w76SxwxMvA8Ai2
         rSWgrzpNB6uuYYmIY9JCUD1gKU0ami+VEGX1TPN5JOLh2oSc9/RINgLEFggdKr7JZWe6
         BWlkq1oxfSSbz8e+RQvZd2tRTc1k7RI2osoNox5wt/t2032QrEl3R1pz6HTFt+QcHeNZ
         wg1XRYD0iPOfuVQiuc+m86toNcU0PUkwBNaxBcGMRpoS8SWvh55EgIgeqv1U06OxWRvC
         n2ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=vTGJaFhXlbsw1EOpmJJykqdjn7GgJkZ5tylkFbIkt4g=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=bA+hrik3qG+6flFZJhLge3p+yLr4A98cdu1N5Ijtu8f+zeCJsXy6kUyICSoh1WY7Kn
         CfrNBTRtatzTjrEwH1wG3UztYKmCJySW0NQmdSoQhJzrpAsqzszUAC/pfJVJblBuYEGL
         c64qs4uiy9dCOuXw3zZwS1LSBTMA4CMiAtZOfiGh5wxxNPonSp0NPwj22IwvO0NIsnqe
         OyrtDJ39jBJx93i0As7/YGfOI8vjISzJsTi6FV+5W0J0XPpI/ZL3LuUm/H64/PRIY0XO
         Jl6+eOzXnPNGxUkoc4GGSPrmQrTerZGJRx90rWdny+Wx01xYGthHJWXLWl6X7Xmr45HP
         M28g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=L2h4ihHa;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::bd as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-189.mta0.migadu.com (out-189.mta0.migadu.com. [2001:41d0:1004:224b::bd])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384e7914csi3159801fa.9.2026.01.21.21.52.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 21:52:59 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::bd as permitted sender) client-ip=2001:41d0:1004:224b::bd;
Date: Thu, 22 Jan 2026 13:52:48 +0800
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
Subject: Re: [PATCH v3 21/21] mm/slub: cleanup and repurpose some stat items
Message-ID: <5rmxfyxuhloucetufg2qic5elgi6frd7onjzdsosmhtjdqglij@5htmiqrdhkoj>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-21-5595cb000772@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-21-5595cb000772@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=L2h4ihHa;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::bd as
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
	TAGGED_FROM(0.00)[bncBAABBPPWY3FQMGQESCD6JQQ];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[linux.dev:email,suse.cz:email,mail-lj1-x237.google.com:helo,mail-lj1-x237.google.com:rdns]
X-Rspamd-Queue-Id: 6D15E62134
X-Rspamd-Action: no action

On Fri, Jan 16, 2026 at 03:40:41PM +0100, Vlastimil Babka wrote:
> A number of stat items related to cpu slabs became unused, remove them.
> 
> Two of those were ALLOC_FASTPATH and FREE_FASTPATH. But instead of
> removing those, use them instead of ALLOC_PCS and FREE_PCS, since
> sheaves are the new (and only) fastpaths, Remove the recently added
> _PCS variants instead.
> 
> Change where FREE_SLOWPATH is counted so that it only counts freeing of
> objects by slab users that (for whatever reason) do not go to a percpu
> sheaf, and not all (including internal) callers of __slab_free(). Thus
> flushing sheaves (counted by SHEAF_FLUSH) no longer also increments
> FREE_SLOWPATH. This matches how ALLOC_SLOWPATH doesn't count sheaf
> refills (counted by SHEAF_REFILL).
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 77 +++++++++++++++++----------------------------------------------
>  1 file changed, 21 insertions(+), 56 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index c12e90cb2fca..d73ad44fa046 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -330,33 +330,19 @@ enum add_mode {
>  };
>  
>  enum stat_item {
> -	ALLOC_PCS,		/* Allocation from percpu sheaf */
> -	ALLOC_FASTPATH,		/* Allocation from cpu slab */
> -	ALLOC_SLOWPATH,		/* Allocation by getting a new cpu slab */
> -	FREE_PCS,		/* Free to percpu sheaf */
> +	ALLOC_FASTPATH,		/* Allocation from percpu sheaves */
> +	ALLOC_SLOWPATH,		/* Allocation from partial or new slab */
>  	FREE_RCU_SHEAF,		/* Free to rcu_free sheaf */
>  	FREE_RCU_SHEAF_FAIL,	/* Failed to free to a rcu_free sheaf */
> -	FREE_FASTPATH,		/* Free to cpu slab */
> -	FREE_SLOWPATH,		/* Freeing not to cpu slab */
> +	FREE_FASTPATH,		/* Free to percpu sheaves */
> +	FREE_SLOWPATH,		/* Free to a slab */

Nits: Would it make sense to add stat(s, FREE_SLOWPATH) in
free_deferred_objects() as well, since it also calls __slab_free()?

Everything else looks good.

This patchset replaces cpu slab with cpu sheaves and really simplifies the code
overall - I really like the direction and the end result. It's really been a
pleasure reviewing this series. Thanks!

Reviewed-by: Hao Li <hao.li@linux.dev>

-- 
Thanks,
Hao

>  	FREE_ADD_PARTIAL,	/* Freeing moves slab to partial list */
>  	FREE_REMOVE_PARTIAL,	/* Freeing removes last object */
> -	ALLOC_FROM_PARTIAL,	/* Cpu slab acquired from node partial list */
> -	ALLOC_SLAB,		/* Cpu slab acquired from page allocator */
> -	ALLOC_REFILL,		/* Refill cpu slab from slab freelist */
> -	ALLOC_NODE_MISMATCH,	/* Switching cpu slab */
> +	ALLOC_SLAB,		/* New slab acquired from page allocator */
> +	ALLOC_NODE_MISMATCH,	/* Requested node different from cpu sheaf */
>  	FREE_SLAB,		/* Slab freed to the page allocator */
> -	CPUSLAB_FLUSH,		/* Abandoning of the cpu slab */
> -	DEACTIVATE_FULL,	/* Cpu slab was full when deactivated */
> -	DEACTIVATE_EMPTY,	/* Cpu slab was empty when deactivated */
> -	DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects */
> -	DEACTIVATE_BYPASS,	/* Implicit deactivation */
>  	ORDER_FALLBACK,		/* Number of times fallback was necessary */
> -	CMPXCHG_DOUBLE_CPU_FAIL,/* Failures of this_cpu_cmpxchg_double */
>  	CMPXCHG_DOUBLE_FAIL,	/* Failures of slab freelist update */
> -	CPU_PARTIAL_ALLOC,	/* Used cpu partial on alloc */
> -	CPU_PARTIAL_FREE,	/* Refill cpu partial on free */
> -	CPU_PARTIAL_NODE,	/* Refill cpu partial from node partial */
> -	CPU_PARTIAL_DRAIN,	/* Drain cpu partial to node partial */
>  	SHEAF_FLUSH,		/* Objects flushed from a sheaf */
>  	SHEAF_REFILL,		/* Objects refilled to a sheaf */
>  	SHEAF_ALLOC,		/* Allocation of an empty sheaf */
> @@ -4347,8 +4333,10 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gfp, int node)
>  	 * We assume the percpu sheaves contain only local objects although it's
>  	 * not completely guaranteed, so we verify later.
>  	 */
> -	if (unlikely(node_requested && node != numa_mem_id()))
> +	if (unlikely(node_requested && node != numa_mem_id())) {
> +		stat(s, ALLOC_NODE_MISMATCH);
>  		return NULL;
> +	}
>  
>  	if (!local_trylock(&s->cpu_sheaves->lock))
>  		return NULL;
> @@ -4371,6 +4359,7 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gfp, int node)
>  		 */
>  		if (page_to_nid(virt_to_page(object)) != node) {
>  			local_unlock(&s->cpu_sheaves->lock);
> +			stat(s, ALLOC_NODE_MISMATCH);
>  			return NULL;
>  		}
>  	}
> @@ -4379,7 +4368,7 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gfp, int node)
>  
>  	local_unlock(&s->cpu_sheaves->lock);
>  
> -	stat(s, ALLOC_PCS);
> +	stat(s, ALLOC_FASTPATH);
>  
>  	return object;
>  }
> @@ -4451,7 +4440,7 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, gfp_t gfp, size_t size,
>  
>  	local_unlock(&s->cpu_sheaves->lock);
>  
> -	stat_add(s, ALLOC_PCS, batch);
> +	stat_add(s, ALLOC_FASTPATH, batch);
>  
>  	allocated += batch;
>  
> @@ -5111,8 +5100,6 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
>  	unsigned long flags;
>  	bool on_node_partial;
>  
> -	stat(s, FREE_SLOWPATH);
> -
>  	if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
>  		free_to_partial_list(s, slab, head, tail, cnt, addr);
>  		return;
> @@ -5416,7 +5403,7 @@ bool free_to_pcs(struct kmem_cache *s, void *object, bool allow_spin)
>  
>  	local_unlock(&s->cpu_sheaves->lock);
>  
> -	stat(s, FREE_PCS);
> +	stat(s, FREE_FASTPATH);
>  
>  	return true;
>  }
> @@ -5664,7 +5651,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
>  
>  	local_unlock(&s->cpu_sheaves->lock);
>  
> -	stat_add(s, FREE_PCS, batch);
> +	stat_add(s, FREE_FASTPATH, batch);
>  
>  	if (batch < size) {
>  		p += batch;
> @@ -5686,10 +5673,12 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
>  	 */
>  fallback:
>  	__kmem_cache_free_bulk(s, size, p);
> +	stat_add(s, FREE_SLOWPATH, size);
>  
>  flush_remote:
>  	if (remote_nr) {
>  		__kmem_cache_free_bulk(s, remote_nr, &remote_objects[0]);
> +		stat_add(s, FREE_SLOWPATH, remote_nr);
>  		if (i < size) {
>  			remote_nr = 0;
>  			goto next_remote_batch;
> @@ -5784,6 +5773,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
>  	}
>  
>  	__slab_free(s, slab, object, object, 1, addr);
> +	stat(s, FREE_SLOWPATH);
>  }
>  
>  #ifdef CONFIG_MEMCG
> @@ -5806,8 +5796,10 @@ void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
>  	 * With KASAN enabled slab_free_freelist_hook modifies the freelist
>  	 * to remove objects, whose reuse must be delayed.
>  	 */
> -	if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt)))
> +	if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt))) {
>  		__slab_free(s, slab, head, tail, cnt, addr);
> +		stat_add(s, FREE_SLOWPATH, cnt);
> +	}
>  }
>  
>  #ifdef CONFIG_SLUB_RCU_DEBUG
> @@ -6705,6 +6697,7 @@ int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  		i = refill_objects(s, p, flags, size, size);
>  		if (i < size)
>  			goto error;
> +		stat_add(s, ALLOC_SLOWPATH, i);
>  	}
>  
>  	return i;
> @@ -8704,33 +8697,19 @@ static ssize_t text##_store(struct kmem_cache *s,		\
>  }								\
>  SLAB_ATTR(text);						\
>  
> -STAT_ATTR(ALLOC_PCS, alloc_cpu_sheaf);
>  STAT_ATTR(ALLOC_FASTPATH, alloc_fastpath);
>  STAT_ATTR(ALLOC_SLOWPATH, alloc_slowpath);
> -STAT_ATTR(FREE_PCS, free_cpu_sheaf);
>  STAT_ATTR(FREE_RCU_SHEAF, free_rcu_sheaf);
>  STAT_ATTR(FREE_RCU_SHEAF_FAIL, free_rcu_sheaf_fail);
>  STAT_ATTR(FREE_FASTPATH, free_fastpath);
>  STAT_ATTR(FREE_SLOWPATH, free_slowpath);
>  STAT_ATTR(FREE_ADD_PARTIAL, free_add_partial);
>  STAT_ATTR(FREE_REMOVE_PARTIAL, free_remove_partial);
> -STAT_ATTR(ALLOC_FROM_PARTIAL, alloc_from_partial);
>  STAT_ATTR(ALLOC_SLAB, alloc_slab);
> -STAT_ATTR(ALLOC_REFILL, alloc_refill);
>  STAT_ATTR(ALLOC_NODE_MISMATCH, alloc_node_mismatch);
>  STAT_ATTR(FREE_SLAB, free_slab);
> -STAT_ATTR(CPUSLAB_FLUSH, cpuslab_flush);
> -STAT_ATTR(DEACTIVATE_FULL, deactivate_full);
> -STAT_ATTR(DEACTIVATE_EMPTY, deactivate_empty);
> -STAT_ATTR(DEACTIVATE_REMOTE_FREES, deactivate_remote_frees);
> -STAT_ATTR(DEACTIVATE_BYPASS, deactivate_bypass);
>  STAT_ATTR(ORDER_FALLBACK, order_fallback);
> -STAT_ATTR(CMPXCHG_DOUBLE_CPU_FAIL, cmpxchg_double_cpu_fail);
>  STAT_ATTR(CMPXCHG_DOUBLE_FAIL, cmpxchg_double_fail);
> -STAT_ATTR(CPU_PARTIAL_ALLOC, cpu_partial_alloc);
> -STAT_ATTR(CPU_PARTIAL_FREE, cpu_partial_free);
> -STAT_ATTR(CPU_PARTIAL_NODE, cpu_partial_node);
> -STAT_ATTR(CPU_PARTIAL_DRAIN, cpu_partial_drain);
>  STAT_ATTR(SHEAF_FLUSH, sheaf_flush);
>  STAT_ATTR(SHEAF_REFILL, sheaf_refill);
>  STAT_ATTR(SHEAF_ALLOC, sheaf_alloc);
> @@ -8806,33 +8785,19 @@ static struct attribute *slab_attrs[] = {
>  	&remote_node_defrag_ratio_attr.attr,
>  #endif
>  #ifdef CONFIG_SLUB_STATS
> -	&alloc_cpu_sheaf_attr.attr,
>  	&alloc_fastpath_attr.attr,
>  	&alloc_slowpath_attr.attr,
> -	&free_cpu_sheaf_attr.attr,
>  	&free_rcu_sheaf_attr.attr,
>  	&free_rcu_sheaf_fail_attr.attr,
>  	&free_fastpath_attr.attr,
>  	&free_slowpath_attr.attr,
>  	&free_add_partial_attr.attr,
>  	&free_remove_partial_attr.attr,
> -	&alloc_from_partial_attr.attr,
>  	&alloc_slab_attr.attr,
> -	&alloc_refill_attr.attr,
>  	&alloc_node_mismatch_attr.attr,
>  	&free_slab_attr.attr,
> -	&cpuslab_flush_attr.attr,
> -	&deactivate_full_attr.attr,
> -	&deactivate_empty_attr.attr,
> -	&deactivate_remote_frees_attr.attr,
> -	&deactivate_bypass_attr.attr,
>  	&order_fallback_attr.attr,
>  	&cmpxchg_double_fail_attr.attr,
> -	&cmpxchg_double_cpu_fail_attr.attr,
> -	&cpu_partial_alloc_attr.attr,
> -	&cpu_partial_free_attr.attr,
> -	&cpu_partial_node_attr.attr,
> -	&cpu_partial_drain_attr.attr,
>  	&sheaf_flush_attr.attr,
>  	&sheaf_refill_attr.attr,
>  	&sheaf_alloc_attr.attr,
> 
> -- 
> 2.52.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5rmxfyxuhloucetufg2qic5elgi6frd7onjzdsosmhtjdqglij%405htmiqrdhkoj.
