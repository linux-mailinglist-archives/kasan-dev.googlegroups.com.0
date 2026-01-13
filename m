Return-Path: <kasan-dev+bncBAABB7OPTHFQMGQEJD2G7XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B0D1D19F8A
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 16:42:55 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-38306501f14sf35410181fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 07:42:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768318974; cv=pass;
        d=google.com; s=arc-20240605;
        b=lhsqfYYujibPgSX/3Zh8+IBd6DJkADVfT93k4E2Dbf3n7hsJzIIbkQ4uhhylj94Jle
         9oiJ3s+Ps/COP0ncZ2+EsO/IJekQRJa+sOQopVJ7+BhlZGHQthOhmOJUqmwUS4JSdNHt
         fPfIblflXJpmeAVn3AnyxWyZacyGdeDdlswbO0rIxlI9Nta5csaIs+Ano1fGs48Xcitw
         pebbHf9gm1QFR29XbegRdHC6/13PbdFZbOMj523I4a0VuXptY1XM4HJBstg48Vs/sCYf
         P7gwNwbFCYTHUu2NseM/KTQmuyc7euyye05BxLd83FrDczFc0OhOPujbfHeCfowIq4sd
         ZW7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=lGn+1omZzV3b8/jksJ0wwCmmwl6UJctTyjpxLDUS2mI=;
        fh=fJp7PHR/qBfwpAvhc3WPsKAiUATzMEh8SrrNLOsbSks=;
        b=PbNiit79HuPhFEHrmwsMWlvL/96Pt7VNz6p37ldd705RtxNI4kqkVfWXbnwevAJY3q
         MLhIX5GKlg8Skd9IAMtFsp1OgUbgwRUj8CN6aVe2Uyah8+aR7SsunV8yA/ONeoD7icgj
         at9SzUNy+7HK1CFFk0akfKYEIwEzGV3DoEXo1VGdMchBVeJXOHXLmOS5x2qTeM6g/kf3
         xkWZgnIMX35jCcWuiu2b65kUFYYudcFzkB5SN6iW+B0Ik3BFw96LqsmfreFxctoWaUk+
         yBtqFUcvSsbhOiL1l49KxQfJ2W7zMgfJeyI2s0bZyLCbxjejQ7ssxl0wrhcHE833E4m5
         Atlw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eCIGcp39;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b5 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768318974; x=1768923774; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lGn+1omZzV3b8/jksJ0wwCmmwl6UJctTyjpxLDUS2mI=;
        b=X1VTdZ3+bdwouMWZhwFurcaFDPaaZVgNIeD8VhRMs6RNZkJB8g+7bXsqt3TfXnA8b9
         LnHsXBSeiQBqdwB2cMvCqZrEYG5df9oGPrckOut8foWXaUFJ1GC6ahgCugNTvYaWVn1K
         8zHO/K7Gv8iTW+OD7WLCzvg6TeKJF1smrSumYd/HRsY1KXf9MGUp9lQNl1WC0FwhhXVT
         htD2H2OZYC3riUCoOT9ZoKpd+4RL4y7G71jsquDDfy7WGYqCdRClz+FnRyrCcGsjT45L
         MJnUelaa6g/hnE4LN2RVhIdgFCqvT2R0Vx6r072C7bdnEjVrXztbuuvhUR0xtVhVWAd5
         Z3Aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768318974; x=1768923774;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lGn+1omZzV3b8/jksJ0wwCmmwl6UJctTyjpxLDUS2mI=;
        b=UGfYtoImwWojhE4nKsh70C0BFfECp6hqusTZ9ZPo7P9zp+vpRVrsIGMNyO5thaUqX9
         3A61KDSnT0Bnliv4NcfLFhnMfvwSp3lTHXqDF078CARq2NVmMpL6LIi2b+BB+4t7j3eS
         omlBZFhgV085yPyUaC60dk2fzULY5tT+8eLBIHZUI/QkCZppYzMwSyvM/kjcjNh/A9Ft
         TKL5nYi+B6FYBPfAxokN75NtUlOyP0WDKh5VF0TrwzYWrOeMK71wW1F3GGs6beM5VwJ1
         DlhhmcI5LaCeN5wmrzKH5gfJsu7xB4YPnkQT47tZ1slQwlulLoCl2Wgf/gXerKT5NGdI
         uE9A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXbX4FaVzZ3rt7oOkzAuaGsrxUrN02cMzWeUbwr5u4VhPO2br9zMuxQ4wuuJZMjGkrEywQw+A==@lfdr.de
X-Gm-Message-State: AOJu0Yze9HLTqBmRtBsLLzXZupLLBMnrhnFS9p+fnzZ6Rvs6BOOcNd5J
	XV192n5g1IgEaenaAu9/Yww/K8PMAhHnkrDKIxSs1MNemqdO5wRDbtBl
X-Google-Smtp-Source: AGHT+IHFttgN84Gt36ltb6cMgyHoFCDkTDZX227SSEdDIuBWOmOdO5c2mh1QdWOD70T2YDdHggwy+g==
X-Received: by 2002:a05:651c:1ca:b0:383:1832:9586 with SMTP id 38308e7fff4ca-3831832a6a1mr47049371fa.1.1768318974328;
        Tue, 13 Jan 2026 07:42:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GkQLpQknWorHIr4thuMWdg6tgvxZ4BQjlyQK2MBwa2iA=="
Received: by 2002:a2e:b008:0:b0:383:1306:64b5 with SMTP id 38308e7fff4ca-383130665bcls4102131fa.2.-pod-prod-05-eu;
 Tue, 13 Jan 2026 07:42:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXYPiOef857BVAxm8m5P4N7F2a1cKaUcnzel+4Fdat9lF3l8/IRBYmT3kAecnR9AIHv6AUvuXPcepo=@googlegroups.com
X-Received: by 2002:a2e:b8c8:0:b0:37b:aa90:1f5 with SMTP id 38308e7fff4ca-382ff829ea5mr57409151fa.39.1768318972160;
        Tue, 13 Jan 2026 07:42:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768318972; cv=none;
        d=google.com; s=arc-20240605;
        b=bbhuUPdZhFJJ1U49odqHD87i137V94OKKonUzsKPPQePNjQHQh0K66Ow2wMyQb8BuT
         Vd8oe1nuxMs8urE2d5uVDGFKlKkmjxZqTdlmRGOdILhykYl3UOQ2Y/R3YFoiCMVVpaOo
         whxqdCix+CIkiBBbQZT4lMWcBHfmlXuz6bXU1p9ExwBeBWR7jZN/EpEFmgq+TJra2eaI
         oeNsKuNk3OMA8wKPDw9viKVEBKR6gjs+aqAFVn1ZG3NUCWMJhy/Z4o2tInbvQNyxW5ZJ
         9wAK8Q+a6cpOMTWR6mJDYTc5gZ/ALdwsn0D0urVrsyJ5wjDYhi2kmS1XWeyPrFTVqbPJ
         Cu5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=kcT0Rq2eZ+lNzxPFLAdKQnxD9hPonR7DRC64KveBJ74=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=dVXLgZGs24vOaaQnCROhRGmrTec4RQ3XCBoI406qvk8dH1tEKzWhq2VbVMFGEhS5AR
         OxaiVT8n9T/dsAG+6vuRQvynxJi8XOgpLNUj7nrCiSKiXqTLS7GU1KDLDO4OsCQbWxLX
         pT89YLhw6QCSYAd5BeD7BWaUFzy/4Ba+Y14V5H/OqyXmayk9Pw/IlAniO88zvVUlrVUR
         7eWk/7UDfJMMLcFuYNySP6QmtAg2nSYRb7QyP9m6jf1SQXKFr5kTl2Mekd/ghqRcDy6/
         sI5CDmmkNOCiIDuNZMENddJm7R8X/+x/qHOeFWlX52m+dNuoNVdaoap2jwyGKYLYCkeP
         roPg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eCIGcp39;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b5 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-181.mta0.migadu.com (out-181.mta0.migadu.com. [2001:41d0:1004:224b::b5])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-382fc3b94f2si3297171fa.7.2026.01.13.07.42.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 07:42:52 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b5 as permitted sender) client-ip=2001:41d0:1004:224b::b5;
Date: Tue, 13 Jan 2026 23:42:29 +0800
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
Subject: Re: [PATCH RFC v2 06/20] slab: make percpu sheaves compatible with
 kmalloc_nolock()/kfree_nolock()
Message-ID: <2hsm2byyftzi2d4xxdtkakqnfggtyemr23ofrnqgkzhkh7q7vc@zoqqfr7hba6f>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-6-98225cfb50cf@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260112-sheaves-for-all-v2-6-98225cfb50cf@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=eCIGcp39;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b5 as
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

On Mon, Jan 12, 2026 at 04:17:00PM +0100, Vlastimil Babka wrote:
> Before we enable percpu sheaves for kmalloc caches, we need to make sure
> kmalloc_nolock() and kfree_nolock() will continue working properly and
> not spin when not allowed to.
> 
> Percpu sheaves themselves use local_trylock() so they are already
> compatible. We just need to be careful with the barn->lock spin_lock.
> Pass a new allow_spin parameter where necessary to use
> spin_trylock_irqsave().
> 
> In kmalloc_nolock_noprof() we can now attempt alloc_from_pcs() safely,
> for now it will always fail until we enable sheaves for kmalloc caches
> next. Similarly in kfree_nolock() we can attempt free_to_pcs().
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 79 +++++++++++++++++++++++++++++++++++++++++++++------------------
>  1 file changed, 57 insertions(+), 22 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 06d5cf794403..0177a654a06a 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2881,7 +2881,8 @@ static void pcs_destroy(struct kmem_cache *s)
>  	s->cpu_sheaves = NULL;
>  }
>  
> -static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn)
> +static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn,
> +					       bool allow_spin)
>  {
>  	struct slab_sheaf *empty = NULL;
>  	unsigned long flags;
> @@ -2889,7 +2890,10 @@ static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn)
>  	if (!data_race(barn->nr_empty))
>  		return NULL;
>  
> -	spin_lock_irqsave(&barn->lock, flags);
> +	if (likely(allow_spin))
> +		spin_lock_irqsave(&barn->lock, flags);
> +	else if (!spin_trylock_irqsave(&barn->lock, flags))
> +		return NULL;
>  
>  	if (likely(barn->nr_empty)) {
>  		empty = list_first_entry(&barn->sheaves_empty,
> @@ -2966,7 +2970,8 @@ static struct slab_sheaf *barn_get_full_or_empty_sheaf(struct node_barn *barn)
>   * change.
>   */
>  static struct slab_sheaf *
> -barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
> +barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty,
> +			 bool allow_spin)
>  {
>  	struct slab_sheaf *full = NULL;
>  	unsigned long flags;
> @@ -2974,7 +2979,10 @@ barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
>  	if (!data_race(barn->nr_full))
>  		return NULL;
>  
> -	spin_lock_irqsave(&barn->lock, flags);
> +	if (likely(allow_spin))
> +		spin_lock_irqsave(&barn->lock, flags);
> +	else if (!spin_trylock_irqsave(&barn->lock, flags))
> +		return NULL;
>  
>  	if (likely(barn->nr_full)) {
>  		full = list_first_entry(&barn->sheaves_full, struct slab_sheaf,
> @@ -2995,7 +3003,8 @@ barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
>   * barn. But if there are too many full sheaves, reject this with -E2BIG.
>   */
>  static struct slab_sheaf *
> -barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full)
> +barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full,
> +			bool allow_spin)
>  {
>  	struct slab_sheaf *empty;
>  	unsigned long flags;
> @@ -3006,7 +3015,10 @@ barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full)
>  	if (!data_race(barn->nr_empty))
>  		return ERR_PTR(-ENOMEM);
>  
> -	spin_lock_irqsave(&barn->lock, flags);
> +	if (likely(allow_spin))
> +		spin_lock_irqsave(&barn->lock, flags);
> +	else if (!spin_trylock_irqsave(&barn->lock, flags))
> +		return ERR_PTR(-EBUSY);
>  
>  	if (likely(barn->nr_empty)) {
>  		empty = list_first_entry(&barn->sheaves_empty, struct slab_sheaf,
> @@ -5000,7 +5012,8 @@ __pcs_replace_empty_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
>  		return NULL;
>  	}
>  
> -	full = barn_replace_empty_sheaf(barn, pcs->main);
> +	full = barn_replace_empty_sheaf(barn, pcs->main,
> +					gfpflags_allow_spinning(gfp));
>  
>  	if (full) {
>  		stat(s, BARN_GET);
> @@ -5017,7 +5030,7 @@ __pcs_replace_empty_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
>  			empty = pcs->spare;
>  			pcs->spare = NULL;
>  		} else {
> -			empty = barn_get_empty_sheaf(barn);
> +			empty = barn_get_empty_sheaf(barn, true);
>  		}
>  	}
>  
> @@ -5157,7 +5170,8 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gfp, int node)
>  }
>  
>  static __fastpath_inline
> -unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
> +unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, gfp_t gfp, size_t size,
> +				 void **p)
>  {
>  	struct slub_percpu_sheaves *pcs;
>  	struct slab_sheaf *main;
> @@ -5191,7 +5205,8 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
>  			return allocated;
>  		}
>  
> -		full = barn_replace_empty_sheaf(barn, pcs->main);
> +		full = barn_replace_empty_sheaf(barn, pcs->main,
> +						gfpflags_allow_spinning(gfp));
>  
>  		if (full) {
>  			stat(s, BARN_GET);
> @@ -5700,7 +5715,7 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
>  	gfp_t alloc_gfp = __GFP_NOWARN | __GFP_NOMEMALLOC | gfp_flags;
>  	struct kmem_cache *s;
>  	bool can_retry = true;
> -	void *ret = ERR_PTR(-EBUSY);
> +	void *ret;
>  
>  	VM_WARN_ON_ONCE(gfp_flags & ~(__GFP_ACCOUNT | __GFP_ZERO |
>  				      __GFP_NO_OBJ_EXT));
> @@ -5727,6 +5742,12 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
>  		 */
>  		return NULL;
>  
> +	ret = alloc_from_pcs(s, alloc_gfp, node);
> +	if (ret)
> +		goto success;
> +
> +	ret = ERR_PTR(-EBUSY);
> +
>  	/*
>  	 * Do not call slab_alloc_node(), since trylock mode isn't
>  	 * compatible with slab_pre_alloc_hook/should_failslab and
> @@ -5763,6 +5784,7 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
>  		ret = NULL;
>  	}
>  
> +success:
>  	maybe_wipe_obj_freeptr(s, ret);
>  	slab_post_alloc_hook(s, NULL, alloc_gfp, 1, &ret,
>  			     slab_want_init_on_alloc(alloc_gfp, s), size);
> @@ -6083,7 +6105,8 @@ static void __pcs_install_empty_sheaf(struct kmem_cache *s,
>   * unlocked.
>   */
>  static struct slub_percpu_sheaves *
> -__pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
> +__pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
> +			bool allow_spin)
>  {
>  	struct slab_sheaf *empty;
>  	struct node_barn *barn;
> @@ -6107,7 +6130,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>  	put_fail = false;
>  
>  	if (!pcs->spare) {
> -		empty = barn_get_empty_sheaf(barn);
> +		empty = barn_get_empty_sheaf(barn, allow_spin);
>  		if (empty) {
>  			pcs->spare = pcs->main;
>  			pcs->main = empty;
> @@ -6121,7 +6144,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>  		return pcs;
>  	}
>  
> -	empty = barn_replace_full_sheaf(barn, pcs->main);
> +	empty = barn_replace_full_sheaf(barn, pcs->main, allow_spin);
>  
>  	if (!IS_ERR(empty)) {
>  		stat(s, BARN_PUT);
> @@ -6129,6 +6152,17 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>  		return pcs;
>  	}
>  
> +	if (!allow_spin) {
> +		/*
> +		 * sheaf_flush_unused() or alloc_empty_sheaf() don't support
> +		 * !allow_spin and instead of trying to support them it's
> +		 * easier to fall back to freeing the object directly without
> +		 * sheaves
> +		 */
> +		local_unlock(&s->cpu_sheaves->lock);
> +		return NULL;
> +	}

It looks like when "allow_spin" is false, __pcs_replace_full_main() can
still end up calling alloc_empty_sheaf() if pcs->spare is NULL (via the
"goto alloc_empty" path). Would it make sense to bail out a bit earlier
in that case?

-- 
Thanks
Hao

> +
>  	if (PTR_ERR(empty) == -E2BIG) {
>  		/* Since we got here, spare exists and is full */
>  		struct slab_sheaf *to_flush = pcs->spare;
> @@ -6196,7 +6230,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>   * The object is expected to have passed slab_free_hook() already.
>   */
>  static __fastpath_inline
> -bool free_to_pcs(struct kmem_cache *s, void *object)
> +bool free_to_pcs(struct kmem_cache *s, void *object, bool allow_spin)
>  {
>  	struct slub_percpu_sheaves *pcs;
>  
> @@ -6207,7 +6241,7 @@ bool free_to_pcs(struct kmem_cache *s, void *object)
>  
>  	if (unlikely(pcs->main->size == s->sheaf_capacity)) {
>  
> -		pcs = __pcs_replace_full_main(s, pcs);
> +		pcs = __pcs_replace_full_main(s, pcs, allow_spin);
>  		if (unlikely(!pcs))
>  			return false;
>  	}
> @@ -6314,7 +6348,7 @@ bool __kfree_rcu_sheaf(struct kmem_cache *s, void *obj)
>  			goto fail;
>  		}
>  
> -		empty = barn_get_empty_sheaf(barn);
> +		empty = barn_get_empty_sheaf(barn, true);
>  
>  		if (empty) {
>  			pcs->rcu_free = empty;
> @@ -6435,7 +6469,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
>  		goto no_empty;
>  
>  	if (!pcs->spare) {
> -		empty = barn_get_empty_sheaf(barn);
> +		empty = barn_get_empty_sheaf(barn, true);
>  		if (!empty)
>  			goto no_empty;
>  
> @@ -6449,7 +6483,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
>  		goto do_free;
>  	}
>  
> -	empty = barn_replace_full_sheaf(barn, pcs->main);
> +	empty = barn_replace_full_sheaf(barn, pcs->main, true);
>  	if (IS_ERR(empty)) {
>  		stat(s, BARN_PUT_FAIL);
>  		goto no_empty;
> @@ -6699,7 +6733,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
>  
>  	if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) == numa_mem_id())
>  	    && likely(!slab_test_pfmemalloc(slab))) {
> -		if (likely(free_to_pcs(s, object)))
> +		if (likely(free_to_pcs(s, object, true)))
>  			return;
>  	}
>  
> @@ -6960,7 +6994,8 @@ void kfree_nolock(const void *object)
>  	 * since kasan quarantine takes locks and not supported from NMI.
>  	 */
>  	kasan_slab_free(s, x, false, false, /* skip quarantine */true);
> -	do_slab_free(s, slab, x, x, 0, _RET_IP_);
> +	if (!free_to_pcs(s, x, false))
> +		do_slab_free(s, slab, x, x, 0, _RET_IP_);
>  }
>  EXPORT_SYMBOL_GPL(kfree_nolock);
>  
> @@ -7512,7 +7547,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
>  		size--;
>  	}
>  
> -	i = alloc_from_pcs_bulk(s, size, p);
> +	i = alloc_from_pcs_bulk(s, flags, size, p);
>  
>  	if (i < size) {
>  		/*
> 
> -- 
> 2.52.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2hsm2byyftzi2d4xxdtkakqnfggtyemr23ofrnqgkzhkh7q7vc%40zoqqfr7hba6f.
