Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4M4TCBAMGQECAYRABI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id EBD8D330CA0
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 12:45:53 +0100 (CET)
Received: by mail-ej1-x63c.google.com with SMTP id jo6sf3947887ejb.13
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 03:45:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615203953; cv=pass;
        d=google.com; s=arc-20160816;
        b=t2MtRzqTGqg7rqSDqnvlhy5vLppeHSy2t1aFv9jZY3Uqy1/5Yn0qnF1PPNQl/8iQ+j
         E0bSikNVXYbiFu6XQaaOJ4qdIPgkQJwf9TOohDpOqgcYQUrRhNBzzz7mews5kNyoUAki
         TU4CyV+pvOwvrW2eRmIlPCS0LQdcTaUx6vc3p0fa+wJoz2gLllBfrQVsjUUB5KIkGxBZ
         hr/mUSMoNLtYsuHnNzKLfyDTAdr8DO2RkzGbwMdbwgEGLQiducfyfYLv3s8IF5KV06ie
         tyTliV2syp6+EJX6Z421QHGmMWnlfGF1E+SERbDaIVHZnYJ/bJSHM5bFO42iBO0uwMdl
         2mpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=KxY+mIoIuJgPXds+8boxy5Z2N386llHm1/McyQMN4pM=;
        b=cEwkSHesdJHEMU+R0NAf/OfoUhjQTueRq0bKQcWeBqHdXyyU07k+N4ImBxnXN6i4jc
         2NScQKszv+wKqFSqm2Q/zymDOO9M19yPEdE/PpWd6twkAaIbXvFbu81jBbE1nVHAR45z
         E2I126zULeRtZ3/GD3AKS1hVuWqJoTSNf15tQffzei+jeTz3ChJE5rnT9fX80MojzgCa
         Y2KihIcuN7ievnul4tPPpIaegt8YW5Kato57a1PBTrV7uVFggB0jEGb5ESVubGzwO++p
         sCDBLIrtUNN8NfQTCt0lIZaBuaCr75xubUKS7QxiqjQo9CY9FPCWaucSrV8FTaubNecv
         CJ/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LnjULmcf;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=KxY+mIoIuJgPXds+8boxy5Z2N386llHm1/McyQMN4pM=;
        b=iadrIFJQIDKdBPTyIybS6L8Ku6lTmVPWB9qvpQFF/2wn3jRUFGeI8bbRTDZSVmtBrJ
         dbJIywAMtcBl24OIPPdPRivdczlWxL9Mq7dhUdF1BF0Yg+2MOCpspmsXr/vqv00Fgye8
         oA54SbHDY2TbcvqIaMXYddaOCcTMMnj8knEOYVJkDG5knhsHPNXOH1L2b8rEfeu+FHNu
         gZoYNzaHHNUqBvD048Of25mJyHlTdj3ds6jDy0W4jMglW4QKDOzJ0Nhs31/BrHVvlKDq
         J3aBntrBFVz6uMlw0K/2fJz576V1VogN6EPGT57noF466DbyOgCNiGWSQdyJ207CFkL2
         wMiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KxY+mIoIuJgPXds+8boxy5Z2N386llHm1/McyQMN4pM=;
        b=Oj9PRnPhKYI55YTDcUroRIabyYt9dTywV45lDZFa7KrqOW8ta2smoi1HfYu49QTe99
         bN9X3SYWGNTRF0X0RTfgCRYcv3ZGZxlJqd2sqtED3CpW0gbCdfVOGysxjw+gMsEAoUIr
         wBlXRQkU1d8BuNi7NIc1/dUnEvil6GIk61cG8M0k1e1wHcB5W6fSdoa1x7jtNbwc2wop
         gouYyUztc0wrh6ZejoTZv4CTxfNwqdRrd4UOsyI+Q7RMMMQdF07V/fejsGnVUSXiwruw
         ZPMrEGzo6YcvPUh3lV51sk/XrxhbZOD4WvEiJumy9IqYd5rl089yoEXDzcGsyIEEFnpt
         tr6Q==
X-Gm-Message-State: AOAM531l1vUv4dShYQ/MrJb6H+1hb530KuFxgA9+zSwa+RkgLvmd5VJh
	6Q0F5zHOCppHRCaTkrjeAck=
X-Google-Smtp-Source: ABdhPJxOjysTvh0wNc9nrWRgqRl70sK4DsNZ8A9U91Kxh2jrm0R9Vby8PH1op54nErpsojew0UwFyQ==
X-Received: by 2002:a17:906:cd12:: with SMTP id oz18mr14677509ejb.498.1615203953674;
        Mon, 08 Mar 2021 03:45:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:c192:: with SMTP id g18ls7766542ejz.10.gmail; Mon,
 08 Mar 2021 03:45:52 -0800 (PST)
X-Received: by 2002:a17:906:d157:: with SMTP id br23mr15052497ejb.192.1615203952577;
        Mon, 08 Mar 2021 03:45:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615203952; cv=none;
        d=google.com; s=arc-20160816;
        b=ntJFyiVZ/K0O8Oh5XPO0+2COzgMGyXynI7ykwC3s3jg4/QiJcl1Ycaji7HryWxqoI3
         RRMQJ+NBkTuOi4lsMLKeOfO8/tz7PI/0XpzYn6L1ym8ZzHTRVXG1jHA3wRZjQq/aQc2Z
         LyBRKLTL03zQl4AUA1hFKuSgq5b8lzwBgAo4wn3ir0fT2mUdsPGYaPakvMHYwdhINJE4
         mnTytT1JDX1TOF8oUFfbn3ou27LVRFW1xK65gQHqdJoBMTy9ORDvDRyV671CxtyYTfx7
         WCMo3jh/H9g34U3OYcYHa02ExNHIls0gr4N7MiSCO8QjayWIEX9XZNxjQ64Pmu1WxoJ7
         Nn3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=cCYaodgn23RpIhtLxdUS0nQYEGZQi2gHsnzCEWxqT00=;
        b=lQsNbAXpAkMaDHeOyQ6InT+t+jh5cPnhzhFlQpcZuLBuRDp2GaIBsNSs7cPHU0AQ3z
         CI0j1JD9/5fm7GgVcEdYKvukDTQsGsnMAXaXQs7s3sUEfeim3pF5CrTf6EuQL7h2NWIB
         VOE0FYMgBga5CjKpkq5+AuStCECrp4im28Ra3RkAvTD6SMs6Q1yG7ETd15kBQWiyScZl
         H7yp8mIXKVhFKYtlPsXGGKPZI2ZQDRmG21wj/5TVyYhO1bwj4aJRQeff10dnzPRGp0hJ
         Vb33u2PmRVvlg+yP/uZ6GslWzqrhBmmsGfZpqDILN4EZ2bCrNh9rBaX0wT39jrlqDhe3
         EYzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LnjULmcf;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id w12si506793edj.2.2021.03.08.03.45.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 03:45:52 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id d15so11117253wrv.5
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 03:45:52 -0800 (PST)
X-Received: by 2002:adf:f148:: with SMTP id y8mr21886984wro.107.1615203952103;
        Mon, 08 Mar 2021 03:45:52 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:9d1d:b6a0:d116:531b])
        by smtp.gmail.com with ESMTPSA id p16sm21167989wrt.54.2021.03.08.03.45.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Mar 2021 03:45:51 -0800 (PST)
Date: Mon, 8 Mar 2021 12:45:45 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 5/5] kasan, mm: integrate slab init_on_free with HW_TAGS
Message-ID: <YEYOaR5jQXe6imp0@elver.google.com>
References: <cover.1614989433.git.andreyknvl@google.com>
 <a313f27d68ad479eda7b36a114bb2ffd56d80bbb.1614989433.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <a313f27d68ad479eda7b36a114bb2ffd56d80bbb.1614989433.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LnjULmcf;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Sat, Mar 06, 2021 at 01:15AM +0100, Andrey Konovalov wrote:
> This change uses the previously added memory initialization feature
> of HW_TAGS KASAN routines for slab memory when init_on_free is enabled.
> 
> With this change, memory initialization memset() is no longer called
> when both HW_TAGS KASAN and init_on_free are enabled. Instead, memory
> is initialized in KASAN runtime.
> 
> For SLUB, the memory initialization memset() is moved into
> slab_free_hook() that currently directly follows the initialization loop.
> A new argument is added to slab_free_hook() that indicates whether to
> initialize the memory or not.
> 
> To avoid discrepancies with which memory gets initialized that can be
> caused by future changes, both KASAN hook and initialization memset()
> are put together and a warning comment is added.
> 
> Combining setting allocation tags with memory initialization improves
> HW_TAGS KASAN performance when init_on_free is enabled.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  include/linux/kasan.h | 10 ++++++----
>  mm/kasan/common.c     | 13 +++++++------
>  mm/slab.c             | 15 +++++++++++----
>  mm/slub.c             | 43 ++++++++++++++++++++++++-------------------
>  4 files changed, 48 insertions(+), 33 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index bb756f6c73b5..1df0f7f0b493 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -193,11 +193,13 @@ static __always_inline void * __must_check kasan_init_slab_obj(
>  	return (void *)object;
>  }
>  
> -bool __kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
> -static __always_inline bool kasan_slab_free(struct kmem_cache *s, void *object)
> +bool __kasan_slab_free(struct kmem_cache *s, void *object,
> +			unsigned long ip, bool init);
> +static __always_inline bool kasan_slab_free(struct kmem_cache *s,
> +						void *object, bool init)
>  {
>  	if (kasan_enabled())
> -		return __kasan_slab_free(s, object, _RET_IP_);
> +		return __kasan_slab_free(s, object, _RET_IP_, init);
>  	return false;
>  }
>  
> @@ -299,7 +301,7 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
>  {
>  	return (void *)object;
>  }
> -static inline bool kasan_slab_free(struct kmem_cache *s, void *object)
> +static inline bool kasan_slab_free(struct kmem_cache *s, void *object, bool init)
>  {
>  	return false;
>  }
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 7ea747b18c26..623cf94288a2 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -322,8 +322,8 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
>  	return (void *)object;
>  }
>  
> -static inline bool ____kasan_slab_free(struct kmem_cache *cache,
> -				void *object, unsigned long ip, bool quarantine)
> +static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
> +				unsigned long ip, bool quarantine, bool init)
>  {
>  	u8 tag;
>  	void *tagged_object;
> @@ -351,7 +351,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache,
>  	}
>  
>  	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
> -			KASAN_KMALLOC_FREE, false);
> +			KASAN_KMALLOC_FREE, init);
>  
>  	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine))
>  		return false;
> @@ -362,9 +362,10 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache,
>  	return kasan_quarantine_put(cache, object);
>  }
>  
> -bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
> +bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> +				unsigned long ip, bool init)
>  {
> -	return ____kasan_slab_free(cache, object, ip, true);
> +	return ____kasan_slab_free(cache, object, ip, true, init);
>  }
>  
>  static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
> @@ -409,7 +410,7 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
>  			return;
>  		kasan_poison(ptr, page_size(page), KASAN_FREE_PAGE, false);
>  	} else {
> -		____kasan_slab_free(page->slab_cache, ptr, ip, false);
> +		____kasan_slab_free(page->slab_cache, ptr, ip, false, false);
>  	}
>  }
>  
> diff --git a/mm/slab.c b/mm/slab.c
> index 936dd686dec9..d12ce9e5c3ed 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -3425,17 +3425,24 @@ static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
>  static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
>  					 unsigned long caller)
>  {
> +	bool init;
> +
>  	if (is_kfence_address(objp)) {
>  		kmemleak_free_recursive(objp, cachep->flags);
>  		__kfence_free(objp);
>  		return;
>  	}
>  
> -	if (unlikely(slab_want_init_on_free(cachep)))
> +	/*
> +	 * As memory initialization is integrated with hardware tag-based

This may no longer be true if the HW-tags architecture doesn't support
init (although currently it is certainly true). 

Perhaps: "As memory initialization may be accelerated by some KASAN
implementations (such as some HW_TAGS architectures) ..."

or whatever else is appropriate.

> +	 * KASAN, kasan_slab_free and initialization memset must be
> +	 * kept together to avoid discrepancies in behavior.
> +	 */
> +	init = slab_want_init_on_free(cachep);
> +	if (init && !IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>  		memset(objp, 0, cachep->object_size);

Same as the other patch, it seems awkward to have
!IS_ENABLED(CONFIG_KASAN_HW_TAGS) rather than a kasan_*() helper that
returns this information.

> -
> -	/* Put the object into the quarantine, don't touch it for now. */
> -	if (kasan_slab_free(cachep, objp))
> +	/* KASAN might put objp into memory quarantine, delaying its reuse. */
> +	if (kasan_slab_free(cachep, objp, init))
>  		return;
>  
>  	/* Use KCSAN to help debug racy use-after-free. */
> diff --git a/mm/slub.c b/mm/slub.c
> index f53df23760e3..c2755670d6bd 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -1532,7 +1532,8 @@ static __always_inline void kfree_hook(void *x)
>  	kasan_kfree_large(x);
>  }
>  
> -static __always_inline bool slab_free_hook(struct kmem_cache *s, void *x)
> +static __always_inline bool slab_free_hook(struct kmem_cache *s,
> +						void *x, bool init)
>  {
>  	kmemleak_free_recursive(x, s->flags);
>  
> @@ -1558,8 +1559,25 @@ static __always_inline bool slab_free_hook(struct kmem_cache *s, void *x)
>  		__kcsan_check_access(x, s->object_size,
>  				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
>  
> -	/* KASAN might put x into memory quarantine, delaying its reuse */
> -	return kasan_slab_free(s, x);
> +	/*
> +	 * As memory initialization is integrated with hardware tag-based
> +	 * KASAN, kasan_slab_free and initialization memset's must be
> +	 * kept together to avoid discrepancies in behavior.
> +	 *
> +	 * The initialization memset's clear the object and the metadata,
> +	 * but don't touch the SLAB redzone.
> +	 */
> +	if (init) {
> +		int rsize;
> +
> +		if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS))
> +			memset(kasan_reset_tag(x), 0, s->object_size);
> +		rsize = (s->flags & SLAB_RED_ZONE) ? s->red_left_pad : 0;
> +		memset((char *)kasan_reset_tag(x) + s->inuse, 0,
> +		       s->size - s->inuse - rsize);
> +	}
> +	/* KASAN might put x into memory quarantine, delaying its reuse. */
> +	return kasan_slab_free(s, x, init);
>  }
>  
>  static inline bool slab_free_freelist_hook(struct kmem_cache *s,
> @@ -1569,10 +1587,9 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
>  	void *object;
>  	void *next = *head;
>  	void *old_tail = *tail ? *tail : *head;
> -	int rsize;
>  
>  	if (is_kfence_address(next)) {
> -		slab_free_hook(s, next);
> +		slab_free_hook(s, next, false);
>  		return true;
>  	}
>  
> @@ -1584,20 +1601,8 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
>  		object = next;
>  		next = get_freepointer(s, object);
>  
> -		if (slab_want_init_on_free(s)) {
> -			/*
> -			 * Clear the object and the metadata, but don't touch
> -			 * the redzone.
> -			 */
> -			memset(kasan_reset_tag(object), 0, s->object_size);
> -			rsize = (s->flags & SLAB_RED_ZONE) ? s->red_left_pad
> -							   : 0;
> -			memset((char *)kasan_reset_tag(object) + s->inuse, 0,
> -			       s->size - s->inuse - rsize);
> -
> -		}
>  		/* If object's reuse doesn't have to be delayed */
> -		if (!slab_free_hook(s, object)) {
> +		if (!slab_free_hook(s, object, slab_want_init_on_free(s))) {
>  			/* Move object to the new freelist */
>  			set_freepointer(s, object, *head);
>  			*head = object;
> @@ -3235,7 +3240,7 @@ int build_detached_freelist(struct kmem_cache *s, size_t size,
>  	}
>  
>  	if (is_kfence_address(object)) {
> -		slab_free_hook(df->s, object);
> +		slab_free_hook(df->s, object, false);
>  		__kfence_free(object);
>  		p[size] = NULL; /* mark object processed */
>  		return size;
> -- 
> 2.30.1.766.gb4fecdf3b7-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEYOaR5jQXe6imp0%40elver.google.com.
