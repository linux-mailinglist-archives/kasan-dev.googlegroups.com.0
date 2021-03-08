Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY4YTCBAMGQEQ3BX7PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E0E5D330C85
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 12:37:07 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id d11sf3333978lfe.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 03:37:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615203427; cv=pass;
        d=google.com; s=arc-20160816;
        b=phs0LpL2yhvI7tMdZNlVPd0nSk1C7HLK+2SwKPV05n2oHWykjLDWGvxbnDXoBAXFYT
         9W3CJ5HMTYxXHDy009DlaIrT0bhpN/Ww3oX/WDT1Jqq5ki3epRkplfN/zUG0jD+97OPF
         4G1YCUotmFZPkC+hAFmtKJQiLAwIa3mFic0G0vqJivmmLegRoKhaU7J1I2Hy6VBr5/5c
         DXc7El0wVqs9ylpfaxocQ6aEtnvSMh3heCIzLo0RGnIK8wYsPB3tOtS3Wdik29hrheOI
         R/GP1m8iX8/EgwtThucFdumJdsSg9swlRAzksug8iBn+o2fw9Ft2UAvNI199dqO46hnD
         qd8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=A+y6naCNSZ3ZYVRrE+8QfTQ0spdKkZxwwN4r9d8Xrlg=;
        b=J8UYEMV55GPu4VJQN816rNLOPPRIQWAktQyH4Top6hgQ4VGh295BqhApy1uBI3B+YX
         koHvYTY01VLMPb8BEXJeYvhEfsg59Ma5ivSkjmZNnBIRvZd6Cw9GkzU08HEkfJmBDMHf
         MTQDlEGgL1VMtW2dxp/2xs1OijyUC3MGXJyIiss9w3d+oXPMS5INKaAG52m7jpDisDAX
         jHrVkQbu3h28lCf0vKOnCZVWfyEO6ZTsR1LlzOsr9HmTHZqhlDrKb10nx4ygF0rX/4jb
         67yqzkjfG9SqAqWGbjKT74BnYRw8jnKBDdijqamu9wJMbmnpQHb25VzT8DEIJRgcT3Td
         qWmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jlVBStZq;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=A+y6naCNSZ3ZYVRrE+8QfTQ0spdKkZxwwN4r9d8Xrlg=;
        b=UCNxvxJSXrxFcUce9ClTJsWJcm0anIOYdF/d1/D+pnywRDdxX/9wbxX60IVMILFLKk
         93zAkgBDZ8h7vwRCW2VEw/dUfbVStevOHwaasKFHfEZRS+IehVxSHUuh4HSxb+SOuNAY
         ZWMbt1JwRLApXx6o1IY+Kjp51moEpNwvisaGNaUKZWJQxpk/aVO4QqNLGTEEx7+o5mqn
         4JYQdT62FJBPcsAqPtocgaXbbcGNXMFqHt3k1wowkcJtT6uY4wQS+JcVwvw9za6ACpcS
         BXFlIDbqyUbP4iihyFYeBBb1ZbE5FSm6Q5y8AkXrpgMdQ6f86bXxXvCgX2IBkVflOXSE
         3M7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=A+y6naCNSZ3ZYVRrE+8QfTQ0spdKkZxwwN4r9d8Xrlg=;
        b=PXBZxWCArnmWvS6IdTQvfVUmZR6oqQzNLuXZaw5ETqGfXBZAR0Sy+Xj3HRnRJ4Y3AO
         Wq+Pa8OQ4SBLeOeCyHMC8+w7p6yyVufZw/dLuxxBMPZl+fwnnPmTfxRhwnOISPruTtPf
         sGaiPPO4T6Cof1okGpFQNFYc2pUx/qD79wcH16YIKVJU//wapVAoywSs05TFPdGjwOR6
         Q/VZyFhE7O5vr2kKVJUw7wnDQvPU7JBXvfgg8A0CfsbQEyd8YdIYgmOwYPoDv0Nke6Q9
         FwUzDRs/ZY9eF0QlpxJaQt51FK1oQx1UILhuO9OMJOHfl7AstJwzeClsvipexQMftbX1
         a1mg==
X-Gm-Message-State: AOAM531U+qAB+hPyhdDAfx+gnKXrDJjI4RqXKcyDsH0vWsXjKUKV2P5U
	JsVL/LuLAZOK6fsTtmGs4DI=
X-Google-Smtp-Source: ABdhPJwWZocAvhLOxU9yCKt2/wdVUMbFrkdEFaBL96bLQXk2Vdug2PCtLbmpBch4f+Ke86GU6+EJ2A==
X-Received: by 2002:a05:6512:31d3:: with SMTP id j19mr14570354lfe.495.1615203427472;
        Mon, 08 Mar 2021 03:37:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc11:: with SMTP id b17ls3337964ljf.7.gmail; Mon, 08 Mar
 2021 03:37:06 -0800 (PST)
X-Received: by 2002:a2e:981a:: with SMTP id a26mr13852224ljj.204.1615203426355;
        Mon, 08 Mar 2021 03:37:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615203426; cv=none;
        d=google.com; s=arc-20160816;
        b=PwiJYjz864zeXvRVRo0ZlZCXKyGz0bk+pnYkm8/JYHTrLQ5YLN9NGbuhCmHIM2JXRo
         3EdfsI8tm+17cvMTRDdgNJFrsHhoF7/o8c9+gB2cYLy7c1SouUeidxJTaKvG4JtnBONQ
         8zM7/AMPD2RDLxfFcVdFQVG27MiPRcLzAUO/bWa+SNNk7NzwczaSvL7Sg8xSLrarCpEY
         eOKE+RSt8VgpGsEhiESQhYbEaxJZhNrQEd5fmjHb2O2Y1E4FqZQuC3sM4pNe/pzENJmt
         ezL/TUSL5L0Ejmf87RdR+EffMw1oK+DhglQihQYrF+c6RuwsYqgAImDXMNAK6AbBmsTD
         IeIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=87FdZea+iM/dFONNBtDahO6WoHLjdEMssDM4fhYdjyg=;
        b=zXx0I9SGW5wiudyLcvbCCjpvx+eJwu0uYvU75mgpjHYr9V9YmHvmk1L/ulhzvNIQeI
         xxP+Jgb1LnKZiP3YLDd93BuB6nYpBEhEM7jXigCV6LgETOYRMezTBHHO0RV5Km2hDSM1
         GlxjMsrEQUAinhi08tCjtyamUoEUWro0mNW+u/F3mJudSfYaVSpwILpEmMzSeRRYaxv9
         YH5Xl8WVZJA0n86IfhOzeZ5wAB5UmGQHXDKg2zi3taK5LiMRBc77tXZ02I6MCh4yGvU4
         DMkws6b7hQZtE51wPF9+7w7oORH9EnRghaWA1cpa1dHv0a1agZNzMwwXzrBEynMREqYk
         /Xyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jlVBStZq;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id x41si374141lfu.10.2021.03.08.03.37.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 03:37:06 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id b2-20020a7bc2420000b029010be1081172so3589945wmj.1
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 03:37:06 -0800 (PST)
X-Received: by 2002:a7b:c119:: with SMTP id w25mr21264635wmi.127.1615203425609;
        Mon, 08 Mar 2021 03:37:05 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:9d1d:b6a0:d116:531b])
        by smtp.gmail.com with ESMTPSA id p14sm18252588wmc.30.2021.03.08.03.37.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Mar 2021 03:37:04 -0800 (PST)
Date: Mon, 8 Mar 2021 12:36:59 +0100
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
Subject: Re: [PATCH 4/5] kasan, mm: integrate slab init_on_alloc with HW_TAGS
Message-ID: <YEYMWynJ3SdDhV8u@elver.google.com>
References: <cover.1614989433.git.andreyknvl@google.com>
 <b8cc85d5cc9818b72e543d8034ce38acce0c0300.1614989433.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b8cc85d5cc9818b72e543d8034ce38acce0c0300.1614989433.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jlVBStZq;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as
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
> of HW_TAGS KASAN routines for slab memory when init_on_alloc is enabled.
> 
> With this change, memory initialization memset() is no longer called
> when both HW_TAGS KASAN and init_on_alloc are enabled. Instead, memory
> is initialized in KASAN runtime.
> 
> The memory initialization memset() is moved into slab_post_alloc_hook()
> that currently directly follows the initialization loop. A new argument
> is added to slab_post_alloc_hook() that indicates whether to initialize
> the memory or not.
> 
> To avoid discrepancies with which memory gets initialized that can be
> caused by future changes, both KASAN hook and initialization memset()
> are put together and a warning comment is added.
> 
> Combining setting allocation tags with memory initialization improves
> HW_TAGS KASAN performance when init_on_alloc is enabled.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  include/linux/kasan.h |  8 ++++----
>  mm/kasan/common.c     |  4 ++--
>  mm/slab.c             | 28 +++++++++++++---------------
>  mm/slab.h             | 17 +++++++++++++----
>  mm/slub.c             | 27 +++++++++++----------------
>  5 files changed, 43 insertions(+), 41 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 4c0f414a893b..bb756f6c73b5 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -216,12 +216,12 @@ static __always_inline void kasan_slab_free_mempool(void *ptr)
>  }
>  
>  void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
> -				       void *object, gfp_t flags);
> +				       void *object, gfp_t flags, bool init);
>  static __always_inline void * __must_check kasan_slab_alloc(
> -				struct kmem_cache *s, void *object, gfp_t flags)
> +		struct kmem_cache *s, void *object, gfp_t flags, bool init)
>  {
>  	if (kasan_enabled())
> -		return __kasan_slab_alloc(s, object, flags);
> +		return __kasan_slab_alloc(s, object, flags, init);
>  	return object;
>  }
>  
> @@ -306,7 +306,7 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object)
>  static inline void kasan_kfree_large(void *ptr) {}
>  static inline void kasan_slab_free_mempool(void *ptr) {}
>  static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
> -				   gfp_t flags)
> +				   gfp_t flags, bool init)
>  {
>  	return object;
>  }
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 6107c795611f..7ea747b18c26 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -428,7 +428,7 @@ static void set_alloc_info(struct kmem_cache *cache, void *object,
>  }
>  
>  void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
> -					void *object, gfp_t flags)
> +					void *object, gfp_t flags, bool init)
>  {
>  	u8 tag;
>  	void *tagged_object;
> @@ -453,7 +453,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
>  	 * Unpoison the whole object.
>  	 * For kmalloc() allocations, kasan_kmalloc() will do precise poisoning.
>  	 */
> -	kasan_unpoison(tagged_object, cache->object_size, false);
> +	kasan_unpoison(tagged_object, cache->object_size, init);
>  
>  	/* Save alloc info (if possible) for non-kmalloc() allocations. */
>  	if (kasan_stack_collection_enabled())
> diff --git a/mm/slab.c b/mm/slab.c
> index 51fd424e0d6d..936dd686dec9 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -3216,6 +3216,7 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid, size_t orig_
>  	void *ptr;
>  	int slab_node = numa_mem_id();
>  	struct obj_cgroup *objcg = NULL;
> +	bool init = false;
>  
>  	flags &= gfp_allowed_mask;
>  	cachep = slab_pre_alloc_hook(cachep, &objcg, 1, flags);
> @@ -3254,12 +3255,10 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid, size_t orig_
>    out:
>  	local_irq_restore(save_flags);
>  	ptr = cache_alloc_debugcheck_after(cachep, flags, ptr, caller);
> -
> -	if (unlikely(slab_want_init_on_alloc(flags, cachep)) && ptr)
> -		memset(ptr, 0, cachep->object_size);
> +	init = slab_want_init_on_alloc(flags, cachep);
>  
>  out_hooks:
> -	slab_post_alloc_hook(cachep, objcg, flags, 1, &ptr);
> +	slab_post_alloc_hook(cachep, objcg, flags, 1, &ptr, init);
>  	return ptr;
>  }
>  
> @@ -3301,6 +3300,7 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, size_t orig_size, unsigned lo
>  	unsigned long save_flags;
>  	void *objp;
>  	struct obj_cgroup *objcg = NULL;
> +	bool init = false;
>  
>  	flags &= gfp_allowed_mask;
>  	cachep = slab_pre_alloc_hook(cachep, &objcg, 1, flags);
> @@ -3317,12 +3317,10 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, size_t orig_size, unsigned lo
>  	local_irq_restore(save_flags);
>  	objp = cache_alloc_debugcheck_after(cachep, flags, objp, caller);
>  	prefetchw(objp);
> -
> -	if (unlikely(slab_want_init_on_alloc(flags, cachep)) && objp)
> -		memset(objp, 0, cachep->object_size);
> +	init = slab_want_init_on_alloc(flags, cachep);
>  
>  out:
> -	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp);
> +	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init);
>  	return objp;
>  }
>  
> @@ -3542,18 +3540,18 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  
>  	cache_alloc_debugcheck_after_bulk(s, flags, size, p, _RET_IP_);
>  
> -	/* Clear memory outside IRQ disabled section */
> -	if (unlikely(slab_want_init_on_alloc(flags, s)))
> -		for (i = 0; i < size; i++)
> -			memset(p[i], 0, s->object_size);
> -
> -	slab_post_alloc_hook(s, objcg, flags, size, p);
> +	/*
> +	 * memcg and kmem_cache debug support and memory initialization.
> +	 * Done outside of the IRQ disabled section.
> +	 */
> +	slab_post_alloc_hook(s, objcg, flags, size, p,
> +				slab_want_init_on_alloc(flags, s));
>  	/* FIXME: Trace call missing. Christoph would like a bulk variant */
>  	return size;
>  error:
>  	local_irq_enable();
>  	cache_alloc_debugcheck_after_bulk(s, flags, i, p, _RET_IP_);
> -	slab_post_alloc_hook(s, objcg, flags, i, p);
> +	slab_post_alloc_hook(s, objcg, flags, i, p, false);
>  	__kmem_cache_free_bulk(s, i, p);
>  	return 0;
>  }
> diff --git a/mm/slab.h b/mm/slab.h
> index 076582f58f68..0116a314cd21 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -506,15 +506,24 @@ static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
>  }
>  
>  static inline void slab_post_alloc_hook(struct kmem_cache *s,
> -					struct obj_cgroup *objcg,
> -					gfp_t flags, size_t size, void **p)
> +					struct obj_cgroup *objcg, gfp_t flags,
> +					size_t size, void **p, bool init)
>  {
>  	size_t i;
>  
>  	flags &= gfp_allowed_mask;
> +
> +	/*
> +	 * As memory initialization is integrated with hardware tag-based
> +	 * KASAN, kasan_slab_alloc and initialization memset must be
> +	 * kept together to avoid discrepancies in behavior.
> +	 *
> +	 * As p[i] might get tagged, memset and kmemleak hook come after KASAN.
> +	 */
>  	for (i = 0; i < size; i++) {
> -		p[i] = kasan_slab_alloc(s, p[i], flags);
> -		/* As p[i] might get tagged, call kmemleak hook after KASAN. */
> +		p[i] = kasan_slab_alloc(s, p[i], flags, init);
> +		if (p[i] && init && !IS_ENABLED(CONFIG_KASAN_HW_TAGS))

Same as the other patch, it seems awkward to have
!IS_ENABLED(CONFIG_KASAN_HW_TAGS) rather than a kasan_*() helper that
returns this information.

> +			memset(p[i], 0, s->object_size);
>  		kmemleak_alloc_recursive(p[i], s->object_size, 1,
>  					 s->flags, flags);
>  	}
> diff --git a/mm/slub.c b/mm/slub.c
> index e26c274b4657..f53df23760e3 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2822,6 +2822,7 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
>  	struct page *page;
>  	unsigned long tid;
>  	struct obj_cgroup *objcg = NULL;
> +	bool init = false;
>  
>  	s = slab_pre_alloc_hook(s, &objcg, 1, gfpflags);
>  	if (!s)
> @@ -2899,12 +2900,10 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
>  	}
>  
>  	maybe_wipe_obj_freeptr(s, object);
> -
> -	if (unlikely(slab_want_init_on_alloc(gfpflags, s)) && object)
> -		memset(kasan_reset_tag(object), 0, s->object_size);
> +	init = slab_want_init_on_alloc(gfpflags, s);
>  
>  out:
> -	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object);
> +	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init);
>  
>  	return object;
>  }
> @@ -3356,20 +3355,16 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  	c->tid = next_tid(c->tid);
>  	local_irq_enable();
>  
> -	/* Clear memory outside IRQ disabled fastpath loop */
> -	if (unlikely(slab_want_init_on_alloc(flags, s))) {
> -		int j;
> -
> -		for (j = 0; j < i; j++)
> -			memset(kasan_reset_tag(p[j]), 0, s->object_size);
> -	}
> -
> -	/* memcg and kmem_cache debug support */
> -	slab_post_alloc_hook(s, objcg, flags, size, p);
> +	/*
> +	 * memcg and kmem_cache debug support and memory initialization.
> +	 * Done outside of the IRQ disabled fastpath loop.
> +	 */
> +	slab_post_alloc_hook(s, objcg, flags, size, p,
> +				slab_want_init_on_alloc(flags, s));
>  	return i;
>  error:
>  	local_irq_enable();
> -	slab_post_alloc_hook(s, objcg, flags, i, p);
> +	slab_post_alloc_hook(s, objcg, flags, i, p, false);
>  	__kmem_cache_free_bulk(s, i, p);
>  	return 0;
>  }
> @@ -3579,7 +3574,7 @@ static void early_kmem_cache_node_alloc(int node)
>  	init_object(kmem_cache_node, n, SLUB_RED_ACTIVE);
>  	init_tracking(kmem_cache_node, n);
>  #endif
> -	n = kasan_slab_alloc(kmem_cache_node, n, GFP_KERNEL);
> +	n = kasan_slab_alloc(kmem_cache_node, n, GFP_KERNEL, false);
>  	page->freelist = get_freepointer(kmem_cache_node, n);
>  	page->inuse = 1;
>  	page->frozen = 0;
> -- 
> 2.30.1.766.gb4fecdf3b7-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEYMWynJ3SdDhV8u%40elver.google.com.
