Return-Path: <kasan-dev+bncBC7OBJGL2MHBB44D5OAAMGQEUMQGAZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id ADE7730DE2F
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 16:32:03 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id o17sf14986997wrv.4
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 07:32:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612366323; cv=pass;
        d=google.com; s=arc-20160816;
        b=yMbGe4QznGDLTZchApAaMT+OWkNxwDi/rqSLRgoylIdVXpsTk6a8gxYNOCJj49njvG
         uC8L706HkhlHu5tb/pwnT6ggTPxB9hDh7SmkioSXHJZhGqxN25nB3qPvsEO+DXIwPCTH
         IQM1QmiQ+Hbo1U28rTvafJYYUnrPbrl8DUutcv1XAjIm8R/qrmoKeWjwHtmWb7xsEGLh
         oPEqO5Dj+oaVxgZa2wQzuZojxSGGQ8GFf1h69Bv21jnSO15GxTDxtVLJ27tJ8Dot9Uaz
         SXCoUHEe5PzWvN1cuqZE62fBnZUvnbYyQan/7SH2+Z7Vjc4BYZuRgJJ/Pop3FUCulGon
         z/Yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=miu2pkypMb0Cd5y945bF5OMV/gF46NsgmokIGO6c4mc=;
        b=J6k+kzniUT205ypnb6wQgONdEjnj5YcRCN1n0f8KB8/gLwJrR+Tco1fwuKjHwd2Ajn
         no+yKl7L9/yj7CWlitrPk7mDSaFXtpRtaiW94OK8Q6dtjIPyzR+u+IcKQ2saXlDXuyv1
         MS6a5WNsB3SU/lk6wOMlXx12IEgxhPWQYRhMrJdts85PjHdEJ85kHjyFF2yYOWbg7EXG
         mKeTFeSKiiFR3jS80Ci1Tb+J0uvVx68IqvjQeSTUkv35Driypbc5Kkm1sdmGPJXFlKRz
         hKI3b1SDps3M9Daz/tD17jPhJTsGjH1IZ9DNHhtRpu6rCqmGeMkOd9jhmFlf1ZjTHTOE
         OF3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NWGEYDLP;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=miu2pkypMb0Cd5y945bF5OMV/gF46NsgmokIGO6c4mc=;
        b=r8devlSxDxJm5fcqawd0LVMyPiGNVyiUY3Urp3v/191irF7wN2y9u3DOfcr1DpsTlW
         SB6/5sxVWFpyqBGRy4mRoM2UgwtzAAOqS/WOOjkM6K0DBquOnmbsH+5usrE/CMPENCW1
         xiA6L2u0QsoCz8/oZiMcsz3GEH6myMvggNWgm47L/f0Q8HjXQ1MvTsd+n1hJ+mOKf9uV
         +0a5wU/4VJ0W9BRHGtMrCZcO5TZhZVIcupQD+SDRx86YlK3NoX/31nt9JbEf/e+Kg546
         zu70simjf8l0U1URn82bOc27PQZ7/Xo99SICA/qVxYubE4NFenAijo44p2pKyocOirq/
         i2xQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=miu2pkypMb0Cd5y945bF5OMV/gF46NsgmokIGO6c4mc=;
        b=d439xKvbRzxxVWjGt7miivCfVABzANvuE+CITLnPozome0Y7dEIgkhfNGIW7HR1q1k
         w4rKRamfZPkha6Vhc6SOk8UYxJlyb/cEF0UJBVadMnVSg68fWN4+OP0VIxxFuMEcoUDx
         3JC0rYuVAvf+iQ+EJayCaDdU29hvZ7fXHzwSF6+2IG0YHjwJJlGqiYN+Ut4ucWMb3TyF
         y8vktQ220XVAZ6ONGgp3VvMUdqDdHNzelnxz263Gv7Xeg8oQ4IwWAAM/w2ZBrk5EiLfk
         rFHpUsL6k0K6pz2bwRWEXErO4dy32IhGU7MMzMVMrVs/Yp903M0rIAH4B8NbajqODk4y
         77dw==
X-Gm-Message-State: AOAM531GEPri0uxZk7aKRwVFpxQzcYX2FQAOMHbXm1xmPCspTPoohx5Y
	EHGM0dWo2nokOrLc/Rz/fpo=
X-Google-Smtp-Source: ABdhPJyCvegbfM3X0Q3C3A1x7lqB3GRsvnyNvxIfAA0Ulx6FZebM3zc2h4djYOUgS7rzJ3uj8mt4ZA==
X-Received: by 2002:a1c:7c17:: with SMTP id x23mr3426964wmc.65.1612366323467;
        Wed, 03 Feb 2021 07:32:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fd09:: with SMTP id e9ls3133007wrr.0.gmail; Wed, 03 Feb
 2021 07:32:02 -0800 (PST)
X-Received: by 2002:a5d:50c1:: with SMTP id f1mr4262769wrt.235.1612366322631;
        Wed, 03 Feb 2021 07:32:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612366322; cv=none;
        d=google.com; s=arc-20160816;
        b=JZcvKGKuA6rvOZd+XroRCCubedZ/3bv0icUvjyl+vH6qyrfC7/PpRJb5w9umLQsU1u
         +lGUndd0ywn6jrFWflI9Saxrw0hq7FTfzKdw1s4A1MvN3qdvPzBa1kt4WZH2n+LdhuFu
         0wRaUVIIegXCMasBOm8e1ul0QU6sC6nWiwjCcP19yEP7usiejk5z2R5algS4+zoeAuR+
         pMeHO9+iJsQHA9ed/XQcXbazmCuHpTl5FNyCFgkNQW+hAHEOq031n4fBsH7e6LD3ULxr
         RgN3jlMAYn4+tJCMBnxSCGkm6Vm0myIKYVy/YM1bbudJa79Q+ktLa2MsktIB0fPGMTuy
         qoxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=m3hMLAUjNEbRoV1KbnJIsefJTccBHrhGuifAQXw+Kb0=;
        b=hZzDRVMI3iovYOEsMZQ75+U9W+4c+kO4yOV38nBwjaobPOVkgVlkoO00CaU6G/osSC
         8QpfC3ZVx8GF7YIQeboUR7aRxIaiZOd3qYLnIygPNrVUc1/dDUwTh1CAHsyyZThKru8c
         gNj2d6gQX4Acfo5QWByXd30xrh1rVy3jdioOyyLv22HaGsQSt22c/5nFQydcqO3l03+6
         T53STpDzX0oFEpwR1hRmORuFykm3d1P23U1C67gJ2FhBmWiqQiya3elwG2hzqzMp7MSz
         xaESwMdSfx/hez8Vpe5s5jp3CAhf0aNbJBYhHGm52ls9HKMzhmQSzuok5vUvk9JBuR8m
         HYHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NWGEYDLP;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id f196si120291wme.2.2021.02.03.07.32.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 07:32:02 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id v15so24882474wrx.4
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 07:32:02 -0800 (PST)
X-Received: by 2002:adf:fa8b:: with SMTP id h11mr4284888wrr.114.1612366321734;
        Wed, 03 Feb 2021 07:32:01 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:b1de:c7d:30ce:1840])
        by smtp.gmail.com with ESMTPSA id h14sm3084106wmq.45.2021.02.03.07.32.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Feb 2021 07:32:00 -0800 (PST)
Date: Wed, 3 Feb 2021 16:31:54 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 09/12] kasan: ensure poisoning size alignment
Message-ID: <YBrB6g9e+636CyFh@elver.google.com>
References: <cover.1612208222.git.andreyknvl@google.com>
 <fee7c8c751dbf871e957935c347fcf7f1ca49beb.1612208222.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fee7c8c751dbf871e957935c347fcf7f1ca49beb.1612208222.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NWGEYDLP;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as
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

On Mon, Feb 01, 2021 at 08:43PM +0100, Andrey Konovalov wrote:
> A previous changes d99f6a10c161 ("kasan: don't round_up too much")
> attempted to simplify the code by adding a round_up(size) call into
> kasan_poison(). While this allows to have less round_up() calls around
> the code, this results in round_up() being called multiple times.
> 
> This patch removes round_up() of size from kasan_poison() and ensures
> that all callers round_up() the size explicitly. This patch also adds
> WARN_ON() alignment checks for address and size to kasan_poison() and
> kasan_unpoison().
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/common.c |  9 ++++++---
>  mm/kasan/kasan.h  | 33 ++++++++++++++++++++-------------
>  mm/kasan/shadow.c | 37 ++++++++++++++++++++++---------------
>  3 files changed, 48 insertions(+), 31 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index a51d6ea580b0..5691cca69397 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -261,7 +261,8 @@ void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
>  
>  void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
>  {
> -	kasan_poison(object, cache->object_size, KASAN_KMALLOC_REDZONE);
> +	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
> +			KASAN_KMALLOC_REDZONE);
>  }
>  
>  /*
> @@ -348,7 +349,8 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>  		return true;
>  	}
>  
> -	kasan_poison(object, cache->object_size, KASAN_KMALLOC_FREE);
> +	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
> +			KASAN_KMALLOC_FREE);
>  
>  	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine))
>  		return false;
> @@ -490,7 +492,8 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  	/* Poison the aligned part of the redzone. */
>  	redzone_start = round_up((unsigned long)(object + size),
>  				KASAN_GRANULE_SIZE);
> -	redzone_end = (unsigned long)object + cache->object_size;
> +	redzone_end = round_up((unsigned long)(object + cache->object_size),
> +				KASAN_GRANULE_SIZE);
>  	kasan_poison((void *)redzone_start, redzone_end - redzone_start,
>  			   KASAN_KMALLOC_REDZONE);
>  
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 6a2882997f23..2f7400a3412f 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -321,30 +321,37 @@ static inline u8 kasan_random_tag(void) { return 0; }
>  
>  #ifdef CONFIG_KASAN_HW_TAGS
>  
> -static inline void kasan_poison(const void *address, size_t size, u8 value)
> +static inline void kasan_poison(const void *addr, size_t size, u8 value)
>  {
> -	address = kasan_reset_tag(address);
> +	addr = kasan_reset_tag(addr);
>  
>  	/* Skip KFENCE memory if called explicitly outside of sl*b. */
> -	if (is_kfence_address(address))
> +	if (is_kfence_address(addr))
>  		return;
>  
> -	hw_set_mem_tag_range((void *)address,
> -			round_up(size, KASAN_GRANULE_SIZE), value);
> +	if (WARN_ON((u64)addr & KASAN_GRANULE_MASK))
> +		return;
> +	if (WARN_ON(size & KASAN_GRANULE_MASK))
> +		return;
> +
> +	hw_set_mem_tag_range((void *)addr, size, value);
>  }
>  
> -static inline void kasan_unpoison(const void *address, size_t size)
> +static inline void kasan_unpoison(const void *addr, size_t size)
>  {
> -	u8 tag = get_tag(address);
> +	u8 tag = get_tag(addr);
>  
> -	address = kasan_reset_tag(address);
> +	addr = kasan_reset_tag(addr);
>  
>  	/* Skip KFENCE memory if called explicitly outside of sl*b. */
> -	if (is_kfence_address(address))
> +	if (is_kfence_address(addr))
>  		return;
>  
> -	hw_set_mem_tag_range((void *)address,
> -			round_up(size, KASAN_GRANULE_SIZE), tag);
> +	if (WARN_ON((u64)addr & KASAN_GRANULE_MASK))
> +		return;
> +	size = round_up(size, KASAN_GRANULE_SIZE);
> +
> +	hw_set_mem_tag_range((void *)addr, size, tag);
>  }
>  
>  static inline bool kasan_byte_accessible(const void *addr)
> @@ -361,7 +368,7 @@ static inline bool kasan_byte_accessible(const void *addr)
>  /**
>   * kasan_poison - mark the memory range as unaccessible
>   * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
> - * @size - range size
> + * @size - range size, must be aligned to KASAN_GRANULE_SIZE
>   * @value - value that's written to metadata for the range
>   *
>   * The size gets aligned to KASAN_GRANULE_SIZE before marking the range.
> @@ -371,7 +378,7 @@ void kasan_poison(const void *addr, size_t size, u8 value);
>  /**
>   * kasan_unpoison - mark the memory range as accessible
>   * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
> - * @size - range size
> + * @size - range size, can be unaligned
>   *
>   * For the tag-based modes, the @size gets aligned to KASAN_GRANULE_SIZE before
>   * marking the range.
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 1ed7817e4ee6..c97f51c557ea 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -69,7 +69,7 @@ void *memcpy(void *dest, const void *src, size_t len)
>  	return __memcpy(dest, src, len);
>  }
>  
> -void kasan_poison(const void *address, size_t size, u8 value)
> +void kasan_poison(const void *addr, size_t size, u8 value)
>  {
>  	void *shadow_start, *shadow_end;
>  
> @@ -78,55 +78,62 @@ void kasan_poison(const void *address, size_t size, u8 value)
>  	 * some of the callers (e.g. kasan_poison_object_data) pass tagged
>  	 * addresses to this function.
>  	 */
> -	address = kasan_reset_tag(address);
> +	addr = kasan_reset_tag(addr);
>  
>  	/* Skip KFENCE memory if called explicitly outside of sl*b. */
> -	if (is_kfence_address(address))
> +	if (is_kfence_address(addr))
>  		return;
>  
> -	size = round_up(size, KASAN_GRANULE_SIZE);
> -	shadow_start = kasan_mem_to_shadow(address);
> -	shadow_end = kasan_mem_to_shadow(address + size);
> +	if (WARN_ON((u64)addr & KASAN_GRANULE_MASK))
> +		return;
> +	if (WARN_ON(size & KASAN_GRANULE_MASK))
> +		return;
> +
> +	shadow_start = kasan_mem_to_shadow(addr);
> +	shadow_end = kasan_mem_to_shadow(addr + size);
>  
>  	__memset(shadow_start, value, shadow_end - shadow_start);
>  }
>  EXPORT_SYMBOL(kasan_poison);
>  
>  #ifdef CONFIG_KASAN_GENERIC
> -void kasan_poison_last_granule(const void *address, size_t size)
> +void kasan_poison_last_granule(const void *addr, size_t size)
>  {
>  	if (size & KASAN_GRANULE_MASK) {
> -		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
> +		u8 *shadow = (u8 *)kasan_mem_to_shadow(addr + size);
>  		*shadow = size & KASAN_GRANULE_MASK;
>  	}
>  }
>  #endif
>  
> -void kasan_unpoison(const void *address, size_t size)
> +void kasan_unpoison(const void *addr, size_t size)
>  {
> -	u8 tag = get_tag(address);
> +	u8 tag = get_tag(addr);
>  
>  	/*
>  	 * Perform shadow offset calculation based on untagged address, as
>  	 * some of the callers (e.g. kasan_unpoison_object_data) pass tagged
>  	 * addresses to this function.
>  	 */
> -	address = kasan_reset_tag(address);
> +	addr = kasan_reset_tag(addr);
>  
>  	/*
>  	 * Skip KFENCE memory if called explicitly outside of sl*b. Also note
>  	 * that calls to ksize(), where size is not a multiple of machine-word
>  	 * size, would otherwise poison the invalid portion of the word.
>  	 */
> -	if (is_kfence_address(address))
> +	if (is_kfence_address(addr))
> +		return;
> +
> +	if (WARN_ON((u64)addr & KASAN_GRANULE_MASK))
>  		return;
>  
> -	/* Unpoison round_up(size, KASAN_GRANULE_SIZE) bytes. */
> -	kasan_poison(address, size, tag);
> +	/* Unpoison all granules that cover the object. */
> +	kasan_poison(addr, round_up(size, KASAN_GRANULE_SIZE), tag);
>  
>  	/* Partially poison the last granule for the generic mode. */
>  	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> -		kasan_poison_last_granule(address, size);
> +		kasan_poison_last_granule(addr, size);
>  }
>  
>  #ifdef CONFIG_MEMORY_HOTPLUG
> -- 
> 2.30.0.365.g02bc693789-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YBrB6g9e%2B636CyFh%40elver.google.com.
