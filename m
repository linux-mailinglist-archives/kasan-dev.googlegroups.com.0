Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE724WAAMGQERMJ6WLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 789D730C57F
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 17:25:55 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id n15sf12842932wrv.20
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 08:25:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612283155; cv=pass;
        d=google.com; s=arc-20160816;
        b=uRORRCKHx4+rQsBeb3EMi2zgv7XlzWzc+5TW5jgXxm8NJ4Hp8hXLffa+Oanhj4Abgs
         0sxR64fqhKHDvgZZyP3FKnnonvT8W5t5mqRA0O2uGaD9XCRrrTjTeJTl6Kn1C2ko5Pb9
         MhQLUk98D+IIJltDYjgxL+jqRYbxlm9ccU2C9DM8rdwAW/jmH7PDapuR0XXcte07uoMA
         QbljxlPBFZcuz1EPgO+4AfUNj7TVjlne2EEL7zLXU1tkxXWsM6fJil1Y5RjnDpSoapH0
         fmq3W2gsbrQWKFPAkY5cDAEabboYJYcXtqR1XvMAzbNnUj82Vu0CS9N6nVVcGxdlmixG
         G+6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=+387E50cCi3tmfxhdfb289hPJUyvRMqi3sW7ZXq0d20=;
        b=g1ObPm21/ThLAWJKnIJ3rGkb/URemO3cS5jCwEgOgoLN3f9tMXTH96xcRZazNQkoyh
         8yO+44OD9FPkp05rg5m5n5xlDtkxO0gwQEUXYkdc9hoCMG/jlmfAAJdRFdswhYTA7rva
         YQS1dVVNg3Rx4W9TBAKcQOTYpxXD9IuFJ+VhsaQ56T0luVJy4daWirCAbZAtSZC6N+nC
         Q9As2lil2ki2mkUrrcD958gOtIb16BTWM1I8/OmdB3mNXCG35c9eFjG5iRukDi/853UK
         b1M4THKjtMnb549S05KMvfS02NU9ui0XO8JS69nXY4IPW4zLNLZzJjjmpEspUxulR8OZ
         laaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RqAcaM9Y;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=+387E50cCi3tmfxhdfb289hPJUyvRMqi3sW7ZXq0d20=;
        b=hRcGHOAuXyYGikfPF1wEf0CmIt0v2UtBzZUSH1P4pjwgtpRgRRJQ+v+ehS+XEGfxB9
         JuAKmJ3uZgDb/pcjhc5bZnOKHyHTCExWG2L+fQtWnM6DhQI3Lz2fUihweBmtwO9HnJJO
         gK0FFyVFT3Mq0DZCASPhEw0a0kODq5JXQPTH4zg0rjtZq4WFHNeNnqot8vtzdqAEPtNQ
         xo79cUHChOHstpNIE/2R4B8cM5A3//GkMULmaJQvz82WGLfT3yREEArA51vHOYyTw/NL
         +cUaqsCANSwJlpHzuGwq6ibxL0tBzErqROj1LpbQln16kQSGLHjxvoGJFl4IDlM0DvoJ
         VJ1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+387E50cCi3tmfxhdfb289hPJUyvRMqi3sW7ZXq0d20=;
        b=q/6BxnsDupV2v4uuSa87sojXYTo04hnmzWh0PJP2t/rqCKdfwUCDJhXiHpt0nS94hV
         pCoR0ZCKGhgP4/xK4/XwqIPvjOAcQkdgilgtuishoq9pc6U5b0yP3o2sDN/bi7cm6n8T
         y1TPyhWYKsYF2wSqP2iUT0V8EIRYluPe7j3RT8Ukrdlwj9Mqi3dOEvMX1ocW6ZJJySt6
         IduERu69tEeobHI+7GxU82YcWkKlf477VKSU6i6Oiwv8kHPWsm9msSy6tS93ZGT9SbL5
         gDXEQffb0xglx9TTUufc8roCLgXGKVvcLbG1e9TTKFHECdlqZsmihiP31ybmSsgyEzvb
         8mcQ==
X-Gm-Message-State: AOAM533kTirmCEtDsjG9fuPJsVZXtXijqFVR3lsnTiil0T9u+aa2wpPh
	xacC2aB2OdlpHjnbjTkti+g=
X-Google-Smtp-Source: ABdhPJxkC0w2ZtYDzIhByyU2iuLH+7VJiJgrvikGrw4VZYfAylXb/4UEr34iYhteZGLZ7Z0VcxqLtA==
X-Received: by 2002:a1c:c904:: with SMTP id f4mr4548569wmb.14.1612283155235;
        Tue, 02 Feb 2021 08:25:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:60c2:: with SMTP id u185ls1609203wmb.2.gmail; Tue, 02
 Feb 2021 08:25:54 -0800 (PST)
X-Received: by 2002:a7b:cd08:: with SMTP id f8mr4476820wmj.142.1612283154268;
        Tue, 02 Feb 2021 08:25:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612283154; cv=none;
        d=google.com; s=arc-20160816;
        b=XTpMb313FTzQAwmIANkFRQp9ve8sfc7kLLm/3p0MvQztFy4DmTdA87jrtsG8RBIYQs
         QmrKCyHmRPNsGAGayI4ry3pApVFWqIdWunHxuX+w/XeeV5k/mFSgUpFR5gMk0rSbuhWo
         KPrcBC/1ZUu61fsJIENBnkwZAIg3ub9U5eiDb9TYU3/Qw776KJGk2OXER+JGzh1n0+no
         YIwyQrHiN6O6Uc4rDJOV8A7EEOVEjnELdZwT4DDaGy15Loo8qhPaZuzjTgRdE0A42XSk
         QdkrezuuuORzF3WDXmMI1zFGin6AxMXg8Ug4sRj0giaYv/eI01h125IIlMmArGfDPsLc
         JNxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=+Tllhc+5c0Pfht0qAuJDHzixy31AJS/JnPan2WRpzvQ=;
        b=Q3yB1+NzJMQg2OFmr+Q0EUmkvUIjbr8LSt05fSxub6K4qjh4HEuuBv5bwLbMlzeZAS
         8FQS+mHszVtaj6jF7P6kRblGOAwzs5OMukPIjQAFNEDGq7n9C8DrlR6IAmxFVVQo5cE/
         pIcN8HJm66ksFX2gZlcPNqu1RLPp/PglkUx18pfruCDv7PL2aG9y6wrvtakE9MwS0881
         Pmvlqa+8sjAfoIBAxXmKrYN/6uwgqDKYEY9/fm7ndOBq0MgR5ixQKXAAWIvqtBFzr9qp
         xbmN3H63ug/wWBmemwmkK+ZQ6fXMbByNela4xoBnKghNNlhLZqQ6nsfAcKXgBYMynPJW
         WhLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RqAcaM9Y;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id h10si121945wmq.4.2021.02.02.08.25.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Feb 2021 08:25:54 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id g10so21125923wrx.1
        for <kasan-dev@googlegroups.com>; Tue, 02 Feb 2021 08:25:54 -0800 (PST)
X-Received: by 2002:a5d:6a45:: with SMTP id t5mr24294755wrw.252.1612283153748;
        Tue, 02 Feb 2021 08:25:53 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id c20sm3790013wmb.38.2021.02.02.08.25.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Feb 2021 08:25:52 -0800 (PST)
Date: Tue, 2 Feb 2021 17:25:47 +0100
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
Subject: Re: [PATCH 02/12] kasan, mm: optimize kmalloc poisoning
Message-ID: <YBl9C+q84BqiFd4F@elver.google.com>
References: <cover.1612208222.git.andreyknvl@google.com>
 <b3a02f4f7cda00c87af170c1bf555996a9c6788c.1612208222.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b3a02f4f7cda00c87af170c1bf555996a9c6788c.1612208222.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RqAcaM9Y;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::429 as
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
> For allocations from kmalloc caches, kasan_kmalloc() always follows
> kasan_slab_alloc(). Currenly, both of them unpoison the whole object,
> which is unnecessary.
> 
> This patch provides separate implementations for both annotations:
> kasan_slab_alloc() unpoisons the whole object, and kasan_kmalloc()
> only poisons the redzone.
> 
> For generic KASAN, the redzone start might not be aligned to
> KASAN_GRANULE_SIZE. Therefore, the poisoning is split in two parts:
> kasan_poison_last_granule() poisons the unaligned part, and then
> kasan_poison() poisons the rest.
> 
> This patch also clarifies alignment guarantees of each of the poisoning
> functions and drops the unnecessary round_up() call for redzone_end.
> 
> With this change, the early SLUB cache annotation needs to be changed to
> kasan_slab_alloc(), as kasan_kmalloc() doesn't unpoison objects now.
> The number of poisoned bytes for objects in this cache stays the same, as
> kmem_cache_node->object_size is equal to sizeof(struct kmem_cache_node).
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  mm/kasan/common.c | 93 +++++++++++++++++++++++++++++++----------------
>  mm/kasan/kasan.h  | 43 +++++++++++++++++++++-
>  mm/kasan/shadow.c | 28 +++++++-------
>  mm/slub.c         |  3 +-
>  4 files changed, 119 insertions(+), 48 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 374049564ea3..128cb330ca73 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -278,21 +278,11 @@ void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
>   *    based on objects indexes, so that objects that are next to each other
>   *    get different tags.
>   */
> -static u8 assign_tag(struct kmem_cache *cache, const void *object,
> -			bool init, bool keep_tag)
> +static u8 assign_tag(struct kmem_cache *cache, const void *object, bool init)
>  {
>  	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>  		return 0xff;
>  
> -	/*
> -	 * 1. When an object is kmalloc()'ed, two hooks are called:
> -	 *    kasan_slab_alloc() and kasan_kmalloc(). We assign the
> -	 *    tag only in the first one.
> -	 * 2. We reuse the same tag for krealloc'ed objects.
> -	 */
> -	if (keep_tag)
> -		return get_tag(object);
> -
>  	/*
>  	 * If the cache neither has a constructor nor has SLAB_TYPESAFE_BY_RCU
>  	 * set, assign a tag when the object is being allocated (init == false).
> @@ -325,7 +315,7 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
>  	}
>  
>  	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
> -	object = set_tag(object, assign_tag(cache, object, true, false));
> +	object = set_tag(object, assign_tag(cache, object, true));
>  
>  	return (void *)object;
>  }
> @@ -413,12 +403,46 @@ static void set_alloc_info(struct kmem_cache *cache, void *object,
>  		kasan_set_track(&alloc_meta->alloc_track, flags);
>  }
>  
> +void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
> +					void *object, gfp_t flags)
> +{
> +	u8 tag;
> +	void *tagged_object;
> +
> +	if (gfpflags_allow_blocking(flags))
> +		kasan_quarantine_reduce();
> +
> +	if (unlikely(object == NULL))
> +		return NULL;
> +
> +	if (is_kfence_address(object))
> +		return (void *)object;
> +
> +	/*
> +	 * Generate and assign random tag for tag-based modes.
> +	 * Tag is ignored in set_tag() for the generic mode.
> +	 */
> +	tag = assign_tag(cache, object, false);
> +	tagged_object = set_tag(object, tag);
> +
> +	/*
> +	 * Unpoison the whole object.
> +	 * For kmalloc() allocations, kasan_kmalloc() will do precise poisoning.
> +	 */
> +	kasan_unpoison(tagged_object, cache->object_size);
> +
> +	/* Save alloc info (if possible) for non-kmalloc() allocations. */
> +	if (kasan_stack_collection_enabled())
> +		set_alloc_info(cache, (void *)object, flags, false);
> +
> +	return tagged_object;
> +}
> +
>  static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
> -				size_t size, gfp_t flags, bool kmalloc)
> +					size_t size, gfp_t flags)
>  {
>  	unsigned long redzone_start;
>  	unsigned long redzone_end;
> -	u8 tag;
>  
>  	if (gfpflags_allow_blocking(flags))
>  		kasan_quarantine_reduce();
> @@ -429,33 +453,41 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  	if (is_kfence_address(kasan_reset_tag(object)))
>  		return (void *)object;
>  
> +	/*
> +	 * The object has already been unpoisoned by kasan_slab_alloc() for
> +	 * kmalloc() or by ksize() for krealloc().
> +	 */
> +
> +	/*
> +	 * The redzone has byte-level precision for the generic mode.
> +	 * Partially poison the last object granule to cover the unaligned
> +	 * part of the redzone.
> +	 */
> +	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +		kasan_poison_last_granule((void *)object, size);
> +
> +	/* Poison the aligned part of the redzone. */
>  	redzone_start = round_up((unsigned long)(object + size),
>  				KASAN_GRANULE_SIZE);
> -	redzone_end = round_up((unsigned long)object + cache->object_size,
> -				KASAN_GRANULE_SIZE);
> -	tag = assign_tag(cache, object, false, kmalloc);
> -
> -	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
> -	kasan_unpoison(set_tag(object, tag), size);
> +	redzone_end = (unsigned long)object + cache->object_size;
>  	kasan_poison((void *)redzone_start, redzone_end - redzone_start,
>  			   KASAN_KMALLOC_REDZONE);
>  
> +	/*
> +	 * Save alloc info (if possible) for kmalloc() allocations.
> +	 * This also rewrites the alloc info when called from kasan_krealloc().
> +	 */
>  	if (kasan_stack_collection_enabled())
> -		set_alloc_info(cache, (void *)object, flags, kmalloc);
> +		set_alloc_info(cache, (void *)object, flags, true);
>  
> -	return set_tag(object, tag);
> -}
> -
> -void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
> -					void *object, gfp_t flags)
> -{
> -	return ____kasan_kmalloc(cache, object, cache->object_size, flags, false);
> +	/* Keep the tag that was set by kasan_slab_alloc(). */
> +	return (void *)object;
>  }
>  
>  void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  					size_t size, gfp_t flags)
>  {
> -	return ____kasan_kmalloc(cache, object, size, flags, true);
> +	return ____kasan_kmalloc(cache, object, size, flags);
>  }
>  EXPORT_SYMBOL(__kasan_kmalloc);
>  
> @@ -496,8 +528,7 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
>  	if (unlikely(!PageSlab(page)))
>  		return __kasan_kmalloc_large(object, size, flags);
>  	else
> -		return ____kasan_kmalloc(page->slab_cache, object, size,
> -						flags, true);
> +		return ____kasan_kmalloc(page->slab_cache, object, size, flags);
>  }
>  
>  void __kasan_kfree_large(void *ptr, unsigned long ip)
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index dd14e8870023..6a2882997f23 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -358,12 +358,51 @@ static inline bool kasan_byte_accessible(const void *addr)
>  
>  #else /* CONFIG_KASAN_HW_TAGS */
>  
> -void kasan_poison(const void *address, size_t size, u8 value);
> -void kasan_unpoison(const void *address, size_t size);
> +/**
> + * kasan_poison - mark the memory range as unaccessible
> + * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
> + * @size - range size
> + * @value - value that's written to metadata for the range
> + *
> + * The size gets aligned to KASAN_GRANULE_SIZE before marking the range.
> + */
> +void kasan_poison(const void *addr, size_t size, u8 value);
> +
> +/**
> + * kasan_unpoison - mark the memory range as accessible
> + * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
> + * @size - range size
> + *
> + * For the tag-based modes, the @size gets aligned to KASAN_GRANULE_SIZE before
> + * marking the range.
> + * For the generic mode, the last granule of the memory range gets partially
> + * unpoisoned based on the @size.
> + */
> +void kasan_unpoison(const void *addr, size_t size);
> +
>  bool kasan_byte_accessible(const void *addr);
>  
>  #endif /* CONFIG_KASAN_HW_TAGS */
>  
> +#ifdef CONFIG_KASAN_GENERIC
> +
> +/**
> + * kasan_poison_last_granule - mark the last granule of the memory range as
> + * unaccessible
> + * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
> + * @size - range size
> + *
> + * This function is only available for the generic mode, as it's the only mode
> + * that has partially poisoned memory granules.
> + */
> +void kasan_poison_last_granule(const void *address, size_t size);
> +
> +#else /* CONFIG_KASAN_GENERIC */
> +
> +static inline void kasan_poison_last_granule(const void *address, size_t size) { }
> +
> +#endif /* CONFIG_KASAN_GENERIC */
> +
>  /*
>   * Exported functions for interfaces called from assembly or from generated
>   * code. Declarations here to avoid warning about missing declarations.
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 1372a2fc0ca9..1ed7817e4ee6 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -69,10 +69,6 @@ void *memcpy(void *dest, const void *src, size_t len)
>  	return __memcpy(dest, src, len);
>  }
>  
> -/*
> - * Poisons the shadow memory for 'size' bytes starting from 'addr'.
> - * Memory addresses should be aligned to KASAN_GRANULE_SIZE.
> - */
>  void kasan_poison(const void *address, size_t size, u8 value)
>  {
>  	void *shadow_start, *shadow_end;
> @@ -83,12 +79,12 @@ void kasan_poison(const void *address, size_t size, u8 value)
>  	 * addresses to this function.
>  	 */
>  	address = kasan_reset_tag(address);
> -	size = round_up(size, KASAN_GRANULE_SIZE);
>  
>  	/* Skip KFENCE memory if called explicitly outside of sl*b. */
>  	if (is_kfence_address(address))
>  		return;
>  
> +	size = round_up(size, KASAN_GRANULE_SIZE);
>  	shadow_start = kasan_mem_to_shadow(address);
>  	shadow_end = kasan_mem_to_shadow(address + size);
>  
> @@ -96,6 +92,16 @@ void kasan_poison(const void *address, size_t size, u8 value)
>  }
>  EXPORT_SYMBOL(kasan_poison);
>  
> +#ifdef CONFIG_KASAN_GENERIC
> +void kasan_poison_last_granule(const void *address, size_t size)
> +{
> +	if (size & KASAN_GRANULE_MASK) {
> +		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
> +		*shadow = size & KASAN_GRANULE_MASK;
> +	}
> +}
> +#endif

The function declaration still needs to exist in the dead branch if
!IS_ENABLED(CONFIG_KASAN_GENERIC). It appears in that case it's declared
(in kasan.h), but not defined.  We shouldn't get linker errors because
the optimizer should remove the dead branch. Nevertheless, is this code
generally acceptable?

>  void kasan_unpoison(const void *address, size_t size)
>  {
>  	u8 tag = get_tag(address);
> @@ -115,16 +121,12 @@ void kasan_unpoison(const void *address, size_t size)
>  	if (is_kfence_address(address))
>  		return;
>  
> +	/* Unpoison round_up(size, KASAN_GRANULE_SIZE) bytes. */
>  	kasan_poison(address, size, tag);
>  
> -	if (size & KASAN_GRANULE_MASK) {
> -		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
> -
> -		if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> -			*shadow = tag;
> -		else /* CONFIG_KASAN_GENERIC */
> -			*shadow = size & KASAN_GRANULE_MASK;
> -	}
> +	/* Partially poison the last granule for the generic mode. */
> +	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +		kasan_poison_last_granule(address, size);
>  }
>  
>  #ifdef CONFIG_MEMORY_HOTPLUG
> diff --git a/mm/slub.c b/mm/slub.c
> index 176b1cb0d006..e564008c2329 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3565,8 +3565,7 @@ static void early_kmem_cache_node_alloc(int node)
>  	init_object(kmem_cache_node, n, SLUB_RED_ACTIVE);
>  	init_tracking(kmem_cache_node, n);
>  #endif
> -	n = kasan_kmalloc(kmem_cache_node, n, sizeof(struct kmem_cache_node),
> -		      GFP_KERNEL);
> +	n = kasan_slab_alloc(kmem_cache_node, n, GFP_KERNEL);
>  	page->freelist = get_freepointer(kmem_cache_node, n);
>  	page->inuse = 1;
>  	page->frozen = 0;
> -- 
> 2.30.0.365.g02bc693789-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YBl9C%2Bq84BqiFd4F%40elver.google.com.
