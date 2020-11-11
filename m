Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYW4WH6QKGQEVT34O4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 001D42AFB9A
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 00:06:10 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id z62sf2972339wmb.1
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 15:06:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605135970; cv=pass;
        d=google.com; s=arc-20160816;
        b=C/wRaPAamq970ss6jqyExeVn+yQ9sO1QgLkqnLDaj99vWYIE1F0O0Mh3pyAPY7pGOS
         sLe3DAERHvXf/mTppsz7ezzLn63zRga1sU84qEv3pkWQN/A/w6BmoKkGBUd0IIsWj142
         Sy90FXxXIxThN99phzD1Y+GEdBQcldImA3BkHozO4xm6ZWUv1KmcQy3annZw+EpL7Krv
         iXOsOsumjyyR0UxSOSKPiQddb5vZSLaVk5TOOi2QALNHsPlGArlSs0/B6P9j0TEIgA35
         VAc8QKGiX+awwsDw0DRXpZ92B/bBoS5BVB0VetmOVyUTxDFsChuwztGekPWHpT5zTJPi
         NeFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=wpUjFANfFiqBfe2qhqDiVSSo/O10WCUY5nyY17Mcc40=;
        b=md/qS0d0NZzuhOFRFlWpnozrvm3pUVo4RbYud8r9cmw0FmG60xgRpF/tqKjaLTx+UE
         heYUlpuPTLbPU1Jf9WcsJNzVArg3iAjtzQa5XmUjFxON21NEUkH+1TrghLUvwVQD7Cgo
         1G0WvFzqy41euBJFkXnliu3fCorx90bqL2EDvn1jsanlnK8+y2xqIu1Iyrj4RGEgNJtW
         E+p96ndMGRpVattfFcNTtJ5gAuEt31Yzar8PdjTK/uxBcigK/bgx4xe/Y6eFc2mnxK2q
         homrUvnCcBDZtfyCRmN6CBRbxY+QFeEjc5chx7F0PPN5z1HEg8UsbZW6FKIMoa2F6oUX
         rwvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eSryZ+Ks;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=wpUjFANfFiqBfe2qhqDiVSSo/O10WCUY5nyY17Mcc40=;
        b=W3SqBqZbppjMDUsTAM1wwNkkWZfW8K9t6ZFDJ+9t2RKuHw16nJRb8w9DRx6po9T4Q9
         /bkFJJqlOU3OUQUcmTVXcIwyYjFjaoM3uD+guiBrIobBXSqYV+kf8zRbsmoegU/SlPW2
         UZl09JQujI4lGEXcWX2ju6e1EHm50p9gXvixp0OXvlEqP3nf/TZVuhZh5FXKZN1LxIoJ
         V9CMfRiIFi8GA06L29zPXbj7Hx4h4DMUCRoEFkdzgCkEabbPCkAPx5kZSr0yXrZpleUQ
         20WRfuLDZwTh+WmNZMrHufy5aRBWPubWx6j9O6N4v4m2MhHP3D4uYkYn+WnDsPSE3quF
         ewLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wpUjFANfFiqBfe2qhqDiVSSo/O10WCUY5nyY17Mcc40=;
        b=fJWCPxPzeo9I5TynHl+Tm8bESRt6NwlHGdUPoV1NgGE3C/Iq0Wr7nKv+i6hGWM+Wgj
         WQ3spEA7VuELo8VkadzfzsRbiFwkR9DfF9LVaOdi9ad28T5QWNrc6dtikfXjdziyiSfx
         O5BqxSGUfvOqvTe3Q0+Rawp96On9fI3Bg1JaU3K6n9TJ/VAZGXzZsL93waVCBYh261Le
         seriWsmOv7LzscYfKvvGm7CMrFdBZWfmPs0TmOW68FjRWIHzV917QMAWScex3TeoVxUg
         tQmUyPXuzul5gsGQ0+IP/PkLz11E3M8vXIYPrhkzJJBpMDBtX+J6D3mCIXrmMTNl307T
         rDqw==
X-Gm-Message-State: AOAM531Z8IqqXiSHHkWVumP9k39SRGTzyhgKU51nzgQEATgKnvDlMNOE
	xggTuopxm2kIn6Y12aio3+8=
X-Google-Smtp-Source: ABdhPJyP61LO6pHPxNYUSSb/WKivS/iOc6HmPZLbpyGCwSdidQTYLiMkHcHCnMfrG2EAuL2ID/eK+Q==
X-Received: by 2002:a1c:c343:: with SMTP id t64mr6747060wmf.140.1605135970608;
        Wed, 11 Nov 2020 15:06:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1bc1:: with SMTP id b184ls366210wmb.1.canary-gmail; Wed,
 11 Nov 2020 15:06:09 -0800 (PST)
X-Received: by 2002:a05:600c:2202:: with SMTP id z2mr6733794wml.95.1605135969455;
        Wed, 11 Nov 2020 15:06:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605135969; cv=none;
        d=google.com; s=arc-20160816;
        b=Qda/Z7c8qq10HxYhk/PcEyZP0+hdxL3FQuQhC2NaCULbwzN6gcweUjbClA1ZqUUGiF
         4Ph74U58DFyhXS3D+FayPmrwb2Whh3Ea/IiQtcVme3414Ea6IMLChArg55vYEYmBE6ho
         XeMHbxIPvObZ/+XjWgWzw4HW0r97wcMrJFuay4Lc3HXhwx72u87AQ9nTbEDLJx+Jocuo
         rQLkAIAt/ltMdE9WyzkS0KjnXlaNV1PbSEfxtsE3Cdu4AqflXMsZCx/OZHYIYSE4Kf3Z
         WC/d6Rdp6Euf4llV3Pkf9y5LG4SWD2zPhtnrP0gz+rVE7GlLnlFaFu3hdYwSHFXZpuqu
         hlQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=IkKZjwHBhJ2TR1aI7YhxuLu2gi4Jfo+WdTELlbP3HYQ=;
        b=IjXDPNG4J71zAv3Cmh5PJAWCj/eYpJRruxn/EBz9pbnNvH3y0qDWwGeNCeLPfDWi/v
         HZ9qaqUSiGtgEwdXE3y474p9m/2Dxx1kHixqA/zg1F2VtQfqHCrHV9DoLs5t82beEVT+
         biEJ60Yd8qJqsisMJJCdeut9uW/dhOjXzBj0dOvOUdkGGKftFHgWI2xnWaVAnIbHnv2v
         ZzjS6kN6c1Cp15uttm3liRsnrmehLEwHj1KykZw/h/ST/Zp+vO9TsAf0iQA51RLSyNUV
         I3Z+c2rn8M9LaeujDz/RRhIx0TeiTTHi+3iXLwk4L1EAlePyYgt7RGwRZ23Ac1fDB04X
         DPrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eSryZ+Ks;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id i1si126980wml.2.2020.11.11.15.06.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 15:06:09 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id p8so4122982wrx.5
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 15:06:09 -0800 (PST)
X-Received: by 2002:a5d:67c4:: with SMTP id n4mr31878771wrw.125.1605135968707;
        Wed, 11 Nov 2020 15:06:08 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id n23sm4262322wmk.24.2020.11.11.15.06.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 15:06:07 -0800 (PST)
Date: Thu, 12 Nov 2020 00:06:01 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 18/20] kasan: clean up metadata allocation and usage
Message-ID: <20201111230601.GA984367@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <fe30e8ab5535e14f86fbe7876e134a76374403bf.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fe30e8ab5535e14f86fbe7876e134a76374403bf.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eSryZ+Ks;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as
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

On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> KASAN marks caches that are sanitized with the SLAB_KASAN cache flag.
> Currently if the metadata that is appended after the object (stores e.g.
> stack trace ids) doesn't fit into KMALLOC_MAX_SIZE (can only happen with
> SLAB, see the comment in the patch), KASAN turns off sanitization
> completely.
> 
> With this change sanitization of the object data is always enabled.
> However the metadata is only stored when it fits. Instead of checking for
> SLAB_KASAN flag accross the code to find out whether the metadata is
> there, use cache->kasan_info.alloc/free_meta_offset. As 0 can be a valid
> value for free_meta_offset, introduce KASAN_NO_FREE_META as an indicator
> that the free metadata is missing.
> 
> Along the way rework __kasan_cache_create() and add claryfying comments.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Icd947e2bea054cb5cfbdc6cf6652227d97032dcb
> ---
>  mm/kasan/common.c         | 112 +++++++++++++++++++++++++-------------
>  mm/kasan/generic.c        |  15 ++---
>  mm/kasan/hw_tags.c        |   6 +-
>  mm/kasan/kasan.h          |  13 ++++-
>  mm/kasan/quarantine.c     |   8 +++
>  mm/kasan/report.c         |  43 ++++++++-------
>  mm/kasan/report_sw_tags.c |   7 ++-
>  mm/kasan/sw_tags.c        |   4 ++
>  8 files changed, 138 insertions(+), 70 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 4360292ad7f3..940b42231069 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -109,9 +109,6 @@ void __kasan_free_pages(struct page *page, unsigned int order)
>   */
>  static inline unsigned int optimal_redzone(unsigned int object_size)
>  {
> -	if (!IS_ENABLED(CONFIG_KASAN_GENERIC))
> -		return 0;
> -
>  	return
>  		object_size <= 64        - 16   ? 16 :
>  		object_size <= 128       - 32   ? 32 :
> @@ -125,47 +122,79 @@ static inline unsigned int optimal_redzone(unsigned int object_size)
>  void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>  			  slab_flags_t *flags)
>  {
> -	unsigned int orig_size = *size;
> +	unsigned int ok_size;
>  	unsigned int redzone_size;
> -	int redzone_adjust;
> +	unsigned int optimal_size;
> +
> +	/*
> +	 * SLAB_KASAN is used to mark caches as ones that are sanitized by
> +	 * KASAN. Currently this is used in two places:
> +	 * 1. In slab_ksize() when calculating the size of the accessible
> +	 *    memory within the object.
> +	 * 2. In slab_common.c to prevent merging of sanitized caches.
> +	 */
> +	*flags |= SLAB_KASAN;
>  
> -	if (!kasan_stack_collection_enabled()) {
> -		*flags |= SLAB_KASAN;
> +	if (!kasan_stack_collection_enabled())
>  		return;
> -	}
>  
> -	/* Add alloc meta. */
> +	ok_size = *size;
> +
> +	/* Add alloc meta into redzone. */
>  	cache->kasan_info.alloc_meta_offset = *size;
>  	*size += sizeof(struct kasan_alloc_meta);
>  
> -	/* Add free meta. */
> -	if (IS_ENABLED(CONFIG_KASAN_GENERIC) &&
> -	    (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
> -	     cache->object_size < sizeof(struct kasan_free_meta))) {
> -		cache->kasan_info.free_meta_offset = *size;
> -		*size += sizeof(struct kasan_free_meta);
> +	/*
> +	 * If alloc meta doesn't fit, don't add it.
> +	 * This can only happen with SLAB, as it has KMALLOC_MAX_SIZE equal
> +	 * to KMALLOC_MAX_CACHE_SIZE and doesn't fall back to page_alloc for
> +	 * larger sizes.
> +	*/
> +	if (*size > KMALLOC_MAX_SIZE) {
> +		cache->kasan_info.alloc_meta_offset = 0;
> +		*size = ok_size;
> +		/* Continue, since free meta might still fit. */
>  	}
>  
> -	redzone_size = optimal_redzone(cache->object_size);
> -	redzone_adjust = redzone_size -	(*size - cache->object_size);
> -	if (redzone_adjust > 0)
> -		*size += redzone_adjust;
> -
> -	*size = min_t(unsigned int, KMALLOC_MAX_SIZE,
> -			max(*size, cache->object_size + redzone_size));
> +	/* Only the generic mode uses free meta or flexible redzones. */
> +	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +		cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
> +		return;
> +	}
>  
>  	/*
> -	 * If the metadata doesn't fit, don't enable KASAN at all.
> +	 * Add free meta into redzone when it's not possible to store
> +	 * it in the object. This is the case when:
> +	 * 1. Object is SLAB_TYPESAFE_BY_RCU, which means that is can

s/that is can/that it can/

> +	 *    be touched after it was freed, or
> +	 * 2. Object has a constructor, which means it's expected to
> +	 *    retain its content until the next allocation, or
> +	 * 3. Object is too small.
> +	 * Otherwise cache->kasan_info.free_meta_offset = 0 is implied.
>  	 */
> -	if (*size <= cache->kasan_info.alloc_meta_offset ||
> -			*size <= cache->kasan_info.free_meta_offset) {
> -		cache->kasan_info.alloc_meta_offset = 0;
> -		cache->kasan_info.free_meta_offset = 0;
> -		*size = orig_size;
> -		return;
> +	if (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||

Braces around

	(cache->flags & SLAB_TYPESAFE_BY_RCU)

> +	    cache->object_size < sizeof(struct kasan_free_meta)) {
> +		ok_size = *size;
> +
> +		cache->kasan_info.free_meta_offset = *size;
> +		*size += sizeof(struct kasan_free_meta);
> +
> +		/* If free meta doesn't fit, don't add it. */
> +		if (*size > KMALLOC_MAX_SIZE) {
> +			cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
> +			*size = ok_size;
> +		}
>  	}
>  
> -	*flags |= SLAB_KASAN;
> +	redzone_size = optimal_redzone(cache->object_size);

redzone_size seems to used once, maybe just change the below to ...

> +	/* Calculate size with optimal redzone. */
> +	optimal_size = cache->object_size + redzone_size;

+	optimal_size = cache->object_size + optimal_redzone(cache->object_size);

?

> +	/* Limit it with KMALLOC_MAX_SIZE (relevant for SLAB only). */
> +	if (optimal_size > KMALLOC_MAX_SIZE)
> +		optimal_size = KMALLOC_MAX_SIZE;
> +	/* Use optimal size if the size with added metas is not large enough. */

Uses the optimal size if it's not "too large" rather than "not large
enough", right? As it is worded now makes me think this is a fallback,
whereas ideally it's the common case, right?

> +	if (*size < optimal_size)
> +		*size = optimal_size;
>  }
>  
>  size_t __kasan_metadata_size(struct kmem_cache *cache)
> @@ -181,15 +210,21 @@ size_t __kasan_metadata_size(struct kmem_cache *cache)
>  struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
>  					      const void *object)
>  {
> +	if (!cache->kasan_info.alloc_meta_offset)
> +		return NULL;
>  	return kasan_reset_tag(object) + cache->kasan_info.alloc_meta_offset;
>  }
>  
> +#ifdef CONFIG_KASAN_GENERIC
>  struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
>  					    const void *object)
>  {
>  	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
> +	if (cache->kasan_info.free_meta_offset == KASAN_NO_FREE_META)
> +		return NULL;
>  	return kasan_reset_tag(object) + cache->kasan_info.free_meta_offset;
>  }
> +#endif
>  
>  void __kasan_unpoison_data(const void *addr, size_t size)
>  {
> @@ -276,11 +311,9 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
>  	struct kasan_alloc_meta *alloc_meta;
>  
>  	if (kasan_stack_collection_enabled()) {
> -		if (!(cache->flags & SLAB_KASAN))
> -			return (void *)object;
> -
>  		alloc_meta = kasan_get_alloc_meta(cache, object);
> -		__memset(alloc_meta, 0, sizeof(*alloc_meta));
> +		if (alloc_meta)
> +			__memset(alloc_meta, 0, sizeof(*alloc_meta));
>  	}
>  
>  	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
> @@ -319,8 +352,7 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>  	if (!kasan_stack_collection_enabled())
>  		return false;
>  
> -	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
> -			unlikely(!(cache->flags & SLAB_KASAN)))
> +	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine))
>  		return false;
>  
>  	kasan_set_free_info(cache, object, tag);
> @@ -345,7 +377,11 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
>  
>  static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
>  {
> -	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
> +	struct kasan_alloc_meta *alloc_meta;
> +
> +	alloc_meta = kasan_get_alloc_meta(cache, object);
> +	if (alloc_meta)
> +		kasan_set_track(&alloc_meta->alloc_track, flags);
>  }
>  
>  static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
> @@ -372,7 +408,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
>  		KASAN_KMALLOC_REDZONE);
>  
> -	if (kasan_stack_collection_enabled() && (cache->flags & SLAB_KASAN))
> +	if (kasan_stack_collection_enabled())
>  		set_alloc_info(cache, (void *)object, flags);
>  
>  	return set_tag(object, tag);
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index d259e4c3aefd..97e39516f8fe 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -338,10 +338,10 @@ void kasan_record_aux_stack(void *addr)
>  	cache = page->slab_cache;
>  	object = nearest_obj(cache, page, addr);
>  	alloc_meta = kasan_get_alloc_meta(cache, object);
> +	if (!alloc_meta)
> +		return;
>  
> -	/*
> -	 * record the last two call_rcu() call stacks.
> -	 */
> +	/* Record the last two call_rcu() call stacks. */
>  	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
>  	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
>  }
> @@ -352,11 +352,11 @@ void kasan_set_free_info(struct kmem_cache *cache,
>  	struct kasan_free_meta *free_meta;
>  
>  	free_meta = kasan_get_free_meta(cache, object);
> -	kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
> +	if (!free_meta)
> +		return;
>  
> -	/*
> -	 *  the object was freed and has free track set
> -	 */
> +	kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
> +	/* The object was freed and has free track set. */
>  	*(u8 *)kasan_mem_to_shadow(object) = KASAN_KMALLOC_FREETRACK;
>  }
>  
> @@ -365,5 +365,6 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>  {
>  	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_KMALLOC_FREETRACK)
>  		return NULL;
> +	/* Free meta must be present with KASAN_KMALLOC_FREETRACK. */
>  	return &kasan_get_free_meta(cache, object)->free_track;
>  }
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 2f6f0261af8c..c3d2a21d925d 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -188,7 +188,8 @@ void kasan_set_free_info(struct kmem_cache *cache,
>  	struct kasan_alloc_meta *alloc_meta;
>  
>  	alloc_meta = kasan_get_alloc_meta(cache, object);
> -	kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
> +	if (alloc_meta)
> +		kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
>  }
>  
>  struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> @@ -197,5 +198,8 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>  	struct kasan_alloc_meta *alloc_meta;
>  
>  	alloc_meta = kasan_get_alloc_meta(cache, object);
> +	if (!alloc_meta)
> +		return NULL;
> +
>  	return &alloc_meta->free_track[0];
>  }
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 5eff3d9f624e..88892c05eb7d 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -154,20 +154,31 @@ struct kasan_alloc_meta {
>  struct qlist_node {
>  	struct qlist_node *next;
>  };
> +
> +/*
> + * Generic mode either stores free meta in the object itself or in the redzone
> + * after the object. In the former case free meta offset is 0, in the latter
> + * case it has some sane value smaller than INT_MAX. Use INT_MAX as free meta
> + * offset when free meta isn't present.
> + */
> +#define KASAN_NO_FREE_META (INT_MAX)

Braces not needed.

>  struct kasan_free_meta {
> +#ifdef CONFIG_KASAN_GENERIC
>  	/* This field is used while the object is in the quarantine.
>  	 * Otherwise it might be used for the allocator freelist.
>  	 */
>  	struct qlist_node quarantine_link;
> -#ifdef CONFIG_KASAN_GENERIC
>  	struct kasan_track free_track;
>  #endif
>  };
>  
>  struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
>  						const void *object);
> +#ifdef CONFIG_KASAN_GENERIC
>  struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
>  						const void *object);
> +#endif
>  
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 0da3d37e1589..23f6bfb1e73f 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -135,7 +135,12 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
>  	if (IS_ENABLED(CONFIG_SLAB))
>  		local_irq_save(flags);
>  
> +	/*
> +	 * As the object now gets freed from the quaratine, assume that its
> +	 * free track is now longer valid.
> +	 */
>  	*(u8 *)kasan_mem_to_shadow(object) = KASAN_KMALLOC_FREE;
> +
>  	___cache_free(cache, object, _THIS_IP_);
>  
>  	if (IS_ENABLED(CONFIG_SLAB))
> @@ -168,6 +173,9 @@ void quarantine_put(struct kmem_cache *cache, void *object)
>  	struct qlist_head temp = QLIST_INIT;
>  	struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
>  
> +	if (!meta)
> +		return;
> +
>  	/*
>  	 * Note: irq must be disabled until after we move the batch to the
>  	 * global quarantine. Otherwise quarantine_remove_cache() can miss
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 7d86af340148..6a95ad2dee91 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -168,32 +168,35 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
>  static void describe_object_stacks(struct kmem_cache *cache, void *object,
>  					const void *addr, u8 tag)
>  {
> -	struct kasan_alloc_meta *alloc_meta = kasan_get_alloc_meta(cache, object);
> -
> -	if (cache->flags & SLAB_KASAN) {
> -		struct kasan_track *free_track;
> +	struct kasan_alloc_meta *alloc_meta;
> +	struct kasan_track *free_track;
>  
> +	alloc_meta = kasan_get_alloc_meta(cache, object);
> +	if (alloc_meta) {
>  		print_track(&alloc_meta->alloc_track, "Allocated");
>  		pr_err("\n");
> -		free_track = kasan_get_free_track(cache, object, tag);
> -		if (free_track) {
> -			print_track(free_track, "Freed");
> -			pr_err("\n");
> -		}
> +	}
> +
> +	free_track = kasan_get_free_track(cache, object, tag);
> +	if (free_track) {
> +		print_track(free_track, "Freed");
> +		pr_err("\n");
> +	}
>  
>  #ifdef CONFIG_KASAN_GENERIC
> -		if (alloc_meta->aux_stack[0]) {
> -			pr_err("Last call_rcu():\n");
> -			print_stack(alloc_meta->aux_stack[0]);
> -			pr_err("\n");
> -		}
> -		if (alloc_meta->aux_stack[1]) {
> -			pr_err("Second to last call_rcu():\n");
> -			print_stack(alloc_meta->aux_stack[1]);
> -			pr_err("\n");
> -		}
> -#endif
> +	if (!alloc_meta)
> +		return;
> +	if (alloc_meta->aux_stack[0]) {
> +		pr_err("Last call_rcu():\n");
> +		print_stack(alloc_meta->aux_stack[0]);
> +		pr_err("\n");
>  	}
> +	if (alloc_meta->aux_stack[1]) {
> +		pr_err("Second to last call_rcu():\n");
> +		print_stack(alloc_meta->aux_stack[1]);
> +		pr_err("\n");
> +	}
> +#endif
>  }
>  
>  static void describe_object(struct kmem_cache *cache, void *object,
> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> index 7604b46239d4..11dc8739e500 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -48,9 +48,10 @@ const char *get_bug_type(struct kasan_access_info *info)
>  		object = nearest_obj(cache, page, (void *)addr);
>  		alloc_meta = kasan_get_alloc_meta(cache, object);
>  
> -		for (i = 0; i < KASAN_NR_FREE_STACKS; i++)
> -			if (alloc_meta->free_pointer_tag[i] == tag)
> -				return "use-after-free";
> +		if (alloc_meta)

add {}

> +			for (i = 0; i < KASAN_NR_FREE_STACKS; i++)

add {}

> +				if (alloc_meta->free_pointer_tag[i] == tag)
> +					return "use-after-free";

while the 2 pairs of {} aren't necessary, it definitely helps
readability in this case, as we have a multi-line then and for blocks.

>  		return "out-of-bounds";
>  	}
>  
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index d1af6f6c6d12..be10d16bd129 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -170,6 +170,8 @@ void kasan_set_free_info(struct kmem_cache *cache,
>  	u8 idx = 0;
>  
>  	alloc_meta = kasan_get_alloc_meta(cache, object);
> +	if (!alloc_meta)
> +		return;
>  
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>  	idx = alloc_meta->free_track_idx;
> @@ -187,6 +189,8 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>  	int i = 0;
>  
>  	alloc_meta = kasan_get_alloc_meta(cache, object);
> +	if (!alloc_meta)
> +		return NULL;
>  
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>  	for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111230601.GA984367%40elver.google.com.
