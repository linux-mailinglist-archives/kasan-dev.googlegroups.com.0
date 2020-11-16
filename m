Return-Path: <kasan-dev+bncBC7OBJGL2MHBB455ZL6QKGQERWLMKMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1383D2B49C2
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 16:47:00 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id z62sf91909wmb.1
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 07:47:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605541619; cv=pass;
        d=google.com; s=arc-20160816;
        b=BxDw0GUtUhNSETbh43wybe9eXKcl5CwX1+SSOGIXSkqzQsdUJn+eZPf6Q4uzo1V7Fd
         CIgP0EOVkX+nfk/G1/V6KkbeKbn2vO6NdPF9m+MwgfMnsafTotPIbcQ7fpxwXqUTyClz
         xUL+6mGyzTVE5Z0apCLf3fghWOvjykJuzpU9/41P10gChE6UaKhOCt4Zloq5ZLN2KwxY
         20lc9eVqYm1zfhuelkR9yB0X6INRqMT2b+RGQ+aq23oTBM/OjGH+zpTEvb8DfiEg3e7R
         HOaqzfsSHOhW593x+2jMV9H0BXzzFKWbjmY9G81283CbGYSyDZvQAfBbejnt/n2NCxJB
         qImg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=yYyQActUHN0JTq3q731DQULEGr6b266EWMfC660wIro=;
        b=mcFL9JTXjyxhhwHwa0BCmgN3Xw8fA/y4YqQtGYN+hwWprvt/2XkMWj7KbHfyz0rblJ
         orFWIrjzsYMy7AxWKujekASL/92kiPsxx5tcgPysqV29EueC7xtQzEnB63WVHTIkGqg6
         84Pq0L+8E2TAmK8+qFztmlJ5n96AA0CvcmSxdWmLT+p9fP7S8Pnra9CPPUSoy8F+XnEw
         IKgEXEdnPE4/on1UAbG3aS9B1qjosTcKqiJhXO7wIgW5E1A59oFP5ulx2tdMVQIkJghv
         6iKKPZqds3w76/0Uvj+SFm+NVXvC0uqcdUqmAwt3v6ZbghB1fj0v6eWXzXhWPv1QJzee
         YoFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lMReklXV;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=yYyQActUHN0JTq3q731DQULEGr6b266EWMfC660wIro=;
        b=oW8t7CCfJWrxHOTffRTg8Fd5My+Zj+l69iea3bceyBcFnQfdo1cpfroHwNXp4EAE/d
         AVa9+nxWiu/KiIowcZLPvbxKYpL9Tvi/t7EeCyKfXIbZVeqI2Y6L+fu4mTVvFZDSWWl8
         vOdQwFSamSH2Bvxj6GhdawstJRrjznv1OJ/0MgsKmBMyxTh79NmIduA3dRK08cjbsljW
         Q9FrzpNYEyDOESmt+Ln6VtZfJg2398Db9ma08otnlUyDg4X0xz/CCbBXKlKapxl3F5QU
         7RQhUFZzSPDGNDsCvtb7wzJ16ffr0cFOd3AkORUM/KWkeVzpBye2v/45rFev033vJV8s
         l95w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yYyQActUHN0JTq3q731DQULEGr6b266EWMfC660wIro=;
        b=HT26Dyie3rFNpMNxvgYGFPq8Il3ddgR9gfPXzDTR+F0eTgKBB+mlgi0BUyI16SCj+q
         LeDzNVEHFffOFf7i10O/YzgRK+nOTh5yHYbj9pdAcM8kcaxpoVQGCMvbENDcTJxHTt2A
         Nh8UyJMXWsesGg5BXKu/By3leDnoo8C7APbUXvPUYJIOTj5dbitjaElvrUZ0qiajgqjk
         taKEMQSM53Q8551UT7N6pkgFfNa0R6wGAomdmjBuzS5NASmaIDNPvV28LWA5UIXzzIb8
         J23yIibrQ4W0p70t2sQFVMBEb+3K8KXMues3RjWt5BL0d230TYvKJ0AZbn2sbHzHOddE
         hZ7g==
X-Gm-Message-State: AOAM531Fhkzh88aNJOxLUJVI4XrAPWBcqd4XMSsj5EbzNJQuqHuC7LSP
	7UExx8SvOBTiATDRn2gxbLI=
X-Google-Smtp-Source: ABdhPJwrI0sz0OVCCDpXBh7F2AgBak6KZKnxVhOMm69oVP+Eu5bcp0Vt/pfegzbdq2xDr0xh4Wbjbw==
X-Received: by 2002:adf:fcc8:: with SMTP id f8mr20071113wrs.331.1605541619785;
        Mon, 16 Nov 2020 07:46:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:408a:: with SMTP id n132ls6939918wma.2.gmail; Mon, 16
 Nov 2020 07:46:58 -0800 (PST)
X-Received: by 2002:a1c:6856:: with SMTP id d83mr16944331wmc.13.1605541618721;
        Mon, 16 Nov 2020 07:46:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605541618; cv=none;
        d=google.com; s=arc-20160816;
        b=ozAqxeFJ72azjpqHBsgD3UH9Sz+T/dIzKCPAiALauo3A6iGgF5UJoQvaSd9MgY8XwU
         nZ9xSGJBKNDNkYE2J88zPncsbfBLwjwYCXo/U98ZKl8xm37Gx0KMLIgdsx517PPxJzG/
         CtYcA0fkXkwLpz+nDYXKolhQETRPa7ABNw2F97Q7A/dSJRtEiCvEAx/LkNKxZzC7tIXA
         Xw0V9cDKpbvEz4m1/JePr5qVq8wtqSTNUWVBpeI0RRx5JOX5VTBAi3DwGALGQQo3LgKv
         A8q7hj2z6bFgPkjGlAA7Tci2ZiQ3zAe/CeTXJ92zSRS8Fo2HzeRG5LgxOqDOQALflgJb
         SpSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/OsHfaSykaQK8sU96jr6RMPoOFbKqEh4RCw0JmHBK7w=;
        b=F7YcF4se3ky8WP5tsc549jwwmUbdZeTOjCLm3nG+AP7ZWl7439Cf7IoBbUl1xUn7Ow
         W9f20zp3nr0s6XvO3MTgye2htEIRIs29gTNeRZ/Ap+rTXTnExS8N694Lz7V7lhCzckid
         nb2/G/+YIy3Wcrz+Vp1Q4L1024BbkkFdvrGZiyESzA46yHfPJML2eNfsU3p1yC2yUNxt
         EwFhjas1dXm5DJnUe45HaqGufrBG92m2Tgqs5/scOd3n5a1haCsvjPNhUYssuCheUYXu
         z7Rwzp3aqqCWNYnt/d3/TNaJv/tiYRl73sQu1kV8069PKNo693gfMj/3MmLBbib97jU+
         BpGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lMReklXV;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id z83si14214wmc.3.2020.11.16.07.46.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Nov 2020 07:46:58 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id h2so24181392wmm.0
        for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 07:46:58 -0800 (PST)
X-Received: by 2002:a1c:2c2:: with SMTP id 185mr16356838wmc.103.1605541618037;
        Mon, 16 Nov 2020 07:46:58 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id m18sm21776138wru.37.2020.11.16.07.46.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 16 Nov 2020 07:46:56 -0800 (PST)
Date: Mon, 16 Nov 2020 16:46:51 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH mm v3 17/19] kasan: clean up metadata allocation and usage
Message-ID: <20201116154651.GH1357314@elver.google.com>
References: <cover.1605305978.git.andreyknvl@google.com>
 <52518837b34d607abbf30855b3ac4cb1a9486946.1605305978.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <52518837b34d607abbf30855b3ac4cb1a9486946.1605305978.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lMReklXV;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as
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

On Fri, Nov 13, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
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
> Co-developed-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
> Signed-off-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Icd947e2bea054cb5cfbdc6cf6652227d97032dcb

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/common.c         | 112 +++++++++++++++++++++++++-------------
>  mm/kasan/generic.c        |  15 ++---
>  mm/kasan/hw_tags.c        |   6 +-
>  mm/kasan/kasan.h          |  13 ++++-
>  mm/kasan/quarantine.c     |   8 +++
>  mm/kasan/report.c         |  43 ++++++++-------
>  mm/kasan/report_sw_tags.c |   9 ++-
>  mm/kasan/sw_tags.c        |   4 ++
>  8 files changed, 139 insertions(+), 71 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 42ba64fce8a3..cf874243efab 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -115,9 +115,6 @@ void __kasan_free_pages(struct page *page, unsigned int order)
>   */
>  static inline unsigned int optimal_redzone(unsigned int object_size)
>  {
> -	if (!IS_ENABLED(CONFIG_KASAN_GENERIC))
> -		return 0;
> -
>  	return
>  		object_size <= 64        - 16   ? 16 :
>  		object_size <= 128       - 32   ? 32 :
> @@ -131,47 +128,77 @@ static inline unsigned int optimal_redzone(unsigned int object_size)
>  void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>  			  slab_flags_t *flags)
>  {
> -	unsigned int orig_size = *size;
> -	unsigned int redzone_size;
> -	int redzone_adjust;
> +	unsigned int ok_size;
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
> +	 */
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
> +	 * 1. Object is SLAB_TYPESAFE_BY_RCU, which means that it can
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
> +	if ((cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor ||
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
> +	/* Calculate size with optimal redzone. */
> +	optimal_size = cache->object_size + optimal_redzone(cache->object_size);
> +	/* Limit it with KMALLOC_MAX_SIZE (relevant for SLAB only). */
> +	if (optimal_size > KMALLOC_MAX_SIZE)
> +		optimal_size = KMALLOC_MAX_SIZE;
> +	/* Use optimal size if the size with added metas is not large enough. */
> +	if (*size < optimal_size)
> +		*size = optimal_size;
>  }
>  
>  size_t __kasan_metadata_size(struct kmem_cache *cache)
> @@ -187,15 +214,21 @@ size_t __kasan_metadata_size(struct kmem_cache *cache)
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
>  void __kasan_poison_slab(struct page *page)
>  {
> @@ -272,11 +305,9 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
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
> @@ -318,8 +349,7 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>  	if (!kasan_stack_collection_enabled())
>  		return false;
>  
> -	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
> -			unlikely(!(cache->flags & SLAB_KASAN)))
> +	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine))
>  		return false;
>  
>  	kasan_set_free_info(cache, object, tag);
> @@ -359,7 +389,11 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
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
> @@ -389,7 +423,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  	poison_range((void *)redzone_start, redzone_end - redzone_start,
>  		     KASAN_KMALLOC_REDZONE);
>  
> -	if (kasan_stack_collection_enabled() && (cache->flags & SLAB_KASAN))
> +	if (kasan_stack_collection_enabled())
>  		set_alloc_info(cache, (void *)object, flags);
>  
>  	return set_tag(object, tag);
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 9c6b77f8c4a4..157df6c762a4 100644
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
> index 30ce88935e9d..c91f2c06ecb5 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -187,7 +187,8 @@ void kasan_set_free_info(struct kmem_cache *cache,
>  	struct kasan_alloc_meta *alloc_meta;
>  
>  	alloc_meta = kasan_get_alloc_meta(cache, object);
> -	kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
> +	if (alloc_meta)
> +		kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
>  }
>  
>  struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> @@ -196,5 +197,8 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>  	struct kasan_alloc_meta *alloc_meta;
>  
>  	alloc_meta = kasan_get_alloc_meta(cache, object);
> +	if (!alloc_meta)
> +		return NULL;
> +
>  	return &alloc_meta->free_track[0];
>  }
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index d01a5ac34f70..88a6e5bee156 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -156,20 +156,31 @@ struct kasan_alloc_meta {
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
> +#define KASAN_NO_FREE_META INT_MAX
> +
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
> index ffa6076b1710..8b6656d47983 100644
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
> index 7604b46239d4..1b026793ad57 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -48,9 +48,12 @@ const char *get_bug_type(struct kasan_access_info *info)
>  		object = nearest_obj(cache, page, (void *)addr);
>  		alloc_meta = kasan_get_alloc_meta(cache, object);
>  
> -		for (i = 0; i < KASAN_NR_FREE_STACKS; i++)
> -			if (alloc_meta->free_pointer_tag[i] == tag)
> -				return "use-after-free";
> +		if (alloc_meta) {
> +			for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> +				if (alloc_meta->free_pointer_tag[i] == tag)
> +					return "use-after-free";
> +			}
> +		}
>  		return "out-of-bounds";
>  	}
>  
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index e17de2619bbf..5dcd830805b2 100644
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
> -- 
> 2.29.2.299.gdc1121823c-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201116154651.GH1357314%40elver.google.com.
