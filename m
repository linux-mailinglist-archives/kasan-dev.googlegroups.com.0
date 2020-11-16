Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFF4ZL6QKGQENXZY25A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 491F12B49A6
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 16:43:17 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id a23sf4232474lji.9
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 07:43:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605541396; cv=pass;
        d=google.com; s=arc-20160816;
        b=ldOhcTg6BkcEqT4WMZ+MYe91LnXDZkleQN4kH07CTvZZTfQrKvv99HiZGDWQ4gXLXs
         E+aMiNzUk32LVNlrKhPlVwfoChHarcsqIRMsGzoY0cF8m8l5JXGK8aWt6EHP+AKL0Bfa
         pP/nrkh/7a+PsRw9kBehohOa748cWs7y9zOHsH6bu1Ik/LPeRf0vuLj1vRB/b/4aj4DQ
         87WryjCdBlTC2yyNURYl+z6M0dcDv/YdefGWRVjjwPpYwHwOss5q6mbHch9wakdtbPtf
         fS9Aiprsxs/59GMNrfkgGsruUkVQr4HUNRvGpn92JPphKiLe7rFAC3MJs8ZFEKzBQIoN
         sWzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=z3wz509MBtL0n7t/5a2xUVuTm6Ewysudc3gFujbzK+Q=;
        b=UcKgr8Rro4tm9RDPAdHOzlDvETCBDVBVSqh7E2eqRmYY1TZC7VlUA21HQAIQ57frlv
         vyrPO0BUnWyPsrVv95SkTXXJGh/ts/vp4U1ARSqDIh0YSs6whK+xg/Y8uTMyR4F6ydal
         uxTpJkrtDk3pHaCJYyMxo2JG8v0DpniLJyogQv+dlpRW+k9IlWAEvQGxy8yQPI14k60A
         fxNf/L6B4ROi0RObVUguD7ye48qe8EIqqJrJm1H9SQrLkhwnd5fuswdYsOQvLaCdC4ob
         aaai6UyIw3TYJO3FF+dri2l+lurgCLjzX12/L05NV+yovN9T+Q5axdBp9TqByiploty9
         Qsrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jdRX0Sra;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=z3wz509MBtL0n7t/5a2xUVuTm6Ewysudc3gFujbzK+Q=;
        b=HDAWYTzr0LXVfgANjK34pAgoU7Z+nlQVXBc3vUyY7ga1qEtXyU1jWebInEZjQmheBJ
         OL+NT9jP+qdi/JOqQ1wp5OC9kADw7dpWJou2mwssVWxW7hVB6u20eEh/0ZcIS4BGsHMj
         bIlg/rZYpRPsR79oidK0i8mvtEwAEOb5XjX8eWikKqppv/9AQaX29SgGzOmswGTd/qyP
         gSaGQZfKcVYCqgexhXlAn6xnA2l+zM9i4y0TF3lER/3HVIdnb+WmliytTrgU2WHPfvNs
         jN6dwQYJWopwE/CWlG9rFRI3gO7U5qV86/PCiB6bC1KdUN/SPFxcVXNzkGBzmqI+giHE
         odYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=z3wz509MBtL0n7t/5a2xUVuTm6Ewysudc3gFujbzK+Q=;
        b=sDy2ztqfF04AqM2g4tIcDHdF2/O20SByRle3ypY8a6Vu7yISQfarpHstnOLymbyubL
         9en/IdJKx2IeupK99h2MnpUUto9sRcDb9HYlS62R0nW5O13vG4qehZb1VRGzSrtXK+Iz
         f31qYYX/SljuRZk/WRV3sPufCNzPQHIWIG3uEmYgGHiL4CRA0ms0u1J7vMYuaiCMwSAe
         OzwEG7MjMc6PGzQq45SgJ4MzwOgWDxRbW8ETmanSHfLPfpsP5QS6TZdOngr+UjBwEEXW
         AFQtBL448oQWzPmPO4I9RV25xYMuT4BWNDbY8imlUl7drdlICCRgXWkkv1utCXaKu3n3
         kPNA==
X-Gm-Message-State: AOAM531ufoUea08ceONyZDGs7mHKolrkYDkWxDSSbxyjfGjZ7MRbkTw6
	hzME1W4M25gy0Hp/rCWPua4=
X-Google-Smtp-Source: ABdhPJxE36N7UmuiVfKpEpJhQchoIqRNA4qj2vV6OWF8/PEyEVEOA4VTQ8tP+KSFbgHlXShpwlfj3w==
X-Received: by 2002:a19:ad06:: with SMTP id t6mr988lfc.222.1605541396800;
        Mon, 16 Nov 2020 07:43:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a378:: with SMTP id i24ls358925ljn.3.gmail; Mon, 16 Nov
 2020 07:43:15 -0800 (PST)
X-Received: by 2002:a2e:9b10:: with SMTP id u16mr6794257lji.403.1605541395610;
        Mon, 16 Nov 2020 07:43:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605541395; cv=none;
        d=google.com; s=arc-20160816;
        b=OPBxuzrIwm1Hv05jwdb15w2yEIB/eZuQdVlSOlPuYZAL3wreQC0T5z5Y+FuYGfrMmZ
         WE6nIPB3hAO97eiks1GdLLh7iWgav5YyROGXfL2xnZQ040QMKQPS4I86a0lnjyo/HwXb
         DVNQZOQLYLxJT1v3/hgCOeBGC2tq/wfvHag18Dd31u2uTRcIiKJdyCl0H2CnuS0BKpoB
         vCclrCAcG5Ij7Y2QU8G6vhBu6MpeEPISOebybT/87TnaigYBz0vBjvwQNF5GQlVyLQ5Z
         g5oRHOKkdUDIG3Mz4B/Ns0mtjRQf884yKYsd7eQyYswo+kaxY5F+eCjFifDj/EWVurK7
         tEgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=j36fSUfGBLe2zZxhs7gruCyn6/GmW8bJyNFpN4VZcls=;
        b=rqMqD97zNjbBsAKshgESVjv9Mu2v7ALgkP+RCC8Ddol7O08LB/0d5P8C4G3PcGCeFF
         D4AzkhQMejV4kq+Ovah7q191NY9vVfCqChBlL6215W/Clx/KbwPQXwOcDzrOWQtmsF5R
         TuEn9tDEnRq4Kz14P73JEx2Lxrmn7le3vIDiCYoCAXNN92FJgRty8/nlqneuia135zAt
         Xor4lfI4TvfBhu0qp9D8sLHK52BU5cmru7zxFSFYPDLxA8YgsKAYW1izFOied3Y1FSg7
         IizjGS9kh5DOr1u7mGAqKlqLIU/0vcCFkIv5cuSKRBfBpgyU29mXiNNUPgmy/pMD4GSR
         4XIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jdRX0Sra;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id t18si162047lfr.1.2020.11.16.07.43.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Nov 2020 07:43:15 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id m6so1997313wrg.7
        for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 07:43:15 -0800 (PST)
X-Received: by 2002:a5d:4a50:: with SMTP id v16mr20283827wrs.106.1605541394849;
        Mon, 16 Nov 2020 07:43:14 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id a9sm22684197wrp.21.2020.11.16.07.43.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 16 Nov 2020 07:43:13 -0800 (PST)
Date: Mon, 16 Nov 2020 16:43:08 +0100
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
Subject: Re: [PATCH mm v3 13/19] kasan, mm: rename kasan_poison_kfree
Message-ID: <20201116154308.GF1357314@elver.google.com>
References: <cover.1605305978.git.andreyknvl@google.com>
 <798e1753fafb37151213a0ad0b1b2f08f66c3877.1605305978.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <798e1753fafb37151213a0ad0b1b2f08f66c3877.1605305978.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jdRX0Sra;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as
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
> Rename kasan_poison_kfree() to kasan_slab_free_mempool() as it better
> reflects what this annotation does. Also add a comment that explains the
> PageSlab() check.
> 
> No functional changes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I5026f87364e556b506ef1baee725144bb04b8810

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  include/linux/kasan.h | 16 ++++++++--------
>  mm/kasan/common.c     | 40 +++++++++++++++++++++++-----------------
>  mm/mempool.c          |  2 +-
>  3 files changed, 32 insertions(+), 26 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 6bd95243a583..16cf53eac29b 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -175,6 +175,13 @@ static __always_inline bool kasan_slab_free(struct kmem_cache *s, void *object,
>  	return false;
>  }
>  
> +void __kasan_slab_free_mempool(void *ptr, unsigned long ip);
> +static __always_inline void kasan_slab_free_mempool(void *ptr, unsigned long ip)
> +{
> +	if (kasan_enabled())
> +		__kasan_slab_free_mempool(ptr, ip);
> +}
> +
>  void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
>  				       void *object, gfp_t flags);
>  static __always_inline void * __must_check kasan_slab_alloc(
> @@ -215,13 +222,6 @@ static __always_inline void * __must_check kasan_krealloc(const void *object,
>  	return (void *)object;
>  }
>  
> -void __kasan_poison_kfree(void *ptr, unsigned long ip);
> -static __always_inline void kasan_poison_kfree(void *ptr, unsigned long ip)
> -{
> -	if (kasan_enabled())
> -		__kasan_poison_kfree(ptr, ip);
> -}
> -
>  void __kasan_kfree_large(void *ptr, unsigned long ip);
>  static __always_inline void kasan_kfree_large(void *ptr, unsigned long ip)
>  {
> @@ -260,6 +260,7 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
>  {
>  	return false;
>  }
> +static inline void kasan_slab_free_mempool(void *ptr, unsigned long ip) {}
>  static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
>  				   gfp_t flags)
>  {
> @@ -279,7 +280,6 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
>  {
>  	return (void *)object;
>  }
> -static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
>  static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
>  
>  #endif /* CONFIG_KASAN */
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 17918bd20ed9..1205faac90bd 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -335,6 +335,29 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
>  	return ____kasan_slab_free(cache, object, ip, true);
>  }
>  
> +void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
> +{
> +	struct page *page;
> +
> +	page = virt_to_head_page(ptr);
> +
> +	/*
> +	 * Even though this function is only called for kmem_cache_alloc and
> +	 * kmalloc backed mempool allocations, those allocations can still be
> +	 * !PageSlab() when the size provided to kmalloc is larger than
> +	 * KMALLOC_MAX_SIZE, and kmalloc falls back onto page_alloc.
> +	 */
> +	if (unlikely(!PageSlab(page))) {
> +		if (ptr != page_address(page)) {
> +			kasan_report_invalid_free(ptr, ip);
> +			return;
> +		}
> +		poison_range(ptr, page_size(page), KASAN_FREE_PAGE);
> +	} else {
> +		____kasan_slab_free(page->slab_cache, ptr, ip, false);
> +	}
> +}
> +
>  static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
>  {
>  	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
> @@ -429,23 +452,6 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
>  						flags, true);
>  }
>  
> -void __kasan_poison_kfree(void *ptr, unsigned long ip)
> -{
> -	struct page *page;
> -
> -	page = virt_to_head_page(ptr);
> -
> -	if (unlikely(!PageSlab(page))) {
> -		if (ptr != page_address(page)) {
> -			kasan_report_invalid_free(ptr, ip);
> -			return;
> -		}
> -		poison_range(ptr, page_size(page), KASAN_FREE_PAGE);
> -	} else {
> -		____kasan_slab_free(page->slab_cache, ptr, ip, false);
> -	}
> -}
> -
>  void __kasan_kfree_large(void *ptr, unsigned long ip)
>  {
>  	if (ptr != page_address(virt_to_head_page(ptr)))
> diff --git a/mm/mempool.c b/mm/mempool.c
> index 583a9865b181..624ed51b060f 100644
> --- a/mm/mempool.c
> +++ b/mm/mempool.c
> @@ -104,7 +104,7 @@ static inline void poison_element(mempool_t *pool, void *element)
>  static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
>  {
>  	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
> -		kasan_poison_kfree(element, _RET_IP_);
> +		kasan_slab_free_mempool(element, _RET_IP_);
>  	else if (pool->alloc == mempool_alloc_pages)
>  		kasan_free_pages(element, (unsigned long)pool->pool_data);
>  }
> -- 
> 2.29.2.299.gdc1121823c-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201116154308.GF1357314%40elver.google.com.
