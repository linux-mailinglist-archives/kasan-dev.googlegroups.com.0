Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFUYTCBAMGQEBA4AV6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D695330C7F
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 12:35:51 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id d15sf4177862ljl.17
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 03:35:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615203351; cv=pass;
        d=google.com; s=arc-20160816;
        b=CZmAHLWnHFCnSaniaw2RfPJ/EwQBuxQavh7egL4Tfni9bIf8CaAKZIHPe9oxGIpH/x
         uHJCe5wkntmffXpuTAzux2UO/3K3U6Uoj/fb5NfjBGgsns97gkP58DTszldtn3APUx2e
         0Pr+/qMSsBYpB3x22wjvVeb3JKcS7oxBvgO6GUzyyu3CsFyN80OX3ymuDz8pDOFtOdYq
         6DfH3NdgEt50aXtn643RMNnxA58UWUT8XFSno2w7VTRG+1hiBC3u69dt2n6KxPt+dZir
         q6qQkffy3/4uRGCwP4S1jMhSI8wMpT7//evwMfwyc0d8+w8H9Ce4Duruw+Vz4Hr02Cyk
         Q1sQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=TgGXbzLCtKkSoUSbNGG1D/JCvVY2XHemhaVPJWEhh+A=;
        b=t0dUxh75wZ2KFJkLV3KK7hAZTStzHMg0wJZF0U/NJ4v5f3bAczV4Cx7jMSGx0dI/Ep
         j35fs4RZvRduH9Z8xX6daGurbFFQ7h/DdnqxFpNWXO7v+tLQRrKEmnBJPCjAtizptWMK
         xo93ImbIkL1yRxzC7mqEMlTgsCGHzyDsNyZxvw/Lc4DcLfl7cagCu54pd6jssVyz6OMX
         Kz7AESTzRdWvm+BqFQkNjnHP4G1M+es3dfWoYbGoDEZJvMHsrqKUK6S4DIdP9R8sAzuD
         29eo/J8si6GnG96efn45zZ8I3rX4/AV2kixIVzxnWS4MtIiHtwhJGnpMBNGNepReGMT+
         u+ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HBtYHyjx;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=TgGXbzLCtKkSoUSbNGG1D/JCvVY2XHemhaVPJWEhh+A=;
        b=QbSRMKjr2LNgv1awK2uzFfQMmNBo2W9GjEKffwuPHOtX15R9D9nQFMWBMPXeRr44M0
         zk53CS7KT8mbibb0toBmlP3fNktkkIlKUXo2SVZU32Kg+IItU3bjU8nshgWzqr6muE9U
         BjVrsOC3y22fykeF0u/Bk2llRusKwAXuiYJyPlQaNaMjL49PafFqLa6Grl4dJFy3ecYO
         sVf2qGPCQrtiT6Bno6HIi2aq+9nvpRy3+O1cLa/7ELX0lUA3yMDBg6VYJIPX4YWGwQEr
         FjZuwHTOTvdFGqjxWvtRPZ13lfgDFE5WjMgWYLGZXd2uqKYDGl414YcrpU+fm2hMqBP9
         /e2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TgGXbzLCtKkSoUSbNGG1D/JCvVY2XHemhaVPJWEhh+A=;
        b=HI65ppeaDfnIKtiJDCq8Mu2SpWv8lcXchGIhPWK1aDLgdkddI4VVhbbNZ3q680SPWT
         mDUEEddHrJpqGc8RDKE9atOCd7xwTYjZeOGdpanN0a5hTo14rzLdG7K85QrIegI2JT/L
         s41NO4h7Ilox40n0V8AWFhkPWc+dmizapeCgsfkX3YvvgUfSIW9oCokJJXs3jFlgJrpi
         K+uvcZSXoVFAKw6FrLbXPgscAGPXoDRuDKdRduA5rt3RYY6bABd3NQHH5p4AKjYftXpY
         juumfhZ4oyLB7ejwlszhzZR25gsh32TJx5iQ+39WHBbEVmKMXeGkNXnYuEuSs8Qkf+6q
         cL1w==
X-Gm-Message-State: AOAM5317J5ypgDASGUOHDveNhae4LgtO3bW5Ime+u0pFTNhinKgCyFax
	GJJWyolEhcyZOJbGKvWX+oA=
X-Google-Smtp-Source: ABdhPJzDOugm4fTajG/XGKYGzo4nlTLYsHbK2qJp3t+RW3dQ/zyL2wpgUc4SuCRNxjDX/3Ost0LyDQ==
X-Received: by 2002:a05:6512:34c3:: with SMTP id w3mr13758979lfr.437.1615203350892;
        Mon, 08 Mar 2021 03:35:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e86:: with SMTP id 128ls310321lfo.0.gmail; Mon, 08 Mar
 2021 03:35:49 -0800 (PST)
X-Received: by 2002:a05:6512:3a8f:: with SMTP id q15mr13401056lfu.389.1615203349764;
        Mon, 08 Mar 2021 03:35:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615203349; cv=none;
        d=google.com; s=arc-20160816;
        b=uBzfnh2Z1ZbyJsfrC5WcuMA+lqgb3mf7AVNA+tBEU5WmXwj74N5246YAT6SXCW5vPL
         0iANkybUdWOpBZnPchNB9fTHcPynCf5il70NDCz1l32RnUVXIWEpcK9JgSsbAkgyigZH
         uy4KLmkcQ3MNw4g5Lui5vHSYXQl1wmBMvwTdxU3RF9uUk/lMVzuvd9VbzkYTBKJwpeH2
         VELsH0FeXVgYNVM8IG9c3o0p1ktadaE50reZr8KxsQu4mAf/D4nkT0Tx3w+i2NqEPqk3
         llaSCt3VGe+UHr1SgsMcjb67ULCsFthMRS6Bw7PdKnOi4bWpizUB0+uO1K1/j0LtpuxA
         I4hA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=n76nfuOBIjU7qAbRDmCDHWm6PPfYsZij7NB352EcUzw=;
        b=ygl1fDyuKvuI+BJEQww200Pd2HEHrRovRHpq8KTAVuCP9HSkm3A8tBej5EgaH0RQ64
         lNhz+OYw6M4A5d10O2amyfYGkQa+Hm0JhqIeM37QZ5BJM8Qmx30owKEzhjYABJgX59mI
         Kn3Totjk7AWkqaucLFVTHf9TwJ3hY8dROj1VN76J3EJJWmEaQaJ8nRQczAZytyata/rz
         a6VVcHqwnAJzEuPZmhROX1zmNNC/5esRdOY+V7Sb+L5XuR8Bf+BiokU3wbWQAuj8XltQ
         RHZDGrk6vVAbQcRmXvxKamGh0QHnHvI8+UrX9OdB7Op+DxPDwNYy97MH40vo07lZGIxd
         SqKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HBtYHyjx;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id q26si458874ljj.4.2021.03.08.03.35.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 03:35:49 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id u14so11089088wri.3
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 03:35:49 -0800 (PST)
X-Received: by 2002:a05:6000:192:: with SMTP id p18mr22136031wrx.403.1615203349305;
        Mon, 08 Mar 2021 03:35:49 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:9d1d:b6a0:d116:531b])
        by smtp.gmail.com with ESMTPSA id o7sm18219797wrs.16.2021.03.08.03.35.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Mar 2021 03:35:48 -0800 (PST)
Date: Mon, 8 Mar 2021 12:35:42 +0100
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
Subject: Re: [PATCH 3/5] kasan, mm: integrate page_alloc init with HW_TAGS
Message-ID: <YEYMDn/9zQI8g+3o@elver.google.com>
References: <cover.1614989433.git.andreyknvl@google.com>
 <a7f1d687b0550182c7f5b4a47c277a61425af65f.1614989433.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <a7f1d687b0550182c7f5b4a47c277a61425af65f.1614989433.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HBtYHyjx;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as
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
> of HW_TAGS KASAN routines for page_alloc memory when init_on_alloc/free
> is enabled.
> 
> With this change, kernel_init_free_pages() is no longer called when
> both HW_TAGS KASAN and init_on_alloc/free are enabled. Instead, memory
> is initialized in KASAN runtime.
> 
> To avoid discrepancies with which memory gets initialized that can be
> caused by future changes, both KASAN and kernel_init_free_pages() hooks
> are put together and a warning comment is added.
> 
> This patch changes the order in which memory initialization and page
> poisoning hooks are called. This doesn't lead to any side-effects, as
> whenever page poisoning is enabled, memory initialization gets disabled.
> 
> Combining setting allocation tags with memory initialization improves
> HW_TAGS KASAN performance when init_on_alloc/free is enabled.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  include/linux/kasan.h | 16 ++++++++--------
>  mm/kasan/common.c     |  8 ++++----
>  mm/mempool.c          |  4 ++--
>  mm/page_alloc.c       | 37 ++++++++++++++++++++++++++-----------
>  4 files changed, 40 insertions(+), 25 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 1d89b8175027..4c0f414a893b 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -120,20 +120,20 @@ static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
>  		__kasan_unpoison_range(addr, size);
>  }
>  
> -void __kasan_alloc_pages(struct page *page, unsigned int order);
> +void __kasan_alloc_pages(struct page *page, unsigned int order, bool init);
>  static __always_inline void kasan_alloc_pages(struct page *page,
> -						unsigned int order)
> +						unsigned int order, bool init)
>  {
>  	if (kasan_enabled())
> -		__kasan_alloc_pages(page, order);
> +		__kasan_alloc_pages(page, order, init);
>  }
>  
> -void __kasan_free_pages(struct page *page, unsigned int order);
> +void __kasan_free_pages(struct page *page, unsigned int order, bool init);
>  static __always_inline void kasan_free_pages(struct page *page,
> -						unsigned int order)
> +						unsigned int order, bool init)
>  {
>  	if (kasan_enabled())
> -		__kasan_free_pages(page, order);
> +		__kasan_free_pages(page, order, init);
>  }
>  
>  void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> @@ -282,8 +282,8 @@ static inline slab_flags_t kasan_never_merge(void)
>  	return 0;
>  }
>  static inline void kasan_unpoison_range(const void *address, size_t size) {}
> -static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
> -static inline void kasan_free_pages(struct page *page, unsigned int order) {}
> +static inline void kasan_alloc_pages(struct page *page, unsigned int order, bool init) {}
> +static inline void kasan_free_pages(struct page *page, unsigned int order, bool init) {}
>  static inline void kasan_cache_create(struct kmem_cache *cache,
>  				      unsigned int *size,
>  				      slab_flags_t *flags) {}
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 316f7f8cd8e6..6107c795611f 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -97,7 +97,7 @@ slab_flags_t __kasan_never_merge(void)
>  	return 0;
>  }
>  
> -void __kasan_alloc_pages(struct page *page, unsigned int order)
> +void __kasan_alloc_pages(struct page *page, unsigned int order, bool init)
>  {
>  	u8 tag;
>  	unsigned long i;
> @@ -108,14 +108,14 @@ void __kasan_alloc_pages(struct page *page, unsigned int order)
>  	tag = kasan_random_tag();
>  	for (i = 0; i < (1 << order); i++)
>  		page_kasan_tag_set(page + i, tag);
> -	kasan_unpoison(page_address(page), PAGE_SIZE << order, false);
> +	kasan_unpoison(page_address(page), PAGE_SIZE << order, init);
>  }
>  
> -void __kasan_free_pages(struct page *page, unsigned int order)
> +void __kasan_free_pages(struct page *page, unsigned int order, bool init)
>  {
>  	if (likely(!PageHighMem(page)))
>  		kasan_poison(page_address(page), PAGE_SIZE << order,
> -			     KASAN_FREE_PAGE, false);
> +			     KASAN_FREE_PAGE, init);
>  }
>  
>  /*
> diff --git a/mm/mempool.c b/mm/mempool.c
> index 79959fac27d7..fe19d290a301 100644
> --- a/mm/mempool.c
> +++ b/mm/mempool.c
> @@ -106,7 +106,7 @@ static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
>  	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
>  		kasan_slab_free_mempool(element);
>  	else if (pool->alloc == mempool_alloc_pages)
> -		kasan_free_pages(element, (unsigned long)pool->pool_data);
> +		kasan_free_pages(element, (unsigned long)pool->pool_data, false);
>  }
>  
>  static void kasan_unpoison_element(mempool_t *pool, void *element)
> @@ -114,7 +114,7 @@ static void kasan_unpoison_element(mempool_t *pool, void *element)
>  	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
>  		kasan_unpoison_range(element, __ksize(element));
>  	else if (pool->alloc == mempool_alloc_pages)
> -		kasan_alloc_pages(element, (unsigned long)pool->pool_data);
> +		kasan_alloc_pages(element, (unsigned long)pool->pool_data, false);
>  }
>  
>  static __always_inline void add_element(mempool_t *pool, void *element)
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index 0efb07b5907c..175bdb36d113 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -396,14 +396,14 @@ static DEFINE_STATIC_KEY_TRUE(deferred_pages);
>   * initialization is done, but this is not likely to happen.
>   */
>  static inline void kasan_free_nondeferred_pages(struct page *page, int order,
> -							fpi_t fpi_flags)
> +						bool init, fpi_t fpi_flags)
>  {
>  	if (static_branch_unlikely(&deferred_pages))
>  		return;
>  	if (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
>  			(fpi_flags & FPI_SKIP_KASAN_POISON))
>  		return;
> -	kasan_free_pages(page, order);
> +	kasan_free_pages(page, order, init);
>  }
>  
>  /* Returns true if the struct page for the pfn is uninitialised */
> @@ -455,12 +455,12 @@ defer_init(int nid, unsigned long pfn, unsigned long end_pfn)
>  }
>  #else
>  static inline void kasan_free_nondeferred_pages(struct page *page, int order,
> -							fpi_t fpi_flags)
> +						bool init, fpi_t fpi_flags)
>  {
>  	if (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
>  			(fpi_flags & FPI_SKIP_KASAN_POISON))
>  		return;
> -	kasan_free_pages(page, order);
> +	kasan_free_pages(page, order, init);
>  }
>  
>  static inline bool early_page_uninitialised(unsigned long pfn)
> @@ -1242,6 +1242,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
>  			unsigned int order, bool check_free, fpi_t fpi_flags)
>  {
>  	int bad = 0;
> +	bool init;
>  
>  	VM_BUG_ON_PAGE(PageTail(page), page);
>  
> @@ -1299,16 +1300,21 @@ static __always_inline bool free_pages_prepare(struct page *page,
>  		debug_check_no_obj_freed(page_address(page),
>  					   PAGE_SIZE << order);
>  	}
> -	if (want_init_on_free())
> -		kernel_init_free_pages(page, 1 << order);
>  
>  	kernel_poison_pages(page, 1 << order);
>  
>  	/*
> +	 * As memory initialization is integrated with hardware tag-based
> +	 * KASAN, kasan_free_pages and kernel_init_free_pages must be
> +	 * kept together to avoid discrepancies in behavior.
> +	 *
>  	 * With hardware tag-based KASAN, memory tags must be set before the
>  	 * page becomes unavailable via debug_pagealloc or arch_free_page.
>  	 */
> -	kasan_free_nondeferred_pages(page, order, fpi_flags);
> +	init = want_init_on_free();
> +	if (init && !IS_ENABLED(CONFIG_KASAN_HW_TAGS))

Doing the !IS_ENABLED(CONFIG_KASAN_HW_TAGS) check is awkward, and
assumes internal knowledge of the KASAN implementation and how all
current and future architectures that support HW_TAGS work.

Could we instead add a static inline helper to <linux/kasan.h>, e.g.
kasan_supports_init() or so?

That way, these checks won't grow uncontrollable if a future
architecture implements HW_TAGS but not init.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEYMDn/9zQI8g%2B3o%40elver.google.com.
