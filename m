Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUUXTGBAMGQES7TUVFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DBAF3312D9
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 17:07:47 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id j194sf3533749lfj.4
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 08:07:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615219667; cv=pass;
        d=google.com; s=arc-20160816;
        b=D72C07XrZHvYRG58D/hvKxwhRt9ybKlKFPmaT6pAj3tm0asQoIIjmbOfAmFC+heoPy
         Hn1Ifla8YXHGS41BbPfqgrWJwSyLRAcCrlw5RR8/rTaAdjhjoU9yzay04cKkmNjeNqKi
         RU18E41adO9+F8M+QEfWc2gL5QWitm81QNe57JmvGhjPWItLH7jSTqhNi8EJ2bmO573s
         YLXh3DVrNYzOmdi8AbyjXs5E2Vhse3P+VXLmaupMg7YnKrP/5/U79pcSlo3BLp1RglRb
         ljPv+3rdJSmTRAiHRqdgKsIbdGQ0vCxMHprEAaWJ2nnuivUOwjR9U3LmJvKVn/fB49sk
         AjiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=1j9+MwRGvV9P/EoQAL+kAEcvLshIo/HlF14p0Hl95dY=;
        b=pL7C/CF50Hq4VO6FRabqcHpUqm3TP0t18d3klsMNuJ9RjOYv0JbVv4ejM4cL/OknYv
         sHGylWjzVKBe8Nm5Gt7Vbr3zYn/7wQW+U0tt9xck1mfw6mAQjATD6sVuDTd6Xh86GbKC
         9uObIUtfIfQpm7SVH/J2ykyu7K715n/bDH1crKcxthJA0uN0KhWVCEy5Nes+Y/HJ0GsR
         ik5vhbHUyWfmQU/cZd2Dex6g2/7/bRFGqy/u/9eQF3OSYSSxjY2SG4l4xPl/a7n1/tEk
         Ea3iUUBjbGPH4fqEJI1JeDUQd9svdYGRbJRxkVKyQgjSvfxTCirzUxNMY1Tbhg/nc4jE
         qpjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TbHIG2UJ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=1j9+MwRGvV9P/EoQAL+kAEcvLshIo/HlF14p0Hl95dY=;
        b=VQwgGUgvSnHvIu59g7jkRFiwusKZoVNHgXA7ZFLmHzbrJBZcXSZyt7fXbbRKr+cpUB
         H+/6kfbCAUUhJ8QqsdF4wwR0Nxo9FT6pR2/L98rXORwAvMzakEaZCLP/hnidkIz71cMQ
         ra1cgkgegmvasF0S6xdMhcEyVVFJhchb/7MyHVcOqYMibIoboEsfBo14Dd3dw3Oksdf8
         19QEmA0/uqUTzqsp8zR/iQOAPbzkFvKZMTP+gxVxNSfhsC2IJIVyMM93T4FqItLzwtaH
         SXdloNpFE289XYWXXuoxK2eNxfylkg8bH6ico7IsrwzPsIJnYpJelWS90gdoQNYqpV9s
         gSnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1j9+MwRGvV9P/EoQAL+kAEcvLshIo/HlF14p0Hl95dY=;
        b=dJowh72BlscdkXSrk1T38Qb6DlWhQD3gUF9grE1qv8zx1+Gvf0XcMgRVQvTV9FLiGP
         89Q087mCJaJz9vy2lcVuZQxbq93qg7NFQqdnXw5Mfh2C0o4xz/PybIheqn64imBwREbZ
         9VQUMaymgA0EI3vy3fEJijMwk0SIbMyCJjGoerZ4Y+5Vcc7DvGmRzQ4pJP7I6Q8aSluT
         WnTA/0JTt3Dxr0Zz5huu6mg5ey18c2MKuEdsw2JwqCTzM1wZmuD6fqW8SuiX39ysg/7V
         k5EQZRG7hHFqaKLFzId9vN5ukHmy1wbRObc8QYBBNjHzIXz7w0NO81kqMX0Kl2B+CJVt
         h2Bw==
X-Gm-Message-State: AOAM533sc2ee2GYDtyPK05rEFXCmgG5IqtFl9SR7aWGb9n3uDuNX9L7X
	AOnaySuFB8enL8+kg0HYVw4=
X-Google-Smtp-Source: ABdhPJzzj7j+tsVniBIl1zi+NMMgOyR1qyVQJ/gKj9yk6tTb6aOH03eUAgoLFraCWwky4khx6ckb2A==
X-Received: by 2002:a05:651c:28b:: with SMTP id b11mr14052708ljo.219.1615219666955;
        Mon, 08 Mar 2021 08:07:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9212:: with SMTP id k18ls3563740ljg.8.gmail; Mon, 08 Mar
 2021 08:07:45 -0800 (PST)
X-Received: by 2002:a2e:8009:: with SMTP id j9mr14455692ljg.364.1615219665802;
        Mon, 08 Mar 2021 08:07:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615219665; cv=none;
        d=google.com; s=arc-20160816;
        b=mO1ANLfhLX//TH4M6ij9wjvnMDugMkkIpkqTjZhYn59KYoFUkVqz4lQz0L8IBfnmiQ
         ZFoeRHueUVNiAkKWqd6iPposDtnTz9OUO6pi/LInPcdXI9txwcfc1oHQrEm0FLtf50rb
         OzORi/YvHLIQpV3+a6ivJ5TJ1ryW2upx3+1g9Dawbq7PnMB7BuoHMoJ34mZOSWZ1HLyA
         mvqUvyCcI16cjfkSdXHN45b+4PtIN+HgY+BfO1wyLWda3CP0AHsjm05Whxkn66KHb9ID
         IEf2VM7hxq318vecITeHat6Ot6XJhn9NVVh9DjFBp5lu/gJKjzJ/PNk1AyPRrMNGhD6h
         AHkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=2q4Skr97mNBOzpDxG2NyajQhR1FVDKa6sc4OrMxpTCY=;
        b=U5yyhs8NkGXLjve8rR2wrWYQA0yFLJh02NTMUyEhkiHmfxCqi4W40gVK86ZiLQzqtQ
         zRcjR3H3th3pVpMI2jM5dN8q837POowqZwTTeu6TEZwUxIZSKdfK1XEqXw4qQwn6kpuS
         4tlRq1EN9+/5iqKLfz28NGCcTF4kYlyyC4u6vgbr5CTVohbezZwCA3IbeCmZb5lG/BP/
         Sjmuq5IAUtgX+bo1Xi4DJwInMUmsYWSAJ9Tzh0TvutkjkLzCwCgv0rip6L3oaBMMHIZy
         NWheXK04pIOnqWGDTwXGsnAN4ik4ohNBTi7xYOO8lZZkPWUZsFvLA0pqrIa41ix+yMLV
         WjWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TbHIG2UJ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id j12si416665lfg.8.2021.03.08.08.07.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 08:07:45 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id f12so12019085wrx.8
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 08:07:45 -0800 (PST)
X-Received: by 2002:a5d:47ab:: with SMTP id 11mr23677720wrb.153.1615219665215;
        Mon, 08 Mar 2021 08:07:45 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:9d1d:b6a0:d116:531b])
        by smtp.gmail.com with ESMTPSA id p6sm18970453wru.2.2021.03.08.08.07.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Mar 2021 08:07:44 -0800 (PST)
Date: Mon, 8 Mar 2021 17:07:39 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 3/5] kasan, mm: integrate page_alloc init with HW_TAGS
Message-ID: <YEZLy3cxq+Nt3Kqe@elver.google.com>
References: <cover.1615218180.git.andreyknvl@google.com>
 <731edf3341d50e863a658689c184eb16abda70e6.1615218180.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <731edf3341d50e863a658689c184eb16abda70e6.1615218180.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TbHIG2UJ;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as
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

On Mon, Mar 08, 2021 at 04:55PM +0100, Andrey Konovalov wrote:
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

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  include/linux/kasan.h | 30 ++++++++++++++++++++++--------
>  mm/kasan/common.c     |  8 ++++----
>  mm/mempool.c          |  4 ++--
>  mm/page_alloc.c       | 37 ++++++++++++++++++++++++++-----------
>  4 files changed, 54 insertions(+), 25 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 1d89b8175027..c89613caa8cf 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -96,6 +96,11 @@ static __always_inline bool kasan_enabled(void)
>  	return static_branch_likely(&kasan_flag_enabled);
>  }
>  
> +static inline bool kasan_has_integrated_init(void)
> +{
> +	return kasan_enabled();

Good catch that we need enabled, too.

> +}
> +
>  #else /* CONFIG_KASAN_HW_TAGS */
>  
>  static inline bool kasan_enabled(void)
> @@ -103,6 +108,11 @@ static inline bool kasan_enabled(void)
>  	return true;
>  }
>  
> +static inline bool kasan_has_integrated_init(void)
> +{
> +	return false;
> +}
> +
>  #endif /* CONFIG_KASAN_HW_TAGS */
>  
>  slab_flags_t __kasan_never_merge(void);
> @@ -120,20 +130,20 @@ static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
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
> @@ -277,13 +287,17 @@ static inline bool kasan_enabled(void)
>  {
>  	return false;
>  }
> +static inline bool kasan_has_integrated_init(void)
> +{
> +	return false;
> +}
>  static inline slab_flags_t kasan_never_merge(void)
>  {
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
> index 0efb07b5907c..aba9cd673eac 100644
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
> +	 * As memory initialization might be integrated into KASAN,
> +	 * kasan_free_pages and kernel_init_free_pages must be
> +	 * kept together to avoid discrepancies in behavior.
> +	 *
>  	 * With hardware tag-based KASAN, memory tags must be set before the
>  	 * page becomes unavailable via debug_pagealloc or arch_free_page.
>  	 */
> -	kasan_free_nondeferred_pages(page, order, fpi_flags);
> +	init = want_init_on_free();
> +	if (init && !kasan_has_integrated_init())
> +		kernel_init_free_pages(page, 1 << order);
> +	kasan_free_nondeferred_pages(page, order, init, fpi_flags);
>  
>  	/*
>  	 * arch_free_page() can make the page's contents inaccessible.  s390
> @@ -2315,17 +2321,26 @@ static bool check_new_pages(struct page *page, unsigned int order)
>  inline void post_alloc_hook(struct page *page, unsigned int order,
>  				gfp_t gfp_flags)
>  {
> +	bool init;
> +
>  	set_page_private(page, 0);
>  	set_page_refcounted(page);
>  
>  	arch_alloc_page(page, order);
>  	debug_pagealloc_map_pages(page, 1 << order);
> -	kasan_alloc_pages(page, order);
> -	kernel_unpoison_pages(page, 1 << order);
> -	set_page_owner(page, order, gfp_flags);
>  
> -	if (!want_init_on_free() && want_init_on_alloc(gfp_flags))
> +	/*
> +	 * As memory initialization might be integrated into KASAN,
> +	 * kasan_alloc_pages and kernel_init_free_pages must be
> +	 * kept together to avoid discrepancies in behavior.
> +	 */
> +	init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
> +	kasan_alloc_pages(page, order, init);
> +	if (init && !kasan_has_integrated_init())
>  		kernel_init_free_pages(page, 1 << order);
> +
> +	kernel_unpoison_pages(page, 1 << order);
> +	set_page_owner(page, order, gfp_flags);
>  }
>  
>  static void prep_new_page(struct page *page, unsigned int order, gfp_t gfp_flags,
> -- 
> 2.30.1.766.gb4fecdf3b7-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEZLy3cxq%2BNt3Kqe%40elver.google.com.
