Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW4TTCBAMGQESULS24I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id E3D4A330C47
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 12:26:19 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id a22sf4201345ljq.4
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 03:26:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615202779; cv=pass;
        d=google.com; s=arc-20160816;
        b=W8P/6X0Toc2Gl/gDkoMjyXLA0+ETfZbDy8UHds6yWYzfRDeUNaT29lih8jkawHjvzp
         gYV2SjvsaMyEPoBJuevrsOUQwkKTWUkJaZLmZR7JWQVB855rLhA63TBlu4+Q2a7Ug/J8
         QRL+tnh2Xl80BZDgIstOlJ80TEl1CLUelWxjIo5kcCtSVUJO7qlg4Vg/q4Urwg5zoCDO
         nZkUVXhXBic9vafqFEYFyixGrVjA2WrPY39OmAdA5pv8bAuGAz4rQYcaIvRIXJffJoVo
         d0VXnWKz/Ti9KuSmbhAH2Lq14oLq+iw4O44aB9qtVY2zCYvG8puL++3sJ/NVzjxvQP3i
         O7XA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=cnH3Uzw6R9FOHjkSdBQXvDqkuulZBJmc6hHIUyVLGZ0=;
        b=LmC5Lcf7Np5bJ/GK39vqA8jZn62ELN6BGIeG/xUAj3GRx4mQu2AoG0nX3Kyxj0OyId
         ca95rxLAT+QaW830EE0BpUt3mBruKzKIcEG9+Ob0A7yPvQHH/5WmjJ9qXEhouDNxR9qP
         HI25p9BGU99AmUMFSYIdzFQ9YGo2+8UySQxn21+GBQZyBUy5qoUWxLADPFag9/iAyrxy
         03Pk+7uHTgNWCYypjljQ9FAa/XkGKMdUnBI2jHGFcfEpMawbxGLGTzoMuUlybqDVi/6k
         eVSUVIT7MIPpKfuF36YqU7QP/uGJvYOL+SxcKlAu/W1HcvguTc31H5pQhyZBaVT2noQX
         mq7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aHi886dZ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=cnH3Uzw6R9FOHjkSdBQXvDqkuulZBJmc6hHIUyVLGZ0=;
        b=F0gruzdOSGPY5viRKmn8CFUHBiRCcnmpC64Ms+ERAxsW+M+uWpsQ+IjM3M2/NgKPET
         agmHooxf/572Mbc+QKti5aTgIkaSEzclhY3jawfjvkDYaIO+QH7XBipO7PnyffVCJytW
         PO+OKJfBScFF4Wshc+yj2+UxUOYDHQETZk4Y5qUVNWiWMoGVBKQ3/est4VchFGn0uLE2
         ABUxfNJvoR809yBMQpYYJsUfwzgZp4Sw4SQ9aP2H83bRHbAV7Oti89vaSg7g5mvCE1SE
         VQXUxjPs6wsfhbpvUNM8fqmUtzcuk7o80WKIXp8gi1ZZZ/IdDL5NAd9x0oFozn8arJgv
         C+mQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cnH3Uzw6R9FOHjkSdBQXvDqkuulZBJmc6hHIUyVLGZ0=;
        b=sCkgT1xfIyFa9EbnbEwCuIev5rG2ZykXa9WdiE4HgZdA/8CmlFsbnLUMNHMDkhkDBR
         5m4M+ib044wd1g19STHr3c9Tedo/O7swFko17oU8X4q2/uuvOB91YQm55VV+NFUTJEMo
         M39PlpBmT/hCRRurgxK0ZefBVeplM0ls5pYJv4LKmitwpvK5nAGRScbCX6e2SEDLUC4B
         9rqXhRQkmJ686J+NaExznR/1GQQEOsokIEIp4lMiOVVZ8wDAuEiR3Ou8j9kaThfJHWj6
         QHl0CpunBnpFiEM0KZGSfURbArTtAn5eMSOcyOJh3KYbK0ze/RKFAs4Gsfr91c21ZRbH
         H4Tw==
X-Gm-Message-State: AOAM5318f+bz3lCJKcfTUolZbLcredEXERn/50VTZfyVSTcYBmLPHqjF
	ewN5sdLtPNt1tE74rZtrG08=
X-Google-Smtp-Source: ABdhPJwsLi6daQneQBKjtPnqyxgTypjvZmRS+HPK3rh7Kvu+mvKcbxEVrOFgCL/lMYOkdRnRwTWOvg==
X-Received: by 2002:a2e:a58f:: with SMTP id m15mr13199180ljp.400.1615202779462;
        Mon, 08 Mar 2021 03:26:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9191:: with SMTP id f17ls3330186ljg.11.gmail; Mon, 08
 Mar 2021 03:26:18 -0800 (PST)
X-Received: by 2002:a2e:98d1:: with SMTP id s17mr13974995ljj.349.1615202778326;
        Mon, 08 Mar 2021 03:26:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615202778; cv=none;
        d=google.com; s=arc-20160816;
        b=qR+RzelEYvODq3/SDGxic4nIg/oyenSDaKt90Nj2n03wAmixAGNZGjNmqkMr/D6Nx1
         lO9CG8W9j1ZplGlNlNx6UPcIVG0AN5HqwOtyeeHr8/4/SkILDiyw7NUN8mdUHJvMbntQ
         CsCPWv8KtLUJKWVEeUcZl6SQdV5wLfkxvu2DJs7QSxxJ9zxaf0x7lwRXLGGIP/SJxtgE
         T64Iqj4EibIMy/1bysnHWCziHAFsdKLNikKIHUOArf2ObxJDMvir9jU8nW7e6WFOg1go
         Qr0gMkRQKwn4lTYzaWNluCzxWzlNZfRjJJ/ZpcQFXGgfVWti0pmbfVLpahDMlYvE352J
         /qfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=C/TD0CHDy4RoQIxiEpylzxCplnrxE4ZRPieQx5Wj4OY=;
        b=I37fU5WSSc8QyLim3dk4RfO3DHhkt/cwa7ZrLFw4WRjMkGdrGzZBzWxf9LXXmqfi9o
         3aToempsn+GfDfxffohhNJCTXYBF5rHkowwWq87ern1rEVEvxnhd3jOfOSvTZODQ5T6f
         p8A+fyByVp+kCuPtR2GACS7bsxLuOyV5KToxxwThwJa/2LBs57xba7vZlbxbjA7GJbY5
         JxfeQX2BDe9ygyNyUl/q3zgysQkrC4RBQhpyVfJG8ji8dIR/qQVhpJaJpWqRuPKeJS1c
         ZTUVYtX66Fy/yHKCSfdjKUU7B5d17fPHJX/ddnKjjHXsJIf6MPpXoP8eJ0msvVnGDPxU
         bgyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aHi886dZ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id b27si328768ljf.6.2021.03.08.03.26.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 03:26:18 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id t5-20020a1c77050000b029010e62cea9deso3569400wmi.0
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 03:26:18 -0800 (PST)
X-Received: by 2002:a05:600c:4ed1:: with SMTP id g17mr13583865wmq.67.1615202777879;
        Mon, 08 Mar 2021 03:26:17 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:9d1d:b6a0:d116:531b])
        by smtp.gmail.com with ESMTPSA id j4sm16663555wmo.10.2021.03.08.03.26.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Mar 2021 03:26:17 -0800 (PST)
Date: Mon, 8 Mar 2021 12:26:11 +0100
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
Subject: Re: [PATCH 2/5] kasan: init memory in kasan_(un)poison for HW_TAGS
Message-ID: <YEYJ0+fmJykM0gjJ@elver.google.com>
References: <cover.1614989433.git.andreyknvl@google.com>
 <09ee2b0a0e9578885b2da1c963e9e94154d5d70a.1614989433.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <09ee2b0a0e9578885b2da1c963e9e94154d5d70a.1614989433.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aHi886dZ;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as
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
> This change adds an argument to kasan_poison() and kasan_unpoison()
> that allows initializing memory along with setting the tags for HW_TAGS.
> 
> Combining setting allocation tags with memory initialization will
> improve HW_TAGS KASAN performance when init_on_alloc/free is enabled.
> 
> This change doesn't integrate memory initialization with KASAN,
> this is done is subsequent patches in this series.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  lib/test_kasan.c   |  4 ++--
>  mm/kasan/common.c  | 28 ++++++++++++++--------------
>  mm/kasan/generic.c | 12 ++++++------
>  mm/kasan/kasan.h   | 14 ++++++++------
>  mm/kasan/shadow.c  | 10 +++++-----
>  mm/kasan/sw_tags.c |  2 +-
>  6 files changed, 36 insertions(+), 34 deletions(-)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index e5647d147b35..d77c45edc7cd 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -1044,14 +1044,14 @@ static void match_all_mem_tag(struct kunit *test)
>  			continue;
>  
>  		/* Mark the first memory granule with the chosen memory tag. */
> -		kasan_poison(ptr, KASAN_GRANULE_SIZE, (u8)tag);
> +		kasan_poison(ptr, KASAN_GRANULE_SIZE, (u8)tag, false);
>  
>  		/* This access must cause a KASAN report. */
>  		KUNIT_EXPECT_KASAN_FAIL(test, *ptr = 0);
>  	}
>  
>  	/* Recover the memory tag and free. */
> -	kasan_poison(ptr, KASAN_GRANULE_SIZE, get_tag(ptr));
> +	kasan_poison(ptr, KASAN_GRANULE_SIZE, get_tag(ptr), false);
>  	kfree(ptr);
>  }
>  
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index b5e08d4cefec..316f7f8cd8e6 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -60,7 +60,7 @@ void kasan_disable_current(void)
>  
>  void __kasan_unpoison_range(const void *address, size_t size)
>  {
> -	kasan_unpoison(address, size);
> +	kasan_unpoison(address, size, false);
>  }
>  
>  #if CONFIG_KASAN_STACK
> @@ -69,7 +69,7 @@ void kasan_unpoison_task_stack(struct task_struct *task)
>  {
>  	void *base = task_stack_page(task);
>  
> -	kasan_unpoison(base, THREAD_SIZE);
> +	kasan_unpoison(base, THREAD_SIZE, false);
>  }
>  
>  /* Unpoison the stack for the current task beyond a watermark sp value. */
> @@ -82,7 +82,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
>  	 */
>  	void *base = (void *)((unsigned long)watermark & ~(THREAD_SIZE - 1));
>  
> -	kasan_unpoison(base, watermark - base);
> +	kasan_unpoison(base, watermark - base, false);
>  }
>  #endif /* CONFIG_KASAN_STACK */
>  
> @@ -108,14 +108,14 @@ void __kasan_alloc_pages(struct page *page, unsigned int order)
>  	tag = kasan_random_tag();
>  	for (i = 0; i < (1 << order); i++)
>  		page_kasan_tag_set(page + i, tag);
> -	kasan_unpoison(page_address(page), PAGE_SIZE << order);
> +	kasan_unpoison(page_address(page), PAGE_SIZE << order, false);
>  }
>  
>  void __kasan_free_pages(struct page *page, unsigned int order)
>  {
>  	if (likely(!PageHighMem(page)))
>  		kasan_poison(page_address(page), PAGE_SIZE << order,
> -			     KASAN_FREE_PAGE);
> +			     KASAN_FREE_PAGE, false);
>  }
>  
>  /*
> @@ -251,18 +251,18 @@ void __kasan_poison_slab(struct page *page)
>  	for (i = 0; i < compound_nr(page); i++)
>  		page_kasan_tag_reset(page + i);
>  	kasan_poison(page_address(page), page_size(page),
> -		     KASAN_KMALLOC_REDZONE);
> +		     KASAN_KMALLOC_REDZONE, false);
>  }
>  
>  void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
>  {
> -	kasan_unpoison(object, cache->object_size);
> +	kasan_unpoison(object, cache->object_size, false);
>  }
>  
>  void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
>  {
>  	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
> -			KASAN_KMALLOC_REDZONE);
> +			KASAN_KMALLOC_REDZONE, false);
>  }
>  
>  /*
> @@ -351,7 +351,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache,
>  	}
>  
>  	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
> -			KASAN_KMALLOC_FREE);
> +			KASAN_KMALLOC_FREE, false);
>  
>  	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine))
>  		return false;
> @@ -407,7 +407,7 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
>  	if (unlikely(!PageSlab(page))) {
>  		if (____kasan_kfree_large(ptr, ip))
>  			return;
> -		kasan_poison(ptr, page_size(page), KASAN_FREE_PAGE);
> +		kasan_poison(ptr, page_size(page), KASAN_FREE_PAGE, false);
>  	} else {
>  		____kasan_slab_free(page->slab_cache, ptr, ip, false);
>  	}
> @@ -453,7 +453,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
>  	 * Unpoison the whole object.
>  	 * For kmalloc() allocations, kasan_kmalloc() will do precise poisoning.
>  	 */
> -	kasan_unpoison(tagged_object, cache->object_size);
> +	kasan_unpoison(tagged_object, cache->object_size, false);
>  
>  	/* Save alloc info (if possible) for non-kmalloc() allocations. */
>  	if (kasan_stack_collection_enabled())
> @@ -496,7 +496,7 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
>  	redzone_end = round_up((unsigned long)(object + cache->object_size),
>  				KASAN_GRANULE_SIZE);
>  	kasan_poison((void *)redzone_start, redzone_end - redzone_start,
> -			   KASAN_KMALLOC_REDZONE);
> +			   KASAN_KMALLOC_REDZONE, false);
>  
>  	/*
>  	 * Save alloc info (if possible) for kmalloc() allocations.
> @@ -546,7 +546,7 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
>  				KASAN_GRANULE_SIZE);
>  	redzone_end = (unsigned long)ptr + page_size(virt_to_page(ptr));
>  	kasan_poison((void *)redzone_start, redzone_end - redzone_start,
> -		     KASAN_PAGE_REDZONE);
> +		     KASAN_PAGE_REDZONE, false);
>  
>  	return (void *)ptr;
>  }
> @@ -563,7 +563,7 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
>  	 * Part of it might already have been unpoisoned, but it's unknown
>  	 * how big that part is.
>  	 */
> -	kasan_unpoison(object, size);
> +	kasan_unpoison(object, size, false);
>  
>  	page = virt_to_head_page(object);
>  
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 2e55e0f82f39..53cbf28859b5 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -208,11 +208,11 @@ static void register_global(struct kasan_global *global)
>  {
>  	size_t aligned_size = round_up(global->size, KASAN_GRANULE_SIZE);
>  
> -	kasan_unpoison(global->beg, global->size);
> +	kasan_unpoison(global->beg, global->size, false);
>  
>  	kasan_poison(global->beg + aligned_size,
>  		     global->size_with_redzone - aligned_size,
> -		     KASAN_GLOBAL_REDZONE);
> +		     KASAN_GLOBAL_REDZONE, false);
>  }
>  
>  void __asan_register_globals(struct kasan_global *globals, size_t size)
> @@ -292,11 +292,11 @@ void __asan_alloca_poison(unsigned long addr, size_t size)
>  	WARN_ON(!IS_ALIGNED(addr, KASAN_ALLOCA_REDZONE_SIZE));
>  
>  	kasan_unpoison((const void *)(addr + rounded_down_size),
> -			size - rounded_down_size);
> +			size - rounded_down_size, false);
>  	kasan_poison(left_redzone, KASAN_ALLOCA_REDZONE_SIZE,
> -		     KASAN_ALLOCA_LEFT);
> +		     KASAN_ALLOCA_LEFT, false);
>  	kasan_poison(right_redzone, padding_size + KASAN_ALLOCA_REDZONE_SIZE,
> -		     KASAN_ALLOCA_RIGHT);
> +		     KASAN_ALLOCA_RIGHT, false);
>  }
>  EXPORT_SYMBOL(__asan_alloca_poison);
>  
> @@ -306,7 +306,7 @@ void __asan_allocas_unpoison(const void *stack_top, const void *stack_bottom)
>  	if (unlikely(!stack_top || stack_top > stack_bottom))
>  		return;
>  
> -	kasan_unpoison(stack_top, stack_bottom - stack_top);
> +	kasan_unpoison(stack_top, stack_bottom - stack_top, false);
>  }
>  EXPORT_SYMBOL(__asan_allocas_unpoison);
>  
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 7fbb32234414..823a90d6a0cd 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -331,7 +331,7 @@ static inline u8 kasan_random_tag(void) { return 0; }
>  
>  #ifdef CONFIG_KASAN_HW_TAGS
>  
> -static inline void kasan_poison(const void *addr, size_t size, u8 value)
> +static inline void kasan_poison(const void *addr, size_t size, u8 value, bool init)
>  {
>  	addr = kasan_reset_tag(addr);
>  
> @@ -344,10 +344,10 @@ static inline void kasan_poison(const void *addr, size_t size, u8 value)
>  	if (WARN_ON(size & KASAN_GRANULE_MASK))
>  		return;
>  
> -	hw_set_mem_tag_range((void *)addr, size, value, false);
> +	hw_set_mem_tag_range((void *)addr, size, value, init);
>  }
>  
> -static inline void kasan_unpoison(const void *addr, size_t size)
> +static inline void kasan_unpoison(const void *addr, size_t size, bool init)
>  {
>  	u8 tag = get_tag(addr);
>  
> @@ -361,7 +361,7 @@ static inline void kasan_unpoison(const void *addr, size_t size)
>  		return;
>  	size = round_up(size, KASAN_GRANULE_SIZE);
>  
> -	hw_set_mem_tag_range((void *)addr, size, tag, false);
> +	hw_set_mem_tag_range((void *)addr, size, tag, init);
>  }
>  
>  static inline bool kasan_byte_accessible(const void *addr)
> @@ -380,22 +380,24 @@ static inline bool kasan_byte_accessible(const void *addr)
>   * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
>   * @size - range size, must be aligned to KASAN_GRANULE_SIZE
>   * @value - value that's written to metadata for the range
> + * @init - whether to initialize the memory range (only for hardware tag-based)
>   *
>   * The size gets aligned to KASAN_GRANULE_SIZE before marking the range.
>   */
> -void kasan_poison(const void *addr, size_t size, u8 value);
> +void kasan_poison(const void *addr, size_t size, u8 value, bool init);
>  
>  /**
>   * kasan_unpoison - mark the memory range as accessible
>   * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
>   * @size - range size, can be unaligned
> + * @init - whether to initialize the memory range (only for hardware tag-based)
>   *
>   * For the tag-based modes, the @size gets aligned to KASAN_GRANULE_SIZE before
>   * marking the range.
>   * For the generic mode, the last granule of the memory range gets partially
>   * unpoisoned based on the @size.
>   */
> -void kasan_unpoison(const void *addr, size_t size);
> +void kasan_unpoison(const void *addr, size_t size, bool init);
>  
>  bool kasan_byte_accessible(const void *addr);
>  
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 63f43443f5d7..727ad4629173 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -69,7 +69,7 @@ void *memcpy(void *dest, const void *src, size_t len)
>  	return __memcpy(dest, src, len);
>  }
>  
> -void kasan_poison(const void *addr, size_t size, u8 value)
> +void kasan_poison(const void *addr, size_t size, u8 value, bool init)
>  {
>  	void *shadow_start, *shadow_end;
>  
> @@ -106,7 +106,7 @@ void kasan_poison_last_granule(const void *addr, size_t size)
>  }
>  #endif
>  
> -void kasan_unpoison(const void *addr, size_t size)
> +void kasan_unpoison(const void *addr, size_t size, bool init)
>  {
>  	u8 tag = get_tag(addr);
>  
> @@ -129,7 +129,7 @@ void kasan_unpoison(const void *addr, size_t size)
>  		return;
>  
>  	/* Unpoison all granules that cover the object. */
> -	kasan_poison(addr, round_up(size, KASAN_GRANULE_SIZE), tag);
> +	kasan_poison(addr, round_up(size, KASAN_GRANULE_SIZE), tag, false);
>  
>  	/* Partially poison the last granule for the generic mode. */
>  	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> @@ -344,7 +344,7 @@ void kasan_poison_vmalloc(const void *start, unsigned long size)
>  		return;
>  
>  	size = round_up(size, KASAN_GRANULE_SIZE);
> -	kasan_poison(start, size, KASAN_VMALLOC_INVALID);
> +	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
>  }
>  
>  void kasan_unpoison_vmalloc(const void *start, unsigned long size)
> @@ -352,7 +352,7 @@ void kasan_unpoison_vmalloc(const void *start, unsigned long size)
>  	if (!is_vmalloc_or_module_addr(start))
>  		return;
>  
> -	kasan_unpoison(start, size);
> +	kasan_unpoison(start, size, false);
>  }
>  
>  static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index 94c2d33be333..bd0c64d4e4d9 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -159,7 +159,7 @@ EXPORT_SYMBOL(__hwasan_storeN_noabort);
>  
>  void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
>  {
> -	kasan_poison((void *)addr, size, tag);
> +	kasan_poison((void *)addr, size, tag, false);
>  }
>  EXPORT_SYMBOL(__hwasan_tag_memory);
>  
> -- 
> 2.30.1.766.gb4fecdf3b7-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEYJ0%2BfmJykM0gjJ%40elver.google.com.
