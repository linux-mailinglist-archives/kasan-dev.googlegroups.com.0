Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPU7TGBAMGQE4V3UWBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 83EE233134D
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 17:24:31 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id d11sf3535143lfe.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 08:24:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615220671; cv=pass;
        d=google.com; s=arc-20160816;
        b=03kfoHF33TRsUeClfcyEaD6La7qyRsEcsanhigQA1jJec/QPzlv84LOz9CLcd0zwWn
         PASa5zcG5ha7VU3EX9l53XAZhu3m/vxR7VAT6zSmx+akdX24VGZcVzOdQURKT+a9E3Wa
         GuX6ntb10Kkq+FxAHPpexw/skbO39aasYitQPLpXeZY6GcRv/B9TBm6j4Krh1JaUgAOz
         XhNQroVqZqXiaPgypK8JpSE+a1Xa9/rdFQc7rjkbsX4WF0ALX9dieI70c+mE/xKPJ1O9
         B+xHz+HhbJkXVc4q3jGWo8zSGAQEA9Pl36RKwJvfMTB5+5tWaseBdVcyL+uF87/W1SmK
         enWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=pohEXmOGPhbJHuOc+Q942P01Ypwj1J140yeJ+h/cW6A=;
        b=qWqhhpBExa0gl4ECVtDlzgkrKZinDVLbb8XNNiyJi7yCvlAn9EZo6s39ChcPLNeYkj
         SHLDP5dIi6vlfr6Er+2CIELeVMXpdOVjnvuNO1mb4lMmFmZJb2H+xwxJNMbo+BKur68J
         gYmijYWw10F6520ImQ85G7QE+OtWYxyTRnJ+T6/4MaSh8poAzIUbwd35mVeYafKzumEd
         Orzwx3wE3u38YaegRmA9pOEHmCKobgXhuht6OWb/qZ0rOcy1uDX8UpGH63LVLA0B9NiR
         uR1C6GhqNpI70fvBFWXgZaO1KG2xci4ucBj38VmhnUkHStepvRcvMgD5GIg2X/u5DrU0
         0aEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jD8zkG1K;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pohEXmOGPhbJHuOc+Q942P01Ypwj1J140yeJ+h/cW6A=;
        b=nMo/w/wy0Y85nR4Mvf9TmwXGu4Zugyw8F3JzmMfo2RH6D6e2C28NI+2Tbk53EdI91F
         tvPTsMbuVkfPsjgmSq6RgJbOVYRvBdzK9nYOFKmYe9VuxJs9YTW58ungaX2cSwgMsher
         xpaxU9C3mrJpKY+mOUo+wK7bjWhU599mHZDOzBkhuD0ipNhKe+zpqvQSkmHaZDAE3xhb
         vyzsxS9VW9sNmNeYJmUdoCc4WuunsYKaLAnRIVIcYFznUJnl8zvQrdT2+xffun86hGnG
         r96m9JchJ+5ambHf7FXQiR/9iBLvWBJ32qAYHkFuAuBVWqyLe8pbdh68xP0ViHKZqjKc
         aiWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pohEXmOGPhbJHuOc+Q942P01Ypwj1J140yeJ+h/cW6A=;
        b=hEPQRjF384FKqWweBe370Q8Pg2TpAxqJmYpxI/PedTgnfPZgZP5RsRBvvRtrU5zi9z
         OyhaNEvu4ly08PUQQ1/OQj8EpOqvFbYDvW4xhQ0TQ3tv9BCVuB4gJfx8Vm7cLiuuOlRz
         YlkJ19ngTgBsrgY46km0syCXPRu5Z9va0YhUzkSjJ/c9VGi0qBH33+wixJ/HtyYeHBgk
         f0ueATjYmghmzM/2uHTL5DSn4ONxUsFfUqi95rcSRkQ0qNdFnbf2/UvdrpdkdXqWgDHh
         cWqP5fPncYw5I6wMXwi3V8xXpEmzcDhDBrOFO89XWyeaXh+iKx0/SGaBzlHQ+TZxkK1v
         z4gQ==
X-Gm-Message-State: AOAM5310AVJ59tOLWhZNMdzsbyeQ9SJ/xiTgvG9V7IUXgsB7+CUYr+sW
	PNO0v6iPRTcbzJlVuLfOnbE=
X-Google-Smtp-Source: ABdhPJz8RuBJk5dkxEGkqxFYgMV7CjaJ6hlrRioQzhYjIBz2kpSLbjVGHKUm318d4aKtSRMfIgwV4Q==
X-Received: by 2002:a2e:9204:: with SMTP id k4mr14240782ljg.203.1615220671115;
        Mon, 08 Mar 2021 08:24:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls1076207lfu.3.gmail; Mon,
 08 Mar 2021 08:24:30 -0800 (PST)
X-Received: by 2002:a19:5f0b:: with SMTP id t11mr14831674lfb.193.1615220669920;
        Mon, 08 Mar 2021 08:24:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615220669; cv=none;
        d=google.com; s=arc-20160816;
        b=pNtF0hsEnEwz9HuApCpzFiWWgnoocNVFkBLToODdfWnpFUgIoUfZ1sr0TIzxeurXrl
         xkAzeNG/TiDRXbGcRQnXZSyOhmH99H1GNUCW2zseMWgeysyk64b9HUUihPv+BFC9M/0y
         0mN7XsLbcGfS1daxMS7Q9x0nSYxCG6MYxqv4xZgc7U8kZshQjOFTDtOhE8g64fWpe+B8
         pkpBZE9mYoHO6s9bD3CKNGV1Wxb43PV6D5UZ8YHw8rIsxOxI/Y0eH70BQmsX9LGpX7Jd
         mgqo8/8AvcbJwERtjzwpdE51k00gOUghKvNXXvrmGqTNTgbUcxPsT4wNir3IJV8HQCTC
         26iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=IOyvlLCqYFrpnxgwF1LxML8x1YXFbGS+oZXfnAp6uWQ=;
        b=QTlEnuOPB8rwessfJujRSrSv+7SYWNKT1wRXLDylaBNJOI8ugVuzRZwhkdtAOR8k4M
         5AsJBGdRde12n+mOjx+4gknOgwyplc8IEYyTH6MhffIlo4wBCW09Squltr3gGqvsHjKq
         zwrnK+VsfzPk1cywg1eOJISU3its7jn8k4BrFtWw2a8dyUSBFrEZ9pyIvCbPRg1NM284
         IPHwdnuQAbvgAAsCUQTXniDJLGxO22bJSlwp+ITSw/6iI97lFfIsSnSC2PakH95IlTN1
         eZfkyl7XQciAJkzt0x/zC2Swrs7yZB1WZ9UwhabPOwpR8b9tg04NNXNzr7/3S1S8PgEC
         E0DQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jD8zkG1K;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id 63si270508lfd.1.2021.03.08.08.24.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 08:24:29 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id b18so12094581wrn.6
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 08:24:29 -0800 (PST)
X-Received: by 2002:a5d:47ab:: with SMTP id 11mr23754002wrb.153.1615220669148;
        Mon, 08 Mar 2021 08:24:29 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:9d1d:b6a0:d116:531b])
        by smtp.gmail.com with ESMTPSA id g5sm4195360wrq.30.2021.03.08.08.24.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Mar 2021 08:24:28 -0800 (PST)
Date: Mon, 8 Mar 2021 17:24:22 +0100
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
Subject: Re: [PATCH v2 4/5] kasan, mm: integrate slab init_on_alloc with
 HW_TAGS
Message-ID: <YEZPttHc1Jw6ksYa@elver.google.com>
References: <cover.1615218180.git.andreyknvl@google.com>
 <027a5988eb8de20cee1595e65a754072fdfcdb1c.1615218180.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <027a5988eb8de20cee1595e65a754072fdfcdb1c.1615218180.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jD8zkG1K;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as
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

This is a pretty intrusive change to the internal slab APIs. However, I
think this is a positive cleanup, removing some code duplication, so I
hope this is the right thing to do.

> To avoid discrepancies with which memory gets initialized that can be
> caused by future changes, both KASAN hook and initialization memset()
> are put together and a warning comment is added.
> 
> Combining setting allocation tags with memory initialization improves
> HW_TAGS KASAN performance when init_on_alloc is enabled.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

The code looks fine to me, but there are some non-obvious changes to the
internal slab APIs, so I'd wait a bit more to see if we missed
something.

> ---
>  include/linux/kasan.h |  8 ++++----
>  mm/kasan/common.c     |  4 ++--
>  mm/slab.c             | 28 +++++++++++++---------------
>  mm/slab.h             | 17 +++++++++++++----
>  mm/slub.c             | 27 +++++++++++----------------
>  5 files changed, 43 insertions(+), 41 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index c89613caa8cf..85f2a8786606 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -226,12 +226,12 @@ static __always_inline void kasan_slab_free_mempool(void *ptr)
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
> @@ -320,7 +320,7 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object)
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
> index 076582f58f68..c6f0e55a674a 100644
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
> +	 * As memory initialization might be integrated into KASAN,
> +	 * kasan_slab_alloc and initialization memset must be
> +	 * kept together to avoid discrepancies in behavior.
> +	 *
> +	 * As p[i] might get tagged, memset and kmemleak hook come after KASAN.
> +	 */
>  	for (i = 0; i < size; i++) {
> -		p[i] = kasan_slab_alloc(s, p[i], flags);
> -		/* As p[i] might get tagged, call kmemleak hook after KASAN. */
> +		p[i] = kasan_slab_alloc(s, p[i], flags, init);
> +		if (p[i] && init && !kasan_has_integrated_init())
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEZPttHc1Jw6ksYa%40elver.google.com.
