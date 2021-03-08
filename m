Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2VATGBAMGQEAFGWXUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 32A87331358
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 17:27:23 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id jo6sf4300705ejb.13
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 08:27:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615220843; cv=pass;
        d=google.com; s=arc-20160816;
        b=bGsbVnFTDKoYXDQEgUUCyJOUpCBWDtJoTnCCJLhqpSVAKSs2nEWs/jTWNqHquhfNDO
         q/dADNUe5fgEYqXkmYpocNBC6/hGjUIv8BLWf1XNma1GyerpDQZnBYfo8qFwlnZjw0U/
         K8K8rPsQ4HqGMbLbdiKYsEMLTpGegB+EJXqAsNorUOaGRjXKuem951PYt5aXulK3Xtu4
         hRJ9Loz6IUsVkHGcqudgEREVBhTN0LJy1LFW3AghYS7AR7miUSkb2TnGxfCTLH3iFXcZ
         0XkHxHVeeAWULWQ0hZGDijLxuBEhodXWmA/wsyXWtw/M5FWbBBYVtoFoSyd1Wmv3/ZQp
         Pvmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=QrXCIio8ih5zfUqnYVibEoObV3tPZ3DnB8lNJRJ48Ac=;
        b=oEuZ8oUpgaz1SoFCsOhtMXpdp0EdXRAv3/RVW+h5StPe82p/0dYfZm5WK2/0iszvmx
         IEyjZWcmCknpqeLrn2ICCGQ5O2bzfpgDdoPPhdfAp0s9Wrg6ehlK4+VgGSDxI6GrJJhn
         qHZspcu/ffuWQzdU7/swzCs01t4k652r8dd2shTivVQnv1jAMq4UKoS30KsBOA4/AbKn
         W9kZf+fDvbP/WtoIApLYqrimiX1DtXsdDjtVnH5ifvzy+E9C2j63MOUgiX4OvMxPA4yQ
         Jv74Gdyu8pcliUZLmFQz56CvtCFREEtETLxKIX0TI7rNcr/OauV91NJwwsubgbXKHgC+
         t5eQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g4jVQNVT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=QrXCIio8ih5zfUqnYVibEoObV3tPZ3DnB8lNJRJ48Ac=;
        b=YQhoHz4QiePi7Rxsc2Li7vao3eHoI31HmRXoQ6KSXLFsc35Sg+vPwedNTR0UjtPbW5
         OMFo0kCgKqtygPnyYC+gF7Bk+NSL1mu+qKQ5G2NgNrvf86H9RhrZfQnlXClvlD5xTHw6
         pQ257SoFUm9pjW88ult0pn1S2DhJQll+XnCwAvDxN7+6wxdfclIVWETfsVXyF46HHLMk
         kuFnfehUblky1WO6T81QPAI8Vu5AvFolBPDMO/hiNqgbJOJXTOqnKOjMRuu3RRgEcuaB
         celoG6jFlTdE99exVD7akeRH72FP/qREuuvs/hNuQNY/yf3ljWxEK3LEyxACWKE3/cxK
         vOgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QrXCIio8ih5zfUqnYVibEoObV3tPZ3DnB8lNJRJ48Ac=;
        b=A7JqYxbvW+AB2vRip9BOXJu64BPozQOAvdvjMCVzaxhDyKj6cASZjiUMnK+r/9MN+H
         9cLl8I0bD8Ald3sOYddIxxXeNrZTAvu0JCAHyPJ87yQ84bLpc+E7Y6j65IngarmL3gAG
         cNZBph6HFrPJ/sdHbLqSOf6EVpZV0wqWAjFtSDAiz0Stq/0LAK7vito5T4bHEG9U4131
         sXWYdphRA8IoUspdqN5bXSe4HfROTMFZOU1ILO5edRVJfTquJRYsTw6FZAIX3jJDCVXF
         JHZ/rr1HRAzI4IlGiYk7MrDE6B8Ocz6RjIDYW5C5U3otbo2OhR08lNxlcre0wN0pHS6S
         K0xA==
X-Gm-Message-State: AOAM532nb9QXH+eGlAyLOo6Bil0COC8cZSFPO0yc7hTfjvvKafpA2HbQ
	G2B0cmgsq8i6OKhg7KEqTqc=
X-Google-Smtp-Source: ABdhPJzT6XzUi+NgDJBdaookrDcVQjdixNpDj5qzPvR09aS8zL3mlUVuaIG2/Fd1KuSNIg7gmZn0bg==
X-Received: by 2002:a17:907:1b1f:: with SMTP id mp31mr15670624ejc.348.1615220842993;
        Mon, 08 Mar 2021 08:27:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:50cd:: with SMTP id h13ls7699579edb.3.gmail; Mon,
 08 Mar 2021 08:27:21 -0800 (PST)
X-Received: by 2002:aa7:de82:: with SMTP id j2mr23064631edv.313.1615220841853;
        Mon, 08 Mar 2021 08:27:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615220841; cv=none;
        d=google.com; s=arc-20160816;
        b=WDoWi1cdq/Ib+R8bYUZ5meCrofqJDCshreh9WQw44qvKvIcONoz6HcuEARgMZsatmS
         PrOOZkCXfmk2D6QJ1uwQgtzyQOqNvHd9PmSl9jiq3UgqVXVElAB3IfIsu2reJvr0afGq
         1NJXA2AXMw2rmp0zPY+LfrRjYN3M7WQCseyZHwQ06gmsU4wKa3CNdsDjjJf0GDn1RSiW
         HUKautN32vzuR/LWdv7rzYrBxDrbnIhg2yXr/2UMIse/OOR2Phdliu55s0Scn3Q3+awb
         lDB7FrO8PiemeGV3+AJvDtJsGDNt7ZzX7p+xQgBUPpO2GgoVlP40c9vj+EIu22Tm0lvb
         zqaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=IiyDYjHRKW2wceZv/UNYcoAbgvHVesLsvlpudR7A0lk=;
        b=WHcAyPlSgChHoNEj6vKCoV7a4qa1QROcpJ5sXBvWnN5wC6mVOYoFoQzfG1HIA1USCf
         DZ24Inlo2955qF7AVgoJPK80T0Ft5xXlNdAfvfQbo6MSjFR9r3R0HkSuli2rUfY13Yof
         XP2wz38TdryvP5o26SRo0uLuEb8Uko3A24BhO5av7WyLcRm/4uXt/DW79qhGMLWMIXpp
         2pFTBkHb8zu02n2NMdkGiw2CIHvXDgY54+B2xJ/eCGdxeyiTP6Md3sx8WZ4Q+0L8pOhV
         WLtjKb5vI2+n2UkOSdgeK5YTGEMk8vOV7LyKj96d0e+38YOzqFS05FUoiMOijeKyZxmP
         u4sQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g4jVQNVT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id w5si106015edv.1.2021.03.08.08.27.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 08:27:21 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id t5-20020a1c77050000b029010e62cea9deso4179527wmi.0
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 08:27:21 -0800 (PST)
X-Received: by 2002:a1c:4c17:: with SMTP id z23mr23208338wmf.17.1615220841452;
        Mon, 08 Mar 2021 08:27:21 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:9d1d:b6a0:d116:531b])
        by smtp.gmail.com with ESMTPSA id 36sm21063862wrh.94.2021.03.08.08.27.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Mar 2021 08:27:20 -0800 (PST)
Date: Mon, 8 Mar 2021 17:27:15 +0100
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
Subject: Re: [PATCH v2 5/5] kasan, mm: integrate slab init_on_free with
 HW_TAGS
Message-ID: <YEZQY2knlfz2Ku8w@elver.google.com>
References: <cover.1615218180.git.andreyknvl@google.com>
 <fe28431edf155e4749cd0f0b25c957f50744914d.1615218180.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fe28431edf155e4749cd0f0b25c957f50744914d.1615218180.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=g4jVQNVT;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as
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
> of HW_TAGS KASAN routines for slab memory when init_on_free is enabled.
> 
> With this change, memory initialization memset() is no longer called
> when both HW_TAGS KASAN and init_on_free are enabled. Instead, memory
> is initialized in KASAN runtime.
> 
> For SLUB, the memory initialization memset() is moved into
> slab_free_hook() that currently directly follows the initialization loop.
> A new argument is added to slab_free_hook() that indicates whether to
> initialize the memory or not.
> 
> To avoid discrepancies with which memory gets initialized that can be
> caused by future changes, both KASAN hook and initialization memset()
> are put together and a warning comment is added.
> 
> Combining setting allocation tags with memory initialization improves
> HW_TAGS KASAN performance when init_on_free is enabled.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

But same as other patch, given the internal API change, let's see if
somebody else responds.

> ---
>  include/linux/kasan.h | 10 ++++++----
>  mm/kasan/common.c     | 13 +++++++------
>  mm/slab.c             | 15 +++++++++++----
>  mm/slub.c             | 43 ++++++++++++++++++++++++-------------------
>  4 files changed, 48 insertions(+), 33 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 85f2a8786606..ed08c419a687 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -203,11 +203,13 @@ static __always_inline void * __must_check kasan_init_slab_obj(
>  	return (void *)object;
>  }
>  
> -bool __kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
> -static __always_inline bool kasan_slab_free(struct kmem_cache *s, void *object)
> +bool __kasan_slab_free(struct kmem_cache *s, void *object,
> +			unsigned long ip, bool init);
> +static __always_inline bool kasan_slab_free(struct kmem_cache *s,
> +						void *object, bool init)
>  {
>  	if (kasan_enabled())
> -		return __kasan_slab_free(s, object, _RET_IP_);
> +		return __kasan_slab_free(s, object, _RET_IP_, init);
>  	return false;
>  }
>  
> @@ -313,7 +315,7 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
>  {
>  	return (void *)object;
>  }
> -static inline bool kasan_slab_free(struct kmem_cache *s, void *object)
> +static inline bool kasan_slab_free(struct kmem_cache *s, void *object, bool init)
>  {
>  	return false;
>  }
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 7ea747b18c26..623cf94288a2 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -322,8 +322,8 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
>  	return (void *)object;
>  }
>  
> -static inline bool ____kasan_slab_free(struct kmem_cache *cache,
> -				void *object, unsigned long ip, bool quarantine)
> +static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
> +				unsigned long ip, bool quarantine, bool init)
>  {
>  	u8 tag;
>  	void *tagged_object;
> @@ -351,7 +351,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache,
>  	}
>  
>  	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
> -			KASAN_KMALLOC_FREE, false);
> +			KASAN_KMALLOC_FREE, init);
>  
>  	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine))
>  		return false;
> @@ -362,9 +362,10 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache,
>  	return kasan_quarantine_put(cache, object);
>  }
>  
> -bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
> +bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> +				unsigned long ip, bool init)
>  {
> -	return ____kasan_slab_free(cache, object, ip, true);
> +	return ____kasan_slab_free(cache, object, ip, true, init);
>  }
>  
>  static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
> @@ -409,7 +410,7 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
>  			return;
>  		kasan_poison(ptr, page_size(page), KASAN_FREE_PAGE, false);
>  	} else {
> -		____kasan_slab_free(page->slab_cache, ptr, ip, false);
> +		____kasan_slab_free(page->slab_cache, ptr, ip, false, false);
>  	}
>  }
>  
> diff --git a/mm/slab.c b/mm/slab.c
> index 936dd686dec9..3adfe5bc3e2e 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -3425,17 +3425,24 @@ static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
>  static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
>  					 unsigned long caller)
>  {
> +	bool init;
> +
>  	if (is_kfence_address(objp)) {
>  		kmemleak_free_recursive(objp, cachep->flags);
>  		__kfence_free(objp);
>  		return;
>  	}
>  
> -	if (unlikely(slab_want_init_on_free(cachep)))
> +	/*
> +	 * As memory initialization might be integrated into KASAN,
> +	 * kasan_slab_free and initialization memset must be
> +	 * kept together to avoid discrepancies in behavior.
> +	 */
> +	init = slab_want_init_on_free(cachep);
> +	if (init && !kasan_has_integrated_init())
>  		memset(objp, 0, cachep->object_size);
> -
> -	/* Put the object into the quarantine, don't touch it for now. */
> -	if (kasan_slab_free(cachep, objp))
> +	/* KASAN might put objp into memory quarantine, delaying its reuse. */
> +	if (kasan_slab_free(cachep, objp, init))
>  		return;
>  
>  	/* Use KCSAN to help debug racy use-after-free. */
> diff --git a/mm/slub.c b/mm/slub.c
> index f53df23760e3..37afe6251bcc 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -1532,7 +1532,8 @@ static __always_inline void kfree_hook(void *x)
>  	kasan_kfree_large(x);
>  }
>  
> -static __always_inline bool slab_free_hook(struct kmem_cache *s, void *x)
> +static __always_inline bool slab_free_hook(struct kmem_cache *s,
> +						void *x, bool init)
>  {
>  	kmemleak_free_recursive(x, s->flags);
>  
> @@ -1558,8 +1559,25 @@ static __always_inline bool slab_free_hook(struct kmem_cache *s, void *x)
>  		__kcsan_check_access(x, s->object_size,
>  				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
>  
> -	/* KASAN might put x into memory quarantine, delaying its reuse */
> -	return kasan_slab_free(s, x);
> +	/*
> +	 * As memory initialization might be integrated into KASAN,
> +	 * kasan_slab_free and initialization memset's must be
> +	 * kept together to avoid discrepancies in behavior.
> +	 *
> +	 * The initialization memset's clear the object and the metadata,
> +	 * but don't touch the SLAB redzone.
> +	 */
> +	if (init) {
> +		int rsize;
> +
> +		if (!kasan_has_integrated_init())
> +			memset(kasan_reset_tag(x), 0, s->object_size);
> +		rsize = (s->flags & SLAB_RED_ZONE) ? s->red_left_pad : 0;
> +		memset((char *)kasan_reset_tag(x) + s->inuse, 0,
> +		       s->size - s->inuse - rsize);
> +	}
> +	/* KASAN might put x into memory quarantine, delaying its reuse. */
> +	return kasan_slab_free(s, x, init);
>  }
>  
>  static inline bool slab_free_freelist_hook(struct kmem_cache *s,
> @@ -1569,10 +1587,9 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
>  	void *object;
>  	void *next = *head;
>  	void *old_tail = *tail ? *tail : *head;
> -	int rsize;
>  
>  	if (is_kfence_address(next)) {
> -		slab_free_hook(s, next);
> +		slab_free_hook(s, next, false);
>  		return true;
>  	}
>  
> @@ -1584,20 +1601,8 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
>  		object = next;
>  		next = get_freepointer(s, object);
>  
> -		if (slab_want_init_on_free(s)) {
> -			/*
> -			 * Clear the object and the metadata, but don't touch
> -			 * the redzone.
> -			 */
> -			memset(kasan_reset_tag(object), 0, s->object_size);
> -			rsize = (s->flags & SLAB_RED_ZONE) ? s->red_left_pad
> -							   : 0;
> -			memset((char *)kasan_reset_tag(object) + s->inuse, 0,
> -			       s->size - s->inuse - rsize);
> -
> -		}
>  		/* If object's reuse doesn't have to be delayed */
> -		if (!slab_free_hook(s, object)) {
> +		if (!slab_free_hook(s, object, slab_want_init_on_free(s))) {
>  			/* Move object to the new freelist */
>  			set_freepointer(s, object, *head);
>  			*head = object;
> @@ -3235,7 +3240,7 @@ int build_detached_freelist(struct kmem_cache *s, size_t size,
>  	}
>  
>  	if (is_kfence_address(object)) {
> -		slab_free_hook(df->s, object);
> +		slab_free_hook(df->s, object, false);
>  		__kfence_free(object);
>  		p[size] = NULL; /* mark object processed */
>  		return size;
> -- 
> 2.30.1.766.gb4fecdf3b7-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEZQY2knlfz2Ku8w%40elver.google.com.
