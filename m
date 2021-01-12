Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQUL637QKGQE5OPPJNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id AC5B42F2DC5
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 12:19:30 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id a9sf851363edy.8
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 03:19:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610450370; cv=pass;
        d=google.com; s=arc-20160816;
        b=dQrQBfxPJz3VhCsEFhhMgptOKzxcNsFGge+6S9ZEN+Lu4jlgubKRN8SQknb7pD0wXU
         W2ffeAbm80K1NvFLkLlwsziu9bjns41ZlXsb0qKvluCfBF2YfYq9BRUC44sTNkFyr+K1
         HOTviOfSMjyR0Rw2lgqAUULny9a1rIrv+joF31gEK2WH60ut7HT6DooiR9MET9b/vVf6
         jhQNAU3TgtWf/HQY4peCWw1krkQu2R3gfSohXvikD1RvOqP6uc6fDw06dJ3MOrGeyQX3
         DumQQqS2JC43xbW3q/jSXugbEz+DEkos920xeVRvs7spB7AY7NwYXoifEghNwCkcATQy
         uFHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=2n2Fj2e2AoqlMHrJMTsKeLK36FftEzUgXXMuayvJnDc=;
        b=SwQyRXH89El3UF7ktioCRHj5tjBMXKifh2MqOHIbwNHRyOZL8GzTq+VRbJfLN4jieu
         rPGzt7LIyVXDqLLB9oySN9SJhmHyHDvId4dQ3A9y6/IBBirdNo2bdWygG+m3hUoHNE4Y
         XuL0w6AK+19R8b4sD9N3ooFci1WvX+2SldiSHe4pmYvNqgra5c4w3FGHxzIiGEHBJURf
         jBeUqxPlY4OqdMdmHtJ3fSZeStBqJjM0tJLEKB5dagGb6RiqdYQoMvZZf3WaEIMBcB5K
         j1bg3Cx6KcMMS5Wv1mtY1UVB882/f0JOxoDg3u8DGgwMyt7DhZcVUrCqM9/dlJt8Zjkr
         oU7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y8EY9Ib5;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=2n2Fj2e2AoqlMHrJMTsKeLK36FftEzUgXXMuayvJnDc=;
        b=lNxfKB+7u0lB4Hvp6RLHgHovw8bdNAX3G34SMaISzUL2RoQA9AKfqn0RcQJGyfTteL
         DG+ZCtlyQ3XrdTTeCl7bM7I9xkJNj8hbExP1glB8XBnJwPKnvSaSCp+iQGDyBmI5IrHo
         ByTFeDME8ayP8BYKT4kJapek9Fx9v4TiPxX2Ce78FhZAss0ScFll3A+16a5xcnlOwFn0
         8+os1vP/xEy98eSWTOPXwamcV6B+VFu3530m4oF4WgnDvER8D2uHrhLSikD/EWt48tgy
         a8anV4DcB9iTAQOlIhrUX93rQZ3r5EfdfQeyuTH2CekONPaziXv9L0ooNWtnA+XVt4yu
         fpSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2n2Fj2e2AoqlMHrJMTsKeLK36FftEzUgXXMuayvJnDc=;
        b=g3EA3vRqpIsiY14cATaEayw4pVLuZDC8/Bixr29ntGZqKyeAFKLEYiIV264pUaeL5w
         ukJ8PsHtetwCYDk5aqKaG1tL3OuTbJdEeHW0Z30iMdpj9jYpD7I6rY4dPkEmEvtpoLOQ
         zBmi5u8dtYpsAvQlLZDHR9QZQ4vfc5Lnm1mEcZ3e5MdKKAyBz2Giw7vHPw3fIbGidQRr
         0SkWn/9+ayXr6wPdj1H5sWz+PUNRbhrqCkuV7LEB0J4hw8wECYV4NiXSMQAlAGAApZ9H
         hXq2betA4IV9oja/AEcuVzLBq4zDuRIuV+kn/pxIv809KUAHzayuW6lU4Ze2SIikLh4f
         iAVA==
X-Gm-Message-State: AOAM530Iv5af0a++sC0pU3edHw1QIX3cd9vjAbBpZK3bsqQ0RQTPZtY3
	oMlGzWZXtL6r1RyhvaMtcus=
X-Google-Smtp-Source: ABdhPJzsvlX2m68hlPvWZtgEXZOs75KOA0FdeRL2Ntn4wllhwUP4Nz8Y3oD+tnqeorb1lGTKZNmBJA==
X-Received: by 2002:a17:906:c09:: with SMTP id s9mr2821321ejf.539.1610450370374;
        Tue, 12 Jan 2021 03:19:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:fd15:: with SMTP id i21ls3028408eds.1.gmail; Tue, 12 Jan
 2021 03:19:29 -0800 (PST)
X-Received: by 2002:a05:6402:3487:: with SMTP id v7mr456193edc.68.1610450369243;
        Tue, 12 Jan 2021 03:19:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610450369; cv=none;
        d=google.com; s=arc-20160816;
        b=mObFSjG36iwnajLZPwsxAQ3WBUkWhPP/i086ogJmYHYC82i1iucNdZvcy7p9Ce7hvr
         cz/mwUzKZMJM5ltkGab6Up94RVdZpDMhQjdq4J/T2CMmHTPuxSUj32pFQc3DShp7Pa3D
         EUvyKfy22nv26tH/o8KzjxgKILQ0/IeoshVDOmYIuWu0Rtt8vFJonU96n2MG3J3dJGSJ
         8sUk9Lfo1aqVKQ1pMXuHbHFNVsB2qK87grZ4epqQOk6e/T5lwkw3IaiX0G2WbZONmLQD
         AzlM/tWshydKlis7/aEZ6OqGHFLCwSvb+uogKni6hKjm7nZzmDsZsvwozm7lDt22QsQA
         Lg8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=JlgETDYBJm6KAGOKgYxU/vTzEch+cdz+/5c0n5ZcQqY=;
        b=vMft5pgodDxDqRTXiOmeT8W9yU7aFn7SprO1rIwdJVASMx6BdoA4eLW0hBVCQ+2t8H
         A5lqgjx8Y2BNwCYfg6NcsaGCXYGLsJQC1AWwbB0T1gQzujunHNwhkPmilevFz4WuGWhP
         eykSLBibGmJTiLWwlEI9XmVHgZNWfGIPCV4OCn208Co/kI1obeRJVHXOipqR5AQo9ZRd
         udDC8hRwSGPnXT6ITpyap/1UjqOUzhNGDFYI9bljeoi2LDOUdo1Hyjn6779sGEAIarqg
         rOwzIpnjN4o689h9fbufqN9TAYCxiA3R+XegxTIxvZWZkp7mSg2OgQ6O4FrnNuVCfO8I
         pfaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y8EY9Ib5;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id d9si152875edr.1.2021.01.12.03.19.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 03:19:29 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id a12so2067883wrv.8
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 03:19:29 -0800 (PST)
X-Received: by 2002:a05:6000:1882:: with SMTP id a2mr3671640wri.237.1610450368580;
        Tue, 12 Jan 2021 03:19:28 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id g194sm1929341wme.39.2021.01.12.03.19.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Jan 2021 03:19:27 -0800 (PST)
Date: Tue, 12 Jan 2021 12:19:22 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 01/11] kasan: prefix exported functions with kasan_
Message-ID: <X/2FujZsDMn49YvA@elver.google.com>
References: <cover.1609871239.git.andreyknvl@google.com>
 <ec89a6eef2254602f5134d676242c0da43fb4caa.1609871239.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ec89a6eef2254602f5134d676242c0da43fb4caa.1609871239.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Y8EY9Ib5;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as
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

Re subject: none of these seem to be exported (but they are global).

On Tue, Jan 05, 2021 at 07:27PM +0100, Andrey Konovalov wrote:
> There's a number of internal KASAN functions that are used across multiple
> source code files and therefore aren't marked as static inline. To avoid
> littering the kernel function names list with generic functions, prefix
> all such KASAN functions with kasan_.
> 
> As a part of this change:
> 
> - Rename internal (un)poison_range() to kasan_(un)poison() (no _range)
>   to avoid name collision with a public kasan_unpoison_range().
> 
> - Rename check_memory_region() to kasan_check_range(), as it seems to be
>   a more fitting name.
> 
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I719cc93483d4ba288a634dba80ee6b7f2809cd26

Reviewed-by: Marco Elver <elver@google.com>

Thank you!

> ---
>  mm/kasan/common.c         | 47 +++++++++++++++++++-------------------
>  mm/kasan/generic.c        | 36 ++++++++++++++---------------
>  mm/kasan/kasan.h          | 48 +++++++++++++++++++--------------------
>  mm/kasan/quarantine.c     | 22 +++++++++---------
>  mm/kasan/report.c         | 13 ++++++-----
>  mm/kasan/report_generic.c |  8 +++----
>  mm/kasan/report_hw_tags.c |  8 +++----
>  mm/kasan/report_sw_tags.c |  8 +++----
>  mm/kasan/shadow.c         | 26 ++++++++++-----------
>  mm/kasan/sw_tags.c        | 16 ++++++-------
>  tools/objtool/check.c     |  2 +-
>  11 files changed, 117 insertions(+), 117 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index b25167664ead..eedc3e0fe365 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -60,7 +60,7 @@ void kasan_disable_current(void)
>  
>  void __kasan_unpoison_range(const void *address, size_t size)
>  {
> -	unpoison_range(address, size);
> +	kasan_unpoison(address, size);
>  }
>  
>  #if CONFIG_KASAN_STACK
> @@ -69,7 +69,7 @@ void kasan_unpoison_task_stack(struct task_struct *task)
>  {
>  	void *base = task_stack_page(task);
>  
> -	unpoison_range(base, THREAD_SIZE);
> +	kasan_unpoison(base, THREAD_SIZE);
>  }
>  
>  /* Unpoison the stack for the current task beyond a watermark sp value. */
> @@ -82,7 +82,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
>  	 */
>  	void *base = (void *)((unsigned long)watermark & ~(THREAD_SIZE - 1));
>  
> -	unpoison_range(base, watermark - base);
> +	kasan_unpoison(base, watermark - base);
>  }
>  #endif /* CONFIG_KASAN_STACK */
>  
> @@ -105,18 +105,17 @@ void __kasan_alloc_pages(struct page *page, unsigned int order)
>  	if (unlikely(PageHighMem(page)))
>  		return;
>  
> -	tag = random_tag();
> +	tag = kasan_random_tag();
>  	for (i = 0; i < (1 << order); i++)
>  		page_kasan_tag_set(page + i, tag);
> -	unpoison_range(page_address(page), PAGE_SIZE << order);
> +	kasan_unpoison(page_address(page), PAGE_SIZE << order);
>  }
>  
>  void __kasan_free_pages(struct page *page, unsigned int order)
>  {
>  	if (likely(!PageHighMem(page)))
> -		poison_range(page_address(page),
> -				PAGE_SIZE << order,
> -				KASAN_FREE_PAGE);
> +		kasan_poison(page_address(page), PAGE_SIZE << order,
> +			     KASAN_FREE_PAGE);
>  }
>  
>  /*
> @@ -246,18 +245,18 @@ void __kasan_poison_slab(struct page *page)
>  
>  	for (i = 0; i < compound_nr(page); i++)
>  		page_kasan_tag_reset(page + i);
> -	poison_range(page_address(page), page_size(page),
> +	kasan_poison(page_address(page), page_size(page),
>  		     KASAN_KMALLOC_REDZONE);
>  }
>  
>  void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
>  {
> -	unpoison_range(object, cache->object_size);
> +	kasan_unpoison(object, cache->object_size);
>  }
>  
>  void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
>  {
> -	poison_range(object, cache->object_size, KASAN_KMALLOC_REDZONE);
> +	kasan_poison(object, cache->object_size, KASAN_KMALLOC_REDZONE);
>  }
>  
>  /*
> @@ -294,7 +293,7 @@ static u8 assign_tag(struct kmem_cache *cache, const void *object,
>  	 * set, assign a tag when the object is being allocated (init == false).
>  	 */
>  	if (!cache->ctor && !(cache->flags & SLAB_TYPESAFE_BY_RCU))
> -		return init ? KASAN_TAG_KERNEL : random_tag();
> +		return init ? KASAN_TAG_KERNEL : kasan_random_tag();
>  
>  	/* For caches that either have a constructor or SLAB_TYPESAFE_BY_RCU: */
>  #ifdef CONFIG_SLAB
> @@ -305,7 +304,7 @@ static u8 assign_tag(struct kmem_cache *cache, const void *object,
>  	 * For SLUB assign a random tag during slab creation, otherwise reuse
>  	 * the already assigned tag.
>  	 */
> -	return init ? random_tag() : get_tag(object);
> +	return init ? kasan_random_tag() : get_tag(object);
>  #endif
>  }
>  
> @@ -346,12 +345,12 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>  	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
>  		return false;
>  
> -	if (check_invalid_free(tagged_object)) {
> +	if (kasan_check_invalid_free(tagged_object)) {
>  		kasan_report_invalid_free(tagged_object, ip);
>  		return true;
>  	}
>  
> -	poison_range(object, cache->object_size, KASAN_KMALLOC_FREE);
> +	kasan_poison(object, cache->object_size, KASAN_KMALLOC_FREE);
>  
>  	if (!kasan_stack_collection_enabled())
>  		return false;
> @@ -361,7 +360,7 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>  
>  	kasan_set_free_info(cache, object, tag);
>  
> -	return quarantine_put(cache, object);
> +	return kasan_quarantine_put(cache, object);
>  }
>  
>  bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
> @@ -386,7 +385,7 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
>  			kasan_report_invalid_free(ptr, ip);
>  			return;
>  		}
> -		poison_range(ptr, page_size(page), KASAN_FREE_PAGE);
> +		kasan_poison(ptr, page_size(page), KASAN_FREE_PAGE);
>  	} else {
>  		____kasan_slab_free(page->slab_cache, ptr, ip, false);
>  	}
> @@ -409,7 +408,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  	u8 tag;
>  
>  	if (gfpflags_allow_blocking(flags))
> -		quarantine_reduce();
> +		kasan_quarantine_reduce();
>  
>  	if (unlikely(object == NULL))
>  		return NULL;
> @@ -421,9 +420,9 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  	tag = assign_tag(cache, object, false, keep_tag);
>  
>  	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
> -	unpoison_range(set_tag(object, tag), size);
> -	poison_range((void *)redzone_start, redzone_end - redzone_start,
> -		     KASAN_KMALLOC_REDZONE);
> +	kasan_unpoison(set_tag(object, tag), size);
> +	kasan_poison((void *)redzone_start, redzone_end - redzone_start,
> +			   KASAN_KMALLOC_REDZONE);
>  
>  	if (kasan_stack_collection_enabled())
>  		set_alloc_info(cache, (void *)object, flags);
> @@ -452,7 +451,7 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
>  	unsigned long redzone_end;
>  
>  	if (gfpflags_allow_blocking(flags))
> -		quarantine_reduce();
> +		kasan_quarantine_reduce();
>  
>  	if (unlikely(ptr == NULL))
>  		return NULL;
> @@ -462,8 +461,8 @@ void * __must_check __kasan_kmalloc_large(const void *ptr, size_t size,
>  				KASAN_GRANULE_SIZE);
>  	redzone_end = (unsigned long)ptr + page_size(page);
>  
> -	unpoison_range(ptr, size);
> -	poison_range((void *)redzone_start, redzone_end - redzone_start,
> +	kasan_unpoison(ptr, size);
> +	kasan_poison((void *)redzone_start, redzone_end - redzone_start,
>  		     KASAN_PAGE_REDZONE);
>  
>  	return (void *)ptr;
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 5106b84b07d4..acab8862dc67 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -158,7 +158,7 @@ static __always_inline bool memory_is_poisoned(unsigned long addr, size_t size)
>  	return memory_is_poisoned_n(addr, size);
>  }
>  
> -static __always_inline bool check_memory_region_inline(unsigned long addr,
> +static __always_inline bool check_region_inline(unsigned long addr,
>  						size_t size, bool write,
>  						unsigned long ret_ip)
>  {
> @@ -179,13 +179,13 @@ static __always_inline bool check_memory_region_inline(unsigned long addr,
>  	return !kasan_report(addr, size, write, ret_ip);
>  }
>  
> -bool check_memory_region(unsigned long addr, size_t size, bool write,
> -				unsigned long ret_ip)
> +bool kasan_check_range(unsigned long addr, size_t size, bool write,
> +					unsigned long ret_ip)
>  {
> -	return check_memory_region_inline(addr, size, write, ret_ip);
> +	return check_region_inline(addr, size, write, ret_ip);
>  }
>  
> -bool check_invalid_free(void *addr)
> +bool kasan_check_invalid_free(void *addr)
>  {
>  	s8 shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
>  
> @@ -194,22 +194,22 @@ bool check_invalid_free(void *addr)
>  
>  void kasan_cache_shrink(struct kmem_cache *cache)
>  {
> -	quarantine_remove_cache(cache);
> +	kasan_quarantine_remove_cache(cache);
>  }
>  
>  void kasan_cache_shutdown(struct kmem_cache *cache)
>  {
>  	if (!__kmem_cache_empty(cache))
> -		quarantine_remove_cache(cache);
> +		kasan_quarantine_remove_cache(cache);
>  }
>  
>  static void register_global(struct kasan_global *global)
>  {
>  	size_t aligned_size = round_up(global->size, KASAN_GRANULE_SIZE);
>  
> -	unpoison_range(global->beg, global->size);
> +	kasan_unpoison(global->beg, global->size);
>  
> -	poison_range(global->beg + aligned_size,
> +	kasan_poison(global->beg + aligned_size,
>  		     global->size_with_redzone - aligned_size,
>  		     KASAN_GLOBAL_REDZONE);
>  }
> @@ -231,7 +231,7 @@ EXPORT_SYMBOL(__asan_unregister_globals);
>  #define DEFINE_ASAN_LOAD_STORE(size)					\
>  	void __asan_load##size(unsigned long addr)			\
>  	{								\
> -		check_memory_region_inline(addr, size, false, _RET_IP_);\
> +		check_region_inline(addr, size, false, _RET_IP_);	\
>  	}								\
>  	EXPORT_SYMBOL(__asan_load##size);				\
>  	__alias(__asan_load##size)					\
> @@ -239,7 +239,7 @@ EXPORT_SYMBOL(__asan_unregister_globals);
>  	EXPORT_SYMBOL(__asan_load##size##_noabort);			\
>  	void __asan_store##size(unsigned long addr)			\
>  	{								\
> -		check_memory_region_inline(addr, size, true, _RET_IP_);	\
> +		check_region_inline(addr, size, true, _RET_IP_);	\
>  	}								\
>  	EXPORT_SYMBOL(__asan_store##size);				\
>  	__alias(__asan_store##size)					\
> @@ -254,7 +254,7 @@ DEFINE_ASAN_LOAD_STORE(16);
>  
>  void __asan_loadN(unsigned long addr, size_t size)
>  {
> -	check_memory_region(addr, size, false, _RET_IP_);
> +	kasan_check_range(addr, size, false, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__asan_loadN);
>  
> @@ -264,7 +264,7 @@ EXPORT_SYMBOL(__asan_loadN_noabort);
>  
>  void __asan_storeN(unsigned long addr, size_t size)
>  {
> -	check_memory_region(addr, size, true, _RET_IP_);
> +	kasan_check_range(addr, size, true, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__asan_storeN);
>  
> @@ -290,11 +290,11 @@ void __asan_alloca_poison(unsigned long addr, size_t size)
>  
>  	WARN_ON(!IS_ALIGNED(addr, KASAN_ALLOCA_REDZONE_SIZE));
>  
> -	unpoison_range((const void *)(addr + rounded_down_size),
> -		       size - rounded_down_size);
> -	poison_range(left_redzone, KASAN_ALLOCA_REDZONE_SIZE,
> +	kasan_unpoison((const void *)(addr + rounded_down_size),
> +			size - rounded_down_size);
> +	kasan_poison(left_redzone, KASAN_ALLOCA_REDZONE_SIZE,
>  		     KASAN_ALLOCA_LEFT);
> -	poison_range(right_redzone, padding_size + KASAN_ALLOCA_REDZONE_SIZE,
> +	kasan_poison(right_redzone, padding_size + KASAN_ALLOCA_REDZONE_SIZE,
>  		     KASAN_ALLOCA_RIGHT);
>  }
>  EXPORT_SYMBOL(__asan_alloca_poison);
> @@ -305,7 +305,7 @@ void __asan_allocas_unpoison(const void *stack_top, const void *stack_bottom)
>  	if (unlikely(!stack_top || stack_top > stack_bottom))
>  		return;
>  
> -	unpoison_range(stack_top, stack_bottom - stack_top);
> +	kasan_unpoison(stack_top, stack_bottom - stack_top);
>  }
>  EXPORT_SYMBOL(__asan_allocas_unpoison);
>  
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index cc4d9e1d49b1..3b38baddec47 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -195,14 +195,14 @@ static inline bool addr_has_metadata(const void *addr)
>  }
>  
>  /**
> - * check_memory_region - Check memory region, and report if invalid access.
> + * kasan_check_range - Check memory region, and report if invalid access.
>   * @addr: the accessed address
>   * @size: the accessed size
>   * @write: true if access is a write access
>   * @ret_ip: return address
>   * @return: true if access was valid, false if invalid
>   */
> -bool check_memory_region(unsigned long addr, size_t size, bool write,
> +bool kasan_check_range(unsigned long addr, size_t size, bool write,
>  				unsigned long ret_ip);
>  
>  #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> @@ -215,19 +215,19 @@ static inline bool addr_has_metadata(const void *addr)
>  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>  
>  #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> -void print_tags(u8 addr_tag, const void *addr);
> +void kasan_print_tags(u8 addr_tag, const void *addr);
>  #else
> -static inline void print_tags(u8 addr_tag, const void *addr) { }
> +static inline void kasan_print_tags(u8 addr_tag, const void *addr) { }
>  #endif
>  
> -void *find_first_bad_addr(void *addr, size_t size);
> -const char *get_bug_type(struct kasan_access_info *info);
> -void metadata_fetch_row(char *buffer, void *row);
> +void *kasan_find_first_bad_addr(void *addr, size_t size);
> +const char *kasan_get_bug_type(struct kasan_access_info *info);
> +void kasan_metadata_fetch_row(char *buffer, void *row);
>  
>  #if defined(CONFIG_KASAN_GENERIC) && CONFIG_KASAN_STACK
> -void print_address_stack_frame(const void *addr);
> +void kasan_print_address_stack_frame(const void *addr);
>  #else
> -static inline void print_address_stack_frame(const void *addr) { }
> +static inline void kasan_print_address_stack_frame(const void *addr) { }
>  #endif
>  
>  bool kasan_report(unsigned long addr, size_t size,
> @@ -244,13 +244,13 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>  
>  #if defined(CONFIG_KASAN_GENERIC) && \
>  	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> -bool quarantine_put(struct kmem_cache *cache, void *object);
> -void quarantine_reduce(void);
> -void quarantine_remove_cache(struct kmem_cache *cache);
> +bool kasan_quarantine_put(struct kmem_cache *cache, void *object);
> +void kasan_quarantine_reduce(void);
> +void kasan_quarantine_remove_cache(struct kmem_cache *cache);
>  #else
> -static inline bool quarantine_put(struct kmem_cache *cache, void *object) { return false; }
> -static inline void quarantine_reduce(void) { }
> -static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
> +static inline bool kasan_quarantine_put(struct kmem_cache *cache, void *object) { return false; }
> +static inline void kasan_quarantine_reduce(void) { }
> +static inline void kasan_quarantine_remove_cache(struct kmem_cache *cache) { }
>  #endif
>  
>  #ifndef arch_kasan_set_tag
> @@ -293,28 +293,28 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  #endif /* CONFIG_KASAN_HW_TAGS */
>  
>  #ifdef CONFIG_KASAN_SW_TAGS
> -u8 random_tag(void);
> +u8 kasan_random_tag(void);
>  #elif defined(CONFIG_KASAN_HW_TAGS)
> -static inline u8 random_tag(void) { return hw_get_random_tag(); }
> +static inline u8 kasan_random_tag(void) { return hw_get_random_tag(); }
>  #else
> -static inline u8 random_tag(void) { return 0; }
> +static inline u8 kasan_random_tag(void) { return 0; }
>  #endif
>  
>  #ifdef CONFIG_KASAN_HW_TAGS
>  
> -static inline void poison_range(const void *address, size_t size, u8 value)
> +static inline void kasan_poison(const void *address, size_t size, u8 value)
>  {
>  	hw_set_mem_tag_range(kasan_reset_tag(address),
>  			round_up(size, KASAN_GRANULE_SIZE), value);
>  }
>  
> -static inline void unpoison_range(const void *address, size_t size)
> +static inline void kasan_unpoison(const void *address, size_t size)
>  {
>  	hw_set_mem_tag_range(kasan_reset_tag(address),
>  			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
>  }
>  
> -static inline bool check_invalid_free(void *addr)
> +static inline bool kasan_check_invalid_free(void *addr)
>  {
>  	u8 ptr_tag = get_tag(addr);
>  	u8 mem_tag = hw_get_mem_tag(addr);
> @@ -325,9 +325,9 @@ static inline bool check_invalid_free(void *addr)
>  
>  #else /* CONFIG_KASAN_HW_TAGS */
>  
> -void poison_range(const void *address, size_t size, u8 value);
> -void unpoison_range(const void *address, size_t size);
> -bool check_invalid_free(void *addr);
> +void kasan_poison(const void *address, size_t size, u8 value);
> +void kasan_unpoison(const void *address, size_t size);
> +bool kasan_check_invalid_free(void *addr);
>  
>  #endif /* CONFIG_KASAN_HW_TAGS */
>  
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 55783125a767..728fb24c5683 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -168,7 +168,7 @@ static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cache)
>  	qlist_init(q);
>  }
>  
> -bool quarantine_put(struct kmem_cache *cache, void *object)
> +bool kasan_quarantine_put(struct kmem_cache *cache, void *object)
>  {
>  	unsigned long flags;
>  	struct qlist_head *q;
> @@ -184,11 +184,11 @@ bool quarantine_put(struct kmem_cache *cache, void *object)
>  
>  	/*
>  	 * Note: irq must be disabled until after we move the batch to the
> -	 * global quarantine. Otherwise quarantine_remove_cache() can miss
> -	 * some objects belonging to the cache if they are in our local temp
> -	 * list. quarantine_remove_cache() executes on_each_cpu() at the
> -	 * beginning which ensures that it either sees the objects in per-cpu
> -	 * lists or in the global quarantine.
> +	 * global quarantine. Otherwise kasan_quarantine_remove_cache() can
> +	 * miss some objects belonging to the cache if they are in our local
> +	 * temp list. kasan_quarantine_remove_cache() executes on_each_cpu()
> +	 * at the beginning which ensures that it either sees the objects in
> +	 * per-cpu lists or in the global quarantine.
>  	 */
>  	local_irq_save(flags);
>  
> @@ -222,7 +222,7 @@ bool quarantine_put(struct kmem_cache *cache, void *object)
>  	return true;
>  }
>  
> -void quarantine_reduce(void)
> +void kasan_quarantine_reduce(void)
>  {
>  	size_t total_size, new_quarantine_size, percpu_quarantines;
>  	unsigned long flags;
> @@ -234,7 +234,7 @@ void quarantine_reduce(void)
>  		return;
>  
>  	/*
> -	 * srcu critical section ensures that quarantine_remove_cache()
> +	 * srcu critical section ensures that kasan_quarantine_remove_cache()
>  	 * will not miss objects belonging to the cache while they are in our
>  	 * local to_free list. srcu is chosen because (1) it gives us private
>  	 * grace period domain that does not interfere with anything else,
> @@ -309,15 +309,15 @@ static void per_cpu_remove_cache(void *arg)
>  }
>  
>  /* Free all quarantined objects belonging to cache. */
> -void quarantine_remove_cache(struct kmem_cache *cache)
> +void kasan_quarantine_remove_cache(struct kmem_cache *cache)
>  {
>  	unsigned long flags, i;
>  	struct qlist_head to_free = QLIST_INIT;
>  
>  	/*
>  	 * Must be careful to not miss any objects that are being moved from
> -	 * per-cpu list to the global quarantine in quarantine_put(),
> -	 * nor objects being freed in quarantine_reduce(). on_each_cpu()
> +	 * per-cpu list to the global quarantine in kasan_quarantine_put(),
> +	 * nor objects being freed in kasan_quarantine_reduce(). on_each_cpu()
>  	 * achieves the first goal, while synchronize_srcu() achieves the
>  	 * second.
>  	 */
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index c0fb21797550..e93d7973792e 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -61,7 +61,7 @@ __setup("kasan_multi_shot", kasan_set_multi_shot);
>  static void print_error_description(struct kasan_access_info *info)
>  {
>  	pr_err("BUG: KASAN: %s in %pS\n",
> -		get_bug_type(info), (void *)info->ip);
> +		kasan_get_bug_type(info), (void *)info->ip);
>  	if (info->access_size)
>  		pr_err("%s of size %zu at addr %px by task %s/%d\n",
>  			info->is_write ? "Write" : "Read", info->access_size,
> @@ -247,7 +247,7 @@ static void print_address_description(void *addr, u8 tag)
>  		dump_page(page, "kasan: bad access detected");
>  	}
>  
> -	print_address_stack_frame(addr);
> +	kasan_print_address_stack_frame(addr);
>  }
>  
>  static bool meta_row_is_guilty(const void *row, const void *addr)
> @@ -293,7 +293,7 @@ static void print_memory_metadata(const void *addr)
>  		 * function, because generic functions may try to
>  		 * access kasan mapping for the passed address.
>  		 */
> -		metadata_fetch_row(&metadata[0], row);
> +		kasan_metadata_fetch_row(&metadata[0], row);
>  
>  		print_hex_dump(KERN_ERR, buffer,
>  			DUMP_PREFIX_NONE, META_BYTES_PER_ROW, 1,
> @@ -350,7 +350,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
>  
>  	start_report(&flags);
>  	pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
> -	print_tags(tag, object);
> +	kasan_print_tags(tag, object);
>  	pr_err("\n");
>  	print_address_description(object, tag);
>  	pr_err("\n");
> @@ -378,7 +378,8 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>  
>  	info.access_addr = tagged_addr;
>  	if (addr_has_metadata(untagged_addr))
> -		info.first_bad_addr = find_first_bad_addr(tagged_addr, size);
> +		info.first_bad_addr =
> +			kasan_find_first_bad_addr(tagged_addr, size);
>  	else
>  		info.first_bad_addr = untagged_addr;
>  	info.access_size = size;
> @@ -389,7 +390,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>  
>  	print_error_description(&info);
>  	if (addr_has_metadata(untagged_addr))
> -		print_tags(get_tag(tagged_addr), info.first_bad_addr);
> +		kasan_print_tags(get_tag(tagged_addr), info.first_bad_addr);
>  	pr_err("\n");
>  
>  	if (addr_has_metadata(untagged_addr)) {
> diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> index 8a9c889872da..41f374585144 100644
> --- a/mm/kasan/report_generic.c
> +++ b/mm/kasan/report_generic.c
> @@ -30,7 +30,7 @@
>  #include "kasan.h"
>  #include "../slab.h"
>  
> -void *find_first_bad_addr(void *addr, size_t size)
> +void *kasan_find_first_bad_addr(void *addr, size_t size)
>  {
>  	void *p = addr;
>  
> @@ -105,7 +105,7 @@ static const char *get_wild_bug_type(struct kasan_access_info *info)
>  	return bug_type;
>  }
>  
> -const char *get_bug_type(struct kasan_access_info *info)
> +const char *kasan_get_bug_type(struct kasan_access_info *info)
>  {
>  	/*
>  	 * If access_size is a negative number, then it has reason to be
> @@ -123,7 +123,7 @@ const char *get_bug_type(struct kasan_access_info *info)
>  	return get_wild_bug_type(info);
>  }
>  
> -void metadata_fetch_row(char *buffer, void *row)
> +void kasan_metadata_fetch_row(char *buffer, void *row)
>  {
>  	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
>  }
> @@ -263,7 +263,7 @@ static bool __must_check get_address_stack_frame_info(const void *addr,
>  	return true;
>  }
>  
> -void print_address_stack_frame(const void *addr)
> +void kasan_print_address_stack_frame(const void *addr)
>  {
>  	unsigned long offset;
>  	const char *frame_descr;
> diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
> index 57114f0e14d1..42b2168755d6 100644
> --- a/mm/kasan/report_hw_tags.c
> +++ b/mm/kasan/report_hw_tags.c
> @@ -15,17 +15,17 @@
>  
>  #include "kasan.h"
>  
> -const char *get_bug_type(struct kasan_access_info *info)
> +const char *kasan_get_bug_type(struct kasan_access_info *info)
>  {
>  	return "invalid-access";
>  }
>  
> -void *find_first_bad_addr(void *addr, size_t size)
> +void *kasan_find_first_bad_addr(void *addr, size_t size)
>  {
>  	return kasan_reset_tag(addr);
>  }
>  
> -void metadata_fetch_row(char *buffer, void *row)
> +void kasan_metadata_fetch_row(char *buffer, void *row)
>  {
>  	int i;
>  
> @@ -33,7 +33,7 @@ void metadata_fetch_row(char *buffer, void *row)
>  		buffer[i] = hw_get_mem_tag(row + i * KASAN_GRANULE_SIZE);
>  }
>  
> -void print_tags(u8 addr_tag, const void *addr)
> +void kasan_print_tags(u8 addr_tag, const void *addr)
>  {
>  	u8 memory_tag = hw_get_mem_tag((void *)addr);
>  
> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> index 1b026793ad57..3d20d3451d9e 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -29,7 +29,7 @@
>  #include "kasan.h"
>  #include "../slab.h"
>  
> -const char *get_bug_type(struct kasan_access_info *info)
> +const char *kasan_get_bug_type(struct kasan_access_info *info)
>  {
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>  	struct kasan_alloc_meta *alloc_meta;
> @@ -72,7 +72,7 @@ const char *get_bug_type(struct kasan_access_info *info)
>  	return "invalid-access";
>  }
>  
> -void *find_first_bad_addr(void *addr, size_t size)
> +void *kasan_find_first_bad_addr(void *addr, size_t size)
>  {
>  	u8 tag = get_tag(addr);
>  	void *p = kasan_reset_tag(addr);
> @@ -83,12 +83,12 @@ void *find_first_bad_addr(void *addr, size_t size)
>  	return p;
>  }
>  
> -void metadata_fetch_row(char *buffer, void *row)
> +void kasan_metadata_fetch_row(char *buffer, void *row)
>  {
>  	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
>  }
>  
> -void print_tags(u8 addr_tag, const void *addr)
> +void kasan_print_tags(u8 addr_tag, const void *addr)
>  {
>  	u8 *shadow = (u8 *)kasan_mem_to_shadow(addr);
>  
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 7c2c08c55f32..38958eb0d653 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -27,20 +27,20 @@
>  
>  bool __kasan_check_read(const volatile void *p, unsigned int size)
>  {
> -	return check_memory_region((unsigned long)p, size, false, _RET_IP_);
> +	return kasan_check_range((unsigned long)p, size, false, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__kasan_check_read);
>  
>  bool __kasan_check_write(const volatile void *p, unsigned int size)
>  {
> -	return check_memory_region((unsigned long)p, size, true, _RET_IP_);
> +	return kasan_check_range((unsigned long)p, size, true, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__kasan_check_write);
>  
>  #undef memset
>  void *memset(void *addr, int c, size_t len)
>  {
> -	if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> +	if (!kasan_check_range((unsigned long)addr, len, true, _RET_IP_))
>  		return NULL;
>  
>  	return __memset(addr, c, len);
> @@ -50,8 +50,8 @@ void *memset(void *addr, int c, size_t len)
>  #undef memmove
>  void *memmove(void *dest, const void *src, size_t len)
>  {
> -	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> -	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> +	if (!kasan_check_range((unsigned long)src, len, false, _RET_IP_) ||
> +	    !kasan_check_range((unsigned long)dest, len, true, _RET_IP_))
>  		return NULL;
>  
>  	return __memmove(dest, src, len);
> @@ -61,8 +61,8 @@ void *memmove(void *dest, const void *src, size_t len)
>  #undef memcpy
>  void *memcpy(void *dest, const void *src, size_t len)
>  {
> -	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> -	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> +	if (!kasan_check_range((unsigned long)src, len, false, _RET_IP_) ||
> +	    !kasan_check_range((unsigned long)dest, len, true, _RET_IP_))
>  		return NULL;
>  
>  	return __memcpy(dest, src, len);
> @@ -72,7 +72,7 @@ void *memcpy(void *dest, const void *src, size_t len)
>   * Poisons the shadow memory for 'size' bytes starting from 'addr'.
>   * Memory addresses should be aligned to KASAN_GRANULE_SIZE.
>   */
> -void poison_range(const void *address, size_t size, u8 value)
> +void kasan_poison(const void *address, size_t size, u8 value)
>  {
>  	void *shadow_start, *shadow_end;
>  
> @@ -90,7 +90,7 @@ void poison_range(const void *address, size_t size, u8 value)
>  	__memset(shadow_start, value, shadow_end - shadow_start);
>  }
>  
> -void unpoison_range(const void *address, size_t size)
> +void kasan_unpoison(const void *address, size_t size)
>  {
>  	u8 tag = get_tag(address);
>  
> @@ -101,7 +101,7 @@ void unpoison_range(const void *address, size_t size)
>  	 */
>  	address = kasan_reset_tag(address);
>  
> -	poison_range(address, size, tag);
> +	kasan_poison(address, size, tag);
>  
>  	if (size & KASAN_GRANULE_MASK) {
>  		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
> @@ -286,7 +286,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
>  	 * // vmalloc() allocates memory
>  	 * // let a = area->addr
>  	 * // we reach kasan_populate_vmalloc
> -	 * // and call unpoison_range:
> +	 * // and call kasan_unpoison:
>  	 * STORE shadow(a), unpoison_val
>  	 * ...
>  	 * STORE shadow(a+99), unpoison_val	x = LOAD p
> @@ -321,7 +321,7 @@ void kasan_poison_vmalloc(const void *start, unsigned long size)
>  		return;
>  
>  	size = round_up(size, KASAN_GRANULE_SIZE);
> -	poison_range(start, size, KASAN_VMALLOC_INVALID);
> +	kasan_poison(start, size, KASAN_VMALLOC_INVALID);
>  }
>  
>  void kasan_unpoison_vmalloc(const void *start, unsigned long size)
> @@ -329,7 +329,7 @@ void kasan_unpoison_vmalloc(const void *start, unsigned long size)
>  	if (!is_vmalloc_or_module_addr(start))
>  		return;
>  
> -	unpoison_range(start, size);
> +	kasan_unpoison(start, size);
>  }
>  
>  static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index 5dcd830805b2..cc271fceb5d5 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -57,7 +57,7 @@ void __init kasan_init_sw_tags(void)
>   * sequence has in fact positive effect, since interrupts that randomly skew
>   * PRNG at unpredictable points do only good.
>   */
> -u8 random_tag(void)
> +u8 kasan_random_tag(void)
>  {
>  	u32 state = this_cpu_read(prng_state);
>  
> @@ -67,7 +67,7 @@ u8 random_tag(void)
>  	return (u8)(state % (KASAN_TAG_MAX + 1));
>  }
>  
> -bool check_memory_region(unsigned long addr, size_t size, bool write,
> +bool kasan_check_range(unsigned long addr, size_t size, bool write,
>  				unsigned long ret_ip)
>  {
>  	u8 tag;
> @@ -118,7 +118,7 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
>  	return true;
>  }
>  
> -bool check_invalid_free(void *addr)
> +bool kasan_check_invalid_free(void *addr)
>  {
>  	u8 tag = get_tag(addr);
>  	u8 shadow_byte = READ_ONCE(*(u8 *)kasan_mem_to_shadow(kasan_reset_tag(addr)));
> @@ -130,12 +130,12 @@ bool check_invalid_free(void *addr)
>  #define DEFINE_HWASAN_LOAD_STORE(size)					\
>  	void __hwasan_load##size##_noabort(unsigned long addr)		\
>  	{								\
> -		check_memory_region(addr, size, false, _RET_IP_);	\
> +		kasan_check_range(addr, size, false, _RET_IP_);	\
>  	}								\
>  	EXPORT_SYMBOL(__hwasan_load##size##_noabort);			\
>  	void __hwasan_store##size##_noabort(unsigned long addr)		\
>  	{								\
> -		check_memory_region(addr, size, true, _RET_IP_);	\
> +		kasan_check_range(addr, size, true, _RET_IP_);		\
>  	}								\
>  	EXPORT_SYMBOL(__hwasan_store##size##_noabort)
>  
> @@ -147,19 +147,19 @@ DEFINE_HWASAN_LOAD_STORE(16);
>  
>  void __hwasan_loadN_noabort(unsigned long addr, unsigned long size)
>  {
> -	check_memory_region(addr, size, false, _RET_IP_);
> +	kasan_check_range(addr, size, false, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__hwasan_loadN_noabort);
>  
>  void __hwasan_storeN_noabort(unsigned long addr, unsigned long size)
>  {
> -	check_memory_region(addr, size, true, _RET_IP_);
> +	kasan_check_range(addr, size, true, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__hwasan_storeN_noabort);
>  
>  void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
>  {
> -	poison_range((void *)addr, size, tag);
> +	kasan_poison((void *)addr, size, tag);
>  }
>  EXPORT_SYMBOL(__hwasan_tag_memory);
>  
> diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> index 5f8d3eed78a1..5b2a22591ea7 100644
> --- a/tools/objtool/check.c
> +++ b/tools/objtool/check.c
> @@ -576,7 +576,7 @@ static void add_ignores(struct objtool_file *file)
>  static const char *uaccess_safe_builtin[] = {
>  	/* KASAN */
>  	"kasan_report",
> -	"check_memory_region",
> +	"kasan_check_range",
>  	/* KASAN out-of-line */
>  	"__asan_loadN_noabort",
>  	"__asan_load1_noabort",
> -- 
> 2.29.2.729.g45daf8777d-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/X/2FujZsDMn49YvA%40elver.google.com.
