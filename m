Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSMZWD6QKGQEM5KSCAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id F11432AF5D2
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 17:09:48 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 201sf20846lfo.12
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 08:09:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605110988; cv=pass;
        d=google.com; s=arc-20160816;
        b=AcAlrRQ9W9+f361ssSANoMGDejhMnrLA+Jic/RKTE06d++GZnDd+R5YyhIHSU2Dkam
         jSotqkMdNLO8tMAW1DT3bX2GVkZW4kbZuOwvMcMnE5skLaDwZlyaAIWJaV7WlsyPwGJO
         assRGsHiWIDxLlQPGNtlR04cVPKVRvaSWwKmaZKuhCmWtZNLh2oq+78EgWYHZZK91XcS
         BYggJjuhLWs/67MO4qM2EmSF+0T5P53izsy4a6qpYFHOA5ZQ/uTwPxyLky/ZeoQIRTGU
         yxHDXWx4R7IMrYiu0y6cpv4aT8WrSKfMwDCOUO1cF7A0ZGiLvKWIVz7BTwkbJkbvQER+
         VbIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=yKmiBupxLB16OPeW2KfTOPRVHq6YuHeud3SyUg6DYvw=;
        b=vrfbz0SQpeR3r3h44sp36e5l9i0skVi98m2S9XXQfe3MImHEvqhErqJ10DrKZL+vgg
         /2PJS7Dr8RoZtx3ER4XaoX49KcDD3Wcs4Buk3CPbqnX/oL4+AEJWok0VomFTISMzkDv4
         PN8KhLwdRP9PyuWUr8jzAfH1ssk8h/l/71yg688K0TMkHSJwJomAG4Ss0q3Cj5+O905A
         ZdF0shaqd9X1fSJ80lKAhEd/vkI4FE61zhCvh2u/9I+3sgcphCORB6f+RbXMhNx5BfhQ
         dSXKP3cUi8qNh3Ege5XrqQKIBuFjvwt2bVixSQpdR94jFfOsjVojefu1LR+ITXGRP7Ev
         PkTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KPIoJai4;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=yKmiBupxLB16OPeW2KfTOPRVHq6YuHeud3SyUg6DYvw=;
        b=RroX9dxv3GkcjWAmBgDvVPBL7xy19M0TwuUfpZkubAChQKxhjWFCDPBFgYpZq+pO9X
         lWSnHBthpOrBwYvL1JaAEee5uHHIFYB2I/u+63KIHkDnoyQMPbvy2GCr5MEwb9Cm+28M
         ABRSVjZlJFvHkC01m+xCcoM8WEuqjBYxDmzR/cg5ZbyRFJoEhXi3KvHjvBzc+GTBBLVt
         YiQWwaKBFHtrPx5NfPFUIN4zCDSHOicV5z8PG4E3rQ/To5sCVobTBwtplHPvB6OuUBmc
         nEysLJqoyJ3FahEVBhjC3bR6dky5IgmHvDpEryOlMq2m0VGyDfqpchNV2n9KsLkpMXiH
         4DZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yKmiBupxLB16OPeW2KfTOPRVHq6YuHeud3SyUg6DYvw=;
        b=ljUlF1nY4oicufybjR6rT92EQ9xFKXzv2KY5V6nZgCflkRvWSTi9lWk+OMeIb0tqJq
         5vLx+OEoyayvkzgMqn9eWdKKR6A6IQd6mFZ1PSu0LTh68AgO4WZ18uhF1Lbuqq/W0nsf
         UcK/NRCQ39H4d6V5CLZ8MD0NWYnkL/keyhYo15F5YLj8k++3qhU99oFiUmRiWfXlG92t
         BPCiMgGX4Jdtz+NuOTpiWnRyhi/trbs1KEf7rT5hy5e8HaGUeAaZMHUUuIT/SVnA25TN
         Rrg4aIzGjpYrZPnru9vY4NuVCzxVogkkik7n61GnoDXbbYvIaiO3MQbzTVBICfHONqXj
         15Kg==
X-Gm-Message-State: AOAM533nBC40x0GQauP6fuvHpflHcRll34eYItyc6UH86WPVGSes+y5k
	UBegVp6AUTCJpl+s0WCqEdw=
X-Google-Smtp-Source: ABdhPJwx9azOntzQM9+PxV/zpiR/yN0qRuvOA6MTzvEY8T2VgAamxGRqC8n7h5KZJr4m6i5xpu7aNg==
X-Received: by 2002:a05:651c:2cc:: with SMTP id f12mr10457653ljo.179.1605110985515;
        Wed, 11 Nov 2020 08:09:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9908:: with SMTP id v8ls18140lji.1.gmail; Wed, 11 Nov
 2020 08:09:44 -0800 (PST)
X-Received: by 2002:a2e:9915:: with SMTP id v21mr2261262lji.460.1605110984293;
        Wed, 11 Nov 2020 08:09:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605110984; cv=none;
        d=google.com; s=arc-20160816;
        b=WJS0fnxVwTyABOkE8ksgFXGCY4qy68Kixjv8Ai1ywDUR1idED7JSYhKBzYqX4Ft0zu
         RVnp8T+NI0BC68bDjmR0P/8agV5bA7h7XvEzPiBsWWDJiDUmQmbj4KAlq4dlMdGbVb+B
         3f7SKfGFR6NJhicdu3MQp63uo4bOl3swcMdS2pVC3gS8hzwEVIfNW/AUU+gBU9EOiXaY
         7gvEKWTMfJNA6q8BMBZ52XIQQ5n++QER/v7jI+TDwp/To6AMYZ8nZ2BU/AiSaabxncu1
         eic3M5mDCXMZc6/WthYqBPjpqkXbIuaBhidNLsRcrX39tC8tQBtQZ2xiZFPVIuV5A/qV
         XWUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=IBs3li60EOi/W5+017BpBFCYAVBpZJoicHAyd9GYBDE=;
        b=d2s78LF0l/x+kcyFRQY7h9+l41HZxsZIEW6ki3ZmpLIHGLlRRMYj4qG9SZrNybHipx
         F1HJ2PgcnUhkFNN3pPRilTrLxZ/1k3fGv7NgkvFDovGVtCxGxQJg+34Hngt/nEAqzGfj
         z7abLE1GFDYoBBWWNdPBZrV607UXtd2+/qiEwadEWpwKOPcn9nW0WpHJbByCwYVfwXRE
         o2xwZkljm9ci/RoEreNR1DFo0dz1rzxl3hqmGuthUnwwVnrQs3THO7UmTQj1TIyPFdZz
         QziM6oIX2oxUvRq3XtLHYw9X9QFWew8lSqr8Zn+8yUeRuLfyEkRBbkcd+cW1BNVBJilF
         ZmdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KPIoJai4;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id v24si93384lfo.5.2020.11.11.08.09.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 08:09:44 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id c16so2828756wmd.2
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 08:09:44 -0800 (PST)
X-Received: by 2002:a1c:5a06:: with SMTP id o6mr5038037wmb.181.1605110983453;
        Wed, 11 Nov 2020 08:09:43 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id v6sm3414128wrb.53.2020.11.11.08.09.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 08:09:42 -0800 (PST)
Date: Wed, 11 Nov 2020 17:09:37 +0100
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
Subject: Re: [PATCH v2 02/20] kasan: rename get_alloc/free_info
Message-ID: <20201111160937.GD517454@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <f60a0852051bbe9a20d5f9eba7567c0e9474a1c4.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f60a0852051bbe9a20d5f9eba7567c0e9474a1c4.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KPIoJai4;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as
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
> Rename get_alloc_info() and get_free_info() to kasan_get_alloc_meta()
> and kasan_get_free_meta() to better reflect what those do and avoid
> confusion with kasan_set_free_info().
> 
> No functional changes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Link: https://linux-review.googlesource.com/id/Ib6e4ba61c8b12112b403d3479a9799ac8fff8de1
> ---
>  mm/kasan/common.c         | 16 ++++++++--------
>  mm/kasan/generic.c        | 12 ++++++------
>  mm/kasan/hw_tags.c        |  4 ++--
>  mm/kasan/kasan.h          |  8 ++++----
>  mm/kasan/quarantine.c     |  4 ++--
>  mm/kasan/report.c         | 12 ++++++------
>  mm/kasan/report_sw_tags.c |  2 +-
>  mm/kasan/sw_tags.c        |  4 ++--
>  8 files changed, 31 insertions(+), 31 deletions(-)

Reviewed-by: Marco Elver <elver@google.com>

> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 5712c66c11c1..8fd04415d8f4 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -175,14 +175,14 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
>  		sizeof(struct kasan_free_meta) : 0);
>  }
>  
> -struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
> -					const void *object)
> +struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
> +					      const void *object)
>  {
>  	return (void *)reset_tag(object) + cache->kasan_info.alloc_meta_offset;
>  }
>  
> -struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
> -				      const void *object)
> +struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
> +					    const void *object)
>  {
>  	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
>  	return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
> @@ -259,13 +259,13 @@ static u8 assign_tag(struct kmem_cache *cache, const void *object,
>  void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
>  						const void *object)
>  {
> -	struct kasan_alloc_meta *alloc_info;
> +	struct kasan_alloc_meta *alloc_meta;
>  
>  	if (!(cache->flags & SLAB_KASAN))
>  		return (void *)object;
>  
> -	alloc_info = get_alloc_info(cache, object);
> -	__memset(alloc_info, 0, sizeof(*alloc_info));
> +	alloc_meta = kasan_get_alloc_meta(cache, object);
> +	__memset(alloc_meta, 0, sizeof(*alloc_meta));
>  
>  	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>  		object = set_tag(object, assign_tag(cache, object, true, false));
> @@ -345,7 +345,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  		KASAN_KMALLOC_REDZONE);
>  
>  	if (cache->flags & SLAB_KASAN)
> -		kasan_set_track(&get_alloc_info(cache, object)->alloc_track, flags);
> +		kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
>  
>  	return set_tag(object, tag);
>  }
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index adb254df1b1d..d259e4c3aefd 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -329,7 +329,7 @@ void kasan_record_aux_stack(void *addr)
>  {
>  	struct page *page = kasan_addr_to_page(addr);
>  	struct kmem_cache *cache;
> -	struct kasan_alloc_meta *alloc_info;
> +	struct kasan_alloc_meta *alloc_meta;
>  	void *object;
>  
>  	if (!(page && PageSlab(page)))
> @@ -337,13 +337,13 @@ void kasan_record_aux_stack(void *addr)
>  
>  	cache = page->slab_cache;
>  	object = nearest_obj(cache, page, addr);
> -	alloc_info = get_alloc_info(cache, object);
> +	alloc_meta = kasan_get_alloc_meta(cache, object);
>  
>  	/*
>  	 * record the last two call_rcu() call stacks.
>  	 */
> -	alloc_info->aux_stack[1] = alloc_info->aux_stack[0];
> -	alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
> +	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
> +	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
>  }
>  
>  void kasan_set_free_info(struct kmem_cache *cache,
> @@ -351,7 +351,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
>  {
>  	struct kasan_free_meta *free_meta;
>  
> -	free_meta = get_free_info(cache, object);
> +	free_meta = kasan_get_free_meta(cache, object);
>  	kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
>  
>  	/*
> @@ -365,5 +365,5 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>  {
>  	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_KMALLOC_FREETRACK)
>  		return NULL;
> -	return &get_free_info(cache, object)->free_track;
> +	return &kasan_get_free_meta(cache, object)->free_track;
>  }
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 0080b78ec843..70b88dd40cd8 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -66,7 +66,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
>  {
>  	struct kasan_alloc_meta *alloc_meta;
>  
> -	alloc_meta = get_alloc_info(cache, object);
> +	alloc_meta = kasan_get_alloc_meta(cache, object);
>  	kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
>  }
>  
> @@ -75,6 +75,6 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>  {
>  	struct kasan_alloc_meta *alloc_meta;
>  
> -	alloc_meta = get_alloc_info(cache, object);
> +	alloc_meta = kasan_get_alloc_meta(cache, object);
>  	return &alloc_meta->free_track[0];
>  }
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index c2c40ec1544d..db8a7a508121 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -148,10 +148,10 @@ struct kasan_free_meta {
>  #endif
>  };
>  
> -struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
> -					const void *object);
> -struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
> -					const void *object);
> +struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
> +						const void *object);
> +struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
> +						const void *object);
>  
>  void kasan_poison_memory(const void *address, size_t size, u8 value);
>  
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index a0792f0d6d0f..0da3d37e1589 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -166,7 +166,7 @@ void quarantine_put(struct kmem_cache *cache, void *object)
>  	unsigned long flags;
>  	struct qlist_head *q;
>  	struct qlist_head temp = QLIST_INIT;
> -	struct kasan_free_meta *info = get_free_info(cache, object);
> +	struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
>  
>  	/*
>  	 * Note: irq must be disabled until after we move the batch to the
> @@ -179,7 +179,7 @@ void quarantine_put(struct kmem_cache *cache, void *object)
>  	local_irq_save(flags);
>  
>  	q = this_cpu_ptr(&cpu_quarantine);
> -	qlist_put(q, &info->quarantine_link, cache->size);
> +	qlist_put(q, &meta->quarantine_link, cache->size);
>  	if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
>  		qlist_move_all(q, &temp);
>  
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index ce06005d4052..0cac53a57c14 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -164,12 +164,12 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
>  static void describe_object(struct kmem_cache *cache, void *object,
>  				const void *addr, u8 tag)
>  {
> -	struct kasan_alloc_meta *alloc_info = get_alloc_info(cache, object);
> +	struct kasan_alloc_meta *alloc_meta = kasan_get_alloc_meta(cache, object);
>  
>  	if (cache->flags & SLAB_KASAN) {
>  		struct kasan_track *free_track;
>  
> -		print_track(&alloc_info->alloc_track, "Allocated");
> +		print_track(&alloc_meta->alloc_track, "Allocated");
>  		pr_err("\n");
>  		free_track = kasan_get_free_track(cache, object, tag);
>  		if (free_track) {
> @@ -178,14 +178,14 @@ static void describe_object(struct kmem_cache *cache, void *object,
>  		}
>  
>  #ifdef CONFIG_KASAN_GENERIC
> -		if (alloc_info->aux_stack[0]) {
> +		if (alloc_meta->aux_stack[0]) {
>  			pr_err("Last call_rcu():\n");
> -			print_stack(alloc_info->aux_stack[0]);
> +			print_stack(alloc_meta->aux_stack[0]);
>  			pr_err("\n");
>  		}
> -		if (alloc_info->aux_stack[1]) {
> +		if (alloc_meta->aux_stack[1]) {
>  			pr_err("Second to last call_rcu():\n");
> -			print_stack(alloc_info->aux_stack[1]);
> +			print_stack(alloc_meta->aux_stack[1]);
>  			pr_err("\n");
>  		}
>  #endif
> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> index aebc44a29e83..317100fd95b9 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -46,7 +46,7 @@ const char *get_bug_type(struct kasan_access_info *info)
>  	if (page && PageSlab(page)) {
>  		cache = page->slab_cache;
>  		object = nearest_obj(cache, page, (void *)addr);
> -		alloc_meta = get_alloc_info(cache, object);
> +		alloc_meta = kasan_get_alloc_meta(cache, object);
>  
>  		for (i = 0; i < KASAN_NR_FREE_STACKS; i++)
>  			if (alloc_meta->free_pointer_tag[i] == tag)
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index dfe707dd8d0d..3bffb489b144 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -174,7 +174,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
>  	struct kasan_alloc_meta *alloc_meta;
>  	u8 idx = 0;
>  
> -	alloc_meta = get_alloc_info(cache, object);
> +	alloc_meta = kasan_get_alloc_meta(cache, object);
>  
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>  	idx = alloc_meta->free_track_idx;
> @@ -191,7 +191,7 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>  	struct kasan_alloc_meta *alloc_meta;
>  	int i = 0;
>  
> -	alloc_meta = get_alloc_info(cache, object);
> +	alloc_meta = kasan_get_alloc_meta(cache, object);
>  
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>  	for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> -- 
> 2.29.2.222.g5d2a92d10f8-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111160937.GD517454%40elver.google.com.
