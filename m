Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP5E3D5QKGQEXR4ADHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 643E0280536
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:30:40 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id jo18sf2551458ejb.3
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:30:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601573440; cv=pass;
        d=google.com; s=arc-20160816;
        b=mlKIwIYdm5pBYmRqusYSjIr2Nnu6N5bXl567bmYRR8AEoTsOdHziiecbfA8+Vslvy0
         NGvyZpSpFhtAUNCwL8Scf5sebYg+XtSRaxdHe7l5bmift7S0KUVTBomGTvmFBEOEPPMZ
         3eujh8DOoaNqG2/KyYHNqZfydHXpzGrlIAOuapkSB5hXtNuiIunRFSGu2ZvZpHZlw4vj
         uSqSrZUvocusmPV0nYiQsBvYxFjy/HWYNhyrXrO10P4qKMHP4PFyp8V8f5CKPbuQrGD+
         3YX4GAlelt1nBXz1arlZ8kxMFWB3ccm0CZO2xY/tU/rgrL7/f+4py6abIxGutX4JI6xY
         YRfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=63Bf8N0tbJgElI8bRT16tqtGK3iqrLDqYPXB8kdg5ZU=;
        b=c56ZUvll4CtZXLfxPU6/uHHEwMTtqncr1RsYEj6zEYpXesVyE8NnxubJKIhIr+2eTe
         KF4KkBZgVKkUL8UkdHga8WXWHs28z9tZlACgANAvjRi2V4kfFr72t170x3wjhZtxeubB
         xlqRbE+2HytTO0hmQfRN3ew2ucjSUrsKBi08FILNhZ1F9X6wQ1AElqZQxO8egNnPvI6a
         AmZlK748yEA+oRMD0RkHkpcBFySokkKlYM/TEK0hixAUMH6qYXwvxDdqMDSWxUAvDmvD
         41sLc1jxfEO8p22TImFY0gf5P9wWuF8aLWOkouuaF1IZu17qNelqcrHvwYGMxmlLhJ83
         COVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NY2eqYRX;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=63Bf8N0tbJgElI8bRT16tqtGK3iqrLDqYPXB8kdg5ZU=;
        b=XlmluT+VUOiBfnl6fqhgDGnJ+PI87wOlfZ87BWqld5QJ4MoO4L9wuOngUQiS0r/wMj
         1BvBg6sKSF9flQVbq7z4DjVX5+y4nj9pVLehby4n2yYy8xA3IDUu0X7XXhSLUQ1Sg48S
         O/yfNWBebYdULiZk5Qju8eUcQY5pLOBqdhr7Nqb2fNDaGOxyB/pjyUs88n/OUoY7M0fa
         dkcblQ6APA5ADjeYIN4zoMqhsseiG9AV7x4a2BQVpeCCg2z+6GkYInzacfNwiwRTf4P4
         W3ITrmZlPmNkbMtFPrR/NVHLNAttnVR+7uZY5SNksaGc6TaHKZlWRLWOqoG4QLxlDWOx
         wsYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=63Bf8N0tbJgElI8bRT16tqtGK3iqrLDqYPXB8kdg5ZU=;
        b=bX0IpwM9aO725145hsytTWITVU0B2LVt1AM+8mUcW9n4EZr7TTMnuWgoFVJhc71Off
         M/pvHPk1WDsNcCrhX/YCrZTEPyZdNOwRd7UmiipHMM6oko1rk2U7z5JjvcvfzFGEDq3/
         FEQ9o1UkWNrGfMhlyBEWO3h1HxEgvniM6EBoFvTSDV9YLqpqyzuledMU68Aqg8PwOFpz
         866kiArP/JB6yWQ0UtCnVm/xVetQQ/X4l4q/kVLVGVuRtlnuZxrFhE+tqx82KG8TaHXD
         V3EH5x227j271aiCxYe+9Mnf0GPfVFJXiohBYtG8POssZACtItyQPVROjiSwTdoY8jFg
         AoLA==
X-Gm-Message-State: AOAM532Off9Tnl4OL/RJ+6ZyI6L55JsTOg6TMl6J5idEnTnFQv37D5A6
	sBbOe4dAwoERCBVGxwGhM9U=
X-Google-Smtp-Source: ABdhPJxQWgiKq3RKMP19vl0vF5lpRkYHR8hEyGWR4K/I8eE9FpTPHc4lMEn94/e/B1ZAUHFT8a/3PQ==
X-Received: by 2002:a50:e3c4:: with SMTP id c4mr9689054edm.90.1601573440056;
        Thu, 01 Oct 2020 10:30:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:af96:: with SMTP id mj22ls248735ejb.5.gmail; Thu, 01
 Oct 2020 10:30:39 -0700 (PDT)
X-Received: by 2002:a17:906:2e14:: with SMTP id n20mr9505800eji.214.1601573438953;
        Thu, 01 Oct 2020 10:30:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601573438; cv=none;
        d=google.com; s=arc-20160816;
        b=Nti5yjIgnzgQqQSshdCU3YQCwqIAQsorFbldEfre0RJDXre4hwwZinc9cs6iIhQUg9
         YEpSYk53qJjOfFzhsXitG0F4FW1cSOh8uoFz+E+smQEIHobE3pfXrlezm4CyXFJ/FW4k
         cjnrta5Q5B/gW3L1tAda63wPYVif51pwcyAsnH5paEMstvDr0DM5rWLQhh0I1B8LqouW
         YVuVBM/dBlgF/NvmpM5o83EidkUHqBw+PTyaMCEBnCTtTPRasH2PGmt9X4JAYUhi1aJX
         vz6ZcjWKTkgvhsYnEN9M9SURnwd3YioRagmqydDuDr/EbF3XWZVH5kRSOva7R4w9UKT3
         2EYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=5EWktHmi0S1UFc9xy6enxB9/oSV/bmiz83UgiMEly7E=;
        b=gP67V3UtH/UG1V+tUOBlYdlxSqpZpqz4hPhQt9uinbuHoF4ko6TPAVK9kGr+v+icap
         mMzSb87xa6F4OmEiujirBsz8OQTSFCh3tkZxZxRs6GItBbHViMYTsjvyYU2YY/0crHm0
         qp6+ng7PQNMVhg6UsvU8HOvotIMQ2tJu0nhvRcYUj+JaElplj6XBkvDOCRVAPGtanN4f
         kr91ig2VfFI35nC1ziZXGoMk/ONEhicZoqfUTKZoHWVTQ/YBeZPStSVOQdbPntIdfoFJ
         LSHDZGBbLkgQh6veLzab72rLb3+BJY8yu5Dvaew688x2h2zcz94O/AUIOj/oE/tk7ud8
         Q0aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NY2eqYRX;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id r17si56487edc.4.2020.10.01.10.30.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:30:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id q9so3743611wmj.2
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:30:38 -0700 (PDT)
X-Received: by 2002:a1c:5583:: with SMTP id j125mr1065552wmb.75.1601573438290;
        Thu, 01 Oct 2020 10:30:38 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id p9sm880708wmg.34.2020.10.01.10.30.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:30:37 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:30:32 +0200
From: elver via kasan-dev <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 06/39] kasan: rename KASAN_SHADOW_* to KASAN_GRANULE_*
Message-ID: <20201001173032.GD4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <55887ae02bd083138050b1dfc1c599c13da8773d.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <55887ae02bd083138050b1dfc1c599c13da8773d.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NY2eqYRX;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: elver@google.com
Reply-To: elver@google.com
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

On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
> 
> The new mode won't be using shadow memory, but will still use the concept
> of memory granules. Each memory granule maps to a single metadata entry:
> 8 bytes per one shadow byte for generic mode, 16 bytes per one shadow byte
> for software tag-based mode, and 16 bytes per one allocation tag for
> hardware tag-based mode.
> 
> Rename KASAN_SHADOW_SCALE_SIZE to KASAN_GRANULE_SIZE, and KASAN_SHADOW_MASK
> to KASAN_GRANULE_MASK.
> 
> Also use MASK when used as a mask, otherwise use SIZE.
> 
> No functional changes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: Iac733e2248aa9d29f6fc425d8946ba07cca73ecf
> ---
>  Documentation/dev-tools/kasan.rst |  2 +-
>  lib/test_kasan.c                  |  2 +-
>  mm/kasan/common.c                 | 39 ++++++++++++++++---------------
>  mm/kasan/generic.c                | 14 +++++------
>  mm/kasan/generic_report.c         |  8 +++----
>  mm/kasan/init.c                   |  8 +++----
>  mm/kasan/kasan.h                  |  4 ++--
>  mm/kasan/report.c                 | 10 ++++----
>  mm/kasan/tags_report.c            |  2 +-
>  9 files changed, 45 insertions(+), 44 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 38fd5681fade..a3030fc6afe5 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -264,7 +264,7 @@ Most mappings in vmalloc space are small, requiring less than a full
>  page of shadow space. Allocating a full shadow page per mapping would
>  therefore be wasteful. Furthermore, to ensure that different mappings
>  use different shadow pages, mappings would have to be aligned to
> -``KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE``.
> +``KASAN_GRANULE_SIZE * PAGE_SIZE``.
>  
>  Instead, we share backing space across multiple mappings. We allocate
>  a backing page when a mapping in vmalloc space uses a particular page
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 53e953bb1d1d..ddd0b80f24a1 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -25,7 +25,7 @@
>  
>  #include "../mm/kasan/kasan.h"
>  
> -#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_SHADOW_SCALE_SIZE)
> +#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
>  
>  /*
>   * We assign some test results to these globals to make sure the tests
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index a4b73fa0dd7e..f65c9f792f8f 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -106,7 +106,7 @@ void *memcpy(void *dest, const void *src, size_t len)
>  
>  /*
>   * Poisons the shadow memory for 'size' bytes starting from 'addr'.
> - * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
> + * Memory addresses should be aligned to KASAN_GRANULE_SIZE.
>   */
>  void kasan_poison_memory(const void *address, size_t size, u8 value)
>  {
> @@ -138,13 +138,13 @@ void kasan_unpoison_memory(const void *address, size_t size)
>  
>  	kasan_poison_memory(address, size, tag);
>  
> -	if (size & KASAN_SHADOW_MASK) {
> +	if (size & KASAN_GRANULE_MASK) {
>  		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
>  
>  		if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
>  			*shadow = tag;
>  		else
> -			*shadow = size & KASAN_SHADOW_MASK;
> +			*shadow = size & KASAN_GRANULE_MASK;
>  	}
>  }
>  
> @@ -296,7 +296,7 @@ void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
>  void kasan_poison_object_data(struct kmem_cache *cache, void *object)
>  {
>  	kasan_poison_memory(object,
> -			round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE),
> +			round_up(cache->object_size, KASAN_GRANULE_SIZE),
>  			KASAN_KMALLOC_REDZONE);
>  }
>  
> @@ -368,7 +368,7 @@ static inline bool shadow_invalid(u8 tag, s8 shadow_byte)
>  {
>  	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>  		return shadow_byte < 0 ||
> -			shadow_byte >= KASAN_SHADOW_SCALE_SIZE;
> +			shadow_byte >= KASAN_GRANULE_SIZE;
>  
>  	/* else CONFIG_KASAN_SW_TAGS: */
>  	if ((u8)shadow_byte == KASAN_TAG_INVALID)
> @@ -407,7 +407,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>  		return true;
>  	}
>  
> -	rounded_up_size = round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE);
> +	rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
>  	kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
>  
>  	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
> @@ -440,9 +440,9 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  		return NULL;
>  
>  	redzone_start = round_up((unsigned long)(object + size),
> -				KASAN_SHADOW_SCALE_SIZE);
> +				KASAN_GRANULE_SIZE);
>  	redzone_end = round_up((unsigned long)object + cache->object_size,
> -				KASAN_SHADOW_SCALE_SIZE);
> +				KASAN_GRANULE_SIZE);
>  
>  	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
>  		tag = assign_tag(cache, object, false, keep_tag);
> @@ -486,7 +486,7 @@ void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
>  
>  	page = virt_to_page(ptr);
>  	redzone_start = round_up((unsigned long)(ptr + size),
> -				KASAN_SHADOW_SCALE_SIZE);
> +				KASAN_GRANULE_SIZE);
>  	redzone_end = (unsigned long)ptr + page_size(page);
>  
>  	kasan_unpoison_memory(ptr, size);
> @@ -584,8 +584,8 @@ static int __meminit kasan_mem_notifier(struct notifier_block *nb,
>  	shadow_size = nr_shadow_pages << PAGE_SHIFT;
>  	shadow_end = shadow_start + shadow_size;
>  
> -	if (WARN_ON(mem_data->nr_pages % KASAN_SHADOW_SCALE_SIZE) ||
> -		WARN_ON(start_kaddr % (KASAN_SHADOW_SCALE_SIZE << PAGE_SHIFT)))
> +	if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
> +		WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT)))
>  		return NOTIFY_BAD;
>  
>  	switch (action) {
> @@ -743,7 +743,7 @@ void kasan_poison_vmalloc(const void *start, unsigned long size)
>  	if (!is_vmalloc_or_module_addr(start))
>  		return;
>  
> -	size = round_up(size, KASAN_SHADOW_SCALE_SIZE);
> +	size = round_up(size, KASAN_GRANULE_SIZE);
>  	kasan_poison_memory(start, size, KASAN_VMALLOC_INVALID);
>  }
>  
> @@ -856,22 +856,22 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
>  	unsigned long region_start, region_end;
>  	unsigned long size;
>  
> -	region_start = ALIGN(start, PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
> -	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
> +	region_start = ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
> +	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
>  
>  	free_region_start = ALIGN(free_region_start,
> -				  PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
> +				  PAGE_SIZE * KASAN_GRANULE_SIZE);
>  
>  	if (start != region_start &&
>  	    free_region_start < region_start)
> -		region_start -= PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE;
> +		region_start -= PAGE_SIZE * KASAN_GRANULE_SIZE;
>  
>  	free_region_end = ALIGN_DOWN(free_region_end,
> -				     PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
> +				     PAGE_SIZE * KASAN_GRANULE_SIZE);
>  
>  	if (end != region_end &&
>  	    free_region_end > region_end)
> -		region_end += PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE;
> +		region_end += PAGE_SIZE * KASAN_GRANULE_SIZE;
>  
>  	shadow_start = kasan_mem_to_shadow((void *)region_start);
>  	shadow_end = kasan_mem_to_shadow((void *)region_end);
> @@ -897,7 +897,8 @@ int kasan_module_alloc(void *addr, size_t size)
>  	unsigned long shadow_start;
>  
>  	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
> -	scaled_size = (size + KASAN_SHADOW_MASK) >> KASAN_SHADOW_SCALE_SHIFT;
> +	scaled_size = (size + KASAN_GRANULE_SIZE - 1) >>
> +				KASAN_SHADOW_SCALE_SHIFT;
>  	shadow_size = round_up(scaled_size, PAGE_SIZE);
>  
>  	if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 7006157c674b..ec4417156943 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -46,7 +46,7 @@ static __always_inline bool memory_is_poisoned_1(unsigned long addr)
>  	s8 shadow_value = *(s8 *)kasan_mem_to_shadow((void *)addr);
>  
>  	if (unlikely(shadow_value)) {
> -		s8 last_accessible_byte = addr & KASAN_SHADOW_MASK;
> +		s8 last_accessible_byte = addr & KASAN_GRANULE_MASK;
>  		return unlikely(last_accessible_byte >= shadow_value);
>  	}
>  
> @@ -62,7 +62,7 @@ static __always_inline bool memory_is_poisoned_2_4_8(unsigned long addr,
>  	 * Access crosses 8(shadow size)-byte boundary. Such access maps
>  	 * into 2 shadow bytes, so we need to check them both.
>  	 */
> -	if (unlikely(((addr + size - 1) & KASAN_SHADOW_MASK) < size - 1))
> +	if (unlikely(((addr + size - 1) & KASAN_GRANULE_MASK) < size - 1))
>  		return *shadow_addr || memory_is_poisoned_1(addr + size - 1);
>  
>  	return memory_is_poisoned_1(addr + size - 1);
> @@ -73,7 +73,7 @@ static __always_inline bool memory_is_poisoned_16(unsigned long addr)
>  	u16 *shadow_addr = (u16 *)kasan_mem_to_shadow((void *)addr);
>  
>  	/* Unaligned 16-bytes access maps into 3 shadow bytes. */
> -	if (unlikely(!IS_ALIGNED(addr, KASAN_SHADOW_SCALE_SIZE)))
> +	if (unlikely(!IS_ALIGNED(addr, KASAN_GRANULE_SIZE)))
>  		return *shadow_addr || memory_is_poisoned_1(addr + 15);
>  
>  	return *shadow_addr;
> @@ -134,7 +134,7 @@ static __always_inline bool memory_is_poisoned_n(unsigned long addr,
>  		s8 *last_shadow = (s8 *)kasan_mem_to_shadow((void *)last_byte);
>  
>  		if (unlikely(ret != (unsigned long)last_shadow ||
> -			((long)(last_byte & KASAN_SHADOW_MASK) >= *last_shadow)))
> +			((long)(last_byte & KASAN_GRANULE_MASK) >= *last_shadow)))
>  			return true;
>  	}
>  	return false;
> @@ -200,7 +200,7 @@ void kasan_cache_shutdown(struct kmem_cache *cache)
>  
>  static void register_global(struct kasan_global *global)
>  {
> -	size_t aligned_size = round_up(global->size, KASAN_SHADOW_SCALE_SIZE);
> +	size_t aligned_size = round_up(global->size, KASAN_GRANULE_SIZE);
>  
>  	kasan_unpoison_memory(global->beg, global->size);
>  
> @@ -274,10 +274,10 @@ EXPORT_SYMBOL(__asan_handle_no_return);
>  /* Emitted by compiler to poison alloca()ed objects. */
>  void __asan_alloca_poison(unsigned long addr, size_t size)
>  {
> -	size_t rounded_up_size = round_up(size, KASAN_SHADOW_SCALE_SIZE);
> +	size_t rounded_up_size = round_up(size, KASAN_GRANULE_SIZE);
>  	size_t padding_size = round_up(size, KASAN_ALLOCA_REDZONE_SIZE) -
>  			rounded_up_size;
> -	size_t rounded_down_size = round_down(size, KASAN_SHADOW_SCALE_SIZE);
> +	size_t rounded_down_size = round_down(size, KASAN_GRANULE_SIZE);
>  
>  	const void *left_redzone = (const void *)(addr -
>  			KASAN_ALLOCA_REDZONE_SIZE);
> diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> index 6bb3f66992df..7d5b9e5c7cfe 100644
> --- a/mm/kasan/generic_report.c
> +++ b/mm/kasan/generic_report.c
> @@ -34,7 +34,7 @@ void *find_first_bad_addr(void *addr, size_t size)
>  	void *p = addr;
>  
>  	while (p < addr + size && !(*(u8 *)kasan_mem_to_shadow(p)))
> -		p += KASAN_SHADOW_SCALE_SIZE;
> +		p += KASAN_GRANULE_SIZE;
>  	return p;
>  }
>  
> @@ -46,14 +46,14 @@ static const char *get_shadow_bug_type(struct kasan_access_info *info)
>  	shadow_addr = (u8 *)kasan_mem_to_shadow(info->first_bad_addr);
>  
>  	/*
> -	 * If shadow byte value is in [0, KASAN_SHADOW_SCALE_SIZE) we can look
> +	 * If shadow byte value is in [0, KASAN_GRANULE_SIZE) we can look
>  	 * at the next shadow byte to determine the type of the bad access.
>  	 */
> -	if (*shadow_addr > 0 && *shadow_addr <= KASAN_SHADOW_SCALE_SIZE - 1)
> +	if (*shadow_addr > 0 && *shadow_addr <= KASAN_GRANULE_SIZE - 1)
>  		shadow_addr++;
>  
>  	switch (*shadow_addr) {
> -	case 0 ... KASAN_SHADOW_SCALE_SIZE - 1:
> +	case 0 ... KASAN_GRANULE_SIZE - 1:
>  		/*
>  		 * In theory it's still possible to see these shadow values
>  		 * due to a data race in the kernel code.
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index 9ce8cc5b8621..dfddd6c39fe6 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -442,8 +442,8 @@ void kasan_remove_zero_shadow(void *start, unsigned long size)
>  	end = addr + (size >> KASAN_SHADOW_SCALE_SHIFT);
>  
>  	if (WARN_ON((unsigned long)start %
> -			(KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE)) ||
> -	    WARN_ON(size % (KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE)))
> +			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
> +	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
>  		return;
>  
>  	for (; addr < end; addr = next) {
> @@ -477,8 +477,8 @@ int kasan_add_zero_shadow(void *start, unsigned long size)
>  	shadow_end = shadow_start + (size >> KASAN_SHADOW_SCALE_SHIFT);
>  
>  	if (WARN_ON((unsigned long)start %
> -			(KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE)) ||
> -	    WARN_ON(size % (KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE)))
> +			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
> +	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
>  		return -EINVAL;
>  
>  	ret = kasan_populate_early_shadow(shadow_start, shadow_end);
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 03450d3b31f7..c31e2c739301 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -5,8 +5,8 @@
>  #include <linux/kasan.h>
>  #include <linux/stackdepot.h>
>  
> -#define KASAN_SHADOW_SCALE_SIZE (1UL << KASAN_SHADOW_SCALE_SHIFT)
> -#define KASAN_SHADOW_MASK       (KASAN_SHADOW_SCALE_SIZE - 1)
> +#define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
> +#define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
>  
>  #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
>  #define KASAN_TAG_INVALID	0xFE /* inaccessible memory tag */
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index c3031b4b4591..fc487ba83931 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -312,24 +312,24 @@ static bool __must_check get_address_stack_frame_info(const void *addr,
>  		return false;
>  
>  	aligned_addr = round_down((unsigned long)addr, sizeof(long));
> -	mem_ptr = round_down(aligned_addr, KASAN_SHADOW_SCALE_SIZE);
> +	mem_ptr = round_down(aligned_addr, KASAN_GRANULE_SIZE);
>  	shadow_ptr = kasan_mem_to_shadow((void *)aligned_addr);
>  	shadow_bottom = kasan_mem_to_shadow(end_of_stack(current));
>  
>  	while (shadow_ptr >= shadow_bottom && *shadow_ptr != KASAN_STACK_LEFT) {
>  		shadow_ptr--;
> -		mem_ptr -= KASAN_SHADOW_SCALE_SIZE;
> +		mem_ptr -= KASAN_GRANULE_SIZE;
>  	}
>  
>  	while (shadow_ptr >= shadow_bottom && *shadow_ptr == KASAN_STACK_LEFT) {
>  		shadow_ptr--;
> -		mem_ptr -= KASAN_SHADOW_SCALE_SIZE;
> +		mem_ptr -= KASAN_GRANULE_SIZE;
>  	}
>  
>  	if (shadow_ptr < shadow_bottom)
>  		return false;
>  
> -	frame = (const unsigned long *)(mem_ptr + KASAN_SHADOW_SCALE_SIZE);
> +	frame = (const unsigned long *)(mem_ptr + KASAN_GRANULE_SIZE);
>  	if (frame[0] != KASAN_CURRENT_STACK_FRAME_MAGIC) {
>  		pr_err("KASAN internal error: frame info validation failed; invalid marker: %lu\n",
>  		       frame[0]);
> @@ -567,6 +567,6 @@ void kasan_non_canonical_hook(unsigned long addr)
>  	else
>  		bug_type = "maybe wild-memory-access";
>  	pr_alert("KASAN: %s in range [0x%016lx-0x%016lx]\n", bug_type,
> -		 orig_addr, orig_addr + KASAN_SHADOW_MASK);
> +		 orig_addr, orig_addr + KASAN_GRANULE_SIZE - 1);
>  }
>  #endif
> diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
> index 5f183501b871..c87d5a343b4e 100644
> --- a/mm/kasan/tags_report.c
> +++ b/mm/kasan/tags_report.c
> @@ -76,7 +76,7 @@ void *find_first_bad_addr(void *addr, size_t size)
>  	void *end = p + size;
>  
>  	while (p < end && tag == *(u8 *)kasan_mem_to_shadow(p))
> -		p += KASAN_SHADOW_SCALE_SIZE;
> +		p += KASAN_GRANULE_SIZE;
>  	return p;
>  }
>  
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001173032.GD4162920%40elver.google.com.
