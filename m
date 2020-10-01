Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBFE3D5QKGQEJ3XPQYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7754D28052E
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:29:41 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id a4sf2086959lff.21
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:29:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601573381; cv=pass;
        d=google.com; s=arc-20160816;
        b=OWU6Urm6c1XKFsTSHgkgyUJfNDad3FETsKyIkDi+a6kOjp4IBr9H3923dI3QWNxkhx
         yREp31ZcMW+zoJLXWv+Vwd3EtqRfDMeiwiuRYPnkje9+Fa0OqvOaMfPJhJjv3UYoJo3A
         A1rmId4GFlhd3c6mFnv3MPZdR9k3SkOsDw8fNFMum+RBwX7M5vtKZXpwnugIwJBzGjav
         HqwRqsPnlz4BhCrSoFFr9MdetYmjeKRKly+IBYJVi9YfsLy6PeiJJ+ieK8gaBcdV7ALu
         MgFCueBMpETpm8XVjSF64vGW5jYZTs0GE9v1WvixpUjY0WytrpM7sxh9Egy7oZMbmCGB
         hImQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=79nCZudJJ0T0+IPI9aKdOfucCCwhhkHQqefJTJR0Pyo=;
        b=BFjqL2ySsBxaa8tQ7/dw5/xQP6xlGIM/6wq9chJ5FDQ0MZgu5kaW77m0B9F+2hLgWb
         4DbLVKKu/j3YzBQXOQHaK498IhWV6MGCJGCYo1ZNdZoDRUN6vwPqcOJteIZolccWPHjt
         B9RGh/FBMECSxDKeKrWnndN0GykEMMK0nRfagpGjZ+C+gdiJQJHbAlO0YFowAfkeQLX6
         9ppbwmIR1Lp8Y2cD2hiOEl30kLenFIMNHFDko1/AjYItjc/EsWCA4nfWMgUxqQ7VthD4
         BO//8N5m6PVJe7aut0oKitzfiqbvdqFQajtJXfNBnUjBahOYBGV+jJdVnp7FHSwcDUKS
         V/QQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J6jJ7KhG;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=79nCZudJJ0T0+IPI9aKdOfucCCwhhkHQqefJTJR0Pyo=;
        b=Sa4bynQ8aWPsEBUWOwut3Z+THvz/lQPtIx9M5TVIC1CronJsK4lfH4VCIfWD4iWiiT
         ZFNbYLZkz7RC18ICcH7tz3WFLBTqcLup53GIMzQjFm+F+YbxU3RtNCSAwJilkN/uja6b
         vrvLM3oGSaAnDw8fFaQfeHSbo3LuWlz9ZWFIVcd4g5thWmgNa+mHaBzhObEhDv0rwPUq
         1D4VUukhObbarFFWoasb84NDjCf8VQlWO/5hY0a4N256/Yz0KC03XAhb+QWpx/GdQMnw
         cMdQWRggtwR/69DcD2bZnNU5JPBHRdwhMMbUDPH9Cp6low6NzflhbmXqkFJfQCAkl7mc
         KBIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=79nCZudJJ0T0+IPI9aKdOfucCCwhhkHQqefJTJR0Pyo=;
        b=Pr/Y4rePVEUsNY7t0Q8t2HoakJSohnwuIhGNbyUmm5rTsUZC5u95tLptNziRig85fx
         CEzm4UvjlG/fV99NkzPpoInuoNjXhnl/BFvvXJ7HrJLeOiN79Y/wHPeHTznKTOgxdSQD
         BSa9bEtyFVxK60Xi8a/12g7X2moLiC4YG7zOPsgfLo+5p0vNUAKGJalZUtvCBRgxZwlX
         2tHVyy1MQclFSpxuV4qMhaN9Kr43U0d3JHti0DugMa1vy8rtl31QQc6x1h3YoPN2zhWm
         TZmPx8cblmwlY4T94P/mSkDRlOJYYFRD0eWLXKEFKmwKRhHCiO75cmfm4TxnxJA5D4UN
         SjYA==
X-Gm-Message-State: AOAM533g6G4KULnK1hk8vtMmIQg9IsSqdLo5YFB7QmjKYlW5gvjDGqFv
	uJV4P/1i9Rrn1ZTYe/jk29c=
X-Google-Smtp-Source: ABdhPJzK3WjEdmbnq6UnOx+QEM5EtsxdgVNuefAX1vcV33qvAepCwLR8nC58yFUku7AKRDkJjklVkQ==
X-Received: by 2002:ac2:5dec:: with SMTP id z12mr3367708lfq.15.1601573380969;
        Thu, 01 Oct 2020 10:29:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5c44:: with SMTP id s4ls1676012lfp.3.gmail; Thu, 01 Oct
 2020 10:29:39 -0700 (PDT)
X-Received: by 2002:a19:fc17:: with SMTP id a23mr2977150lfi.179.1601573379683;
        Thu, 01 Oct 2020 10:29:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601573379; cv=none;
        d=google.com; s=arc-20160816;
        b=vZMb4PD3pa6h2d8xoN4QimRq1EXkZVb+UNtfYPaprau3RPUE0H3beWSVvmStakDWl7
         4lSJEviMOfj/LKwRiLYfLhCRy6XrggIF1eoaVZGYZNAiBT2mszx5vA3ZlyBk3K84E9cZ
         dif2tsPcf0tYZTzHppAkdpG9x4fqplDFhVXLxHLH/Y1fLDhHS39u+LQPsSy1i3iR4O2K
         OEex61e07cbla2zsC8HX7W/R4919m6mEBkxMQOBbHfbvRblSEcoK9cF43re5VS71XSpC
         SAOiNegn909KafPbJYe9wGpI7jtlzWk5OggW+9OMtvZnLsEvOHHvmPc5sdnHL/0vMyeo
         YquA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=2OtA/MQIMRXMsCUop5Uag7KhLiK1JLQolrYfEtsL53I=;
        b=ca2apEoA23hEyz6E9pV0B7gIyirUTB3h8kAlAZeY1TRbmEMvzeWDxg8/ObQkJkjBM+
         5U+ZuE/lKO9Crgkov2fpYPRbxbcjrrTF30/wnKqUaC2xKXD7xRbzWV6xoSzCVm6tzUtm
         eRpCcKbpWD93LRguizbNAlF+3u+dr+W1ACMwD2rsX9QDxG1pkCmSKIY56dvd8s76TZQZ
         smv1H8eOeTX8eP+1ZwqmdY9EHy6b/5aYaW5hSknu/ZkoUPWbAXUYs4ZOF4lbGav7vOoq
         UQOQKYgB3bxV3Emf6w+qAHHA2Tu6HLf+LjpUZqAokSxERwE/PE7O30V6zK85ova51Kq7
         4Ecg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J6jJ7KhG;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id k10si164089ljj.0.2020.10.01.10.29.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:29:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id e16so6756427wrm.2
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:29:39 -0700 (PDT)
X-Received: by 2002:adf:e4c9:: with SMTP id v9mr10012247wrm.375.1601573378859;
        Thu, 01 Oct 2020 10:29:38 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id 63sm11662851wrc.63.2020.10.01.10.29.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:29:38 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:29:32 +0200
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
Subject: Re: [PATCH v3 05/39] kasan: rename (un)poison_shadow to
 (un)poison_memory
Message-ID: <20201001172932.GC4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <b19896256a15051346c87a25d01cc73a7bd999ad.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b19896256a15051346c87a25d01cc73a7bd999ad.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=J6jJ7KhG;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as
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
> The new mode won't be using shadow memory, but will reuse the same
> functions. Rename kasan_unpoison_shadow to kasan_unpoison_memory,
> and kasan_poison_shadow to kasan_poison_memory.
> 
> No functional changes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: Ia359f32815242c4704e49a5f1639ca2d2f8cba69
> ---
>  include/linux/kasan.h |  6 +++---
>  kernel/fork.c         |  4 ++--
>  mm/kasan/common.c     | 38 +++++++++++++++++++-------------------
>  mm/kasan/generic.c    | 12 ++++++------
>  mm/kasan/kasan.h      |  2 +-
>  mm/kasan/tags.c       |  2 +-
>  mm/slab_common.c      |  2 +-
>  7 files changed, 33 insertions(+), 33 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 44a9aae44138..18617d5c4cd7 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -60,7 +60,7 @@ extern void kasan_enable_current(void);
>  /* Disable reporting bugs for current task */
>  extern void kasan_disable_current(void);
>  
> -void kasan_unpoison_shadow(const void *address, size_t size);
> +void kasan_unpoison_memory(const void *address, size_t size);
>  
>  void kasan_unpoison_task_stack(struct task_struct *task);
>  
> @@ -97,7 +97,7 @@ struct kasan_cache {
>  size_t __ksize(const void *);
>  static inline void kasan_unpoison_slab(const void *ptr)
>  {
> -	kasan_unpoison_shadow(ptr, __ksize(ptr));
> +	kasan_unpoison_memory(ptr, __ksize(ptr));
>  }
>  size_t kasan_metadata_size(struct kmem_cache *cache);
>  
> @@ -106,7 +106,7 @@ void kasan_restore_multi_shot(bool enabled);
>  
>  #else /* CONFIG_KASAN */
>  
> -static inline void kasan_unpoison_shadow(const void *address, size_t size) {}
> +static inline void kasan_unpoison_memory(const void *address, size_t size) {}
>  
>  static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
>  
> diff --git a/kernel/fork.c b/kernel/fork.c
> index 4d32190861bd..b41fecca59d7 100644
> --- a/kernel/fork.c
> +++ b/kernel/fork.c
> @@ -224,8 +224,8 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
>  		if (!s)
>  			continue;
>  
> -		/* Clear the KASAN shadow of the stack. */
> -		kasan_unpoison_shadow(s->addr, THREAD_SIZE);
> +		/* Mark stack accessible for KASAN. */
> +		kasan_unpoison_memory(s->addr, THREAD_SIZE);
>  
>  		/* Clear stale pointers from reused stack. */
>  		memset(s->addr, 0, THREAD_SIZE);
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 89e5ef9417a7..a4b73fa0dd7e 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -108,7 +108,7 @@ void *memcpy(void *dest, const void *src, size_t len)
>   * Poisons the shadow memory for 'size' bytes starting from 'addr'.
>   * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
>   */
> -void kasan_poison_shadow(const void *address, size_t size, u8 value)
> +void kasan_poison_memory(const void *address, size_t size, u8 value)
>  {
>  	void *shadow_start, *shadow_end;
>  
> @@ -125,7 +125,7 @@ void kasan_poison_shadow(const void *address, size_t size, u8 value)
>  	__memset(shadow_start, value, shadow_end - shadow_start);
>  }
>  
> -void kasan_unpoison_shadow(const void *address, size_t size)
> +void kasan_unpoison_memory(const void *address, size_t size)
>  {
>  	u8 tag = get_tag(address);
>  
> @@ -136,7 +136,7 @@ void kasan_unpoison_shadow(const void *address, size_t size)
>  	 */
>  	address = reset_tag(address);
>  
> -	kasan_poison_shadow(address, size, tag);
> +	kasan_poison_memory(address, size, tag);
>  
>  	if (size & KASAN_SHADOW_MASK) {
>  		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
> @@ -153,7 +153,7 @@ static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
>  	void *base = task_stack_page(task);
>  	size_t size = sp - base;
>  
> -	kasan_unpoison_shadow(base, size);
> +	kasan_unpoison_memory(base, size);
>  }
>  
>  /* Unpoison the entire stack for a task. */
> @@ -172,7 +172,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
>  	 */
>  	void *base = (void *)((unsigned long)watermark & ~(THREAD_SIZE - 1));
>  
> -	kasan_unpoison_shadow(base, watermark - base);
> +	kasan_unpoison_memory(base, watermark - base);
>  }
>  
>  void kasan_alloc_pages(struct page *page, unsigned int order)
> @@ -186,13 +186,13 @@ void kasan_alloc_pages(struct page *page, unsigned int order)
>  	tag = random_tag();
>  	for (i = 0; i < (1 << order); i++)
>  		page_kasan_tag_set(page + i, tag);
> -	kasan_unpoison_shadow(page_address(page), PAGE_SIZE << order);
> +	kasan_unpoison_memory(page_address(page), PAGE_SIZE << order);
>  }
>  
>  void kasan_free_pages(struct page *page, unsigned int order)
>  {
>  	if (likely(!PageHighMem(page)))
> -		kasan_poison_shadow(page_address(page),
> +		kasan_poison_memory(page_address(page),
>  				PAGE_SIZE << order,
>  				KASAN_FREE_PAGE);
>  }
> @@ -284,18 +284,18 @@ void kasan_poison_slab(struct page *page)
>  
>  	for (i = 0; i < compound_nr(page); i++)
>  		page_kasan_tag_reset(page + i);
> -	kasan_poison_shadow(page_address(page), page_size(page),
> +	kasan_poison_memory(page_address(page), page_size(page),
>  			KASAN_KMALLOC_REDZONE);
>  }
>  
>  void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
>  {
> -	kasan_unpoison_shadow(object, cache->object_size);
> +	kasan_unpoison_memory(object, cache->object_size);
>  }
>  
>  void kasan_poison_object_data(struct kmem_cache *cache, void *object)
>  {
> -	kasan_poison_shadow(object,
> +	kasan_poison_memory(object,
>  			round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE),
>  			KASAN_KMALLOC_REDZONE);
>  }
> @@ -408,7 +408,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>  	}
>  
>  	rounded_up_size = round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE);
> -	kasan_poison_shadow(object, rounded_up_size, KASAN_KMALLOC_FREE);
> +	kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
>  
>  	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
>  			unlikely(!(cache->flags & SLAB_KASAN)))
> @@ -448,8 +448,8 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  		tag = assign_tag(cache, object, false, keep_tag);
>  
>  	/* Tag is ignored in set_tag without CONFIG_KASAN_SW_TAGS */
> -	kasan_unpoison_shadow(set_tag(object, tag), size);
> -	kasan_poison_shadow((void *)redzone_start, redzone_end - redzone_start,
> +	kasan_unpoison_memory(set_tag(object, tag), size);
> +	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
>  		KASAN_KMALLOC_REDZONE);
>  
>  	if (cache->flags & SLAB_KASAN)
> @@ -489,8 +489,8 @@ void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
>  				KASAN_SHADOW_SCALE_SIZE);
>  	redzone_end = (unsigned long)ptr + page_size(page);
>  
> -	kasan_unpoison_shadow(ptr, size);
> -	kasan_poison_shadow((void *)redzone_start, redzone_end - redzone_start,
> +	kasan_unpoison_memory(ptr, size);
> +	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
>  		KASAN_PAGE_REDZONE);
>  
>  	return (void *)ptr;
> @@ -523,7 +523,7 @@ void kasan_poison_kfree(void *ptr, unsigned long ip)
>  			kasan_report_invalid_free(ptr, ip);
>  			return;
>  		}
> -		kasan_poison_shadow(ptr, page_size(page), KASAN_FREE_PAGE);
> +		kasan_poison_memory(ptr, page_size(page), KASAN_FREE_PAGE);
>  	} else {
>  		__kasan_slab_free(page->slab_cache, ptr, ip, false);
>  	}
> @@ -709,7 +709,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
>  	 * // vmalloc() allocates memory
>  	 * // let a = area->addr
>  	 * // we reach kasan_populate_vmalloc
> -	 * // and call kasan_unpoison_shadow:
> +	 * // and call kasan_unpoison_memory:
>  	 * STORE shadow(a), unpoison_val
>  	 * ...
>  	 * STORE shadow(a+99), unpoison_val	x = LOAD p
> @@ -744,7 +744,7 @@ void kasan_poison_vmalloc(const void *start, unsigned long size)
>  		return;
>  
>  	size = round_up(size, KASAN_SHADOW_SCALE_SIZE);
> -	kasan_poison_shadow(start, size, KASAN_VMALLOC_INVALID);
> +	kasan_poison_memory(start, size, KASAN_VMALLOC_INVALID);
>  }
>  
>  void kasan_unpoison_vmalloc(const void *start, unsigned long size)
> @@ -752,7 +752,7 @@ void kasan_unpoison_vmalloc(const void *start, unsigned long size)
>  	if (!is_vmalloc_or_module_addr(start))
>  		return;
>  
> -	kasan_unpoison_shadow(start, size);
> +	kasan_unpoison_memory(start, size);
>  }
>  
>  static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 37ccfadd3263..7006157c674b 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -202,9 +202,9 @@ static void register_global(struct kasan_global *global)
>  {
>  	size_t aligned_size = round_up(global->size, KASAN_SHADOW_SCALE_SIZE);
>  
> -	kasan_unpoison_shadow(global->beg, global->size);
> +	kasan_unpoison_memory(global->beg, global->size);
>  
> -	kasan_poison_shadow(global->beg + aligned_size,
> +	kasan_poison_memory(global->beg + aligned_size,
>  		global->size_with_redzone - aligned_size,
>  		KASAN_GLOBAL_REDZONE);
>  }
> @@ -285,11 +285,11 @@ void __asan_alloca_poison(unsigned long addr, size_t size)
>  
>  	WARN_ON(!IS_ALIGNED(addr, KASAN_ALLOCA_REDZONE_SIZE));
>  
> -	kasan_unpoison_shadow((const void *)(addr + rounded_down_size),
> +	kasan_unpoison_memory((const void *)(addr + rounded_down_size),
>  			      size - rounded_down_size);
> -	kasan_poison_shadow(left_redzone, KASAN_ALLOCA_REDZONE_SIZE,
> +	kasan_poison_memory(left_redzone, KASAN_ALLOCA_REDZONE_SIZE,
>  			KASAN_ALLOCA_LEFT);
> -	kasan_poison_shadow(right_redzone,
> +	kasan_poison_memory(right_redzone,
>  			padding_size + KASAN_ALLOCA_REDZONE_SIZE,
>  			KASAN_ALLOCA_RIGHT);
>  }
> @@ -301,7 +301,7 @@ void __asan_allocas_unpoison(const void *stack_top, const void *stack_bottom)
>  	if (unlikely(!stack_top || stack_top > stack_bottom))
>  		return;
>  
> -	kasan_unpoison_shadow(stack_top, stack_bottom - stack_top);
> +	kasan_unpoison_memory(stack_top, stack_bottom - stack_top);
>  }
>  EXPORT_SYMBOL(__asan_allocas_unpoison);
>  
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index ac499456740f..03450d3b31f7 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -150,7 +150,7 @@ static inline bool addr_has_shadow(const void *addr)
>  	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
>  }
>  
> -void kasan_poison_shadow(const void *address, size_t size, u8 value);
> +void kasan_poison_memory(const void *address, size_t size, u8 value);
>  
>  /**
>   * check_memory_region - Check memory region, and report if invalid access.
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 5c8b08a25715..4bdd7dbd6647 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -153,7 +153,7 @@ EXPORT_SYMBOL(__hwasan_storeN_noabort);
>  
>  void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
>  {
> -	kasan_poison_shadow((void *)addr, size, tag);
> +	kasan_poison_memory((void *)addr, size, tag);
>  }
>  EXPORT_SYMBOL(__hwasan_tag_memory);
>  
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index f9ccd5dc13f3..53d0f8bb57ea 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1176,7 +1176,7 @@ size_t ksize(const void *objp)
>  	 * We assume that ksize callers could use whole allocated area,
>  	 * so we need to unpoison this area.
>  	 */
> -	kasan_unpoison_shadow(objp, size);
> +	kasan_unpoison_memory(objp, size);
>  	return size;
>  }
>  EXPORT_SYMBOL(ksize);
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001172932.GC4162920%40elver.google.com.
