Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ77V76QKGQEBBJFQNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 679252AF484
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 16:13:44 +0100 (CET)
Received: by mail-ej1-x637.google.com with SMTP id dx19sf784016ejb.7
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 07:13:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605107624; cv=pass;
        d=google.com; s=arc-20160816;
        b=UsVo3pIsb68Ro3i2HcY3QQoYZ6hyQmZ22fQDSbUyOhunH6ZFrgIv5Tpo464k4D7sw8
         0juohxX9cue3sHLdrnShFd2bAMLjItfh2dnIxI68btdELdVoCnz/Gh+m/ggZzt4OTneP
         MT9GkHx9H7JtLXLi6GCb6PK13VrVgHa2bJzKs6Oflp3AoYLYs0+hEAhMn0aHww2OfyeF
         SOUOMlU2qOfWAJjA4beZGlKS+9sX1Q/JcVSGVWCOsLjvTyEfe//uwSxaiXOhjzS+sCwp
         aV5+l7CsqV4m6aYVUlY4iLRtDZOfKhONCe1Nzh1hdSwP5HvGDZr9GDMeD3pD6FQuQ4vA
         e/QQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=jxR6BGExBMeSRxqJEdo4rSaZgT8dCyKVOpjRrakQaBA=;
        b=sgksHc9AkI2b80M0ahHXDwX7JDZ6QL6RpmcTKe/0WgyW53KvyimRcY6K9TB30DV1uP
         CJmuKAbyG1+04AwP4NRC72fWnWbRn7JXK5XEsMdtNqIgC30S0tnutg02anXlbYrKa92/
         TxZLGJFfvX1rN5LdewUdlOEAIDu0B5Kd2cu6UUHcd26YggN7HIwdxYfmUeMCK0ePO4nc
         9XxCOjU0eHYjDzN0b736LDm90bEbVYoelQKX1cCbl6jrjIyq6Tiw0/esi1TpuxMnqgdv
         DeL94aLaDzHBMGeO1te+nyPnT7cMJMac/wLpuHcW0xxtPkwa8x0mQ10Mnneadcvm8BTl
         6Isg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gCOH6uGa;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=jxR6BGExBMeSRxqJEdo4rSaZgT8dCyKVOpjRrakQaBA=;
        b=sgiVu7Q7Pd1Yxek9aQTgscD7BoUM6DaJUW8NxeObQJ9bkVLCLLpyBYd5Ii04+hmxYf
         V0DXlAw+IR+z96+UXaM/9XczZwTit3S5qLGRblpk2OfN3+Euh1d6y1WOCqVqPpc6MjSL
         hsWl68VeHZu0zTycwdGRfaThd7zBk9ncV8PHVt/i1AZdIaO49TJR7nPV1gzrRxovApZ0
         skOHQXhZpoKGEZi5EVhCyD4D/t8S+8jE+dpLaIZmdJrTAlKx5Qc2DCrbUon3uWfqjZVb
         JaKP3++1q9xLnomsZwL6nX8qdXdJ1op6fcsfULmCdPM+fDUi9u/Gz+H5KHCLzNTKwBEd
         R6Uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jxR6BGExBMeSRxqJEdo4rSaZgT8dCyKVOpjRrakQaBA=;
        b=DnpnbgIgX+iqS8Ibg9R9RkmtPgEqYgzZyHM+d+/1es1MMIyRGLus3px+MUhAdHw3uV
         f8C17kb3b9LFtgr8k0Cw2a5e4qQi3iFvzFNkUMHH3/lcEsltQI8xv7b//5HqLYVY7y2U
         Q/+Hp7FH62akddBV/EtEOoJRoL5q66vQX7A4DLpQv8CuaYujRzKrWVxZrC5MdzJrGgrH
         bvDYDn6vIA2HVsdIeAbDWgXAXyOMlM/R5hpcQL/oyRufREyeDfbjSfhTbGWGEh5unFJ/
         rsFsFDEgUAOb8V69E+CoUTE0HiDO1Ref4PqxsGavDh9sbNXpNGFdvXRIEeZ0C3vIlz4q
         1vvQ==
X-Gm-Message-State: AOAM531pQ9ZuoQVJ/nnJqC3e956V6whVM9X1PuC2pJHUfK61ft73hQ+d
	wuiQnILzY1RVqnVhdHQM+jg=
X-Google-Smtp-Source: ABdhPJz3ZX9GdEg1ppCUK/Xid96g83vZx5adRH/UbZAEy0OzhNasXrl9BOfPMnP1UKdyPCmdYDZMUw==
X-Received: by 2002:a17:906:170f:: with SMTP id c15mr26310696eje.347.1605107624106;
        Wed, 11 Nov 2020 07:13:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c04e:: with SMTP id k14ls5430edo.1.gmail; Wed, 11 Nov
 2020 07:13:43 -0800 (PST)
X-Received: by 2002:a05:6402:7c7:: with SMTP id u7mr27136717edy.351.1605107623071;
        Wed, 11 Nov 2020 07:13:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605107623; cv=none;
        d=google.com; s=arc-20160816;
        b=UZxKxeeXU+yPUrfQjfCDsuEFAlXV+yh4RpsRH8Oncf7BKihMeVx7lotAvbtTEhP7gO
         mk55QG8KZD2cNrJxJlaMv34w6I1WsPG7n/oXDaQTBjI0x3eUdZ5RfSHquzwVEWSOgfTj
         T/8TA7khGxVhbP4+n+H4DZoxIVnK3r/iX5r59txb8Ig+nm2V78qw7JYr4Xv5IJYalfkU
         Q9EVcwDBa3T9Efu8qVSnFkxS5USOrtMn75cVLSi6RyRttMA8EduaMUHEdj+GrqlHWtVk
         7RrVIIGdZuDfA3zhjNI3nT0EkxRvZa04auPbaEo/jldONuax6r26dcqi7FD7sfLRSF1+
         Qv/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=p+INv8JEk5XPkG3ax0MxxlvUdmFmE55+jTOg5CXTsRM=;
        b=utKMQqdHY/+Q30pIMKOpWgjT5yXxyuwHyVWlkHtG0XisEFUel+pMh8xtK5TCbXB4Hy
         W+l2s7BhV/A57x2KmAdxv2bOTH/t9QaBiYXqoERv5g4s5R61p3cw6cQ0jzDPzxW/qriC
         FCGJ81/c3vQfHS7abCWFBpmKpsU9SbpGfIjRPpnNDbD6JAEb+FtTQwU0GrSaXKo/AlAS
         LcwBZAxEWf1k6ddF994dBvSqFbY9OZNsj8yUDcNeIKGDojftRqXDFk7GIq9A6USA0iuc
         AKZwYQNTZcIpF/rQCswp0z7OjStpDuzH1Ox8MfX8Gtwxaf7CTay1ISyLmwrWzXYfKJV9
         Ll5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gCOH6uGa;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id v7si135350edj.5.2020.11.11.07.13.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 07:13:43 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id s8so2838990wrw.10
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 07:13:43 -0800 (PST)
X-Received: by 2002:adf:db4a:: with SMTP id f10mr15496651wrj.420.1605107622540;
        Wed, 11 Nov 2020 07:13:42 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id p13sm2763952wrt.73.2020.11.11.07.13.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 07:13:41 -0800 (PST)
Date: Wed, 11 Nov 2020 16:13:36 +0100
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
Subject: Re: [PATCH v2 19/20] kasan, mm: allow cache merging with no metadata
Message-ID: <20201111151336.GA517454@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <936c0c198145b663e031527c49a6895bd21ac3a0.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <936c0c198145b663e031527c49a6895bd21ac3a0.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gCOH6uGa;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as
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
> The reason cache merging is disabled with KASAN is because KASAN puts its
> metadata right after the allocated object. When the merged caches have
> slightly different sizes, the metadata ends up in different places, which
> KASAN doesn't support.
> 
> It might be possible to adjust the metadata allocation algorithm and make
> it friendly to the cache merging code. Instead this change takes a simpler
> approach and allows merging caches when no metadata is present. Which is
> the case for hardware tag-based KASAN with kasan.mode=prod.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Ia114847dfb2244f297d2cb82d592bf6a07455dba
> ---
>  include/linux/kasan.h | 26 ++++++++++++++++++++++++--
>  mm/kasan/common.c     | 11 +++++++++++
>  mm/slab_common.c      | 11 ++++++++---
>  3 files changed, 43 insertions(+), 5 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 534ab3e2935a..c754eca356f7 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -81,17 +81,35 @@ struct kasan_cache {
>  };
>  
>  #ifdef CONFIG_KASAN_HW_TAGS
> +
>  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
> +
>  static inline kasan_enabled(void)
>  {
>  	return static_branch_likely(&kasan_flag_enabled);
>  }
> -#else
> +
> +slab_flags_t __kasan_never_merge(slab_flags_t flags);
> +static inline slab_flags_t kasan_never_merge(slab_flags_t flags)
> +{
> +	if (kasan_enabled())
> +		return __kasan_never_merge(flags);
> +	return flags;
> +}
> +
> +#else /* CONFIG_KASAN_HW_TAGS */
> +
>  static inline kasan_enabled(void)
>  {
>  	return true;
>  }
> -#endif
> +
> +static inline slab_flags_t kasan_never_merge(slab_flags_t flags)
> +{
> +	return flags;
> +}
> +
> +#endif /* CONFIG_KASAN_HW_TAGS */
>  
>  void __kasan_alloc_pages(struct page *page, unsigned int order);
>  static inline void kasan_alloc_pages(struct page *page, unsigned int order)
> @@ -240,6 +258,10 @@ static inline kasan_enabled(void)
>  {
>  	return false;
>  }
> +static inline slab_flags_t kasan_never_merge(slab_flags_t flags)
> +{
> +	return flags;
> +}
>  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
>  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
>  static inline void kasan_cache_create(struct kmem_cache *cache,
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 940b42231069..25b18c145b06 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -81,6 +81,17 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
>  }
>  #endif /* CONFIG_KASAN_STACK */
>  
> +/*
> + * Only allow cache merging when stack collection is disabled and no metadata
> + * is present.
> + */
> +slab_flags_t __kasan_never_merge(slab_flags_t flags)
> +{
> +	if (kasan_stack_collection_enabled())
> +		return flags;
> +	return flags & ~SLAB_KASAN;
> +}
> +
>  void __kasan_alloc_pages(struct page *page, unsigned int order)
>  {
>  	u8 tag;
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index f1b0c4a22f08..3042ee8ea9ce 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -18,6 +18,7 @@
>  #include <linux/seq_file.h>
>  #include <linux/proc_fs.h>
>  #include <linux/debugfs.h>
> +#include <linux/kasan.h>
>  #include <asm/cacheflush.h>
>  #include <asm/tlbflush.h>
>  #include <asm/page.h>
> @@ -49,12 +50,16 @@ static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
>  		    slab_caches_to_rcu_destroy_workfn);
>  
>  /*
> - * Set of flags that will prevent slab merging
> + * Set of flags that will prevent slab merging.
> + * Use slab_never_merge() instead.
>   */
>  #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
>  		SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
>  		SLAB_FAILSLAB | SLAB_KASAN)

Rather than changing this to require using slab_never_merge() which
removes SLAB_KASAN, could we not just have a function
kasan_never_merge() that returns KASAN-specific flags that should never
result in merging -- because as-is now, making kasan_never_merge()
remove the SLAB_KASAN flag seems the wrong way around.

Could we not just do this:

  #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
  		SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
  		SLAB_FAILSLAB | kasan_never_merge())

??

Of course that might be problematic if this always needs to be a
compile-time constant, but currently that's not a requirement.

> +/* KASAN allows merging in some configurations and will remove SLAB_KASAN. */
> +#define slab_never_merge() (kasan_never_merge(SLAB_NEVER_MERGE))

Braces unnecessary.

>  #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
>  			 SLAB_CACHE_DMA32 | SLAB_ACCOUNT)
>  
> @@ -164,7 +169,7 @@ static unsigned int calculate_alignment(slab_flags_t flags,
>   */
>  int slab_unmergeable(struct kmem_cache *s)
>  {
> -	if (slab_nomerge || (s->flags & SLAB_NEVER_MERGE))
> +	if (slab_nomerge || (s->flags & slab_never_merge()))
>  		return 1;
>  
>  	if (s->ctor)
> @@ -198,7 +203,7 @@ struct kmem_cache *find_mergeable(unsigned int size, unsigned int align,
>  	size = ALIGN(size, align);
>  	flags = kmem_cache_flags(size, flags, name, NULL);
>  
> -	if (flags & SLAB_NEVER_MERGE)
> +	if (flags & slab_never_merge())
>  		return NULL;
>  
>  	list_for_each_entry_reverse(s, &slab_caches, list) {
> -- 
> 2.29.2.222.g5d2a92d10f8-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111151336.GA517454%40elver.google.com.
