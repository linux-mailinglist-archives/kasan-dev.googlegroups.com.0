Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDVD3D5QKGQEYWXMC7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 660E4280520
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:27:43 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id j17sf2090406lfm.9
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:27:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601573263; cv=pass;
        d=google.com; s=arc-20160816;
        b=UAHVlpjhxlLXpsvPErGhMQnRKmsLPuYM+FaScXCTqNbPxc8qsssidJYT24/DEnpCXG
         2XK5Z2NnFw0FbKyqtGS+F85UqlI2F+8mselvYFDGA4DgnBnifbSDeT3Ys54tO8PDO1Wl
         345GaR/o4n74sEncq/7OzOYZQ52SaiviqCwVivhO04N/Qr2zCynMeMr6z0tjKVnhVINu
         cLl/+FuFLJyRJ5MGX/BFKjm+649upAYNjKuI6AbOJIt+ohr3efx8KJUb9bybWoor1/D7
         nIAG0M/CqdQ9tePt8uzQnZcwOUIcVTLibTdHr1OEGj+vxVxJnZ+zypILh2Kj0Im+5sBx
         6FFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=hlCdr6j/YJJIodBuNsQZ8FoYk9YDU7OsQG7SpIQoHwc=;
        b=QyTBF9Tl1JVG0SCvnowtiBiZIyn7KJDKWY5PAO1XbwJNDAq/eKsZfdtDl1Ypo5ujH5
         FeKM6+LG+JnmKKsu0FYhGgeCmkYqgI9tGluVso+pr5/a4EQuBqEgNnLfBHi21P5k+KYq
         ueeabx7C3NBL3sNzaOQN53Zu2xQ0pcEFF4Z5CKh3kkjNnKM3tF0eMP1f+nF1MPKcTx54
         cjPRQJJRUKimfDSBmiMeRoc0urT/Qis0ZVMmttqvQhoqq2jzZWm1fq1Cdmv5TUWFI7E4
         XUQpomSlol/HQnKFTzidXEKg9EmbCv0ACunIUTLAF84wtyMKHq+uVAHGZeUJ+NkoJhMX
         hxUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UbnsuLPi;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=hlCdr6j/YJJIodBuNsQZ8FoYk9YDU7OsQG7SpIQoHwc=;
        b=jjvPVfNypOFv1CkvgfFufS/obx+6IbabwiAZLHb3EQ5xn3lBdwYoirUyaTTAlLHyfB
         ckjG/ryCqikaZfad9dhYJI+AXBCxoRKBpGKshTvpohgT6RlE6D9EuIEIvOlav9cNTe7A
         eqkjYQIvHbbrN4DBa5c1RQQDz8dE+ojydlYR3Rhjmp2bLyi1oReALd2rWLJArfZArHIn
         3ON1tb7mGoA024A686iPrkpK0Om18jmS+cLub6kgBDL0eS5lvxaOvTFt+S2i9MCrxRg7
         IxIEM46Zq1Lt9IfyL1Sc19PCg/EJtqvyP72f3OvSFOangfQSbuoORPsp/Q07Qwi5bBd3
         U6CQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hlCdr6j/YJJIodBuNsQZ8FoYk9YDU7OsQG7SpIQoHwc=;
        b=tZcVsMqWNyTEJdDarxGKVGofSjxV5DvJKTEu28N5WBVlIP4POklt3ACue7BR1p4bak
         O0qhUBergd1yyXlr60jFJp6aQjVC3YePtJVKHJncusxDfKk10b8CMR5VJJE6cnUV3/KE
         yacdgb0emIm8p2e50qLZsdTH+CK2PwkcmPBW8kAVMumBi390gU6P4nkf8HXDc2x2h7dF
         GRo6GsXvH4J20R9Ag4nHDT8WqmoLwRstQUrkON27JCd0dqVyLS05hjiur0zuwdnFdNhn
         spTKBskKmnvfz3ndxq6w2XvtsN8aLP32rcpFU1yGhTqtk51hl6eKddFCcddRRkdsM7ld
         tjRQ==
X-Gm-Message-State: AOAM530XauGIMiYmjcsL+rDw89p368iA2MCXav0YvXi8OwhCt9GI6JUM
	VnF9dfprCjJFvxcvpDCsy/8=
X-Google-Smtp-Source: ABdhPJxiWDUNESjFstLzn0ulU0dyUeouzdFaFPlUf+cNulEDuJ82DYGj2/ubfuXL7R9GvLbZ/GLSFg==
X-Received: by 2002:a2e:a163:: with SMTP id u3mr2866339ljl.414.1601573262921;
        Thu, 01 Oct 2020 10:27:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:544e:: with SMTP id d14ls1673911lfn.2.gmail; Thu, 01 Oct
 2020 10:27:41 -0700 (PDT)
X-Received: by 2002:a05:6512:707:: with SMTP id b7mr3247987lfs.457.1601573261872;
        Thu, 01 Oct 2020 10:27:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601573261; cv=none;
        d=google.com; s=arc-20160816;
        b=clz8RoQF6XARawFrDxZymPT6apkXEAGdcReD8Y8Grt8HJpk4bn+NHRqaXDsmrMKUVb
         Tr9+JVp4PhJkNeI0PPd1ctuTnNvEx4wdRJfmS7goJOIB9Y1kjD0QmTW2Gtno5GVpP2bB
         cuBthckW66bwICC5B7zto/WUPp5zEI/JzHSIj/QGZVfPAKueKa0fxPd46mPz6o8wYoPt
         BaioGIA7cMJYkAC5+D2ZWD12DEk8E2ZumXDtphof50v6HS6zu9J6ww7j54BSv+6DsNjj
         Gn0sV7oQFJgwjCRIZoFtHdhPKNnn3YYKCbidjEp7NlDfKrY5jKYDT5XOk/rgb9PwYjng
         /Tgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=z6gRseKf/QBoG3LPhRd6/dtXrjTURXY+qNj3glhnuQo=;
        b=GITwtqsDFW8MAulW7X5SEnmTof4WDSCqdjuZwuNyxKPZ/M8qzI9+T/4BpIUBBya/VW
         typDvpCnyuAtVB79mw+pHTpu7c3s98xG7fRQ3g9qdLbUYg+e3o9clWDAyqw76dpmvd9a
         F3L2S10Gs5ZoH2ZRLEe0WmjAeTe/v7LBp2W19qqYtOtNYJVHHBeWdWVoDlcnBkVDRrai
         j5g4eaLg1dl6WzfkJlpXZzOjl+wS4olXgb4WvgV2fPtqlPu/twaY3MGno3oFq6V2lBN7
         SMPmuMFi2WFPCqoHjZG6BUNmlkLKUhwDmeeV7pxsmEyfN4bQ/oEa5V5p3aLf0AQRY4xj
         ng2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UbnsuLPi;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id r6si217263lji.4.2020.10.01.10.27.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:27:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id z1so6742731wrt.3
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:27:41 -0700 (PDT)
X-Received: by 2002:adf:dd0b:: with SMTP id a11mr9987807wrm.422.1601573260984;
        Thu, 01 Oct 2020 10:27:40 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id p3sm772060wmm.40.2020.10.01.10.27.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:27:40 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:27:34 +0200
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
Subject: Re: [PATCH v3 03/39] kasan: group vmalloc code
Message-ID: <20201001172734.GA4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <4f59e6ddef35c6a3b93b0951a47e7e9b8a680667.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4f59e6ddef35c6a3b93b0951a47e7e9b8a680667.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UbnsuLPi;       spf=pass
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
> Group all vmalloc-related function declarations in include/linux/kasan.h,
> and their implementations in mm/kasan/common.c.
> 
> No functional changes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: Ie20b6c689203cd6de4fd7f2c465ec081c00c5f15
> ---
>  include/linux/kasan.h | 41 +++++++++++++----------
>  mm/kasan/common.c     | 78 ++++++++++++++++++++++---------------------
>  2 files changed, 63 insertions(+), 56 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 087fba34b209..bd5b4965a269 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -69,19 +69,6 @@ struct kasan_cache {
>  	int free_meta_offset;
>  };
>  
> -/*
> - * These functions provide a special case to support backing module
> - * allocations with real shadow memory. With KASAN vmalloc, the special
> - * case is unnecessary, as the work is handled in the generic case.
> - */
> -#ifndef CONFIG_KASAN_VMALLOC
> -int kasan_module_alloc(void *addr, size_t size);
> -void kasan_free_shadow(const struct vm_struct *vm);
> -#else
> -static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
> -static inline void kasan_free_shadow(const struct vm_struct *vm) {}
> -#endif
> -
>  int kasan_add_zero_shadow(void *start, unsigned long size);
>  void kasan_remove_zero_shadow(void *start, unsigned long size);
>  
> @@ -150,9 +137,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
>  	return false;
>  }
>  
> -static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
> -static inline void kasan_free_shadow(const struct vm_struct *vm) {}
> -
>  static inline int kasan_add_zero_shadow(void *start, unsigned long size)
>  {
>  	return 0;
> @@ -205,13 +189,16 @@ static inline void *kasan_reset_tag(const void *addr)
>  #endif /* CONFIG_KASAN_SW_TAGS */
>  
>  #ifdef CONFIG_KASAN_VMALLOC
> +
>  int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
>  void kasan_poison_vmalloc(const void *start, unsigned long size);
>  void kasan_unpoison_vmalloc(const void *start, unsigned long size);
>  void kasan_release_vmalloc(unsigned long start, unsigned long end,
>  			   unsigned long free_region_start,
>  			   unsigned long free_region_end);
> -#else
> +
> +#else /* CONFIG_KASAN_VMALLOC */
> +
>  static inline int kasan_populate_vmalloc(unsigned long start,
>  					unsigned long size)
>  {
> @@ -226,7 +213,25 @@ static inline void kasan_release_vmalloc(unsigned long start,
>  					 unsigned long end,
>  					 unsigned long free_region_start,
>  					 unsigned long free_region_end) {}
> -#endif
> +
> +#endif /* CONFIG_KASAN_VMALLOC */
> +
> +#if defined(CONFIG_KASAN) && !defined(CONFIG_KASAN_VMALLOC)
> +
> +/*
> + * These functions provide a special case to support backing module
> + * allocations with real shadow memory. With KASAN vmalloc, the special
> + * case is unnecessary, as the work is handled in the generic case.
> + */
> +int kasan_module_alloc(void *addr, size_t size);
> +void kasan_free_shadow(const struct vm_struct *vm);
> +
> +#else /* CONFIG_KASAN && !CONFIG_KASAN_VMALLOC */
> +
> +static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
> +static inline void kasan_free_shadow(const struct vm_struct *vm) {}
> +
> +#endif /* CONFIG_KASAN && !CONFIG_KASAN_VMALLOC */
>  
>  #ifdef CONFIG_KASAN_INLINE
>  void kasan_non_canonical_hook(unsigned long addr);
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 33d863f55db1..89e5ef9417a7 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -536,44 +536,6 @@ void kasan_kfree_large(void *ptr, unsigned long ip)
>  	/* The object will be poisoned by page_alloc. */
>  }
>  
> -#ifndef CONFIG_KASAN_VMALLOC
> -int kasan_module_alloc(void *addr, size_t size)
> -{
> -	void *ret;
> -	size_t scaled_size;
> -	size_t shadow_size;
> -	unsigned long shadow_start;
> -
> -	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
> -	scaled_size = (size + KASAN_SHADOW_MASK) >> KASAN_SHADOW_SCALE_SHIFT;
> -	shadow_size = round_up(scaled_size, PAGE_SIZE);
> -
> -	if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
> -		return -EINVAL;
> -
> -	ret = __vmalloc_node_range(shadow_size, 1, shadow_start,
> -			shadow_start + shadow_size,
> -			GFP_KERNEL,
> -			PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
> -			__builtin_return_address(0));
> -
> -	if (ret) {
> -		__memset(ret, KASAN_SHADOW_INIT, shadow_size);
> -		find_vm_area(addr)->flags |= VM_KASAN;
> -		kmemleak_ignore(ret);
> -		return 0;
> -	}
> -
> -	return -ENOMEM;
> -}
> -
> -void kasan_free_shadow(const struct vm_struct *vm)
> -{
> -	if (vm->flags & VM_KASAN)
> -		vfree(kasan_mem_to_shadow(vm->addr));
> -}
> -#endif
> -
>  #ifdef CONFIG_MEMORY_HOTPLUG
>  static bool shadow_mapped(unsigned long addr)
>  {
> @@ -685,6 +647,7 @@ core_initcall(kasan_memhotplug_init);
>  #endif
>  
>  #ifdef CONFIG_KASAN_VMALLOC
> +
>  static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>  				      void *unused)
>  {
> @@ -923,4 +886,43 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
>  				       (unsigned long)shadow_end);
>  	}
>  }
> +
> +#else /* CONFIG_KASAN_VMALLOC */
> +
> +int kasan_module_alloc(void *addr, size_t size)
> +{
> +	void *ret;
> +	size_t scaled_size;
> +	size_t shadow_size;
> +	unsigned long shadow_start;
> +
> +	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
> +	scaled_size = (size + KASAN_SHADOW_MASK) >> KASAN_SHADOW_SCALE_SHIFT;
> +	shadow_size = round_up(scaled_size, PAGE_SIZE);
> +
> +	if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
> +		return -EINVAL;
> +
> +	ret = __vmalloc_node_range(shadow_size, 1, shadow_start,
> +			shadow_start + shadow_size,
> +			GFP_KERNEL,
> +			PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
> +			__builtin_return_address(0));
> +
> +	if (ret) {
> +		__memset(ret, KASAN_SHADOW_INIT, shadow_size);
> +		find_vm_area(addr)->flags |= VM_KASAN;
> +		kmemleak_ignore(ret);
> +		return 0;
> +	}
> +
> +	return -ENOMEM;
> +}
> +
> +void kasan_free_shadow(const struct vm_struct *vm)
> +{
> +	if (vm->flags & VM_KASAN)
> +		vfree(kasan_mem_to_shadow(vm->addr));
> +}
> +
>  #endif
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001172734.GA4162920%40elver.google.com.
