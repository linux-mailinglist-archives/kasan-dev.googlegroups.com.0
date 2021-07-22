Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4U74WDQMGQETSSGUWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 095B63D225D
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jul 2021 13:01:07 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id h15-20020adffd4f0000b0290137e68ed637sf2292006wrs.22
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jul 2021 04:01:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626951666; cv=pass;
        d=google.com; s=arc-20160816;
        b=fR89l2RRVqs0RbJZ/mSlrjko79gB/TebUixXYYNayQS8BN+1h92bfVJsrQBPv+x+Ip
         4/us0NdUTYapsGQ/X0OihLdBCEhe221MXv9owbMD6HX84NfupYNwX7z49FxiwulK9xXq
         4eR1GKXag449oQZKljj1yYb4qJi9qAAA2c5kXYfDIja7WIjhrniKRhSmfz3EapdbUZm/
         FTNvraBXcWyEFpXQ74olyF6G8lOBaRA4CpAYtMpI6QmoLGIVntG+sUAaRKxyRszeAe/r
         /HJifUU+VtAOtLtxJp01Uc7vRrM6+5t8eqEAtqZ9R9ryZw0m1IUzmVPrc1e0mqGo92Y4
         4U3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=LbIs9Uy06BaZp020QwtjQQDX50Vk1lNq5AfZxvZJohs=;
        b=EFNr1nrGIJQ/1XXM6x26gt3xkdVzCMWDtnrqTTt9Okz0+gtCzt39a+tr2mNlgYHf+K
         QV0YT7Sa9MIas73hiX1G6oNfl8r7nMfcSB6gIdU9NlI8ivO981mnTghQYOUjWkKqpdr4
         govFqXxUucrIzROIXvgp2Rttny4qrqTMOObn0LzvocIxLU441CtuOP8B0iEy68BoF8gT
         1eJXLYu1NHigaojQBwl9Dcm1bfNmlpAwLNx214GsY4a+6kbdVe08HshC3XftgEjOPi+0
         Av5OqoN5QTeqlWB3qrQ+8fMsYv9+PXiWrzy+bXhW0sYgTmVOcfE4AGJW5Y54agEAQlbq
         PcYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YrvoAqcZ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=LbIs9Uy06BaZp020QwtjQQDX50Vk1lNq5AfZxvZJohs=;
        b=FL+RSJseZmIc3YZJbE2wFpfwMJtLclrZffLRPM0bA69ji2/jmmXUl30rOTQNQ7TGuP
         9kE4b6hPU+LGu0Ph8+u3ymCxy8n9766MqcrpPMcPA9XEdYJQwfHAct3nhgTizdqAu6pO
         FzOS07G/NZCApGXUZzcAtg2gtKLAMQ7SrBlEuNqLAY6oGqDHzSyFUWr4r1dRALRQadah
         6f95RWGQzLaaKELieWK0q3EjotHHalFUDY151vdO71w3lq2ztKDERQaqrYs6AMuG2eJN
         ILC8ziJihXYHjgVLEFrkBVgBnPPRri211rZcMc7Mg7lXcMvxNnKekWU0b7dIKm02RopE
         O7uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LbIs9Uy06BaZp020QwtjQQDX50Vk1lNq5AfZxvZJohs=;
        b=Cfjx6ByZctMOOfidmjce37zp7jFcIUUN+mYMc/w8Afi8BR42HvBn+5thjf+y8QoQOy
         SAqWmttYN8j8XRkdi+uqQN3zdSBjquzLFyWqBdhxqLY9Wmbq4emdpxAd6mOI4u01zuni
         z865BR1ZL98Jb2Uy20YM4+HRBLIBvSWvA2dfr0NWM3LGLse3xwXxdIwJ4iIs2/qmS//4
         LOYKqU8g5gmRh6oe51XE2dQA0BEbra6ZPJ7v49rCHG5OiybO2kE4Gh+fPISgyyWqbPsO
         ExBSN5MMs/s845LRcaoNVf2ThYAQLBEZU8nJrnRHgt60vIx6y9JQcl9MFi+JEBQJzlDt
         wGlQ==
X-Gm-Message-State: AOAM530PoqD11JpkGjSi23DKSHWsJLw+/ELsiaFz3QMcDAPSs2/ar4/a
	6xp54+olik8nNuO0eu1tKGY=
X-Google-Smtp-Source: ABdhPJziczFpZI4NGOGXP023kiRO5TiSKUI5oVY1WZphMLfShi+8VzT5hrpAOf8jGwUo+spQwwbeZQ==
X-Received: by 2002:a5d:6982:: with SMTP id g2mr46918865wru.119.1626951666815;
        Thu, 22 Jul 2021 04:01:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:198b:: with SMTP id t11ls2502402wmq.2.gmail; Thu,
 22 Jul 2021 04:01:05 -0700 (PDT)
X-Received: by 2002:a7b:c934:: with SMTP id h20mr41460317wml.59.1626951665684;
        Thu, 22 Jul 2021 04:01:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626951665; cv=none;
        d=google.com; s=arc-20160816;
        b=c/T4htq6PIdxuO48AXcnC7IJ6H+y+CmQAYHjTdO6HPXb/CJUK5pCcwH/iX10tGeyQS
         b7ggJZ+9IaNz7VjlzillkDjhyO1RQLEQJov44FYsyQzTMbsfqx9oJkcWaASu0Ev+drUP
         H0CsmneMaZY8ihdPwf79rBbLJ/JFoCHplJhaU/eF3mWDyQNEOol6UP/pbUdUyx/c7tGk
         jqu/R7TLCtX6yfn6Mg2XXtMx1Oo+AZZK7C4jTKH566bt1Ch4PLLiqcBuSdlchWYlFHp9
         C+H3Hs6+SYnW0dfekq1k8/tBDAFW1tsf58334C9bNmlA7FP/mD8qkATLxZ1PbnzuTD4a
         xiGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=yw+1MR2KgBc9luUx0cAPZIkqUAmN57bRrzE4rXs4RXE=;
        b=GxvgWBvD7dubhCYwfKDiZrC37kja8W2uRANOG6UR/yTddjfZTBDB39kC2Ft+rOQPtN
         hT9IQgSy9IJ7YQDhBHTTcVHRTya2aC0NZ6gtLtkldQQAI38ZGS5l9i1fDypRImiyQ649
         68L7NIR7JbxC4LzN3HOaEkdvMlPqpqUL1qjJtHXV96VhBklb9ToW96WPS2QN+q2ib6Ub
         VjQgiFg5LbhqZsfCrfmzpgV7F7+xFs+rR9UJNPclPQ6PHb00UNvMlnKgtwxGSyLB0TEL
         s00cofD4wsj1Agl5MkX1zv9jidgW+ByPa/5L9+0o3oJxfFRiVGAz0w4xkJ0jFlwSY8ws
         ryiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YrvoAqcZ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id z70si168005wmc.0.2021.07.22.04.01.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Jul 2021 04:01:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id l7so5457948wrv.7
        for <kasan-dev@googlegroups.com>; Thu, 22 Jul 2021 04:01:05 -0700 (PDT)
X-Received: by 2002:adf:ffd1:: with SMTP id x17mr26958377wrs.411.1626951665168;
        Thu, 22 Jul 2021 04:01:05 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:f1d2:f5fd:de90:c735])
        by smtp.gmail.com with ESMTPSA id a8sm29702579wrt.61.2021.07.22.04.01.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jul 2021 04:01:04 -0700 (PDT)
Date: Thu, 22 Jul 2021 13:00:58 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Subject: Re: [PATCH v2 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash
 with KASAN_VMALLOC
Message-ID: <YPlP6h4O1WA0NVDs@elver.google.com>
References: <20210720025105.103680-1-wangkefeng.wang@huawei.com>
 <20210720025105.103680-4-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210720025105.103680-4-wangkefeng.wang@huawei.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YrvoAqcZ;       spf=pass
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

On Tue, Jul 20, 2021 at 10:51AM +0800, Kefeng Wang wrote:
> With KASAN_VMALLOC and NEED_PER_CPU_PAGE_FIRST_CHUNK, it crashs,
> 
> Unable to handle kernel paging request at virtual address ffff7000028f2000
> ...
> swapper pgtable: 64k pages, 48-bit VAs, pgdp=0000000042440000
> [ffff7000028f2000] pgd=000000063e7c0003, p4d=000000063e7c0003, pud=000000063e7c0003, pmd=000000063e7b0003, pte=0000000000000000
> Internal error: Oops: 96000007 [#1] PREEMPT SMP
> Modules linked in:
> CPU: 0 PID: 0 Comm: swapper Not tainted 5.13.0-rc4-00003-gc6e6e28f3f30-dirty #62
> Hardware name: linux,dummy-virt (DT)
> pstate: 200000c5 (nzCv daIF -PAN -UAO -TCO BTYPE=--)
> pc : kasan_check_range+0x90/0x1a0
> lr : memcpy+0x88/0xf4
> sp : ffff80001378fe20
> ...
> Call trace:
>  kasan_check_range+0x90/0x1a0
>  pcpu_page_first_chunk+0x3f0/0x568
>  setup_per_cpu_areas+0xb8/0x184
>  start_kernel+0x8c/0x328
> 
> The vm area used in vm_area_register_early() has no kasan shadow memory,
> Let's add a new kasan_populate_early_vm_area_shadow() function to populate
> the vm area shadow memory to fix the issue.
> 
> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>

Acked-by: Marco Elver <elver@google.com>

for the kasan bits.

> ---
>  arch/arm64/mm/kasan_init.c | 17 +++++++++++++++++
>  include/linux/kasan.h      |  6 ++++++
>  mm/kasan/init.c            |  5 +++++
>  mm/vmalloc.c               |  1 +
>  4 files changed, 29 insertions(+)
> 
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index 61b52a92b8b6..46c1b3722901 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -287,6 +287,23 @@ static void __init kasan_init_depth(void)
>  	init_task.kasan_depth = 0;
>  }
>  
> +#ifdef CONFIG_KASAN_VMALLOC
> +void __init kasan_populate_early_vm_area_shadow(void *start, unsigned long size)
> +{
> +	unsigned long shadow_start, shadow_end;
> +
> +	if (!is_vmalloc_or_module_addr(start))
> +		return;
> +
> +	shadow_start = (unsigned long)kasan_mem_to_shadow(start);
> +	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
> +	shadow_end = (unsigned long)kasan_mem_to_shadow(start + size);
> +	shadow_end = ALIGN(shadow_end, PAGE_SIZE);
> +	kasan_map_populate(shadow_start, shadow_end,
> +			   early_pfn_to_nid(virt_to_pfn(start)));
> +}
> +#endif
> +
>  void __init kasan_init(void)
>  {
>  	kasan_init_shadow();
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index dd874a1ee862..3f8c26d9ef82 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -133,6 +133,8 @@ struct kasan_cache {
>  	bool is_kmalloc;
>  };
>  
> +void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
> +
>  slab_flags_t __kasan_never_merge(void);
>  static __always_inline slab_flags_t kasan_never_merge(void)
>  {
> @@ -303,6 +305,10 @@ void kasan_restore_multi_shot(bool enabled);
>  
>  #else /* CONFIG_KASAN */
>  
> +static inline void kasan_populate_early_vm_area_shadow(void *start,
> +						       unsigned long size)
> +{ }
> +
>  static inline slab_flags_t kasan_never_merge(void)
>  {
>  	return 0;
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index cc64ed6858c6..d39577d088a1 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -279,6 +279,11 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
>  	return 0;
>  }
>  
> +void __init __weak kasan_populate_early_vm_area_shadow(void *start,
> +						       unsigned long size)
> +{
> +}
> +
>  static void kasan_free_pte(pte_t *pte_start, pmd_t *pmd)
>  {
>  	pte_t *pte;
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index a98cf97f032f..f19e07314ee5 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -2249,6 +2249,7 @@ void __init vm_area_register_early(struct vm_struct *vm, size_t align)
>  	vm->addr = (void *)addr;
>  
>  	vm_area_add_early(vm);
> +	kasan_populate_early_vm_area_shadow(vm->addr, vm->size);
>  }
>  
>  static void vmap_init_free_space(void)
> -- 
> 2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YPlP6h4O1WA0NVDs%40elver.google.com.
