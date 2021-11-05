Return-Path: <kasan-dev+bncBDOY5FWKT4KRBOEVS2GAMGQE3YGHJMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BA0544694B
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Nov 2021 20:49:13 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id c14-20020ac87d8e000000b002ac69908b09sf6774070qtd.9
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Nov 2021 12:49:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1636141752; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q2j70QLGosV8e3yXh4zvlR5YAHaPHbX+cx7+LpGEtbJQPMzHMD9nLbmMBuI+/rNZX/
         nzo+2ar55rJ7U1lbYdF2Mr9sJnUVmrXRoXLJ3+iYClVtckM5sHVh1mUpjF2jnDs4zOZM
         wJ+D8hYZH88774/zVz/FusrzeONfVMnUQcRzo3IiY9Xd1qpY71Gb9+wucroULghTQmLT
         WUVVk31iWZy+MpeHWRTLNZ4mMXupn61IR8G1QMFyXRVn8Q0rLfFDsCSTllCMbIVhxDcm
         e+V7MP2TxkiotF1+4q8cxMaLoY0fd1TpDWidA+N/mqlV1INr+gEj71rc+FG8g4B0k43t
         7n6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=dkFi8MoHKqeSZU/lr732phmmAmc+USofM+6QBduXIAw=;
        b=xIxabjZmduINHIEMY1RRttH1A/DFWzJujVB/oNXFOQsebpyNNaLN0yDY92wi5THK7v
         IkiB9Sfd1llb7tAA5epd/jYIYSmkuEVjzSIckHHp5jsP6rZK75oXE2FM7hVhTtMHPD82
         bDA2XmYuuW3JNIUCOfX631qjmSV+UAQ+OXJSuqeb4pz2KoH4SyG0z+7P65fxyztjOPHg
         IdC7411Drk2E7nddsGQQY/1vh6F/3z18xSGHkOOi8G7IcmwRyUZ7qJ/UXr9S4PwpCJ8t
         V0XC0zBu1tkJVLCOWAF+Jz9Ha5aN/OS8xnKkLlSqWeRl53EqYF0hqx8U2HDvRPrjviWX
         lPKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=U46T9o8I;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dkFi8MoHKqeSZU/lr732phmmAmc+USofM+6QBduXIAw=;
        b=dSYOlLY7za6BT8df1pO3+HCScyiJj2NisHm1RwsSfjRc8rHVvrmn6k+ZvYv11uSHIc
         v8tiDiEi3FFbCFVs/sS3O9dMxropfxPC7KCkW/r0xd/ebsFl8X6VB/ukeTRw3GX0wJB+
         DgbT3FUPpyEeekYX/DHtzL9LGfi10uUiD4bZeyeyQS2lDg2FWUVDsMlHQzncgfhzAP9L
         pqs+/ibY8TS3plFNa0cC27an5SqP5xhKbzPI/iCbNxF+6I0oAw++5viyOcmJsvkAcMog
         MAyOXsg7sN4PKsYIwDcbyJYor0aR0dHo/gX+d7TVx7Uu9FuGE3UVo7ywP71HULhibetO
         CSXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dkFi8MoHKqeSZU/lr732phmmAmc+USofM+6QBduXIAw=;
        b=cmG7qfjEi3BgzX+x27tZfzKtekSy25pnp7oImBzMs1oZhbGFKsfIOkJPpiMqSUTc2c
         T/K3uhO6BsqKQEdTHkmcWo/0/hwbVyrLsAGcZF0YLzLqDPPLyZO7eN+ZdxFpoECUP6uA
         yQnByzccKXLYSeXn9/0SiFsv0So7lRNA7oC/Op/1zZItEbYggQVvWMI9hFxumankmOpz
         AphTmQKWnDmoSTybI0lZs4UV2y+Au/phwNOn9CO8EiLnJuyNm3qAzJWYdKeYYPkGesDO
         bN/xX/Rzxtio/sUTGEw4I5aMejZa9Yr6arnnP9Mo7fyt+wff9jo390L8MRVRLiWBvYI+
         Xgng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533KBhvNXCKrmCVk5IfSYDbuwXb0czhf631SkGwKmZeQPTsv8hvn
	nbknLSlztH+TYdBUF5MMUME=
X-Google-Smtp-Source: ABdhPJzTESL0dhP3ZcFKNwce/zv7GCL+Miuh+eS9eGaxHrXKb7V1b+iiDXNRcP0GFt0Iz/AbsasQOQ==
X-Received: by 2002:a05:6214:763:: with SMTP id f3mr449726qvz.49.1636141752430;
        Fri, 05 Nov 2021 12:49:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:f118:: with SMTP id k24ls5592993qkg.11.gmail; Fri, 05
 Nov 2021 12:49:12 -0700 (PDT)
X-Received: by 2002:a05:620a:28ce:: with SMTP id l14mr32875423qkp.456.1636141751985;
        Fri, 05 Nov 2021 12:49:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1636141751; cv=none;
        d=google.com; s=arc-20160816;
        b=NW2IXyjUqBmAHZUMuEGerKQcHJce1NjUtJhugmTf7GP7EDdBUlmuV7iGh/H8VmgvbI
         ZfjA08cnMKp2iBshyp+uOauABBFUfe1p23qlpMc5ARtbekwAiTpsyvyTFGjlkoi6cH5g
         A5/+knrvAUpMNKT++abdodbBt+eXl9NEpPPZtdyb3JBjHf6ROfytxR3krh+eC5IQ5J1L
         SrcC7RrCCMhXT63lcDXD3bzVJO61AoMnXbX56U5hjH6ukcFXRBPGoYwKCELMtGn9WSKX
         Zt1CQzX78R+DyAbaqPp6x7C4CuGokjWlqRyYitvKkTzTzH6l7X1hPV767mKQiIxVHKBF
         Nd8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=3XnMoEU2qD07dmT/K4t5V4FzdPIXjThhgwQ6Ve9TRjA=;
        b=bx72fFWusyc96esVa7j28KQCVjE4tgX3RZOefIZdNZ65rbZEe7pafn99/XIIOItBqk
         fDFkrfDgGZ+O8r6TFGwc+jRwPumRMDE1swJnwEcCcWfErQTEKtaQ2OiVKoBrwkuWLHDr
         MIY999K1Zslbq2o3VlGt95G3+Es4bCh7uawNummEF1oSiAIBpX+9ybdpWhcVc8MR+gLp
         dCIUhzRQC9OqvTxPUSpAMnJbIiT769A2jY03xdN2wBMIVJ4WS8he4+VXsyYnIvbQFw7/
         pvn1+mYc3qGQRFl8tOSLZH3QJotUEqWL+TprFGr+U69cJV0ekSRDxtFapu0PmnG+bJf/
         T9xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=U46T9o8I;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r22si1448387qkp.1.2021.11.05.12.49.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Nov 2021 12:49:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 9B51D61053;
	Fri,  5 Nov 2021 19:49:06 +0000 (UTC)
Date: Fri, 5 Nov 2021 21:49:01 +0200
From: Mike Rapoport <rppt@kernel.org>
To: Qian Cai <quic_qiancai@quicinc.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Russell King <linux@armlinux.org.uk>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] arm64: Track no early_pgtable_alloc() for kmemleak
Message-ID: <YYWKrdrVbjXLn0wJ@kernel.org>
References: <20211105150509.7826-1-quic_qiancai@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211105150509.7826-1-quic_qiancai@quicinc.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=U46T9o8I;       spf=pass
 (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Fri, Nov 05, 2021 at 11:05:09AM -0400, Qian Cai wrote:
> After switched page size from 64KB to 4KB on several arm64 servers here,
> kmemleak starts to run out of early memory pool due to a huge number of
> those early_pgtable_alloc() calls:
> 
>   kmemleak_alloc_phys()
>   memblock_alloc_range_nid()
>   memblock_phys_alloc_range()
>   early_pgtable_alloc()
>   init_pmd()
>   alloc_init_pud()
>   __create_pgd_mapping()
>   __map_memblock()
>   paging_init()
>   setup_arch()
>   start_kernel()
> 
> Increased the default value of DEBUG_KMEMLEAK_MEM_POOL_SIZE by 4 times
> won't be enough for a server with 200GB+ memory. There isn't much
> interesting to check memory leaks for those early page tables and those
> early memory mappings should not reference to other memory. Hence, no
> kmemleak false positives, and we can safely skip tracking those early
> allocations from kmemleak like we did in the commit fed84c785270
> ("mm/memblock.c: skip kmemleak for kasan_init()") without needing to
> introduce complications to automatically scale the value depends on the
> runtime memory size etc. After the patch, the default value of
> DEBUG_KMEMLEAK_MEM_POOL_SIZE becomes sufficient again.
> 
> Signed-off-by: Qian Cai <quic_qiancai@quicinc.com>

Reviewed-by: Mike Rapoport <rppt@linux.ibm.com>

> ---
> v2:
> Rename MEMBLOCK_ALLOC_KASAN to MEMBLOCK_ALLOC_NOLEAKTRACE to deal with
> those situations in general.
> 
>  arch/arm/mm/kasan_init.c   | 2 +-
>  arch/arm64/mm/kasan_init.c | 5 +++--
>  arch/arm64/mm/mmu.c        | 3 ++-
>  include/linux/memblock.h   | 2 +-
>  mm/memblock.c              | 9 ++++++---
>  5 files changed, 13 insertions(+), 8 deletions(-)
> 
> diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
> index 4b1619584b23..5ad0d6c56d56 100644
> --- a/arch/arm/mm/kasan_init.c
> +++ b/arch/arm/mm/kasan_init.c
> @@ -32,7 +32,7 @@ pmd_t tmp_pmd_table[PTRS_PER_PMD] __page_aligned_bss;
>  static __init void *kasan_alloc_block(size_t size)
>  {
>  	return memblock_alloc_try_nid(size, size, __pa(MAX_DMA_ADDRESS),
> -				      MEMBLOCK_ALLOC_KASAN, NUMA_NO_NODE);
> +				      MEMBLOCK_ALLOC_NOLEAKTRACE, NUMA_NO_NODE);
>  }
>  
>  static void __init kasan_pte_populate(pmd_t *pmdp, unsigned long addr,
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index 6f5a6fe8edd7..c12cd700598f 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -36,7 +36,7 @@ static phys_addr_t __init kasan_alloc_zeroed_page(int node)
>  {
>  	void *p = memblock_alloc_try_nid(PAGE_SIZE, PAGE_SIZE,
>  					      __pa(MAX_DMA_ADDRESS),
> -					      MEMBLOCK_ALLOC_KASAN, node);
> +					      MEMBLOCK_ALLOC_NOLEAKTRACE, node);
>  	if (!p)
>  		panic("%s: Failed to allocate %lu bytes align=0x%lx nid=%d from=%llx\n",
>  		      __func__, PAGE_SIZE, PAGE_SIZE, node,
> @@ -49,7 +49,8 @@ static phys_addr_t __init kasan_alloc_raw_page(int node)
>  {
>  	void *p = memblock_alloc_try_nid_raw(PAGE_SIZE, PAGE_SIZE,
>  						__pa(MAX_DMA_ADDRESS),
> -						MEMBLOCK_ALLOC_KASAN, node);
> +						MEMBLOCK_ALLOC_NOLEAKTRACE,
> +						node);
>  	if (!p)
>  		panic("%s: Failed to allocate %lu bytes align=0x%lx nid=%d from=%llx\n",
>  		      __func__, PAGE_SIZE, PAGE_SIZE, node,
> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
> index d77bf06d6a6d..acfae9b41cc8 100644
> --- a/arch/arm64/mm/mmu.c
> +++ b/arch/arm64/mm/mmu.c
> @@ -96,7 +96,8 @@ static phys_addr_t __init early_pgtable_alloc(int shift)
>  	phys_addr_t phys;
>  	void *ptr;
>  
> -	phys = memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
> +	phys = memblock_phys_alloc_range(PAGE_SIZE, PAGE_SIZE, 0,
> +					 MEMBLOCK_ALLOC_NOLEAKTRACE);
>  	if (!phys)
>  		panic("Failed to allocate page table page\n");
>  
> diff --git a/include/linux/memblock.h b/include/linux/memblock.h
> index 7df557b16c1e..8adcf1fa8096 100644
> --- a/include/linux/memblock.h
> +++ b/include/linux/memblock.h
> @@ -389,7 +389,7 @@ static inline int memblock_get_region_node(const struct memblock_region *r)
>  /* Flags for memblock allocation APIs */
>  #define MEMBLOCK_ALLOC_ANYWHERE	(~(phys_addr_t)0)
>  #define MEMBLOCK_ALLOC_ACCESSIBLE	0
> -#define MEMBLOCK_ALLOC_KASAN		1
> +#define MEMBLOCK_ALLOC_NOLEAKTRACE	1
>  
>  /* We are using top down, so it is safe to use 0 here */
>  #define MEMBLOCK_LOW_LIMIT 0
> diff --git a/mm/memblock.c b/mm/memblock.c
> index 659bf0ffb086..1018e50566f3 100644
> --- a/mm/memblock.c
> +++ b/mm/memblock.c
> @@ -287,7 +287,7 @@ static phys_addr_t __init_memblock memblock_find_in_range_node(phys_addr_t size,
>  {
>  	/* pump up @end */
>  	if (end == MEMBLOCK_ALLOC_ACCESSIBLE ||
> -	    end == MEMBLOCK_ALLOC_KASAN)
> +	    end == MEMBLOCK_ALLOC_NOLEAKTRACE)
>  		end = memblock.current_limit;
>  
>  	/* avoid allocating the first page */
> @@ -1387,8 +1387,11 @@ phys_addr_t __init memblock_alloc_range_nid(phys_addr_t size,
>  	return 0;
>  
>  done:
> -	/* Skip kmemleak for kasan_init() due to high volume. */
> -	if (end != MEMBLOCK_ALLOC_KASAN)
> +	/*
> +	 * Skip kmemleak for those places like kasan_init() and
> +	 * early_pgtable_alloc() due to high volume.
> +	 */
> +	if (end != MEMBLOCK_ALLOC_NOLEAKTRACE)
>  		/*
>  		 * The min_count is set to 0 so that memblock allocated
>  		 * blocks are never reported as leaks. This is because many
> -- 
> 2.30.2
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YYWKrdrVbjXLn0wJ%40kernel.org.
