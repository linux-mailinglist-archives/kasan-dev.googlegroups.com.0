Return-Path: <kasan-dev+bncBDDL3KWR4EBRBUUKTOEAMGQEDOWIVEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 78BF03DCC8C
	for <lists+kasan-dev@lfdr.de>; Sun,  1 Aug 2021 18:01:23 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id j5-20020ab064c50000b02902a95e238e05sf5448287uaq.4
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Aug 2021 09:01:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627833682; cv=pass;
        d=google.com; s=arc-20160816;
        b=s6QBaN3az/jzTy9RKuSuyM1LvGo85ATTwxPLvCacnaKAH/qCZ6MP1rU5fgb+X5vlV+
         WZcx1LGD+lhAYVaB3SZTIi5dQJxSCZU9xodNn8BCjMEy0LaarP1UjmXqKVg0ldOKbnMH
         bsODLa1NU3h0VeYTAoB6KX0cKygBLAHiikM0FIO2PzUnwxkWAJhwTIxfCdmm0Nx2IfR8
         0KjnhCABopTIjQDdt99C73QaFhkLqSj1B0u081OqVn8Ccdssx2kEeFX4LU3703/5ZXfb
         rIvgNzZd5H0OHw+J0IVMEinXvFPwSFcM4IThzoeMUg8YC5zIUmTtBhp+Alw3Jum8+RYE
         5D0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=vZP7ko1jKEMAwzb+EFhr1TGnnGu6cWCd7TgA/MaSYiM=;
        b=YDUlfhKgBkG/DhWeQgP2d0LauQKFmH+jXcsp3yxrilzqvohYcNprA9E510Eh5RYVFK
         XcXjKuKOljoFnsTvDhcP7B49WrwdSvFWghXy0nUREMuWeNupDVdQ18ruAQdln/yF3fr9
         SkwQInvlrqOFJuRIb1I+P5ktBNjuZ/6rW24PrXGzh0HoDfOV8XGOCcqtfetrGVc3cfi1
         oCfYU8QOinjK/6B5qzhGe8lIGC9i6rV1xJUZZmrgbzJNEzeBnLuIAmAXzIvDPosIgeZP
         fZKKpdavQ1ulZi3c/Jr/ZtmEm6K1WWoDBwTK0pfQ5M7kEQYY6uzFREgGsNOiw5N5ZpZr
         xTHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vZP7ko1jKEMAwzb+EFhr1TGnnGu6cWCd7TgA/MaSYiM=;
        b=ZmRl/3jRkNd6ugfsL0oUsgNHVQYvicbs3f5BxsZk5xwtbxExeMsxi6pbA5Eod3mabP
         UUcwAH33PBhuAKhdnVnjpJrdXgD1o7xSCRZVdzX6tcH5+4XFmJpk1N09e19YqqiY5vvC
         jAx312dfJNJE4qrCb1rwZJs7zsG5XqA+F7w4F0LU4D4VZSreYL0fw2MilZyDVUmJb2j+
         BaJZ7Hnf1ez/v4xm0ibDwLQ9Z1iGS5EaVU+EXLf7E4+Ibbq+dVnNjZVjapTRJ0y8ff7u
         56TTCjURBFiVyTGCljf5Gn40MSMZgXoi8WtTYktw1+BmYrD2XTsg3j6Ugqf8jdVPpB1y
         CAYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vZP7ko1jKEMAwzb+EFhr1TGnnGu6cWCd7TgA/MaSYiM=;
        b=tmvgavGPBye9v/62oHQq0rGRG9LFiaARHI89h4SK0wipgrM2Fi9GvSL2n32uD8IC14
         fLoUTL1utDSJA3U07iqdjJzzo7EOESAPwYD33sT6MdAD1lx2rbgOllxG2as6hwzYN3Xc
         WT64HJZ1qStnIUEiOeIrvM5gK1guqF6EhDp7JHqylkd/LgtriyVJIQphFxjc+NDt11tD
         pALDY392NbydiM2rtmKItvKsfT0sIu7MfxTGNMPXpeCYEsnHfyWFU4CVkkNp7M3OT39z
         l5BPiOytCn/ouVbqFqn5nPNEYz6TkDUMw9kSclAqaRDgXVS4O+DVV5ZaFuAh5EjDhXkN
         ofMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Jz5I3eAdtrBjSGrnX2Pkbip4+WX/Omps4bG3lApKdtEVkldcT
	ARW54szeVaU6i6LAOZ4uWYo=
X-Google-Smtp-Source: ABdhPJxz341RYIag2Ha77R3zWOImUx9BEWmgOQO4QGJNkYXYnKHTVYM5J928ogjcGO6TTIJzI41RxQ==
X-Received: by 2002:ab0:48f2:: with SMTP id y47mr1218705uac.10.1627833682613;
        Sun, 01 Aug 2021 09:01:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:7285:: with SMTP id w5ls750215uao.8.gmail; Sun, 01 Aug
 2021 09:01:22 -0700 (PDT)
X-Received: by 2002:ab0:64ca:: with SMTP id j10mr8314646uaq.89.1627833682161;
        Sun, 01 Aug 2021 09:01:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627833682; cv=none;
        d=google.com; s=arc-20160816;
        b=CDqxR2QlSTctNbyeayieIE0SQR7dIXjA/StUlzzHuPO7gQ3AvSa2az/MmYSqymAjZG
         b9GVK4nqi3xldd7RbczHhKMfgdP9zU+/u+Dw+M9RQObvDAe7wnyMcY+2UgCtq8Z8k8G9
         LZYaUChaKbY4x+sLuSxNNf8yNkAp8KPlffaa/l2HxIs4CZEA2Th8UKxJ39N01eFJB/Cd
         rPIvxp3Njxk5DtsTLFJoepKHLk41RJ0PDi84o2KqWxG5MBBKLSi7g3Y8AfscjYqGGHOR
         98bFVzw2Hmbz1IviuLqqhoWabQMiEBSb4dM6mEzvt8uAkyWmdT0Cuw4tgX2zNTCb29Bc
         CjqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=q0XI/YQyanjvJCDT8Pme5AdWIRIUck+oqvPZnCO7EOw=;
        b=H4dopA7ZXHRtDAF/TBdnJMurW0R6pe8BSqftiBZo5U1fnxVnG8JYqYwU8bcoQBo0Sb
         Ldk0Pn6NxzfqxfrykaUkD7VgI61/YXEE3RbcG6SDMFVy/jSCREp/7E8/9dC2cTuQfBa9
         +mHp+GEVDWHTIk5SKMXlwsX99DieG55Bj985DEtwb6vpQbuWsN+qu70J9zAhr/na3Ze9
         jubu772GKYExIoiKQv2xNo7Z2Ybu0CeeeBPo9SkdxJjaHOGFlKs41TfNo1F82zJZR9IP
         +qfUIyCrRapUi3UhhzeSoEKIWwKSjWsNMwteb8sTi7aEm/DacE4TOU22uIK9kUoTkHHy
         9CEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l10si27782uap.1.2021.08.01.09.01.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 01 Aug 2021 09:01:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 9223160200;
	Sun,  1 Aug 2021 16:01:17 +0000 (UTC)
Date: Sun, 1 Aug 2021 08:53:13 -0700
From: Catalin Marinas <catalin.marinas@arm.com>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Will Deacon <will@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH v2 2/3] arm64: Support page mapping percpu first chunk
 allocator
Message-ID: <20210801155302.GA29188@arm.com>
References: <20210720025105.103680-1-wangkefeng.wang@huawei.com>
 <20210720025105.103680-3-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210720025105.103680-3-wangkefeng.wang@huawei.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Jul 20, 2021 at 10:51:04AM +0800, Kefeng Wang wrote:
> Percpu embedded first chunk allocator is the firstly option, but it
> could fails on ARM64, eg,
>   "percpu: max_distance=0x5fcfdc640000 too large for vmalloc space 0x781fefff0000"
>   "percpu: max_distance=0x600000540000 too large for vmalloc space 0x7dffb7ff0000"
>   "percpu: max_distance=0x5fff9adb0000 too large for vmalloc space 0x5dffb7ff0000"
> 
> then we could meet "WARNING: CPU: 15 PID: 461 at vmalloc.c:3087 pcpu_get_vm_areas+0x488/0x838",
> even the system could not boot successfully.
> 
> Let's implement page mapping percpu first chunk allocator as a fallback
> to the embedding allocator to increase the robustness of the system.

It looks like x86, powerpc and sparc implement their own
setup_per_cpu_areas(). I had a quick look on finding some commonalities
but I think it's a lot more hassle to make a generic version out of them
(powerpc looks the simplest though). I think we could add a generic
variant with the arm64 support and later migrate other architectures to
it if possible.

The patch looks ok to me otherwise but I'd need an ack from Greg as it
touches drivers/.

BTW, do we need something similar for the non-NUMA
setup_per_cpu_areas()? I can see this patch only enables
NEED_PER_CPU_PAGE_FIRST_CHUNK if NUMA.

Leaving the rest of the patch below for Greg.

> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> ---
>  arch/arm64/Kconfig       |  4 ++
>  drivers/base/arch_numa.c | 82 +++++++++++++++++++++++++++++++++++-----
>  2 files changed, 76 insertions(+), 10 deletions(-)
> 
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index b5b13a932561..eacb5873ded1 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -1045,6 +1045,10 @@ config NEED_PER_CPU_EMBED_FIRST_CHUNK
>  	def_bool y
>  	depends on NUMA
>  
> +config NEED_PER_CPU_PAGE_FIRST_CHUNK
> +	def_bool y
> +	depends on NUMA
> +
>  source "kernel/Kconfig.hz"
>  
>  config ARCH_SPARSEMEM_ENABLE
> diff --git a/drivers/base/arch_numa.c b/drivers/base/arch_numa.c
> index 4cc4e117727d..563b2013b75a 100644
> --- a/drivers/base/arch_numa.c
> +++ b/drivers/base/arch_numa.c
> @@ -14,6 +14,7 @@
>  #include <linux/of.h>
>  
>  #include <asm/sections.h>
> +#include <asm/pgalloc.h>
>  
>  struct pglist_data *node_data[MAX_NUMNODES] __read_mostly;
>  EXPORT_SYMBOL(node_data);
> @@ -168,22 +169,83 @@ static void __init pcpu_fc_free(void *ptr, size_t size)
>  	memblock_free_early(__pa(ptr), size);
>  }
>  
> +#ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
> +static void __init pcpu_populate_pte(unsigned long addr)
> +{
> +	pgd_t *pgd = pgd_offset_k(addr);
> +	p4d_t *p4d;
> +	pud_t *pud;
> +	pmd_t *pmd;
> +
> +	p4d = p4d_offset(pgd, addr);
> +	if (p4d_none(*p4d)) {
> +		pud_t *new;
> +
> +		new = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> +		if (!new)
> +			goto err_alloc;
> +		p4d_populate(&init_mm, p4d, new);
> +	}
> +
> +	pud = pud_offset(p4d, addr);
> +	if (pud_none(*pud)) {
> +		pmd_t *new;
> +
> +		new = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> +		if (!new)
> +			goto err_alloc;
> +		pud_populate(&init_mm, pud, new);
> +	}
> +
> +	pmd = pmd_offset(pud, addr);
> +	if (!pmd_present(*pmd)) {
> +		pte_t *new;
> +
> +		new = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> +		if (!new)
> +			goto err_alloc;
> +		pmd_populate_kernel(&init_mm, pmd, new);
> +	}
> +
> +	return;
> +
> +err_alloc:
> +	panic("%s: Failed to allocate %lu bytes align=%lx from=%lx\n",
> +	      __func__, PAGE_SIZE, PAGE_SIZE, PAGE_SIZE);
> +}
> +#endif
> +
>  void __init setup_per_cpu_areas(void)
>  {
>  	unsigned long delta;
>  	unsigned int cpu;
> -	int rc;
> +	int rc = -EINVAL;
> +
> +	if (pcpu_chosen_fc != PCPU_FC_PAGE) {
> +		/*
> +		 * Always reserve area for module percpu variables.  That's
> +		 * what the legacy allocator did.
> +		 */
> +		rc = pcpu_embed_first_chunk(PERCPU_MODULE_RESERVE,
> +					    PERCPU_DYNAMIC_RESERVE, PAGE_SIZE,
> +					    pcpu_cpu_distance,
> +					    pcpu_fc_alloc, pcpu_fc_free);
> +#ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
> +		if (rc < 0)
> +			pr_warn("PERCPU: %s allocator failed (%d), falling back to page size\n",
> +				   pcpu_fc_names[pcpu_chosen_fc], rc);
> +#endif
> +	}
>  
> -	/*
> -	 * Always reserve area for module percpu variables.  That's
> -	 * what the legacy allocator did.
> -	 */
> -	rc = pcpu_embed_first_chunk(PERCPU_MODULE_RESERVE,
> -				    PERCPU_DYNAMIC_RESERVE, PAGE_SIZE,
> -				    pcpu_cpu_distance,
> -				    pcpu_fc_alloc, pcpu_fc_free);
> +#ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
> +	if (rc < 0)
> +		rc = pcpu_page_first_chunk(PERCPU_MODULE_RESERVE,
> +					   pcpu_fc_alloc,
> +					   pcpu_fc_free,
> +					   pcpu_populate_pte);
> +#endif
>  	if (rc < 0)
> -		panic("Failed to initialize percpu areas.");
> +		panic("Failed to initialize percpu areas (err=%d).", rc);
>  
>  	delta = (unsigned long)pcpu_base_addr - (unsigned long)__per_cpu_start;
>  	for_each_possible_cpu(cpu)
> -- 
> 2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210801155302.GA29188%40arm.com.
