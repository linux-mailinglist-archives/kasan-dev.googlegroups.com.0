Return-Path: <kasan-dev+bncBDV37XP3XYDRBNWBUGFAMGQEDMJU65I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id CC41E4112CD
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 12:21:42 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id p3-20020a0565121383b0290384997a48fcsf11878224lfa.21
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 03:21:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632133302; cv=pass;
        d=google.com; s=arc-20160816;
        b=TtH7M5snTmYCbCw5t30cjEYpvIeNuyY08Ilm1DLghaZdUwZQvKluIdiyLlScX0jk6N
         UBIEVeaNo4Gd1dpU09GvVxP2xRSOqp3aVA4njq5n0m/W+UNQBfa/0wigY8aNtXgmhgOh
         Gj7Rk9Aah1GejXP7TxkD1gjAPLZYLprwzQibEX3HeN+4Kjtfd4FnmXFLe8qbFRQsO9oW
         W48ktBXfg0xMUyq1iOVKYBf7ktwlEunnh30P19GlRjqwLe2DuLJLrMjC/RVAAzB2QnjN
         PdNxepOHjQCM6nc7y7LOmFUfJRkqq8sE7Hxcn+pB0BQWKvO4yaSZ9pyHeHFuu9aaUjX2
         IzNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=fw0V/Dz7/NX687dWtRWaSxbdHw3ylxIB64V1V2BbDwM=;
        b=JozLS+oaid9hRfsbJ583LRoc0ugwTYWsvT+Dk8D9ZwYGLtTCmA9EcREp8XBLTS5YKQ
         837SV0ef/oBR/M5Dx57P7GbbLAxE5EbL7EqSLYOBC6MR28r1tHIpPHU+5eN3QPp5YP/v
         abr8W2ISO9cjuA2fhLkJY4jnhkJJ/Gtxk/KiKJkN9MK2LsdIc1s/3VzBpr88ipb51Bg1
         XWvYx271uW+26JPxXVPSuZKSn1XzngpRKj76L9l118PR1Der0KbLF/K9RvhhMsW14xx4
         M4Ou1OLbRALP3RnPYUUkiYOqI9avVOTxFHdVp3e/nf0FYqSK3qw+cCt07dp971vjDsZh
         g3mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fw0V/Dz7/NX687dWtRWaSxbdHw3ylxIB64V1V2BbDwM=;
        b=eTlprGGKMUBsgHqOTYXFeialJ2fVWSWBZYV7k7zywu+4RM193UwQYWrjK9vXdh4w+U
         r+N4tQjrW4aBd4GScEU2T16E6TIRANRe4ws4NSLtvgSYB90hLJHh+tp6D3jQJgTdGcZP
         zVLcBzo5opki2sK4qahYuicHwQKrryTNVucUqFksJuPENy6PdpyLoPC/3SbDizktV3wY
         xb5iuYsdyOifR9E2bRUZJgVhl/UGXGhKSr+QYWA6ZPRlnPwObbtnDEQ6Cv/cOQxt0dw2
         jDVXpGz1MKXaFRpWDGzoxyNq17RHX/Sj/546j7NCV7wuaxRMIHjJx4kpxLIi6wZmbVZK
         2HGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fw0V/Dz7/NX687dWtRWaSxbdHw3ylxIB64V1V2BbDwM=;
        b=54iUIadB9li6o9uEaxQX93d1HFwpfxlpvGuCDucn/rmR8k3IVCULT01lvMK9SotHkU
         tDq17EbeD5cGw0ILjo59OgDFZfNSqPgk2zdHbaA3+UC5+UcSDe0dEQlzoM6AubVli1YY
         UsvxPNa0ziThqrPau+LIVzg6sIJrMm+czSOfKgZtPPve57rcQwASfggK33/QGCtJVdoe
         /n+ZUSjdKYZVuAPfJF7p8AvrvZ1eWMY+PxnnbBX4cpzcBhudwF/yMH2QNUmRV/XQzq/K
         3FF6VcQ7nAKOXpGX0y0osmlXsS5Ok8Y7FFdcTPbqWtMXj4WptL4nKbKXeqmAWIbgGiiL
         pbzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530VuOaP/SW61z87Wa59gYuICBz6lUyeiG6ug5iOdGLeuTwwPcko
	w3SI6Nyiujkcziu7z8I83uo=
X-Google-Smtp-Source: ABdhPJwO0r+7+hB2wY8RmMGfa58Rwg0NgzGrjdVNtzQvyGAlKWel0QyDXLb/qUyqp2bd2CuyLJhvsA==
X-Received: by 2002:a05:6512:c2a:: with SMTP id z42mr10264566lfu.664.1632133302325;
        Mon, 20 Sep 2021 03:21:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a48d:: with SMTP id h13ls890937lji.8.gmail; Mon, 20 Sep
 2021 03:21:41 -0700 (PDT)
X-Received: by 2002:a2e:750b:: with SMTP id q11mr22057770ljc.172.1632133301041;
        Mon, 20 Sep 2021 03:21:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632133301; cv=none;
        d=google.com; s=arc-20160816;
        b=h2lRQv65m/kwwVnZK0u+dkr4Dxnr7zwEibvqd/GbIkWmfFGsygb2NjLvbUuWK6v8Sz
         XSAG6XlRYUz+VAMB+VWJ4rnBfu/4BA1KzJnmJCo6gSLPhZOsb/99NzYL4vSYLDmQnMvE
         db3JED0zlKtEBIGIEV4jRwIfo7OJ2l/W6GDwzM1an8aPJSeOc/m3mU53njLo5BEKvs7r
         LdqOD+HzIW5/zwS6L4KK+6JxTruPfCgJUAXvDZ4YA+SwOaVrpTns5zSD/AoyB+cJ3Mxi
         y1toDTxuFEYK60NJ7zwwrnQk6eae3Acpn77pjNYLUsT1xjJ7figJjM062IbYUJXf78qU
         FqUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=HBPtad2sw6hrPEM5CDUy0wjm2zQ2PFAzoNdR3yq+RM0=;
        b=Oc1NPGX68aCZk/ieaUaYyFrK/xpRqR5uZ6VNDwhix9aOWFyrJ8E5POfMmz8/qiFnRU
         EOsnFM8LC2gbaPiUUYeEscuEevSno0qUe0JCDorP9ZNUDrqZYGFdioxfE271RsrvVg1Q
         DW3zNiTJsH5jCllKc4NiClwr4sjhSrLlYS954L4NKY/dcRcQxB1Ge5tqm5QDSMsNFTFx
         grxOWJPzbIkHIf1eMYNR42Bo30Wf62uyEabMCOxAmp0axb04P3sfdkh5lKyIIf/6Zy3I
         rFsuUyNwnGJmhlXIhSAtTWrZyLFw+04409xyyoPsYczP64PWFuPi4FppAPEgzvfpYzh/
         vWmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m7si431911lfq.0.2021.09.20.03.21.40
        for <kasan-dev@googlegroups.com>;
        Mon, 20 Sep 2021 03:21:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8DC031063;
	Mon, 20 Sep 2021 03:21:39 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.16.51])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 1803E3F59C;
	Mon, 20 Sep 2021 03:21:36 -0700 (PDT)
Date: Mon, 20 Sep 2021 11:21:28 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Liu Shixin <liushixin2@huawei.com>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] arm64: remove page granularity limitation from KFENCE
Message-ID: <20210920101938.GA13863@C02TD0UTHF1T.local>
References: <20210918083849.2696287-1-liushixin2@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210918083849.2696287-1-liushixin2@huawei.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Sat, Sep 18, 2021 at 04:38:49PM +0800, Liu Shixin wrote:
> Currently if KFENCE is enabled in arm64, the entire linear map will be
> mapped at page granularity which seems overkilled. Actually only the
> kfence pool requires to be mapped at page granularity. We can remove the
> restriction from KFENCE and force the linear mapping of the kfence pool
> at page granularity later in arch_kfence_init_pool().
> 
> Signed-off-by: Liu Shixin <liushixin2@huawei.com>

We'd made this apply to the entire linear map because it was simpler to
do so, there are other reasons to want the linear map at page
granularity (e.g. RODATA_FULL), and is also the default behaviour (since
RODATA_FULL_DEFAULT_ENABLED is `default y`).

We also avoid live changes from block<->table mappings, since the
archtitecture gives us very weak guarantees there and generally requires
a Break-Before-Make sequence (though IIRC this was tightened up
somewhat, so maybe going one way is supposed to work). Unless it's
really necessary, I'd rather not split these block mappings while
they're live.

The bigger question is does this actually matter in practice? I
understand that in theory this can result in better TLB usage, but does
this actually affect a workload in a meaningful way? Without numbers,
I'd rather leave this as-is so that we're not adding complexity and an
ongoing maintenance burden.

Thanks,
Mark.

> ---
>  arch/arm64/include/asm/kfence.h | 69 ++++++++++++++++++++++++++++++++-
>  arch/arm64/mm/mmu.c             |  4 +-
>  2 files changed, 70 insertions(+), 3 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
> index aa855c6a0ae6..bee101eced0b 100644
> --- a/arch/arm64/include/asm/kfence.h
> +++ b/arch/arm64/include/asm/kfence.h
> @@ -8,9 +8,76 @@
>  #ifndef __ASM_KFENCE_H
>  #define __ASM_KFENCE_H
>  
> +#include <linux/kfence.h>
>  #include <asm/set_memory.h>
> +#include <asm/pgalloc.h>
>  
> -static inline bool arch_kfence_init_pool(void) { return true; }
> +static inline int split_pud_page(pud_t *pud, unsigned long addr)
> +{
> +	int i;
> +	pmd_t *pmd = pmd_alloc_one(&init_mm, addr);
> +	unsigned long pfn = PFN_DOWN(__pa(addr));
> +
> +	if (!pmd)
> +		return -ENOMEM;
> +
> +	for (i = 0; i < PTRS_PER_PMD; i++)
> +		set_pmd(pmd + i, pmd_mkhuge(pfn_pmd(pfn + i * PTRS_PER_PTE, PAGE_KERNEL)));
> +
> +	smp_wmb(); /* See comment in __pte_alloc */
> +	pud_populate(&init_mm, pud, pmd);
> +	flush_tlb_kernel_range(addr, addr + PUD_SIZE);
> +	return 0;
> +}
> +
> +static inline int split_pmd_page(pmd_t *pmd, unsigned long addr)
> +{
> +	int i;
> +	pte_t *pte = pte_alloc_one_kernel(&init_mm);
> +	unsigned long pfn = PFN_DOWN(__pa(addr));
> +
> +	if (!pte)
> +		return -ENOMEM;
> +
> +	for (i = 0; i < PTRS_PER_PTE; i++)
> +		set_pte(pte + i, pfn_pte(pfn + i, PAGE_KERNEL));
> +
> +	smp_wmb(); /* See comment in __pte_alloc */
> +	pmd_populate_kernel(&init_mm, pmd, pte);
> +
> +	flush_tlb_kernel_range(addr, addr + PMD_SIZE);
> +	return 0;
> +}
> +
> +static inline bool arch_kfence_init_pool(void)
> +{
> +	unsigned long addr;
> +	pgd_t *pgd;
> +	p4d_t *p4d;
> +	pud_t *pud;
> +	pmd_t *pmd;
> +
> +	for (addr = (unsigned long)__kfence_pool; is_kfence_address((void *)addr);
> +	     addr += PAGE_SIZE) {
> +		pgd = pgd_offset(&init_mm, addr);
> +		if (pgd_leaf(*pgd))
> +			return false;
> +		p4d = p4d_offset(pgd, addr);
> +		if (p4d_leaf(*p4d))
> +			return false;
> +		pud = pud_offset(p4d, addr);
> +		if (pud_leaf(*pud)) {
> +			if (split_pud_page(pud, addr & PUD_MASK))
> +				return false;
> +		}
> +		pmd = pmd_offset(pud, addr);
> +		if (pmd_leaf(*pmd)) {
> +			if (split_pmd_page(pmd, addr & PMD_MASK))
> +				return false;
> +		}
> +	}
> +	return true;
> +}
>  
>  static inline bool kfence_protect_page(unsigned long addr, bool protect)
>  {
> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
> index cfd9deb347c3..b2c79ccfb1c5 100644
> --- a/arch/arm64/mm/mmu.c
> +++ b/arch/arm64/mm/mmu.c
> @@ -516,7 +516,7 @@ static void __init map_mem(pgd_t *pgdp)
>  	 */
>  	BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
>  
> -	if (can_set_direct_map() || crash_mem_map || IS_ENABLED(CONFIG_KFENCE))
> +	if (can_set_direct_map() || crash_mem_map)
>  		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
>  
>  	/*
> @@ -1485,7 +1485,7 @@ int arch_add_memory(int nid, u64 start, u64 size,
>  	 * KFENCE requires linear map to be mapped at page granularity, so that
>  	 * it is possible to protect/unprotect single pages in the KFENCE pool.
>  	 */
> -	if (can_set_direct_map() || IS_ENABLED(CONFIG_KFENCE))
> +	if (can_set_direct_map())
>  		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
>  
>  	__create_pgd_mapping(swapper_pg_dir, start, __phys_to_virt(start),
> -- 
> 2.18.0.huawei.25
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210920101938.GA13863%40C02TD0UTHF1T.local.
