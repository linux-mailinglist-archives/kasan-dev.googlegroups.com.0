Return-Path: <kasan-dev+bncBCRKFI7J2AJRBAGJZSQAMGQEAMQHHYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CF3D6BD21F
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 15:15:29 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id f8-20020a0cbec8000000b005b14a30945csf1124766qvj.8
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 07:15:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678976128; cv=pass;
        d=google.com; s=arc-20160816;
        b=IMO86fCUh4FYgSTXPyDkayOaMs4xKVevysjcOgY/p3XkNL8O95cAbMhm7o9NH0q+Gi
         G350kFMwlzMxPZ/dYr0cSjlFuGe4I39LHGKJepVjg9azP5tXcZvA3vNnngHj86ta8kNL
         qWU5qpxIbgydQV+nkav/pkGjvr13vsHDxRekBxZ4DxQUUzwNsifyYkhHZC23+Kz/7BGQ
         Ps4bg9pZseqCX0L2SfV/T/z+UwnTb6AkmR/PqjNE+F0b/COMLesASfcEl1lYXW2qF5hR
         VDXm+7J3UrNq/idjmxBlR8AeuV8etPZv9Gh33JU8LyZhx9X+DbAnZTrdqvM6uVWRsDpQ
         Hchw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=VjizowIhefR+hkKT8ytx2Ozqrg0ybQ0uRUqrBBJ7gp0=;
        b=08Ru50mLWLCFlrxZRtX0hhBjDzA0FBiVFGbv+XfBxj65YHUbDXKDCvub5teDoiSo1K
         LLgxNKCcfFKotFoyzEz/X9STzX1pwtknC8cnJVW864kzDMvKIPceF4EQMYNRPi6mXhwl
         i2+loCMIwtZwObfBrVRXOetJ/a95bHXGHSZX97v52L1K0JMkN0C9xPpPMhxmX+SnhPx8
         PiXD4rr/3K4f5atKkj0MarwbPQ0aMBq56R4xH29F3ALO0HVamPnPBr0ZTOZvFwfLCmk3
         otQy4yVcQihHx4lPMpkkjCX5DI8yo9FApI6oOz0mcZzzVjdrZo4b5Zl30m+MDV1t+RZY
         JBYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678976128;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VjizowIhefR+hkKT8ytx2Ozqrg0ybQ0uRUqrBBJ7gp0=;
        b=PkPsLU55VA2o1cdA4tCrVcKzrVC9VtOzGQwBY5qKwza0Rp61dlUWMbyHK/Sc3PiEZx
         64NJshWlDvNosPOQbye7QHrWaN2TNtWAk/oganxo+Y5tpaf91fH0Ui5AbiMOhqdqQUxg
         0Dbjal0YoNPsaNEzZ/cxU/I/baJ8PP1iL+XBL+CdUfJhtm72ThFyrh2ZWvZ2N1PUs1NN
         XdHyvyUzHjRQpTgyOkptHE9RLZ36bT4Cr1Qqx2DSwOYiKxE9y4IFBr8BcLwtL5ntqF8+
         P1xE4Yzw1MB/3r2N2gfyxtXOD6IAuGpiIvV/wbCyNBRDsZmQuwCcpoTnoWgPudtFKnWh
         Tbpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678976128;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:from:to:cc:subject
         :date:message-id:reply-to;
        bh=VjizowIhefR+hkKT8ytx2Ozqrg0ybQ0uRUqrBBJ7gp0=;
        b=Ccl9mm0cW6/NTQHu+C64Zl8060ThmwKSHZryRmR/OvDW5K4o3s1OdqwzrvplmqXHFM
         vj3BmqrnONpPVEfGQa8oh5d1U+i9z1zazXQJqkL8HWkWcxSqZV63MezjsLGd+KGvGnMf
         xTc00a9/cBEBKA5bjR1g1PXbOFd+EGym6HTFsxdzRwP1+2LMhU6Cet0StYOduFZyLEmd
         H0VbY0UHOoN3Ajk+EihDqifqwttZG699bQXlPaoY9ocz6lTpDIvMBwDabVU7Wubrb+/c
         /EiCGnNrcA61rjudGXBzHrZ3BEP3tCchCuDMgOLCtx+ughxEmtPn5wnddrQ0PXnhF9Zv
         0Lcg==
X-Gm-Message-State: AO0yUKVwdKC92epKLn9hY/uue3aCm3AdUXxbinptYtsjaVRTQopx8Umk
	wIDfkNS0BWO8tHEB1LOzFgo=
X-Google-Smtp-Source: AK7set9zR7367heWzUP5ODgy2H7n6Vf+F7xXLHJNcu2g0/gNcv6rf+1gtaCSGV3mQAsG8KWWP1U7vA==
X-Received: by 2002:ae9:e211:0:b0:742:9e15:3e0 with SMTP id c17-20020ae9e211000000b007429e1503e0mr6352689qkc.5.1678976128238;
        Thu, 16 Mar 2023 07:15:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5f94:0:b0:3bf:affe:dd2b with SMTP id j20-20020ac85f94000000b003bfaffedd2bls2003648qta.10.-pod-prod-gmail;
 Thu, 16 Mar 2023 07:15:27 -0700 (PDT)
X-Received: by 2002:a05:622a:14cf:b0:3bf:d974:8ad5 with SMTP id u15-20020a05622a14cf00b003bfd9748ad5mr6468325qtx.61.1678976127546;
        Thu, 16 Mar 2023 07:15:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678976127; cv=none;
        d=google.com; s=arc-20160816;
        b=a4k9I8HDjtV1xF2RvcTUxU5IGMYk8uMCTGQdrLflTZWf5cWfA6EVgyzQiQfC5OWHDV
         7U3Fu8/IVj1FG9JzgE0/tXbPI8ydQX966a/Aqa/YHZOWUoBbnyQlQMKEAAgtVZMW55TF
         9DCsmrxFtAEJ65G3mLaMzY7Fq2+tbAx1u/Z3357dK8gpXH2WJ5Dpung6Z6InIhbOU82L
         5Va5sNpNyuFmak1SNPkKlXF+oymi106fIfnU9UzPGrKkt+fQRwColghpIP7mMhy/3kNF
         b5vnhSsQFuVuETLdDmFjxX39Ch72KM1bZoLSr0xcimY8f9VvQDrYOb2pYQgXnPtAhnWQ
         jWTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=ITp1vHSci2s5kqwS5Dp8A5D8uw63JhX4AO9+qtEWxPc=;
        b=KveZvbOaxN2fmp0n0WgE+SYEiQu4aU+iiCydFdJ3CW6fQy8C4daJXRvUPRr95i5JAB
         xu/gcv0JVAuqrsUSojML3MzxHUQadgxu7Y2UDDTMQ3GaOzeA8fyVmSZrxrPbOHCXsIxw
         3VfdDTui4a/AG+2R/iTd0QVnom0+PQkpPzzJ9nfXEckig2cvFNrvomGTVrVVPVdeXqcG
         30cDncGi+M9xtDSBinkzKelgYKfS7czmEJC1lj6sM98BZehIOIf2F7bALnYT8u+bRGNa
         /CCRxg5hgi33zueYTW/c2C2asqZzC8L1u77ftunHfPcpdHqJfqZEivxPHqKDFdrpRQQj
         FMmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id a21-20020a05620a125500b0074230d17fb4si366181qkl.3.2023.03.16.07.15.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Mar 2023 07:15:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggpemm500001.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4Pcq3l0qXmzHwj1;
	Thu, 16 Mar 2023 22:13:07 +0800 (CST)
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.21; Thu, 16 Mar 2023 22:15:18 +0800
Message-ID: <8f064a51-723e-986e-be25-ec2929b685de@huawei.com>
Date: Thu, 16 Mar 2023 22:15:18 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.1
Subject: Re: [PATCH v10] mm,kfence: decouple kfence from page granularity
 mapping judgement
Content-Language: en-US
To: Zhenhua Huang <quic_zhenhuah@quicinc.com>, <catalin.marinas@arm.com>,
	<will@kernel.org>, <glider@google.com>, <elver@google.com>,
	<dvyukov@google.com>, <akpm@linux-foundation.org>, <robin.murphy@arm.com>,
	<mark.rutland@arm.com>, <jianyong.wu@arm.com>, <james.morse@arm.com>
CC: <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>, <quic_guptap@quicinc.com>,
	<quic_tingweiz@quicinc.com>
References: <1678969110-11941-1-git-send-email-quic_zhenhuah@quicinc.com>
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <1678969110-11941-1-git-send-email-quic_zhenhuah@quicinc.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Kefeng Wang <wangkefeng.wang@huawei.com>
Reply-To: Kefeng Wang <wangkefeng.wang@huawei.com>
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



On 2023/3/16 20:18, Zhenhua Huang wrote:
> Kfence only needs its pool to be mapped as page granularity, if it is
> inited early. Previous judgement was a bit over protected. From [1], Mark
> suggested to "just map the KFENCE region a page granularity". So I
> decouple it from judgement and do page granularity mapping for kfence
> pool only. Need to be noticed that late init of kfence pool still requires
> page granularity mapping.
> 
> Page granularity mapping in theory cost more(2M per 1GB) memory on arm64
> platform. Like what I've tested on QEMU(emulated 1GB RAM) with
> gki_defconfig, also turning off rodata protection:
> Before:
> [root@liebao ]# cat /proc/meminfo
> MemTotal:         999484 kB
> After:
> [root@liebao ]# cat /proc/meminfo
> MemTotal:        1001480 kB
> 
> To implement this, also relocate the kfence pool allocation before the
> linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
> addr, __kfence_pool is to be set after linear mapping set up.
> 

A few little comments,


> LINK: [1] https://lore.kernel.org/linux-arm-kernel/Y+IsdrvDNILA59UN@FVFF77S0Q05N/
> Suggested-by: Mark Rutland <mark.rutland@arm.com>
> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
> ---
>   arch/arm64/include/asm/kfence.h | 10 +++++++
>   arch/arm64/mm/mmu.c             | 61 +++++++++++++++++++++++++++++++++++++++++
>   arch/arm64/mm/pageattr.c        |  7 +++--
>   mm/kfence/core.c                |  4 +++
>   4 files changed, 80 insertions(+), 2 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
> index aa855c6..a81937f 100644
> --- a/arch/arm64/include/asm/kfence.h
> +++ b/arch/arm64/include/asm/kfence.h
> @@ -19,4 +19,14 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
>   	return true;
>   }
>   
> +#ifdef CONFIG_KFENCE
> +extern bool kfence_early_init;
> +static inline bool arm64_kfence_can_set_direct_map(void)
> +{
> +	return !kfence_early_init;
> +}
> +#else /* CONFIG_KFENCE */
> +static inline bool arm64_kfence_can_set_direct_map(void) { return false; }
> +#endif /* CONFIG_KFENCE */
> +
>   #endif /* __ASM_KFENCE_H */
> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
> index ae25524d..aaf1801 100644
> --- a/arch/arm64/mm/mmu.c
> +++ b/arch/arm64/mm/mmu.c
> @@ -24,6 +24,7 @@
>   #include <linux/mm.h>
>   #include <linux/vmalloc.h>
>   #include <linux/set_memory.h>
> +#include <linux/kfence.h>
>   
>   #include <asm/barrier.h>
>   #include <asm/cputype.h>
> @@ -38,6 +39,7 @@
>   #include <asm/ptdump.h>
>   #include <asm/tlbflush.h>
>   #include <asm/pgalloc.h>
> +#include <asm/kfence.h>
>   
>   #define NO_BLOCK_MAPPINGS	BIT(0)
>   #define NO_CONT_MAPPINGS	BIT(1)
> @@ -521,12 +523,67 @@ static int __init enable_crash_mem_map(char *arg)
>   }
>   early_param("crashkernel", enable_crash_mem_map);
>   
> +#ifdef CONFIG_KFENCE
> +
> +bool kfence_early_init = !!CONFIG_KFENCE_SAMPLE_INTERVAL;

maybe add __ro_after_init

> +
> +/* early_param() will be parsed before map_mem() below. */
> +static int __init parse_kfence_early_init(char *arg)
> +{
> +	int val;
> +
> +	if (get_option(&arg, &val))
> +		kfence_early_init = !!val;
> +	return 0;
> +}
> +early_param("kfence.sample_interval", parse_kfence_early_init);
> +
> +static phys_addr_t arm64_kfence_alloc_pool(void)

and __init

> +{
> +	phys_addr_t kfence_pool;
> +
> +	if (!kfence_early_init)
> +		return 0;
> +
> +	kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
> +	if (!kfence_pool) {
> +		pr_err("failed to allocate kfence pool\n");
> +		kfence_early_init = false;
> +		return 0;
> +	}
> +
> +	/* Temporarily mark as NOMAP. */
> +	memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
> +
> +	return kfence_pool;
> +}
> +
> +static void arm64_kfence_map_pool(phys_addr_t kfence_pool, pgd_t *pgdp)

Ditto.

Reviewed-by: Kefeng Wang <wangkefeng.wang@huawei.com>

> +{
> +	if (!kfence_pool)
> +		return;
> +
> +	/* KFENCE pool needs page-level mapping. */
> +	__map_memblock(pgdp, kfence_pool, kfence_pool + KFENCE_POOL_SIZE,
> +			pgprot_tagged(PAGE_KERNEL),
> +			NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
> +	memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
> +	__kfence_pool = phys_to_virt(kfence_pool);
> +}
> +#else /* CONFIG_KFENCE */
> +
> +static inline phys_addr_t arm64_kfence_alloc_pool(void) { return 0; }
> +static inline void arm64_kfence_map_pool(phys_addr_t kfence_pool, pgd_t *pgdp) { }
> +
> +#endif /* CONFIG_KFENCE */
> +
>   static void __init map_mem(pgd_t *pgdp)
>   {
>   	static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
>   	phys_addr_t kernel_start = __pa_symbol(_stext);
>   	phys_addr_t kernel_end = __pa_symbol(__init_begin);
>   	phys_addr_t start, end;
> +	phys_addr_t early_kfence_pool;
>   	int flags = NO_EXEC_MAPPINGS;
>   	u64 i;
>   
> @@ -539,6 +596,8 @@ static void __init map_mem(pgd_t *pgdp)
>   	 */
>   	BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
>   
> +	early_kfence_pool = arm64_kfence_alloc_pool();
> +
>   	if (can_set_direct_map())
>   		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
>   
> @@ -604,6 +663,8 @@ static void __init map_mem(pgd_t *pgdp)
>   		}
>   	}
>   #endif
> +
> +	arm64_kfence_map_pool(early_kfence_pool, pgdp);
>   }
>   
>   void mark_rodata_ro(void)
> diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
> index debdecf..dd1291a 100644
> --- a/arch/arm64/mm/pageattr.c
> +++ b/arch/arm64/mm/pageattr.c
> @@ -11,6 +11,7 @@
>   #include <asm/cacheflush.h>
>   #include <asm/set_memory.h>
>   #include <asm/tlbflush.h>
> +#include <asm/kfence.h>
>   
>   struct page_change_data {
>   	pgprot_t set_mask;
> @@ -22,12 +23,14 @@ bool rodata_full __ro_after_init = IS_ENABLED(CONFIG_RODATA_FULL_DEFAULT_ENABLED
>   bool can_set_direct_map(void)
>   {
>   	/*
> -	 * rodata_full, DEBUG_PAGEALLOC and KFENCE require linear map to be
> +	 * rodata_full and DEBUG_PAGEALLOC require linear map to be
>   	 * mapped at page granularity, so that it is possible to
>   	 * protect/unprotect single pages.
> +	 *
> +	 * KFENCE pool requires page-granular mapping if initialized late.
>   	 */
>   	return (rodata_enabled && rodata_full) || debug_pagealloc_enabled() ||
> -		IS_ENABLED(CONFIG_KFENCE);
> +		arm64_kfence_can_set_direct_map();
>   }
>   
>   static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 1417888..bf2f194c 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -824,6 +824,10 @@ void __init kfence_alloc_pool(void)
>   	if (!kfence_sample_interval)
>   		return;
>   
> +	/* if the pool has already been initialized by arch, skip the below. */
> +	if (__kfence_pool)
> +		return;
> +
>   	__kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
>   
>   	if (!__kfence_pool)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8f064a51-723e-986e-be25-ec2929b685de%40huawei.com.
