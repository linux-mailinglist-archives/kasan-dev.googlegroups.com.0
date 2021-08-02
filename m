Return-Path: <kasan-dev+bncBCRKFI7J2AJRBMFZTWEAMGQEWCAMLWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BE263DCEBF
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Aug 2021 04:47:14 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id w19-20020a170902d113b029012c1505a89fsf4745371plw.13
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Aug 2021 19:47:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627872433; cv=pass;
        d=google.com; s=arc-20160816;
        b=FT8E6ZMaBi3PEBBcw3Yorwz8v/qIWg56dl4T+iHcyc+WgPW1Ccbeimp4VEv/H0RCFP
         KNGKQOw2hJxfyd9xtCfpXZp1HP2AOEO9eK7LT+Gcj/0mWbwqRTuZ308i/REskk1tstpj
         9DU052lhyms75qFolmdgJnCl29fgSovJ6EqXvH/axw1DW5CJnBAybcHK96qX+wgdCDJC
         llvpLF2SHl4G47Tte/QGt/PeqcFhb7DY0bbWJ/tOh7VSwdGXfZ3ckjC1BSWUmhatjx9C
         u4PlNQd4SNWhQ4kKbOD0VlkhGluLalKMzIU2zBQVHQfUL6sRwPYB671vVRI44l1Ot/qX
         laGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=NMdXzHNTqrsj2aOzDDBVoXlJJcIZyj4W0eyT54plXD4=;
        b=a9E7gvBl/F3q3PWb93/qt6y1d0gB0kaqOIWNVKy2W8Ie/+p61B1Ph6ylD4+/b4pAqQ
         Hmz3rUiVQqIc5PpBV0Bfd8MylpUp3MiKMSPJkj7dfLOGkEhmM7e6auKred5fbnoiVwp/
         h+3D6MOXDF9m51QSyYDx0Wf28SWGIHTV89jePRmxwxTN45F+pNX50VkZk2hq4JpJ0ATi
         56Lk9MtjwHoaHFjWF3SbMJsNv4yM5RcuYMPDKXEup1IkDhzYnnO0sKIQE/6dVVY1X0eJ
         xUtnn0jlcdn3wgO7P9rwT8EmYkLJY63/q/PtpDLUCdXi+2nL9N3emVLUNJSQE7YutpkA
         6bJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NMdXzHNTqrsj2aOzDDBVoXlJJcIZyj4W0eyT54plXD4=;
        b=UDSVmoolk3CUJJaMloUWPjHCCkaPkk6+lqD0hJocfowkt0f9XmwHmUIeOgu+0VNLCA
         ivYCTuTYH/WCvVm91750UkWj4QVZJHZZALlzk3U4thuu6a6fnTpOvw5ujzx4JQZR+DMf
         R/4zaID/TFtebtj+7prNeq2KNYGcLtYfPAXHzN9Q77ZS6C8s7UwwddU1iKuNJFyh1ZwM
         g43GSFevI1F8f5DQHPqvpYozlom5DjQceoSXpwJC7gm5Dj7SaI4ctQ9UIsZ2xLoF2rGi
         lXD/ginlILc+HwAduwhvMOIm8HrbwlEODUJcnOph/ADU8K/7CAlSjNqcJGNocLqGb60G
         hH3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NMdXzHNTqrsj2aOzDDBVoXlJJcIZyj4W0eyT54plXD4=;
        b=jR8mMAzJhsZhiy073GtgjgLZGPRKHOd6lYpi0S4G33euMilFq9Q7QFoW6QSintpPpA
         NOH5vH9MG9gl+W+G9vB5+Mlki/xupR6SbNxCnEhhBeWSwcaDOFmEx2iJfisLyfCXQ1Je
         MINSC3fjvGsAyqtoUCn6uLTrQASIuPVILEdsz3zPoVlYgru9J9FhBqBLekL+EBTvX6dp
         vqHJW4UGZPPVBNPd1Y5rkLcDfbGGohAuT5cN2ajY2whjGThUA3f+lHEYBP4zzSmXdYCS
         F+fURAUX7eySPAeo7p7xaJjA6dQuHrGSO4tmPuAyCuwlDJhEjvHvHYM7G4EvnGFt/Xeu
         PfDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531WNAugOunVt6JC4K75N0oWDbSWWU0bt5xRlbT2leq2DgqTfgkc
	RQPJLH3vIifnb0iRcd3j1LY=
X-Google-Smtp-Source: ABdhPJwoGO3mEDU07vgA3lnLhdqAq38NNX6GjRgsjmXebBvQDKkD6ka029KSPEL3RGVJRAdtIMkOsQ==
X-Received: by 2002:a17:902:7885:b029:12c:437a:95eb with SMTP id q5-20020a1709027885b029012c437a95ebmr12309240pll.80.1627872432897;
        Sun, 01 Aug 2021 19:47:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5256:: with SMTP id s22ls3767928pgl.11.gmail; Sun, 01
 Aug 2021 19:47:12 -0700 (PDT)
X-Received: by 2002:a62:3342:0:b029:3b7:6395:a93 with SMTP id z63-20020a6233420000b02903b763950a93mr7133269pfz.71.1627872432385;
        Sun, 01 Aug 2021 19:47:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627872432; cv=none;
        d=google.com; s=arc-20160816;
        b=MYlxFDzSPDagT3C093erqU0gqiiyqM9VpNWHNk9CERS+XDExox3ob84m/xq8AlnUZS
         Ib2Ng/uomT/Bp1QZEPI9W0r/QEAEz3HjlFEQgDN2cuD1D8TWim78xfLsKM1d+NzlTbp+
         ZZbtPQ8rC32gitsVCBj62s0pVfBMwIj8sxc+imGpL+5VoOHKDeAD/fxaZ6OqmCAXusRz
         rNck4ATFgYgnNsL0aSTRz89aqtxBTg9TMB55ZIDRJPG1Z7Rtfi1peBuSbTWCPVEgMevK
         mRqCiPhwGODXMfxWQDDhbSt2moAqwXW6gi0fbeGmUK70tUB1+RsqIpnfygxJ5UPKDiNy
         JkHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=u2HMBOof5arDyhZd8kkgrPv/h6eHo/dfM91hLmDAZKY=;
        b=A129EkuSrwDTfePwwEch0tV4c+on9s0mPIngc4uJLanhzptGLqcjo2hnenf1R2ZkIL
         7e3uLje9NgmYU7AVQpYxYBEPBn6TXTgP/Qa2fpyjZBvysGJguvBJnIygDRjcDw0QUNXh
         UrSq+LO29og9Td4BIIGM3+CGTjFGKXAbsSOOAZjOFMsk3GTnt0BUtuF4g7Dtuw1tzltX
         1XT9yRnm32tf4IKH+VQQzRmJIxgJ/TiNWxDU8AA5yUeQGlmKMUSgOLht9U7y7ioe8Q8t
         41M1sbYF786soYTVwbgX9wkiF+URaoKBw3uWRHdYPv0DrYYp7k5yF9QpOTeJhWWRWrQP
         /B1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id k91si173983pja.3.2021.08.01.19.47.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 01 Aug 2021 19:47:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.53])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4GdMkw0WYZzcjk4;
	Mon,  2 Aug 2021 10:43:36 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 2 Aug 2021 10:47:05 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 2 Aug 2021 10:47:04 +0800
Subject: Re: [PATCH v2 2/3] arm64: Support page mapping percpu first chunk
 allocator
To: Catalin Marinas <catalin.marinas@arm.com>
CC: Will Deacon <will@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, Greg Kroah-Hartman
	<gregkh@linuxfoundation.org>
References: <20210720025105.103680-1-wangkefeng.wang@huawei.com>
 <20210720025105.103680-3-wangkefeng.wang@huawei.com>
 <20210801155302.GA29188@arm.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <c98e372c-be3e-0440-f37c-0dd0bf8f79c3@huawei.com>
Date: Mon, 2 Aug 2021 10:47:04 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20210801155302.GA29188@arm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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


On 2021/8/1 23:53, Catalin Marinas wrote:
> On Tue, Jul 20, 2021 at 10:51:04AM +0800, Kefeng Wang wrote:
>> Percpu embedded first chunk allocator is the firstly option, but it
>> could fails on ARM64, eg,
>>    "percpu: max_distance=0x5fcfdc640000 too large for vmalloc space 0x781fefff0000"
>>    "percpu: max_distance=0x600000540000 too large for vmalloc space 0x7dffb7ff0000"
>>    "percpu: max_distance=0x5fff9adb0000 too large for vmalloc space 0x5dffb7ff0000"
>>
>> then we could meet "WARNING: CPU: 15 PID: 461 at vmalloc.c:3087 pcpu_get_vm_areas+0x488/0x838",
>> even the system could not boot successfully.
>>
>> Let's implement page mapping percpu first chunk allocator as a fallback
>> to the embedding allocator to increase the robustness of the system.
> It looks like x86, powerpc and sparc implement their own
> setup_per_cpu_areas(). I had a quick look on finding some commonalities
> but I think it's a lot more hassle to make a generic version out of them
> (powerpc looks the simplest though). I think we could add a generic
> variant with the arm64 support and later migrate other architectures to
> it if possible.
Ok, let's do it later, I could try to make some cleanup after the 
patchset is merged ;)
> The patch looks ok to me otherwise but I'd need an ack from Greg as it
> touches drivers/.

the arch_numa is only used ARM64 and riscv, the 
NEED_PER_CPU_PAGE_FIRST_CHUNK

is not enabled on RISCV, so it's no bad effect.

>
> BTW, do we need something similar for the non-NUMA
> setup_per_cpu_areas()? I can see this patch only enables
> NEED_PER_CPU_PAGE_FIRST_CHUNK if NUMA.
>
> Leaving the rest of the patch below for Greg.
>
>> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
>> ---
>>   arch/arm64/Kconfig       |  4 ++
>>   drivers/base/arch_numa.c | 82 +++++++++++++++++++++++++++++++++++-----
>>   2 files changed, 76 insertions(+), 10 deletions(-)
>>
>> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
>> index b5b13a932561..eacb5873ded1 100644
>> --- a/arch/arm64/Kconfig
>> +++ b/arch/arm64/Kconfig
>> @@ -1045,6 +1045,10 @@ config NEED_PER_CPU_EMBED_FIRST_CHUNK
>>   	def_bool y
>>   	depends on NUMA
>>   
>> +config NEED_PER_CPU_PAGE_FIRST_CHUNK
>> +	def_bool y
>> +	depends on NUMA
>> +
>>   source "kernel/Kconfig.hz"
>>   
>>   config ARCH_SPARSEMEM_ENABLE
>> diff --git a/drivers/base/arch_numa.c b/drivers/base/arch_numa.c
>> index 4cc4e117727d..563b2013b75a 100644
>> --- a/drivers/base/arch_numa.c
>> +++ b/drivers/base/arch_numa.c
>> @@ -14,6 +14,7 @@
>>   #include <linux/of.h>
>>   
>>   #include <asm/sections.h>
>> +#include <asm/pgalloc.h>
>>   
>>   struct pglist_data *node_data[MAX_NUMNODES] __read_mostly;
>>   EXPORT_SYMBOL(node_data);
>> @@ -168,22 +169,83 @@ static void __init pcpu_fc_free(void *ptr, size_t size)
>>   	memblock_free_early(__pa(ptr), size);
>>   }
>>   
>> +#ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
>> +static void __init pcpu_populate_pte(unsigned long addr)
>> +{
>> +	pgd_t *pgd = pgd_offset_k(addr);
>> +	p4d_t *p4d;
>> +	pud_t *pud;
>> +	pmd_t *pmd;
>> +
>> +	p4d = p4d_offset(pgd, addr);
>> +	if (p4d_none(*p4d)) {
>> +		pud_t *new;
>> +
>> +		new = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
>> +		if (!new)
>> +			goto err_alloc;
>> +		p4d_populate(&init_mm, p4d, new);
>> +	}
>> +
>> +	pud = pud_offset(p4d, addr);
>> +	if (pud_none(*pud)) {
>> +		pmd_t *new;
>> +
>> +		new = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
>> +		if (!new)
>> +			goto err_alloc;
>> +		pud_populate(&init_mm, pud, new);
>> +	}
>> +
>> +	pmd = pmd_offset(pud, addr);
>> +	if (!pmd_present(*pmd)) {
>> +		pte_t *new;
>> +
>> +		new = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
>> +		if (!new)
>> +			goto err_alloc;
>> +		pmd_populate_kernel(&init_mm, pmd, new);
>> +	}
>> +
>> +	return;
>> +
>> +err_alloc:
>> +	panic("%s: Failed to allocate %lu bytes align=%lx from=%lx\n",
>> +	      __func__, PAGE_SIZE, PAGE_SIZE, PAGE_SIZE);
>> +}
>> +#endif
>> +
>>   void __init setup_per_cpu_areas(void)
>>   {
>>   	unsigned long delta;
>>   	unsigned int cpu;
>> -	int rc;
>> +	int rc = -EINVAL;
>> +
>> +	if (pcpu_chosen_fc != PCPU_FC_PAGE) {
>> +		/*
>> +		 * Always reserve area for module percpu variables.  That's
>> +		 * what the legacy allocator did.
>> +		 */
>> +		rc = pcpu_embed_first_chunk(PERCPU_MODULE_RESERVE,
>> +					    PERCPU_DYNAMIC_RESERVE, PAGE_SIZE,
>> +					    pcpu_cpu_distance,
>> +					    pcpu_fc_alloc, pcpu_fc_free);
>> +#ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
>> +		if (rc < 0)
>> +			pr_warn("PERCPU: %s allocator failed (%d), falling back to page size\n",
>> +				   pcpu_fc_names[pcpu_chosen_fc], rc);
>> +#endif
>> +	}
>>   
>> -	/*
>> -	 * Always reserve area for module percpu variables.  That's
>> -	 * what the legacy allocator did.
>> -	 */
>> -	rc = pcpu_embed_first_chunk(PERCPU_MODULE_RESERVE,
>> -				    PERCPU_DYNAMIC_RESERVE, PAGE_SIZE,
>> -				    pcpu_cpu_distance,
>> -				    pcpu_fc_alloc, pcpu_fc_free);
>> +#ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
>> +	if (rc < 0)
>> +		rc = pcpu_page_first_chunk(PERCPU_MODULE_RESERVE,
>> +					   pcpu_fc_alloc,
>> +					   pcpu_fc_free,
>> +					   pcpu_populate_pte);
>> +#endif
>>   	if (rc < 0)
>> -		panic("Failed to initialize percpu areas.");
>> +		panic("Failed to initialize percpu areas (err=%d).", rc);
>>   
>>   	delta = (unsigned long)pcpu_base_addr - (unsigned long)__per_cpu_start;
>>   	for_each_possible_cpu(cpu)
>> -- 
>> 2.26.2
> .
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c98e372c-be3e-0440-f37c-0dd0bf8f79c3%40huawei.com.
