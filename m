Return-Path: <kasan-dev+bncBCRKFI7J2AJRBGH3RKDAMGQE5FCTQSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A31F3A3951
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jun 2021 03:34:18 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id b23-20020a17090ae397b0290163949acb4dsf4977390pjz.9
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 18:34:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623375257; cv=pass;
        d=google.com; s=arc-20160816;
        b=xf6h1IFXxDDDubMC4uMTkuP4MmAXGknIFNVb/LoZkinAn1+34X/TXJUQDAOkIBwgOL
         2yOqJwXS0fy5AvNCJn+/Z5/9WqDnn2/dIp6vgHx7WK/A2PGEUq32Ie2xzcvSBv9wN6U8
         cGrQQ837h1NqJJ5cvTxqVISU0gDb6FnQqVhTODx/fQPQARAq1EdnPLU2bSyzghnmUgpO
         Bu8qFtH/cLN3kH5/ugfsWDyoNr3dNIP5fCnJZcRjhOTaUDGzwWFBizZyy48oH0b9DIOf
         L0tdNXcHdT1D6YoPXzwicmjIes1wFUIz6+xtxpRTH37CBdmbDHg/XcReWnIX+qs6UCS4
         YXmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=dL6CGWDG8OWsG1bPffZ7cHbHCcgB0RtD4yPYlPxxowc=;
        b=CcnNbVPBWIIdrLVFPKghvxE9QtqUwZiup8tTfPFSZ0cditK3JtvxRzItxPUK+jCv1s
         Sl09KB8p7+VC3ogKXMiKdi2RfQqXHCTJLw/BqkEdqZjeAUkel3faf4INanG9Zvm3AMGf
         DZPq0zHvEORU8nb5oPiByZ4kZUCMEh3vzlUTaxNcBB2VN5j8qgkIua/PIqXmUNfeNqnC
         PxQWIWybrq2pNnUsTNDWWZfaWQrXx7CrUqZmKMc7jP5clk7J3mni+ASMayo5uqQf2b0T
         jQ4/uHdyKWqrA4YmZFFsXuZEIR8TjFrxSbkT3EvyurKVORbS/1iB9n0f1yWivGgj/OFE
         umOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dL6CGWDG8OWsG1bPffZ7cHbHCcgB0RtD4yPYlPxxowc=;
        b=FohLSahRzr1cSkLl779L6caCNEL+NMCXCnAx3mKuu2R63hM/40xPTEQ0ezR01LW/qO
         zGcOR4onVg+BoRFcMsSsayUXB2O4yLUMJQFbR7MpsC9RAz8PeJDz2WU1qEG86t2x4vGu
         aq+cz7ADdpm83esM7cgBNv4GLaswQsQPNW5NBEK1oYisyihhlLSUjtUBarOALdCLt27k
         LWdmg9JoMRpXmCh5vdtJj//OpamWQt5OhUeyhseuQ4M+CWe6/cSZFFO3Zb27JsPqNV/b
         8R30lMbOawiR9jCeEstdTLG21xPt/zNyj0LcL74DMgPFbq1Q4OwriUxjxDJtek1pF6Bm
         /41w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dL6CGWDG8OWsG1bPffZ7cHbHCcgB0RtD4yPYlPxxowc=;
        b=QtU3/69IpzE9IKIDNlPq6eIa/JIy/agTOpgXWQjueXR734WjTqU+v9ECS6ApBSMHpv
         w/fiqH3OGuHUER+rslQ8pCEo1xgaDfEJuhUb0POAmKqPisn8iG2cxXNc6OK+9ShrpGgJ
         ob7yFiEYgCBYITVVkj4TRxQ0llu6yxkxaOz7ZI2TVmu0YiGwIe/cc9moo1jEsmnxmosH
         1uybQX84knxIwNlOFJPx9QRzOWWM/hH8GTpI30ZA1st1MyXXWWqT74nFHhEuNfRj4K9D
         mfV9J4EbmFIxkS3SOKo9CfA3yrg/n2RGCaX9yVlI3QbmALGyPYb9iJZEO+PmDJrDBT5g
         YJEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533vdbtmh2scKrc5t2U/FJi2zxBYy615okCdM6kdQgnoYhlg1cJh
	F5RbZ2v6jFBu7UhONKJ6itk=
X-Google-Smtp-Source: ABdhPJwws+lhmsY6ZYqTTqTp6+LdK8QgUo1fwCSCoyFLN/F0EogwXlHADFbs2LWVpwlGbFlf1of/IQ==
X-Received: by 2002:a63:1163:: with SMTP id 35mr1175732pgr.400.1623375256898;
        Thu, 10 Jun 2021 18:34:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e804:: with SMTP id u4ls4463085plg.9.gmail; Thu, 10
 Jun 2021 18:34:16 -0700 (PDT)
X-Received: by 2002:a17:90a:de8a:: with SMTP id n10mr1752309pjv.76.1623375256342;
        Thu, 10 Jun 2021 18:34:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623375256; cv=none;
        d=google.com; s=arc-20160816;
        b=sfb9ey9xDFOuli0y4uYKPtVK6C3ZievxJx1r2G/q9/lG5Vua7uX3N13BhrJHT/EZ1W
         4EMVgswnZX8yw1lVSoNuMBVcUxtFBmVYPQIwP0din6jn+FLxfbMW9/DImXF0KxIx2E37
         R6vwahFGBaxSWSzV6IuYshEFZNjkhun4xL6uNk7suFVkB3rx3axVpPvTlAMJshlXysum
         TBOgAnt9/pB1MoZmdy1pmJ2dkBm9CYx1UV7JwCHwDFRB4tM+gBQ1hghZ9EcbTQ3ow+sa
         KIgin8mKyuxKtJkEg9UumWPFlV1s5+A2o1DbRBKrhQtZgmIdh0KKpLXCclgM3AoiA2QA
         bwuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=afaFi8Ks7iipy+6fw1Oi9pQDfd3hTUMugzohOFkmQQc=;
        b=tj28RbNjJqZXZiT0yO5HYotz8cSUbKPQfqs4f7DRjImTbhULYqUfLolxeqGHwY3rrB
         GUH/TtbrbjBSIL74tZNBRV2EzQYkfVb3Un0Wl+g3hgFPehZdzwCcbdiU3BpsHIeoRPm2
         DdJHN0DOr2bKTUhS598bAugRQCOV3NP+bdGMTxz8JMpxP0drkAW4cxmP8z5W+43Tx+Ri
         7vSLNLLGMV7ERxBeUs2w8R+L4E224fKiyudAe1NmgYDW5XKVBvajvt/BpeudcLekvvAb
         /qLq8HPMg2Ee+J4O0JI7Q3eJKgiB+HWMWCZd8Kzd07zWmUYkNqFd+0q2UgkBuEbT/RMw
         d8Jg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id s14si465014pfu.0.2021.06.10.18.34.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Jun 2021 18:34:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4G1NZj1TTDz6xWH;
	Fri, 11 Jun 2021 09:30:37 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Fri, 11 Jun 2021 09:33:13 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Fri, 11 Jun 2021 09:33:12 +0800
Subject: Re: [PATCH -next] riscv: Enable KFENCE for riscv64
To: Liu Shixin <liushixin2@huawei.com>, Paul Walmsley
	<paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou
	<aou@eecs.berkeley.edu>, Alexander Potapenko <glider@google.com>, Marco Elver
	<elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
CC: <linux-riscv@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Palmer Dabbelt <palmerdabbelt@google.com>
References: <20210529080340.2987212-1-liushixin2@huawei.com>
 <0a3ee489-47db-47f5-6192-794457fc74f8@huawei.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <a7c49be6-e01e-72de-fc2c-e662fc147495@huawei.com>
Date: Fri, 11 Jun 2021 09:33:12 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <0a3ee489-47db-47f5-6192-794457fc74f8@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
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


On 2021/6/9 14:17, Liu Shixin wrote:
> Hi, everybody,
>
> I perfected the patch based on the previous advice. How about this version?
Reviewed-by: Kefeng Wang <wangkefeng.wang@huawei.com>
>
> Thanks,
>
>
> On 2021/5/29 16:03, Liu Shixin wrote:
>> Add architecture specific implementation details for KFENCE and enable
>> KFENCE for the riscv64 architecture. In particular, this implements the
>> required interface in <asm/kfence.h>.
>>
>> KFENCE requires that attributes for pages from its memory pool can
>> individually be set. Therefore, force the kfence pool to be mapped at
>> page granularity.
>>
>> Testing this patch using the testcases in kfence_test.c and all passed.
>>
>> Signed-off-by: Liu Shixin <liushixin2@huawei.com>
>> ---
>> 1. Add helper function split_pmd_page() which is used to split a pmd to ptes.
>> 2. Add the judgment on the result of pte_alloc_one_kernel().
>>
>>   arch/riscv/Kconfig              |  1 +
>>   arch/riscv/include/asm/kfence.h | 63 +++++++++++++++++++++++++++++++++
>>   arch/riscv/mm/fault.c           | 11 +++++-
>>   3 files changed, 74 insertions(+), 1 deletion(-)
>>   create mode 100644 arch/riscv/include/asm/kfence.h
>>
>> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
>> index 4982130064ef..2f4903a7730f 100644
>> --- a/arch/riscv/Kconfig
>> +++ b/arch/riscv/Kconfig
>> @@ -65,6 +65,7 @@ config RISCV
>>   	select HAVE_ARCH_JUMP_LABEL_RELATIVE
>>   	select HAVE_ARCH_KASAN if MMU && 64BIT
>>   	select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
>> +	select HAVE_ARCH_KFENCE if MMU && 64BIT
>>   	select HAVE_ARCH_KGDB
>>   	select HAVE_ARCH_KGDB_QXFER_PKT
>>   	select HAVE_ARCH_MMAP_RND_BITS if MMU
>> diff --git a/arch/riscv/include/asm/kfence.h b/arch/riscv/include/asm/kfence.h
>> new file mode 100644
>> index 000000000000..d887a54042aa
>> --- /dev/null
>> +++ b/arch/riscv/include/asm/kfence.h
>> @@ -0,0 +1,63 @@
>> +/* SPDX-License-Identifier: GPL-2.0 */
>> +
>> +#ifndef _ASM_RISCV_KFENCE_H
>> +#define _ASM_RISCV_KFENCE_H
>> +
>> +#include <linux/kfence.h>
>> +#include <linux/pfn.h>
>> +#include <asm-generic/pgalloc.h>
>> +#include <asm/pgtable.h>
>> +
>> +static inline int split_pmd_page(unsigned long addr)
>> +{
>> +	int i;
>> +	unsigned long pfn = PFN_DOWN(__pa((addr & PMD_MASK)));
>> +	pmd_t *pmd = pmd_off_k(addr);
>> +	pte_t *pte = pte_alloc_one_kernel(&init_mm);
>> +
>> +	if (!pte)
>> +		return -ENOMEM;
>> +
>> +	for (i = 0; i < PTRS_PER_PTE; i++)
>> +		set_pte(pte + i, pfn_pte(pfn + i, PAGE_KERNEL));
>> +	set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(pte)), PAGE_TABLE));
>> +
>> +	flush_tlb_kernel_range(addr, addr + PMD_SIZE);
>> +	return 0;
>> +}
>> +
>> +static inline bool arch_kfence_init_pool(void)
>> +{
>> +	int ret;
>> +	unsigned long addr;
>> +	pmd_t *pmd;
>> +
>> +	for (addr = (unsigned long)__kfence_pool; is_kfence_address((void *)addr);
>> +	     addr += PAGE_SIZE) {
>> +		pmd = pmd_off_k(addr);
>> +
>> +		if (pmd_leaf(*pmd)) {
>> +			ret = split_pmd_page(addr);
>> +			if (ret)
>> +				return false;
>> +		}
>> +	}
>> +
>> +	return true;
>> +}
>> +
>> +static inline bool kfence_protect_page(unsigned long addr, bool protect)
>> +{
>> +	pte_t *pte = virt_to_kpte(addr);
>> +
>> +	if (protect)
>> +		set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
>> +	else
>> +		set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
>> +
>> +	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
>> +
>> +	return true;
>> +}
>> +
>> +#endif /* _ASM_RISCV_KFENCE_H */
>> diff --git a/arch/riscv/mm/fault.c b/arch/riscv/mm/fault.c
>> index 096463cc6fff..aa08dd2f8fae 100644
>> --- a/arch/riscv/mm/fault.c
>> +++ b/arch/riscv/mm/fault.c
>> @@ -14,6 +14,7 @@
>>   #include <linux/signal.h>
>>   #include <linux/uaccess.h>
>>   #include <linux/kprobes.h>
>> +#include <linux/kfence.h>
>>   
>>   #include <asm/ptrace.h>
>>   #include <asm/tlbflush.h>
>> @@ -45,7 +46,15 @@ static inline void no_context(struct pt_regs *regs, unsigned long addr)
>>   	 * Oops. The kernel tried to access some bad page. We'll have to
>>   	 * terminate things with extreme prejudice.
>>   	 */
>> -	msg = (addr < PAGE_SIZE) ? "NULL pointer dereference" : "paging request";
>> +	if (addr < PAGE_SIZE)
>> +		msg = "NULL pointer dereference";
>> +	else {
>> +		if (kfence_handle_page_fault(addr, regs->cause == EXC_STORE_PAGE_FAULT, regs))
>> +			return;
>> +
>> +		msg = "paging request";
>> +	}
>> +
>>   	die_kernel_fault(msg, addr, regs);
>>   }
>>   
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv
> .
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a7c49be6-e01e-72de-fc2c-e662fc147495%40huawei.com.
