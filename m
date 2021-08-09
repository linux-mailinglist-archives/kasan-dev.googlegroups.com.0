Return-Path: <kasan-dev+bncBCRKFI7J2AJRBFU2YSEAMGQEC5Z7B4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id B0F203E446C
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 13:10:15 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id l9-20020a0568080209b0290267587da9dasf3325733oie.15
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Aug 2021 04:10:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628507414; cv=pass;
        d=google.com; s=arc-20160816;
        b=S702UStcy+OFmGb4zGaHhYnW9lHeunko4avZCfExmPWg78EZEk2B5yB/LcaLB38cOB
         ETwn2uc0PYGhOacoEp3FTNoPUbA03fOI064mV4dUuMo69lu+NHlX3B6CflxnDNA5QcNV
         a0U5YvmDtQcYNTWXK40iK96EMNwBY8px+hi15UQwoqpYR7nORYqpxgWegfA+ZOpkCbeR
         yBN4utyHrgQPQjG/1oyyMOnNAJoXmhq8DL4mAfwW4yAZjovKRC7ele7dnLT2w0HaSijo
         DpxbFBGoS/9xinfuyVPDp0oyylz6qZ9+hUF4pN1KrHmkYbN8Or4prV6VA2mIdiFzpSb3
         fkFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=gzwb1t3q9qmJ099UzVrZKy9VHqSZhnmCDrwY+lpA/hA=;
        b=UUWrg0P4nJu9ej0vvnVJA/wz/lXYJ+GpB7nysFY899mfry6h3pSYdMGWcyfPyN1z2W
         pClI/PpeE6J+3azYLtr2WSQ7Rd2Lr88+GXYwNLQ6hHJrVN9Er8yEIdn3tDTWw/qIXSy6
         1kiedbgJKYXZs9IOMvRVsU+jfo2kNCtXgHZkgkXpr9VExdVyf1cyMjEtqwTLy+LLimbv
         UUtZEnKUQmmnf6cAWhoGB5FxReQhAw6jJlvk9/6lbuGZfREtCV6N5+MBVzELVhO6eSXC
         ZXWn1FDfzQTxpTD61gWMgUHfCJ4wanMUnsMdlmbSDyL52NHvpOeBTQ1i9IhXwWFO47mF
         N/Lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gzwb1t3q9qmJ099UzVrZKy9VHqSZhnmCDrwY+lpA/hA=;
        b=UnmxFWTcdV/lOFaVuse2QAFLfWD8sEs3zsAIZ/8cDQmEOnu4lRzyLgAogq7LsAgZ3c
         cIgoN3x7o0Lj1LQEEUO+sjlgqLIRk1mZhFaREifnJNzESu7Kwi3F0jw0sAHQq0MxwC+j
         ayKtpSq74mMp5hUJ1th1ua1fH6HWKCctCuDiy8I6QF1sOWDBDLs8w56T1oT6CKrBmj3n
         zWFnvEiWhhyszqYEBjd7WtEskMh11syaiVYQp+gMmsKqDvazoi435Be+Iq4uOX62dT/Y
         Cpj8taIXhe8JOrxfPdXSFwR9IZwp48nC3WT6tu0AXf+9sZ04hR56zJgka7ShTR48Xa8R
         TLSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gzwb1t3q9qmJ099UzVrZKy9VHqSZhnmCDrwY+lpA/hA=;
        b=Ld8PgvExP+pb7IxDSn3lE7DCIuCx29WVe2d4Bl0vqKnEu7ALDPu4IsjWdRCMJbbsKD
         szS6uZDCMrsDF++COe7y0Knmh81Oo54oQG5Lxvc8j+59z1lYdd5XvuoumhGTEPrQrpoe
         KUiFqQFR/regYY79fBlSXZzSgZrUOiHOnx4Gelk7BCXNNWd8uChMqwSDfBwf4IqbT+G1
         1DD2urQn/xhGDDxJDl+Xcu1qKre9Lfdq3eAyFjn3qWY96OpKu0EyOJPzus4beQmzZFZT
         ThdQkVCFOwUrr/ZBTz7knXN08UGJKt445y5IZUIdOw9z7irPPfzRm09sGIsAabssWJ4T
         JTIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533VJ/zLfyLbmkr0DB7lXN9eJbNNpA+vVSfTkbfiDCmz5ZdqQVfm
	ARPFQPj3hMr92FeBEctlR/w=
X-Google-Smtp-Source: ABdhPJwqEd5nfGyGPC4tZVLgDu1ZlYhkFE8fh/mQX8054qQGYAT852XhlvXhD04y56hWaPv5AIng2g==
X-Received: by 2002:a05:6808:1301:: with SMTP id y1mr17416000oiv.156.1628507414752;
        Mon, 09 Aug 2021 04:10:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:51c7:: with SMTP id s190ls788034ooa.7.gmail; Mon, 09 Aug
 2021 04:10:14 -0700 (PDT)
X-Received: by 2002:a4a:9cd7:: with SMTP id d23mr14630703ook.12.1628507414353;
        Mon, 09 Aug 2021 04:10:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628507414; cv=none;
        d=google.com; s=arc-20160816;
        b=JoMl6Tp8J3uY/L7iqJrpE38j+FWeEqEsVArTBVBYMuRdpCpOboFitoOMTEKOjg2EAl
         fQeR9yAElOXMR48WB72mWDgv3++BiVji4B1fo4hoPqAbd4TYQvEqjvloEkpzjJC3ZV8q
         r05NFSFiBcb+lJIEvudqL1Vt0kl3ICB6zNK9g+MCDgoa1LShMgvZeaXNFGhu5k3nBzqM
         fBnHHVEHbIp3jdzelDU8Yt79NGpjqy+xl4QEhCzs8BnH7x3v7XbajD3JhAE/m5O8H7cu
         hzOXz7I+79N6kwNYSr2H9+j53fK1/T451T3GX1ESvvUDk9OSOOqQf9GtgjORaN6eb/8W
         En9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=fi1lvl8vnDSLMhKTbU4KJnadB7+V65wy0N+a0B9Sdxk=;
        b=hqkRBvGhEJnPMlHrA4C1duh9I5CQLpKZhL+go+VqOslidv8e+EH7QaVFRzVy2oP5fp
         0qUZFumoPyybCWoofvQkrQ7n7xtNNaLP85UIE4yUbkHxnbNbLMvBqtdQQxoL6b87yoyB
         cZk1KOHv2V67LRkxaR3fYMA5oDFB5avcCaMV7VCubOW2l9GyYpq0gbqQNR5MU4gLscGE
         u6FrMYRK7TmLF6L7peoHHSCtOSDQIZJzWnQudRSJBqzfEGaSws3DbP1IfCNvWUNB0yLV
         BhacSneJmO3AZdX7j3fFjS2T3VxU5UzVmekpB0iq1nCdQNlzsIeRmz49ycembjYAbSNi
         b3sg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id o7si659465oik.2.2021.08.09.04.10.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Aug 2021 04:10:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.57])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4GjtZ11gHqzb06D;
	Mon,  9 Aug 2021 19:06:33 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 9 Aug 2021 19:10:10 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 9 Aug 2021 19:10:10 +0800
Subject: Re: [PATCH v3 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash with
 KASAN_VMALLOC
To: <will@kernel.org>, <catalin.marinas@arm.com>, <ryabinin.a.a@gmail.com>,
	<andreyknvl@gmail.com>, <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, <elver@google.com>
References: <20210809093750.131091-1-wangkefeng.wang@huawei.com>
 <20210809093750.131091-4-wangkefeng.wang@huawei.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <ae15c02e-d825-dbef-1419-5b5220f826c1@huawei.com>
Date: Mon, 9 Aug 2021 19:10:09 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20210809093750.131091-4-wangkefeng.wang@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187
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


On 2021/8/9 17:37, Kefeng Wang wrote:
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
>   kasan_check_range+0x90/0x1a0
>   pcpu_page_first_chunk+0x3f0/0x568
>   setup_per_cpu_areas+0xb8/0x184
>   start_kernel+0x8c/0x328
>
> The vm area used in vm_area_register_early() has no kasan shadow memory,
> Let's add a new kasan_populate_early_vm_area_shadow() function to populate
> the vm area shadow memory to fix the issue.

Should add Acked-by: Marco Elver <elver@google.com> [for KASAN parts] ,

missed here :(

> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> ---
>   arch/arm64/mm/kasan_init.c | 16 ++++++++++++++++
>   include/linux/kasan.h      |  6 ++++++
>   mm/kasan/init.c            |  5 +++++
>   mm/vmalloc.c               |  1 +
>   4 files changed, 28 insertions(+)
>
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index 61b52a92b8b6..5b996ca4d996 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -287,6 +287,22 @@ static void __init kasan_init_depth(void)
>   	init_task.kasan_depth = 0;
>   }
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
> +	kasan_map_populate(shadow_start, shadow_end, NUMA_NO_NODE);
> +}
> +#endif
> +
>   void __init kasan_init(void)
>   {
>   	kasan_init_shadow();
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index dd874a1ee862..3f8c26d9ef82 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -133,6 +133,8 @@ struct kasan_cache {
>   	bool is_kmalloc;
>   };
>   
> +void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
> +
>   slab_flags_t __kasan_never_merge(void);
>   static __always_inline slab_flags_t kasan_never_merge(void)
>   {
> @@ -303,6 +305,10 @@ void kasan_restore_multi_shot(bool enabled);
>   
>   #else /* CONFIG_KASAN */
>   
> +static inline void kasan_populate_early_vm_area_shadow(void *start,
> +						       unsigned long size)
> +{ }
> +
>   static inline slab_flags_t kasan_never_merge(void)
>   {
>   	return 0;
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index cc64ed6858c6..d39577d088a1 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -279,6 +279,11 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
>   	return 0;
>   }
>   
> +void __init __weak kasan_populate_early_vm_area_shadow(void *start,
> +						       unsigned long size)
> +{
> +}
> +
>   static void kasan_free_pte(pte_t *pte_start, pmd_t *pmd)
>   {
>   	pte_t *pte;
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 1e8fe08725b8..66a7e1ea2561 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -2253,6 +2253,7 @@ void __init vm_area_register_early(struct vm_struct *vm, size_t align)
>   	vm->addr = (void *)addr;
>   
>   	vm_area_add_early(vm);
> +	kasan_populate_early_vm_area_shadow(vm->addr, vm->size);
>   }
>   
>   static void vmap_init_free_space(void)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ae15c02e-d825-dbef-1419-5b5220f826c1%40huawei.com.
