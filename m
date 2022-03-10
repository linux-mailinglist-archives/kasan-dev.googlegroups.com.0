Return-Path: <kasan-dev+bncBAABBX5PUWIQMGQEPMEIQLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B2204D3EDD
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Mar 2022 02:44:01 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id e14-20020a17090a684e00b001bf09ac2385sf2472482pjm.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Mar 2022 17:44:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646876640; cv=pass;
        d=google.com; s=arc-20160816;
        b=gcRaPDHS07KRthilZ/3FFDK0525aM9PYi0HsYQQ+XBreb9dPejI5P4zDdHlDYgqufO
         q/BP5Cl9QaKHCucOPCKlyyKzjiq5D7pfZryUNXHVjHC8LPz7d/kQTVpVLl+mbFhQ1j6h
         raALHSgNrW48W9nfyKIYKpJ9oncnVdWQhmfnOKfio4H5KxbJ1/0g6VJtpL/NzSD+FUMM
         +NUaaz7JtgFb44/il34dMHNUqMVExbPAuRi7bEqAy7PAfGFFmvCuEcOmq94Uad0MDcg/
         yXMom4aIBxszdNkeno1b8MfkaN1EUGnnIH2JaBEJbrn5BKOoowknEEWj6aLqA17CSiw4
         CYWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=TxaP7kQDYYYTl7y5LlrP993AnxDS35oq+VYHrkcbw30=;
        b=wwayj+lg/c5qLX6krFywD6YF81pWTOrYU1o5LxMuoAWupwC3e815rf/0VwbB9mfaIE
         05iWgQ4otBmDtqXbgF1zflg2YB/V5H1TV+M+NMi9k7u+Lk2mtgOsqHqUnHBJUZFRirOE
         meP0LshjK1DiI4FJ6VgWcUW+ryowL/OvpsQcCqmQwdmgUjHoMc09AOQw3h5DRG6Y2kCU
         kz64UEM0Q5MsDzRlVJkwqR/Wq9rz/ALrbA3fbWRrLYzaofyyoO6+vbsaYq5HzQCz3ZTA
         I+TjK3vigVT+w2veNNV3UdrAJ/CAEZwcp97EEo1ZQyxJ4V/uq02+R13d4NLQu28Z17R0
         xqIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=message-id:date:mime-version:user-agent:subject:content-language:to
         :cc:references:from:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=TxaP7kQDYYYTl7y5LlrP993AnxDS35oq+VYHrkcbw30=;
        b=F0P0UaYeqWfj+VmNgQuM/Ox/7rmuhknZMWWFK541a5fWZuxyFCo8AghONLbd1YFCc+
         g8MCewf7dUiPl+eBYOPzDtU4uibg8B+Oli1RyVXRQBCnTPG6D6SKRoIJ2aZiPZWaGZrg
         XSZ7pktQJ+/yPP4iKPd+7ZaRXGcIxMrL19lJ7Q29rNl0LzdyEGBNL4p2O+7T1ibLAHs8
         Je5Ji0CMoRdftb+h7sr4vi90u3I2KsdoWdI0nZ8rAzdXDal/HbDTMC3dslGQzP9vEtF0
         +agXcPMw9EEzWIBUbLmDHgxKvwG65Wj1gN0IEoGDvxRJPlV8odkG+Z6YhFyO8b63Aexg
         A6cQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TxaP7kQDYYYTl7y5LlrP993AnxDS35oq+VYHrkcbw30=;
        b=H1qwr/zl50ib6B//n8eKeL15nI+aY9FRU0fhlq+GkpAMMoP+ypGmdGIsfmkRf3CPvY
         JA2eNobeYOjbZcrE1L5aJSqBflEeaaUMXvsndGOT/GYsFd2ud2MaZD4jDvAbewwXMADM
         /Ox9FesnJ8StBUP+ecDK/xPc4hv7jPzRex/niiCxgdiC+7JUNeJtl1QGQCjI7Vu4xnnJ
         8lgEJJ/xW8G29svdETj1VCPn2vruhVm91+ZjlUr9zf5FH0LpRO0BBeGZbd1gpPl2HY1E
         WwpWOzrvHoNHr9Nffu8hLpf5jc02xU0624x5RkQfcYi7qttmnHcJ+LcVfWt2I2EhPzvw
         3bSA==
X-Gm-Message-State: AOAM532hrKOko5SS0/IanbKsjDdXVzhiKcWVceMCNSjRWbkMHy4bi8y6
	pOj4o4Zi2GF19FZYuwlT2tY=
X-Google-Smtp-Source: ABdhPJwtY7NqQlUqP/8dXc4ZZpqGpZS8y4mXfExr9kZIAAm0gNc5+wznSTmbDzX/1q/PKRCq7kihjg==
X-Received: by 2002:a17:903:2341:b0:150:2371:ee59 with SMTP id c1-20020a170903234100b001502371ee59mr2403965plh.57.1646876639968;
        Wed, 09 Mar 2022 17:43:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7ad6:0:b0:4f7:1c55:c251 with SMTP id v205-20020a627ad6000000b004f71c55c251ls1870506pfc.0.gmail;
 Wed, 09 Mar 2022 17:43:59 -0800 (PST)
X-Received: by 2002:a65:6805:0:b0:373:dd4e:d7a2 with SMTP id l5-20020a656805000000b00373dd4ed7a2mr2022437pgt.569.1646876639462;
        Wed, 09 Mar 2022 17:43:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646876639; cv=none;
        d=google.com; s=arc-20160816;
        b=DisNS72dAALO4TQ7ibvVcU+ThYXEpHIgPbxb4rqUatcqFiL/QkBur+609ylDEJ98u+
         jTxqUb6vR71/aZiSS2ChMlaOYOksdEO9L4QbdN/E4x4ngXUYXpBJVd1//yz2OfI/RZuO
         DyJFtzgrPEixLfY2yAK6WWcVwYznkMQg7dlvMCqXV2RiLeroIZgBd2Vw+SAqAuw1CDbh
         9z9PODyjjikpab4xAgAafTjxrxsevI9994DAUMEDqHtV6tcnAoQuoK/HFOOEUl334JPZ
         RoQeCMjHtcXOFXccZba3gxtfboNWXvMqxJa5nO8VBF8Z4QhHIoPoqMo+oNXfm8FDHu/x
         wrLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=3xKZDPiIp0UXSCsg+EjEsa1zosZu3C38o7agh9DzMN8=;
        b=TO+fzyyLLZPAHcIz9VEvKmtFt/FxkNQAVBwhOjKBibyVzyDb+K7geu/iZkCN1+oLfy
         YLlB46fKLsy8vgRfxZ97Je2UJYvxJs99/zvKllokkYBP2IqfBDEWj46+NHLT9hMRP7qo
         vlZAFpDztl0Qdk0HdMx8ATQen9hMXenWkAKJ6SzF7HA3/aHraQeQAsqG0kXzLf2r50Ba
         /Yd+z0tNKiUQ91oZuOjNpEhBZ5po4BraGVJ+fhDOl+chfdF9n0ttRZexvKc3b1ej5HGs
         ThcipXhgwk2SrJGKVuvLeH8Mv9cLni6mTMJqF2G3UoGMwlrEzgUokz4o8UJvU4tHDIDP
         IyBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id ge24-20020a17090b0e1800b001bf6ac2c31bsi180077pjb.1.2022.03.09.17.43.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 09 Mar 2022 17:43:59 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from kwepemi500013.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4KDWyy1n01zfYqd;
	Thu, 10 Mar 2022 09:42:34 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi500013.china.huawei.com (7.221.188.120) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Thu, 10 Mar 2022 09:43:57 +0800
Received: from [10.174.179.19] (10.174.179.19) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Thu, 10 Mar 2022 09:43:56 +0800
Message-ID: <385d153f-b3e7-5b2f-a1b1-e777d0b8fd2f@huawei.com>
Date: Thu, 10 Mar 2022 09:43:55 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.2
Subject: Re: [PATCH v3 2/2] kfence: Alloc kfence_pool after system startup
Content-Language: en-US
To: Tianchen Ding <dtcccc@linux.alibaba.com>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>
References: <20220307074516.6920-1-dtcccc@linux.alibaba.com>
 <20220307074516.6920-3-dtcccc@linux.alibaba.com>
From: "'liupeng (DM)' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20220307074516.6920-3-dtcccc@linux.alibaba.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.174.179.19]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-CFilter-Loop: Reflected
X-Original-Sender: liupeng256@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=liupeng256@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: "liupeng (DM)" <liupeng256@huawei.com>
Reply-To: "liupeng (DM)" <liupeng256@huawei.com>
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

On 2022/3/7 15:45, Tianchen Ding wrote:
> Allow enabling KFENCE after system startup by allocating its pool via the
> page allocator. This provides the flexibility to enable KFENCE even if it
> wasn't enabled at boot time.
>
> Signed-off-by: Tianchen Ding <dtcccc@linux.alibaba.com>
Tested-by: Peng Liu <liupeng256@huawei.com>
> ---
>   mm/kfence/core.c | 111 ++++++++++++++++++++++++++++++++++++++---------
>   1 file changed, 90 insertions(+), 21 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index caa4e84c8b79..f126b53b9b85 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -96,7 +96,7 @@ static unsigned long kfence_skip_covered_thresh __read_mostly = 75;
>   module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, ulong, 0644);
>   
>   /* The pool of pages used for guard pages and objects. */
> -char *__kfence_pool __ro_after_init;
> +char *__kfence_pool __read_mostly;
>   EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
>   
>   /*
> @@ -537,17 +537,19 @@ static void rcu_guarded_free(struct rcu_head *h)
>   	kfence_guarded_free((void *)meta->addr, meta, false);
>   }
>   
> -static bool __init kfence_init_pool(void)
> +/*
> + * Initialization of the KFENCE pool after its allocation.
> + * Returns 0 on success; otherwise returns the address up to
> + * which partial initialization succeeded.
> + */
> +static unsigned long kfence_init_pool(void)
>   {
>   	unsigned long addr = (unsigned long)__kfence_pool;
>   	struct page *pages;
>   	int i;
>   
> -	if (!__kfence_pool)
> -		return false;
> -
>   	if (!arch_kfence_init_pool())
> -		goto err;
> +		return addr;
>   
>   	pages = virt_to_page(addr);
>   
> @@ -565,7 +567,7 @@ static bool __init kfence_init_pool(void)
>   
>   		/* Verify we do not have a compound head page. */
>   		if (WARN_ON(compound_head(&pages[i]) != &pages[i]))
> -			goto err;
> +			return addr;
>   
>   		__SetPageSlab(&pages[i]);
>   	}
> @@ -578,7 +580,7 @@ static bool __init kfence_init_pool(void)
>   	 */
>   	for (i = 0; i < 2; i++) {
>   		if (unlikely(!kfence_protect(addr)))
> -			goto err;
> +			return addr;
>   
>   		addr += PAGE_SIZE;
>   	}
> @@ -595,7 +597,7 @@ static bool __init kfence_init_pool(void)
>   
>   		/* Protect the right redzone. */
>   		if (unlikely(!kfence_protect(addr + PAGE_SIZE)))
> -			goto err;
> +			return addr;
>   
>   		addr += 2 * PAGE_SIZE;
>   	}
> @@ -608,9 +610,21 @@ static bool __init kfence_init_pool(void)
>   	 */
>   	kmemleak_free(__kfence_pool);
>   
> -	return true;
> +	return 0;
> +}
> +
> +static bool __init kfence_init_pool_early(void)
> +{
> +	unsigned long addr;
> +
> +	if (!__kfence_pool)
> +		return false;
> +
> +	addr = kfence_init_pool();
> +
> +	if (!addr)
> +		return true;
>   
> -err:
>   	/*
>   	 * Only release unprotected pages, and do not try to go back and change
>   	 * page attributes due to risk of failing to do so as well. If changing
> @@ -623,6 +637,26 @@ static bool __init kfence_init_pool(void)
>   	return false;
>   }
>   
> +static bool kfence_init_pool_late(void)
> +{
> +	unsigned long addr, free_size;
> +
> +	addr = kfence_init_pool();
> +
> +	if (!addr)
> +		return true;
> +
> +	/* Same as above. */
> +	free_size = KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool);
> +#ifdef CONFIG_CONTIG_ALLOC
> +	free_contig_range(page_to_pfn(virt_to_page(addr)), free_size / PAGE_SIZE);
> +#else
> +	free_pages_exact((void *)addr, free_size);
> +#endif
> +	__kfence_pool = NULL;
> +	return false;
> +}
> +
>   /* === DebugFS Interface ==================================================== */
>   
>   static int stats_show(struct seq_file *seq, void *v)
> @@ -771,31 +805,66 @@ void __init kfence_alloc_pool(void)
>   		pr_err("failed to allocate pool\n");
>   }
>   
> +static void kfence_init_enable(void)
> +{
> +	if (!IS_ENABLED(CONFIG_KFENCE_STATIC_KEYS))
> +		static_branch_enable(&kfence_allocation_key);
> +	WRITE_ONCE(kfence_enabled, true);
> +	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
> +	pr_info("initialized - using %lu bytes for %d objects at 0x%p-0x%p\n", KFENCE_POOL_SIZE,
> +		CONFIG_KFENCE_NUM_OBJECTS, (void *)__kfence_pool,
> +		(void *)(__kfence_pool + KFENCE_POOL_SIZE));
> +}
> +
>   void __init kfence_init(void)
>   {
> +	stack_hash_seed = (u32)random_get_entropy();
> +
>   	/* Setting kfence_sample_interval to 0 on boot disables KFENCE. */
>   	if (!kfence_sample_interval)
>   		return;
>   
> -	stack_hash_seed = (u32)random_get_entropy();
> -	if (!kfence_init_pool()) {
> +	if (!kfence_init_pool_early()) {
>   		pr_err("%s failed\n", __func__);
>   		return;
>   	}
>   
> -	if (!IS_ENABLED(CONFIG_KFENCE_STATIC_KEYS))
> -		static_branch_enable(&kfence_allocation_key);
> -	WRITE_ONCE(kfence_enabled, true);
> -	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
> -	pr_info("initialized - using %lu bytes for %d objects at 0x%p-0x%p\n", KFENCE_POOL_SIZE,
> -		CONFIG_KFENCE_NUM_OBJECTS, (void *)__kfence_pool,
> -		(void *)(__kfence_pool + KFENCE_POOL_SIZE));
> +	kfence_init_enable();
> +}
> +
> +static int kfence_init_late(void)
> +{
> +	const unsigned long nr_pages = KFENCE_POOL_SIZE / PAGE_SIZE;
> +#ifdef CONFIG_CONTIG_ALLOC
> +	struct page *pages;
> +
> +	pages = alloc_contig_pages(nr_pages, GFP_KERNEL, first_online_node, NULL);
> +	if (!pages)
> +		return -ENOMEM;
> +	__kfence_pool = page_to_virt(pages);
> +#else
> +	if (nr_pages > MAX_ORDER_NR_PAGES) {
> +		pr_warn("KFENCE_NUM_OBJECTS too large for buddy allocator\n");
> +		return -EINVAL;
> +	}
> +	__kfence_pool = alloc_pages_exact(KFENCE_POOL_SIZE, GFP_KERNEL);
> +	if (!__kfence_pool)
> +		return -ENOMEM;
> +#endif
> +
> +	if (!kfence_init_pool_late()) {
> +		pr_err("%s failed\n", __func__);
> +		return -EBUSY;
> +	}
> +
> +	kfence_init_enable();
> +	return 0;
>   }
>   
>   static int kfence_enable_late(void)
>   {
>   	if (!__kfence_pool)
> -		return -EINVAL;
> +		return kfence_init_late();
>   
>   	WRITE_ONCE(kfence_enabled, true);
>   	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/385d153f-b3e7-5b2f-a1b1-e777d0b8fd2f%40huawei.com.
