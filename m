Return-Path: <kasan-dev+bncBCRKFI7J2AJRBVNYVKQAMGQE2VENANQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 56B0D6B3469
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Mar 2023 03:56:23 +0100 (CET)
Received: by mail-ua1-x93d.google.com with SMTP id c19-20020ab06ed3000000b0068b9f3e0a2dsf1643472uav.6
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 18:56:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678416982; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pe3ZmYh8rVOfDS3SRR4kthB2t8Ez96jDe+uTM3fudTe+4OvLUBB1s5kvU66gbDVfuu
         TCXSM5uo5YKdsbm4Lc/5VhyN4KSkb6BMJUoA91EkQ5Qn6Bp09x/fpLBLuDpJ7bA9kPVp
         At/3k6CPofSAMbwPVoz8h4Z8aqK2uDrm5HcEDIYMO0aYwt3BBcIBEqSf1fWT4kPnd3GW
         Mge/sgsZ3Jrt79Aj5yIz7f+opeUEo/JHSrUfhXgUzrZ+nUm1PBm4eHGPRr6cMEkSPXtg
         4I67rDe5h4QlKM3XCpu6oYCDsmza4Bl/M/SdIgC4EnS3+hrhy8FRKVOxWSYlCRXcfaX+
         CwZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=8JItxqG0xeUMKPZuqooB534qJrbpfYLozRSgRVESUzI=;
        b=B2lAKAjLYiETa0pP/fuHYGr5lAZrSsv6x7Snm7MOxrFslMXaX0WDcQuCbcJHuU4OrH
         pL6ZwJfzO8EB4eOrliyWKfV1FtsOiSE7K0EHlKvfZQYBVzO0sE2g+9mzQT7V/rr8Sff/
         AWbrPzD+kSed0iCiEBWaj6X/JV5mUCxauxKQ4CZ7/XVavXQwmU+WRAEA2pA7MhmGPucM
         WC1mLrJ7JJYnUVISgYEFDlZC43fmBgXEi76S23Fl0qLZSEM5vVKw3B8dDcN5Gc3k01On
         3A5EuDoInI9lc0aXfFoZKFo9yYxW/TP8WoEVD/xICEZAPrlURdwMfv4Jj80wWLdOGazT
         Bhfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678416982;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8JItxqG0xeUMKPZuqooB534qJrbpfYLozRSgRVESUzI=;
        b=P7VmaMOSDWP41MgOTPZG1cWOHF1Big+brIP9RKv123kSe16Yl7TN07ZVyNgHKm9Uz3
         00+l61oSHhUHtskPXTxR6BSg9cAP2euXKNZyIWgGYfYUrfuQ52MEkmcfbN2Njg4xss2S
         fd0+2H2RAAaGZYb02mLnIwyjsf3T0AQJCG7QQ+69JaKAaw6HHP/jPlDG07Y1x7NZHA4I
         OqZxxhAj+ExxkmMkBN6h9EFdPfGaQ5dPJwYeuA8AEQ26/ztGutrKZpj2nxIwYVNcqgkf
         T+2pD+ucUht5V5PsgDQVYoXSmpoM2QBEwf3g8Gi+yIigvc7UnKAuX5kAk0O/ctw077e2
         TtxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678416982;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:from:to:cc:subject
         :date:message-id:reply-to;
        bh=8JItxqG0xeUMKPZuqooB534qJrbpfYLozRSgRVESUzI=;
        b=FxnkmlhaXuySdl7vBFtkHOgPfbqVONlDYFFxB/p86+uSFm9wRTBizlPZv9lb5umTy+
         o2cUS78KqeWOGahAwBsmAXSlyCzE+dQ5rFjY4CCXtJYGEHHUnWbNZ4G7eEVIwstsgwpn
         HaKM2XxISJzi91zyT7z1rdP9KXyymsF74TjYB/7qq8nlL36bmqSNjH10s+PZ1A7deIxW
         /DkVZFPvrjMAvuiRLHiczoMg8YI/qa1oLE5oO1cxNJfyos6DwPjY6FtnQFIowXd1N5Jg
         Umyn9Pw5TrGZ//Xa/EZWxuEstTUy+FNGqo07c9zC5ii1qTjFonWxpf7mGZRNYyUDVHOd
         3+Gw==
X-Gm-Message-State: AO0yUKWzac26X6FpDJHKwdY4zyZRfJUb0IShrA8YEeX2AJYWoLymWYug
	ZF6zUDyILgX979n5Lq7H7Hw=
X-Google-Smtp-Source: AK7set9IiKJhfNVVmwygWwitNaGa6waNSiK0jwcoeff7avkMoOsi1tqEAxyNnTFq8Rk8tyHfUk7C/g==
X-Received: by 2002:a67:e3cb:0:b0:421:e25b:3d0c with SMTP id k11-20020a67e3cb000000b00421e25b3d0cmr10158033vsm.3.1678416982067;
        Thu, 09 Mar 2023 18:56:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:c48:b0:412:4ec9:7df6 with SMTP id
 y8-20020a0561020c4800b004124ec97df6ls1035869vss.8.-pod-prod-gmail; Thu, 09
 Mar 2023 18:56:21 -0800 (PST)
X-Received: by 2002:a05:6102:3414:b0:421:9052:1b82 with SMTP id p20-20020a056102341400b0042190521b82mr12563335vsi.0.1678416981350;
        Thu, 09 Mar 2023 18:56:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678416981; cv=none;
        d=google.com; s=arc-20160816;
        b=kfYOFH0/rQszZIFN/w/7bU4Dtleaa3sgcDkecnLtc0OSpWjela9PmqmnHTpIEskxeV
         Nzs1jBGJYqMxmGYo41SXLjyWE/duQA9Tz+7a6nOFyHjWSGqT6+H3pslRUXZLUfg9m6t7
         09rPECjWO8CjYn8q/nzwWv3ESI0Y5MOKsOPF5Fc0LstXYH+EFiT8SkNskvhDH1oivHYo
         oVgX83b83wPJR/wmdsZyULSU1v/PeFxTGJhCiv12rNBg4PdmQEloG3Y4yxxeyH2qn6VY
         Mm8JZwDp+TFqbVvnbKBb0MPPOScNTPieNralw5j/6r2hljwLYHQmjnXjGQuv0+1EB8s+
         DpQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=vT87YGgktJdj9T+D8+KT85q6n2CZqLFXzkUqqaM6JGU=;
        b=ba7MHtvoXNW3jNTSqfvvzYQQtmIQP2we315tqoJaMr9L76t1c7AfjPioRtpFO6jKG0
         SpF6n4QRZpbyzx/hjULEUrwdPAZMYypM7eI1rC3I2xHQ7Qc9m8WHdbUUQAvb2msGSx6u
         yLo2xOjhc91NHwKMI+lLcVYZZO1ypTewwEnVTH9UH2E3zUJ8VhuQ0wnCLKns0mKIu0OP
         WR9gRqG3wQd0batcz+qXoHgY5rZnSRUCcbbAsymD9x1aP+Z3dJa4iGs4YJdwfKpDritb
         XI8rs2pmT3Unbbeu956gyJLEkTwPTYqZEhaSgDaSBAc4yLFh78i8hLR3puZPFT/XD5Va
         3lYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id y22-20020ab020b6000000b00690829432ebsi29691ual.2.2023.03.09.18.56.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Mar 2023 18:56:21 -0800 (PST)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggpemm500001.china.huawei.com (unknown [172.30.72.57])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4PXrJd6bVgzrS7W;
	Fri, 10 Mar 2023 10:55:29 +0800 (CST)
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.21; Fri, 10 Mar 2023 10:56:17 +0800
Message-ID: <5251f2a0-95bf-3330-6524-ec5716cc3d29@huawei.com>
Date: Fri, 10 Mar 2023 10:56:16 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.1
Subject: Re: [PATCH v3] mm,kfence: decouple kfence from page granularity
 mapping judgement
Content-Language: en-US
To: Zhenhua Huang <quic_zhenhuah@quicinc.com>, <catalin.marinas@arm.com>,
	<will@kernel.org>, <glider@google.com>, <elver@google.com>,
	<dvyukov@google.com>, <akpm@linux-foundation.org>, <robin.murphy@arm.com>,
	<mark.rutland@arm.com>, <jianyong.wu@arm.com>, <james.morse@arm.com>
CC: <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>, <quic_guptap@quicinc.com>,
	<quic_tingweiz@quicinc.com>
References: <1678413750-6329-1-git-send-email-quic_zhenhuah@quicinc.com>
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <1678413750-6329-1-git-send-email-quic_zhenhuah@quicinc.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187
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


Hi Zhenhua,

On 2023/3/10 10:02, Zhenhua Huang wrote:
> Kfence only needs its pool to be mapped as page granularity, previous
> judgement was a bit over protected. Decouple it from judgement and do
> page granularity mapping for kfence pool only [1].
> 
> To implement this, also relocate the kfence pool allocation before the
> linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
> addr, __kfence_pool is to be set after linear mapping set up.
> 
We do the same way in our 5.10 kernel, a minor comment below,

> LINK: [1] https://lore.kernel.org/linux-arm-kernel/1675750519-1064-1-git-send-email-quic_zhenhuah@quicinc.com/T/
> Suggested-by: Mark Rutland <mark.rutland@arm.com>
> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
> ---
>   arch/arm64/mm/mmu.c      | 44 ++++++++++++++++++++++++++++++++++++++++++++
>   arch/arm64/mm/pageattr.c |  5 ++---
>   include/linux/kfence.h   |  8 ++++++++
>   mm/kfence/core.c         |  9 +++++++++
>   4 files changed, 63 insertions(+), 3 deletions(-)
> 
> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
> index 6f9d889..9f06a29e 100644
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
> @@ -525,6 +526,33 @@ static int __init enable_crash_mem_map(char *arg)
>   }
>   early_param("crashkernel", enable_crash_mem_map);
>   
> +#ifdef CONFIG_KFENCE
> +
> +static phys_addr_t arm64_kfence_alloc_pool(void)
> +{
> +	phys_addr_t kfence_pool = 0;

The kfence_pool is no need to be initialized.

> +
> +	if (!kfence_sample_interval)
> +		return (phys_addr_t)NULL;

And one more missing case, kfence support late int, see commit
b33f778bba5e ("kfence: alloc kfence_pool after system startup"),
this changes will break this feature, we add a new cmdline to alloc
kfence_pool regardless of kfence_sample_interval value, maybe there some
other way to deal with this issue.

> +
> +	kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
> +	if (!kfence_pool) {
> +		pr_err("failed to allocate kfence pool\n");
> +		return (phys_addr_t)NULL;

no need this return;

> +	}

> +
> +	return kfence_pool;
> +}
> +
> +#else
> +
> +static phys_addr_t arm64_kfence_alloc_pool(void)
> +{
> +	return (phys_addr_t)NULL;
> +}
> +
> +#endif
> +

I like all of '(phys_addr_t)NULL' to 0

>   static void __init map_mem(pgd_t *pgdp)
>   {
>   	static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
> @@ -532,6 +560,7 @@ static void __init map_mem(pgd_t *pgdp)
>   	phys_addr_t kernel_end = __pa_symbol(__init_begin);
>   	phys_addr_t start, end;
>   	int flags = NO_EXEC_MAPPINGS;
> +	phys_addr_t kfence_pool = 0;

it's no need to be initialized too.

>   	u64 i;
>   
>   	/*
> @@ -564,6 +593,10 @@ static void __init map_mem(pgd_t *pgdp)
>   	}
>   #endif
>   
> +	kfence_pool = arm64_kfence_alloc_pool();
> +	if (kfence_pool)
> +		memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
> +
>   	/* map all the memory banks */
>   	for_each_mem_range(i, &start, &end) {
>   		if (start >= end)
> @@ -608,6 +641,17 @@ static void __init map_mem(pgd_t *pgdp)
>   		}
>   	}
>   #endif
> +
> +	/* Kfence pool needs page-level mapping */
> +	if (kfence_pool) {
> +		__map_memblock(pgdp, kfence_pool,
> +			kfence_pool + KFENCE_POOL_SIZE,
> +			pgprot_tagged(PAGE_KERNEL),
> +			NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
> +		memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
> +		/* kfence_pool really mapped now */
> +		kfence_set_pool(kfence_pool);
> +	}
>   }
>   

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5251f2a0-95bf-3330-6524-ec5716cc3d29%40huawei.com.
