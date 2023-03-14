Return-Path: <kasan-dev+bncBDVL3PXJZILBBMVLYCQAMGQEDYWO6CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 726A36B8B48
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 07:35:32 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id l19-20020a056a0016d300b006257255adb4sf234583pfc.13
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 23:35:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678775731; cv=pass;
        d=google.com; s=arc-20160816;
        b=xW6EnsUVseorZnMdL7ZI9hrk5X7H795zOzeCZurhzLxylaljIpfteLO5HnTe2wL41t
         t9wwZiuFXciOr3DA6XPFvwXeC09lJpOF2QyMOt6j/ryuL9pcpY40dFn62p94CVbW2eTI
         pwRJehDBnTdFGKDU/PkvCpHtNZO09gcEhL2LF698jgeBCY5cZ+KrsdnC5kbfBpra0a5B
         O2ZisO1mG41KBat7DuW1wWA3tpg+Jn95nuqSCBk4cEs+iO/j4ixGn7kFzob2Tj7wA3qo
         Zm/oSp+r8jLLNaHF9KD5WFEsFgXcdWgXH8cp/nE2Ps0yIfW7uNu6tIfnZmUgIx4OoAup
         AdXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=SP/db48EPkStyAsUdkHD4HoC677tsJmvJiDIElOBEgM=;
        b=y0Y+UyGrZ/W5MeChODHarYVzCXsWj9zBamKKFtcebf8Fn/WNyJ/RmqEWRYvBOrIIRr
         Rq0x8s0ZH0VANQVJKVY/RDttgZstotqUWPBh0AKB2aEhclSbCMtr6Me9H1XuMXIOStEY
         4hLf1eOOd54CAfZW7u24B7slERBTn/LfSz0DUzUNzxisx2gZaZgxlKy/5OLcjD1CD/Lj
         utEINBpRiOlEuBelStFUr6JP41POn8foKUBh76eCrS1GPxg59EO3U9KTREM+uUyJOoG1
         kQxGRmpf3a3xv99MsB77dtdDqrZ/oxFFycuxglwHQ65xOWT6n+7JFLqh0p9QLnSTUyzx
         ulrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=VrsN7ytU;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678775731;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SP/db48EPkStyAsUdkHD4HoC677tsJmvJiDIElOBEgM=;
        b=lB8TCsMq++/JVHBXkGRpbOGdrF48Q+dwmiOYT8g9rXyiSXQukP9eRs/SW7IeazVjw8
         GWltTUc+Ah/c4RRGPnVhbbsUUxHUwUKpiVjDLhcyXMCl4Y/aBW1+X3JEkdFsgvmBSN0+
         eNsjjkj2t5n7OtrsBXOQmEuYovHd17H+Y6JU8MJ4AzSGb6RGqBVK2vh4ymBtlM9eeS5u
         ZFr6SJ8Lxv1t9tnv1omtsqBFEVJI6g9stq6+QpbDfY0sN4wtjLnCitzTNVgmqeQok8W8
         AlfOQO7bYHMZVu4uZqhHQXdO4lNcLjCQeL9sVfQ+uaogru61IC9h3Lmv+S5aW8CrfyHp
         jFXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678775731;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SP/db48EPkStyAsUdkHD4HoC677tsJmvJiDIElOBEgM=;
        b=1YnsZmxrQ8jxcF7km6LJ9M3GPzZyyTOzr0GxXAd4kXyz+E4NSzPI22WzFaWmFFV1Ls
         yeu9kfkaSxl6amBGVzooog7g6uFHDmc6Alb5UQdbfkpsWUhwrLUZFrkJR4h14GIh5M3Z
         FxK5b0Y7j0BSZQ308F2w/jwLBt5t/q228nlNbS1WveT3I4qbooWE14JlfYfJ6VSs8i8Y
         Y2l2bMO2EoTordg2v3F+rVpzZAEfJKeewiNu7c5crpmGx0PSzVIOvVsHFiGUJefG0gjB
         HHBR6vn4edhJBiUWXrCBAYJCiZz3GmEGUylgq7lSANN+7JaPt08KWJYoIVQ/CJ5sGaqN
         1F9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKV5w5bIugWUZfmVvoxwlylSt9BNcgYfIFFynZ0EkUA9VVDzSzZs
	XiQCsiHSyEdU4iSORP3rZrg=
X-Google-Smtp-Source: AK7set8esvBA2O/GpFokBTkONDihCU43dW2JZtUO6O4ZlUsp1K/Z7b7c1uq0qP/zxm03o4iN3a2IyA==
X-Received: by 2002:a17:90a:1c02:b0:234:bed1:1012 with SMTP id s2-20020a17090a1c0200b00234bed11012mr13077656pjs.6.1678775730819;
        Mon, 13 Mar 2023 23:35:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e546:b0:1a0:482d:27cc with SMTP id
 n6-20020a170902e54600b001a0482d27ccls5365967plf.3.-pod-prod-gmail; Mon, 13
 Mar 2023 23:35:30 -0700 (PDT)
X-Received: by 2002:a17:903:2283:b0:1a0:6a14:58d with SMTP id b3-20020a170903228300b001a06a14058dmr1030014plh.65.1678775730096;
        Mon, 13 Mar 2023 23:35:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678775730; cv=none;
        d=google.com; s=arc-20160816;
        b=jfKOR/fEovSxaT0rdOuUjmLfrA3vTO96JNAciw6ybs92LGCU64pXu05kZwnagP3sze
         xNddkfMUPita1vTGqVf2VzDdWEpO6xQkdRhLVefIo+vFkjIsYmvNl8NS6J00weol7Wc0
         P2yHgyrsHMqy2GzV7q1juEp/5/iOyep4HXOm/B4040OrHnp0uUfDdY1AbjDVpIH/15ES
         dLSJJcfzdRjPzrGHyfXMeUPs5a959S42fpSFPf8KnlgL1/P8cvpCVRKN8F+nq1wl2aXG
         3XBqD943BgVist6BmhQV5Hnb6uHOZXeinJpksXQuRdhUKYy6D8t8RJSa3rGJkHqAzS0M
         qX6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=ROJMYYbxq9FJwbyRIIIbMG/dzRppxAUMWepU8mV5Dgk=;
        b=ajttngcFU3gISoj2yMkDkakO0DNwAKxEJKlICS6/+T1dRGi6VGfodIVjnV5eypw0Rz
         z627JGflhVcOclFXfRQ9qmJfg+NBesN3tb2b62oVIORXkvZhb77KcJISoWGqLMMnUVdt
         CJg6wd3P/K+Tkd9R/p0MPR0bkzsSVxWZW8YaxpxaHQnod62WDSzvHnLaAK9bcj1Okmr8
         igeuY9fPFkwRXzkyRBWP7EG89zhIfeiLsIomcLkbiOEcEt29oa4qjQSNlXtIBH4IutcO
         DX0s+YfwisbPPktYmm6hF4o6Jc9n80ZNwo+Z3tFaA1/E2fCDzVTltA74kUSHjDdpFCsI
         QuDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=VrsN7ytU;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id p1-20020a170902ebc100b001a053f33764si78564plg.11.2023.03.13.23.35.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Mar 2023 23:35:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279868.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32E3YkaK032233;
	Tue, 14 Mar 2023 06:35:24 GMT
Received: from nalasppmta03.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3pa9gfhgbf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Mar 2023 06:35:24 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA03.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32E6ZNoS012097
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Mar 2023 06:35:23 GMT
Received: from [10.239.132.245] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Mon, 13 Mar
 2023 23:35:18 -0700
Message-ID: <8c032dab-bb59-f212-7fe3-8a069fa8dc69@quicinc.com>
Date: Tue, 14 Mar 2023 14:35:15 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.8.0
Subject: Re: [PATCH v7] mm,kfence: decouple kfence from page granularity
 mapping judgement
Content-Language: en-US
To: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <elver@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <wangkefeng.wang@huawei.com>
CC: <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
References: <1678771586-13332-1-git-send-email-quic_zhenhuah@quicinc.com>
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <1678771586-13332-1-git-send-email-quic_zhenhuah@quicinc.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: Mf0eLHx-FtTmVmKdhmxguNGAIgQ7z5T1
X-Proofpoint-ORIG-GUID: Mf0eLHx-FtTmVmKdhmxguNGAIgQ7z5T1
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-13_13,2023-03-14_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 mlxscore=0
 mlxlogscore=999 suspectscore=0 adultscore=0 clxscore=1015 phishscore=0
 bulkscore=0 spamscore=0 impostorscore=0 priorityscore=1501
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2303140057
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=VrsN7ytU;       spf=pass
 (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131
 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
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



On 2023/3/14 13:26, Zhenhua Huang wrote:
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
> LINK: [1] https://lore.kernel.org/linux-arm-kernel/Y+IsdrvDNILA59UN@FVFF77S0Q05N/
> Suggested-by: Mark Rutland <mark.rutland@arm.com>
> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
> ---
>   arch/arm64/mm/mmu.c      | 43 +++++++++++++++++++++++++++++++++++++++++++
>   arch/arm64/mm/pageattr.c |  8 ++++++--
>   include/linux/kfence.h   | 11 +++++++++++
>   mm/kfence/core.c         |  9 +++++++++
>   4 files changed, 69 insertions(+), 2 deletions(-)
> 
> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
> index 6f9d889..7f34206 100644
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
> +	phys_addr_t kfence_pool;
> +
> +	if (!kfence_sample_interval)
> +		return 0;
> +
> +	kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
> +	if (!kfence_pool)
> +		pr_err("failed to allocate kfence pool\n");
> +
> +	return kfence_pool;
> +}
> +
> +#else
> +
> +static phys_addr_t arm64_kfence_alloc_pool(void)
> +{
> +	return 0;
> +}
> +
> +#endif
> +
> +phys_addr_t early_kfence_pool;

I suddenly realized it would break other arch as only defined under 
arm64, let me relocate the declaration to arm64 headers as well. Sorry 
for inconvenience.

> +
>   static void __init map_mem(pgd_t *pgdp)
>   {
>   	static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
> @@ -543,6 +571,10 @@ static void __init map_mem(pgd_t *pgdp)
>   	 */
>   	BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
>   
> +	early_kfence_pool = arm64_kfence_alloc_pool();
> +	if (early_kfence_pool)
> +		memblock_mark_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
> +
>   	if (can_set_direct_map())
>   		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
>   
> @@ -608,6 +640,17 @@ static void __init map_mem(pgd_t *pgdp)
>   		}
>   	}
>   #endif
> +
> +	/* Kfence pool needs page-level mapping */
> +	if (early_kfence_pool) {
> +		__map_memblock(pgdp, early_kfence_pool,
> +			early_kfence_pool + KFENCE_POOL_SIZE,
> +			pgprot_tagged(PAGE_KERNEL),
> +			NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
> +		memblock_clear_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
> +		/* kfence_pool really mapped now */
> +		kfence_set_pool(early_kfence_pool);
> +	}
>   }
>   
>   void mark_rodata_ro(void)
> diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
> index 79dd201..83f57d2 100644
> --- a/arch/arm64/mm/pageattr.c
> +++ b/arch/arm64/mm/pageattr.c
> @@ -7,6 +7,7 @@
>   #include <linux/module.h>
>   #include <linux/sched.h>
>   #include <linux/vmalloc.h>
> +#include <linux/kfence.h>
>   
>   #include <asm/cacheflush.h>
>   #include <asm/set_memory.h>
> @@ -22,12 +23,15 @@ bool rodata_full __ro_after_init = IS_ENABLED(CONFIG_RODATA_FULL_DEFAULT_ENABLED
>   bool can_set_direct_map(void)
>   {
>   	/*
> -	 * rodata_full, DEBUG_PAGEALLOC and KFENCE require linear map to be
> +	 * rodata_full and DEBUG_PAGEALLOC require linear map to be
>   	 * mapped at page granularity, so that it is possible to
>   	 * protect/unprotect single pages.
> +	 *
> +	 * Kfence pool requires page granularity mapping also if we init it
> +	 * late.
>   	 */
>   	return (rodata_enabled && rodata_full) || debug_pagealloc_enabled() ||
> -		IS_ENABLED(CONFIG_KFENCE);
> +	    (IS_ENABLED(CONFIG_KFENCE) && !early_kfence_pool);
>   }
>   
>   static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 726857a..f1330b6 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -18,6 +18,7 @@
>   #include <linux/static_key.h>
>   
>   extern unsigned long kfence_sample_interval;
> +extern phys_addr_t early_kfence_pool;
>   
>   /*
>    * We allocate an even number of pages, as it simplifies calculations to map
> @@ -64,6 +65,12 @@ static __always_inline bool is_kfence_address(const void *addr)
>   void __init kfence_alloc_pool(void);
>   
>   /**
> + * kfence_set_pool() - allows an arch to set the
> + * KFENCE pool during early init
> + */
> +void __init kfence_set_pool(phys_addr_t addr);
> +
> +/**
>    * kfence_init() - perform KFENCE initialization at boot time
>    *
>    * Requires that kfence_alloc_pool() was called before. This sets up the
> @@ -222,8 +229,12 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
>   
>   #else /* CONFIG_KFENCE */
>   
> +extern phys_addr_t early_kfence_pool;
> +
> +#define KFENCE_POOL_SIZE 0
>   static inline bool is_kfence_address(const void *addr) { return false; }
>   static inline void kfence_alloc_pool(void) { }
> +static inline void kfence_set_pool(phys_addr_t addr) { }
>   static inline void kfence_init(void) { }
>   static inline void kfence_shutdown_cache(struct kmem_cache *s) { }
>   static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 5349c37..0765395 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -814,12 +814,21 @@ void __init kfence_alloc_pool(void)
>   	if (!kfence_sample_interval)
>   		return;
>   
> +	/* if the pool has already been initialized by arch, skip the below */
> +	if (__kfence_pool)
> +		return;
> +
>   	__kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
>   
>   	if (!__kfence_pool)
>   		pr_err("failed to allocate pool\n");
>   }
>   
> +void __init kfence_set_pool(phys_addr_t addr)
> +{
> +	__kfence_pool = phys_to_virt(addr);
> +}
> +
>   static void kfence_init_enable(void)
>   {
>   	if (!IS_ENABLED(CONFIG_KFENCE_STATIC_KEYS))

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8c032dab-bb59-f212-7fe3-8a069fa8dc69%40quicinc.com.
