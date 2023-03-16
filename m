Return-Path: <kasan-dev+bncBDVL3PXJZILBBMXCZOQAMGQEDYRHBPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id A022C6BCCEF
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 11:36:35 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id l7-20020a0566022dc700b0074cc9aba965sf668152iow.11
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 03:36:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678962994; cv=pass;
        d=google.com; s=arc-20160816;
        b=CPkRD3xSV9NlaeKcSCa+6KME3ZqGyCvKJ6RssbSEy2gR1M7wP1Mj9YWcFYMmzpEHq7
         LttCOyZ9zUXC6Cut9Zpnfcwx9QswxHQHz7DgSA4WLNkYGrFkW6CRuJbLmT8sXWJxeceA
         Tp7oSfAleP/yErluOZCLbNdXBlprHaULY2s88XEJIGkANB9kt2XQVO/ZKOhQTX7rbRhq
         bFX5Yg2ElBNfqmOqUr9A6i9fp7Sr1njrW8WLWl9St9uQiBVwdBgsOWjOtPt1dExUhNpj
         X7OHTKPtRHEY296nWWkIPeBAlURWu3LzZNwRJm+Jtc7ABcmESqLM6Y64crMeCOeXmLQg
         SEGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=VHzevLehWUSq/DIo2Z9OgEMmURpUMAf1lb8dtaeBqmc=;
        b=KTYDLYlNUDlU81RUBySL/1fT2TllomjdGd+U8uugjmeI4ezf80nna1o0cF/ewqc16l
         S39VJLJnhcH4rk5iyKSuZMfqm3RRpjR7YGslMnFVxqvEfp5iuKSrHh8/KhCb1tOfHGaP
         dST4uuKlbrqNy2cfr9KDxSAQUKRrakaBfoZcTAEd7s5GYkeb/mED6qXe4jx8G30g0Mv+
         e2f+dKs5iv2vI5kgz0pUXmJdCZLBgG1HTryuoEy+O2yEVf+upihqGnmi6LQjbtnIxdXh
         WXbopUG26YGiM4jAjIu9AgJ8za9kiEtanGJIDqVWDVFIxwkYZIdC4EeGA63bpSfBVxkZ
         jK2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=c8dVDPTt;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678962994;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=VHzevLehWUSq/DIo2Z9OgEMmURpUMAf1lb8dtaeBqmc=;
        b=PrAWQxfE1sL4XatorKArs82E81vXAnbVTcbML28UhyNAu9WRVFb0DAywa7+HXsm5Qt
         EQL+NWm+cxYbjWOSrclfMJ1EOn7C1KStLvfVlXaMoCUTYCU9t99li4mDYJh3pewvwzN2
         mglxBQrxXJ6ecd7I0npa/FFgiX7DpWzfn4OupwwuEWnriavJJ0TVbVnSwMXKs9EPOb0G
         MZVYENr727g0b2YqrSChQ0Pr3YvVPf3MM7OSFKe+drN6UYQUDe3/O/HYZ6DJIqgZ4DoR
         T7mSl1aiMauVYqF7CsaaVl6OlN7mbc8K8rcoMswbXad3+T7T4K0HUKaZYQPKeC5EnKGL
         k9KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678962994;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VHzevLehWUSq/DIo2Z9OgEMmURpUMAf1lb8dtaeBqmc=;
        b=QR1GRGtNUm5dapgXsggcHfDSsqebS6F7XrPYjiu2NNtWZjH4SnxceNFbgpnSpNS2p/
         a+2V7qR/wdGaxhCDZJIKt08J4m+CObTtkAFxBxP0ElExXfRBcrpcPFiXwAHWMcKI8vCO
         GnV2B2Dgao5LgH0ik5QL8n+JCVGJiPhSOMaerkDpk+PHXP/yR5K9APbju9PMUPMzL/ee
         I+5L1kHxFufOCoWgVIPPuzp/IsXY7CSFsJS6eUsCkVKihmZ/4RllUGHQ9xqln50Fq/lP
         VJXc/xzMafoQ/fMOM/rs0TSr7aTTxZwhoukIf1BTY4BF+MV2YY13ZVsdo9EYTmtdy/75
         1ljg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKX3ctRB8stKSDjG3FLQr+8mxh3M9k9yPYSinjtL17Sr2PNEMlOF
	Ex+jndWiwYaCF4aAKAIVB5Q=
X-Google-Smtp-Source: AK7set9yHjrdgxZmcZhaTqLjp7WFoNyAD0vOBbyyrn5PDb8FwQEJanDeNApxcOuoB8zHIg3MKBC6Uw==
X-Received: by 2002:a02:a98f:0:b0:3b7:9d19:fec7 with SMTP id q15-20020a02a98f000000b003b79d19fec7mr20453808jam.0.1678962994131;
        Thu, 16 Mar 2023 03:36:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:358a:b0:752:e91b:7425 with SMTP id
 bi10-20020a056602358a00b00752e91b7425ls148625iob.9.-pod-prod-gmail; Thu, 16
 Mar 2023 03:36:33 -0700 (PDT)
X-Received: by 2002:a6b:6802:0:b0:712:cf90:e3e with SMTP id d2-20020a6b6802000000b00712cf900e3emr18731833ioc.2.1678962993513;
        Thu, 16 Mar 2023 03:36:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678962993; cv=none;
        d=google.com; s=arc-20160816;
        b=mSEyOTA5HJsi4bYMHlwFgQJUAGRIeUt+3xmT1pKZPA6BcawImzcMDwbEbWjtiQbARB
         1j8Kwh4PpkgVbN6+t2yYVUL1WEJh4Yt5OA7Mp7hwMILN282CcJ+86EUhYlXYG2hu0H+w
         yir1E3SRWB5DQEolhLSobN5O9K+fIQQgKS+ryskIZPPQyLHC3i7yuNuP79aLqIZX+Ee2
         u0Ca04+jFL5WozruY1t8OFBvkJmccGAJymVROVxWkUPTH/CkkDyQJ8mw/yJ+yKG8dkPG
         WTqJfWniEPyEdc4Woj1dxJGsWYe7Wwwe5l6UQgLrlWei7lle8tiVVi/40RnsReUSUdMK
         8Cag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=OSD3n1LVf/WQIYSIYg5Y9H48EDmpFGFOUTMFpzi7BcA=;
        b=0fwBVTx06ZT1J3c0YiOQTD/UNuY5QfiXG2Q4cLJ8K1XgkdOFfqXh2RvpiQc2ZzzXJf
         j1txQuYIxIgvtw/hClZ/cs+6AjXcVxdrDfNFFQlmtf/Nnk2/tZoTm6H8qNKuXw/pPZKS
         gNY9ERxZZ9W26M/1Mfz1cCY1fx0128DYJaCvrHtQXzoIpfkiNIgi0HJlYGdak9JgZR7o
         IOlnIZVm1vwg0bTAobhmIYm94a02VdVZKILPrIJboyMXLXHIZHMi5zrFyzXGxeLfiav9
         WSQBf06GIlHzD9ZvADUkmZZK4xSBA5+1xO9jL/5zoILpalGXtBaU/DAQO02SXY6hfNSS
         w8nw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=c8dVDPTt;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id bx1-20020a056602418100b0074c8a51ed45si369361iob.2.2023.03.16.03.36.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Mar 2023 03:36:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279866.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32G25xQX030577;
	Thu, 16 Mar 2023 10:36:27 GMT
Received: from nalasppmta03.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3pbpxjsj36-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Mar 2023 10:36:27 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA03.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32GAaQQK011261
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Mar 2023 10:36:26 GMT
Received: from [10.239.132.245] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Thu, 16 Mar
 2023 03:36:21 -0700
Message-ID: <b47a9bc3-f9d7-77a6-c8d0-977e47f65f4a@quicinc.com>
Date: Thu, 16 Mar 2023 18:36:19 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.8.0
Subject: Re: [PATCH v9] mm,kfence: decouple kfence from page granularity
 mapping judgement
Content-Language: en-US
To: Marco Elver <elver@google.com>
CC: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <wangkefeng.wang@huawei.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
References: <1678956620-26103-1-git-send-email-quic_zhenhuah@quicinc.com>
 <ZBLqOv2RTScbydrj@elver.google.com>
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <ZBLqOv2RTScbydrj@elver.google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: SPekO0UiqqbVHqJS-M-gNBCLLO77nrI0
X-Proofpoint-ORIG-GUID: SPekO0UiqqbVHqJS-M-gNBCLLO77nrI0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-16_07,2023-03-16_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0
 priorityscore=1501 phishscore=0 malwarescore=0 lowpriorityscore=0
 adultscore=0 impostorscore=0 mlxscore=0 bulkscore=0 clxscore=1015
 mlxlogscore=999 suspectscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2303150002 definitions=main-2303160089
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=c8dVDPTt;       spf=pass
 (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131
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



On 2023/3/16 18:06, Marco Elver wrote:
> On Thu, Mar 16, 2023 at 04:50PM +0800, Zhenhua Huang wrote:
>> Kfence only needs its pool to be mapped as page granularity, if it is
>> inited early. Previous judgement was a bit over protected. From [1], Mark
>> suggested to "just map the KFENCE region a page granularity". So I
>> decouple it from judgement and do page granularity mapping for kfence
>> pool only. Need to be noticed that late init of kfence pool still requires
>> page granularity mapping.
>>
>> Page granularity mapping in theory cost more(2M per 1GB) memory on arm64
>> platform. Like what I've tested on QEMU(emulated 1GB RAM) with
>> gki_defconfig, also turning off rodata protection:
>> Before:
>> [root@liebao ]# cat /proc/meminfo
>> MemTotal:         999484 kB
>> After:
>> [root@liebao ]# cat /proc/meminfo
>> MemTotal:        1001480 kB
>>
>> To implement this, also relocate the kfence pool allocation before the
>> linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
>> addr, __kfence_pool is to be set after linear mapping set up.
>>
>> LINK: [1] https://lore.kernel.org/linux-arm-kernel/Y+IsdrvDNILA59UN@FVFF77S0Q05N/
>> Suggested-by: Mark Rutland <mark.rutland@arm.com>
>> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
>> ---
>>   arch/arm64/include/asm/kfence.h | 16 +++++++++++
>>   arch/arm64/mm/mmu.c             | 59 +++++++++++++++++++++++++++++++++++++++++
>>   arch/arm64/mm/pageattr.c        |  9 +++++--
>>   include/linux/kfence.h          |  1 +
>>   mm/kfence/core.c                |  4 +++
>>   5 files changed, 87 insertions(+), 2 deletions(-)
>>
>> diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
>> index aa855c6..8143c91 100644
>> --- a/arch/arm64/include/asm/kfence.h
>> +++ b/arch/arm64/include/asm/kfence.h
>> @@ -10,6 +10,22 @@
>>   
>>   #include <asm/set_memory.h>
>>   
>> +extern phys_addr_t early_kfence_pool;
> 
> This should not be accessible if !CONFIG_KFENCE.
> 
>> +#ifdef CONFIG_KFENCE
>> +
>> +extern char *__kfence_pool;
>> +static inline void kfence_set_pool(phys_addr_t addr)
>> +{
>> +	__kfence_pool = phys_to_virt(addr);
>> +}
> 
> kfence_set_pool() is redundant if it's for arm64 only, because we know
> where it's needed, and there you could just access __kfence_pool
> directly. So let's just remove this function. (Initially I thought you
> want to provide it generally, also for other architectures.)
> 
>> +#else
>> +
>> +static inline void kfence_set_pool(phys_addr_t addr) { }
>> +
>> +#endif
>> +
>>   static inline bool arch_kfence_init_pool(void) { return true; }
> [...]
>> +#endif
>> +
>> +phys_addr_t early_kfence_pool;
> 
> This variable now exists in non-KFENCE builds, which is wrong.
> 
>>   static void __init map_mem(pgd_t *pgdp)
>>   {
>>   	static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
>> @@ -543,6 +587,10 @@ static void __init map_mem(pgd_t *pgdp)
>>   	 */
>>   	BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
>>   
>> +	early_kfence_pool = arm64_kfence_alloc_pool();
>> +	if (early_kfence_pool)
>> +		memblock_mark_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
>> +
>>   	if (can_set_direct_map())
>>   		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
>>   
>> @@ -608,6 +656,17 @@ static void __init map_mem(pgd_t *pgdp)
>>   		}
>>   	}
>>   #endif
>> +
>> +	/* Kfence pool needs page-level mapping */
>> +	if (early_kfence_pool) {
>> +		__map_memblock(pgdp, early_kfence_pool,
>> +			early_kfence_pool + KFENCE_POOL_SIZE,
>> +			pgprot_tagged(PAGE_KERNEL),
>> +			NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
>> +		memblock_clear_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
>> +		/* kfence_pool really mapped now */
>> +		kfence_set_pool(early_kfence_pool);
>> +	}
> 
> This whole piece of code could also be wrapped in another function,
> which becomes a no-op if !CONFIG_KFENCE. Then you also don't need to
> provide the KFENCE_POOL_SIZE define for 0 if !CONFIG_KFENCE.
> 
> [...]
>> +	 *
>> +	 * Kfence pool requires page granularity mapping also if we init it
>> +	 * late.
>>   	 */
>>   	return (rodata_enabled && rodata_full) || debug_pagealloc_enabled() ||
>> -		IS_ENABLED(CONFIG_KFENCE);
>> +	    (IS_ENABLED(CONFIG_KFENCE) && !early_kfence_pool);
> 
> Accessing a non-existent variable if !CONFIG_KFENCE works because the
> compiler optimizes out the access, but is generally bad style.

Hi Marco,

Actually my previous intention is not to do separation between KFENCE 
and non-KFENCE, instead to ensure early_kfence_pool always to be NULL in 
non-KFENCE build. That works well from my side w/ and w/o 
CONFIG_KFENCE.. but Yes that not clear to have this variable still in 
non-Kfence build.

Sure, I will follow your suggestion below and tested on my side. Thanks.

Thanks,
Zhenhua

> 
> 
> I think the only issue that I have is that the separation between KFENCE
> and non-KFENCE builds is not great.
> 
> At the end of the email are is a diff against your patch which would be
> my suggested changes (while at it, I fixed up a bunch of other issues).
> Untested, so if you decide to adopt these changes, please test.
> 
> Thanks,
> -- Marco
> 
> ------ >8 ------
> 
> 
> diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
> index 8143c91854e1..a81937fae9f6 100644
> --- a/arch/arm64/include/asm/kfence.h
> +++ b/arch/arm64/include/asm/kfence.h
> @@ -10,22 +10,6 @@
>   
>   #include <asm/set_memory.h>
>   
> -extern phys_addr_t early_kfence_pool;
> -
> -#ifdef CONFIG_KFENCE
> -
> -extern char *__kfence_pool;
> -static inline void kfence_set_pool(phys_addr_t addr)
> -{
> -	__kfence_pool = phys_to_virt(addr);
> -}
> -
> -#else
> -
> -static inline void kfence_set_pool(phys_addr_t addr) { }
> -
> -#endif
> -
>   static inline bool arch_kfence_init_pool(void) { return true; }
>   
>   static inline bool kfence_protect_page(unsigned long addr, bool protect)
> @@ -35,4 +19,14 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
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
> index 61944c7091f0..683958616ac1 100644
> --- a/arch/arm64/mm/mmu.c
> +++ b/arch/arm64/mm/mmu.c
> @@ -528,17 +528,14 @@ static int __init enable_crash_mem_map(char *arg)
>   early_param("crashkernel", enable_crash_mem_map);
>   
>   #ifdef CONFIG_KFENCE
> +bool kfence_early_init = !!CONFIG_KFENCE_SAMPLE_INTERVAL;
>   
> -static bool kfence_early_init __initdata = !!CONFIG_KFENCE_SAMPLE_INTERVAL;
> -/*
> - * early_param can be parsed before linear mapping
> - * set up
> - */
> -static int __init parse_kfence_early_init(char *p)
> +/* early_param() will be parsed before map_mem() below. */
> +static int __init parse_kfence_early_init(char *arg)
>   {
>   	int val;
>   
> -	if (get_option(&p, &val))
> +	if (get_option(&arg, &val))
>   		kfence_early_init = !!val;
>   	return 0;
>   }
> @@ -552,22 +549,34 @@ static phys_addr_t arm64_kfence_alloc_pool(void)
>   		return 0;
>   
>   	kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
> -	if (!kfence_pool)
> +	if (!kfence_pool) {
>   		pr_err("failed to allocate kfence pool\n");
> +		kfence_early_init = false;
> +		return 0;
> +	}
> +
> +	/* Temporarily mark as NOMAP. */
> +	memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
>   
>   	return kfence_pool;
>   }
>   
> -#else
> -
> -static phys_addr_t arm64_kfence_alloc_pool(void)
> +static void arm64_kfence_map_pool(phys_addr_t kfence_pool, pgd_t *pgdp)
>   {
> -	return 0;
> -}
> -
> -#endif
> +	if (!kfence_pool)
> +		return;
>   
> -phys_addr_t early_kfence_pool;
> +	/* KFENCE pool needs page-level mapping. */
> +	__map_memblock(pgdp, kfence_pool, kfence_pool + KFENCE_POOL_SIZE,
> +		       pgprot_tagged(PAGE_KERNEL),
> +		       NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
> +	memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
> +	__kfence_pool = phys_to_virt(kfence_pool);
> +}
> +#else /* CONFIG_KFENCE */
> +static inline phys_addr_t arm64_kfence_alloc_pool(void) { return 0; }
> +static inline void arm64_kfence_map_pool(phys_addr_t kfence_pool, pgd_t *pgdp) { }
> +#endif /* CONFIG_KFENCE */
>   
>   static void __init map_mem(pgd_t *pgdp)
>   {
> @@ -575,6 +584,7 @@ static void __init map_mem(pgd_t *pgdp)
>   	phys_addr_t kernel_start = __pa_symbol(_stext);
>   	phys_addr_t kernel_end = __pa_symbol(__init_begin);
>   	phys_addr_t start, end;
> +	phys_addr_t early_kfence_pool;
>   	int flags = NO_EXEC_MAPPINGS;
>   	u64 i;
>   
> @@ -588,8 +598,6 @@ static void __init map_mem(pgd_t *pgdp)
>   	BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
>   
>   	early_kfence_pool = arm64_kfence_alloc_pool();
> -	if (early_kfence_pool)
> -		memblock_mark_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
>   
>   	if (can_set_direct_map())
>   		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
> @@ -656,17 +664,7 @@ static void __init map_mem(pgd_t *pgdp)
>   		}
>   	}
>   #endif
> -
> -	/* Kfence pool needs page-level mapping */
> -	if (early_kfence_pool) {
> -		__map_memblock(pgdp, early_kfence_pool,
> -			early_kfence_pool + KFENCE_POOL_SIZE,
> -			pgprot_tagged(PAGE_KERNEL),
> -			NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
> -		memblock_clear_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
> -		/* kfence_pool really mapped now */
> -		kfence_set_pool(early_kfence_pool);
> -	}
> +	arm64_kfence_map_pool(early_kfence_pool, pgdp);
>   }
>   
>   void mark_rodata_ro(void)
> diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
> index 7ce5295cc6fb..aa8fd12cc96f 100644
> --- a/arch/arm64/mm/pageattr.c
> +++ b/arch/arm64/mm/pageattr.c
> @@ -7,7 +7,6 @@
>   #include <linux/module.h>
>   #include <linux/sched.h>
>   #include <linux/vmalloc.h>
> -#include <linux/kfence.h>
>   
>   #include <asm/cacheflush.h>
>   #include <asm/set_memory.h>
> @@ -28,11 +27,10 @@ bool can_set_direct_map(void)
>   	 * mapped at page granularity, so that it is possible to
>   	 * protect/unprotect single pages.
>   	 *
> -	 * Kfence pool requires page granularity mapping also if we init it
> -	 * late.
> +	 * KFENCE pool requires page-granular mapping if initialized late.
>   	 */
>   	return (rodata_enabled && rodata_full) || debug_pagealloc_enabled() ||
> -	    (IS_ENABLED(CONFIG_KFENCE) && !early_kfence_pool);
> +	       arm64_kfence_can_set_direct_map();
>   }
>   
>   static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 91cbcc98e293..726857a4b680 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -222,7 +222,6 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
>   
>   #else /* CONFIG_KFENCE */
>   
> -#define KFENCE_POOL_SIZE 0
>   static inline bool is_kfence_address(const void *addr) { return false; }
>   static inline void kfence_alloc_pool(void) { }
>   static inline void kfence_init(void) { }
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index fab087d39633..e7f22af5e710 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -818,7 +818,7 @@ void __init kfence_alloc_pool(void)
>   	if (!kfence_sample_interval)
>   		return;
>   
> -	/* if the pool has already been initialized by arch, skip the below */
> +	/* If the pool has already been initialized by arch, skip the below. */
>   	if (__kfence_pool)
>   		return;
>   

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b47a9bc3-f9d7-77a6-c8d0-977e47f65f4a%40quicinc.com.
