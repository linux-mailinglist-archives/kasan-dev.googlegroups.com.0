Return-Path: <kasan-dev+bncBDVL3PXJZILBBHHGZOQAMGQETGAXFZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 190856BCD13
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 11:44:46 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id j7-20020a17090aeb0700b0023d19dfe884sf623543pjz.4
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 03:44:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678963484; cv=pass;
        d=google.com; s=arc-20160816;
        b=PUZwmuz8wEI8eaQT1PSFuKAPSRjxSZqDSds1z+9GC2UBUEgCCSYfB8EUVtjGvAFr0n
         EzHwnHAE1bl1IqKSGiEAiirdhyx4VKLMDqapWoNWO0s6zuN3d4WxW/7TveOuauMcrWJk
         YtAcDUWDiZjT5llTVugQEFXNMuQSesDVOivHUXViLJjw4YSYB9O7tNOHVhS7vXJ+rkVV
         FByyCha5wthEVX8LbY/aEe5paEYieJkgAmqNnW57ADzOEGXtrqG/MT9rA3BxQTRgFA2j
         mfZM4U1AL8E3fwLkJiTw6Gk3DZiazPU93W+cu+kEJHgDzjkqhO49Uk5lKBQ8wffT7SBS
         kMQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=1XU0bXyYQKCJU2Y4s563xNV873b3V13v4cAq3BRoXRg=;
        b=qEVye7VLSbUEpO1iY3j0G+IZEhftiUDubYvFY6ch94AQznkfvtawhTElfomDQl54pB
         8BKOsI3E24cXRm/DWlvwadhTmK7XCVfYSEIxCJ6CRiu9QGeMgOF00X8v2AJMk5+jxyJZ
         mXKgIa1ribuzN+jgyw3LHTEPPaLvNTcsPPsRp0wYmuvWwKu1rhY168nACIwme2IrX9JA
         K2Z9fZZOY9/bLCgWIgjEjgkCaYppDbMC5MquoiwqKQNiZhsITd6MtlXL3zWtIq2jlNh2
         8CyHmXe7378R5ltuOXjNWqI/GPzK5X2XdkG8U5lBIU4vZCGJCiHQcpBef/GjddD1w7i0
         o5AQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b="lXgU/oLj";
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678963484;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1XU0bXyYQKCJU2Y4s563xNV873b3V13v4cAq3BRoXRg=;
        b=MZMe1DKp/l46uLuZiUYwcKyZ8NQ+50e865LALgt0RUp5Omwwk1eyjWUu30fc8ici0l
         XkI2ycrHNbRFpRjWP2Sr64rntmVeNmgT7EiXhf5lqNaLP5Kw3mH9zfMV6pjb+5Y/erL2
         gVk14f9OiM8YmY5FuLBIpUAecr+4gjO/ttPghFVyuOdkdaPdVaGvvbHq0hvr3Gd+pgUh
         oX9P8v5GJguEWIc1wlfHLNNpM49YfJ3rvYU2Ji6+KSzMM4RQZH7iEHE584TcbZgEy3vI
         9s+o7BDCb2bME8j863CI/6Bjn6WfCYBbKYydTd5VOOceG2WgxOQL8Rn86YATUXodVURb
         4a2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678963484;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1XU0bXyYQKCJU2Y4s563xNV873b3V13v4cAq3BRoXRg=;
        b=cvwlM92in+HWjG0qrEHXTSkHrqKrr0sZeVOt+sCJMtE5jp+S8iOM6/4lOEfaMY+GT6
         ah24Lhsoxdf6KmNb8T581bF/JkikIauB4GYO+DzkQkgZueSg+IDOJoJzhYkeTWwp53EC
         RrnN3Ypg2Lg97QiaT9drWn6Qc4laGkuSEse/+ss96MYN7OjwE7i0PuJ+brzYigtfhwzq
         RGkOPQTEflW7jsa2OQJqraRkerEUKGtdQYcrknzF+zj4M1nS+Wp7TRJtG42HJMhx3yAg
         Eu2XFx099HVCDtxvISQoRYfPBzmWWb5HR/33urupbz8DKlVFYwfBo1gLux9gc7IvJUX/
         yQsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWs0BZQddxfmpsIgNyFBSh/VhUpPglgfVuW06r6cKI2PppjK0Hv
	UCp1HkzxkqAu5XWBJbv+S30=
X-Google-Smtp-Source: AK7set9dLGZ5b70LYc241pZ7b6Y6x9I+N+CQohngy88HLppPFP+92mFfkaToJ4tAooou1lRf6t6gVg==
X-Received: by 2002:a17:903:3295:b0:19f:1ee9:a1b with SMTP id jh21-20020a170903329500b0019f1ee90a1bmr1170965plb.4.1678963484611;
        Thu, 16 Mar 2023 03:44:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:747:b0:19c:b41a:3d75 with SMTP id
 kl7-20020a170903074700b0019cb41a3d75ls1698954plb.7.-pod-prod-gmail; Thu, 16
 Mar 2023 03:44:44 -0700 (PDT)
X-Received: by 2002:a17:90b:4a47:b0:23d:39e0:142 with SMTP id lb7-20020a17090b4a4700b0023d39e00142mr3300606pjb.42.1678963483920;
        Thu, 16 Mar 2023 03:44:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678963483; cv=none;
        d=google.com; s=arc-20160816;
        b=bS/AB38jQnCyogzPGcSECZnScQ85sWihwIM+kwJ6+vhEc+SGyLnIYoZhbIqdJgW8Ju
         /1nMaD+DxjU8MUPPDoIsVFSiFBuHTlqLYLPRboTt8uvASUmyIX/q0BqY8ys3GJ0D/EuY
         dG2bTG6TPx+b9jBmcVDoGAxz8bhFADYZMx/I7m1Ju7SnikgTRo26DA4c5sOpYQznPu2C
         sbNC4Xy089/obJ7YcI5yBf3ggRXzRctWUxJDVIG4m2FHr5ap0xKYFnnI4bMp+FMsTmY4
         EkaRp90F4udQs6etqVHKU8xILsv/BENc1Xqk+12iswei93DTTFS4SLUtPihieeFXOBaS
         DNkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=14GYDjYY4VNO6IiBgshsow5iP0Cizb5AZtr8wbZoB4Y=;
        b=ustm6mRyS+ptQbUMmuV7F/v6CaRqINXM7N2qolHES5QOymSaoyFYrerv1jiTVw6qc2
         wL6kX2aV/7aFPKOaYJ5DEB8YKTuM8bN0FrwwPNrRtejaM0HYdKkcrq0tc+nbVlh9RPnq
         1dL7NUl9i/m1OsswXHRr0uB6Ak36Fs3qvcVGpyY0Q8E3mwAqjsPMpDZ84nAFWRKbSD5H
         LpPW3X2K9B0rlWJuDj1j1Ewgg1O2IINWygBcG5iZzqkSzEGp11bGhgDj+c+IXwYn5cWu
         siMGlKtyYaxHjomMrqNLx/i1JtpCXOLPKzn/aIf61hUZL2thCHENH74cBhEnrEzZcwvK
         dQtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b="lXgU/oLj";
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id hk9-20020a17090b224900b0023d2abf8e47si118235pjb.3.2023.03.16.03.44.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Mar 2023 03:44:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279871.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32G2n8Yk002031;
	Thu, 16 Mar 2023 10:44:39 GMT
Received: from nalasppmta05.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3pbpy9hgag-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Mar 2023 10:44:38 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA05.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32GAib2J028141
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Mar 2023 10:44:37 GMT
Received: from [10.239.132.245] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Thu, 16 Mar
 2023 03:44:23 -0700
Message-ID: <e363fd76-67fb-5a0f-5ef9-59d55aa2f447@quicinc.com>
Date: Thu, 16 Mar 2023 18:44:20 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.8.0
Subject: Re: [PATCH v9] mm,kfence: decouple kfence from page granularity
 mapping judgement
Content-Language: en-US
To: Pavan Kondeti <quic_pkondeti@quicinc.com>
CC: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <elver@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <wangkefeng.wang@huawei.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_guptap@quicinc.com>,
        <quic_tingweiz@quicinc.com>
References: <1678956620-26103-1-git-send-email-quic_zhenhuah@quicinc.com>
 <20230316095812.GA1695912@hu-pkondeti-hyd.qualcomm.com>
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <20230316095812.GA1695912@hu-pkondeti-hyd.qualcomm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: jFXwG-C6V8Q8rFx153ri762FweDKjBJI
X-Proofpoint-GUID: jFXwG-C6V8Q8rFx153ri762FweDKjBJI
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-16_07,2023-03-16_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 clxscore=1015 mlxlogscore=971 suspectscore=0 spamscore=0 malwarescore=0
 mlxscore=0 priorityscore=1501 bulkscore=0 adultscore=0 phishscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2303150002 definitions=main-2303160090
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b="lXgU/oLj";       spf=pass
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



On 2023/3/16 17:58, Pavan Kondeti wrote:
> On Thu, Mar 16, 2023 at 04:50:20PM +0800, Zhenhua Huang wrote:
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
>> +
>> +#ifdef CONFIG_KFENCE
>> +
>> +extern char *__kfence_pool;
>> +static inline void kfence_set_pool(phys_addr_t addr)
>> +{
>> +	__kfence_pool = phys_to_virt(addr);
>> +}
>> +
>> +#else
>> +
>> +static inline void kfence_set_pool(phys_addr_t addr) { }
>> +
>> +#endif
>> +
>>   static inline bool arch_kfence_init_pool(void) { return true; }
>>   
>>   static inline bool kfence_protect_page(unsigned long addr, bool protect)
>> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
>> index 6f9d889..61944c70 100644
>> --- a/arch/arm64/mm/mmu.c
>> +++ b/arch/arm64/mm/mmu.c
>> @@ -24,6 +24,7 @@
>>   #include <linux/mm.h>
>>   #include <linux/vmalloc.h>
>>   #include <linux/set_memory.h>
>> +#include <linux/kfence.h>
>>   
>>   #include <asm/barrier.h>
>>   #include <asm/cputype.h>
>> @@ -38,6 +39,7 @@
>>   #include <asm/ptdump.h>
>>   #include <asm/tlbflush.h>
>>   #include <asm/pgalloc.h>
>> +#include <asm/kfence.h>
>>   
>>   #define NO_BLOCK_MAPPINGS	BIT(0)
>>   #define NO_CONT_MAPPINGS	BIT(1)
>> @@ -525,6 +527,48 @@ static int __init enable_crash_mem_map(char *arg)
>>   }
>>   early_param("crashkernel", enable_crash_mem_map);
>>   
>> +#ifdef CONFIG_KFENCE
>> +
>> +static bool kfence_early_init __initdata = !!CONFIG_KFENCE_SAMPLE_INTERVAL;
>> +/*
>> + * early_param can be parsed before linear mapping
>> + * set up
>> + */
>> +static int __init parse_kfence_early_init(char *p)
>> +{
>> +	int val;
>> +
>> +	if (get_option(&p, &val))
>> +		kfence_early_init = !!val;
>> +	return 0;
>> +}
>> +early_param("kfence.sample_interval", parse_kfence_early_init);
>> +
>> +static phys_addr_t arm64_kfence_alloc_pool(void)
>> +{
>> +	phys_addr_t kfence_pool;
>> +
>> +	if (!kfence_early_init)
>> +		return 0;
>> +
>> +	kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
>> +	if (!kfence_pool)
>> +		pr_err("failed to allocate kfence pool\n");
>> +
>> +	return kfence_pool;
>> +}
>> +
>> +#else
>> +
>> +static phys_addr_t arm64_kfence_alloc_pool(void)
>> +{
>> +	return 0;
>> +}
>> +
>> +#endif
>> +
>> +phys_addr_t early_kfence_pool;
>> +
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
> Why not wrap this under CONFIG_KFENCE ? early_kfence_pool can also go in
> there?

Because I didn't want to add CONFIG_KFENCE in function.. in the case of 
w/o CONFIG_KFENCE, early_kfence_pool should be always NULL.

Thanks,
Zhenhua

> 
> Thanks,
> Pavan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e363fd76-67fb-5a0f-5ef9-59d55aa2f447%40quicinc.com.
