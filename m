Return-Path: <kasan-dev+bncBDVL3PXJZILBBWEEU6QAMGQEUYY7UPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 49CA36B22D3
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Mar 2023 12:26:18 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id p10-20020a170902e74a00b0019ec1acba17sf964544plf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 03:26:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678361177; cv=pass;
        d=google.com; s=arc-20160816;
        b=idHr/NDm5AP2eDCq2GCayq/BWPyGNohPE9steOC5UuI/GlJdLBGKilhBfNO91b1iV/
         y3AWKaOGHcn1227lmpp5carCXCVKIkPZh9WYfDTUrqx5lzedmLboRBH23INypYNAZ4Ua
         Anf447vwv9zSzxQhSGS3gjFh18JEtJPWRV3tFkO3YJXyt906cYqS7RFFn9NianRdUOCp
         vHbBkHY0IKvNeTZ/FEjxCpiIrNc4vIJHiSegZrLe6J+epdMPzz8By+RAmwEab9QhoVzy
         am8s3x5wXY7VrCFx7X5iGYePbi+CnvTJHhbU8JmBfHDFJi8jC362vP0nJ3b2b048770g
         9OjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=bd5oVpl0tLatokaraLV5uRFF90f9rfuziM83LLB3d9M=;
        b=jKABkZS88ok6vEpYGB2Mys1gPhwn/YS0VDJTGSZis5sR69KMlrNuCOXrOT+KeK4r3N
         H43S/bc9UA4CI/rFQc4SmQvAbTF9fkJr9ZeMvNH7Cvl/eTcMDci8De3FHClugIoNXhCf
         +nQZJ212GNlN9q5cUyjJMDmO5s7f6hL+W7wjV5iscFeUbagTGVIfhp1+8vezOW2GId3u
         u+swwdCuhbfsJfz0dJcx4GCZRGSTCrmhDS8bqCt+0fGD3QG6Zt1e8JmX/XAVLwe7w1YO
         WAtJ6806yLxW6+kTwQ4yLaCdQAxN5CC42EpkQqKgkO5WkfxxAsP/PhnnKgtjKCqw7Hvv
         0Vcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=SeGS5rYw;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678361177;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bd5oVpl0tLatokaraLV5uRFF90f9rfuziM83LLB3d9M=;
        b=BfWP2kycSBk4Qd4B7sAt5bOd7XIfU8dRIstPbvtLRYsAjqA76TNtlQrFWyncTO31Ry
         qAcpFr6ykLu8qvEiYKv49Ns0Z1IptD23LY2srJfIaosP2strmvggdXD4UBLZ01w0CQiU
         aWk51j7lPZ5IkYH/LpxAXFnZtZF0V1M/16B6Ky5WTdjREa+mLG7K3KYTntCkxY4xuayn
         UNpF+zGngy+eQzW6TenwpvTM7K1cwIcVFlP1Xer0GdrvThXCEmmUSP5wby3JtHQstnM8
         r7Mc1792kzUXASJJAKM6wqxKOo7K0Q78MqejsiCJvmw2BcUfZ2Oxh1yX+zmNT7uK4WjV
         rGZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678361177;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bd5oVpl0tLatokaraLV5uRFF90f9rfuziM83LLB3d9M=;
        b=eBF/Oms+CI0/ag+nD1XqGqhGHXHMqq8q8CsL3/4S80W7WNUB+4AcjEO4ggQ5gITLV0
         OGd+jIOmpHI4WWCTXdV5B3Ln/aJ0eGxby7q/gKRYIC7wVWUlPICP74ZHZYgiuNmY6ckt
         rAjbDRqdKaIH2dpTICNUBEJ+Kr3wVbDO011dW8j7QmCiaSbGdig+Hti0EP5gRLgN+p3y
         K7W6vqCj0VLU7XiS/LfG/OnJJHPWcs89hdMHYtJRUkMycHhMNkt5FTPi8Lktvj3HEdBZ
         TFxXpIL+Zudx+ZcAHGyNVWYHo7PgIkPmBQ1NQSaSBKKdMrYwNFXAhR9tutZlM0ZYIqjx
         0Bbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWfwFFfAYP3tGwwDwRAMtmTXtnEN4/NVlGY+8k/3fpjdLoezoDW
	uHz7HmVIaT6eKjTUjxWjTJA=
X-Google-Smtp-Source: AK7set8705mVRREDmaG64x8Xtz42UdMpa8fjzYrfaZKBFAGTg32O2uC+Z9CtFDkYSEbgEEE8jUFkCw==
X-Received: by 2002:a63:a80c:0:b0:503:7be5:f9bd with SMTP id o12-20020a63a80c000000b005037be5f9bdmr7717323pgf.10.1678361176811;
        Thu, 09 Mar 2023 03:26:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2406:b0:19c:b41a:3d75 with SMTP id
 e6-20020a170903240600b0019cb41a3d75ls1964554plo.7.-pod-prod-gmail; Thu, 09
 Mar 2023 03:26:16 -0800 (PST)
X-Received: by 2002:a17:90b:4d12:b0:233:d657:2c7e with SMTP id mw18-20020a17090b4d1200b00233d6572c7emr22864109pjb.8.1678361175981;
        Thu, 09 Mar 2023 03:26:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678361175; cv=none;
        d=google.com; s=arc-20160816;
        b=lpESupqGha/qT4McbIMiqYz5NC7QjDmEYhVDD0jS2L+YE5uVjvNIkE3qJgbti13bG8
         sOa5GtNsX5Q3q2TKSVa42unUQ6o7IbORDqldLRTz4tsxLUFvifeaAeN0xCaOfag4ERdi
         r/T6DxjLOAoZomxkPSEx3io3Hk7B+DlF5FtzJ9ES6N1yU1DLO5JCczcAl51Gn7dHuNJm
         Cf1IFSre6bi5z8hCxVDzek4qhMPOLg5mQvVF8UCE8g8UsIO1JLVl3ErlszJ87R51JirF
         8Cf4DJLkcdvXiYDPwS6jgrSa9QCSAiWUrG+Hhq5CHmPCfPnaBbUzDLzEROBT4ON5PT2D
         p1gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=wsbzJND1dSHOF71Db7QhoIK6N4yaqlfxD3cGUuJMWRE=;
        b=V+QTPYlpDVZGKlVaTHd688lS/TnODGyhl3G3/eqI9tydaFxMfi6w0aGgOWnWH4cxFS
         cKFfSPkqW1AG5Ht+yqqA9sbBxrefUNKUZNY7j7h3rdTqDNKxxwP5COfjVVNc5noTTejH
         LMe+77kjPMRX7v6v0qhn/1WZ+zYDm6PqcsTtXfOSV9yaSl0zAuMBFLR7EUexDsywMKB/
         cwdrXj8pXBSnQjZtAjHLhTY14YhInjVqdyNa8v/9TZWYWcz6PY2Yw03NLPJhL9eCtlxO
         gxKidolqegvqdM3O3Ath9wHN6JCVbW6hEDP+RSUjMON2ToaIpiOfK7eEwKO8AktyL61U
         U12g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=SeGS5rYw;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id h10-20020a17090ac38a00b00239e36686e4si232090pjt.3.2023.03.09.03.26.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Mar 2023 03:26:15 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279869.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3298QOuj025524;
	Thu, 9 Mar 2023 11:26:11 GMT
Received: from nalasppmta05.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3p75yq9bd5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 09 Mar 2023 11:26:10 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA05.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 329BQ92c013812
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 9 Mar 2023 11:26:09 GMT
Received: from [10.253.32.183] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Thu, 9 Mar 2023
 03:26:05 -0800
Message-ID: <3e8606e4-0585-70fa-433d-75bf115aa191@quicinc.com>
Date: Thu, 9 Mar 2023 19:26:02 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
Subject: Re: [PATCH] mm,kfence: decouple kfence from page granularity mapping
 judgement
Content-Language: en-US
To: Marco Elver <elver@google.com>
CC: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <linux-arm-kernel@lists.infradead.org>,
        <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
        <quic_pkondeti@quicinc.com>, <quic_guptap@quicinc.com>,
        <quic_tingweiz@quicinc.com>
References: <1678349122-19279-1-git-send-email-quic_zhenhuah@quicinc.com>
 <CANpmjNOah6gSB_mRvhsK_9DpBtiYinRd5z34PU+tOFgSqXB8Sw@mail.gmail.com>
 <706340ef-1745-c1e4-be4d-358d5db4c05e@quicinc.com>
 <CANpmjNP64OSJgnYyfrijJMdkBNhsvVM9hmwLXOkKJAxoZJV=tg@mail.gmail.com>
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <CANpmjNP64OSJgnYyfrijJMdkBNhsvVM9hmwLXOkKJAxoZJV=tg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: Xhr9FFRlEqPZmOBQGEmXNQor7FN0hkEv
X-Proofpoint-ORIG-GUID: Xhr9FFRlEqPZmOBQGEmXNQor7FN0hkEv
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-09_06,2023-03-08_03,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 clxscore=1015
 adultscore=0 spamscore=0 priorityscore=1501 impostorscore=0 suspectscore=0
 lowpriorityscore=0 phishscore=0 malwarescore=0 mlxscore=0 mlxlogscore=999
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2212070000
 definitions=main-2303090091
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=SeGS5rYw;       spf=pass
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

Thanks Marco!

On 2023/3/9 19:09, Marco Elver wrote:
> On Thu, 9 Mar 2023 at 12:04, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
>>
>> Thanks Marco.
>>
>> On 2023/3/9 18:33, Marco Elver wrote:
>>> On Thu, 9 Mar 2023 at 09:05, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
>>>>
>>>> Kfence only needs its pool to be mapped as page granularity, previous
>>>> judgement was a bit over protected. Decouple it from judgement and do
>>>> page granularity mapping for kfence pool only [1].
>>>>
>>>> To implement this, also relocate the kfence pool allocation before the
>>>> linear mapping setting up, kfence_alloc_pool is to allocate phys addr,
>>>> __kfence_pool is to be set after linear mapping set up.
>>>>
>>>> LINK: [1] https://lore.kernel.org/linux-arm-kernel/1675750519-1064-1-git-send-email-quic_zhenhuah@quicinc.com/T/
>>>> Suggested-by: Mark Rutland <mark.rutland@arm.com>
>>>> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
>>>> ---
>>>>    arch/arm64/mm/mmu.c      | 24 ++++++++++++++++++++++++
>>>>    arch/arm64/mm/pageattr.c |  5 ++---
>>>>    include/linux/kfence.h   | 10 ++++++++--
>>>>    init/main.c              |  1 -
>>>>    mm/kfence/core.c         | 18 ++++++++++++++----
>>>>    5 files changed, 48 insertions(+), 10 deletions(-)
>>>>
>>>> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
>>>> index 6f9d889..bd79691 100644
>>>> --- a/arch/arm64/mm/mmu.c
>>>> +++ b/arch/arm64/mm/mmu.c
>>>> @@ -24,6 +24,7 @@
>>>>    #include <linux/mm.h>
>>>>    #include <linux/vmalloc.h>
>>>>    #include <linux/set_memory.h>
>>>> +#include <linux/kfence.h>
>>>>
>>>>    #include <asm/barrier.h>
>>>>    #include <asm/cputype.h>
>>>> @@ -532,6 +533,9 @@ static void __init map_mem(pgd_t *pgdp)
>>>>           phys_addr_t kernel_end = __pa_symbol(__init_begin);
>>>>           phys_addr_t start, end;
>>>>           int flags = NO_EXEC_MAPPINGS;
>>>> +#ifdef CONFIG_KFENCE
>>>> +       phys_addr_t kfence_pool = 0;
>>>> +#endif
>>>>           u64 i;
>>>>
>>>>           /*
>>>> @@ -564,6 +568,12 @@ static void __init map_mem(pgd_t *pgdp)
>>>>           }
>>>>    #endif
>>>>
>>>> +#ifdef CONFIG_KFENCE
>>>> +       kfence_pool = kfence_alloc_pool();
>>>> +       if (kfence_pool)
>>>> +               memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
>>>> +#endif
>>>> +
>>>>           /* map all the memory banks */
>>>>           for_each_mem_range(i, &start, &end) {
>>>>                   if (start >= end)
>>>> @@ -608,6 +618,20 @@ static void __init map_mem(pgd_t *pgdp)
>>>>                   }
>>>>           }
>>>>    #endif
>>>> +
>>>> +       /* Kfence pool needs page-level mapping */
>>>> +#ifdef CONFIG_KFENCE
>>>> +       if (kfence_pool) {
>>>> +               __map_memblock(pgdp, kfence_pool,
>>>> +                       kfence_pool + KFENCE_POOL_SIZE,
>>>> +                       pgprot_tagged(PAGE_KERNEL),
>>>> +                       NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
>>>> +               memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
>>>> +               /* kfence_pool really mapped now */
>>>> +               kfence_set_pool(kfence_pool);
>>>> +       }
>>>> +#endif
>>>> +
>>>>    }
>>>>
>>>>    void mark_rodata_ro(void)
>>>> diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
>>>> index 79dd201..61156d0 100644
>>>> --- a/arch/arm64/mm/pageattr.c
>>>> +++ b/arch/arm64/mm/pageattr.c
>>>> @@ -22,12 +22,11 @@ bool rodata_full __ro_after_init = IS_ENABLED(CONFIG_RODATA_FULL_DEFAULT_ENABLED
>>>>    bool can_set_direct_map(void)
>>>>    {
>>>>           /*
>>>> -        * rodata_full, DEBUG_PAGEALLOC and KFENCE require linear map to be
>>>> +        * rodata_full and DEBUG_PAGEALLOC require linear map to be
>>>>            * mapped at page granularity, so that it is possible to
>>>>            * protect/unprotect single pages.
>>>>            */
>>>> -       return (rodata_enabled && rodata_full) || debug_pagealloc_enabled() ||
>>>> -               IS_ENABLED(CONFIG_KFENCE);
>>>> +       return (rodata_enabled && rodata_full) || debug_pagealloc_enabled();
>>>>    }
>>>>
>>>>    static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
>>>> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
>>>> index 726857a..0252e74 100644
>>>> --- a/include/linux/kfence.h
>>>> +++ b/include/linux/kfence.h
>>>> @@ -61,7 +61,12 @@ static __always_inline bool is_kfence_address(const void *addr)
>>>>    /**
>>>>     * kfence_alloc_pool() - allocate the KFENCE pool via memblock
>>>>     */
>>>> -void __init kfence_alloc_pool(void);
>>>> +phys_addr_t __init kfence_alloc_pool(void);
>>>> +
>>>> +/**
>>>> + * kfence_set_pool() - KFENCE pool mapped and can be used
>>>> + */
>>>> +void __init kfence_set_pool(phys_addr_t addr);
>>>>
>>>>    /**
>>>>     * kfence_init() - perform KFENCE initialization at boot time
>>>> @@ -223,7 +228,8 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
>>>>    #else /* CONFIG_KFENCE */
>>>>
>>>>    static inline bool is_kfence_address(const void *addr) { return false; }
>>>> -static inline void kfence_alloc_pool(void) { }
>>>> +static inline phys_addr_t kfence_alloc_pool(void) { return (phys_addr_t)NULL; }
>>>> +static inline void kfence_set_pool(phys_addr_t addr) { }
>>>>    static inline void kfence_init(void) { }
>>>>    static inline void kfence_shutdown_cache(struct kmem_cache *s) { }
>>>>    static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }
>>>> diff --git a/init/main.c b/init/main.c
>>>> index 4425d17..9aaf217 100644
>>>> --- a/init/main.c
>>>> +++ b/init/main.c
>>>> @@ -839,7 +839,6 @@ static void __init mm_init(void)
>>>>            */
>>>>           page_ext_init_flatmem();
>>>>           init_mem_debugging_and_hardening();
>>>> -       kfence_alloc_pool();
>>>
>>> This breaks other architectures.
>>
>> Nice catch. Thanks!
>>
>>>
>>>>           report_meminit();
>>>>           kmsan_init_shadow();
>>>>           stack_depot_early_init();
>>>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>>>> index 5349c37..dd5cdd5 100644
>>>> --- a/mm/kfence/core.c
>>>> +++ b/mm/kfence/core.c
>>>> @@ -809,15 +809,25 @@ static void toggle_allocation_gate(struct work_struct *work)
>>>>
>>>>    /* === Public interface ===================================================== */
>>>>
>>>> -void __init kfence_alloc_pool(void)
>>>> +phys_addr_t __init kfence_alloc_pool(void)
>>>>    {
>>>
>>> You could just return here:
>>>
>>>     if (__kfence_pool)
>>>       return; /* Initialized earlier by arch init code. */
>>
>> Yeah.
>>
>>>
>>> ... and see my comments below.
>>>
>>>> +       phys_addr_t kfence_pool;
>>>>           if (!kfence_sample_interval)
>>>> -               return;
>>>> +               return 0;
>>>>
>>>> -       __kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
>>>> +       kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
>>>>
>>>> -       if (!__kfence_pool)
>>>> +       if (!kfence_pool) {
>>>>                   pr_err("failed to allocate pool\n");
>>>> +               return 0;
>>>> +       }
>>>> +
>>>> +       return kfence_pool;
>>>> +}
>>>> +
>>>> +void __init kfence_set_pool(phys_addr_t addr)
>>>> +{
>>>> +       __kfence_pool = phys_to_virt(addr);
>>>>    }
>>>
>>> I would suggest leaving kfence_alloc_pool() to return nothing (with
>>> the addition above), and just set __kfence_pool as before.
>>> __kfence_pool itself is exported by include/linux/kfence.h, so if you
>>> call kfence_alloc_pool() in arm64 earlier, you can access
>>> __kfence_pool to get the allocated pool.
>>
>> Shall we add one new function like arm64_kfence_alloc_pool() ? The
>> reason is linear mapping at that time not set up and we must alloc phys
>> addr based on memblock. We can't use common kfence_alloc_pool()..
> 
> Ah right - well, you can initialize __kfence_pool however you like
> within arm64 init code. Just teaching kfence_alloc_pool() to do
> nothing if it's already initialized should be enough. Within
> arch/arm64/mm/mmu.c it might be nice to factor out some bits into a
> helper like arm64_kfence_alloc_pool(), but would just stick to
> whatever is simplest.

Many thanks Marco. Let me conclude as following:
1. put arm64_kfence_alloc_pool() within arch/arm64/mm/mmu.c as it's 
arch_ specific codes.
2. leave kfence_set_pool() to set _kfence_pool within kfence driver, as 
it may become common part.

The reason we still need #2 is because _kfence_pool only can be used 
after mapping set up, it must be late than pool allocation. Do you have 
any further suggestion?

> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3e8606e4-0585-70fa-433d-75bf115aa191%40quicinc.com.
