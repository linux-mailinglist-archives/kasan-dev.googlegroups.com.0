Return-Path: <kasan-dev+bncBDVL3PXJZILBBOH2U2QAMGQEKJWKQDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AD196B222F
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Mar 2023 12:04:26 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id a6-20020a17090acb8600b0023797a1b2f7sf860623pju.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 03:04:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678359864; cv=pass;
        d=google.com; s=arc-20160816;
        b=pJVbJa7FNGTHR0a46PUgTT1H0kJ7rhT+Apo5nxW8aSfvKlB415K7P/ZtE6AV4u/6JJ
         ua0xnPY+urLEXa+7ndC5IOB75ia+Hp40HADK981rVR9TOtKiQbpELQAjxxZcjMt9ApRE
         SKy4ABL1Q1FIl9z3zYHSy/791TJVpSEdKHND0OZQbkJRzd4t+/zWFj3OE/HaSK9BUKWr
         J+P3I1KlK5+iWNLMWuHb514YSYGYYLc7od29nCugcsLmZA9c6LhJwxGzrcDiW6c6QiE3
         ZlWncq2vSSY5ururDLWCJ64CD0FM6MEM4Ezmr96sz6JYu9bLmGP1+gFsndQgz/0X1zkW
         QCww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=wS0AhIML36zEvW7IsOe+IaBSwcSMu3tDpBLQOxWd35I=;
        b=zGyPK7i0quKNH4FmnLe7tqMCOlXP+M7R9XpjvAFAWbnR24oA9rH8ht4+xexZgmGvwK
         WTIpQRVKfAjYAPTNGIzhoaIRseOo/KJFFfYsne+PQuddNUNiYztDdVo1gEXFWiZE/nty
         6G4lWLoicBJID0tTnYAVIgFB1hJ/zKw1U66Y/0g0Dagss2AR0TV7I9lGqv7w6h9RjaBJ
         w7C3iJ1IGOQ7gcajbUyVh+XM9l0lpYhGb84V9zE8VGZX0e0/8CidWlesA64h0y8/jq/b
         qBscNZIGuKNt6osGjscidiEWZoJ6R14aNCcwkRh97NTJxVVuWJbxGHytNGHPpiNbalub
         8NZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=PoSq9Ypv;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678359864;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=wS0AhIML36zEvW7IsOe+IaBSwcSMu3tDpBLQOxWd35I=;
        b=gPZWIViY6o/JzuOlX4BQgyiVHgulm1xC9nkpc7F1CEsQmb6vcuQBchbbWaveUuTMWC
         6abq0RMFBVHx/DGqDZT8+r3SrxEyABXDPrCfLo/Gdf5Jj9gKpSmIinGDITDnnWbHY+5I
         tt5R3kYF88wuKky8H+SYK2YDu79mMe+ftUh3jOQoStLyfEoMsOBhrH8OPqQG6Se4dq6/
         I5ruHWxAu1Mgo+3DJf55H8lRS9XKwrlt2YgD2bsHYdkzGN+ENvQYtCj/EVri7ghsSP2n
         sbAdDeE1c4+1O+4c82rf00wa87QzbWMjWwOkOmWq+BC6PgD71sTfErAc74PbMNJ02hPb
         jmnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678359864;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wS0AhIML36zEvW7IsOe+IaBSwcSMu3tDpBLQOxWd35I=;
        b=Xy8lmZUWdOY9zSQp403bKDFXW7abqlB1cVVyQ0St1HThQxh1wdQogGaY90nmmGB6WG
         kXYrDlmMOYqpntvT5tJHaXGef1axTWNOHaZXsP+w/QPmLmMEoe25Qg5q65PLEAgSWU6L
         vJmTmqrhD3xbw8ky0ORz3sUklQ7sNBOMYbV61gYfM/Bktc8msSeyP+s0D+ArNGbbPaVS
         USsIsYjC/c03WKGk3MSQlDs9HOF784B8QJOSwQh6Fyn9lVuCbl/l35FMHIie6x52YPSK
         +2PpaRoqaL/d1y5B5Flf0qQbO0imv9dA+vdLXaiWNIv/TKAwmL+rRy3x9LuDRQ5OeaF/
         QnAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWkoFYj3DCVwru2Y/uTtRlLp+dh+NSBPx1MEksLvzEtzKoDtGYK
	Cq/rL4YZ1LvFWJSMHnKQi5A=
X-Google-Smtp-Source: AK7set+8OF/iCrg4/0G9l9AYz2n2S28NYtyHgTWjrTgJZVOPlMTocbKPWXErPOjF8mADBQHQz+HvWA==
X-Received: by 2002:a63:715d:0:b0:4fb:b3d4:864d with SMTP id b29-20020a63715d000000b004fbb3d4864dmr7656128pgn.4.1678359864583;
        Thu, 09 Mar 2023 03:04:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b60e:b0:19c:a86d:b340 with SMTP id
 b14-20020a170902b60e00b0019ca86db340ls1910040pls.9.-pod-prod-gmail; Thu, 09
 Mar 2023 03:04:23 -0800 (PST)
X-Received: by 2002:a17:902:d549:b0:19c:be09:20d5 with SMTP id z9-20020a170902d54900b0019cbe0920d5mr23882217plf.11.1678359863666;
        Thu, 09 Mar 2023 03:04:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678359863; cv=none;
        d=google.com; s=arc-20160816;
        b=AMJdEEcNt7KBsFcV94pBB5XCujJ6TM5tkNmb2cJT0fDarcNuKQuihOGntqY9fyVLWR
         YvNEVsxnQSKGfgNi+YF8Bs9C67M/Nyd7SFO9oPkLcbokx64YanmJN7SkNsIudZxWJd/a
         FFRdHvtWHL3kM41AzO3ZCMbd0cA/VqfhLoFnI17vX7o9wsBhk5qyBvUNeUJzIYEIQGVt
         VaT5k78Vy/GTzx7Qt7K/vzTKwNDv49mxe3GZHGt8OGxgfEIa3r0Udc/r8FWcjBOWkdR5
         hLxkmi1rPyeHdMeIce2zxpdCHB6X+Zhw+dd376+N0MyOx4QHZWa3SF+jlG3vThoqF26a
         35lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=X8dvdWP7SdnknCw1GjXHCc1StyfP73x157+3jLFM+gw=;
        b=Eb0p6xIfazKxxNPWwCg0LVjONhVkkruqt3V8yD3dcCub+OxOuR5RSFnXQooVdWPSZH
         uRSj2X0eOS2c1TbqVp3fBTCmUeH28jiT7kyHIHDkgtf6wW/4nzJtbY3EdmRJ4eoO/D59
         7iNF/dderzRmnF6ioWWGdL5y2Ec6r6Gkq+rwM/8lz22UzzDmXNI4qKkq8ythiqkkRGkm
         rOiE0h/D+cTwXKnJdSi428PgPebpfKuHN+tqqUz3uJGM+p+wed+IbievX2LBiGVoVXL4
         ZtoVj6tn+3qv68fEQZTdS0rFR7XkXpSNqFOiFWwXx+SWwZFL0opy3OTEiWM4gOc2TUhV
         0hog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=PoSq9Ypv;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id jk19-20020a170903331300b0018712ccd6e0si765190plb.2.2023.03.09.03.04.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Mar 2023 03:04:23 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279871.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3298QNPY016690;
	Thu, 9 Mar 2023 11:04:19 GMT
Received: from nalasppmta02.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3p72qaspwx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 09 Mar 2023 11:04:18 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA02.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 329B4HWV022239
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 9 Mar 2023 11:04:17 GMT
Received: from [10.253.32.183] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Thu, 9 Mar 2023
 03:04:13 -0800
Message-ID: <706340ef-1745-c1e4-be4d-358d5db4c05e@quicinc.com>
Date: Thu, 9 Mar 2023 19:03:59 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
Subject: Re: [PATCH] mm,kfence: decouple kfence from page granularity mapping
 judgement
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
Content-Language: en-US
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <CANpmjNOah6gSB_mRvhsK_9DpBtiYinRd5z34PU+tOFgSqXB8Sw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: MW6ODZvyxvNlmGGdMW-Idxhfp13rQb1X
X-Proofpoint-ORIG-GUID: MW6ODZvyxvNlmGGdMW-Idxhfp13rQb1X
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-09_06,2023-03-08_03,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 adultscore=0 impostorscore=0 suspectscore=0 clxscore=1015 bulkscore=0
 mlxlogscore=999 spamscore=0 mlxscore=0 phishscore=0 lowpriorityscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2303090087
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=PoSq9Ypv;       spf=pass
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

Thanks Marco.

On 2023/3/9 18:33, Marco Elver wrote:
> On Thu, 9 Mar 2023 at 09:05, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
>>
>> Kfence only needs its pool to be mapped as page granularity, previous
>> judgement was a bit over protected. Decouple it from judgement and do
>> page granularity mapping for kfence pool only [1].
>>
>> To implement this, also relocate the kfence pool allocation before the
>> linear mapping setting up, kfence_alloc_pool is to allocate phys addr,
>> __kfence_pool is to be set after linear mapping set up.
>>
>> LINK: [1] https://lore.kernel.org/linux-arm-kernel/1675750519-1064-1-git-send-email-quic_zhenhuah@quicinc.com/T/
>> Suggested-by: Mark Rutland <mark.rutland@arm.com>
>> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
>> ---
>>   arch/arm64/mm/mmu.c      | 24 ++++++++++++++++++++++++
>>   arch/arm64/mm/pageattr.c |  5 ++---
>>   include/linux/kfence.h   | 10 ++++++++--
>>   init/main.c              |  1 -
>>   mm/kfence/core.c         | 18 ++++++++++++++----
>>   5 files changed, 48 insertions(+), 10 deletions(-)
>>
>> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
>> index 6f9d889..bd79691 100644
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
>> @@ -532,6 +533,9 @@ static void __init map_mem(pgd_t *pgdp)
>>          phys_addr_t kernel_end = __pa_symbol(__init_begin);
>>          phys_addr_t start, end;
>>          int flags = NO_EXEC_MAPPINGS;
>> +#ifdef CONFIG_KFENCE
>> +       phys_addr_t kfence_pool = 0;
>> +#endif
>>          u64 i;
>>
>>          /*
>> @@ -564,6 +568,12 @@ static void __init map_mem(pgd_t *pgdp)
>>          }
>>   #endif
>>
>> +#ifdef CONFIG_KFENCE
>> +       kfence_pool = kfence_alloc_pool();
>> +       if (kfence_pool)
>> +               memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
>> +#endif
>> +
>>          /* map all the memory banks */
>>          for_each_mem_range(i, &start, &end) {
>>                  if (start >= end)
>> @@ -608,6 +618,20 @@ static void __init map_mem(pgd_t *pgdp)
>>                  }
>>          }
>>   #endif
>> +
>> +       /* Kfence pool needs page-level mapping */
>> +#ifdef CONFIG_KFENCE
>> +       if (kfence_pool) {
>> +               __map_memblock(pgdp, kfence_pool,
>> +                       kfence_pool + KFENCE_POOL_SIZE,
>> +                       pgprot_tagged(PAGE_KERNEL),
>> +                       NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
>> +               memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
>> +               /* kfence_pool really mapped now */
>> +               kfence_set_pool(kfence_pool);
>> +       }
>> +#endif
>> +
>>   }
>>
>>   void mark_rodata_ro(void)
>> diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
>> index 79dd201..61156d0 100644
>> --- a/arch/arm64/mm/pageattr.c
>> +++ b/arch/arm64/mm/pageattr.c
>> @@ -22,12 +22,11 @@ bool rodata_full __ro_after_init = IS_ENABLED(CONFIG_RODATA_FULL_DEFAULT_ENABLED
>>   bool can_set_direct_map(void)
>>   {
>>          /*
>> -        * rodata_full, DEBUG_PAGEALLOC and KFENCE require linear map to be
>> +        * rodata_full and DEBUG_PAGEALLOC require linear map to be
>>           * mapped at page granularity, so that it is possible to
>>           * protect/unprotect single pages.
>>           */
>> -       return (rodata_enabled && rodata_full) || debug_pagealloc_enabled() ||
>> -               IS_ENABLED(CONFIG_KFENCE);
>> +       return (rodata_enabled && rodata_full) || debug_pagealloc_enabled();
>>   }
>>
>>   static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
>> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
>> index 726857a..0252e74 100644
>> --- a/include/linux/kfence.h
>> +++ b/include/linux/kfence.h
>> @@ -61,7 +61,12 @@ static __always_inline bool is_kfence_address(const void *addr)
>>   /**
>>    * kfence_alloc_pool() - allocate the KFENCE pool via memblock
>>    */
>> -void __init kfence_alloc_pool(void);
>> +phys_addr_t __init kfence_alloc_pool(void);
>> +
>> +/**
>> + * kfence_set_pool() - KFENCE pool mapped and can be used
>> + */
>> +void __init kfence_set_pool(phys_addr_t addr);
>>
>>   /**
>>    * kfence_init() - perform KFENCE initialization at boot time
>> @@ -223,7 +228,8 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
>>   #else /* CONFIG_KFENCE */
>>
>>   static inline bool is_kfence_address(const void *addr) { return false; }
>> -static inline void kfence_alloc_pool(void) { }
>> +static inline phys_addr_t kfence_alloc_pool(void) { return (phys_addr_t)NULL; }
>> +static inline void kfence_set_pool(phys_addr_t addr) { }
>>   static inline void kfence_init(void) { }
>>   static inline void kfence_shutdown_cache(struct kmem_cache *s) { }
>>   static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }
>> diff --git a/init/main.c b/init/main.c
>> index 4425d17..9aaf217 100644
>> --- a/init/main.c
>> +++ b/init/main.c
>> @@ -839,7 +839,6 @@ static void __init mm_init(void)
>>           */
>>          page_ext_init_flatmem();
>>          init_mem_debugging_and_hardening();
>> -       kfence_alloc_pool();
> 
> This breaks other architectures.

Nice catch. Thanks!

> 
>>          report_meminit();
>>          kmsan_init_shadow();
>>          stack_depot_early_init();
>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index 5349c37..dd5cdd5 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -809,15 +809,25 @@ static void toggle_allocation_gate(struct work_struct *work)
>>
>>   /* === Public interface ===================================================== */
>>
>> -void __init kfence_alloc_pool(void)
>> +phys_addr_t __init kfence_alloc_pool(void)
>>   {
> 
> You could just return here:
> 
>    if (__kfence_pool)
>      return; /* Initialized earlier by arch init code. */

Yeah.

> 
> ... and see my comments below.
> 
>> +       phys_addr_t kfence_pool;
>>          if (!kfence_sample_interval)
>> -               return;
>> +               return 0;
>>
>> -       __kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
>> +       kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
>>
>> -       if (!__kfence_pool)
>> +       if (!kfence_pool) {
>>                  pr_err("failed to allocate pool\n");
>> +               return 0;
>> +       }
>> +
>> +       return kfence_pool;
>> +}
>> +
>> +void __init kfence_set_pool(phys_addr_t addr)
>> +{
>> +       __kfence_pool = phys_to_virt(addr);
>>   }
> 
> I would suggest leaving kfence_alloc_pool() to return nothing (with
> the addition above), and just set __kfence_pool as before.
> __kfence_pool itself is exported by include/linux/kfence.h, so if you
> call kfence_alloc_pool() in arm64 earlier, you can access
> __kfence_pool to get the allocated pool.

Shall we add one new function like arm64_kfence_alloc_pool() ? The 
reason is linear mapping at that time not set up and we must alloc phys 
addr based on memblock. We can't use common kfence_alloc_pool()..

> 
> Because at that point, KFENCE isn't yet running, that only happens
> after kfence_init() much later.
> 
> With these changes, you should be able to make arm64 work the way you
> want, and not break other architectures where we don't need arch init
> code to allocate the pool.
> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/706340ef-1745-c1e4-be4d-358d5db4c05e%40quicinc.com.
