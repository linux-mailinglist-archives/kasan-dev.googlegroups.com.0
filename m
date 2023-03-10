Return-Path: <kasan-dev+bncBDVL3PXJZILBBN47VKQAMGQEUBFLZ2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 53F646B33EA
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Mar 2023 03:02:33 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id m6-20020a17090a668600b002375cbab773sf3526553pjj.9
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 18:02:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678413752; cv=pass;
        d=google.com; s=arc-20160816;
        b=QBqJN/bH1pCkhEHiLAmWRyeIU+WeOQsLmQgJdpwGCipGm7S9zZS3l1MUPagqqjDc9Z
         C+Wpq9xEWDkga8A9kBi6j8sbpimgT1UemwJJMnG7VTaXjYU5MwONoLkU7yjegwsYs1oM
         lWrOSGzNiWnlxX/jMUkHxZH8tkRDYL9F85ulH9NUoraMs9fEcAarwkDzPg1y34cTzGkr
         XZYARp6OqMl4IK1L4yw0NK1xn8AFLiRCvH2OKxoOSV9537Kq7DtqeDnzqWRaWYheOQp8
         P2dbjKVvNfDmyCS1+NXsafxLQ/oqbIe6f5Mv9guPqHF0Y1fHMcPABU9tfst8RyWGs7ac
         LFgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=1eeSwmhodlq9te7KGHx3ULiHQ63e+MvQgVmkbXMwqx0=;
        b=GtERLjVFmh/YoMjkrkgq958OIdr+byh9BSd6YnClqYA3970ygSkSEnjEdR9JJIrOAj
         QlVjUUgmgxTfqRoTclSJiNJhaDZ7Kx0zIw2FpqE3MgJFxeCz5J2fPMvPJsSQdqzgj0By
         lffAeS1OZFBuIuTfXyf/EYJ5JA46uuDhjxxWg4umtclNzonhDPCdrPTl8iDPvLgeVWkg
         wenyz63IEk64DTSz/W4ncJXds3Joj5uy7DG+R1WPZWTWswMSjT60YxacJKzMEFy3kmHo
         6x7i/gs5AdgL2rjG+yFIk2zhfx7ikDdzuzEcRQKtbJ5J/G9e6or1eGY4hqIVuNtEfr3A
         yqYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=pGQ8Aqqm;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678413752;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1eeSwmhodlq9te7KGHx3ULiHQ63e+MvQgVmkbXMwqx0=;
        b=UQ7uv3er4H0ePdHrxr2+EjcqDDDg3lw6ir7x8bmXsl51Y9aRCL7H/0FGwSaeiQnmwi
         7NJ5rHMqmP+1fAS3lwNdpDpKb75QV0gZPQokfBIF4B4jk1iHbBvKQZkmABKtK8HTSU++
         K/dEzG9VpwAYD+8AZkWhmOo7XblsMZgFUilBN9BqWcVZQsTIIdveCDJI20hK0P4e7xLQ
         ugUJi2p4AEfTCjQlsEhIDrDeo2VuurmyAWUeMWNsdpHOLqwRIbcIuYX7oAKqws2NkRZs
         9SR5VDG1EOMzRoYZ5qcGgZa9vmh6Wuo+KkUs8N4O9YP6U2a2yUuwunTrPKaLMiEnGI8K
         6nVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678413752;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1eeSwmhodlq9te7KGHx3ULiHQ63e+MvQgVmkbXMwqx0=;
        b=ym80XHuCeVSQFRL9h5ZDjRskV+N+cdhwS7QsaEEEvxMYjde+MOFkpNvaMwwSApn+Pv
         i+AY+FiLw6oFmB6gkp3wk9Oea60qzqgM3ec1CBuzDYmb/LIGuIeDhtAVz2UpjzkFlEv0
         +U+8Og/9RQ3jzWGf+4fb3MKWsHvNBH2h4L5p06aZM8mllP2EAtvMauzMSqmNplFfxxou
         MDrRGjyJl2cNOWZROEM8TsZlq5+C3bapkAMmDmlfl6iI1zwD55hxVFafNF5Bg9wTJKxM
         dd5uK9G/1ZiSVyCFaGm40ymiCKLtNKHEVlxkGHdRdzb1i25eGbmv3MPApyYTpjSMes00
         LQlQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVOf14AgFqxPNgvB/jU33gdeJv266FGKaZx7fzEk1CaCtOGuLcK
	zpk8YeAuZwKituyR+Lx+4wI=
X-Google-Smtp-Source: AK7set9qXiTRIqXo5yMSzyDSc+6IM7cTXAKo5ez6N/zQ+xU7bq6I5xilGYN+FHZSgfGX73vJ2Y3Dwg==
X-Received: by 2002:a17:90b:3787:b0:237:5ddf:25d8 with SMTP id mz7-20020a17090b378700b002375ddf25d8mr8925940pjb.4.1678413751743;
        Thu, 09 Mar 2023 18:02:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5ac7:b0:237:7ef0:5b8 with SMTP id
 n65-20020a17090a5ac700b002377ef005b8ls5624818pji.3.-pod-canary-gmail; Thu, 09
 Mar 2023 18:02:31 -0800 (PST)
X-Received: by 2002:a17:90b:3b4b:b0:237:39b1:7c88 with SMTP id ot11-20020a17090b3b4b00b0023739b17c88mr24940162pjb.35.1678413750902;
        Thu, 09 Mar 2023 18:02:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678413750; cv=none;
        d=google.com; s=arc-20160816;
        b=cMMxgkc3VNpxeGcyxauG/TY8zz/UGpgPiE47Se0+sDsmu+7eRBbbdInJS1JzPs5S2/
         HeNEyFwnMjIS35xWzsMhCt4UhPKWNSzeFZ5A+qb7wfnB2fgCDfrtCka28xGkCay85413
         djAHkzXiyVo6CSx5XQjX/OeqzB7SAznouBIwyW0ruBEjflEwvGNPteHqnIJ3sG/0nr+k
         gSMBUef0WqOqJG0zpIYTYYKvInvSTJ0ntgauf2ebYTwzbnqS22n1/DmUE7P3MwvrBZSX
         vt3Q24R3WAdOWEPF/X7w2h6sowFJnPMtyIz4UOfwsYIi6wsg7+xnprwJaEUNOMkzDK9C
         o49g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=cZFvUJb53zmu/pYLiBd8ADdacQgpkHgQfYJNoAAh/6w=;
        b=x/zFT6XDRgqjbmtZVrI9ZpyNtfU7yo+REfpqSLBxSfFurqQ5BCZmXsa/mM7vC4nWYE
         KvV1q4EsP/1ij9G6/44pi8Ce6HkognQpQe8jE0FQYTriEAK4fq+jTlCwq3cwHQIItl1r
         AOvDchs9bCXF1PhIRIio3omCPryjoD9ZEwF4Iwkzp54f6ox3qpV4Sz15da3ZJmfdrMQG
         57j/bArwu07AhgzZfooYlQwFRRXMuZWQOPnw3CRf4s81oSp+9aDaBKajD9wj5X0UbvR0
         CsJklIWVVWOt7HR8vOUM0MZLAkZT51fZ18kKChsHY2bknmyjltz/D+oELyLFmcUr3QtM
         4gXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=pGQ8Aqqm;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id 194-20020a6300cb000000b00502efc8c657si26946pga.4.2023.03.09.18.02.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Mar 2023 18:02:30 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279868.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32A15I8L031357;
	Fri, 10 Mar 2023 02:02:24 GMT
Received: from nalasppmta03.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3p758cuj2w-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 10 Mar 2023 02:02:24 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA03.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32A22NGH000362
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 10 Mar 2023 02:02:23 GMT
Received: from [10.253.32.183] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Thu, 9 Mar 2023
 18:02:19 -0800
Message-ID: <d76d78d3-66e9-02a9-c31e-da41622334a3@quicinc.com>
Date: Fri, 10 Mar 2023 10:02:17 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
Subject: Re: [PATCH v2] mm,kfence: decouple kfence from page granularity
 mapping judgement
Content-Language: en-US
To: Marco Elver <elver@google.com>
CC: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <linux-arm-kernel@lists.infradead.org>,
        <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
        <quic_pkondeti@quicinc.com>, <quic_guptap@quicinc.com>,
        <quic_tingweiz@quicinc.com>
References: <1678376273-7030-1-git-send-email-quic_zhenhuah@quicinc.com>
 <CANpmjNO90KXo3UNCPC6qVt90hJvKLb_o7_99+cWMbtGSNzKTZw@mail.gmail.com>
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <CANpmjNO90KXo3UNCPC6qVt90hJvKLb_o7_99+cWMbtGSNzKTZw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: _V3dJwdVVIZQ07JTf682-QZDx6L3FnkA
X-Proofpoint-GUID: _V3dJwdVVIZQ07JTf682-QZDx6L3FnkA
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-09_14,2023-03-09_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 malwarescore=0
 priorityscore=1501 suspectscore=0 spamscore=0 clxscore=1015
 impostorscore=0 mlxscore=0 mlxlogscore=985 phishscore=0 lowpriorityscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2303100011
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=pGQ8Aqqm;       spf=pass
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

Thanks Marco for your detailed review!

On 2023/3/9 23:48, Marco Elver wrote:
> On Thu, 9 Mar 2023 at 16:38, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
>>
>> Kfence only needs its pool to be mapped as page granularity, previous
>> judgement was a bit over protected. Decouple it from judgement and do
>> page granularity mapping for kfence pool only [1].
>>
>> To implement this, also relocate the kfence pool allocation before the
>> linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
>> addr, __kfence_pool is to be set after linear mapping set up.
>>
>> LINK: [1] https://lore.kernel.org/linux-arm-kernel/1675750519-1064-1-git-send-email-quic_zhenhuah@quicinc.com/T/
>> Suggested-by: Mark Rutland <mark.rutland@arm.com>
>> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
>> ---
>>   arch/arm64/mm/mmu.c      | 44 ++++++++++++++++++++++++++++++++++++++++++++
>>   arch/arm64/mm/pageattr.c |  5 ++---
>>   include/linux/kfence.h   |  7 +++++++
>>   mm/kfence/core.c         |  9 +++++++++
>>   4 files changed, 62 insertions(+), 3 deletions(-)
>>
>> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
>> index 6f9d889..46afe3f 100644
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
>> @@ -525,6 +526,33 @@ static int __init enable_crash_mem_map(char *arg)
>>   }
>>   early_param("crashkernel", enable_crash_mem_map);
>>
>> +#ifdef CONFIG_KFENCE
>> +
>> +static phys_addr_t arm64_kfence_alloc_pool(void)
>> +{
>> +       phys_addr_t kfence_pool = 0;
>> +
>> +       if (!kfence_sample_interval)
>> +               return 0;
>> +
>> +       kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
>> +       if (!kfence_pool) {
>> +               pr_err("failed to allocate kfence pool\n");
>> +               return 0;
>> +       }
>> +
>> +       return kfence_pool;
>> +}
>> +
>> +#else
>> +
>> +static phys_addr_t arm64_kfence_alloc_pool(void)
>> +{
>> +       return (phys_addr_t)NULL;
> 
> Just return "0" - which the above function does as well on error. Or
> the above function should also do (phys_addr_t)NULL for consistency.

Done

> 
>> +}
>> +
>> +#endif
>> +
>>   static void __init map_mem(pgd_t *pgdp)
>>   {
>>          static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
>> @@ -532,6 +560,7 @@ static void __init map_mem(pgd_t *pgdp)
>>          phys_addr_t kernel_end = __pa_symbol(__init_begin);
>>          phys_addr_t start, end;
>>          int flags = NO_EXEC_MAPPINGS;
>> +       phys_addr_t kfence_pool = 0;
>>          u64 i;
>>
>>          /*
>> @@ -564,6 +593,10 @@ static void __init map_mem(pgd_t *pgdp)
>>          }
>>   #endif
>>
>> +       kfence_pool = arm64_kfence_alloc_pool();
>> +       if (kfence_pool)
>> +               memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
>> +
>>          /* map all the memory banks */
>>          for_each_mem_range(i, &start, &end) {
>>                  if (start >= end)
>> @@ -608,6 +641,17 @@ static void __init map_mem(pgd_t *pgdp)
>>                  }
>>          }
>>   #endif
>> +
>> +       /* Kfence pool needs page-level mapping */
>> +       if (kfence_pool) {
>> +               __map_memblock(pgdp, kfence_pool,
>> +                       kfence_pool + KFENCE_POOL_SIZE,
>> +                       pgprot_tagged(PAGE_KERNEL),
>> +                       NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
>> +               memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
>> +               /* kfence_pool really mapped now */
>> +               kfence_set_pool(kfence_pool);
>> +       }
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
>> index 726857a..d982ac2 100644
>> --- a/include/linux/kfence.h
>> +++ b/include/linux/kfence.h
>> @@ -64,6 +64,11 @@ static __always_inline bool is_kfence_address(const void *addr)
>>   void __init kfence_alloc_pool(void);
>>
>>   /**
>> + * kfence_set_pool() - KFENCE pool mapped and can be used
> 
> I don't understand the comment. Maybe just "allows an arch to set the
> KFENCE pool during early init"

What I want to emphasize is __kfence_pool can be used now :)
Sure, your comment is more clear.

> 
>> + */
>> +void __init kfence_set_pool(phys_addr_t addr);
>> +
>> +/**
>>    * kfence_init() - perform KFENCE initialization at boot time
>>    *
>>    * Requires that kfence_alloc_pool() was called before. This sets up the
>> @@ -222,8 +227,10 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
>>
>>   #else /* CONFIG_KFENCE */
>>
>> +#define KFENCE_POOL_SIZE 0
>>   static inline bool is_kfence_address(const void *addr) { return false; }
>>   static inline void kfence_alloc_pool(void) { }
>> +static inline void kfence_set_pool(phys_addr_t addr) { }
>>   static inline void kfence_init(void) { }
>>   static inline void kfence_shutdown_cache(struct kmem_cache *s) { }
>>   static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }
>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index 5349c37..a17c20c2 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -814,12 +814,21 @@ void __init kfence_alloc_pool(void)
>>          if (!kfence_sample_interval)
>>                  return;
>>
>> +       /* if __kfence_pool already initialized in some arch, abort */
> 
> Abort sounds like it's a failure condition, but it's actually ok.
> 
> Maybe just write:
> 
>   /* Check if the pool has already been initialized by arch; if so,
> skip the below. */

Yes, your comment is more clear. Done.

> 
>> +       if (__kfence_pool)
>> +               return;
>> +
>>          __kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
>>
>>          if (!__kfence_pool)
>>                  pr_err("failed to allocate pool\n");
>>   }
>>
>> +void __init kfence_set_pool(phys_addr_t addr)
>> +{
>> +       __kfence_pool = phys_to_virt(addr);
>> +}
>> +
> 
> The rest looks good.

Updated patchset V 3 :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d76d78d3-66e9-02a9-c31e-da41622334a3%40quicinc.com.
