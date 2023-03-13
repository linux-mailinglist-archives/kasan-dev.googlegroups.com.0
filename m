Return-Path: <kasan-dev+bncBDVL3PXJZILBBX6OXOQAMGQE76OIUEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id A66086B71FD
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 10:05:36 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id bk18-20020a0568081a1200b0037dc3a143bbsf5046802oib.9
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 02:05:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678698335; cv=pass;
        d=google.com; s=arc-20160816;
        b=E7jk3VIJkrVkmE9X954vZZRUBjtHGwPpn6hrPVObp/AiY+X60zlDC9mMOwFNa/Bkyw
         s/2tJKombfYXE8syhYNsp/v13UcRgJcC4IExEqBx7AMK/CcNOqV3BC/BLC6XIwB4lT/1
         6wM0EebBLETg/gkENzYyjpMILXnXC2Cs8V4Oj62PQI83qE7Dnzl7sP/VyfizMLpo14Rx
         Vp7Widm1ak1C002mToICRSgp4OVd/8iXvWgcc1rBchSG9g2FBZBvXMMTBm9sVqHviI54
         8+cinqmM9Z/qbvWTCNUctXHmYUOMTCNnEPiiCoeoCNQnCFSoiWyLGc/RJZOptyqQfVwm
         BxQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=1o+X9x1ZjoOA4TdVWIjCkZZfqRSWT30OUfaU/IyHXEw=;
        b=wCualUg0aQbelaMixOgliOQLA8nxJug6aWjnJFUc4qs1zwlSLYdn6h+Po+oYCCN6fT
         waq/B2y6oeH8I6otMIai+ySl4qaiv4ppgQ/mT6c4uy6qvG4yHkd7EIUuO20Gpn2HQkWm
         7J7Eiyp3w6RONUUfMcVSvqQcQcdAPpSktdVC/OyDNPukebcj85rwx5S+gJdbFHWRqpdA
         K1CT7g5QCPoGK2nFUPSv6RVCEAEwqwp21oHGAij1nLPXmuf1NybPmnBA1bzZy5iw5fuw
         OkOoShko2bNsn/PTuzasdOG9I6PlIp8e56g0oKBl8oXoHh5orkZ/G5oet1Tbc7NWgM46
         jlsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=c3SYwiD3;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678698335;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1o+X9x1ZjoOA4TdVWIjCkZZfqRSWT30OUfaU/IyHXEw=;
        b=pcBnEq9TmFzSeM9igJN5tf2PFwwywZJfWKbEQNxVZdi53mlg3QeVnpQOOHPckUy4ZN
         NtzGKVxZYB1QOOcRw/Bp2SDzs91U1B8bnAo0p10MqGjFJ+6REscSyuCrw+0YkBZBGhoF
         AwGRrHNu+bG8eWgAJamU2BXu0ZbRLbwJHaHZX5CW3/1ono/yuuXcY4F/aEjxnSG/bfaJ
         8cv3UYzHdcMR2KhaKhyoEvohYurCIIJsImtqpF2gmAgNQD6FYJlRNSMDmdRJ8pz9VccK
         d6y/0VOky6yM4k9bfUhWL1dJcBj7HCw0ulcUMdEmWyXPJ5m4Bv9230aGbQLcg4EY2Lm1
         cnYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678698335;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1o+X9x1ZjoOA4TdVWIjCkZZfqRSWT30OUfaU/IyHXEw=;
        b=YNZ3MDd4+8jPrP7a8zIQOPcYZ8vlaTvYe1vRoBjKHu/c9Txdc3NIQZ+8QcCuROoMeW
         urMzvzHMwu0bbAEEyweLrJNtBYQuZ8is9fh9PI30iEshWZYBjMUAYZHDgZFfKvSZjfkR
         sTo7BguGwQmgDZzfBXQucTHYFIAOXa9uM/CCvzaOLvAjSlJn643ayCLpzxLMQuj2IozZ
         VYD9IgIinltNLuh8lYJyhVmR+cK3yMwfJYNh2+/7Uzx3+fOM/yMW7o970gn9/+qwxHBR
         47RoAwgf7iNx4jC22VRZVieYS2V3M6DnT3Q65RXzGAztvzSf3XNWgHprPtDsqmFC14EK
         cJ+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWzcFLTNbwHRdq1bCo+DWKC+tOvkhZuHRia6QGX/bcdqOXsYf+p
	yLtKlRVXtRW+SOMQ95V0tZU=
X-Google-Smtp-Source: AK7set9VqNfyQe7FAH1SeC8QgRuA4j7yYLMcLICm/Nlq+clq/9qWmIwPB+OVWjWroJpNdLMMCdJTOA==
X-Received: by 2002:a05:6830:343:b0:68b:d5dc:7806 with SMTP id h3-20020a056830034300b0068bd5dc7806mr12072722ote.6.1678698335481;
        Mon, 13 Mar 2023 02:05:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:524b:b0:177:90a9:cbc3 with SMTP id
 o11-20020a056870524b00b0017790a9cbc3ls2300678oai.2.-pod-prod-gmail; Mon, 13
 Mar 2023 02:05:35 -0700 (PDT)
X-Received: by 2002:a05:6870:331f:b0:177:ac71:a213 with SMTP id x31-20020a056870331f00b00177ac71a213mr1594806oae.28.1678698334847;
        Mon, 13 Mar 2023 02:05:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678698334; cv=none;
        d=google.com; s=arc-20160816;
        b=KRXgMaRKT8/WUm/E48nRDyZSXdvgswQ8SqCoEfS1mYjTqKPjIF5tGuC2jv6hWfdI6F
         RwC9CEB30xxw0V7tsP3ixACrRABXyFR2U37bKegu37eey+WA8wMReYIxvYvgVwig9UrF
         djm2tD5w+KEcBUDbTH0HEJTs9EJoPsPJB7nVL/G8xZhH2VScCmjL5DG06XSTzVsXwePD
         JisAqXgtY5cC8WeRcOaONTg8IEjmXq3JfNq3xOtDIEvtfYfb8uNNWZP9NH5wWDdUDM6g
         CmBiXI9NmiLoDdlhjJefQyVbKEGeC68AuJZCQnF1PoRyuLnXZZVKQBTO4U6Ee/9IKkyL
         topQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=W/GkWcXkMcg8ireH2fo6PdRFQoOrc4QQ+VCESLIhobU=;
        b=WYq/tgZv6D3HfERuoANEe6uXvSur9fjRI0polL8IWYAsc4w9nTPXQZScaum4wSZzBA
         rLS8/B8sF9SJetNgo0tkg4TJd3pmbXflnTbXMuPxODHD+M0k/L+PX59Dc6/6m2ahFAbi
         BXh+qa1qWRUWOtRSjMMpRRGNxW7WKl5gw161tOIaMbMwH9BvKuOJ2KZBAiqP1s7/dYUl
         Ztcblnnj2l0ym+V8zHfpU7vVbP9vO9BkJbrKEhm5c1aO6VkT+Nuy0QysivSPUtfBh/yH
         mfgqsiruQa1PRj5I5Xr8cVpeQMhlXBOufl0r+TnD7wU4emYet0ECCdhuzZyIqIB03gQ2
         wf8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=c3SYwiD3;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id oa11-20020a056870bc0b00b001762cd3225csi1152269oab.3.2023.03.13.02.05.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Mar 2023 02:05:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279864.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32D08BLs019499;
	Mon, 13 Mar 2023 09:05:28 GMT
Received: from nalasppmta05.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3p8jtwva47-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 Mar 2023 09:05:27 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA05.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32D95RiC024686
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 Mar 2023 09:05:27 GMT
Received: from [10.239.132.245] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Mon, 13 Mar
 2023 02:05:23 -0700
Message-ID: <8b44b20d-675c-25d0-6ddb-9b02da1c72d2@quicinc.com>
Date: Mon, 13 Mar 2023 17:05:19 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.8.0
Subject: Re: [PATCH v5] mm,kfence: decouple kfence from page granularity
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
References: <1678683825-11866-1-git-send-email-quic_zhenhuah@quicinc.com>
 <CANpmjNNYgP+4mAdQ1cVaJRFGkKMHWWW7nq9_YjKEPDZZ_uBOYg@mail.gmail.com>
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <CANpmjNNYgP+4mAdQ1cVaJRFGkKMHWWW7nq9_YjKEPDZZ_uBOYg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: YxZHp2RILOao7frQ2_6H3et8CPAlUy_Z
X-Proofpoint-GUID: YxZHp2RILOao7frQ2_6H3et8CPAlUy_Z
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-13_01,2023-03-10_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 impostorscore=0
 phishscore=0 suspectscore=0 priorityscore=1501 clxscore=1015
 malwarescore=0 mlxscore=0 adultscore=0 lowpriorityscore=0 mlxlogscore=999
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2303130074
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=c3SYwiD3;       spf=pass
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

Thanks Marco!

On 2023/3/13 15:50, Marco Elver wrote:
> On Mon, 13 Mar 2023 at 06:04, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
>>
>> Kfence only needs its pool to be mapped as page granularity, previous
>> judgement was a bit over protected. From [1], Mark suggested to "just
>> map the KFENCE region a page granularity". So I decouple it from judgement
>> and do page granularity mapping for kfence pool only.
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
> 
> This patch still breaks the late-init capabilities that Kefeng pointed out.
> 
> I think the only viable option is:
> 
>   1. If KFENCE early init is requested on arm64, do what you're doing here.
> 
>   2. If KFENCE is compiled in, but not enabled, do what was done
> before, so it can be enabled late.

I'm fine with above solution as well. The Disadvantage is if we want to 
dynamically disable kfence through kfence_sample_interval, it must be 
mapped into page granularity still.

> 
> Am I missing an option?
> 

Another option is what Kefeng firstly thought and I had proposed on 
comments of patchsetV3, actually I wanted to do in an separate patch:

"
So how about we raise another change, like you mentioned bootargs 
indicating to use late init of b33f778bba5e ("kfence: alloc kfence_pool 
after system startup").
1. in arm64_kfence_alloc_pool():
    if (!kfence_sample_interval && !using_late_init)
              return 0;
    else
              allocate pool
2. also do the check in late allocation,like
    if (do_allocation_late && !using_late_init)
              BUG();
"
The thought is to allocate pool early as well if we need to 
using_late_init.

Kefeng, Marco,

How's your idea?

>>
>> LINK: [1] https://lore.kernel.org/linux-arm-kernel/Y+IsdrvDNILA59UN@FVFF77S0Q05N/
>> Suggested-by: Mark Rutland <mark.rutland@arm.com>
>> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
>> ---
>>   arch/arm64/mm/mmu.c      | 42 ++++++++++++++++++++++++++++++++++++++++++
>>   arch/arm64/mm/pageattr.c |  5 ++---
>>   include/linux/kfence.h   |  8 ++++++++
>>   mm/kfence/core.c         |  9 +++++++++
>>   4 files changed, 61 insertions(+), 3 deletions(-)
>>
>> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
>> index 6f9d889..ca5c932 100644
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
>> @@ -525,6 +526,31 @@ static int __init enable_crash_mem_map(char *arg)
>>   }
>>   early_param("crashkernel", enable_crash_mem_map);
>>
>> +#ifdef CONFIG_KFENCE
>> +
>> +static phys_addr_t arm64_kfence_alloc_pool(void)
>> +{
>> +       phys_addr_t kfence_pool;
>> +
>> +       if (!kfence_sample_interval)
>> +               return 0;
>> +
>> +       kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
>> +       if (!kfence_pool)
>> +               pr_err("failed to allocate kfence pool\n");
>> +
>> +       return kfence_pool;
>> +}
>> +
>> +#else
>> +
>> +static phys_addr_t arm64_kfence_alloc_pool(void)
>> +{
>> +       return 0;
>> +}
>> +
>> +#endif
>> +
>>   static void __init map_mem(pgd_t *pgdp)
>>   {
>>          static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
>> @@ -532,6 +558,7 @@ static void __init map_mem(pgd_t *pgdp)
>>          phys_addr_t kernel_end = __pa_symbol(__init_begin);
>>          phys_addr_t start, end;
>>          int flags = NO_EXEC_MAPPINGS;
>> +       phys_addr_t kfence_pool;
>>          u64 i;
>>
>>          /*
>> @@ -564,6 +591,10 @@ static void __init map_mem(pgd_t *pgdp)
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
>> @@ -608,6 +639,17 @@ static void __init map_mem(pgd_t *pgdp)
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
>> index 726857a..570d4e3 100644
>> --- a/include/linux/kfence.h
>> +++ b/include/linux/kfence.h
>> @@ -64,6 +64,12 @@ static __always_inline bool is_kfence_address(const void *addr)
>>   void __init kfence_alloc_pool(void);
>>
>>   /**
>> + * kfence_set_pool() - allows an arch to set the
>> + * KFENCE pool during early init
>> + */
>> +void __init kfence_set_pool(phys_addr_t addr);
>> +
>> +/**
>>    * kfence_init() - perform KFENCE initialization at boot time
>>    *
>>    * Requires that kfence_alloc_pool() was called before. This sets up the
>> @@ -222,8 +228,10 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
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
>> index 5349c37..0765395 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -814,12 +814,21 @@ void __init kfence_alloc_pool(void)
>>          if (!kfence_sample_interval)
>>                  return;
>>
>> +       /* if the pool has already been initialized by arch, skip the below */
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
>>   static void kfence_init_enable(void)
>>   {
>>          if (!IS_ENABLED(CONFIG_KFENCE_STATIC_KEYS))
>> --
>> 2.7.4
>>
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8b44b20d-675c-25d0-6ddb-9b02da1c72d2%40quicinc.com.
