Return-Path: <kasan-dev+bncBDVL3PXJZILBBJ42YGQAMGQE66ZOBRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 505536B900A
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 11:32:08 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id g6-20020ad45426000000b005a33510e95asf4361484qvt.16
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 03:32:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678789927; cv=pass;
        d=google.com; s=arc-20160816;
        b=PMZS96MxPJq3gKbJBBXi7X8EwTgw6IptW07uttD+zd2tPP1GhuIiCo3GWhcnZb1kWw
         YwBZSpifB15XLuz/CQbbsRRCRorEoI+oJ6I0Ad/SohsOghW8KP02h+IFZqXB8BnrMEaG
         FYawk/oQDbN6v9uNzbrXqhJpVh7kqT9q2NRiP7NxVBdiG8PEiUfJ4El6UueKTRP578o2
         cwgpTweDoloOG+DDYqRK5ja42LXWLx1CxozrTMSjyEgUUGQp/fQUGr6bxILvUSrjWVc4
         OyIUjeeR+W+tHR07NJVkNR+XJlHdmFBv24TDIUngMbMCXQ4HtJnP+wzN7+xpYFhcbAq1
         fYBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=jkCAKCU+6LMDCXkCOv99TG4GnZU+xPJ4qtd4f1sNSh8=;
        b=GNgfrO5uchwcaKtGizn7IoN1uLqN5YsNNKCiBOQdOTr85WsgTWgTwXAvW+xR1AcUxq
         8cu5Z82WKbL1DUZt2sP7nGBw3IJE1aCvkQckB4e/a6I0OveIZncBTOfGaZ4uzjI4Wgr1
         VTVLzyNac3YzwSL/pihlb/xaWyW3VfX3iWGrfN2wDjXQiQoOa9WAzyTjQgv+sPzCCJDy
         KXoKA5xdZDUwV8Sfvh2e0d3SiVjlrZqi7krrBwwu7oxlq/aE+60cghicHI4qHKMY0t58
         bDv3WA3CwKBkyj8B0LDNUf3fFWxwsOzv9f7S9lY6weDO+PHeD5Fvu5OYDKTXh3l7TH51
         I/sA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=jp1JzcQx;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678789927;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=jkCAKCU+6LMDCXkCOv99TG4GnZU+xPJ4qtd4f1sNSh8=;
        b=dfg4kmPdxuPfNSf5jlC+2ji2iDZewJzsmmjrLmUtlzhxYQanyeNUyzVNueUh4Doo6a
         Av9gF4LlexwR2I6bYz6FHowdWQil6yQfN/hOspaEv7vFDA6hYCYPIdCutfPaMd9QMQWh
         xIF+CeOMMBOXGllGvoRBdLPgmtvz6bU48+MKc2upqWa+Vhs20c/1BgTW9nLu8d/Si59H
         xUkBcVd33A2WZjDzhv3/NZD3F/I+YNhgirnv6e+qvoScLungCUbqOhaS1b0Uac4HmNQi
         m24kNGv1WwSgL+92EiEmqo2ejq/tfiuNgKy9s9ieN7RT1vWBZWgSKRy446SH3wEHmQhd
         HUBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678789927;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jkCAKCU+6LMDCXkCOv99TG4GnZU+xPJ4qtd4f1sNSh8=;
        b=W8hbvH9F/1n0t3A0x98VNoE2YjFxIlOae6H5Yg/y+Ss43MPBKy2s/cXleA06zVR1lo
         Ly7oaRuPpGu9uH6W1Yb9IRrD8YDX+fSEzk4v1dhtvfpi9lyxMnV+NVGoqLTyZnh9U0TH
         Gnk2lvc2LpBU95bQyeb7vQYX0yAluZb5kqYy9rCdzEivYTMOJ/+iVtPwX8l8cBbLhA4D
         o9KXoBXkHSNxWy2SJncwS6zLcgXZoYYIoFcST+7q9r4LgJhwyM1kTpY4GTW68hfagg4I
         ROloTZCgUy7SjzSVeIjtp9JsGalyFis6KfvtjPiKXsrQnlw0m2SNyTGo3p1e7MrTyb0q
         qFnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKV02sVVF55svFVjI90TOsWn7yNE5yuQ8IKbB//+OpkwDGW9zzXn
	AN9sLblnV+INi5nnMhR0Oro=
X-Google-Smtp-Source: AK7set/7dH5DvIAHGohy/nE6lrkhOZujx5vYY8UQH8D91ege6FCRlVCDJa6SNGHD8UbvjkXnqjJ5Fg==
X-Received: by 2002:a05:6214:8c6:b0:56e:ace8:866f with SMTP id da6-20020a05621408c600b0056eace8866fmr2689029qvb.3.1678789927176;
        Tue, 14 Mar 2023 03:32:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5a52:0:b0:3d2:22ea:ef7a with SMTP id o18-20020ac85a52000000b003d222eaef7als1448786qta.1.-pod-prod-gmail;
 Tue, 14 Mar 2023 03:32:06 -0700 (PDT)
X-Received: by 2002:a05:622a:181d:b0:3b8:689f:d8ef with SMTP id t29-20020a05622a181d00b003b8689fd8efmr60342714qtc.18.1678789926484;
        Tue, 14 Mar 2023 03:32:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678789926; cv=none;
        d=google.com; s=arc-20160816;
        b=L7egcrfVjnZ0ymcSfu+d1nLvNcBKJhtGyIo7Ojp6YnzjjBaQX/DlNbVtbQk1WgAEnF
         wqI6prjLjSEDqT1RJKzibGH3uOeMT/5If0coW9FUuLYJkirtOYwUFl/c14rLrUtGWw8E
         Bxae8JTv2F3eW8Y69+UNIwtVnodpc/MdUFUSaDESVrwjO3M6k1AfQF4lo8770noA+5i8
         +k8To0eDT7O09cUP/LTlbiW5QSaBW3fCQkeCfJsDpJYqaHK9fHrEj5GQYxXl/nrrWoxy
         lp3nbgl8M719BEt48qKpN1VSOZZxtMBzpSewdvA+NZlI163wpExe/N3FoH3TS5KMY/Wz
         7++w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=+0L/+ZLoHB8P/U6T9eCxaODfDhHGRx9v5KE7t9F/pb8=;
        b=c4BOvNbdmdHhiyQcf2usDoDpuXMmFVvbAeo6bQMEetekSY2+3l3/j0EjJ7rY3z1wJt
         +9OzshbCjdUsf4OEz7b+H2rvxFpGhyATQNr0O3V3qlC37NUHH1KMdkEjR3oWfhuCr6Eb
         NsEydrjro/CNQHmO3GDFbC9ADcp7YgYDsjR1M+3lkDx2VWoO5GIX7aIJErGqDrRkfNPw
         LmOUkkpJtdXce1yGZ4O4egzk4QwsmCEaTRrQ9VvloeTisJs8hGddkdIaCWxNio11lraV
         ZqNe7nFTaXaYMKRNEf2pfoVao+EIBBS4bykmwq33l00YYA+LTsuX/Ij0VjIaN8byDGaM
         uqkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=jp1JzcQx;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id ee22-20020a05620a801600b00725bdb9a8acsi115796qkb.5.2023.03.14.03.32.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Mar 2023 03:32:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279867.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32EAScsD028598;
	Tue, 14 Mar 2023 10:31:59 GMT
Received: from nalasppmta02.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3paay39xx3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Mar 2023 10:31:59 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA02.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32EAVwHT003805
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Mar 2023 10:31:58 GMT
Received: from [10.239.132.245] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Tue, 14 Mar
 2023 03:31:54 -0700
Message-ID: <f207f711-9b43-c677-6b5e-03141a6a893a@quicinc.com>
Date: Tue, 14 Mar 2023 18:31:52 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.8.0
Subject: Re: [PATCH v8] mm,kfence: decouple kfence from page granularity
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
References: <1678777502-6933-1-git-send-email-quic_zhenhuah@quicinc.com>
 <CANpmjNP2zDi9j+14-9Cqi5bMCuq7HcCi6om7SP_gfoVxs_AMbA@mail.gmail.com>
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <CANpmjNP2zDi9j+14-9Cqi5bMCuq7HcCi6om7SP_gfoVxs_AMbA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: ysTxSfXRYWA1q52lwszIXn_iKXZzw_yc
X-Proofpoint-GUID: ysTxSfXRYWA1q52lwszIXn_iKXZzw_yc
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-14_04,2023-03-14_02,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 mlxscore=0
 mlxlogscore=999 malwarescore=0 adultscore=0 lowpriorityscore=0 bulkscore=0
 phishscore=0 spamscore=0 impostorscore=0 priorityscore=1501 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2212070000
 definitions=main-2303140090
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=jp1JzcQx;       spf=pass
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



On 2023/3/14 16:41, Marco Elver wrote:
> On Tue, 14 Mar 2023 at 08:05, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
>>
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
>>   arch/arm64/include/asm/kfence.h |  2 ++
>>   arch/arm64/mm/mmu.c             | 44 +++++++++++++++++++++++++++++++++++++++++
>>   arch/arm64/mm/pageattr.c        |  9 +++++++--
>>   include/linux/kfence.h          |  8 ++++++++
>>   mm/kfence/core.c                |  9 +++++++++
>>   5 files changed, 70 insertions(+), 2 deletions(-)
>>
>> diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
>> index aa855c6..f1f9ca2d 100644
>> --- a/arch/arm64/include/asm/kfence.h
>> +++ b/arch/arm64/include/asm/kfence.h
>> @@ -10,6 +10,8 @@
>>
>>   #include <asm/set_memory.h>
>>
>> +extern phys_addr_t early_kfence_pool;
>> +
>>   static inline bool arch_kfence_init_pool(void) { return true; }
>>
>>   static inline bool kfence_protect_page(unsigned long addr, bool protect)
>> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
>> index 6f9d889..7fbf2ed 100644
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
>>   #define NO_BLOCK_MAPPINGS      BIT(0)
>>   #define NO_CONT_MAPPINGS       BIT(1)
>> @@ -525,6 +527,33 @@ static int __init enable_crash_mem_map(char *arg)
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
>> +phys_addr_t early_kfence_pool;
> 
> The compiler will not optimize out this global. This now exists in all
> arm64 kernel builds.
> 
> Furthermore, there's no need for this to be phys_addr_t. Nothing
> outside map_mem() needs the address, so this can just be a bool.

Seems we need this early_kfence_bool to be explicit phys_addr_t as we 
need to mark/clear NOMAP for the region, so that it will not do linear 
mapping in the for loop.

> 
> I'd recommend moving the variable under CONFIG_KFENCE, and in the asm
> header, just having a static inline helper function e.g.
> arm64_kfence_early_pool(). That helper just returns false in the
> !CONFIG_KFENCE case.
> 
>>   static void __init map_mem(pgd_t *pgdp)
>>   {
>>          static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
>> @@ -543,6 +572,10 @@ static void __init map_mem(pgd_t *pgdp)
>>           */
>>          BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
>>
>> +       early_kfence_pool = arm64_kfence_alloc_pool();
>> +       if (early_kfence_pool)
>> +               memblock_mark_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
>> +
>>          if (can_set_direct_map())
>>                  flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
>>
>> @@ -608,6 +641,17 @@ static void __init map_mem(pgd_t *pgdp)
>>                  }
>>          }
>>   #endif
>> +
>> +       /* Kfence pool needs page-level mapping */
>> +       if (early_kfence_pool) {
>> +               __map_memblock(pgdp, early_kfence_pool,
>> +                       early_kfence_pool + KFENCE_POOL_SIZE,
>> +                       pgprot_tagged(PAGE_KERNEL),
>> +                       NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
>> +               memblock_clear_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
>> +               /* kfence_pool really mapped now */
>> +               kfence_set_pool(early_kfence_pool);
>> +       }
>>   }
>>
>>   void mark_rodata_ro(void)
>> diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
>> index 79dd201..7ce5295 100644
>> --- a/arch/arm64/mm/pageattr.c
>> +++ b/arch/arm64/mm/pageattr.c
>> @@ -7,10 +7,12 @@
>>   #include <linux/module.h>
>>   #include <linux/sched.h>
>>   #include <linux/vmalloc.h>
>> +#include <linux/kfence.h>
>>
>>   #include <asm/cacheflush.h>
>>   #include <asm/set_memory.h>
>>   #include <asm/tlbflush.h>
>> +#include <asm/kfence.h>
>>
>>   struct page_change_data {
>>          pgprot_t set_mask;
>> @@ -22,12 +24,15 @@ bool rodata_full __ro_after_init = IS_ENABLED(CONFIG_RODATA_FULL_DEFAULT_ENABLED
>>   bool can_set_direct_map(void)
>>   {
>>          /*
>> -        * rodata_full, DEBUG_PAGEALLOC and KFENCE require linear map to be
>> +        * rodata_full and DEBUG_PAGEALLOC require linear map to be
>>           * mapped at page granularity, so that it is possible to
>>           * protect/unprotect single pages.
>> +        *
>> +        * Kfence pool requires page granularity mapping also if we init it
>> +        * late.
>>           */
>>          return (rodata_enabled && rodata_full) || debug_pagealloc_enabled() ||
>> -               IS_ENABLED(CONFIG_KFENCE);
>> +           (IS_ENABLED(CONFIG_KFENCE) && !early_kfence_pool);
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
> 
> Please move this function to the header as a static inline function,
> because nothing else other than arm64 needs this, having this function
> be here introduces a .text size increase for everyone.
> 
> The function is so short that having it as a static inline function is
> fine, and will save a few bytes of .text.

Reasonable! Thanks!

> 
>>   static void kfence_init_enable(void)
>>   {
>>          if (!IS_ENABLED(CONFIG_KFENCE_STATIC_KEYS))
>> --
>> 2.7.4
>>

Thanks,
Zhenhua

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f207f711-9b43-c677-6b5e-03141a6a893a%40quicinc.com.
