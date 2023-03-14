Return-Path: <kasan-dev+bncBDVL3PXJZILBBFUPYGQAMGQEZFN2PZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 87A2C6B8F3F
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 11:08:25 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id e15-20020a056808148f00b003844fd09434sf6593242oiw.5
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 03:08:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678788504; cv=pass;
        d=google.com; s=arc-20160816;
        b=b9fvI695wzi72jacfSBHV1Hg2/MQc03UPcj+3X18379yEGnAvZLRVeHD4QrZ45w10a
         60BAdgZM+Avml9kT+piHB3prQXi3xcOr/3jONzFXNJRodaW0yHPp0vdEhObYJJPhNwDH
         aHqgZ8PhhmCA4yZ64Q6gPik46ucffsZU48UeoRSIec1BnCaRluul62Q0uIhBHfDh+qR4
         GxSz0d1fygXTWB0R2J73HBKoqCuT8iulosr6Uc6alunJFUP+vSGIXeYJ0np7SvGdfB3U
         Q0daIIrrj5qWRDCG1evZGuuVncwGcUDo3nvxQnfCg19x93I3V24rB/gmIfBl2kki/4Ka
         fviQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=cghcVoO3mpcQiavM4EBFwDMMGzMyjyQhBxmAomEc2bQ=;
        b=eUbiQAeVYdVYLwleR2w79SDygS8qgHPLDEPNWQ/jo4xFozZazPxuiLXLiiTl+nvuPA
         an6bains7QKL0pdF0Gk3vh17Bx8XhPhkY3j1dDPsZW/ZcRxd4hasuKF8ct3ECmJCAHQi
         Ma41/4LPdsM4ODXH+Em2YnsIP5RW4VriGCsTxNh1TAhDtAP+RV9BXoNV6BOrRbV4zKwk
         Rm+q0L+K6O3v7UaIFDjA8RY5mM+lYxXOZWId/vvP5Rr/H251qW4CadX0uitYnZNpw8R+
         M6BOvCSTJb8mGMVWv/RxINjvCz4aMMXr+viVexrgeP/edLZ9mXiWLkrQw/K5gH14kHmA
         ttCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=ZimRCRGj;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678788504;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cghcVoO3mpcQiavM4EBFwDMMGzMyjyQhBxmAomEc2bQ=;
        b=J2xTZwIobgyMGOsTKd5NLFW9thHFwqsubZVx1Gdt/SYXXxiHCHiH0H1RSMKf9Wnmao
         Au6SngkVc7VlwLbKAQYNwBrhgOlfEOSzIZnCq/FD4JHWDmbPeB4nP+16fXIiB+w089b5
         VebywqkVl0Xbw00oZIGYA7KLjTsR9pd4v8LYfekR65ZZ5y8qB15pLrD4Uk9kdEcvME+l
         PgYfErn008rKN1tp8+07Eg/FF/Ffhgeho+p39Tt5KjIQQkImbRgkdSylOKoJNGurfLSj
         jUOQYIlToyLrMCqfGcj+M08SEtwRYcoTDU1LS4FORadsPja4h/ggMo3b/7YPd9u47Pdi
         yrMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678788504;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cghcVoO3mpcQiavM4EBFwDMMGzMyjyQhBxmAomEc2bQ=;
        b=iNQXPZ/uEhnX1PtI7Z9QfMzzP282TkaPxitU1gpXsP4/4lLkLmzMA2WUT6Kfli+p0z
         ekVqh27TY+yyMJcxQowoUZCHGUyaN92eBBxFmE6ouCbT71ToIl2oU9VEBMCZTb5YEWO4
         bb+UAgwMASMnsFDP0AH4YDw9UxkKNrdmQKncdZbZsA66y/KdAtHELuTs7VmXpA9PKtA2
         WOUEHTgg2BbbaSLDl/LBfpcsFUdttS//U+JHrVTmH4RHE/zu5Yaw1BzI33QhKHoqeYwx
         9iYGN5wDUsbaNiJIjro+8//KrIRwgTt2E4UTsacDhGwrqAE61okaOTqwn3UruWWDxX+5
         X/sQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVz41zsHZ6hajgdCTFOLuPdhZvc81wGM6/8r+GlSY8mf0WCChRt
	W00UEZJkB2GgOKt8/du3QEg=
X-Google-Smtp-Source: AK7set9rABmiMeYvxUL/1HwalfeRmQXMDyOTD95kMmBXPUBk0t5nM4ag7J6ub3a6+497L4UGAuI91A==
X-Received: by 2002:a05:6870:44d0:b0:177:a568:7a91 with SMTP id t16-20020a05687044d000b00177a5687a91mr3047188oai.1.1678788502689;
        Tue, 14 Mar 2023 03:08:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6212:0:b0:693:c1a6:22ff with SMTP id g18-20020a9d6212000000b00693c1a622ffls3441061otj.10.-pod-prod-gmail;
 Tue, 14 Mar 2023 03:08:22 -0700 (PDT)
X-Received: by 2002:a05:6830:2370:b0:696:611d:fc9 with SMTP id r16-20020a056830237000b00696611d0fc9mr949257oth.37.1678788502180;
        Tue, 14 Mar 2023 03:08:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678788502; cv=none;
        d=google.com; s=arc-20160816;
        b=DJjh2reTP92Paai8NTmDPZZxGL+SyUeAZAMZC6nJy/4JBV7/+2/Su4jEWJ1JehMNQ8
         rjk2wXi6lZEOxnGSyWJH6Jb7ynV8/g6GuMx+aV0rPht+3K+bTv5g3q1l/b4cAOSze9vG
         dd9UNHdlbKGfk5Rs7rH3N6X9gmjurTlrYG3OODQty9UIRCGV80S1HX3I+sgkao4rWBEA
         fusWB3T2BKmITGlwX/7mYNADSUZ4oEs3v4P5FzXxd6COKBLhEoGtEcsPAbkmSWb84Ol6
         7dB3iPNFSjimv451Hu6f2mQvoz7LHKnaMGK3W3UtwsgzfUDnhFPYNjvalCvM84IxV6uq
         5BDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=v8dAvwjdcl/p/jJDKWeTJ50+He1Re8qCMMafqf8Emo0=;
        b=GvXoXjyKnx3sfOByGKRJbKZjQjaryAMtjA5xQCinQdnwJX6gTcsw2zEVUME5Rwl50r
         B+y5kXZjDe76tFpfHvdmnidsDGPlt2DE//gXpa+S3lu9iQyQay0Isfjguq6kJ7jcTxWi
         YUDzyC447D/qPyNm8BiAokcUKsT0glUa8QDTdeJn6/rpC4pEPv45094kIfZp06Xchszm
         XWEc+YT9MC7qdOtTyITMLN7bQK496IdrXHGGNUcEp40QEPbyL/WzTGb05Umsx+9ZrzGT
         wDwuW8b6UXIbtg752WU0MnRqVRRKlk/3rx9iKXjGc4LC3ie36F1FVNU2SuJOaNklQf5v
         ucrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=ZimRCRGj;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id bu15-20020a0568300d0f00b006941e4e6ac6si186826otb.4.2023.03.14.03.08.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Mar 2023 03:08:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279863.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32E3W9iN027645;
	Tue, 14 Mar 2023 10:08:15 GMT
Received: from nalasppmta03.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3paef89fs1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Mar 2023 10:08:14 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA03.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32EA8ECg029800
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Mar 2023 10:08:14 GMT
Received: from [10.239.132.245] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Tue, 14 Mar
 2023 03:08:09 -0700
Message-ID: <b1273aad-c952-8c42-f869-22b6fd78c632@quicinc.com>
Date: Tue, 14 Mar 2023 18:08:07 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.8.0
Subject: Re: [PATCH v8] mm,kfence: decouple kfence from page granularity
 mapping judgement
Content-Language: en-US
To: Pavan Kondeti <quic_pkondeti@quicinc.com>
CC: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <elver@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <wangkefeng.wang@huawei.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_guptap@quicinc.com>,
        <quic_tingweiz@quicinc.com>, <quic_charante@quicinc.com>
References: <1678777502-6933-1-git-send-email-quic_zhenhuah@quicinc.com>
 <20230314083645.GA556474@hu-pkondeti-hyd.qualcomm.com>
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <20230314083645.GA556474@hu-pkondeti-hyd.qualcomm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: 8Q0_-CrbR7Rk1ABatQiHIqTXb0znQD_R
X-Proofpoint-GUID: 8Q0_-CrbR7Rk1ABatQiHIqTXb0znQD_R
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-14_04,2023-03-14_02,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 bulkscore=0 adultscore=0 suspectscore=0 mlxlogscore=999 malwarescore=0
 mlxscore=0 impostorscore=0 clxscore=1015 spamscore=0 phishscore=0
 priorityscore=1501 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2303140087
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=ZimRCRGj;       spf=pass
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



On 2023/3/14 16:36, Pavan Kondeti wrote:
> On Tue, Mar 14, 2023 at 03:05:02PM +0800, Zhenhua Huang wrote:
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
>>   #define NO_BLOCK_MAPPINGS	BIT(0)
>>   #define NO_CONT_MAPPINGS	BIT(1)
>> @@ -525,6 +527,33 @@ static int __init enable_crash_mem_map(char *arg)
>>   }
>>   early_param("crashkernel", enable_crash_mem_map);
>>   
>> +#ifdef CONFIG_KFENCE
>> +
>> +static phys_addr_t arm64_kfence_alloc_pool(void)
>> +{
>> +	phys_addr_t kfence_pool;
>> +
>> +	if (!kfence_sample_interval)
>> +		return 0;
>> +
> 
> Are you sure that kernel commandline param are processed this early?
> AFAICS, start_kernel()->parse_args() process the kernel arguments. We
> are here before that. without your patch, mm_init() which takes care of
> allocating kfence memory is called after parse_args().
> 
> Can you check your patch with kfence.sample_interval=0 appended to
> kernel commandline?
> 

Thanks Pavan. I have tried and you're correct. Previously I thought it's 
parsed by the way:
setup_arch()->parse_early_param(earlier)->parse_early_options-> 
do_early_param
Unfortunately seems not take effect.

Then the only way left is we always allocate the kfence pool early? as 
we can't get sample_invertal at this early stage.

>> +	kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
>> +	if (!kfence_pool)
>> +		pr_err("failed to allocate kfence pool\n");
>> +
> For whatever reason, if this allocation fails, what should be done? We
> end up not calling kfence_set_pool(). kfence_alloc_pool() is going to
> attempt allocation again but we did not setup page granularity. That
> means, we are enabling KFENCE without meeting pre-conditions. Can you
> check this?

In this scenario, early_kfence_pool should be false(0) and we will end 
up using page granularity mapping? should be fine IMO.

> 
>> +	return kfence_pool;
>> +}
>> +
> 
> Thanks,
> Pavan

Thanks,
Zhenhua

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b1273aad-c952-8c42-f869-22b6fd78c632%40quicinc.com.
