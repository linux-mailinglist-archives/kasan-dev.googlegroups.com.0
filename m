Return-Path: <kasan-dev+bncBDVL3PXJZILBBA6WYWQAMGQEKVUJBHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C51276BA869
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Mar 2023 07:51:48 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-177c9cc7db5sf3985352fac.15
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 23:51:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678863107; cv=pass;
        d=google.com; s=arc-20160816;
        b=vUPUyHXV7muuhjw5wW8HYaC90QoCXhhFmVZiQkrt8u7y4WDYCLFX9RMzckfyDaSOOU
         sD7vmV2dMXNEuDhOOkiInmluhjGhlRMEWJabYwpf2LBoFfmxehaavgFLoWIPnB5jkiux
         p5XGVKKTKtqs/bNZgh/WqbklsYMER29Ut3Kc1Inw8GCmeD2CwI3DSnxirV7XZD6bnG9S
         sn5+wTxTOiYXXOElQ9IXLuT5adqBjHe7jp6PhkFEVFTCJRAhwFJrQ3weJFMdGLfwXNXc
         fcmq974et+a18eXnMcni4aEGOpsAB2MDDIe1i0Nr9ilH8zCq0PFpChJphPxRRLbncgfZ
         HMeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=kqEmz7bjRFdCGu1EdArOZdn8C0liBk0mJJJ5h/tOPdc=;
        b=xTYuF4XxD2MJA2+JaTB5f4fwUQlRY0lfMbOK3O8eBEo6ptgcKcgDu+Q4nHlW9vf3yD
         l7/M46RENzvUWPcW2ImA+nKl5k/07ZWlDUT7vFmIH0AbLmjo+P/DgjmMUTehcnIYCSOT
         cYpHPjPb6rSZN4BvCYhXg4AH0NdPpgFhBgsXr23N7rXjTIV0aEWE/m1V72xB+u41NH6A
         JD73lAE2v3pA4uQwyRtDpbMhhZViJN/V1U9FJ9qcmzGsM1SO9hhNNVf2h5eqDXhWXXAm
         UXmkuuwUhE5QL6CypShBZ4yj7j7i18kTAl5EarSyCRbgtAmGT/j7MyAYk4825lGAm25I
         7EDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=p01TWw+W;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678863107;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kqEmz7bjRFdCGu1EdArOZdn8C0liBk0mJJJ5h/tOPdc=;
        b=CxS1XlqwUnWMIqR+qsfM8IqCLt4p+qhq7avtLbHfx4AhWDFrqn3IuUIALyZl7h39Ff
         8RFc82C2bAC7dyg7Z3fuE6ZfrDBsTwOO7MAruv88oqgn3ssG8as//b0CerC5WIXoE/rD
         FYyeQM+IfTH1izoJcdwjVVVd9+mGZimMOx0/FRqHzLGY0ypuFng9IfVouvzveGdmqi48
         92d3oQdhYI09wQNp35LpF0zjmNDr9ux93amdeBN4TVPSAMvsWhn7MPkEsIE57q47X849
         awRSag7DKLYvJcOjjdVGnfVSn2nkvjXImQLkeebJPVXOxdBSp5NYsra6s1mLGHvrp4JO
         DCgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678863107;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kqEmz7bjRFdCGu1EdArOZdn8C0liBk0mJJJ5h/tOPdc=;
        b=ZJL3MdD/2nZc66ap/zJ58Ev9Gcoa38xedvIM2XiBsUhYCV0hsR56JH5ZAZr2uv0pmJ
         Z7IX1fKX4HEkug+N0l6IuzWKazEmNnBipGClyThQCyUIbXbKnNOhOWamXOyj5oQp5Ark
         LTCr9UtiyYktAm2NQoGWeONrbQdWxMOJIrh2rXljUVzZNanztx2nids0OV14yS7oscT4
         gSjH8DmndKfSSOKB3Dq+brwXnzHDuzOz6u5rsry8Tp6VIocKkzYjRUiBrZnuxqlz2AQv
         h87koBATbnxnz+/9QQyOEbe5WGQ5ctpfrhTZpN9T2oPARIaYShNRhCkfxEMTQ02H0R0v
         p+5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXWG2bi/vxiPhii33XoNxCauDZjf4qNAV8ZzNv+wPulU7v+lgoP
	bNm/crPJxizIzE/inN2XmbU=
X-Google-Smtp-Source: AK7set9jzRhSHJTlra5wlmLBzoxYuPcO+tOZD2BcSPI/NBjnOdHE5G/9MxFw5pnvhoXDTV3WtKT34g==
X-Received: by 2002:a05:6808:188f:b0:386:a829:48d4 with SMTP id bi15-20020a056808188f00b00386a82948d4mr155216oib.0.1678863107180;
        Tue, 14 Mar 2023 23:51:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:589b:b0:177:b49b:e7f5 with SMTP id
 be27-20020a056870589b00b00177b49be7f5ls3967592oab.11.-pod-prod-gmail; Tue, 14
 Mar 2023 23:51:46 -0700 (PDT)
X-Received: by 2002:a05:6870:3510:b0:177:c0e4:1bd4 with SMTP id k16-20020a056870351000b00177c0e41bd4mr6223688oah.50.1678863106659;
        Tue, 14 Mar 2023 23:51:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678863106; cv=none;
        d=google.com; s=arc-20160816;
        b=tN9JjJ7f9osb0H+CiGsTnzdCvr+45wS8fnxG3MBNI3TwtwsdWGI2uTADrBgf9ZJl+C
         Q1Hhr5+M2YkpgeLKCpdUyaLUYogkL1OXxhio7hjVR11reWsJjaGExnGazwDfa617BpwK
         cXuq/sk5Z2hd4cdkFNPQ59qqxjpdWzCd0hX0op3PYAxg9530iJFndXOKBJAy0Hk2BnL0
         pxnYOp8Mszj5Z/Pw11Z/VE87MP+TUYIfH80Z4fclmvzxY18727HSGeLjdOpp4E7fMq5p
         YF/L6lNlcti42nnsoejgZB4A2F8GOoIJjfuICVUpdKQBOYaYsJ2t3kMyy+NFOhLMZSrY
         22RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=kra+8hgk+4G1Ndw6ydEk7SMxwpkBli/6/VwGY22RaLM=;
        b=1EKdnp41IFlRdJU0UqY9leGDdhjKj8bXENzQHufoyvPRvALXnWS+VQuvGfuqkV1I33
         /rd3WEjxIsH7xxhE3wL8KucjdyWhuw4OjQZUwSg0Hv8WOT+OjzyYCYrE8i741YpkfMLR
         YLjQhTRTJXAX6KZfClVZn7G0d063K12y0h9VZ+Tx/S8iegCnPv4WwLs3MeQbV9hzGdU7
         n3w73Gbzl047cIwcSJjRs9l7JzAOgQaM+F2S8yUhpkXuhDHe57MVg6cZ6ZhsMimDpfiY
         ojn9Gh5gzLEDqVpkdPgmh80f8GrPLZh06GX64HWrSFUIVHXAUESQiu9iIAt3ic3rmWGe
         Minw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=p01TWw+W;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id j19-20020a056830271300b00693cf8eb076si294041otu.5.2023.03.14.23.51.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Mar 2023 23:51:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279865.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32F5O9FN027420;
	Wed, 15 Mar 2023 06:51:40 GMT
Received: from nalasppmta03.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3pb2c98sm6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Mar 2023 06:51:39 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA03.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32F6pdoq004909
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Mar 2023 06:51:39 GMT
Received: from [10.239.132.245] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Tue, 14 Mar
 2023 23:51:35 -0700
Message-ID: <3253f502-aa2e-f8c9-b5bd-8eb20e5f6c5e@quicinc.com>
Date: Wed, 15 Mar 2023 14:51:32 +0800
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
 <b1273aad-c952-8c42-f869-22b6fd78c632@quicinc.com>
 <20230314111422.GB556474@hu-pkondeti-hyd.qualcomm.com>
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <20230314111422.GB556474@hu-pkondeti-hyd.qualcomm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: _zmci54ELkPN5x39baaOuMXRVRCzNYNU
X-Proofpoint-GUID: _zmci54ELkPN5x39baaOuMXRVRCzNYNU
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-15_02,2023-03-14_02,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 phishscore=0 mlxlogscore=999 clxscore=1015 spamscore=0 mlxscore=0
 lowpriorityscore=0 malwarescore=0 bulkscore=0 impostorscore=0
 suspectscore=0 adultscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2302240000 definitions=main-2303150059
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=p01TWw+W;       spf=pass
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

Thanks Pavan.

On 2023/3/14 19:14, Pavan Kondeti wrote:
> On Tue, Mar 14, 2023 at 06:08:07PM +0800, Zhenhua Huang wrote:
>>
>>
>> On 2023/3/14 16:36, Pavan Kondeti wrote:
>>> On Tue, Mar 14, 2023 at 03:05:02PM +0800, Zhenhua Huang wrote:
>>>> Kfence only needs its pool to be mapped as page granularity, if it is
>>>> inited early. Previous judgement was a bit over protected. From [1], Mark
>>>> suggested to "just map the KFENCE region a page granularity". So I
>>>> decouple it from judgement and do page granularity mapping for kfence
>>>> pool only. Need to be noticed that late init of kfence pool still requires
>>>> page granularity mapping.
>>>>
>>>> Page granularity mapping in theory cost more(2M per 1GB) memory on arm64
>>>> platform. Like what I've tested on QEMU(emulated 1GB RAM) with
>>>> gki_defconfig, also turning off rodata protection:
>>>> Before:
>>>> [root@liebao ]# cat /proc/meminfo
>>>> MemTotal:         999484 kB
>>>> After:
>>>> [root@liebao ]# cat /proc/meminfo
>>>> MemTotal:        1001480 kB
>>>>
>>>> To implement this, also relocate the kfence pool allocation before the
>>>> linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
>>>> addr, __kfence_pool is to be set after linear mapping set up.
>>>>
>>>> LINK: [1] https://lore.kernel.org/linux-arm-kernel/Y+IsdrvDNILA59UN@FVFF77S0Q05N/
>>>> Suggested-by: Mark Rutland <mark.rutland@arm.com>
>>>> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
>>>> ---
>>>>    arch/arm64/include/asm/kfence.h |  2 ++
>>>>    arch/arm64/mm/mmu.c             | 44 +++++++++++++++++++++++++++++++++++++++++
>>>>    arch/arm64/mm/pageattr.c        |  9 +++++++--
>>>>    include/linux/kfence.h          |  8 ++++++++
>>>>    mm/kfence/core.c                |  9 +++++++++
>>>>    5 files changed, 70 insertions(+), 2 deletions(-)
>>>>
>>>> diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
>>>> index aa855c6..f1f9ca2d 100644
>>>> --- a/arch/arm64/include/asm/kfence.h
>>>> +++ b/arch/arm64/include/asm/kfence.h
>>>> @@ -10,6 +10,8 @@
>>>>    #include <asm/set_memory.h>
>>>> +extern phys_addr_t early_kfence_pool;
>>>> +
>>>>    static inline bool arch_kfence_init_pool(void) { return true; }
>>>>    static inline bool kfence_protect_page(unsigned long addr, bool protect)
>>>> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
>>>> index 6f9d889..7fbf2ed 100644
>>>> --- a/arch/arm64/mm/mmu.c
>>>> +++ b/arch/arm64/mm/mmu.c
>>>> @@ -24,6 +24,7 @@
>>>>    #include <linux/mm.h>
>>>>    #include <linux/vmalloc.h>
>>>>    #include <linux/set_memory.h>
>>>> +#include <linux/kfence.h>
>>>>    #include <asm/barrier.h>
>>>>    #include <asm/cputype.h>
>>>> @@ -38,6 +39,7 @@
>>>>    #include <asm/ptdump.h>
>>>>    #include <asm/tlbflush.h>
>>>>    #include <asm/pgalloc.h>
>>>> +#include <asm/kfence.h>
>>>>    #define NO_BLOCK_MAPPINGS	BIT(0)
>>>>    #define NO_CONT_MAPPINGS	BIT(1)
>>>> @@ -525,6 +527,33 @@ static int __init enable_crash_mem_map(char *arg)
>>>>    }
>>>>    early_param("crashkernel", enable_crash_mem_map);
>>>> +#ifdef CONFIG_KFENCE
>>>> +
>>>> +static phys_addr_t arm64_kfence_alloc_pool(void)
>>>> +{
>>>> +	phys_addr_t kfence_pool;
>>>> +
>>>> +	if (!kfence_sample_interval)
>>>> +		return 0;
>>>> +
>>>
>>> Are you sure that kernel commandline param are processed this early?
>>> AFAICS, start_kernel()->parse_args() process the kernel arguments. We
>>> are here before that. without your patch, mm_init() which takes care of
>>> allocating kfence memory is called after parse_args().
>>>
>>> Can you check your patch with kfence.sample_interval=0 appended to
>>> kernel commandline?
>>>
>>
>> Thanks Pavan. I have tried and you're correct. Previously I thought it's
>> parsed by the way:
>> setup_arch()->parse_early_param(earlier)->parse_early_options->
>> do_early_param
>> Unfortunately seems not take effect.
>>
>> Then the only way left is we always allocate the kfence pool early? as we
>> can't get sample_invertal at this early stage.
>>
> 
> That would mean, we would allocate the kfence pool memory even when it
> is disabled from commandline. That does not sound good to me.
> 
> Is it possible to free this early allocated memory later in
> mm_init()->kfence_alloc_pool()? if that is not possible, can we think of
> adding early param for kfence?

If we freed that buffer, there may be no chance to get that page 
granularity mapped buffer again.. as all these allocation/free are 
through normal buddy allocator.

At this stage, seems only additional early param can work.. Marco 
previously wanted to reuse sample_interval but seems not doable now.

Hi Marco,

Sorry, Can we thought of the solution again? like
ARM64:
1. intercepts early boot arg and gives early alloc memory to KFENCE
2. KFENCE to disable dynamic switch
3. disable page gran and save memory overhead
The purpose is in the case of w/o boot arg, it's just same as now.. arch 
specific kfence buffer will not allocate. And w/ boot arg, we can get 
expected saving.

Thanks,
Zhenhua

> 
>>>> +	kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
>>>> +	if (!kfence_pool)
>>>> +		pr_err("failed to allocate kfence pool\n");
>>>> +
>>> For whatever reason, if this allocation fails, what should be done? We
>>> end up not calling kfence_set_pool(). kfence_alloc_pool() is going to
>>> attempt allocation again but we did not setup page granularity. That
>>> means, we are enabling KFENCE without meeting pre-conditions. Can you
>>> check this?
>>
>> In this scenario, early_kfence_pool should be false(0) and we will end up
>> using page granularity mapping? should be fine IMO.
>>
> 
> Right, I missed that hunk in can_set_direct_map().
> 
> Thanks,
> Pavan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3253f502-aa2e-f8c9-b5bd-8eb20e5f6c5e%40quicinc.com.
