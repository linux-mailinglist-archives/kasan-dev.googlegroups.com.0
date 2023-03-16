Return-Path: <kasan-dev+bncBDVL3PXJZILBBDXDZSQAMGQE4JAV32A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id BD2136BD2F7
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 16:11:11 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id d4-20020a05620a166400b00742859d0d4fsf1088256qko.15
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 08:11:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678979470; cv=pass;
        d=google.com; s=arc-20160816;
        b=zZZZ8WW+E1BLrLrtfww3x2tGvBFsgxlksXIG65ANZNtJIYKf/EB9vf9Y9oSAqbnfNM
         79+IF7hiQW8Ku3vJzj/5WMIcWELs2Bk7sxdiyfn8hm5h4vN/fuqMfEqllHpuw8kEBa4p
         A881vWHQjezBwnK0luItH9IBVpwEecmB99CBc24ZS0rm5uv7qMvYj9rgg65aFmDoM+gX
         xgOdtte0ifCeEzAGZozkZiymfV9OtKnVeq3bbiOhM8a+R0LztQWfrN1tXVEE+eJq2n1O
         13gEB3wqep/VyOoVwPEPxosH9LDmG4U4fPJ05PCHvhSm4w34Rd5DEz7HgGjw5xPjx1LM
         /c0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=xCRDUhLJ1KjAufPoAGlWW4lz4+KnGikFCfi0TmQDSSs=;
        b=MhMA5AAH2D1HAFahmM4vkfASpmztMK7O1V7Vr1f9V9eBkG5uvEWQiNQNeuTL+P0JfP
         7KezWnLIdPkcw47lG3jYks4rQcuw+4XG4XaKd7mfXEMQx/qPCkWKxaweaA9P76eS1cvS
         CQw5jYxN296kND53TWIEN6cnay1a/IiwvmA4wjHtFRRBtsZ13jdtisRTPA4Zq7DSw9XK
         b9uqxgpH76TqwE0LNVLjl5WPgwIUGn967IfHdjr9BNW28wFBfap8GGfpSWppAevZu37j
         5faQFPrCpsfA79MF+afDdJm/7E2yQpstB99gMz62OYB7FO/i47Mvv8t+P9ChQrY5h9Tu
         EPkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=jTKfj9vc;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678979470;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xCRDUhLJ1KjAufPoAGlWW4lz4+KnGikFCfi0TmQDSSs=;
        b=b9mhtHcQwLmlc3cVtOk4pyNr4WEiGMI91p1d/7dBQ9MgrurMLLSkrITfi+4BnGo2KK
         2PaVeHQBcoOkgpwLe/hv1cvvFw8TMubY6KO+UsqFCRv0cgHcEqgrBfirxQl5LsE9l/5l
         aKpGWTG1jF1Hcp1EjvzSVUHnimB22OB37+QbedEK1lADZNKdUgAZkjjS0CRYOD/mCYEF
         gNBqEm2VmLkA6L70Ek5XMcrTPPSmGlR8AoaYl+fxbe36U2u4O+RySsuizTilccYcGZyq
         UiXiptG8pBQbqO5+3uI7utv9vOMx/GkUJ66824DqBCKyBxaF7t9ekp0AYc/UcqgqmcBE
         pb7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678979470;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xCRDUhLJ1KjAufPoAGlWW4lz4+KnGikFCfi0TmQDSSs=;
        b=jjk4HL4oFpGxBmY41LEbZmZ4iXfLTgUQlMejnmjdbLdAsY/KCY0V0oiU2V9wBTvdkn
         sGi18YM+lKEYIWMKDJaIIOG/Gqx1CVZp5rBlTs5W6CtRJN/iEjvQIj8/w9nkPvz1gSC2
         Iz5E+OzUGIf6P9G8ZFeSMoaHq425EUdBGKBuOhBS1d1hgjK+WqRGqFBTdVqgCRsCZ+YR
         bCsvufwy5lEAPCit+Cvo/cKc9LrIcUWpgzaUgGJz1Sktpe95JVTraYUzOOt0YctF3MWO
         RbUbNANZjNLR07ENnu5L5lPnFaqoQS9aZDkV0Rqb+fT8CHYzFLANooRBx++1HFPyBog7
         yBpQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUvTMVhiV9ZL+H+cHXLUYmxKnchJwa8w4iaC4RQMN8SWIi3QbEF
	bb2FFjCdRNd0SvZ3vE7JWDk=
X-Google-Smtp-Source: AK7set+G1+UGXUkisduCcP5vVmCFGdzEv0GR1R+rcbju5AS7n0ssGy4KfBG0PmV85uuUAb+BHMk03Q==
X-Received: by 2002:ad4:58cd:0:b0:5a8:6ec7:b5ef with SMTP id dh13-20020ad458cd000000b005a86ec7b5efmr3602764qvb.9.1678979470784;
        Thu, 16 Mar 2023 08:11:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:12c4:0:b0:3bc:edc5:2588 with SMTP id b4-20020ac812c4000000b003bcedc52588ls2170423qtj.6.-pod-prod-gmail;
 Thu, 16 Mar 2023 08:11:10 -0700 (PDT)
X-Received: by 2002:a05:622a:c3:b0:3bf:d254:bb9b with SMTP id p3-20020a05622a00c300b003bfd254bb9bmr6854984qtw.44.1678979470138;
        Thu, 16 Mar 2023 08:11:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678979470; cv=none;
        d=google.com; s=arc-20160816;
        b=vJ7m9XF/5ITrnRrPgSlCGiqZ2JeIswp7+XrCcjQRrkEpOzEtSDn4h80bQRH5VeRUjA
         JFK0zcgvperlLKwwOcTelJFT/reR0piS4Ts1XaxFHwNvxw8icQA5hnkMzYzfhsa+aXwR
         LuN8NgRgVie+2tmEPAgqkCbHqyS0bf3HENimsZaz3SMse+H5rcTQ/uAl9YZFB5HG/d2s
         PzsMg/Axul0aG3YjYzj5j3a69BDj1YCaOyKwD17OEZBbDBQHA53sAMlRTEZ/1M0adkOu
         eqvLY0b8HUNFnHhhk7Y8nFLeIXZYZmyuo4tWmmTOGUyKnKU0Pkk7MYe9XtlMoaIkYfpN
         UgZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=0ugVgRxy8hZ3/3OpBR3JVOANzKxtq2sgvDV6Grf6dNM=;
        b=gRK70CjX9A+rSQXH6HvmZz3C2lTSnyDhwqx9mHIrjlj9gBe1JzCiAKS7eM6rsl6XhX
         CLL1mMG12toXkPdGzxRERbLhXIdGaH9AcywDoMfkQDWxTfPKdoSPVFPabde54oIjkTiB
         npSb4qzAE355pmewHUA3jc4EfdDtMruCBAuOHcYJLkNKgXcYdV/Ct0f7lGJfhm/UOqbE
         TNIFP6F8z1VvMVPe80ZaI6Cn41Y9RUy9GDKaqqdRKCtFwDXROxfAGX/PnxwpNK7gV43M
         L/dKFEVZoxN6STraf4JNkVKrk1svxqcXE/D0YSP8pW3M2kfLD794hcY70Ovon2Vx0YAt
         PuwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=jTKfj9vc;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id gd9-20020a05622a5c0900b003d66b64aa7esi207236qtb.0.2023.03.16.08.11.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Mar 2023 08:11:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279873.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32GER89S031439;
	Thu, 16 Mar 2023 15:11:06 GMT
Received: from nalasppmta01.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3pc4vv8554-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Mar 2023 15:11:05 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA01.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32GFB4ZF030484
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Mar 2023 15:11:04 GMT
Received: from [10.253.39.45] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Thu, 16 Mar
 2023 08:11:00 -0700
Message-ID: <1176a4b0-f95f-d93e-75c4-e02dbb300f80@quicinc.com>
Date: Thu, 16 Mar 2023 23:10:58 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.8.0
Subject: Re: [PATCH v10] mm,kfence: decouple kfence from page granularity
 mapping judgement
Content-Language: en-US
To: Kefeng Wang <wangkefeng.wang@huawei.com>, <catalin.marinas@arm.com>,
        <will@kernel.org>, <glider@google.com>, <elver@google.com>,
        <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>
CC: <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
References: <1678969110-11941-1-git-send-email-quic_zhenhuah@quicinc.com>
 <8f064a51-723e-986e-be25-ec2929b685de@huawei.com>
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <8f064a51-723e-986e-be25-ec2929b685de@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: t5eRAWpFNuauNVGxeAyLpkca2sEJ-Rfq
X-Proofpoint-GUID: t5eRAWpFNuauNVGxeAyLpkca2sEJ-Rfq
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-16_10,2023-03-16_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 phishscore=0
 mlxlogscore=999 mlxscore=0 spamscore=0 clxscore=1015 impostorscore=0
 bulkscore=0 malwarescore=0 suspectscore=0 priorityscore=1501
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2303150002 definitions=main-2303160122
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=jTKfj9vc;       spf=pass
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



On 2023/3/16 22:15, Kefeng Wang wrote:
>=20
>=20
> On 2023/3/16 20:18, Zhenhua Huang wrote:
>> Kfence only needs its pool to be mapped as page granularity, if it is
>> inited early. Previous judgement was a bit over protected. From [1], Mar=
k
>> suggested to "just map the KFENCE region a page granularity". So I
>> decouple it from judgement and do page granularity mapping for kfence
>> pool only. Need to be noticed that late init of kfence pool still=20
>> requires
>> page granularity mapping.
>>
>> Page granularity mapping in theory cost more(2M per 1GB) memory on arm64
>> platform. Like what I've tested on QEMU(emulated 1GB RAM) with
>> gki_defconfig, also turning off rodata protection:
>> Before:
>> [root@liebao ]# cat /proc/meminfo
>> MemTotal:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 999484 kB
>> After:
>> [root@liebao ]# cat /proc/meminfo
>> MemTotal:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 1001480 kB
>>
>> To implement this, also relocate the kfence pool allocation before the
>> linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
>> addr, __kfence_pool is to be set after linear mapping set up.
>>
>=20
> A few little comments,

Thanks Kefeng. Addressed your comments in latest patch.

Thanks,
Zhenhua

>=20
>=20
>> LINK: [1]=20
>> https://lore.kernel.org/linux-arm-kernel/Y+IsdrvDNILA59UN@FVFF77S0Q05N/
>> Suggested-by: Mark Rutland <mark.rutland@arm.com>
>> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
>> ---
>> =C2=A0 arch/arm64/include/asm/kfence.h | 10 +++++++
>> =C2=A0 arch/arm64/mm/mmu.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 61=20
>> +++++++++++++++++++++++++++++++++++++++++
>> =C2=A0 arch/arm64/mm/pageattr.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 |=C2=A0 7 +++--
>> =C2=A0 mm/kfence/core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 4 +++
>> =C2=A0 4 files changed, 80 insertions(+), 2 deletions(-)
>>
>> diff --git a/arch/arm64/include/asm/kfence.h=20
>> b/arch/arm64/include/asm/kfence.h
>> index aa855c6..a81937f 100644
>> --- a/arch/arm64/include/asm/kfence.h
>> +++ b/arch/arm64/include/asm/kfence.h
>> @@ -19,4 +19,14 @@ static inline bool kfence_protect_page(unsigned=20
>> long addr, bool protect)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return true;
>> =C2=A0 }
>> +#ifdef CONFIG_KFENCE
>> +extern bool kfence_early_init;
>> +static inline bool arm64_kfence_can_set_direct_map(void)
>> +{
>> +=C2=A0=C2=A0=C2=A0 return !kfence_early_init;
>> +}
>> +#else /* CONFIG_KFENCE */
>> +static inline bool arm64_kfence_can_set_direct_map(void) { return=20
>> false; }
>> +#endif /* CONFIG_KFENCE */
>> +
>> =C2=A0 #endif /* __ASM_KFENCE_H */
>> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
>> index ae25524d..aaf1801 100644
>> --- a/arch/arm64/mm/mmu.c
>> +++ b/arch/arm64/mm/mmu.c
>> @@ -24,6 +24,7 @@
>> =C2=A0 #include <linux/mm.h>
>> =C2=A0 #include <linux/vmalloc.h>
>> =C2=A0 #include <linux/set_memory.h>
>> +#include <linux/kfence.h>
>> =C2=A0 #include <asm/barrier.h>
>> =C2=A0 #include <asm/cputype.h>
>> @@ -38,6 +39,7 @@
>> =C2=A0 #include <asm/ptdump.h>
>> =C2=A0 #include <asm/tlbflush.h>
>> =C2=A0 #include <asm/pgalloc.h>
>> +#include <asm/kfence.h>
>> =C2=A0 #define NO_BLOCK_MAPPINGS=C2=A0=C2=A0=C2=A0 BIT(0)
>> =C2=A0 #define NO_CONT_MAPPINGS=C2=A0=C2=A0=C2=A0 BIT(1)
>> @@ -521,12 +523,67 @@ static int __init enable_crash_mem_map(char *arg)
>> =C2=A0 }
>> =C2=A0 early_param("crashkernel", enable_crash_mem_map);
>> +#ifdef CONFIG_KFENCE
>> +
>> +bool kfence_early_init =3D !!CONFIG_KFENCE_SAMPLE_INTERVAL;
>=20
> maybe add __ro_after_init
>=20
>> +
>> +/* early_param() will be parsed before map_mem() below. */
>> +static int __init parse_kfence_early_init(char *arg)
>> +{
>> +=C2=A0=C2=A0=C2=A0 int val;
>> +
>> +=C2=A0=C2=A0=C2=A0 if (get_option(&arg, &val))
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfence_early_init =3D !!val;
>> +=C2=A0=C2=A0=C2=A0 return 0;
>> +}
>> +early_param("kfence.sample_interval", parse_kfence_early_init);
>> +
>> +static phys_addr_t arm64_kfence_alloc_pool(void)
>=20
> and __init
>=20
>> +{
>> +=C2=A0=C2=A0=C2=A0 phys_addr_t kfence_pool;
>> +
>> +=C2=A0=C2=A0=C2=A0 if (!kfence_early_init)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>> +
>> +=C2=A0=C2=A0=C2=A0 kfence_pool =3D memblock_phys_alloc(KFENCE_POOL_SIZE=
, PAGE_SIZE);
>> +=C2=A0=C2=A0=C2=A0 if (!kfence_pool) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pr_err("failed to allocate k=
fence pool\n");
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfence_early_init =3D false;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>> +=C2=A0=C2=A0=C2=A0 }
>> +
>> +=C2=A0=C2=A0=C2=A0 /* Temporarily mark as NOMAP. */
>> +=C2=A0=C2=A0=C2=A0 memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
>> +
>> +=C2=A0=C2=A0=C2=A0 return kfence_pool;
>> +}
>> +
>> +static void arm64_kfence_map_pool(phys_addr_t kfence_pool, pgd_t *pgdp)
>=20
> Ditto.
>=20
> Reviewed-by: Kefeng Wang <wangkefeng.wang@huawei.com>
>=20
>> +{
>> +=C2=A0=C2=A0=C2=A0 if (!kfence_pool)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return;
>> +
>> +=C2=A0=C2=A0=C2=A0 /* KFENCE pool needs page-level mapping. */
>> +=C2=A0=C2=A0=C2=A0 __map_memblock(pgdp, kfence_pool, kfence_pool + KFEN=
CE_POOL_SIZE,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgpr=
ot_tagged(PAGE_KERNEL),
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 NO_B=
LOCK_MAPPINGS | NO_CONT_MAPPINGS);
>> +=C2=A0=C2=A0=C2=A0 memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
>> +=C2=A0=C2=A0=C2=A0 __kfence_pool =3D phys_to_virt(kfence_pool);
>> +}
>> +#else /* CONFIG_KFENCE */
>> +
>> +static inline phys_addr_t arm64_kfence_alloc_pool(void) { return 0; }
>> +static inline void arm64_kfence_map_pool(phys_addr_t kfence_pool,=20
>> pgd_t *pgdp) { }
>> +
>> +#endif /* CONFIG_KFENCE */
>> +
>> =C2=A0 static void __init map_mem(pgd_t *pgdp)
>> =C2=A0 {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 static const u64 direct_map_end =3D _PAGE=
_END(VA_BITS_MIN);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t kernel_start =3D __pa_symbol(=
_stext);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t kernel_end =3D __pa_symbol(__=
init_begin);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t start, end;
>> +=C2=A0=C2=A0=C2=A0 phys_addr_t early_kfence_pool;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int flags =3D NO_EXEC_MAPPINGS;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 u64 i;
>> @@ -539,6 +596,8 @@ static void __init map_mem(pgd_t *pgdp)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON(pgd_index(direct_map_end - 1=
) =3D=3D=20
>> pgd_index(direct_map_end));
>> +=C2=A0=C2=A0=C2=A0 early_kfence_pool =3D arm64_kfence_alloc_pool();
>> +
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (can_set_direct_map())
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 flags |=3D NO_BLO=
CK_MAPPINGS | NO_CONT_MAPPINGS;
>> @@ -604,6 +663,8 @@ static void __init map_mem(pgd_t *pgdp)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> =C2=A0 #endif
>> +
>> +=C2=A0=C2=A0=C2=A0 arm64_kfence_map_pool(early_kfence_pool, pgdp);
>> =C2=A0 }
>> =C2=A0 void mark_rodata_ro(void)
>> diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
>> index debdecf..dd1291a 100644
>> --- a/arch/arm64/mm/pageattr.c
>> +++ b/arch/arm64/mm/pageattr.c
>> @@ -11,6 +11,7 @@
>> =C2=A0 #include <asm/cacheflush.h>
>> =C2=A0 #include <asm/set_memory.h>
>> =C2=A0 #include <asm/tlbflush.h>
>> +#include <asm/kfence.h>
>> =C2=A0 struct page_change_data {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgprot_t set_mask;
>> @@ -22,12 +23,14 @@ bool rodata_full __ro_after_init =3D=20
>> IS_ENABLED(CONFIG_RODATA_FULL_DEFAULT_ENABLED
>> =C2=A0 bool can_set_direct_map(void)
>> =C2=A0 {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
>> -=C2=A0=C2=A0=C2=A0=C2=A0 * rodata_full, DEBUG_PAGEALLOC and KFENCE requ=
ire linear map to be
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * rodata_full and DEBUG_PAGEALLOC require line=
ar map to be
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * mapped at page granularity, so th=
at it is possible to
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * protect/unprotect single pages.
>> +=C2=A0=C2=A0=C2=A0=C2=A0 *
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * KFENCE pool requires page-granular mapping i=
f initialized late.
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return (rodata_enabled && rodata_full) ||=
=20
>> debug_pagealloc_enabled() ||
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 IS_ENABLED(CONFIG_KFENCE);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 arm64_kfence_can_set_direct_=
map();
>> =C2=A0 }
>> =C2=A0 static int change_page_range(pte_t *ptep, unsigned long addr, voi=
d=20
>> *data)
>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index 1417888..bf2f194c 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -824,6 +824,10 @@ void __init kfence_alloc_pool(void)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!kfence_sample_interval)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return;
>> +=C2=A0=C2=A0=C2=A0 /* if the pool has already been initialized by arch,=
 skip the=20
>> below. */
>> +=C2=A0=C2=A0=C2=A0 if (__kfence_pool)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return;
>> +
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __kfence_pool =3D memblock_alloc(KFENCE_P=
OOL_SIZE, PAGE_SIZE);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!__kfence_pool)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1176a4b0-f95f-d93e-75c4-e02dbb300f80%40quicinc.com.
