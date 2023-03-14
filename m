Return-Path: <kasan-dev+bncBDVL3PXJZILBBH4LYCQAMGQEZBF7HSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 64C1D6B8A41
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 06:26:57 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id d10-20020a05620a240a00b0073baf1de8ebsf7831272qkn.19
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 22:26:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678771616; cv=pass;
        d=google.com; s=arc-20160816;
        b=M2ajtxfiDEr7KZlxc/IwPVm6LeBHAHqnzprztj0IamkQiidJ7AefFyr/a17QYpkdva
         TckgXu+p1h4HDNqChKMmayaR+EhZ9y/1WaufyPWaTvXk+j+L9DyTslpbj4ROW7HDZioC
         3HkXbVkhmsDUOz7w7OI4+LaxBa0Y0BrAc3+L+PyTtff6Nq+vKej5ozrrIwYhWz+6hsiK
         5pXbCvv+Y3j+FTflQHvH07UtwtGEOhf841LHwu/YFKeET3QAYDXerYLN2cvy4nJHVzxm
         RG15IOiI4d7vBtWzJOHMGfhJM/ob20FKNyU0B+6VS/BuOvvIbudUJDfZNwhnU7rRKHFw
         mCkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=CilCg6ySvqxK2kSFUnvKndiQ6pCb4LEiURPEqnoGKBY=;
        b=mFjkeaf5hSPHDG+UuzHzsoqMfunm07h7gaNgA7/eK1eymPi1l3VoEXxI3PqzOvDppC
         t1fXH3wLo4lyvDKHS3p8CVbFslPXU26RL02DRicNZ1R/IoEhgd16TqiCKLdr1J/gz94r
         L9E99nm6l0tI9hbPEoTHgpz1eJtjBLpcHBNdu2UyW9QLn+RDWz6QXRrG4Ns6awyRU//s
         Yepn3n1CkSs8t2hEhtX8jPiSDByOy7U29HucISsSaInhJ25teqvaLmWR6J4zE4a+4Krn
         fkU69RqdTXmz7JuMvfqXHLCM4J3GCMxKggpFGiQSzrEbdto675of2pe6YUfxDvrPm5yo
         ndvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=StOFPTda;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678771616;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CilCg6ySvqxK2kSFUnvKndiQ6pCb4LEiURPEqnoGKBY=;
        b=jnjy4nJJXhw5mhLazT6scsaZN3B0SyQlBY3vk1Xc1tj//dSgiy7dNgIzTXOunVguZ2
         +e92c3H8Py1J8g4BLCUK2kfMqG994ydEb4dHZVKpCk1R1vz5AKQdeJHVXdMDgX2+/sg1
         8xv1A6BfncAMPtJATZxO3+yB5UXrx9t6/FrXfAFmkjNxt+Sc4Wue9eP/s31jx9BX/B7I
         SIsTey0efIIysvWS4DGV80vE2KgNDaSLBtgOIYn+/wnM3ljGeJMwRgSU+WFDDJMeDwQj
         qdMUf8KsZGhjXytO7P5M8umpnRQfki/hZdHVmNYYvPnhP++Be4w2Vz7Vivvz+9XaZRa/
         Zjrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678771616;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CilCg6ySvqxK2kSFUnvKndiQ6pCb4LEiURPEqnoGKBY=;
        b=PM4K7ANhqV0ZofXaRdm+0puYFFaEqvWt48fxFwTg84UdMcy6meAybaO2L+DzumV5H3
         L5I2YTXEP48xz2sSWRedd9bb0hXb0vzzqzVzA976oyseVfktTQf0/dGxtI6hjdKqE1gH
         WiesMYY8xXjQdcu0orNcdOZBTX4oPfJkHPcSC9NYDR1aaynooTC9XERmeroTO/9pJu9J
         cEAYg7r2lUoDmBsDO1mbBRUC14jqoUDNpXrizexEgHeydQOxNlvR0q6cfXbP/ocFB/7v
         YPx0bOWGf5KawQoeLwS7M2JLH9+PZGtv/iV1joOCuQiK/DK0G+AbL9rTiLAjYvJAyb8E
         yTKQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXyPMo9vCcS9o1gfCWUy7R6Dfhsdc2iwOO/TTwPP6OwvLSyw1Ux
	OjVKkGuADeS8emmo8exQzcE=
X-Google-Smtp-Source: AK7set/MEfOsc0gMmHEcs4rAIYPeOVC56lGmsSOYK4rPlgO0xjcfasMR1zPJwkl2BX4m7UPBDnkNVw==
X-Received: by 2002:ac8:c9:0:b0:3d2:e040:cd72 with SMTP id d9-20020ac800c9000000b003d2e040cd72mr77717qtg.5.1678771615935;
        Mon, 13 Mar 2023 22:26:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:114d:b0:3ac:c6f0:fe49 with SMTP id
 f13-20020a05622a114d00b003acc6f0fe49ls15665350qty.7.-pod-prod-gmail; Mon, 13
 Mar 2023 22:26:55 -0700 (PDT)
X-Received: by 2002:a05:622a:178e:b0:3bf:bb87:2470 with SMTP id s14-20020a05622a178e00b003bfbb872470mr24717711qtk.23.1678771615285;
        Mon, 13 Mar 2023 22:26:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678771615; cv=none;
        d=google.com; s=arc-20160816;
        b=u02EoF3dGpPcTBppqmcKGlesCEjbmNt8IeWNZXwT1uoPRp0UOAG9NZe9MtCNt4tJZX
         zKKKlFYTpcpXj1ARnIFei7slhe27rCCmR13sVlPMP+bRkaurDmcEE5waK8E6VlzjK4rL
         /DET90ELEoZKbAIZxAPoroqfBXX0MbOEBoZCbCSA8s9TPaTLk1lHXWZC2dhlnTPC8XN5
         27tNPh8CSQJQSSmRTlFcytpbrPM2zEB5msRh46QZxLsQ2rpXu9TTpopKI5jmwK7wAJRX
         B5yscx+5St6GaCCeHeDqpYelY8XoPE7IkA9KEEYXS57h3aXP0nUARDVVLO+SI8XPRJ6H
         FEbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=VlTj/BSZdiSgRaCFf4tRZ6asMFzFqKu8djlnb3KOotk=;
        b=K5vNZ8rlcFrlEfcIFsaLQ8y8HLzpg/iBqEoq+/YS/vBJrL3TuGf6+TGUNmvB1r9YZ9
         npDMpIddUQsIuGKnZbL64PIWrNNdsmgjbymB/S2YM16zzlXb5kfwZdVWbWc5H/zC3Jxw
         F+8YvTZuUN7tuH8NTdPG66wdeRm+ah4LXi6ptbwagvjsPoWj1WfO+vbB2M/ZsXyFS0mi
         drlvyZTHWXniAEzOdU1EieZVMovI3VXtGDuQI6ajyMrGMWUkIiDvMOlNWami8Yf90L2+
         ZTVVl0oLtPXMj0UvJMl9R9F9bklFdCxE1oCfMr+TEq0pjpipgCSOC+nrZDzSeLiJAxIU
         yy3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=StOFPTda;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id cf20-20020a05622a401400b003bb820fca79si98327qtb.1.2023.03.13.22.26.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Mar 2023 22:26:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279869.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32E3ipX5004587;
	Tue, 14 Mar 2023 05:26:51 GMT
Received: from nalasppmta05.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3pa6n31qyr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Mar 2023 05:26:51 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA05.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32E5QoRv009564
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Mar 2023 05:26:50 GMT
Received: from [10.239.132.245] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Mon, 13 Mar
 2023 22:26:46 -0700
Message-ID: <ad29db2f-f10d-ce89-19b0-253c39ad9194@quicinc.com>
Date: Tue, 14 Mar 2023 13:26:43 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.8.0
Subject: Re: [PATCH v6] mm,kfence: decouple kfence from page granularity
 mapping judgement
Content-Language: en-US
To: Kefeng Wang <wangkefeng.wang@huawei.com>, Marco Elver <elver@google.com>
CC: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <linux-arm-kernel@lists.infradead.org>,
        <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
        <quic_pkondeti@quicinc.com>, <quic_guptap@quicinc.com>,
        <quic_tingweiz@quicinc.com>
References: <1678708637-8669-1-git-send-email-quic_zhenhuah@quicinc.com>
 <CANpmjNNBhfdshGhiycY5S-sMnubQx=qGCBcKL5Hm=WL2HXQ2uw@mail.gmail.com>
 <41a98759-1626-5e8f-3b1b-d038ef1925a7@huawei.com>
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <41a98759-1626-5e8f-3b1b-d038ef1925a7@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: 5P-s7k1LDX2T0L3iEKkBpzwXYjDOzg5Y
X-Proofpoint-GUID: 5P-s7k1LDX2T0L3iEKkBpzwXYjDOzg5Y
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-13_13,2023-03-13_03,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 mlxscore=0
 bulkscore=0 mlxlogscore=999 impostorscore=0 priorityscore=1501
 adultscore=0 phishscore=0 spamscore=0 lowpriorityscore=0 clxscore=1015
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2303140046
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=StOFPTda;       spf=pass
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



On 2023/3/13 22:42, Kefeng Wang wrote:
>=20
>=20
> On 2023/3/13 21:00, Marco Elver wrote:
>> On Mon, 13 Mar 2023 at 12:57, Zhenhua Huang=20
>> <quic_zhenhuah@quicinc.com> wrote:
>>>
>>> Kfence only needs its pool to be mapped as page granularity, if it is
>>> inited early. Previous judgement was a bit over protected. From [1],=20
>>> Mark
>>> suggested to "just map the KFENCE region a page granularity". So I
>>> decouple it from judgement and do page granularity mapping for kfence
>>> pool only. Need to be noticed that late init of kfence pool still=20
>>> requires
>>> page granularity mapping.
>>>
>>> Page granularity mapping in theory cost more(2M per 1GB) memory on arm6=
4
>>> platform. Like what I've tested on QEMU(emulated 1GB RAM) with
>>> gki_defconfig, also turning off rodata protection:
>>> Before:
>>> [root@liebao ]# cat /proc/meminfo
>>> MemTotal:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 999484 kB
>>> After:
>>> [root@liebao ]# cat /proc/meminfo
>>> MemTotal:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 1001480 kB
>>>
>>> To implement this, also relocate the kfence pool allocation before the
>>> linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
>>> addr, __kfence_pool is to be set after linear mapping set up.
>>>
>>> LINK: [1]=20
>>> https://lore.kernel.org/linux-arm-kernel/Y+IsdrvDNILA59UN@FVFF77S0Q05N/
>>> Suggested-by: Mark Rutland <mark.rutland@arm.com>
>>> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
>>> ---
>>> =C2=A0 arch/arm64/mm/mmu.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 42=20
>>> ++++++++++++++++++++++++++++++++++++++++++
>>> =C2=A0 arch/arm64/mm/pageattr.c |=C2=A0 8 ++++++--
>>> =C2=A0 include/linux/kfence.h=C2=A0=C2=A0 | 10 ++++++++++
>>> =C2=A0 mm/kfence/core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 |=C2=A0 9 +++++++++
>>> =C2=A0 4 files changed, 67 insertions(+), 2 deletions(-)
>>>
>>> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
>>> index 6f9d889..ca5c932 100644
>>> --- a/arch/arm64/mm/mmu.c
>>> +++ b/arch/arm64/mm/mmu.c
>>> @@ -24,6 +24,7 @@
>>> =C2=A0 #include <linux/mm.h>
>>> =C2=A0 #include <linux/vmalloc.h>
>>> =C2=A0 #include <linux/set_memory.h>
>>> +#include <linux/kfence.h>
>>>
>>> =C2=A0 #include <asm/barrier.h>
>>> =C2=A0 #include <asm/cputype.h>
>>> @@ -525,6 +526,31 @@ static int __init enable_crash_mem_map(char *arg)
>>> =C2=A0 }
>>> =C2=A0 early_param("crashkernel", enable_crash_mem_map);
>>>
>>> +#ifdef CONFIG_KFENCE
>>> +
>>> +static phys_addr_t arm64_kfence_alloc_pool(void)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t kfence_pool;
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!kfence_sample_interval)
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 return 0;
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfence_pool =3D memblock_phys_all=
oc(KFENCE_POOL_SIZE, PAGE_SIZE);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!kfence_pool)
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 pr_err("failed to allocate kfence pool\n");
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return kfence_pool;
>>> +}
>>> +
>>> +#else
>>> +
>>> +static phys_addr_t arm64_kfence_alloc_pool(void)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>>> +}
>>> +
>>> +#endif
>>> +
>>> =C2=A0 static void __init map_mem(pgd_t *pgdp)
>>> =C2=A0 {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 static const u64 direc=
t_map_end =3D _PAGE_END(VA_BITS_MIN);
>>> @@ -532,6 +558,7 @@ static void __init map_mem(pgd_t *pgdp)
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t kernel_end=
 =3D __pa_symbol(__init_begin);
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t start, end=
;
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int flags =3D NO_EXEC_=
MAPPINGS;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t kfence_pool;
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 u64 i;
>>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
>>> @@ -564,6 +591,10 @@ static void __init map_mem(pgd_t *pgdp)
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>> =C2=A0 #endif
>>>
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfence_pool =3D arm64_kfence_allo=
c_pool();
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (kfence_pool)
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
>>> +
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* map all the memory =
banks */
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 for_each_mem_range(i, =
&start, &end) {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (start >=3D end)
>>> @@ -608,6 +639,17 @@ static void __init map_mem(pgd_t *pgdp)
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>> =C2=A0 #endif
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Kfence pool needs page-level m=
apping */
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (kfence_pool) {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 __map_memblock(pgdp, kfence_pool,
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfence_pool=
 + KFENCE_POOL_SIZE,
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgprot_tagg=
ed(PAGE_KERNEL),
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 NO_BLOCK_MA=
PPINGS | NO_CONT_MAPPINGS);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 /* kfence_pool really mapped now */
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 kfence_set_pool(kfence_pool);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>> =C2=A0 }
>>>
>>> =C2=A0 void mark_rodata_ro(void)
>>> diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
>>> index 79dd201..25e4a983 100644
>>> --- a/arch/arm64/mm/pageattr.c
>>> +++ b/arch/arm64/mm/pageattr.c
>>> @@ -7,6 +7,7 @@
>>> =C2=A0 #include <linux/module.h>
>>> =C2=A0 #include <linux/sched.h>
>>> =C2=A0 #include <linux/vmalloc.h>
>>> +#include <linux/kfence.h>
>>>
>>> =C2=A0 #include <asm/cacheflush.h>
>>> =C2=A0 #include <asm/set_memory.h>
>>> @@ -22,12 +23,15 @@ bool rodata_full __ro_after_init =3D=20
>>> IS_ENABLED(CONFIG_RODATA_FULL_DEFAULT_ENABLED
>>> =C2=A0 bool can_set_direct_map(void)
>>> =C2=A0 {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * rodata_full, DEBUG_PAGEAL=
LOC and KFENCE require linear map=20
>>> to be
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * rodata_full and DEBUG_PAG=
EALLOC require linear map to be
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * mapped at page=
 granularity, so that it is possible to
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * protect/unprot=
ect single pages.
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 *
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * Kfence pool requires page=
 granularity mapping also if we=20
>>> init it
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * late.
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return (rodata_enabled=
 && rodata_full) ||=20
>>> debug_pagealloc_enabled() ||
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 IS_ENABLED(CONFIG_KFENCE);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (IS_ENABL=
ED(CONFIG_KFENCE) && !kfence_sample_interval);
>>
>> If you're struggling with kfence_sample_interval not existing if
>> !CONFIG_KFENCE, this is one of the occasions where it'd be perfectly
>> fine to write:
>>
>> bool can_set_direct_map(void) {
>> #ifdef CONFIG_KFENCE
>> =C2=A0=C2=A0=C2=A0=C2=A0 /* ... your comment here ...*/
>> =C2=A0=C2=A0=C2=A0=C2=A0 if (!kfence_sample_interval)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return true;
>> }
>> #endif
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return .........
>> }
>>
>>> =C2=A0 }
>>>
> The can_set_direct_map() could be called anytime, eg, memory add,
> vmalloc, and this will make different state of can_set_direct_map()
> if kfence is re-enabled, I think that we need a new value to check=20
> whether or not the early kfence_pool is initialized.

Many thanks, Kefeng and Marco for your careful review. Agree,=20
kfence_sample_interval can be modified in a few ways and we can't use it=20
in can_set_direct_map().

To be honest, previously I wanted to allocate kfence pool early always=20
but it seems breaks the flexibility that b33f778bba5e ("kfence: alloc=20
kfence_pool after system startup") introduced.

Now I prefer to introduce one global variable early_kfence_pool to=20
indicate if kfence_pool is initialized early, then can_set_direct_map()=20
should be easy and clear to handle: just add "(IS_ENABLED(CONFIG_KFENCE)=20
&& !early_kfence_pool)" for the case of possibility we may init kfence=20
pool later. The naming of early_kfence_pool also can well expressed what=20
we're doing :)

How about your idea? I will update a new patchset.

>=20
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ad29db2f-f10d-ce89-19b0-253c39ad9194%40quicinc.com.
