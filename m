Return-Path: <kasan-dev+bncBDVL3PXJZILBBAFRYGQAMGQELY7H2VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 095336B917B
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 12:20:34 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id e12-20020a9d63cc000000b006944a810ab3sf7353374otl.20
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 04:20:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678792832; cv=pass;
        d=google.com; s=arc-20160816;
        b=pLzcjgoANF+hC9TX8SE8N2TgoADEoHNTMZCYgJ9UpVubCWyLsitxXlDFDXBKrtT2RG
         Ui1o4pgkvgFNOLsKEWhSt4X1UuPcSOtrL5JvKOKAAo2Sumb895x6kjR+OksM165OpCL5
         EG5bB+6bg/X4yKM44R6oGC0SDn469oOQ1MZb4ZYSr5XbrCW9BGdUM38ToKMI3ARI+BcY
         WY9TJ15sGfrTx18zYdcp+RcpRNutv448gSFl3QKBF7fQk819gHyUXxR0bbavPvoazDgi
         dXcirFNBVDe6HnuEK3yJRmI3EmWfkg8dKRc1xaUnYV0L0Qxbw4M6YNr1tgIjnMl79ICC
         7M/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:references:cc:to:from:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=s1EKlFrnjgiAXKgkL3SqIkVdWyTjatySPwAgg44ZZCA=;
        b=lAXxsBDCZmuavu9Lq/uQL11YkCuHmKRYbT4w6A170bz2ySxcLC2SUkBchqAqaSdWhp
         wJ9Afi/mQB2EiutX9b9VMiFRhl/FBjrygs1J0qxNp01u/H/SPf6UcP2ji6DHCIY46zGP
         GW0dNOUtbK9+TnXNpKdjjaJtcFm0A4HXyScZOdoo6fBNNMGpy0+k5Y1nBlNjFTQ7W3yT
         /kFKd6+9TCdo7yUkxpUMYRRd0U6LCKkqqL2Bei/jjhTXxk9FSKlrAv3q3kmCa+aQwDnT
         LG0PH0H80f50R3EvLaQK9Z3leHPAakHPGQUCdChuqEeD/0ydQelNE7HsqGdlZfvwIIxK
         ZR5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=UoAFg8eK;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678792832;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:references
         :cc:to:from:content-language:subject:user-agent:mime-version:date
         :message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=s1EKlFrnjgiAXKgkL3SqIkVdWyTjatySPwAgg44ZZCA=;
        b=smRzaA4oVZhYW350Ic46mwdbQt7v87oijHiJ7lxkYJWYGYY748syG+UPzJXowk1hNk
         /0KBPxebQp2TjWwiEBMBGabkL2HpqmJyD90gmQozG1hB2tiy7kgEncFN46DrVM1Gx6CO
         ZLVPrwCpT9y+r9MawY53eV9+voR6VtvWLS48GCe9DTz8Xci6sMWs0l2lihrnNKaRdkkG
         WHBYWr4ppWohs454m1Q/ULdmQhOe4/q89WcIJNEZDHoSUGnUfUeoZ4VhiiwJArfXmisd
         KZT8QvvSK22FG9/1PAcCng8p+5SxLQmqchEl6TQmGa7a1QEPk1az5rVGhnBNmvpLBRop
         rksg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678792832;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=s1EKlFrnjgiAXKgkL3SqIkVdWyTjatySPwAgg44ZZCA=;
        b=OV6JfVhafXN4XbN/9uEpdTGhy3UhZ0CTEVwopvFqRiKTooFY2QIUURBfGPiZi6g2z6
         rHMxphs7qZVIlmXPeHgSbT7FDbZg3kSXlnZHrqo95AKXG6bkgwXcAXHkzzUkHqSe0YlQ
         PNsEkRhhNwhL5ODpV0rj0MjXR6fcKLoEkm2uhVKxH+lkM1yIwKl2Wdhhzrse/L8lRFMZ
         mPqykCkd4A0OB/ft8Woxgffzv5Hs10hMa9SJw5J18W5fEyEWf9RCgIHpnLm26BS1MBJC
         5xNNkD9Bn/ki6y98Ju59db4ETnnyF0Rb5caBO7N/O2kEZetgtJyHMFmySLYOKbXUwrLd
         aASw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUvItcjDDPmqTftQB1lPd1oOnHckSFOOGPKsCK3Nak99WA6+p4s
	Psc/GAJkURHL6Vfno92Aows=
X-Google-Smtp-Source: AK7set+M3NRi14XIKTgV30i5iFYvv8evmhFV8zE9jEfXJzpW4hrC3Dhbg0VaM9oDG2ISeEyKZdf+gw==
X-Received: by 2002:a05:6830:1614:b0:688:cf52:6e14 with SMTP id g20-20020a056830161400b00688cf526e14mr12497970otr.0.1678792832572;
        Tue, 14 Mar 2023 04:20:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4783:b0:176:30d5:30b9 with SMTP id
 c3-20020a056870478300b0017630d530b9ls6959025oaq.9.-pod-prod-gmail; Tue, 14
 Mar 2023 04:20:32 -0700 (PDT)
X-Received: by 2002:a05:6870:d186:b0:177:af7c:906f with SMTP id a6-20020a056870d18600b00177af7c906fmr4834520oac.40.1678792832074;
        Tue, 14 Mar 2023 04:20:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678792832; cv=none;
        d=google.com; s=arc-20160816;
        b=CVqIT0nojgRL+o2kTk1f9ZzU7dph6+MXS8oVKKGKV+Ws1WHE9Nu464H2qMzC4Wi+Sv
         XoMca1qvKS3K1qONj+Ck25/SQ6VxM8TMAMk11M8PcaP7CM1N9U0vJV/omCJ5xF11nbO1
         EIJ5h6Z2jYqRpWVMMnpFyvsgmSUMDq5QIxlaTMif48urpwErOggPWXo8wPEVSfv6QDuz
         W37McR9vEzdxSWdtcDgG4rT532Cfl97FrsnaHUE7z6X4BNKCQP6ctStTf7Vn+PEgAdWj
         0QQCpXg8k1rQ8YuRywoEtYEMDWRwlRD994KQKnEP5fbtymkIPcL0DMuFlNjzR0jU8Nhq
         6MXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=qz8gssYCYPv/XC6ElU0LbrFoosjkHS19wWGngVnluFQ=;
        b=D82yJTNLFLiac1K9vKbSEDLByU1270OWavd3VNBhof1PazTQkrLLWc6Y8mShG+TiMm
         C1gY1el1Ipo+PQXejSBVKPPfnSFGkhopF9vV/gWHw6tEOOtI/07l/Q6XSIemv18aQpEo
         w7PptSSrUau9tTXe8pUuXKCKPLdKKYIKXVIIgmEvj8I2Sw/Tderm6ygwmm7zFaRTeIW6
         SMf1zE1QR/DvFXJ6GsddsAq6VDXg2Fc9M+ujX9+SGsfBKTu+hIHKFGtNhXmBfLvm+g/f
         6ATTt00MXWqhUr2zYyVo2fRjq80FgPtMDxS3aJNMK3DAtTc+DK7cc/qvvJzTzhNnnFQ+
         0p6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=UoAFg8eK;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id pn12-20020a0568704d0c00b001723959e146si376000oab.4.2023.03.14.04.20.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Mar 2023 04:20:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279863.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32EASNRs030510;
	Tue, 14 Mar 2023 11:20:25 GMT
Received: from nalasppmta03.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3paef89mkt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Mar 2023 11:20:25 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA03.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32EBKOOG027096
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Mar 2023 11:20:24 GMT
Received: from [10.239.132.245] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Tue, 14 Mar
 2023 04:20:19 -0700
Message-ID: <a851cf97-cc7f-08c4-9b06-548783cb90e5@quicinc.com>
Date: Tue, 14 Mar 2023 19:20:17 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.8.0
Subject: Re: [PATCH v8] mm,kfence: decouple kfence from page granularity
 mapping judgement
Content-Language: en-US
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
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
In-Reply-To: <b1273aad-c952-8c42-f869-22b6fd78c632@quicinc.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: ymEGbYDEjf9-fF450_jbKzGd-JK0ld2F
X-Proofpoint-GUID: ymEGbYDEjf9-fF450_jbKzGd-JK0ld2F
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-14_05,2023-03-14_02,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 bulkscore=0 adultscore=0 suspectscore=0 mlxlogscore=999 malwarescore=0
 mlxscore=0 impostorscore=0 clxscore=1015 spamscore=0 phishscore=0
 priorityscore=1501 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2303140096
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=UoAFg8eK;       spf=pass
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



On 2023/3/14 18:08, Zhenhua Huang wrote:
>=20
>=20
> On 2023/3/14 16:36, Pavan Kondeti wrote:
>> On Tue, Mar 14, 2023 at 03:05:02PM +0800, Zhenhua Huang wrote:
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
>>> =C2=A0 arch/arm64/include/asm/kfence.h |=C2=A0 2 ++
>>> =C2=A0 arch/arm64/mm/mmu.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 44=20
>>> +++++++++++++++++++++++++++++++++++++++++
>>> =C2=A0 arch/arm64/mm/pageattr.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 |=C2=A0 9 +++++++--
>>> =C2=A0 include/linux/kfence.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 |=C2=A0 8 ++++++++
>>> =C2=A0 mm/kfence/core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 9 +++++++++
>>> =C2=A0 5 files changed, 70 insertions(+), 2 deletions(-)
>>>
>>> diff --git a/arch/arm64/include/asm/kfence.h=20
>>> b/arch/arm64/include/asm/kfence.h
>>> index aa855c6..f1f9ca2d 100644
>>> --- a/arch/arm64/include/asm/kfence.h
>>> +++ b/arch/arm64/include/asm/kfence.h
>>> @@ -10,6 +10,8 @@
>>> =C2=A0 #include <asm/set_memory.h>
>>> +extern phys_addr_t early_kfence_pool;
>>> +
>>> =C2=A0 static inline bool arch_kfence_init_pool(void) { return true; }
>>> =C2=A0 static inline bool kfence_protect_page(unsigned long addr, bool=
=20
>>> protect)
>>> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
>>> index 6f9d889..7fbf2ed 100644
>>> --- a/arch/arm64/mm/mmu.c
>>> +++ b/arch/arm64/mm/mmu.c
>>> @@ -24,6 +24,7 @@
>>> =C2=A0 #include <linux/mm.h>
>>> =C2=A0 #include <linux/vmalloc.h>
>>> =C2=A0 #include <linux/set_memory.h>
>>> +#include <linux/kfence.h>
>>> =C2=A0 #include <asm/barrier.h>
>>> =C2=A0 #include <asm/cputype.h>
>>> @@ -38,6 +39,7 @@
>>> =C2=A0 #include <asm/ptdump.h>
>>> =C2=A0 #include <asm/tlbflush.h>
>>> =C2=A0 #include <asm/pgalloc.h>
>>> +#include <asm/kfence.h>
>>> =C2=A0 #define NO_BLOCK_MAPPINGS=C2=A0=C2=A0=C2=A0 BIT(0)
>>> =C2=A0 #define NO_CONT_MAPPINGS=C2=A0=C2=A0=C2=A0 BIT(1)
>>> @@ -525,6 +527,33 @@ static int __init enable_crash_mem_map(char *arg)
>>> =C2=A0 }
>>> =C2=A0 early_param("crashkernel", enable_crash_mem_map);
>>> +#ifdef CONFIG_KFENCE
>>> +
>>> +static phys_addr_t arm64_kfence_alloc_pool(void)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0 phys_addr_t kfence_pool;
>>> +
>>> +=C2=A0=C2=A0=C2=A0 if (!kfence_sample_interval)
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>>> +
>>
>> Are you sure that kernel commandline param are processed this early?
>> AFAICS, start_kernel()->parse_args() process the kernel arguments. We
>> are here before that. without your patch, mm_init() which takes care of
>> allocating kfence memory is called after parse_args().
>>
>> Can you check your patch with kfence.sample_interval=3D0 appended to
>> kernel commandline?
>>
>=20
> Thanks Pavan. I have tried and you're correct. Previously I thought it's=
=20
> parsed by the way:
> setup_arch()->parse_early_param(earlier)->parse_early_options->=20
> do_early_param
> Unfortunately seems not take effect.
>=20
> Then the only way left is we always allocate the kfence pool early? as=20
> we can't get sample_invertal at this early stage.

 From logs, it seems early param can take effect before doing linear=20
mapping set up. Let me think about it :) Thanks for pointing this out!

>=20
>>> +=C2=A0=C2=A0=C2=A0 kfence_pool =3D memblock_phys_alloc(KFENCE_POOL_SIZ=
E, PAGE_SIZE);
>>> +=C2=A0=C2=A0=C2=A0 if (!kfence_pool)
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pr_err("failed to allocate =
kfence pool\n");
>>> +
>> For whatever reason, if this allocation fails, what should be done? We
>> end up not calling kfence_set_pool(). kfence_alloc_pool() is going to
>> attempt allocation again but we did not setup page granularity. That
>> means, we are enabling KFENCE without meeting pre-conditions. Can you
>> check this?
>=20
> In this scenario, early_kfence_pool should be false(0) and we will end=20
> up using page granularity mapping? should be fine IMO.
>=20
>>
>>> +=C2=A0=C2=A0=C2=A0 return kfence_pool;
>>> +}
>>> +
>>
>> Thanks,
>> Pavan
>=20
> Thanks,
> Zhenhua

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/a851cf97-cc7f-08c4-9b06-548783cb90e5%40quicinc.com.
