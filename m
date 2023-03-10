Return-Path: <kasan-dev+bncBDVL3PXJZILBBCHRVOQAMGQEAVTHQEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id A48ED6B3A6C
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Mar 2023 10:29:46 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id v10-20020a056602058a00b007076e06ba3dsf2217296iox.20
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Mar 2023 01:29:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678440585; cv=pass;
        d=google.com; s=arc-20160816;
        b=sx1j8yrRijDt0H+TC91EU8WToCfvPr70rPhqltjt1dMGM+TIOQ7pGWa9VPQVVglwi3
         9IqDEtAsjcRJ8Dx0jBsMPQKWy/UqIlj4cCDHKewVtIcaqW9gWk+4Kw83tFbW9empgYf1
         HfvRFlGOWGGh2I+krb3R5ZYeOoWjQkLVNkEZyMx44y71IZTqID6dOKai2pdZOIkuASLn
         Jd2nJj4k8uB66/47cNDEzTcaTw93MrGb7TmhdPovbkt/nI2uz1OXgVjASMlmZvTFEvL1
         HtsRKHlQH33EmLUGitz7JMODljcGPITgLhItCPpHBc2kiivJ2FxU/rrTbQs2GOqOuzIs
         JfGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=Zdn1GkOZr2WFLXg6scvr5PPbddFJsrMX4oTnSNkQ7HM=;
        b=jK0AKtmNEbwmN1/BPruYBLJ97gd99ZeJQ5AqC9RGc0OW5Zh88swLQdfHxLKvlcIJEU
         Pned/q9/fy8qnn8lFfO16a4QNAMQXirivAfVb7Iy5ihJRpSAePiQIPzaJDgFkkeQsG0l
         XxQeAwjMmozefUV0hWznW/m+XVsoxPLnUML7uYZEQ/5e7tU2nla8N8bXlbscStTKlcuz
         Wzmrx6XJakf4JMq6EufG0TaxmjLIE52v/jKSNEb2qWqd8jMJjRCswJbGmntW7uaOnjXy
         D7z9JqGIo25O7CCXeYvv9oZ0/WIl3LTk5kFv0QTZkiMmmjNAfkIdikRCrE67sr8nkCvv
         qtXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=ROtSz69D;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678440585;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Zdn1GkOZr2WFLXg6scvr5PPbddFJsrMX4oTnSNkQ7HM=;
        b=DnxJfy02cMUOeH17ra07FrJom8A6Q2mNmLzQFfAhV05Y+4dynWYSSeMjGtmjtDA2LP
         Kn6OhFIuceEtoRPsv1JyHIIWbpIFM9sPyprpmrxP/jRVUMiZN7jf+7wnuKxSlN03Ci8V
         bEC2pHlDEc0bUIhxzgrDmrNBIg6Pc7ElJIGdBrf73faZTt1SJiQXHY2uraPOtRdSHs8M
         vr052t6DnH8S7YEVXx+7dptz0SfOVIhaH+IbJbs9KhJopjln+KhYX5udHDADbAVAbS1j
         5K+l/7Q9r2rO+4kp2o/LCM5VnuZ826ic80YuSEXs26wYASDkUEilvzZVG0rBu1B3Ln6M
         h2dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678440585;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Zdn1GkOZr2WFLXg6scvr5PPbddFJsrMX4oTnSNkQ7HM=;
        b=hy+FRtWgY1wcEPNfmCeAqkd8oa9OcgJXVrISJ9OWo2PG2qwyFI0vBjIFrDnF7itlM+
         7EMFCYstkPaR12GNRjlOJzU4ewE8+HaXX02XHeuik+FkohTZW0BHwy4SdLjPECvlHno/
         qdApAwewgCy5cAZA5eTEFQXhxRx1kilyFaCHvZ+yG3mzEq2lWnYO06hyHLDfXSV4nA6M
         aQ0twcq+IqESKUXLp7sacn4sRksZLbu5EkqDQsL+1xgSJ0LBo4LqodYnqmdM+jidcZAV
         HWHr4ZPDIX56XtfB6CwPEJ2pja/e93yNtkoZyoAEOrEHUGUZAURXR+Ga/xRxWnOwl71X
         o9aw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXNiG2dHavGxiHAsloO05hZk0Z8rEoKQrGEMz53h/AmKMQRmfl1
	Cs2uPCmLWFoSyGMkjT0v0xQ=
X-Google-Smtp-Source: AK7set9kGQgs9KA19rBRGte55X+AumJY/l2epGdCDVQhnJJfnvOtgC5hPq32BXn2BuOO0llev5g5rA==
X-Received: by 2002:a92:c5c2:0:b0:315:8de2:2163 with SMTP id s2-20020a92c5c2000000b003158de22163mr11662826ilt.5.1678440585045;
        Fri, 10 Mar 2023 01:29:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d3c8:0:b0:315:e39c:90ef with SMTP id c8-20020a92d3c8000000b00315e39c90efls1155767ilh.6.-pod-prod-gmail;
 Fri, 10 Mar 2023 01:29:44 -0800 (PST)
X-Received: by 2002:a92:cda3:0:b0:317:97ab:e5ca with SMTP id g3-20020a92cda3000000b0031797abe5camr18322042ild.9.1678440584415;
        Fri, 10 Mar 2023 01:29:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678440584; cv=none;
        d=google.com; s=arc-20160816;
        b=Ywg/flTBQo3aET+ufl16t40wMACoTkXPXYmDulBsba2rFy8AZHcO3nciFpGSgdu6Mx
         JLw9+Yp07q09zRzn8Tap0ck1I1XuyMowlKuKjuz69E8/oSIWDjyLMqLJgnLQrV4OpTRV
         qkOhQoYlNYqXkSiVhhDYh8Lji/Sgo5P82885Znl3Z9lt6Nk1GwcruzzWz2onjSM1gdU8
         UBc+Ms2zcoSH799U7Zff4b1a1gN05nD6ob5QAY4Au0wGdqolI4+Le5np+3rKWJ/GzzDD
         6F+vYo+JzHvJwHxTMgYR2d/6nPn+74ZuQIGoiTssrOUeEu/zmjhpNj+lYvOROkWcxo6u
         D9Tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=36SY5d1GG8v8iH/GYRU2asdPqj5l46qJiLE0fvgiPQE=;
        b=kLMhszeFXIPSPmJwJzQ64g/tg/QMZG/Ab47Xh9hQ3BVYa1KOzklrjPhsKSj8TuanqX
         2oOgmALB1yLdJYEr0R9ldzZGhG8mtHVvI60/lcHxSAm3oQ6+hK4XKi4fRRcj7Kbc1jTZ
         ifaoa/8g7aYqC75h2JbWPwvG/JC+JZhO0bR0L6qLddiiqDySlhcXKk4qzhlPwwepYoaw
         OX4F3e129BJjNILAoXsC69HUswi37U7Sm9srEULMedP8jTmdlvSueWRpn6FD52t87W3R
         x7BbyKAglBHghIZMQnXxsWxOzcVIAb9Ijs4yEUDf8gjLTMFwhJ9VNUUOTM6K9zifP01+
         qLWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=ROtSz69D;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id z9-20020a926509000000b0031580b246e4si102231ilb.2.2023.03.10.01.29.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Mar 2023 01:29:44 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279870.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32A7HTkL013807;
	Fri, 10 Mar 2023 09:29:40 GMT
Received: from nalasppmta03.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3p7pm11n3c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 10 Mar 2023 09:29:40 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA03.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32A9TcKP019099
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 10 Mar 2023 09:29:38 GMT
Received: from [10.253.32.183] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Fri, 10 Mar
 2023 01:29:34 -0800
Message-ID: <4dc71eb5-a5eb-d081-a73f-544b63e52537@quicinc.com>
Date: Fri, 10 Mar 2023 17:29:31 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
Subject: Re: [PATCH v3] mm,kfence: decouple kfence from page granularity
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
References: <1678413750-6329-1-git-send-email-quic_zhenhuah@quicinc.com>
 <5251f2a0-95bf-3330-6524-ec5716cc3d29@huawei.com>
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <5251f2a0-95bf-3330-6524-ec5716cc3d29@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: MzIfZmvHY_nEOC4_0bL-AiY66vQ3g7hp
X-Proofpoint-ORIG-GUID: MzIfZmvHY_nEOC4_0bL-AiY66vQ3g7hp
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-10_03,2023-03-09_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0
 lowpriorityscore=0 adultscore=0 suspectscore=0 clxscore=1011 bulkscore=0
 mlxlogscore=999 priorityscore=1501 mlxscore=0 spamscore=0 phishscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2303100071
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=ROtSz69D;       spf=pass
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

Appreciate Kefeng for your review!

On 2023/3/10 10:56, Kefeng Wang wrote:
>=20
> Hi Zhenhua,
>=20
> On 2023/3/10 10:02, Zhenhua Huang wrote:
>> Kfence only needs its pool to be mapped as page granularity, previous
>> judgement was a bit over protected. Decouple it from judgement and do
>> page granularity mapping for kfence pool only [1].
>>
>> To implement this, also relocate the kfence pool allocation before the
>> linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
>> addr, __kfence_pool is to be set after linear mapping set up.
>>
> We do the same way in our 5.10 kernel, a minor comment below,

Yeah.. low memory device can benefit from this.

>=20
>> LINK: [1]=20
>> https://lore.kernel.org/linux-arm-kernel/1675750519-1064-1-git-send-emai=
l-quic_zhenhuah@quicinc.com/T/
>> Suggested-by: Mark Rutland <mark.rutland@arm.com>
>> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
>> ---
>> =C2=A0 arch/arm64/mm/mmu.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 44=20
>> ++++++++++++++++++++++++++++++++++++++++++++
>> =C2=A0 arch/arm64/mm/pageattr.c |=C2=A0 5 ++---
>> =C2=A0 include/linux/kfence.h=C2=A0=C2=A0 |=C2=A0 8 ++++++++
>> =C2=A0 mm/kfence/core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
|=C2=A0 9 +++++++++
>> =C2=A0 4 files changed, 63 insertions(+), 3 deletions(-)
>>
>> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
>> index 6f9d889..9f06a29e 100644
>> --- a/arch/arm64/mm/mmu.c
>> +++ b/arch/arm64/mm/mmu.c
>> @@ -24,6 +24,7 @@
>> =C2=A0 #include <linux/mm.h>
>> =C2=A0 #include <linux/vmalloc.h>
>> =C2=A0 #include <linux/set_memory.h>
>> +#include <linux/kfence.h>
>> =C2=A0 #include <asm/barrier.h>
>> =C2=A0 #include <asm/cputype.h>
>> @@ -525,6 +526,33 @@ static int __init enable_crash_mem_map(char *arg)
>> =C2=A0 }
>> =C2=A0 early_param("crashkernel", enable_crash_mem_map);
>> +#ifdef CONFIG_KFENCE
>> +
>> +static phys_addr_t arm64_kfence_alloc_pool(void)
>> +{
>> +=C2=A0=C2=A0=C2=A0 phys_addr_t kfence_pool =3D 0;
>=20
> The kfence_pool is no need to be initialized.

Done

>=20
>> +
>> +=C2=A0=C2=A0=C2=A0 if (!kfence_sample_interval)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return (phys_addr_t)NULL;
>=20
> And one more missing case, kfence support late int, see commit
> b33f778bba5e ("kfence: alloc kfence_pool after system startup"),
> this changes will break this feature, we add a new cmdline to alloc
> kfence_pool regardless of kfence_sample_interval value, maybe there some
> other way to deal with this issue.

Yeah, Thanks for reminder. It seems we need only to avoid the case which=20
allocating pool later. kfence_pool also seems only to be allocated once,=20
and once allocated, will not be freed any more. So how about we raise=20
another change, like you mentioned bootargs indicating using feature of=20
b33f778bba5e ("kfence: alloc kfence_pool after system startup").
1. in arm64_kfence_alloc_pool():
    if (!kfence_sample_interval && !bootargs)
              return 0;
    else
              allocate pool
2. also do the check in late allocation,like
    if (do_allocation_late && !bootargs)
              BUG();

>=20
>> +
>> +=C2=A0=C2=A0=C2=A0 kfence_pool =3D memblock_phys_alloc(KFENCE_POOL_SIZE=
, PAGE_SIZE);
>> +=C2=A0=C2=A0=C2=A0 if (!kfence_pool) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pr_err("failed to allocate k=
fence pool\n");
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return (phys_addr_t)NULL;
>=20
> no need this return;

Done

>=20
>> +=C2=A0=C2=A0=C2=A0 }
>=20
>> +
>> +=C2=A0=C2=A0=C2=A0 return kfence_pool;
>> +}
>> +
>> +#else
>> +
>> +static phys_addr_t arm64_kfence_alloc_pool(void)
>> +{
>> +=C2=A0=C2=A0=C2=A0 return (phys_addr_t)NULL;
>> +}
>> +
>> +#endif
>> +
>=20
> I like all of '(phys_addr_t)NULL' to 0

I've tried, yeah, seems no warning. Updated.

>=20
>> =C2=A0 static void __init map_mem(pgd_t *pgdp)
>> =C2=A0 {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 static const u64 direct_map_end =3D _PAGE=
_END(VA_BITS_MIN);
>> @@ -532,6 +560,7 @@ static void __init map_mem(pgd_t *pgdp)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t kernel_end =3D __pa_symbol(__=
init_begin);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t start, end;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int flags =3D NO_EXEC_MAPPINGS;
>> +=C2=A0=C2=A0=C2=A0 phys_addr_t kfence_pool =3D 0;
>=20
> it's no need to be initialized too.

Done

>=20
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 u64 i;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
>> @@ -564,6 +593,10 @@ static void __init map_mem(pgd_t *pgdp)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> =C2=A0 #endif
>> +=C2=A0=C2=A0=C2=A0 kfence_pool =3D arm64_kfence_alloc_pool();
>> +=C2=A0=C2=A0=C2=A0 if (kfence_pool)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memblock_mark_nomap(kfence_p=
ool, KFENCE_POOL_SIZE);
>> +
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* map all the memory banks */
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 for_each_mem_range(i, &start, &end) {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (start >=3D en=
d)
>> @@ -608,6 +641,17 @@ static void __init map_mem(pgd_t *pgdp)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> =C2=A0 #endif
>> +
>> +=C2=A0=C2=A0=C2=A0 /* Kfence pool needs page-level mapping */
>> +=C2=A0=C2=A0=C2=A0 if (kfence_pool) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __map_memblock(pgdp, kfence_=
pool,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfen=
ce_pool + KFENCE_POOL_SIZE,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgpr=
ot_tagged(PAGE_KERNEL),
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 NO_B=
LOCK_MAPPINGS | NO_CONT_MAPPINGS);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memblock_clear_nomap(kfence_=
pool, KFENCE_POOL_SIZE);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* kfence_pool really mapped=
 now */
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfence_set_pool(kfence_pool)=
;
>> +=C2=A0=C2=A0=C2=A0 }
>> =C2=A0 }
>=20

Addressed above comments, I've raised V4 patchset, please help review:)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/4dc71eb5-a5eb-d081-a73f-544b63e52537%40quicinc.com.
