Return-Path: <kasan-dev+bncBDVL3PXJZILBB44SZSQAMGQEPBKX7PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 614196BCF46
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 13:20:05 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-176249fbc56sf1100796fac.6
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 05:20:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678969204; cv=pass;
        d=google.com; s=arc-20160816;
        b=KjmjgRtEDIVy5a1zTWPoUN8RBj1GewiM+eOWqRQdUeUrUF8IkPm8ZHNhN2CKYm4yr1
         VqNZZJCM7iaA0Pd2Cz4NG6bsz+bQ6rvwYvplVv6yUmYCPB1luOqvSykrN7FspofBGtkj
         a2BX5cPbpMeqfxQgCz7Od0sFPoOib6TnIud9Gg8/YrZfG4aQCpi1m+KnZXNNG1m8ppn7
         hDBJR4hhIDqn/UPTrk9koDquw25/2EabQ2lAIr0ltfIGKjQ1W5PVdXGgFQnpvF35bs/y
         9vdUnfjkaFGV7XLFe5sXoHFwtVhmMaHwgufL9mYFH7IN6Dq9XLX3b25rkOwHTTU+jktE
         +X3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:references:cc:to:from:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=CFYbMu+PK6e1TdfUILNQqgz0kQHwh2Fs0ju8oNndkMs=;
        b=0Z4iSnSWCgZ4GdjwiyrLvKjpC06ApqYnxV7mVAfXB9tuBeJDmhO2EWe8ok/5/PMX3L
         PqPKJpl3zu/P6iHwqRSNx471MgdE4dRPXP4Uy5jeHuRbALog6Ow/VaR9C/D5dYZ1aSvb
         2MwOSRYYk0mUrWeP4PgXVKP3qbKebNgb+9SZQeOYGCt73Ymmu79bOESl/AjkVzaPpcBz
         G/aNDJdM4zc/YsJGPBUFpr1oIyNL0X0NDJ1s4E4T9yWd0PRjbqpwz6+x2Ih9wtrZhTdm
         m3SrJOrdMq6DUhxJlpoZn+lbW7xtsQas1dKSJIFBsfd0yRkM3E9yrWpunWQZaeSNKAiG
         Zzcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=NDR7e9nT;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678969204;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:references
         :cc:to:from:content-language:subject:user-agent:mime-version:date
         :message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CFYbMu+PK6e1TdfUILNQqgz0kQHwh2Fs0ju8oNndkMs=;
        b=CEqIoXQkgyF1h1nPkPnNxqWSsCCBX6D0jgI2wTVHgOxX2sF/IiwPQqzSox+iyc5a98
         nLxPTI0BgI9LnEasWGHIaCeyYyi87ZI/bmtjSFhfQlsp2PqCvCgkJcjqX3/tRMH6iBns
         VWHx0IK5jeUiOmjlo9gQOuaqx2+jz3byuLo6jdDb4HB0XY5NztUtx1STN4xQBRlwsTDw
         7dkCUMhFEFGyxq1sLBZocpT6fpgmD8+Tzx3F3EjYPkXdQbe7Ag6AOMACQPhUM1f0Zdw4
         rpSpS0UaZuVFrSS7JgvdV2Tog3wDPZZfCNwZyZjYOpYZcIs0IUU9xWF18cU9n9Bo1n4k
         Ub1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678969204;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CFYbMu+PK6e1TdfUILNQqgz0kQHwh2Fs0ju8oNndkMs=;
        b=nlQJqjcQB3DWLiQpc2saGCHgqXkc/rts9nZvBsTo3n7z6QnVyAvn3qY+D+jsPb8lDG
         QXXFp441ht+nxZl4Wf9PKxCeFxkdLD1k6QT4pnOVjKFjLdOYJ81/ntpI8SPiLR7Uhv5F
         lKkDjcLE4bzXnaJ+TycVD9aFe4lzxeaXNze+DVGDETE93l3qMy2CeA655yMaf6/vzCsl
         lk//yRYFalyrmx8PKLTUw0JXjYuUn25RQfXYzYq6qynsR6+mmxiXfb6Ub/wg7E4XZfcp
         1CEXBKHqRjKuvplERtS5BYzoyoD0XzJbDaDDiZt82HA/9tLj6/rcLecY1AXXC8UlYPfZ
         nJDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUDNiUVEC5qph8Hs9VxjD/IJUdf60e+6WYtZD42N5fbfmwUc05t
	WyIKx8pK6DHdT8ViG1cHdvM=
X-Google-Smtp-Source: AK7set/URfaOHnYgNjfvqu6tyk6hn8Fnx7SNKH/gs0y5cGqzads1CaGdQBMwowWvSNv/xdRTy9lQeA==
X-Received: by 2002:a05:6870:1058:b0:17a:b713:63e9 with SMTP id 24-20020a056870105800b0017ab71363e9mr3164298oaj.4.1678969204039;
        Thu, 16 Mar 2023 05:20:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:e999:b0:177:b908:1eda with SMTP id
 r25-20020a056870e99900b00177b9081edals626688oao.1.-pod-prod-gmail; Thu, 16
 Mar 2023 05:20:03 -0700 (PDT)
X-Received: by 2002:a05:6871:413:b0:17a:d863:4cfc with SMTP id d19-20020a056871041300b0017ad8634cfcmr3092464oag.38.1678969203531;
        Thu, 16 Mar 2023 05:20:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678969203; cv=none;
        d=google.com; s=arc-20160816;
        b=p7iPq/kS5fwq+P7mtFJo6vlDAVsl0KU1QHK+wcHqpICa7U65FM9ympE5adDZdhhiOe
         +B2JjjcFbafKxyadL577NLW8nlkGQiht5vdj2xrqKVLahfq+W6wnzmBbtnoooEHm8Vys
         2gMmgClVL1RIGrc4KOHsW0oOlYvgcVFOl6yiQ3BVINJYSvYz6dyCrbGgSMJ3TvO+5Y+/
         tqJi0gaRSYte0DUkez4LuWCR9JKqFaF1+uqLJbZNLRICdcI0I7YX+Cx47/22zCulmH0d
         +2Nw3lc6mOWYO8RHmqI40R0uTeidoWaNQmETXLt5geIqZpVwG0an57vSDvhUcOdSHEAa
         gTJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=AG74fjdSctjP7e/B3IYzY6uBYNMQ0Wgjh9MkmYE2g/4=;
        b=G4bncC14VNfLLoaRdqS8xB5JyYxJPz+8zaNNiuuFZtjBG2IwhnM2TQhafTpwIEtYgx
         znQYQ1If2O6dxQ3NBg507En1AJWTtKsqy0pmIR5uqleTo3eH8RJ3uKj23CkiC1J5cSHh
         fJ/thtenbWH13ChVroc9VeTpzYzYPeqRmZsxNeNuqvLks8M4RjrzCmqtvW06cgw7c9I2
         cLiBZ1byZg2ISnJJz/5NEN0xiGGfkNqrOb9tuHQGI/bPm26Ai+rfaVit86U30Lq16Bk0
         j9ra7WN9OFxYXi2oZCvIA8EsOriYUSBLahPxMFGespbntHDVEt5TSgoSGHlYiXGiQJCs
         uC/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=NDR7e9nT;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id pn12-20020a0568704d0c00b001723959e146si1352376oab.4.2023.03.16.05.20.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Mar 2023 05:20:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279868.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32GAsYWl032638;
	Thu, 16 Mar 2023 12:19:59 GMT
Received: from nalasppmta04.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3pbpya1q4n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Mar 2023 12:19:59 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA04.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32GCJwqH013552
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Mar 2023 12:19:58 GMT
Received: from [10.239.132.245] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Thu, 16 Mar
 2023 05:19:54 -0700
Message-ID: <33aae812-ab0a-d5fb-8211-6ed6f0368b42@quicinc.com>
Date: Thu, 16 Mar 2023 20:19:51 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.8.0
Subject: Re: [PATCH v9] mm,kfence: decouple kfence from page granularity
 mapping judgement
Content-Language: en-US
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
To: Marco Elver <elver@google.com>
CC: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <wangkefeng.wang@huawei.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
References: <1678956620-26103-1-git-send-email-quic_zhenhuah@quicinc.com>
 <ZBLqOv2RTScbydrj@elver.google.com>
 <b47a9bc3-f9d7-77a6-c8d0-977e47f65f4a@quicinc.com>
In-Reply-To: <b47a9bc3-f9d7-77a6-c8d0-977e47f65f4a@quicinc.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: 46-ZSdruD3kHwpCRnPZdVnewAgSYLycm
X-Proofpoint-GUID: 46-ZSdruD3kHwpCRnPZdVnewAgSYLycm
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-16_08,2023-03-16_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 mlxlogscore=999 spamscore=0 phishscore=0 bulkscore=0 impostorscore=0
 adultscore=0 priorityscore=1501 malwarescore=0 suspectscore=0
 clxscore=1015 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2303150002 definitions=main-2303160102
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=NDR7e9nT;       spf=pass
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



On 2023/3/16 18:36, Zhenhua Huang wrote:
>=20
>=20
> On 2023/3/16 18:06, Marco Elver wrote:
>> On Thu, Mar 16, 2023 at 04:50PM +0800, Zhenhua Huang wrote:
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
>>> =C2=A0 arch/arm64/include/asm/kfence.h | 16 +++++++++++
>>> =C2=A0 arch/arm64/mm/mmu.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 59=20
>>> +++++++++++++++++++++++++++++++++++++++++
>>> =C2=A0 arch/arm64/mm/pageattr.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 |=C2=A0 9 +++++--
>>> =C2=A0 include/linux/kfence.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 |=C2=A0 1 +
>>> =C2=A0 mm/kfence/core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 4 +++
>>> =C2=A0 5 files changed, 87 insertions(+), 2 deletions(-)
>>>
>>> diff --git a/arch/arm64/include/asm/kfence.h=20
>>> b/arch/arm64/include/asm/kfence.h
>>> index aa855c6..8143c91 100644
>>> --- a/arch/arm64/include/asm/kfence.h
>>> +++ b/arch/arm64/include/asm/kfence.h
>>> @@ -10,6 +10,22 @@
>>> =C2=A0 #include <asm/set_memory.h>
>>> +extern phys_addr_t early_kfence_pool;
>>
>> This should not be accessible if !CONFIG_KFENCE.
>>
>>> +#ifdef CONFIG_KFENCE
>>> +
>>> +extern char *__kfence_pool;
>>> +static inline void kfence_set_pool(phys_addr_t addr)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0 __kfence_pool =3D phys_to_virt(addr);
>>> +}
>>
>> kfence_set_pool() is redundant if it's for arm64 only, because we know
>> where it's needed, and there you could just access __kfence_pool
>> directly. So let's just remove this function. (Initially I thought you
>> want to provide it generally, also for other architectures.)
>>
>>> +#else
>>> +
>>> +static inline void kfence_set_pool(phys_addr_t addr) { }
>>> +
>>> +#endif
>>> +
>>> =C2=A0 static inline bool arch_kfence_init_pool(void) { return true; }
>> [...]
>>> +#endif
>>> +
>>> +phys_addr_t early_kfence_pool;
>>
>> This variable now exists in non-KFENCE builds, which is wrong.
>>
>>> =C2=A0 static void __init map_mem(pgd_t *pgdp)
>>> =C2=A0 {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 static const u64 direct_map_end =3D _PAG=
E_END(VA_BITS_MIN);
>>> @@ -543,6 +587,10 @@ static void __init map_mem(pgd_t *pgdp)
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON(pgd_index(direct_map_end - =
1) =3D=3D=20
>>> pgd_index(direct_map_end));
>>> +=C2=A0=C2=A0=C2=A0 early_kfence_pool =3D arm64_kfence_alloc_pool();
>>> +=C2=A0=C2=A0=C2=A0 if (early_kfence_pool)
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memblock_mark_nomap(early_k=
fence_pool, KFENCE_POOL_SIZE);
>>> +
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (can_set_direct_map())
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 flags |=3D NO_BL=
OCK_MAPPINGS | NO_CONT_MAPPINGS;
>>> @@ -608,6 +656,17 @@ static void __init map_mem(pgd_t *pgdp)
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>> =C2=A0 #endif
>>> +
>>> +=C2=A0=C2=A0=C2=A0 /* Kfence pool needs page-level mapping */
>>> +=C2=A0=C2=A0=C2=A0 if (early_kfence_pool) {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __map_memblock(pgdp, early_=
kfence_pool,
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ear=
ly_kfence_pool + KFENCE_POOL_SIZE,
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgp=
rot_tagged(PAGE_KERNEL),
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 NO_=
BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memblock_clear_nomap(early_=
kfence_pool, KFENCE_POOL_SIZE);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* kfence_pool really mappe=
d now */
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfence_set_pool(early_kfenc=
e_pool);
>>> +=C2=A0=C2=A0=C2=A0 }
>>
>> This whole piece of code could also be wrapped in another function,
>> which becomes a no-op if !CONFIG_KFENCE. Then you also don't need to
>> provide the KFENCE_POOL_SIZE define for 0 if !CONFIG_KFENCE.
>>
>> [...]
>>> +=C2=A0=C2=A0=C2=A0=C2=A0 *
>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * Kfence pool requires page granularity mappi=
ng also if we init it
>>> +=C2=A0=C2=A0=C2=A0=C2=A0 * late.
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return (rodata_enabled && rodata_full) |=
|=20
>>> debug_pagealloc_enabled() ||
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 IS_ENABLED(CONFIG_KFENCE);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (IS_ENABLED(CONFIG_KFENCE) =
&& !early_kfence_pool);
>>
>> Accessing a non-existent variable if !CONFIG_KFENCE works because the
>> compiler optimizes out the access, but is generally bad style.
>=20
> Hi Marco,
>=20
> Actually my previous intention is not to do separation between KFENCE=20
> and non-KFENCE, instead to ensure early_kfence_pool always to be NULL in=
=20
> non-KFENCE build. That works well from my side w/ and w/o=20
> CONFIG_KFENCE.. but Yes that not clear to have this variable still in=20
> non-Kfence build.
>=20
> Sure, I will follow your suggestion below and tested on my side. Thanks.
>=20
> Thanks,
> Zhenhua
>=20
>>
>>
>> I think the only issue that I have is that the separation between KFENCE
>> and non-KFENCE builds is not great.
>>
>> At the end of the email are is a diff against your patch which would be
>> my suggested changes (while at it, I fixed up a bunch of other issues).
>> Untested, so if you decide to adopt these changes, please test.

Hi Marco,

All below seems well except minor change like we can't define=20
kfence_early_init as __initdata because it is used by non init function=20
like can_set_direct_map. Warning reported:
WARNING: modpost: vmlinux.o: section mismatch in reference:=20
can_set_direct_map (section: .text) -> kfence_early_init (section:=20
.init.data)

I have modified and sent out a new patchset. Please help review.

Thanks,
Zhenhua

>>
>> Thanks,
>> -- Marco
>>
>> ------ >8 ------
>>
>>
>> diff --git a/arch/arm64/include/asm/kfence.h=20
>> b/arch/arm64/include/asm/kfence.h
>> index 8143c91854e1..a81937fae9f6 100644
>> --- a/arch/arm64/include/asm/kfence.h
>> +++ b/arch/arm64/include/asm/kfence.h
>> @@ -10,22 +10,6 @@
>> =C2=A0 #include <asm/set_memory.h>
>> -extern phys_addr_t early_kfence_pool;
>> -
>> -#ifdef CONFIG_KFENCE
>> -
>> -extern char *__kfence_pool;
>> -static inline void kfence_set_pool(phys_addr_t addr)
>> -{
>> -=C2=A0=C2=A0=C2=A0 __kfence_pool =3D phys_to_virt(addr);
>> -}
>> -
>> -#else
>> -
>> -static inline void kfence_set_pool(phys_addr_t addr) { }
>> -
>> -#endif
>> -
>> =C2=A0 static inline bool arch_kfence_init_pool(void) { return true; }
>> =C2=A0 static inline bool kfence_protect_page(unsigned long addr, bool=
=20
>> protect)
>> @@ -35,4 +19,14 @@ static inline bool kfence_protect_page(unsigned=20
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
>> index 61944c7091f0..683958616ac1 100644
>> --- a/arch/arm64/mm/mmu.c
>> +++ b/arch/arm64/mm/mmu.c
>> @@ -528,17 +528,14 @@ static int __init enable_crash_mem_map(char *arg)
>> =C2=A0 early_param("crashkernel", enable_crash_mem_map);
>> =C2=A0 #ifdef CONFIG_KFENCE
>> +bool kfence_early_init =3D !!CONFIG_KFENCE_SAMPLE_INTERVAL;
>> -static bool kfence_early_init __initdata =3D=20
>> !!CONFIG_KFENCE_SAMPLE_INTERVAL;
>> -/*
>> - * early_param can be parsed before linear mapping
>> - * set up
>> - */
>> -static int __init parse_kfence_early_init(char *p)
>> +/* early_param() will be parsed before map_mem() below. */
>> +static int __init parse_kfence_early_init(char *arg)
>> =C2=A0 {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int val;
>> -=C2=A0=C2=A0=C2=A0 if (get_option(&p, &val))
>> +=C2=A0=C2=A0=C2=A0 if (get_option(&arg, &val))
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfence_early_init=
 =3D !!val;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>> =C2=A0 }
>> @@ -552,22 +549,34 @@ static phys_addr_t arm64_kfence_alloc_pool(void)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfence_pool =3D memblock_phys_alloc(KFENC=
E_POOL_SIZE, PAGE_SIZE);
>> -=C2=A0=C2=A0=C2=A0 if (!kfence_pool)
>> +=C2=A0=C2=A0=C2=A0 if (!kfence_pool) {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pr_err("failed to=
 allocate kfence pool\n");
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfence_early_init =3D false;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>> +=C2=A0=C2=A0=C2=A0 }
>> +
>> +=C2=A0=C2=A0=C2=A0 /* Temporarily mark as NOMAP. */
>> +=C2=A0=C2=A0=C2=A0 memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return kfence_pool;
>> =C2=A0 }
>> -#else
>> -
>> -static phys_addr_t arm64_kfence_alloc_pool(void)
>> +static void arm64_kfence_map_pool(phys_addr_t kfence_pool, pgd_t *pgdp)
>> =C2=A0 {
>> -=C2=A0=C2=A0=C2=A0 return 0;
>> -}
>> -
>> -#endif
>> +=C2=A0=C2=A0=C2=A0 if (!kfence_pool)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return;
>> -phys_addr_t early_kfence_pool;
>> +=C2=A0=C2=A0=C2=A0 /* KFENCE pool needs page-level mapping. */
>> +=C2=A0=C2=A0=C2=A0 __map_memblock(pgdp, kfence_pool, kfence_pool + KFEN=
CE_POOL_SIZE,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 pgprot_tagged(PAGE_KERNEL),
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
>> +=C2=A0=C2=A0=C2=A0 memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
>> +=C2=A0=C2=A0=C2=A0 __kfence_pool =3D phys_to_virt(kfence_pool);
>> +}
>> +#else /* CONFIG_KFENCE */
>> +static inline phys_addr_t arm64_kfence_alloc_pool(void) { return 0; }
>> +static inline void arm64_kfence_map_pool(phys_addr_t kfence_pool,=20
>> pgd_t *pgdp) { }
>> +#endif /* CONFIG_KFENCE */
>> =C2=A0 static void __init map_mem(pgd_t *pgdp)
>> =C2=A0 {
>> @@ -575,6 +584,7 @@ static void __init map_mem(pgd_t *pgdp)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t kernel_start =3D __pa_symbol(=
_stext);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t kernel_end =3D __pa_symbol(__=
init_begin);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t start, end;
>> +=C2=A0=C2=A0=C2=A0 phys_addr_t early_kfence_pool;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int flags =3D NO_EXEC_MAPPINGS;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 u64 i;
>> @@ -588,8 +598,6 @@ static void __init map_mem(pgd_t *pgdp)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON(pgd_index(direct_map_end - 1=
) =3D=3D=20
>> pgd_index(direct_map_end));
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 early_kfence_pool =3D arm64_kfence_alloc_=
pool();
>> -=C2=A0=C2=A0=C2=A0 if (early_kfence_pool)
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memblock_mark_nomap(early_kf=
ence_pool, KFENCE_POOL_SIZE);
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (can_set_direct_map())
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 flags |=3D NO_BLO=
CK_MAPPINGS | NO_CONT_MAPPINGS;
>> @@ -656,17 +664,7 @@ static void __init map_mem(pgd_t *pgdp)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> =C2=A0 #endif
>> -
>> -=C2=A0=C2=A0=C2=A0 /* Kfence pool needs page-level mapping */
>> -=C2=A0=C2=A0=C2=A0 if (early_kfence_pool) {
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __map_memblock(pgdp, early_k=
fence_pool,
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 earl=
y_kfence_pool + KFENCE_POOL_SIZE,
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgpr=
ot_tagged(PAGE_KERNEL),
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 NO_B=
LOCK_MAPPINGS | NO_CONT_MAPPINGS);
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memblock_clear_nomap(early_k=
fence_pool, KFENCE_POOL_SIZE);
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* kfence_pool really mapped=
 now */
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kfence_set_pool(early_kfence=
_pool);
>> -=C2=A0=C2=A0=C2=A0 }
>> +=C2=A0=C2=A0=C2=A0 arm64_kfence_map_pool(early_kfence_pool, pgdp);
>> =C2=A0 }
>> =C2=A0 void mark_rodata_ro(void)
>> diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
>> index 7ce5295cc6fb..aa8fd12cc96f 100644
>> --- a/arch/arm64/mm/pageattr.c
>> +++ b/arch/arm64/mm/pageattr.c
>> @@ -7,7 +7,6 @@
>> =C2=A0 #include <linux/module.h>
>> =C2=A0 #include <linux/sched.h>
>> =C2=A0 #include <linux/vmalloc.h>
>> -#include <linux/kfence.h>
>> =C2=A0 #include <asm/cacheflush.h>
>> =C2=A0 #include <asm/set_memory.h>
>> @@ -28,11 +27,10 @@ bool can_set_direct_map(void)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * mapped at page granularity, so th=
at it is possible to
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * protect/unprotect single pages.
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 *
>> -=C2=A0=C2=A0=C2=A0=C2=A0 * Kfence pool requires page granularity mappin=
g also if we init it
>> -=C2=A0=C2=A0=C2=A0=C2=A0 * late.
>> +=C2=A0=C2=A0=C2=A0=C2=A0 * KFENCE pool requires page-granular mapping i=
f initialized late.
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return (rodata_enabled && rodata_full) ||=
=20
>> debug_pagealloc_enabled() ||
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (IS_ENABLED(CONFIG_KFENCE) &=
& !early_kfence_pool);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 arm64_kfen=
ce_can_set_direct_map();
>> =C2=A0 }
>> =C2=A0 static int change_page_range(pte_t *ptep, unsigned long addr, voi=
d=20
>> *data)
>> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
>> index 91cbcc98e293..726857a4b680 100644
>> --- a/include/linux/kfence.h
>> +++ b/include/linux/kfence.h
>> @@ -222,7 +222,6 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp,=20
>> void *object, struct slab *sla
>> =C2=A0 #else /* CONFIG_KFENCE */
>> -#define KFENCE_POOL_SIZE 0
>> =C2=A0 static inline bool is_kfence_address(const void *addr) { return=
=20
>> false; }
>> =C2=A0 static inline void kfence_alloc_pool(void) { }
>> =C2=A0 static inline void kfence_init(void) { }
>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index fab087d39633..e7f22af5e710 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -818,7 +818,7 @@ void __init kfence_alloc_pool(void)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!kfence_sample_interval)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return;
>> -=C2=A0=C2=A0=C2=A0 /* if the pool has already been initialized by arch,=
 skip the=20
>> below */
>> +=C2=A0=C2=A0=C2=A0 /* If the pool has already been initialized by arch,=
 skip the=20
>> below. */
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (__kfence_pool)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return;
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/33aae812-ab0a-d5fb-8211-6ed6f0368b42%40quicinc.com.
