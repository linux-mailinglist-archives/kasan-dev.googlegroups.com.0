Return-Path: <kasan-dev+bncBDVL3PXJZILBBEHVXOQAMGQEGTKPMTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 967C66B73E9
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 11:27:30 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id oa14-20020a17090b1bce00b0023d1b58d3basf582404pjb.4
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 03:27:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678703249; cv=pass;
        d=google.com; s=arc-20160816;
        b=PzM3Gy6YQIVz5WaI4ov1FxISzqsbV2VlIoOs302rKiCQEWemgSq+RNqR/mY6POElRa
         CUkAemBwYT38pvO0pIjh0bWpjz70zDx3Qp/c7jXtNpq1RrK57AtWeSf1zkRK0TALyqXv
         GHpYAXlbdK8JczKuEtrWtf7iB5LB22dv2RmFkGNY159/U8g5b0/GaDezCo9NByPsJxBn
         1no9Wm9dgCPyTHTzpJWasr+gnzW6ZqL0xoAOmupir1dr0LFs5yaIMU93AyMLvApyMD8V
         OAkHM3OSu5ZEg1bo1C+gNeXXRM1uI23hD8/eyEUmKVs/0nIMCtCd6651j90Ebo+7NQzX
         mDOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=lTXM0IdiYgLgnFnDqwzOu0cjBtmKGTbWTDVHF2lxiuU=;
        b=u0Ar8OaU66L0Q7ocLsBAGK5ryyr+dS4+0oIWBuH/NHjI2mB2o9BhJEvOdAPoNtFyEg
         PnDaB9ls8h1XqZteHEqqAR4MVnlAISF9w7RYZCdMwCaYFb4EOUvwBE9FYVSeRSrMYQRK
         iAFfSNccky98xnl/2C/SqbeEn4y0HLQP6ZF7o7mbGYSYGS0lkLcMRlXsMNOnWLqb2OJn
         Vmq2ff/N1r01g7jmiHxN5PCJFWOu5s5IhpCkS3pA4RuoPU6igUgqtfnmFRRCcpnknlAG
         5kTpUyl/7p11RJfpaUOGZ+yGegZHdCGpi4s411x8QYBzzkOKf6mGwhTiDcoOmdhZsVDx
         6KgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=bOlAGVk7;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678703249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lTXM0IdiYgLgnFnDqwzOu0cjBtmKGTbWTDVHF2lxiuU=;
        b=NuMsOXTsiy4Qcb7+E3+Nq9HE6cxofffsEBOPueYECLnc7v6jeiXlfkeU5UEEFmiSwT
         4a0bDy+IV1lYJfmRs4BPMKngvipDm037KuBGjR0vlOD4KXXPI83fuZw0/BGSdSKxZ/jP
         /eSHAGjjL/sk9QHaBl0pHUNgTDVD4+Pq13ta89ae5rwEBNR4m7cl7hxzexwPUUxAp1Qy
         hAEZ2WoqAbJrBaWVBjB9iwzdCzkzDx8eDZf4cGnLxiWdyh1s22oTyYf5dyBE7H/CCk9+
         DmdD1w0Xoi4Z4yIFp0KzwhEL/tnu3W9ldjkDK4idIVO2whduOn9k/KDG2tcE6XXI1n3L
         z+/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678703249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lTXM0IdiYgLgnFnDqwzOu0cjBtmKGTbWTDVHF2lxiuU=;
        b=OMq7dfIleomsV2+5RksiT/B5TKYzMv887p4zgFwWdKiZ11zCnylwPGLe0P3d2jX0YJ
         Or59RiFir5RPiypIl73+tO3/1TEP4AfvCgNYNvy7Avr98xXMP2JSzM/3aVNLkxc7js2a
         6g1IFYU/ukf/q2yW3Jn8AxHEkthg07OwX9Os9G73wOFTV+Mp2qzSP3twQ7yfLWJ1dfYX
         wRWkSjdbYgy38Z94fEOe985e7wRAGj4DjeKf+G48U0KOfQFTDenS3OjF0C8BpR4GSUwg
         v5ydWhgBY3GrO9+y3b4X341d77w0L5CtK0hm3AJ2RKLW6rT2WCbohlnl9yCJSC/g8ICV
         V3HA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWEVvZ6hFIzmjYq40BnLejwQhFvI92WOQ6w4w6ySZeo6DZw2q3o
	crFGs1/Ztfhv6TdDxfML1SU=
X-Google-Smtp-Source: AK7set8PPFZqXIpLpfhBQP/KGLur+tX2IzxrEvrjNt5TkhX56fqdPL9OGW8rcgjb0jaJFJ37RXY0bA==
X-Received: by 2002:a17:902:9a45:b0:19a:b98f:46a0 with SMTP id x5-20020a1709029a4500b0019ab98f46a0mr4210909plv.0.1678703248999;
        Mon, 13 Mar 2023 03:27:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c943:b0:196:751e:4f6e with SMTP id
 i3-20020a170902c94300b00196751e4f6els12106086pla.10.-pod-prod-gmail; Mon, 13
 Mar 2023 03:27:28 -0700 (PDT)
X-Received: by 2002:a17:90b:38c3:b0:237:d44c:5861 with SMTP id nn3-20020a17090b38c300b00237d44c5861mr35622426pjb.12.1678703248176;
        Mon, 13 Mar 2023 03:27:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678703248; cv=none;
        d=google.com; s=arc-20160816;
        b=OnKRYZPBFdW3RgqwZi6GKAu5INECRjW0Bct5Bm5zhmQt/JwXWc53qIqeg+fXlstCoj
         ex8KZSkcZU5jXjbB8zaTxmRLH3GFCTycdsZ6HHEy1DtjfwIaLviUPeJINl5icw4y4lDZ
         HixxLm/rGUgGLkB2cJGWce8peoQvA1X6Ub50LtOiYZgKn92llrz7Ck93/uvTghar3+gz
         piojyAEu1HsjYj52euFoex/zmeTiKtx98uuIqDhenWZsaz8LH+R7T4dcdleuR3WvzJJ1
         mgbmUFZjaCi2L5wdytk45oqaeQ/CdEdjNCNh8pP01yYYfyRqf4e7GXFPS5u1so3Ye7dS
         AT6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=rofOjC9A+Ai///mQWL9wVXqOvBS/3fDbNXwUVpk+DCQ=;
        b=MtjPRd6Z25C8cY0d2hEYGhAVEPAFkcsDXHl+PTU5yilHYH3pJKQi1gm6hhSbzS+D4/
         aIDvcSjRE1kYxRbs1JdR3jfwjq1eHu/MiCumfN+QeEv65g0aA2jicz3VBPwG7+sVz8e7
         H+JsdlUQE1uz3eOTRjL3dU7qTdC5Z5PLHdDapYDZ4F7qzI9B8aXBqLjndJDffdIC1IZ/
         +kDDu4L2ft9yjIGwvdux3hGZTvvnWV8bge/DmfgxKNpPhUI/z0v1JoEtqg+KMvQJvcm7
         NEoHqpxu62K58ftKYbokUQ2ILeLZPSx93VWHuyIPEXvlT1fargOY4okGonOdacIXg8oG
         mbzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=bOlAGVk7;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id ot14-20020a17090b3b4e00b002373b032314si358813pjb.0.2023.03.13.03.27.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Mar 2023 03:27:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279868.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32D9fAAb008657;
	Mon, 13 Mar 2023 10:27:23 GMT
Received: from nalasppmta04.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3p8gysve4e-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 Mar 2023 10:27:23 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA04.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32DARLFM004777
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 Mar 2023 10:27:21 GMT
Received: from [10.239.132.245] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Mon, 13 Mar
 2023 03:27:17 -0700
Message-ID: <148243e5-8dfb-4094-9ebc-b221e2e9c01f@quicinc.com>
Date: Mon, 13 Mar 2023 18:27:15 +0800
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
 <8b44b20d-675c-25d0-6ddb-9b02da1c72d2@quicinc.com>
 <CANpmjNN6sQ+sWBVxn+Oy5Z8VBCAquVUvYwXC1MGKOr7AFkHa3w@mail.gmail.com>
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <CANpmjNN6sQ+sWBVxn+Oy5Z8VBCAquVUvYwXC1MGKOr7AFkHa3w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: l6wPTF02mlGoWqbaOAXACTGE-pIo_OOi
X-Proofpoint-ORIG-GUID: l6wPTF02mlGoWqbaOAXACTGE-pIo_OOi
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-13_02,2023-03-10_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 mlxscore=0
 impostorscore=0 lowpriorityscore=0 malwarescore=0 bulkscore=0
 suspectscore=0 adultscore=0 phishscore=0 priorityscore=1501 clxscore=1015
 mlxlogscore=999 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2303130084
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=bOlAGVk7;       spf=pass
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

Thanks Marco!

On 2023/3/13 17:49, Marco Elver wrote:
> On Mon, 13 Mar 2023 at 10:05, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
>>
>> Thanks Marco!
>>
>> On 2023/3/13 15:50, Marco Elver wrote:
>>> On Mon, 13 Mar 2023 at 06:04, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
>>>>
>>>> Kfence only needs its pool to be mapped as page granularity, previous
>>>> judgement was a bit over protected. From [1], Mark suggested to "just
>>>> map the KFENCE region a page granularity". So I decouple it from judgement
>>>> and do page granularity mapping for kfence pool only.
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
>>>
>>> This patch still breaks the late-init capabilities that Kefeng pointed out.
>>>
>>> I think the only viable option is:
>>>
>>>    1. If KFENCE early init is requested on arm64, do what you're doing here.
>>>
>>>    2. If KFENCE is compiled in, but not enabled, do what was done
>>> before, so it can be enabled late.
>>
>> I'm fine with above solution as well. The Disadvantage is if we want to
>> dynamically disable kfence through kfence_sample_interval, it must be
>> mapped into page granularity still.
>>
>>>
>>> Am I missing an option?
>>>
>>
>> Another option is what Kefeng firstly thought and I had proposed on
>> comments of patchsetV3, actually I wanted to do in an separate patch:
> 
> Please do it in the same patch (or patch series), otherwise we end up
> with a regression.

OK.

> 
>> "
>> So how about we raise another change, like you mentioned bootargs
>> indicating to use late init of b33f778bba5e ("kfence: alloc kfence_pool
> 
> Please avoid introducing another bootarg just for this. It will
> confuse users and will cause serious annoyance (bad UX).

OK, got it.

> 
>> after system startup").
>> 1. in arm64_kfence_alloc_pool():
>>      if (!kfence_sample_interval && !using_late_init)
>>                return 0;
>>      else
>>                allocate pool
> 
> The whole point of late allocation was that the entire pool is _not_
> allocated until it's needed (during late init). So for space-conscious
> users, this option is actually worse.
> 
>> 2. also do the check in late allocation,like
>>      if (do_allocation_late && !using_late_init)
>>                BUG();
> 
> BUG() needs to be avoided. Just because a user used the system wrong,
> should not cause it to crash (WARN instead)... but I'd really prefer
> you avoid introducing another boot arg, because it'll lead to bad UX.
> 
>> "
>> The thought is to allocate pool early as well if we need to
>> using_late_init.
>>
>> Kefeng, Marco,
>>
>> How's your idea?
> 
> I recommend that you just make can_set_direct_map() conditional on
> KFENCE being initialized early or not. With rodata protection most
> arm64 kernels likely pay the page granular direct map cost anyway. And
> for your special usecase where you want to optimize memory use, but
> know that KFENCE is enabled, it'll result in the savings you desire.

Thanks Marco, got your idea. Yeah.. rodata is another over-protection 
case. I will do the change following your suggestion for your review.

> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/148243e5-8dfb-4094-9ebc-b221e2e9c01f%40quicinc.com.
