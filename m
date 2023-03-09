Return-Path: <kasan-dev+bncBDVL3PXJZILBBEX3U6QAMGQEKU6UIQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id F03756B28F2
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Mar 2023 16:38:59 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id q15-20020a63d60f000000b00502e1c551aasf660395pgg.21
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 07:38:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678376338; cv=pass;
        d=google.com; s=arc-20160816;
        b=NTcweiyNqgNpbEhz5d8b5rEB56BWWMbZ9OIF2tMyt5tm+/FIUVELk+Jic8IHP3OXGT
         JLP1fqQJpK94RVicuSJvOFbcjtU+JvxuQMPM7e042QauZVMymhSMCLaHXWpphsFa/Wpb
         MSS9RojCYpubUuUwldnhK7P1QIuzUGtNen4ji9EytVSE9HLWyPRLJU6MK/QW+zt/Hm8O
         +hadGbHCAPYz70F8HjLsXkHGAqZSWai2eJplTM9vBZ/XZYezHS/ic30lcZT4A26g4nNt
         rEeYjrVc+m/UfNPGEKjCWux6NdeYJ2Q/8XLO6USZjEIOEL6Nm3BJMmW/pcQNjubCdei5
         fGCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=MLd+sDSOBECQT6sqLDwXitxgFqF7m3Q2f6lrIcwoB68=;
        b=ZN/0dk5r7TQECKep65jKqLYjUWABjE+Vy3YmEyywXqXH5wM6CTTzy34jLLEIhMdEqs
         bjXhn7xMsmkoqTTejEYQE5KdkuwCTmbGCfZ/T0DY0VexF/BmUuM8jLJBg16M2i4bd/Ao
         lv7LpBqhsTXxlWHvDwlVp/i5xzWzHPYlJKiimkkQSNIAViDVIIL5kycOMjZ3F9EQ7lPt
         appaax2l+fsJvneg0+8VFmsGsjHXCjHGTnqxQFvRm1DbLwlCBiLrRMwxeQ1xBmiS6M9i
         S3kS6VmoE2l5JrP2bKWkMdIyYW4dFf5aBgDH+ddB8RX51wSHIMfRJ1EjJ+TCDJksARH/
         tEaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=KAllfzh2;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678376338;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MLd+sDSOBECQT6sqLDwXitxgFqF7m3Q2f6lrIcwoB68=;
        b=ePY7Ac26+Hg1NktlVS0KARaJod56ZIssZ8uXEM053ew3a/uviHmxwsNoNpYGWl4Cg/
         Yjr5gMXADfb0hFS3W6FrtvAJVsSxGYfwu0a6wQ30vdSgyrc70lAFK/C7T2TFe5ybpuVC
         Cx6TIOR9r7PkoYZLL10LE41+mwBLTCQc8boeHV3owZO1Zg/Vg6Y9h4/tYSeH5UIGe4kK
         zlKBpho7/gYqMyzwRCv2zesCYDAn7p7Z17PjNsrgkjnhUVbCpqUjeVASmaB5FhOgZP0o
         0BHDqJkrFsmCz9nKTbz+l7HqLdKKC26XNZM6nUFgQO4eFAuZ4qSrf18WxY/L698J9UCF
         3D7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678376338;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MLd+sDSOBECQT6sqLDwXitxgFqF7m3Q2f6lrIcwoB68=;
        b=4MloKanAKjbaGHkrYRFUWCqSZrbkBRaZ9rqjuegnUFfYuaNeHaJn23YOpQUbSgXRhZ
         QFPpriPZEcRx7GcvcEbof9ldEza58VzNYFS0Vk6J7GfLbHtX4vNnouot9a1Flrs8AWrW
         7IVCteQZZxoR/WwFV5nhJRjnm1+1ge0dQZCxO5O1U4OFYv0lCeAe9aFQQsq5ppuxj/am
         7rAmAVZp4oOnIAXYh2aXENFT1fjIY8FPwMLilCjvAg6AwWhLwi4jqDEi9PaePAXm0H+g
         smYWn6DwVH0lkPVg3xJ2AXEtJoOXNgC40vPuI0bsB5yRG4BLi6rJHko6qOEEXRkMDDhO
         dBgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVMP++T8x/xbKSljuYgqKWkaT1QHDhMokLSnEaYCnMZofHfQD6S
	YQstwQtE641ht0Ewlw4O578=
X-Google-Smtp-Source: AK7set+Ko/VM7WRoZxlXfidNLNFUXlCuRSga3Evs292ojPv+R4z+ing/AivO+5w52wOxvE6PwuQhoA==
X-Received: by 2002:a17:903:25cc:b0:19c:1748:25d9 with SMTP id jc12-20020a17090325cc00b0019c174825d9mr8297512plb.9.1678376338238;
        Thu, 09 Mar 2023 07:38:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5ac7:b0:237:7ef0:5b8 with SMTP id
 n65-20020a17090a5ac700b002377ef005b8ls4569984pji.3.-pod-canary-gmail; Thu, 09
 Mar 2023 07:38:57 -0800 (PST)
X-Received: by 2002:a17:90a:1d1:b0:237:2edb:d4e3 with SMTP id 17-20020a17090a01d100b002372edbd4e3mr2437019pjd.27.1678376337390;
        Thu, 09 Mar 2023 07:38:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678376337; cv=none;
        d=google.com; s=arc-20160816;
        b=NHuIBowfdfkFSGLy7vUqamj6R7YLaz7pY2G1cox+tMDed6+Og0iySHwXPsWl5H+dd/
         /NwRNEAwa7hsFCDR+LF+MsfUFM6DN1ALbezML1WFeY78o8k0PeMeQjhHj9MvqoAH08FL
         /+xg3d7+RDTqbscNvRhSSoghY/48Nl7+1DYWJjC+tHuk313xcmFXcVqCHwTLGQPrSf+u
         BIrEu62s5RNMYViKWzM6zLjJa7nMfQQmLbZwVFkplavjamrq1bjNxsMAhUm/g1SlR13i
         BpgM39V+i3gBcJOiy338kIjgoNEAsz1/NlYEd9DDnBK/BEK5/xMLwsDtNzBBP5H7+3cF
         8CUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=AYIRtoWFboOFtBFZyeFYqp6QnxOiw1kg1yPvAfxdN+c=;
        b=00NXsEu7tpkhGoiOt3YkfLZjZtpU+X8G7UBGothTd8oPXawX80cR2BBwnfVju5zQI8
         qeHzK4o/bKTBX/K6AiTlfy20prk4vNYMHpwr/fs9rerMcphSkLtPifl+fLuGswG/Bm3h
         cvliAeeglxxxsMC3sZ4vzmcUHLGBHUCtZ2VLnWS9gd5Wef4Z6pcHvtzpWS+uN4Bd0Y7u
         sEXprKdGfvIfmSQ+l6j07A03bXIFkkfMRZnSyS1g/f9lhc1cmNhCYeyHwmDqLHJZxwHS
         fgY85qFpPXbfTdlqLnbm7upflefYNm6zC7TY0fb4eL5gPBTuRC3/BUvjx1PhTljK8+Ir
         RKog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=KAllfzh2;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id f23-20020a17090ace1700b002347fe543c0si11413pju.1.2023.03.09.07.38.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Mar 2023 07:38:57 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279872.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 329C67bt007017;
	Thu, 9 Mar 2023 15:38:53 GMT
Received: from nalasppmta03.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3p6vrmuetp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 09 Mar 2023 15:38:52 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA03.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 329FcpHJ023219
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 9 Mar 2023 15:38:51 GMT
Received: from [10.253.32.183] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Thu, 9 Mar 2023
 07:38:47 -0800
Message-ID: <9142bfe9-4ec8-13fe-7e19-fd35821afe8f@quicinc.com>
Date: Thu, 9 Mar 2023 23:38:44 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
Subject: Re: [PATCH] mm,kfence: decouple kfence from page granularity mapping
 judgement
Content-Language: en-US
To: Marco Elver <elver@google.com>
CC: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <dvyukov@google.com>, <akpm@linux-foundation.org>,
        <robin.murphy@arm.com>, <mark.rutland@arm.com>, <jianyong.wu@arm.com>,
        <james.morse@arm.com>, <linux-arm-kernel@lists.infradead.org>,
        <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
        <quic_pkondeti@quicinc.com>, <quic_guptap@quicinc.com>,
        <quic_tingweiz@quicinc.com>
References: <1678349122-19279-1-git-send-email-quic_zhenhuah@quicinc.com>
 <CANpmjNOah6gSB_mRvhsK_9DpBtiYinRd5z34PU+tOFgSqXB8Sw@mail.gmail.com>
 <706340ef-1745-c1e4-be4d-358d5db4c05e@quicinc.com>
 <CANpmjNP64OSJgnYyfrijJMdkBNhsvVM9hmwLXOkKJAxoZJV=tg@mail.gmail.com>
 <3e8606e4-0585-70fa-433d-75bf115aa191@quicinc.com>
 <CANpmjNOT9kk00nps2vcZ8_Zuh+m1zVpReT+k28U4iD7iOC5cQw@mail.gmail.com>
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <CANpmjNOT9kk00nps2vcZ8_Zuh+m1zVpReT+k28U4iD7iOC5cQw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: WWtGiyOMv62IvZBRtJdgWj_45yDmXOG1
X-Proofpoint-GUID: WWtGiyOMv62IvZBRtJdgWj_45yDmXOG1
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-09_08,2023-03-09_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 bulkscore=0
 mlxscore=0 malwarescore=0 suspectscore=0 adultscore=0 phishscore=0
 clxscore=1015 priorityscore=1501 lowpriorityscore=0 impostorscore=0
 mlxlogscore=849 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2303090123
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=KAllfzh2;       spf=pass
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



On 2023/3/9 19:38, Marco Elver wrote:
> On Thu, 9 Mar 2023 at 12:26, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
> [...]
>>> Ah right - well, you can initialize __kfence_pool however you like
>>> within arm64 init code. Just teaching kfence_alloc_pool() to do
>>> nothing if it's already initialized should be enough. Within
>>> arch/arm64/mm/mmu.c it might be nice to factor out some bits into a
>>> helper like arm64_kfence_alloc_pool(), but would just stick to
>>> whatever is simplest.
>>
>> Many thanks Marco. Let me conclude as following:
>> 1. put arm64_kfence_alloc_pool() within arch/arm64/mm/mmu.c as it's
>> arch_ specific codes.
>> 2. leave kfence_set_pool() to set _kfence_pool within kfence driver, as
>> it may become common part.
>>
>> The reason we still need #2 is because _kfence_pool only can be used
>> after mapping set up, it must be late than pool allocation. Do you have
>> any further suggestion?
> 
> I don't mind kfence_set_pool() if it helps avoid some #ifdef CONFIG_KFENCE.
> 
> However, do note that __kfence_pool is exported from
> include/linux/kfence.h. Since you guard all the new arm64 code by
> #ifdef CONFIG_KFENCE, kfence_set_pool() doesn't look necessary.
> However, if you do something like:
> 
> #ifdef CONFIG_KFENCE
> ... define arm64_kfence_alloc_pool ...
> #else
> ... define empty arm64_kfence_alloc_pool that returns NULL ...
> #endif
> 
> and make that the only #ifdef CONFIG_KFENCE in the new arm64 code,
> then you need kfence_set_pool(). I think that'd be preferable, so that
> most code is always compile-tested, even if the compiler ends up
> optimizing it out if it's dead code if !CONFIG_KFENCE.

Thanks Marco, good suggestion. I've done like this: only one 
CONFIG_KFENCE now in arch/arm64/mm/mmu.c. I also tested w/ both 
CONFIG_KFENCE and !CONFIG_KFENCE.
Please help review v2 patch :)

> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9142bfe9-4ec8-13fe-7e19-fd35821afe8f%40quicinc.com.
