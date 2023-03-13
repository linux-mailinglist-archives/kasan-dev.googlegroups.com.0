Return-Path: <kasan-dev+bncBDVL3PXJZILBB4G4XKQAMGQEI5ZO2WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F3926B6EA9
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 06:02:42 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id y15-20020a0568301d8f00b006942b6e66d8sf5590273oti.13
        for <lists+kasan-dev@lfdr.de>; Sun, 12 Mar 2023 22:02:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678683761; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pem6dIct58T4KaHr/APQXFTqztGbqiH9k9GlUiOIm/YnqpE9o9oAwMXhCiZT8xEEfi
         IjOIU/TUyhpcrDuOCcE/5R8N/VTv+/Yr/J9qGVHLC5Va/mfwQk1OuqXRshqIOrqnUbIw
         lK2topn2fVeDT18+bQ4fvOET5jq2eeRGmZZUlgXSbpjSdexrlJ4CqLm0du1aVBcn+2gp
         TcvXhwazu9hZ9VFUsTEmi/qcPrT3grzWIg/hjrtvSIwxRq7n4niv4o0dAx5OdeRxGVim
         1NLQ3HtLlRinZcRn+7HFmsSaz3hhzFH197pfBH6w51KoP0c4l9wROYgY4i/h1jXXTTJ/
         5VFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=XOByg3iwRpQl8PVPXVIsG6iyK+Ojvn2Qhi2NytzZrvc=;
        b=Lx55dYJOivgh8VVB/esNNsIS8Rq6XEgmd8QUrPRQoDYTwEJRQhZfQ+nasbIObOqgHJ
         qKvglgPoz64Zti4lpvv/uXP6Kb7HQ8YVEFXya19r7rAihiMIdUPCbk/xGEWJhSEpRDty
         AXz8mOq+phd4b7NDjZpVxKNKx9gmcnvKj4tIXh07uI7WtshAYFXzBUBO7aO6BopXnb9L
         zed2cl/1MuDt7KQdEn7vCPBg1xS18H9G5TzcoouHxEDqba8s/td3lkgwDqEK80bous3Z
         ZTVjUZO7wW3zW1qJZMRIAIWoLpfVXjXtHqnjC1JW/qJwu5jkkMtX89F8HVw9Uuos8HZC
         oMOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=MG7nJJpG;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678683761;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XOByg3iwRpQl8PVPXVIsG6iyK+Ojvn2Qhi2NytzZrvc=;
        b=U0CnHB9/JskSaZ0v05WwXRduLaGNScwT65AsrrgMZg3fF98wR0CIPtRhmhzD1MTr/B
         ncA78G1+fiXxTR8bbkmdiOxMHozcML0aSW2KspPAU/oH4BdcnAN2KyeNqEgtSuasE30R
         Blebqv8kpCXYnNq0VnB2Jcr8J+CJ6q1w9P6VcflT7Qi0khdzlPeFzTcqTx5p3A3eGjo6
         8Y6UB9L6bGeCJ9guqU/UxqBNKv3Bq62qTDfoHLa1L1kKOpY9sXz9oKk0bHvmdQ+xJZiF
         FoQnJctlgeh1XdIBMF4wFNQ2dKUxknPnTHDNoZmOhcAxtuZHB0Rs9uec5HOCPTPYr/9A
         co0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678683761;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XOByg3iwRpQl8PVPXVIsG6iyK+Ojvn2Qhi2NytzZrvc=;
        b=u5NY4XVCPiy0uKO+27/fNaqBpFwz96MwlkrBRP3Nu8bPV97KQyJ9COEXfsBxZ9FaNq
         HpQluYL1MpVtIx7qCbIPwSH7QWUKaix0L3Z1+QV2CZYKK1Xbj4doqCuT+qnoEYNusUF1
         QtYPEg53WhWImBTdjFCtw1gRR0iggIbNrMmvEINiLZXORqOAeGNNt6x2yyK0z5huhHCs
         4cwXQcCn6ws4N022SwSY5/phNIm4lOp8as9zLCgst8A8CaxhAJfOmkfbvMrZ+z3fvnjK
         tcKdyVnO0XTrUX3KChvivLxNPoHa08dt6oBYHu2NC5cfaAH0ghlCAGomaRlAdUZxgPTW
         Oj3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWpTjp/a8Xyb8H869mYcL6/+AQiavpdj6qlb2zaIRvMlJVY5q0s
	ujSY+bSBNQ0suxlqy1pPNtI=
X-Google-Smtp-Source: AK7set/uV3x584IJox8Khs+FNl5ep2Hf5t07I6ESAYj1evl2V9j//cLeS4nyOPhfYOp3GIjen/2+EA==
X-Received: by 2002:a05:6870:d2ab:b0:176:3f64:b0ea with SMTP id d43-20020a056870d2ab00b001763f64b0eamr11702259oae.7.1678683760767;
        Sun, 12 Mar 2023 22:02:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5742:0:b0:525:74c2:ff62 with SMTP id u63-20020a4a5742000000b0052574c2ff62ls703373ooa.4.-pod-prod-gmail;
 Sun, 12 Mar 2023 22:02:40 -0700 (PDT)
X-Received: by 2002:a4a:7518:0:b0:517:9157:9480 with SMTP id j24-20020a4a7518000000b0051791579480mr14611652ooc.4.1678683760269;
        Sun, 12 Mar 2023 22:02:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678683760; cv=none;
        d=google.com; s=arc-20160816;
        b=L6JVs6R4Xg7zW4ou0EHZSUzqFqJSfOP1qtEQvp2DyonWnrS/0rFyTz88S6rgvIYG5N
         d5xG4BT5oFp1w5dauKAtNfSjMconpA9n7WyZbFy1meJB63c3bjLTxb/qkoHSipQi42fp
         U14eWNH7GFn50ztfgQfLtT897ANLsdwZ90coPWluhXNiXV1eUaHYwM9x5eHSA14T87ci
         nh0LbPhHSauWZ3M9CIr/vHIjMFQ+BM4ylZRE8OWbAcngZOAFSqEwgd5uCnmr68mM769g
         YELrYAg+0daVkfHmJXtCkUMQLnIR9DwMXqVXWWCDrHY7zXLPmibBd5yUyNviCV6T+KJG
         DUwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=zlRAjgzGmeNJJ++2QqMF2DHPtCSrvDgTpJJ/Q7dvuIE=;
        b=oQ85kPkOZS6MYr4uzIF3UwdGF52zw6LvwTpPMfR0Y4Ka3Tx/iEwzVXdGEuOsiRiX63
         x810/ZF+6KX5RdO3oKtiqnJyHI3WyHdTPhcMFbMMxThqveTX2Tqpc8pUvwdjVen+5gPJ
         Xgkl1wNuuOtY7UjQcw+GgDA5jx1GH7aJnNzgWDveIsjHjMw/RW1I4ketQoN+1WYE3TAf
         /EiakWnOW/4Dr1QHhvjVd2ZGEQJq/vSezhJxpVnm6suZd38nVBERijeIkz2tNQSQHQNm
         RKJkdZYqUJCGICL2n4uys7KGULWutn2hThtX9eVibfqWRKkNuDoy0eNkdhk9GEuaBaYF
         rSOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=MG7nJJpG;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id r2-20020a4ad4c2000000b005176d876205si681505oos.0.2023.03.12.22.02.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 12 Mar 2023 22:02:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279869.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32D4hZkO014008;
	Mon, 13 Mar 2023 05:02:36 GMT
Received: from nalasppmta03.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3p8gnq3tcy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 Mar 2023 05:02:36 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA03.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32D52Zqa026742
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 Mar 2023 05:02:35 GMT
Received: from [10.239.132.245] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Sun, 12 Mar
 2023 22:02:31 -0700
Message-ID: <f105b2e3-3625-7094-082c-2e17021b42f9@quicinc.com>
Date: Mon, 13 Mar 2023 13:02:29 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.8.0
Subject: Re: [PATCH v4] mm,kfence: decouple kfence from page granularity
 mapping judgement
To: Andrew Morton <akpm@linux-foundation.org>
CC: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
        <elver@google.com>, <dvyukov@google.com>, <robin.murphy@arm.com>,
        <mark.rutland@arm.com>, <jianyong.wu@arm.com>, <james.morse@arm.com>,
        <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
References: <1678440604-796-1-git-send-email-quic_zhenhuah@quicinc.com>
 <20230312140110.4f3571b92a2556767d7667fc@linux-foundation.org>
Content-Language: en-US
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <20230312140110.4f3571b92a2556767d7667fc@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: IFgUprvrHhH4jbUfn3wnINwe6LjKvfU9
X-Proofpoint-ORIG-GUID: IFgUprvrHhH4jbUfn3wnINwe6LjKvfU9
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-12_10,2023-03-10_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 bulkscore=0
 mlxlogscore=999 spamscore=0 phishscore=0 suspectscore=0 lowpriorityscore=0
 priorityscore=1501 adultscore=0 impostorscore=0 clxscore=1015
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2303130040
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=MG7nJJpG;       spf=pass
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

Thanks Andrew!

On 2023/3/13 5:01, Andrew Morton wrote:
> On Fri, 10 Mar 2023 17:30:04 +0800 Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
> 
>> Kfence only needs its pool to be mapped as page granularity, previous
>> judgement was a bit over protected. Decouple it from judgement and do
>> page granularity mapping for kfence pool only [1].
>>
>> To implement this, also relocate the kfence pool allocation before the
>> linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
>> addr, __kfence_pool is to be set after linear mapping set up.
> 
> Why make this change?  What are the benefits?  What are the user
> visible effects?
> 
>> LINK: [1] https://lore.kernel.org/linux-arm-kernel/1675750519-1064-1-git-send-email-quic_zhenhuah@quicinc.com/T/
> 
> Chasing the links indicates that "page-granular mapping costed more (2M
> per 1GB) memory".  Please spell all this out in this patch's changelog.

Yeah, let me update these and also my test outcome in changelog to make 
it clear~! Thanks.

> 
> btw. this format:
> 
> Link: https://lore.kernel.org/linux-arm-kernel/1675750519-1064-1-git-send-email-quic_zhenhuah@quicinc.com/T/ [1]
> 
> is conventional.

Do you mean it was not directly pointing to Mark's suggestion? let me 
update to: 
https://lore.kernel.org/linux-arm-kernel/Y+IsdrvDNILA59UN@FVFF77S0Q05N/

> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f105b2e3-3625-7094-082c-2e17021b42f9%40quicinc.com.
