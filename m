Return-Path: <kasan-dev+bncBDVL3PXJZILBBU6QZ6QAMGQESPMLAEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 389186BE007
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Mar 2023 05:11:01 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id t19-20020a5d8853000000b007530e3e2408sf1931383ios.20
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 21:11:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679026260; cv=pass;
        d=google.com; s=arc-20160816;
        b=yUqCrRXh48T7VD9wz7Du7oxZlOmeqpvuzEMIaUCGkU1ur68aj0o8uzCC/KwbvkiQd9
         lKmmuNaiXXHeup0STFn95s2vHLJ1QPpifrbLQzncwbjfbBaMdWpC+ZbSMoUSsi1N5+gX
         zMVHmqrN/kQ4GaAekGtCqGNLyprRQC8f8M0MGZNhE56CKUbONVX9pNB0S8caEEVRKhRF
         Nuy2x66s4Xc0+GCJqKDCXnK1tmz64SWbxp/c/ulDb1litet70wONF378rMWNXIQRhdRW
         xtBDRWRqdO7slls5k5a4odcQe+w8j9AnHfeI5PKl3qEZKe0uSIx7ek54I6NuNpM8C3H5
         P4YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=NYCpD4CCBbD+hPntdYJZMHGqgoiFjwsotwu5R52/rVk=;
        b=UHW+NYo9U2DNCU7xWA7xF6INJyoKydEHd3QleqY1YQ41qo5KXTB44hF7wTqjAikJnv
         sbEoTNp0RQUDyhmlXYbS0PjtIiGeJh7UjuyfnjpWe8O8GJ7jJlK4SMyIsIUa8wj8dQvm
         REdo+IfkHGZAp7o7jHi2eZvRN5TMarD2zspBA0hiZfdeQ3QpmJp611wpuVKJi+nA8V0z
         IMN1wjMBsOPaVFQpJ6l3fiBetPbZ3kH2073G1liNMHRLQSutglI2CHwMufD+K3Ga+Irt
         5Ndn2oa3VFpzxh9r9ITHcZiq9FGpuoeIHMnXEJw9hKBnkfsI5UzrWvZbcxgGiJLxXcRp
         mCsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b="b2V+k/Dc";
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679026260;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NYCpD4CCBbD+hPntdYJZMHGqgoiFjwsotwu5R52/rVk=;
        b=el3guq4MzgrOf4aZmC9abhflXUs3uo2ZEQLW121xY29uqa/ddY080OCVcAMaRnfnv8
         BC2n0otqDXabg7q62gOIRyw35RvnszMRDZ4+Npg3KFBBqJeg6vYB9ipETx6+J3YjSGjk
         QORemt+FF3PzDbgtu2wMB8Gy/Pthn+126aP0dIiRiflr/biSKUCtJaWo0V98qYuXy71U
         qISQRgAc30j0t8K31o6KHbBkVfktJgCO8JD7ZPem1NCUNi5i23zC9c4CssciAdywJh7E
         V8hpAoj2pWfT+1lQDIk3HXe6m/wcMioIsrBdDsvTv87uXWlSAQYPVUs1YUtdNt0MugkP
         zWsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679026260;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NYCpD4CCBbD+hPntdYJZMHGqgoiFjwsotwu5R52/rVk=;
        b=izXUhcNOJnjHsi827WApxFKq4ALiWN4Sbun/0ypaIMRcKs6XlGX67mOHdlrZLXEfxm
         DtvKHNuZhq+SHG6OZjqqFjH0fMkfPDDMFXlpj6Sm9Ro5iqP8+qsHzI58mG9fA40QORfk
         WV8sCxrCS72Mt3y87ni+rJgZpSuc1SOhX3v7mzEEeHpGMkLsLFyHUXPUK0pP04Voinhv
         jCIjCCZmhHAUyp3gIklUPoXW9onK9Ux1QQO1w+TIvHjQv0oo4ka+UrbHTevoZJWgH7ce
         V0Z7ihWWeUKcKqbOVgM0QY8bT09UGPTZ+N2ZmYknK76FOc3244UMluzySEIpFeT+HI1O
         2+/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWo5CtUW6tF2nLH9hVXE+yDqIGAQzp34XzlXhfNt8eM0himcRLQ
	ug+1Y0LtNyZPMsxBIrnVyTY=
X-Google-Smtp-Source: AK7set+hZWjVz9zk8o9W+F5hHRQUEmbdQ9lqIFynbaRSVzsvVrneWi1NlrFo2OPrnTF3YBB33FkTRw==
X-Received: by 2002:a02:7315:0:b0:3ca:61cc:4bbc with SMTP id y21-20020a027315000000b003ca61cc4bbcmr667503jab.2.1679026260038;
        Thu, 16 Mar 2023 21:11:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c56a:0:b0:314:10d2:cf32 with SMTP id b10-20020a92c56a000000b0031410d2cf32ls931518ilj.7.-pod-prod-gmail;
 Thu, 16 Mar 2023 21:10:59 -0700 (PDT)
X-Received: by 2002:a05:6e02:10e:b0:324:5d02:f9dd with SMTP id t14-20020a056e02010e00b003245d02f9ddmr787529ilm.6.1679026259512;
        Thu, 16 Mar 2023 21:10:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679026259; cv=none;
        d=google.com; s=arc-20160816;
        b=cLWOOOMRS+vsUKk0dTiudhhPL+ZkjEuH7PTeOZXOf/DrwN3qqoYVLfOC3PGw7DBF9u
         Z4JIjWacPdyqEQNZVaYRonJ5pJho9aLcJT87Wyxi7VyoLQrUvKUQ26FeEmI95agrmsU0
         IFbBAR+pwRszo/t5a6aFTTfzt7Zs1LpikaMi7Tx2G9jhNBr2SoLK6gTSLGAROR20IcZs
         5ooiFdx5MzawVaXLNRKA/odcm30PfwN1LecYzG2PQDjPzrr8vETlVyA5VVoovrtHml3S
         ko5qK2bFQ3Xtf+87RGPnRYHjZPKuoqrM7MozoP/uNoOPzOJgICjtkQhi/QsKCZJ5fIQH
         yaCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=s+1pbwr/Cc4LTRim75vnmUoKCUh3reZCLwfHbyYDJZ4=;
        b=XTceUTFbgY3wvPpLYIUSg7Mw9b2Hg+K5FqW9BNpQzXqWq7jrl3F4pIBgKoS1WuoHS0
         pucL3q0RyFT1E2a6qVnavhxxAJCt3Izr+Pl26RBHlCQg5OI3QEJFmkYE0NFoKNoDl5hC
         loMCb89v+NHmSTF+D7BozStJ9oLcRkkePq+F3kMQXJmFo9w3OcrfYrwRsWsYZgVUwLFm
         J0l5YyonJ2j7jpkRFNU78cn/LiU2o4eAqDGkdzRD2TM7ExzEGRxGE5kLuCn6kZUCLN6v
         WV/N1hi9uGhsSOToFy0nRrYsSKb7JyymlBzpNxP0lTzkCXOOnaJnM8T+EqE99Daanldi
         J/ng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b="b2V+k/Dc";
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id f12-20020a056638168c00b004063285e3f3si149474jat.7.2023.03.16.21.10.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Mar 2023 21:10:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279865.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32H3dhml021094;
	Fri, 17 Mar 2023 04:10:52 GMT
Received: from nalasppmta05.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3pc624hn11-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 17 Mar 2023 04:10:52 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA05.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32H4Apq3005910
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 17 Mar 2023 04:10:51 GMT
Received: from [10.253.39.45] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Thu, 16 Mar
 2023 21:10:47 -0700
Message-ID: <73f9140a-428c-14da-9695-dd0d39e0248e@quicinc.com>
Date: Fri, 17 Mar 2023 12:10:44 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.8.0
Subject: Re: [PATCH v11] mm,kfence: decouple kfence from page granularity
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
References: <1678979429-25815-1-git-send-email-quic_zhenhuah@quicinc.com>
 <CANpmjNPeyEPOfk_OtxHzZhbJ30W1ik_arW4N1fKW6bpZwB0JCA@mail.gmail.com>
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <CANpmjNPeyEPOfk_OtxHzZhbJ30W1ik_arW4N1fKW6bpZwB0JCA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: 1oupcNSA8kTZtaJPyd74k4xNYxU5CQDV
X-Proofpoint-ORIG-GUID: 1oupcNSA8kTZtaJPyd74k4xNYxU5CQDV
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-17_01,2023-03-16_02,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 phishscore=0
 adultscore=0 mlxlogscore=999 priorityscore=1501 spamscore=0 suspectscore=0
 impostorscore=0 mlxscore=0 bulkscore=0 malwarescore=0 lowpriorityscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2303150002
 definitions=main-2303170024
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b="b2V+k/Dc";       spf=pass
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



On 2023/3/17 5:43, Marco Elver wrote:
> On Thu, 16 Mar 2023 at 16:10, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
>>
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
>> Reviewed-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> 
> Reviewed-by: Marco Elver <elver@google.com>
> 
> One question: what happens if the page-granular direct map is
> requested either way, is there any downside with this patch? Does it
> mean map_mem() just does a little extra work it shouldn't have? (Not
> saying that's a problem, just trying to ask you to double-check it's
> ok.)
> 

Yeah.. I think so Marco. Seems the extra work in map_mem() is we did 
judgement there.. Other side is we added one early param.

> However, please also wait for an arm64 maintainer to have a look. I'm
> assuming that because it touches mostly arm64 code, this patch ought
> to go through the arm64 tree?

Yeah, sure. We will wait for arm64 maintainers' comments.

Thanks,
Zhenhua

> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/73f9140a-428c-14da-9695-dd0d39e0248e%40quicinc.com.
