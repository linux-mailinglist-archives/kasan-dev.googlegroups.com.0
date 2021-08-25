Return-Path: <kasan-dev+bncBCRKFI7J2AJRBANHTCEQMGQEIY2SG5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id CEB823F7258
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 11:55:14 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id c2-20020a17090a558200b001873dcb7f09sf3788065pji.7
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 02:55:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629885313; cv=pass;
        d=google.com; s=arc-20160816;
        b=KDL2NQnkci+yCVXwxpLdkRFWW+mdsVWqqOKiuCHB8ZSxGjsO/9u1Pvnr2dWDy84oIT
         Gew4H7HHbhtdMYufoCcNudd5gwb+hzI80yVl47l4AKXPyJMfxmjnw7ZKdVO+tt7MhSui
         5cov1eBlbc5gaiIwAQ6MU42xuiIUKfqQHIm0efs2fPGwXgM/9tr1k/E4jEWK3XrzpS+E
         Ay5GFqWGGphLwa2t7e1z8D9+zqF0/G4SZ0V0rvE9Xzi2UM5Ktbm82TKdX9WKRcENEgaH
         jgJ8hSp8nCTXTOcKOv3TieXaoGa+IGUVuRozRODwJB9agZyINrS9QTmMjeBuPtx/GJPV
         BmxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=2kOEC5GXjUQtmLLXNpxIGbbiL7U9qG3tHkuIEep79i0=;
        b=WKZF+VD9hyMqilOE43wUeKVrpV/BV7VtKML/EaxCfAzzKps1+/gep9pA8kEPLpyPHc
         zQ/2Dn21GD1hMW6f2Cv7oj/z0alDONe1o1wDENclxkF4DkUTVt1Polqg0EHJSZ2vW1iT
         xi8ugY/n6twFYO38uDsPYEuUGhesolUgQ9fHCNZKqkSASlv2Yh8kx4n0BSqJf0qzICje
         BWPpX00FjgwRGQKfsxKNVuLzdPyZDSEGT5tW4Kn6nuO0WTPzct9UmLTLfW4ligVNQPXH
         Y6FbVUZtepjaVwv7Xm+bb7flDvKz+9nJpVkJXg2ceYtLnDrg1O1c0+p2S6avKHuMBni2
         TXqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2kOEC5GXjUQtmLLXNpxIGbbiL7U9qG3tHkuIEep79i0=;
        b=YxbsuEP2cnv4M61PNDXZ5oPXQ3p/5wtVhvYjqqITrG8Xg2YqU0BXbOsEYaR/JTsnTg
         ngE01N/t19R5KD0dkChsDze0P9GQxhzMnjLBbTEECwGy2wZeGrWIEMK1FmGjR7d0cAPf
         HGcv7pEqalf6I/9VutLZPCnBkjK2fIz+YoGB57YyIM18/kASntLq+qtRbj6POVLAdVEe
         DaQsiX/sYl27F8XweHsDyFylY0fdcNAF+zsp7xOvox55sbJTcuYASQ1G2ZkYu5wQqR0S
         zx1Q1gEiLqzdUbFk3ZU1vcWXA1T9uoTXej/2LoQ/CR6SpZunomrzI8H9pmEup/NKynLV
         Ch/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2kOEC5GXjUQtmLLXNpxIGbbiL7U9qG3tHkuIEep79i0=;
        b=GQG7RIjLv6G9+dMYdeM7Y65TdzTq3QSyfFauP4MZgsXp2ScJzVepfO+U6qiokNeKsq
         VwHjyzG5WxFhUAtiuNKDpS0vTh7p0EOVlpeostSX27T9Akc3/H3CTJCDCemZaFlOb3Ys
         LHOmnEZgOVfJs8630DNt8Yh0kEiZBfRV+xaCrsXXi8HTdOGzDyqmKlm1Qz/ZHLMYwTfm
         suA0dUYGTSH4bUCnFBmaS+sldbRQ05fTWk9/AIhskHrIWifMaFDhNPWWu3jyN2xOZFny
         BWnAE6BrkxgQUjNjuIujofcH8V1feu9EhZzy4oNwBzx5aUdxQNotYJoLzArrrW+wgJQZ
         aS9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530zGNRbThzHi/WSG6Ny3PjRieV1tB54jatDQEBHo7AyqLEzE5Wf
	Vs8yTAIqt0TW6RdVdMLkyn4=
X-Google-Smtp-Source: ABdhPJw5Xn92SLPmvA2+sYJuZXASlNJ24iDAfHMNLZ1XwIYT16IpK1URR+bfs1oCQSOuC7DfEAlcaQ==
X-Received: by 2002:a17:90a:1f49:: with SMTP id y9mr9620626pjy.225.1629885313372;
        Wed, 25 Aug 2021 02:55:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6487:: with SMTP id e7ls766160pgv.7.gmail; Wed, 25 Aug
 2021 02:55:12 -0700 (PDT)
X-Received: by 2002:a63:f959:: with SMTP id q25mr41265997pgk.79.1629885312844;
        Wed, 25 Aug 2021 02:55:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629885312; cv=none;
        d=google.com; s=arc-20160816;
        b=JLJqPapzwYpI6KYis7szIHusUqCxXXbwXdAchNYsRqMHB4vOsUEwy5mP/D0aplKmpr
         N8pryqnM8I8Luej9tUzfWHIW7oxBLV28jci8BSZtFhGrf9fnh2A2bQHpDhXxRrCLoxgp
         rHyUYADbEzLe0cddmnbLOg84s3xmuSLI6IN41B3HqkLFuyABlvJJbnMzkohWIoZvZtbs
         zM5xBNXGY938kreUnuTp9T0twSA1/r+zL5xT9F8vn9QimBKZ/S26Sz/qSYmQ9x4ltP70
         JwzBvCIZyo4hZ8Yek0qmkU0EyPMEteAENBDGMYhKOzJ8VkN/zH+O1Mabuja9qdp6O2r5
         PCBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=A/Ek4Re9cXiSkQ6wCKsBqFoTD3Z5GO/F5412zlAFc5k=;
        b=CM0EqgBJy6OU00dFjneMtpq7E9Y08n84Cn9gi4WW5mr/gCFvs5naImCCvV+tCDySA7
         fYdTaWQn8zDFviEFeuaTz0vSQMIwKWKytj4cU7++J++bFru/u6Hv8irzsXj3M6uXpOSR
         5e0ymVLC5EXdpStRSX/SVoAOsdvAazr6h8fGHTaeqvufoPiZuxTjk0NUsW/BfiYdyJRV
         NIiwDCv63Z+czEsbngsAmrVJulElLoEhV7r7FTq3UwXU9wywKNivzTeHMDSf7F6L0S/o
         d0jMWQL+QQQ8WPdXnO9IEP2Cd1qS91LI5MftZt1v2Gp22iyLprZ7D+y3E8e/NUk7bWTh
         RefQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id m9si1367897pgl.4.2021.08.25.02.55.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Aug 2021 02:55:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.53])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4Gvh7q53XLzbddf;
	Wed, 25 Aug 2021 17:51:19 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 25 Aug 2021 17:55:02 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 25 Aug 2021 17:55:02 +0800
Subject: Re: [PATCH 4/4] mm: kfence: Only load kfence_test when kfence is
 enabled
To: Alexander Potapenko <glider@google.com>
CC: Russell King <linux@armlinux.org.uk>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton
	<akpm@linux-foundation.org>
References: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
 <20210825092116.149975-5-wangkefeng.wang@huawei.com>
 <CAG_fn=X9oaw0zJrcmShNcvd3UsNSFKsH3kSdD5Yx=4Sk_WtNrQ@mail.gmail.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <99daf260-76af-8316-fa9a-a649c8a8d1ab@huawei.com>
Date: Wed, 25 Aug 2021 17:55:01 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <CAG_fn=X9oaw0zJrcmShNcvd3UsNSFKsH3kSdD5Yx=4Sk_WtNrQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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


On 2021/8/25 17:31, Alexander Potapenko wrote:
> On Wed, Aug 25, 2021 at 11:17 AM Kefeng Wang <wangkefeng.wang@huawei.com> wrote:
>> Provide kfence_is_enabled() helper, only load kfence_test module
>> when kfence is enabled.
> What's wrong with the current behavior?
> I think we need at least some way to tell the developer that KFENCE
> does not work, and a failing test seems to be the perfect one.

If the kfence is not enabled, eg kfence.sample_interval=0, kfence_test 
spend too much time,

and all tests will fails. It is meaningless. so better to just skip it ;)

>> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
>> index eb6307c199ea..4087f9f1497e 100644
>> --- a/mm/kfence/kfence_test.c
>> +++ b/mm/kfence/kfence_test.c
>> @@ -847,6 +847,8 @@ static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
>>    */
>>   static int __init kfence_test_init(void)
>>   {
>> +       if (!kfence_is_enabled())

Add a print info here?

>> +               return 0;
>>          /*
>>           * Because we want to be able to build the test as a module, we need to
>>           * iterate through all known tracepoints, since the static registration
>> --
>> 2.26.2
>>
>> --
>> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210825092116.149975-5-wangkefeng.wang%40huawei.com.
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/99daf260-76af-8316-fa9a-a649c8a8d1ab%40huawei.com.
