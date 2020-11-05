Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBLERSD6QKGQEG2DPIFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id B655F2A8085
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 15:14:05 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id p15sf1007725plr.2
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 06:14:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604585644; cv=pass;
        d=google.com; s=arc-20160816;
        b=tX3VLzyUZdpICbIFJBQvIL3//Bar0B3iQVYoMLa2liyWTlVRk1pvwwt/YSDKaklYqW
         z8Beve0hKcZKfJ8kDuU5K5MnFriL2yOzg459TFUgnIbM7NXGDpfogKDEuoiHxGgkM6+o
         TjkVix/YWJpJnCyeaxikGqGpY/XoYKN8pf1UT4gLZEbcRGBWTvKh5SE7FjyXzrxCaRSu
         w5PNNJn6qrHd7+zII5jaE87EMlxYjH80SYeTJXPS77W7cGYXrL8jlkII770pMoBSTS+B
         1BEWIB2FZuifLs/ODfATk1chyeF7R6YSlnfJZ9kk0lyDUyY+ykTYMYAdFlQqXz/Sec5Z
         C6+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=TiNmKw14aEcM/R3VachPWjp+ilbCBTLii3M3/6z4K7o=;
        b=Onkhsv7sz9Qakx0vecDVIjD4xjbodPHewiCqPoiVXeqdQS7k2UQ9Zh5usqoojR8lgD
         fUlBIh9C5QGGQFLhrXhjEpZ989brEvJGQezoRUkypPHc/o0khCm7r6B6yGBqvfy3uSPN
         v8A0uZj7Yj8cEGZ9RctliLugwG7f4QW1wc3gHEJEymDWOEFdS1MSmUWZS4b9vR+YWZNd
         fqOIsp24KiOFUtT+mID+puTUc2kMHXohZ/9G499Gml/QoP0h2qEbcA96oZcv8tN1CfDJ
         jieB0O2GlME2Qo3r/8+BKJYhg7HbOLTKJW5jyFgJOSxjCvdFX/fMB3hdi6LPkPVUUdq+
         qTWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TiNmKw14aEcM/R3VachPWjp+ilbCBTLii3M3/6z4K7o=;
        b=Ib/rzicm1WcP6OcQGBOrLlJq7MMWhtjfKcxVkthXewvhksUFnb0th1A/+82miZZ2sI
         aTaKyieV5MdMDub000ybPh1yH1l4fXaB0wQC7Mcdn4tVQDG5gpsUoF+vU8FByHSTWYLS
         jLocSPV5JEqIqfAj1+wgHDgPBWANeNuAmJN8MjGmOGYFX09fUWnaov+rXnEEwNS6tpWq
         fOB0JjhGdEKxt+459MtbrWZwWkXXa/zHj5+MelvZwD6yWcYiP56veeItL4zAqUCEbIQF
         4Db6TGwX0FBPD4aNYoCG6IFfBup7lHnMvBDF/KYfsj+9mNrpXe18Zs4eXeN+Uawx+eU+
         Zw9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TiNmKw14aEcM/R3VachPWjp+ilbCBTLii3M3/6z4K7o=;
        b=UXCQsK5na5zk1tFR1KqMavbrqI/u698+vlOr9Ue1Ds2mn5ldEex/HN9htujc1LA1bs
         35nsayrxNy0ZPtk5X6NRSR6rbjSIBtEe7oUPfmEyEWKWXBT06yVm+OOvUs6QIzzk1/o4
         eBOvy8PUb5X87mrgvqefUJ2ESfLMblfu8C3OpB2Iulp9udA9uICeDH9af/3r+b5KtRMw
         OX0oRe9NlbTwLDQ07hST+tecm62zodTmnz2sUoWe1imQm0yXON7ZGs50vrh+T0XpUOAL
         KtFJYNCb+NwQ2GbuJADeePstwaG8oNAai+FhBrXfkCQfiICTQ8yxEsLs3f6tjfHq5HU/
         C5lg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531rhOTtAqtl14VK21Dgq+d9Mun5eS0x+4acGH+9XBKJ0KQrLfoH
	3Nq/TjtegibRzLHUa4dCdKY=
X-Google-Smtp-Source: ABdhPJxZvpfo6GtAUlsNJa55bpWqr35KQtbafz3jOKRS28E40hO8MHC7Z2ou79PntTj8CAxhfpoTlA==
X-Received: by 2002:a63:65c5:: with SMTP id z188mr2585323pgb.139.1604585644178;
        Thu, 05 Nov 2020 06:14:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8495:: with SMTP id k143ls835916pfd.11.gmail; Thu, 05
 Nov 2020 06:14:03 -0800 (PST)
X-Received: by 2002:a63:4855:: with SMTP id x21mr2593147pgk.382.1604585643675;
        Thu, 05 Nov 2020 06:14:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604585643; cv=none;
        d=google.com; s=arc-20160816;
        b=0ahGcy3gWkIAYrpOKsE1P9LjzgKnnBMYGL/AUXXZXqg2bI3xfVNX1xgpMpyFpY3Ony
         lT4ouoKRBg85ONhJVSm/daZOzdjlG8WbMq/BXaNGbf/FDrRtNXdLgL4xiasakgJS43qA
         rhXgCojZThwoIgwmhWHPog0QKZFlII1Up9Vt+Ynz68M75OXIWvzHrXzAK2UBspFsrMEn
         n+xWYu4BYosLI/KaxlCoGsGp+lH5dRrW9d1nPQiBEPlfDFNO02h9m1g5drg+tzSRX3J1
         skbnQWmKx2NlswDnt9oGANqs8u5VZ1MFu5hXLbh83Plkew/uFm8lcjJOzlfZ8hMLHG5I
         vrug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=KJui/J8Njil7Yx6hHB3WMhFoyDAcP7al0OmVm/Xhb4Y=;
        b=ELl5Swb7z7rK5j4NKyRA6pD42LYkhgWbvWAmriSFv6XDyGn0D9GkFzYKzRSOmew+OM
         vThXKoZbEpq+qPsd57m4PCJYE8cA1pFjWObMID7y/PD+XmJcrygX+UpChip4Uwx4QH5V
         zAx2fF1vjNATAJ6qToP/gedF8HGsdWndrfG6FPqI4h73jkqdn+F7wfkFf2CGkM7q4Bwk
         fQqxzqU+lxDwH2oVaR80ozW+eWX4oDawtASllYnWZisoGsEA8HiOX1Bqh2d+b7pQJoFf
         stTcDYw0vFUuYsGrFMgBC9lLc6004TDhR7SzLzuADS9UfuNI1DBFsy+jK5Cz0TckdSvJ
         8n+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p12si112143pjn.1.2020.11.05.06.14.03
        for <kasan-dev@googlegroups.com>;
        Thu, 05 Nov 2020 06:14:03 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 894BA14BF;
	Thu,  5 Nov 2020 06:14:02 -0800 (PST)
Received: from [10.37.12.41] (unknown [10.37.12.41])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id C55673F719;
	Thu,  5 Nov 2020 06:13:59 -0800 (PST)
Subject: Re: [PATCH v8 30/43] arm64: kasan: Allow enabling in-kernel MTE
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
 Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 LKML <linux-kernel@vger.kernel.org>
References: <cover.1604531793.git.andreyknvl@google.com>
 <5e3c76cac4b161fe39e3fc8ace614400bc2fb5b1.1604531793.git.andreyknvl@google.com>
 <58aae616-f1be-d626-de16-af48cc2512b0@arm.com>
 <CAAeHK+yfQJbHLP0ja=_qnEugyrtQFMgRyw3Z1ZOeu=NVPNCFgg@mail.gmail.com>
 <1ef3f645-8b91-cfcf-811e-85123fea90fa@arm.com>
 <CAAeHK+zuJtMbUK75TEFSmLjpu8h-wTfkra1ZGV533shYKEYi6g@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <090ab218-8566-772b-648f-00001413fef2@arm.com>
Date: Thu, 5 Nov 2020 14:17:00 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+zuJtMbUK75TEFSmLjpu8h-wTfkra1ZGV533shYKEYi6g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 11/5/20 12:14 PM, Andrey Konovalov wrote:
> On Thu, Nov 5, 2020 at 12:39 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>
>> On 11/5/20 11:35 AM, Andrey Konovalov wrote:
>>> This will work. Any preference on the name of this function?
>>>
>>
>> I called it in my current iteration mte_enable(), and calling it from
>> cpu_enable_mte().
>>
>>> Alternatively we can rename mte_init_tags() to something else and let
>>> it handle both RRND and sync/async.
>>
>> This is an option but then you need to change the name of kasan_init_tags and
>> the init_tags indirection name as well. I would go for the simpler and just
>> splitting the function as per above.
>>
>> What do you think?
> 
> OK, let's split. mte_enable() as a name sounds good to me. Both
> functions will still be called one right after another from
> kasan_init_hw_tags (as it's now called) though. I think the name
> works, as it means initializing the hw_tags mode, not just the tags.
> 

I agree. When you finish with v9, could you please provide a tree with both the
sets on top similar to [1]? I would like to repeat the tests (ltp + kselftests)
and even to rebase my async code on top of it since we are aligning with the
development.

[1] https://github.com/xairy/linux/tree/up-boot-mte-v1

> Will do in v9.
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/090ab218-8566-772b-648f-00001413fef2%40arm.com.
