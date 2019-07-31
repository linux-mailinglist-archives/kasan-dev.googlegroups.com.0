Return-Path: <kasan-dev+bncBC5L5P75YUERBQ4UQ7VAKGQEVWTOK6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id F01F37C9D9
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2019 19:05:07 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id n3sf42791083edr.8
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2019 10:05:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564592707; cv=pass;
        d=google.com; s=arc-20160816;
        b=J0TGqrqvBf0KeRFHc58wN8NTyweNMyl1O95a2DWF53fLX4hzQ2p7Z279FrS1aYpSbd
         A0PoRREaTem+UYmdGZziGBfRSsvVCjCbgRkuePBZcLnnHZALFyDoJlGpqG4YtiVWAEnA
         k5ndOhy4s/rolEJN2Z8VXjizGfD9QV+IROGOF2RSYI2Tq6qiObXRrBo1P1UWk5678eNc
         tiwN/NNRNptc+ExiU1T68WscawxWCIBosxBK3QUSawaWircFQ9XveQhv1SL9RYoRuJDK
         cE/sXQGlcn8YjKpisw9T3Edd9wpJczFW2ONo/6jVUE522NtvOtyKPUYtjzpMQ0iyOLE+
         0e4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=r86Eu2abhHxvxy3QwjKe7uOHIDS6btRA96/HCojAd2c=;
        b=C/DYcxYO396Bs9ERuj96/H126hWM334AiDlfVnbE94Q8tz39qNKvxCXF3KlfR+E6sn
         TBUV1NWrqgG1PYxQEpH0iiJOu1Qn3OYm4g2XXsPBDZbQc8wBV9licoVZqDnPAHfrTV2s
         J1S0maAPgXKV/xiLkmcfLINg3jwjZ7rHsAGv7a8Jd38CS3EgunD20h4wEklajUXqK6Fx
         227pwh2lfGWkwV290uRJMaDk4piWm3XsvUpPkmyB7y7T/sCf8nikuH9c9BGys9h2bYoF
         r/wxntHKDuVfp7eOeUb/HlQk+EraAduniyNkCH7clo6IE2vtuVOoktk+XVAbSjhJSK2Q
         qfEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=r86Eu2abhHxvxy3QwjKe7uOHIDS6btRA96/HCojAd2c=;
        b=UfimxC5jBumKv3Ql4mZialOAFBhNXLT4vsFxEE0oQ3x0P3pcwjWW8YSDtLcFkfSMvM
         Ed6qoxEQ9o1fWKhdgT0GmMTnvviJejRSa4mTEs7jzMp1sR8YZxCoVwnkXTbcidfdtrm0
         0zC7uf4V9GONb+chVT2yqy3EHa3P4FJIlgSycw98Kz7EmCyt/+56sgNfF0c23HzKzCnZ
         fmoQ73Z0/VgxQtteMhHwMdJzvzX7PdmOqCC8rky+tJbhB5PlCXXFJdFGNAWjFSrnYw/f
         t6D0P8dDF9mhkQF7A0SOwswnUmBKPSa1HG3D/cuc/7RSs7XvLFXzjLrOub2Y2clfgosh
         CYKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=r86Eu2abhHxvxy3QwjKe7uOHIDS6btRA96/HCojAd2c=;
        b=sCqgzwf/DC0dP0XSD3pVpYE6zpW/rSOvo17/kveAqd2CKFtqPSzX4TpiK7ZSjFuCcG
         q5eWfJre1F0p38LVVY62pM6PlRDSqXj5fzTVszXXLd3PdAo7LXbVgXSDq1LzpVeM/Tn2
         GEzcLoa/hEUJACRAMp/5i99D/wc7D376zXyRU5TBdbldoeUwuUYf/5LADuZxbZfPncRX
         p/4T4ettouCiUrwN7Mm3P4aM2G8lcWPreotDVOquzFIQLwUQy09BnkzIiVE8T7VXLZvH
         dYFSl2Cn7Shg30Nk1kGIiCJE/YFmIrCiprkPZBNQO2jmDfPPy4UMQV7WZupLOMnKuS37
         lPqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVLqFjnmXo6OFDd8RiXSsifyWCmgpCQYSYzhQfxhNudoP+by6ld
	E6hXjgZ44hv49j8pc7bbXcM=
X-Google-Smtp-Source: APXvYqz4kFCeIMf9cyQj4LqfjQnH1qu2RyS92YzeKfl0OwWwvkeAD7LB1PMLTL0u7Os9r9dDHbDDpQ==
X-Received: by 2002:a50:f98a:: with SMTP id q10mr108336969edn.267.1564592707722;
        Wed, 31 Jul 2019 10:05:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:ac62:: with SMTP id w31ls16249490edc.10.gmail; Wed, 31
 Jul 2019 10:05:07 -0700 (PDT)
X-Received: by 2002:aa7:c3d8:: with SMTP id l24mr110946831edr.58.1564592707211;
        Wed, 31 Jul 2019 10:05:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564592707; cv=none;
        d=google.com; s=arc-20160816;
        b=rd0XBjgf4r/k4XlumHYvYtIHfyN+BF8upF7hXSSlJlJSGFVNGWu3+mWNAEZ/UYJvC+
         bFs/d0kNf8xvPAb27lvLCg9XCJbchkohUodJwQL96i0t1HXh6AY+sDU5G+weWLv6oaZp
         K00bU0ceSe8qZTXJu2yvrHrA/d1g9OATg427X3p12ZFvsA8xLBg0s86QJTpiQncyNrF/
         AkOGPdaefYzp92zaBD13WL162cf5yeejf96RxDSX1+V6Oq/0YlpX7ucyqLZhsRzF4JL8
         Nc1YoWn5BDLBLwDqz5khEZUtF6fqQ8d2+B33hPdw4eFC9nx84WB8uFSjpVY8kVWMUi5m
         PGwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=gLsZksY+gBpgTVjGj1ZFUu3CK/yOt5FqgBnNEXrwvKg=;
        b=MtZMLttdgg4LiyZg3qYMGZgzaBdDq6IGmrRBsGMptvTgTPLJkKZjanX5zMIYCUSOD0
         CQW9cn7nhG07V3PQTJicBeVwmjg6PBOGWMtRbzIhza8oWmxR3txGwlDBneNcWgA4/Oo4
         9a+zQnfKjGP7aEwaxXTweANs4ykf/15TO/efs4ZlWU+xvZNna10cU2P0UNgnYccKeQMB
         1ZRtiEMbbnOyHMihY8yQYdjHiU/jGPKa630MIjlVCtJV9OSpRaDjr7dtwnyDA1iRC6U8
         ON+10r7Kr9RRjTnf1hPLT4P43sIYfOPtRbbOADTgx8TKBkapKwXdTl9S0hwgxMHH46i1
         y73A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id h23si574602edb.2.2019.07.31.10.05.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 31 Jul 2019 10:05:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hss1z-0001ux-M2; Wed, 31 Jul 2019 20:04:51 +0300
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
 Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>,
 Vasily Gorbik <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>,
 "Jason A . Donenfeld" <Jason@zx2c4.com>, Miles Chen
 <miles.chen@mediatek.com>, kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 linux-mediatek@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
 <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
 <1560447999.15814.15.camel@mtksdccf07> <1560479520.15814.34.camel@mtksdccf07>
 <1560744017.15814.49.camel@mtksdccf07>
 <CACT4Y+Y3uS59rXf92ByQuFK_G4v0H8NNnCY1tCbr4V+PaZF3ag@mail.gmail.com>
 <1560774735.15814.54.camel@mtksdccf07> <1561974995.18866.1.camel@mtksdccf07>
 <CACT4Y+aMXTBE0uVkeZz+MuPx3X1nESSBncgkScWvAkciAxP1RA@mail.gmail.com>
 <ebc99ee1-716b-0b18-66ab-4e93de02ce50@virtuozzo.com>
 <1562640832.9077.32.camel@mtksdccf07>
 <d9fd1d5b-9516-b9b9-0670-a1885e79f278@virtuozzo.com>
 <1562839579.5846.12.camel@mtksdccf07>
 <37897fb7-88c1-859a-dfcc-0a5e89a642e0@virtuozzo.com>
 <1563160001.4793.4.camel@mtksdccf07>
 <9ab1871a-2605-ab34-3fd3-4b44a0e17ab7@virtuozzo.com>
 <1563789162.31223.3.camel@mtksdccf07>
 <e62da62a-2a63-3a1c-faeb-9c5561a5170c@virtuozzo.com>
 <1564144097.515.3.camel@mtksdccf07>
 <71df2bd5-7bc8-2c82-ee31-3f68c3b6296d@virtuozzo.com>
 <1564147164.515.10.camel@mtksdccf07>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <f29ee964-cf12-1b5d-e570-1d5baa49a580@virtuozzo.com>
Date: Wed, 31 Jul 2019 20:04:59 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <1564147164.515.10.camel@mtksdccf07>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 7/26/19 4:19 PM, Walter Wu wrote:
> On Fri, 2019-07-26 at 15:52 +0300, Andrey Ryabinin wrote:
>>
>> On 7/26/19 3:28 PM, Walter Wu wrote:
>>> On Fri, 2019-07-26 at 15:00 +0300, Andrey Ryabinin wrote:
>>>>
>>>
>>>>>
>>>>>
>>>>> I remember that there are already the lists which you concern. Maybe we
>>>>> can try to solve those problems one by one.
>>>>>
>>>>> 1. deadlock issue? cause by kmalloc() after kfree()?
>>>>
>>>> smp_call_on_cpu()
>>>
>>>>> 2. decrease allocation fail, to modify GFP_NOWAIT flag to GFP_KERNEL?
>>>>
>>>> No, this is not gonna work. Ideally we shouldn't have any allocations there.
>>>> It's not reliable and it hurts performance.
>>>>
>>> I dont know this meaning, we need create a qobject and put into
>>> quarantine, so may need to call kmem_cache_alloc(), would you agree this
>>> action?
>>>
>>
>> How is this any different from what you have now?
> 
> I originally thought you already agreed the free-list(tag-based
> quarantine) after fix those issue. If no allocation there,

If no allocation there, than it must be somewhere else.
We known exactly the amount of memory we need, so it's possible to preallocate it in advance.


> i think maybe
> only move generic quarantine into tag-based kasan, but its memory
> consumption is more bigger our patch. what do you think?
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f29ee964-cf12-1b5d-e570-1d5baa49a580%40virtuozzo.com.
