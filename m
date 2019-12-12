Return-Path: <kasan-dev+bncBC5L5P75YUERBHU6ZDXQKGQEHSVSZZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id B8CBF11C9FE
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 10:57:50 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id i17sf654894wmd.1
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 01:57:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576144670; cv=pass;
        d=google.com; s=arc-20160816;
        b=rPtLbmtmxQKjnfG9dNh9fN00lrCBdKMXo6rARGR5tRYl1xZ8OGBnj07wjXgJrI6c8p
         6XFBQVnUqsMMIcniU3tcgRGRvtpwwcjsJHBdP9qzrtnDHNP5GCy0K8F+niY85a5BGoGe
         l6ga4EOLJc7N7ABK4oiv0tC5k88YqboMFdG9RBVGMWwWx2jRdyIulZ/hqV8uVs2KVZxR
         kGXydNQpGj0BHVXhyolmSKmICMm7H/fclXunCHpsBWVagedDwRkDytQVLV8rSuUUiBZD
         RAvm6lyaU/NvYCtkFRytgM0aPIalgF5iFeUF81/VDFNhvVW9VaTmeCGb4W3XohG5K1RP
         Z+Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:to:subject
         :sender:dkim-signature;
        bh=CNAz5Xu4LhuEEbRZ39lezXhxWxzqkyd2JZXhveCOacA=;
        b=tC4rE5oZVf4kQlY0ZLYx9hq2lrr5h3OaHRCpTdGC+0d24Hybg3fFSGKLTkT21m/0+v
         zHRd/SBi5b/lUmglF9+xg0d5G/4aX7DO+8cfyEeC+gGaJ5JogcG3mo8T6V3oNiTR3sKp
         D/h10U7frYC77w4+UmnpONKhoCNf4VfWDApwgxn8A5zx6oRdg4roem58ibL9zoCGLx/h
         WvZ5KkZmAyLKVKMu+kvEC4M5NKXU0Xp4JLSGN7JQQ/WWznErRJjMXexoyPBG7+BnMf16
         DUKMZa95EcETFE4wl+y/oY8VyKNxUUQVmZJQlbTppZj/oa1cPZvUQXvA0HBrrjAtBSKw
         s99g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CNAz5Xu4LhuEEbRZ39lezXhxWxzqkyd2JZXhveCOacA=;
        b=TLhnWavWtScrASaFT6PqGHloHKrMQ61foB3V8czZy2NHv03QL6k88JxgqWOZiEYLYz
         QtvNt/iVh10Q7W36ySH/liy8Rafgr1uoO77iCcvstVmmWjMeDn+NQDP6LL61YaRoRW9Y
         Te+dxXj9/V44MIZz15vWnOzXAPNPDcfp0D1Ti4ITTHQL1Bn/XdxexecIffo6Nb9Z8TwF
         vSY1Hf7SRJaRtEP04iUcfGcnKBFp/IJnbcr5Q1nc075TBa4ZKwkGNh4+SEZj8KzFKvov
         SiaJklM+XvjBYl+quFYzufbATwJMRQvXCJOBQYb7sI6RYdIBsZzb3dPr1M1SMSz3t0Gd
         z2KA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CNAz5Xu4LhuEEbRZ39lezXhxWxzqkyd2JZXhveCOacA=;
        b=WD+vHS43bQbh8kXXfEuFil6ra2kFXCxNudCT4bv8CRd08Szprmzgxla1wE52ciEf5W
         38nDXT47graNgdngFcklfOM+XKm1sfV6dWOKispjgJBvuujgEsg6IHQMGZfgi55iGyqS
         s05dZcv489e0xBdBdwdNFt5f2Mvt/RxUPtBMU3YmtEu32Qx7SWYHVTmTY4SZJIOD90wi
         uRqpYOMsHUCpkxMfr2TmncTR8Dy6YMj00vaCmvFitGQVj7sb5+jTDrL4aXif4iKqU8aO
         pUpxlx6yiqRN3dhGLXe7n7hs4G6eC74yYRtUrxr3htffNEn4/Y9gsSrVajtbTqF3eq0S
         jlfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVLUkVrhWarJ960CjkD0LUGsoqoE4tsuvgMICDvegWfJMOqGZVk
	OTeQpF4Cwp7rdQ9ZmuSxIjQ=
X-Google-Smtp-Source: APXvYqxuQeZSOGbJma5ZGCZy2Hx1p2XJBYD62H5wEqf7+I0YekAMQile3CIXCeEjon/nBDyRmwfhVw==
X-Received: by 2002:a5d:488c:: with SMTP id g12mr5155717wrq.67.1576144670382;
        Thu, 12 Dec 2019 01:57:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6912:: with SMTP id t18ls1910915wru.7.gmail; Thu, 12 Dec
 2019 01:57:49 -0800 (PST)
X-Received: by 2002:adf:c147:: with SMTP id w7mr5334458wre.389.1576144669888;
        Thu, 12 Dec 2019 01:57:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576144669; cv=none;
        d=google.com; s=arc-20160816;
        b=x8vbePZ8YsJ/iRihAnFKOZ3msKKjba7lEi48GGNLPiVOW9UehX85lRWOkjC6zK5BCd
         TFUYO3M/04Hb4Vfnu+e6MlpwsO+KGY0CkuWZwPcLKNhjLCEWbdYfAyu6ZUp74pN9RZB2
         38ZBJXC/WtCkAKL9mqRD4kbMhJv6lH5aDcFrG4pXnC2CSUVBck74ypPX2RgHJ/LeHFSw
         ymRvLGWAkVdp6DpwAUQDSAGWBI9oIAiTeJxJf9ewvy4J0WM3gD0vbkunt5oHLAxWY/oD
         u3qITcoWkdrRdDxfDo+/ydaut9Vm/Y0+O6H6bWSsPyVe0o1kfFtYGGV24qkSnaasFbiE
         aYQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject;
        bh=saIL5uEJI5P9qia1ysht0sf7XW4M7qQT3cTu2c67mDM=;
        b=bXbqA2FgN9Wvnt30+ZwWRHEMWPJLeepZIzLE0znPgK6mOSD7XRgLoAL7lR02FWj73V
         4I3DWMEsUOldjeB1puThbo6beiHiTzmYcIFI7wD7QmSWN2LI4epVNzImesnWruPKLVDj
         YJpkVSPBDafnAPVOKVcfZdiUwBJhdk7SGkN0BGIRdJfon4CXbK0UGYzK/ZbV7ybmBnxb
         8os4taMOE3EL6Y5MFhFumhYby04gXCQQiRenilYN6f1YMx4h56SLwD7zDN4zD896/HSd
         bK2z42Jr1p2xH/A9vrpqYdKZR97VgbkuTFP8L6AoLtF6hwU6Hp8pTJICKGTucWkjARYs
         8Vwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id x5si49255wmk.1.2019.12.12.01.57.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Dec 2019 01:57:49 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from dhcp-172-16-25-5.sw.ru ([172.16.25.5])
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1ifLDd-00051z-5a; Thu, 12 Dec 2019 12:57:13 +0300
Subject: Re: [PATCH v2 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
To: Daniel Axtens <dja@axtens.net>, Balbir Singh <bsingharora@gmail.com>,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org,
 linux-xtensa@linux-xtensa.org, linux-arch@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com,
 christophe.leroy@c-s.fr, aneesh.kumar@linux.ibm.com,
 Dmitry Vyukov <dvyukov@google.com>
References: <20191210044714.27265-1-dja@axtens.net>
 <20191210044714.27265-5-dja@axtens.net>
 <71751e27-e9c5-f685-7a13-ca2e007214bc@gmail.com>
 <875zincu8a.fsf@dja-thinkpad.axtens.net>
 <2e0f21e6-7552-815b-1bf3-b54b0fc5caa9@gmail.com>
 <87wob3aqis.fsf@dja-thinkpad.axtens.net>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <023d59f1-c007-e153-9893-3231a4caf7d1@virtuozzo.com>
Date: Thu, 12 Dec 2019 12:56:56 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.3.0
MIME-Version: 1.0
In-Reply-To: <87wob3aqis.fsf@dja-thinkpad.axtens.net>
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

On 12/11/19 5:24 PM, Daniel Axtens wrote:
> Hi Balbir,
> 
>>>>> +Discontiguous memory can occur when you have a machine with memory spread
>>>>> +across multiple nodes. For example, on a Talos II with 64GB of RAM:
>>>>> +
>>>>> + - 32GB runs from 0x0 to 0x0000_0008_0000_0000,
>>>>> + - then there's a gap,
>>>>> + - then the final 32GB runs from 0x0000_2000_0000_0000 to 0x0000_2008_0000_0000
>>>>> +
>>>>> +This can create _significant_ issues:
>>>>> +
>>>>> + - If we try to treat the machine as having 64GB of _contiguous_ RAM, we would
>>>>> +   assume that ran from 0x0 to 0x0000_0010_0000_0000. We'd then reserve the
>>>>> +   last 1/8th - 0x0000_000e_0000_0000 to 0x0000_0010_0000_0000 as the shadow
>>>>> +   region. But when we try to access any of that, we'll try to access pages
>>>>> +   that are not physically present.
>>>>> +
>>>>
>>>> If we reserved memory for KASAN from each node (discontig region), we might survive
>>>> this no? May be we need NUMA aware KASAN? That might be a generic change, just thinking
>>>> out loud.
>>>
>>> The challenge is that - AIUI - in inline instrumentation, the compiler
>>> doesn't generate calls to things like __asan_loadN and
>>> __asan_storeN. Instead it uses -fasan-shadow-offset to compute the
>>> checks, and only calls the __asan_report* family of functions if it
>>> detects an issue. This also matches what I can observe with objdump
>>> across outline and inline instrumentation settings.
>>>
>>> This means that for this sort of thing to work we would need to either
>>> drop back to out-of-line calls, or teach the compiler how to use a
>>> nonlinear, NUMA aware mem-to-shadow mapping.
>>
>> Yes, out of line is expensive, but seems to work well for all use cases.
> 
> I'm not sure this is true. Looking at scripts/Makefile.kasan, allocas,
> stacks and globals will only be instrumented if you can provide
> KASAN_SHADOW_OFFSET. In the case you're proposing, we can't provide a
> static offset. I _think_ this is a compiler limitation, where some of
> those instrumentations only work/make sense with a static offset, but
> perhaps that's not right? Dmitry and Andrey, can you shed some light on
> this?
> 

There is no code in the kernel is poisoning/unpoisoning
redzones/variables on stack. It's because it's always done by the compiler, it inserts
some code in prologue/epilogue of every function.
So compiler needs to know the shadow offset which will be used to poison/unpoison
stack frames.

There is no such kind of limitation on globals instrumentation. The only reason globals
instrumentation depends on -fasan-shadow-offset is because there was some bug related to
globals in old gcc version which didn't support -fasan-shadow-offset.


If you want stack instrumentation with not standard mem-to-shadow mapping, the options are:
1. Patch compiler to make it possible the poisoning/unpoisonig of stack frames via function calls.
2. Use out-line instrumentation and do whatever mem-to-shadow mapping you want, but keep all kernel
stacks in some special place for which standard mem-to-shadow mapping (addr >>3 +offset)
works.


> Also, as it currently stands, the speed difference between inline and
> outline is approximately 2x, and given that we'd like to run this
> full-time in syzkaller I think there is value in trading off speed for
> some limitations.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/023d59f1-c007-e153-9893-3231a4caf7d1%40virtuozzo.com.
