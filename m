Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBENGT35AKGQEK5S6VGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B725254413
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 13:03:46 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id f67sf1276913ilf.9
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 04:03:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598526225; cv=pass;
        d=google.com; s=arc-20160816;
        b=IS5gCnTMs9crHPZ4qX/irehlwd2a4u8U8mj5myoiNdRZ2hM9YbgAZ7FvF6R8W1g8Xk
         pFfxQdrZqWhxDBoFwZUz0fKg5T5ahuekoVlQOg4DdHWzENJlw58EQXGk3MeS9ebKK9O/
         /kwkFXduUpal8LAMJp0/edDuLX5SjB/spJO6HVbtIVifOqKN+Iro82GULVK+ygXHqpxX
         XA2ihbP65H0a0Dk/fafVwg9rduTcwevedTxzsb7egn5z2Pk1FJ76AEZ36SdK/B5JcxAp
         iOtiRQ8DYNa/hQiTJ5B23LIgBRB3h8IrQl7r2Vo7/To0EP3szp+JQa8MQ74m77NqUH4p
         83Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=el6jNW60jd4deDGfeg/N9c6c0V6YBynj0h3hwRCbCqo=;
        b=L2qTNw91s5FQQDlAlqbnXvt21RL8F12Ne1wU2GGR5LmlienfjAqKrWy6ss326fHtZd
         1WzziDtmTm129OupqBRzzOAnZT79sjYwXSNzUsLnsIkVoxqUk+X2nlXv6m3MYEBajod9
         EdoIcQem/p3PODoHGjhMsNJfwcVIvcKv9OUVnqlmEkHpwTK8vf6PpYWKnhHQPxVNGiBc
         TfxL+4YIiDqUyQ7fBX4laqeb5IJUHwZxEVsHcizMJe7+IgC+zYx0jQ73KNfBkJ/60Tti
         HQfv7M1qcBFZlr4vjG9GekwNvRHCCbcwrVtCKmvcjpV+/bmTsUNhAFYMbuK1KMgLz+N5
         sNkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=el6jNW60jd4deDGfeg/N9c6c0V6YBynj0h3hwRCbCqo=;
        b=ZkXhOS2wpBvRdaFqZwRmhZH5D52LGEwh+/CPbxDkcg3P1KHbl2Ny1466uKht/KNF7L
         OvX/0UboTTMh6q/6TLEk0UGuGhf6kAGT+h/WyQ0qxO7tCymiyJ1ixJdlfIOBLk27p11M
         3waH18x3o6//TROFozrY9aOA1e54PUKbmGTnc1TOvzDvy51L7DboCPlY01873FdwyMV6
         kd2YKd1yHGGs3Srt/BAI01zSCISe29oT3k6338S4/iTV1YWV2TrG1ZlgllDho/9UvIjq
         GUq0h9L2cXfQ7iWES2Lne8s2UvwcDo5HHIl2g6sS+9aYv0IVvP6ljmmc5/rD9kvIkADl
         RCoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=el6jNW60jd4deDGfeg/N9c6c0V6YBynj0h3hwRCbCqo=;
        b=VjQyZCmaFhI2Y5n3J59TnCbPaAlYU0j803aLHuAxj0XOEyjPmXQYO7IUQdYn+TV6aR
         MgLmM2bRoZXzwKd0afkAL/CZ2jle8dtZ2vr/SKE3JyIKIDyyVGAsDK59qNlA7OUoRbEL
         MuE3zkVqJ+B2Wl2ITxV3RT6XyQ8WHoghcz8ePyXq6oeWWQRfFaWZemNP42aN3vnhGaWd
         fQ6lmksfYSLfoaN3/x4I0Kc+vkSLtGm7/zvcu1NMZ75hTUlwL6r8WBRigTCeLSdYRRZH
         QgSbkcM0VZyrYjzdv/ZP1NI4Ex1jFNENztpJeCBRGlYE9TImoWgA6U2MgMuBFX111tWT
         OUaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531L9Qhe3ybimdgy3Mve1zoFZiXoK/zT7IHjCjL8YXhzko7dxF74
	c1u8wgBWsrDR/W+pPishQLk=
X-Google-Smtp-Source: ABdhPJxHGCW316tWIYbqg4Va8RSg4yWfqgDsfLR2Isu05q1BGoH4eRwSIEyr97ZjjFUX3gMEXmWRaw==
X-Received: by 2002:a05:6e02:13e9:: with SMTP id w9mr1708732ilj.211.1598526225506;
        Thu, 27 Aug 2020 04:03:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:8bc4:: with SMTP id i187ls433875ild.2.gmail; Thu, 27 Aug
 2020 04:03:45 -0700 (PDT)
X-Received: by 2002:a92:bb13:: with SMTP id w19mr17228815ili.300.1598526225102;
        Thu, 27 Aug 2020 04:03:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598526225; cv=none;
        d=google.com; s=arc-20160816;
        b=wJphQRff1/ldejs9ADnRLEJqDdFPY1pq34lle2OAUOHyTpQJrcaetYcvQk5527aUM9
         mThRmgHEhtugu8lj+mfas9ORzacUyQz6hnFTlP4goThN/OakP08fkrV4PKfeCfJboCkR
         ar8F8KvsVb7S4DNqPLcfva8e5ubE68/ugSTDP4GY58bmapQkuzyAnOCxJBN2qQFOGTvx
         jd4zN5BNEXzsFLpfLuodxw8++oTx36GJ1TeFXw/lOjkvV/AZxc8wkNFgvEXPh5gzJCht
         SamQIj6FKMCD0eT37//N4eDkA5q3hED4wH0I8wQiVL1+pXgwYZynIYrJtGfgpVPs96pv
         FLuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Rd/tHTlXW8dTpodpayo6Hm5m4V9VVKaJz5d+oRmY7+M=;
        b=NQJO2CUVyYv3RMsxIRjBblxGUnDkmO42B+uBCnYNgn2EnJbN/4PKkyRzfkQBzthfii
         I2YFxkcE6PjSgQRcjnGtPF+ZcqWRqs6h38Z6+Q2q8AWt9kNNgw5GxufA/SwUV7X2LZ8v
         OtfBPCOqEc0RDZzO/AjYC5VwRpgxgE/wF8Hb7+8+lxqvmtgMF3+thzRrPtF7h+rZbirf
         i8e8FF0pPbpwWKs+v54bcW5iXOLO4Npwh39+wL6Vva048EoKEv2Fjn42t3eCOmr4Ox+Z
         BVXwyDkeufqLHYOppB3bjNWhtAZMLBCAA7zfE81Vi7ecx4O2ClizcBtIhqKByh7Qtj/Z
         UV7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l6si24123ild.0.2020.08.27.04.03.45
        for <kasan-dev@googlegroups.com>;
        Thu, 27 Aug 2020 04:03:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id AD5041045;
	Thu, 27 Aug 2020 04:03:44 -0700 (PDT)
Received: from [192.168.1.190] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 858883F68F;
	Thu, 27 Aug 2020 04:03:42 -0700 (PDT)
Subject: Re: [PATCH 26/35] kasan, arm64: Enable TBI EL1
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1597425745.git.andreyknvl@google.com>
 <518da1e5169a4e343caa3c37feed5ad551b77a34.1597425745.git.andreyknvl@google.com>
 <20200827104033.GF29264@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <9c53dfaa-119e-b12e-1a91-1f67f4aef503@arm.com>
Date: Thu, 27 Aug 2020 12:05:55 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200827104033.GF29264@gaia>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
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

On 8/27/20 11:40 AM, Catalin Marinas wrote:
> On Fri, Aug 14, 2020 at 07:27:08PM +0200, Andrey Konovalov wrote:
>> diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
>> index 152d74f2cc9c..6880ddaa5144 100644
>> --- a/arch/arm64/mm/proc.S
>> +++ b/arch/arm64/mm/proc.S
>> @@ -38,7 +38,7 @@
>>  /* PTWs cacheable, inner/outer WBWA */
>>  #define TCR_CACHE_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA
>>  
>> -#ifdef CONFIG_KASAN_SW_TAGS
>> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>>  #define TCR_KASAN_FLAGS TCR_TBI1
>>  #else
>>  #define TCR_KASAN_FLAGS 0
> 
> I prefer to turn TBI1 on only if MTE is present. So on top of the v8
> user series, just do this in __cpu_setup.
> 

Not sure I understand... Enabling TBI1 only if MTE is present would break
KASAN_SW_TAGS which is based on TBI1 but not on MTE.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9c53dfaa-119e-b12e-1a91-1f67f4aef503%40arm.com.
