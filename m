Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBCNPT35AKGQEMEMRNCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id E214325443B
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 13:22:50 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id x2sf4002192pfd.8
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 04:22:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598527369; cv=pass;
        d=google.com; s=arc-20160816;
        b=tV2XpD+4iV78ihydoEft1v73Mjr+vs+0vyNcPx70ceM1jE7wlHVJj7RBHHWHm/vLbD
         Py4CZEhZCh462emGNCyBr1i0wDqIctNVYM+08q1rxt234Du7vkn095BlRIyLEm7yBpfU
         3bl96DGRJpB9ltF8N+YQ5lQqH7OVmLzH8sNL2Ywgi5xjpMzTqAQVgIADA4wA4qNL4G6Z
         syCGcDeYcuIhlna6jtuAdufdqlgNGmw2X4TH3V/hbVMY45HOiv0oF0KYgGjaRI30I9wb
         wAPNkgQwVzf6ZkKrk86guR7YuzNz+wYg1MyqBbaXgQn4tHFCl9U3ezwVI340eNAAUMYF
         /Zqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=z63Y195AqGh2Nrmp1OqB4bXaqVPIpf3nRvcVYtpTUg8=;
        b=QjnbH+btocm77HwBgGv67em0KXZkkqmUFXXyqlVwzG1AD8OsJXznU6A7c/mI23HO8t
         gOTYOGiehslRfNwa+1FS/kaiWcKgcZaFbiOxrLMg1XX+WUkIzA17Ey14bn/AOmROpk2h
         Zf5JpJOEOofnbPGSvhRFGwX1GEV1gokhnXiGkOqX3gZZt1MMYVZm99yp9Ke6J4AZ2Gt2
         OQPwJAmF674ySPwbmoRjccDgvCowT80zHwcj2a6jupfb3zFVyQSNGXucH38+Otbt8+5f
         JT+7lB4Qalgyr6qCxHP1uNF9K+hcsSbfuRf34Q2LE5Z4J3Ageunw1/qAbQ8QXZpM+agr
         vN2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=z63Y195AqGh2Nrmp1OqB4bXaqVPIpf3nRvcVYtpTUg8=;
        b=iIv3G1VyeW9OjDzg2EHsKQFNelZaqxVvyjjUQSaJ+F/AnqqYgtuEzqtbuGAT9hC2vZ
         WvBa4EmkT608fRobLBIm3MlhbJkOahFWMLvSp+XL+xeLOdHiW/e2RscrW3DTOEGmjdCu
         QX4sLF3tBctNmPl9BOIHRUHKJYB8LeVsU8ToIvMW0Bg2qQZv8P4MHIyMwrb904s4dd/h
         WF/T9zMHhSXJHR6nQewQShxZgU00iOcSa599Oi1DeY3yKXJdCDS7Ub6slActS63nONDF
         2kEEABx7WB2yOEprSYEgremtKgPZEImX5KJq4xCSz6h5yOvuiq3lOL40LH3F3Q4RQJhA
         9Jlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=z63Y195AqGh2Nrmp1OqB4bXaqVPIpf3nRvcVYtpTUg8=;
        b=t//tJEF376txHbV5PLRmq70bxQ0Z79SafpQ0UFakC0ann8k7kbeZGImEorkBDZJECM
         /y0tWsUjp84ELrhiWTn7JkKqMMDm/KTFzrVMjFuaSPEDh1sk/p/9RlkdBQ/kJJminni+
         XCbMLpBE+OU8p4w7EGC1utH3e0vV14tEp57NlOw+6TOlznaLGkpWU9McOG3g2E6qTALF
         5g2o+l9FkXimBmG6ZynDxbPcnrOQE60jYdNqXXWuJYkjKoedcofKw/D2hIWldbCw28Ru
         jGAQK2zw4TH5Yz+JL4QpAAQgDNJUbE1YmUdTqpfG8es/WNdJxAPjyR5ys1BRcGzgLMcY
         KOiw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533vreI7z39oApfN2rnwxmgiVudQHi+bnJ5WjawfU6ES9/NuWKaL
	fuMVbVSvMiWEURsEHabF+cY=
X-Google-Smtp-Source: ABdhPJxdqkIWXk7BoejrqLVqS0K7+0AQFUoAoO8gLsyPB68inT0A2jPTZE/NmG9bXdrfHEMLiXOhUw==
X-Received: by 2002:a17:90a:e989:: with SMTP id v9mr5520620pjy.29.1598527369243;
        Thu, 27 Aug 2020 04:22:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1b12:: with SMTP id b18ls839629pfb.8.gmail; Thu, 27 Aug
 2020 04:22:48 -0700 (PDT)
X-Received: by 2002:aa7:9344:: with SMTP id 4mr16582782pfn.30.1598527368740;
        Thu, 27 Aug 2020 04:22:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598527368; cv=none;
        d=google.com; s=arc-20160816;
        b=G3JTMowTT4qheFs3gddVInS84nTZ4XOAFeGpb1PPPi1+gal3j7S2fs1Y6LfzjCPsUJ
         cfxwsqKMbo6S880rphqR7Iht7gHsu8ckWIpTsp1xL/c4BHJuL8sK8G+yAVJ2Ld6xpvng
         MPtOBEA8f5RA1Be1UBCPD9cobjRi1aXXGh9UuKItoTBw5ociwYIMMe6wa3gDE/ZNFzrM
         yk+3AV9du7yVh7uGPYUYIENOTr5KL9EoD1kzfik0bbGOmm80wXQmUBm1dn6qVpcizyib
         lgLbGk/NnY2krjxne3teenmqfFlmCAtJjz5cuhkMXcVp9vTwIYg9zboovfa3lYFxZDL9
         VILQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=hwn2OCexPd8oMlzLuvo0do82b0ZImoR4uiwUt9xK3cY=;
        b=B9ymFVygI86LmYgZ3SNe3JME/DMKCtV839xy8NQNSCNZbinBECZHfmLmDQNGc7ehwS
         GhmIjScYLBx15Yv41uFe5ly56TFgfCuhUzZp29qAihdqZdvgI2FAGye3hC9+hdfFYAc0
         qTOJbdW+7k7Gsp5uwjaNOKaRUkJ+K4npqttMQvPeAG/G8oObjWk/GAFeLtmSj66KEmTp
         61HZZ49MJyTH3gz4JPLI1ZdvMHesPK2fVFahZo7H8gvqSlH07DEHEPOFvAMtMMC08IRU
         VQdyIaxupTIpGMrwGtcT9ocoB/rrbcnUAAmtaf2q2XiIZJPO0r5KmHx5mtuDaTESfKUQ
         kMew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id c11si98493pjn.0.2020.08.27.04.22.48
        for <kasan-dev@googlegroups.com>;
        Thu, 27 Aug 2020 04:22:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9DFD211B3;
	Thu, 27 Aug 2020 04:22:47 -0700 (PDT)
Received: from [192.168.1.190] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 84D723F68F;
	Thu, 27 Aug 2020 04:22:45 -0700 (PDT)
Subject: Re: [PATCH 20/35] arm64: mte: Add in-kernel MTE helpers
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1597425745.git.andreyknvl@google.com>
 <2cf260bdc20793419e32240d2a3e692b0adf1f80.1597425745.git.andreyknvl@google.com>
 <20200827093808.GB29264@gaia> <588f3812-c9d0-8dbe-fce2-1ea89f558bd2@arm.com>
 <20200827111027.GJ29264@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <921c4ed0-b5b5-bc01-5418-c52d80f1af59@arm.com>
Date: Thu, 27 Aug 2020 12:24:58 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200827111027.GJ29264@gaia>
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



On 8/27/20 12:10 PM, Catalin Marinas wrote:
> On Thu, Aug 27, 2020 at 11:31:56AM +0100, Vincenzo Frascino wrote:
>> On 8/27/20 10:38 AM, Catalin Marinas wrote:
>>> On Fri, Aug 14, 2020 at 07:27:02PM +0200, Andrey Konovalov wrote:
>>>> +void * __must_check mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>>>> +{
>>>> +	void *ptr = addr;
>>>> +
>>>> +	if ((!system_supports_mte()) || (size == 0))
>>>> +		return addr;
>>>> +
>>>> +	tag = 0xF0 | (tag & 0xF);
>>>> +	ptr = (void *)__tag_set(ptr, tag);
>>>> +	size = ALIGN(size, MTE_GRANULE_SIZE);
>>>
>>> I think aligning the size is dangerous. Can we instead turn it into a
>>> WARN_ON if not already aligned? At a quick look, the callers of
>>> kasan_{un,}poison_memory() already align the size.
>>
>> The size here is used only for tagging purposes and if we want to tag a
>> subgranule amount of memory we end up tagging the granule anyway. Why do you
>> think it can be dangerous?
> 
> In principle, I don't like expanding the size unless you are an
> allocator. Since this code doesn't control the placement of the object
> it was given, a warn seems more appropriate.
> 

That's a good point. Ok, we can change this in a warning.

>>>> +/*
>>>> + * Assign allocation tags for a region of memory based on the pointer tag
>>>> + *   x0 - source pointer
>>>> + *   x1 - size
>>>> + *
>>>> + * Note: size is expected to be MTE_GRANULE_SIZE aligned
>>>> + */
>>>> +SYM_FUNC_START(mte_assign_mem_tag_range)
>>>> +	/* if (src == NULL) return; */
>>>> +	cbz	x0, 2f
>>>> +	/* if (size == 0) return; */
>>>
>>> You could skip the cbz here and just document that the size should be
>>> non-zero and aligned. The caller already takes care of this check.
>>
>> I would prefer to keep the check here, unless there is a valid reason, since
>> allocate(0) is a viable option hence tag(x, 0) should be as well. The caller
>> takes care of it in one place, today, but I do not know where the API will be
>> used in future.
> 
> That's why I said just document it in the comment above the function.
> 
> The check is also insufficient if the size is not aligned to an MTE
> granule, so it's not really consistent. This function should end with a
> subs followed by b.gt as cbnz will get stuck in a loop for unaligned
> size.
> 

That's correct. Thanks for pointing this out. I currently used it only in places
where the caller took care to align the size. But in future we cannot know hence
we should harden the function with what you are suggesting.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/921c4ed0-b5b5-bc01-5418-c52d80f1af59%40arm.com.
