Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBGW2TSAAMGQELBU2C6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 63AA32FBFAB
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 20:03:55 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id m8sf20579871qvt.14
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 11:03:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611083034; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kp2CniChf5uVsjbzsAcqo2Ms3DQZ8toZg5W+vw+dUrXi2EGx5iBx/pNMIYlgDgbAY5
         O90mDTku9EsNwrE8VwVq56o75Yxw4hTgVZtnOnzM76qeezxUCfCtpIedfMFpAeWu9DUp
         0flpSzKup+SSpZDlBy4NMWAHWY3MoO3ODTC0SfNX36wYcQB0GUNglNLeny/kF1uQ+YIR
         x4ovJkPurepASrqTM/NjpALwxX4a/FGna41e8pcjxLSq6F16V4fL2//OU9BdiMMS2UBN
         Xa3M1PqndGzWWCxaieXLc7uewZlS6ORz0TwZdO1sapOXIZP8DRguiVu910fnGiuIRX7T
         YAQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=5nzbC5VsxVXoATcwrVoucB9o1clrckI3F6HyB/3csYQ=;
        b=Ve3hlM7l65jgMpHo/8GY7ql4mgTPcRyS9xbKELv9uv4h6EevpjSSJ7YQ+0qySrs/6M
         g7h6AyZIirkrgeLy7SexE4f275WkhnLCVlq/BwEb5S6+0GzoUqTcas0AFF5tk9Rl+gjm
         7HqSg6gyHFsCkHSyJhp4ptS3UytQGBYE6IgZeRDuXdU7jI/5tG+5tJ+QjHo8McGzICyf
         npQQcqyryYmFA6G4nZYocwUex+XLySZAqvQgvtsVjOk0kwC8Ya8Qj7nP76lQIM2et4ib
         zUxuY/tVp5PYra4FMkPNQhD1JEgl66CtxezsBpBcImTXnai3DB5IQGdwJbYhoAGew2Sr
         rxyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5nzbC5VsxVXoATcwrVoucB9o1clrckI3F6HyB/3csYQ=;
        b=JVADa7P6l32ZGzNbJF83PkRYP+qdWtzAfXBCdLhVCI7W1MkbnUmz8RuT3bDpESYNh6
         vJxb4P6cXkX2y+E4TBV0JzW/X/RCpw5OUyoe7I+SCnFdUMcKjzSAFOnF4nK10qvmyAmR
         BgLidnr7EuOg/0mHzS+ahZmu3F0iUNmiOHX8+Ak2kifRrIvISVY3uhkWURoivDalDfwK
         PIs3QMpnqhrJq8VE8svz+SnNGKJnOsJ2nLA5Tnn11/u9USmgU9i5/ozfLzFextISJYp9
         9T1Va7n1OCUOAcoI8M0u50a/8X6PToagyN6CsCnBLYCUf0dDgoMawKv/r5hdpCMIjKkU
         CPnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5nzbC5VsxVXoATcwrVoucB9o1clrckI3F6HyB/3csYQ=;
        b=pEQBA0yNUgQ0xRfKfQqHnCtVwDJpdTnIY5SbYmmEPygISf4RbmgJacgDkq4sPgeg2B
         n1fCyoXamZbIjMd43ZydI1pEfQqmiAtTJvuNC/alWfvkw8dl1byAnNbCDhAqpxyN1h9g
         zfP/dSxL2HXYFCmuyYKhrysFqF0ogPdJOS6mU3Px9fJDa27ajzi9mBn1JqZ0iDiP///B
         TjMv8cmMxAg5Sih4BmVcW9rCKtmZ6jcd9y6SqNkkULmVsW6wrTEjT2nGmiUSZuBpPRdP
         eT52qhQ+PxKFoRjqVm+rT8NMTfY98ScOovMGjiOXapyF6N+Ba5Xoj6zvdbTbQ1iGsgZG
         t6dw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531XfmKz9E+rPw6xFMWTokFjiBIIRsTz7DSCwMDQ1tSULDESjoP6
	MUx7oekSKHWu+k4mGhH+JN4=
X-Google-Smtp-Source: ABdhPJytY0UL2oefcjlQGP8x7au95I1jcLKYeWe78TuHzfWUicm9QbK2CTFFmC/I99/aYSMCL0Ikeg==
X-Received: by 2002:ad4:5187:: with SMTP id b7mr5974411qvp.2.1611083034113;
        Tue, 19 Jan 2021 11:03:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:6790:: with SMTP id b16ls9025699qtp.7.gmail; Tue, 19 Jan
 2021 11:03:53 -0800 (PST)
X-Received: by 2002:ac8:7a9a:: with SMTP id x26mr5689092qtr.382.1611083033693;
        Tue, 19 Jan 2021 11:03:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611083033; cv=none;
        d=google.com; s=arc-20160816;
        b=JLSWXeblxdkUEna2/9fdwvHA/khprDp6NPr08xlAVgG2VuiqrGsjFhYCGZpeKr18bq
         ipYrWFKEX/w850tDVsUXLMblShpS9zPPkEma+2mLT5PlFJmhGGd10mJ0QFWmjM8sr+cX
         0zCLvKiDoioIn9+O2LFBkU1jIiD8sQgNUSAMNbA6U5Jz1QdBvjyiqfqwTFZ+/1k4Wy78
         x39vsQdp3TOrebZJSGeEDPQ7jxyklUxSZIa0y6mTlNjid662rVBMpYicAp6VRnEmNpa8
         cnUyt9Go3bUmWIltq34x63ijCpA6NRbtLj2W5C8kJGCQGkAvY4ykMMaflv1Q3exxkOOp
         5unA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=yHxb8Z6AJL7zX7fSp+7ajBPe/XcIOEbi3gaxsu2Hfts=;
        b=0W+vEchTJBI1KsJ8DatSuvkBHvoi6dDeFtXKDP8zfOBzY7uUQjnIMhUKB1GjGpBGj5
         hgHcnmQzQMP3osq/uRLJa6nGQxFYs9Op5KFvktUh355eJfdMSrEcsIBaxx1laRB6Stdz
         V6JUL5jI8jgN0/D8rm1v9OnYXKgZ2agkOhGUtVgoc1AKH8wWtLRhceTYliTHqVu3PLuf
         YycIjUjqRxRstqEOJukaK8tB5u/tu+B0aZesqaueus7qAFvSv/KswnrCV0chLOFVz32j
         0AoWZCXF8RmU2ez/gWUO5Z/dqQG8MGUnl9HMY31JvVmCQ/y7f2P/U8KtlC0vmstTJ6nO
         hOCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id y12si1432092qkl.1.2021.01.19.11.03.53
        for <kasan-dev@googlegroups.com>;
        Tue, 19 Jan 2021 11:03:53 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id F27ADD6E;
	Tue, 19 Jan 2021 11:03:52 -0800 (PST)
Received: from [10.37.8.29] (unknown [10.37.8.29])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 76AB83F719;
	Tue, 19 Jan 2021 11:03:51 -0800 (PST)
Subject: Re: [PATCH] kasan: Add explicit preconditions to kasan_report()
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Leon Romanovsky <leonro@mellanox.com>,
 Alexander Potapenko <glider@google.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>
References: <20210119172607.18400-1-vincenzo.frascino@arm.com>
 <CAAeHK+zpB6GZcAbWnmvKu5mk_HuNEaXV2OwRuSNnVjddjBqZMQ@mail.gmail.com>
 <20210119185206.GA26948@gaia> <e3d67672-1825-894a-db68-5709b33b4991@arm.com>
 <20210119190219.GC26948@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <6a5600c0-002a-3e80-0229-494d1c9648ac@arm.com>
Date: Tue, 19 Jan 2021 19:07:40 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210119190219.GC26948@gaia>
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



On 1/19/21 7:02 PM, Catalin Marinas wrote:
> On Tue, Jan 19, 2021 at 07:00:57PM +0000, Vincenzo Frascino wrote:
>> On 1/19/21 6:52 PM, Catalin Marinas wrote:
>>> On Tue, Jan 19, 2021 at 07:27:43PM +0100, Andrey Konovalov wrote:
>>>> On Tue, Jan 19, 2021 at 6:26 PM Vincenzo Frascino
>>>> <vincenzo.frascino@arm.com> wrote:
>>>>>
>>>>> With the introduction of KASAN_HW_TAGS, kasan_report() dereferences
>>>>> the address passed as a parameter.
>>>>>
>>>>> Add a comment to make sure that the preconditions to the function are
>>>>> explicitly clarified.
>>>>>
>>>>> Note: An invalid address (e.g. NULL pointer address) passed to the
>>>>> function when, KASAN_HW_TAGS is enabled, leads to a kernel panic.
>>>>>
>>>>> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
>>>>> Cc: Alexander Potapenko <glider@google.com>
>>>>> Cc: Dmitry Vyukov <dvyukov@google.com>
>>>>> Cc: Leon Romanovsky <leonro@mellanox.com>
>>>>> Cc: Andrey Konovalov <andreyknvl@google.com>
>>>>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>>>>> ---
>>>>>  mm/kasan/report.c | 11 +++++++++++
>>>>>  1 file changed, 11 insertions(+)
>>>>>
>>>>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>>>>> index c0fb21797550..2485b585004d 100644
>>>>> --- a/mm/kasan/report.c
>>>>> +++ b/mm/kasan/report.c
>>>>> @@ -403,6 +403,17 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>>>>>         end_report(&flags);
>>>>>  }
>>>>>
>>>>> +/**
>>>>> + * kasan_report - report kasan fault details
>>>>> + * @addr: valid address of the allocation where the tag fault was detected
>>>>> + * @size: size of the allocation where the tag fault was detected
>>>>> + * @is_write: the instruction that caused the fault was a read or write?
>>>>> + * @ip: pointer to the instruction that cause the fault
>>>>> + *
>>>>> + * Note: When CONFIG_KASAN_HW_TAGS is enabled kasan_report() dereferences
>>>>> + * the address to access the tags, hence it must be valid at this point in
>>>>> + * order to not cause a kernel panic.
>>>>> + */
>>>>
>>>> It doesn't dereference the address, it just checks the tags, right?
>>>>
>>>> Ideally, kasan_report() should survive that with HW_TAGS like with the
>>>> other modes. The reason it doesn't is probably because of a blank
>>>> addr_has_metadata() definition for HW_TAGS in mm/kasan/kasan.h. I
>>>> guess we should somehow check that the memory comes from page_alloc or
>>>> kmalloc. Or otherwise make sure that it has tags. Maybe there's an arm
>>>> instruction to check whether the memory has tags?
>>>
>>> There isn't an architected way to probe whether a memory location has a
>>> VA->PA mapping. The tags are addressed by PA but you can't reach them if
>>> you get a page fault on the VA. So we either document the kasan_report()
>>> preconditions or, as you suggest, update addr_has_metadata() for the
>>> HW_TAGS case. Something like:
>>>
>>>         return is_vmalloc_addr(virt) || virt_addr_valid(virt));
>>
>> Or we could have both ;)
> 
> True. Documentation doesn't hurt (well, only when it's wrong ;)).
> 

Testing the patch now, I will send it in half an hour.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6a5600c0-002a-3e80-0229-494d1c9648ac%40arm.com.
