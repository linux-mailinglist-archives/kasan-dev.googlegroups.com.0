Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBX5MUGAAMGQEO5TGDHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 7450B2FD503
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jan 2021 17:12:18 +0100 (CET)
Received: by mail-vk1-xa39.google.com with SMTP id h63sf12376331vkh.8
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jan 2021 08:12:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611159136; cv=pass;
        d=google.com; s=arc-20160816;
        b=MkXwRK2bTU65umsHkScvKMYRmb1ps8KJEvehzZsZRlHjW2JIJ+gX0/GbosSM7QkEoU
         iNe98jrJw5dq6Tj8zRrURic216r8U67B5PgUJpmDkAK//p8idiStABeVzXKqASk1jPro
         6r9CcxAQOIMvcNC5iqpfFy2LGHMsQao8EAnhEX4VsA2kXeshVrwTiqqDBPGSaiCXoYG9
         yQVkPN26NgeVALu5cLeabTXR82pJ8HY5N3Ubtzagb4QddHlVw0EQGvkBXUJpSSA14NSW
         wKT556Ll9KKf+zH4RY+LipZe0HM5rmV7spI7nysXfYl3MKtWh/o7aoUxxf9MtPJxDK09
         dYgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=GOzjX20KFxnCfy1FAy+xzydBuDrkAx3Bincw3UXWZEw=;
        b=sdmZzXMM8S3WNI8c861oF0nH+R2VCFaTzQDk+FBzqQ5+djlEQGQeE8KXaslbxHGBYs
         mU059NdF5z8u2fQrKAwZdSiOrTPSGBctuuISi5te+XGsbHH6MKRszeN5+56OIqfi3LQu
         hVQwSZRnyRE32l96uEoO6g/iN1095ZFuI3osMX0YuCdA9wp7I8UonVUkTkg4Ug+5HUB+
         dOo0SZ/tBF0zC5thCA8/TXNHiYoZUexXT1Cb36nViDRI6zKPQC1YFaPpnoe8MUTvdCz8
         37IwYJiVaJLZzjYmebYtTnxNJuK2KQ/Fopc6LtqmxCsFhotfc33/8j1Y5g3uECNQzqd0
         rsVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GOzjX20KFxnCfy1FAy+xzydBuDrkAx3Bincw3UXWZEw=;
        b=NIr5jFKNTBqaXbs+dJcx/oWjeY+dfq1JDjv1QgwqH1uzGflK+FPGaqMkFuvcUwBo+m
         JG57Fkp1aARWNCjkBYyDSOr2Vv4arkg2rKLOQo4TDzordPd+L76VnzBs17Ss8m8yfWbb
         NNTh71xbKcQ+51PVz8+yIIbRVJ4GB+cCLm5aAWZoNeEkxUGojX5JUGMV/boloTa82XHz
         vssxz66mJ74D+2Se6G1B284NoNj0g2iS/JDJ5Hn1mEIScOaAvzMukK7Di4Bpx2iOl92P
         kvXUIyovq8Aw6fbK3ENAL+CDeplbnQvSpoSiVXwd3j/hm0xO0fXvWrgwrpVdftKPjyF7
         lmOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GOzjX20KFxnCfy1FAy+xzydBuDrkAx3Bincw3UXWZEw=;
        b=RWIiTobp1DyQQfPZvJQIlIekKE13N6/r3dUo+LKATb4QYM17nqcp87NcepYkOPJMxH
         KFMYvQLYuJFVU1RYPpEtkQdz7amxmJxX2ODbcHAWYczBbwBJFkYT74gAAtIUuZG+op3n
         alRN6pPlUkI2kT3jDNi2b8quGXxV6lArXKeuwTCuCjgWSpHSvxyypCxh45RZ8p8g+MQE
         rQ4+zdL5xz8r5fzQ7A3tNExFjemFELgyUJpSLNdLxCHYELOYr9W58XP6zBipeh9BwcBu
         BF1ZpqVi3IQ1Qtp+ZQj1QBwiUfcNjX0nqUlFUudc91ppHhkrMY912auTluaHuOa8IxMZ
         0SYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533J0GzEs7TxKB2H3ZxhSGeQPMd8igqVwL3CQQN3/2KTc1P94JBg
	OW8iXYa6Ag3g1blIQYxQGlQ=
X-Google-Smtp-Source: ABdhPJxCEjhCzFSAvZqm5bj9mDOoHeUM7ZJoOeR3IDhdjFYjPabQ/NqrBIC2jVlG+WJn9Y1102fIeA==
X-Received: by 2002:a05:6102:109:: with SMTP id z9mr2652530vsq.34.1611159136097;
        Wed, 20 Jan 2021 08:12:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:4823:: with SMTP id b32ls2110034uad.2.gmail; Wed, 20 Jan
 2021 08:12:15 -0800 (PST)
X-Received: by 2002:a9f:2c07:: with SMTP id r7mr6823351uaj.4.1611159135526;
        Wed, 20 Jan 2021 08:12:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611159135; cv=none;
        d=google.com; s=arc-20160816;
        b=Kq4RBreddXxaljTM2glUQASheChXGOzZ7RB4hp9EiHlee0Jo4vG5xIYnUEgSTpqbS/
         xPg3YSg12O7rcYVU8a30jVpbg/Garqtgn8Ie1cyEpPfwhuXhD+q+7qeR1rbYljz29o3k
         3ekOsuGWnoWE4V22rTv32r1+0DUNeItB6MtdS27OQsNJghz4F9BB3DHOhnfdqimAaOjj
         QhAzb4SCSlsQmHKe20qQprwYPtk5DEZQ9s3/qt157iArBCIWeVD1yOTI0KD1oaUDgINs
         0EFWdPTOQ+Ktl+ARS1i2+GwROQYQMqYHenyXehTkMp3291dYtXuph4JIb117NWuh4hDz
         FBhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=PkLITnDREFo+zqyRbE18DFKUvOvCqESGIqYaeb/QCTQ=;
        b=TWY/lOp0OW35iUMLyuqxQ0Pw+TIbALjJW6l0yWlvroj0DH/QaKygRIshQbVt8O9CeG
         k5HJI6GBf7CN/jgfsmTXwMJ8xQylkcnJgphghzmp+H2+KVsKdG1Pp5Y/7/ehNqCy8/A4
         bgCok08PT3920sC4/+Mm2foL+waBOyvlrRO86kwC/S2ir4zNtWPcUq3jaV6tLmENyKC3
         bH0d0765qQH55dEybzFcHM9nKHa/4W+eGiV+Tq9f7ZxEx9CMgPws1y+6i0mC9C1EenmE
         Oz6bIIiS5lfQE9jbS6aLqDtYBTrkmuEE2kvy1Z9C7rWde5ShBJupbR0AKFkRWMkLwaWf
         IWmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id h123si247318vkg.0.2021.01.20.08.12.14
        for <kasan-dev@googlegroups.com>;
        Wed, 20 Jan 2021 08:12:15 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 2614C31B;
	Wed, 20 Jan 2021 08:12:14 -0800 (PST)
Received: from [10.37.8.30] (unknown [10.37.8.30])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 9EE953F68F;
	Wed, 20 Jan 2021 08:12:12 -0800 (PST)
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
 <20210119185206.GA26948@gaia> <418db49b-1412-85ca-909e-9cdcd9fdb089@arm.com>
 <20210120160416.GF2642@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <6525b31a-9258-a5d1-9188-5bce68af573c@arm.com>
Date: Wed, 20 Jan 2021 16:16:02 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210120160416.GF2642@gaia>
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



On 1/20/21 4:04 PM, Catalin Marinas wrote:
> On Tue, Jan 19, 2021 at 08:35:49PM +0000, Vincenzo Frascino wrote:
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
>>>
>>
>> This seems not working on arm64 because according to virt_addr_valid 0 is a
>> valid virtual address, in fact:
>>
>> __is_lm_address(0) == true && pfn_valid(virt_to_pfn(0)) == true.
> 
> Ah, so __is_lm_address(0) is true. Maybe we should improve this since
> virt_to_pfn(0) doesn't make much sense.
> 

How do you propose to improve it?

>> An option could be to make an exception for virtual address 0 in
>> addr_has_metadata() something like:
>>
>> static inline bool addr_has_metadata(const void *addr)
>> {
>> 	if ((u64)addr == 0)
>> 		return false;
>>
>> 	return (is_vmalloc_addr(addr) || virt_addr_valid(addr));
>> }
> 
> As Andrey replied, passing a non-zero small value would still be
> incorrectly detected as valid.
> 

I would like to remove the check completely and have virt_addr_valid(addr) to
return the right thing if possible.

I admit, yesterday evening I did not thing it through completely before posting
this code that had the sole purpose to open the discussion. I agree in principle
on what Andrey said as well (addr < PAGE_SIZE).

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6525b31a-9258-a5d1-9188-5bce68af573c%40arm.com.
