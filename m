Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBB6XTSAAMGQE3UJAV2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 63E072FBF8E
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 19:57:12 +0100 (CET)
Received: by mail-vk1-xa40.google.com with SMTP id h15sf11124884vka.10
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 10:57:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611082631; cv=pass;
        d=google.com; s=arc-20160816;
        b=h3s57M3bGahRSQkBi6zQ7jzeZ+Z2550pi/v466yoP6gJgPRldnfsKEtPFh9s+asO0k
         JZubI91g+Rg0ZxCeAG7wo8goOvS1rfdhUoqzhyFlsmlB7g0p8bhYDnNoSgsM6v13BCCZ
         SiKpOvp1OSbTraGeDtO67++IRDipZ4YEf9qpqvA1RVLIdLf0TwCuMdG4mbguKCcV6x78
         LdHNIPdsVuW9IEd9WEgy6//r+ywXYjozGcLBlKXrjX9FPFTI9MY94m9NFCTlJ8s2RQrd
         h9Tsai/BZDZC2YaazGjQvgyeKs9i0hQOR7jTz84IDEc5yq6FG99BGcxJ10x8dq6x7hhl
         cPbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=ye9NPA2aiuq5DbaM13kL+uZym6EmvkZWDEtwNLskuNw=;
        b=Lq7LwxsVg1t+qWuXl6oGEWWqi9nX3wdBaJD+oSUo7awZlxYJWTNJdOgFyxF+gAFpgf
         PVUu7XeBHI5AHcJBQ68mXygePsgSCtdwCSa4Rj/+gGTkEr/n3++utUwGoh0akCMbcsC6
         WqAILErBg3wjJ29LYyA30qAih9HcuzhG2SkOfbte21sJzKzhn1jg4CBKIaBmcNMSvQ2N
         yayWfgtTs0r+7VzFbHjmhMLhZtNqtHuEyksG7DSJ5zaBu8T45a0eZ2+6gQizWTwBFKmo
         x3t/B2X31jWQvMlUdm0nUrBp1kKuoMMtpD8pWnHwrnhITfUk63BiJ3Qe3pOz3X9oBhso
         7YBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ye9NPA2aiuq5DbaM13kL+uZym6EmvkZWDEtwNLskuNw=;
        b=hC2M+glhrCeRJlBMpWKqCAyP+RGsntAZz2F/CrVIz68gzPRnrQlFU4SOB2oBJgZTBw
         SWtaNt7721WoZtgnkzoaeEBXSURdx5WytiV2cYXLI5crBEhjMuRvZ3oKtYm1UwuFXcPX
         l05D8kNk2j/8NbGSnoKXmlSKM+Q/2TYQk9WGBGuQjozjLD3LwIpDhI4HLwLPYnTUQz5o
         Rn7h2B+GxdAwdKWwOADCJN5jUAAQeXIKvoSJPfcWVaRxWj8QA87Uyg3ZO0xe2tqmuldi
         SrD4PZOgI53iTz7pK2tXSsqdChbEUFRAyFEjYiZqPkx0GMnWtGR/AA8O7DqQBzaY0Ekn
         dZwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ye9NPA2aiuq5DbaM13kL+uZym6EmvkZWDEtwNLskuNw=;
        b=HxBgXjByb2BhgnRJyhLgUw8WCNlxQFGHgN+qlsSvxYTY+P5SFeC8lvmImbw5cvaU3T
         rsrRum8jy3W3E4swFwS9G7QOZRW9DEizYfC9in6+vZIKbjw8WqvUcf5fAjWUg3XfJZI4
         4ZYjTCb5Jzs3ZnQFY6vxGLzI7O7xgckBWVd00qT9Y5peh/kMsFSzvWjYjO+bSENbVkAE
         UFF8CNwDOSWLznyUz4nqjAtbU04aLG2QKT6sk5yawOsiqSdrf1b0dhajJwO0TuyWpBdZ
         EJ469ENhGw+1uJ8b7lLn8WW1XyEx3FvcQqB94HSFZNek/tmI6zM9UTeOZou77kB+ZmKu
         AkSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5303hkG9hxZmNp45RzZ4DMsGfq3kr9dE6nk6XQxP0FvLXjTWJeAN
	+38shgBVgYbEi6HcmTwph6w=
X-Google-Smtp-Source: ABdhPJzS0rQC8Rnal/LboOpKVPFbSBaOJ7uBssvVesnEGl0DgsHi01Nurb437B9nZVhxRgqn49BoDQ==
X-Received: by 2002:ab0:2b13:: with SMTP id e19mr3678992uar.107.1611082631436;
        Tue, 19 Jan 2021 10:57:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:214e:: with SMTP id h14ls3065376vsg.2.gmail; Tue,
 19 Jan 2021 10:57:10 -0800 (PST)
X-Received: by 2002:a67:ee42:: with SMTP id g2mr3755633vsp.24.1611082630850;
        Tue, 19 Jan 2021 10:57:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611082630; cv=none;
        d=google.com; s=arc-20160816;
        b=Mx8rwA/y8wdOodb82eR8PUBabp6wPQWtt5paXS6zxZ97Z4s9hzVT0eI+23TmWTO3Og
         OhGEANLt0MuenO8TzzbBt8zeb4nWFH1B23iQ2ZuAeoAv+9cxRYwQe8JMnVlDcr1QqZaP
         HVXnClrB294zLuj3kZzuvj/StKHJrnvm93J9QkOdangkp6nKRZEOninVQ5/XFxddaPQa
         9/YrFFmtaFE96qKzq0CDuF5xzZUycrfST0Uk8N/6exVgRyS9mynBnKKtg1ZEVnjeOl5f
         AFFHYecgVxouWKsB6JQDgxpNdORCkg3KLQVQD2eP+uttyGXV0yA1dewSwMHt9YuJEq5Z
         CfOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=DZJD7qSf2V5MHY2pzI8PtQ7U9zZKIF7P1ohErVNv6uw=;
        b=Ld9Wii+lA2QPfw7EN2Ls3nsigtqm1kNMdFE3X8kAnFOLdq43Bvz0x37Sbpxw5z81Mj
         4cMpwu65+o6swAd0RVEMdd8kt+HOzVsxnG62k8cl8ihf5pjTIum9eFFEQa8+ruymVO0W
         Wt1A18/x5WYrWpgrLYkvx7zkHKlp1IafS9/ZfIT0/DgsFSuxOsv6b+N4MllGZwQwCPUY
         sqksMDPNf6c926eWshgs/8uuW9C9hIfy/ChByz2PG5z0UZXdBk/KHY/+RZtPG+f1irj5
         Fx3nSym/9Iq95CmlkF0hD6eBkKYtZvuuNA/4QV3/m+8S5GQZmDS2KB5CgU6/0ggQ8X9/
         ShHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l11si115301vkr.5.2021.01.19.10.57.10
        for <kasan-dev@googlegroups.com>;
        Tue, 19 Jan 2021 10:57:10 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 27FEA11B3;
	Tue, 19 Jan 2021 10:57:10 -0800 (PST)
Received: from [10.37.8.29] (unknown [10.37.8.29])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 9ECCE3F719;
	Tue, 19 Jan 2021 10:57:08 -0800 (PST)
Subject: Re: [PATCH] kasan: Add explicit preconditions to kasan_report()
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>, Leon Romanovsky
 <leonro@mellanox.com>, Alexander Potapenko <glider@google.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>
References: <20210119172607.18400-1-vincenzo.frascino@arm.com>
 <CAAeHK+zpB6GZcAbWnmvKu5mk_HuNEaXV2OwRuSNnVjddjBqZMQ@mail.gmail.com>
 <20210119185206.GA26948@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <e3d67672-1825-894a-db68-5709b33b4991@arm.com>
Date: Tue, 19 Jan 2021 19:00:57 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210119185206.GA26948@gaia>
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



On 1/19/21 6:52 PM, Catalin Marinas wrote:
> On Tue, Jan 19, 2021 at 07:27:43PM +0100, Andrey Konovalov wrote:
>> On Tue, Jan 19, 2021 at 6:26 PM Vincenzo Frascino
>> <vincenzo.frascino@arm.com> wrote:
>>>
>>> With the introduction of KASAN_HW_TAGS, kasan_report() dereferences
>>> the address passed as a parameter.
>>>
>>> Add a comment to make sure that the preconditions to the function are
>>> explicitly clarified.
>>>
>>> Note: An invalid address (e.g. NULL pointer address) passed to the
>>> function when, KASAN_HW_TAGS is enabled, leads to a kernel panic.
>>>
>>> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
>>> Cc: Alexander Potapenko <glider@google.com>
>>> Cc: Dmitry Vyukov <dvyukov@google.com>
>>> Cc: Leon Romanovsky <leonro@mellanox.com>
>>> Cc: Andrey Konovalov <andreyknvl@google.com>
>>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>>> ---
>>>  mm/kasan/report.c | 11 +++++++++++
>>>  1 file changed, 11 insertions(+)
>>>
>>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>>> index c0fb21797550..2485b585004d 100644
>>> --- a/mm/kasan/report.c
>>> +++ b/mm/kasan/report.c
>>> @@ -403,6 +403,17 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>>>         end_report(&flags);
>>>  }
>>>
>>> +/**
>>> + * kasan_report - report kasan fault details
>>> + * @addr: valid address of the allocation where the tag fault was detected
>>> + * @size: size of the allocation where the tag fault was detected
>>> + * @is_write: the instruction that caused the fault was a read or write?
>>> + * @ip: pointer to the instruction that cause the fault
>>> + *
>>> + * Note: When CONFIG_KASAN_HW_TAGS is enabled kasan_report() dereferences
>>> + * the address to access the tags, hence it must be valid at this point in
>>> + * order to not cause a kernel panic.
>>> + */
>>
>> It doesn't dereference the address, it just checks the tags, right?
>>
>> Ideally, kasan_report() should survive that with HW_TAGS like with the
>> other modes. The reason it doesn't is probably because of a blank
>> addr_has_metadata() definition for HW_TAGS in mm/kasan/kasan.h. I
>> guess we should somehow check that the memory comes from page_alloc or
>> kmalloc. Or otherwise make sure that it has tags. Maybe there's an arm
>> instruction to check whether the memory has tags?
> 
> There isn't an architected way to probe whether a memory location has a
> VA->PA mapping. The tags are addressed by PA but you can't reach them if
> you get a page fault on the VA. So we either document the kasan_report()
> preconditions or, as you suggest, update addr_has_metadata() for the
> HW_TAGS case. Something like:
> 
>         return is_vmalloc_addr(virt) || virt_addr_valid(virt));
> 

Or we could have both ;)

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e3d67672-1825-894a-db68-5709b33b4991%40arm.com.
