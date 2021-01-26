Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB34FYCAAMGQEEQYZAHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id BB085303C2D
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 12:54:25 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id u10sf1747868pjx.3
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 03:54:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611662064; cv=pass;
        d=google.com; s=arc-20160816;
        b=D2waU0msFjAYa8f6MAFW2rLTqIp+sdE4Sxsc4IrIwGdy7eQg3k/9waDojoLsi/7e3F
         T2twJBBbYncySQJsj9dUs9ofOaHHELlbxwmdUZM2AbiJmn6Xf6oCVfZAEulZO/wbim90
         Hxodhhd95q7hJ1DXMzHbaV2oAUSsBhWXBQPU5Ljqw3cdnkceBtwP39oEHQUfll8+62gn
         7+bz3MMQK9oUuW+2BOuZ7+/Kdvohdhsqo9SbANxf5JMp8oyIUtOI6PKe7qSd1kEmi6N1
         yugfB0bNrk8FDzLgC9JrLnIUb5TKpKSBo0vwkYwWudNcoJDKvcdaDLy4fkJx9k4jMPYD
         ZvaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=OAz5MK3ZCy0W1fpdhFMz8nzk9vxjhvnKsvbs+ibQOwE=;
        b=Ilj4FD0OMk3KtsT34UCx/UTMS6V+oJtrnFfNzey+CF/sgyAipplMlnIoyXn5tks5vY
         z975gn8LB+HhmjHeFlFnenSlaoAS+45OA3D5Q1ceQmMvW2NZUnjt6G9+PGkLDNFOcKC9
         CsWVYKWHvgw5DJNTNxQmqgzXKmGWDS5LFUCxHvHk1KRr5LQD33qAxJdx9IBLDBqqkYbv
         FTQOYU3ViDorbMigkppH9tVz6aBir6VYdjUE2vkMTjRnB6tJlWup/LJd+MrpkVYBIjCt
         a26C2pWCr53vyR5ImOeeQQJS99o45xmCPDng6YzFD+CK9tOxxiWT3s5dTaETAH6+023r
         sQcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OAz5MK3ZCy0W1fpdhFMz8nzk9vxjhvnKsvbs+ibQOwE=;
        b=JOt/jw+CUYWfz9UgDm+aKGvnVLlyCtNj1qIaWkqcmuA7eUOSaKY9OgaRQd03z9iuNo
         l7wdLXJjZnO7j69YRzqgiCM3XMCOMOtfMjXaK5EH7Zu+8CaFmsS4lmhow2naPXnMS6w9
         Tl3QFMDL8jSpiwuqghdQl5dtB89OzfxmwnUgKVmRNPNSNWOXZsUqgim5YGo0gNoU6PeG
         +7+fESbTpGpp/QabUCUSv2NrzMXaecnGNGN6Pe6KG2Q3QMQ2PvHsaXt3nWn6BR7hOQIR
         csuOWspFSk4xqP8wZKLcy1YClJcYr0UInrHRvyJMBtKpjNfDHjEVCN8PzUnoC3Lf/0eL
         WhwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OAz5MK3ZCy0W1fpdhFMz8nzk9vxjhvnKsvbs+ibQOwE=;
        b=TS5vqq+eeGHXaw+W66G4FMp2tTOxzTQ7lgLSLpenhthWPvMMD8lnNWGLW+pyfWoJ+5
         Io262G+2EsfhY02Q5aRJHcZKYuOMmcGvNSATDjEnYFpUd6kntYFqGfOpffSIYPP3Dauj
         UVn5EJh2xuAP1ydNnSQPNNeJz4nTep37yjB6XYkbscb+kwDtwAJQY9ZnzmipmlGpIaOw
         LZKy2GIx6mujNJeibFLpzJJnvQIp97fuHjhCmDeCJt3xxa4zCrSBGqSWqoe3Qh/ZW0+z
         /ycOfznUDudmKULJ/JbmtgpSk6kYiVwhubD4eiBHe1xUq32PYbsqevn8BnwVey0UBdeJ
         JM3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533P3heQAGvEtJuyY3wqixaPij2zMjg64MDhDsmAheplAtmKqCQW
	r04IiQXwR1TrM5IcameOUfY=
X-Google-Smtp-Source: ABdhPJzHQE3y5lHwZIJm5GCGGfXhsq+ESgQBvcpETFv8EaLc1Yfagxq3BMKyAtIVOhRSi/c6titHqQ==
X-Received: by 2002:a17:902:b212:b029:df:ec2e:6a1f with SMTP id t18-20020a170902b212b02900dfec2e6a1fmr5783119plr.24.1611662063956;
        Tue, 26 Jan 2021 03:54:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:19d8:: with SMTP id 207ls5958894pfz.5.gmail; Tue, 26 Jan
 2021 03:54:23 -0800 (PST)
X-Received: by 2002:a63:dc56:: with SMTP id f22mr5289836pgj.106.1611662063413;
        Tue, 26 Jan 2021 03:54:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611662063; cv=none;
        d=google.com; s=arc-20160816;
        b=QSS4qigHtSiEUQi9CPkDfju2F8qgnsFXLv2Ui+QtTNgQnifgdIHASeHokDU6ISOk1Q
         hFo6Omooz5lsgwhCQK2OaDWm4bfK+dQeTxqNKtat/gdWAXqFlszU15sm/pOGKMboeim1
         AbALofXGqUxxd3wUbcyChzC2KEj4dnBxE2LWhH+NgqzKBNRmzBIgj0f+B2pQytfVjOFS
         giGNKHTn3pYWSS/NAjojf55yAk3VVj1i55q5sf/uxKOrhkQMdYSYIVUFFRakTI7+G+zR
         SKaa+GXY2ufZtbcgKnIHYziOzn49C1rVFzrnhqh8itdMtmdO4aAO1PEq1fmtGPIchXfZ
         mT0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=PXqQGPq3ll7UHp9/4NpsEU4ZHUtPgKgCmbAW8ARI7Jk=;
        b=eIfTTzddFsYf6SX55XxIVRkS0AA3J0rGXRJDhBWxEjo3Y9BLB6NzSHcmVIi5K7TDeu
         UaMmpLIVgOSX/dy3z9nR66lYaVRRrtpVDQuV7noTM4v0cUENwzcyfJof59ggqDWXO8HY
         rYg78oalin4Q6oV9SE4Lp1JWr6L/LbMbXm/GxydBEynjFtWYlZ4xcuoS2P5VqyKQcrfn
         K6aGLSWT6oN3iIN4IZRjfnzDbdK1Ap4TeTPJEqMjOHVKyYJhKcOkCddY9ZzlRsDvWFls
         10yRjGOSxvxGSO6ZY26iS/12bA++88bzZWxlIAj5BN1JejbdYVwaWjZjO6oFzo+KSUQK
         FHwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l22si172629pjt.3.2021.01.26.03.54.23
        for <kasan-dev@googlegroups.com>;
        Tue, 26 Jan 2021 03:54:23 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 5924D101E;
	Tue, 26 Jan 2021 03:54:22 -0800 (PST)
Received: from [10.37.12.25] (unknown [10.37.12.25])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id EA0703F66B;
	Tue, 26 Jan 2021 03:54:19 -0800 (PST)
Subject: Re: [PATCH v4 1/3] arm64: Improve kernel address detection of
 __is_lm_address()
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Mark Rutland <mark.rutland@arm.com>,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Leon Romanovsky <leonro@mellanox.com>,
 Andrey Konovalov <andreyknvl@google.com>, Will Deacon <will@kernel.org>,
 "Paul E . McKenney" <paulmck@kernel.org>,
 Naresh Kamboju <naresh.kamboju@linaro.org>
References: <20210122155642.23187-1-vincenzo.frascino@arm.com>
 <20210122155642.23187-2-vincenzo.frascino@arm.com>
 <20210125130204.GA4565@C02TD0UTHF1T.local>
 <ddc0f9e2-f63e-9c34-f0a4-067d1c5d63b8@arm.com> <20210125145911.GG25360@gaia>
 <4bd1c01b-613c-787f-4363-c55a071f14ae@arm.com> <20210125175630.GK25360@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <62348cb4-0b2e-e17a-d930-8d41dc4200d3@arm.com>
Date: Tue, 26 Jan 2021 11:58:13 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210125175630.GK25360@gaia>
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



On 1/25/21 5:56 PM, Catalin Marinas wrote:
> On Mon, Jan 25, 2021 at 04:09:57PM +0000, Vincenzo Frascino wrote:
>> On 1/25/21 2:59 PM, Catalin Marinas wrote:
>>> On Mon, Jan 25, 2021 at 02:36:34PM +0000, Vincenzo Frascino wrote:
>>>> On 1/25/21 1:02 PM, Mark Rutland wrote:
>>>>> On Fri, Jan 22, 2021 at 03:56:40PM +0000, Vincenzo Frascino wrote:
>>>>>> Currently, the __is_lm_address() check just masks out the top 12 bits
>>>>>> of the address, but if they are 0, it still yields a true result.
>>>>>> This has as a side effect that virt_addr_valid() returns true even for
>>>>>> invalid virtual addresses (e.g. 0x0).
>>>>>>
>>>>>> Improve the detection checking that it's actually a kernel address
>>>>>> starting at PAGE_OFFSET.
>>>>>>
>>>>>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>>>>>> Cc: Will Deacon <will@kernel.org>
>>>>>> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
>>>>>> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
>>>>>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>>>>>
>>>>> Looking around, it seems that there are some existing uses of
>>>>> virt_addr_valid() that expect it to reject addresses outside of the
>>>>> TTBR1 range. For example, check_mem_type() in drivers/tee/optee/call.c.
>>>>>
>>>>> Given that, I think we need something that's easy to backport to stable.
>>>>>
>>>>
>>>> I agree, I started looking at it this morning and I found cases even in the main
>>>> allocators (slub and page_alloc) either then the one you mentioned.
>>>>
>>>>> This patch itself looks fine, but it's not going to backport very far,
>>>>> so I suspect we might need to write a preparatory patch that adds an
>>>>> explicit range check to virt_addr_valid() which can be trivially
>>>>> backported.
>>>>>
>>>>
>>>> I checked the old releases and I agree this is not back-portable as it stands.
>>>> I propose therefore to add a preparatory patch with the check below:
>>>>
>>>> #define __is_ttrb1_address(addr)	((u64)(addr) >= PAGE_OFFSET && \
>>>> 					(u64)(addr) < PAGE_END)
>>>>
>>>> If it works for you I am happy to take care of it and post a new version of my
>>>> patches.
>>>
>>> I'm not entirely sure we need a preparatory patch. IIUC (it needs
>>> checking), virt_addr_valid() was fine until 5.4, broken by commit
>>> 14c127c957c1 ("arm64: mm: Flip kernel VA space"). Will addressed the
>>> flip case in 68dd8ef32162 ("arm64: memory: Fix virt_addr_valid() using
>>> __is_lm_address()") but this broke the <PAGE_OFFSET case. So in 5.4 a
>>> NULL address is considered valid.
>>>
>>> Ard's commit f4693c2716b3 ("arm64: mm: extend linear region for 52-bit
>>> VA configurations") changed the test to no longer rely on va_bits but
>>> did not change the broken semantics.
>>>
>>> If Ard's change plus the fix proposed in this test works on 5.4, I'd say
>>> we just merge this patch with the corresponding Cc stable and Fixes tags
>>> and tweak it slightly when doing the backports as it wouldn't apply
>>> cleanly. IOW, I wouldn't add another check to virt_addr_valid() as we
>>> did not need one prior to 5.4.
>>
>> Thank you for the detailed analysis. I checked on 5.4 and it seems that Ard
>> patch (not a clean backport) plus my proposed fix works correctly and solves the
>> issue.
> 
> I didn't mean the backport of the whole commit f4693c2716b3 as it
> probably has other dependencies, just the __is_lm_address() change in
> that patch.
> 

Then call it preparatory patch ;)

>> Tomorrow I will post a new version of the series that includes what you are
>> suggesting.
> 
> Please post the __is_lm_address() fix separately from the kasan patches.
> I'll pick it up as a fix via the arm64 tree. The kasan change can go in
> 5.12 since it's not currently broken but I'll leave the decision with
> Andrey.
> 

Ok, will do.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/62348cb4-0b2e-e17a-d930-8d41dc4200d3%40arm.com.
