Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB36YXOAAMGQEIJTUIHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id EAB20302771
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 17:06:08 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id l21sf5481547ooh.8
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 08:06:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611590768; cv=pass;
        d=google.com; s=arc-20160816;
        b=GZtFBLwPn0Xsh5yDbFxQHy7QBZ8HKxTl12NuRpnBKHFKv6lKQ/3R0zXxcoz0fJ80Fl
         Mr1KImgq01ln8s+IZAvoYDHs0XpxBG0aNyoGtIIO9zHJw147iSWV+dW2+H0n9CzynjOu
         TCgQ7QwYzWFmrxNzXqV4kE27tiJABiFkK6i5EtcA/w7rGiKnGhDR56mI4TR7cdulyue9
         DQY63NLENKdl0QZsb7SItrWkMFH8wY2v7kUhY0TwtcAIs4NoWcR0KuB7BigUA4N4JvfT
         b2/6ORleti3panMIkKDE/05T6zs0xtgURRiJokfhbE8OR00LjuO0XXYN1pgxZspL+5mx
         twDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=r59ut8IrNHx0kwO0EGXzWZjcMQzRRcVGIJY94W9V59c=;
        b=x2+5mhlqP5KiRcU6GBcPaVp2ZEIz9nhfLh27rkfCedglmzR+V1B8hBQiseKfRNAOoP
         A7iEeku6XnWNXJ/GzDP0Pws/OOt3c+/I/7BLo7xo4sZYtIYhvZzD+/pNIIFKcqcn5Cb8
         f6KDnRfHGIN5mSzVTUMZ8+XWpitPfcKaxg+bc0HmG4gRrR1CL/VkQXdB7Ye4aUtc+lnH
         nrYE0Ib1g3KwyCVY2SqVPiDjOhr6JeYCenxJDhva+ClbZrEImS8hw7iA6ZMNFas2v6CT
         FpdZgwmy78/60bh7cM1jbk9yZLbbgz+CJ6Hgzn8lodfFD5enYuptDwxgZA9X72lhziOQ
         KKmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=r59ut8IrNHx0kwO0EGXzWZjcMQzRRcVGIJY94W9V59c=;
        b=dEj8eFXvO0LEeOeEHjyE778Skx1JDo5iyFMaE0K9XZu/0ia7j05wOwbnGoQqtddzX+
         TRbZmAICO3xpiRDHK0lvpJxK/KPkNJe9G1SdilceROriVTyFLUly52Fan0IAIRyvUWtu
         T4P4NigZSqYfx//P+GQ5k1JRQdS9p1dsyDacoBgxZjAFt//wjZDDnfzO3WsmM02h5c40
         i+Rd5AjO4OhxnrcviFBPn2c3djOKzXBBOwbJRMwwUwVVvr1PzDrKmA0J5ssHS5QxS1gh
         KndbfhwdswURgX8lG9YCTnsDjVs7PL1q+NQMrdrgYEXGEJjej43jOQiHfh0SREjJL1mr
         dmIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=r59ut8IrNHx0kwO0EGXzWZjcMQzRRcVGIJY94W9V59c=;
        b=bNGvFXPc0HH3PxsCfCAkiOIgvSE06yeB0n0GAOpejM6FziP3KuN6Ixy2AjdclovEuu
         eyD2cJLQXlZ45LEy/0t7ynd10kUhiwad7KqLJoBXvAuKpMhqadFO6n1ug7/AtZ6GVm+S
         SqRLA1cVJDghWC6e5RsjCnb+OyLEvJ1HAC2WnLFkKeoQqxpz0/hiTm+RVlcbVYjHPRbs
         a1b+bviQ4INy3/PSC1Si/byT4bitma7r/VACkI2Na4u/TdirXqQK0jQpDczuPvizjvPk
         IyQfE1ewCd4obyruw8+5bWxuwnm2sArG/l04t4FmNfzT7lsYDjyRnro8Pl+Wo1VbBcbN
         bKgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533a3GTdUS+/TlibWFd2QrFUVNFUhTqapUo3j7pzUkqxQ5ifFbqz
	Ld5GvQNN6YzJAWq7jiR1bi0=
X-Google-Smtp-Source: ABdhPJyGcyVLsgTeyftDZkMu1LcpTzHcBKep4kUfojwjIvAMPh761JJzeyhkJliaHCpGnYjNGoggIQ==
X-Received: by 2002:a9d:7519:: with SMTP id r25mr930441otk.339.1611590767943;
        Mon, 25 Jan 2021 08:06:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b489:: with SMTP id d131ls2127158oif.10.gmail; Mon, 25
 Jan 2021 08:06:07 -0800 (PST)
X-Received: by 2002:aca:5bd4:: with SMTP id p203mr563431oib.108.1611590767593;
        Mon, 25 Jan 2021 08:06:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611590767; cv=none;
        d=google.com; s=arc-20160816;
        b=IN0lneL4oECNuDirV5ANS0CuwL24atpvD0jAkz5q77r0QLcjNftGsJBP4ddX51+8+h
         c129nZ5vYCreXuznsJUc6N+dlxLnNOj3BWgifL4gvkZZK4NdIJ41QTh3yZt4rbPfSObA
         bZkxW/YRwbFRkXlK01QnWIKzUmI+Z6gxHavnXht/KDIktUqIdb6QjYNqb3w16tfBG3zp
         KFOkYZ9w4+oRgfb6njR4Na2XCb87HaB7XadmcNVslj3knmScKFrWOS0DUjUT2z1J41pe
         IWg31BsT6/OjKI7/AlF7CVla+iUBX2xYTxw4YDI0wJrzNLFeY4unviE9JxDpktQaMtfd
         l6PA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=9zTpZydWCcNHQQC71CpRKgsK4aUTURwt6AR33ovc1bw=;
        b=U/tRdC+6TvWUiCH7F0La4N9V2JQGFdWkucaY3oQIqhqxk6ZR6mN7+z/dnph8WC4TF4
         DZPtF/3CTGXxyCpxKJbmR84NAmVR/rlt5dQbORk7Ia2tjYTNWebfoACmkhrC/jtVVvUR
         SXQnsc12x1rvUNOLPIz7TgawX00ivJgJPtMwM3rD8i32X8yhOO/EkIrb+v4fXr7ezmwH
         adnIB+guZgHWXqo8UJtBX8demBY/5RPoTwI76n0WB4wI2N2u36ksoqfhBQsJvFNzvFcu
         2AGGCIDgK9vc9ruoal1mXDqv64vQY2WPw7436WIz5eyb7nsWGznTX11fS4i7x6lSngxG
         Uv7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a188si502719oob.1.2021.01.25.08.06.07
        for <kasan-dev@googlegroups.com>;
        Mon, 25 Jan 2021 08:06:07 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 22511139F;
	Mon, 25 Jan 2021 08:06:07 -0800 (PST)
Received: from [10.37.8.33] (unknown [10.37.8.33])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 68E893F68F;
	Mon, 25 Jan 2021 08:06:04 -0800 (PST)
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
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <4bd1c01b-613c-787f-4363-c55a071f14ae@arm.com>
Date: Mon, 25 Jan 2021 16:09:57 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210125145911.GG25360@gaia>
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



On 1/25/21 2:59 PM, Catalin Marinas wrote:
> On Mon, Jan 25, 2021 at 02:36:34PM +0000, Vincenzo Frascino wrote:
>> On 1/25/21 1:02 PM, Mark Rutland wrote:
>>> On Fri, Jan 22, 2021 at 03:56:40PM +0000, Vincenzo Frascino wrote:
>>>> Currently, the __is_lm_address() check just masks out the top 12 bits
>>>> of the address, but if they are 0, it still yields a true result.
>>>> This has as a side effect that virt_addr_valid() returns true even for
>>>> invalid virtual addresses (e.g. 0x0).
>>>>
>>>> Improve the detection checking that it's actually a kernel address
>>>> starting at PAGE_OFFSET.
>>>>
>>>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>>>> Cc: Will Deacon <will@kernel.org>
>>>> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
>>>> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
>>>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>>>
>>> Looking around, it seems that there are some existing uses of
>>> virt_addr_valid() that expect it to reject addresses outside of the
>>> TTBR1 range. For example, check_mem_type() in drivers/tee/optee/call.c.
>>>
>>> Given that, I think we need something that's easy to backport to stable.
>>>
>>
>> I agree, I started looking at it this morning and I found cases even in the main
>> allocators (slub and page_alloc) either then the one you mentioned.
>>
>>> This patch itself looks fine, but it's not going to backport very far,
>>> so I suspect we might need to write a preparatory patch that adds an
>>> explicit range check to virt_addr_valid() which can be trivially
>>> backported.
>>>
>>
>> I checked the old releases and I agree this is not back-portable as it stands.
>> I propose therefore to add a preparatory patch with the check below:
>>
>> #define __is_ttrb1_address(addr)	((u64)(addr) >= PAGE_OFFSET && \
>> 					(u64)(addr) < PAGE_END)
>>
>> If it works for you I am happy to take care of it and post a new version of my
>> patches.
> 
> I'm not entirely sure we need a preparatory patch. IIUC (it needs
> checking), virt_addr_valid() was fine until 5.4, broken by commit
> 14c127c957c1 ("arm64: mm: Flip kernel VA space"). Will addressed the
> flip case in 68dd8ef32162 ("arm64: memory: Fix virt_addr_valid() using
> __is_lm_address()") but this broke the <PAGE_OFFSET case. So in 5.4 a
> NULL address is considered valid.
> 
> Ard's commit f4693c2716b3 ("arm64: mm: extend linear region for 52-bit
> VA configurations") changed the test to no longer rely on va_bits but
> did not change the broken semantics.
> 
> If Ard's change plus the fix proposed in this test works on 5.4, I'd say
> we just merge this patch with the corresponding Cc stable and Fixes tags
> and tweak it slightly when doing the backports as it wouldn't apply
> cleanly. IOW, I wouldn't add another check to virt_addr_valid() as we
> did not need one prior to 5.4.
> 

Thank you for the detailed analysis. I checked on 5.4 and it seems that Ard
patch (not a clean backport) plus my proposed fix works correctly and solves the
issue.

Tomorrow I will post a new version of the series that includes what you are
suggesting.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4bd1c01b-613c-787f-4363-c55a071f14ae%40arm.com.
