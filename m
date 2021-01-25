Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBDFNXOAAMGQEX2DEHKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 51FDC302652
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 15:32:46 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id m9sf7696211plt.5
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 06:32:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611585165; cv=pass;
        d=google.com; s=arc-20160816;
        b=rSBVBDIdKn8M6W7kfBLjxU4RMvpatEqhg3EzOq2F1DdPAMiU4Lq/7cOUiRX2FzGfQO
         NcPzF1I87sjLRkAFdGkJgl1UGIQcTHz+1mHW3RJ7ldJLlBxk0NqkRmYppRNExELZnXMw
         P5iebY7vQIYdvqqglYVxFfWUF4OvH9QydE4n/kCq6weHYc24151mtwqg+z9j9/qNkpZh
         Wo/eRM7Aj54MXPjs8z2FYzjEMiHRkWivIIExudom/6sXNTNwMtmqiyJTCD8JNxXs2/In
         HxthCQdblM4OlTLs7mYBqWcS1heSR1txDDzZsUomoI0ZiSfVqQbaxKFdn+bM3a5O7QRS
         Exrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=4AYSwYUGGFQjjpjhELGSFaEVyM5S05cx+taG/7JR1Vw=;
        b=PDDeXCcCdDvI4qwyOBRINcfdbDUXqPLI6gO7MK4tlNW8SLrbcaIRlJXIGqVyZ5d++H
         B32bfW9RkJsWzNcZz5RlFFvsWIgbzUHgNe0x3cecLe0cbWL1ynNU1wfQRQZkNEVvMwH1
         1m/0xeQt367T80Yqn2rzacxj2jHrDTsWWFpdhYcmrD9HpeQOP6rJNUCvH+MN7Ru6iYui
         eB9aaEqwwZWk3dz9FTZeempXoIwkNnseyg9Ker/6tAidy5uopZPkYsB7stnMjYx28+zy
         dVEdYqdQApecSAry94WyECdobrmp46sco9NOMEz6/bW5iUeWotDdAkWLfiT7X9W1m6Ua
         xhvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4AYSwYUGGFQjjpjhELGSFaEVyM5S05cx+taG/7JR1Vw=;
        b=mNG9BTmfPTO8+M8OphhvKNRbqZZLVRQarWl7EaC7tsmkCtEXCAp9fNGEbdlUD7j20y
         UEgqNbyLOUO0PfpEeByo20XPXeBzf4Yiplu+Vhsuo153SNNnzW5TrQOG/ouzlz//1J8N
         WMUjFd9sxUQDLaQ+kcdEBvpJobWQPkvZMFAJ+0u2fv0M0GHNqi7GXpqu2WwY8E9OSYDG
         T5/hXulWpJndT/Q+CJOgDrxbgLWe6ORMM9fvL2kffpD7C4rIim+oyHYI0Zs4YxzmThQF
         PqGI3iEh0RjcdVixLeNi8OCk2iHEVzgUyjyE7D8pk4OOGtXFaJPR1+5NzsmuPxcYgv29
         Y5UA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4AYSwYUGGFQjjpjhELGSFaEVyM5S05cx+taG/7JR1Vw=;
        b=g7BgqcqyNTpddVnAprmsSZyYM49y4bUr83WauckhpzjPGZL/2pDT7/gwWTJgs7qMZ0
         w8WyEk4tZ8CIpQ1DKmcIlL1FnzuQZhLl97sgN0E0Zlb+dvh7o8R421+oqy1um6oETKys
         4VD9+rtuFjMTA1XcSHsN6GYdmuVl/Fi1NASNpCRX+ufClojoSWWhVwjum+o9vXm0mv+m
         X6kutfnIAiM3vlAW0Pf/8u5bsajE7LYf/ZGMFP+FRKCEHVc1TwJO/B901k4UtfJN3Q41
         cyzWFmibChkypClMBzso97t4KOgTgaSg/OTasab1Sf+E1z13P1ihlE+bfCY+VjcPUTTr
         G0LQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532nT3M+xa/2IBc4ZT7xk8DnBkaQ4IRWeT6yDYqssGoXBUQR3Xh8
	EVKMtm/FSH0oqzQlqcBulpw=
X-Google-Smtp-Source: ABdhPJwQoyLtG8s/yA6YVPADGrgm7g1sVsIOwiVXOkkEXuV5Ks2+3oygZHOXI6FThnSXnD7MFShChA==
X-Received: by 2002:a63:5720:: with SMTP id l32mr929197pgb.64.1611585164773;
        Mon, 25 Jan 2021 06:32:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4b8f:: with SMTP id lr15ls7605636pjb.3.gmail; Mon,
 25 Jan 2021 06:32:44 -0800 (PST)
X-Received: by 2002:a17:902:47:b029:de:c58e:8257 with SMTP id 65-20020a1709020047b02900dec58e8257mr934001pla.61.1611585164245;
        Mon, 25 Jan 2021 06:32:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611585164; cv=none;
        d=google.com; s=arc-20160816;
        b=HWlPmYaY1fpwRcfzHzgyuMszpAcSNUaLoygfbZGdqKidj9gCARDtJycoB60tUT3Rgh
         o3y2AdW2BWTHl/ico2lAG7UWvcD7OPouSOymv7mLvZUwVDOKb/Tti1yU9mWUhObxrLip
         pCpxh5wPIWcMcd+fwSfIHcStV6gRg0QcuwL67Ls2/M0i9ajwg2JaoTuc7fSfJCDte70g
         l7XQsaQH+HaQkS6hEkldPUIk8NSpptGuyxXWZK8LGherZ7pZIB+3UGQRITA/DETV/684
         DaZHDqT2oF+FKgkgG13JgTswxcuMzRyJI6KyN+STc0Q5zm9RIDeArwnJQnfIIaQElvtX
         sP/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=MR5LtK4nKh6IV6Q8EHP7KZSH5ColUDc9Z12plxwkoLM=;
        b=U6x6OQTW/VbDpK9+nLVTHB07EXZ8Z7y1oqIXI7XLqnnUu2BP+mu4skUoDzoXARDHWl
         fxxFbVYKzBI88KFk/wLQg+nXXjvvIyZg42NYRDwkDGd9jKeI9EsfwazSbJZrkJI478MA
         jO0xSXus52f+ZNqTXe+vVUtzYVYHKQnyp7PN0Y0+qM19c4KUrQ3Vl9VaKrRA2j2GHsXA
         Zf0QLddnXzoIwt5/7GZRf6c9r8uO1RzBm11HNvK12UDe5/XBueARaU7Dgr3jEANKguOa
         Kjpv/2ZuVzadKbv3k0nqp/lfSog/LdjgE/9uUGc+DxhoUmf9/aSzMoFtbS59mfLQ5aj7
         +PEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id c3si769160pll.0.2021.01.25.06.32.43
        for <kasan-dev@googlegroups.com>;
        Mon, 25 Jan 2021 06:32:44 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 3AD53139F;
	Mon, 25 Jan 2021 06:32:43 -0800 (PST)
Received: from [10.37.8.33] (unknown [10.37.8.33])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 26BA03F66B;
	Mon, 25 Jan 2021 06:32:41 -0800 (PST)
Subject: Re: [PATCH v4 1/3] arm64: Improve kernel address detection of
 __is_lm_address()
To: Mark Rutland <mark.rutland@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Leon Romanovsky <leonro@mellanox.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 "Paul E . McKenney" <paulmck@kernel.org>,
 Naresh Kamboju <naresh.kamboju@linaro.org>
References: <20210122155642.23187-1-vincenzo.frascino@arm.com>
 <20210122155642.23187-2-vincenzo.frascino@arm.com>
 <20210125130204.GA4565@C02TD0UTHF1T.local>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <ddc0f9e2-f63e-9c34-f0a4-067d1c5d63b8@arm.com>
Date: Mon, 25 Jan 2021 14:36:34 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210125130204.GA4565@C02TD0UTHF1T.local>
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

Hi Mark,

On 1/25/21 1:02 PM, Mark Rutland wrote:
> Hi Vincenzo,
> 
> On Fri, Jan 22, 2021 at 03:56:40PM +0000, Vincenzo Frascino wrote:
>> Currently, the __is_lm_address() check just masks out the top 12 bits
>> of the address, but if they are 0, it still yields a true result.
>> This has as a side effect that virt_addr_valid() returns true even for
>> invalid virtual addresses (e.g. 0x0).
>>
>> Improve the detection checking that it's actually a kernel address
>> starting at PAGE_OFFSET.
>>
>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>> Cc: Will Deacon <will@kernel.org>
>> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
>> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> 
> Looking around, it seems that there are some existing uses of
> virt_addr_valid() that expect it to reject addresses outside of the
> TTBR1 range. For example, check_mem_type() in drivers/tee/optee/call.c.
> 
> Given that, I think we need something that's easy to backport to stable.
> 

I agree, I started looking at it this morning and I found cases even in the main
allocators (slub and page_alloc) either then the one you mentioned.

> This patch itself looks fine, but it's not going to backport very far,
> so I suspect we might need to write a preparatory patch that adds an
> explicit range check to virt_addr_valid() which can be trivially
> backported.
> 

I checked the old releases and I agree this is not back-portable as it stands.
I propose therefore to add a preparatory patch with the check below:

#define __is_ttrb1_address(addr)	((u64)(addr) >= PAGE_OFFSET && \
					(u64)(addr) < PAGE_END)

If it works for you I am happy to take care of it and post a new version of my
patches.

Thanks!

> For this patch:
> 
> Acked-by: Mark Rutland <mark.rutland@arm.com>
> 
> Thanks,
> Mark.
> 
>> ---
>>  arch/arm64/include/asm/memory.h | 6 ++++--
>>  1 file changed, 4 insertions(+), 2 deletions(-)
>>
>> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
>> index 18fce223b67b..99d7e1494aaa 100644
>> --- a/arch/arm64/include/asm/memory.h
>> +++ b/arch/arm64/include/asm/memory.h
>> @@ -247,9 +247,11 @@ static inline const void *__tag_set(const void *addr, u8 tag)
>>  
>>  
>>  /*
>> - * The linear kernel range starts at the bottom of the virtual address space.
>> + * Check whether an arbitrary address is within the linear map, which
>> + * lives in the [PAGE_OFFSET, PAGE_END) interval at the bottom of the
>> + * kernel's TTBR1 address range.
>>   */
>> -#define __is_lm_address(addr)	(((u64)(addr) & ~PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
>> +#define __is_lm_address(addr)	(((u64)(addr) ^ PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
>>  
>>  #define __lm_to_phys(addr)	(((addr) & ~PAGE_OFFSET) + PHYS_OFFSET)
>>  #define __kimg_to_phys(addr)	((addr) - kimage_voffset)
>> -- 
>> 2.30.0
>>

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ddc0f9e2-f63e-9c34-f0a4-067d1c5d63b8%40arm.com.
