Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBSN2U2AAMGQEVWKFKJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id CD1942FEE92
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 16:27:06 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id z20sf1453680pgh.18
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 07:27:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611242825; cv=pass;
        d=google.com; s=arc-20160816;
        b=ji/Z9ZvF8Uk3362Metbn8Xtl51EW0ZSqye4/9CoRo4FYlMvkKuE9IcDHlcRWsYWKbs
         FtIZQ668p+oEd9ze7LqzdO7OklROFmD4o2SSL0LMHx3MnLjNV8QYH8rd+1KLaIOB4+d7
         L0VIF15NAMiESvjq/Wd7XfR5zWo6OPJaQKsynhHsH0w8s9+h1h88NdXFnPY+VFltFDeP
         m10A+pkfMEmUh8Vd9wiPl0RJ725nYFH2BLq5wJgiUEvtX9DHDqSn1aVnZXBGRPy+hWZ7
         grlyX/yw4lQWNH/w8nxRboT4kFz7rgzzj30JdTfhbMW5FMvNT5LkxrE86WbdJhydXDKl
         3GbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=5D31iylSxXhnqGRMLA/m+tHS9WV5XrVH+R/8dpEK/ZY=;
        b=ijeD6WJ6fd+pwm9OHy39k/3/eASb3odNqF9Q11HqOYdobzOR8qrCTQ4lDQl/U0RljS
         bQPoYguB1zi7hQeL8IAYmiKWRXUA4ANXmNfrrenql7vPvoVkTzvnX/t+S6x7rZivMWfP
         lcXzGFc3fu/28PVyF/eOB9dkp0tjwLCkpc7BvAz+OU/b+kheENiM1+qUxDnLos2Fabo4
         C6ZH9Tyr2/cNjmptidQmBrLU+SRfEe/F8aGnCZVOCQt4KsXKdw6OOASnGw1i8N25pQb4
         XW4P/o8RSwbQmmpGL7IfzPxKJMSK3R8+xz5q1V4W4Yilnrb8J1/kD3rfgyP2gaWEudLE
         2wTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5D31iylSxXhnqGRMLA/m+tHS9WV5XrVH+R/8dpEK/ZY=;
        b=AuMZllaP0x0jNA+bqrxbRCK2WcsBKkGadh8/stwUN6MnGnI2xSjKD/KZ88W3/3AZa6
         3gxRwVHZX72Q0sKAFRc1ycUlcccGyhdoqsWX/+J7cnOiq3uDM+Wf66TG+2RrRvtYKziR
         lXboB0LsASzzxhpU5LIUkN7kgP4cfBk9FoHxzqDNP+a3HsSJp7kpnzgaKkRV0qzX1Wn/
         EVh+nDlLxwjPabAQqBIoqWdFjsjJefuVIVq8yWd6Dtzq4fASN/VSskU493YTMRGqCC/X
         Tz99P9uHMLGy2nh7ZkfV97EuLQpA81xZEaGHHeELNba2D9iJPhO7Je357iR4/SzYu6f4
         YLLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5D31iylSxXhnqGRMLA/m+tHS9WV5XrVH+R/8dpEK/ZY=;
        b=XFLYWuEWbQpZVeIqx6g3/rcNTPKxekTdPg48PeCSxhQ8LcUbp1DJRwX3EZIavHn53a
         D2nAhOLbxBApqQ5QnaznvVVW46Wmue0V0pRDaub9vnAvxuFMXJq918V/NvZbkAUqDwO2
         l+lqkQnFcBclL/0obV/Wu8KDi/EQyux2qjHY5gCCqd7Z8zYVb0eL2vqNecBF7cpWYd+y
         S9EpyJYAj2kbAtfOk0Yy47FCub75qtsBSDVSh/L1z6M1RG8GflkEZoq2vrMFGJKwoFwP
         eLOYjjsbUBuCacENay2NqT0GEqYL4Z+jcMvLqJnzLSMGnkMNZiAN5dWWYdd/De6TeILP
         r6hg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5314gc+d++O2YU0jx6bP3uRlhGb6RJwBbGJY+90OFWJTwoRjbgKk
	lkvfbpclk/O+Y926PXvqKGM=
X-Google-Smtp-Source: ABdhPJztAK4624EMPxupZVDyvxrcTBCPczokv/t1G52umJ31tOdr+tyBaDE8ToMl/4LPbqMJ9UtLKA==
X-Received: by 2002:a17:902:ff04:b029:df:d5e5:9acc with SMTP id f4-20020a170902ff04b02900dfd5e59accmr222671plj.1.1611242825566;
        Thu, 21 Jan 2021 07:27:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4704:: with SMTP id u4ls999131pga.0.gmail; Thu, 21 Jan
 2021 07:27:05 -0800 (PST)
X-Received: by 2002:a65:57c2:: with SMTP id q2mr15210367pgr.86.1611242824863;
        Thu, 21 Jan 2021 07:27:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611242824; cv=none;
        d=google.com; s=arc-20160816;
        b=y5B9x5VOmbZXQJNSevdOlndhJU5DK7hnavLwdmwW2MPuqoZ6jk6GwKzQcoJJdmdyxN
         aJeiGI8ghWUJncNjXBlrMpgPL4mPX6On1THEPi50P8Hndt8e0wNsw4kUMIEjuremSvqv
         lc78O57XB3N2Lm20/I3LjuR8n8ax6TcSiW1soBnBWYDD27aHKGQiB2DsMZpdHqiHDPVR
         2+V1qCwDVZ1HLKpKYk+9Q16xZ3hOqv3jd7v64RTn0JoH7aWH5vYUtZvwpOFXrWgYtosU
         KQiP64RZjc1pdiDDqkQ4NR1dUmkqwAk02k4FA0X/j51H6iFY9WXwXxYIxattfQnu+qob
         +MKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=nYDFUlgc1WPX9NIeSkqHa02i2OlOQ9+G1LT0yi4CTwE=;
        b=wmtGDS9w7TKGK3nR+5oHwAzoeTzt8RqnpLKXWo876eNGYbV55HhiGOcb0JMPf6IWp9
         k3FeLfSYV8aSHNr6HZ18XKTZOwU9Of6qUjMsaOGVddD01AcS1pUZv04uz3XMOFHkOuFp
         qnsjFZmtHnDXd9u4Po+9T164XxftiaZ3NVunHcJd0pejNrYfssOeOHBgsfJVTSxaf6Wi
         oTQXv+pXgQJifYmcNbGz8UHb+ZaNNFephZzr9QL6CSgpaXTHZ8RXYrNwBL7M/3W3dTAS
         YsS7TcORoFkt4xyqqcwYk1bi6d0QcYGwyR8bYdrN81+VkGe4QzS9gqwi8GDfQ+yw6fhY
         DBPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id nl3si691040pjb.0.2021.01.21.07.27.04
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 07:27:04 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id CD45C11D4;
	Thu, 21 Jan 2021 07:27:03 -0800 (PST)
Received: from [10.37.8.32] (unknown [10.37.8.32])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 24B3B3F68F;
	Thu, 21 Jan 2021 07:27:01 -0800 (PST)
Subject: Re: [PATCH v2 1/2] arm64: Fix kernel address detection of
 __is_lm_address()
To: Mark Rutland <mark.rutland@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrey Konovalov <andreyknvl@google.com>,
 Leon Romanovsky <leonro@mellanox.com>,
 Alexander Potapenko <glider@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Ard Biesheuvel <ardb@kernel.org>
References: <20210121131956.23246-1-vincenzo.frascino@arm.com>
 <20210121131956.23246-2-vincenzo.frascino@arm.com>
 <20210121151206.GI48431@C02TD0UTHF1T.local>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <95727b4c-4578-6eb5-b518-208482e8ba62@arm.com>
Date: Thu, 21 Jan 2021 15:30:51 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210121151206.GI48431@C02TD0UTHF1T.local>
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



On 1/21/21 3:12 PM, Mark Rutland wrote:
> [adding Ard]
>

Thanks for this, it is related to his patch and I forgot to Cc: him directly.

> On Thu, Jan 21, 2021 at 01:19:55PM +0000, Vincenzo Frascino wrote:
>> Currently, the __is_lm_address() check just masks out the top 12 bits
>> of the address, but if they are 0, it still yields a true result.
>> This has as a side effect that virt_addr_valid() returns true even for
>> invalid virtual addresses (e.g. 0x0).
> 
> When it was added, __is_lm_address() was intended to distinguish valid
> kernel virtual addresses (i.e. those in the TTBR1 address range), and
> wasn't intended to do anything for addresses outside of this range. See
> commit:
> 
>   ec6d06efb0bac6cd ("arm64: Add support for CONFIG_DEBUG_VIRTUAL")
> 
> ... where it simply tests a bit.
> 
> So I believe that it's working as intended (though this is poorly
> documented), but I think you're saying that usage isn't aligned with
> that intent. Given that, I'm not sure the fixes tag is right; I think it
> has never had the semantic you're after.
>

I did not do much thinking on the intended semantics. I based my interpretation
on what you are saying (the usage is not aligned with the intent). Based on what
you are are saying, I will change the patch description removing the "Fix" term.

> I had thought the same was true for virt_addr_valid(), and that wasn't
> expected to be called for VAs outside of the kernel VA range. Is it
> actually safe to call that with NULL on other architectures?
> 

I am not sure on this, did not do any testing outside of arm64.

> I wonder if it's worth virt_addr_valid() having an explicit check for
> the kernel VA range, instead.
> 

I have no strong opinion either way even if personally I feel that modifying
__is_lm_address() is more clear. Feel free to propose something.

>> Fix the detection checking that it's actually a kernel address starting
>> at PAGE_OFFSET.
>>
>> Fixes: f4693c2716b35 ("arm64: mm: extend linear region for 52-bit VA configurations")
>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>> Cc: Will Deacon <will@kernel.org>
>> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>> ---
>>  arch/arm64/include/asm/memory.h | 2 +-
>>  1 file changed, 1 insertion(+), 1 deletion(-)
>>
>> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
>> index 18fce223b67b..e04ac898ffe4 100644
>> --- a/arch/arm64/include/asm/memory.h
>> +++ b/arch/arm64/include/asm/memory.h
>> @@ -249,7 +249,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
>>  /*
>>   * The linear kernel range starts at the bottom of the virtual address space.
>>   */
>> -#define __is_lm_address(addr)	(((u64)(addr) & ~PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
>> +#define __is_lm_address(addr)	(((u64)(addr) ^ PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
> 
> If we're going to make this stronger, can we please expand the comment
> with the intended semantic? Otherwise we're liable to break this in
> future.
> 

Based on your reply on the above matter, if you agree, I am happy to extend the
comment.

> Thanks,
> Mark.
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/95727b4c-4578-6eb5-b518-208482e8ba62%40arm.com.
