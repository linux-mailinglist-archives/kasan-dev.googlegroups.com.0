Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBIWJU2AAMGQE454XZEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id CD89D2FEF9A
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 16:58:27 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id 18sf1504869pgp.22
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 07:58:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611244706; cv=pass;
        d=google.com; s=arc-20160816;
        b=dIXPtTfjY5VQ63rgnrHLhdX3WJht+lRkyVWdFk7aKnDuQbjTG2l1Ur09l7523zUteo
         cYCW+jdmK45BgbfszmqQ4i2p2FJc2uYvB4sxKeCaDgCSmnScOn/31/Uutp3DMl5HRZSa
         wa2YgNRffOKK5148bYUnhn0N5k4wUD9metPel+PhvZ98aUl6srvBNQJGJMGbAob9OQSe
         lO9gAO97ALxrVje2hIdNOB56ocaa/aG2H6w+lP10yBYrBewzgnembGEJvQSuD7ApeSXZ
         NP8qXRajsBhpYO7dfFZ0cDk1jBqII3WsI2VX0HMWWgUFOhoq+tfMRXXJh0UeO1GqAslQ
         yKQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=wf1f1zG81zlPy7RE/dT7/MQ+qFlqNDGxPfcqT16On4k=;
        b=WYqlR3x0tBfq6FzSFw6kBvEW1LfRIgpW0/UlWC3Sm/Kh8QGA8kbwZ3D2aDY4S4K9vP
         XvkGtVtM1xdic7GyTHQnMh8Buxk505HzIATgyVh0bm8TE7nSFUur+UPxzXT1hIfeEaUM
         Zxncs9uo8EFw+Yo+QN/QssSZXaLTxDDktKCpAxZ/wW9j9Ur5n4ovwVWlxT2JqOT4YYsF
         cBQsVwwb5G84aBkGf3iebQfiDpS6Claaq0ILYwCNtCr+oZ6liTsMp5MPcfkVf7bNZQgY
         j/qetWMK6mt4zTTFHLhjAuhtnQ9c83/BesUvIgfQ+vQQrz3n3zEGMtzNQMCGPxrcNNBS
         n8LQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wf1f1zG81zlPy7RE/dT7/MQ+qFlqNDGxPfcqT16On4k=;
        b=bLiKA+9XA2TX22k7nXtHBADMfNUMHVWCevbwOazkASTqVUAub/su8J/6gu3nNZFT37
         p/rZGfFPsyXQf+Tvi4Wz2E0iwJEu9m6oAlVMIhhaXTTXu8m6MixMOyoG/C8wZMI/zisR
         5pV04I7Fqlju7iHAyTlx2aLNS2ndxQdVYn8CfVPMu0imFIISfA8VUg95YTKVCcE6n3/P
         fplOtx2ZW457njk6C+sv2gNgrRjegacGC7Co5OW4zBn0WVc5uyUAqnHcujBQq9/BHTwY
         TAFU1OXvA+CYhHAcd8n5hEXZ3ywWaEVWkICTycJYTedMOImij7KrX2br1BKkx+BXxbCe
         KY7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wf1f1zG81zlPy7RE/dT7/MQ+qFlqNDGxPfcqT16On4k=;
        b=gY7JxTexsxxx0Yum1LXezaIP6WYYbLlJYmvhAHc3WxAdC9D6Zq7GyNO1jOinskDFdX
         8HfBNV7NCfvocye4dOG56OtpDiDWq+I22t+pXmES3K6Kllmw5E0n2d1DrObeuHfHNuUt
         iRtMQiwrxwABCYI/pPpey51W8DNIPQc9F6237qTdlVxNwzING+nM42ikSgvVVhsFArqs
         gOaFbb4YTjzUAfLadtnAZUXMNtfEYCfJvFmm3oirVaFEMeIrB9gM8BVO8fs0W5C3+5ol
         Xnvi5U2tC2GYqUpXRK50AzoHqAdnNdQ4pBRIAWs95zzMkF8I+6XYaXBmJCQJE0MKyBpC
         Upow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533cay1gudfemJtKb/JNKRigVs6XWNdLtzSqTpifPC3xERSsmp3i
	PH5gRiEkHo+hN/vQHylmKCg=
X-Google-Smtp-Source: ABdhPJyDM+IZnhswRaPUCdkJQudF5SFBpHA8AGYhg/xeKldlWViW5UhC8J5p6tw0bfrOVWekXg2qdA==
X-Received: by 2002:a17:902:bccc:b029:de:8483:506d with SMTP id o12-20020a170902bcccb02900de8483506dmr315936pls.53.1611244706553;
        Thu, 21 Jan 2021 07:58:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6d0e:: with SMTP id i14ls1012150pgc.8.gmail; Thu, 21 Jan
 2021 07:58:26 -0800 (PST)
X-Received: by 2002:a65:6212:: with SMTP id d18mr546519pgv.141.1611244705976;
        Thu, 21 Jan 2021 07:58:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611244705; cv=none;
        d=google.com; s=arc-20160816;
        b=t5EmnXjAYYgtOVdVFa6YB54M/aUzYhI6ly3XNg6VO+Rcoun34TXUH208ozjvhmHSTo
         PUjIlY24fm91FUKhkOUWiDyN6Wf6uYKpIUtbCyRP9fIiw9rFxGYC//WJ+IXRTFVHIhg4
         ITZvCOJNUi6dGY9oN+SspQfsV6nmtPVcqG6CYqs4YOuO8/wRFXWLQ80zROuEKFdiCt92
         7N04JO5w1VQ1YFCR+sxWbwsFhn95S9oLJXG1LdjPaOYg9Elud+xwc+aI0LxgQf3CtS7N
         fUzBChRN28VmrHdEMmYthfu35XV35nvd1oxbrQGKRwuFYWRBT2hwM1K8MzFtaVUiXMT2
         UpOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=xt2FOzk5uFuFDdXmOBCm+9sqNy+fqMvm+e6I49Cw85E=;
        b=PBwrIsrd2Vro/W7fHaxJWzxnOMDUeevy2FLu0qRi24eARc4j7y3ErBZVDfjz7JwUWb
         RSNvVIyRp5Y//qNbr5fr9nsiYOY2xOCLUsY/09Avi1rrFbFyTXjwaYOwkbgNg/HBjQcq
         Nv+xhKAbQ9+BzcsknoVCzZ76vROzEjeXZ8325kUskrlYSWGVIjkIUEelpH0wprCUrRos
         X71LnO/2Xh/R0kmpuPv28r+jayZ82DdL8YWMLq+4hxeXgIyLNWLQQe+bxH3cdDmNUldi
         3pblIXHhfkDVWQVQlEaYq7hxX9JeOZy7ngz8+SNbNlLwJ/gRz9CiNCOw5pR+RNycpYG1
         WkTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d13si305945pgm.5.2021.01.21.07.58.25
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 07:58:25 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 66F7A139F;
	Thu, 21 Jan 2021 07:58:25 -0800 (PST)
Received: from [10.37.8.32] (unknown [10.37.8.32])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 740DD3F68F;
	Thu, 21 Jan 2021 07:58:23 -0800 (PST)
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
 <95727b4c-4578-6eb5-b518-208482e8ba62@arm.com>
 <20210121154938.GJ48431@C02TD0UTHF1T.local>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <5a389787-4f6a-7577-22fc-f5594409e1ae@arm.com>
Date: Thu, 21 Jan 2021 16:02:14 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210121154938.GJ48431@C02TD0UTHF1T.local>
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



On 1/21/21 3:49 PM, Mark Rutland wrote:
> On Thu, Jan 21, 2021 at 03:30:51PM +0000, Vincenzo Frascino wrote:
>> On 1/21/21 3:12 PM, Mark Rutland wrote:
>>> On Thu, Jan 21, 2021 at 01:19:55PM +0000, Vincenzo Frascino wrote:
>>>> Currently, the __is_lm_address() check just masks out the top 12 bits
>>>> of the address, but if they are 0, it still yields a true result.
>>>> This has as a side effect that virt_addr_valid() returns true even for
>>>> invalid virtual addresses (e.g. 0x0).
>>>
>>> When it was added, __is_lm_address() was intended to distinguish valid
>>> kernel virtual addresses (i.e. those in the TTBR1 address range), and
>>> wasn't intended to do anything for addresses outside of this range. See
>>> commit:
>>>
>>>   ec6d06efb0bac6cd ("arm64: Add support for CONFIG_DEBUG_VIRTUAL")
>>>
>>> ... where it simply tests a bit.
>>>
>>> So I believe that it's working as intended (though this is poorly
>>> documented), but I think you're saying that usage isn't aligned with
>>> that intent. Given that, I'm not sure the fixes tag is right; I think it
>>> has never had the semantic you're after.
>>>
>> I did not do much thinking on the intended semantics. I based my interpretation
>> on what you are saying (the usage is not aligned with the intent). Based on what
>> you are are saying, I will change the patch description removing the "Fix" term.
> 
> Thanks! I assume that also means removing the fixes tag.
>

Obviously ;)

>>> I had thought the same was true for virt_addr_valid(), and that wasn't
>>> expected to be called for VAs outside of the kernel VA range. Is it
>>> actually safe to call that with NULL on other architectures?
>>
>> I am not sure on this, did not do any testing outside of arm64.
> 
> I think it'd be worth checking, if we're going to use this in common
> code.
> 

Ok, I will run some tests and let you know.

>>> I wonder if it's worth virt_addr_valid() having an explicit check for
>>> the kernel VA range, instead.
>>
>> I have no strong opinion either way even if personally I feel that modifying
>> __is_lm_address() is more clear. Feel free to propose something.
> 
> Sure; I'm happy for it to live within __is_lm_address() if that's
> simpler overall, given it doesn't look like it's making that more
> complex or expensive.
> 
>>>> Fix the detection checking that it's actually a kernel address starting
>>>> at PAGE_OFFSET.
>>>>
>>>> Fixes: f4693c2716b35 ("arm64: mm: extend linear region for 52-bit VA configurations")
>>>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>>>> Cc: Will Deacon <will@kernel.org>
>>>> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
>>>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>>>> ---
>>>>  arch/arm64/include/asm/memory.h | 2 +-
>>>>  1 file changed, 1 insertion(+), 1 deletion(-)
>>>>
>>>> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
>>>> index 18fce223b67b..e04ac898ffe4 100644
>>>> --- a/arch/arm64/include/asm/memory.h
>>>> +++ b/arch/arm64/include/asm/memory.h
>>>> @@ -249,7 +249,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
>>>>  /*
>>>>   * The linear kernel range starts at the bottom of the virtual address space.
>>>>   */
>>>> -#define __is_lm_address(addr)	(((u64)(addr) & ~PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
>>>> +#define __is_lm_address(addr)	(((u64)(addr) ^ PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
>>>
>>> If we're going to make this stronger, can we please expand the comment
>>> with the intended semantic? Otherwise we're liable to break this in
>>> future.
>>
>> Based on your reply on the above matter, if you agree, I am happy to extend the
>> comment.
> 
> Works for me; how about:
> 
> /*
>  * Check whether an arbitrary address is within the linear map, which
>  * lives in the [PAGE_OFFSET, PAGE_END) interval at the bottom of the
>  * kernel's TTBR1 address range.
>  */
> 
> ... with "arbitrary" being the key word.
> 

Sounds good to me! I will post the new version after confirming the behavior of
virt_addr_valid() on the other architectures.

> Thanks,
> Mark.
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5a389787-4f6a-7577-22fc-f5594409e1ae%40arm.com.
