Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBG4I3X7QKGQEDHTIG5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 48E162ED57A
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Jan 2021 18:25:49 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id u1sf4857955ooi.12
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Jan 2021 09:25:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610040348; cv=pass;
        d=google.com; s=arc-20160816;
        b=cO+GbXdHQ6v+JpPh8d1Iv6S3BQOEJUyITTmh68QheySxlP2ezASKHBf+Yb57GZ0T6g
         vJGY2a+0HiSR9CYelUQvQZSvMWxO/h3gw6pVg4PeVB5bfmxv0Pr8COUJ89cjhv8g7kGU
         YtpXC4ZmwOEGlkwE7/rOPjcdurI6uzlXghRnt6X/5zvyIYTcu8c6kgMBHXrtTWe1BP6T
         uiROUo8eWuG56ZXxgfDR18jc48BqxFSMQM3czq1y0AOoT3q11WLUUpck/jUXbyREx0LR
         Efm6OKgz/blXy842g1zwa2qLSi+K64UwqcFH1OaMDpXWiP5tAwo/jnB1BTblZSw1UlCY
         8UZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=O0PWc/YdvfaCf6qdHe6BzAL8OSMOPHT/iSPZ7GfC6DA=;
        b=kem4VCxaPzw4wYACKdAWRVxdj3emNRDIlJKyM/AUt9jjvPEhn/lKotgxbJNF2mzgn6
         wwzv5WQYrRRoh63Zl0av0dpgrKP28rBtTDvAd/uJ2exEOT9HANgqg3jaMqhbIg7iITFs
         Uh++oBKTgo8ayjSXCJxrLMpR14YMT1kLrIWDCyrTV2K+4xH14uk/7EohntSYf43k2Bgq
         87axMxjQ5qYfMGfoKPzaAGCHDzZnZ10ynXJe7Sb0XJ0Mq2/7rwcIA9+lHXH8vCtsuvBB
         gV41HCPAYjDglH/Y7ugrciOYpYa//7TKRlWP5XVveqXC5z6ck/n8mYoLPcnUuaxY+7C3
         2Jwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=O0PWc/YdvfaCf6qdHe6BzAL8OSMOPHT/iSPZ7GfC6DA=;
        b=TPKSeofWocap39xl118ImrEnPm3GmxHspu8sftPOss/M0plryERjK0QNANUxru3TPH
         zG681ek/dwmPWBQ3lq1oHxA0o7JgEpLiKQ4+n6oZVBGffIWWKZHzw9RgNJ9oz57m60jv
         EqGEOKf7htwVYyCySjHgaKWW+5CjFJ/yfc3+7ZATdDniQsIDSBUdU0D+4ib98H29EmyS
         oa95hNWlaItqOOMJofOrpwTDDw7jZSJlfJ00vgGQcY6vVDjWni009kCCyWbqtE1c9Qcv
         XmWKoszW4bbSY2IJVZRmQJL8j9ESKlCF6VDiQVxrF8d7Th9Sfnr1aEPDwKxxWXh0d3B1
         Ekgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=O0PWc/YdvfaCf6qdHe6BzAL8OSMOPHT/iSPZ7GfC6DA=;
        b=cgVv6UbVPhj6NhplkFDxj8uUOUZ6Uu8Y6em8Svw65YySnL3TfWEu/bSaS0+VVKU5J/
         OOb2j+8JZbtuaIrlDhOyVKDxX9skPJJiCi57Hf1KOnmU0G/Qhs8qeSmkaaSmcSFtGacb
         cblBDJsO+Dpqzje3UsK336pKO6/IzHF3iHcE3vVlF6v0gwgwt1P5yClVqYCzoQQBOT/n
         tWOK0ih2M4MD68wjZhP3MjjJpM0O326OkJzhLA8U3E23uOuy3U4KFvxRKlBA4/+Lztm0
         4+lQbn6KHTAzysI8FRxPRviyjcU1xPoj1zM9gFD23Ctzi3R9o3dc9LtD7DX8dCYLQkYI
         pXwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532vcmb7CBVQWMZe+OQY0FQgrzchMzBelKvDgY+fQBu44bnAgz9K
	Pbq/0CUMQUy9m8OTmIxt4gw=
X-Google-Smtp-Source: ABdhPJwGNrwM7Fx80whhA4y8JfOWQvBy8ncZlr2Eehca4BgV9lWjcIon9OZ6XUMjxVn/cGUc9IrLHA==
X-Received: by 2002:a9d:6f02:: with SMTP id n2mr7073684otq.182.1610040347978;
        Thu, 07 Jan 2021 09:25:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:331:: with SMTP id 46ls2100125otv.7.gmail; Thu, 07 Jan
 2021 09:25:47 -0800 (PST)
X-Received: by 2002:a9d:19c9:: with SMTP id k67mr7327279otk.292.1610040347593;
        Thu, 07 Jan 2021 09:25:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610040347; cv=none;
        d=google.com; s=arc-20160816;
        b=ggDICCbWa2uiX5+zPfvFN7pvj5AMeOpHZhNbpeThkG9wx2hQIUy8QQ0RBOfTvHd0Q6
         2kxCNNSKRKqBlr7KqiLXwazooi4ypHbNyI7CotgUC9nBsmNhaE32KKzLXNGfEFwLuGyh
         LEzz+ZrZrr5PjYj6vlTmub6krslhP30t+In3bk7xrVANU3kittmeI6lwp2HpT4QWTJ/Y
         vsvo8RAd7fVwzrzF7BlxGKP2QjwIFI2kG1CkI1S8Vq+4fFO1EUlcFwwDxk2lAzsXkR66
         +vaCITUQmI6Ap8ayb9TYztwhwQ20yDvlANr7pozOhfnfG0vgprF6et31PV38QKAuAe6P
         xMYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=vMhxWIfdyWLp8A2ziG0xsqbvCQUFxEjH7HET0wKd9lc=;
        b=leqmjhf/YrePdijTBGufp9kI8e9sTd3JmYgMvRJLkEqVTtBGvLHX1boeDr8RFTvqq2
         pfKS7E2UFwTCRHf+M5VvtJxxp2/M4g7RNAQgHl9rrP3zayKj+wacgYG5RFKmUJVAmKbF
         YWqsehvFdvNVl1crxsOzkA/L+l+dZrhKc1FuwVgcPSiby9vpAHwt6hdbizbLbKoI28XY
         V8Em/vfl+oV0KyrMz4Y5r7ZJ3ZVqMeBhro8XLpfqtmurQNzdFCz4zbHTjviFP4p6TJHe
         6D7tKumPhmDEBe+esSz8kuKb3iS1fS1wWkom0dIGc9Xo7lQGt7H3TiB/XGH1AHWQDQhP
         MBCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a33si515022ooj.2.2021.01.07.09.25.47
        for <kasan-dev@googlegroups.com>;
        Thu, 07 Jan 2021 09:25:47 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 1A85B31B;
	Thu,  7 Jan 2021 09:25:47 -0800 (PST)
Received: from [10.37.8.33] (unknown [10.37.8.33])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 6166C3F719;
	Thu,  7 Jan 2021 09:25:44 -0800 (PST)
Subject: Re: [PATCH 2/4] arm64: mte: Add asynchronous mode support
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon
 <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210106115519.32222-1-vincenzo.frascino@arm.com>
 <20210106115519.32222-3-vincenzo.frascino@arm.com>
 <CAAeHK+xuGRzkLdrfGZVo-RVfkH31qUrNdBaPd4k5ffMKHWGfTQ@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <c4f04127-a682-d809-1dad-5ee1f51d3e0a@arm.com>
Date: Thu, 7 Jan 2021 17:29:24 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+xuGRzkLdrfGZVo-RVfkH31qUrNdBaPd4k5ffMKHWGfTQ@mail.gmail.com>
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

Hi Andrey,

On 1/7/21 4:29 PM, Andrey Konovalov wrote:
> On Wed, Jan 6, 2021 at 12:56 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>
>> MTE provides an asynchronous mode for detecting tag exceptions. In
>> particular instead of triggering a fault the arm64 core updates a
>> register which is checked by the kernel at the first entry after the tag
>> exception has occurred.
>>
>> Add support for MTE asynchronous mode.
>>
>> The exception handling mechanism will be added with a future patch.
>>
>> Note: KASAN HW activates async mode via kasan.mode kernel parameter.
>> The default mode is set to synchronous.
>>
>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>> Cc: Will Deacon <will.deacon@arm.com>
>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>> ---
>>  arch/arm64/kernel/mte.c | 31 +++++++++++++++++++++++++++++--
>>  1 file changed, 29 insertions(+), 2 deletions(-)
>>
>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index 24a273d47df1..5d992e16b420 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -153,8 +153,35 @@ void mte_init_tags(u64 max_tag)
>>
>>  void mte_enable_kernel(enum kasan_arg_mode mode)
>>  {
>> -       /* Enable MTE Sync Mode for EL1. */
>> -       sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
>> +       const char *m;
>> +
>> +       /* Preset parameter values based on the mode. */
>> +       switch (mode) {
>> +       case KASAN_ARG_MODE_OFF:
>> +               return;
>> +       case KASAN_ARG_MODE_LIGHT:
>> +               /* Enable MTE Async Mode for EL1. */
>> +               sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_ASYNC);
>> +               m = "asynchronous";
>> +               break;
>> +       case KASAN_ARG_MODE_DEFAULT:
>> +       case KASAN_ARG_MODE_PROD:
>> +       case KASAN_ARG_MODE_FULL:
>> +               /* Enable MTE Sync Mode for EL1. */
>> +               sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
>> +               m = "synchronous";
>> +               break;
>> +       default:
>> +               /*
>> +                * kasan mode should be always set hence we should
>> +                * not reach this condition.
>> +                */
>> +               WARN_ON_ONCE(1);
>> +               return;
>> +       }
>> +
>> +       pr_info_once("MTE: enabled in %s mode at EL1\n", m);
>> +
>>         isb();
>>  }
>>
>> --
>> 2.29.2
>>
> 
> Hi Vincenzo,
> 
> It would be cleaner to pass a bool to mte_enable_kernel() and have it
> indicate sync/async mode. This way you don't have to pull all these
> KASAN constants into the arm64 code.
>

Boolean arguments are generally bad for legibility, hence I tend to avoid them.
In this case exposing the constants does not seem a big issue especially because
the only user of this code is "KASAN_HW_TAGS" and definitely improves its
legibility hence I would prefer to keep it as is.
> Thanks!
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c4f04127-a682-d809-1dad-5ee1f51d3e0a%40arm.com.
