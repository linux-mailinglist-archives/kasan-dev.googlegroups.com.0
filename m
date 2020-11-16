Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBKPHZH6QKGQENXPWMMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 071EC2B43DF
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 13:42:19 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id v85sf8181361oia.16
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 04:42:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605530538; cv=pass;
        d=google.com; s=arc-20160816;
        b=sevkceat5+YW8jP/HZOdbRPPKocHT7uyNR+p5FVBhGfSLEIBmJCMUDT/9m5gTzyMY3
         48JS0KyV907toWio+8MuSHjqoScBz01Mco0yz0F2/n4OYKQTIAj7xmq0Rv49umrjLITr
         oQr0rc7vPkA/g1msjMVvs0D1Tc1GqUADWQCdgQxeCwD4/DmTzJ6BUduRu724vdS57Aji
         rSfiHfHl+z/9SMteWVz4VRc4gPEB/3R0IcTg4ZsOfkQhMWWXbHh6BDNRW6VTN59FKGhz
         BG4ptTuR1dp72DiHuhF0718YT1g6XBigS4W4TVgKxM/gl2UBTyJ4urt6H0tGm2jKxil8
         TY0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=V01UDQm0WFGS/CgNKZpMVmbCKQNz20i9JWPza8i1fMk=;
        b=fKwFMVmxhiohPwtSDlVPLe83Vd/ey1SKV8S+A/fShAZsCjvqPmwqCj+zo5h7fJV5af
         wS+piih/Adnd+fpwBYu8zyiuukcjBbIswgUbBSforsrGCO91MqglKUaK+Deb1b3QCqDW
         0Sns5elLAl+D40vj626eEGfNahBW+neC1/dPZ9T8dKr3xfqtp/JLqEPMhX9ZhcHwb1ne
         a8b3EW/SwbZNFzbmsA/tsrfBDLGtgfs2UqjnuO60tlSRfd0AgEklKS1xIx1QiTLok0nO
         TQxuIHWoXxlGiMINDBHclYe5dHtAOTpHsgvkBfkQGhbwsv5FwH89pnq4RLSeeWM38fKq
         yPww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=V01UDQm0WFGS/CgNKZpMVmbCKQNz20i9JWPza8i1fMk=;
        b=j3orAX///dVT/flbUNG9p4dbj9Xx55Xk95j4IkXGXU1iHqSJi48ci5XjAd4PVRH8sG
         kTNbYLTG/8KGY5U3pAC7pkqlHxPx787JGsrKhSnswPvljglgK9KXymHUt8aQvJGr/Gef
         urxZ6I6Upe+YRZ5ooeeL8LE9Bzb7x7QOGfz0XbgIP7B6bOhWzKThi1OjqveA/hbIOMe5
         pb/PisZHcbwZQV8TTjxJ/wvx2LxEoBd0f0aQbGd43zKzriTcKVkk1wKEZEFfrNXFFFIu
         uqWXuCftz3D8JwGtpk4piokHLZXCQzaYD84MiBudDElOb3YZhGQ+JPGKfIryvw5KXqpr
         EsUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=V01UDQm0WFGS/CgNKZpMVmbCKQNz20i9JWPza8i1fMk=;
        b=tpdU037nbvAv2rWbqZbP31yoJle69pxClY+jiQek7XEb2D89uuECgFZ2A/ie+eFTt8
         iLY18QZmG1mtzoOYHEZzv3jgHw2HuO4FkAzMeqqp344OZHo+19+zPIppYjmjuyq6Y//L
         6JtynK9Lp9EUmN4/0DzINpw9fJ4xwoqxnt3DJ98Aa0/ZtNmKB4/ZM4nmQbHsGCJrzfRX
         Fb5wfHZREZuBI+25q7EGGIrbkq25/8sA2/Hx4LOkohVhT5CyaF8xicfyPJIahvMCxqFy
         6JCUjIH1d/nKOabBJWQA1dccvBZ41C6tcWgl5cMWcsR+7Z45D1kAndQTYo5ocaxzcgQZ
         m9Hw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531PTXXjkvZMe/P5LpBpu3IAuHLxC96pn8e9RWoIvDUpjYeTXWUl
	YqYLE5gjqL1M0WOpnJwjNEM=
X-Google-Smtp-Source: ABdhPJz18zI087XX0vlLD9tvMFJf+s8q4mthvglM0m+oc+KtrgMzws2grHzGYYsSltmRoBm8uxJSpA==
X-Received: by 2002:a54:4614:: with SMTP id p20mr9237385oip.131.1605530537713;
        Mon, 16 Nov 2020 04:42:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:bb2:: with SMTP id 47ls3217870oth.9.gmail; Mon, 16 Nov
 2020 04:42:17 -0800 (PST)
X-Received: by 2002:a9d:7081:: with SMTP id l1mr10884418otj.139.1605530537341;
        Mon, 16 Nov 2020 04:42:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605530537; cv=none;
        d=google.com; s=arc-20160816;
        b=FP5S9u8xnExwn7rkp0Gvk156GI7sQgB8xRbHlP/oHre6jNYm/p31MV5B2MmeHRIM9f
         wzT9K56jxDr3d28qS4+F80+zduhy0RMPeH9e501hLsXm6hzQzItBMVBV1FB+5waZBZqe
         ri5nNPkGwNPMTmEX+rQWC8YROW7wLJZgRDGbMtd0pI0qPzjfqVjO/xGrHEy93BFQ3aGa
         h+ZO+IWKUNgd+tvUzZlRSgOKVF69KP3nBsGVwzA/Lk8b0cRCyfkdESilS3rBOZS5Hdsr
         lbZ9YRulfQPjK1ZbjBx1TS0xbru9lCp9baB/4rOzOc/0jV5VOgLd9UYncf0psLFk/Vg8
         79fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=MqIy6vRHBVfAzA3qssTHaKjQGN38IC2kr4TlO0tIc90=;
        b=mDRF8FxSHlFSn955hpUVRd/HKN/Pw/sW7skSqjsfCYcuzF6AruR+MJNWr2RCeyHX3F
         7uAva1LNXeDsisxmJO8R3sIDEfJecAShti2zI9Adu8gtvAq+jOIndhMSiZZ4qzKncUbl
         zU061vBIMgDp686YTx7A/aTxZ9df++dcY3/udMSVvdqrY9qv8STQnO2rkdA7UPg4yeHK
         Obynhzt+RffLpj8kBs0smczH268LvOBa+vkyyOTb7JMhsUHtjCtbVYnSrhKX615UuW/j
         Phqro3Q/kEdstdzomnzn5WWs1X7e5c6y9KRFP24JQdsv7eZeMSxljvqhfzRQ9YuXqsg6
         dk5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e206si1409591oob.2.2020.11.16.04.42.17
        for <kasan-dev@googlegroups.com>;
        Mon, 16 Nov 2020 04:42:17 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id DC39B101E;
	Mon, 16 Nov 2020 04:42:16 -0800 (PST)
Received: from [10.37.12.42] (unknown [10.37.12.42])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 003023F70D;
	Mon, 16 Nov 2020 04:42:12 -0800 (PST)
Subject: Re: [PATCH RFC v2 04/21] kasan: unpoison stack only with
 CONFIG_KASAN_STACK
To: Dmitry Vyukov <dvyukov@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@google.com>,
 Will Deacon <will.deacon@arm.com>, Alexander Potapenko <glider@google.com>,
 Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>,
 Peter Collingbourne <pcc@google.com>,
 Serban Constantinescu <serbanc@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova
 <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
References: <cover.1603372719.git.andreyknvl@google.com>
 <ded454eeff88f631dc08eef76f0ad9f2daff0085.1603372719.git.andreyknvl@google.com>
 <CACT4Y+Zys3+VUsO6GDWQEcjCS6Wx16W_+B6aNy-fyhPcir7eeA@mail.gmail.com>
 <CAAeHK+xvGZNwTtvkzNnU7Hh7iUiPKFNDKDpKT8UPcqQk6Ah3yQ@mail.gmail.com>
 <CACT4Y+Z3UCwAY2Mm1KiQMBXVhc2Bobi-YrdiNYtToNgMRjOE4g@mail.gmail.com>
 <CANpmjNPNqHsOfcw7Wh+XQ_pPT1610-+B9By171t7KMS3aB2sBg@mail.gmail.com>
 <X7Jthb9D5Ekq93sS@trantor>
 <CACT4Y+ZubLBEiGZOVyptB4RPf=3Qr570GN+JBpSmaeEvHWQB5g@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <9d4156e6-ec4f-a742-a44e-f38bf7fa9ba9@arm.com>
Date: Mon, 16 Nov 2020 12:45:19 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CACT4Y+ZubLBEiGZOVyptB4RPf=3Qr570GN+JBpSmaeEvHWQB5g@mail.gmail.com>
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



On 11/16/20 12:19 PM, Dmitry Vyukov wrote:
> On Mon, Nov 16, 2020 at 1:16 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>>
>> On Mon, Nov 16, 2020 at 12:50:00PM +0100, Marco Elver wrote:
>>> On Mon, 16 Nov 2020 at 11:59, Dmitry Vyukov <dvyukov@google.com> wrote:
>>>> On Thu, Oct 29, 2020 at 8:57 PM 'Andrey Konovalov' via kasan-dev
>>>> <kasan-dev@googlegroups.com> wrote:
>>>>> On Tue, Oct 27, 2020 at 1:44 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>>>>>>
>>>>>> On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>>>>>>>
>>>>>>> There's a config option CONFIG_KASAN_STACK that has to be enabled for
>>>>>>> KASAN to use stack instrumentation and perform validity checks for
>>>>>>> stack variables.
>>>>>>>
>>>>>>> There's no need to unpoison stack when CONFIG_KASAN_STACK is not enabled.
>>>>>>> Only call kasan_unpoison_task_stack[_below]() when CONFIG_KASAN_STACK is
>>>>>>> enabled.
>>>>>>>
>>>>>>> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>>>>>>> Link: https://linux-review.googlesource.com/id/If8a891e9fe01ea543e00b576852685afec0887e3
>>>>>>> ---
>>>>>>>  arch/arm64/kernel/sleep.S        |  2 +-
>>>>>>>  arch/x86/kernel/acpi/wakeup_64.S |  2 +-
>>>>>>>  include/linux/kasan.h            | 10 ++++++----
>>>>>>>  mm/kasan/common.c                |  2 ++
>>>>>>>  4 files changed, 10 insertions(+), 6 deletions(-)
>>>>>>>
>>>>>>> diff --git a/arch/arm64/kernel/sleep.S b/arch/arm64/kernel/sleep.S
>>>>>>> index ba40d57757d6..bdadfa56b40e 100644
>>>>>>> --- a/arch/arm64/kernel/sleep.S
>>>>>>> +++ b/arch/arm64/kernel/sleep.S
>>>>>>> @@ -133,7 +133,7 @@ SYM_FUNC_START(_cpu_resume)
>>>>>>>          */
>>>>>>>         bl      cpu_do_resume
>>>>>>>
>>>>>>> -#ifdef CONFIG_KASAN
>>>>>>> +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
>>>>>>>         mov     x0, sp
>>>>>>>         bl      kasan_unpoison_task_stack_below
>>>>>>>  #endif
>>>>>>> diff --git a/arch/x86/kernel/acpi/wakeup_64.S b/arch/x86/kernel/acpi/wakeup_64.S
>>>>>>> index c8daa92f38dc..5d3a0b8fd379 100644
>>>>>>> --- a/arch/x86/kernel/acpi/wakeup_64.S
>>>>>>> +++ b/arch/x86/kernel/acpi/wakeup_64.S
>>>>>>> @@ -112,7 +112,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
>>>>>>>         movq    pt_regs_r14(%rax), %r14
>>>>>>>         movq    pt_regs_r15(%rax), %r15
>>>>>>>
>>>>>>> -#ifdef CONFIG_KASAN
>>>>>>> +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
>>>>>>>         /*
>>>>>>>          * The suspend path may have poisoned some areas deeper in the stack,
>>>>>>>          * which we now need to unpoison.
>>>>>>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>>>>>>> index 3f3f541e5d5f..7be9fb9146ac 100644
>>>>>>> --- a/include/linux/kasan.h
>>>>>>> +++ b/include/linux/kasan.h
>>>>>>> @@ -68,8 +68,6 @@ static inline void kasan_disable_current(void) {}
>>>>>>>
>>>>>>>  void kasan_unpoison_memory(const void *address, size_t size);
>>>>>>>
>>>>>>> -void kasan_unpoison_task_stack(struct task_struct *task);
>>>>>>> -
>>>>>>>  void kasan_alloc_pages(struct page *page, unsigned int order);
>>>>>>>  void kasan_free_pages(struct page *page, unsigned int order);
>>>>>>>
>>>>>>> @@ -114,8 +112,6 @@ void kasan_restore_multi_shot(bool enabled);
>>>>>>>
>>>>>>>  static inline void kasan_unpoison_memory(const void *address, size_t size) {}
>>>>>>>
>>>>>>> -static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
>>>>>>> -
>>>>>>>  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
>>>>>>>  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
>>>>>>>
>>>>>>> @@ -167,6 +163,12 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
>>>>>>>
>>>>>>>  #endif /* CONFIG_KASAN */
>>>>>>>
>>>>>>> +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
>>>>>>
>>>>>> && defined(CONFIG_KASAN_STACK) for consistency
>>>>>
>>>>> CONFIG_KASAN_STACK is different from other KASAN configs. It's always
>>>>> defined, and its value is what controls whether stack instrumentation
>>>>> is enabled.
>>>>
>>>> Not sure why we did this instead of the following, but okay.
>>>>
>>>>  config KASAN_STACK
>>>> -       int
>>>> -       default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
>>>> -       default 0
>>>> +       bool
>>>> +       default y if KASAN_STACK_ENABLE || CC_IS_GCC
>>>> +       default n
>>>
>>> I wondered the same, but then looking at scripts/Makefile.kasan I
>>> think it's because we directly pass it to the compiler:
>>>     ...
>>>     $(call cc-param,asan-stack=$(CONFIG_KASAN_STACK)) \
>>>     ...
>>
>> Try this instead:
>>
>>       $(call cc-param,asan-stack=$(if $(CONFIG_KASAN_STACK),1,0)) \
> 
> 
> We could have just 1 config instead of 2 as well.
> For gcc we could do no prompt and default value y, and for clang --
> prompt and default value n. I think it should do what we need.
> 

I agree with Catalin's proposal since it should simplify things.

Nit: 'default n' is the default hence I do not think it should be required
explicitly.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9d4156e6-ec4f-a742-a44e-f38bf7fa9ba9%40arm.com.
