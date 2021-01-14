Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBYFVQGAAMGQEBYTBHLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 041A42F6374
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 15:53:22 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id v7sf8700197ioj.16
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 06:53:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610636001; cv=pass;
        d=google.com; s=arc-20160816;
        b=efRu5GQfmU9Jp7tCMJozILwVflwgPIU8P0MWnzTrTv7Ses6m3Xg7+4ZEkqg0vBd/pD
         8Fa90ZQzVZcgrsfm23AUkIyesZ0QGVKXU7qkv6SW3PN6Ul2B7HU3Co8CG2/NSO5DG65T
         hCRrDSFa+MxM81tSoEVR0C6bWMeCW5uqo6fYNSxqBsehbsHRIbfKiNi0cFmkZADXYfHV
         LxFpr5b0yrmVZ1pvZlWNx0vpusZHfV9YDeX7u0RCNi+2jvf/8YTzOlBd5dZEqAyipMPX
         QoVA3g/Vc97POQNVrviImKFSJHD59E2pEF4xd8VVN4DahrO+A0wvX17/bQFCIp7eVLVO
         GHRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=cuAQ1KLLavzSsLwSw/FCxXfFVEOfwZzTHHm9fR12yvI=;
        b=oE/nyhVNRf/S+5poesP2q8cXLF58ybZP4IJPHQKDQpFNPUAC3lJKTOZA/RonSfZRTC
         UikaHLRG1QYyuHWdmQfE5LLOvHFGXlmSlCa/3esE/sCExwosjky/Kr1gyKuhB2yfuM/n
         6d5cn4rlZXWDS4TYfp+6TsIrI9c9GSKz+eMcUc6T/zJvSizfHRlcsm9aI78zZCrNCYwQ
         gCUZrfq2uR8cC95pfU+bE8fyOAeoAspnWCBQ9MD9j6a82S9MbR+9w/txzsIe1ynHuTjO
         dKXuvR6XnDU/GUAYaupILOPfDzQ4vg41EGxAOOPV+cO8E2GRmTiCiGJYWsmu+kqLijoW
         BsZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cuAQ1KLLavzSsLwSw/FCxXfFVEOfwZzTHHm9fR12yvI=;
        b=o3kfBvOzHeRTZYr0Hertyy2729bBpYREb+vjh/gelZEmeN1iXfLNicv1ZPZmxMCxCi
         XbroIdk6sfWwcjnojgB6ZZJMQjthBPjHR05SJUy0bx7gOm3uQU/7akbaRgnkrxJBi5iy
         3gRzH+/sOkLFDpAXPKpqDW5yb92fJpFZTuV5U9tsUJbO1RuWDa87xpXCTPhF+bUOgray
         F2HFaULq6IjaI+hwQBX4g64rT6boqxitQPg/MS/BwPCM9TW3F9FMzifaGAGs7Pd/yzUX
         x4+vZoewL1qxDVnJAPUbWYLLmzAaCewjqXEqwQpJvlEQUS3HiuWMza+bSXPsm/q/fIjf
         2H8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cuAQ1KLLavzSsLwSw/FCxXfFVEOfwZzTHHm9fR12yvI=;
        b=r7ZZ4TtJ8Ke34dL/7uVR1KmZoEigRWPJPiByX/8/EtJVBfgReMTsNhrS50gmbuj3wt
         EFeL6MrgYNyAoXjfx2QdKAzgI0m4pyZaEFU1o8MqwEL8/GQhLdkEEXY2hn7sc1wKHFbR
         e5z6+AQIZPS4+AHhR6BqaOylLlL1NJkhSG7/x2gFbdgV+1QEgUIr0ul5pfUHp7OLNMrM
         fkkHP8v5G1D36aYpFLKwVIyzYIhiZs2nkz4D7UA6hmMqCFS8vZtONBGP47vpdktfpSF2
         UCX6R4RuHwY/JT8ewgbc0OVzog25lHbAeA0FgbJFX6EmMLTGAKto0Q5dammJ73ysy3Z0
         C+ZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531b99rFYNkDuCf87sN05OOPAk+SUZtpF9h2pjiNWnikUpPc6r5r
	EovP9Sibf/sV3VmwDjwU+So=
X-Google-Smtp-Source: ABdhPJywtnpOZXHvlVlhMrO1idynxT/laqxCsN7xYafst0h2TxZH6vPDFrC2P8w6DqR80v6fS0I3sA==
X-Received: by 2002:a02:3f62:: with SMTP id c34mr6759633jaf.16.1610636001086;
        Thu, 14 Jan 2021 06:53:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:13c5:: with SMTP id i5ls694277jaj.1.gmail; Thu, 14
 Jan 2021 06:53:20 -0800 (PST)
X-Received: by 2002:a02:c7d1:: with SMTP id s17mr6694869jao.142.1610636000661;
        Thu, 14 Jan 2021 06:53:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610636000; cv=none;
        d=google.com; s=arc-20160816;
        b=o6fcXoLyygn6A/WjSGZ5LSzfCY9BQz/eFqwaL5S8zZ72pLpJuzgOPy1TSSI1uHRVGd
         G/5m7Qyd0xbAmdm0v0zI7KDencGWu2jKFGO40J/pYH42LtP59hvz0EE+w+rhB1nHopwR
         153CmAEcIyEiYU1yUfgvVrxqTwRZZCZKkrE+XfUGuWU/dalH7XJ1DaWtDvBg9Oo/KHE7
         0tXkOYxh4xOz4CDEuQtSukBxTncW8O7pqwgQcRKJx3lRTl1NCJi1o7MofiCIm6vzR0Xx
         R9viC99rGbpSB7tq3qtV2ULjicdDcb+9OUIiM0w7lAFq/T5HF5OqA67pGny2WjCyTHvF
         JOnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=x/ZcG8YQyv0thFNUHU0oxAG1Y+jtZj6t07ndYA0Cnb0=;
        b=1H7zUkdnDUJcTMUtMpoUkbqZLXB2kEDZlyhRoa/s37GINb6EQUq8f97VDofHVwoXxb
         7d9dqzXRwtc4lFI194iKKbvzXFqoJxfQ6i4BXFfUuUTOfQ7O5GlwXDQNkFOGNIQJZ2A2
         SVX5+GOucNKaAsyDftOMlkmMTNHLi20mdVNSKdA3OvxqxYgx7KCWbe/zUA56ycRrA3DG
         iuAdu9CZT6F/Yoda93eZ4hniM9jLysxV5RLSWbqsLUOvZB1pr96NKKpOJu979XeiaYAv
         vAR9Ez375GQmS0Fk28CSpujBHusGgDgGD+LYOAQ5WRarlA9WR3U7U1vjquFGgvypxXA+
         p/SA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id v81si272010iod.4.2021.01.14.06.53.20
        for <kasan-dev@googlegroups.com>;
        Thu, 14 Jan 2021 06:53:20 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 38C49ED1;
	Thu, 14 Jan 2021 06:53:20 -0800 (PST)
Received: from [10.37.12.3] (unknown [10.37.12.3])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 40A493F70D;
	Thu, 14 Jan 2021 06:53:18 -0800 (PST)
Subject: Re: [PATCH v2 3/4] arm64: mte: Enable async tag check fault
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210107172908.42686-1-vincenzo.frascino@arm.com>
 <20210107172908.42686-4-vincenzo.frascino@arm.com>
 <20210113181121.GF27045@gaia> <efbb0722-eb4e-7be2-b929-77ec91cc0ae0@arm.com>
 <20210114142512.GB16561@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <80492795-4ebf-0d77-3f07-37593845a733@arm.com>
Date: Thu, 14 Jan 2021 14:57:03 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210114142512.GB16561@gaia>
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



On 1/14/21 2:25 PM, Catalin Marinas wrote:
> On Thu, Jan 14, 2021 at 10:24:25AM +0000, Vincenzo Frascino wrote:
>> On 1/13/21 6:11 PM, Catalin Marinas wrote:
>>> On Thu, Jan 07, 2021 at 05:29:07PM +0000, Vincenzo Frascino wrote:
>>>>  static inline void mte_sync_tags(pte_t *ptep, pte_t pte)
>>>>  {
>>>>  }
>>>> diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
>>>> index 5346953e4382..74b020ce72d7 100644
>>>> --- a/arch/arm64/kernel/entry-common.c
>>>> +++ b/arch/arm64/kernel/entry-common.c
>>>> @@ -37,6 +37,8 @@ static void noinstr enter_from_kernel_mode(struct pt_regs *regs)
>>>>  	lockdep_hardirqs_off(CALLER_ADDR0);
>>>>  	rcu_irq_enter_check_tick();
>>>>  	trace_hardirqs_off_finish();
>>>> +
>>>> +	mte_check_tfsr_el1();
>>>>  }
>>>>  
>>>>  /*
>>>> @@ -47,6 +49,8 @@ static void noinstr exit_to_kernel_mode(struct pt_regs *regs)
>>>>  {
>>>>  	lockdep_assert_irqs_disabled();
>>>>  
>>>> +	mte_check_tfsr_el1();
>>>> +
>>>>  	if (interrupts_enabled(regs)) {
>>>>  		if (regs->exit_rcu) {
>>>>  			trace_hardirqs_on_prepare();
>>>> @@ -243,6 +247,8 @@ asmlinkage void noinstr enter_from_user_mode(void)
>>>>  
>>>>  asmlinkage void noinstr exit_to_user_mode(void)
>>>>  {
>>>> +	mte_check_tfsr_el1();
>>>
>>> While for kernel entry the asynchronous faults are sync'ed automatically
>>> with TFSR_EL1, we don't have this for exit, so we'd need an explicit
>>> DSB. But rather than placing it here, it's better if we add a bool sync
>>> argument to mte_check_tfsr_el1() which issues a dsb() before checking
>>> the register. I think that's the only place where such argument would be
>>> true (for now).
>>
>> Good point, I will add the dsb() in mte_check_tfsr_el1() but instead of a bool
>> parameter I will add something more explicit.
> 
> Or rename the function to mte_check_tfsr_el1_no_sync() and have a static
> inline mte_check_tfsr_el1() which issues a dsb() before calling the
> *no_sync variant.
> 
> Adding an enum instead here is not worth it (if that's what you meant by
> not using a bool).
> 

I like this option more, thanks for pointing it out.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/80492795-4ebf-0d77-3f07-37593845a733%40arm.com.
