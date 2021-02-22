Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBJVCZ2AQMGQE7KQO6AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 099F93214CE
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 12:10:32 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id a3sf6044626oiy.22
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 03:10:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613992230; cv=pass;
        d=google.com; s=arc-20160816;
        b=TGGcGWDMAG9l6qpNQ7KBKG8JMjTdgps38zsHQeWOKG/l204Om0V/VnxrRbHVqcGKOm
         J83eguSoSyU/YumEOsVlwFAtRdDe0ME2mMinvgVbYIuoZOKHkEnSxqUoM+mhvYpynr87
         JXLmZH+CkOWwJ/syBXKSi5u0UeUut9taus4GgM3fLzVqgWwr6bJmmMdnomU6bgIYbOoD
         zHOcRSshY74BD0kX/bk/gsf66+X2jkfEU/BQquW0/vow6OwPfbLvR95lQlBYzaVGZ6G9
         Zx8fytqxnZ0hOjVFX85TMQ6PixkrT5SURQ9evBgbdQr1m4D9KeUVmlkDBxpYMN/mk3mS
         dZiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=KOAWzL0vU23FucYTWPG08lMY9F0ir7h+G8EMKETExQs=;
        b=JMIiaeKElEJ6TTU9v3mx1hCrMwZtsuA7dqIKJfwAopggbcFKmn295J0oc3J8n+na9l
         CT56JbIDVY0gDCqpTfwjL+3Uhzs0C53gjkzl3XJ+BsjzDykffUXTGuO0BMQkRftPKMxj
         NwoehmD+YzpbrmGxjGG/j7xxJXR/QSVr+ZnMCscuL5QNR71PkzxBKZThOUl3vzOa2roL
         NJDLv6GJMnR3Q3GJmuSP3ypDrAeHPybBbxrXQWbbuCd5AAquOOEkNA1vpGmh/ZN1Lkug
         QiQivIRJMYgL87sKP3Ux/iOK0wyHtDosu2ALSByAZR+l44k3gk04P2xPgeRGRa10Yl5k
         y0hA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KOAWzL0vU23FucYTWPG08lMY9F0ir7h+G8EMKETExQs=;
        b=B5ZPDZIFQN6Me5w15i7v8kEOia4PUtsX+hyjYgweJevlmScRZNLTiioiNelPmIQfAa
         6t7fNxmYYNxR74EVyv/0+m9ndhaKSJQXp9vUFt1TYXqWHiDBJ6ZTjAboceU1YnZClHmN
         u3i0ksQVFvbE25IZEIoC/B4A4ko4C7zWg6Wgu++x/NiuTS6rW7kXna+HLU8+KGBbtx7a
         rsryBpjx5fdXj4aFAcG6XbU9UpuDPfczMnLPydbZmZLq1rWs5tWk2ArxlkqqgNB4sT6y
         Xt2xS0Y4QFoD9/OPanATjIaDtIreNpTSlTD4pF6F+88qJnBZ0kQwBpp6aBsVfN22gQQr
         zyTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KOAWzL0vU23FucYTWPG08lMY9F0ir7h+G8EMKETExQs=;
        b=lfO0Hgky0yeZjzusioDOjUtkZ4QTOm9nt8lbDwC2voqp576pcsxTZQGc/X5pU229jd
         fY2flw+lbCxaDo/BSMJqMp5e7wONwRGb3xIGaVWDPy9O9icM0RlDmXQw2ehd36wudxtu
         6x5prnr2bIPv+/V9aalm1dhBRSQhqr/FnKo2IiZKXP4igss5yKg3jygM200mJEdgDg97
         FChVsPBocZSbl7NGPXjy2Rq1dQQKl7hyD5AM7AeiXv4uG1DMvnPjfpjE+Gg8y8ME6d1W
         yiCJOusndlZTcT+Nkc6Zi7jG5Llrk5cBT4suuAGHHjDcpFltWtG9x1h8SB290EIun85/
         Lr/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533OHt69si2RUnG/wh0H6X27ZRa7W2yI9LDHw/p1x1BBBs2/oVem
	dgEqQsn1Z0TSuncBZB2VDtE=
X-Google-Smtp-Source: ABdhPJzKnNEbcunMqk36U9WsgIcoHfoqVaaKmAih1Sv8RZfNETkKRRbo2YElmLGhAkP6auXlWZOMRA==
X-Received: by 2002:a05:6830:1552:: with SMTP id l18mr16593716otp.233.1613992230772;
        Mon, 22 Feb 2021 03:10:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7d86:: with SMTP id j6ls1358625otn.11.gmail; Mon, 22 Feb
 2021 03:10:30 -0800 (PST)
X-Received: by 2002:a05:6830:100c:: with SMTP id a12mr1173614otp.345.1613992230366;
        Mon, 22 Feb 2021 03:10:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613992230; cv=none;
        d=google.com; s=arc-20160816;
        b=wFhvy4cSiVcvJW5Xk4Zs1uwWbiuQpPVpFIi31OfJdZfdCq6UnKzkCc9l8ifSDB1qJZ
         cRgSMUEz5SMoXvOKFVsx+OYojim3Vy2oUP26YPjP70TJiYtxpbQDck0eRm4IkKrI/HY8
         Lr567NBcE8dhgYJrjomSGZbkxSTR8aT3zXy7wGhSty80pWsTWKpfCexPGdKsTGot6ERc
         9zOgDtBFpGIyFYHaJdp7Gw6gSHK5Qgna9GsB5gKNclnWONQ0Pfnksajq5jRsu63ML2pk
         e9+4YVFI3xOx6h31ob/QXaSWYM0ZXtcziTe9ep86HLzltf/sLmMzQ3sJLa6yc81XsWRm
         au5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=n1xZrbTDNoqHd/0EhqNsRoUrAL/vF7RShVqA3NF5m9M=;
        b=FOtKBg8xEFLt0HnxRZy9V5HsdNxOfJQIcQ01YmN6aakdPgdeatsY9bTYX+wrRZPYLJ
         BlpO19gJnOcMjNQhYnnp9GLye6MNta5tYVZcBHrVfSlw5AEL2q6BWKEiKgj0bGNkXiau
         7rBqxsMg2ukAx5b0DK9aaGA2gIktt8/8DRJlo7fcVFYAKUQhg9r1jusGIaWg+8GnMswQ
         iFXinFQfZD9Iq5hO4uQDzv6xpSpNTfyKYgmyAiipHcOXobayVMzM2Y4kowYqkCINntA3
         dHmDx3/bK1d8NjKr4ilWeuKCU4Cd3nGFpkX3y1hE2aerDo7ZoCgz+IaoqgbqtLm3VhUL
         Gd3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b10si821382ots.5.2021.02.22.03.10.30
        for <kasan-dev@googlegroups.com>;
        Mon, 22 Feb 2021 03:10:30 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 1CF701FB;
	Mon, 22 Feb 2021 03:10:30 -0800 (PST)
Received: from [10.37.8.9] (unknown [10.37.8.9])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id ADCBB3F73B;
	Mon, 22 Feb 2021 03:10:26 -0800 (PST)
Subject: Re: [PATCH v13 1/7] arm64: mte: Add asynchronous mode support
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-2-vincenzo.frascino@arm.com>
 <CAAeHK+xM1VHvSF_9ELf=_nDwJsUV2S1=LQy-rU-O0oyrNexzXw@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <d20e596b-f9b0-8f55-43a8-aacc3c0cb88f@arm.com>
Date: Mon, 22 Feb 2021 11:14:38 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+xM1VHvSF_9ELf=_nDwJsUV2S1=LQy-rU-O0oyrNexzXw@mail.gmail.com>
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

On 2/12/21 9:21 PM, Andrey Konovalov wrote:
> On Thu, Feb 11, 2021 at 4:34 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>
>> MTE provides an asynchronous mode for detecting tag exceptions. In
>> particular instead of triggering a fault the arm64 core updates a
>> register which is checked by the kernel after the asynchronous tag
>> check fault has occurred.
>>
>> Add support for MTE asynchronous mode.
>>
>> The exception handling mechanism will be added with a future patch.
>>
>> Note: KASAN HW activates async mode via kasan.mode kernel parameter.
>> The default mode is set to synchronous.
>> The code that verifies the status of TFSR_EL1 will be added with a
>> future patch.
>>
>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>> Cc: Will Deacon <will@kernel.org>
>> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
>> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>> ---
>>  arch/arm64/include/asm/memory.h    |  3 ++-
>>  arch/arm64/include/asm/mte-kasan.h |  9 +++++++--
>>  arch/arm64/kernel/mte.c            | 19 ++++++++++++++++---
>>  3 files changed, 25 insertions(+), 6 deletions(-)
>>
>> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
>> index c759faf7a1ff..91515383d763 100644
>> --- a/arch/arm64/include/asm/memory.h
>> +++ b/arch/arm64/include/asm/memory.h
>> @@ -243,7 +243,8 @@ static inline const void *__tag_set(const void *addr, u8 tag)
>>  }
>>
>>  #ifdef CONFIG_KASAN_HW_TAGS
>> -#define arch_enable_tagging()                  mte_enable_kernel()
>> +#define arch_enable_tagging_sync()             mte_enable_kernel_sync()
>> +#define arch_enable_tagging_async()            mte_enable_kernel_async()
> 
> We need to update KASAN usage of arch_enable_tagging() to
> arch_enable_tagging_sync() in this patch as well. Otherwise, this
> leaves KASAN broken between this patch and the next one.
>

Yes you are right, still can't explain why it did bysect cleanly though.
I will introduce temporarily here:

#define arch_enable_tagging() arch_enable_tagging_sync()

and remove it again in the respective kasan patch.

> 
>>  #define arch_set_tagging_report_once(state)    mte_set_report_once(state)
>>  #define arch_init_tags(max_tag)                        mte_init_tags(max_tag)
>>  #define arch_get_random_tag()                  mte_get_random_tag()
>> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
>> index 7ab500e2ad17..4acf8bf41cad 100644
>> --- a/arch/arm64/include/asm/mte-kasan.h
>> +++ b/arch/arm64/include/asm/mte-kasan.h
>> @@ -77,7 +77,8 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>>         } while (curr != end);
>>  }
>>
>> -void mte_enable_kernel(void);
>> +void mte_enable_kernel_sync(void);
>> +void mte_enable_kernel_async(void);
>>  void mte_init_tags(u64 max_tag);
>>
>>  void mte_set_report_once(bool state);
>> @@ -104,7 +105,11 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>>  {
>>  }
>>
>> -static inline void mte_enable_kernel(void)
>> +static inline void mte_enable_kernel_sync(void)
>> +{
>> +}
>> +
>> +static inline void mte_enable_kernel_async(void)
>>  {
>>  }
>>
>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index a66c2806fc4d..706b7ab75f31 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -107,13 +107,26 @@ void mte_init_tags(u64 max_tag)
>>         write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
>>  }
>>
>> -void mte_enable_kernel(void)
>> +static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
>>  {
>>         /* Enable MTE Sync Mode for EL1. */
>> -       sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
>> +       sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, tcf);
>>         isb();
>> +
>> +       pr_info_once("MTE: enabled in %s mode at EL1\n", mode);
>> +}
>> +
>> +void mte_enable_kernel_sync(void)
>> +{
>> +       __mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
>> +}
>> +EXPORT_SYMBOL_GPL(mte_enable_kernel_sync);
>> +
>> +void mte_enable_kernel_async(void)
>> +{
>> +       __mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
>>  }
>> -EXPORT_SYMBOL_GPL(mte_enable_kernel);
>> +EXPORT_SYMBOL_GPL(mte_enable_kernel_async);
>>
>>  void mte_set_report_once(bool state)
>>  {
>> --
>> 2.30.0
>>

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d20e596b-f9b0-8f55-43a8-aacc3c0cb88f%40arm.com.
