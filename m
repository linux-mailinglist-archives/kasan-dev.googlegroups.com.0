Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBYOWYCJAMGQENFXANAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id C5D4B4F95D6
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Apr 2022 14:32:34 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id d41-20020a0565123d2900b0044a10c21f39sf3044847lfv.22
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Apr 2022 05:32:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649421154; cv=pass;
        d=google.com; s=arc-20160816;
        b=H+xgQrWyrs6cncBznvaHv/kiGB9tgJcFYQbBiyIviG8t5Lns1hTQroFKDvJ9d8GXGo
         srKkWkmcPgnDXz62L8KhukwqRFjFMpjHr0lqHbzDnOaZfaofIPVee0tpx+SKPBLoxebj
         Y42dYHscWEkSJAxoi42P4bJ4+Aigqf9CSTmC+K7TRklKI0DSNAEJ64XBG5keZVAKvttR
         Mui4l/Os8ZdMLCsOoLvnTh8PSlxn8i+SPCVwArwrhgM9OaqhtTEjbzdCjb6tKiaRSx8A
         Zh92ydADGGG0AiD45XF2WtwxkP5O2s0TSmMyARfC2StiizNtzDRyYUJ6A2qVxQVGAIi5
         gKYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=cQ0MSdkt6ucY7E3B6mhsg5UvOTDCQq1XcUw+6cDxs2g=;
        b=CxAl9emI6MPhTk9NpAF4nNyW79j3+dlx46gBYomM1eiao13C3urvhAn7P7Q39upraW
         AvX8IgXnIdcrkSgHyHazWyuIzJF9Xohz4MiXu4BqNKfqyeeV9GapIKDCEiJUQrQ0j5HJ
         e66J7nEarTCKxHYqyDSqA5QYkE+9Uws5SsJ9BX6RDqeT2ppGKet/7xI2SvCQFSikjTod
         xEehTGcgwPecYqVx+l+fd/vkfYFAKMfqigzJ9BDGUNV94vqAnYxWqaAG55h1WcF4c14p
         x2NNPgerHqpgZGS95RtGfqTsX3KDY/G2AXW0JhU5jmxEfnP7H7gDewrEIrUaXzJssj9+
         Bulg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cQ0MSdkt6ucY7E3B6mhsg5UvOTDCQq1XcUw+6cDxs2g=;
        b=HnCB68LhKgWiYHU3Kmjuk2BfEnB4hYle3nW0gxGAdrliVPcRLkLlT3UQy7Ud2tMHTu
         sBn+4/Oh1w7i5u01Qq1i09idreR4h+y6QZ+qu7HgQaDnQ5FNN9JqNdp6tiGweXR38Eng
         f+oZdjY1o8Ec+eeQ/yzdbqckZnnfSWrvYA3oueAdVFLspt6XSU261hjuPrSRQ+m/cTyY
         dKVKhXWo1yvRT6rOd8nXIVXelAipcNfvwfIM18KoYyPozWozgu/+X84g83r5fvD6Bo0+
         NxHFYzjVko8oAlOG3LsaFC9S2hKk1SXPdbl1XOirzdnwwW80cvUcyORyzTg2xBvsvQ0U
         HEOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cQ0MSdkt6ucY7E3B6mhsg5UvOTDCQq1XcUw+6cDxs2g=;
        b=d94bqDJfjjUJyTdjvzeE+O7BnJ8mCk8ptSFkoIpEigWPNx40vMIXwJkJiKI7bk3Z4Q
         MOjWVTdWYaCHHVxA7R8kFhn6rJh6vrA8cffRa+38Gr1ckkOgLziD7BJ9qYo02xBdXtHz
         gViJsDT/LunsfL04ub5HBYALe19QE6l+mGhY6e8b+WCqbF1BzGAyxjantcDhrLWyGm9l
         ZEwNBYoeqL9p0kI3q7tCw5I9UM5JYqD6SUJoFsi6lUw1fJc3H1m51VFz4ZXdAYa6S18I
         QhtMWLI5UKFNDeVFW8ozokUDd8b00kkwcbVtNM4yU2wJN0uVndOHQV79JXF7OLFeluQE
         u1pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OIklT8oH8L6KPLGttTcZsqqhcD3DYHAEZ6tcYsR6CTYuYSu4E
	HMX/av5NKkPrYi/RMVK/UEo=
X-Google-Smtp-Source: ABdhPJwB2lV0VvP3/ecasE5cZwnqac9dT9Wz2iqZauxeZ3tmc03V8p5Nx0D1kGK9FecvE2Ww24wZ6Q==
X-Received: by 2002:a05:651c:1241:b0:24b:108d:3783 with SMTP id h1-20020a05651c124100b0024b108d3783mr11533964ljh.278.1649421154167;
        Fri, 08 Apr 2022 05:32:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als1234903lfa.2.gmail; Fri, 08 Apr 2022
 05:32:33 -0700 (PDT)
X-Received: by 2002:a05:6512:b8a:b0:44b:4ba:c332 with SMTP id b10-20020a0565120b8a00b0044b04bac332mr12292345lfv.684.1649421153030;
        Fri, 08 Apr 2022 05:32:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649421153; cv=none;
        d=google.com; s=arc-20160816;
        b=R1cp0k6cETPBRfrH84sd80/oHlKk7rgiO6SY129X4w45fwkt5+qYzyQdnsVQf4kbFU
         NjmZDgKRz8vZUB7jFB/0+OD69W8N+WqO9XTgCROp+GRLWxiRBQx26SmQ7ls5VK7IID0x
         2lOW6ny9SEs94PdFWjjLGKOl8pcnXwmXKg2xG2g1QIIFl6bG+U85L2LOmohmaX8cm5+D
         T3zkdxLOnJclw9BYYJH7346qEyoywlrqyKMxqZ24oNR9iqOeMWdL2rkH5xh7xBkjyUQA
         n6YwDaohAOWmJW5M1aT0qlQ5OHm19nsBzgYBj9CHtbNW7shb3STgXeoxa7GWKhooDFgp
         DJbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=h6EeEH7sCwNxEpXkZ+xi03n0nKfe6EyGqOkRUvm7agw=;
        b=chnkWcYwRYxCKOfUK4MlX1o5UjONi7gqs63vUdzGLrZ9Z4uXxxZPk3DVFfM9fZMK8t
         0tqDGcSj66gg0aCfUW0J6nYDvgT9XrVtti7P9LbLV7e8qsp3O+Em4bsk0w5ONYsCDhz8
         DUwAwsCiMIh5cGLnS65jWl2Lcx/rWTMDYcnJ+OXqBYuxvIf9ttI3FCN1fBTxM0MYVEKg
         M1YzW9HEPodGinkf9zLNVF2oDYnnUHe9FEQoQo3UVTkD5B9dALXUNAVidvU2BH/dcIz+
         QOzTWvPo700YcxXMaYt+CAbifTBhzf/vjcTI53ONmKatqI5bPNegOx0CeJ9VEL/CKjEC
         FavA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id n4-20020a056512310400b0044ada59207bsi57479lfb.9.2022.04.08.05.32.32
        for <kasan-dev@googlegroups.com>;
        Fri, 08 Apr 2022 05:32:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E5C04113E;
	Fri,  8 Apr 2022 05:32:31 -0700 (PDT)
Received: from [10.57.9.161] (unknown [10.57.9.161])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id CB9673F5A1;
	Fri,  8 Apr 2022 05:32:29 -0700 (PDT)
Message-ID: <08e480cf-90d4-8225-1af9-fe187fc622be@arm.com>
Date: Fri, 8 Apr 2022 13:32:28 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.8.0
Subject: Re: [PATCH] kasan: Fix hw tags enablement when KUNIT tests are
 disabled
Content-Language: en-US
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>
References: <20220408100340.43620-1-vincenzo.frascino@arm.com>
 <CA+fCnZcoFWXyhjfKSxPh2djiTWjYCh2xmirPehyJS94DaoJC9w@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
In-Reply-To: <CA+fCnZcoFWXyhjfKSxPh2djiTWjYCh2xmirPehyJS94DaoJC9w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
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

On 4/8/22 1:26 PM, Andrey Konovalov wrote:
> On Fri, Apr 8, 2022 at 12:04 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>
>> Kasan enables hw tags via kasan_enable_tagging() which based on the mode
>> passed via kernel command line selects the correct hw backend.
>> kasan_enable_tagging() is meant to be invoked indirectly via the cpu features
>> framework of the architectures that support these backends.
>> Currently the invocation of this function is guarded by CONFIG_KASAN_KUNIT_TEST
>> which allows the enablement of the correct backend only when KUNIT tests are
>> enabled in the kernel.
> 
>> ... and prevents to enable MTE on arm64 when KUNIT tests for kasan hw_tags are
>> disabled.
> 
> Oh, indeed. Thanks for finding this!
> 
>> This inconsistency was introduced in commit:
>>
>>   f05842cfb9ae2 ("kasan, arm64: allow using KUnit tests with HW_TAGS mode")
> 
> No, that commit is fine. The issue was introduced recently in
> ed6d74446cbf ("kasan: test: support async (again) and asymm modes for
> HW_TAGS"), where I changed kasan_init_hw_tags_cpu() to call
> kasan_enable_tagging() instead of hw_enable_tagging_*().
>

Thanks for pointing this out, the commit message above is referring to when the
guard was introduced but I agree it is more correct to refer to when the logical
issue was introduced. I will update it in v2.

>> Fix the issue making sure that the CONFIG_KASAN_KUNIT_TEST guard does not
>> prevent the correct invocation of kasan_enable_tagging().
>>
>> Fixes: f05842cfb9ae2 ("kasan, arm64: allow using KUnit tests with HW_TAGS mode")
>> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
>> Cc: Alexander Potapenko <glider@google.com>
>> Cc: Andrey Konovalov <andreyknvl@gmail.com>
>> Cc: Dmitry Vyukov <dvyukov@google.com>
>> Cc: Andrew Morton <akpm@linux-foundation.org>
>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>> Cc: Will Deacon <will@kernel.org>
>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>> ---
>>  mm/kasan/hw_tags.c |  4 ++--
>>  mm/kasan/kasan.h   | 10 ++++++----
>>  2 files changed, 8 insertions(+), 6 deletions(-)
>>
>> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
>> index 07a76c46daa5..e2677501c36e 100644
>> --- a/mm/kasan/hw_tags.c
>> +++ b/mm/kasan/hw_tags.c
>> @@ -336,8 +336,6 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size)
>>
>>  #endif
>>
>> -#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
>> -
>>  void kasan_enable_tagging(void)
>>  {
>>         if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
>> @@ -349,6 +347,8 @@ void kasan_enable_tagging(void)
>>  }
>>  EXPORT_SYMBOL_GPL(kasan_enable_tagging);
> 
> Please keep this EXPORT_SYMBOL_GPL under CONFIG_KASAN_KUNIT_TEST.
> 

Will do. Thanks!

>>
>> +#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
>> +
>>  void kasan_force_async_fault(void)
>>  {
>>         hw_force_async_tag_fault();
>> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
>> index d79b83d673b1..b01b4bbe0409 100644
>> --- a/mm/kasan/kasan.h
>> +++ b/mm/kasan/kasan.h
>> @@ -355,25 +355,27 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>>  #define hw_set_mem_tag_range(addr, size, tag, init) \
>>                         arch_set_mem_tag_range((addr), (size), (tag), (init))
>>
>> +void kasan_enable_tagging(void);
>> +
>>  #else /* CONFIG_KASAN_HW_TAGS */
>>
>>  #define hw_enable_tagging_sync()
>>  #define hw_enable_tagging_async()
>>  #define hw_enable_tagging_asymm()
>>
>> +static inline void kasan_enable_tagging(void) { }
>> +
>>  #endif /* CONFIG_KASAN_HW_TAGS */
>>
>>  #if defined(CONFIG_KASAN_HW_TAGS) && IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
>>
>> -void kasan_enable_tagging(void);
>>  void kasan_force_async_fault(void);
>>
>> -#else /* CONFIG_KASAN_HW_TAGS || CONFIG_KASAN_KUNIT_TEST */
>> +#else /* CONFIG_KASAN_HW_TAGS && CONFIG_KASAN_KUNIT_TEST */
>>
>> -static inline void kasan_enable_tagging(void) { }
>>  static inline void kasan_force_async_fault(void) { }
>>
>> -#endif /* CONFIG_KASAN_HW_TAGS || CONFIG_KASAN_KUNIT_TEST */
>> +#endif /* CONFIG_KASAN_HW_TAGS && CONFIG_KASAN_KUNIT_TEST */
>>
>>  #ifdef CONFIG_KASAN_SW_TAGS
>>  u8 kasan_random_tag(void);
>> --
>> 2.35.1
>>
> 
> Thank you, Vincenzo!

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/08e480cf-90d4-8225-1af9-fe187fc622be%40arm.com.
