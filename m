Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBUFDVOAAMGQEVN7NPIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D44130040F
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 14:23:29 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id n22sf3526272qtv.10
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 05:23:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611321808; cv=pass;
        d=google.com; s=arc-20160816;
        b=BLtrnJ+/h3rZOXyvCqNhDyIt7LyA4gtT4fIuZnlIvdC8bFSblqRQDEqdMHImAkKAJO
         ad/1FchzbljQLJOZoPzwSziVtn8qm8DbpQCFnEdjU5qpqOxQDq35DJbKmfljFZF7qTnK
         xur/Cs8F0Ql7FxDCe10ubeoVEf/pHEcUMpqjx09I7LabnZc/pBW2DPE+d3dmN7pF2be7
         eogM0bCuxjiONFTla+3KraLyBo64ru4v1wPIDVpmLIi4k9NwrpOBa1dEJqrfnPmeHCkv
         Bx9eFLsz3oDDkRV4aKv/SGcBz8PfHsA4CKJ4zpoGeg9dxl3IeJmrnmSela3vSui5X801
         D6wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=s4iU3ItH/XbOWcJlAoWVjaFQ5vJ/hPRg7BMDpmq9N7w=;
        b=qKo0mFfpY5uc4WJCLGEye9MMyWF1lQNy+OwDh1HtoC5OH99/vfw7yPONc7YpwDxPmX
         DSYs6PR+xvVtJtmFj3keUFrQtbgonu47ZWWxmamEUbWR7uEtpqGcPEk+Ti29G/RO7670
         d6ILjtiXGF29sMUYFeUxdFb/11+BLEZIq1KjyK0ayD4KpUTysEihX8f6wlc4CcUxPH9Q
         MJWyrHqDPlMNwM1MjcrvmOjXuQ6hgLR3SgQx7WAeIetBkgo2qa48fp4u/Rewv1GcriSN
         kfT6FpZ3Q1E/JfKpjC34JGSNcshbHjaE7BUKvLmw9OQzs6JXQBbiSsWN3fEFUWKMiy3b
         hMIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=s4iU3ItH/XbOWcJlAoWVjaFQ5vJ/hPRg7BMDpmq9N7w=;
        b=sFseDRqzqJvOwsiNs9L1KfEv7soLagsxx4WokV3b0E38VCvIlWtUdXdSCVo/GnA/Vx
         LzPY4yMpL97bKEO9Wyr5JoOeZRNKj/Q2lu98kJeuL/H5bhUQ6vFuT5cEtspQDqfQv3Rt
         EwfR294Vigs1Jw9QhiubCGjYdFIq7UdPsV+yMKRs/7B74fiBbkmjcflXPRvwpLs7XNqq
         jM7TACUXiqwhs3w7GqspzqbArzB6vMVw5HhccoaA7wg5/KqsCI/hYs3QnxEo+iSe4pNw
         kJ/Y111hrg7LhOCAY1+OwTilpfbhr5oy3AQSdK5yKMuq5GDRv/ozQs0f+kSrLMFkPfcD
         BLPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=s4iU3ItH/XbOWcJlAoWVjaFQ5vJ/hPRg7BMDpmq9N7w=;
        b=s6tTwISj5zCDuoeKWd01lARfG3wleUTwtSHPOvNI8pPquUm4JgWER7NRvIhlaPZuZh
         5h7GRcCDrTwp16Q718CPXqQzPMGaZtTV63V1zV7vNCjuatgnEI5hb2WBjQ6ErGu2ga7P
         DuN/xGdRsKoqxyDHEfe+lr8W8sjCvR3zKzWh/k2QVftDgKuiVsIfqbJfGpWfj9d+POcw
         6ZA7wxYP2Aak6OTDQIyiPZg5kPMK+/rDXGgWnFgWjAlin5oBlsG5rsHY2BzjHtufWORs
         AEzT+7XqSnsANsGwDxUjv3LOK/1VU87t8JPJIn6fF0BUhiEcui38KxqTLIgI66gDr3U8
         tEmg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5306d8Bgxm4h/TPBdHifp8UUVMhAEFsRWUmggiJs97y8BckpkJ3I
	etZqzyPMNflUxlWj1ynzmDc=
X-Google-Smtp-Source: ABdhPJzF/GDhl+cUWsP7LvkZDpT/DY+5KnWyWsAvTe1zgonBEsAURrliRWbxof+KUNZgjjet87vR8g==
X-Received: by 2002:ac8:7304:: with SMTP id x4mr4197037qto.338.1611321808509;
        Fri, 22 Jan 2021 05:23:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:590e:: with SMTP id ez14ls1414955qvb.6.gmail; Fri, 22
 Jan 2021 05:23:28 -0800 (PST)
X-Received: by 2002:a05:6214:2b2:: with SMTP id m18mr4231566qvv.40.1611321808104;
        Fri, 22 Jan 2021 05:23:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611321808; cv=none;
        d=google.com; s=arc-20160816;
        b=0/TuL4HoHumb1eXooiygI+ez46n1gLc8hyCcShtWFsOshZattZTv3eWGeJFRIgzWzm
         NbAE689s2zlXYtdfRUwJUTor33McyLQ+YbONP1vGEgu+gSvJ/xnAciTQrjNBHA25rWW5
         rJ9RhaT89gLw5bgjMGEEU9xqVT896okHibkirTRT+ocnSa7QxWZCkDpbz+cFoCJlqHsU
         XkBavli8VWYe5cIuJYpZvE1B8QwXGSwftb1E2z9fJKMeY780Nil8ajlyLB+3r4D8F10I
         r4fr1R6V7k71UTJLUVhK7A5Un4tuj1lzZsMBDD5ryRpMzuA2C/10v3cvKlQ/SpqT8b5f
         e4JQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=74rMpNKUAbZM5ds80fc7TzSc+gRcLM8U0K/NdUp6sfA=;
        b=mFAxBbmxJBtbTPWVaU90OAXCOvZo8D4BEB2fUUdIOEQtRyjib62jeI/ptVESvApgIR
         1HSeYoMBWxOQj8DlMw3o6ia9FvCUjYPekPwl+EiR1vCYrydN1Pncjzum0fshmE3iRWHD
         xz8T4bgMuqrQqb7aHyPLIz1s/Vo+AsXwJES6MdYwLLsRRmnq5D3Hq3gsPNBoZOFEbf/Q
         qB+qs+FCalTwUECU6IINW7Zm6DtaFpzIUmWvXhKN1EnjkSvsV8hGvzFH6+GW5cPtSZLg
         U83q2X+9ojZ202tn8C9dXjgx8La5YGboaRFmcXCJszh1YyWButlsr7x+51m1jUCe3GzA
         siuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id h123si473628qkf.6.2021.01.22.05.23.27
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 05:23:27 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4320711B3;
	Fri, 22 Jan 2021 05:23:27 -0800 (PST)
Received: from [10.37.8.28] (unknown [10.37.8.28])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id DA7743F66E;
	Fri, 22 Jan 2021 05:23:24 -0800 (PST)
Subject: Re: [PATCH v5 3/6] kasan: Add report for async mode
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210121163943.9889-1-vincenzo.frascino@arm.com>
 <20210121163943.9889-4-vincenzo.frascino@arm.com>
 <20210122131933.GD8567@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <6ccde9db-98cd-5a56-b93d-0b79f4df56a7@arm.com>
Date: Fri, 22 Jan 2021 13:27:15 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210122131933.GD8567@gaia>
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



On 1/22/21 1:19 PM, Catalin Marinas wrote:
> On Thu, Jan 21, 2021 at 04:39:40PM +0000, Vincenzo Frascino wrote:
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index bb862d1f0e15..b0a1d9dfa85c 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -351,6 +351,8 @@ static inline void *kasan_reset_tag(const void *addr)
>>  bool kasan_report(unsigned long addr, size_t size,
>>  		bool is_write, unsigned long ip);
>>  
>> +void kasan_report_async(void);
>> +
>>  #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>>  
>>  static inline void *kasan_reset_tag(const void *addr)
>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>> index 234f35a84f19..2fd6845a95e9 100644
>> --- a/mm/kasan/report.c
>> +++ b/mm/kasan/report.c
>> @@ -358,6 +358,17 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
>>  	end_report(&flags);
>>  }
>>  
>> +void kasan_report_async(void)
>> +{
>> +	unsigned long flags;
>> +
>> +	start_report(&flags);
>> +	pr_err("BUG: KASAN: invalid-access\n");
>> +	pr_err("Asynchronous mode enabled: no access details available\n");
>> +	dump_stack();
>> +	end_report(&flags);
>> +}
> 
> I think the kernel test robot complains that with KASAN_SW_TAGS and
> HW_TAGS disabled, the kasan_report_async() prototype is no longer
> visible but you still have the non-static function definition here. So
> either move kasan_report_async() out of this #ifdef or add the #ifdef
> around the function definition.
>

I think adding #ifdef around the function would be the best way in this case,
for consistency with the header.

> It looks like the original kasan_report() prototype is declared in two
> places (second one in mm/kasan/kasan.h). I'd remove the latter and try
> to have a consistent approach for kasan_report() and
> kasan_report_async().
> 

Ok, I will remove it.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6ccde9db-98cd-5a56-b93d-0b79f4df56a7%40arm.com.
