Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB662ROAAMGQEEAJB5PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id B4A652F8D70
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 14:43:24 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id a1sf20428571ios.2
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 05:43:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610804603; cv=pass;
        d=google.com; s=arc-20160816;
        b=CLoFarwE1g001h3x9hz50By+hllKn8MmCEMgQNevBZcrcktTmp67WY4uxp/ykLMVnW
         K8/dFduUX/Qgf/bb0d5tRT9V0f+YMEyAG5UnPfnyHQ5n3YrVqQpukWmTJzrvf5OOffWL
         nB5uNI9Ap0cYbwF8JQFgYhtuKJVtF3w71CGV3hy+rD5N0ACdDEly1YU0buHwZc5lhqo+
         cIJkCtTc6xEPxg+e4XrKjCGHU45paBXvImvuZ3L4BoMEvM2nxdDiRUu4ZGUwsz6E3CWM
         pQtx6c5beNwzVv/ghDj9bB8vOconhz/d8bLP5ghy62h7LGGipqCEyHt3FskiyXoBvlN8
         oXKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=3zRrpVarLNBSQVyuTl/yk93RdKuMZFwq/61y4c/Exyk=;
        b=Pp6tLGY+KS6kyCjczeOsQZ9/0UEM49pgurRWHCWUa/y6CgZDK27SMQWPU0ji4xylr4
         GLBpyUmtTQqopgCAOhEIudSxWf7fRJmp3urY6GJVPowbOV+iOpeLXx1NVLN3ZLwQX6BW
         pNhnv1bLRR1UmrUky5kj+0r6A78URUyNm2nsPiQmd9XT5W7Uu8Vm3kEMYYhqRVbZLfvE
         IzWh1bgoOiAvZ1bfRCH6zTT1IkirExSj9lbpr/9h3vuc/sX7Rp1om6UceeDyiFHAQpx9
         fiFFq0XAP1QQvBqrwq/YTZvzhWDcrIlq8yC6bYH2UyzCS7FexJuyD0mroVntlWw1j4Zk
         JSWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3zRrpVarLNBSQVyuTl/yk93RdKuMZFwq/61y4c/Exyk=;
        b=SXMiU/vY+XQwgeEM81q1brzWoXLIxBcNqK35gs/XhmfUu4GuPlWZ6cpAjpKPmQWUyY
         SbL6dIU61y4dkJF9MFExb44DCY6u9DzrfRBPUesPaGqCrMIhh4RdHbO01IgaXQTLOCFS
         xiBJCv7qtNpJ73wTCB8jAdNDq1y28F0j0epzjV08iy39WlAs69pJg9x8dmhJGkOZ2Z9W
         PSu3JQ/977FfS/V7Uk5lO2tmzcc/tuSnYO3S4Kh94wj9cP9DNJZjxVYiplchJ/9tcJwy
         gEbkxTJhUkNcHpvkoIoXkf/RNWTNJnCVR8I/5ZflI5wLaVA2WpjJp9r0qYnVFZAD9xRr
         j0Iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3zRrpVarLNBSQVyuTl/yk93RdKuMZFwq/61y4c/Exyk=;
        b=eGR5vID8AwKmTNuxPnaItyUuJMVFaY8lXLbwDANKOkw/N+PZUuozUYtDrsjpAXZqbF
         uvRpBFn1KMrrGqTfqlQN4tm4jSDoxYXr+ZZPAn9Gb1pgED9kIAR+bPnwPqztbYVVtdrf
         kIEmCrjNmDc03cGtj7/eJY1dkxwGYnjvwvIZzheHh9JC8/7HbH7upA5MGLjh6yqrUZzD
         XO4Wi+AMFE3M6QXO67UH+zSP2uKhZBJshxd4wIDe4c+4eVkqHQzsbXZWDF1BaUtYWglz
         a9tNI1aCs+cMwC3DHKCfDmjYR/8AJL9YX+w3T4/sCk38tpoS8NV+2TJ5wI138fjRzoB3
         Kdew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5333ft9VduAYw7aWfZR2K7wglBBmfV/lmXCv5/bIy4LofFzQoMfU
	YHqbSc1k8Oou9KADbT9cYjM=
X-Google-Smtp-Source: ABdhPJwF0Qi9d3yLMf4iEDpSH9OAjziUIMNLD4LMj0+lzxveAvl61sXQ6gfQiGDQoT2TANliLqRBOw==
X-Received: by 2002:a5d:8405:: with SMTP id i5mr11983942ion.164.1610804603790;
        Sat, 16 Jan 2021 05:43:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:10d:: with SMTP id t13ls1916334ilm.5.gmail; Sat, 16
 Jan 2021 05:43:23 -0800 (PST)
X-Received: by 2002:a92:5b82:: with SMTP id c2mr9961182ilg.289.1610804603491;
        Sat, 16 Jan 2021 05:43:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610804603; cv=none;
        d=google.com; s=arc-20160816;
        b=GW5CBXALI8i0PGylOIXkZrDnemLfXFlPR8MfT/pSBWyso8EtrSlRBttC6EtOlledri
         qPe+7XuSraG2iXdfAO/N4/7N5Wt9ig3QoiZK05B5ENCZydjA4X4qUi4BPISYtHVRR2YI
         z6stPu9Bt+0L5C3A1mNG368Qwi45f1OoWxzf1BA4Fzcp63exMCFchWJHsOrBnosjyyfK
         94KIe0d4swWyxeUO1Opj8YMWAF4hQbgAoMkvj/qcfPRDd7lSxI6b1q81u4U4MAHgt1BE
         ALVdPvORKClXG6loqmW1ItD4GS1uqvEjj35QA32uQ20g4vdf45koLc47c34HYFvzhqwq
         2jdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=YB72YrsK7zmJZe/nPEZBCku7dLw3TuhKxlFkSmd7FwQ=;
        b=03W6TKgnRUSgm5C0gPKfXcB35SpUKN9kR1mUFahS7GzL5Ev4xzdMilig5j0MSpU2BK
         NCCo81XYnWXqLsAHKXYhUl0WxchGUOYEyQBMxBKOYuUKazMuea0ZvPtfe3GhZfyNV6Qb
         LnxEX5H1LfZqqQFOZzAPvOSpokuNWcmDC5HmCv4MsqYWHZo6CdP0X0mWPhfheGuPB9yx
         YwEPaE2JS/8oq5SZ/nFmpjF4jFQDi7JRUj3+/uIkujjVGPfntGimBpduskxZKdg1MwW0
         95BQROnXL45ndUlgRNLlBYxGd2ZBu/zGz/jkqgL6BovlfTElLgcdlta6v3TGSEurxXMS
         zEMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l3si687052iol.1.2021.01.16.05.43.23
        for <kasan-dev@googlegroups.com>;
        Sat, 16 Jan 2021 05:43:23 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D3540101E;
	Sat, 16 Jan 2021 05:43:22 -0800 (PST)
Received: from [10.37.8.30] (unknown [10.37.8.30])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 61EBC3F719;
	Sat, 16 Jan 2021 05:43:20 -0800 (PST)
Subject: Re: [PATCH v3 1/4] kasan, arm64: Add KASAN light mode
To: Mark Rutland <mark.rutland@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Marco Elver <elver@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Alexander Potapenko <glider@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-2-vincenzo.frascino@arm.com>
 <20210115150811.GA44111@C02TD0UTHF1T.local>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <ba23ab9b-8f49-bdb7-87d8-3eb99ddf54b6@arm.com>
Date: Sat, 16 Jan 2021 13:47:08 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210115150811.GA44111@C02TD0UTHF1T.local>
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

On 1/15/21 3:08 PM, Mark Rutland wrote:
> On Fri, Jan 15, 2021 at 12:00:40PM +0000, Vincenzo Frascino wrote:
>> Architectures supported by KASAN HW can provide a light mode of
>> execution. On an MTE enabled arm64 hw for example this can be identified
>> with the asynch mode of execution.
>> In this mode, if a tag check fault occurs, the TFSR_EL1 register is
>> updated asynchronously. The kernel checks the corresponding bits
>> periodically.
> 
> What's the expected usage of this relative to prod, given that this has
> to be chosen at boot time? When/where is this expected to be used
> relative to prod mode?
> 

IIUC the light mode is meant for low spec devices. I let Andrey comment a bit
more on this topic.

>> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
>> index 18fce223b67b..3a7c5beb7096 100644
>> --- a/arch/arm64/include/asm/memory.h
>> +++ b/arch/arm64/include/asm/memory.h
>> @@ -231,7 +231,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
>>  }
>>  
>>  #ifdef CONFIG_KASAN_HW_TAGS
>> -#define arch_enable_tagging()			mte_enable_kernel()
>> +#define arch_enable_tagging(mode)		mte_enable_kernel(mode)
> 
> Rather than passing a mode in, I think it'd be better to have:
> 
> * arch_enable_tagging_prod()
> * arch_enable_tagging_light()
> 
> ... that we can map in the arch code to separate:
> 
> * mte_enable_kernel_sync()
> * mte_enable_kernel_async()
> 
> ... as by construction that avoids calls with an unhandled mode, and we
> wouldn't need the mode enum kasan_hw_tags_mode...
> 
>> +static inline int hw_init_mode(enum kasan_arg_mode mode)
>> +{
>> +	switch (mode) {
>> +	case KASAN_ARG_MODE_LIGHT:
>> +		return KASAN_HW_TAGS_ASYNC;
>> +	default:
>> +		return KASAN_HW_TAGS_SYNC;
>> +	}
>> +}
> 
> ... and we can just have a wrapper like this to call either of the two functions directly, i.e.
> 
> static inline void hw_enable_tagging_mode(enum kasan_arg_mode mode)
> {
> 	if (mode == KASAN_ARG_MODE_LIGHT)
> 		arch_enable_tagging_mode_light();
> 	else
> 		arch_enable_tagging_mode_prod();
> }
>

Fine by me, this would remove the need of adding a new enumeration as well and
reflect on the arch code. I would keep "arch_enable_tagging_mode_sync" and
"arch_enable_tagging_mode_async" though to give a clear indication in the KASAN
code of the mode we are setting. I will adapt my code accordingly for v4.

> Thanks,
> Mark.
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ba23ab9b-8f49-bdb7-87d8-3eb99ddf54b6%40arm.com.
