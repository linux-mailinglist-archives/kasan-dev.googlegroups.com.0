Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBINQW75QKGQEYGRDSNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id BC6FA278630
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 13:44:34 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id y7sf1752611pjt.1
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 04:44:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601034273; cv=pass;
        d=google.com; s=arc-20160816;
        b=lnwgr/aNXzPhpLAjyFbdn7qyWWoCJxbuxaJrt8DfwhQuWqklBBfnk8BlvM8bRnbswE
         f1nudLfepR3Neuz0hz8zoRQOSgQiTkceIaTEQaaPX3aaw2lcYet8ah83wS74ODKZgEyQ
         ciJSSs8hmtm93yGio0Im0FLFu0dC1dUvuQzhGmHR9hItOLLhAGls8gYv7WSaWf8uPTLx
         xRfr/l5jrATsfTLbh+tGnm8euYBVdxUrPVA3jr1fKM2ygzFOrWsVnreokO0QOYCyC2rB
         LufpfY8Pzy42NtX9GfgK4pC1bQMDZCVGKrvnMnCkF3uxKJD1FHJ6cpTqGw8xZJ8uoYzB
         uqVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=3s9Ftx8MbQGzA3EMWRNKR+C2rui8WHBFHm3glRgtB4s=;
        b=IuZNq1vOWXEjKrk1m+0vj91UBzc4p/8k3cPHBR2qc8kkUmEg580nww1cgTRKDsmzJ9
         5jE5V0RAE+a1IiL586FlLOavJkiI6dARX5eFBA0Qq6dnqr9RxBzqE4bKM35OXJzWUJpW
         Z7uZ8U77hY4SR64pTNk/9Bhfv1QlA1OyieF30xrFBh6yNvMhcqEnyvsmeo7bEh1MEwnI
         wfRymfi9Ln8rElOfUQwbRnkoDKg0FWjfgBlmREEyi10KcZms5ozm2MlLFHjKIrmDxOo1
         tR7ufanX7BoMtvJoEkurEws5GkXIT+CluAwwDzLXYf2ibIt/wUOyhz+mwcH1OKLb5D0M
         NaOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3s9Ftx8MbQGzA3EMWRNKR+C2rui8WHBFHm3glRgtB4s=;
        b=ca+cO+droIj6ED3Stp6oCf9hM9EXjueLJbcHhPr78i4LM/wQVuEcXbejDoCRJA3ITI
         iK+pi/R9iJD3HFuZ6WFbLK+Gm8gVZPiWNj9tKfzm71phePm99rmZ59duTh6o91j//1jH
         ICqVBNrHdU5F+SsiJHfZEUsOH+3Q0et7UV0af5Q6xQgM7Pg1GyesgP/hh/teJciDfsOg
         kW6xBP9GXIf3SHoP6baOi/oHLZt7qvXmFCVVk9uLXnTw+fjWjt083P7fUYT3jlVwhfJ+
         Xg8FYZmo7mwyP6JN080tKRAzC+xvqFJSbbak/gVzZc+WYsMWLGuFAqdfDJT4jaUHRoR1
         Qo6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3s9Ftx8MbQGzA3EMWRNKR+C2rui8WHBFHm3glRgtB4s=;
        b=mPThMidotcD1KLc4XZYFvAvos3XZ91NmpGxJy7/527JYB+7C15BIGl0Mmc2XRrtwo2
         Hivga4roIFDyCT2OJJ1XrW0adUXWpnEwYp+dJo1l4m5CyjPnvP7LHlqY5FY9wjLO26om
         ZPX89N9UrnJxOAw6Wm1MCQ10uSmOIS67xFQg79HAM/LGgHrWqaGeZK7b+h8gQmgH6Vjs
         QtvJ2Csm5P4mLQbysaJv43uiHkAWRshjaRQNwKcrsbp2vzAhsIB3VMKLX8a4/p/UQzHk
         s9HH+ZLJ1y0s1JbwgZzlLG2sjIAzvw/OHBSKyCA+OZWG2As0AzWP+B1Mq36aM8UC2ExZ
         G6mw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530TUnvJzAUd9t6Do8OyNuIPOODjPDQQN6aOoNRaqXKemIbLMtAh
	Z5UqD3z4lYl/PXR86mnzWK4=
X-Google-Smtp-Source: ABdhPJzwF2blIXLBktPPnP5OqoGAuKXfucTu+vr+zS+nKAN7groxTYMEbfL9o1ybV7jMZ2GjpTV/+Q==
X-Received: by 2002:a17:902:c393:b029:d0:89f4:6228 with SMTP id g19-20020a170902c393b02900d089f46228mr4191310plg.16.1601034273487;
        Fri, 25 Sep 2020 04:44:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7449:: with SMTP id e9ls1447203plt.0.gmail; Fri, 25
 Sep 2020 04:44:33 -0700 (PDT)
X-Received: by 2002:a17:90a:e60d:: with SMTP id j13mr2268377pjy.61.1601034272891;
        Fri, 25 Sep 2020 04:44:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601034272; cv=none;
        d=google.com; s=arc-20160816;
        b=rFQ6YmcYBlJOLzSC6PvNeex5Cx3uH5BeSuM9GVTi8unRaF7Hsyf0BTLvgmts9irBXi
         70c2uFDSznALVMO8rpzJ2g4LQ49PCSOTOO12YE3zIQp6Ainq16RV/13j8lSaK1nBV3lq
         rGhv55eywxrvQ3aZui7cyA7Pewo/YBzPuonr4y7a0eYiYEoqf3tNd6xFhatR5/YgzJE2
         rU4aae8DzbpBaAi01DFEt98Xl85cgE3QHyMJ/qIlZIGYBoeiJovdmJyeHvqMP07AbgJi
         xNzUWutI/ymszvjdpuXqY7DEFMVK+BrM9KA6s7V9LqGTgIQC2Qkgx/OQnzRylIipnrGY
         q8Pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=jMj/nypHuXtv7AtcMP8ctTMylo4XtP4+xsZpj9YShg4=;
        b=vwdvq7KLXGjKOHPLD2b91k5c+pnSQDasdB1k1LvsUJ413oQFKry8Yc1KJ/yNOdFJhH
         XLwM/cxV0GGqRAVP3MPfWX+0NsLYb2Z8CFYjwGeIabCMCFFZMpjVOB714w2uM9ECbcq/
         s0bEA18pqMNIsUgaLcBnfSY6RjFf1s1Tj6XivTwyiEGm4lK4xplhe2ZTMvr0tNZ+XdH6
         M7fRClD5drutaJGWTwb5lyVqR57soylYeqD5KuJKB6szX2Y/6F7AFS2oEwEQIRjmXbuC
         K4F6zqz/WtoPw3psWbQTgsCcNclvCWrfansLs15fAUTZ43qx/0ZAe9JBikpjfZhkozwA
         FINg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id t15si130575pjq.1.2020.09.25.04.44.32
        for <kasan-dev@googlegroups.com>;
        Fri, 25 Sep 2020 04:44:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B9EAB101E;
	Fri, 25 Sep 2020 04:44:31 -0700 (PDT)
Received: from [10.37.12.53] (unknown [10.37.12.53])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 93BBE3F70D;
	Fri, 25 Sep 2020 04:44:28 -0700 (PDT)
Subject: Re: [PATCH v3 30/39] arm64: kasan: Enable TBI EL1
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1600987622.git.andreyknvl@google.com>
 <733e94d7368b54473b242bb6a38e421cf459c9ad.1600987622.git.andreyknvl@google.com>
 <20200925113748.GG4846@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <59c25256-374e-9a13-8098-1543b1768248@arm.com>
Date: Fri, 25 Sep 2020 12:47:01 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200925113748.GG4846@gaia>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
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



On 9/25/20 12:37 PM, Catalin Marinas wrote:
> On Fri, Sep 25, 2020 at 12:50:37AM +0200, Andrey Konovalov wrote:
>> diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
>> index 12ba98bc3b3f..dce06e553c7c 100644
>> --- a/arch/arm64/mm/proc.S
>> +++ b/arch/arm64/mm/proc.S
>> @@ -40,9 +40,13 @@
>>  #define TCR_CACHE_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA
>>  
>>  #ifdef CONFIG_KASAN_SW_TAGS
>> -#define TCR_KASAN_FLAGS TCR_TBI1
>> +#define TCR_KASAN_SW_FLAGS TCR_TBI1
>>  #else
>> -#define TCR_KASAN_FLAGS 0
>> +#define TCR_KASAN_SW_FLAGS 0
>> +#endif
>> +
>> +#ifdef CONFIG_KASAN_HW_TAGS
>> +#define TCR_KASAN_HW_FLAGS TCR_TBI1
>>  #endif
>>  
>>  /*
>> @@ -454,6 +458,9 @@ SYM_FUNC_START(__cpu_setup)
>>  
>>  	/* set the TCR_EL1 bits */
>>  	orr	mte_tcr, mte_tcr, #SYS_TCR_EL1_TCMA1
>> +#ifdef CONFIG_KASAN_HW_TAGS
>> +	orr	mte_tcr, mte_tcr, #TCR_KASAN_HW_FLAGS
>> +#endif
> 
> I missed this in an earlier patch. Do we need TCMA1 set without
> KASAN_HW? If not, we could add them both to TCR_KASAN_HW_FLAGS.
> 

We don't. I will move the code around in the next version.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/59c25256-374e-9a13-8098-1543b1768248%40arm.com.
