Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBSHDW75QKGQET6OYVOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id AFD822789A0
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 15:34:01 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id m1sf1898267iln.19
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 06:34:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601040840; cv=pass;
        d=google.com; s=arc-20160816;
        b=dc35JltOMLNvg0tq1CPiTzat3e7lMZNzj+0mvXMAbKvpxW94i3RhgX5Fi3xbSkgK6l
         Lz/UByAFxSWw+lYAdMGYvtN2RftS7PvWi6yl/9inEeUUsztLxa3PlkU53uZxyHeh/E51
         PAEGWZb2pGdfOtms8w6s6POPvn6+HvetI1EDAANk+N94T+5eshfo90PuUEi340vclvjq
         L5g2KRHgj4aprLWrxHHHW9o3zANr5r3ZxQiMoYY5Mlz3BwpZoT9pwgC0F6fiW6CkdjvN
         PmNo7nWif4v/0Wt8LKcDKArUWNfRt0YBfTUF4VHu8KEUjafwt0vIkixIVSKE2xAyfjA2
         xJPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=uliRjYdMVa6GjUrjewYBw4tsrfDcUmKMCvVFxYdHsOo=;
        b=ApDzoPcRP2KEfZhW9FzYgcfCNABeOX+R+9vZnk2vu2o1lB0Qn6b7xKaMmNFkWJOKFc
         RaMw8LY5FhIZTVJZVqbwtoLNdJ78uuRwiaeKKWfXS5xjZRrqgTOVGsfRXdm/ofcIvE0V
         k1Eqz7Rz3tbg+01ZEEQUb6tVfKsOUKi+5T1wtG+7EDxAUUWMPqIw5Lp1gB+RBtVXAJPx
         jp83kY+XVqDnSzCF9nkacGOTJc93WD+gzPLms/E40czUAEX8Mk/3fX9XFQ5z7pntwAlR
         KfBsZWSA99shxLwIFxasX4jqpFcf3q9+3L8MIdfxgolaO999LOqeRn8coPUaHAYi+stb
         o+bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uliRjYdMVa6GjUrjewYBw4tsrfDcUmKMCvVFxYdHsOo=;
        b=eaWiW3DB5mJwGbMxFxMmTBUfDK0JaREGzeF8Y8+jlr7hAXlTxqeotlW+/0yVCeb7q2
         2aQGih/9skpvpOtNTwx3h7Gp1bkhpSYe02J9cHPSMvXg2TFkjG+CUcxkl/lxdOFFq5vB
         ucbYofeydXJN9uR6CSgy/vLTqgD5dGEOS/X6N7w+9brssJNVdpTN8aAoNTL3dso84CIj
         lzVK2mPDYi1MX/bqFIoaaK2ATeLnjOULhGoP4lZINyL5nbbiRWhoPi8H6Jw5kHEMQeWa
         2UCuCKM4lA4j8R0AKjnMYPqEuTB4CCdenFn78HFsY/JdeU+YHCH3w7D7ofsF2B78xES5
         SZzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uliRjYdMVa6GjUrjewYBw4tsrfDcUmKMCvVFxYdHsOo=;
        b=a4Jep343rNeDu8vVk+y5XgLR+Vnv3cVS/Adsya86fAFbrFcYVIJB3ySpU0tjiYlRgv
         1sJ1fH+9UX7iy29NFI3E9Z4zK9j43Vcvq9lUqijuyWdE4tPJbZL1BxhVXUYCgQunrZFz
         0tlX5CHzvLYj7PgFhHT9qJPKPHrrsxufTJUntcPwZGpSskxjgZzii5r8VXhlQihqXt6R
         2EXqa+b8JAsEa+4FXfxnKDjBdONaBXNaU0/8LUvYsI3/3ue3Cul1NOi7+nrnONhA3dbn
         iUGiloHzMZeEbejYu/QsfTcflmxXZOdijHKdW8rfEmHOhGVYylt7haWZKLkH/og22px7
         lzTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532LQJBRKpoF1+URERk1BE+SWPs/3h/Uw7IfTyTJLgS0lreC4Bmi
	ns4LwmIYgAQ+VP2VxV6saaU=
X-Google-Smtp-Source: ABdhPJxPNbZx3Bz/wgm94TsgeTVl5kC+ODi27oGw0H0NP9KmUFid6MscwwXPVkDy4J0ErKTu6X3LNg==
X-Received: by 2002:a92:d94d:: with SMTP id l13mr206625ilq.140.1601040840713;
        Fri, 25 Sep 2020 06:34:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1307:: with SMTP id r7ls378440jad.7.gmail; Fri, 25
 Sep 2020 06:34:00 -0700 (PDT)
X-Received: by 2002:a02:c8c8:: with SMTP id q8mr3302507jao.46.1601040840289;
        Fri, 25 Sep 2020 06:34:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601040840; cv=none;
        d=google.com; s=arc-20160816;
        b=oPrNke5zQbxE3Km8+Zv5pJMbprZRmTNzgpcatvI59bQv54QG18qJvVFpGH+phEE1Tl
         Hk/4GQky/NtV57UbsgS0wk3OAwfiOUnEv/qXXO2+2AAwcPplg9fwvOumRUtg5U7dyTbm
         99qC1LufE77J/4nQYrnEn0dEGbUaNrgtt9o2wFxgiqtiNB8DbbNvnAY+o3qC9K60XAI+
         vHib1+Ylec/FQeqc2iunSHqfm9znjsSLOXQno1kh7G3UpMcfcHbBe4TjAthEL4oh6fBz
         5v3/qf9kcsJu0y1RLfD59CGtDQWCOMRM2q2A1cxKjInkDDeS2/Cimt9CiUxSAV3Zou7f
         HZOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=YTT4Ps3uj4P9Fss76d8pYoO0PmQ6VUjcu8hiGXgWjLs=;
        b=NtGDViYoJ1M1wBO+1h7KbvBwRum23mA/epBDcbYwNiijdKN4P8BDTiMwE4bgarkmaF
         w00M9XOs96M0bDFJIvA7IcfSGb/rdfYVMQXBZ9P7tdU7EpdNO52ksBFK4XqfZc2sqiPb
         D+xj3z3HEWY6QelSLF79zoEjHJPgW0w5jXvyaO1gGkybYc9pzIdWh0GhbdtBApWOvAfD
         i9WvJGqJiHNEy8mpQDfuWf4fSs09uppjQU1Qtk3BuqrZs5tJs35ljnmRKSIfVd+yqIZF
         XkWaS6kBaWfHdGNAkc1Sj/litYa7Xgk/DD2E7uRH6arbGDghb0+OgQEFq7P4ZPLHctvG
         SZGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m2si177703ill.5.2020.09.25.06.34.00
        for <kasan-dev@googlegroups.com>;
        Fri, 25 Sep 2020 06:34:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B12AB11B3;
	Fri, 25 Sep 2020 06:33:59 -0700 (PDT)
Received: from [10.37.12.53] (unknown [10.37.12.53])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id EB5953F73B;
	Fri, 25 Sep 2020 06:33:56 -0700 (PDT)
Subject: Re: [PATCH v3 24/39] arm64: mte: Add in-kernel MTE helpers
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1600987622.git.andreyknvl@google.com>
 <ae603463aed82bdff74942f23338a681b8ed8820.1600987622.git.andreyknvl@google.com>
 <20200925101558.GB4846@gaia> <e41f2af1-f208-cc99-64f9-2311ad7d50bf@arm.com>
 <20200925125059.GM4846@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <a2c5d41e-1895-2e3f-5624-4f277066f98c@arm.com>
Date: Fri, 25 Sep 2020 14:36:29 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200925125059.GM4846@gaia>
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



On 9/25/20 1:50 PM, Catalin Marinas wrote:
>>>> + */
>>>> +SYM_FUNC_START(mte_assign_mem_tag_range)
>>>> +	/* if (src == NULL) return; */
>>>> +	cbz	x0, 2f
>>>> +	/* if (size == 0) return; */
>>>> +	cbz	x1, 2f
>>> I find these checks unnecessary, as I said a couple of times before,
>>> just document the function pre-conditions. They are also incomplete
>>> (i.e. you check for NULL but not alignment).
>>>
>> I thought we agreed to harden the code further, based on [1]. Maybe I
>> misunderstood. I am going to remove them and extend the comment in the next version.
>>
>> [1]
>> https://lore.kernel.org/linux-arm-kernel/921c4ed0-b5b5-bc01-5418-c52d80f1af59@arm.com/
> Well, you concluded that but I haven't confirmed ;). Since it's called
> from a single place which does the checks already, I don't see the point
> in duplicating them. Documenting should be sufficient.

Have you ever heard about "tacit consent"? ;) Anw, fine by me, I will add a
comment here.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a2c5d41e-1895-2e3f-5624-4f277066f98c%40arm.com.
