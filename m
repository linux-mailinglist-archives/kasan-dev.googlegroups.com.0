Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBQMET35AKGQEMWBI5JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id E86792542C2
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 11:52:02 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id a5sf2670298ooj.6
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 02:52:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598521921; cv=pass;
        d=google.com; s=arc-20160816;
        b=04qNRPXg+qBLafETjdFJpHsIH6dBChZPXf9PlbhH7ns5CWFJYeL8fdtUYA4DXdqE6m
         FmAAVaPuAYb8B+xOcVdzYRUoKxa6Jv25RCGC82EQHkQc5d5i3T/2bJOuBZuQCv+1+e6T
         yfC6QhyHEryI32eEDmmp+cIObPIRogYRb6j8HtIRHZ4CkIkQwRRn5IDAGvF7eyPUrL+M
         mLxoi1aDLyrYEArr0OVssOMKp9+RahOf36te70juOiJEA2xa3savLWKLF7aBWA0+zUsO
         XxJZ1vSFKJZFcRjxLysZIZx2INkAUQWz5MsrJjXdKvpMGvuOZba9gadN/PAzzn3vk37s
         302A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=NofHSISWDkmyH7Lbn8AYr8CAndfsbkbyAdqeROL6LQ8=;
        b=w3g4rIA2IXZ3IMz4TgzXCAobtEkTqEmQTsyXSEHEGVssA6kYxjr7Zn61yCYqlzbPlK
         JK/Qa4p2YNPaV6yjmGz7nIXoS4BF6gisSWepf1CK/Taydx9OtwyB50+V9ojzLIjXSfwj
         8mz1CBCRUUCqtngM763JcbtzwQEbdjOMWeh8gt3zmkzGqKae7Rlkj3QfXzCQIh5o8izK
         ZX1bfMkmKC46dL2sNNytfgsjsozlbMYYsFSTi/S3WXXYt2ejN88H/crjomXKtQX4bwKr
         mRBQkn1YvPAD7NrBYHlwQQoamJ3E3pAIjhn83pPZUJ9QOgCOofek6U2yEjqbNUfFed63
         DwBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NofHSISWDkmyH7Lbn8AYr8CAndfsbkbyAdqeROL6LQ8=;
        b=Mc/8Sp/GWl1xNO5HKJzUQFDQXGUnpCN+qqxm3AqbC7lZMoB+6Lw4pFerFT2XZh90zp
         +QZrKnypY4mrFYdwwtob+mUfW6jGcos2NL9LApmqKuisAQBc8o/nG/n88ibXNn6uXEz8
         ILczDamzM4vHOl6T1hfENyR8OhFsqUSuzO5tO7OqWk7JIUxitKD/qA1ptjZb/eTLySI7
         0KoI+wNRxUrxB93GLUqfIZuyDnGjTQ8ukWTGx7uLwH3LuYFRyJ2tArzZO9wEc6honOUF
         8frQBlGVGAcwegI9nkHZCRqY/+Ls95Fnv1/Rgf9dbBKGLZNNV9l8CGmbMsfOwKuVkfri
         yF1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NofHSISWDkmyH7Lbn8AYr8CAndfsbkbyAdqeROL6LQ8=;
        b=qfyIdBqM9a6oMY6n0OcY8ZLBn2B1IXxA1OowNsupeY4WEYlLb0jUtT0bVZH+EolaVs
         gncAcbj50sZpTjUv6U/fIAJvq/8aqmTISvuNsrylnJewkgPpmzhEP6YUrlG+VJnZ0dg6
         MibuRhVVOS2Cfh7AMDPh/90+O6/lYWKI1pJTEq6y/E8C4+8ISmSwBqBGEIMHnn+OllAa
         f1mwVcouWijoSW4llAF9SEmuc9wPhrLABhR6/tu5u2sA5aeZq8ziq9Wg/N+oaISbtt/S
         WNPE1FoGZnhXTG8IAG3JTqHBIgsI0YNalpWj9iVMsHaNEYCUoD/Z1oSU/o+qe9uIo9Te
         6mFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532uaAK2lbAoAMX+xw6f318l4BdQjRkgNsvSl+bD6D9O7jy1jZtJ
	yGpoBemWJVRK5Zj6+DbstE0=
X-Google-Smtp-Source: ABdhPJw3JDmoYoo/JhjxKU8+wdoCmkFx6t/DMSTtOrhXLCJNwEXjHxh2nhKL5wn6fYzeIfa0CNYoPg==
X-Received: by 2002:a05:6808:6d2:: with SMTP id m18mr6526089oih.89.1598521921262;
        Thu, 27 Aug 2020 02:52:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f31:: with SMTP id e17ls480165oth.2.gmail; Thu, 27
 Aug 2020 02:52:01 -0700 (PDT)
X-Received: by 2002:a05:6830:31a6:: with SMTP id q6mr1151713ots.218.1598521920946;
        Thu, 27 Aug 2020 02:52:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598521920; cv=none;
        d=google.com; s=arc-20160816;
        b=kqs7c82hJLeq302MkV00e5tXfRNxKbUjgAsCOYh1EXNGt5oCJKe3sU167clT2jlVX6
         NdW9mHhyEb2Z/W/tDyAEyQaqgq5xFcIQ5LSdpYuK7MgkB21YmsO9gGbq0S0IeLvdU8DQ
         Sefg3ukagd4RhkN8Z7JrEBblT1G/0Bg7H41AJAlaOKVAc24P2fYfYIeiDIn/Z3NxEezR
         +mpFqiNd7YhbWHBkuleFXu8hrPZz8+ZLlp+auFqgVzj9LHFXlCqWluFg9y6ikgItB+lT
         jLNfnb7u42rWmo5fa7FG/NV8QTnzC5aqNV2MpU7p+2hQo216cLLQtuIC23aYnmKtMAmC
         b9tA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=GP75yR+Gwma8nioK1ZoW6mQvdedwE/qzVjp+HUnqSyU=;
        b=tcSGWtfq0xDLjneHvbc1+lxqnNKFd+U9+qI6KCPuhzitwUbJBn9a7WrrasE3XFVdRe
         DWKDlbiCtjMj7Qf45xZ4D3RJi62vA80syx5jab/cCYol2S0TCRSJ44PQ4Mlg2JUx1QAO
         wsP0XTObNC4vXKo/Ra4j/p7uVYYDditGpIW7MkOzZgwyv0LWGPaWo2RqUkXVF+N688p/
         uyaOvPuACkYkmNy7wDh6EFEdIeJm+nHJnSB+7pDketGuAfiN+qs3ANylwsHN2Kwdr//m
         0NM6bzImA1yxPwpcl+vpMyxynhjzK9sceWKf/5QIBPn6bjcJ+dUdONbLzZFUVgdEnLo9
         Gq4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id t21si61728oif.4.2020.08.27.02.52.00
        for <kasan-dev@googlegroups.com>;
        Thu, 27 Aug 2020 02:52:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A53D7101E;
	Thu, 27 Aug 2020 02:52:00 -0700 (PDT)
Received: from [192.168.1.190] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 7C99F3F66B;
	Thu, 27 Aug 2020 02:51:58 -0700 (PDT)
Subject: Re: [PATCH 19/35] kasan: don't allow SW_TAGS with ARM64_MTE
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
References: <cover.1597425745.git.andreyknvl@google.com>
 <5185661d553238884613a432cf1d71b1480a23ba.1597425745.git.andreyknvl@google.com>
 <20200827080442.GA29264@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <56ba1b14-36af-31ea-116b-23300525398d@arm.com>
Date: Thu, 27 Aug 2020 10:54:11 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200827080442.GA29264@gaia>
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

Hi Andrey,

On 8/27/20 9:04 AM, Catalin Marinas wrote:
> On Fri, Aug 14, 2020 at 07:27:01PM +0200, Andrey Konovalov wrote:
>> Software tag-based KASAN provides its own tag checking machinery that
>> can conflict with MTE. Don't allow enabling software tag-based KASAN
>> when MTE is enabled.
>>
>> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>> ---
>>  lib/Kconfig.kasan | 1 +
>>  1 file changed, 1 insertion(+)
>>
>> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
>> index b4cf6c519d71..e500c18cbe79 100644
>> --- a/lib/Kconfig.kasan
>> +++ b/lib/Kconfig.kasan
>> @@ -69,6 +69,7 @@ config KASAN_GENERIC
>>  config KASAN_SW_TAGS
>>  	bool "Software tag-based mode"
>>  	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
>> +	depends on !ARM64_MTE
> 
> I think that's better as:
> 
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index 10cf81d70657..736c32bd8905 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -131,7 +131,7 @@ config ARM64
>  	select HAVE_ARCH_JUMP_LABEL
>  	select HAVE_ARCH_JUMP_LABEL_RELATIVE
>  	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
> -	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
> +	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN && !ARM64_MTE
>  	select HAVE_ARCH_KGDB
>  	select HAVE_ARCH_MMAP_RND_BITS
>  	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
> 

I agree with Catalin here, "select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN &&
!ARM64_MTE" should be sufficient.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/56ba1b14-36af-31ea-116b-23300525398d%40arm.com.
