Return-Path: <kasan-dev+bncBC7M5BFO7YCRBHXCQHAAMGQE5ESB4CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id EDEA9A911DD
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 05:10:24 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3d443811ed2sf6772215ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 20:10:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744859423; cv=pass;
        d=google.com; s=arc-20240605;
        b=NvFR6McS4BYyL3gGXaGbRjNap1HnE95m+N097LPTJdn2gljXWyQ2VOQmQ8RCUHPAtI
         i9N4wMxBNh0ORKuCiJ7HP5Ef6dFWbq431+cqct+NjRkzbg6yC9rN5czSxv5fVbaBWRZF
         RVGW3Qk6eiv5L+iFD60DH6nhG/Ftl58yWDUso0jn41vef9nrP96IXZPeJvl/i9AiUWP9
         ThdgoZnAJUsP7v+O3AiNd7n/ZrN2h+Mq61ACEOE9NWHmSaVAp1jAKErE7eRyZjV5QxyE
         3K4P08jTznTT0H7d6ptgUy2x60WHbOI0TapMWl1x/YC0G1pKXMqiyzM2FB4Xr7Uw1h5V
         MsVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=IS6zXJpfse7aKyGnk4bxNMpJkfJNclzewIdqj0UZAhI=;
        fh=6EgcrOLxq0yENuxZ13Yv9JYdIGKG+RKuQ2p6WUyTLtA=;
        b=hpnIWc2f1bcZoxyc/GVRggphZOP3ExF2unRrkyndfELPL9TuSxpE+u02A5/iKMHFXz
         VHFkbLVKeho3k66WXDleWm3wNeR/hSfqR2uEHRONcL4VkmfLhfWy4iU2JdmLOBFwFLhN
         ZVhUdA2cRdRd8vn+aIVfj4yN9DZg89j/IYQlbp+T8QTofHzxNGBsY/y24t8rbocKByTq
         dBo/7OIy9w6dfEDipgwNdnHd5sx+O3WioJIgw5grXG/5YY8RxhARYmC0TFN0O3NUpgWr
         ArKZv+BymxqzRNVX1abckRerewK6YKVuGFJ29QTH0Dmp42WMwvyNLuEnGhJ2xf99PXje
         ddAQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=U3cB7Y7s;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744859423; x=1745464223; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IS6zXJpfse7aKyGnk4bxNMpJkfJNclzewIdqj0UZAhI=;
        b=OlfJ0TgmtsPv/gnt6iElSycAVbjbGUMIvAimagBACs0U8ISAJa3nHdIey9lAzO2iSN
         CD0oTJ/SVxgtnukYX3Pk8o2LgtfxthqWcg+hE1TEHsER72JSYFoZltYZOEGTPMBKf68e
         hog2nSUXNWpQsz7ZSbUKbQJrYzU+pWkCXPfhG9GaFPmrHhwS4oiD9wYDM8PZDL7VH9G9
         Is7o75XZwxMi8RNDtuJihuw6Kv5VTTeMujPaj/4NRFrAyuJlWy8Fg8nkKbpf89cfuc3a
         DuUQnFsQXEiMDTc+TLtvMsuGCPbFJLcR3OTYnX5j8dQRsyxGdsPSdfiUEGzh0vkK12V7
         cLXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744859423; x=1745464223;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IS6zXJpfse7aKyGnk4bxNMpJkfJNclzewIdqj0UZAhI=;
        b=nRnDRsJyTAu5TutgLOe1RqFuWFAvbrUDnEUyqd5ggqhBBzHXMVw3vsUq59H2iXpm1g
         hppQ14PrR22mGksrmYhDkdOuRq5c/GiTo8iQyhmVbDr8iK1iwRSx/49HV+Pa2rUnfHks
         er06NZ3hyfl/aJlixfdTQsprw8NKTMqiAQyfOCFML9j4OLHOarkwtbJwyWQGwTwjG3zB
         TpWTbwoa2JqjLKTKAL57qzn6xxsqQklceDUCMx4xHRlwAU50O41QgIk2VzbxxgCloAkX
         6GFSxaZtUJa+ACFJctfoRyf0uGmII3K0VrJ06475Qi0nUiHHIH48GJopA4iKl2iBEsUo
         EHZA==
X-Forwarded-Encrypted: i=2; AJvYcCWoYDRFkOGj6sjUigOIH7uOVGB/u6OILvufpqoAlRVOMAa8GVhOoyegdMbfZ54WmTi3sbF+NA==@lfdr.de
X-Gm-Message-State: AOJu0YyjQQ+QFXOyvewDjHziUE+wH/RaTqK3hs1F1+HdMPuKDERC90b5
	YZKMhwWTFGL83rz1hOs7fHyRnHkw9xGmJk9fhUePyCy3IKTG7MuD
X-Google-Smtp-Source: AGHT+IEogJbVZZzXOWr9qQUELFNIqhVNxba/TBgL3To1dkNQ62VlXkOVTeHOVfB5Qw3aDUE8p79yRQ==
X-Received: by 2002:a05:6e02:b25:b0:3d3:d823:5402 with SMTP id e9e14a558f8ab-3d815b10dbemr43991265ab.7.1744859422878;
        Wed, 16 Apr 2025 20:10:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKD5rUYKQsA8+ufC0iYmvBDLVW507QNroTEeESV0CKIWg==
Received: by 2002:a05:6e02:601:b0:3d1:3d13:5489 with SMTP id
 e9e14a558f8ab-3d81a763f83ls5932405ab.0.-pod-prod-02-us; Wed, 16 Apr 2025
 20:10:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXYg9YKLNBaLGh22dZmxaHdOGJRjAGlPxzn7/tTaXGGzyRPYAkjs+6ipeqFdy+OGXoMW7dN6/flMxQ=@googlegroups.com
X-Received: by 2002:a05:6602:6a87:b0:85c:5521:cbfe with SMTP id ca18e2360f4ac-861c510e090mr446123739f.8.1744859421952;
        Wed, 16 Apr 2025 20:10:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744859421; cv=none;
        d=google.com; s=arc-20240605;
        b=Bf4XhBKL3HUs7m+Qju9xGmvpfiGC+0Trjjq6IoLbpiNLsn0OUzdAElCpOgEl+rYl9f
         w5JxcnMJp0Kudy7+sQycn+E9mwGu0/eOJLghZGq1QrDpd0iYYUFGZQdP90kV3RGd7z3g
         iHrNrDvJq2Vl3oDeQfADK2NMsBkjXFiYpp9spvlL7GfLTpZ2GdQkpGLi52a0gw7YEqDl
         txUd7Ky56BeMN9je0hSe9PChDGhQofeUctjJl0Mjc+xdW05MdDzuRnI2WTnQu0+jJzOq
         oKwR+8OL0FDHT/1LpzEs0/6hKHTAHvSsi8QfJuo+YIhbrIDHALTbMmha17mZvlIY9NSs
         c7KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=AkgcOD0s8sY0OqEBhP6EzDl8Yl3YNlrB/xY8BfBUKys=;
        fh=iOI63sgS6JrRbazd14yRzX76fPWvg+qvJlKR2UVjyaY=;
        b=lXKu7yGbtobKp4NKAh9ysBPnwFdPNKdrm0lLKrkZ2wkysKO4H8cjIUHbiR9Efw1ErI
         bzjqJNyM8NjRnSjeIoTBQuQDvY7GygmuHH5NxIql6nJH+LEhwrOjNYAh0bcQsLuaUmZJ
         wcTsy9UZi2x5oV5R0aPunYrmwRL92QPqGXohU15h91HPrVXCYkGdUBIyjlH7bJp3oaKg
         3Wzf2gbkaavdz0zJDpF9E21+zRwy9lBFLSXhPC5QuzRAJ9DGJjxrHsIqdI/bssgyXWMl
         9xG1KBd/aR0AolPcF/Ex6AeEVpbt8A3twVls3tCVd7ngWUgPZxlaezJJmZE3fSUZHvAs
         CovA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=U3cB7Y7s;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f505da16f7si731123173.3.2025.04.16.20.10.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 20:10:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-736b98acaadso246742b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 20:10:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWxg2+aJnEHckBoNb4oHJGuzTNCL0rOpt99jE3yFl/HHJRXpe3tAh/nPmIJUMl7DH0Wj0Q9BeRHBlc=@googlegroups.com
X-Gm-Gg: ASbGncssukCBbLIbLCjF+7u9dItVyJczwbomTJXigg1pV6G826V924kg41xqY3GFmow
	UiiUUIR2sBUZb4xwando791z4i8vaJw5URoHxOFWPB7ewziO8Fm0UP3e/kHRajpdkKptq2fRME5
	N0uvLLHey6BERyD/YkdJcAX5PSdDmUs/Ncu/1s57moU3UIA7c4acnSbVA+DXUqqtgnyhGVxEoTb
	ST+/HDQyLbetHKpV1QS2NmFbAT/wF7UoTmINKIpV0ipoecoXjYRwOeSJI0j8Xk5L2/ClpFEFT8x
	hCSs6rUGMmhfVvse1Tbxowto2rrKEqDD6lypY+JyOnhzqDQIxkRdOt/8ofJ/n3q1HZeRBXcROXK
	3Q3GY+hI5ObyklQ==
X-Received: by 2002:a05:6a00:240c:b0:736:a8db:93bb with SMTP id d2e1a72fcca58-73c266b9927mr5874992b3a.5.1744859421318;
        Wed, 16 Apr 2025 20:10:21 -0700 (PDT)
Received: from ?IPV6:2600:1700:e321:62f0:da43:aeff:fecc:bfd5? ([2600:1700:e321:62f0:da43:aeff:fecc:bfd5])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-73bd230e8b1sm11580740b3a.148.2025.04.16.20.10.19
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 20:10:20 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Message-ID: <b35dc3bb-71ca-4f5e-af29-8e1605ec5bde@roeck-us.net>
Date: Wed, 16 Apr 2025 20:10:19 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] x86/Kconfig: Fix allyesconfig
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, Linus Torvalds <torvalds@linux-foundation.org>
References: <20250416230559.2017012-1-linux@roeck-us.net>
 <20250416170359.a0267b77d3db85ff6d5f8ac0@linux-foundation.org>
 <4d9cb937-2a8a-4b3c-af32-f8fae922aa5c@roeck-us.net>
 <20250416182828.9e2b312a75ed90b706483250@linux-foundation.org>
Content-Language: en-US
From: Guenter Roeck <linux@roeck-us.net>
Autocrypt: addr=linux@roeck-us.net; keydata=
 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
 mDW4+i+XlNFUPUYMrIKi9joBhu18ssf5i5Q=
In-Reply-To: <20250416182828.9e2b312a75ed90b706483250@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=U3cB7Y7s;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::42b as
 permitted sender) smtp.mailfrom=groeck7@gmail.com;       dara=pass header.i=@googlegroups.com
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

On 4/16/25 18:28, Andrew Morton wrote:
> On Wed, 16 Apr 2025 17:17:00 -0700 Guenter Roeck <linux@roeck-us.net> wrote:
> 
>> On 4/16/25 17:03, Andrew Morton wrote:
>>> On Wed, 16 Apr 2025 16:05:59 -0700 Guenter Roeck <linux@roeck-us.net> wrote:
>>>
>>>> 64-bit allyesconfig builds fail with
>>>>
>>>> x86_64-linux-ld: kernel image bigger than KERNEL_IMAGE_SIZE
>>>>
>>>> Bisect points to commit 6f110a5e4f99 ("Disable SLUB_TINY for build
>>>> testing") as the responsible commit. Reverting that patch does indeed
>>>> fix the problem. Further analysis shows that disabling SLUB_TINY enables
>>>> KASAN, and that KASAN is responsible for the image size increase.
>>>>
>>>> Solve the build problem by disabling KASAN for test builds.
>>>>
>>>
>>> Excluding KASAN from COMPILE_TEST builds is regrettable.
>>>
>>> Can we address this some other way?  One way might be to alter or
>>> disable the KERNEL_IMAGE_SIZE check if COMPILE_TEST?  That will be sad
>>> for anyone who tries to boot a COMPILE_TEST kernel, but who the heck
>>> does that?
>>
>> I tried increasing the limit. It didn't work. With the RFC I sent earlier
>> I made it dependent on allmodconfig, but Linus said I should just disable
>> it for test builds (which was the cases anyway until commit 6f110a5e4f99).
>>
>> Personally I don't have a preference either way. I can also do nothing and
>> stop testing allyesconfig. That would help reducing the load on my testbed,
>> so I would be all for it.
> 
> How about this?
> 
> 
> 
> --- a/arch/x86/kernel/vmlinux.lds.S~a
> +++ a/arch/x86/kernel/vmlinux.lds.S
> @@ -466,10 +466,19 @@ SECTIONS
>   }
>   
>   /*
> - * The ASSERT() sink to . is intentional, for binutils 2.14 compatibility:
> + * COMPILE_TEST kernels can be large - CONFIG_KASAN, for example, can cause
> + * this.  Let's assume that nobody will be running a COMPILE_TEST kernel and
> + * let's assert that fuller build coverage is more valuable than being able to
> + * run a COMPILE_TEST kernel.
> + */
> +#ifndef CONFIG_COMPILE_TEST
> +/*
> +/*
> + * The ASSERT() sync to . is intentional, for binutils 2.14 compatibility:
>    */
>   . = ASSERT((_end - LOAD_OFFSET <= KERNEL_IMAGE_SIZE),
>   	   "kernel image bigger than KERNEL_IMAGE_SIZE");
> +#endif
>   

Yes, that is what I ended up doing with v3 (thanks for the idea), lacking the comment.
Guess I'll need to send v4, but I'll wait a bit to see if there is feedback from others.

>   /* needed for Clang - see arch/x86/entry/entry.S */
>   PROVIDE(__ref_stack_chk_guard = __stack_chk_guard);
> _
> 
> 
> (contains gratuitous s/sink/sync/)
> 
> 
> I'd like to add
> 
> #else
> 	WARN((_end - LOAD_OFFSET <= KERNEL_IMAGE_SIZE),
>   	   "kernel image bigger than KERNEL_IMAGE_SIZE - kernel probably will not work");
> #endif	/* CONFIG_COMPILE_TEST */
> 
> but I lack the patience to figure out how to do that.

WARN is a define which declares C code. That doesn't work in linker scripts.
I only got #ifdef to work. I did not find a linker script command which would
be equivalent to WARN(). Maybe someone else knows if it is possible and how
to do it.

Guenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b35dc3bb-71ca-4f5e-af29-8e1605ec5bde%40roeck-us.net.
