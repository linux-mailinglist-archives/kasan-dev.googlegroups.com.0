Return-Path: <kasan-dev+bncBC7M5BFO7YCRBAERQHAAMGQEOFXD7HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B0A2A9100D
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 02:17:06 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-6021152ab3csf69403eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 17:17:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744849025; cv=pass;
        d=google.com; s=arc-20240605;
        b=aXELqP++HRLhE0dfv5vVnSrz9tQ/6ls84THZwGOmeanbkCxOyfWgAWqpL0XbBlh6IE
         nTEy8/m7szrcjg+ahCHNe+Pgd9/VNEjIbOreBcHqtxdPOqMMCVX//PBWDkeZEtpRs0Kq
         CNFc9snX877MyOHVVPPvw8/rzclpvpzOQbtlx0WuzbCD3dKWPL2oePdrAtW21+AFtJ+q
         RiGicjpq8hfpsHZZDp6tlQBTIQ9s2xMiQjTBRWR41H8gDtHLRvCUUFoM3bRIUjGXRiI3
         HZaiDwdWrRop5zvFko0ZiIi0fpjQRNCj2hKM+zwfr6gvhjHr8AtMMcaJksKcxk/KgRXS
         uYDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=sDQTj4YONhUhsiR4zIL7SCUSymb146YrtI2mW0BZITc=;
        fh=9Upz0N7YkL4e3o2wfLvNzMr8e5JEkAu3XZrf/p1FPUE=;
        b=TdAHA7MmAea3q2QLa3kGhZACYmEM58ET+Ee8m/u1DtMs1LHFEIt9LxiMKCqJdJdBtU
         0O7kj849NmhKyCo7xffePjX446FNzhk+QCOhSML2N8zCzi2nRXSyBQZWhj+d5LksEVGf
         sbtkf96r7T8OGV7j0JejmDA2+Bg0+XHeTt943siC+DOGruyKOkfIrQQCpYMH70jlNRpi
         h3WY7775eL3aUa9ff4BpX8PtF6Ds8nrBbtkyCWWXJITMhL82uO2NRo7SxmnrnRKuuyEQ
         t3fKTSszSutkL10uSUH+Il3cL3eMZmiG3yIClNoeBrVzWIzF9glN70f3+xbh0eDuqKfU
         1QIA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ta7mEkpF;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744849025; x=1745453825; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sDQTj4YONhUhsiR4zIL7SCUSymb146YrtI2mW0BZITc=;
        b=gUALydbMdjZi3pjuERugcLHnNrNGIPEcBizeDF3huLXbEEJs65rWCbYotrfN731nPK
         mR/oBxZsEfbfp2eKjc7zEC2E7LoXG5LpckF6R7Xj/ZMihrSdy28svqj/ChsFZ8SX8XbJ
         6VhAzZsh92pLRbl/X40qtPJunvCvGhYN/L0owBZpNqKar5A0LNrVcMslXfLbjPbQ/G5u
         EwwWY474UsnS9UdqfpXFIuybrGXGdHinA39K6Gt08I7Shuxh8eF7k6u6OW2g7MkqT482
         0DrCGKyN0B+6IQtaFtHYORa7OxJV9HUm9AueXt29HhUoOKg2kWjG5Yz8jt1X1Vvhn0eX
         Gm3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744849025; x=1745453825;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=sDQTj4YONhUhsiR4zIL7SCUSymb146YrtI2mW0BZITc=;
        b=eJVwQyorsbwKVA/ig6cTc6kED5t1fEl3kQzaefDskJrRrlCfOpOpskSbVdXGBvCYU0
         c6pFQ+Z5VC7HRzFVZHAQZqrgCwKC1TPs54FZ6MomW6BHAd0F8UE3jXH7aUjqfP8f+Uuw
         CDFHxZ5AGHmLbz69oxR2EsaqygQeuwLmQmDwbCOSUBb3ZaHHscSREf37pIG5RYx9wfQQ
         WgrEz+QLauCXI+ARfW0/QnZbu05RlzoIYqjoAMQe7DWIiRHjM8VF3sPX44Zff5xlJecU
         xFgwmN9StXWtYNGm7fSKZpE9JMctvkSK7J785VnyCZ7+WljJwoiarX+zV6zGhlC/r9RX
         tgcA==
X-Forwarded-Encrypted: i=2; AJvYcCUpQTv2Qike3BZdozMoaKI8azN4lw9wRXvK3Zs4T+LkN5ljyB1poXSHeOB/pqfKMjBBhWzTeQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzqq/6jvT0K3u4BZXW16w2qomXXEHeQyjy3jmnJeYkB49iS0uUt
	V2cQ6y6jMFVck5g/MYJqWZY1WfQZ0Q4+Ma2TwAMlWomzNnJ10y+t
X-Google-Smtp-Source: AGHT+IEpQ5Eg3MzajJAgUyZkPBByyOHPnuGc34G3YRILbc3UYRVEw26mNaglEq89MdeeDI1g11ZIVQ==
X-Received: by 2002:a05:6820:54d:b0:603:f820:7be4 with SMTP id 006d021491bc7-604a930c68bmr2194646eaf.8.1744849024794;
        Wed, 16 Apr 2025 17:17:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIxwpIQN86L4jw5A4Y9FhkorkBLceZ0EONpTEhBQGaYug==
Received: by 2002:a4a:c71a:0:b0:602:84e3:e8d0 with SMTP id 006d021491bc7-604d079d021ls148802eaf.2.-pod-prod-08-us;
 Wed, 16 Apr 2025 17:17:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWOhlUHPx+k3yDrtNXs16nJHfksSzyjAVZKiaxIAD2yal+Z2ZSf9gxNvP7+c1KZvG2t8tLo4rY+mv0=@googlegroups.com
X-Received: by 2002:a05:6808:158c:b0:3fa:ba79:6e63 with SMTP id 5614622812f47-400b022f4a4mr2709809b6e.30.1744849023545;
        Wed, 16 Apr 2025 17:17:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744849023; cv=none;
        d=google.com; s=arc-20240605;
        b=lBuTWP414stMe3ByZUwun/7gzcfaEwIFaPQEgUSa4GSQle1G6n2vjV41L9nZ4YVi4J
         T2fwxly4mHj2IFSsT8+f9GizF++jOa5lsQX9eBKcTTNSx8RVhcTJYuqExeqwzgtZlgzB
         QkSwR6nhA00Ch2ctgHR8Zse2SsMhpks+t9YrzKz4jkOhSB8oQG+ELhszbGdf+15Iq4j9
         NANNTynyU9KPhC2CKcPLITi62RZIKNhke61oDGfNib9/ADw3XNGKOatux2+WmAkqOdjS
         ICULojnlrC7nSOZBy/9s0P72jBHDhi2/vng0DNYdlfwx3gsxpyCTG3o1wlPIl2i2TFrj
         Or9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=Ou/vN4o4n3TBeIVFHaSiKpFZDK8cAIRKfyt0XdDezGY=;
        fh=ckZCFMJI7plD9IGHldAOFMhsJK8ItPezMc49o7QMzF4=;
        b=gnFdYKGYom94ubizOwvNwic0GZTJCDN/LIEIpfd9KY27Bwmy6Mo+G8TUZmjGnARKEw
         CWT7y8SUmKl6nbeP83u7eCoRLkg3sLTbPtA8KdAIaOAWUzqFeKXwVAGt4zPdbq7V81/T
         7i36UK7RQi1kYymoEWC01BWSP8NSJLPi6fW2dPC95dy0I7aBBw2WXrfs/60agtu3uEgc
         nZ1aC/qhOpTZHlCf2apIt9jxfdk7WVDNOdovHl8hsECRxXiFTW1iOeXfrkLX3uF9ORhS
         /eERe+bKCI5+2np9UiX4V9z+JL9j/wYJU+FiAmYEBTS3VWJZYfIOnmM9QP35NsulB0zZ
         FViw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ta7mEkpF;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-4007635607esi305274b6e.3.2025.04.16.17.17.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 17:17:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id 98e67ed59e1d1-301cda78d48so168953a91.0
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 17:17:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXaV9kb+EE0C0ySGKs8Iy8K/Jr8+bnP10B1QPSJGcbIpWFKquVqC+USEo6KEUDOnmIa5vrwGLzxZ9Y=@googlegroups.com
X-Gm-Gg: ASbGncsmQ3kqvPMN/OxY5RkS8pY2zZ6bq8zxVh/OagfAkVqXzdcons5HbXfyBMZwX0n
	a0NAgjbvJywdq87pAIadBLAN15MFNvFXTetonhtqdyd3gZrlVw+e7zHiO+17ELNAW1kBYZJte89
	05juy9R6WBWAAGclKpG35UXpn7HPouqp2uaieLLCk1L3UQh60CGtwDT/lRmXW1oFBmwRmowAIgA
	WnBtug8UYyILMwJDZlRB2SbEb7GqrSYfrRkB41v0pzDB6VTR6CiKiL1/TOBFoN4nIOa3F0iEQKD
	lSg1LMALCOJ7GlSgII2lqx2eHlkPIQ2oORNBjecQeWSLrK8Q9D8t+gRzNt3rjzt6mhBn5XNPaHK
	Mvp+qHrgZfBMmpzEJQA7OIIv1
X-Received: by 2002:a17:90b:4d0f:b0:2fe:b8ba:62de with SMTP id 98e67ed59e1d1-3086416638dmr5022435a91.25.1744849022538;
        Wed, 16 Apr 2025 17:17:02 -0700 (PDT)
Received: from ?IPV6:2600:1700:e321:62f0:da43:aeff:fecc:bfd5? ([2600:1700:e321:62f0:da43:aeff:fecc:bfd5])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-308613b2f13sm2551008a91.36.2025.04.16.17.17.00
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 17:17:01 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Message-ID: <4d9cb937-2a8a-4b3c-af32-f8fae922aa5c@roeck-us.net>
Date: Wed, 16 Apr 2025 17:17:00 -0700
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
Content-Language: en-US
From: Guenter Roeck <linux@roeck-us.net>
Autocrypt: addr=linux@roeck-us.net; keydata=
 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
 mDW4+i+XlNFUPUYMrIKi9joBhu18ssf5i5Q=
In-Reply-To: <20250416170359.a0267b77d3db85ff6d5f8ac0@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Ta7mEkpF;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::102c
 as permitted sender) smtp.mailfrom=groeck7@gmail.com;       dara=pass header.i=@googlegroups.com
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

On 4/16/25 17:03, Andrew Morton wrote:
> On Wed, 16 Apr 2025 16:05:59 -0700 Guenter Roeck <linux@roeck-us.net> wrote:
> 
>> 64-bit allyesconfig builds fail with
>>
>> x86_64-linux-ld: kernel image bigger than KERNEL_IMAGE_SIZE
>>
>> Bisect points to commit 6f110a5e4f99 ("Disable SLUB_TINY for build
>> testing") as the responsible commit. Reverting that patch does indeed
>> fix the problem. Further analysis shows that disabling SLUB_TINY enables
>> KASAN, and that KASAN is responsible for the image size increase.
>>
>> Solve the build problem by disabling KASAN for test builds.
>>
> 
> Excluding KASAN from COMPILE_TEST builds is regrettable.
> 
> Can we address this some other way?  One way might be to alter or
> disable the KERNEL_IMAGE_SIZE check if COMPILE_TEST?  That will be sad
> for anyone who tries to boot a COMPILE_TEST kernel, but who the heck
> does that?

I tried increasing the limit. It didn't work. With the RFC I sent earlier
I made it dependent on allmodconfig, but Linus said I should just disable
it for test builds (which was the cases anyway until commit 6f110a5e4f99).

Personally I don't have a preference either way. I can also do nothing and
stop testing allyesconfig. That would help reducing the load on my testbed,
so I would be all for it.

Guenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4d9cb937-2a8a-4b3c-af32-f8fae922aa5c%40roeck-us.net.
