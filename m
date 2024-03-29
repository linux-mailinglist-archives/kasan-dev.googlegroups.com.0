Return-Path: <kasan-dev+bncBC7M5BFO7YCRBPW2TOYAMGQEM5U6EHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 642948921A8
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Mar 2024 17:33:04 +0100 (CET)
Received: by mail-oi1-x23b.google.com with SMTP id 5614622812f47-3c3ae7cadb7sf2204468b6e.2
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Mar 2024 09:33:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711729983; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y6KrRyDzBI/fNJLM+XZPRFfSNHygO0EBbbIQsvzp0bevSfbD8NqvRKtq566CBEIx5Z
         VRlp8Jb+Q+6g5fycN6AWsgbL2dlKpzbzl5j59oJS6NdbZkKZaRFcVX+7hO3xIOWWaRo3
         bnH94uyh+B+t/zqZvuJ6JCST5B4d0Ip35e2jqf6vPXhtawZ9JbMbuKF97VDmV29B0Zlc
         C1IuVhC8RtgmQXjDkyrwnyXcvfIxui0xFpw5w1QlDksClhqPBRcpu+riJlEqdLN2qY1B
         qHhM/a1ElJ4WH3bOFJGg7bjwMDebvMyr+w8Dntf/i+Z3XiqtlQrIJgqKfsVupg5cuXD/
         lO6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=/+Tn4VFbFSKvWjJC0Dng792UjKDtsXji0W4ZLYUQ3vU=;
        fh=fYHiurJz2p5TcqNZtdDylJZAVKAzIoLzbaBHztAbn3g=;
        b=IuDAtdxr/7CSyhf5ADl/2XcfTKhsK7teDPLFa2rvcrkzFTdkUZGSIPOF6Yc2bQShqs
         OqkIMcewhNNjB5eDFvvvhGckepC0q0RaoaHtPC1ufIWP2HfEPKY1gK+bsdxIbaNmOugz
         PU6Wpa6XDpXiKnFfmGD0pwBRG7DmO9QFvyCF92JaZWiVRyk2QMn5lPCxN6vst7HOX1Kk
         1EJlMld+5qEssG7h0oszaT4jOO2CtgF0YidNwJCuD4MZoUdyz2b35ENxbbUmey8PCMlf
         f4eGIW1RehERVNoDkjOgs3RTLldx6SnjyAfMY98IDiBKVfAGqtkhuEKfFoyvibJ75G3L
         fCAQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Y7uqpYig;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=groeck7@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1711729983; x=1712334783; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/+Tn4VFbFSKvWjJC0Dng792UjKDtsXji0W4ZLYUQ3vU=;
        b=TFapyyrskwAkA+lNqhVGfhATcKXWVEz3jXXPb00ZzWXkTDdFKiBLdlNVBcN1wcw+tT
         bXuaASn0LWSYBvn570z82N+vbOWnm/ImoKzOTIQ//hUWd8NIzKJYm+0JkN7KViM5Numb
         OdY1eZcwVwULRzA6tV4NqVQXRQcrswnPg49hWpRk58SCl8TQhv72qkmuqwRtsykPxa7t
         g+/Ck7SCkkceDtvKk3nF2yK5eoUXPjafMMlRden4LSIn4qJf+cvGFMjKOSKUQ4zYDCXX
         Vg/0Ez27t5OGpPgiVqcHxyv8nBaHJTJR9EAfVOtPcHK5DHK2D/7PP1mDCJm6goErdIe8
         Hw1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711729983; x=1712334783;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/+Tn4VFbFSKvWjJC0Dng792UjKDtsXji0W4ZLYUQ3vU=;
        b=BKRbZM8ezSR964XrY5mdXFNwoyLnVIDJ/GIOzkVViE6AuJujo6uPAKbdvOpnB8LVi5
         UheNCU7oSiPxMqanCYjZ+Az9y0fSlmVmmG8G/JSM17xwoCcecM/CDYo7hYlKtglkvNPo
         Z/X38W6XSnq1cslxXAWI6xPOdL6RT3cbo8hy1PqsaOfR98O2EMXQpuz1FLwdEvDf9TZm
         oDfzx3RRyVd91u0DbN10JeArDrAFkMDrOB1x8QqR6Pl9sk5fNli+/eeLHrhKChIiyPPB
         y3fKuZ75xszT6NvQLUSPq9YqpXeGrOintJNETyrYWmAFT7Ne0H7frDkW6JTzGjCe65Qf
         HokA==
X-Forwarded-Encrypted: i=2; AJvYcCXA9mX+T06kQmSXLK9/lo/d5ocJQUt7pcIA/ba/X8yp7/zxIibnjiXJkl0U87fqjGP27diQYsx4Vvo8x9aVszIGadPkTWUtNg==
X-Gm-Message-State: AOJu0YzcEpE5Al/3fHpCFehLhhoLQPuac5LmBu3kA2X15Yn6oqTgBcmG
	lmBMGlb8AfNhNopfT3T/pGCkrPoneMWAZUcNe/PmKVrFwU/OuFR8
X-Google-Smtp-Source: AGHT+IFR5Ca+QZnYsfkuAE5NyOSIpCjW0teEKvkjrPXyL9ThdCt2exznXM4ehMDUCIWaGQsvLSz4IA==
X-Received: by 2002:a05:6808:1929:b0:3c3:d2df:6433 with SMTP id bf41-20020a056808192900b003c3d2df6433mr3274453oib.49.1711729982822;
        Fri, 29 Mar 2024 09:33:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2402:b0:690:af1c:7f0f with SMTP id
 fv2-20020a056214240200b00690af1c7f0fls2615933qvb.1.-pod-prod-08-us; Fri, 29
 Mar 2024 09:33:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXQDih4dG79rxGvSmxuB9Tqk0OjvLAHR1dNTeIv3oO96tJ3B9MzMO2D3Ce4tlY7pMcf43AQknyvt/oSPfmPfylvTpI6SaQYtO+cfA==
X-Received: by 2002:a05:6122:2659:b0:4d4:2398:51a2 with SMTP id dr25-20020a056122265900b004d4239851a2mr2066318vkb.8.1711729981608;
        Fri, 29 Mar 2024 09:33:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711729981; cv=none;
        d=google.com; s=arc-20160816;
        b=JG4VhaLYzoDHXQKgJVJbdoINzIj6I5T0VPTc7P+r/Q1v9ZiV00Vsfk1xdZ74TAGExe
         3YZiKZAeMDo8DLzepO0gOjtgdvdOROGgH4CPTH+CwOJQ1+TAkjznF7PeAKD3BWt05pmY
         MtlOCAAE++qDFzOZc6uJin6HqkxqE5BZkJM4uV08lsgDMyzYNrn+jKlgp5X4ctW5EFq8
         5lXXMFqzH4CivnQruhgBnnF8k6cQwkso4k8ZYelW+9ZeSBaJo+WSZmeBQu+Vh7nh0EwL
         iH4dmKeGmVG20wsjwS9rcGIbevNuIU1/wtvycA4QnEtPgWzqVNeW0imugrbhG5nTU3/j
         M4xQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=oVniadOtylzye8e5zu9LavRkpC4RAr2fHGysUpfczOo=;
        fh=vfLEF7nZQ6RRojylgDFItlmMCy3aEhDN+eKGkAn/k3c=;
        b=uErKwAsSJf4I5tGXe8I5kMz6+035SKPQnj4FG6BXucp2KL9YmKQU3sfD1U0RwyVosK
         5EnZEj+H5qkPtQe0FWDsdLILwkAEanYdePpwkhinIBT9oZvBrISUjcyBziJPgCzuhA4i
         JGphfn9Ij3tZdLRZvFcrCZlIWn9y2zntc9RtSYulx0iYTL1geDW36WXv5MQQnWMptvTt
         b20ZqUgAmdia4GeQyLDnrJffmQBTb2g0uc6We/xcMPdDPecQArdwvz37622v7gdJquae
         DJf/WSDC5HKiiWq3kKkeMqbZCgpx84xPGZVm7/p5sMHBGcbmzo96nNp+fuOv+IDVAKWy
         ASug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Y7uqpYig;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=groeck7@gmail.com
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id cd35-20020a05612230a300b004d41fe2c37csi168958vkb.5.2024.03.29.09.33.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Mar 2024 09:33:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id 41be03b00d2f7-5d4d15ec7c5so1555320a12.1
        for <kasan-dev@googlegroups.com>; Fri, 29 Mar 2024 09:33:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU/Of5LLxbe6kiNDsU3a1M7DzoV7UDoOP6Hj/+JzFIjnV4lcFXuz7fjOMp0JulOzuSQ4Khx6klcKffPCZr87v46PL6pnoHJm9jchA==
X-Received: by 2002:a17:90a:7f84:b0:2a2:d48:9d50 with SMTP id m4-20020a17090a7f8400b002a20d489d50mr2676972pjl.44.1711729981121;
        Fri, 29 Mar 2024 09:33:01 -0700 (PDT)
Received: from ?IPV6:2600:1700:e321:62f0:329c:23ff:fee3:9d7c? ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id ft4-20020a17090b0f8400b0029de1e54bcesm5386072pjb.18.2024.03.29.09.32.59
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Mar 2024 09:33:00 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Message-ID: <0e754d23-b2b0-4469-8deb-2e42796b30b0@roeck-us.net>
Date: Fri, 29 Mar 2024 09:32:58 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: Kernel BUG with loongarch and CONFIG_KFENCE and CONFIG_DEBUG_SG
Content-Language: en-US
To: Huacai Chen <chenhuacai@kernel.org>
Cc: Xi Ruoyao <xry111@xry111.site>, loongarch@lists.linux.dev,
 WANG Xuerui <kernel@xen0n.name>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com
References: <c352829b-ed75-4ffd-af6e-0ea754e1bf3d@roeck-us.net>
 <4d2373e3f0694fd02137a72181d054ee2ebcca45.camel@xry111.site>
 <19c0ec82-59ce-4f46-9a38-cdca059e8867@roeck-us.net>
 <CAAhV-H7Po9B5WQMAUfB9jUmGAVit0+NiDbhV4jG5xKJUbWEBOw@mail.gmail.com>
From: Guenter Roeck <linux@roeck-us.net>
Autocrypt: addr=linux@roeck-us.net; keydata=
 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
 mDW4+i+XlNFUPUYMrIKi9joBhu18ssf5i5Q=
In-Reply-To: <CAAhV-H7Po9B5WQMAUfB9jUmGAVit0+NiDbhV4jG5xKJUbWEBOw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Y7uqpYig;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::52f as
 permitted sender) smtp.mailfrom=groeck7@gmail.com
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

On 3/28/24 19:17, Huacai Chen wrote:
> Hi, Guenter,
> 
> Thank you for your report, we find there are several kfence-related
> problems, and we have solved part of them.
> Link: https://github.com/chenhuacai/linux/commits/loongarch-next
> 

Thanks a lot for the update.

A note regarding the patches in that tree, not related to the kfence
problem: I don't immediately see why the hwmon driver should reside
outside drivers/hwmon/, and hwmon_device_register_with_groups() is
deprecated and should not be used in new drivers.
On top of that, shutting off the system in case of thermal issues
is not the responsibility of a hardware monitoring driver.
That functionality should be handled by the thermal subsystem.

Thanks,
Guenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0e754d23-b2b0-4469-8deb-2e42796b30b0%40roeck-us.net.
