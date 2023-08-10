Return-Path: <kasan-dev+bncBD7I3CGX5IPRBRGS2KTAMGQE5YPCGZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id B1C927773BC
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Aug 2023 11:09:26 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2b9aa4db031sf7993911fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Aug 2023 02:09:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691658566; cv=pass;
        d=google.com; s=arc-20160816;
        b=HULhtGUBXr1DiDKmaWn9WR91IcxK1B//IToNg5TYdCJ0MCkusEP6lXDwPnm/LfaCo9
         8eKDDfuKrBLigacvgh+WbrafNQLAEE11WBDpMWW7ZF/0TAqWLIoz4SFcSnc1Z++Abs+V
         GR5P1eqLQ8HkIYuBUyD+/jKs+/5Vekqa7DurpL+hNBH9nKOveZTYGCqtePA8bNTbLTsS
         fmD+D8NaC9csQb5q5qp+1bd7sh0pjVm8ivryR4Bhbf8WuyMnIQxKpR2z1MyTNAz7Fpdk
         4az+fwSSYzUUb8rapbLhxfRqV8nroKztuDjYHGnGe0DB8IEVjD4CdprGfCIAx5krWKVc
         h4lA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=E8gWo3T6JzQYkGjfpSsVtLz/JkuKpyan0fRvsMF4oTQ=;
        fh=6WNc4MQKJ2PVuR+1NcvDj2LMJXZ4guPhuNqgpbYrfHA=;
        b=ejIkLMyZ1TrrUgLbaW7M4yvZ62pe8aM2Ro3BpR9jPSfj4w97/x+2V6a1BsVxblGVMg
         FtY+4APJG6AQK0kjrIgdxoKCmvWUST9svIUTyborgDv605Ft/UMGcJu+JVrZxGdjv1fs
         CtuCC7wKY77Xz6WzaxS/mFS3T+hTLYpXmtKk+p+HlG+4GMuT+qtinzNmmzEthgebWRU0
         GlD5WLpj3VN/QkE6VMjm8TCF32CqO6ulPONVteWHrrcojJo65PGUJMejGiO2Az7BxmOV
         Dc2LloIShlinxWPaoWaQXewUA5Ysk3DgaqvsRms1bqMQ0Ss25d+XxxCep7ax+7iP5uw0
         4IBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b=HuwTeero;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691658566; x=1692263366;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=E8gWo3T6JzQYkGjfpSsVtLz/JkuKpyan0fRvsMF4oTQ=;
        b=e5uWBmFRI/51QwyVl3PiaFly7CTzvvDWyUmlMdXzvuqEJk8D015MhZQA5TAlVvYQwK
         awojAYJm2mxsFed8cv44K7+niRil8KYwqTT8ajErkF/McKG3ZBrJpbiWwxaj4gOOd4bF
         8JayGgOqRNinumVbAz1foNfofwMAzPSvz0EiTn9OwYAH3PozHYYivghqCNwZ+Fwpd+HD
         0AQTrBs2Iamqx06YZ1Mi8RO2XaUtkJNaIWRrr5gbQtwAS66g+5dlMxsxzIFWRlWB38Cv
         XdZ0AixUH0JmY5ZHfp3TvfxFCamHJcB52c0zvPcQPqSEvW7heDz8dIFSLXfL+jy4QoHd
         hnTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691658566; x=1692263366;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=E8gWo3T6JzQYkGjfpSsVtLz/JkuKpyan0fRvsMF4oTQ=;
        b=KCzFixwFyY1CZKwJ2pVH2DTQzOzNW59/wxIy+JrSvpZ8Aqm9JqkMuGOm5mV+KtvVh/
         GZBbmkQVun1vaihDdcljPadJuATTuUBjeyQ1xSGctUF8SZQp3QjZ7/YUuSBkSc+vRhA+
         HQ8oOL6L80WfNKnf9JG4AOpDBYUcSRqGa55pVPfMDDSAqUr0cY9WxxqqhCz+f3kNxgZY
         WxEUrioBlLMVwH+g8cQc1r4KfyVeXDEw0P4bIIpJVtrUYlPZ0F/wkwUa3IT6X0zpffB8
         E0bAa1aokhfnZQKvOx37wW+9APvK8HPyPfSwrc0gkqn7Nnaqs2/RyXZn+iYXqo/7MvJR
         TNCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwE/Dn7BQ4BXOvP38k0bIXB8dozRzDMSkQr8Rz4iPQ3yNT0t/b9
	ntB8Z99bfi2C16XweQUt880=
X-Google-Smtp-Source: AGHT+IG37X1Un3D3W5iPK8DT2R864xMA0mR3ix3+BcEWBfhmDHpZtw91Jct992C5G//XtpSmcrpbFQ==
X-Received: by 2002:a2e:7c0a:0:b0:2b9:ef0a:7d40 with SMTP id x10-20020a2e7c0a000000b002b9ef0a7d40mr1430030ljc.41.1691658565244;
        Thu, 10 Aug 2023 02:09:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d23:b0:3fe:240e:2547 with SMTP id
 l35-20020a05600c1d2300b003fe240e2547ls32493wms.0.-pod-prod-09-eu; Thu, 10 Aug
 2023 02:09:23 -0700 (PDT)
X-Received: by 2002:a05:6000:120e:b0:317:f18b:a950 with SMTP id e14-20020a056000120e00b00317f18ba950mr1664236wrx.26.1691658563474;
        Thu, 10 Aug 2023 02:09:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691658563; cv=none;
        d=google.com; s=arc-20160816;
        b=vQ6+G+eMpw2iHFJJkaTu0DIGWFPM5WiiGY6/BM6kuD7UdHDrGr8akXjuzkbuUZeMXR
         A5qWVbOLFja29spG0LySqUGl4HZYyFc9l15LDRQhh4qX4NmOVMGCdtLeEq2CJdteKtUN
         nHFAZeW6W4eprFORhHv3IRQTPxpqf9KAlZwt+0YJuqjscT8UU7H7uFRIxl7lcN7Q7tLq
         xleovVC789gCua9lZQKFLZ6NLu0M+wneAIAvC6DbTiDoi8f3iCH2mtZtF9sDJvNxiavq
         +9fhIav7LJD9kDYkLIz8cfVTGs47j7hSHnFiCSY0XVszuq7t/EqMfftk2f8i60grMY/G
         S6IA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=IAppfDze+b0mlNksRhfLMmF8syWDm1cJ2oYz5chDViw=;
        fh=6WNc4MQKJ2PVuR+1NcvDj2LMJXZ4guPhuNqgpbYrfHA=;
        b=JrdhGDuRL12aoDiEOPqxDZqbqh+LjqPl9PuWeOaw6lA5WH0VGs59NqVuknd6GgLtu4
         JlhDUZ/oVp/XpxfxnpdsvIHZI6RjAfSneM3FS0J1RBBV4DPzoP6rDpzF3oQrUZbWTWyd
         1XOT35vFQ0sCXiXDfX323P/odFa7xSHbcKEZi77tBSSSab0BFEPxbAIDU0NEc/uRVvmt
         fHHYjSstHQQILixuqPvIo+1ndVRBffgShoz6AUBiA+gEeeYrTIvRwyRLjOqRdv3y1d/i
         7GSwmfW0iIC1azRHnv18Gr13YZhN5MCZe3cron3TAfPryV5/FcdepRYrsGpOOEax2Xd7
         8d8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b=HuwTeero;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
Received: from mail-lf1-x12e.google.com (mail-lf1-x12e.google.com. [2a00:1450:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id k8-20020adfd228000000b0031596f8eeebsi68026wrh.7.2023.08.10.02.09.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Aug 2023 02:09:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::12e as permitted sender) client-ip=2a00:1450:4864:20::12e;
Received: by mail-lf1-x12e.google.com with SMTP id 2adb3069b0e04-4fe389d6f19so925901e87.3
        for <kasan-dev@googlegroups.com>; Thu, 10 Aug 2023 02:09:23 -0700 (PDT)
X-Received: by 2002:a05:6512:3194:b0:4fb:242:6dfa with SMTP id i20-20020a056512319400b004fb02426dfamr1689323lfe.57.1691658562818;
        Thu, 10 Aug 2023 02:09:22 -0700 (PDT)
Received: from [172.16.11.116] ([81.216.59.226])
        by smtp.gmail.com with ESMTPSA id r11-20020aa7c14b000000b0051e26c7a154sm530135edp.18.2023.08.10.02.09.21
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Aug 2023 02:09:22 -0700 (PDT)
Message-ID: <67ddbcec-b96f-582c-a38c-259234c3f301@rasmusvillemoes.dk>
Date: Thu, 10 Aug 2023 11:09:20 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.13.0
Subject: Re: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Content-Language: en-US, da
To: Petr Mladek <pmladek@suse.com>,
 Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 Steven Rostedt <rostedt@goodmis.org>,
 Sergey Senozhatsky <senozhatsky@chromium.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrew Morton <akpm@linux-foundation.org>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <ZNEHt564a8RCLWon@alley> <ZNEJQkDV81KHsJq/@smile.fi.intel.com>
 <ZNEJm3Mv0QqIv43y@smile.fi.intel.com> <ZNEKNWJGnksCNJnZ@smile.fi.intel.com>
 <ZNHjrW8y_FXfA7N_@alley> <ZNI5f+5Akd0nwssv@smile.fi.intel.com>
 <ZNScla_5FXc28k32@alley>
From: Rasmus Villemoes <linux@rasmusvillemoes.dk>
In-Reply-To: <ZNScla_5FXc28k32@alley>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linux@rasmusvillemoes.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rasmusvillemoes.dk header.s=google header.b=HuwTeero;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates
 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
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

On 10/08/2023 10.15, Petr Mladek wrote:

> Everyone agrees that kernel.h should be removed. But there are always
> more possibilities where to move the definitions. For this, the use
> in C files must be considered. Otherwise, it is just a try&hope approach.
> 
>> Also, please, go through all of them and tell, how many of them are using
>> stuff from kernel.h besides sprintf.h and ARRAY_SIZE() (which I plan
>> for a long time to split from kernel.h)?
> 
> I am all for removing vsprintf declarations from linux.h.
> 
> I provided the above numbers to support the idea of moving them
> into printk.h.
> 
> The numbers show that the vsprintf function famility is used
> quite frequently. IMHO, creating an extra tiny include file
> will create more harm then good. By the harm I mean:
> 
>     + churn when updating 1/6 of source files

Well, we probably shouldn't do 5000 single-line patches to add that
sprintf.h include, and another 10000 to add an array-macros.h include
(just as an example). Some tooling and reasonable batching would
probably be required. Churn it will be, but how many thousands of
patches were done to make i2c drivers' probe methods lose a parameter
(first converting them all to .probe_new, then another round to again
assign to .probe when that prototype was changed). That's just the cost
of any tree-wide change in a tree our size.

>     + prolonging the list of #include lines in .c file. It will
>       not help with maintainability which was one of the motivation
>       in this patchset.

We really have to stop pretending it's ok to rely on header a.h
automatically pulling in b.h, if a .c file actually uses something
declared in b.h. [Of course, the reality is more complicated; e.g. we
have many cases where one must include linux/foo.h, not asm/foo.h, but
the actual declarations are in the appropriate arch-specific file.
However, we should not rely on linux/bar.h pulling in linux/foo.h.]

>     + an extra work for people using vsprintf function family in
>       new .c files. People are used to get them for free,
>       together with printk().

This is flawed. Not every C source file does a printk, or uses anything
else from printk.h. E.g. a lot of drivers only do the dev_err() family,
some subsystems have their own wrappers, etc. So by moving the
declarations to printk.h you just replace the kernel.h with something
equally bad (essentially all existing headers are bad because they all
include each other recursively). Also, by not moving the declarations to
a separate header, you're ignoring the fact that your own numbers show
that 5/6 of the kernel's TUs would become _smaller_ by not having to
parse those declarations. And the 1/6 that do use sprintf() may become
smaller by thousands of lines once they can avoid kernel.h and all that
that includes recursively.

But those gains can never be achieved if we don't start somewhere, and
if every such baby step results in 20+ message threads.

Rasmus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/67ddbcec-b96f-582c-a38c-259234c3f301%40rasmusvillemoes.dk.
