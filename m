Return-Path: <kasan-dev+bncBD7I3CGX5IPRBSEUYWTAMGQETPE4R2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 06552772FDB
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 21:47:22 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-3fe1dadb5d2sf26030745e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 12:47:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691437641; cv=pass;
        d=google.com; s=arc-20160816;
        b=n3g4gGTlv2eUlsGhdxRp3k+FYIP9NBRgH5i9NyaWWtRq8qBOBbBygHFzcPCAQfjDIu
         Sdk7+9WD/rNGgRvX2TDSos8dTwdlwc1X8zhKRaXXd9Y09X7XGy2uoVDkC9Ydq28P8HlB
         l+iK27lKlViT/f1NbrT5LtCLQ/S0d4FxYGx1ys5Ac9HsxQP5QuF5XSzaNpVa4OxSXTro
         gt5tZ2p1DIPJwUwDFW8Lp1I4vJh4KjQmfn97ANSmF0g7iz1HTJ4jUNtIpvRfV1jnjGHj
         Vs8ebJ1+MOb6aKKSCir10FVTTbwZhg28ycVPc8aiz97e58io5mYGlDWsbPEtHDGq9+Ks
         ok+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=NIJGrwza8SHOXeCnDepv0F7GP6uTC0KSRX9edIOEy/0=;
        fh=H916aE72tP0nYeT3Gwk1EsUKVvRhoNsiKya+K8CDpwM=;
        b=QRPjNXtjADSbk16gHP6onvwdqRVe8oI5IbsmjwkSZyzGvlbl9DsCuxC4eEb8ThkW10
         Q1uQppjenUkG0G00uJ8YARGUfH/DiyCcEtEmuV2Ci2zCilQ7uHiOepWgcQ2R285Zxm8q
         /+Brd86Y05mIRy97iAOpOQOsFLZAaCksUsoDTEa64SqVcCCATOTo0Wrxp/1BkqP9awIC
         8M8xafrsdr//f+g6vSDyn1s98/Y55WOPYl/7y0VBVXcHKYUXFWucDo9aU7KFg5Idqlsv
         a01+P8E7zyj1qwFq2GjAKAHyfmvtoJ19AapkQ2NrPJ8xtReuoeT5O725w8dAA2x7hsdu
         w6Cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b=ACLAwZ5Q;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691437641; x=1692042441;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NIJGrwza8SHOXeCnDepv0F7GP6uTC0KSRX9edIOEy/0=;
        b=WU+tRtQUkt3xO/yT6mX2riY0LeiGWMqAT0Q9pLlE9QmFDcU9AVIlmkPBW/iZV8DrUp
         gtkAxLZLEMso0WLQ1VBRVV0NEXKnz2fI4x+pEBLMLGChexPI7Rc+b4VJ+oIHRnEHWvyH
         N2+LUGz//IHgAdHPX+7NSmeEcnLBU2O5Ir5n2ysHB4E+khNJehVwZgazssJm3JPV/QUi
         SNyHVzUcYKl9s7atYJgq5/GlsEPDrqjhnKicdkmOrD/9CEk1/Yj8mXE0oYKOamAqAZ72
         anMk97ndh3QC0qJi/s4jG4HIlKZMxcOROL7dH0AK/R0TvYEjdsIvXhBoGC3FkQo4c7gA
         YFQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691437641; x=1692042441;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NIJGrwza8SHOXeCnDepv0F7GP6uTC0KSRX9edIOEy/0=;
        b=BD2OYTr4N2jI92zoICI4AjngrVP+IjTCgN0/QlcCswDKW1nyKBbgFav3CdaZMdhYol
         nSrHl6drrF4vwqspszV8Iuq2gjyH7yX2xaaRSDg9iJFyVznOCUdyr8oqY+9KjKf8NfQL
         sUB/H7/zQETjkztLywZF0BFXRiJZ+sxyLbHHkgZr+06vvNqk400XnNjTKd7aIWTAYPmS
         V+rcVosCWRNAZRGANzCfAQKZLQ+OVTt5PIq490PuUbY2wg7yaO4UjngDA35ZNyAGkIvw
         uBw/fCovWCKU+UJqO6+cxrZ4r36PONjZtv7kCfv5C8+xb4Ly4pXtc9c/yXCT2qyF/rOY
         uBgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzAuL3mMS4D087P4iYkqq0XCfJ3UeOkoWzxiFbo/bGJEzYf/rQY
	hSOp72CAsW6v4sb8V+vLzRE=
X-Google-Smtp-Source: AGHT+IHRbowQ63Y0b6O9DEhb7tBdl4LZDo43CbeFm27IF4hF/L4SkcKpxVmIUIP5oB7ebJz7LywpzA==
X-Received: by 2002:a7b:cd14:0:b0:3fe:1679:ba7b with SMTP id f20-20020a7bcd14000000b003fe1679ba7bmr6685393wmj.24.1691437640638;
        Mon, 07 Aug 2023 12:47:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:a4d:b0:3fe:3b28:d0ad with SMTP id
 c13-20020a05600c0a4d00b003fe3b28d0adls1184487wmq.1.-pod-prod-01-eu; Mon, 07
 Aug 2023 12:47:19 -0700 (PDT)
X-Received: by 2002:a1c:7709:0:b0:3fe:1b9e:e790 with SMTP id t9-20020a1c7709000000b003fe1b9ee790mr6978208wmi.2.1691437638977;
        Mon, 07 Aug 2023 12:47:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691437638; cv=none;
        d=google.com; s=arc-20160816;
        b=0pSicYRNWfy9PE09OFwea8DClIk6o7jvEGJImhLcOmRegTDMm7pywCziYhbDc5p+d5
         KEn5lpaf8ayvtX2L2WTK35YVL11p7elVA9OE6erDefq87mCcfQDrz0yrcKsE+WnwzIYH
         L6377Kl6hdwSvcUSCZfeLKj5mTZ51PEklUYh/sIFZ5/jdBdC0C1QsoGo5tTfF0v0NfrU
         uRipY9UNt615YujwyXWSwowOknMc66nIfSzFc0MG31gM+X04hwsLYxNAUjxXMPd778QP
         kPfphlwOoZIFlWYmjIdHFX5i4BvvMiLSl449HYdMeYllLsp7bAA3vAmJy42X41UPMz88
         4S1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=9w+dD7oBoo3Er0Bu1CBuXGCJGgEYD7GFzLamH3ZCcr8=;
        fh=H916aE72tP0nYeT3Gwk1EsUKVvRhoNsiKya+K8CDpwM=;
        b=WdBAlD0GcFgDs3RqqF7wopYoaiBI/QvJLG/3z15FL97k/Vd4uHyLJkSILFXzeJMdNi
         WQYo+1aDY4WGKxtFS9uGQR+7vR9WkuYa4t4mK10QwpOob8HoZwuotWFlCv+zHa7aca6g
         F0wpcb+NmnyhRlg0/+cdc/IOMoFOU8aOJarzia77qG8Fxz8zDGR6AacAEYgOBx79WtA4
         DO5zWO7vWv9relEsNHdySbTQJSo7j7Pst/z3Z6ENAv/GtJEe2fn4Lazk2YoRh9wgRFgQ
         gNFnpLnXcbbyjFl6PJkrWVpbG8G4P6rizeLfbLdEXTQmr55pbfTera2TTD87GeYQb7E0
         pJRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b=ACLAwZ5Q;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
Received: from mail-ed1-x534.google.com (mail-ed1-x534.google.com. [2a00:1450:4864:20::534])
        by gmr-mx.google.com with ESMTPS id n16-20020a05600c501000b003fe16346f74si730279wmr.0.2023.08.07.12.47.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Aug 2023 12:47:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::534 as permitted sender) client-ip=2a00:1450:4864:20::534;
Received: by mail-ed1-x534.google.com with SMTP id 4fb4d7f45d1cf-52229f084beso7017660a12.2
        for <kasan-dev@googlegroups.com>; Mon, 07 Aug 2023 12:47:18 -0700 (PDT)
X-Received: by 2002:a17:906:1db:b0:993:f2c2:7512 with SMTP id 27-20020a17090601db00b00993f2c27512mr10894304ejj.33.1691437638444;
        Mon, 07 Aug 2023 12:47:18 -0700 (PDT)
Received: from [192.168.1.128] (77.33.185.10.dhcp.fibianet.dk. [77.33.185.10])
        by smtp.gmail.com with ESMTPSA id x13-20020a1709064bcd00b00992b3ea1ee4sm5701924ejv.149.2023.08.07.12.47.17
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Aug 2023 12:47:17 -0700 (PDT)
Message-ID: <5eca0ab5-84be-2d8f-e0b3-c9fdfa961826@rasmusvillemoes.dk>
Date: Mon, 7 Aug 2023 21:47:17 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.13.0
Subject: Re: [PATCH v2 1/3] lib/vsprintf: Sort headers alphabetically
Content-Language: en-US, da
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
 Petr Mladek <pmladek@suse.com>
Cc: Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 Steven Rostedt <rostedt@goodmis.org>,
 Sergey Senozhatsky <senozhatsky@chromium.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrew Morton <akpm@linux-foundation.org>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-2-andriy.shevchenko@linux.intel.com>
 <ZNEASXq6SNS5oIu1@alley> <ZNEGrl2lzbbuelV7@smile.fi.intel.com>
From: Rasmus Villemoes <linux@rasmusvillemoes.dk>
In-Reply-To: <ZNEGrl2lzbbuelV7@smile.fi.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linux@rasmusvillemoes.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rasmusvillemoes.dk header.s=google header.b=ACLAwZ5Q;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates
 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
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

On 07/08/2023 16.58, Andy Shevchenko wrote:
> On Mon, Aug 07, 2023 at 04:31:37PM +0200, Petr Mladek wrote:
>> On Sat 2023-08-05 20:50:25, Andy Shevchenko wrote:
>>> Sorting headers alphabetically helps locating duplicates, and
>>> make it easier to figure out where to insert new headers.
>>
>> I agree that includes become a mess after some time. But I am
>> not persuaded that sorting them alphabetically in random source
>> files help anything.
>>
>> Is this part of some grand plan for the entire kernel, please?
>> Is this outcome from some particular discussion?
>> Will this become a well know rule checked by checkpatch.pl?
>>
>> I am personally not going to reject patches because of wrongly
>> sorted headers unless there is some real plan behind it.
>>
>> I agree that it might look better. An inverse Christmas' tree
>> also looks better. But it does not mean that it makes the life
>> easier.
> 
> It does from my point of view as maintainability is increased.
> 
>> The important things are still hidden in the details
>> (every single line).
>>
>> From my POV, this patch would just create a mess in the git
>> history and complicate backporting.
>>
>> I am sorry but I will not accept this patch unless there
>> is a wide consensus that this makes sense.
> 
> Your choice, of course, But I see in practice dup headers being
> added, or some unrelated ones left untouched because header list
> mess, and in those cases sorting can help (a bit) in my opinion.

I agree with Andy on this one. There doesn't need to be some grand
master plan to apply this to the entire kernel, but doing it to
individual files bit by bit does increase the maintainability. And I
really don't buy the backporting argument. Sure, backporting some patch
across the release that does the sorting is harder - but then,
backporting the sorting patch itself is entirely trivial (maybe not the
textual part, but redoing the semantics of it is). _However_,
backporting a patch from release z to release y, both of which being
later than the release x that did the sorting, is going to be _easier_.
It also reduces merge conflicts - that's also why lots of Makefiles are
kept sorted.

It's of course entirely unrelated to moving the declarations of the
provided functions to a separate header file, but IMO both are worth doing.

Rasmus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5eca0ab5-84be-2d8f-e0b3-c9fdfa961826%40rasmusvillemoes.dk.
