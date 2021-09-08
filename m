Return-Path: <kasan-dev+bncBC7M5BFO7YCRB3WQ4SEQMGQEJBSYWYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BF1B404078
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Sep 2021 23:17:35 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id i7-20020a9d6507000000b0051c10643794sf2192544otl.22
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Sep 2021 14:17:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631135854; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZRLBDRd44QCCRM6eAnV/7k88tTQ9UxSYjud51TFKpvlXgaIOhCxckTmMnceoLLRMiW
         Q6NmR6/v8YR7lH9FPKGk6rfoG9ivjrAJvBhYoIGmI5bHanyez9SsWQT9sdaZ56Kru/SN
         9NofgkqqWeZLZ4TOFbUOt1m31wfmBMupZhMZnOGPa8JK2oMj+mZt7nZR15P+hQjYErxN
         t4q+6rfwXztcUO0a8olZoaVtQ7THeH4NgAjJCZBOybFeRtaDloFG8Z0U7SkmQlruwe1A
         oSN9DUwZPTdwDzEY4HtfNn8DEgPqXElc046NiHCpjokhaT4MKAkAY2+mzzMCWoZcs+bE
         b+Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=mm5WcNkJB0QKOofiOZ0Y5jzGlmeFY+q95PvuxQIvPp4=;
        b=UFmiJvhvJQfUmM35lBKgwa9NTe6VWMh7syUTl8AhrObaB9ZrG2FfrBOXFONJjNWDzm
         PNqCDEUYn9LxnIINLFCVLp4KhcLMPnHZ4IB/J0tILstxfGffw+ss4vfthm/BOEnwQWqB
         rKY/mSTahlL9zrP3wRp0HUi67j9VrK+gN+c4CvMAg5t33cWuznCrIeVy9+XXgA4URdTY
         aLLpSfbfNeHz4RV0URLzF1bvJEYQR63H4cflL0j8hYxmHthCsYyLFcDCeaBvliixPfSK
         5OsbHzKskiOZyi3PQYOoaOsTDV3fv2TjkBv43DR5CCzW7ke4KCCM5X/if5LGnSRrzxwl
         RRyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=k5Abv4lP;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=groeck7@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mm5WcNkJB0QKOofiOZ0Y5jzGlmeFY+q95PvuxQIvPp4=;
        b=Uh2Ltvw19PgYGKVViwxZaFA2co67HGKPyIm4OkwjFVnxwoKPYFPrOAfx7zsZX2TAaq
         VV8VHwgmG+ZLWO7xOq8/LC2EiRYob3zAsnvBh6zM4tHgazaKAqhlEt/2+j0C4xUp+1jo
         KFv6vE+DEj+SJcIoSLeilxCrKdwwlZogs6e5pAnrScpGovVMVHz+VpJ5F+0HlmSQl0Ct
         uz30/n4XzL7cGOfU1SnLw/T44F7auICNFoak+2fNyQf7oCMNOwtrH5Q+3djKmFYDWKpp
         GaU20zUDHC3hiNQQdOfxd2mMXqi6ORFWxkqDx5XZj29hv1VLWaeqpfy6E8SV0qYGfuw3
         O3Rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:sender:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mm5WcNkJB0QKOofiOZ0Y5jzGlmeFY+q95PvuxQIvPp4=;
        b=qtBoPTD5WA4aSPswUHnmghhJGyyjWqwEghhAlcIGfWyXJfUSRIBZ0Ub5UO0TYf9+qu
         ZHGz2e7jvQ3cVNTacaepdEiBGfSTNAaO+POE7XlWoZkmdZQN3MMK4jWaA9BOyb6Qd42W
         X3kacltnScAcaEqxPCah/DBXDasyu8ytX0st7j/dL6U6QrQkxaL4zeDFaWFxMiktxKHy
         zXIcl8qOg5caxhKj6/ulg2ny66BsF+DlvXPK2KMI0rvWIb/DKBjx0Cz3SRCVML5mcyC2
         Pa/WTiv4CyC/v3ooRWANvSdsXPhF8BPWUeC1CClfoc5uAlcl1qFaKBFPoaahXT3Mb6FT
         2i1g==
X-Gm-Message-State: AOAM531zSFQk7DLnTv08SI1/lVT2W/1jBtcDbrsgQo0sK0gkPmOTqh/d
	8y2cDy8ni28N9OwnUqovQK8=
X-Google-Smtp-Source: ABdhPJzzb981nhDrx32YlS7FZjx5GSQFxtXVJ3TWb6Fs+UNYNGIg/SnOxH3rO20gvDOucqAXBgfYAQ==
X-Received: by 2002:a05:6830:805:: with SMTP id r5mr147764ots.209.1631135854199;
        Wed, 08 Sep 2021 14:17:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:210a:: with SMTP id 10ls901787oiz.1.gmail; Wed, 08 Sep
 2021 14:17:33 -0700 (PDT)
X-Received: by 2002:a05:6808:1910:: with SMTP id bf16mr110898oib.56.1631135853863;
        Wed, 08 Sep 2021 14:17:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631135853; cv=none;
        d=google.com; s=arc-20160816;
        b=fI63bxqFAto6ERssD4Nr05OK5JTbIzo57oKTG59h2ZzI5s7BqJ4Oo8FfsOmNlap4os
         ieiyL70yAZqJ/UUdtzfyg1dWNC0NPzt9W0YzmD7VA19UcV8dHUvVs62wDxieC/RMW0g1
         FYpZ8hSbq3EfmKHe6XZseyi7AwyLqxupsJEVJkrpFnXdjd8NtSa69gKL5eBnn49/1qXm
         2AYkOQAg3Oah/NO+dTJv60to4Gkc41XWjRjnljiM53M9dFo2YK+zjIwlXAiyXxL/RmCM
         fqLXENrJ7BapbZNCGRMQfPp+a9ujJkKQOvLaoMgTbqLMcG7YXnl5sv+GTqO7/cFs3Qkc
         gGVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject:sender
         :dkim-signature;
        bh=TPlAlW9m0l3/305TAZdOn8PajEjpurMWCxqwt3GbkS4=;
        b=bFi3WsghtkhtEpTrdIYRR5SzeeF3V+sN7hxGwUxLXgYWK1a/k7SS7FVa3arI2ALs2p
         HVI2sqQ2VNBrXO8GSUpxeb6EPkKS/NK1b8xZPDmSiaGsxnYe0JNhjGAxBiCxrVCx65ut
         9vVFmeHfMsQJt2amcsuI9ptnL44Gwo/LI/B5K8WgStXC6dW6qRlWbfjsjVGQ9OiZd6jL
         tovOa4Qab4CiJJqAgBw4QmEI6sunIXzToQELsLG0oCWH1nOM5Mh00kZrFg9Zyaw7sjLN
         b/r9KVvwHSWippg3ZEl4cB2EOlFEwUMGeLo84po1w9gZZNh/aWsPJ9SDhLhIvbyec7UP
         mvZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=k5Abv4lP;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=groeck7@gmail.com
Received: from mail-ot1-x32e.google.com (mail-ot1-x32e.google.com. [2607:f8b0:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id s20si16133ois.4.2021.09.08.14.17.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Sep 2021 14:17:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::32e as permitted sender) client-ip=2607:f8b0:4864:20::32e;
Received: by mail-ot1-x32e.google.com with SMTP id i8-20020a056830402800b0051afc3e373aso4801506ots.5
        for <kasan-dev@googlegroups.com>; Wed, 08 Sep 2021 14:17:33 -0700 (PDT)
X-Received: by 2002:a9d:7f07:: with SMTP id j7mr181524otq.84.1631135853295;
        Wed, 08 Sep 2021 14:17:33 -0700 (PDT)
Received: from server.roeck-us.net ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id j8sm39523ooc.21.2021.09.08.14.16.32
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Sep 2021 14:17:03 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Subject: Re: [PATCH] Enable '-Werror' by default for all kernel builds
To: Nathan Chancellor <nathan@kernel.org>, Arnd Bergmann <arnd@kernel.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 llvm@lists.linux.dev, Nick Desaulniers <ndesaulniers@google.com>,
 Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 linux-riscv@lists.infradead.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com
References: <20210906142615.GA1917503@roeck-us.net>
 <CAHk-=wgjTePY1v_D-jszz4NrpTso0CdvB9PcdroPS=TNU1oZMQ@mail.gmail.com>
 <YTbOs13waorzamZ6@Ryzen-9-3900X.localdomain>
 <CAK8P3a3_Tdc-XVPXrJ69j3S9048uzmVJGrNcvi0T6yr6OrHkPw@mail.gmail.com>
 <YTkjJPCdR1VGaaVm@archlinux-ax161>
From: Guenter Roeck <linux@roeck-us.net>
Message-ID: <75a10e8b-9f11-64c4-460b-9f3ac09965e2@roeck-us.net>
Date: Wed, 8 Sep 2021 14:16:28 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <YTkjJPCdR1VGaaVm@archlinux-ax161>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=k5Abv4lP;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::32e as
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

On 9/8/21 1:55 PM, Nathan Chancellor wrote:
> Hi Arnd,
> 
> On Tue, Sep 07, 2021 at 11:11:17AM +0200, Arnd Bergmann wrote:
>> On Tue, Sep 7, 2021 at 4:32 AM Nathan Chancellor <nathan@kernel.org> wrote:
>>>
>>> arm32-allmodconfig.log: crypto/wp512.c:782:13: error: stack frame size (1176) exceeds limit (1024) in function 'wp512_process_buffer' [-Werror,-Wframe-larger-than]
>>> arm32-allmodconfig.log: drivers/firmware/tegra/bpmp-debugfs.c:294:12: error: stack frame size (1256) exceeds limit (1024) in function 'bpmp_debug_show' [-Werror,-Wframe-larger-than]
>>> arm32-allmodconfig.log: drivers/firmware/tegra/bpmp-debugfs.c:357:16: error: stack frame size (1264) exceeds limit (1024) in function 'bpmp_debug_store' [-Werror,-Wframe-larger-than]
>>> arm32-allmodconfig.log: drivers/gpu/drm/amd/amdgpu/../display/dc/calcs/dce_calcs.c:3043:6: error: stack frame size (1384) exceeds limit (1024) in function 'bw_calcs' [-Werror,-Wframe-larger-than]
>>> arm32-allmodconfig.log: drivers/gpu/drm/amd/amdgpu/../display/dc/calcs/dce_calcs.c:77:13: error: stack frame size (5560) exceeds limit (1024) in function 'calculate_bandwidth' [-Werror,-Wframe-larger-than]
>>> arm32-allmodconfig.log: drivers/mtd/chips/cfi_cmdset_0001.c:1872:12: error: stack frame size (1064) exceeds limit (1024) in function 'cfi_intelext_writev' [-Werror,-Wframe-larger-than]
>>> arm32-allmodconfig.log: drivers/ntb/hw/idt/ntb_hw_idt.c:1041:27: error: stack frame size (1032) exceeds limit (1024) in function 'idt_scan_mws' [-Werror,-Wframe-larger-than]
>>> arm32-allmodconfig.log: drivers/staging/fbtft/fbtft-core.c:902:12: error: stack frame size (1072) exceeds limit (1024) in function 'fbtft_init_display_from_property' [-Werror,-Wframe-larger-than]
>>> arm32-allmodconfig.log: drivers/staging/fbtft/fbtft-core.c:992:5: error: stack frame size (1064) exceeds limit (1024) in function 'fbtft_init_display' [-Werror,-Wframe-larger-than]
>>> arm32-allmodconfig.log: drivers/staging/rtl8723bs/core/rtw_security.c:1288:5: error: stack frame size (1040) exceeds limit (1024) in function 'rtw_aes_decrypt' [-Werror,-Wframe-larger-than]
>>> arm32-fedora.log: drivers/gpu/drm/amd/amdgpu/../display/dc/calcs/dce_calcs.c:3043:6: error: stack frame size (1376) exceeds limit (1024) in function 'bw_calcs' [-Werror,-Wframe-larger-than]
>>> arm32-fedora.log: drivers/gpu/drm/amd/amdgpu/../display/dc/calcs/dce_calcs.c:77:13: error: stack frame size (5384) exceeds limit (1024) in function 'calculate_bandwidth' [-Werror,-Wframe-larger-than]
>>>
>>> Aside from the dce_calcs.c warnings, these do not seem too bad. I
>>> believe allmodconfig turns on UBSAN but it could also be aggressive
>>> inlining by clang. I intend to look at all -Wframe-large-than warnings
>>> closely later.
>>
>> I've had them close to zero in the past, but a couple of new ones came in.
>>
>> The amdgpu ones are probably not fixable unless they stop using 64-bit
>> floats in the kernel for
>> random calculations. The crypto/* ones tend to be compiler bugs, but hard to fix
> 
> I have started taking a look at these. Most of the allmodconfig ones
> appear to be related to CONFIG_KASAN, which is now supported for
> CONFIG_ARM.
> 

Would it make sense to make KASAN depend on !COMPILE_TEST ?
After all, the point of KASAN is runtime testing, not build testing.

Guenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/75a10e8b-9f11-64c4-460b-9f3ac09965e2%40roeck-us.net.
