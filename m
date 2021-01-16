Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBDPEROAAMGQE2XJPIYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F09C2F8D84
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 15:02:54 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id x74sf11428531qkb.12
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Jan 2021 06:02:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610805773; cv=pass;
        d=google.com; s=arc-20160816;
        b=ubQdwrn72Y7UVtqmw6o950VFmTEHNToEpTNncSKJnTL11CcOlBxzX0twgBG27SoxO7
         J7KVVcDjCsjbNSY08U3EtPHj7zoWTWR9DaKKXYdKerOeg5QD03rVrAtlzw1Up/e/w1tZ
         SObTCFk87+GBbZVF1QIkGnGn9RJoe7RAVs2Tf8StaSJ00xp9dyBMZfMl2ay7TPaEHLC/
         64pMeZY9OZN2Desq8NDxPott1edUD4mQNr0K7gKtas35DrZsSF4DaYgEIsAS7QvDZvTh
         dAFQonq5Qa8rtPxTtFvsk53Hv2FiLr0n2sgyQ0a8OsB4u5jdBzl2NUs1gOCwaAUtGM5p
         8jgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=yMqW2CaQCT0t61eY3Kwa6h77As4AG78Wd0Njljh/U/s=;
        b=wZIXPT2J6mEHe8j6a+wmytEkPRgCoZYXW/qkxmNRN7cfKdBTqewHjgIco3V2ETFPmD
         7VVILeW6QvVhI5i1OX2CBkL4FmVgaWod3LCzz4vTM9LvnjKsy8kKQ0PX+9QOdOUkzwxu
         fuVQO8vADbMM698IWesmqwMx6hBUTKPYDmsmGXtCSqrXlyXvLyGpzdRBo4aCIfiYjx5/
         ErYTiciOuvGFU/wxcX7G+tWLcb8AalA2+xRbd4A0E8Jr964fJN/Tw3ng9wWIM+is9A5e
         BFZ2yjFMawKhZUHUPvMdPZs3hfQuJ87Df9xViyi0Pi16JZnoIUMLQ48woCyfnu0a3220
         Moew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yMqW2CaQCT0t61eY3Kwa6h77As4AG78Wd0Njljh/U/s=;
        b=ebh55vDymFZ8b+BH90wyjiMlswRM+iJFiwgNV0hpmbolTvTyvIYzhmAE+Yq/mIqh10
         WfCOvBlGx/NC4zERfDqDsMxduxNygDWEpB2QT7eXZbKOzOqd4HuCPaFF3bdUkvDPxenH
         IGt7oFaPVcIb1LUjSNU4rQLpN2E2U8dMwcVoDtb7hdn4sgB+1ILmwn+cWNdRwX9m7efC
         I0gcabG31vTx6Qzyjx4WTJfweZd/tAWTpJsS6mop4bzylp+b6ePxghhce/ZnlrqO5Wnc
         kHAE+GUTyLj9jT0yTggb3M54W9w3t8S2R0brRXJ01Xte14ugtiK4E1y2eHNGOsqhTLO/
         Ua2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yMqW2CaQCT0t61eY3Kwa6h77As4AG78Wd0Njljh/U/s=;
        b=tWYKwxgky5+2ShQ0XLwMP5XRIjktilXI736r4lAHdYtKKAg7cr8A67a1LjawWgTJuX
         NV3XPa0N5sSautwGVTHxQL5Z947CUIR42x4bejIYIIDrRmTTrhJndlXuNsvT5w1q5/iG
         otha9umoBv74DFAmGHs4Ju5P2DYKqE9Jz5ofhGSDWRH0JGEiLchwU07Oe3d3C79pGxZF
         fRCxn3NTNhrXv2AvYgJzaccKhRvnLSHRjZcMH0ehQNwXKURTKKzqwqIjtjz0DsJEtB+D
         mYoBLrWnIJ900mE9qkP8te62xGmfBja5A4aveKVVC24tAPedN8x0sSemPJjYNTlS1Odk
         czaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Wc4X0KHuA5nhY2YiH856WB8pXWNm98ACXwftjO0CXFvGgT2wJ
	Wc+IIOktk1QvKTQzldD6LZQ=
X-Google-Smtp-Source: ABdhPJxuzq9Lmqeh4Y4W3+7CPoXKeaksWI1C/QQctELYungbqDXL56YVOpoqdWW4NbiOfZEZI/+8yQ==
X-Received: by 2002:a37:6744:: with SMTP id b65mr16931911qkc.199.1610805773188;
        Sat, 16 Jan 2021 06:02:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:3763:: with SMTP id p32ls5071854qtb.11.gmail; Sat, 16
 Jan 2021 06:02:52 -0800 (PST)
X-Received: by 2002:aed:2d83:: with SMTP id i3mr16336285qtd.248.1610805772746;
        Sat, 16 Jan 2021 06:02:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610805772; cv=none;
        d=google.com; s=arc-20160816;
        b=I6TT/SzJDwxVYnxZaEUGGUN3AtyoEe9tGnqUzsBcD++gC6RMDrAvKgFkE7lF18QVfP
         Y+2rE/8gT4KS8eT+aVmqjkE4BzktOPEitt5cpCqGYC9MqoRHu5QA+SPCmAR4bcOgCEyC
         xG2lP0BaLdVIev5Q/hh0U2Kp3WS2ctBUMyTwnBux0c1GIgpSy3CByVhYS9AVqRNk4CcG
         5Ox4s2BcvjLiHqzm4VkkvJDtyPMvgNFH5rJvRTZylHlt50hXMwHRrqnxGObsyVix+1sd
         47jrRcINGrESo2vnO8ybPeCqVL0uty/8L5gphMrd7bWSDydmCD+QVwRCLo4dO2AQZgWa
         ZcPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=LZUEHt2NyH75Y2ByjuBbCyoShiDoHLyTvmNWUlhfKHg=;
        b=qclYtgZFPhwDdgKELyjtEZXdCyqeTVQVfWKTua7PvYx2bZNTPFhEN6FyeFVJBs8Hja
         TpnQTyX+M3anIZsQFXBX8pz46kK2Ri42rs4n5FW79GiC1SjrPArWAwP9lm0bIq1UYPJM
         c88ZsKRysUU5nkeY1E/PEL1r8y6jZhLsa24O2mlNB61OZu9007NsKZd7tIJKeId2RTuj
         XeK2rrd31g0j3h7TsumBksSkDvMmV5yG8ui3y+IRx2g/DRBN5pig0gHHN8XUhr6EgCme
         lmvBrZZfWGrZXNKEqCYv61565r0sFezA3hbxoKY8n5GmcgCjUjhZBeMGIYjnyzf60tMi
         8hWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j33si1090769qtd.5.2021.01.16.06.02.52
        for <kasan-dev@googlegroups.com>;
        Sat, 16 Jan 2021 06:02:52 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 058B711D4;
	Sat, 16 Jan 2021 06:02:52 -0800 (PST)
Received: from [10.37.8.30] (unknown [10.37.8.30])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 148063F719;
	Sat, 16 Jan 2021 06:02:49 -0800 (PST)
Subject: Re: [PATCH v3 1/4] kasan, arm64: Add KASAN light mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-2-vincenzo.frascino@arm.com>
 <CAAeHK+xt4MWuxAxx_5nJNvC5_d7tvZDqPaA19bV0GNXsAzYfOA@mail.gmail.com>
 <4335128b-60bf-a5c4-ddb5-154500cc4a22@arm.com>
 <CAAeHK+zsY7zdkj90K2zgXOScOj1WbackfBPv6gjJ77SfdzDi4w@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <06986687-3e7d-e2b0-10e0-5c39d9fae431@arm.com>
Date: Sat, 16 Jan 2021 14:06:37 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+zsY7zdkj90K2zgXOScOj1WbackfBPv6gjJ77SfdzDi4w@mail.gmail.com>
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

On 1/16/21 1:59 PM, Andrey Konovalov wrote:
> On Sat, Jan 16, 2021 at 2:37 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>
>>> [1] https://lkml.org/lkml/2021/1/15/1242
>>>
>>
>> Thanks for this. I will have a look into it today. In the meantime, could you
>> please elaborate a bit more on kasan.trap?
> 
> That's what I call the boot parameter that allows switching between
> sync and async. We'll need one as we're dropping
> kasan.mode=off/prod/light/full.
> 
> Feel free to name it differently. Perhaps, as kasan.mode is now
> unused, we can use that for sync/async.
> 

I see, thanks for the explanation. "mode" or "trap" would work for me.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/06986687-3e7d-e2b0-10e0-5c39d9fae431%40arm.com.
