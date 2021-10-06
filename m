Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBOHD62FAMGQEUOGLDII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 04BE4424004
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 16:24:57 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id bp11-20020a056512158b00b003fc7d722819sf2147960lfb.7
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 07:24:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633530296; cv=pass;
        d=google.com; s=arc-20160816;
        b=azIlkEEOjRE0ufcIf3D7/tJZx96g7nCakVhU0PVNHcnfxAc6JgZV2xfY0trfcTCMJE
         Zwls8SVlxVm3pGzFM+P3zv/696pNw/porjl1gNhbqsHNmzl7BFDgGMDpUZ6BgvUPh8Hf
         KpL/tIwytL72AOz/6q6jxcRudB/BZBZ9ydMjE1z7k4VQfdR1zZDNKRhh6LGw3ffW8uAt
         mZFQAFFbSyUh4rSWKmaMzkJ8b2iMRVE6aKHfERG9tXp0oQAYy4f7c7jLYDzRsoykSC5S
         fo9AXbmguwLWZn0S6aL79dO145FwbB6g/R4JKEHAkGUk/xzyGXyogkg0hVq1aOGBk/e8
         PJKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=J72TxlvGc+e23X3JYvTJwl3SyBEqllsFkeql8fQ8Kr0=;
        b=DFXOvm+bR8Uuu9XfF556OnfXkptg1fzC5e2QEdYSMAN3zj231IAMMpGGfpkNmDeGvp
         QRpcJft5Oty7LlYJRkl4Dg8qLCjqvc508nCQpzekOdumycxvP+p2glv/ZqhCxJ1cHE+J
         9iBacmyp/ZMq4Qzd+15+D5S20yiyfYqo7AHlMV7ZAkBm/K6Ob1BJiLIQaBSkF+8H6C8p
         EKcfq7+MuV4cB5bs1KYGpvrEmacvWUmI6O/QFaCWaH2GgH0W1sBoyWB0YrEmwh5b+1re
         Y6sB1mjJ3jVTeDAJB3IwZopxq8EmxkNYd8aEeRMFQCmXWY5AXglg3otjuCMNTcsWQM8S
         MWbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=J72TxlvGc+e23X3JYvTJwl3SyBEqllsFkeql8fQ8Kr0=;
        b=aESxrdkCbXKKJKg8BuET359SvtwFyZlQSsRsH+eoNSUWLGqSPVZE3ggnU6GXU5uF56
         1Eel+uAFGZiZar2nKbBsccs9YMeC+IS90/33OKK4QTIZy4ksYaabPEDDh5bCGlACLrHT
         7EOZnZSjTddmJEw4sY1SAKYZHr8gYpxpn3FtNoCwv803ZhCq9bf2BRB89KqbUjbZ9zga
         IaDmUMsK6JKppAl9Lmxx4AF3BIa+2dFQMQ7cYy5H3CIebMg4V+3n9vTU+4IWptcu6sj6
         73rKRjr0+l+Ev/6FBRLuQmqG5oawsFoOi6QxzFxrisuIdegyD5nolYZtzmxsd7AOf53+
         gkyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=J72TxlvGc+e23X3JYvTJwl3SyBEqllsFkeql8fQ8Kr0=;
        b=LTIKlc3yPQcLJeIQJlFmdEaD6CMb1MW7fzpEmsmDCfwUCISUicu1nmuWBvUirAsD11
         TWdBRaaL3oXMusACpjIoXiIvGU55NfBHzxIFnPRsNGcFJ4oFx98RvOumCWH6H/UBEeT1
         8rzPTOWx0RQXZwAUJRZgwOnrIC49dYYo54b30+ctErdILz2VCN2KsHRmhC4hE8rdWoac
         wHxhUqCVXqwgEanMk6xhROFXVAxAN/VHVApUTBmhAN4l4dB4r8wpm62O3Ys7ZaXh8a+A
         WoBV8AbZDRiWRMoqoLC4D/w0i8fb4kXN/PHm9q3VSJbjx0D6ye69JYEDUtvRFDLXT8OF
         ytrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531+2/qYWjmz3NYsGFyNIamTekm0L919uTKLrgEVnOWEiAj28WAP
	hmSm0XD8lWe/ku7E9FCCdJs=
X-Google-Smtp-Source: ABdhPJzaYwgMrozRZ7RnhiDy6oYO7RlKgRZWdClw3h5JYJD/IXQRugsHWqvE+SRKA3sd7NK5tV5s0A==
X-Received: by 2002:a2e:b888:: with SMTP id r8mr28114501ljp.147.1633530296511;
        Wed, 06 Oct 2021 07:24:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1242:: with SMTP id h2ls1531ljh.2.gmail; Wed, 06
 Oct 2021 07:24:55 -0700 (PDT)
X-Received: by 2002:a05:651c:4c7:: with SMTP id e7mr29955366lji.386.1633530295531;
        Wed, 06 Oct 2021 07:24:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633530295; cv=none;
        d=google.com; s=arc-20160816;
        b=XY7ymaQ6Bblm+IpsrraDZgxaBQZ8OCWQYv4Uh+lFwFnAQYTAYv0/E1duyblyE5cjpY
         lFFgkYsg/c5mDhOQtEyU8F5UWun01LHRfT02/Km/de4EV8Np+kU0XRWd4gKDrLMNieiX
         dC3YtwAUASexUgRBLpwfbpUSmOwOdFn1lOXqMdfL0n/QpatSh5OeQV7mXi2u82aX+ZlJ
         c8M5dYLK/jQpqd5PZZJWCRg950gNd0xJVuIsel4dK4xQuc0KbvXMbG6sySmMofWoS4Gh
         3Q1XdII/D7zvQd5ZpwqfCiy/gnY7KsS3N5q+TOMKFeoaTwgAxn58MWonp7BxW0PLatuT
         jxDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=JZuvWhmR//5ho+lEx8K+QLYwBCWJI2jhDZuwj25pb8U=;
        b=BcreYINK/aTyHnhhv6BWUghRHwrisP10vM4pX6++NGsJ00GdW943d4Ak0jOdJ83CPu
         RBZrvu9mJuoVSliI6y0LOGAJUO4snWBeY0tZ+W8vNYfFX2CXFwX5GlXt/QNHt8TlO1ul
         s9XLChJLx3+s09UsF21AM0UTIoZJe2NXXkM0azauF3YZjnjSnwbp01RQ1zFxEzpKAx/2
         iew3dlE6LuNCh9kZpTKL5sGZwew1WOZ+2MTvC/UdpvZUaBUR5z1Rd+4Uc6IVzdRHHklB
         +kTRmXl1o3obJ0y1Z7bQKeXKPh7PQK28yTXk7JLyZJF+zz317EkDDbHXURZ118LdnpEZ
         DUng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z12si1295490lfd.13.2021.10.06.07.24.55
        for <kasan-dev@googlegroups.com>;
        Wed, 06 Oct 2021 07:24:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4F5EC6D;
	Wed,  6 Oct 2021 07:24:54 -0700 (PDT)
Received: from [10.57.43.152] (unknown [10.57.43.152])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 378173F66F;
	Wed,  6 Oct 2021 07:24:51 -0700 (PDT)
Subject: Re: [PATCH v2 5/5] kasan: Extend KASAN mode kernel parameter
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20211004202253.27857-1-vincenzo.frascino@arm.com>
 <20211004202253.27857-6-vincenzo.frascino@arm.com>
 <CA+fCnZfuu3MLgeSJONqKaXMzkBsGxTQYjTtF0_=fMf4dGGQZCw@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <a0cb9136-186e-77f2-8f5f-ead2209cbf6e@arm.com>
Date: Wed, 6 Oct 2021 16:25:08 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CA+fCnZfuu3MLgeSJONqKaXMzkBsGxTQYjTtF0_=fMf4dGGQZCw@mail.gmail.com>
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

On 10/6/21 2:19 PM, Andrey Konovalov wrote:
>> +static inline bool kasan_sync_fault_possible(void)
>> +{
>> +       return !kasan_flag_async | kasan_flag_asymm;
> This should be just !kasan_flag_async.
> 
> It seems that choosing one exclusive option out of 3 via two bools is
> confusing. How about an enum?
> 
> enum kasan_mode {
>   KASAN_MODE_SYNC,
>   KASAN_MODE_ASYNC,
>   KASAN_MODE_ASYMM,
> };
> 
> enum kasan_mode kasan_mode __ro_after_init;
> EXPORT_SYMBOL_GPL(kasan_mode);

Fine by me. I will change the code in v3.

Thanks!

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a0cb9136-186e-77f2-8f5f-ead2209cbf6e%40arm.com.
