Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBJ5O2GAAMGQEBMZ62GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 31431308C9E
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 19:42:48 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id l197sf2137071ybf.17
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 10:42:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611945767; cv=pass;
        d=google.com; s=arc-20160816;
        b=sNkxOHgQsYaQ4WiroiUo8NTxwxvhVz3/TgKRyL/Ff4FSVBz1RnMtJyj3hS/HrbWmFu
         VfRzjYWxuQMN5K92mxN9Hosr2PgtqlpvTpiXBSWabO4dRHhBcGzxp3EocD45/Lr2HXer
         Cy/U4a2PelsOxVh2OrRgrl6kcj5MbWKNP+Ii29+rjQDb7rJ5e22WD65b/IbxJQ2oq7wm
         P4IY/BdYIT4ASCRLQjmGbWRlxMTwyKo8+owjjcLANcQxt1IFgoT4gkmmbsl+rIsOoD3T
         IhwGd9xnU1pBoqUTCC4mMi0GlL2WhScx7+6HOzhXlXQ+AVVPnwVg4jw55J0WcXZ8tgaq
         3lYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:references:cc:to:from
         :subject:sender:dkim-signature;
        bh=mO6I6LNabsxVKwRq23v744HBCdSfc6wqvHoYaDmoGvk=;
        b=qwn9gwMf8JG+IBSpJkOTrzomiYR4Nd3EAj0Y55QzQ8J2J9xNOjJQu1HCpxmOgIPfUm
         78wANcWMRaAc3cNOtRGMkPpzYtX/IKsKpYGbAeh7pzSPx9VATRSOMXgbYVr0mryFSGDz
         kKZ6Ie9z6qd5juhnBMxVb6+rCgT0NmI+C5Z4dzVJ2IsakPtVNUg4b+gwu/LKz46AWgYA
         3ze9pepZJtu+U/2Gl8xyN4EP7Iz0upvFRu7g4dxxvUdnynSaKEmzOrwCxoonZEe/UVGD
         PLRBqlHbqLFzf59a//KL0PLyKJTGEpAdSj07xIPjXAEzlJ0Rj0aFjYx/k2K37xB0d0ZA
         ZjUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mO6I6LNabsxVKwRq23v744HBCdSfc6wqvHoYaDmoGvk=;
        b=dSN+tkbQu/jz4lgwOUk1byvvOa7HB1HuiZ1FyWnfDJZ32CdvL4lXnmOobyhlNe9Fp3
         NJjZHYIjOuQ8CJIlh1Ci4SX81YY8Sum0l6QGp3dmUeARvNQJ6rFEXKgMTaxPCjWXTvfy
         hArz3+goZFeqRMTaY+1VwbPp3sFEW0SNAQLh+SjufcCtD7CFEVjOpF7x0iRXlmyONpMf
         2IyvN49rfP28DIrAT8czlC2wZiqBNbcmy2bf9s/xRQY9Vjtm1HdjAFFJFJjrA66PR8M6
         M/HyPaDkU3jtldK6HcBOxSOtvmsK70XDApyp+b0WI26WQNOHTLEm5d4bdzy4Vf89tV1x
         41Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mO6I6LNabsxVKwRq23v744HBCdSfc6wqvHoYaDmoGvk=;
        b=Qyasy9XLKGnmKBcpMyXwcZRIAh0dK0W3ONcRw2yeTEKjlsAtKlTwneyqdQfOh6b+3S
         BFLfD8XAPTYPg83HtldlycpbE62gIquEKQRucQa7gnWtpCiB0Fh9gE8rHj8f5roAXws1
         PYeuEfhvvUayzwyP7ppwgZ2xDgCSc4B28CbnkH7HKzthLQ0FTiZ5piNETk1U5yM7+9cB
         8JbFidDRWqRtMC5zZvlp90oSFvwxkGsBfcxlDDz28xOgEXim1gNwHnGLClKF5R1MY8CW
         ElHTMg1sgLJzkfamqpCtN1rSMV67bNDEyauoPUmuPJIhINilTHY8H5XXR/mRbg593jX8
         sJaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532HGtH8qTtK7qSv3ASIJWSjw2lc2rYLHd1y9Zp4TQALpFJRcEfJ
	cihtAG6uJ8BZb9NMps7Qgh0=
X-Google-Smtp-Source: ABdhPJzA3UdhzjXbSSw75Ijw6sec10gBxgl0qVwxcpLXml8o0puY+tLqjRAJ+zIn87Al+0ftkgyhbg==
X-Received: by 2002:a5b:b51:: with SMTP id b17mr4786916ybr.169.1611945767174;
        Fri, 29 Jan 2021 10:42:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:af4a:: with SMTP id c10ls807623ybj.1.gmail; Fri, 29 Jan
 2021 10:42:46 -0800 (PST)
X-Received: by 2002:a25:6d8a:: with SMTP id i132mr8140620ybc.337.1611945766806;
        Fri, 29 Jan 2021 10:42:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611945766; cv=none;
        d=google.com; s=arc-20160816;
        b=a2XQ21Rd/v6n8XFvV3+t9t6Lz20WZyv8eOmzZf2kZqDNo46SXmCdDLoM/x4GHbAGKz
         I3K9fXO6wWLFcTVAIOa0l3QiEL3eWZKw0d8dYoMGUj5+Uaj7Z7nHreFDQ1caH7rlqLe5
         PzQnzwt5zIQh60Kcoh7BW3jbr0ZAt0G+dqbJgZ4I+WoKx5TGOoMzXt/+0qNQ/xjnrI4L
         7JhPnYg80ji5cHIzZFD74hMZ5KBP+fgukZK6w0XwCPSN1Ano134F199IbcUNRQPscaJh
         YOdtdqTYN2MtSfd17Orf9DdD94T+PRgE8VYSmN9ycp+aznQbAOAATbgQTrjen9vsEDCo
         t8Rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject;
        bh=UWZ/EnyUmif10m2fIOGWaHnXbb5J48pjKqCKJ67ZooQ=;
        b=G9MX6gv715B8kD0+pQ56VpGprL5TGkwtfTRdrR+O3rxYC1ILNFnVLtcnoAciXJFnub
         VTohAqABEnukge+LB9p2Jk//KYf3YNLsDxxPYyMfwNcBmV3JPVHFVHebuMx03iodOcIY
         SBkpoZ7QDHeIChOJHzs0Ye1o7IXonUfPXxn2m9rdI97QDbMRXN7XJNcnxvqgxETM3Q3Y
         UEUqLBQyrbgQO5vFqQIkgQ5tcQdVopQeMOvEw4HZPMWtSJovARFH/aN0mTq3kx+5OXv7
         AywEtdKgpOg3sDBfl2+iXMGbYpY11Mxu81BnvN9Y3Fr3H04+f3HJfDVBzDHn9c+KHWsv
         VUew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id c10si642368ybf.1.2021.01.29.10.42.46
        for <kasan-dev@googlegroups.com>;
        Fri, 29 Jan 2021 10:42:46 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 50C0813A1;
	Fri, 29 Jan 2021 10:42:46 -0800 (PST)
Received: from [10.37.12.11] (unknown [10.37.12.11])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 97AF73F885;
	Fri, 29 Jan 2021 10:42:43 -0800 (PST)
Subject: Re: [PATCH v9 3/4] kasan: Add report for async mode
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>,
 Alexander Potapenko <glider@google.com>
Cc: Branislav Rankov <Branislav.Rankov@arm.com>,
 Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>,
 Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will@kernel.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>
References: <20210126134603.49759-1-vincenzo.frascino@arm.com>
 <20210126134603.49759-4-vincenzo.frascino@arm.com>
 <CAAeHK+xAbsX9Zz4aKXToNTrbgrrYck23ohGJHXvgeSTyZy=Odg@mail.gmail.com>
 <e5582f87-2987-a258-350f-1fac61822657@arm.com>
 <CAAeHK+x5O595yU9q03G8xPvwpU_3Y6bQhW=+09GziOuTPZNVHw@mail.gmail.com>
 <f1ad988d-6385-45e0-d683-048bfca0b9c0@arm.com>
Message-ID: <8021dbc4-8745-2430-8d52-6236ae8c47c7@arm.com>
Date: Fri, 29 Jan 2021 18:46:38 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <f1ad988d-6385-45e0-d683-048bfca0b9c0@arm.com>
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

Hi Andrey,

On 1/29/21 6:16 PM, Vincenzo Frascino wrote:
> What I meant is instead of:
> 
> if (addr) trace_error_report_end(...);
> 
> you might want to do:
> 
> if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS)) trace_error_report_end(...);
> 
> because, could make sense to trace 0 in other cases?
> 
> I could not find the implementation of trace_error_report_end() hence I am not
> really sure on what it does.

I figured it out how trace_error_report_end() works. And in doing that I
realized that the problem is sync vs async, hence I agree with what you are
proposing:

if (addr) trace_error_report_end(...);

I will post v10 shortly. If we want to trace the async mode we can improve it in
-rc1.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8021dbc4-8745-2430-8d52-6236ae8c47c7%40arm.com.
