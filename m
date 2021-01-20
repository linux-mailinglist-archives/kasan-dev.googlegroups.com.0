Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB4MCUGAAMGQEOQ43RCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1319D2FD2E2
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jan 2021 15:42:59 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id a19sf32766121ioq.20
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jan 2021 06:42:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611153778; cv=pass;
        d=google.com; s=arc-20160816;
        b=CYig5zzc9zdGQ5SVgD0T9UCucfpaTuCEeJmsEvssfe8c6S6jQ/+01GEkpy+TFGILUh
         GOHofJiRktVH36w0ul0BF/epoW7uihmbzBr6AEcPMeX15S1G+7E25qvYbB4fTHNDMRn7
         6Q3kxL5aTECoUWDqTgkyCNeZ0LrPuwHoCepdwaWWsemqe8NnrCbNkdzlkzcg0+pxg6I/
         FCGze0WTp0cV2FcTCSg7kMwZEBMMSr9oFRXzFopZURdwEykgs5XdCBZ60xcLH63NZP/S
         6PMQ2AqPMPLadWim+XTGpzhXDdF3Qi0UrTlIod2OdoKm1F/8UJ4FqEnTxgsjP7Rl21jP
         7YKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=QS9u/l7uOdJmPVagRgQskDxdYXZYwUGoLqorJLFoHxc=;
        b=JbswNpTkTy22TAHnNRqhDwBl8wxbs+MRB8Zolcm0++r+RBFJVmKiNBGeODNeJ93RUy
         IiWEIS7AoWSyGgvYbTAa5oWRjf3/pZm298P5b7wdBXuX0tL8+l0lF4D5Koyr3wKPEM5P
         a5SExSLpFe2tEnYtCD9XrFarfo/JBTytuEvehrJCIsah/uvwsRfIk1UyTb3VDKNpht4X
         MP44IYpCYx4MVPICkLHEHLrxPMCGUpO3athY+FiAAgRf1i//RjgNrNtWcGvNddZAwwnl
         26eWUTzVP2uoJwsUV/0/Hic9gvg2tkrre9O0xb9uGqa5SKSJL7vsTt9KQ/gsFWP4Seuz
         K5mg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QS9u/l7uOdJmPVagRgQskDxdYXZYwUGoLqorJLFoHxc=;
        b=BUCrLqRwGRE+6wPGDJW3F7UeKNeO5zNgdiCTSSjU1fwwqdCuID65OXMUUNZ3MwC7YT
         6O4ausrIZsZsgKFJlFnaFb2bHodT4gnQpzstMzY2QhouVJzJyrxCi2CKANUWkNtK2AQw
         bqr1pwDCYGDl+z7mG7EJx6kbia8jsamdIai5sxcyqbyCVYwetpx8UfsH7YkSAZQretC5
         XKn9qrid0Ix63fuwmp/sagwxyECz9BzY9vuGoRnupp6EDRLygg5tfSj8ZLyleTUQYQQ1
         RCsH4BjZezoH2H+KbxQlorVDnsw/5l+ez4/Jtqy20NJ+E9YxE1YdQbQtMoVvWUsJ1H+4
         alOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QS9u/l7uOdJmPVagRgQskDxdYXZYwUGoLqorJLFoHxc=;
        b=COdbukW86ibcvfO2WDY1dWRGNqd+3/WfIzUBBrcxneMMB3HHEjGp/1hPiLNppFZIxx
         IrQoh9llKLOemX8wI64bBN4E4Z2Lv4MBTw9fUZQwB4sNioVdehiuBMz8StVFgeVVNwAi
         rtXyDkkOvE0hPsux4tCfJod3xYI3cUUhYYJvy9XqTfVtYbKUV715XpAziq3Zv1QVTR7M
         OGFrKDnJGHj1txly209pR4KYewhIrwkXeBFzLllb1Bjc2HpkBOtkWFegiW7psFXr41yM
         S1GB2NE819N9bRYYEeHh41oeTwikUkRiypZ+Qq5z6i/J7Qk1QZCGM811wnBcd2BBZB9S
         /dxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531g4g7ETiUvcOTXHcTkw5CKsQfwU70lWj+Gof81XEBzk3ntUqw6
	ZRbuw6+90GLyd/5wCwSvOUQ=
X-Google-Smtp-Source: ABdhPJxleXL/1wTxO8vHn+OzON3dMXS08Z8hbtPKD8gEFpsB8INS4BV0tI2vByE4ECEMvYV9078Y/g==
X-Received: by 2002:a92:1f9b:: with SMTP id f27mr8338811ilf.190.1611153777893;
        Wed, 20 Jan 2021 06:42:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:13c5:: with SMTP id i5ls3002290jaj.1.gmail; Wed, 20
 Jan 2021 06:42:57 -0800 (PST)
X-Received: by 2002:a05:6638:214a:: with SMTP id z10mr8085900jaj.41.1611153777580;
        Wed, 20 Jan 2021 06:42:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611153777; cv=none;
        d=google.com; s=arc-20160816;
        b=aRP5oNZlKGeIvrl+uYvMdXhJzAdy5nNdhZwTkhwLCPgKN4qQrs54Pv56bO+uw85hly
         H37n3+cRgeO2wDBV32D0olMr/cKRQibzY4SbmrLwF01l9NqXUxqmj0xbz0l/S3ATUkz/
         r7ZNRg50YptFkW7swLbnX0CS/G0ZnCA7w7iAo1AZRMsecp1uUZKbkRl/8SAEiVZW47b4
         hD15QJPanpuIhc0yM2me5PP8toMO5JTPNt8A8eK+fqs6E6WQ56YdhTEWJPmLMES07SxG
         NdfnGwiXQiEu6yDVzFgR6j06aIIAgmJzetT6seeS4C4wPJP0YxSZV4e3aTcBoGoaV/y1
         M7LQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=pQoE+jZT5D5oNLAazHyyrDxuGn23vg74d38j5MioIRA=;
        b=vmLVEm5p+CusCJyX4r7rqPvSkHDjJBkoTNiFKtRYk9CNQB4NacHTRueoqNEY//QMZn
         F+V568yakdaww6Nku68tc0vBKxwBe/QJLwm6enZ9GnbXmWhl3lPuzZO748DqL9197Y3j
         efdwMIF1D2tFmdnuBQYrS7OMcpVrpW52fMYVmTyI1LuNL9waINWsRa9wT/i6hQUv6aWF
         ASwZ/kWuK4EmPRcbVWCvDIPtZp9CaCA2mJsqF1VrRTaWnipIoIUJfjJQSX6B++nYbSKR
         MF0kYip+0Fle3gWG/GoaJBkzFv5YG18bewXwCKtLa03s1LAhEUaHvfDgiSTmE3fvbv02
         WDcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b8si310202ile.1.2021.01.20.06.42.57
        for <kasan-dev@googlegroups.com>;
        Wed, 20 Jan 2021 06:42:57 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 987AFD6E;
	Wed, 20 Jan 2021 06:42:56 -0800 (PST)
Received: from [10.37.8.30] (unknown [10.37.8.30])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 7F7583F66E;
	Wed, 20 Jan 2021 06:42:54 -0800 (PST)
Subject: Re: [PATCH v4 3/5] kasan: Add report for async mode
To: Andrey Konovalov <andreyknvl@google.com>,
 Mark Rutland <mark.rutland@arm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Alexander Potapenko <glider@google.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
 <20210118183033.41764-4-vincenzo.frascino@arm.com>
 <20210119130440.GC17369@gaia> <813f907f-0de8-6b96-c67a-af9aecf31a70@arm.com>
 <20210119144625.GB2338@C02TD0UTHF1T.local>
 <CAAeHK+wcWk_URtGROUc1VLR4PjVQChCUpSLFya9DNTytQP2mVg@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <d9ee1147-be64-4910-aca5-6b83f1c71895@arm.com>
Date: Wed, 20 Jan 2021 14:46:44 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+wcWk_URtGROUc1VLR4PjVQChCUpSLFya9DNTytQP2mVg@mail.gmail.com>
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


On 1/19/21 6:12 PM, Andrey Konovalov wrote:
> On Tue, Jan 19, 2021 at 3:46 PM Mark Rutland <mark.rutland@arm.com> wrote:
>>
>> Given there's no information available, I think it's simpler and
>> preferable to handle the logging separately, as is done for
>> kasan_report_invalid_free(). For example, we could do something roughly
>> like:
>>
>> void kasan_report_async(void)
>> {
>>         unsigned long flags;
>>
>>         start_report(&flags);
>>         pr_err("BUG: KASAN: Tag mismatch detected asynchronously\n");
> 
> "BUG: KASAN: invalid-access"
>

Ok, I will do in v5. It looks more uniform with what we have for the sync exception.

> It also might make sense to pass the ip, even though it's not exactly
> related to the access:
> 

I would like to avoid to add a builtin for something that has not a real meaning
as you are correctly pointing out.

> pr_err("BUG: KASAN: invalid-access in %pS\n", (void *)ip);
> 
> Up to you.
> 
>>         pr_err("KASAN: no fault information available\n");
> 
> pr_err("Asynchronous mode enabled: no access details available\n");
> 
>>         dump_stack();
>>         end_report(&flags);
>> }
> 
> This approach with a dedicated function is better. Thanks, Mark!
> 
> Please put it next to kasan_report_invalid_free().
> 

Will do in v5.

Thanks!

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d9ee1147-be64-4910-aca5-6b83f1c71895%40arm.com.
