Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBGGV6WAAMGQERRV3QXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 09EBF310D72
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 16:56:10 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id g190sf3792077oob.13
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 07:56:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612540569; cv=pass;
        d=google.com; s=arc-20160816;
        b=gXKUjAgOIdZwfSo4mt3pl6m74K93GU2KkWDiY5RGLMEVGImi1rpNYO/FEFaTu1u4rX
         01FgI7zd5sDok7wNtaf5y3XrlV9GLLJxvlmsenm0+6ur7C9ILi7rIjj+PIYSPyUVs2uo
         wsCLeCi6MYRk1GOg2D2pUbGXlcNyxlVLmyvCU74IGWe4qTtIJbCH46wweuJRPjxk8UlL
         1mReJF+nOP9xkMZThprK1jbUXd1ySh7U5my5t6/Rx8WEsOXCaA8dbrxNnFDoZUGD5V1c
         qaW2yw30yKkycMldvAa2n0VtmZVJ5S4lX4rlnLZRX9gnF/Nqn/9wpwNm3gEMigtuYwoX
         AjCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=36pHGuuEbY7KuTIOceLLVDP1KQKIUwQ+90JK4LGNxmM=;
        b=Lm6TfJOSEs1CoavzYShHrvDvImPp9jEqJNeR36SwoWNuSsP67Z1S7GiexU9jnAci9o
         CNHUflJRjHgm41oLPWskorn9I26jpbNJVe1YT3ahYCIWM2YrNqUOslQQFF6WJ2B/wKSV
         zeM4EpgSFp79Xn41mNxQiYKhv+Cm85XEivBmcYJUUKy+GkB5g2RihjZJraPfISBMIVjp
         FJ7Y1F9VSzwcjFMGnBRtLESCYJl8DGYh4+pamriKd2eK7h1cmPV64RvD9Au7p/s/uGDt
         kQdx11TKUUb9urtm5/zmzoqnkvzTTfV6/VL5+2Rbsn0zMcQuZqU54827FFLhKc86zOz7
         Qj2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=36pHGuuEbY7KuTIOceLLVDP1KQKIUwQ+90JK4LGNxmM=;
        b=jIN+DLdkUhaot6ag1SCz7TXzph12LRgCsczxF6HE5BaPCL9qNAY4XeFYCDrMnRv50I
         kH95qN81BrY7SqTX/DkY3RJJHfB6KrXVvjDLriZ9FoogEv1eFXJzTnUuhJjJ1QZU6P4M
         u0bi5G7KN6+yvp9BBZZ6GsjfALkgGRnxFKPjt/pkqtMtIFaQGFrozOUcOO6A6oW8RZ2I
         AzxkTPPtIP8hdITNbaLJNE9skG5R+spxFD3nOXUkcZ2zN0+23GLjjVEzUCx/NX1WOlo5
         CPmv59ZgRcG/0AElKNGyIniGT/rvaN1shjxzSVPk5+hjE97hQYh5WT5Kf5l4CTMZP5B9
         tuHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=36pHGuuEbY7KuTIOceLLVDP1KQKIUwQ+90JK4LGNxmM=;
        b=JeRV3tktDl/sAUYDB4xgcZPGS1cDZvWiLCDTRAA7jFhpgW3ejbHPibwq13/8H+M0Hj
         7/Fy03zzYCflyvZw9EKYr2iRDwQbJmcS+xOutzr35CnPc0VRxD1xZOZ8IvBwUGd5kEmu
         a/nr7E7jHh1IYO9m/9CDloogOMBppfAnzfPqcw1W05AgYVMjbUYIavMuCFNfpEN464E6
         CiI+GLPlfIKbdxhAHlKCIAQqLXZkLOwB3Fs1GXOO9Idq2raJbbj0kd7KP4qBS2Jq+ai1
         rutmNMr4gSCSqQTEJ689iit5YOtI1zl0kwYpY0uH55iofCy1avGyPTLKQUy2fcK0o1Xd
         Xt2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532d6IYiHomPLFTQUtEOVcF3CleIfxnb83KpwfnLf4GlLqt7oyQ3
	iEcl1SUWEmccwwKW59xgWnI=
X-Google-Smtp-Source: ABdhPJxOMXvpRa8qYBpN62p5NWpKsD6rRjaBkGqFXFx+auOrT4fPg+PWiWaNvxnAA1WYsh3dwpB/Cg==
X-Received: by 2002:a05:6830:2114:: with SMTP id i20mr3923317otc.91.1612540569009;
        Fri, 05 Feb 2021 07:56:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f0d:: with SMTP id u13ls2344825otg.8.gmail; Fri,
 05 Feb 2021 07:56:08 -0800 (PST)
X-Received: by 2002:a05:6830:4ae:: with SMTP id l14mr3695312otd.158.1612540568631;
        Fri, 05 Feb 2021 07:56:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612540568; cv=none;
        d=google.com; s=arc-20160816;
        b=iVcuPov7ojfPhQSFbiueIC2VKhCoJvREMPms0KO9/GPINvUm2SD4T77HN6Lg3FT+8Z
         Y5CilHHC+BG0m1WTdI4bTCRMuXvOPztZkj9fooSn7PzUBYj6ASUKw2d5ScEaxjN7JR60
         sWXkXaQa8EiTdDs64+6UNmoLyHkImnEtqoiLRe9+8hGoReVQg1lETKVE+0qZ/Si4U1n4
         UI0rni/r39+NeCWBO09CTAsG7yK4rcUOnKpDF9YfJ+Y/Lnt3BUL0DHpFtR0BQNAqreMh
         t8Jpn5z3Tdf7JE3HgP9EKpbKzXq5ZtQMQR7u3S6YOuZcC/DoSebgcyBVjc/WEy10eVXC
         TZOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=NJR3AwwkR4ziYs6+5xAbpbtz6PoLkkqZPWT8vqidcm8=;
        b=uBl3uPVS1/kiw3+k4bTmZOBTR63Y2T+vtEPWI7C281HTQdF6Ygm3hvtCW7FyM6MBve
         DcT9FiShVbeRH4fOWua2Md1KyvCmx2nfu6fxnLbdMeBaSeYIkQfy7hOJOd4N8m93tga2
         L6yyZmFsFLWl3u3F/Op5DkxDQ08be+ka914pCJECIPOJmSgm2qAIpu3aUcpNpGgQCnV0
         rajl86qMFYs+VBI0ovnxmToO9oB6J/GIeQBvSn0R5ZX2YONcigOEJbQeFZmZlfHS1aFf
         TrN/mUgarPRpwJXbZcRq8G5HbAB7FB/gTfEJEmSwql2fygKfLO6yLZku9yagn0RdbGUX
         6Qlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i84si15811oib.4.2021.02.05.07.56.08
        for <kasan-dev@googlegroups.com>;
        Fri, 05 Feb 2021 07:56:08 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 514AA11B3;
	Fri,  5 Feb 2021 07:56:08 -0800 (PST)
Received: from [10.37.8.15] (unknown [10.37.8.15])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 726743F719;
	Fri,  5 Feb 2021 07:56:06 -0800 (PST)
Subject: Re: [PATCH v11 2/5] kasan: Add KASAN mode kernel parameter
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210130165225.54047-1-vincenzo.frascino@arm.com>
 <20210130165225.54047-3-vincenzo.frascino@arm.com>
 <CAAeHK+y=t4c5FfVx3r3Rvwg3GTYN_q1xme=mwk51hgQfJX9MZw@mail.gmail.com>
 <CAAeHK+wdPDZkUSu+q1zb=YWxVD68mXqde9c+gYB4bb=zCsvbZw@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <96163fa8-c093-8c2f-e085-8c2148882748@arm.com>
Date: Fri, 5 Feb 2021 16:00:07 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+wdPDZkUSu+q1zb=YWxVD68mXqde9c+gYB4bb=zCsvbZw@mail.gmail.com>
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



On 2/5/21 3:49 PM, Andrey Konovalov wrote:
> On Mon, Feb 1, 2021 at 9:04 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>>
>> On Sat, Jan 30, 2021 at 5:52 PM Vincenzo Frascino
>> <vincenzo.frascino@arm.com> wrote:
>>>
>>> @@ -45,6 +52,9 @@ static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
>>>  DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
>>>  EXPORT_SYMBOL(kasan_flag_enabled);
>>>
>>> +/* Whether the asynchronous mode is enabled. */
>>> +bool kasan_flag_async __ro_after_init;
>>
>> Just noticed that we need EXPORT_SYMBOL(kasan_flag_async) here.
> 
> Hi Vincenzo,
> 
> If you post a new version of this series, please include
> EXPORT_SYMBOL(kasan_flag_async).
>

I can do that, no problem.

> Thanks!
> 
>>
>> There are also a few arm64 mte functions that need to be exported, but
>> I've addressed that myself here:
>>
>> https://lore.kernel.org/linux-arm-kernel/cover.1612208222.git.andreyknvl@google.com/T/#m4746d3c410c3f6baddb726fc9ea9dd1496a4a788

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/96163fa8-c093-8c2f-e085-8c2148882748%40arm.com.
