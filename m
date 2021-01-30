Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBZVF2WAAMGQEABGWGMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id 683E330951D
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Jan 2021 13:36:55 +0100 (CET)
Received: by mail-ua1-x940.google.com with SMTP id d9sf363001uaf.18
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Jan 2021 04:36:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612010214; cv=pass;
        d=google.com; s=arc-20160816;
        b=eyhyhvC6q+wVjkJ3OGeC1wCfkmgFKkLslPFbJHEO0Vs318XeXD+nep2W/CYNEKynHn
         tyExXWuyAY0ps0YEFaAyPt0bb7z2qU1ml8tQEbWxz9wKyZg23sooEIhKoMCkDVgbc/gi
         7o8CgKnWoT58YmqJ692SwojqtzBC+cB4qQ6/0CHavwPjhEYtKFFCLWfPwBZ3GqMPCs2k
         5+FlrHbk2oKRAjxIcvKEeF9T5/w3ZjGQTEeN4AtSXjeA5ZMInJh92SclYTXCP3tSBVhC
         u24o4ASmLgUqyomRNn9ZSk/RNsSHvaB7RF56JtQrd0HOlybQih/t2r5Qjd2O04TMgKem
         +rRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:references:cc:to:subject
         :from:sender:dkim-signature;
        bh=+kEPI3xbIHhQtbnVbPWN95uHI+1OYdcynM+OnZoyigE=;
        b=N5KfP64jpX11Za5qy4YBMRO9ZcKOH8F00JaLI+puoLZ/noex1GGSCISyy87DIsppa3
         /otBSbdORK4Hys7kCgN/2vrm62X6mrV5DAEwldwmJw94/V1F+ELvxxhw6zKG4wD0wnIs
         swssB25VhX/1cH5XE5A0wZGbnJT7Sh+aLZnS0ncQc94u79CxN/fmGBAd9uWGVTSu0RJ9
         BRXZyEICLfr7u8eNTiFJSBnNphqHjy9278DZJhEKORw1docLcik1N2j/lYMHzZgTgeYi
         jSgJSqlDeMNsJtrFgKDdoQknbLAR08bLqp6Vwko3EErWin6FLxz0WgEAqCJA4j2jFtN+
         FJdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:subject:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+kEPI3xbIHhQtbnVbPWN95uHI+1OYdcynM+OnZoyigE=;
        b=DVtgFmxGFIg2qgBEoCpmll9ykH0c8M4+eStVH94QEtKLKfxtQ2uTjBCzD3iy2sEkRB
         QMP3Yl3TTpnofTMjQkvLNYrso+u/qUalsClaeSfexpub0xe7ISFNVxXIQiPoMVd37Vrz
         CcZ0go8sFbgF8vKNpGrvjiVspwFVuk/I9EZd6+oookKIK8sN7vgMLN5KB3qFE8TKynt0
         C285cTZYObQnCvZF7nL4cf2WSkQyUQRVzhmY7ANo/qni9hyjxWGS4o7YrUqviUujOYLS
         ooRyiKpbI1SUuj6lzBXITE87B8W8+oi7Ziz8x/BRHzwbmkGqpGei/si5nYjoymmuColX
         QE0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:subject:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+kEPI3xbIHhQtbnVbPWN95uHI+1OYdcynM+OnZoyigE=;
        b=QNpXYWHyaGmd3mL6ceYZY3dDacml1Q9rJjjNgyVkKCGAG4lwKJDAyBfVrOBO9y07MG
         ve1vaGCQYaZzzS9Am6ItL5DHWoNcJ0WGHjTB/GBH4gnlVADh2gYtHRa8of0TAvFln0H4
         T9FKH6LkRUpwMJEBNCp9F8GTTVeO6aHqQcmgXmjQbqJ/bVP3WVZl4lNjIkGscx5juhK5
         t7wY6HdjHCLnnLPq1qbsUGlh6d8u2bFCf8Nh7O5h+84XuayUJS0P0iCOmkjI28OgSTc7
         NdYrQS7Fb8t7SmwCUOLi5E7xwiViYznfoRkHs+PZxJXUrGpFI76Itv42lnlMsNJGgdtY
         J7+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532E9f5jGCVFO8w+KwnUKQKvUALNQvsNR8WgNtRH0cthz/746+mq
	fR0aMKEkCKksG4uB9zsG2EQ=
X-Google-Smtp-Source: ABdhPJyzbdyd8QJGIaC+32cfk7lBhW0f481YrU9WpyNrlfwAznJ91FXdOTu2wq2G0WIQXh256gCKnQ==
X-Received: by 2002:a9f:25e6:: with SMTP id 93mr5123859uaf.57.1612010214462;
        Sat, 30 Jan 2021 04:36:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:4823:: with SMTP id b32ls926617uad.2.gmail; Sat, 30 Jan
 2021 04:36:54 -0800 (PST)
X-Received: by 2002:a9f:36cc:: with SMTP id p70mr5189767uap.137.1612010213999;
        Sat, 30 Jan 2021 04:36:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612010213; cv=none;
        d=google.com; s=arc-20160816;
        b=z5+fRapF1fykvp+Pagsz9h+8e6YtZWMAPwQhR08GeEIawuoYPS3x708kBFBIfddfOc
         LMjwJWXr2zRY67vfRfWA15x2uzeugBYxC/Y1KylYPITp0N/5h1ZeMT7dNrJVTDl48MTE
         N4ekN0w3SBDQ6BxOoHG5GxMvdsoMquc4zukLMQL3Aj8lLlbHaRhnGYNeL/nEfmZ4nWhC
         AQLEFuci0FO5OZxfz1f+52ng/cPgcFpRRgwK7ZwYKtGGvLUMkuyByWTvjSnN1+m4mtNR
         fnt1M43K4AJWGj1J+4BxxJLXaB6+i2g4pT8MONCjsRURPYyEUNAJna6njlO6TEPR2iW1
         ADrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:subject:from;
        bh=CmeZNRAW+5lhoExNC/bMZOxZx97qCE2bkagUnHGzcO8=;
        b=Y0FUfmvu0xpU74di3vkiT/kiBjIGm++n3O1ouX4tcR5eVDa3Ui6zZ4gfcTS29aliiN
         iQa8ujJZi1IbcFe5unBlcxC+p0mVVon9dO+s46/Kxqr01/XF0mY4T8Gg/2eUwwyICM6X
         hQuAjPAx6sqkUH9aOVUNflGzUqO8gTLu7gt0RKPChfecpE5XkHEAhtgexbTQ27YKiUYY
         /hO+QUaz3czczdMc502GqUIecdXmujeLDYbNC5Vzi7NxAi+sjbUYWOoSexRdYLYKe/6o
         2iijKEi0/GIzgnBPNqEI61P2270+NaWkBkN4AT9FCIf90jU9u2sYBD5HtNnBwo1tEaUh
         afOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p73si588971vkp.3.2021.01.30.04.36.53
        for <kasan-dev@googlegroups.com>;
        Sat, 30 Jan 2021 04:36:53 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 1F28FED1;
	Sat, 30 Jan 2021 04:36:53 -0800 (PST)
Received: from [10.37.8.6] (unknown [10.37.8.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0AA313F71B;
	Sat, 30 Jan 2021 04:36:50 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Subject: Re: [PATCH v10 0/4] arm64: ARMv8.5-A: MTE: Add async mode support
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210129184905.29760-1-vincenzo.frascino@arm.com>
 <CAAeHK+w5hHcN-4Q8KYpMnG1rQvz9N_kXc7=uY07nH=937MUTjA@mail.gmail.com>
Message-ID: <4e14f83d-26a6-b06a-7ef6-f11dcd5457d2@arm.com>
Date: Sat, 30 Jan 2021 12:40:47 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+w5hHcN-4Q8KYpMnG1rQvz9N_kXc7=uY07nH=937MUTjA@mail.gmail.com>
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

On 1/29/21 7:21 PM, Andrey Konovalov wrote:
>> The series is based on linux-next/akpm.
>>
>> To simplify the testing a tree with the new patches on top has been made
>> available at [1].
>>
>> [1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v10.async.akpm
>>
>> Changes:
>> --------
>> v10:
>>   - Rebase on the latest linux-next/akpm
>>   - Address review comments.
> Thinking again about this: properly fixing that tracing issue is
> similar to fixing the issue with the tests. Let's do both as a part of
> this series.
> 
> Here's a tree with the fixes. I've marked the ones that need to be
> squashed with "fix!". PTAL, and if the additions look good, please
> send v11 with them included.
> 
> https://github.com/xairy/linux/commits/vf-v10.async.akpm-fixes

I checked your code this morning and it seems OK (very similar to my proposal in
logic but done in KASAN code as you anticipated).

I am fine to add the changes to my patches but before then that I would like to
conduct some testing, hence I will most likely have v11 sometimes this
afternoon/evening UK time.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4e14f83d-26a6-b06a-7ef6-f11dcd5457d2%40arm.com.
