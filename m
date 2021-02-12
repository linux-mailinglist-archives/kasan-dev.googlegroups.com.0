Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBGHYTGAQMGQEPAAZV7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A3D2319F4E
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 14:01:13 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id c16sf9133425ile.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 05:01:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613134872; cv=pass;
        d=google.com; s=arc-20160816;
        b=URAvK6QiJBTfJ/ocY+RKy8UXvNNP3LUU2v98tg5qlnfJu1yGnI2LouVy5xcL409a6v
         cg2fKp8RYezHZPcvB2C7kFW59vS8+HYS0qtBBP5vulI+H8UwhLdT3ntxxAbrR2ovqHz0
         5CoXdH517/jRJcQHe3kRLT6LDV90r6WJF0KasgpbLqWXSb4IUC/U2dRO7Uw3d44vurZB
         FnyneJ0MFXo78skGnTUGO3j8Czayt+qli6fIeuu3vqw0//JJUPptOTKe4PJwocQpT7vh
         3RsGe1+FZxZXanFiRND867k2mTe9Gi99+b8RjIVYpVCkDzvY4VJCkxHW59v42vWpeLHS
         Vspw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=qWFwycLLw/4AbOLJngAockd5N+D7LYT4cRvcCDv+eA4=;
        b=fyriMl4jlExD4j84L1n0g/onAH/6d1Jt7jiW0Q1qm8k5yNfhVcU1I+AociCx580tyP
         uZULIvk+mJCuzCJgZv5v4c+00KRyPZyjEGh4CxYYKgCh6j4RnTUTGw+yUIVrtCJxOHBo
         xNnbQyQdswbSsO4Ueaovboi2OTibfclqSHOBomyNC9OOWAwdreQbh+ZhDZnxh4jaiLod
         PxAL3dPyuXAQBY9H3TAodT9MjIdW1MXa+J5F4zyf72dCnqeMtmroy/i2O3cCDXxYs5yu
         JLatOgjSjj3J3xdaHcG9qil38C9NdWflZVJ9TK5yvVUJGjI9AkHXE2dg3y1wAsoQzsN+
         QP7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qWFwycLLw/4AbOLJngAockd5N+D7LYT4cRvcCDv+eA4=;
        b=MJUZiP+/XSO4TaGu7sOEtIItFPU2mDhm+jcPt78LcimKg3Cr/ICV/evzh5kQ07h4wJ
         GVrtVhj/l+8v9jPgFO9oBnImuITpqjJeijzBAUjKUkbZozpWDOopZKBEURjHGk0zinkX
         mtyHx6evCKy+K2TUqK8WbReHSSa65ArlHYn5flxE0irRGb5TgT5JJnd5qCPXX0/UugJc
         4N0wNFOWjXKEHse8ghFGUmO1L9UiVg+cnT89+sJ0T/EzbE8XOExmbrwjs1j6zqHMTA/w
         Q9wDxms5DgzAuoLQO28XLoAat3lodkZZ1wHjKY3J3wH3cIF5zZ4djVM9dr+ajlOrbBSS
         aWDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qWFwycLLw/4AbOLJngAockd5N+D7LYT4cRvcCDv+eA4=;
        b=X8Y4JrNPRvyi3hE3MRguzrVFiGHaL1tSqLCNJ/P610rKs+O8Q3UgYLuJ+xhYfJduVv
         Pwof8iBvbsklMI538/2k83zlOhf5/VX4LsRII6KYDl9HmNNC+P40SGeZU2ifVqYF3K64
         bKyOif5nA7VvnQC/DM53hCidMc42jbmtYG+0+ZwKZY+HtlBW1kGTFYob4d/4AFTMSyc9
         7R3dMlbJGnFa7PGOMvqB3ccoAkMTGhyN9xRV1b6rMfqc3P2HzHDmeSaYTtYOVCz/A4g0
         p5giZLNu59CX80iJcZHQdoDU7u8Zhg7JP84ydhhJQTED5vlk9c+Y8wXmGETaV83C6vip
         Yd/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531yw9Y6vsPv053egfcMwCHSNZgEpYEUJvUTA3koz9tx+/wczQBH
	sxtCUGaxjG+DW/ZCnIX3Z1Q=
X-Google-Smtp-Source: ABdhPJyjN3H9JamIllSEl+Uc/ZDmIm/PRB20axW7s4p14DeLdkwBNvlRbpswvGmusRwF8bZ5t5uBhw==
X-Received: by 2002:a92:de4b:: with SMTP id e11mr2134203ilr.123.1613134872293;
        Fri, 12 Feb 2021 05:01:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7f0f:: with SMTP id a15ls2291034ild.8.gmail; Fri, 12 Feb
 2021 05:01:11 -0800 (PST)
X-Received: by 2002:a92:cccb:: with SMTP id u11mr2261148ilq.44.1613134871872;
        Fri, 12 Feb 2021 05:01:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613134871; cv=none;
        d=google.com; s=arc-20160816;
        b=CbWIORgEYeKgd86JgM7XCIIdYgRDu7Onis2IRj2gBUboOncuomSv9tf/tTW58cDXWY
         wPC0JFEj/i9vV5Q4yP2G79151YhPVK2viFfm4cLiDZuZbQrqMzy7Fd63OqSwLB0mycnS
         kbKcDawqn9Kj9q+7YXgv/cNZoGTAdTrOriLDMevSJjivKJUtDEiMK7LUWkuuYQfl1Z3h
         AA6T2GvjLnIxLIDlgvZEzGbHpEwQpx+c+tpg+lqs/xRX4VZLNSWmLqqyN8XHYmiCevsD
         qoBleOvZXUXKUY1NtJ8jNRpDzqP2tRvUrqG9SrDzlQ8W5Ogwjus0TY0ktu9IOP1n5Ak1
         8Lrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=PTenlBbFUctATyu2rcMilTcG108p8qa58ZJcEMz/3ww=;
        b=mukgtoZMvHe5S/dt06NTF8i537Yf6Kz1GzLWJp2g6fsNmVHhrziAfRKLYYNYkSmYv1
         QNZkMgcr3Uu95759bUhc/SXIGmLz4llj8CuGKiL1Tr6v3KAOxBl8X9Sb9hsOBCZysqLE
         ZnT5ib5YoTIXLQJoD/cfyTGsLfYbmOBQ1kLIeB+VieFk+J5Jj2eiYjcg9857KVQn+1Jh
         2KugPmN+ByFKkE+jYh31exWyFnprGiRxnqnSBnVspQiM3r8WRmMeUe2xatEDtrmQj5ON
         S0J/pMCqKWZ7cBiLRNHNY6+/KIA7PeKJcJ3iSxjguRdlt/8nZ20d5mHmtoOu7dCdMN0g
         wk5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id o7si384417ilu.0.2021.02.12.05.01.11
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Feb 2021 05:01:11 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 5001D1063;
	Fri, 12 Feb 2021 05:01:11 -0800 (PST)
Received: from [10.37.8.13] (unknown [10.37.8.13])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 57E053F719;
	Fri, 12 Feb 2021 05:01:09 -0800 (PST)
Subject: Re: [PATCH v13 6/7] arm64: mte: Report async tag faults before
 suspend
To: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Cc: Branislav Rankov <Branislav.Rankov@arm.com>,
 Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>,
 Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov
 <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will@kernel.org>,
 linux-arm-kernel@lists.infradead.org
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-7-vincenzo.frascino@arm.com>
 <20210212120015.GA18281@e121166-lin.cambridge.arm.com>
 <20210212123029.GA19585@e121166-lin.cambridge.arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <9d7b4475-dd59-d84f-5835-9222c2758eac@arm.com>
Date: Fri, 12 Feb 2021 13:05:15 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210212123029.GA19585@e121166-lin.cambridge.arm.com>
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



On 2/12/21 12:30 PM, Lorenzo Pieralisi wrote:
>> However, I have a question. We are relying on context switch to set
>> sctlr_el1_tfc0 right ? If that's the case, till the thread resuming from
>> low power switches context we are running with SCTLR_EL1_TCF0 not
>> reflecting the actual value.
> Forget this, we obviously restore sctlr_el1 on resume (cpu_do_resume()).
> 
> With the line above removed:
> 
> Reviewed-by: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
> 

Thanks Lorenzo, I will remove the register write in the next version and add
your tag.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9d7b4475-dd59-d84f-5835-9222c2758eac%40arm.com.
