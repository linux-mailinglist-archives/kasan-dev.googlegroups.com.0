Return-Path: <kasan-dev+bncBDTZTRGMXIFBBMGMZT7QKGQEUG6WIJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4709C2E9742
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jan 2021 15:29:06 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id gt6sf12235625pjb.7
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jan 2021 06:29:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609770545; cv=pass;
        d=google.com; s=arc-20160816;
        b=hrtS7UHgmz9w56a4/YZUrDR/8EIo6Ldi2Z3d5rxSsJYQBXbRDRk8adDARCfGOWHtYy
         WtjzEZvy3Vh2zfMcKYgqgLGEOvedXn//1p9+5lAJNy/EJVpfzqvfhwFk7fH2h/T9Ai/n
         BJPmYDiR+ueHfxBb+w3S7V+j4QnEux2pl4yOHAhSuUIZ3+oTerztb/MJw3cZZDqw0sHn
         Nu5x56+WAtTkg7eVDl8/6+2jrynkxT2KKPCU1Si+LPjf4GXChEd68GOmJDpywsFYGxAL
         F3OwgDc88nZ3N41ruPYXUtU6XQ2DKmcV86tqOvGo606B3pJ20MZO4g5GqdVuGNGFm+pD
         qTkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6V/NuDYj2Szj1dFGwPd6Mz6vOcE0syMpo/IMk6cqxBg=;
        b=CG3XrJ+GfCPja5U5WUcnOtMt7BYvuJfaFbijijbGi8NQv7KwIqezhOfLjVhFTwfDeQ
         c3ZizF04FjoAXwh74VUv7ilEQIC+WWTUrgHQZRmxOArqniCb5W1PaBtrRdzc3yQg76wR
         WgWJWKxC9fUlEydPsYKaTAW0aOJ6uqIVvyQoe7nBAr2k8JKWnVidrKocluejClsl+FWF
         Ap9zrYuJ5aHiHipiMvinnzsAx195IRB45Mp0T3SQjtAQi/4oyOY6M1M1IF3xgtJ7qn9d
         6r/XNcNdq7nNRiV1/ahKACJ1UUYiZxFWQgWGGkeUk8MuSXXjC/HUyqsuGfOKhgLpMHmq
         8F3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="LvB3E/G+";
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6V/NuDYj2Szj1dFGwPd6Mz6vOcE0syMpo/IMk6cqxBg=;
        b=I8mTvko2GsiaYBEqD1e+hl8+Ky15oW5tUvWgG3iQNUwb/VbuKK47MoaPGf677grsN7
         an0IbwUCpdcBZJagv57zfP8Cc603sGwRm6yoeuENBvUxRYP9z8tyO0PJNbsMxqLthw9/
         alBRR035nHnEjgG4hQ1UUcuFQJq3ejnW5P98OPPkFBrPsFBZfoILFdPiQ9tfGW4Rgw7r
         xLt9U7CeGo76ZEFBtRNfozNK+Z5K1XssRD4eoobWoQUc4ks0y2xoPWvj2kpbDdHR6NeW
         rvhTcjhSL+XtQmuUWMQ4xwqY0gEOJhQZktQ/PhBB8oBe8BJexsGNryYpy45OzmFnLeWu
         b+eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6V/NuDYj2Szj1dFGwPd6Mz6vOcE0syMpo/IMk6cqxBg=;
        b=hz8XSJL53CTUkFoVJdxnXUDrZeDfb+lR/sPQN1B37pOheMGuLBitHw6L1odFAnNh+Q
         uUt9U2qnd1yM8IFFw/9yoNhlq9Lhm4kCnV27h8xXj8mo963lvPBc30xiraWhejqB7+lq
         urK78XrQNenblY1YJE0oQK5HceS+/fV2Xw6S+pi1021DB7+/u3WVqEiFKoKedg9dcuMi
         2MrBequ6tOgHfy6EIOPZfYY638MaEsEtgBQF1yB6acRXpnvpMQ/Jk4rDwBRtxifEaGLN
         gHw/PkXLdU6SNnmx0ib95wXwvuDIlkgLsMRGMFWBly/LWiPKxtF1N/6EYsAPGw6s6/Pl
         FXsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532zc8vcL+ZmCJwjYJmmA9h63P92dG+Jo74KUPzd1wsa8jZrBNqr
	4BKrfQIAADvQe9YESDqzEPE=
X-Google-Smtp-Source: ABdhPJzM4qQMMoAyn9hfC2IreE6SuUONXZ3sGsziF7NbBTF/Lq3wjzw/79rLzcyxnPJU4yOTa+u61A==
X-Received: by 2002:a17:90a:e38d:: with SMTP id b13mr30461934pjz.101.1609770544994;
        Mon, 04 Jan 2021 06:29:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:96d4:: with SMTP id h20ls28371111pfq.5.gmail; Mon, 04
 Jan 2021 06:29:04 -0800 (PST)
X-Received: by 2002:aa7:978c:0:b029:1a9:1989:a07 with SMTP id o12-20020aa7978c0000b02901a919890a07mr45440430pfp.30.1609770544429;
        Mon, 04 Jan 2021 06:29:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609770544; cv=none;
        d=google.com; s=arc-20160816;
        b=04CYomOAnpFMRMJUXe8XRfyeQCSI9cLQY8uqsqx5gQ6AC4EjGREOKm/aC2m2LulogG
         mfeD8vz9+y1jTrVKx+L9K/QlpOK3z0che8UmuJmz80tTe8K1JvpTHiXwh57Mzs+JmjFA
         i5Oht6Oryg0YI24Po0j6JGBWh9Axu9k2KF+h0w8FBl4h837ZcrJmgh8ltK/NdQwdOW/9
         8I3L+73viksCX9DCgnqQCbA2jwfWM3o4KlK5jV7bfaTJ5eCcWAcBzkNWKSQva+ZssL/K
         T/MTYeAz9C5eyzlou5y+EGSpK79vInYUls99jZGZeQZ2YeEHxoWLzpB8hxhVdZ0cDaOk
         quRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Hi1SopwmgwxwPfqSLvfi9/TppcqQZE707g/DKi0+Z60=;
        b=LBSp/+C/milJQJZDkHygVx06NqGO+rIVz8JAZvDqG00X8+MBvPt+4QFGtGkkT0vg2G
         czxnLCGr169kHLhCCvk1jgB3P1B1O6k90lxfwHUR0I6m8a4KRsw2XPIGkFr41Do566AZ
         88zi8DYU9cSBK/0vTR+TNHUaFRIAlXNV/v8Lcd1vlDy/1TD08EEIYpCDi4BbQ0dYUlWv
         /SfjaWNcddc/anYdHiASkDGUd0CnIeEhBfEh4BUniJZI4mIeOnkHqhdEVo/uNRR/KsTh
         Vfps2w/cL8BVoGmzeD2THTBgZ5u37DLgCPuXYdvUQuJMeVXsmY87TdZ35QqTrKPQVgWl
         2gRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="LvB3E/G+";
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f204si2818568pfa.5.2021.01.04.06.29.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 04 Jan 2021 06:29:04 -0800 (PST)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 9CE4D21D93;
	Mon,  4 Jan 2021 14:29:03 +0000 (UTC)
Date: Mon, 4 Jan 2021 09:29:01 -0500
From: Sasha Levin <sashal@kernel.org>
To: Ahmad Fatoum <a.fatoum@pengutronix.de>
Cc: linux-kernel@vger.kernel.org, stable@vger.kernel.org,
	Linus Walleij <linus.walleij@linaro.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Ard Biesheuvel <ardb@kernel.org>,
	Florian Fainelli <f.fainelli@gmail.com>,
	Russell King - ARM Linux <rmk+kernel@armlinux.org.uk>,
	Abbott Liu <liuwenliang@huawei.com>,
	linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH AUTOSEL 5.10 01/31] ARM: 9014/2: Replace string mem*
 functions for KASan
Message-ID: <20210104142901.GC3665355@sasha-vm>
References: <20201230130314.3636961-1-sashal@kernel.org>
 <25b25571-41d6-9482-4c65-09fe88b200d5@pengutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Disposition: inline
In-Reply-To: <25b25571-41d6-9482-4c65-09fe88b200d5@pengutronix.de>
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="LvB3E/G+";       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, Dec 30, 2020 at 03:18:13PM +0100, Ahmad Fatoum wrote:
>Hello Sasha,
>
>On 30.12.20 14:02, Sasha Levin wrote:
>> From: Linus Walleij <linus.walleij@linaro.org>
>>
>> [ Upstream commit d6d51a96c7d63b7450860a3037f2d62388286a52 ]
>>
>> Functions like memset()/memmove()/memcpy() do a lot of memory
>> accesses.
>>
>> If a bad pointer is passed to one of these functions it is important
>> to catch this. Compiler instrumentation cannot do this since these
>> functions are written in assembly.
>>
>> KASan replaces these memory functions with instrumented variants.
>
>Unless someone actually wants this, I suggest dropping it.
>
>It's a prerequisite patch for KASan support on ARM32, which is new in
>v5.11-rc1. Backporting it on its own doesn't add any value IMO.

I'll drop it, thanks.

-- 
Thanks,
Sasha

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210104142901.GC3665355%40sasha-vm.
