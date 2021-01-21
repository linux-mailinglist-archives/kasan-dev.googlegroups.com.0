Return-Path: <kasan-dev+bncBAABBZUTU2AAMGQEA44ODMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id E8A3B2FEC96
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 15:04:23 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id 98sf1229247pla.12
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 06:04:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611237862; cv=pass;
        d=google.com; s=arc-20160816;
        b=NyianU32PTlZvmRl01WF2yXrUbgqGU+rNIseu8/XjVQH7OklstykSWV+WnQ8QQy8Y/
         TVQm/h8O1A8HyLFUFYnvbPXJjbeY/SMXSpSMVQYEEpHYG2hTcIji8Yoj/OraPyQ0ddtO
         cC7A61dXcpYEgUPS0OFy7t1VU4arvUXges26ZsxKpqTSQkSzDSSEV4wdt2NuN0pEVNjO
         n9Yncq66KxfPRFX/fslsA8sFq6YSQH4veBrHJY1QRDPqgYgEwxG3LBRisiYZIobN5YpA
         7i2egr9C/5fpi9LRayft9EOPqBE2wu7JI1OJYjxtWA4C1qNUQ6+nNhk/GtY64Xixk/fY
         WTLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=h7xqrKcA+6WY5RZvHgJl7aj74Agdu8yX2ylfjwWOJTk=;
        b=GK64WzJkx04jPnNH4bdTGcTlhX30YG18dazTsnAWVr6a0MXF0DpY95pq7zOhr8Q5Fw
         ztF9R1uUrzZMfR5eVv3LwbNZR76tCvndOkN6n+Qp6btMoOFA5rbiMsFfL7fa4/WtMCZF
         OOA/G0DRCjF/TcsykOTRZrBJq46/OT7rWV5FXbUFhU5QtTyDHPAAtvPiGavY0u4adqdq
         /kGSn2cKbegf2GOv3lZidJUdPT5SjfLcZRLQRfYHkXKPZwbjKVAg0mVHQKuIIeSRJM0R
         fn8qVHHG/lg8jd6IQKllm340hBHq5scY7NkoCZERRj3NAnb12zZEn1DTG6UDkIup3bLo
         B2oA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BlZJL9j+;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h7xqrKcA+6WY5RZvHgJl7aj74Agdu8yX2ylfjwWOJTk=;
        b=C1rl6mdKO5RR4ZFhqbjmF9hdnOMyrHLUQ7vkAAPc2nBFa40drDucPgHm2iqKQsROM2
         8DTXE1grMQVQXvGhjNysQEf2l4dxXzRkYAGYeywO8D76KnIIwFUAef4thPPxJbHPthAp
         LjcE8/94qt82lNqDSm9kSKdrwyiPRciTp+7JYhdRiCeMe6MccFUq/djShnMhDzgIQov+
         SjJtjHD7DBNOSK56kQd7+tZausLVMab8LgoxBkqGvKYDLymvfNdaoy8W59CUSoKI0QP4
         Qa+KLNuqbOJ0J23dtbb7aRGCjhX9ms8vzy73Um9fYD0V8NnrYB4PjlRmb1Nz6OE4Gj6P
         TVMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h7xqrKcA+6WY5RZvHgJl7aj74Agdu8yX2ylfjwWOJTk=;
        b=tj4XopGKPWC38w0GRY1nFETbvhgZJus1wOllHaGtWQdBSQvRza4XQkxawoC9s0EZt2
         B3OJ4FRJwypazqSp7wfmpBdmEv8kI8AZ+2VdREu+Ho4fF9V+mrN+SF2OgC/sLnv5zr+8
         Pst4p4VhmC9LsgURXkMj6BUgDJvs4oix17BBVxmVZkK791sOFClaQmWDqmgtu0QfFG+L
         fsHP5AZXpsArShOiQt3ypcaTuxjHqYB6otp/vJSVPWqKFc4jQRIMYxq+kTf1NnWRw5SB
         QRsa2K75HEH1iM2+FUDZcwWastPLQYdIkxi6q1X0GUZg61G5u1hrd+JxKz/kNlXu6ojw
         EvyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530mQwpGClk4ryEiVwtpCKL9N2V4nhe4ZWobOE1dPRQ/n/rL3oFB
	q6I8IQAq1q6BTrUOh1MUq+g=
X-Google-Smtp-Source: ABdhPJw0JyIc5rgVZoCNEWtD6yq1ZwFI7gR5LzGNbsugnCait1Ap+pAlm8d1qMNT+Iw25oTbYCiKUg==
X-Received: by 2002:a17:90a:6842:: with SMTP id e2mr12158227pjm.190.1611237862675;
        Thu, 21 Jan 2021 06:04:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4704:: with SMTP id u4ls928996pga.0.gmail; Thu, 21 Jan
 2021 06:04:22 -0800 (PST)
X-Received: by 2002:a63:d305:: with SMTP id b5mr14553642pgg.452.1611237862184;
        Thu, 21 Jan 2021 06:04:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611237862; cv=none;
        d=google.com; s=arc-20160816;
        b=qoafS8EAsSzJk4zJmFAsPRNVM/CFkSz+UL1VFhacBF6s8QilhQVtogVB5avXpit9U3
         VoTkgyPn/Fb+2TL5wmVZgcMrgD8ZCIpE04q/Yp7W7gefcjDchvOVuVdwyjCYDIPwTGj6
         41DzBJa35eXaFRPm7HGAcyW7Crj/xSrqw4lI+kLk89TyuxGYc7kCygueXqYxpnWvwRpT
         S/DA5HBnMnwF5HG7qM4ZisRp6Fa3xDzYXiaW23G/WoNa+EthFv3+L1dFWrUC5L0ATzg+
         7kuXP4ZMALUEw1fupS7yEkKtGSRgfgpSzCa8B14NQUdkr3BmUpN/etu74yEQHvLfz0I4
         XyDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4cg9PuOHP1xXJ/GhNKih0QNpJbf4x0vvMerVXw7U45s=;
        b=kkXOL35Yq+NJHO2CywZ2atUzvEbNslDmS/9PrnaKx6kJioc+Ju8eqHrkEVDeEXiA9Q
         SLcQ8Qdag60CiKuv/UZo51lsDEcaktocQAxq1/Oihtgs+1im+BFe6SiF8M14Tm2xRMQs
         LqrdtjWfAhammTTgnsxZ9gN2FFV41GgI47mcnRsUE5ZC8F0FYK7vLQtnVLrAVLEGKHPh
         tJJLgmwhysubm+9oMxracnNMGxHzbaqthjKTzsa5hMxt6QH0148YAGF6TIcmvq3DsMun
         21fn+TDxcSD1iWlNdvP2WNuREu0wHXBjmrs0UfWRvYUfdSxJik8wtpLkZu3T3dQ39D7U
         V3lQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BlZJL9j+;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g11si417310pjp.3.2021.01.21.06.04.22
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 Jan 2021 06:04:22 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 9C9AA239EE;
	Thu, 21 Jan 2021 14:04:21 +0000 (UTC)
Received: by mail-oo1-f48.google.com with SMTP id k7so518052ooa.0;
        Thu, 21 Jan 2021 06:04:21 -0800 (PST)
X-Received: by 2002:a4a:bb01:: with SMTP id f1mr1459614oop.66.1611237860846;
 Thu, 21 Jan 2021 06:04:20 -0800 (PST)
MIME-Version: 1.0
References: <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
 <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
 <CACT4Y+Yyw6zohheKtfPsmggKURhZopF+fVuB6dshJREsVz8ehQ@mail.gmail.com>
 <20210119111319.GH1551@shell.armlinux.org.uk> <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
 <20210119114341.GI1551@shell.armlinux.org.uk> <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
 <20210119123659.GJ1551@shell.armlinux.org.uk> <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
 <20210119194827.GL1551@shell.armlinux.org.uk> <20210121131444.GP1551@shell.armlinux.org.uk>
 <CACT4Y+Yj5T8PKadhN1jL9D4EnXd04_-EvCQgYMVM2rQ0g4ARXg@mail.gmail.com>
In-Reply-To: <CACT4Y+Yj5T8PKadhN1jL9D4EnXd04_-EvCQgYMVM2rQ0g4ARXg@mail.gmail.com>
From: Arnd Bergmann <arnd@kernel.org>
Date: Thu, 21 Jan 2021 15:04:04 +0100
X-Gmail-Original-Message-ID: <CAK8P3a29_Yj1jBPGLTOBc5_nvN7o6rSWT6O0KA+XvitR+aJmQQ@mail.gmail.com>
Message-ID: <CAK8P3a29_Yj1jBPGLTOBc5_nvN7o6rSWT6O0KA+XvitR+aJmQQ@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Russell King - ARM Linux admin <linux@armlinux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Linus Walleij <linus.walleij@linaro.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	syzkaller <syzkaller@googlegroups.com>, Krzysztof Kozlowski <krzk@kernel.org>, 
	Hailong Liu <liu.hailong6@zte.com.cn>, Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BlZJL9j+;       spf=pass
 (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, Jan 21, 2021 at 2:49 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> On Thu, Jan 21, 2021 at 2:14 PM Russell King - ARM Linux admin <linux@armlinux.org.uk> wrote:
> >
> > The PC value in the ELF coredump seems to be spinning through a large
> > amount of memory (physical address) and the CPSR is 0x197, which
> > suggests it's taken an abort without any vectors setup.
> >
> > I'm currently struggling to find a way to debug what's going on.
>
> I wonder if qemu has some kind of tracing that may be useful in such cases.
> Some googling shows this, which seems that it can give a trace of all
> PCs (which is a reasonable feature to have), it may show where things
> go wrong:
> https://rwmj.wordpress.com/2016/03/17/tracing-qemu-guest-execution/
> https://github.com/qemu/qemu/blob/master/docs/devel/tracing.txt
> But I never used such heavy-weight artillery myself.

I tend to attach gdb, in one of two ways:

- If the bug is in really early boot, I single-step the instructions to see when
  it goes wrong. Using 'stepi 30000' I see if it's still in a sane state 30000
  instructions into the boot, or if the registers are in an obviously
broken state.
  From there, I can bisect the number of instructions after boot before it
  breaks, which usually doesn't take that long.

- If it crashes after setting up the virtual mapping, I use normal breakpoints
  to see how far it gets, and bisect init/main.c symbolically, starting with a
  breakpoint in start_kernel().

Of course, if it doesn't get into start_kernel, but there are too many
instructions before the crash, neither of the two works all that well.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a29_Yj1jBPGLTOBc5_nvN7o6rSWT6O0KA%2BXvitR%2BaJmQQ%40mail.gmail.com.
