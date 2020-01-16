Return-Path: <kasan-dev+bncBDQ27FVWWUFRBY7L77YAKGQERXMIBAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3a.google.com (mail-yw1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 52FD813D3C9
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 06:34:29 +0100 (CET)
Received: by mail-yw1-xc3a.google.com with SMTP id z7sf21504520ywd.21
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 21:34:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579152868; cv=pass;
        d=google.com; s=arc-20160816;
        b=v0UWriAMqcwwFUJdHw4DXt/TPRLlba7akPhR+/XTM1dZ2ZXFaqRxlYZnr7XTTriRqA
         UPG2MMamBJEsnk6KC6lXJ2qUgMMgztr/y9FAAARnHCuVTi0RgQC10b7NJp4v62mliWms
         tTK/dMCKgp35jOu+/792tkQ9K7bN8PXFHFwVjlMUq0koT/NIWfH+mIWpJDlFYpjK4P6y
         Xr9qqq4rm1hFOmJxE5lKSRjX0WN2qoqD8qK/2QrZYyhpMXxJel8/93V8nD5R9IkBY5VT
         FGrv2O6di/ckHlE7XJdQhdmbCXFSqOloU2IASCg73t2q7Ym5TAWuuWIyC5LcI15lm4gy
         mzgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=xoFeWDiPSjF5b6TFoPzneY1jzx/Tg2WDMM3NnULDu6w=;
        b=xKXSziL7sGALSXy1xCfAW0ThZYPZY6K7zm09/gf6rZQFnzsPouGk5pEI3QUhAEeaRa
         IoOJs+MLc1AtRewJDzwyYydGtrakNuyoYhbeUK3Cf1FSoj7/hP9b46uOPd12aRIX35uC
         SYRlhwcXh/krxCQCVvhP13Y2BiBySlciM9xX2dr86SyCK6tUsMASd5+I+7IPtGbCoEJg
         WxNkBSgJsSbXS5zEPPdMJXZAVeWqeSR0x4TM0U2zhKtfc86HvjThXgfrC7gyT+tr28dU
         AmyiFTRtdKplZWbXB8Nt7BtTQTej+YoLfofovLYsKEqpqrb9jn2uXFjM6kmtdShacAxN
         TgXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=ZgcbuRsf;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xoFeWDiPSjF5b6TFoPzneY1jzx/Tg2WDMM3NnULDu6w=;
        b=juKzobVtWV3GkiW1kLH2J+bYPeacYeDJ0+Jt/bNLc6MyZ6Vf3G0wvLDxN/WCOUtzEz
         L3B26HG8xymBU+aUxHk1J2fQn/P7ACF4SYB9j8KhqcB6ZQYqs8XVAqey5RCdwast3QnW
         A0Egpi1Vd7RNPuwA79Z02+K4NLIEoK7alXsfA40KWDKXS6uUHHWUaKbF4Y8qrVTPCMal
         ZsBKgAWjxwKWOkHqsXsqyWZVuPG2Zpigi2KubbIEa5AerLjWV3sWrFzes3mOpXCBfALf
         ynCkuo7AEflkOffzNpJlidJGQycgDJ/7SqA7wuPtWBOCFKRPIvsFnCdu5Oj35Qx+h5jv
         ZYAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xoFeWDiPSjF5b6TFoPzneY1jzx/Tg2WDMM3NnULDu6w=;
        b=QplV7D8UZ+6iQvH5vLiKfZ1qKaNg8eStNqDINR0Cd2AMUhUvTS78bpn8edlqvNc0Gx
         X37KVWA/rJx4vqb3M6hjmCRAQo4YDtfBsVRfERzTvvHzPjyiDH/eXizdUYOQB7V122ax
         cc95+6LhnR+35E56GiRjxKnUlih3N/FKt90MD4bAIMng5b11ksjlcS5uThNc3/BMSu4X
         omzLflzFH2G0ektrjo6yzziJOtJhgCSXGE6zgLApYMvGHDsi+DGiVGf+8yRqgLwkeent
         Vf4UkZcft5UZBIiEw5Ab4Pcxi7L5qgvUdnNO7RE3+KgwemkmlsssPQIajLbo+iXh+1zs
         AZfQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW3MkhgcTDpoQbWgadMDWxseB/gkmyWJqPWDtaxbYz+yueApmBV
	QL8n68OrRBm5ukr11/w3VjA=
X-Google-Smtp-Source: APXvYqyeS6FAtPeWmiY9qoalj/dCzlCjqtzN6dU2APyX0UPfN1KUseVWMEecz68z4GbhWi+xmfQWJg==
X-Received: by 2002:a5b:58b:: with SMTP id l11mr23875118ybp.258.1579152867880;
        Wed, 15 Jan 2020 21:34:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:df8b:: with SMTP id i133ls3394304ywe.7.gmail; Wed, 15
 Jan 2020 21:34:27 -0800 (PST)
X-Received: by 2002:a81:6d4e:: with SMTP id i75mr25341529ywc.487.1579152867444;
        Wed, 15 Jan 2020 21:34:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579152867; cv=none;
        d=google.com; s=arc-20160816;
        b=C+uroRuOcONVb6xIZ448S/GbcOT4olw6d9D7bVM6QaVqSDSHjsRPmA26GFKq8Gb/Ei
         TjHSPiKHB9ZJKqH+WB4jh3kr4mWHzBEik1UXTlbEKxo8Uj8MuDFaY9I7+dZxP03YI75k
         tvctkevdnrZmTu2GY3xV7xlMnp+fnoO29pRgKGE/ZbcuLJivnE+rVTtR5zHqoRnsln/P
         1s35ar24NVsIKeLJABfPA1x88zXW1h0eZ6pX3FPIfcr+NpkQnv6sMaH69nSCgwtwyiyv
         Vh37CdNzQq2TmQQaX26Wktf163HQ2RDor4/oGrh2T8jEOodP0ussA766acrbPxgWX9Ws
         xohg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=OjhLrwSUixWKfHPYVjag4pJ4Twky6Gk6dHImQohRolQ=;
        b=v8xxW1C8Jvu4Sw7vyz1Syu6c/xk1MyFkj6ZxIVSvr11vJQGOVzsjNoywMDX1df7GWG
         TvOnWoACOziHbCgg2qr0v3osPD6uUinZPgr3cziD8t+rls7HcdNOsdcSeDREO64u/vP9
         h/1joGaSqsHnLsMb7vfQJj4JkYLlKilgmY/JqUabojHeOXuV9wGvcNp7D43vu8qU9ImT
         pZkdFxhYUldk2Eu6yTeROLCMDifMGdegcQLZlKN5xxOd/n42wjUwo1GYkhKK4m3ET7RY
         fX3sC9C4hmeLcwkdbFlb3gsIpCRC0+0aRfxdNk526oqM73CrPGb20+NP06FxjZY4wWVF
         Bo8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=ZgcbuRsf;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id v64si1173567ywa.4.2020.01.15.21.34.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 21:34:27 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id l24so9319098pgk.2
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 21:34:27 -0800 (PST)
X-Received: by 2002:aa7:98d0:: with SMTP id e16mr34318946pfm.77.1579152866617;
        Wed, 15 Jan 2020 21:34:26 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-097c-7eed-afd4-cd15.static.ipv6.internode.on.net. [2001:44b8:1113:6700:97c:7eed:afd4:cd15])
        by smtp.gmail.com with ESMTPSA id p16sm24333466pfq.184.2020.01.15.21.34.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Jan 2020 21:34:25 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Dmitry Vyukov <dvyukov@google.com>, Christophe Leroy <christophe.leroy@c-s.fr>
Cc: linux-s390 <linux-s390@vger.kernel.org>, linux-xtensa@linux-xtensa.org, the arch/x86 maintainers <x86@kernel.org>, LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, Daniel Micay <danielmicay@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH 1/2] kasan: stop tests being eliminated as dead code with FORTIFY_SOURCE
In-Reply-To: <CACT4Y+Y-qPLzn2sur5QnS2h4=Qb2B_5rFxwMKuzhe-hwsReGqg@mail.gmail.com>
References: <20200115063710.15796-1-dja@axtens.net> <20200115063710.15796-2-dja@axtens.net> <CACT4Y+bAuaeHOcTHqp-=ckOb58fRajpGYk4khNzpS7_OyBDQYQ@mail.gmail.com> <917cc571-a25c-3d3e-547c-c537149834d6@c-s.fr> <CACT4Y+Y-qPLzn2sur5QnS2h4=Qb2B_5rFxwMKuzhe-hwsReGqg@mail.gmail.com>
Date: Thu, 16 Jan 2020 16:34:23 +1100
Message-ID: <87zheoj76o.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=ZgcbuRsf;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

>> >> +/*
>> >> + * We assign some test results to these globals to make sure the tests
>> >> + * are not eliminated as dead code.
>> >> + */
>> >> +
>> >> +int int_result;
>> >> +void *ptr_result;
>> >
>> > These are globals, but are not static and don't have kasan_ prefix.
>> > But I guess this does not matter for modules?
>> > Otherwise:
>> >
>> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
>> >
>>
>> I think if you make them static, GCC will see they aren't used and will
>> eliminate everything still ?
>
> static volatile? :)

Yeah so these are module globals. They'd be accessible from any other
files you linked into the module (currently there are no such
files). They're not visible outside the module because they're not
EXPORTed.

Making them static does lead to them getting eliminated, and 'static
volatile' seems both gross and like something checkpatch would complain
about. I'll leave them as they are but stick a kasan_ prefix on them
just for the additional tidiness.

Regards,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87zheoj76o.fsf%40dja-thinkpad.axtens.net.
