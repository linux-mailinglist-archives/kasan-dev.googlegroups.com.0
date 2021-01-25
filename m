Return-Path: <kasan-dev+bncBCT4XGV33UIBBZEVXWAAMGQEMN4Y75Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id D744A302F5C
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 23:49:09 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id z20sf8867607pgh.18
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 14:49:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611614948; cv=pass;
        d=google.com; s=arc-20160816;
        b=dgttEyBl61PiOMZvjdDGIdnsSzx4l3yh/wVbxTYS6/i2MpaHq8pyTMMjQhdRbS2kcR
         jP2/JsZYhCTYbh+VxwgUzH0TQIsuL+t6WEVOFW3Yz5zKnIgSS5ZjsxZmo4I5xnaXLQmb
         UwES/O6TBD4HwE47qGN/itK76vxqG+Ftsx6k08635aEC891DJh3GKJcAUdrfIqi1MOFN
         F3cP3enEcA4den5dqTzN4o8ytsDT1Ue2JH6rspj0U3eAOqyloVMHqMekT9qpGQl9af1v
         AwSlMPnLHHx24d/V7XznwuquDW489bzShQnbphdsuiGB8JdcBWQSRO1TjKw+A6mhKSUD
         X8wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=PWVPLUVdfsrbh9stgc8GLK4fd4ZWYlQ3+5y7PU44tNw=;
        b=HRlocNdQ4oSdumT2xcSjgtjE/s/WYAag0rSU2bFAO3NmojCtlpLH5GZy8f+EqrqgfD
         wTYUN8KdXx6wPeFKAqvosBR4d8zr0wlw8IhZrwMyy71qYADAY7S26t8LrgYzSEkPspg7
         GQGCsdcVYzP6rCYFF5wUXsoD4Lx6dpkNqu4eYDKbsJYc1rG1X9gqLYLdYHO1iy4S6ws1
         3HAFT78uQSQIEyhw18J7IDqp3hUttER0vjntR4GAlGyeHDvWglNkYMT40EL77jKYahhk
         1PDdfMs61YzgIJ0Krf0DOCCjfFE/xw13sHtQy1diYk8xLqOZ+5QdFq5vEVQraTdLnWWx
         p/YA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=CcSoT0Jc;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PWVPLUVdfsrbh9stgc8GLK4fd4ZWYlQ3+5y7PU44tNw=;
        b=FwcCmLxQTcVmoiZA4py3ivLf2TCYJJQdB2Gn/qpPaYnBd6l70Qb/df9SOaa6SXNeo8
         OYtxShGlPxeQgHsf5qQQsFL2YH0VaN8NEP0u+L7rqNYW6hfJyih0AaO/Ked1DtvN2meP
         PptMUnO9EWYeWoP7oZ3190ZQnI6GVvZlhfhz6bFtlY+ymlaCCFkfgY+3RXFtHK9OFK0p
         lVrBYQFi22Oi4wYuF4xTxlF5wDDfZjtYE01m0IZowEiSCoLjcmn4hXXdeKfYiKAn0bzA
         2mzPGPtKFSmpP6qqICWS3F+e4HuvZ6KVtA+kv/c0ursP2jfD9i2dp6vwctVs9vj7oTr0
         ikww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PWVPLUVdfsrbh9stgc8GLK4fd4ZWYlQ3+5y7PU44tNw=;
        b=HA2eBJeuptpNbceAQHPKHouRuoCvL7GPqQ7ZcZ8GAJuD34OaUbWj4hkytSiBHvkpRT
         5DDbxbAoUM4WV2jW3v3zH3wTdAX/B+KQb84IFQAq5OcuVeWSB04kEL3t+w+FG6ke6Usl
         Y3mq1SwE4Z5DD6l2ewLaL0KKxQxbrKNT9Fwzdvbo/AZRCEvAio5MwjrnHwk6S947epM1
         sPhyA+/tmYqpamwdEDjbuAOKR+HOy3VmmUSYHhnJXMkK8xpwMnRxu6MBdsPNVHX51f3p
         ELb21YcQhYltnh7Nb/26YwHKINYjHqdrN0InzzhP0m8ALOw0+KvRSNjIktGF/lSEPpPi
         v3CQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531CFX+26QZMW4JW2hXF7G/XyeQFZT6jiURt/rfLMIhi7ACz4B7S
	At8aghzFuWAqhhikyG9YaO4=
X-Google-Smtp-Source: ABdhPJxm9eKU9Yn2S5OiAoxYmM3nzQGy7jihl7W6cuLEfHCqWQb5mXZeX96VycxISSDSFNlt7usvZA==
X-Received: by 2002:a17:90a:a10e:: with SMTP id s14mr2502993pjp.133.1611614948647;
        Mon, 25 Jan 2021 14:49:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:fb01:: with SMTP id o1ls5312506pgh.7.gmail; Mon, 25 Jan
 2021 14:49:08 -0800 (PST)
X-Received: by 2002:a65:608e:: with SMTP id t14mr2724754pgu.436.1611614947986;
        Mon, 25 Jan 2021 14:49:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611614947; cv=none;
        d=google.com; s=arc-20160816;
        b=rveFwTgir/R4zrcpPl8pjWBLw6owkFDOn2+J81PMlxoONbvSvNQ3S/YcCctO9JdzNx
         QtARAsLH/pGiNuG8xTrInCqemmRpdlrtkwaU/B3RbIbRdfIrf/12DjJiVuFt+Sxx1x+x
         QkveoU7g4xYLzzw7LEGp/qt1SujwV2hiRa4hD8JL1rjMkCUoRPd1JsCZBKPWYmavdYjC
         ScmIYHK+oRTQKkcUYGtWyMEzItaNNt7b70TWR0JJ5/BclKOBwBY9/9NXjnU8ZM0mrAod
         ndcJmuZ/YFIT7HkvPWKvPfO4PaCe4AJpSnjKVyMrN6O3oG6ViACgC3l9vucBw6DMfOZm
         SGww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=tApU4rCovaFn4InxVjja30AHqLuj7YZXeNxsX4I7ZOE=;
        b=zHvVSR+vSbjuJh032JClOvtbEuRAfsP91tvewB4FiPaB7OXaqPqdFgwJfaXCXoS3MJ
         SxAiHQ8k+36ronDEDFkI2J3m+DAN5Zv3aqccODpPpmG76To6I6bifKeqweV4eWAxw9ZL
         2RhhF0v52VPk+ZW3X2p5gHDRc3du7l9k5FpPbmREXJPKzWr55AjzGJ2cY2OPKQsS2tDO
         +V1tZ5Q5T3HY17scObY1eTQgmM8ed8Wnvvrj6MxJAVu4+1Kjbe9POJ0E9qIINUmDq3Rd
         wqM6drDfPqsq7EKBaX+SQiiNmwNnE5hq4d1Zwo0vBE1/u2XYl1EqK7cgicFj/2CEXr+x
         /QFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=CcSoT0Jc;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m63si903695pfb.3.2021.01.25.14.49.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 25 Jan 2021 14:49:07 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 62090221E7;
	Mon, 25 Jan 2021 22:49:07 +0000 (UTC)
Date: Mon, 25 Jan 2021 14:49:06 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: Anders Roxell <anders.roxell@linaro.org>, Alexander Potapenko
 <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: kfence: implicit declaration of function
Message-Id: <20210125144906.0115ae711abfcf757828d828@linux-foundation.org>
In-Reply-To: <CANpmjNMzwa8kEY0GRP1MwYZJsLA8wL031W1cO4CvxQL4Ltvrkg@mail.gmail.com>
References: <CADYN=9L7q8hZKsfmj2m2k2HoPSTqm=Y1SjG654e-uK1gutg4fw@mail.gmail.com>
	<CANpmjNMzwa8kEY0GRP1MwYZJsLA8wL031W1cO4CvxQL4Ltvrkg@mail.gmail.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=CcSoT0Jc;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 25 Jan 2021 13:37:51 +0100 Marco Elver <elver@google.com> wrote:

> [+Cc kasan-dev, akpm]
>=20
> On Mon, 25 Jan 2021 at 11:19, Anders Roxell <anders.roxell@linaro.org> wr=
ote:
> > Hi Marco,
> >
> > I hope you had a good weekend.
> >
> > Sorry for the direct email.
> >
> > I can see this error showing up again [1] on todays next-20210125:
> >
> > n file included from mm/kfence/report.c:13:
> > arch/arm64/include/asm/kfence.h: In function =E2=80=98kfence_protect_pa=
ge=E2=80=99:
> > arch/arm64/include/asm/kfence.h:12:2: error: implicit declaration of
> > function =E2=80=98set_memory_valid=E2=80=99 [-Werror=3Dimplicit-functio=
n-declaration]
> >    12 |  set_memory_valid(addr, 1, !protect);
> >       |  ^~~~~~~~~~~~~~~~
> >
> > Have you seen it to or do you know what happened?
>=20
> Looks like "kfence: fix implicit function declaration" was dropped
> from -next?  Andrew, do you know what happened? Is the fix still in
> -mm?

It's in there.  Now moved into the secretmem patch series, as
set_memory-allow-querying-whether-set_direct_map_-is-actually-enabled-fix.p=
atch.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210125144906.0115ae711abfcf757828d828%40linux-foundation.org.
