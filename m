Return-Path: <kasan-dev+bncBDYJPJO25UGBBSFPZL7AKGQELR7GGMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 523C32D6A64
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Dec 2020 22:48:57 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id i184sf8497730ybg.7
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Dec 2020 13:48:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607636936; cv=pass;
        d=google.com; s=arc-20160816;
        b=z656UqvUqiQYSbsbB0DTD1CNB08L043kajbQo9s26zQTqSB+iEbeoiuzelgFeKxsvZ
         M+OsqTpBzIEZzPFqGExXH22dTyrPkYIzWPbew9p9lT1FmvRkMwvSpaSZaGOO+1v+X+Tz
         AvEyeBLuaAvGUNOkqYaeez4oBcHhDO3gpzmHsyc3zg4E/Vw/H/w1OWX/mYjoFY9uTMj0
         MaFmh+1/uALttHftPbVJV+t6a0DdITwx/YRN8LLps/bk65w+Bwy0RJydSd8Dtfan2n2Y
         UU5eSxFcCnYa6HQUwmwXGCxPfl/EV5o7PxHtYGmee2skH2HPsMnx66R7TuyUqXOWXbMU
         ITNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AFFNdWa5sw1mZFrPcpYoL7mJC8Xi0Sh7M9SHClj5HrI=;
        b=IAru6/oM4FRtEf6RVTq+g2frWHMpXpf8LUwVLQfu+f/UXxxUpULTLiO2ktjEmhJxNQ
         4+nzJzqnyfMjnYjXaGeOzmQAAcx0xkJfD1l1DiltQYjoAKp5YxCmg0DP2xhD60DKAPKn
         dFEIZhv1ZWBEEJ5mXdcgJimhd7KhHde5nAbKDBtzRaDFpyrR7KfshGY1GoluY1y1kLe0
         vdVnmosQ7yGHHevmw+86mQjizvNGyGkhrODcoN19OBdMpXPOSZak/lbBGa7x3BUKvJLQ
         ZglDxX65DhOjr2l7ED2gwPWWIk00qYFjK7DDbSHi3FPvNAenJWpZ06fZ6CAJ9r1yTizG
         VWYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eyVki26Q;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AFFNdWa5sw1mZFrPcpYoL7mJC8Xi0Sh7M9SHClj5HrI=;
        b=doSqe021t8MMOv/LQ63aNsEHeCYGmnPLjDjUkkZaTXRbYJKLm0jEGAtB/s5FEIKOrn
         Z+gyRVVi19AzHaqq2ervE9wC1Rnb38abVsIXGpuGfgGpxKjtbYCOugOJd8PFRpOchv1x
         kqE63yTTUInKUI0tpU4itMJtT5FBBSYYq0rnhOSO8P6N4PLYysxnGLbxbCJ8hHT75zzN
         mQnfLzNBoVZPLdUFRN3486CxpB/OxX+yMrsJ3NDJ1ITsDw7lDL+ext0SzK8wcHayVRqg
         mLsDPp5MzN/Y17vJKnl3ZZ3P0QZHyxveRkPDZhGpWPiJ4Pulv/5wqfKEQ8y6k463BXUm
         /xhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AFFNdWa5sw1mZFrPcpYoL7mJC8Xi0Sh7M9SHClj5HrI=;
        b=dHGzzWURXjvi3VI0sUyk4KnFiiMZTsns4EegtyO0ltmTzcob6Lqu7JddXH5I0+NTkk
         i18m1jnLA6+3gjdi0AhJL5xk6yN5D1X0/tUaNy9QbBjcm8O3ItwTOwnkifQWxv2uwI6K
         kU9thgIALJiZVsbOXKe0hvAFhEJHB51qQvbRwTLSsL0ku25hSTYKLVBdMlUyEOopRJA7
         T5BAIoECGC4HQRQoLpDEhzM+SyQ7NRYXiaSA9kAJaFSK3A/P7MuQZoeyO0WtFqkpM2GN
         YrWzMh6K2hW/zX6LMJgnthMMlX3lyRh8pfv23Q488QNaQueIxvA+dHIjLXUOpl96hiiA
         w9/Q==
X-Gm-Message-State: AOAM532h4GR/6kFOJbU8PKuLmvnxGHSU/v3C8zU3SzbpWW40VmMQJ1oy
	29S54nd5gmQMwu1GuWU/fBc=
X-Google-Smtp-Source: ABdhPJy6Bw2+RV0XUoiAaZwr/3KGxYyUggyQpEyqm3X80gFoJRjWx2KhuH3QI9fR8Opu3nRnLjqisA==
X-Received: by 2002:a25:5c3:: with SMTP id 186mr13957299ybf.131.1607636936159;
        Thu, 10 Dec 2020 13:48:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:77cc:: with SMTP id s195ls3237841ybc.2.gmail; Thu, 10
 Dec 2020 13:48:55 -0800 (PST)
X-Received: by 2002:a25:6d0a:: with SMTP id i10mr13840971ybc.445.1607636935691;
        Thu, 10 Dec 2020 13:48:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607636935; cv=none;
        d=google.com; s=arc-20160816;
        b=LJpiwONSYrOD22niex81OAoiFe6RAINx0p0y/R1cf/oBhjejoFiKDIeoNUJ7B2gyrM
         kSqUcpSubLSl9AIFAi5XpJTXm4PYKLnkiGuhHiChjzQfbAm8EnTOfxZUG9uDak9eyJ3b
         qQGak5jeVPTHXfQIhfUyKkU1Dwzr5XtnsKiyBz2a0k5Ve28s6McNQ8hfVNUdYXsf4y9h
         KbTtcpuZs0/GsS4WX4OqE3ieiOjviY2WjYhtShTq+ttN0MgX3LYdCofSLS8YMFhxlnzZ
         kpZilmWY8+wOkAYn1NqfisP6561uditdZkzt++GR48LSpHvGuvsTY1AodRmKKLgV+7cQ
         yBXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FDWcEk/bsx49QrHA7le6QrzeyX76Cr1G90wWwfXt9og=;
        b=o5XvVoRfeSZfSjZdCoPv1yir5fGNHXCpM9yz6qeuNptEFuVVJztn6Fspi0ocE7AoHC
         OrvGlYjBBTaHEU2M3aYYSkLWYegzazZcW6UJufFxi+pW8zx++AhoL9/XzoPWOdQ+5dKA
         5KNB2WHB/P7Q245liW1fFHtdKIdWkOpRxhXf5YzZ9l/jiZWnV1Rp45CfXcQr0Ante+Zz
         VS+YxkVhkE90EnG9tto7+lH/Gf4+41UOIsmdHZkIcXNS0afQeHBDnYZqcWtAo2el2p41
         QKBtqsTHjksr54pg3g25BfIKXg7emgBWszRsqWD/r2QQQRBWud4uX9bkKHOprnq2gBiW
         8hcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eyVki26Q;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id u13si428304ybk.0.2020.12.10.13.48.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Dec 2020 13:48:55 -0800 (PST)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id g18so5527667pgk.1
        for <kasan-dev@googlegroups.com>; Thu, 10 Dec 2020 13:48:55 -0800 (PST)
X-Received: by 2002:a63:184c:: with SMTP id 12mr1082455pgy.381.1607636935147;
 Thu, 10 Dec 2020 13:48:55 -0800 (PST)
MIME-Version: 1.0
References: <20201201152017.3576951-1-elver@google.com> <CAKwvOdkcv=FES2CXfoY+AFcvg_rbPd2Nk8sEwXNBJqXL4wQGBg@mail.gmail.com>
 <CANpmjNOUHdANKQ6EZEzgbVg0+jqWgBEAuoLQxpzQJkstv6fxBg@mail.gmail.com>
 <CANpmjNOdJZUm1apuEHZz_KYJTEoRU6FVxMwZUrMar021hTd5Cg@mail.gmail.com>
 <CANiq72kwZtBn-YtWhZmewVNXNbjEXwqeWSpU1iLx45TNoLLOUg@mail.gmail.com> <CANpmjNN3akp+Npf6tqJR44kn=85WpkRh89Z4BQtBh0nGJEiGEQ@mail.gmail.com>
In-Reply-To: <CANpmjNN3akp+Npf6tqJR44kn=85WpkRh89Z4BQtBh0nGJEiGEQ@mail.gmail.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 10 Dec 2020 13:48:43 -0800
Message-ID: <CAKwvOdn7c20vATaJMzsMYtCngs6ZDQMW8LX9ywhARxL6OKEdNg@mail.gmail.com>
Subject: Re: [PATCH] genksyms: Ignore module scoped _Static_assert()
To: Marco Elver <elver@google.com>
Cc: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Joe Perches <joe@perches.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Richard Henderson <richard.henderson@linaro.org>, Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eyVki26Q;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::543
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Thu, Dec 10, 2020 at 8:25 AM Marco Elver <elver@google.com> wrote:
>
> On Thu, 10 Dec 2020 at 14:29, Miguel Ojeda
> <miguel.ojeda.sandonis@gmail.com> wrote:
> > On Thu, Dec 10, 2020 at 11:35 AM Marco Elver <elver@google.com> wrote:
> > >
> > > It looks like there's no clear MAINTAINER for this. :-/
> > > It'd still be good to fix this for 5.11.
> >
> > Richard seems to be the author, not sure if he picks patches (CC'd).
> >
> > I guess Masahiro or akpm (Cc'd) would be two options; otherwise, I
> > could pick it up through compiler attributes (stretching the
> > definition...).
>
> Thanks for the info. I did find that there's an alternative patch to
> fix _Static_assert() with genksyms that was sent 3 days after mine
> (it's simpler, but might miss cases). I've responded there (
> https://lkml.kernel.org/r/X9JI5KpWoo23wkRg@elver.google.com ).
>
> Now we have some choice. I'd argue for this patch, because it's not
> doing preprocessor workarounds, but in the end I won't make that call.
> :-)

I was half kidding about depending on a production C parser.  See
internal reference pa/1432607, choice quotes:
```
...
CONFIG_MODVERSIONS uses scripts/genksyms/genksyms to create a file,
Module.symvers, that is a simple mapping of CRCs of various symbols'
types to the symbol names.  It produces these CRCs by using the C
preprocessor, then passing this into genksyms. genksyms has a lex/yacc
based C parser to parse the preprocessed sources of kernel modules.  It
turns out that it's incomplete, copied from an upstream project that
ceased development in 2013, and was slated to be removed around the 4.9
kernel release.
...
Some possible solutions:
* Update the kernel's version of genksyms.  There's a comment that the
  kernel's sources were copied from "modutils." It seems that modutils'
  last release was v2.4.27 in 2004, and that development on it has
  stopped.  Upstream modutils also has the same parsing bug.
...
* Fix the parsing bug in genksysms. While the discussion about removing
  CONFIG_MODVERSIONS has started again upstream due to my bugreport,
  this would be the optimal solution, if I could just figure out how to
  rewrite the parser correctly.
...
A better long term solution would be to replace genksyms's
modutils/lex/yacc based incomplete and dead C parser with a libclang
based one, but such work is beyond the scope of a toolchain update.

For future travelers that would like to take a crack at fixing the
existing parser, I found the develop/build/test/debug cycle to be:

$ rm scripts/genksyms/genksyms
$ make scripts/genksyms/
$ ./scripts/genksyms/genksyms -d < test_case.i
$ ./scripts/genksyms/genksyms -d -d < test_case.i
Best of luck on that endeavor.
```

I was planning on talking about this timebomb at plumbers, but had to
cut it due to the tight time constraints we were allotted.
-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOdn7c20vATaJMzsMYtCngs6ZDQMW8LX9ywhARxL6OKEdNg%40mail.gmail.com.
