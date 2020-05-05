Return-Path: <kasan-dev+bncBDEKVJM7XAHRBW76YX2QKGQEVOTYNTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A3991C5A43
	for <lists+kasan-dev@lfdr.de>; Tue,  5 May 2020 16:59:40 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id b203sf967702wmd.6
        for <lists+kasan-dev@lfdr.de>; Tue, 05 May 2020 07:59:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588690780; cv=pass;
        d=google.com; s=arc-20160816;
        b=m2W1BrRz58/vS06VMPIEfN3iMnUe3VSpkiwhpmD6AWKEPu0FMF2XxdNbNxFGj7DhCM
         4dnghWO96mRxH2NnpRTgwzJV+a7O4pQZ2uqax/vLTR7pN4uOHFIpL5QdyoA+Igvj0LqF
         u1PwxgtJ0Scgwx3Dl7v0heAEpD9Ey3ymgca8iWy2oj9Ksz0N0Ipx9USw0B7bzqYwUpss
         5M6xBGkwyRQ0gBU22mkKGZ6nmVtWvFEgUdOOiRlDNDEVBkncqfhJwHSs7f4mppyI5XmP
         bY9rKsb4TLEdZQXf4yg7vTtClGa+F3F2VKY8Tu1NhojLj+gXh2u8mUxh1vMoOb3ycqyK
         AqYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=bKhQ5kkc3++usZ5jcUQe3QOEJOPe9yBa9MAK2C63VVs=;
        b=IyV7YY5JqkaBcPDfTqUfb07zgJjj/3gJtiX1o1Fs0EWmHZjBu3e5rVOO7CZfxxSbPB
         m2D2koH6tknlRd6hZd0P1X4nZQ96aB6DRLoBp0mxNujLKqpnWtYxP4Gn9RTMtVMgoYYL
         OKAlOtR7I3Ghlyorkh0hZsiLVzrXrn4cNdFz1ffm0Ur46pmswDDdkP1pq5IKNsyniRXF
         G778BGk4kGepnCJzCilSfRJAzb8cj6PwAjCmJInyVssXyOxCxrrkgyIQVpcCmp4AXSF8
         8e1LVkmQvWLujQk2x4LEla9pSmC4Pt9hG7hcddCyyUpkMj1UVWUnUjlpZb+YbHLEqUEH
         IbGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.17.13 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bKhQ5kkc3++usZ5jcUQe3QOEJOPe9yBa9MAK2C63VVs=;
        b=DA3L3LR6Bu57ap2b+p+d7h8YGidS6qWM4roF7kUjLQDG31a/78tFoe/7OMEzJqjSk9
         qSw5ChR3FuXa5X1SF+GJqyCAh9eY5d61Nha91CPeRtFRbx1zYxXnZPBA2Nzq4lnngGmY
         oAEE9YcYgy9mqcuBfe0821SWGyh9ylfEqM+IFDsvIK5sA9yBuBtVUNBDOK5mR4/W3eZY
         q7hD12egYYRd3g7F3MvagZcZeA0uRKJM4T10wNy9WPnb7iUIWI29923gDngQqyJwxN7+
         A6aFBN4JzMbbfpIg1Qqwzel3tI0Isx1ROUB43o30URpinpQZZxX8OI4MpJJRlklgCKk7
         HWsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bKhQ5kkc3++usZ5jcUQe3QOEJOPe9yBa9MAK2C63VVs=;
        b=BLCFMvUU0kVMRRo8NA6U2mzZnsHBAn1b28XDw7byxKw+OXPePEJhXc7ll0Llg1FbEz
         iMp/jZAnwuIxQmhpalO7OYOZwjlUWyNkxU/AZBqA29kt3uZ3UfKTVwoFlTyA4xMh60sT
         cu2+QnfRHDWCmPh16K9pbsd7eyUKO3++402PO2JjHBQbuV0mP8NDOtStEhLVn9i3/Nls
         IvOUKanEf0XppxEi03r7BsSGMzrv7+N5C1Vx7G0ZcxQ+7ji1ur6hV1idi8r4DhF7mEjl
         enhhgQZWpT5nUNMlNFuROsM/ETsumH3mU7WXtprKIBfpFn5sjXRItysixMJ0shOXAZUe
         V1lQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYFSpWtUyVYJIk/I3W6N32JcK03UnKkuqWsoDeWUmcDCC9pLK6Z
	MOhYRJhw1kBFf+1gI9gMRmc=
X-Google-Smtp-Source: APiQypLjFgQZs7TgYcl8uFpf9FXT/gyo/yS44pcFjvTk5cR0lTzehc8qv6o6aIqXIrQENHrauFCaNQ==
X-Received: by 2002:a05:600c:2dcf:: with SMTP id e15mr3974337wmh.171.1588690779859;
        Tue, 05 May 2020 07:59:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:668b:: with SMTP id l11ls4453895wru.0.gmail; Tue, 05 May
 2020 07:59:39 -0700 (PDT)
X-Received: by 2002:adf:ee4c:: with SMTP id w12mr4613366wro.347.1588690779274;
        Tue, 05 May 2020 07:59:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588690779; cv=none;
        d=google.com; s=arc-20160816;
        b=LVzVPWm3/mCrez69dK2ZZERzJadfiZfx/9uVCrlBTrPu8FpKozkk4FWQCrqpbdY6FQ
         YP8Vnc5tBgYop4U2wqkD7Eiy4lRjF8GFuDRxuctbyGgRmrbBw/fpYHlMwS8WIazs0+ux
         a8efcjxbw/oW4wCVugOhkws5kVvre4Z7cEvtyH9gcw6/3kYiRRhJGHucTDuVFWKEGFex
         RyID6niK23hbeNjj19arTdO9WQr1p6PrOVxs/UF5ozZeyfmbn2u1rfVsfF+RmM4c5I+A
         IH4pEfBzhzauxVbvJQpvR7LdjksuqJZf3yDjNHP9uitj+Sia2uF1rsnPat5MW+8iKs8P
         mubw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=YNYB3K96/IdhKEEdr8N1NKAkIyq2gns1y4XdLMjk7ek=;
        b=MJG1eW+xmycrDZYLSy+iTAFATrz1Jo+NDWJOPxRrJN48/kRlUj89OFoVoD2DGCLRyT
         MJhMlJMQltff2QTIr9+e2zjGqKxjjioOcQzFP4gRYrKjKSW2KnehDDbKba43S1E1EIKj
         AYZhLVuqoz4JCCDYKah67Go7rKTi3+6OK/jwprHbrpyoxwMmdhyWz8YgRXPmWqUtZWQ5
         s2hyISf/vR/L8e6LU6gnIICLcIDGDQGnJ+Dte8doZB6tOY7Wlfr22hoddn0QJFysZG1X
         0RsnoHhaknSCK/601Rdxr6mG/IT1x1rDMdPEO7nCk2O8u2ni3ccN5qRex56KGDF1oJ50
         8+zQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.17.13 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.17.13])
        by gmr-mx.google.com with ESMTPS id u23si232649wmn.0.2020.05.05.07.59.39
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 05 May 2020 07:59:39 -0700 (PDT)
Received-SPF: neutral (google.com: 212.227.17.13 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.17.13;
Received: from mail-qk1-f179.google.com ([209.85.222.179]) by
 mrelayeu.kundenserver.de (mreue108 [212.227.15.145]) with ESMTPSA (Nemesis)
 id 1MmlbE-1ipjY42wJq-00jnCz; Tue, 05 May 2020 16:59:38 +0200
Received: by mail-qk1-f179.google.com with SMTP id i14so2516922qka.10;
        Tue, 05 May 2020 07:59:38 -0700 (PDT)
X-Received: by 2002:a37:a492:: with SMTP id n140mr4097616qke.352.1588690777455;
 Tue, 05 May 2020 07:59:37 -0700 (PDT)
MIME-Version: 1.0
References: <20200505142341.1096942-1-arnd@arndb.de> <CANpmjNMtGy6YK8zuqf0dmkykZMt=qkxkZrZNEKde1nbw84ZLkg@mail.gmail.com>
 <CACT4Y+Zpp=+JJedhMpunuUh832eJFu+af-r8631Ar0kE2nv72A@mail.gmail.com>
In-Reply-To: <CACT4Y+Zpp=+JJedhMpunuUh832eJFu+af-r8631Ar0kE2nv72A@mail.gmail.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Tue, 5 May 2020 16:59:20 +0200
X-Gmail-Original-Message-ID: <CAK8P3a23XzLhZQNuFbeQhaSNru1abPwXV_mXR_P6N6Dvxm6jFw@mail.gmail.com>
Message-ID: <CAK8P3a23XzLhZQNuFbeQhaSNru1abPwXV_mXR_P6N6Dvxm6jFw@mail.gmail.com>
Subject: Re: [PATCH] ubsan, kcsan: don't combine sanitizer with kcov
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Kees Cook <keescook@chromium.org>, Andrey Konovalov <andreyknvl@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Thomas Gleixner <tglx@linutronix.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:hyR7Ox/myYz3aM0AbiuocaW7xwzp1dKvsByExjJF4NwfKiaZZqh
 Ii1Y0ntWLCLVtDUqhkoT+74QmVeOiAOr2ZlOQrmdyGK5EZzLlKdqqrXNYvLIDD/O7+ox+XS
 TNhOVXr1F80uYgF1l58vS4j7y7X5ThvZj0ILYThLaNn+4VQQc+LUzoRGEdkHsJVESREv7Qg
 uqv+uHeuZYZDLYkAvsGOg==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:SeEJAuoqTIw=:qbnMonlpbTwXDSGSiQPrJJ
 7CJvlmtlGxYj5bsrwA1+9CRTutBTm7mU47uel75g+Zrye69DL4BHQcCJrWGTIqhVVHics4rFB
 bTP5XUZLqBOUMBsPJAcpQWnMW5BDG7rjxGerjmJTsP8X2dCiUHY5i5l/uPHciz9fvEpWd1I0L
 Fj175dHs9DgXvP+qLyRHhpEutk36JZpO56fL6lmdmLNdtc5YWcrUkmiqvRlVMn6azbG/IN/A9
 vzse6UR8/nwzg/aHMIUSC9w/dWouPMCfIrDM3fl8zKnuV7K/Z3H98YEYeoLqOoWrmJTQCcmGW
 seBCPKfWSp+r+rDPWcPQnmiktcAZ0DQxQHDtrZBEp+lTUI2H7SRGfFXUMlqv0twoS8Fiembw2
 E6EuYSYLCd413s5yUsydJXk55haeij3MHAhy4bzZEniwRH6MuH/idemqZDqPwHJ6seHWowwpC
 p6ntsnlkCEP/zuQuf2BW9mn9XA8IRoSnD1qiyMFllaKq+BaVHt5p5a9Tq8RfJeOchAdMMmtq7
 GkTkePSOjGXZiOulXmPOFBsgLx1nz+Y2iglDbA9FpLqZTwV9fsd2OGxHW1XkvM/BfIpTQy9XL
 WJlZ70nT4gwqUtWqyOlBsO00KLKfTBPMrz/j/bp95i7CfL4rmbnY0WZXjIGh48eYrkqV9EJUe
 PukjHCChTrA4PT9kETAOOJXFZbf6J8kAH8QSuTBHX6syUU/v22qFYW1brR1Oi/WO+AEL7WJxd
 kdBEVaAXGRhUywlotfcpg299Lrj0+0Eyde2hWBHOMiVwzOmzH5flDXOhD2IqikjGd7GhnZmOw
 Rojtqh9VcVye5yzxyLFQYRZzchIJZ3jiRcWRZACRTNnQpmheac=
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.17.13 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Tue, May 5, 2020 at 4:50 PM 'Dmitry Vyukov' via Clang Built Linux
<clang-built-linux@googlegroups.com> wrote:
> On Tue, May 5, 2020 at 4:36 PM Marco Elver <elver@google.com> wrote:
> > > Clang does not allow -fsanitize-coverage=trace-{pc,cmp} together
> > > with -fsanitize=bounds or with ubsan:
> > >
> > > clang: error: argument unused during compilation: '-fsanitize-coverage=trace-pc' [-Werror,-Wunused-command-line-argument]
> > > clang: error: argument unused during compilation: '-fsanitize-coverage=trace-cmp' [-Werror,-Wunused-command-line-argument]
> > >
> > >  menuconfig KCSAN
> > >         bool "KCSAN: dynamic data race detector"
> > > -       depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN
> > > +       depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN && !KCOV
> >
> > This also disables KCOV with GCC. Why does this not work with KCSAN?

My mistake, this should be kept enabled for gcc. If we can get the combination
to work in clang, that's something that should also get enabled.

> > This is a huge problem for us, since syzbot requires KCOV. In fact
> > I've always been building KCSAN kernels with CONFIG_KCOV=y (with GCC
> > or Clang) and cannot reproduce the problem.

I have some local patches that change the way we pick the warning options
for each compiler, and enable more of the warnings that are normally disabled.

Maybe -Wunused-command-line-argument is disabled by default?
I only started seeing this problem recently. It's also possible that there
are some other options that interact with it so only Kcov+FOO leads to
KCSAN being ignored.

> > Ditto, we really need KCOV for all sanitizers. I also just tried to
> > reproduce the problem but can't.
> >
> > Which version of clang is causing this? I'm currently using Clang 9.
> > My guess is that we should not fix this by disallowing KCOV, but
> > rather make Clang work with these configs.
> >
> > Dmitry, can you comment?
>
> FWIW I can reproduce both with clang:
>
> $ clang /tmp/test.c -c -fsanitize-coverage=trace-pc -fsanitize=bounds
> clang-11: warning: argument unused during compilation:
> '-fsanitize-coverage=trace-pc' [-Wunused-command-line-argument]
>
> $ clang /tmp/test.c -c -fsanitize-coverage=trace-pc -fsanitize=thread
> clang-11: warning: argument unused during compilation:
> '-fsanitize-coverage=trace-pc' [-Wunused-command-line-argument]
>
> with both my disto's 9.0.1 and fresher 11.0.0
> (7b80cb7cf45faf462d6193cc41c2cb7ad556600d.
>
> But both work with gcc
>
> $ gcc /tmp/test.c -c -fsanitize-coverage=trace-pc -fsanitize=thread
> $ gcc /tmp/test.c -c -fsanitize-coverage=trace-pc -fsanitize=bounds
>
> Is it a known issue in clang?
>
> Can we somehow disable it only for clang and not gcc?
>
> This will immediately break KCSAN on syzbot as it enables KCSAN and KCOV:
> https://syzkaller.appspot.com/upstream?manager=ci2-upstream-kcsan-gce

I can respin the patch with this fixup if you like:

--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -5,7 +5,7 @@ config HAVE_ARCH_KCSAN

 menuconfig KCSAN
        bool "KCSAN: dynamic data race detector"
-       depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN && !KCOV
+       depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN && !(KCOV
&& CC_IS_CLANG)
        select STACKTRACE
        help
          The Kernel Concurrency Sanitizer (KCSAN) is a dynamic

As you both say, the combination seems to be quite important, so maybe there
is something else that can be to also enable it with clang.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a23XzLhZQNuFbeQhaSNru1abPwXV_mXR_P6N6Dvxm6jFw%40mail.gmail.com.
