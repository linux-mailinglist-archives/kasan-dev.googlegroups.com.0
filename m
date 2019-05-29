Return-Path: <kasan-dev+bncBCMIZB7QWENRBGERXHTQKGQEBBBHPOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id C11AB2D83C
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 10:53:45 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id b197sf1243081iof.12
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 01:53:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559120024; cv=pass;
        d=google.com; s=arc-20160816;
        b=ot1LuTn3RX64Vu475wV66sZ6E0KJ11WOgLFmzHaoGR3DdN2iwUaYP7uhJm0anv4FKK
         LOIsDwpXkZpGHqmxEwXk7YOUvMWp/ZzQfeVDnv/5h0jiF5mC9Fc8iSXxO+UJPU+fINop
         O29arPAIazp8NMZJPVfTBI9+78oFDT4dg1wiQRZnxpuG5T8rHG9PT/QJE38AI/GfzSRW
         co2zGxdF1RPRx5VRcucWX9zMc4ow9KNr+e6MZ/kV1J/aIn7gFzuIVD29u+k0XQHGvTBo
         0SSFImiQaiQbkp7HQBafTxjAafhYdMH2x1/mu/Ag9bPrT5P6p0+Q3Jb0KcOcMEKTwSVY
         dTlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+bHQQbxvvFycMAC+NDXcnOyehXSJE9Qz/zTKgiZSg4M=;
        b=TBRjgzhQj1Zc4MrU5uVNHqsvJtZNZuaAyaKdN2kJ8YBV2s/8qwu6mdX7ZnnJ8ddKqP
         TUkx2CS/M4ghthMAER0EtK+epQD6tQLwXo3N/oLhY5P2JiWLL6vnRzmf525AhVRt7JP9
         PZxX7rOgurOm66oZuZqMxs4gr7v5CnEO8nlr0eYNOJ36qcEUWDndbXuoGof/5eHCXR2I
         KlBolaHt8YZS0HavYwR9WUGAFDgaDv7mydCIs1hhbrroxY0qCBUgYJF8MfG8mwbvKExz
         uQAiNpvRN290icwRIrJRCh9neazHiOWFeUI3/DT+SDnYdK+y/ST62FO/qYEnXP2iY7S6
         mcXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iag1iqkl;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::130 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+bHQQbxvvFycMAC+NDXcnOyehXSJE9Qz/zTKgiZSg4M=;
        b=FikacW+QOjbngwSvqY1HLczOOcwRFA8FS8FRskWdK9TzCh9dXVR9pObs5iFERS93rA
         GJZoHbEmkocTN4So4qGD84PIXZDgJ3gKflp2YCIQ1evWI6vug9fdXRNrpBOcpmil8JNc
         Cku1yodqC1d2egwSbKUj3o7vF2Yg3pbUP8GVtYh84g7WtFgFPYtA2qTNAvy5UKhG0q99
         Oxazf8wGUOGwRA9G6MlVT0lqAYdTKxhkDAWzAcZxWudvXrkE/yXSGLlF87Xa83OJnph1
         0tpv23o/fbvaAAy+99qVRHJ8TewgSegGa0cKOj/P9BCET5LMd5jVIA+Op/AgNE+65yUK
         0pCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+bHQQbxvvFycMAC+NDXcnOyehXSJE9Qz/zTKgiZSg4M=;
        b=Ds02cRiHGkvZvNLT0f72ReGOA+dK2G2+6zVzzgbZpvcz1BxJvf57h5ePkTJFeLDJBU
         US8/An/FlN0Ks/5PueWq4wvUmf+IDmlfaSwt5ca+8fwYgCQsRyBF7oPNm0Eyfl6w6v6W
         dDkfwIu+rBpew788ZCvViwrG2f7faCTVgB29562tOJvUyjk4sEO/WeIo3jrasWm9t3bp
         bP5f8MZC672llM+AwEz7Vm9CidR29Rz381S37+TbFKV+nEZ7WfvUZ11CECDIZ1kz8Mt2
         7fV4Scr8PK01ZzrmY/ehY7h/XRZdHtiVAcm0Ab4OV3hzZr1JvIzvG/ivA7/i2wCwI8QA
         SGQg==
X-Gm-Message-State: APjAAAUynbnrXmHbz2ja7dwkunrwkjYniTUtc34L/NBmT6Kc7FJJFETt
	UUmOj5M2WuREEnWRG/mjhIE=
X-Google-Smtp-Source: APXvYqwF8G03TaIXvMFFcwSFmuLhkRQrcMCiMZSs68LDNlDAzGR0kTA4lh7lbTYOcW/ymrKfd2vzmg==
X-Received: by 2002:a6b:ea06:: with SMTP id m6mr10592577ioc.271.1559120024586;
        Wed, 29 May 2019 01:53:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:5445:: with SMTP id t66ls133655jaa.0.gmail; Wed, 29 May
 2019 01:53:44 -0700 (PDT)
X-Received: by 2002:a02:9a0f:: with SMTP id b15mr10422253jal.32.1559120024311;
        Wed, 29 May 2019 01:53:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559120024; cv=none;
        d=google.com; s=arc-20160816;
        b=MHqnGDLJoEjxWiOCOWeEUFfzIjkZvkeIpxVZFbrUC4BueXG4tiRAiF6gnzYZD9zpgo
         NRVrCFrcdEwj315+7pNypTyBKNsdSNCui9370w4WPjJzgHGpCOF2iNP9ARVlYGNUVhwY
         uuSambdOQE9mlH/iTBJgNvJRZKC1/8ZLIaRm18HWk32eQew10V0qGzkHkVMVdGpymziA
         of41UURlmr3+HFBL2tAz+9SE8HQtxQi3DHfxPc6L+FtQavrnjHuVo0PdWyIBly2/YoJB
         VdpwmhsbBdHByP/Z6PaS8a5SfRKkKpuMI2tDExAQvqaJxkQOltFiK25gq247yxSP3dfb
         uF9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fk93ITL8R4mrLU9REN4UKK4IhmKV6EO0365BfuSaHXw=;
        b=XpD3qLcaFnQF7o8LfUaI8NWoSIewBWZjcHrRejGj23cU/g0iBLyyGEHcfD978uaJZ6
         f36lCrsdlk3FUN4gPEb8cbOVdzHztHz+7HQHeqs8kS2yPAQU8XY9RU9TRT1sMvPYxVV6
         pKzuh9hKy0+8XYsDLTRSW0z22Q2+iESMgFJYjS5VkBfiScGrgYmEn1TWHBHUVqZLVsa5
         K/SatJjBZ5kIsxSoSdRZ3lEJF3NDEu0r7chUVMtjJvCfudCsdobAvZ0MbDxy2Dv2Y7Js
         TycJsdu5O0S6neHMVnIPL6J47XEYBHgKf88yLbVQouardYMSOiSuKFUO6jqr2NL3xv1I
         CCRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iag1iqkl;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::130 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-it1-x130.google.com (mail-it1-x130.google.com. [2607:f8b0:4864:20::130])
        by gmr-mx.google.com with ESMTPS id d190si488127iof.3.2019.05.29.01.53.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 May 2019 01:53:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::130 as permitted sender) client-ip=2607:f8b0:4864:20::130;
Received: by mail-it1-x130.google.com with SMTP id m3so2437773itl.1
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2019 01:53:44 -0700 (PDT)
X-Received: by 2002:a24:91d2:: with SMTP id i201mr6764834ite.88.1559120023781;
 Wed, 29 May 2019 01:53:43 -0700 (PDT)
MIME-Version: 1.0
References: <20190528163258.260144-1-elver@google.com> <20190528163258.260144-3-elver@google.com>
 <20190528165036.GC28492@lakrids.cambridge.arm.com>
In-Reply-To: <20190528165036.GC28492@lakrids.cambridge.arm.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 29 May 2019 10:53:32 +0200
Message-ID: <CACT4Y+bV0CczjRWgHQq3kvioLaaKgN+hnYEKCe5wkbdngrm+8g@mail.gmail.com>
Subject: Re: [PATCH 3/3] asm-generic, x86: Add bitops instrumentation for KASAN
To: Mark Rutland <mark.rutland@arm.com>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iag1iqkl;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::130
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, May 28, 2019 at 6:50 PM Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Tue, May 28, 2019 at 06:32:58PM +0200, Marco Elver wrote:
> > This adds a new header to asm-generic to allow optionally instrumenting
> > architecture-specific asm implementations of bitops.
> >
> > This change includes the required change for x86 as reference and
> > changes the kernel API doc to point to bitops-instrumented.h instead.
> > Rationale: the functions in x86's bitops.h are no longer the kernel API
> > functions, but instead the arch_ prefixed functions, which are then
> > instrumented via bitops-instrumented.h.
> >
> > Other architectures can similarly add support for asm implementations of
> > bitops.
> >
> > The documentation text has been copied/moved, and *no* changes to it
> > have been made in this patch.
> >
> > Tested: using lib/test_kasan with bitops tests (pre-requisite patch).
> >
> > Bugzilla: https://bugzilla.kernel.org/show_bug.cgi?id=198439
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  Documentation/core-api/kernel-api.rst     |   2 +-
> >  arch/x86/include/asm/bitops.h             | 210 ++++----------
> >  include/asm-generic/bitops-instrumented.h | 327 ++++++++++++++++++++++
> >  3 files changed, 380 insertions(+), 159 deletions(-)
> >  create mode 100644 include/asm-generic/bitops-instrumented.h
>
> [...]
>
> > +#if !defined(BITOPS_INSTRUMENT_RANGE)
> > +/*
> > + * This may be defined by an arch's bitops.h, in case bitops do not operate on
> > + * single bytes only. The default version here is conservative and assumes that
> > + * bitops operate only on the byte with the target bit.
> > + */
> > +#define BITOPS_INSTRUMENT_RANGE(addr, nr)                                  \
> > +     (const volatile char *)(addr) + ((nr) / BITS_PER_BYTE), 1
> > +#endif
>
> I was under the impression that logically, all the bitops operated on
> the entire long the bit happend to be contained in, so checking the
> entire long would make more sense to me.
>
> FWIW, arm64's atomic bit ops are all implemented atop of atomic_long_*
> functions, which are instrumented, and always checks at the granularity
> of a long. I haven't seen splats from that when fuzzing with Syzkaller.
>
> Are you seeing bugs without this?

bitops are not instrumented on x86 at all at the moment, so we have
not seen any splats. What we've seen are assorted crashes caused by
previous silent memory corruptions by incorrect bitops :)

Good point. If arm already does this, I guess we also need to check
whole long's.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbV0CczjRWgHQq3kvioLaaKgN%2BhnYEKCe5wkbdngrm%2B8g%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
