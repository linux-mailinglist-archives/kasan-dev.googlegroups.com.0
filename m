Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPM2QWCAMGQEBP6GCPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 79F6D367E74
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 12:17:34 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id 14-20020a05620a078eb02902e3f1eae0f1sf6671402qka.22
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 03:17:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619086653; cv=pass;
        d=google.com; s=arc-20160816;
        b=tJ+EH0+QRbDvgLIFxm9OdbyrTKFaFfxiCaSp+wcneezPoyZxaKVbP+PoaYxuZ/qlF6
         0RuZe2HBOtME3/4ZZeEQwWmG+cdVliJRLffRHml/8HINkTAXh+Ej4QbQehGexe7uCBE9
         tk+s0sIOXfOE8IkV4x3Q70PziL+vAikht4lzyYU7+59pCyex4nRgrWSkwW0/Zxd+vb46
         qhX4qATx5GX7xIBNwGwCHBK4djvO5NV/a1ODcLTl4eu+uXhHuwZsa/7r6/YvYPooqCaj
         Alq4hXF22ZZ1q1lfTXyeHCtgRArjMamzkCAUizH8tsiYQ0mnioVTxgkgz/heKRGdCrEi
         9d2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WNs7TAnFan7dmZJrVdxQmn8RrXBrzrSH6UmAj0OQm1U=;
        b=iKmYOXPXS+JFn9aRudeHY4p77MIgfcJjURX2asvZCoFfRfoHMYNaYGsEejdEXH6OGU
         d8xAL4NxCcmKHNix12wVZZaUQlb4LJwlTSqH+kIoYO9KxAmlb91X3IBcnJHyZPGHM1+H
         TCd7P0YyoxTXHFQfflkX1imwdXdkYr7JF0xxvfT/sVxsz2x2rK2MgGjm3YQdEIllMBL4
         mzowrKguud2rtGWGF/PJL9OGH0N3ZThosrfwX2+FfcRMtydOCoK0ijib8qWuX7WIk2uS
         jCzVcngBGyyRXsmJ9eqXbCe8zlRQlmLYKA/T2Dg24UdXgAIWo0anF+lRvewCDpMGePg+
         lLAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nyhWc3nG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WNs7TAnFan7dmZJrVdxQmn8RrXBrzrSH6UmAj0OQm1U=;
        b=kks+zI/9vHBpBGxTg8o1Wq/b/cHSwv89ToGTHZaMM6wAqnPQ6uqeerD2N9cP1OJVbo
         LYChi0Sv+jGgVJkJliCYtYB1zQzSXrOH+T4n8D9bR5YYXZ7dOmFOt7QM9eTgA4PUWHmB
         QUoAtUdCHnrsc9CS3t8SSb39mhX6zILFHJDr6QSjwDFX9k6K4n9wnQUBGDBd5USFn1m9
         eNuVAXzOqG848XaYS7CwTy4p6PUcrOZ5h2JsyWDtbQdJp7EzWc8xDjGJq87gs21ouV0O
         r24ykgxOqBOpkMwx/FVNlk6lHy3aXApdxskKyYmvEIiOeBsseArxMDWwyOEa3yAukUaS
         1E7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WNs7TAnFan7dmZJrVdxQmn8RrXBrzrSH6UmAj0OQm1U=;
        b=dZv3XsxE23A+wy4d5mjpU0PKeuC9dlRp3NDL8EqEaDiaW0xutSeR93B2VvCgKz03Sb
         PA+GEcCP2IyjuI5IF5m/s5GOYgXsE1lVOa6V7QdbjqjPk/XxtPRayK++IkvmLt39LrDI
         mr5EoLy57uzUASabks6WJBZBPhH3Tsizruyy/q/NBNjWp+dX567DU3j0xycfG0vDb+IQ
         BYwijuBQdfDgmn6ZFkGtYpXEnawcPIDy2D2a3ADV4F+d4QeuQX7vIIVpIVReFAW3q9jw
         CwTS8+U/41wonoc4ZN6NJGZsm253RdvnwX7Qv8dOnzv0wKUlbUwrCtu0Q+Lh0CCvXCmb
         2txw==
X-Gm-Message-State: AOAM531o6RWW/6MK4NJAj+pTdIyFJ4AjokTon8MiPD2jUUEOgUek69d0
	Xzh59t4er5b4uQ2Y7o9zAB0=
X-Google-Smtp-Source: ABdhPJwJH9tGLZgS9usPNg5TLFsA4zP5nE5H0J9d0tWiIge85GOH+68lMrjsIkCM6uYpP4aiQprEAg==
X-Received: by 2002:ac8:57cf:: with SMTP id w15mr2418178qta.336.1619086653275;
        Thu, 22 Apr 2021 03:17:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5b89:: with SMTP id 9ls1493320qvp.8.gmail; Thu, 22 Apr
 2021 03:17:32 -0700 (PDT)
X-Received: by 2002:a0c:e388:: with SMTP id a8mr2760532qvl.25.1619086652880;
        Thu, 22 Apr 2021 03:17:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619086652; cv=none;
        d=google.com; s=arc-20160816;
        b=bDdEGRiEEqcNBEq+cuZQBVQ587ejtOghg8WMLZdBIXpVZ9wZAFvBvFnZ8XYcyVsb+D
         fdnCkQFoi7/QnPzlV63QD4YblT3H1KHgKYGqHsfvEn6czGVgQk0t87g9h6nB5CLiNRlK
         rkj1AOZRtdod6yV8+S43BsgUeYVOoxrpp7ky5oFPhPXq6SV5soQ9DHQAExa1Zh5ff9VR
         3v1qLuOjPCHAvc57JSqnBodLTSiH9pTHE3pCttfv3HTEL0Kd897GoKTZsOkED2h+zmPA
         B/pH0Areet+on8D6yCCadJWn8hKH3AZlea4Tg8NZyItcIXy1yKaU/NYUjWWr0rFVum/P
         qxBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2gsWkNJIVwwQTgMpqGzbaIUC/BfooyEOt1c03CyO1cY=;
        b=wQLjIpVXOSUuqJCEh9H5hRXoEbDSYLkK+uY3gh2SIBoVOw3VwxhqcHNC5DssyRsW0L
         9q/0gAERjqzEfZmHk2agGFgSoBa98OP49qpc6qUayCPldxVUoIfhBVAKpBKNJRm5LT0z
         138LsjNjaLvFssmLe3q10pUTdfX0ZcV5bVE4jPYfp7lqtgglFv+hueGJcocVF+5abC/w
         wR/gxmCQtZr5C9iidI0LrP0KMEi0ZNQSWFvFEyJ0WSKXBVFYrDtu41u3pskwM6N9O5WG
         +ZKDCHiv9LTtJQGO2GR8nICD5dOgy+f/xU82nypCSnJIrBwnPMWgwUXVlDDeYGkqioV1
         r4og==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nyhWc3nG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32f.google.com (mail-ot1-x32f.google.com. [2607:f8b0:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id h13si298312qtx.0.2021.04.22.03.17.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Apr 2021 03:17:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) client-ip=2607:f8b0:4864:20::32f;
Received: by mail-ot1-x32f.google.com with SMTP id e89-20020a9d01e20000b0290294134181aeso15849046ote.5
        for <kasan-dev@googlegroups.com>; Thu, 22 Apr 2021 03:17:32 -0700 (PDT)
X-Received: by 2002:a05:6830:241b:: with SMTP id j27mr2248529ots.17.1619086652316;
 Thu, 22 Apr 2021 03:17:32 -0700 (PDT)
MIME-Version: 1.0
References: <20210422064437.3577327-1-elver@google.com> <d480a4f56d544fb98eb1cdd62f44ae91@AcuMS.aculab.com>
In-Reply-To: <d480a4f56d544fb98eb1cdd62f44ae91@AcuMS.aculab.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Apr 2021 12:17:20 +0200
Message-ID: <CANpmjNNjkQdziFZDkPy5EnwCF+VyBWKXEwCDgNpxHGZd+BLQag@mail.gmail.com>
Subject: Re: [PATCH tip 1/2] signal, perf: Fix siginfo_t by avoiding u64 on
 32-bit architectures
To: David Laight <David.Laight@aculab.com>
Cc: "peterz@infradead.org" <peterz@infradead.org>, "mingo@redhat.com" <mingo@redhat.com>, 
	"tglx@linutronix.de" <tglx@linutronix.de>, "m.szyprowski@samsung.com" <m.szyprowski@samsung.com>, 
	"jonathanh@nvidia.com" <jonathanh@nvidia.com>, "dvyukov@google.com" <dvyukov@google.com>, 
	"glider@google.com" <glider@google.com>, "arnd@arndb.de" <arnd@arndb.de>, 
	"christian@brauner.io" <christian@brauner.io>, "axboe@kernel.dk" <axboe@kernel.dk>, 
	"pcc@google.com" <pcc@google.com>, "oleg@redhat.com" <oleg@redhat.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"linux-arch@vger.kernel.org" <linux-arch@vger.kernel.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nyhWc3nG;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 22 Apr 2021 at 11:48, David Laight <David.Laight@aculab.com> wrote:
>
> From: Marco Elver
> > Sent: 22 April 2021 07:45
> >
> > On some architectures, like Arm, the alignment of a structure is that of
> > its largest member.
>
> That is true everywhere.
> (Apart from obscure ABI where structure have at least 4 byte alignment!)

For instance, x86 didn't complain, nor did m68k. Both of them have
compile-time checks for the layout (I'm adding those for Arm
elsewhere).

> > This means that there is no portable way to add 64-bit integers to
> > siginfo_t on 32-bit architectures, because siginfo_t does not contain
> > any 64-bit integers on 32-bit architectures.
>
> Uh?
>
> The actual problem is that adding a 64-bit aligned item to the union
> forces the union to be 8 byte aligned and adds a 4 byte pad before it
> (and possibly another one at the end of the structure).

Yes, which means there's no portable way (without starting to add
attributes that are outside the C std) to add 64-bit integers to
siginfo_t without breaking the ABI on 32-bit architectures.

> > In the case of the si_perf field, word size is sufficient since there is
> > no exact requirement on size, given the data it contains is user-defined
> > via perf_event_attr::sig_data. On 32-bit architectures, any excess bits
> > of perf_event_attr::sig_data will therefore be truncated when copying
> > into si_perf.
>
> Is that right on BE architectures?

We effectively do

  u64 sig_data = ...;
  unsigned long si_perf = sig_data;

Since the user decides what to place into perf_event_attr::sig_data,
whatever ends up in si_perf is fully controllable by the user, who
knows which arch they're on. So I do not think this is a problem.

> > Since this field is intended to disambiguate events (e.g. encoding
> > relevant information if there are more events of the same type), 32 bits
> > should provide enough entropy to do so on 32-bit architectures.
>
> What is the size of the field used to supply the data?
> The size of the returned item really ought to match.

It's u64, but because perf_event_attr wants fixed size fields, this
can't change.

> Much as I hate __packed, you could add __packed to the
> definition of the structure member _perf.
> The compiler will remove the padding before it and will
> assume it has the alignment of the previous item.
>
> So it will never use byte accesses.

Sure __packed works for Arm. But I think there's no precedent using
this on siginfo_t, possibly for good reasons? I simply can't find
evidence that this is portable on *all* architectures and for *all*
possible definitions of siginfo_t, including those that live in things
like glibc.

Can we confirm that __packed is fine to add to siginfo_t on *all*
architectures for *all* possible definitions of siginfo_t? I currently
can't. And given it's outside the scope of the C standard (as of C11
we got _Alignas, but that doesn't help I think), I'd vote to not
venture too far for code that should be portable especially things as
important as siginfo_t, and has definitions *outside* the kernel (I
know we do lots of non-standard things, but others might not).

Thanks,
-- Marco

>         David
>
> >
> > For 64-bit architectures, no change is intended.
> >
> > Fixes: fb6cc127e0b6 ("signal: Introduce TRAP_PERF si_code and si_perf to siginfo")
> > Reported-by: Marek Szyprowski <m.szyprowski@samsung.com>
> > Tested-by: Marek Szyprowski <m.szyprowski@samsung.com>
> > Reported-by: Jon Hunter <jonathanh@nvidia.com>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >
> > Note: I added static_assert()s to verify the siginfo_t layout to
> > arch/arm and arch/arm64, which caught the problem. I'll send them
> > separately to arm&arm64 maintainers respectively.
> > ---
> >  include/linux/compat.h                                | 2 +-
> >  include/uapi/asm-generic/siginfo.h                    | 2 +-
> >  tools/testing/selftests/perf_events/sigtrap_threads.c | 2 +-
> >  3 files changed, 3 insertions(+), 3 deletions(-)
> >
> > diff --git a/include/linux/compat.h b/include/linux/compat.h
> > index c8821d966812..f0d2dd35d408 100644
> > --- a/include/linux/compat.h
> > +++ b/include/linux/compat.h
> > @@ -237,7 +237,7 @@ typedef struct compat_siginfo {
> >                                       u32 _pkey;
> >                               } _addr_pkey;
> >                               /* used when si_code=TRAP_PERF */
> > -                             compat_u64 _perf;
> > +                             compat_ulong_t _perf;
> >                       };
> >               } _sigfault;
> >
> > diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
> > index d0bb9125c853..03d6f6d2c1fe 100644
> > --- a/include/uapi/asm-generic/siginfo.h
> > +++ b/include/uapi/asm-generic/siginfo.h
> > @@ -92,7 +92,7 @@ union __sifields {
> >                               __u32 _pkey;
> >                       } _addr_pkey;
> >                       /* used when si_code=TRAP_PERF */
> > -                     __u64 _perf;
> > +                     unsigned long _perf;
> >               };
> >       } _sigfault;
> >
> > diff --git a/tools/testing/selftests/perf_events/sigtrap_threads.c
> > b/tools/testing/selftests/perf_events/sigtrap_threads.c
> > index 9c0fd442da60..78ddf5e11625 100644
> > --- a/tools/testing/selftests/perf_events/sigtrap_threads.c
> > +++ b/tools/testing/selftests/perf_events/sigtrap_threads.c
> > @@ -44,7 +44,7 @@ static struct {
> >  } ctx;
> >
> >  /* Unique value to check si_perf is correctly set from perf_event_attr::sig_data. */
> > -#define TEST_SIG_DATA(addr) (~(uint64_t)(addr))
> > +#define TEST_SIG_DATA(addr) (~(unsigned long)(addr))
> >
> >  static struct perf_event_attr make_event_attr(bool enabled, volatile void *addr)
> >  {
> > --
> > 2.31.1.498.g6c1eba8ee3d-goog
>
> -
> Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
> Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNjkQdziFZDkPy5EnwCF%2BVyBWKXEwCDgNpxHGZd%2BBLQag%40mail.gmail.com.
