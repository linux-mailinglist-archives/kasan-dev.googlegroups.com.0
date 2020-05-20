Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZXRST3AKGQEW4B4DRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id DFE501DB5DE
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 16:04:23 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id l1sf1630886qvy.20
        for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 07:04:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589983463; cv=pass;
        d=google.com; s=arc-20160816;
        b=wRf5rcPrMC7pRg6S4sNnmqnnABbmNf3DBn3dkG6kA0NytiM5gmpEYzViGx+mGXAcOb
         Y5YeJSNuef4xKMDbFmpT++Ue/i+q1gH+2WtQdN/nGibuihYeQWghPdW1bCVVPSdhBLUz
         cegKiLHyCmq1OYLjn0KOke5fxw32KBiOBzY/9s3NM+3yJ8G9kqs7b/p7S8QpnLiaOukf
         W7UaB8MeMxt4QystrVGo37w1/DAWBK4dAgfMax1UGsCptJqeV7FonuotIx9FTs1ejk47
         TNPkmkQqDLpAxQm3W5VqlGKZE6i4Ij0h+4MgX6uhimEsEO1T/JiAPOeTCzajfeQVmGGb
         stNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qu6f54wvUM8OkITij9bLlH3dOJkmCgnifZfYpPt9j9o=;
        b=WtWF5EChleQbLbLC0e1swFd96T27SdSHxisvf+rPgaB9l3WiCfiIBgLtm+3EPpcKdv
         CNIWsUwht8uyn/FtkoA/AiUmihxrNNun7kNVW66YDZGLEvYqSqwDXlhd4eetuFuhbXas
         5z6oUg66/JUThUkM1ISMbsYypdxyfDwHoJZZ+0uFeBspOCsCv5+dRTbAykXjECII+Hjy
         FZWHFUeWYpl8xe+x0o5lVulA9Y/aWXgSOt+b4KQjGCNMCmdElwIzZ5GJMtGXQktiOifE
         OCGqcOZT3CzUPMRT6UzMTmfcIL525y4A3P5bewHeDKN1+tN2Ar3b4slThTQoPQ3RppLO
         Brew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fGEgsjMV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=qu6f54wvUM8OkITij9bLlH3dOJkmCgnifZfYpPt9j9o=;
        b=IkjJxvcG2E346Yi2WvuNncbJqyVPzRHMwdBtBQVwhVEKpTsUJOF/eEZSMUd2Y64/9z
         JvA/PNNf/LHGNlI9Q+3ueiFN/6nDmOL4bvO4hWEs4gJE3SkRgf7aO1paxZta00HOSedk
         5NPUC15rR7KXkkDcPRfv9IcSMbNgjLbibMALzv6vxI2xCJV70u43nVXQbl9c05eIGp30
         zrN50FezH4Dk6R+boWwcEhAH4TT6NaoDmECtWXsXHLXUL6y+gOrC+vDuuNI+sIaoInCq
         2lB5/rTkqZIBIJmcol9NbuLKup8RAy8W6U/F5/GXRiAJGYD8kGqKYQo0uBd3a88TDUZ/
         jV3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qu6f54wvUM8OkITij9bLlH3dOJkmCgnifZfYpPt9j9o=;
        b=NH+rl+tPiIeUDIMfXE15oN3R0DeEB0P9d77mqA5/8vqJgh/OygQG12fqfx5UBHPW49
         9RwQ5RF/KzfkfObgl0pNKA3Clpu2CFTTB5BlwXVALccy2sE8Zw0DNl2pd0z1+yheYFJs
         E9BWHMnCMPSddFymne4LNaix78Fx8KbMGwP4giDJmNJ1g+U4OIktE8KnMWsOWg6S2Uwf
         R4F4RyPDYSHoaCEaDVlEP8IHxBUwuV+zN0kMfwchFCfeJajU7J9Fe/BpJvkYFeYLXAeM
         zG6PmTKHvhtmnoSCwKEQvyhHw6Ku4hh15yUjLfK0a46pn53PkdwPzZPbgy3zINN+vfa9
         G2pQ==
X-Gm-Message-State: AOAM5304wHDlwbYPYJzK63k4VuRXtW6a/Q/ACt1XNhH8qVuoqt/YfwN0
	U54DVqvqZKHG8i9ZZ9/P0o8=
X-Google-Smtp-Source: ABdhPJxHFa/piEfV3dhfBAz9iw+PmmiWcqYRkLaW63FnSpDi2uW2cNKfdEPU++l/KF4D42ZE4SiuZA==
X-Received: by 2002:ac8:534b:: with SMTP id d11mr5344489qto.287.1589983462805;
        Wed, 20 May 2020 07:04:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:935:: with SMTP id t50ls1369348qth.9.gmail; Wed, 20 May
 2020 07:04:22 -0700 (PDT)
X-Received: by 2002:ac8:44ba:: with SMTP id a26mr5376510qto.323.1589983462399;
        Wed, 20 May 2020 07:04:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589983462; cv=none;
        d=google.com; s=arc-20160816;
        b=YNf7T76YzLxLB3JxWAHyKhsAWqksQChbNPAZj+UN9dhPyfB1+ppQCVzPUzT3oKKEFZ
         8Po3DH4cHwYQ8D0Dk6z76KSDPbK+A2iQw4U/oMqtdsXq5E32eXAqSJ338bNn6eD4ZxSy
         sZDEE0NBKxPucEzvYBKgSRTVi69uM1nzhheLqK2yGbK8dO+33VWRyqm1gGvZaE0q0xtn
         C58WGRCXU+J8/ehPrfdPwAbCto9+c7ab485fFtjSKsbWBAqoEPt+6i8jCCvsrkUkQfnW
         kgBYCEFKSTeOTOted2D2lrA70AmKc8wNtOxPpm2ZXtgse+lgU7MrP6cGgyLl0ddrKOzp
         /Mpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Yyyks53waupDusR8Q8QOC3nGTPoJ0h5feo1AmzQZ/sY=;
        b=VecX5ggC+7B9TSGVA9K1WCyKqCZw5oq4FPUYyTEnJNedUWZdodGXKob3rq3UwG7wHZ
         hsbXOPIApX64rSwOAIn+mHk2IzjexzukNRvTXMtlYKn/Rou3qCgCNPednzNj6L9nDF4z
         DZwnMV/NTfW87tjSebPgM7k6uMtxFTXf1l/BzlYzFIJxIvk7p/3R4W9vAvS0L6DiXAsb
         FkisZjWmV7OV5v9IH81afclRvo3GPX44aK0Utp+ww4KmfsjNQwwb+lmWUBsM/lKClZ6N
         cF3mi7DidpW9Z/nvB5ky21lasUWO9q1rnrqA5E1BpQV1jtWxUK5Zoz8E2dTq/CP8yBtU
         aPXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fGEgsjMV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id n23si203366qtv.0.2020.05.20.07.04.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 May 2020 07:04:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id o7so3026890oif.2
        for <kasan-dev@googlegroups.com>; Wed, 20 May 2020 07:04:22 -0700 (PDT)
X-Received: by 2002:aca:ebc5:: with SMTP id j188mr3311511oih.70.1589983461390;
 Wed, 20 May 2020 07:04:21 -0700 (PDT)
MIME-Version: 1.0
References: <20200423154250.10973-1-elver@google.com> <0e79d50f-163d-0878-709b-4d5ab06ff8eb@suse.cz>
In-Reply-To: <0e79d50f-163d-0878-709b-4d5ab06ff8eb@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 May 2020 16:04:09 +0200
Message-ID: <CANpmjNNH6Sfo7t8Vp13fXfqg0AWYS3v07xveihgZgtPfR9b9wQ@mail.gmail.com>
Subject: Re: [PATCH] tsan: Add optional support for distinguishing volatiles
To: =?UTF-8?Q?Martin_Li=C5=A1ka?= <mliska@suse.cz>
Cc: GCC Patches <gcc-patches@gcc.gnu.org>, Jakub Jelinek <jakub@redhat.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fGEgsjMV;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Wed, 20 May 2020 at 15:30, Martin Li=C5=A1ka <mliska@suse.cz> wrote:
>
> On 4/23/20 5:42 PM, Marco Elver via Gcc-patches wrote:
>
> Hello.
>
> Not being a maintainer of libsanitizer but I can provide a feedback:

Thank you for the review!

Note, this is not touching libsanitizer or user-space TSAN runtime,
only the compiler. Alternative runtimes may enable the option where
required (particularly, kernel space runtimes).

> > Add support to optionally emit different instrumentation for accesses t=
o
> > volatile variables. While the default TSAN runtime likely will never
> > require this feature, other runtimes for different environments that
> > have subtly different memory models or assumptions may require
> > distinguishing volatiles.
> >
> > One such environment are OS kernels, where volatile is still used in
> > various places for various reasons, and often declare volatile to be
> > "safe enough" even in multi-threaded contexts. One such example is the
> > Linux kernel, which implements various synchronization primitives using
> > volatile (READ_ONCE(), WRITE_ONCE()). Here the Kernel Concurrency
> > Sanitizer (KCSAN) [1], is a runtime that uses TSAN instrumentation but
> > otherwise implements a very different approach to race detection from
> > TSAN.
> >
> > While in the Linux kernel it is generally discouraged to use volatiles
> > explicitly, the topic will likely come up again, and we will eventually
> > need to distinguish volatile accesses [2]. The other use-case is
> > ignoring data races on specially marked variables in the kernel, for
> > example bit-flags (here we may hide 'volatile' behind a different name
> > such as 'no_data_race').
>
> Do you have a follow up patch that will introduce such an attribute? Does=
 clang
> already have the attribute?

Ah, sorry I wasn't clear enough here. As far as the compiler is aware,
no extra attribute, so no patch for the compilers for that. It's an
extra use-case, but not the main reason we need this. Re attribute, we
may do:

#ifdef __SANITIZE_THREAD__
#define no_data_race volatile
#else
#define no_data_race
#endif

in the kernel. It's something that was expressed by kernel
maintainers, as some people want to just have a blanket annotation to
make the data race detector ignore or treat certain variables as if
they were atomic, even though they're not. But for all intents and
purposes, please ignore the 'no_data_race' comment.

The main use-case, of actually distinguishing volatile accesses is now
required for KCSAN in the kernel, as without it the race detector
won't work anymore after some {READ,WRITE}_ONCE() rework. Right now,
KCSAN in the kernel is therefore Clang only:
https://lore.kernel.org/lkml/20200515150338.190344-1-elver@google.com/

Getting this patch into GCC gets us one step closer to being able to
re-enable KCSAN for GCC in the kernel, but there are some other loose
ends that I don't know how to resolve (independent of this patch).

[...]
> > +-param=3Dtsan-distinguish-volatile=3D
> > +Common Joined UInteger Var(param_tsan_distinguish_volatile) IntegerRan=
ge(0, 1) Param
> > +Emit special instrumentation for accesses to volatiles.
>
> You want to add 'Optimization' keyword as the parameter can be different
> per-TU (in LTO mode).

Will add in v2.

> > +
> >   -param=3Duninit-control-dep-attempts=3D
> >   Common Joined UInteger Var(param_uninit_control_dep_attempts) Init(10=
00) IntegerRange(1, 65536) Param Optimization
> >   Maximum number of nested calls to search for control dependencies dur=
ing uninitialized variable analysis.
> > diff --git a/gcc/sanitizer.def b/gcc/sanitizer.def
> > index 11eb6467eba..a32715ddb92 100644
> > --- a/gcc/sanitizer.def
> > +++ b/gcc/sanitizer.def
> > @@ -214,6 +214,27 @@ DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_READ_RANGE, "_=
_tsan_read_range",
> >   DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_WRITE_RANGE, "__tsan_write_range"=
,
> >                     BT_FN_VOID_PTR_PTRMODE, ATTR_NOTHROW_LEAF_LIST)
> >
> > +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ1, "__tsan_volatile_r=
ead1",
> > +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> > +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ2, "__tsan_volatile_r=
ead2",
> > +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> > +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ4, "__tsan_volatile_r=
ead4",
> > +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> > +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ8, "__tsan_volatile_r=
ead8",
> > +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> > +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ16, "__tsan_volatile_=
read16",
> > +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> > +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE1, "__tsan_volatile_=
write1",
> > +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> > +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE2, "__tsan_volatile_=
write2",
> > +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> > +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE4, "__tsan_volatile_=
write4",
> > +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> > +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE8, "__tsan_volatile_=
write8",
> > +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> > +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE16, "__tsan_volatile=
_write16",
> > +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> > +
> >   DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_ATOMIC8_LOAD,
> >                     "__tsan_atomic8_load",
> >                     BT_FN_I1_CONST_VPTR_INT, ATTR_NOTHROW_LEAF_LIST)
> > diff --git a/gcc/testsuite/ChangeLog b/gcc/testsuite/ChangeLog
> > index 245c1512c76..f1d3e236b86 100644
> > --- a/gcc/testsuite/ChangeLog
> > +++ b/gcc/testsuite/ChangeLog
> > @@ -1,3 +1,7 @@
> > +2020-04-23  Marco Elver  <elver@google.com>
> > +
> > +     * c-c++-common/tsan/volatile.c: New test.
> > +
> >   2020-04-23  Jakub Jelinek  <jakub@redhat.com>
> >
> >       PR target/94707
> > diff --git a/gcc/testsuite/c-c++-common/tsan/volatile.c b/gcc/testsuite=
/c-c++-common/tsan/volatile.c
> > new file mode 100644
> > index 00000000000..d51d1e3ce8d
> > --- /dev/null
> > +++ b/gcc/testsuite/c-c++-common/tsan/volatile.c
>
> Can you please add a run-time test-case that will check gd-output for TSA=
N
> error messages?

What do you mean? The user-space TSAN runtime itself does not make use
of the option, and therefore will and should never implement
__tsan_volatile*.

As stated in the commit message, it's an option for alternative
runtimes. Recently, the KCSAN runtime in the Linux kernel (there are
also "CSAN" ports to NetBSD and FreeBSD kernels, which also had the
same problem that default TSAN instrumentation doesn't distinguish
volatiles). Note, we chose "CSAN" instead of "TSAN" for naming the
different runtime, to avoid confusion since the runtimes function very
very differently, just use the same instrumentation. (There was also a
KTSAN for the kernel, but it turned out to be too complex in kernel
space -- still, very little in common with the user-space runtime,
just similar algorithm.)

FWIW we have a test in the Linux kernel that checks the runtime, since
that's where the runtime is implemented.

> > @@ -0,0 +1,62 @@
> > +/* { dg-additional-options "--param=3Dtsan-distinguish-volatile=3D1" }=
 */
> > +
> > +#include <assert.h>
> > +#include <stdint.h>
> > +#include <stdio.h>
> > +
> > +int32_t Global4;
> > +volatile int32_t VolatileGlobal4;
> > +volatile int64_t VolatileGlobal8;
[...]
> >     else if (rhs =3D=3D NULL)
> > -    g =3D gimple_build_call (get_memory_access_decl (is_write, size),
> > -                        1, expr_ptr);
> > +    {
> > +      builtin_decl =3D get_memory_access_decl (is_write, size,
> > +                                             TREE_THIS_VOLATILE(expr))=
;
> > +      g =3D gimple_build_call (builtin_decl, 1, expr_ptr);
> > +    }
> >     else
> >       {
> >         builtin_decl =3D builtin_decl_implicit (BUILT_IN_TSAN_VPTR_UPDA=
TE);
> >
>
> And please check coding style, 8 spares are not expanded with a tab.

Will fix for v2.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNNH6Sfo7t8Vp13fXfqg0AWYS3v07xveihgZgtPfR9b9wQ%40mail.gmail.=
com.
