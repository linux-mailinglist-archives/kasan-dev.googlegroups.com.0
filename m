Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRUTQSAQMGQEKK3B7WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id E0BB7312DF4
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 10:52:08 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id n81sf16254961ybg.20
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 01:52:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612777927; cv=pass;
        d=google.com; s=arc-20160816;
        b=0whoE2nTixMtHeKWiP6BXlBl7rSQ8FP5F+mQAfB7GH8vHF0JlOrYk0YmMZMCHRIgk9
         GbY/Z053iKPtVBibFBSoL/plsjQBNayjbdjYlSrzvvVUzrvTdQbALYM/E6RurphccM9a
         vEb96U3wW4+9y5ooXK+5g5wz+WqC4rJyc43ZkL1h32SJSSbpPtFChQKkCBMq9zr2Y6Ag
         MiTOs/nTwfwveVPgsqj8L3xiXWkS2zp4u26FRIm9zD1B/KlbqbHca34P9Mbj56oC8EpF
         u3FHdlRhxTtpTfd/IyHqfvwNRjLnopfxeSQ9T92DVyfLtqOgT0wREj7dvTeg3dxBPTk6
         yFeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mJVvoKnfCovxP9rbnP7ahrJhUyN0IQB7K6yDwGBtfe4=;
        b=VdNC2KwGt4wxRK7IVfnbMhT/7qJH1GncivXyyyFw7zEghsIjgmTqmsNIixoYLE43e+
         qFU+Y53Gkj1AlFbLgX4GFJi/bmXRuNxzmodBk0YzXFhtdZEK7dN8t1nc4mCFn8+vLUoc
         3wfPyZfczVcX/zdcEiTrv2POTTWZaCf5Gsk54CI8R0M3oNKzfa/BAfBI8Lf/md5dOGCf
         uqsbOWcSEs+hvBZwoGU98s8aQsOnqhP1sdBdcZqAKXLrXCZIDgphNZiqC+wHSNT2DEnv
         WlRDXYE+O/PVg3UAf+citU7VyAub4Pw/LVrlAlr7sAyn8ntHud8rjEVV+UaoMz8xnvtc
         l3Ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KLWyl72H;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=mJVvoKnfCovxP9rbnP7ahrJhUyN0IQB7K6yDwGBtfe4=;
        b=Mnrospdv2DkCEMAoyD4wcoqFftnscl01X6V7KlAFjuovrQIfxacZiqNw1/j/E6ryHB
         unvR+abfqTNoi4fYdXho/1S8/EyaSOl7A3xe8KS+4aE4PaRG7tkSaJUZZISynYfhaAOg
         vHH+MtuDiwsjxe9DoOkd51Zsq3RkPm0QGRUCwtdfT57rdll+T2OPhffvw2JsjZSn68Zg
         KREIyknr6KX+b5A6yhe2S+dMA8Tn3fYS8xPK6oW0mXAugBxrkEARZsPI4977iym5KGru
         Ay96L88RR1kFK6GrLmKSKQKwZ4eRXre3jY4u+m3pA2gO58B2jdRzvjfFntyP0cVj1eld
         4h7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mJVvoKnfCovxP9rbnP7ahrJhUyN0IQB7K6yDwGBtfe4=;
        b=AD7XFlLiYi3FGZ1jZun68dh1Pdb5yYW+u997TKDtsFz9ggRlUv4PeG4XzZ0ICX2TaD
         VTWNfGCAp+8tcBYkcBvvdnl3bbbcd61VC5kPs7LgDweSkmZjV/ghiKfRv8wo/Id2AyVm
         DYuI2r6DdYVucTetfsUdJNSi86ba4jiMVBrFiQ3hTN+FWcXuX0KdPAsAGfnMXsJalU54
         Ly369CEJMHKsVlGtPmleaX+S28bH+JROo2GiwzJoI0AQ+dy5fhKDS4J/NgcqWPd8mh5D
         3GNcIzEtuYvO87mrNaaIRXv+T3kBlDcitUF6dwg9YddHhwumWtpXAQIxv7+dJJpcO3qm
         bCOw==
X-Gm-Message-State: AOAM531OqMCg9TZnXFIcTH6GMldvrooMlJeDT7P6u8XY/cathccEJ+oL
	WjwYr8Qh00JJLZdrPuomR+I=
X-Google-Smtp-Source: ABdhPJxyv7H11s6t5JflXz/zrwqPDztZV5AJcvhntEOU/5zLqG7/RUcGompmf8UETEl2+dEThDM8WA==
X-Received: by 2002:a25:d803:: with SMTP id p3mr9862022ybg.98.1612777926665;
        Mon, 08 Feb 2021 01:52:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:1482:: with SMTP id 124ls8189473ybu.7.gmail; Mon, 08 Feb
 2021 01:52:06 -0800 (PST)
X-Received: by 2002:a25:d94b:: with SMTP id q72mr4237058ybg.135.1612777926243;
        Mon, 08 Feb 2021 01:52:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612777926; cv=none;
        d=google.com; s=arc-20160816;
        b=G3qkHJUAwQd44ECi8vJ7y8rLcVfnJawAMn/ki7EbFWfa+3c+sBTefj1Z99Bsr/6OdD
         Essz5wM/ejJbMi3wGuijAhrVoFXaWmPTj+DNuoZMeM7Cj+noYkzAb8VuBy6Sa7s98Dbd
         kGFF1ZccuUotSsHzlfwXbDcv4EVXgAbxqVRafxzJCbjEPuELQ/Q7ArmfuUQwFRZkeCJN
         uUfqGgvC2T2JNh32wXfPuPLGORUuTw3kkY/f5GD+6c7clR3LJln4vpFLwTdEIAYhFIRZ
         MUrZQVKEcMSFB7ny/uf3WL8SlIqs/Hdm+1IGDprTpofQrFpiOIEs1vChrthQFrlAIMTc
         u6Tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=EpKxIqmOlqMl7mzttLPN+VwSDt9L8MOcCkjs1vmLiI8=;
        b=tTCM4ADDPx4thv902k7SoVidf1AJVPCQ3dVN9y0SWgtThclMw8z/hespoYI32BMTwJ
         p86JwTQzI/8hxAlttr+LZp2uYJOd8H6Y9hnZTUbeEa1EB7+HqOaZC63a5YPajvyznoBN
         cMTBSffdihTfsK+/fUKl/gdEhW+0URPzWRKGnSDL7uAGd4DRSVlRRW/NuiT/tWgTzYkp
         OMOVDcOGo0w7sDJ7vaGhoYLOsJl7224nsUr21f1SxsDA7x1h+37S2fqZiWW1oLctcEbG
         vq3w1xo0SkUNv3PlS/R7fvqDQIn5jpHk/9vdn77sLBmJZIVp6uo8DwzBffwvSxbKXqx1
         y3yQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KLWyl72H;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x234.google.com (mail-oi1-x234.google.com. [2607:f8b0:4864:20::234])
        by gmr-mx.google.com with ESMTPS id d37si921367ybi.4.2021.02.08.01.52.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Feb 2021 01:52:06 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) client-ip=2607:f8b0:4864:20::234;
Received: by mail-oi1-x234.google.com with SMTP id u66so13060952oig.9
        for <kasan-dev@googlegroups.com>; Mon, 08 Feb 2021 01:52:06 -0800 (PST)
X-Received: by 2002:aca:c505:: with SMTP id v5mr30902oif.172.1612777925613;
 Mon, 08 Feb 2021 01:52:05 -0800 (PST)
MIME-Version: 1.0
References: <YCB4Sgk5g5B2Nu09@arch-chirva.localdomain> <YCCFGc97d2U5yUS7@arch-chirva.localdomain>
 <YCCIgMHkzh/xT4ex@arch-chirva.localdomain>
In-Reply-To: <YCCIgMHkzh/xT4ex@arch-chirva.localdomain>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Feb 2021 10:51:54 +0100
Message-ID: <CANpmjNO9B8KivLB8OnOFzK+M7wf=BGayfJy2+Dr2r2obk_s-fw@mail.gmail.com>
Subject: =?UTF-8?B?UmU6IFBST0JMRU06IDUuMTEuMC1yYzcgZmFpbHMgdG8gY29tcGlsZSB3aXRoIGVycm9yOg==?=
	=?UTF-8?B?IOKAmC1taW5kaXJlY3QtYnJhbmNo4oCZIGFuZCDigJgtZmNmLXByb3RlY3Rpb27igJkgYXJlIG5vdCBj?=
	=?UTF-8?B?b21wYXRpYmxl?=
To: Stuart Little <achirvasub@gmail.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	linux-arch <linux-arch@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Josh Poimboeuf <jpoimboe@redhat.com>, nborisov@suse.com, 
	Borislav Petkov <bp@suse.de>, seth.forshee@canonical.com, 
	Masahiro Yamada <yamada.masahiro@socionext.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andy Lutomirski <luto@kernel.org>, linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KLWyl72H;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as
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

On Mon, 8 Feb 2021 at 01:40, Stuart Little <achirvasub@gmail.com> wrote:
>
> And for good measure: reverting that commit
>
> 20bf2b378729c4a0366a53e2018a0b70ace94bcd
>
> flagged by the bisect right on top of the current tree compiles fine.
>
> On Sun, Feb 07, 2021 at 07:26:01PM -0500, Stuart Little wrote:
> > The result of the bisect on the issue reported in the previous message:
> >
> > --- cut ---
> >
> > 20bf2b378729c4a0366a53e2018a0b70ace94bcd is the first bad commit
> > commit 20bf2b378729c4a0366a53e2018a0b70ace94bcd
> > Author: Josh Poimboeuf <jpoimboe@redhat.com>
> > Date:   Thu Jan 28 15:52:19 2021 -0600
> >
> >     x86/build: Disable CET instrumentation in the kernel
> >
> >     With retpolines disabled, some configurations of GCC, and specifica=
lly
> >     the GCC versions 9 and 10 in Ubuntu will add Intel CET instrumentat=
ion
> >     to the kernel by default. That breaks certain tracing scenarios by
> >     adding a superfluous ENDBR64 instruction before the fentry call, fo=
r
> >     functions which can be called indirectly.
> >
> >     CET instrumentation isn't currently necessary in the kernel, as CET=
 is
> >     only supported in user space. Disable it unconditionally and move i=
t
> >     into the x86's Makefile as CET/CFI... enablement should be a per-ar=
ch
> >     decision anyway.
> >
> >      [ bp: Massage and extend commit message. ]
> >
> >     Fixes: 29be86d7f9cb ("kbuild: add -fcf-protection=3Dnone when using=
 retpoline flags")
> >     Reported-by: Nikolay Borisov <nborisov@suse.com>
> >     Signed-off-by: Josh Poimboeuf <jpoimboe@redhat.com>
> >     Signed-off-by: Borislav Petkov <bp@suse.de>
> >     Reviewed-by: Nikolay Borisov <nborisov@suse.com>
> >     Tested-by: Nikolay Borisov <nborisov@suse.com>
> >     Cc: <stable@vger.kernel.org>
> >     Cc: Seth Forshee <seth.forshee@canonical.com>
> >     Cc: Masahiro Yamada <yamada.masahiro@socionext.com>
> >     Link: https://lkml.kernel.org/r/20210128215219.6kct3h2eiustncws@tre=
ble
> >
> >  Makefile          | 6 ------
> >  arch/x86/Makefile | 3 +++
> >  2 files changed, 3 insertions(+), 6 deletions(-)
> >
> > --- end ---
> >
> > On Sun, Feb 07, 2021 at 06:31:22PM -0500, Stuart Little wrote:
> > > I am trying to compile on an x86_64 host for a 32-bit system; my conf=
ig is at
> > >
> > > https://termbin.com/v8jl
> > >
> > > I am getting numerous errors of the form
> > >
> > > ./include/linux/kasan-checks.h:17:1: error: =E2=80=98-mindirect-branc=
h=E2=80=99 and =E2=80=98-fcf-protection=E2=80=99 are not compatible

This is an empty static inline function...

> > > and
> > >
> > > ./include/linux/kcsan-checks.h:143:6: error: =E2=80=98-mindirect-bran=
ch=E2=80=99 and =E2=80=98-fcf-protection=E2=80=99 are not compatible

... and so is this. I think these have very little to do with the
problem that you reported. My guess is they show up because these are
included very early.

> > > and
> > >
> > > ./arch/x86/include/asm/arch_hweight.h:16:1: error: =E2=80=98-mindirec=
t-branch=E2=80=99 and =E2=80=98-fcf-protection=E2=80=99 are not compatible
> > >
> > > (those include files indicated whom I should add to this list; apolog=
ies if this reaches you in error).
> > >
> > > The full log of the build is at
> > >
> > > https://termbin.com/wbgs

The commonality between all these errors is that they originate from
compiling arch/x86/entry/vdso/vdso32/vclock_gettime.c.

Is the build system adding special flags for vdso? In which case, it's
probably just GCC complaining about every function definition (static
inline or otherwise) for that TU if (for whatever reason) it's
delaying the flag compatibility check until it inspects function
attributes.

And indeed, I can see:

  RETPOLINE_VDSO_CFLAGS_GCC :=3D -mindirect-branch=3Dthunk-inline
-mindirect-branch-register

And taking any test source with even an empty function definition:

  > gcc -mindirect-branch=3Dthunk-inline -fcf-protection test.c
  > test.c: In function =E2=80=98main=E2=80=99:
  > test.c:6:1: error: =E2=80=98-mindirect-branch=E2=80=99 and =E2=80=98-fc=
f-protection=E2=80=99 are
not compatible

> > > 5.11.0-rc6 built fine last week on this same setup.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNO9B8KivLB8OnOFzK%2BM7wf%3DBGayfJy2%2BDr2r2obk_s-fw%40mail.=
gmail.com.
