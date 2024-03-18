Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUOC4GXQMGQEE4MDCWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 60FA787EC62
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Mar 2024 16:44:19 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5a4b8bad9aesf845806eaf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Mar 2024 08:44:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710776658; cv=pass;
        d=google.com; s=arc-20160816;
        b=EdlDXW6MCRjPhRp2VRWFEDM32ifMxclhPXC/rWyGWJ2clpoZWXZs61buQh3E2OcCnP
         dnV+Gx3v+txgva/nrE9o1T086OM8MjszVLABXpxhWMDFjxmITc/2l1cjyuoAEjm5yLNU
         nZIQiFnEVsSQasQuLn2ZDOEm43S4FWndSRnkaWoJGuS+xlF+NDcgH67LgpYlsvP+9VLk
         glCb4o7Z/VAJ+Eyt6goomTuAHQvxzC6HRxd7BcbzsfbejdGzPJrqs9PsJTafWdabRFrN
         38Oaq6GVyfh1bT6qOfrrE6X+rBfk3DszJhm2vaWTraqxwzh1kiJOk4Bzh1tq+2iI4fUl
         kcYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=m53NEjyPisNiEwKh+hFrpS3Qr47wC7Q5Ji9Qyx9cz5c=;
        fh=iw9HhyPBJ4bWe1veT6nqCdGAuv5PE6ShuonkMroPz2g=;
        b=wSOvlXK7Vt7VUR1Tv+g/WTo5+bIyQReN3UFCflBQ1GD3tEIM89ZQZr4BYWWUuSH/St
         Er66I6pa7jNbrv75zeW6MPviI969XzCxf/DyHD5LADHUR+2ULJpFTnELs5EshVYyRpkR
         V8UWnEmlrHVQG5Ubi3sabLXzfXgx+nJCBhND7sqWHT0CVPWXFlbyMYUjjGSl/7UkU6M1
         Pg0r3K2AF64MWuibOipUeXGZQ2bRtNW4I4nK6DKahXKL1ospdl+I/ymKn0zRuulSplmd
         5LmEgZUzpaEZIoaLPKr79QYCa0/ghMftrz8UAqpJM8HHzxGnTWpBt2Rm2oopfH25qoHJ
         qXMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aJgp+orK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710776658; x=1711381458; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=m53NEjyPisNiEwKh+hFrpS3Qr47wC7Q5Ji9Qyx9cz5c=;
        b=E7DwAGnjwy8MVCXxgcRpkLNXJfCZzoH2GYLYwc5Qp9LMU/abJMjt7ZW4otYXAklW88
         FG/PGEaGOz/vLC23ePgkBQDf01uBopGltUjsPEQl2DU36Z8uM6sH011EUGnEfJGsEr0K
         99Q2h/xDizUqaPgffpEalsAxlJuendyz2ssrZRR3hQ42cSM2b3AaDKuBjGq9on3yJXxH
         8fj9fsGqCcob/oc/dSmy5AtOZYcN3QlvujdD3awYvfsCQdvzCB6V9Yb7S/7vdh8ZE7GP
         qXtMj7kSsug7b/JIQ4p7ey5Z9R1PrVBQMR+R36e4m/FvsshRHlyoZGYsvL+3+Yp+1NXT
         n8bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710776658; x=1711381458;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=m53NEjyPisNiEwKh+hFrpS3Qr47wC7Q5Ji9Qyx9cz5c=;
        b=BZQMUTGR2l3k8v1n0m88g4nuh9U7TM0MKOlKMSpO7yMeDNiXqCGLTcLUxPjsqb6Zc/
         Q/oED7TAQarmRhsgaZGSPmi37wPL4O00LJCMMXfgyBdqb35kwTl7nzU9S7Tl/fTJvmez
         VjCYTUIbgo7wMNVU69ZdNnn6qdpJuQ18P+t+g4sdvCG6htI8pqTWpekrFnOQSPFR4iMm
         yJBFfjzUYi58sTnMkb9dKlc4//D4CHPFmy6ui3ES3U6RdrqDtxwCrghZh3JIBRWgflUC
         51IUqSKquM6F5OwJeMCoL+wUCwIBS5HjtCZTMrsX79dF3A3tW2qXfCfo69BHiCAU3f0b
         q4oA==
X-Forwarded-Encrypted: i=2; AJvYcCU4Ly6PA69xN3jBk97Qovh7eHMVC1otKdTp2QFd0n6NDciaCwr040izQF8x51VnZQr0QHfNJZsra2iCUW+xQ0zh5/V7oo8HCg==
X-Gm-Message-State: AOJu0Yxx0HqjHNha1GRq1V6e5/JDzTBwevkvhZZ+ApWk40NwZBmWS0qN
	pbbsmLKq+n9ulxJbreBou2j27R4duIOHh/nHBvllvnj1VxSM0ZrV
X-Google-Smtp-Source: AGHT+IGRKvkbJp6MQj71LFXYwRsE0utIbLkDd7zwCOySpqo3LrymgIcGfJGj9KeAMqXxrmzG0/uhYQ==
X-Received: by 2002:a05:6820:2714:b0:5a4:91c1:967b with SMTP id db20-20020a056820271400b005a491c1967bmr5109120oob.1.1710776657907;
        Mon, 18 Mar 2024 08:44:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:2299:b0:5a4:905d:743f with SMTP id
 ck25-20020a056820229900b005a4905d743fls832150oob.1.-pod-prod-05-us; Mon, 18
 Mar 2024 08:44:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWnV6sW6FDfbBGEB2QnyhfoAaLO2tBX0pacxuWHog8rFuRp54Wh1Mi6N3at+ij8s7KqohQ1mM2RUc4YYqc253BY89jMK54tVCn7lw==
X-Received: by 2002:a05:6808:bc9:b0:3c2:5eff:3d08 with SMTP id o9-20020a0568080bc900b003c25eff3d08mr14007057oik.3.1710776657059;
        Mon, 18 Mar 2024 08:44:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710776657; cv=none;
        d=google.com; s=arc-20160816;
        b=sq8iLWRvKdBY4RCw8IMrZDSU45J419MmRmYi05AHWGXZxAZVGqlu3XRD7LJ4hPso13
         lqIqD3dNkD8EnxcoflvW80sEetRjPsc3BugJNwcGqz8959maPCxHkclP8M11ctGLB1bj
         FlYMe3cpNeBYA4O5cT+xA0YtNtl2bn/uWAnzum7Nxznb50im4KUajIpqLem0poNNPGbx
         pOozuh7vW7FYLt6C8eDsArVo0o38mUPIZvc/vCotRlcRJhFFB9hS+CeVwdoOMbuIGpob
         9FnVM8Wi+hffmoBahP/THbADZb/UMkxAqBYMGXkoXALe/UTv5lUBtuSKjwqoVVOQd01Y
         ZBng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jzbjB+Gs1Kwvcbil1vU+BLYNe1OnSHfExrWee+0iEgg=;
        fh=z5j7CxAvFcU7uvT8xRWx/gOT7YP47BCFlOnQcjWmcy0=;
        b=YojmGMbbwB8dCbPYY36yevLQFDwP35Siwzeh1GJzzja8+5bAos+gCwgHwUPXHzSc6p
         AGby1GFImmcw2Sevb5PlMgBBCJOPUYWQ6zhCT4Md6TiCtXsDQ/XPTlzAaNWusp1LVUO4
         NVTdOk0gS4gTiTguN1gwDlrXQvh8G5Eifyh0LsF6TtmnJ06NTsOfqUB6p/h1ssAgyatM
         kOy3x8QDBK/DjqQoH4EYiZy5unbT2my/hYFSJbjhU/I4AhO1RWgmDuP2o+LcMtftMFZE
         3hNv0v8u+0K40vWlIjB5YpQuBX6un7GFrpVY9wdJSy4VJXmMdMskU/ScSO9UH6a0N0ca
         Hipw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aJgp+orK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa34.google.com (mail-vk1-xa34.google.com. [2607:f8b0:4864:20::a34])
        by gmr-mx.google.com with ESMTPS id bd1-20020a056808220100b003c1ca7945f4si959764oib.4.2024.03.18.08.44.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Mar 2024 08:44:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a34 as permitted sender) client-ip=2607:f8b0:4864:20::a34;
Received: by mail-vk1-xa34.google.com with SMTP id 71dfb90a1353d-4d4552911ceso304905e0c.2
        for <kasan-dev@googlegroups.com>; Mon, 18 Mar 2024 08:44:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUhLiMz31KpWktup86FIP666jbX4xaHFjEfm7DRaGdxx6KEVo2sKSdf1NLzpggkWoS/8rlLgM6i8tm/1rKqWR4a3bYzsrtVZ/mH/g==
X-Received: by 2002:a05:6122:36a6:b0:4d3:362f:f9c1 with SMTP id
 ec38-20020a05612236a600b004d3362ff9c1mr8716909vkb.13.1710776656296; Mon, 18
 Mar 2024 08:44:16 -0700 (PDT)
MIME-Version: 1.0
References: <0733eb10-5e7a-4450-9b8a-527b97c842ff@paulmck-laptop>
 <CANpmjNO+0d82rPCQ22xrEEqW_3sk7T28Dv95k1jnB7YmG3amjA@mail.gmail.com>
 <53a68e29-cd33-451e-8cf0-f6576da40ced@paulmck-laptop> <67baae71-da4f-4eda-ace7-e4f61d2ced0c@paulmck-laptop>
 <CANpmjNOmpOCfaFyMUnMtc3TT=VuTpWC4c85FW_u4dobmtikHtQ@mail.gmail.com>
In-Reply-To: <CANpmjNOmpOCfaFyMUnMtc3TT=VuTpWC4c85FW_u4dobmtikHtQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 Mar 2024 16:43:38 +0100
Message-ID: <CANpmjNNLXR1kC8XAqFjEO3N0P3scRott8Z1OcW2yoKu5BEDaYQ@mail.gmail.com>
Subject: Re: [PATCH RFC rcu] Inform KCSAN of one-byte cmpxchg() in rcu_trc_cmpxchg_need_qs()
To: paulmck@kernel.org
Cc: rcu@vger.kernel.org, kasan-dev@googlegroups.com, dvyukov@google.com, 
	glider@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=aJgp+orK;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a34 as
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

On Mon, 18 Mar 2024 at 11:01, Marco Elver <elver@google.com> wrote:
>
> On Sun, 17 Mar 2024 at 22:55, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Fri, Mar 08, 2024 at 02:31:53PM -0800, Paul E. McKenney wrote:
> > > On Fri, Mar 08, 2024 at 11:02:28PM +0100, Marco Elver wrote:
> > > > On Fri, 8 Mar 2024 at 22:41, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > >
> > > > > Tasks Trace RCU needs a single-byte cmpxchg(), but no such thing exists.
> > > >
> > > > Because not all architectures support 1-byte cmpxchg?
> > > > What prevents us from implementing it?
> > >
> > > Nothing that I know of, but I didn't want to put up with the KCSAN report
> > > in the interim.
> >
> > And here is a lightly tested patch to emulate one-byte and two-byte
> > cmpxchg() for architectures that do not support it.  This is just the
> > emulation, and would be followed up with patches to make the relevant
> > architectures make use of it.
> >
> > The one-byte emulation has been lightly tested on x86.
> >
> > Thoughts?
> >
> >                                                         Thanx, Paul
> >
> > ------------------------------------------------------------------------
> >
> > commit d72e54166b56d8b373676e1e92a426a07d53899a
> > Author: Paul E. McKenney <paulmck@kernel.org>
> > Date:   Sun Mar 17 14:44:38 2024 -0700
> >
> >     lib: Add one-byte and two-byte cmpxchg() emulation functions
> >
> >     Architectures are required to provide four-byte cmpxchg() and 64-bit
> >     architectures are additionally required to provide eight-byte cmpxchg().
> >     However, there are cases where one-byte and two-byte cmpxchg()
> >     would be extremely useful.  Therefore, provide cmpxchg_emu_u8() and
> >     cmpxchg_emu_u16() that emulated one-byte and two-byte cmpxchg() in terms
> >     of four-byte cmpxchg().
> >
> >     Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> >     Cc: Marco Elver <elver@google.com>
> >     Cc: Andrew Morton <akpm@linux-foundation.org>
> >     Cc: Thomas Gleixner <tglx@linutronix.de>
> >     Cc: "Peter Zijlstra (Intel)" <peterz@infradead.org>
> >     Cc: Douglas Anderson <dianders@chromium.org>
> >     Cc: Petr Mladek <pmladek@suse.com>
> >     Cc: <linux-arch@vger.kernel.org>
> >
> > diff --git a/arch/Kconfig b/arch/Kconfig
> > index 154f994547632..eef11e9918ec7 100644
> > --- a/arch/Kconfig
> > +++ b/arch/Kconfig
> > @@ -1506,4 +1506,7 @@ config FUNCTION_ALIGNMENT
> >         default 4 if FUNCTION_ALIGNMENT_4B
> >         default 0
> >
> > +config ARCH_NEED_CMPXCHG_1_2_EMU
> > +       bool
> > +
> >  endmenu
> > diff --git a/include/linux/cmpxchg-emu.h b/include/linux/cmpxchg-emu.h
> > new file mode 100644
> > index 0000000000000..fee8171fa05eb
> > --- /dev/null
> > +++ b/include/linux/cmpxchg-emu.h
> > @@ -0,0 +1,16 @@
> > +/* SPDX-License-Identifier: GPL-2.0+ */
> > +/*
> > + * Emulated 1-byte and 2-byte cmpxchg operations for architectures
> > + * lacking direct support for these sizes.  These are implemented in terms
> > + * of 4-byte cmpxchg operations.
> > + *
> > + * Copyright (C) 2024 Paul E. McKenney.
> > + */
> > +
> > +#ifndef __LINUX_CMPXCHG_EMU_H
> > +#define __LINUX_CMPXCHG_EMU_H
> > +
> > +uintptr_t cmpxchg_emu_u8(volatile u8 *p, uintptr_t old, uintptr_t new);
> > +uintptr_t cmpxchg_emu_u16(volatile u16 *p, uintptr_t old, uintptr_t new);
> > +
> > +#endif /* __LINUX_CMPXCHG_EMU_H */
> > diff --git a/lib/Makefile b/lib/Makefile
> > index 6b09731d8e619..fecd7b8c09cbd 100644
> > --- a/lib/Makefile
> > +++ b/lib/Makefile
> > @@ -238,6 +238,7 @@ obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
> >  lib-$(CONFIG_GENERIC_BUG) += bug.o
> >
> >  obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) += syscall.o
> > +obj-$(CONFIG_ARCH_NEED_CMPXCHG_1_2_EMU) += cmpxchg-emu.o
>
> Since you add instrumentation explicitly, we need to suppress
> instrumentation somehow. For the whole file this can be done with:
>
> KCSAN_SANITIZE_cmpxchg-emu.o := n

Hrm, I recall this doesn't actually work as-is because it also
disables instrument_read_write() instrumentation.

So I think the most reliable would be to use data_race() after all.
It'll be a bit slower because of double-instrumenting, but I think
that's not a major concern with an instrumented build anyway.

> Note, since you use cmpxchg, which pulls in its own
> instrument_read_write(), we can't use a function attribute (like
> __no_kcsan) if the whole-file no-instrumentation seems like overkill.
> Alternatively the cmpxchg could be wrapped into a data_race() (like
> your original RCU use case was doing).
>
> But I think "KCSAN_SANITIZE_cmpxchg-emu.o := n" would be my preferred way.
>
> With the explicit "instrument_read_write()" also note that this would
> do double-instrumentation with other sanitizers (KASAN, KMSAN). But I
> think we actually want to instrument the whole real access with those
> tools - would it be bad if we accessed some memory out-of-bounds, but
> that memory isn't actually used? I don't have a clear answer to that.
>
> Also, it might be useful to have an alignment check somewhere, because
> otherwise we end up with split atomic accesses (or whatever other bad
> thing the given arch does if that happens).
>
> Thanks,
> -- Marco
>
> >  obj-$(CONFIG_DYNAMIC_DEBUG_CORE) += dynamic_debug.o
> >  #ensure exported functions have prototypes
> > diff --git a/lib/cmpxchg-emu.c b/lib/cmpxchg-emu.c
> > new file mode 100644
> > index 0000000000000..508b55484c2b6
> > --- /dev/null
> > +++ b/lib/cmpxchg-emu.c
> > @@ -0,0 +1,68 @@
> > +/* SPDX-License-Identifier: GPL-2.0+ */
> > +/*
> > + * Emulated 1-byte and 2-byte cmpxchg operations for architectures
> > + * lacking direct support for these sizes.  These are implemented in terms
> > + * of 4-byte cmpxchg operations.
> > + *
> > + * Copyright (C) 2024 Paul E. McKenney.
> > + */
> > +
> > +#include <linux/types.h>
> > +#include <linux/export.h>
> > +#include <linux/instrumented.h>
> > +#include <linux/atomic.h>
> > +#include <asm-generic/rwonce.h>
> > +
> > +union u8_32 {
> > +       u8 b[4];
> > +       u32 w;
> > +};
> > +
> > +/* Emulate one-byte cmpxchg() in terms of 4-byte cmpxchg. */
> > +uintptr_t cmpxchg_emu_u8(volatile u8 *p, uintptr_t old, uintptr_t new)
> > +{
> > +       u32 *p32 = (u32 *)(((uintptr_t)p) & ~0x3);
> > +       int i = ((uintptr_t)p) & 0x3;
> > +       union u8_32 old32;
> > +       union u8_32 new32;
> > +       u32 ret;
> > +
> > +       old32.w = READ_ONCE(*p32);
> > +       do {
> > +               if (old32.b[i] != old)
> > +                       return old32.b[i];
> > +               new32.w = old32.w;
> > +               new32.b[i] = new;
> > +               instrument_atomic_read_write(p, 1);
> > +               ret = cmpxchg(p32, old32.w, new32.w);
> > +       } while (ret != old32.w);
> > +       return old;
> > +}
> > +EXPORT_SYMBOL_GPL(cmpxchg_emu_u8);
> > +
> > +union u16_32 {
> > +       u16 h[2];
> > +       u32 w;
> > +};
> > +
> > +/* Emulate two-byte cmpxchg() in terms of 4-byte cmpxchg. */
> > +uintptr_t cmpxchg_emu_u16(volatile u16 *p, uintptr_t old, uintptr_t new)
> > +{
> > +       u32 *p32 = (u32 *)(((uintptr_t)p) & ~0x1);
> > +       int i = ((uintptr_t)p) & 0x1;
> > +       union u16_32 old32;
> > +       union u16_32 new32;
> > +       u32 ret;
> > +
> > +       old32.w = READ_ONCE(*p32);
> > +       do {
> > +               if (old32.h[i] != old)
> > +                       return old32.h[i];
> > +               new32.w = old32.w;
> > +               new32.h[i] = new;
> > +               instrument_atomic_read_write(p, 2);
> > +               ret = cmpxchg(p32, old32.w, new32.w);
> > +       } while (ret != old32.w);
> > +       return old;
> > +}
> > +EXPORT_SYMBOL_GPL(cmpxchg_emu_u16);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNLXR1kC8XAqFjEO3N0P3scRott8Z1OcW2yoKu5BEDaYQ%40mail.gmail.com.
