Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIUC22AQMGQEM2N7IJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C8343233B0
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 23:26:43 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id h13sf209328qti.21
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 14:26:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614119202; cv=pass;
        d=google.com; s=arc-20160816;
        b=mnZFxA25wDKQE+JC138ieokIoAzBe7gk2dVBZYMTZO2iMsOp8Cpm6dPQTSk2dV1J0y
         Sy5ELUNsWAi7sV8znh9AwQ1I0uiBMp2z8AmpscRWaopLgAdFYaqw2tl9ZVqUfwMeo8tw
         ZJDjcQ5fCAFfxcPH3dmxITYSpOF3FKP08UvtaUtvl2Iyvn+DaMmkwhtHuXhft5Wtt98K
         noMKq3ZP0fafYrkab2nIFhAOkuTw5MmYw4o2lx6lsP01FS/aAbl3jPpk6hCye9ZhHSEJ
         PRoUUHPoyfMSei7HA7Cgf7yhQNCsklthuPcBtDwW6AEDZa3sIqvpfv7uh+Cu74pK7PTG
         f7Kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tsQ2dqg7dwY/U1/2haH4ymmz85Mlg9ZcLjlwmAqBgIE=;
        b=DpKrwpfmdr3kLY1nK0e5QGyh/6kYOqP9Yx1OJIuuVsbYBAWwSHrEzf+28q9qUQkfl5
         bGhxYQgDf/uEz6Ieo7YLj6Or6uspe3SZ+VKYVbdLkVLenAMldwuysy6gal/mbv2bkyEw
         5F77Assi0Y747IYKyDgxsiUl3bIBWVz9MEM1fMoro1AHaWGTkh36UaXcAe8OnAuwfvSx
         R6uUEi67s1oOzlLhpSUsmrY9WHzgQZWNSFGj+rgKcCSp5rGbvB9ttRyNic1disH/Cp7p
         BRLQHiIX/+3QMZZ2THnuvUirhKID9DfND+5jO5xqt5Ihcli9GEOfGXZjm14VIVf/EzTx
         6zlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Lkb/fePh";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=tsQ2dqg7dwY/U1/2haH4ymmz85Mlg9ZcLjlwmAqBgIE=;
        b=bzzUvXRog+7mRi2xLVGo7opSSDM5k0uF5s+W2DoTv+w9b769if2P78syxvV6p87yrm
         FQeXFnVDGDL1SF0T2GTeNLFNOZHbhTev8FwYoPsAGSGAyeQHBkvp7tDGZA7t1OGcc2Ul
         C5LWGCTN9SNyn7+PNwSlzSWOsAavKlNIRsm4WtKWr6obYoXwX3Xh2jZkKy33R8iGGMRT
         H8/4aPlE0/199nLyE9RX41DKiuYPyclIIQW1eXUiVbEPlhnaJ9bSp63qJDpvjN2ohgDA
         2COUXf96XCUrd4qv/Yv3v3syBLx9yscroV50o6JAMWNjAZVn0Mzbj6r1cn5O/mOsUBV7
         e/ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tsQ2dqg7dwY/U1/2haH4ymmz85Mlg9ZcLjlwmAqBgIE=;
        b=ZmlAB2ZhqA7+pbY4kunO3X8DIi0sQGLye+LWImj2b2LWa/Yut/6MXbAJsJO26a015b
         eSfibSRcQxcAtbuTy2QcZ4TQNc3tNID2SmJbMfroeU4WeIR3MpNAtBUDnNbU4I6+Zq5s
         FSec+rNPdIwfmBoHXPvYsGyrTT/qOM1PQsLcp1N2uFrxaKZdEvo0ktnV8kKQvZz63M4A
         OltIOqTAEIW0tY3kACAEgv1EJpKbV0WiPBcQICL6rHgc5qXSYYvFR4UQFTve7wGkV/AO
         nM8sTgb/TqGdHsW1wFkNjb5ahKbz1cQm6XIMqFfKuAe1sxWfHlOpXCTGsPyg9UwtJKFC
         nmLQ==
X-Gm-Message-State: AOAM5330++D/mT1TPB6R3+q8Vt1+RiThhKyihb0P+vsWEvnmn88I2Blw
	o9Mes3ISvfqFrr6WqEuncOI=
X-Google-Smtp-Source: ABdhPJya+ojYIaF29c1g2rPHlYVy3doMG1ReJS95TCzqDxwKRcaXc14K9O46O81LrQA5nqJI+MEidg==
X-Received: by 2002:a05:6214:6a2:: with SMTP id s2mr13950550qvz.2.1614119202409;
        Tue, 23 Feb 2021 14:26:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5e13:: with SMTP id h19ls8316889qtx.7.gmail; Tue, 23 Feb
 2021 14:26:41 -0800 (PST)
X-Received: by 2002:ac8:7b23:: with SMTP id l3mr13339246qtu.74.1614119201879;
        Tue, 23 Feb 2021 14:26:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614119201; cv=none;
        d=google.com; s=arc-20160816;
        b=BYqk4jGKxbyDLpftOd8cHaO8sfcWPa0FfS4TnOzED12bZM5919jc5fIM6eBSzYqkV6
         alPrA8T/RjcfAJkIUG5SLtxTfDNl5FwBgAZQm7pSHqzpmG/dHs46ul23P2NXuEUhtP2W
         O7ademtb0o7183zjc5CaKtguySHOTtaeLYF6eLNarIWsBHqDm5DCh9dcC2tMrL0O7pUh
         GqQ7xh1SJ19wXM3dDJSXM2E6Gjao+zbQPzkWLMvOoAuuq7VRdcZOClFMArACT5deTKym
         LhTRyIGTLFnd46DUG6aAxPWwGuuNU3/QFHop/FF8WGBxzkjU/ODowtKCiZ1rcws7tBkR
         hBYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fZxhrFPoVeuINwqWYDTQrRIMFcJNq/iX5+xBlXUPDIw=;
        b=W+ij+zTG8gMnR9jMDBVU0U1xQKZk0EKVgIyVOl+INWJgwvkXJt79EHJjYWVuJ4zho/
         2kXhPdX/W0smTAnEaUxofN0CyO0bW0ILxw7ytIy5oKLwy7/92vkxpY50feM8vQmfkIFN
         18iORNDHQ5RMe6qLcdlNbOwaDtoZWsBBo6GsNPC3eTg+t4p33eE6CQpdinXAtwAKzjcx
         0P/TuKALce/hYqnn/lwM83ZMR40+sWq8VuQGxgDmUF5GsBzvCHrJeoxKvrda54aQqKeB
         NFPc3phQA1ZrqPe6KKV1rLiRafH3vzdyt3wq5wcDeGUSJE26M8TQB4fijl3jibsffUlV
         xkXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Lkb/fePh";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x335.google.com (mail-ot1-x335.google.com. [2607:f8b0:4864:20::335])
        by gmr-mx.google.com with ESMTPS id w30si19317qkw.4.2021.02.23.14.26.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Feb 2021 14:26:41 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) client-ip=2607:f8b0:4864:20::335;
Received: by mail-ot1-x335.google.com with SMTP id s3so261478otg.5
        for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 14:26:41 -0800 (PST)
X-Received: by 2002:a9d:5a05:: with SMTP id v5mr22397134oth.17.1614119201352;
 Tue, 23 Feb 2021 14:26:41 -0800 (PST)
MIME-Version: 1.0
References: <20210223143426.2412737-1-elver@google.com> <3D507285-835F-4C83-8343-2888835971B4@amacapital.net>
In-Reply-To: <3D507285-835F-4C83-8343-2888835971B4@amacapital.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Feb 2021 23:26:29 +0100
Message-ID: <CANpmjNOpq27pDnoPaNON7a_gi7Ls=7xQXBH5-BSe9jwiFE763A@mail.gmail.com>
Subject: Re: [PATCH RFC 0/4] Add support for synchronous signals on perf events
To: Andy Lutomirski <luto@amacapital.net>
Cc: Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Jens Axboe <axboe@kernel.dk>, Matt Morehouse <mascasa@google.com>, 
	Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-m68k@lists.linux-m68k.org, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Lkb/fePh";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as
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

On Tue, 23 Feb 2021 at 21:27, Andy Lutomirski <luto@amacapital.net> wrote:
> > On Feb 23, 2021, at 6:34 AM, Marco Elver <elver@google.com> wrote:
> >
> > =EF=BB=BFThe perf subsystem today unifies various tracing and monitorin=
g
> > features, from both software and hardware. One benefit of the perf
> > subsystem is automatically inheriting events to child tasks, which
> > enables process-wide events monitoring with low overheads. By default
> > perf events are non-intrusive, not affecting behaviour of the tasks
> > being monitored.
> >
> > For certain use-cases, however, it makes sense to leverage the
> > generality of the perf events subsystem and optionally allow the tasks
> > being monitored to receive signals on events they are interested in.
> > This patch series adds the option to synchronously signal user space on
> > events.
>
> Unless I missed some machinations, which is entirely possible, you can=E2=
=80=99t call force_sig_info() from NMI context. Not only am I not convinced=
 that the core signal code is NMI safe, but at least x86 can=E2=80=99t corr=
ectly deliver signals on NMI return. You probably need an IPI-to-self.

force_sig_info() is called from an irq_work only: perf_pending_event
-> perf_pending_event_disable -> perf_sigtrap -> force_sig_info. What
did I miss?

> > The discussion at [1] led to the changes proposed in this series. The
> > approach taken in patch 3/4 to use 'event_limit' to trigger the signal
> > was kindly suggested by Peter Zijlstra in [2].
> >
> > [1] https://lore.kernel.org/lkml/CACT4Y+YPrXGw+AtESxAgPyZ84TYkNZdP0xpoc=
X2jwVAbZD=3D-XQ@mail.gmail.com/
> > [2] https://lore.kernel.org/lkml/YBv3rAT566k+6zjg@hirez.programming.kic=
ks-ass.net/
> >
> > Motivation and example uses:
> >
> > 1.    Our immediate motivation is low-overhead sampling-based race
> >    detection for user-space [3]. By using perf_event_open() at
> >    process initialization, we can create hardware
> >    breakpoint/watchpoint events that are propagated automatically
> >    to all threads in a process. As far as we are aware, today no
> >    existing kernel facility (such as ptrace) allows us to set up
> >    process-wide watchpoints with minimal overheads (that are
> >    comparable to mprotect() of whole pages).
>
> This would be doable much more simply with an API to set a breakpoint.  A=
ll the machinery exists except the actual user API.

Isn't perf_event_open() that API?

A new user API implementation will either be a thin wrapper around
perf events or reinvent half of perf events to deal with managing
watchpoints across a set of tasks (process-wide or some subset).

It's not just breakpoints though.

> >    [3] https://llvm.org/devmtg/2020-09/slides/Morehouse-GWP-Tsan.pdf
> >
> > 2.    Other low-overhead error detectors that rely on detecting
> >    accesses to certain memory locations or code, process-wide and
> >    also only in a specific set of subtasks or threads.
> >
> > Other example use-cases we found potentially interesting:
> >
> > 3.    Code hot patching without full stop-the-world. Specifically, by
> >    setting a code breakpoint to entry to the patched routine, then
> >    send signals to threads and check that they are not in the
> >    routine, but without stopping them further. If any of the
> >    threads will enter the routine, it will receive SIGTRAP and
> >    pause.
>
> Cute.
>
> >
> > 4.    Safepoints without mprotect(). Some Java implementations use
> >    "load from a known memory location" as a safepoint. When threads
> >    need to be stopped, the page containing the location is
> >    mprotect()ed and threads get a signal. This can be replaced with
> >    a watchpoint, which does not require a whole page nor DTLB
> >    shootdowns.
>
> I=E2=80=99m skeptical. Propagating a hardware breakpoint to all threads i=
nvolves IPIs and horribly slow writes to DR1 (or 2, 3, or 4) and DR7.  A TL=
B flush can be accelerated using paravirt or hypothetical future hardware. =
Or real live hardware on ARM64.
>
> (The hypothetical future hardware is almost present on Zen 3.  A bit of w=
ork is needed on the hardware end to make it useful.)

Fair enough. Although watchpoints can be much more fine-grained than
an mprotect() which then also has downsides (checking if the accessed
memory was actually the bytes we're interested in). Maybe we should
also ask CPU vendors to give us better watchpoints (perhaps start with
more of them, and easier to set in batch)? We still need a user space
API...

Thanks,
-- Marco



> >
> > 5.    Tracking data flow globally.
> >
> > 6.    Threads receiving signals on performance events to
> >    throttle/unthrottle themselves.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOpq27pDnoPaNON7a_gi7Ls%3D7xQXBH5-BSe9jwiFE763A%40mail.gmai=
l.com.
