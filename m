Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLN72WAQMGQE2SYVG3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 000CB3231BD
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 21:03:58 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id c3sf12846879ioa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 12:03:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614110638; cv=pass;
        d=google.com; s=arc-20160816;
        b=PHDuggGFOsZJT1bV097Wl+6imHRWy9ZHBGYzVncmoj4l+dv5PFAmiL9680+3Ve2w35
         31p8XM4H5OHPpOFTSwiTcVMzSYLfT4hvmms2UXDJUmRUl0YtgW8qZU31axwkI2XyOGjj
         xZPM6t50ZTgfCEQcMR/iytQaCq4jym9JERJLSjvWAHO9lUjDRYbrTxxr3cAbESrLy3jj
         Rl98utE2rwViCKxvJAmHvvvJVn7d4Bxo5U5ZObnrn06Ralz0OExRBNYgDxgJDB/PIihK
         OG4LhBGLVSO0MazFycYIAcrKeFUOFWhFYL6zVyB7mqknJo9DQ2Hr+E9SWp525vwnHSkI
         RiIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=q7TZ/hAnq7ETHbZ8r19MkiKeyh8+c94Z4zw5qk/FM3Q=;
        b=kwFDM3FrAEy4Qy2ROJP4CYeVdo1yNe0LXzrUUMBPspO9Je1qPQt92SmoN0k2+Vafvs
         Meq4G3lCPt0Pv66HxE0viL8u0XZYPuz05GQbbiv+iqjTMPRJxo9/gqL3sAQ4SEnkKWRq
         WPJXZwveXYB86Vi8Ra1pXuWJCcZFw8m0YV2Ab6NewNpHz1ToByAW3o5S2YAUQRkz91TR
         XEGbe2USPImdWakUMhxHV7ZMJlOQ9v0jksajXp4QVzzlPj0OhDeBEc1+AgfUFVJCODUc
         7YTLGiRlpt5Uxxx9IrDepEZ7VR5e4iQd02nhftjWiuohmWzz87NOVueYFnRPYpB9hYkS
         WQWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uueyZEhC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q7TZ/hAnq7ETHbZ8r19MkiKeyh8+c94Z4zw5qk/FM3Q=;
        b=mM9dLxtLGcVccUpIHxK7VkSjPe8QxUJOBa3zBL4ELYL32ugEdmmQxdEIxqktrRyiX2
         3AlADWQ5NaOCPTztqdgOxoEY9myTDMYajBrT3Qblij7sdtzsJ/A0K3DkhWdQlhZH468a
         LdPrwvgFdkM0KwR8gfYv+HEGM+KVRt5Dhm001wBIyISfKStO/g/JmAhroLO3ROMnUWJ7
         NAL4sjFFAqjsOczTaDfWDsGbb9KzE0WsU+l6NPg1XoDYxfcmKtMmwLFjb3E5G/n9+1Zk
         khx+2ZnaAdlVl8Y9Ah3sQ609QXbY4qMkCZUdPhIHy0RGcXBAHIkDyk1caHPxRhwkN1Eg
         U7lQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q7TZ/hAnq7ETHbZ8r19MkiKeyh8+c94Z4zw5qk/FM3Q=;
        b=Tclmw4xN3bRonefrML8VolRlRteF/MgTNBnCyduXw/wODSmJ608WMkFbXLv4rzun7N
         WBmQ1se39SAHZWyZOyZ7UamAFLdqO2nEYqCPdPItkTAojWG9M3UXg3dCGVgjGbE4eN9D
         6Byj9iv7oaMCkti+l3stHHbJHg7hxKeiZ1NKRce9UUdyMnSnw3oN6gSdI5Ua4ZI9rGGm
         3fgEa3qyyWjGFQwexVSs9ONct0Cr/4JKgjFthH5RdLp4oQM8PLCx336CNA0d2tg9XesL
         GSD25oT7zSNXEET6ytlNNVF9lO94xWDBPSNLXnlsFFfeTvQK1KvoFEeTKuYyhnG+p9hY
         m8tA==
X-Gm-Message-State: AOAM531edP3X8ywzcc4xyk0NL4cgglTt74FfXc95oXdNrGN8e90L6KIF
	biqrIkjayeoLVO3b8zPkMt4=
X-Google-Smtp-Source: ABdhPJx119fXy5q4X7b+uLX5SRWRhnJvu6W4XNytf3Ebk2zSPUSTnKL1h/wUW1Mz+XmkH6mFw7CEpA==
X-Received: by 2002:a05:6e02:1564:: with SMTP id k4mr21163865ilu.282.1614110637444;
        Tue, 23 Feb 2021 12:03:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:860b:: with SMTP id f11ls3777700iol.10.gmail; Tue, 23
 Feb 2021 12:03:57 -0800 (PST)
X-Received: by 2002:a5e:8a03:: with SMTP id d3mr10554994iok.135.1614110637121;
        Tue, 23 Feb 2021 12:03:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614110637; cv=none;
        d=google.com; s=arc-20160816;
        b=BvP9vXu0gOS1BuNUAajO3DSoKqx3SCiTrx88uO5I8iOMh9oEvCMFaJ4TXZqr3k0e+y
         MJXpjRA22L16UkZoAnSzoA71NbbRjfix/vmAnF1GGu527SPN0K6vD5rtL/sXYTpCKgAW
         iTgdhShY4Pa5pR3r0nA66jL9kdbH5E+5aV0pR3AKfiXM84S6fw0WHkX3Ccwah4mSoJU7
         e/diEZukIttHUBlS7IJGgQVlRf5GD2qB+BsTOxdvKbIPif8GeWuO6fp5s4CAkdGHCSWt
         sbw9vbrjGQ901xmZVQOaEpYYM6FzoLrVwhxTu01aPqLGktsPj/YxfoKjcKZsmFyPOhPS
         o4uQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KDbWfjB7meY0E7XLsjIrc5m2e7z/Yrkuj6hZaVwwlGE=;
        b=PWA26D9syOoI3xqU4RpvpN1GxgdtF3+NN4Vstfe78oX0xoqoatfTysoOoLahXGTJL5
         aZQrdt9hb657CHzTRAYI8yiD+XSHU5inQa7EFKjkz2dVXulg6MYoMRiocc9e0BiAAw7v
         95XjVmyUp8w/uYBOpkwRcqO6tUzo0EbBP53W+7dZ1gvNofuvZNtY79DvP+A6Mau6upHg
         yxaRo9CZYCQGJ2HIWZin15Yw9iAR0PtgrXHCbkfzCltSlxwO/bzqSagQr010iXZPYqBT
         DzSsJJ5NSQvZz+A82Y8NuQ5PyhXEAAhio0zjbEECnYlq+KhdVvzQvyl/Ss/k/n3+qET4
         DRfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uueyZEhC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32a.google.com (mail-ot1-x32a.google.com. [2607:f8b0:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id v81si1190346iod.4.2021.02.23.12.03.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Feb 2021 12:03:57 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) client-ip=2607:f8b0:4864:20::32a;
Received: by mail-ot1-x32a.google.com with SMTP id r19so9618101otk.2
        for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 12:03:57 -0800 (PST)
X-Received: by 2002:a05:6830:18e6:: with SMTP id d6mr22473227otf.251.1614110636519;
 Tue, 23 Feb 2021 12:03:56 -0800 (PST)
MIME-Version: 1.0
References: <20210223143426.2412737-1-elver@google.com>
In-Reply-To: <20210223143426.2412737-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Feb 2021 21:03:44 +0100
Message-ID: <CANpmjNPEzA0EP9zEGE-O7tz=3EhKjdhVi43jbhoTDRG5wo3C1A@mail.gmail.com>
Subject: Re: [PATCH RFC 0/4] Add support for synchronous signals on perf events
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>
Cc: Alexander Potapenko <glider@google.com>, Al Viro <viro@zeniv.linux.org.uk>, 
	Arnd Bergmann <arnd@arndb.de>, Christian Brauner <christian@brauner.io>, Dmitry Vyukov <dvyukov@google.com>, 
	Jann Horn <jannh@google.com>, Jens Axboe <axboe@kernel.dk>, Matt Morehouse <mascasa@google.com>, 
	Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-m68k@lists.linux-m68k.org, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uueyZEhC;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as
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

On Tue, 23 Feb 2021 at 15:34, Marco Elver <elver@google.com> wrote:
>
> The perf subsystem today unifies various tracing and monitoring
> features, from both software and hardware. One benefit of the perf
> subsystem is automatically inheriting events to child tasks, which
> enables process-wide events monitoring with low overheads. By default
> perf events are non-intrusive, not affecting behaviour of the tasks
> being monitored.
>
> For certain use-cases, however, it makes sense to leverage the
> generality of the perf events subsystem and optionally allow the tasks
> being monitored to receive signals on events they are interested in.
> This patch series adds the option to synchronously signal user space on
> events.
>
> The discussion at [1] led to the changes proposed in this series. The
> approach taken in patch 3/4 to use 'event_limit' to trigger the signal
> was kindly suggested by Peter Zijlstra in [2].
>
> [1] https://lore.kernel.org/lkml/CACT4Y+YPrXGw+AtESxAgPyZ84TYkNZdP0xpocX2jwVAbZD=-XQ@mail.gmail.com/
> [2] https://lore.kernel.org/lkml/YBv3rAT566k+6zjg@hirez.programming.kicks-ass.net/
>
> Motivation and example uses:
>
> 1.      Our immediate motivation is low-overhead sampling-based race
>         detection for user-space [3]. By using perf_event_open() at
>         process initialization, we can create hardware
>         breakpoint/watchpoint events that are propagated automatically
>         to all threads in a process. As far as we are aware, today no
>         existing kernel facility (such as ptrace) allows us to set up
>         process-wide watchpoints with minimal overheads (that are
>         comparable to mprotect() of whole pages).
>
>         [3] https://llvm.org/devmtg/2020-09/slides/Morehouse-GWP-Tsan.pdf
>
> 2.      Other low-overhead error detectors that rely on detecting
>         accesses to certain memory locations or code, process-wide and
>         also only in a specific set of subtasks or threads.
>
> Other example use-cases we found potentially interesting:
>
> 3.      Code hot patching without full stop-the-world. Specifically, by
>         setting a code breakpoint to entry to the patched routine, then
>         send signals to threads and check that they are not in the
>         routine, but without stopping them further. If any of the
>         threads will enter the routine, it will receive SIGTRAP and
>         pause.
>
> 4.      Safepoints without mprotect(). Some Java implementations use
>         "load from a known memory location" as a safepoint. When threads
>         need to be stopped, the page containing the location is
>         mprotect()ed and threads get a signal. This can be replaced with
>         a watchpoint, which does not require a whole page nor DTLB
>         shootdowns.
>
> 5.      Tracking data flow globally.
>
> 6.      Threads receiving signals on performance events to
>         throttle/unthrottle themselves.
>
>
> Marco Elver (4):
>   perf/core: Apply PERF_EVENT_IOC_MODIFY_ATTRIBUTES to children
>   signal: Introduce TRAP_PERF si_code and si_perf to siginfo
>   perf/core: Add support for SIGTRAP on perf events
>   perf/core: Add breakpoint information to siginfo on SIGTRAP

Note that we're currently pondering fork + exec, and suggestions would
be appreciated. We think we'll need some restrictions, like Peter
proposed here: here:
https://lore.kernel.org/lkml/YBvj6eJR%2FDY2TsEB@hirez.programming.kicks-ass.net/

We think what we want is to inherit the events to children only if
cloned with CLONE_SIGHAND. If there's space for a 'inherit_mask' in
perf_event_attr, that'd be most flexible, but perhaps we do not have
the space.

Thanks,
-- Marco

>
>  arch/m68k/kernel/signal.c          |  3 ++
>  arch/x86/kernel/signal_compat.c    |  5 ++-
>  fs/signalfd.c                      |  4 +++
>  include/linux/compat.h             |  2 ++
>  include/linux/signal.h             |  1 +
>  include/uapi/asm-generic/siginfo.h |  6 +++-
>  include/uapi/linux/perf_event.h    |  3 +-
>  include/uapi/linux/signalfd.h      |  4 ++-
>  kernel/events/core.c               | 54 +++++++++++++++++++++++++++++-
>  kernel/signal.c                    | 11 ++++++
>  10 files changed, 88 insertions(+), 5 deletions(-)
>
> --
> 2.30.0.617.g56c4b15f3c-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPEzA0EP9zEGE-O7tz%3D3EhKjdhVi43jbhoTDRG5wo3C1A%40mail.gmail.com.
