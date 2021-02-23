Return-Path: <kasan-dev+bncBD42DY67RYARBHWK2WAQMGQEMDTTPWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C6BC32320E
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 21:27:11 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id e19sf6773324ote.10
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 12:27:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614112030; cv=pass;
        d=google.com; s=arc-20160816;
        b=ekMgDLmVtlBV4fiySvGfL/1NUDPel7l7VfBHml7/vwW6SO9qsu025Z2f25BPtUsP3Y
         8i0gTPWOz+dCumTxtEcYDauR7J8PRanQuCJDdREWXW1TwjYrquHCKj5S8e00vnmWAVoo
         XL6CU0T4h6+VkjYFP89STJXqZch1IrIB3qCHZ6RcMiqa79ADPISUmWHpXiwaMH7qiwj0
         51UPg0mHwK1NT52igqPLnSLkBsreGeOcanpobltkMSfDFvPDffS49hHXtCTwh98FfrCP
         xo3VATELzVQkhytmxUoeP803KMgM/kM4BeAnxC+hajfphmgUy0pIciS9NECF3FvLEIbT
         R/EA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=jGrsHLSiZWT2dLa1VTT4nGlAV7OG5Ps+dKRD8W/Sr6U=;
        b=MuYpzRFlR3eoRSagbiZqhjL1+jSW26Am6Y4Nna1LxVGSmhDRLzw8KJpuYiHfDXPeC+
         yKl31ZPy0Gq3TIP19nJFADK1xDPsl8PO1XGNCf3dNCzQ5G8/aSjebUg2pgC+ueItSZE1
         a9RRwEps+ImLEXb8QfG/LWjgOn5ONIYwLFAZY6RJaKDk/RguxqH2wYCnU1jPTTQAYYsl
         s6qu+aoA4KvvPfOLF+iqzNryvvBB6uDnf5JxdX5ONIWgQC2ZqvO6pTNj4/SNSKNXrnGQ
         lqWisFqtombWiq8Zwq93k+zhTCN4Qq9GNecq4AMTt7k1MeUKZyu7NiM/IQ+thOa9Wa/k
         2rww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623 header.b=rII14qYh;
       spf=pass (google.com: domain of luto@amacapital.net designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=luto@amacapital.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jGrsHLSiZWT2dLa1VTT4nGlAV7OG5Ps+dKRD8W/Sr6U=;
        b=qUjHeIjH7CI0tGFuJOYqtoK4PWZohuqyl/+FMc6aKAG/bSTYXrTdbEy7ahTOd7F5vX
         sIH7wWhRP/I9T0BDoFklsnckofUTWfs1mnZuqUJRWtS/EYQYIiBk70vxMf5OngVHYFq9
         tsvjvuHwevM692/ahMw8ZrgDfIChtjGR4YNNgDPjNYd7IOtzRsnUI2OFFQAOqYzHHB3q
         Ro9RtB+MWLxIsOc4G0jghGbLRMAmnBHkYA3NlFUIr/N/Z5VludpvWHP24HDjks0ty3F1
         xm0r8mIeXMCVpFu9Ii6yGkdRRKmAajdr8OqmJ4kVV4xMfLNmHty1pZT+pX2Q0IpAxLhj
         9VvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jGrsHLSiZWT2dLa1VTT4nGlAV7OG5Ps+dKRD8W/Sr6U=;
        b=ny7Q9qrDdfZpNRF7xuGrob5K8MUFGLQAIa3UgBzgQeAMWjnWuHsi++5XRZ4+qcBMOc
         naaankqz8ynvWLx1BS1C9zVj0qpOKtDDDmG0U1M9clkikWcvZsYewRdMlwi9Z7q+AHEQ
         I7wBSDOBSnZZilRaz7x28AURteYcEni5C4tMjzvkboXSwz+j+tvt5TU7ZVNLtcJ2qw1h
         hFqt703dLXprLAidM0iH3VUCl1mO6MopoSOB2NxjZCKb4uz9+bdHzCNK0cicGGC8MC7f
         YIWF/pZiwtjashIb7HFU32P1ETPPlMm0TWTshlLjgsq4UgzJSGsWQ5iMleQviM3Xrmkq
         8nDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531M3JcFlSHMHHac3RlJ/Gp/sB4D+n3v440cFMJYfPPA8PBitWP+
	/uyCp/nCH44/dwHHyUJcYLY=
X-Google-Smtp-Source: ABdhPJwNlckfDFNPhyLp23VRKpnWd5gQNsJ8poiQgLvUqR6fFCxwnPHmINs7llup2wa7CRShyfGzRw==
X-Received: by 2002:a05:6830:1f3c:: with SMTP id e28mr21950466oth.93.1614112030212;
        Tue, 23 Feb 2021 12:27:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6a0e:: with SMTP id g14ls1607174otn.3.gmail; Tue, 23 Feb
 2021 12:27:09 -0800 (PST)
X-Received: by 2002:a9d:6a99:: with SMTP id l25mr584765otq.307.1614112029894;
        Tue, 23 Feb 2021 12:27:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614112029; cv=none;
        d=google.com; s=arc-20160816;
        b=iBukTeGds++4pJNn0SY9hl9JdWArOXZ7usWfMzg8/2JI2aL7WrlWVwg61Vxx95If3m
         VPoPgtwcC2jktv+RH6ANnB5L/Uu1TpQ4VDFqN/fJqj/eBNksPkRDBW2xF+kmhDXOMhqY
         Gw6WXdIoZY6aQfAlaXLtP5fdxz9dZlGvRO4Ke1w3KI2ZcJBPTZKxuNjybFZXbi8g+Z/G
         Jdsw86JwYrpp6szlTUXySspnMFHTnGOS6ug0lW6U+2ZWDu5ZThgCzeSLFEecIYaJhZ9l
         +LYiJXwzsdvp3c2B/l7MCd/IzSwe/ngXX5tUiZ5wMGzHAda6uh/My22ZFrcByp4NzGfm
         kSyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=Kk5JpRbDq4xRfQD7TUXlnwHHd/9lf684NeDm/b3OOQ4=;
        b=xtRAV5MIL76NWN5i2oKy58KF2vi1u2ILvZmr3PJUZoXW+mNVvB3xxfL5pbq0vX9zR5
         JTvWlUXyWUY+L11KBnxuneCKM4KGr8/M0Kq+jKervYKyhbck0VIXAcrNM8LlN3nGDAOZ
         Ag4kfNMl73uUxdYbmQRwgM7l/F93BVonUCk2GvhcpLJGfkpbXNyD2/hqi+gFK9g1Ltom
         0T5qKrwGIo09qISFdUzc590KqKPgzeZqhbcaK8Wltk+7adp7Mia1DlH4FbyEwBGhKlp3
         SycJWSCl5a48iRRqk5pyTYmoIxdcVTnR/nlb1G7hycTvn0QPo83vexW5s5xPcycPG9rd
         kEJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623 header.b=rII14qYh;
       spf=pass (google.com: domain of luto@amacapital.net designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=luto@amacapital.net
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id l18si798440otk.3.2021.02.23.12.27.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Feb 2021 12:27:09 -0800 (PST)
Received-SPF: pass (google.com: domain of luto@amacapital.net designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id j24so6604992pfi.2
        for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 12:27:09 -0800 (PST)
X-Received: by 2002:a62:1ad4:0:b029:1ed:b92c:6801 with SMTP id a203-20020a621ad40000b02901edb92c6801mr3749066pfa.7.1614112029199;
        Tue, 23 Feb 2021 12:27:09 -0800 (PST)
Received: from ?IPv6:2600:1010:b005:a3de:6cc4:ccf5:1045:b347? ([2600:1010:b005:a3de:6cc4:ccf5:1045:b347])
        by smtp.gmail.com with ESMTPSA id o188sm16858149pfb.102.2021.02.23.12.27.07
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Feb 2021 12:27:08 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Andy Lutomirski <luto@amacapital.net>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH RFC 0/4] Add support for synchronous signals on perf events
Date: Tue, 23 Feb 2021 12:27:05 -0800
Message-Id: <3D507285-835F-4C83-8343-2888835971B4@amacapital.net>
References: <20210223143426.2412737-1-elver@google.com>
Cc: peterz@infradead.org, alexander.shishkin@linux.intel.com,
 acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com,
 namhyung@kernel.org, tglx@linutronix.de, glider@google.com,
 viro@zeniv.linux.org.uk, arnd@arndb.de, christian@brauner.io,
 dvyukov@google.com, jannh@google.com, axboe@kernel.dk, mascasa@google.com,
 pcc@google.com, irogers@google.com, kasan-dev@googlegroups.com,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-m68k@lists.linux-m68k.org,
 x86@kernel.org
In-Reply-To: <20210223143426.2412737-1-elver@google.com>
To: Marco Elver <elver@google.com>
X-Mailer: iPhone Mail (18D52)
X-Original-Sender: luto@amacapital.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623
 header.b=rII14qYh;       spf=pass (google.com: domain of luto@amacapital.net
 designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=luto@amacapital.net
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


> On Feb 23, 2021, at 6:34 AM, Marco Elver <elver@google.com> wrote:
>=20
> =EF=BB=BFThe perf subsystem today unifies various tracing and monitoring
> features, from both software and hardware. One benefit of the perf
> subsystem is automatically inheriting events to child tasks, which
> enables process-wide events monitoring with low overheads. By default
> perf events are non-intrusive, not affecting behaviour of the tasks
> being monitored.
>=20
> For certain use-cases, however, it makes sense to leverage the
> generality of the perf events subsystem and optionally allow the tasks
> being monitored to receive signals on events they are interested in.
> This patch series adds the option to synchronously signal user space on
> events.

Unless I missed some machinations, which is entirely possible, you can=E2=
=80=99t call force_sig_info() from NMI context. Not only am I not convinced=
 that the core signal code is NMI safe, but at least x86 can=E2=80=99t corr=
ectly deliver signals on NMI return. You probably need an IPI-to-self.

>=20
> The discussion at [1] led to the changes proposed in this series. The
> approach taken in patch 3/4 to use 'event_limit' to trigger the signal
> was kindly suggested by Peter Zijlstra in [2].
>=20
> [1] https://lore.kernel.org/lkml/CACT4Y+YPrXGw+AtESxAgPyZ84TYkNZdP0xpocX2=
jwVAbZD=3D-XQ@mail.gmail.com/
> [2] https://lore.kernel.org/lkml/YBv3rAT566k+6zjg@hirez.programming.kicks=
-ass.net/=20
>=20
> Motivation and example uses:
>=20
> 1.    Our immediate motivation is low-overhead sampling-based race
>    detection for user-space [3]. By using perf_event_open() at
>    process initialization, we can create hardware
>    breakpoint/watchpoint events that are propagated automatically
>    to all threads in a process. As far as we are aware, today no
>    existing kernel facility (such as ptrace) allows us to set up
>    process-wide watchpoints with minimal overheads (that are
>    comparable to mprotect() of whole pages).

This would be doable much more simply with an API to set a breakpoint.  All=
 the machinery exists except the actual user API.

>    [3] https://llvm.org/devmtg/2020-09/slides/Morehouse-GWP-Tsan.pdf=20
>=20
> 2.    Other low-overhead error detectors that rely on detecting
>    accesses to certain memory locations or code, process-wide and
>    also only in a specific set of subtasks or threads.
>=20
> Other example use-cases we found potentially interesting:
>=20
> 3.    Code hot patching without full stop-the-world. Specifically, by
>    setting a code breakpoint to entry to the patched routine, then
>    send signals to threads and check that they are not in the
>    routine, but without stopping them further. If any of the
>    threads will enter the routine, it will receive SIGTRAP and
>    pause.

Cute.

>=20
> 4.    Safepoints without mprotect(). Some Java implementations use
>    "load from a known memory location" as a safepoint. When threads
>    need to be stopped, the page containing the location is
>    mprotect()ed and threads get a signal. This can be replaced with
>    a watchpoint, which does not require a whole page nor DTLB
>    shootdowns.

I=E2=80=99m skeptical. Propagating a hardware breakpoint to all threads inv=
olves IPIs and horribly slow writes to DR1 (or 2, 3, or 4) and DR7.  A TLB =
flush can be accelerated using paravirt or hypothetical future hardware. Or=
 real live hardware on ARM64.

(The hypothetical future hardware is almost present on Zen 3.  A bit of wor=
k is needed on the hardware end to make it useful.)

>=20
> 5.    Tracking data flow globally.
>=20
> 6.    Threads receiving signals on performance events to
>    throttle/unthrottle themselves.
>=20
> Marco Elver (4):
>  perf/core: Apply PERF_EVENT_IOC_MODIFY_ATTRIBUTES to children
>  signal: Introduce TRAP_PERF si_code and si_perf to siginfo
>  perf/core: Add support for SIGTRAP on perf events
>  perf/core: Add breakpoint information to siginfo on SIGTRAP
>=20
> arch/m68k/kernel/signal.c          |  3 ++
> arch/x86/kernel/signal_compat.c    |  5 ++-
> fs/signalfd.c                      |  4 +++
> include/linux/compat.h             |  2 ++
> include/linux/signal.h             |  1 +
> include/uapi/asm-generic/siginfo.h |  6 +++-
> include/uapi/linux/perf_event.h    |  3 +-
> include/uapi/linux/signalfd.h      |  4 ++-
> kernel/events/core.c               | 54 +++++++++++++++++++++++++++++-
> kernel/signal.c                    | 11 ++++++
> 10 files changed, 88 insertions(+), 5 deletions(-)
>=20
> --=20
> 2.30.0.617.g56c4b15f3c-goog
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/3D507285-835F-4C83-8343-2888835971B4%40amacapital.net.
