Return-Path: <kasan-dev+bncBCMIZB7QWENRB74IWGJAMGQECM2LKWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id C08164F3459
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Apr 2022 15:30:40 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id m8-20020a170902db0800b001568cd44d9csf2598066plx.9
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Apr 2022 06:30:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649165439; cv=pass;
        d=google.com; s=arc-20160816;
        b=KxFlaC9T1B2GMp0X28tF2Mb5oFxieZ+75eWulQ+32OHQ4A4TluLeX3WfvDZ3pWs98Y
         gTGclfR0qndEFhv4PwHKPoKIWogRJrgLfEYWlcdOZhdziU4qY2C0GNE3UeWDQmn2BaTi
         f5inj8Dq1Wssm4lKTghmNrckuQzEHnD4Wm5Ak2I4u/MSrs4KbdMnD+6gp3Hvwe/4yViy
         3tpFgKkHSalcbY0aomEIHogUC3OxKI6kiek6luqZMN99aNQUh1pzz6YDE/a3WZGkyR+x
         mffSUxWFo2jYG4wSkJmLGm72WYp+/VGIXZEp8x7GW2LGXgMwM/r16GgC9RCyVi8WCsQE
         J5Ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=92nSRaQWXV0L4XOiw6rIm+g3NAuDlEESOts/UGY/g2o=;
        b=LYFYoaYC4hfFx/IAXIRnJc43W0foX8CaRvoo0zNweGu+fu90//MSLV5apclgBdfrES
         pDJ97sMCx3i6stQspeR8xx90lDiaHT0tmtMHyjL6fBZNhPR1bVHptoraVn7I6ei1K5HR
         J8013lqPJYCh9mqF9O7ZdLxVaEa1Oz18hV81eSuwSJsQf1BbfkvGsifAaoabprgLUPFd
         YEPKHZNt95Sg59MNcxwTZ4QyMwxpSAgOxf+w+cPOtPboms4SJG/XJQSf2pU65Spnp30n
         Z2kyom7luLGwCdgy+sw+7Ao1UrD0moJ9++4vCMM8sFIUJYh73ZDG892TuwEVf8bfxbCW
         ehRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sY8UN9C1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2001:4860:4864:20::36 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=92nSRaQWXV0L4XOiw6rIm+g3NAuDlEESOts/UGY/g2o=;
        b=a5SETNtZwydAB44XzlVhX67N2mAIgEYi3sseVTJf/gxU6A907fLYPt6kSKl4WDzvJ7
         Mf175GYDiCy7FmnF/1Yh9Vc9Rwy0tFC8z+9XCaMWgxwL7poJ66Yh7JyoIwJVeRXe4Fez
         d6Wj3zARdlWhrOq8mQ7ql74BznjBamuNOruiYWxIRHaOG9h1WyD/aJKwDBm8x//jMkz0
         +ZWLG6JhHLwMmqVq0YqEcA3+ESlnyX+p5E2LLXjyYMV8dCfogo09dfK/9lAPuLkrbuY+
         Mn8rC1uZy/ssnKPJNssIIy7L3Zh//fjmDUbDiYeopgwQwbbB/vq13aJ/IcyXMGRC02MY
         6Akw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=92nSRaQWXV0L4XOiw6rIm+g3NAuDlEESOts/UGY/g2o=;
        b=WWXV1WkHu0Tr5b1A8XGSaQai9ov2DwFY3tp4P5cHxkpO7HYvMNceb2WQ/al/HOAgKw
         07LRDpNuds0gJuUMMm+oJMsXAWHJGyXQeg+VRYzjV7YHMMO1ecb6gVzU3F3UuC0oYzfT
         j4EAR71qK3MYbQ8uipqoG/69EBciwCRXIZvid7npldnB69UlxqufImeH3ws/ZGHOqiZ/
         s0bgbmJV+z2DRtTX8saM8l8Q6xv8jsbIOkDRtPBnb2xhp68MMrAfO7w4c0EKoVpYLmnu
         4raP+h/tOG5qeUpchKXzsbB1JCWhv/l2aEaRsGoFSyfln2qSa9Asfipcq58e8SsPpH47
         6juQ==
X-Gm-Message-State: AOAM5316Za0VUTwtlOz0KokhPgyM0XOqZ++TDRABw+wb7rB0MLcn5Aro
	sGb7zoy5ZKzPvcVhVE0gRpI=
X-Google-Smtp-Source: ABdhPJwYyoUjUHnJz9eCfXnUUoHHzhKFEF5EZgwJIBTCs4AADrpecZ8RtvKXD2Wj5owEjG9D2AoLWQ==
X-Received: by 2002:a17:90b:4a82:b0:1c7:5837:ab5c with SMTP id lp2-20020a17090b4a8200b001c75837ab5cmr4092611pjb.55.1649165439417;
        Tue, 05 Apr 2022 06:30:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:6782:b0:1b9:7c8a:8c03 with SMTP id
 o2-20020a17090a678200b001b97c8a8c03ls2586377pjj.0.gmail; Tue, 05 Apr 2022
 06:30:38 -0700 (PDT)
X-Received: by 2002:a17:90b:3447:b0:1c6:fe01:675c with SMTP id lj7-20020a17090b344700b001c6fe01675cmr4063208pjb.59.1649165438641;
        Tue, 05 Apr 2022 06:30:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649165438; cv=none;
        d=google.com; s=arc-20160816;
        b=UHKhyXgNbifCqu0G0IawK70vz4qzvnV2cztVF3uNMB/BgMeoHKMWgeThh1sdQayD1r
         KDbJKEAvqJiUYR1MPG2ta6tfcmxYH4g0MPgrKtUY+xAhDdX6HKBTwIBKIJYM+kfW98d2
         GctI5It103dLm1XTzx/qub+HMc91/QSat+au2Fk9OGSPw11mQ1InuBX3UM81WBoXJETY
         ux12x6MQFZizcvtNT5+CpPg2bgArhahn/lzF5Ad88v5ls0yxupSf2LBYUVmA5YsMx67v
         LDxifxDxRpAbqt99mUkhsEDkap/NTjj1vkgTUdCWdQ3UQiGjHIZFsc1lAw1nGDRee3SH
         NjrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9SUjbR6d0Hm/+GiUujjBnx6+L5jTOpdyMzjgCeWVv18=;
        b=PG7FJ0AdB52zrETGV2x5W2kEgv0nWlWkB4rq5v2Upf+xHrRhNzJedyuHUbJws9yQfa
         ek/5RQYlmX786mypsnZEUP31kkF+8ouaMWdPft4y2K0TuQvqAIBGvjjiy1SOaHt/Aa8f
         G1mTO8qI3hhue2NfP99tQHaGAnYqiawpasxxVAfQCuN37Lm0bWzfcB1JbdDgHXCh2LiL
         4KXuZymn/ZUuHQVPTDmOTkJoVuOtKYPF/qeyZpyuZbs8dSqGnVn10WitlCTlJIo3FMTK
         LR174EpUzUst4SZJMP06AcyTVdXcajvZc5lNeHaLS5BxIss7DYkf1te92DwLUApdYW4H
         yUXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sY8UN9C1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2001:4860:4864:20::36 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oa1-x36.google.com (mail-oa1-x36.google.com. [2001:4860:4864:20::36])
        by gmr-mx.google.com with ESMTPS id f11-20020a17090ac28b00b001c62073e04asi217457pjt.2.2022.04.05.06.30.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Apr 2022 06:30:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2001:4860:4864:20::36 as permitted sender) client-ip=2001:4860:4864:20::36;
Received: by mail-oa1-x36.google.com with SMTP id 586e51a60fabf-e1e5e8d9faso9091803fac.4
        for <kasan-dev@googlegroups.com>; Tue, 05 Apr 2022 06:30:38 -0700 (PDT)
X-Received: by 2002:a05:6870:e0d1:b0:e2:1c3b:cca2 with SMTP id
 a17-20020a056870e0d100b000e21c3bcca2mr1459916oab.163.1649165437660; Tue, 05
 Apr 2022 06:30:37 -0700 (PDT)
MIME-Version: 1.0
References: <20220404111204.935357-1-elver@google.com>
In-Reply-To: <20220404111204.935357-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Apr 2022 15:30:26 +0200
Message-ID: <CACT4Y+YiDhmKokuqD3dhtj67HxZpTumiQvvRp35X-sR735qjqQ@mail.gmail.com>
Subject: Re: [PATCH] signal: Deliver SIGTRAP on perf event asynchronously if blocked
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, "Eric W. Biederman" <ebiederm@xmission.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, x86@kernel.org, 
	linux-arm-kernel@lists.infradead.org, linux-m68k@lists.linux-m68k.org, 
	sparclinux@vger.kernel.org, linux-arch@vger.kernel.org, 
	linux-perf-users@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sY8UN9C1;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2001:4860:4864:20::36 as
 permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
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

On Mon, 4 Apr 2022 at 13:12, Marco Elver <elver@google.com> wrote:
>
> With SIGTRAP on perf events, we have encountered termination of
> processes due to user space attempting to block delivery of SIGTRAP.
> Consider this case:
>
>     <set up SIGTRAP on a perf event>
>     ...
>     sigset_t s;
>     sigemptyset(&s);
>     sigaddset(&s, SIGTRAP | <and others>);
>     sigprocmask(SIG_BLOCK, &s, ...);
>     ...
>     <perf event triggers>
>
> When the perf event triggers, while SIGTRAP is blocked, force_sig_perf()
> will force the signal, but revert back to the default handler, thus
> terminating the task.
>
> This makes sense for error conditions, but not so much for explicitly
> requested monitoring. However, the expectation is still that signals
> generated by perf events are synchronous, which will no longer be the
> case if the signal is blocked and delivered later.
>
> To give user space the ability to clearly distinguish synchronous from
> asynchronous signals, introduce siginfo_t::si_perf_flags and
> TRAP_PERF_FLAG_ASYNC (opted for flags in case more binary information is
> required in future).
>
> The resolution to the problem is then to (a) no longer force the signal
> (avoiding the terminations), but (b) tell user space via si_perf_flags
> if the signal was synchronous or not, so that such signals can be
> handled differently (e.g. let user space decide to ignore or consider
> the data imprecise).
>
> The alternative of making the kernel ignore SIGTRAP on perf events if
> the signal is blocked may work for some usecases, but likely causes
> issues in others that then have to revert back to interception of
> sigprocmask() (which we want to avoid). [ A concrete example: when using
> breakpoint perf events to track data-flow, in a region of code where
> signals are blocked, data-flow can no longer be tracked accurately.
> When a relevant asynchronous signal is received after unblocking the
> signal, the data-flow tracking logic needs to know its state is
> imprecise. ]
>
> Link: https://lore.kernel.org/all/Yjmn%2FkVblV3TdoAq@elver.google.com/
> Fixes: 97ba62b27867 ("perf: Add support for SIGTRAP on perf events")
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Marco Elver <elver@google.com>

Tested-by: Dmitry Vyukov <dvyukov@google.com>

I've tested delivery of SIGTRAPs when it's blocked with sigprocmask,
it does not kill the process now.

And tested the case where previously I was getting infinite recursion
and stack overflow (SIGTRAP handler causes another SIGTRAP recursively
before being able to detect recursion and return). With this patch it
can be handled by blocking recursive SIGTRAPs (!SA_NODEFER).


> ---
>  arch/arm/kernel/signal.c           |  1 +
>  arch/arm64/kernel/signal.c         |  1 +
>  arch/arm64/kernel/signal32.c       |  1 +
>  arch/m68k/kernel/signal.c          |  1 +
>  arch/sparc/kernel/signal32.c       |  1 +
>  arch/sparc/kernel/signal_64.c      |  1 +
>  arch/x86/kernel/signal_compat.c    |  2 ++
>  include/linux/compat.h             |  1 +
>  include/linux/sched/signal.h       |  2 +-
>  include/uapi/asm-generic/siginfo.h |  7 +++++++
>  kernel/events/core.c               |  4 ++--
>  kernel/signal.c                    | 18 ++++++++++++++++--
>  12 files changed, 35 insertions(+), 5 deletions(-)
>
> diff --git a/arch/arm/kernel/signal.c b/arch/arm/kernel/signal.c
> index 459abc5d1819..ea128e32e8ca 100644
> --- a/arch/arm/kernel/signal.c
> +++ b/arch/arm/kernel/signal.c
> @@ -708,6 +708,7 @@ static_assert(offsetof(siginfo_t, si_upper) == 0x18);
>  static_assert(offsetof(siginfo_t, si_pkey)     == 0x14);
>  static_assert(offsetof(siginfo_t, si_perf_data)        == 0x10);
>  static_assert(offsetof(siginfo_t, si_perf_type)        == 0x14);
> +static_assert(offsetof(siginfo_t, si_perf_flags) == 0x18);
>  static_assert(offsetof(siginfo_t, si_band)     == 0x0c);
>  static_assert(offsetof(siginfo_t, si_fd)       == 0x10);
>  static_assert(offsetof(siginfo_t, si_call_addr)        == 0x0c);
> diff --git a/arch/arm64/kernel/signal.c b/arch/arm64/kernel/signal.c
> index 4a4122ef6f39..41b5d9d3672a 100644
> --- a/arch/arm64/kernel/signal.c
> +++ b/arch/arm64/kernel/signal.c
> @@ -1011,6 +1011,7 @@ static_assert(offsetof(siginfo_t, si_upper)       == 0x28);
>  static_assert(offsetof(siginfo_t, si_pkey)     == 0x20);
>  static_assert(offsetof(siginfo_t, si_perf_data)        == 0x18);
>  static_assert(offsetof(siginfo_t, si_perf_type)        == 0x20);
> +static_assert(offsetof(siginfo_t, si_perf_flags) == 0x24);
>  static_assert(offsetof(siginfo_t, si_band)     == 0x10);
>  static_assert(offsetof(siginfo_t, si_fd)       == 0x18);
>  static_assert(offsetof(siginfo_t, si_call_addr)        == 0x10);
> diff --git a/arch/arm64/kernel/signal32.c b/arch/arm64/kernel/signal32.c
> index d984282b979f..4700f8522d27 100644
> --- a/arch/arm64/kernel/signal32.c
> +++ b/arch/arm64/kernel/signal32.c
> @@ -487,6 +487,7 @@ static_assert(offsetof(compat_siginfo_t, si_upper)  == 0x18);
>  static_assert(offsetof(compat_siginfo_t, si_pkey)      == 0x14);
>  static_assert(offsetof(compat_siginfo_t, si_perf_data) == 0x10);
>  static_assert(offsetof(compat_siginfo_t, si_perf_type) == 0x14);
> +static_assert(offsetof(compat_siginfo_t, si_perf_flags)        == 0x18);
>  static_assert(offsetof(compat_siginfo_t, si_band)      == 0x0c);
>  static_assert(offsetof(compat_siginfo_t, si_fd)                == 0x10);
>  static_assert(offsetof(compat_siginfo_t, si_call_addr) == 0x0c);
> diff --git a/arch/m68k/kernel/signal.c b/arch/m68k/kernel/signal.c
> index 49533f65958a..b9f6908a31bc 100644
> --- a/arch/m68k/kernel/signal.c
> +++ b/arch/m68k/kernel/signal.c
> @@ -625,6 +625,7 @@ static inline void siginfo_build_tests(void)
>         /* _sigfault._perf */
>         BUILD_BUG_ON(offsetof(siginfo_t, si_perf_data) != 0x10);
>         BUILD_BUG_ON(offsetof(siginfo_t, si_perf_type) != 0x14);
> +       BUILD_BUG_ON(offsetof(siginfo_t, si_perf_flags) != 0x18);
>
>         /* _sigpoll */
>         BUILD_BUG_ON(offsetof(siginfo_t, si_band)   != 0x0c);
> diff --git a/arch/sparc/kernel/signal32.c b/arch/sparc/kernel/signal32.c
> index f9fe502b81c6..dad38960d1a8 100644
> --- a/arch/sparc/kernel/signal32.c
> +++ b/arch/sparc/kernel/signal32.c
> @@ -779,5 +779,6 @@ static_assert(offsetof(compat_siginfo_t, si_upper)  == 0x18);
>  static_assert(offsetof(compat_siginfo_t, si_pkey)      == 0x14);
>  static_assert(offsetof(compat_siginfo_t, si_perf_data) == 0x10);
>  static_assert(offsetof(compat_siginfo_t, si_perf_type) == 0x14);
> +static_assert(offsetof(compat_siginfo_t, si_perf_flags)        == 0x18);
>  static_assert(offsetof(compat_siginfo_t, si_band)      == 0x0c);
>  static_assert(offsetof(compat_siginfo_t, si_fd)                == 0x10);
> diff --git a/arch/sparc/kernel/signal_64.c b/arch/sparc/kernel/signal_64.c
> index 8b9fc76cd3e0..570e43e6fda5 100644
> --- a/arch/sparc/kernel/signal_64.c
> +++ b/arch/sparc/kernel/signal_64.c
> @@ -590,5 +590,6 @@ static_assert(offsetof(siginfo_t, si_upper) == 0x28);
>  static_assert(offsetof(siginfo_t, si_pkey)     == 0x20);
>  static_assert(offsetof(siginfo_t, si_perf_data)        == 0x18);
>  static_assert(offsetof(siginfo_t, si_perf_type)        == 0x20);
> +static_assert(offsetof(siginfo_t, si_perf_flags) == 0x24);
>  static_assert(offsetof(siginfo_t, si_band)     == 0x10);
>  static_assert(offsetof(siginfo_t, si_fd)       == 0x14);
> diff --git a/arch/x86/kernel/signal_compat.c b/arch/x86/kernel/signal_compat.c
> index b52407c56000..879ef8c72f5c 100644
> --- a/arch/x86/kernel/signal_compat.c
> +++ b/arch/x86/kernel/signal_compat.c
> @@ -149,8 +149,10 @@ static inline void signal_compat_build_tests(void)
>
>         BUILD_BUG_ON(offsetof(siginfo_t, si_perf_data) != 0x18);
>         BUILD_BUG_ON(offsetof(siginfo_t, si_perf_type) != 0x20);
> +       BUILD_BUG_ON(offsetof(siginfo_t, si_perf_flags) != 0x24);
>         BUILD_BUG_ON(offsetof(compat_siginfo_t, si_perf_data) != 0x10);
>         BUILD_BUG_ON(offsetof(compat_siginfo_t, si_perf_type) != 0x14);
> +       BUILD_BUG_ON(offsetof(compat_siginfo_t, si_perf_flags) != 0x18);
>
>         CHECK_CSI_OFFSET(_sigpoll);
>         CHECK_CSI_SIZE  (_sigpoll, 2*sizeof(int));
> diff --git a/include/linux/compat.h b/include/linux/compat.h
> index 1c758b0e0359..01fddf72a81f 100644
> --- a/include/linux/compat.h
> +++ b/include/linux/compat.h
> @@ -235,6 +235,7 @@ typedef struct compat_siginfo {
>                                 struct {
>                                         compat_ulong_t _data;
>                                         u32 _type;
> +                                       u32 _flags;
>                                 } _perf;
>                         };
>                 } _sigfault;
> diff --git a/include/linux/sched/signal.h b/include/linux/sched/signal.h
> index 3c8b34876744..bab7cc56b13a 100644
> --- a/include/linux/sched/signal.h
> +++ b/include/linux/sched/signal.h
> @@ -320,7 +320,7 @@ int send_sig_mceerr(int code, void __user *, short, struct task_struct *);
>
>  int force_sig_bnderr(void __user *addr, void __user *lower, void __user *upper);
>  int force_sig_pkuerr(void __user *addr, u32 pkey);
> -int force_sig_perf(void __user *addr, u32 type, u64 sig_data);
> +int send_sig_perf(void __user *addr, u32 type, u64 sig_data);
>
>  int force_sig_ptrace_errno_trap(int errno, void __user *addr);
>  int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno);
> diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
> index 3ba180f550d7..ffbe4cec9f32 100644
> --- a/include/uapi/asm-generic/siginfo.h
> +++ b/include/uapi/asm-generic/siginfo.h
> @@ -99,6 +99,7 @@ union __sifields {
>                         struct {
>                                 unsigned long _data;
>                                 __u32 _type;
> +                               __u32 _flags;
>                         } _perf;
>                 };
>         } _sigfault;
> @@ -164,6 +165,7 @@ typedef struct siginfo {
>  #define si_pkey                _sifields._sigfault._addr_pkey._pkey
>  #define si_perf_data   _sifields._sigfault._perf._data
>  #define si_perf_type   _sifields._sigfault._perf._type
> +#define si_perf_flags  _sifields._sigfault._perf._flags
>  #define si_band                _sifields._sigpoll._band
>  #define si_fd          _sifields._sigpoll._fd
>  #define si_call_addr   _sifields._sigsys._call_addr
> @@ -270,6 +272,11 @@ typedef struct siginfo {
>   * that are of the form: ((PTRACE_EVENT_XXX << 8) | SIGTRAP)
>   */
>
> +/*
> + * Flags for si_perf_flags if SIGTRAP si_code is TRAP_PERF.
> + */
> +#define TRAP_PERF_FLAG_ASYNC (1u << 0)
> +
>  /*
>   * SIGCHLD si_codes
>   */
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index cfde994ce61c..6eafb1b0ad4a 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -6533,8 +6533,8 @@ static void perf_sigtrap(struct perf_event *event)
>         if (current->flags & PF_EXITING)
>                 return;
>
> -       force_sig_perf((void __user *)event->pending_addr,
> -                      event->attr.type, event->attr.sig_data);
> +       send_sig_perf((void __user *)event->pending_addr,
> +                     event->attr.type, event->attr.sig_data);
>  }
>
>  static void perf_pending_event_disable(struct perf_event *event)
> diff --git a/kernel/signal.c b/kernel/signal.c
> index 30cd1ca43bcd..e43bc2a692f5 100644
> --- a/kernel/signal.c
> +++ b/kernel/signal.c
> @@ -1805,7 +1805,7 @@ int force_sig_pkuerr(void __user *addr, u32 pkey)
>  }
>  #endif
>
> -int force_sig_perf(void __user *addr, u32 type, u64 sig_data)
> +int send_sig_perf(void __user *addr, u32 type, u64 sig_data)
>  {
>         struct kernel_siginfo info;
>
> @@ -1817,7 +1817,18 @@ int force_sig_perf(void __user *addr, u32 type, u64 sig_data)
>         info.si_perf_data = sig_data;
>         info.si_perf_type = type;
>
> -       return force_sig_info(&info);
> +       /*
> +        * Signals generated by perf events should not terminate the whole
> +        * process if SIGTRAP is blocked, however, delivering the signal
> +        * asynchronously is better than not delivering at all. But tell user
> +        * space if the signal was asynchronous, so it can clearly be
> +        * distinguished from normal synchronous ones.
> +        */
> +       info.si_perf_flags = sigismember(&current->blocked, info.si_signo) ?
> +                                    TRAP_PERF_FLAG_ASYNC :
> +                                    0;
> +
> +       return send_sig_info(info.si_signo, &info, current);
>  }
>
>  /**
> @@ -3432,6 +3443,7 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
>                 to->si_addr = ptr_to_compat(from->si_addr);
>                 to->si_perf_data = from->si_perf_data;
>                 to->si_perf_type = from->si_perf_type;
> +               to->si_perf_flags = from->si_perf_flags;
>                 break;
>         case SIL_CHLD:
>                 to->si_pid = from->si_pid;
> @@ -3509,6 +3521,7 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
>                 to->si_addr = compat_ptr(from->si_addr);
>                 to->si_perf_data = from->si_perf_data;
>                 to->si_perf_type = from->si_perf_type;
> +               to->si_perf_flags = from->si_perf_flags;
>                 break;
>         case SIL_CHLD:
>                 to->si_pid    = from->si_pid;
> @@ -4722,6 +4735,7 @@ static inline void siginfo_buildtime_checks(void)
>         CHECK_OFFSET(si_pkey);
>         CHECK_OFFSET(si_perf_data);
>         CHECK_OFFSET(si_perf_type);
> +       CHECK_OFFSET(si_perf_flags);
>
>         /* sigpoll */
>         CHECK_OFFSET(si_band);
> --
> 2.35.1.1094.g7c7d902a7c-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYiDhmKokuqD3dhtj67HxZpTumiQvvRp35X-sR735qjqQ%40mail.gmail.com.
