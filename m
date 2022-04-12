Return-Path: <kasan-dev+bncBC7OBJGL2MHBBONX2WJAMGQELWLLWJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A5964FDBF4
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Apr 2022 13:00:10 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id g63-20020a1f5242000000b0033f4c7f7561sf2185322vkb.18
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Apr 2022 04:00:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649761209; cv=pass;
        d=google.com; s=arc-20160816;
        b=XVuv7pCl4VKfQOkmHoq1s441F8kewopNcujnBLPLWQqT7tMsh3hSKs/CDZ3eo2AGF1
         2TnBeApKmomrl0T6nMdMR/JEVMjL4Y/qLp54MXEmo3DUkKjdJIqrj5rkYrJjbEPjo3lO
         Td7u4GrTjCfJ3ZVxQe/bDKEUra7u0w0DBMtvU2nS/EJCrMY6KvOJ4vs7Ix+4u4Kj+U9P
         hI9S+wL3RGEFoZ4TgxEF0kI46yWEyTuacyWzeHPKZf5MN44zBLVwrVyOtS15g4Pj9Ijl
         NsENxJVAidj4+idUcX/NofYfts0BHuQTnZN/fDXPmQ23GfrorLp7qNkdGpQE6RLbNxEI
         93qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Rabp2xwb2UaXOdEjJ+5uP/qfbiDWnAvU1UNzsJm85So=;
        b=wfT6vpEGBhMMs6E2poK/eh1UmAMo1jj0H42Rawct0kVFzPSEXFy1iajKftZDUZrbLk
         nHqRm3/yuVCdE1GOxb10TiDjj7r43cbShhNvXZM29pi4oWXWIAvWmdFqNmWjCIQu161R
         g3ecWRbKpWCxHuKTF7WGgpntrfPDB5AcGKF5U+FyTZdVIwql8oper4xdqJYdv7p1HQg/
         OrPF5e62ROR6wBwYUKS+/3xByozJqWQdZysnrewtg0Uwh7SgR5jeWnkEbKvqKlIdqOHs
         jz+kJphdBUGftEfaq2keWR3sIaztq1pP+QzChhMRJyKd5paDYbndoIesUxLxBnCkLGCY
         ZGlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=b4v6GqYx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Rabp2xwb2UaXOdEjJ+5uP/qfbiDWnAvU1UNzsJm85So=;
        b=HqyL+d3DHalT4GKodcJxcv5Y4kW1vajtB0SAz/SpA7YOzT3eB49nWMqAR5GexoOlgO
         18h6KhcURWFqzGeek1mwqilBClD7CIZbpB5E/L4/tG4WQF4eu82COW3sRUE1IbVCZbws
         G/qDRXw7MFumCo5CymCAPT8xmNq0bQ3tOXAgyaDbrze+mcHGztOr22Er5OuZOwsNlRtq
         RwmKd/PT5dcoyB2Y6P5tTxA6Qm91Af1MuPqcEac2F5G+qldt8OsJIaQGhiiP3YA1c4K4
         /kQM+REGUTpl0XbWSJAl+EMfqjZC3bP2Tt+EdBDmY81p0TBljZSwn6v6HgPeTg0f/a+5
         J+zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Rabp2xwb2UaXOdEjJ+5uP/qfbiDWnAvU1UNzsJm85So=;
        b=QFDAWzBWl8UkQluF0EgrMthd+jy4Cvju97bBV4jrDWTO4muc4Ch+0GtHC6N/dH9T93
         tZxKpQkLrMa+x0Yj/IcNH0qC9taaxLwzePh90BuJNunDdbtZxc+Grv8HKqJVK/AmJHgB
         F7mfLh0xuqN6JGX/5eTzP7/EUoZ7/j0sA321Tysn/ZfMee2XFoscKZy0Z5r6gbn4L/Q+
         SVDRF3ICTlC/TrU7zEIxZ+CF0xmicJ68qBA611ScM0/O+Kk09IhxsvYqsw+G7EznWo0U
         6IfIZxX21Dr8sp0IIxL3xidhjnIktC7xuKQPaO03ZheN4zt9ttUav0TBrwuPhg4sqTMj
         yP/Q==
X-Gm-Message-State: AOAM530PhwHuEFkw5P/bkAsh2XLAMK+uY2/FnoHRdH2LqutV6UFOahzh
	S8hCIQ/InS5btpMReqIVSKw=
X-Google-Smtp-Source: ABdhPJxaDS7wZzo7A+uF3Kl8CY42/Sjq86znmzy9x7ml1kJPH8b4WfjKuAv49Cgiw7v5sul3XlMw8w==
X-Received: by 2002:a67:f958:0:b0:325:5698:52c1 with SMTP id u24-20020a67f958000000b00325569852c1mr11455857vsq.67.1649761209415;
        Tue, 12 Apr 2022 04:00:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:1809:b0:345:426e:1969 with SMTP id
 ay9-20020a056122180900b00345426e1969ls2775413vkb.9.gmail; Tue, 12 Apr 2022
 04:00:08 -0700 (PDT)
X-Received: by 2002:a05:6122:d98:b0:331:47bf:b437 with SMTP id bc24-20020a0561220d9800b0033147bfb437mr11821563vkb.29.1649761208707;
        Tue, 12 Apr 2022 04:00:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649761208; cv=none;
        d=google.com; s=arc-20160816;
        b=Zdt+TBiHif2VHkAJhu6cOM4LlvAQ2226CQrWSVbCr0B9CYEYgYs7sNYLBcFqy+A3D7
         YzZICOuahH5lfoi1cdOsXS+JOlPZK2dv7j77/2u595a3RloxRrch/CFRNjTveGEuhVzy
         XP2f2NSAYNDwWSjTLJ3u6Zt4RoMvMXmRK1ZkXfGMff1XjGEFaXLKjZ+lHW8/cLfgMXW3
         OZDXS2xTjvK+EOn0ey/5pbPfAOKjllK2cVbPTTR4Yx+72f2o/matAr6dEdW9hoowICwE
         lo3dWMPWweKVQ5NFQUTBwhZO7jqluz9yoG4oGsYP9IfxXylRVf745F9ea25bfEHPWJRP
         FD1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=v2zi2giavZdO2HMDfrc7yK4A4aR/ngLsqIJD3W77LNs=;
        b=On1QvKMxhQXxJoxtytL3uXfGhjAz6bVkTFGjMjrSiB/C0cbQ+oChxXszzu3i2C4eEY
         GGUfwA76uJb7TB1837n8yL2alZKMCqh8xcwSO4QgGjXXBPgx/o0q+RnnGt93fVQcRaK9
         gdDWpQ/0HPH84KwM+gWGW3+hodj6ZEEPiJAPLCs7gITHkUclA9UsBsMJz5pJMRVV6qpH
         60U//MnhgRJHjGx85a//GgSDGORN1qW1qXoR6e215cNx6qUxgF9AjkFIssdcgU7rpSUZ
         GVFSXzS91deWY358KkarRTWSGMJdSWhibmPdGpG+CBlofVaR5UGNigElL+N84nJgbyTr
         KGyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=b4v6GqYx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id b11-20020a05612202eb00b0032cd88afa9asi1335161vko.3.2022.04.12.04.00.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Apr 2022 04:00:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-2ed65e63afcso37232807b3.9
        for <kasan-dev@googlegroups.com>; Tue, 12 Apr 2022 04:00:08 -0700 (PDT)
X-Received: by 2002:a0d:e743:0:b0:2eb:3106:9b32 with SMTP id
 q64-20020a0de743000000b002eb31069b32mr30496791ywe.512.1649761208158; Tue, 12
 Apr 2022 04:00:08 -0700 (PDT)
MIME-Version: 1.0
References: <20220404111204.935357-1-elver@google.com> <CACT4Y+YiDhmKokuqD3dhtj67HxZpTumiQvvRp35X-sR735qjqQ@mail.gmail.com>
In-Reply-To: <CACT4Y+YiDhmKokuqD3dhtj67HxZpTumiQvvRp35X-sR735qjqQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Apr 2022 13:00:00 +0200
Message-ID: <CANpmjNPQ9DWzPRx4QWDnZatKGU96xLhb2qN-wgbD84zyZ6_Mig@mail.gmail.com>
Subject: Re: [PATCH] signal: Deliver SIGTRAP on perf event asynchronously if blocked
To: Dmitry Vyukov <dvyukov@google.com>, "Eric W. Biederman" <ebiederm@xmission.com>, 
	Peter Zijlstra <peterz@infradead.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, x86@kernel.org, 
	linux-arm-kernel@lists.infradead.org, linux-m68k@lists.linux-m68k.org, 
	sparclinux@vger.kernel.org, linux-arch@vger.kernel.org, 
	linux-perf-users@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=b4v6GqYx;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as
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

On Tue, 5 Apr 2022 at 15:30, Dmitry Vyukov <dvyukov@google.com> wrote:
> On Mon, 4 Apr 2022 at 13:12, Marco Elver <elver@google.com> wrote:
> > With SIGTRAP on perf events, we have encountered termination of
> > processes due to user space attempting to block delivery of SIGTRAP.
> > Consider this case:
> >
> >     <set up SIGTRAP on a perf event>
> >     ...
> >     sigset_t s;
> >     sigemptyset(&s);
> >     sigaddset(&s, SIGTRAP | <and others>);
> >     sigprocmask(SIG_BLOCK, &s, ...);
> >     ...
> >     <perf event triggers>
> >
> > When the perf event triggers, while SIGTRAP is blocked, force_sig_perf()
> > will force the signal, but revert back to the default handler, thus
> > terminating the task.
> >
> > This makes sense for error conditions, but not so much for explicitly
> > requested monitoring. However, the expectation is still that signals
> > generated by perf events are synchronous, which will no longer be the
> > case if the signal is blocked and delivered later.
> >
> > To give user space the ability to clearly distinguish synchronous from
> > asynchronous signals, introduce siginfo_t::si_perf_flags and
> > TRAP_PERF_FLAG_ASYNC (opted for flags in case more binary information is
> > required in future).
> >
> > The resolution to the problem is then to (a) no longer force the signal
> > (avoiding the terminations), but (b) tell user space via si_perf_flags
> > if the signal was synchronous or not, so that such signals can be
> > handled differently (e.g. let user space decide to ignore or consider
> > the data imprecise).
> >
> > The alternative of making the kernel ignore SIGTRAP on perf events if
> > the signal is blocked may work for some usecases, but likely causes
> > issues in others that then have to revert back to interception of
> > sigprocmask() (which we want to avoid). [ A concrete example: when using
> > breakpoint perf events to track data-flow, in a region of code where
> > signals are blocked, data-flow can no longer be tracked accurately.
> > When a relevant asynchronous signal is received after unblocking the
> > signal, the data-flow tracking logic needs to know its state is
> > imprecise. ]
> >
> > Link: https://lore.kernel.org/all/Yjmn%2FkVblV3TdoAq@elver.google.com/
> > Fixes: 97ba62b27867 ("perf: Add support for SIGTRAP on perf events")
> > Reported-by: Dmitry Vyukov <dvyukov@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Tested-by: Dmitry Vyukov <dvyukov@google.com>
>
> I've tested delivery of SIGTRAPs when it's blocked with sigprocmask,
> it does not kill the process now.
>
> And tested the case where previously I was getting infinite recursion
> and stack overflow (SIGTRAP handler causes another SIGTRAP recursively
> before being able to detect recursion and return). With this patch it
> can be handled by blocking recursive SIGTRAPs (!SA_NODEFER).

Thanks!


Should there be any further comments, please shout.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPQ9DWzPRx4QWDnZatKGU96xLhb2qN-wgbD84zyZ6_Mig%40mail.gmail.com.
