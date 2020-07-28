Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW4BQH4QKGQEMWR66TI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 16655230D56
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jul 2020 17:14:37 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id v188sf14150347qkb.17
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jul 2020 08:14:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595949276; cv=pass;
        d=google.com; s=arc-20160816;
        b=RmzrGuOlSNCmvByX7Kh81oLRZXB8EHLNo67NN/U8P2vI8sSL9lFOTUYhZyeRUYDZug
         3n+HBL967kjgnoO0+Uh2XPMeD8PdYi6bhM7W+/jl/vSXdLeQ2+E+xDowmZSew/Zmaf9o
         N1sb+HSAn+F0aSC4fikH+VhqK0Shul0rrnj4S8cnCFm13VUHm41tCA/DAcbjTBM1KK4q
         TVS0BGmIVxTV7H9CzX0yozHNhVp1eH0zvpLgytPCJio8E9XaMV3LxV3JdzA8cEWDQelM
         1KYY2fBcMwEcFTO0Kp66PzT/Q2bONAu3O+uyhWTiESTlgMQ2aLceno3QIrzi3OzhpyK2
         wg4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8MXjezZ4VqQCQ8+6xshvGNTeIqXoLrlaZCPSyswjzPo=;
        b=cwUygcD6shVpZUp7gAjCbH5191IBJI1Qwkm1/Jwn1OlbfkZk28Cao7B8Y4iPnQmV8w
         Q+vdfbFis3RcwDAojv16De5jlBMK7aKCsfcNZPf7ecehEPf73JkXHwhqaP9kJ6QDTRZP
         H/al04Qz35eCLX6/DaC3O9A3lD0AXku9wMfAY1vDGsDgmAkS73XVGgQfGXgeGz7t1RR0
         DVOeXY6TS8VOR+UimxDkSyb7nJVLPi1ld1K+k3PWiAH0d2CFAp1W8/PowsCsjNiwtE0/
         ybTlRL/ArEwmw5LN4opYZAydDEE16m8Tp79jwP+NKR9zaMsNqlmuxgWyGQ3xrp31he6P
         6CWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GXFztRqU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8MXjezZ4VqQCQ8+6xshvGNTeIqXoLrlaZCPSyswjzPo=;
        b=DHHabjZqLPS13xzcxSAdNW7qEsbtUnZAf9J6HLWmyfVRr1gOl6GTPwJqe08IvR87Ba
         2T9nD/zXhyWETs4pWNILXtxHoxb0MjMk8oIubayR1Uw/wAwOBQSL/eXeGJBB0kIJMaqX
         N0aWPbl138VuAqBT8k5dEKcIPdyilIiBUJhDajIit2WUO5MGctRYSQbx32xP94jfLw7P
         PP6Te8l5briwZKQSkZxt1oFv7wsoEA+V4mkUp15zP0+Y+dVKQL9QyeZgxVyUQYT8hkSm
         5k+8M1RI+O4X409VFWIS/TY6+kYoMIccvcHSTF/6Htwuo/IeSV4Gh4LRfYYJCBxGZrwW
         RKrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8MXjezZ4VqQCQ8+6xshvGNTeIqXoLrlaZCPSyswjzPo=;
        b=JJP4TVSxJA9RTNrQQauQhI48a/E5tTT7asgGlxj1oWAHzguX4MswisC8GYyzdOy7CT
         //xc9Uz3pR5kWrljmsfrg/wA6FKcIsOPn7QsrkbJEP4DFCYzq00jHZ8yJ4j7Vcjar99/
         iOfZ68VmM/OiDC8VTtKw5ROdJI4ntXi6ujOZVwgDketcwzXcXJMK2YB6SEqhtxo2yfFJ
         qIeegxOk76Ev2wX1+KOibq7ckrvcOUR4Hti++O4uxG4EFSS+w4N4++JmpuCY13Y42jZ0
         7qXoVQSt1SkAZzzFyVFfmy6X7zHgy33r4eAX/+Q4zzDv536uZT1+4rbfZmxceNyXlbT3
         8gzQ==
X-Gm-Message-State: AOAM5320C8gHQ/2JZmbdHFUkbFuZT3jer+MVDbQ9H9KahN/Rxths6exK
	8BlZDGYjfzjSuOxbfXix/Xg=
X-Google-Smtp-Source: ABdhPJwEp+itp5xTABa5uSjyvPAl/9+uf4vP68Oo+bfs24mF1C7l0vj7T1EsA9NaYvTatPiJQ19/2A==
X-Received: by 2002:a37:74c:: with SMTP id 73mr26928243qkh.468.1595949276125;
        Tue, 28 Jul 2020 08:14:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:2343:: with SMTP id i3ls7803774qtc.8.gmail; Tue, 28 Jul
 2020 08:14:35 -0700 (PDT)
X-Received: by 2002:ac8:51c1:: with SMTP id d1mr20835942qtn.385.1595949275667;
        Tue, 28 Jul 2020 08:14:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595949275; cv=none;
        d=google.com; s=arc-20160816;
        b=sOmSe58yMRtQWloocU85D/Pbwr34VwBMIkcelGqFHCuKL2JTGJM9SGBLF5lYxRtMpL
         6YgksO5+d2aCzkg5OkHSxYz7EHLUNKVhIp06IpoHk5U3hdTP5PWGlDX9f0YuswCV3yXf
         GR4qmMIYcmV4vYxrtnb4/yZ3rGSZ+XOcHyKx1k2AtjYZV6vUPiHsliIJS04lNFAy+iym
         mY7R2PULu8vW3r3/oZDPVr5Dm3oyvBKObpJuiKLeIQAXWSuPWj6Z9QUbotNo43rk2fzX
         rR3Y453+q+jeEmdl0bGEvsG7e2fZuWIeA7pxPfjKAlmiq5h0k3/muUiarcWisq0CT+tb
         9MNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iJCizSAjAPUE7EUcp95DY3gcG9GO9i7tyIUefzlKX5w=;
        b=WA9wl8Wi9WE/OkAh2WM4TEpo3ALBBjYZHMZzh4jwhAkVyNTW+0OAjT1kbDEcrmkFsQ
         XYuaPLmSUAnsdCec3bXf+NASLLq6AkCNbbzPZxVda/ZsfM7+ZoIh9uXKLnjG2aeQV8st
         n+IAgW9+FTdAcCCxjD/fwn9mVhWQm8Q6yj1SECfZxCYPYmKvqb8p2S31M27vkfjCptKX
         XMxI/J6qBn0IA/8dvOTQUYzEIN+lr2ZZynXJq7xxeRHIyv9WI7tNpN3G1vR8vn8lC6Fi
         XIshLGThWqCG9Rb0ZSLDaE6Kxe4pSWq/BiUhNHfRE9Ky+G6/ngJgpQWIOw14mmmuOgOB
         +vKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GXFztRqU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id f38si572055qte.4.2020.07.28.08.14.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jul 2020 08:14:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id v6so4349727ota.13
        for <kasan-dev@googlegroups.com>; Tue, 28 Jul 2020 08:14:35 -0700 (PDT)
X-Received: by 2002:a05:6830:1612:: with SMTP id g18mr8986816otr.251.1595949274880;
 Tue, 28 Jul 2020 08:14:34 -0700 (PDT)
MIME-Version: 1.0
References: <20200720120348.2406588-1-elver@google.com> <20200728113044.GA233444@gmail.com>
In-Reply-To: <20200728113044.GA233444@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jul 2020 17:14:21 +0200
Message-ID: <CANpmjNOMQ09N4+W9Dt53j=GKAuj0Sd__agRtqpDkubZEkULAJg@mail.gmail.com>
Subject: Re: [PATCH tip/locking/core] kcsan: Improve IRQ state trace reporting
To: Ingo Molnar <mingo@kernel.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GXFztRqU;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Tue, 28 Jul 2020 at 13:30, Ingo Molnar <mingo@kernel.org> wrote:
>
>
> * Marco Elver <elver@google.com> wrote:
>
> > To improve the general usefulness of the IRQ state trace information
> > with KCSAN enabled, save and restore the trace information when entering
> > and exiting the KCSAN runtime as well as when generating a KCSAN report.
> >
> > Without this, reporting the IRQ state trace (whether via a KCSAN report
> > or outside of KCSAN via a lockdep report) is rather useless due to
> > continuously being touched by KCSAN. This is because if KCSAN is
> > enabled, every instrumented memory access causes changes to IRQ state
> > tracking information (either by KCSAN disabling/enabling interrupts or
> > taking report_lock when generating a report).
> >
> > Before "lockdep: Prepare for NMI IRQ state tracking", KCSAN avoided
> > touching the IRQ state trace via raw_local_irq_save/restore() and
> > lockdep_off/on().
> >
> > Fixes: 248591f5d257 ("kcsan: Make KCSAN compatible with new IRQ state tracking")
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
[...]
> > +void kcsan_restore_irqtrace(struct task_struct *task)
> > +{
> > +#ifdef CONFIG_TRACE_IRQFLAGS
> > +     task->irq_events = task->kcsan_save_irqtrace.irq_events;
> > +     task->hardirq_enable_ip = task->kcsan_save_irqtrace.hardirq_enable_ip;
> > +     task->hardirq_disable_ip = task->kcsan_save_irqtrace.hardirq_disable_ip;
> > +     task->hardirq_enable_event = task->kcsan_save_irqtrace.hardirq_enable_event;
> > +     task->hardirq_disable_event = task->kcsan_save_irqtrace.hardirq_disable_event;
> > +     task->softirq_disable_ip = task->kcsan_save_irqtrace.softirq_disable_ip;
> > +     task->softirq_enable_ip = task->kcsan_save_irqtrace.softirq_enable_ip;
> > +     task->softirq_disable_event = task->kcsan_save_irqtrace.softirq_disable_event;
> > +     task->softirq_enable_event = task->kcsan_save_irqtrace.softirq_enable_event;
> > +#endif
>
> Please, make such type of assignment blocks cleaner by using a local
> helper variable, and by aligning the right side vertically as well.
>
> Also, would it make sense to unify the layout between the fields in
> task struct and the new one you introduced? That would allow a simple
> structure copy.

Makes sense, thanks for the suggestion. I think we could introduce a
new struct 'irqtrace_events'. I currently have something that adds
this struct in <linux/irqtrace.h>. AFAIK it also adds readability
improvements on initialization and use of the fields. I'll send a v2
with 2 patches.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOMQ09N4%2BW9Dt53j%3DGKAuj0Sd__agRtqpDkubZEkULAJg%40mail.gmail.com.
