Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6NE576QKGQEZBHJV5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id EFF092C0E8A
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 16:17:14 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id s18sf4350486pfc.10
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 07:17:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606144633; cv=pass;
        d=google.com; s=arc-20160816;
        b=EyJG3DZFnJN2U+jdGr0538L410TEYZaGbupkdFJutettkQ5dtym0YzoGKKv9rXisVO
         xFRdUUw+Go35BuOBPLkScmuPIqGHRWxA3acm3eLn1/0viW2fXqJsplvhyY6cVGtjd/P6
         sVqA9+fJsyTnmBp/ZaFnxxZ04NhEvj8zFYfbs6Msbx8OTCUtAPzYgrRVcdTr/q4ToIxv
         uZyyDQ7iQx72va7BkcuiDdwknHCueTRb7G+KnSYL3UD4vrv84uE225I/1+AsUwCIXO1h
         fFLV/g/LFJOHvzo4D6VAebCFrFQXfOiaz75sryARmSFbyyOqat3X9fVOE15TOG6PWlQp
         TTxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Tf3atOPkbh8QaC7rIWbd3IKp1Vw740V8d6CqSFBkt4c=;
        b=XeqOHP83TcBDNbtNP7j2r2zw/onYo9QcMxCYE29knvsWLn4Nze/pFQP2uFGG+cpDBZ
         t9zy5Z8Z6jE2QTy5esUqmESKQtqCaMEYuQDeo3j9HvmGlT34davjxeAfzVJtvwnnCGGC
         gnNtV1PxVeJNddM+g2qJMCAIXg+0uQ/v4WB9BVIpuaKqHnolKJkuCA76aXAnX5qE0RwQ
         9Zo5nCbv8we6LG+snbrmgpmFh+lQx06FUWqK+EyZJp+7elo17cHOx5Tl84Fq1Np6OD1+
         kuTlyV//jhGPt1EbQtDLBxj3EFnD+8eGjR1MFSRfCZAQjbNFqnrvyh1a7piw3ktK2Jzv
         nOew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N84kzZfU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tf3atOPkbh8QaC7rIWbd3IKp1Vw740V8d6CqSFBkt4c=;
        b=P3y2xbxAVFPlc4fvtDP076XChvQoERhpprHYB8s3G7KdYZgaQj9/F0VTzMjK7OHMo8
         0V6tAJhTad6StVhcDjBA1P482XMhG5ABc8evcv8U6BFQigZOJ/uZlG+/HTfkTabLgZnC
         FDoBmZzmTSQ55JbuKx2bi7vNNJBEDXv+5/TH89ZrrIuxKUO8ShY1rOXA2Ed3o36eVfZX
         VFDBIOq3LAD0yqedYZBy/FXEnFJeV94rhLJWOCba2Anib1gYKlFWZvUsoZ4CYjDe4z65
         pAH1OtS2GErqClPuIX+bVyjf7REesLIa4NHuvaEeVMGBi533vtLJGvXGSyCwKPRbOoAJ
         EZVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tf3atOPkbh8QaC7rIWbd3IKp1Vw740V8d6CqSFBkt4c=;
        b=pCskGxDiaVcwWugRtaACPQR0vqAtCR3m5HvKG7Vn+X9UiPTuPEmoqoken4hP9k5A/0
         5AkVKK8iYuMD2wMNFWO/tTS7oGm8Y60H56kT3rZuj0/1wrHa6dLWykxrvChkwrHQFHEL
         oE4wy9diZ6T9VxGu/dcW8qNsWPAh9CcwMJLsaoqZyMQhiF0idbsbW1Pq5uib+MBLUEz8
         h43usY5NC39ERN3YQ2OgMJZpyko9gjs2LLuaFS6KIITVMhipoPNeruCNX1JprGISfmhC
         Pr5O85pHfpiNmQ2HaPBXU+ygmOwfj5+7bDmt+q9CX0+kULCp/clLWeeUsN46qSms7+yv
         PqaQ==
X-Gm-Message-State: AOAM531VQ67DgSfKvoizK9UEw5jhCj43lyRRI3MwhswkhWBeAbF1VaMI
	HkA4h8OfTLoB+sjn4sRFT2g=
X-Google-Smtp-Source: ABdhPJypYowGOj7ZKGOlfgAlRsT+RY8EZdbKtoYEXq/tt8MBmJdaeM/zIDrWNcvOK8gzzrHg3tyNxw==
X-Received: by 2002:a63:1845:: with SMTP id 5mr27512236pgy.393.1606144633685;
        Mon, 23 Nov 2020 07:17:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:be18:: with SMTP id a24ls8244815pjs.3.canary-gmail;
 Mon, 23 Nov 2020 07:17:13 -0800 (PST)
X-Received: by 2002:a17:90a:458e:: with SMTP id v14mr263615pjg.40.1606144633147;
        Mon, 23 Nov 2020 07:17:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606144633; cv=none;
        d=google.com; s=arc-20160816;
        b=Kz0fwYzJyty2W0MP6a2fiCMihTaCxDMuFjgACtmxOazdK1zakU1Bv+aCgGc/gSC4tN
         1+8LtI0fPbGaAmf+90tpeKhJTPhZ3Lc665bgtkd1Oqg/HATWLawaBuJ84MuAlIkhOFv9
         eg31Yd55HXAQbaOVvBVqYqqBwFhiV3xQVANPC0M8i39K/x6AOujo5fe0A5B5eMQeHrYD
         ItAsd7Vvqt+eJyMiK2qHNqeIk6x0mSOC2IV9OHMkIaV/F4u/ZxtHYFoukX8878iKsPl7
         Pjxk3VIBq9m1sIXnkD7IvB1VeFO7XAnqdps2mM/sCaMiFLbEOGehBgBwSeU7YlfVt8vA
         vGlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=01wWOa3KrZt/xsoNZQpghL+y/uBnQBFRvt5GfUXKKDw=;
        b=M1W65ZPWzBN6QJ/wS+03lLOh52DMlxxlmOk1b5r0VjPm3IilvIsOoU2kP7rMevCqsH
         bRBCNPpZJ/3VojQpnbQNUFsLLIZxj/pH1Eex2oqJ9O1yfn2G/0nLYckf7964NHXbJ1kn
         9q6esYF1AmEPMLkuw2gR8We9PcnKhu0rhCKo1Duxy78/f875JfqEfEvhSIXqAPMkj4ZM
         4u6gNAtBuQzFibRZ6bW9mkHQbLh0vdgGx2Ozy5jkj88MVYNzrhGE0YuFeXmL3pbqV3ka
         8OtGdJU0gC5PSGloIshzK1wyfXIIh/uBcv/BF0sWFsGd/QDgV+QV5Lqz2KUjv9PIYAfV
         fQqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N84kzZfU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc41.google.com (mail-oo1-xc41.google.com. [2607:f8b0:4864:20::c41])
        by gmr-mx.google.com with ESMTPS id bi5si625705plb.2.2020.11.23.07.17.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 07:17:13 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) client-ip=2607:f8b0:4864:20::c41;
Received: by mail-oo1-xc41.google.com with SMTP id l10so4010640oom.6
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 07:17:13 -0800 (PST)
X-Received: by 2002:a4a:e4cc:: with SMTP id w12mr22858288oov.36.1606144632330;
 Mon, 23 Nov 2020 07:17:12 -0800 (PST)
MIME-Version: 1.0
References: <20201123132300.1759342-1-elver@google.com> <20201123135512.GM3021@hirez.programming.kicks-ass.net>
In-Reply-To: <20201123135512.GM3021@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 23 Nov 2020 16:17:00 +0100
Message-ID: <CANpmjNPwuq8Hph3oOyJCVgWQ_d-gOTPEOT3BpbR2pnm5LBeJbw@mail.gmail.com>
Subject: Re: [PATCH v2] kcsan: Avoid scheduler recursion by using
 non-instrumented preempt_{disable,enable}()
To: Peter Zijlstra <peterz@infradead.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Will Deacon <will@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=N84kzZfU;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as
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

On Mon, 23 Nov 2020 at 14:55, Peter Zijlstra <peterz@infradead.org> wrote:
> On Mon, Nov 23, 2020 at 02:23:00PM +0100, Marco Elver wrote:
> > When enabling KCSAN for kernel/sched (remove KCSAN_SANITIZE := n from
> > kernel/sched/Makefile), with CONFIG_DEBUG_PREEMPT=y, we can observe
> > recursion due to:
> >
> >       check_access() [via instrumentation]
> >         kcsan_setup_watchpoint()
> >           reset_kcsan_skip()
> >             kcsan_prandom_u32_max()
> >               get_cpu_var()
> >                 preempt_disable()
> >                   preempt_count_add() [in kernel/sched/core.c]
> >                     check_access() [via instrumentation]
> >
> > Avoid this by rewriting kcsan_prandom_u32_max() to only use safe
> > versions of preempt_disable() and preempt_enable() that do not call into
> > scheduler code.
> >
> > Note, while this currently does not affect an unmodified kernel, it'd be
> > good to keep a KCSAN kernel working when KCSAN_SANITIZE := n is removed
> > from kernel/sched/Makefile to permit testing scheduler code with KCSAN
> > if desired.
> >
> > Fixes: cd290ec24633 ("kcsan: Use tracing-safe version of prandom")
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > v2:
> > * Update comment to also point out preempt_enable().
> > ---
> >  kernel/kcsan/core.c | 15 ++++++++++++---
> >  1 file changed, 12 insertions(+), 3 deletions(-)
> >
> > diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> > index 3994a217bde7..10513f3e2349 100644
> > --- a/kernel/kcsan/core.c
> > +++ b/kernel/kcsan/core.c
> > @@ -284,10 +284,19 @@ should_watch(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *
> >   */
> >  static u32 kcsan_prandom_u32_max(u32 ep_ro)
> >  {
> > -     struct rnd_state *state = &get_cpu_var(kcsan_rand_state);
> > -     const u32 res = prandom_u32_state(state);
> > +     struct rnd_state *state;
> > +     u32 res;
> > +
> > +     /*
> > +      * Avoid recursion with scheduler by using non-tracing versions of
> > +      * preempt_disable() and preempt_enable() that do not call into
> > +      * scheduler code.
> > +      */
> > +     preempt_disable_notrace();
> > +     state = raw_cpu_ptr(&kcsan_rand_state);
> > +     res = prandom_u32_state(state);
> > +     preempt_enable_no_resched_notrace();
>
> This is a preemption bug. Does preempt_enable_notrace() not work?

No it didn't, because we end up calling preempt_schedule_notrace(),
which again might end in recursion.

Normally we could surround this by
kcsan_disable_current/kcsan_enable_current(), but that doesn't work
because we have this sequence:

     reset_kcsan_skip();
     if (!kcsan_is_enabled())
         ...

to avoid underflowing the skip counter if KCSAN is disabled. That
could be solved by writing to the skip-counter twice: once with a
non-random value, and if KCSAN is enabled with a random value. Would
that be better?

And I'd like to avoid adding __no_kcsan to scheduler functions.

Any recommendation?

Thanks,
-- Marco


>
> >
> > -     put_cpu_var(kcsan_rand_state);
> >       return (u32)(((u64) res * ep_ro) >> 32);
> >  }
> >
> > --
> > 2.29.2.454.gaff20da3a2-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPwuq8Hph3oOyJCVgWQ_d-gOTPEOT3BpbR2pnm5LBeJbw%40mail.gmail.com.
