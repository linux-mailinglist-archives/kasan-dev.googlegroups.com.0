Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXMAYT4QKGQEJMFTYYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id CBD8B240332
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 10:07:58 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id f5sf7253009pfe.2
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 01:07:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597046877; cv=pass;
        d=google.com; s=arc-20160816;
        b=II5liRYHgun/jV+UWdPz/TbZHQGfsFohqGgXBvmWmymaikBuTHJkGI8/DwAjAR/Vgu
         qw4Oa25dWCtr65JQOuqpc5R4vd9jliwePqTOWAjIDejJG3jOD98bu/BspEcxasDH3Rid
         8fjwIrPMfbewY4niFe0qlbGtPKc1Dj5MHGGrwD1dS5KvCWHmDImwdCzaGqoC8ddfCoDH
         /tzrmApShCmJ9866P8B+e6oXhV36Im1YjLjsWnioQeOrnOZ2+9Hk+2jT+/mzeCMQR4zo
         OOfOpw0psS6su7XaGGPjNMDoKXPZUzDrZyYZkfKdjekpeDvowQUJNF5FzI6jAn/PbVjJ
         jJIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=I2KzTSniOtIAeLlFGqBN3oqJDKN0dHqIATJf5mSZoQY=;
        b=rfKrJATIao8GfSd4gC1O4ZR+uRbtlyYgjgw08jdhElCm4MVeV1A00LuskrPqMmXYo1
         v0bT2yLKUhQeAtPjIR5rvpGRr6zWlPAX3wku1zcRGT43lI5Tf/Iy6RyaxBeuVzqplGOF
         azBX6wcWk1a8Nqw/LKjNNP0BcGshjmCrTtbuRGn579+F8XEE9ROL7VC7sCAeaBBZh7J9
         Gegt5Oqd4nVEUjpNI9IS0hq2Y0bgDN80DmxqjcJIJBm7zrUH4VSQDHKKnhWJtLfhCRP4
         xE1lMxXobXjfjaFpNV2BrCngoP4cz14sOy2s7cP1gcPr7LLB1ofYvByvCEzrjlZ9CKDh
         Kr/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FXtn7Xam;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I2KzTSniOtIAeLlFGqBN3oqJDKN0dHqIATJf5mSZoQY=;
        b=AV1j6xjggpL+fFbUP8KGvzaA0XW8Xyh3dSOPaa0VGIM339zSuggPgFdgnVN2ynyXjp
         x3flNmCkWXKO3XJmU2SpHxEcU2vkjX8/iMBcGbi1+cmv52l693r7OcOtccb0ePGf7atV
         pZ5M1QbBjmBt47bqnWqUgBykVjkI1acS24wiY22f7IjMjtygjjZYFjZqpkX0dFUf/gjY
         52LBcgV4uAwMdXm8BW2eXYYr11TbcLKuSt/yParF3Kz/uIQyI9lptxCSK5svymgdENoG
         YS2i8uqwgvoCNC0VzIpxILISFnjKMNyxLsPU1pztCHCQqvELMkSIbt1rEt0Olb8O1GZG
         hraw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I2KzTSniOtIAeLlFGqBN3oqJDKN0dHqIATJf5mSZoQY=;
        b=eN+Cg59p8poEzBjp/Aw5o1HUjTte+r1HtEGM35rqOrHJGRqTfXG+gAn6NnA/r8kdTx
         8t9mCOnN+yZaYNV2nzi3BSlzpjSRRoSAhtDhKYtm2Qjr+Jdt51JYDCXg4m7bUZyalZ/6
         mY+v9DiNm/JsgE4v/E9VLHxNvKV6zKYM1PYi3HzSZZq73V6ZjWUfTssa/rJ+coIUuhC3
         G3YP1nA2hUkVwcrAAgjAT3H419qy/onc+WAmmxGc6kZO/qoBbzgqxyfrb36FD99Cg/SB
         3IH2bTAmXcSHiPGBdvU5Y5rf+lP4SC1Er5pnFp2EEWmI0c0pgvr1AtD+zkGW1ysNk2AA
         pdiw==
X-Gm-Message-State: AOAM532uc/Q2peHSghlU/H5fXgeZ1H7+4BJhLYU17+cEJaXU4uquQY5t
	5qqjAp0kzUvedXsPCDSYgvs=
X-Google-Smtp-Source: ABdhPJzd3A9sj8g+xZhG6IWx5xmJvTeMlDVF2f4XZF7DzJ1c9Rt6khQ1McFtCGxaXlYEm4h6iAtTTQ==
X-Received: by 2002:a63:9dc2:: with SMTP id i185mr13433811pgd.203.1597046877370;
        Mon, 10 Aug 2020 01:07:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3367:: with SMTP id m94ls6615044pjb.1.canary-gmail;
 Mon, 10 Aug 2020 01:07:57 -0700 (PDT)
X-Received: by 2002:a17:90a:b107:: with SMTP id z7mr26938970pjq.4.1597046876874;
        Mon, 10 Aug 2020 01:07:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597046876; cv=none;
        d=google.com; s=arc-20160816;
        b=gVV7JnakIk0mKaOIFwShkfug5G4ZTyPuWnbHl9CLn/6zpqo80vim6rJ3iW2PG1nQ4A
         tLuApn6vKxpzWQxMdywvYJ6cqx+m6RLSl7pCWgSAPyYWt8CelJEHHmyatejT0Cvuz1Zn
         r5XQ8ivCWUaS45wKAqlixSWtI6VrHXDrgmnOlPbt0HBOIsIL+rQPo31qSBmd6rBPFm4/
         EtGpJcRahPmEElrTFX6FPDJJswWusxZA1pd5eentEwGc7/jdEEngro/R89L31zHKnti6
         UO2x/GiyZGwFSm+fj3YhVWLLmmSGj1UxrHJyLfyoI6oMRm9+4dSFCstPKeilW4eMBfxE
         Txaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hGTCJkoIKMtHtW/Pwvl8SwnSj7DsdCNAqdhJNP6CKQo=;
        b=PFb6WO/mbaDt/xxXDCLqUaJTTEXBTzaP+tZ3xiv67A8qtBXQi0RV3NbOV/uqrbOCuv
         +cE9E5ZD1C06dznkHtt/+CGmudg1CLlQ9km6oMjMEI4Hj+Gq9a3ZPkLK0Gm1xfmG3tCK
         ij5qjYg1mS6J0m8jeHGWsMy02t69y4r+KIgisMX1XUFp94utbwdjEwLf2735ueAZFT1o
         NFV8NN5SlCckQdI0sa6zkTgBK/sKha10D7/LWmaxt6PMV+yCfVSwtCKy0drIaEyHqpe8
         AaCm1utcjkz6wRpyx7Dda9aAvLRBDJawrmN4qenqsZEBWN7GKQSNQurw6TRj7v8IOnws
         m/6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FXtn7Xam;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id l26si641390pfe.2.2020.08.10.01.07.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Aug 2020 01:07:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id e6so8164960oii.4
        for <kasan-dev@googlegroups.com>; Mon, 10 Aug 2020 01:07:56 -0700 (PDT)
X-Received: by 2002:aca:d4d5:: with SMTP id l204mr21041277oig.70.1597046875877;
 Mon, 10 Aug 2020 01:07:55 -0700 (PDT)
MIME-Version: 1.0
References: <20200807090031.3506555-1-elver@google.com> <20200807170618.GW4295@paulmck-ThinkPad-P72>
In-Reply-To: <20200807170618.GW4295@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 10 Aug 2020 10:07:44 +0200
Message-ID: <CANpmjNPqEeQvg53wJ5EsyfssSqyOqCsPG+YTV6ytj6wsc+5BPQ@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Treat runtime as NMI-like with interrupt tracing
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FXtn7Xam;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Fri, 7 Aug 2020 at 19:06, Paul E. McKenney <paulmck@kernel.org> wrote:
> On Fri, Aug 07, 2020 at 11:00:31AM +0200, Marco Elver wrote:
> > Since KCSAN instrumentation is everywhere, we need to treat the hooks
> > NMI-like for interrupt tracing. In order to present an as 'normal' as
> > possible context to the code called by KCSAN when reporting errors, we
> > need to update the IRQ-tracing state.
> >
> > Tested: Several runs through kcsan-test with different configuration
> > (PROVE_LOCKING on/off), as well as hours of syzbot testing with the
> > original config that caught the problem (without CONFIG_PARAVIRT=y,
> > which appears to cause IRQ state tracking inconsistencies even when
> > KCSAN remains off, see Link).
> >
> > Link: https://lkml.kernel.org/r/0000000000007d3b2d05ac1c303e@google.com
> > Fixes: 248591f5d257 ("kcsan: Make KCSAN compatible with new IRQ state tracking")
> > Reported-by: syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com
> > Co-developed-by: Peter Zijlstra (Intel) <peterz@infradead.org>

Peter, if you're fine with it, I think we'll require your
Signed-off-by (since Co-developed-by).

> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > Patch Note: This patch applies to latest mainline. While current
> > mainline suffers from the above problem, the configs required to hit the
> > issue are likely not enabled too often (of course with PROVE_LOCKING on;
> > we hit it on syzbot though). It'll probably be wise to queue this as
> > normal on -rcu, just in case something is still off, given the
> > non-trivial nature of the issue. (If it should instead go to mainline
> > right now as a fix, I'd like some more test time on syzbot.)
>
> The usual, please let me know when/if you would like me to apply
> to -rcu.  And have a great weekend!

I think we need to wait until you have rebased -rcu to 5.9-rc1 some
time next week. I will send a reminder after, and if it doesn't apply
cleanly, I'll send a rebased patch.

Thank you!

-- Marco

>                                                 Thanx, Paul
>
> > ---
> >  kernel/kcsan/core.c  | 79 ++++++++++++++++++++++++++++++++++----------
> >  kernel/kcsan/kcsan.h |  3 +-
> >  2 files changed, 62 insertions(+), 20 deletions(-)
> >
> > diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> > index 9147ff6a12e5..6202a645f1e2 100644
> > --- a/kernel/kcsan/core.c
> > +++ b/kernel/kcsan/core.c
> > @@ -291,13 +291,28 @@ static inline unsigned int get_delay(void)
> >                               0);
> >  }
> >
> > -void kcsan_save_irqtrace(struct task_struct *task)
> > -{
> > +/*
> > + * KCSAN instrumentation is everywhere, which means we must treat the hooks
> > + * NMI-like for interrupt tracing. In order to present a 'normal' as possible
> > + * context to the code called by KCSAN when reporting errors we need to update
> > + * the IRQ-tracing state.
> > + *
> > + * Save and restore the IRQ state trace touched by KCSAN, since KCSAN's
> > + * runtime is entered for every memory access, and potentially useful
> > + * information is lost if dirtied by KCSAN.
> > + */
> > +
> > +struct kcsan_irq_state {
> > +     unsigned long           flags;
> >  #ifdef CONFIG_TRACE_IRQFLAGS
> > -     task->kcsan_save_irqtrace = task->irqtrace;
> > +     int                     hardirqs_enabled;
> >  #endif
> > -}
> > +};
> >
> > +/*
> > + * This is also called by the reporting task for the other task, to generate the
> > + * right report with CONFIG_KCSAN_VERBOSE. No harm in restoring more than once.
> > + */
> >  void kcsan_restore_irqtrace(struct task_struct *task)
> >  {
> >  #ifdef CONFIG_TRACE_IRQFLAGS
> > @@ -305,6 +320,41 @@ void kcsan_restore_irqtrace(struct task_struct *task)
> >  #endif
> >  }
> >
> > +/*
> > + * Saves/restores IRQ state (see comment above). Need noinline to work around
> > + * unfortunate code-gen upon inlining, resulting in objtool getting confused as
> > + * well as losing stack trace information.
> > + */
> > +static noinline void kcsan_irq_save(struct kcsan_irq_state *irq_state)
> > +{
> > +#ifdef CONFIG_TRACE_IRQFLAGS
> > +     current->kcsan_save_irqtrace = current->irqtrace;
> > +     irq_state->hardirqs_enabled = lockdep_hardirqs_enabled();
> > +#endif
> > +     if (!kcsan_interrupt_watcher) {
> > +             kcsan_disable_current(); /* Lockdep might WARN, etc. */
> > +             raw_local_irq_save(irq_state->flags);
> > +             lockdep_hardirqs_off(_RET_IP_);
> > +             kcsan_enable_current();
> > +     }
> > +}
> > +
> > +static noinline void kcsan_irq_restore(struct kcsan_irq_state *irq_state)
> > +{
> > +     if (!kcsan_interrupt_watcher) {
> > +             kcsan_disable_current(); /* Lockdep might WARN, etc. */
> > +#ifdef CONFIG_TRACE_IRQFLAGS
> > +             if (irq_state->hardirqs_enabled) {
> > +                     lockdep_hardirqs_on_prepare(_RET_IP_);
> > +                     lockdep_hardirqs_on(_RET_IP_);
> > +             }
> > +#endif
> > +             raw_local_irq_restore(irq_state->flags);
> > +             kcsan_enable_current();
> > +     }
> > +     kcsan_restore_irqtrace(current);
> > +}
> > +
> >  /*
> >   * Pull everything together: check_access() below contains the performance
> >   * critical operations; the fast-path (including check_access) functions should
> > @@ -350,11 +400,13 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
> >       flags = user_access_save();
> >
> >       if (consumed) {
> > -             kcsan_save_irqtrace(current);
> > +             struct kcsan_irq_state irqstate;
> > +
> > +             kcsan_irq_save(&irqstate);
> >               kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_MAYBE,
> >                            KCSAN_REPORT_CONSUMED_WATCHPOINT,
> >                            watchpoint - watchpoints);
> > -             kcsan_restore_irqtrace(current);
> > +             kcsan_irq_restore(&irqstate);
> >       } else {
> >               /*
> >                * The other thread may not print any diagnostics, as it has
> > @@ -387,7 +439,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
> >       unsigned long access_mask;
> >       enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
> >       unsigned long ua_flags = user_access_save();
> > -     unsigned long irq_flags = 0;
> > +     struct kcsan_irq_state irqstate;
> >
> >       /*
> >        * Always reset kcsan_skip counter in slow-path to avoid underflow; see
> > @@ -412,14 +464,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
> >               goto out;
> >       }
> >
> > -     /*
> > -      * Save and restore the IRQ state trace touched by KCSAN, since KCSAN's
> > -      * runtime is entered for every memory access, and potentially useful
> > -      * information is lost if dirtied by KCSAN.
> > -      */
> > -     kcsan_save_irqtrace(current);
> > -     if (!kcsan_interrupt_watcher)
> > -             local_irq_save(irq_flags);
> > +     kcsan_irq_save(&irqstate);
> >
> >       watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
> >       if (watchpoint == NULL) {
> > @@ -559,9 +604,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
> >       remove_watchpoint(watchpoint);
> >       kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
> >  out_unlock:
> > -     if (!kcsan_interrupt_watcher)
> > -             local_irq_restore(irq_flags);
> > -     kcsan_restore_irqtrace(current);
> > +     kcsan_irq_restore(&irqstate);
> >  out:
> >       user_access_restore(ua_flags);
> >  }
> > diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
> > index 29480010dc30..6eb35a9514d8 100644
> > --- a/kernel/kcsan/kcsan.h
> > +++ b/kernel/kcsan/kcsan.h
> > @@ -24,9 +24,8 @@ extern unsigned int kcsan_udelay_interrupt;
> >  extern bool kcsan_enabled;
> >
> >  /*
> > - * Save/restore IRQ flags state trace dirtied by KCSAN.
> > + * Restore IRQ flags state trace dirtied by KCSAN.
> >   */
> > -void kcsan_save_irqtrace(struct task_struct *task);
> >  void kcsan_restore_irqtrace(struct task_struct *task);
> >
> >  /*
> > --
> > 2.28.0.236.gb10cc79966-goog
> >
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200807170618.GW4295%40paulmck-ThinkPad-P72.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPqEeQvg53wJ5EsyfssSqyOqCsPG%2BYTV6ytj6wsc%2B5BPQ%40mail.gmail.com.
