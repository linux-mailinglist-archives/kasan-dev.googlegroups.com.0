Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBE54L3AKGQEAXD534A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AAFA1EDCE5
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 08:02:45 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id h18sf3696186qkj.13
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 23:02:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591250564; cv=pass;
        d=google.com; s=arc-20160816;
        b=QE51CujetUlLbguGNc6gMkprazgWz8a+xf0c9WINX0cg9Kg03BYoqgmfYtkbCaVeB/
         VlaDoJomgjGsidFzCeeLGv2OOrhOWPIU0BRkq0ajhSyvmF4rHA2xjCb9/7oGgBVNb84+
         9pfBqh4XbjENgEYkb+RqbGNYwMFXEQ/GravTVycEIlnhnJHlMuhq/RI1yaO5xhPjwQFl
         c+lW67+TAt5nI1Iwskhj4VfHFdlmnkY5JvE/glWr7FMXVUMrNbkBPXXLUqWJJLg3/RVg
         KrrWB/9ZfWIX+p9FMZ5JF2aVr96TyhbX1PbqvGlnPc/gnYSRdbRawrItP6mnawU62P3i
         f3Qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SZmSSck1tOsl4ux2xPxCSzLdbdDpTTwRvJIW6GOzWGg=;
        b=xSuPaqro/ft5pwYcN7LwyTzi89utC2Fed8MT8NFmd0z13LmkPFRdLW5XYrqDshJh8I
         mo8y4BkgWlmK+DJsb526l46T9P6FJEr8Ucj6bbjXrn38e5a3DTXNoo7rGpCm/F2+Obsm
         C7xqW4zpcx6sSlBQij4Tmzz9pt4UfZrhG+AyMmzrmt7SxORb3ypBV7F7xeV2VzchVW2i
         NIONvU+mF+TlSwQMBsiwacaRA8M09WFBqcgA2iNLFwcIvS9HUtfdfPlcPnSSG7CgxbtW
         daC4c7I8TzwpaHjIiCW4VUHktTdKkp1iEcjFVe4Jg7rgamnxPyeUPKgI2eDOyLNJAJSh
         jO+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YVGS0KiJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SZmSSck1tOsl4ux2xPxCSzLdbdDpTTwRvJIW6GOzWGg=;
        b=AaFQ4dbvmrEziIRiMYm1WQTey3LbdBhYuGdvDEEIpBnXL63yi9vJYJuRX1D/pIIXDY
         N/PRIL2KGt6jDw+6rr/087iD8DJ3LrQbf9PBX6XzvLkD92LVcivGak4rKYUUUj+Km3hZ
         5XWTqlNXomDrgQPXwUNgcAcNv7WGY9Q4xj7RNDw9a54LSHXPX5oEiRkpO2fFcq5WhPQg
         /aEdT1foTncpVvMaaR7rE58/YzTsw427pc799j+oc00Jupv1Uibaq0hDSTO/AAlQPdSB
         zNiDt+qBBuzGR7tvq/g09kBIfR/REfENvyTLizYihbc3NucisFuLXWkEjWxsE1ZImcXD
         UQiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SZmSSck1tOsl4ux2xPxCSzLdbdDpTTwRvJIW6GOzWGg=;
        b=QOSZYdpa74h5SoHkBNph+UC1vvJMguseFcIvbzpRPFVK1zU3OymkNMz/qa7+ySap1x
         ZzwlSf7G56wLAV2iD+4rx/FkPfh/QgUqoTqlAD8fAcCutvqbXnGfBPhrHY61VKqeA1AH
         NoCBx4dARSRmgYaggfPZ/aik3LckJOJDgS2yOGqFX2Z/EZgFllWFF7e04qpkc+ERPrqF
         BF/tg1YfQilSaJneoDhgWlzVrY8Ke5qyPMWGQ/Dz7hGddHAGGDDjOtMUf7A33Gi48wWR
         fA6VLAn1LrmBqcbMi4oLB0dmQ/3FbCqLy9pEIeKmELY2M2iMJP/tITfs4XcceD4vXIUY
         jBhw==
X-Gm-Message-State: AOAM533vJfmSAdK5P/EHsFgYaO8r5UM7rF+qjcm7wKSbyjUe16uHxNRy
	pt/l+66ultDFPNVNVQ0YKN4=
X-Google-Smtp-Source: ABdhPJxzdupZhMWFThTKIGrYJhSAj/xlm85HlDKONpcUulhKWnpDVu2TXEE00yfYOJfvswt9uN/AbQ==
X-Received: by 2002:a37:dce:: with SMTP id 197mr3350787qkn.250.1591250564173;
        Wed, 03 Jun 2020 23:02:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7c8b:: with SMTP id y11ls1450490qtv.4.gmail; Wed, 03 Jun
 2020 23:02:43 -0700 (PDT)
X-Received: by 2002:ac8:7350:: with SMTP id q16mr2923039qtp.74.1591250563833;
        Wed, 03 Jun 2020 23:02:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591250563; cv=none;
        d=google.com; s=arc-20160816;
        b=dzdseMEfJmaSFcGTqEgyv3jdGrI1hcf3xl9dGHGdCsJg2XfGgVDTtyuu6n9r1kKTyJ
         TgjNzcxLCy2n+SnNMMOe+7ks5CWx5gGvGGKUsMkExD6y2ZABmuaglEopiz+2/rqlKcJy
         zJeBhrKYsfWS9FdMUTlqaPa0zOuMt0fEcaLGVmrGlVnvCGo53Vfh14yTn53e0cUpAqrR
         jInBbnH+X1JLgs0AyaFFG1zi4o5aI9XRLh8787VcazgEWVX4/aYlVMwWhWDR8wE7Km1p
         Qw65+LEZneaMguWcY3kRNHOYn9aCg2X6KWCRqqViHeEuVt1zyrjmPLL3OMLYs0mT+g0n
         t3eA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SnnBoUNb8YbnZYmKYOcPjU3YbYG/8fac3+VAiSLpC54=;
        b=z3/GHDDTCATpbQrVmZAG6CqQzB4L3a3WJE8NP2zv9vM8puiY2s8JAXPBDNnRgZUprD
         ZzumM08XZd13I3RTWXFOBhJLIsQxYyWimJ94EHgNoJMUSkTEqk4Stk1JEOn1rCsZV5OM
         w8ReaIShgRIZPOYemzIFzxBcp7wLDWEJQldGxXdOnIbkEQ9GAzxZkkNMDPGeZQRPt+Ll
         Izb3+YCicS13L0gvQi9silyHY0Mjiy7TMDr8ydA860HTKBJRz2yVu5maZPmu4Qi7fKNI
         gQH+PplyekKzueEhu26X7h+VtLb56Z1TJ4GA70Mpvh+CKAWh/Iib9OwyJiwvYNSvpO3D
         WfwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YVGS0KiJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id c186si228537qkb.7.2020.06.03.23.02.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Jun 2020 23:02:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id u23so3866103otq.10
        for <kasan-dev@googlegroups.com>; Wed, 03 Jun 2020 23:02:43 -0700 (PDT)
X-Received: by 2002:a9d:7dc4:: with SMTP id k4mr2392364otn.251.1591250563027;
 Wed, 03 Jun 2020 23:02:43 -0700 (PDT)
MIME-Version: 1.0
References: <20200603114014.152292216@infradead.org> <20200603114051.896465666@infradead.org>
 <20200603164600.GQ29598@paulmck-ThinkPad-P72> <20200603171320.GE2570@hirez.programming.kicks-ass.net>
 <20200604033409.GX29598@paulmck-ThinkPad-P72>
In-Reply-To: <20200604033409.GX29598@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Jun 2020 08:02:31 +0200
Message-ID: <CANpmjNPmXLR1MsLonhn_gdDuOquzQ0Ovw7PAWejOJ-aV2F=iHg@mail.gmail.com>
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	"the arch/x86 maintainers" <x86@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YVGS0KiJ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Thu, 4 Jun 2020 at 05:34, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Wed, Jun 03, 2020 at 07:13:20PM +0200, Peter Zijlstra wrote:
> > On Wed, Jun 03, 2020 at 09:46:00AM -0700, Paul E. McKenney wrote:
> >
> > > > --- a/kernel/rcu/tree.c
> > > > +++ b/kernel/rcu/tree.c
> > > > @@ -250,7 +250,7 @@ static noinstr void rcu_dynticks_eqs_ent
> > > >    * next idle sojourn.
> > > >    */
> > > >   rcu_dynticks_task_trace_enter();  // Before ->dynticks update!
> > > > - seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> > > > + seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> > >
> > > To preserve KCSAN's ability to see this, there would be something like
> > > instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks)) prior
> > > to the instrumentation_end() invoked before rcu_dynticks_eqs_enter()
> > > in each of rcu_eqs_enter() and rcu_nmi_exit(), correct?
> >
> > Yes.
> >
> > > >   // RCU is no longer watching.  Better be in extended quiescent state!
> > > >   WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
> > > >                (seq & RCU_DYNTICK_CTRL_CTR));
> > > > @@ -274,13 +274,13 @@ static noinstr void rcu_dynticks_eqs_exi
> > > >    * and we also must force ordering with the next RCU read-side
> > > >    * critical section.
> > > >    */
> > > > - seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> > > > + seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> > >
> > > And same here, but after the instrumentation_begin() following
> > > rcu_dynticks_eqs_exit() in both rcu_eqs_exit() and rcu_nmi_enter(),
> > > correct?
> >
> > Yep.
> >
> > > >   // RCU is now watching.  Better not be in an extended quiescent state!
> > > >   rcu_dynticks_task_trace_exit();  // After ->dynticks update!
> > > >   WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
> > > >                !(seq & RCU_DYNTICK_CTRL_CTR));
> > > >   if (seq & RCU_DYNTICK_CTRL_MASK) {
> > > > -         atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
> > > > +         arch_atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
> > >
> > > This one is gone in -rcu.
> >
> > Good, because that would make things 'complicated' with the external
> > instrumentation call. And is actually the reason I didn't even attempt
> > it this time around.
> >
> > > >           smp_mb__after_atomic(); /* _exit after clearing mask. */
> > > >   }
> > > >  }
> > > > @@ -313,7 +313,7 @@ static __always_inline bool rcu_dynticks
> > > >  {
> > > >   struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
> > > >
> > > > - return !(atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
> > > > + return !(arch_atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
> >
> > The above is actually instrumented by KCSAN, due to arch_atomic_read()
> > being a READ_ONCE() and it now understanding volatile.
> >
> > > Also instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks)) as
>
> Right, this should instead be instrument_read(...).
>
> Though if KCSAN is unconditionally instrumenting volatile, how does
> this help?  Or does KCSAN's instrumentation of volatile somehow avoid
> causing trouble?

When used normally outside noinstr functions, because this is an
__always_inline function, it will be instrumented. Within noinstr
(which imply __no_kcsan) functions it should not be instrumented.

Thanks,
-- Marco


> > > follows:
> > >
> > > o   rcu_nmi_exit(): After each following instrumentation_begin().
> >
> > Yes
> >
> > > o   In theory in rcu_irq_exit_preempt(), but as this generates code
> > >     only in lockdep builds, it might not be worth worrying about.
> > >
> > > o   Ditto for rcu_irq_exit_check_preempt().
> > >
> > > o   Ditto for __rcu_irq_enter_check_tick().
> >
> > Not these, afaict they're all the above arch_atomic_read(), which is
> > instrumented due to volatile in these cases.
> >
> > > o   rcu_nmi_enter(): After each following instrumentation_begin().
> >
> > Yes
> >
> > > o   __rcu_is_watching() is itself noinstr:
> > >
> > >     o       idtentry_enter_cond_rcu(): After each following
> > >             instrumentation_begin().
> > >
> > > o   rcu_is_watching(): Either before or after the call to
> > >     rcu_dynticks_curr_cpu_in_eqs().
> >
> > Something like that yes.
> >
> > > >  }
> > > >
> > > >  /*
> > > > @@ -692,6 +692,7 @@ noinstr void rcu_nmi_exit(void)
> > > >  {
> > > >   struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
> > > >
> > > > + instrumentation_begin();
> > > >   /*
> > > >    * Check for ->dynticks_nmi_nesting underflow and bad ->dynticks.
> > > >    * (We are exiting an NMI handler, so RCU better be paying attention
> > > > @@ -705,7 +706,6 @@ noinstr void rcu_nmi_exit(void)
> > > >    * leave it in non-RCU-idle state.
> > > >    */
> > > >   if (rdp->dynticks_nmi_nesting != 1) {
> > > > -         instrumentation_begin();
> > > >           trace_rcu_dyntick(TPS("--="), rdp->dynticks_nmi_nesting, rdp->dynticks_nmi_nesting - 2,
> > > >                             atomic_read(&rdp->dynticks));
> > > >           WRITE_ONCE(rdp->dynticks_nmi_nesting, /* No store tearing. */
> > > > @@ -714,7 +714,6 @@ noinstr void rcu_nmi_exit(void)
> > > >           return;
> > > >   }
> > > >
> > > > - instrumentation_begin();
> > > >   /* This NMI interrupted an RCU-idle CPU, restore RCU-idleness. */
> > > >   trace_rcu_dyntick(TPS("Startirq"), rdp->dynticks_nmi_nesting, 0, atomic_read(&rdp->dynticks));
> > > >   WRITE_ONCE(rdp->dynticks_nmi_nesting, 0); /* Avoid store tearing. */
> > >
> > > This one looks to be having no effect on instrumentation of atomics, but
> > > rather coalescing a pair of instrumentation_begin() into one.
> > >
> > > Do I understand correctly?
> >
> > Almost, it puts the WARN_ON_ONCE()s under instrumentation_begin() too,
> > and that makes a differnce, iirc it was the
> > rcu_dynticks_curr_cpu_in_eqs() call that stood out. But that could've
> > been before I switched it to arch_atomic_read(). In any case, I find
> > this form a lot clearer.
>
> Got it, thank you.
>
>                                                 Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPmXLR1MsLonhn_gdDuOquzQ0Ovw7PAWejOJ-aV2F%3DiHg%40mail.gmail.com.
