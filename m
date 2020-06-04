Return-Path: <kasan-dev+bncBAABBP4D4T3AKGQELZARW6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 87F911EE664
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 16:14:25 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id s7sf4744298plp.13
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 07:14:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591280064; cv=pass;
        d=google.com; s=arc-20160816;
        b=AvzHgY8fMOQaxa5mxle0O4yXTbWmmozVRm2sE7QJw82jQID3Zq3itvxnnI6OjIoOKR
         dPyDgWc3Xp7d29zm/EZ1g8HMuUUvLHm5moZBpOoGgNR11mswxuajuSNszCmnAiRWRRsE
         baI89P9MnD87UQj3zOrQytVaFLeDxwZR1fS/Ejjn4xZDkgh2Asf3nQQF7S8TCWsvQISL
         7UAN5gkLEbhrQpcF3RZWYkSJPqJiMvJqyEZdvGY14DinHh3yh9eu/qrF3mOGhm2LQPrq
         eLIDl0DtyRXeIYeLCz+fCEgZTdill/uOqWTkyHClIajZh5nhtlGz0SyXsCiG8aXrVNQI
         UF9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=7ES8UDxW9YmNgLKc+rFca/KnSDDtVBjNNomx75qAMlQ=;
        b=YKU1eLFEKEY5+3mpOLCjMZP2MK3j1UbL+EpPAgbzzgK9cLwQRV0B7PbpAmck83nkZV
         s2Yvw0VOYhgJJyeWWXFrl6ITMkzz256A2ihxVNinRmNmGf1m7rOvh86GO/+rQHQalIC1
         lVW7qlDcDaUqIFhMQys/NHbQO3Iy5xf8bpeSITJk+P3Gqs3atrJDigB2i57rx4XYN1hf
         /gTZBxjzj/aHwRPOBGbFFsHkyPK8dzHwmcnRl6GDFcJsxBoYGELWWqVB8opWxTX/vVPO
         gTPmpn8JG/WLyMUyeZgTjnRKLQ404hWtaCGZbrvPZIQgze7DWeF6Ata0IrtTzXQpqZLP
         o5Tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=doB9Gd21;
       spf=pass (google.com: domain of srs0=yzmc=7r=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YzMc=7R=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7ES8UDxW9YmNgLKc+rFca/KnSDDtVBjNNomx75qAMlQ=;
        b=my/0ElS3hX4K+WV/mEZ2Fp7k6EIxnOhrBgAReIZnVwWVPFvdmvgwA0UjUb8pxWMMoe
         KAbiIKpFwfP1SreaJ+xlsGK8+y48PflGpxKHHuWukerLGza86UNBdoZiL9qiJ1pJuRou
         Q539THY1x6NHflDTJrMTu40xXVTI4PdaIYQ5EvH4rnFSV1HRLc2XLI0QXqo3yNq+64y4
         h+oe5brr2fHu2n7mAZ2QoogFK/5xdlhB5iRnMALLX/PZZH2p6iKj7NdTSoUFJ1kosPqV
         Csw/QhWJQpTtJ6VKX/V7J9eqVXreirucykZTjKgPeDapyB6Jz9mqqcXGSkNuXwkUEaDt
         so0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7ES8UDxW9YmNgLKc+rFca/KnSDDtVBjNNomx75qAMlQ=;
        b=Djj+ZW+936FG3bGPDGOFn9HwCbtN2CagoSYqjPNyKooLwBKZ7Vy/Ya9cJTjvCFwEGT
         6kkJt06QvVlToHq6FFawFs5/fh71Gx4Sd6ow9O8o8m4C9A7uHQCOxJ8C9MDDFxTi2p4r
         ZMnFyTSgaZui9juDuiihIGExtHMO3WvhjH7VO4uKTAIpahNQezua3n5gDqcpySvhd1WE
         LXkqKqQEKB/l7DwfZ+E9UdHeLc3GcWL3ad9MkOh1Ji3gczF5hBRtYSUhCYleZ1xp1nI7
         p2HX+UWNriovrgQUdFW1jykSRNyJhVDwb8IrCZpgd0dQhnBTlV6kFX5clulCOC8Llh3w
         XBkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532gYkI+FXOCCuHOAH2QWvhKGBd702B+0C+X6/0+hcoZpe9M06Ph
	+/aqc3aZt6xihM5uEFjapOE=
X-Google-Smtp-Source: ABdhPJw9dqeTCb5uom2QOTiKVZQBKZj8O2bUiuRbNUz4c1NnRxHTNbYh+ZtxR0KX9pYzcVgiEaBxTQ==
X-Received: by 2002:a17:90b:245:: with SMTP id fz5mr6630485pjb.138.1591280064032;
        Thu, 04 Jun 2020 07:14:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:384c:: with SMTP id nl12ls3302442pjb.2.canary-gmail;
 Thu, 04 Jun 2020 07:14:23 -0700 (PDT)
X-Received: by 2002:a17:902:9044:: with SMTP id w4mr5156375plz.83.1591280063664;
        Thu, 04 Jun 2020 07:14:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591280063; cv=none;
        d=google.com; s=arc-20160816;
        b=fM1G3DhlA4MfTzryZgzG0YxC7vrI04IMo50imhXdw9PIrYgR0sS3cx8gjUZnsnD2Ww
         NYt/oMfIilfKLeeiw83Lt4oi3vhWwWeqf1o117GL30bAaQR757JHogVLbVagSYb1Z5Cm
         +DBBld1SnFI/WHBxfJ8HJxk2a2Im/NFvDx6AFa34EHWVcWEyL4NwPRotomSMoGwgAMZZ
         jC3sNhp3TYkspd7F9FtyBo9EjwbWCGqYJIJyZX1MGqqCFoutvOl2v2PHQPxmVUGKIRrG
         ddxvyh1Vu0pg9TjhAq5QtcuujAB25QkKAq4s99uCVPLnxO7DEU6D90akxnqWLxiQrTqz
         OWDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=NbmAd59CRAYanHn56dcGrYnJ85/A2yUgt+iQqu2zmcs=;
        b=CU1hvi0OE7YzIgY+j9LSyHJxUjp9bNQ/NodqwX6gI0Gf0RyambSo/8N7PoGYHMLEUF
         95WnXARVGlM5rTcj0xkZEFauVH8o35g2yMovcG0sStkQ90l2atqqQMqq7IguZ5SAx4QQ
         HCnAdBew3zwp3GMLCcjlxHg8TLnT7wUWRZtPkbg0GAbszK2zg5GK9JBKHvJ58ud5q6ZB
         6jDqQYwMAEsAK57qScO8/9lfCEz4Ak0zc40tR8/Qoi5PNjfGSrF1QoZ7Bh0kyBDmnsbF
         X9vnjyMntNPdx9Pgl2Ze8UsF+tCPQ/VIFZ7TjdbfWUNdObPGk4U9ZQlhslaIx7ijZ5Q5
         a4xw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=doB9Gd21;
       spf=pass (google.com: domain of srs0=yzmc=7r=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YzMc=7R=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g10si303868plg.3.2020.06.04.07.14.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Jun 2020 07:14:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=yzmc=7r=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 5019B207D8;
	Thu,  4 Jun 2020 14:14:23 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 2D9CB35228BC; Thu,  4 Jun 2020 07:14:23 -0700 (PDT)
Date: Thu, 4 Jun 2020 07:14:23 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	the arch/x86 maintainers <x86@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200604141423.GY29598@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
 <20200603164600.GQ29598@paulmck-ThinkPad-P72>
 <20200603171320.GE2570@hirez.programming.kicks-ass.net>
 <20200604033409.GX29598@paulmck-ThinkPad-P72>
 <CANpmjNPmXLR1MsLonhn_gdDuOquzQ0Ovw7PAWejOJ-aV2F=iHg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPmXLR1MsLonhn_gdDuOquzQ0Ovw7PAWejOJ-aV2F=iHg@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=doB9Gd21;       spf=pass
 (google.com: domain of srs0=yzmc=7r=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YzMc=7R=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Thu, Jun 04, 2020 at 08:02:31AM +0200, Marco Elver wrote:
> On Thu, 4 Jun 2020 at 05:34, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Wed, Jun 03, 2020 at 07:13:20PM +0200, Peter Zijlstra wrote:
> > > On Wed, Jun 03, 2020 at 09:46:00AM -0700, Paul E. McKenney wrote:
> > >
> > > > > --- a/kernel/rcu/tree.c
> > > > > +++ b/kernel/rcu/tree.c
> > > > > @@ -250,7 +250,7 @@ static noinstr void rcu_dynticks_eqs_ent
> > > > >    * next idle sojourn.
> > > > >    */
> > > > >   rcu_dynticks_task_trace_enter();  // Before ->dynticks update!
> > > > > - seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> > > > > + seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> > > >
> > > > To preserve KCSAN's ability to see this, there would be something like
> > > > instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks)) prior
> > > > to the instrumentation_end() invoked before rcu_dynticks_eqs_enter()
> > > > in each of rcu_eqs_enter() and rcu_nmi_exit(), correct?
> > >
> > > Yes.
> > >
> > > > >   // RCU is no longer watching.  Better be in extended quiescent state!
> > > > >   WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
> > > > >                (seq & RCU_DYNTICK_CTRL_CTR));
> > > > > @@ -274,13 +274,13 @@ static noinstr void rcu_dynticks_eqs_exi
> > > > >    * and we also must force ordering with the next RCU read-side
> > > > >    * critical section.
> > > > >    */
> > > > > - seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> > > > > + seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> > > >
> > > > And same here, but after the instrumentation_begin() following
> > > > rcu_dynticks_eqs_exit() in both rcu_eqs_exit() and rcu_nmi_enter(),
> > > > correct?
> > >
> > > Yep.
> > >
> > > > >   // RCU is now watching.  Better not be in an extended quiescent state!
> > > > >   rcu_dynticks_task_trace_exit();  // After ->dynticks update!
> > > > >   WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
> > > > >                !(seq & RCU_DYNTICK_CTRL_CTR));
> > > > >   if (seq & RCU_DYNTICK_CTRL_MASK) {
> > > > > -         atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
> > > > > +         arch_atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
> > > >
> > > > This one is gone in -rcu.
> > >
> > > Good, because that would make things 'complicated' with the external
> > > instrumentation call. And is actually the reason I didn't even attempt
> > > it this time around.
> > >
> > > > >           smp_mb__after_atomic(); /* _exit after clearing mask. */
> > > > >   }
> > > > >  }
> > > > > @@ -313,7 +313,7 @@ static __always_inline bool rcu_dynticks
> > > > >  {
> > > > >   struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
> > > > >
> > > > > - return !(atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
> > > > > + return !(arch_atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
> > >
> > > The above is actually instrumented by KCSAN, due to arch_atomic_read()
> > > being a READ_ONCE() and it now understanding volatile.
> > >
> > > > Also instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks)) as
> >
> > Right, this should instead be instrument_read(...).
> >
> > Though if KCSAN is unconditionally instrumenting volatile, how does
> > this help?  Or does KCSAN's instrumentation of volatile somehow avoid
> > causing trouble?
> 
> When used normally outside noinstr functions, because this is an
> __always_inline function, it will be instrumented. Within noinstr
> (which imply __no_kcsan) functions it should not be instrumented.

Got it, thank you!

This is going to require some serious commenting.  ;-)

							Thanx, Paul

> Thanks,
> -- Marco
> 
> 
> > > > follows:
> > > >
> > > > o   rcu_nmi_exit(): After each following instrumentation_begin().
> > >
> > > Yes
> > >
> > > > o   In theory in rcu_irq_exit_preempt(), but as this generates code
> > > >     only in lockdep builds, it might not be worth worrying about.
> > > >
> > > > o   Ditto for rcu_irq_exit_check_preempt().
> > > >
> > > > o   Ditto for __rcu_irq_enter_check_tick().
> > >
> > > Not these, afaict they're all the above arch_atomic_read(), which is
> > > instrumented due to volatile in these cases.
> > >
> > > > o   rcu_nmi_enter(): After each following instrumentation_begin().
> > >
> > > Yes
> > >
> > > > o   __rcu_is_watching() is itself noinstr:
> > > >
> > > >     o       idtentry_enter_cond_rcu(): After each following
> > > >             instrumentation_begin().
> > > >
> > > > o   rcu_is_watching(): Either before or after the call to
> > > >     rcu_dynticks_curr_cpu_in_eqs().
> > >
> > > Something like that yes.
> > >
> > > > >  }
> > > > >
> > > > >  /*
> > > > > @@ -692,6 +692,7 @@ noinstr void rcu_nmi_exit(void)
> > > > >  {
> > > > >   struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
> > > > >
> > > > > + instrumentation_begin();
> > > > >   /*
> > > > >    * Check for ->dynticks_nmi_nesting underflow and bad ->dynticks.
> > > > >    * (We are exiting an NMI handler, so RCU better be paying attention
> > > > > @@ -705,7 +706,6 @@ noinstr void rcu_nmi_exit(void)
> > > > >    * leave it in non-RCU-idle state.
> > > > >    */
> > > > >   if (rdp->dynticks_nmi_nesting != 1) {
> > > > > -         instrumentation_begin();
> > > > >           trace_rcu_dyntick(TPS("--="), rdp->dynticks_nmi_nesting, rdp->dynticks_nmi_nesting - 2,
> > > > >                             atomic_read(&rdp->dynticks));
> > > > >           WRITE_ONCE(rdp->dynticks_nmi_nesting, /* No store tearing. */
> > > > > @@ -714,7 +714,6 @@ noinstr void rcu_nmi_exit(void)
> > > > >           return;
> > > > >   }
> > > > >
> > > > > - instrumentation_begin();
> > > > >   /* This NMI interrupted an RCU-idle CPU, restore RCU-idleness. */
> > > > >   trace_rcu_dyntick(TPS("Startirq"), rdp->dynticks_nmi_nesting, 0, atomic_read(&rdp->dynticks));
> > > > >   WRITE_ONCE(rdp->dynticks_nmi_nesting, 0); /* Avoid store tearing. */
> > > >
> > > > This one looks to be having no effect on instrumentation of atomics, but
> > > > rather coalescing a pair of instrumentation_begin() into one.
> > > >
> > > > Do I understand correctly?
> > >
> > > Almost, it puts the WARN_ON_ONCE()s under instrumentation_begin() too,
> > > and that makes a differnce, iirc it was the
> > > rcu_dynticks_curr_cpu_in_eqs() call that stood out. But that could've
> > > been before I switched it to arch_atomic_read(). In any case, I find
> > > this form a lot clearer.
> >
> > Got it, thank you.
> >
> >                                                 Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604141423.GY29598%40paulmck-ThinkPad-P72.
