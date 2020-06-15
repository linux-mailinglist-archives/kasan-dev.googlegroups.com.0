Return-Path: <kasan-dev+bncBAABBZFGT73QKGQEDTJDS6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 582541FA0DC
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 22:00:38 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id 22sf12927483pgf.13
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 13:00:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592251237; cv=pass;
        d=google.com; s=arc-20160816;
        b=Knc77nqwmNfMectXeL5CJ8g/pbMEJkM2iF4XvgxPSgdFvnxgqohSIJE58w1R+fWqNH
         n3gPKaBNSeLBZyBebCSjOJH97Tyw84v0mSB2b0Qrmwqd6pa2wNslG6az0X3X6ryZo5+a
         rOrFn/apNA3WenKpHjv7IpOdli8ia2gHcHNAq1QSg/kjETcG3tMczhypAuosGXLHPml8
         vvVmKg04D8Xp9HBrLQeLr/y3A4jgmiB3Iyz84ZMGKeH6AmWOwK9iCtgg4/Rg/XYSab/F
         eHiEK35mEgeiLqJ4ooMWOeKOxlH5NSsGIsF3iMXByRJqciuBvE/GNaXnI7jqENHlQoEQ
         TUGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=rahu+39ArXSb7YMiugf42kokMK6U0A4J0HhfgzTylAM=;
        b=kE8H5yiyk71SOTg9FyPnSqpDc8WWGsg2hPuM1lcZdeZcG7mV8sSeLuCVldhXxJjr+e
         fhfd56pPx5riwYj0PNjPsk0WOwzbYC/neiZk8h3fr0eEyzqJc3GIPXU0TuAuq1cojEqj
         p4wC1xxPVe++b14EZC3uPpSbWN8iS19+X5sFM8s/Yq4mbJA27w84vGp1vj8J2flM5+Pu
         A079S6GY7mMzXglJQBW6WtzomWAH2TCoLUxVMkzIPtGePw0KoFvTVQZPfqZ50PlM6rYt
         RGUZN5jVjlVUu7fAYcNEenzg/xgrHWodGA1vll+QmhQ1OfFDE0XhoLdWQG+2LTifg7p8
         gKmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=LEWoOKSm;
       spf=pass (google.com: domain of srs0=xl4n=74=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xl4N=74=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rahu+39ArXSb7YMiugf42kokMK6U0A4J0HhfgzTylAM=;
        b=oPrMOaViC1+C0TAOlGYMqOImUjp0TCoteNdGgOR53eVFJgi5fbHUqz60zxhIS8CW9K
         sYd4JSlUYur3oFHWCPhNIc7qXRLPLP9DggvMfqmECCzV6v1ErzlGyThYRHHZE2foPFd/
         gstvdUZCFDXu3lPLYCFLrrtgBWEj9fpzjO3iWwns7EJrjxJATUBxw2IPauzz62FEb+RA
         EG0MtlLx9RWvCcYRdSR0B/rnMQJR9sr2/Qrvq0nybonCKaOdV+GmzUVmdnQmEWD70uoL
         Pjueg0eAQcZErOuEOdxUXILFltXAAxb6KvoXMdKjBMUBEkSv3+CbrJK59AX5IfmBv2e+
         hwqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rahu+39ArXSb7YMiugf42kokMK6U0A4J0HhfgzTylAM=;
        b=SN1W+m+q4nE8vvpulF2OxMgvLcgGOkbeALEOOZVhflpmZbmy+/ljhWG4FS9ZoMFjlh
         sslPAii5Q3OXnHcUJbweEQYwz+Fw3J9WwtgdrgtBGwSvohhRaAE9xir4NEQGbIKZUEwn
         oASs8UkikIuVG2Nde+2/GjSHJNi3KN/3etUquIadCaWm7r/odtM306vW7G1U2WqIHYtV
         CjC+ZEkzKaHKu2FwZHZFrXc7K5DQwu9P0jlyw7Zi8bcBHNPlbOYbSdp0/GEGlkmtyati
         pyOK62lk9OT/YgPS6PAFDSw3ubNrFuBkbPDR5bY7Dhn94uDBVeUV0Vc7g8lSIW9LKsfh
         yg3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531vFxlsTHKMLvWl4U1kGZ9f47Sf+fmkXPIJIm/BD3Tpml5hJlLy
	O5INUcidyXKUry5ostdcx2A=
X-Google-Smtp-Source: ABdhPJzQ3juLjdvMAIg0xtbH+LFRtpHmgJ4QVb+udERZHMvPNALfXMGvdQYuIQBov4GGjUf87lEA9A==
X-Received: by 2002:a62:64ca:: with SMTP id y193mr24904891pfb.123.1592251236910;
        Mon, 15 Jun 2020 13:00:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6845:: with SMTP id f5ls5235878pln.8.gmail; Mon, 15
 Jun 2020 13:00:36 -0700 (PDT)
X-Received: by 2002:a17:902:b942:: with SMTP id h2mr2489268pls.163.1592251236464;
        Mon, 15 Jun 2020 13:00:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592251236; cv=none;
        d=google.com; s=arc-20160816;
        b=YtZGtQQ8qdjk/cvRNeL/zXhGrGTVQ41GEcNNY+s2AGJ7rBpFM3BtBTMoQhHaMnJHJA
         yrUBer5N9/cTIKa+avz7ye+44UtKaB/YYTP37+YwQQDiN3I+G/eaopQIXYEcx1oENtWi
         GraiXSGWPLgd9ca1y3Unmw8Kg4ynLR/eq+tFj82Q/And8tEgF9JYnpx9cUbBxhSFTlgi
         hcJuluUlU596bk4volUu5Aq0kB5i2bGQwgdkRAWaS1Xz+cu6lvNZ4domklZLVsiDouzZ
         iaUDxwIMFSFaBffY92wgugmkOCZJuOXcCDyGU/MUWMDbD0D7ga5cTljWoA3Eu1paRXIR
         Pskw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Af848PbePB4esRezq0LDtIADcMI6ti7JfbbtFj21jL8=;
        b=H8yNwlSeO/2/ZNuhOF6QAIyhsCHldYkVUyYQLNVywsH4bRmdW9o94bFrYTm1XbIodq
         sZYNBtW2N824DO7Ea7mqPkYGD8svNE71uBK65IB4Ua11mgnbsl9t80s46fOGkSUkDs5k
         Y8dDXc9Mj2njmFGjzEAl+gQhIgrQt71YiHbYAorVnINFkP5UIVDktgElcI0Ncf/eybj3
         +sswqTPXZANHV5viEdAi1WPDxOh5ZnWfu5gCe/vYqbaalBFqrPU4S9kqHv/1dI8n9vC3
         Xx0nFPSw7hRXGS03lghJ7d+9bnE/+1HE7eVxHxAB4drhXVR89u7KaI6sKE7lBZvy6JEL
         7GhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=LEWoOKSm;
       spf=pass (google.com: domain of srs0=xl4n=74=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xl4N=74=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i17si20002pjv.1.2020.06.15.13.00.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Jun 2020 13:00:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xl4n=74=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 10BDA2071A;
	Mon, 15 Jun 2020 20:00:36 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id E938235218F0; Mon, 15 Jun 2020 13:00:35 -0700 (PDT)
Date: Mon, 15 Jun 2020 13:00:35 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: tglx@linutronix.de, x86@kernel.org, elver@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200615200035.GA5052@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
 <20200615154905.GZ2531@hirez.programming.kicks-ass.net>
 <20200615155513.GG2554@hirez.programming.kicks-ass.net>
 <20200615162427.GI2554@hirez.programming.kicks-ass.net>
 <20200615171404.GI2723@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200615171404.GI2723@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=LEWoOKSm;       spf=pass
 (google.com: domain of srs0=xl4n=74=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xl4N=74=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Jun 15, 2020 at 10:14:04AM -0700, Paul E. McKenney wrote:
> On Mon, Jun 15, 2020 at 06:24:27PM +0200, Peter Zijlstra wrote:
> > On Mon, Jun 15, 2020 at 05:55:13PM +0200, Peter Zijlstra wrote:
> > > On Mon, Jun 15, 2020 at 05:49:05PM +0200, Peter Zijlstra wrote:
> > > > @@ -983,13 +993,17 @@ noinstr void rcu_nmi_enter(void)
> > > >  		if (!in_nmi())
> > > >  			rcu_cleanup_after_idle();
> > > >  
> > > > +		instrumentation_begin();
> > > > +		// instrumentation for the noinstr rcu_dynticks_curr_cpu_in_eqs()
> > > > +		instrument_atomic_read(&rdp->dynticks, sizeof(rdp->dynticks));
> > > > +		// instrumentation for the noinstr rcu_dynticks_eqs_exit()
> > > > +		instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks));
> > > > +
> > > >  		incby = 1;
> > > >  	} else if (!in_nmi()) {
> > > >  		instrumentation_begin();
> > > >  		rcu_irq_enter_check_tick();
> > > > -		instrumentation_end();
> > > >  	}
> > > > -	instrumentation_begin();
> > > >  	trace_rcu_dyntick(incby == 1 ? TPS("Endirq") : TPS("++="),
> > > >  			  rdp->dynticks_nmi_nesting,
> > > >  			  rdp->dynticks_nmi_nesting + incby, atomic_read(&rdp->dynticks));
> > > 
> > > Oh, that's lost a possible instrumentation_begin() :/ But weirdly
> > > objtool didn't complain about that... Let me poke at that.
> 
> This merge window has been quite the trainwreck, hasn't it?  :-/
> 
> > Like so then...
> 
> Looks plausible, firing up some tests.

And it passes light rcutorture testing across all the scenarios.
So looks even more plausible.  ;-)

							Thanx, Paul

> > ---
> > Subject: rcu: Fixup noinstr warnings
> > 
> > A KCSAN build revealed we have explicit annoations through atomic_*()
> > usage, switch to arch_atomic_*() for the respective functions.
> > 
> > vmlinux.o: warning: objtool: rcu_nmi_exit()+0x4d: call to __kcsan_check_access() leaves .noinstr.text section
> > vmlinux.o: warning: objtool: rcu_dynticks_eqs_enter()+0x25: call to __kcsan_check_access() leaves .noinstr.text section
> > vmlinux.o: warning: objtool: rcu_nmi_enter()+0x4f: call to __kcsan_check_access() leaves .noinstr.text section
> > vmlinux.o: warning: objtool: rcu_dynticks_eqs_exit()+0x2a: call to __kcsan_check_access() leaves .noinstr.text section
> > vmlinux.o: warning: objtool: __rcu_is_watching()+0x25: call to __kcsan_check_access() leaves .noinstr.text section
> > 
> > Additionally, without the NOP in instrumentation_begin(), objtool would
> > not detect the lack of the 'else instrumentation_begin();' branch in
> > rcu_nmi_enter().
> > 
> > Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> > ---
> >  include/linux/compiler.h |    2 +-
> >  kernel/rcu/tree.c        |   33 +++++++++++++++++++++++++--------
> >  2 files changed, 26 insertions(+), 9 deletions(-)
> > 
> > --- a/include/linux/compiler.h
> > +++ b/include/linux/compiler.h
> > @@ -123,7 +123,7 @@ void ftrace_likely_update(struct ftrace_
> >  #ifdef CONFIG_DEBUG_ENTRY
> >  /* Begin/end of an instrumentation safe region */
> >  #define instrumentation_begin() ({					\
> > -	asm volatile("%c0:\n\t"						\
> > +	asm volatile("%c0: nop\n\t"						\
> >  		     ".pushsection .discard.instr_begin\n\t"		\
> >  		     ".long %c0b - .\n\t"				\
> >  		     ".popsection\n\t" : : "i" (__COUNTER__));		\
> > --- a/kernel/rcu/tree.c
> > +++ b/kernel/rcu/tree.c
> > @@ -250,7 +250,7 @@ static noinstr void rcu_dynticks_eqs_ent
> >  	 * next idle sojourn.
> >  	 */
> >  	rcu_dynticks_task_trace_enter();  // Before ->dynticks update!
> > -	seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> > +	seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> >  	// RCU is no longer watching.  Better be in extended quiescent state!
> >  	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
> >  		     (seq & RCU_DYNTICK_CTRL_CTR));
> > @@ -274,13 +274,13 @@ static noinstr void rcu_dynticks_eqs_exi
> >  	 * and we also must force ordering with the next RCU read-side
> >  	 * critical section.
> >  	 */
> > -	seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> > +	seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> >  	// RCU is now watching.  Better not be in an extended quiescent state!
> >  	rcu_dynticks_task_trace_exit();  // After ->dynticks update!
> >  	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
> >  		     !(seq & RCU_DYNTICK_CTRL_CTR));
> >  	if (seq & RCU_DYNTICK_CTRL_MASK) {
> > -		atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
> > +		arch_atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
> >  		smp_mb__after_atomic(); /* _exit after clearing mask. */
> >  	}
> >  }
> > @@ -313,7 +313,7 @@ static __always_inline bool rcu_dynticks
> >  {
> >  	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
> >  
> > -	return !(atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
> > +	return !(arch_atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
> >  }
> >  
> >  /*
> > @@ -633,6 +633,10 @@ static noinstr void rcu_eqs_enter(bool u
> >  	do_nocb_deferred_wakeup(rdp);
> >  	rcu_prepare_for_idle();
> >  	rcu_preempt_deferred_qs(current);
> > +
> > +	// instrumentation for the noinstr rcu_dynticks_eqs_enter()
> > +	instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks));
> > +
> >  	instrumentation_end();
> >  	WRITE_ONCE(rdp->dynticks_nesting, 0); /* Avoid irq-access tearing. */
> >  	// RCU is watching here ...
> > @@ -692,6 +696,7 @@ noinstr void rcu_nmi_exit(void)
> >  {
> >  	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
> >  
> > +	instrumentation_begin();
> >  	/*
> >  	 * Check for ->dynticks_nmi_nesting underflow and bad ->dynticks.
> >  	 * (We are exiting an NMI handler, so RCU better be paying attention
> > @@ -705,7 +710,6 @@ noinstr void rcu_nmi_exit(void)
> >  	 * leave it in non-RCU-idle state.
> >  	 */
> >  	if (rdp->dynticks_nmi_nesting != 1) {
> > -		instrumentation_begin();
> >  		trace_rcu_dyntick(TPS("--="), rdp->dynticks_nmi_nesting, rdp->dynticks_nmi_nesting - 2,
> >  				  atomic_read(&rdp->dynticks));
> >  		WRITE_ONCE(rdp->dynticks_nmi_nesting, /* No store tearing. */
> > @@ -714,13 +718,15 @@ noinstr void rcu_nmi_exit(void)
> >  		return;
> >  	}
> >  
> > -	instrumentation_begin();
> >  	/* This NMI interrupted an RCU-idle CPU, restore RCU-idleness. */
> >  	trace_rcu_dyntick(TPS("Startirq"), rdp->dynticks_nmi_nesting, 0, atomic_read(&rdp->dynticks));
> >  	WRITE_ONCE(rdp->dynticks_nmi_nesting, 0); /* Avoid store tearing. */
> >  
> >  	if (!in_nmi())
> >  		rcu_prepare_for_idle();
> > +
> > +	// instrumentation for the noinstr rcu_dynticks_eqs_enter()
> > +	instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks));
> >  	instrumentation_end();
> >  
> >  	// RCU is watching here ...
> > @@ -838,6 +844,10 @@ static void noinstr rcu_eqs_exit(bool us
> >  	rcu_dynticks_eqs_exit();
> >  	// ... but is watching here.
> >  	instrumentation_begin();
> > +
> > +	// instrumentation for the noinstr rcu_dynticks_eqs_exit()
> > +	instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks));
> > +
> >  	rcu_cleanup_after_idle();
> >  	trace_rcu_dyntick(TPS("End"), rdp->dynticks_nesting, 1, atomic_read(&rdp->dynticks));
> >  	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) && !user && !is_idle_task(current));
> > @@ -983,13 +993,20 @@ noinstr void rcu_nmi_enter(void)
> >  		if (!in_nmi())
> >  			rcu_cleanup_after_idle();
> >  
> > +		instrumentation_begin();
> > +		// instrumentation for the noinstr rcu_dynticks_curr_cpu_in_eqs()
> > +		instrument_atomic_read(&rdp->dynticks, sizeof(rdp->dynticks));
> > +		// instrumentation for the noinstr rcu_dynticks_eqs_exit()
> > +		instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks));
> > +
> >  		incby = 1;
> >  	} else if (!in_nmi()) {
> >  		instrumentation_begin();
> >  		rcu_irq_enter_check_tick();
> > -		instrumentation_end();
> > +	} else {
> > +		instrumentation_begin();
> >  	}
> > -	instrumentation_begin();
> > +
> >  	trace_rcu_dyntick(incby == 1 ? TPS("Endirq") : TPS("++="),
> >  			  rdp->dynticks_nmi_nesting,
> >  			  rdp->dynticks_nmi_nesting + incby, atomic_read(&rdp->dynticks));

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615200035.GA5052%40paulmck-ThinkPad-P72.
