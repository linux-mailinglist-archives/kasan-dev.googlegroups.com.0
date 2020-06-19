Return-Path: <kasan-dev+bncBAABBHHSWT3QKGQEZ5FESNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 39101201DE9
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Jun 2020 00:15:58 +0200 (CEST)
Received: by mail-ua1-x93b.google.com with SMTP id s13sf3924025uar.17
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Jun 2020 15:15:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592604957; cv=pass;
        d=google.com; s=arc-20160816;
        b=zo9Nt5HxHTRNYeeXDhmZq7YtNxE3u2jTtmcZxXMg1QcYWygFhz/4HCUj9qS7bOfNZ6
         QouDxOf6ecMQUqRkGL5zhCzHyi2SlPGaAwGN0IlnjXOrro4ZO5VpFNLtu5ylVyE2rXQ5
         hbLh/AsQxVnTc7keSBJSCQal3XQo7+B/QqFY1GyCsOdN9q7NA6F0OSRtbdJsp81EUnjg
         pIR1pvb90x1yeRLQSfBxO7vwSVWNgMFc7i4Y+odxJ4QwVX60WHTKthO+SRo0QFIAXQV8
         XbYIsN0jFuugfixZMYPDLIpK+0atB2F+v4g8rKwu62UYR0Dd5tLr4saLPQ73HXJGhf/4
         IXMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=dFTWh7896AytdnjdkNo64jYcjgl4GPlnOYHg/GoH/rI=;
        b=CBskB/8B8NgQaVfU5lqkfxS9fcF+WoJQJQ4hAJoo4XMdrs8GDvef2jFkgCwkQ/qNhb
         sZkKogNzpiHOJRFP7AyM4im4HnPg0mykNYv2DbijAnh2lF+VJ3wKHRiXyE3E3sUkO8Tm
         71TS1ZvfGlZXAavARsxikt80uys5ZhCyMSCXD70J8ztYm9wzg05/UYNjkOZBsLPYKCkQ
         +vOr/Ohft1ed28vt/MFcBmMOgxTRAtQwBbR54WB5H4f0j6/aa6RxoRDt1QyE7HBD4rHX
         8jXuLmxl6u9fO2gu49W2GdSFgVbCk+6e+R+U+mrYIZAZTjiAI9xVHuqNz2bREJxgwUjm
         YJcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=emfRRWgr;
       spf=pass (google.com: domain of srs0=m+cg=aa=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=M+cG=AA=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dFTWh7896AytdnjdkNo64jYcjgl4GPlnOYHg/GoH/rI=;
        b=dBwyyZcDtLpzSxEZErG2PnlXUlqOHYGWm0XtOOPFCcK6IXgX+j+TF38In/ADif/oi2
         RkeBn2fQairV8L+Qd/EfYnpJGHqeospHPE7YbatL8CBW9Ysf7SnTOPS5BffY04OCXZu9
         1j+cw/0V15BY3k7zNs0v4lAzyLP5rJ8oYcvVcUw2dcB2kVY9MRlRvNUdCpSpX39cNH38
         y+PIHWoPvx2Q/EEGsPe/E0kf7q/xOcvzNTcaFTz8cPYT1on9J8ZYHRp/vlvjAdLf4UL3
         RZLBKEdOOZCutQkBQMePu4rlZnc2osB4mkZ+TBipkYXVXtxOFU/Y0I1Ekvffqdy+w5xV
         miwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dFTWh7896AytdnjdkNo64jYcjgl4GPlnOYHg/GoH/rI=;
        b=nJCYIKbz3UH86k8l5KU6syebE8kkItzzd4n2TD1JP3uEc6vTjTsq04uxEvofwvAFnz
         23oJN8Ef5+2rE2nJyrCKDNRG/8p5wsu4cUf1Tn26LbuPXf3Z+KnqR8UPPwyIDTda5R0B
         NLuj1An3upAuaoV/epoEJy2o/UtYN68hNVs6s7NOy03CHE7yawYvNYG72EfgyQkaWSvn
         dkNuAJVrvayuYo7OeTOHhY5jGoqTSTiAwjK1XkVInEfxWJVQldHuCe13bUN65i00y2/g
         xzisGvfE0CWhByUkwnWhovVx/mGr5PgYIcODRg0JIqEI8oe3fkj9IApsLtEhf+zAQQeh
         dp0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531gRzp4kSUizKXGSHRZvafPE5XE1706DpLz6AaXbR+isGCJ0fxU
	+FK7EdoCRmKe5gF6bYDHKbc=
X-Google-Smtp-Source: ABdhPJx4XfPOI60Lup/MA4+Dm683toZRGJShENWQG3uZ1vdYofJL7a4jAQrrObkGbe0ECtHqAutnGw==
X-Received: by 2002:a67:3311:: with SMTP id z17mr9479554vsz.52.1592604957075;
        Fri, 19 Jun 2020 15:15:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f993:: with SMTP id b19ls1340598vsq.5.gmail; Fri, 19 Jun
 2020 15:15:56 -0700 (PDT)
X-Received: by 2002:a67:fc0b:: with SMTP id o11mr8993763vsq.114.1592604956735;
        Fri, 19 Jun 2020 15:15:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592604956; cv=none;
        d=google.com; s=arc-20160816;
        b=iYNeXUhW5VGgrdsY+Oek3qnxQKEXymHfbscpqIswHSjKNVXhCXu9yE+0jEwArLVJx4
         HHDZLjwLVBnUgG/57IbY7XROOAGA99HEF/p3AzwhwXGN5N7HhahJJ6MCWKwHg4UZ50M9
         rzDFz4hydOGzqiJgYkyV51avEZUVh7jauXmh5UPSSxNHCTD8/uqvB3NvCJ4aiI+ECD6x
         AR2QDlpnWZNUqp6FOVq21bX6VJ4jagJ4M+GWR1xLosM1YDLN6GmHy5xAKaexwBdz/TQJ
         xzsCO+PCGjg1SOf77MV5aN8I90Xr06HeLQVQabORDPeqW0NzzDOJxkD6R+ZX7BvzVaRI
         8ZyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=DxOMilel3/edrWLLJd9hJLwFdh3qTeBKoB2vRZNsls8=;
        b=sx68Ppg5HfmXyUi9yoaIgRsHl9nzEf0k/cCmPddRnb4PVop3315n+GUULn4777ehhB
         PQfLDlVPTbe3nCpcoaq2PZxd3zSy3Et1yVvK8ZGLZUtp6spZbtZyawCtreqIpCYxufoR
         p4OBO5bqgXPHoyM5EindYKXyr+jTG15+TyqXeVn0xl2TUZYXSgIE8cQHaCK7xHXaEBfm
         +Jb/ap42FZle8su4leWzyDaX4L46pF2bkNI7AT5QOBzvGN97/fXFNqMJsJsLxwoVGc4E
         Nzv6SvBNcp1BwpLADgYTeaqqGSOlIMrF4kMETpdxSz+riWIShMpYNewFcgy9tZ3h+Cnh
         XCwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=emfRRWgr;
       spf=pass (google.com: domain of srs0=m+cg=aa=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=M+cG=AA=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f12si392717vsr.0.2020.06.19.15.15.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Jun 2020 15:15:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=m+cg=aa=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 8BBD622277;
	Fri, 19 Jun 2020 22:15:55 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 5CEF93522B50; Fri, 19 Jun 2020 15:15:55 -0700 (PDT)
Date: Fri, 19 Jun 2020 15:15:55 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: tglx@linutronix.de, x86@kernel.org, elver@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200619221555.GA12280@paulmck-ThinkPad-P72>
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
 header.i=@kernel.org header.s=default header.b=emfRRWgr;       spf=pass
 (google.com: domain of srs0=m+cg=aa=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=M+cG=AA=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

Just following up because I don't see this anywhere.  If I am supposed
to take this (which is more plausible now that v5.8-rc1 is out), please
let me know.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200619221555.GA12280%40paulmck-ThinkPad-P72.
