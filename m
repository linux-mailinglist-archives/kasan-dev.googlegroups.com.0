Return-Path: <kasan-dev+bncBAABBXWYT33QKGQEI4OUDKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DACB1F9E38
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 19:14:07 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id r5sf8335436ooq.18
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 10:14:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592241246; cv=pass;
        d=google.com; s=arc-20160816;
        b=VNhSWz4UsQ0rE+hfauXIXUgWV4CuXM5MwE8rJ/R+HDhfz5mj7Dm6hN6HBCRXrE2ilv
         K+pqRp6DM+80SYOY/XbfQHAw8tMPhDezTFeC6ZfqFzd6zlP/yUFO3MetEi5lwG+RsjoZ
         zyVXvayEaVf+3yqKFkZdIlKxpuSgzT3RWpdID9CUdXxjgbs5RMMp6S4364xEEc15/GmP
         KIb00Y63kbaxcfKw3ok+pIjlXeaIgoz0hIv2UgWMn64UQ3ZjxiVgwg7/AEFODp8CMeJN
         mfgRZeTMI2NOXmM3hAtlGajc4UVwEkQdMShtf4fgsjHkA6SN+EFq84j+Q3IyDQVbPUuN
         /FRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=wo3GuLZX5+3hh+vMfJSqXhhVj2+wkC6GvCFDLiiYMTA=;
        b=NDYnREAFBeEnbR5OeFiuW7jIvvwQ+k1XbqlGPNdXmER9Iivv24QtMdAKcG1cqlvqYu
         wCrXW8fsBnUkKVHGGS1WHtTMV9q6WAmyNfPA4ReqtV1dQHdFONEpEq183Brb3MgQ3UvE
         JMZU/ATGSpCNVdmL8eEEUhzY8OVvsbEEtzpZonXiO81p9R0k9IVuUTU2GYvn93GY3Swb
         Si+imOKG9noTL0xugWcYscRfARy/ZGUOEEyujtUGJBtlPw56dLTInqSxdxxpIdDc0hrm
         YjxIrM3KoEedeRNmsLHIWRLvIsb6b7dpZoiyFI1tC9gnBi3Q1Rs9+E+vpOHhxwvU8vv6
         P21w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=KhxUCVrD;
       spf=pass (google.com: domain of srs0=xl4n=74=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xl4N=74=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wo3GuLZX5+3hh+vMfJSqXhhVj2+wkC6GvCFDLiiYMTA=;
        b=QaiQViM3qkP1LGo1pdYKS9LSUQY9yEYxZFiHaR7MwIX+2sEtSjncFr0zlpNnOgFFeD
         ixWnjRvY2+dwyjvx05efO+dhFIlPlUVbBGF81uPS1heVxbvakuKuinbE1bVT6sem1y9l
         oQWsymU/fSbDjLM2ArndA9IxLLHfZg5IyCIkOE7fMGg/FWuLcIlKpEgzwk5zHqOKUjC/
         qrv3IS8YtKdAm9iYuvNl++pGZ5izge3nG9OgjuxOCDYLHHl0C+BvTO7YoMBKUiENoqzM
         fTcUFvvEkIU5G1lGNHS0VEdft/SRl5KmIZZtz3o30ON4sXwwucInZDH96goHO43n0ZEH
         8Ecw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wo3GuLZX5+3hh+vMfJSqXhhVj2+wkC6GvCFDLiiYMTA=;
        b=KPYv+/viRDan5S1xCArBXCOCEvyW0pCUsfLH+Zl7kXw9rL2KqI4w1CUnqWAb69/H3g
         Zt8GfT5UtnyH64QMZrgqOc1Hri1Kae/HzWTt0Cl/jfRI6r91G03LLhc+g6RDaIdhETjG
         v5NJXXWytRFxi1+NxVtg+Gh+CIVJGFlD4s3qR8Qk8YvfvYKv2fO+bM4Sug2B8A4aFJHu
         9svZMBFBAT8i7WFhsPKMlN39wx4tnvAZNL2gx+T+u5Hbvn6YSbQfZj/ci5UM4F6rEnW1
         Hr2zsmJESXbLNoEFF1eIweqdsbyIAoNwp2s38tOvp57V6fRDALRQkGGbsnRNSB7x85BT
         3OHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530fsr00x0QRuLXe/fqLgf6hwT4Q04UCbU0aDEnHRssS9XvF3wM6
	JSka3pXWMv36wH+1KEFirSY=
X-Google-Smtp-Source: ABdhPJx/x/B2rU8bRqTPIsKDJbwOUFMQtPNqXNUzAe0YF4DBo00vejMtCXbm8JMm/2g/VbjAfq5d7Q==
X-Received: by 2002:aca:5152:: with SMTP id f79mr289380oib.146.1592241246186;
        Mon, 15 Jun 2020 10:14:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:a401:: with SMTP id v1ls239470ool.8.gmail; Mon, 15 Jun
 2020 10:14:05 -0700 (PDT)
X-Received: by 2002:a4a:7ac2:: with SMTP id a185mr21982646ooc.84.1592241245852;
        Mon, 15 Jun 2020 10:14:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592241245; cv=none;
        d=google.com; s=arc-20160816;
        b=tZdO8lYvp0LcZt9ydkd0Y86Rt+e62kFT46phJTLy0RfnyMs3+DCkd4yrUm/7wSGu3j
         SsGKgs509BiEdkL38CVFVc+oHzaCceyBgUnx7Z3LMZ3WCpVKGeTEsWK4a7PuD0J00Cf+
         GwbuaC10Pw0wi/peI28KDRz+WqoywHTy2GmZ2uBccCmUtwkUgHFPhEgqEEInqzvq1bl8
         iqpgeDwP1O9Hf2BsfwakcdDoWI9c9K50dwyUX/HJZWBN0J+RZLvh0cLWuB8E2cdeDcvl
         rfN5tGY4h3GujrxZeRamJAlNa2TpXNbQ+vp7r5cWmYb2McjgHdcAogNzDWjf4Yt8BCJX
         dNTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=StsWHch+AIf69+6f8JZgiWWERBCOhzD7SQd0aMfl+54=;
        b=yoHaKz/Omo5bg/Lm3fqu/xoDb3WC0xIKC+JpKgJIikne+aph2IdL3BqMs3j376aRSG
         UyaDrES+jGy4bnUVnZSGUYwPo6PPpf17l+2oN5nU9sJdZ0mxgUvBkhE0s19sEd+cM38a
         YHfuv7qX0pOql3ISnPBv8Ylrep0TIu1CEgQ0kX7VPoUzGmAob9ThnBm6cpY0fFe2vV4w
         SJSLEu8GodoB9fIcPzg+TBaWW6kpOYGP2AYHrJCzM2/l6xBDe1Abk48JBMN4GJTm6CKZ
         8nStsRIaMcV/CjMNJVi1Nq3QOAwVENxoDO5tUNikRGWa7PGabTwD8gb419Oms5lOnN+v
         yevw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=KhxUCVrD;
       spf=pass (google.com: domain of srs0=xl4n=74=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xl4N=74=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m26si87411otn.5.2020.06.15.10.14.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Jun 2020 10:14:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xl4n=74=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id EF219207DA;
	Mon, 15 Jun 2020 17:14:04 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id D737935218F0; Mon, 15 Jun 2020 10:14:04 -0700 (PDT)
Date: Mon, 15 Jun 2020 10:14:04 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: tglx@linutronix.de, x86@kernel.org, elver@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200615171404.GI2723@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
 <20200615154905.GZ2531@hirez.programming.kicks-ass.net>
 <20200615155513.GG2554@hirez.programming.kicks-ass.net>
 <20200615162427.GI2554@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200615162427.GI2554@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=KhxUCVrD;       spf=pass
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

On Mon, Jun 15, 2020 at 06:24:27PM +0200, Peter Zijlstra wrote:
> On Mon, Jun 15, 2020 at 05:55:13PM +0200, Peter Zijlstra wrote:
> > On Mon, Jun 15, 2020 at 05:49:05PM +0200, Peter Zijlstra wrote:
> > > @@ -983,13 +993,17 @@ noinstr void rcu_nmi_enter(void)
> > >  		if (!in_nmi())
> > >  			rcu_cleanup_after_idle();
> > >  
> > > +		instrumentation_begin();
> > > +		// instrumentation for the noinstr rcu_dynticks_curr_cpu_in_eqs()
> > > +		instrument_atomic_read(&rdp->dynticks, sizeof(rdp->dynticks));
> > > +		// instrumentation for the noinstr rcu_dynticks_eqs_exit()
> > > +		instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks));
> > > +
> > >  		incby = 1;
> > >  	} else if (!in_nmi()) {
> > >  		instrumentation_begin();
> > >  		rcu_irq_enter_check_tick();
> > > -		instrumentation_end();
> > >  	}
> > > -	instrumentation_begin();
> > >  	trace_rcu_dyntick(incby == 1 ? TPS("Endirq") : TPS("++="),
> > >  			  rdp->dynticks_nmi_nesting,
> > >  			  rdp->dynticks_nmi_nesting + incby, atomic_read(&rdp->dynticks));
> > 
> > Oh, that's lost a possible instrumentation_begin() :/ But weirdly
> > objtool didn't complain about that... Let me poke at that.

This merge window has been quite the trainwreck, hasn't it?  :-/

> Like so then...

Looks plausible, firing up some tests.

							Thanx, Paul

> ---
> Subject: rcu: Fixup noinstr warnings
> 
> A KCSAN build revealed we have explicit annoations through atomic_*()
> usage, switch to arch_atomic_*() for the respective functions.
> 
> vmlinux.o: warning: objtool: rcu_nmi_exit()+0x4d: call to __kcsan_check_access() leaves .noinstr.text section
> vmlinux.o: warning: objtool: rcu_dynticks_eqs_enter()+0x25: call to __kcsan_check_access() leaves .noinstr.text section
> vmlinux.o: warning: objtool: rcu_nmi_enter()+0x4f: call to __kcsan_check_access() leaves .noinstr.text section
> vmlinux.o: warning: objtool: rcu_dynticks_eqs_exit()+0x2a: call to __kcsan_check_access() leaves .noinstr.text section
> vmlinux.o: warning: objtool: __rcu_is_watching()+0x25: call to __kcsan_check_access() leaves .noinstr.text section
> 
> Additionally, without the NOP in instrumentation_begin(), objtool would
> not detect the lack of the 'else instrumentation_begin();' branch in
> rcu_nmi_enter().
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> ---
>  include/linux/compiler.h |    2 +-
>  kernel/rcu/tree.c        |   33 +++++++++++++++++++++++++--------
>  2 files changed, 26 insertions(+), 9 deletions(-)
> 
> --- a/include/linux/compiler.h
> +++ b/include/linux/compiler.h
> @@ -123,7 +123,7 @@ void ftrace_likely_update(struct ftrace_
>  #ifdef CONFIG_DEBUG_ENTRY
>  /* Begin/end of an instrumentation safe region */
>  #define instrumentation_begin() ({					\
> -	asm volatile("%c0:\n\t"						\
> +	asm volatile("%c0: nop\n\t"						\
>  		     ".pushsection .discard.instr_begin\n\t"		\
>  		     ".long %c0b - .\n\t"				\
>  		     ".popsection\n\t" : : "i" (__COUNTER__));		\
> --- a/kernel/rcu/tree.c
> +++ b/kernel/rcu/tree.c
> @@ -250,7 +250,7 @@ static noinstr void rcu_dynticks_eqs_ent
>  	 * next idle sojourn.
>  	 */
>  	rcu_dynticks_task_trace_enter();  // Before ->dynticks update!
> -	seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> +	seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
>  	// RCU is no longer watching.  Better be in extended quiescent state!
>  	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
>  		     (seq & RCU_DYNTICK_CTRL_CTR));
> @@ -274,13 +274,13 @@ static noinstr void rcu_dynticks_eqs_exi
>  	 * and we also must force ordering with the next RCU read-side
>  	 * critical section.
>  	 */
> -	seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> +	seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
>  	// RCU is now watching.  Better not be in an extended quiescent state!
>  	rcu_dynticks_task_trace_exit();  // After ->dynticks update!
>  	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
>  		     !(seq & RCU_DYNTICK_CTRL_CTR));
>  	if (seq & RCU_DYNTICK_CTRL_MASK) {
> -		atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
> +		arch_atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
>  		smp_mb__after_atomic(); /* _exit after clearing mask. */
>  	}
>  }
> @@ -313,7 +313,7 @@ static __always_inline bool rcu_dynticks
>  {
>  	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
>  
> -	return !(atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
> +	return !(arch_atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
>  }
>  
>  /*
> @@ -633,6 +633,10 @@ static noinstr void rcu_eqs_enter(bool u
>  	do_nocb_deferred_wakeup(rdp);
>  	rcu_prepare_for_idle();
>  	rcu_preempt_deferred_qs(current);
> +
> +	// instrumentation for the noinstr rcu_dynticks_eqs_enter()
> +	instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks));
> +
>  	instrumentation_end();
>  	WRITE_ONCE(rdp->dynticks_nesting, 0); /* Avoid irq-access tearing. */
>  	// RCU is watching here ...
> @@ -692,6 +696,7 @@ noinstr void rcu_nmi_exit(void)
>  {
>  	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
>  
> +	instrumentation_begin();
>  	/*
>  	 * Check for ->dynticks_nmi_nesting underflow and bad ->dynticks.
>  	 * (We are exiting an NMI handler, so RCU better be paying attention
> @@ -705,7 +710,6 @@ noinstr void rcu_nmi_exit(void)
>  	 * leave it in non-RCU-idle state.
>  	 */
>  	if (rdp->dynticks_nmi_nesting != 1) {
> -		instrumentation_begin();
>  		trace_rcu_dyntick(TPS("--="), rdp->dynticks_nmi_nesting, rdp->dynticks_nmi_nesting - 2,
>  				  atomic_read(&rdp->dynticks));
>  		WRITE_ONCE(rdp->dynticks_nmi_nesting, /* No store tearing. */
> @@ -714,13 +718,15 @@ noinstr void rcu_nmi_exit(void)
>  		return;
>  	}
>  
> -	instrumentation_begin();
>  	/* This NMI interrupted an RCU-idle CPU, restore RCU-idleness. */
>  	trace_rcu_dyntick(TPS("Startirq"), rdp->dynticks_nmi_nesting, 0, atomic_read(&rdp->dynticks));
>  	WRITE_ONCE(rdp->dynticks_nmi_nesting, 0); /* Avoid store tearing. */
>  
>  	if (!in_nmi())
>  		rcu_prepare_for_idle();
> +
> +	// instrumentation for the noinstr rcu_dynticks_eqs_enter()
> +	instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks));
>  	instrumentation_end();
>  
>  	// RCU is watching here ...
> @@ -838,6 +844,10 @@ static void noinstr rcu_eqs_exit(bool us
>  	rcu_dynticks_eqs_exit();
>  	// ... but is watching here.
>  	instrumentation_begin();
> +
> +	// instrumentation for the noinstr rcu_dynticks_eqs_exit()
> +	instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks));
> +
>  	rcu_cleanup_after_idle();
>  	trace_rcu_dyntick(TPS("End"), rdp->dynticks_nesting, 1, atomic_read(&rdp->dynticks));
>  	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) && !user && !is_idle_task(current));
> @@ -983,13 +993,20 @@ noinstr void rcu_nmi_enter(void)
>  		if (!in_nmi())
>  			rcu_cleanup_after_idle();
>  
> +		instrumentation_begin();
> +		// instrumentation for the noinstr rcu_dynticks_curr_cpu_in_eqs()
> +		instrument_atomic_read(&rdp->dynticks, sizeof(rdp->dynticks));
> +		// instrumentation for the noinstr rcu_dynticks_eqs_exit()
> +		instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks));
> +
>  		incby = 1;
>  	} else if (!in_nmi()) {
>  		instrumentation_begin();
>  		rcu_irq_enter_check_tick();
> -		instrumentation_end();
> +	} else {
> +		instrumentation_begin();
>  	}
> -	instrumentation_begin();
> +
>  	trace_rcu_dyntick(incby == 1 ? TPS("Endirq") : TPS("++="),
>  			  rdp->dynticks_nmi_nesting,
>  			  rdp->dynticks_nmi_nesting + incby, atomic_read(&rdp->dynticks));

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615171404.GI2723%40paulmck-ThinkPad-P72.
