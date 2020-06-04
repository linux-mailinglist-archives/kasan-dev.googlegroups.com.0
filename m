Return-Path: <kasan-dev+bncBAABBMWX4H3AKGQEQW7HYNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id C2D721EDBB7
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 05:34:11 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9sf3602076pll.12
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 20:34:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591241650; cv=pass;
        d=google.com; s=arc-20160816;
        b=fvn3Ukwvd5u5hkaXIxTr176Agukaj5xHoaltxmL887kP3M503M9gnExSivECDb3FA2
         gXNVPuXMW1LubnynBiQvT3lUxpUDoBsbyLvI7JQxT7AxDAOJPmtq0l1fB0h9NeWB3P9T
         xrong/v/+wYDyx5LARG6eq6PqqsHRKDTyyGH7D4nn+B04XexK1gVSz6XxfyMqWGFx+5Z
         IPERE37/Am+4E4lxKYNnq/qiO0FNeLQGf0hMtUAufkfSQ3nvANoiJlHue/Nfm4TtKqvE
         Kbz+2xSs70RoDd+N2Y+T7x2HelQBXatBsNQUyMVGceK4JRgnWn8S3ns49HfXTQmWfQD8
         X5TQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=hhK89qIB8SFXEkCTZzWdmUgXD/4qXj0UjTta26DbJt0=;
        b=cECJM1hThL1SmCnTrKibcT/ppzH28WxTlizEmhQR0bIL5WuQdrzx4FLSqMLEuG1WRe
         kKrolQkSDa+/kr7jMbggfsDHCGVYOAfrrYNKLiEVjuu8dc62+vsf8LUAEdra99lZc+r5
         R+WMMRHAXTuSliAih2VTCL6Emb2SkoQbSzngJ4ITwqlfN91Hc96y8FU1ZBjQW4me6qnf
         OXemea7Xfj7W7ENnrmyf/X6SvH5QCUSzRarpdSSuYz+8369llMkbQPKc/LeMq09u+LLi
         SiMVg1qQ9KqGsozbhukcU5fCVxAI3uLjIx70OY+M0VNBR5+z/VyTWw+Ot8laNIhhpChX
         Lajw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=F8kKGoeQ;
       spf=pass (google.com: domain of srs0=yzmc=7r=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YzMc=7R=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hhK89qIB8SFXEkCTZzWdmUgXD/4qXj0UjTta26DbJt0=;
        b=kydmZMIHnkpPRRrFg9GnsbaiRvTiUvFj4G+jyhjqX8tSpfaiQtEs55y0KEM8J3clzH
         y7R83fZZy4V8IZs8otk2AWhoEyMdCmHtpuDNR2YzdyCW9N2PTv7Xf0Z0OUOzTpF5UDDj
         InvHaFSvfuTsWhL0svfSmsKy30MGJ/2oBObfasNTbqHSvvhbB42ZJrgc+yWXznmYsrYV
         yYbQQksr9dsH2SwXOvZn0UxzGyUYLlrld05YBLD2ReBAfhi/zOHFO+yH83LxzdoITgIB
         F74/Iw6IiAw6ROaohgGOEmfui06lRPfSrbQyQb35VQzyzqBbXEcZpdbAsfNyDYhP941i
         IwmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hhK89qIB8SFXEkCTZzWdmUgXD/4qXj0UjTta26DbJt0=;
        b=aV39dLa+1GLVlsS3YmATDkrEG/VvLW08pWYWKOGVAvBzwGf4pCSBxCdIjAgreK2KMv
         EgIAZG3UcnUR2LwqbzrqwvA1MXfC4/35Yv34JOOmqnw3CF8M7OaKkdyiJNzSSHRAJDop
         8gqrv9gdqBrQFtsWZY7RsxVx1x5sjgjrmG/Kd5lb7e4L1Ie12afx3a5BXZ94RFzRy3FR
         uPHHV/OUczQxRjK1s6qtaZSj+RHrpdpKFdx7u/1CmvIp29zn6eB8XPqAAD04v0OoeanR
         s/Q6YbFfu3J4xqd2Z181HSYd8+gHwdvR7nxnQSpJVr4+5tsT376lbEgYiRltS85Hao76
         OKTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5322gAuMNY67b/ny66MZf46Tpm3CEt0VKkmM1E3yEIKucgrkxaXc
	XnFQVssw4Ge2IyF8Dy4GAZA=
X-Google-Smtp-Source: ABdhPJzxza3Kr1GgZmyqUJGOtu/2CdvwUPy8LWkADfJsUPsQxfryD8wmE6dhqJ16goboe4enlEvrNg==
X-Received: by 2002:a63:63c4:: with SMTP id x187mr2637025pgb.112.1591241650546;
        Wed, 03 Jun 2020 20:34:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:70c3:: with SMTP id l3ls1602786plt.0.gmail; Wed, 03
 Jun 2020 20:34:10 -0700 (PDT)
X-Received: by 2002:a17:90a:ff0e:: with SMTP id ce14mr3652491pjb.65.1591241650161;
        Wed, 03 Jun 2020 20:34:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591241650; cv=none;
        d=google.com; s=arc-20160816;
        b=rnLwHfKi/qKer6zuwrH5VT1Am2Atj8w8vSLAyimV21saHuY8e2ZMfQZIsiDZeQq8Er
         oTjnhAi+kJYvZ5nsfvH9RNjPucTbgqhYoSTmgHyCT5hRDWhLpkcq4+giaZ+w4PhKrxSZ
         GM+BXhT33K7YA3IkBKyNsECPYBcTR4c3/DfsrZPALGksn+F0a81QZlvvGes5dVIbuAB4
         tobCrfypxgANAAEGTr8GROmrmvxn0nOfvKpB6JbYMeki9ihECaqJ8T7q8MBL+akg5LRh
         pEQC7eJqDW5cX0EbUl5/H+uWZnQmSdg0EcZHJHeHTgESZR5CiAKq1u16REzDj9/jdrbG
         ZZ+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=cYni1uVqqfou0Wg6BQUYul0ljOulcNsm9hKc69fYIKY=;
        b=GUMJTRf3mAWBLZNuocAGgdom5ezgsxTZcYvxKIOtlcCvgBVydmr5R9z9atJV2aeAdS
         e1HLOMlW1+B2cei/VRcTknnrbQbB8nFXRlQOJKdzfTo4YFJdFTQnMI5wEMjiGtTwxbac
         inXMbQLR2v6YwKVXrLVuT8odJhO2VD7W9dsFYHSP0OKEx7rwc1q6xZ/4AoD9Lc4JACVz
         t1XeIimi8c6vu6FO7QJzHuBPZSaTM/9safGGmt/lPlzQp09U7ddjCB2r/p8qlpdt83zT
         gE2xBL5E0a+Pm/LM+AB1igZGI6ueewdVjpwJWKa8K/IS2yxNaShrFbfnCorBrrTIsEdo
         XOiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=F8kKGoeQ;
       spf=pass (google.com: domain of srs0=yzmc=7r=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YzMc=7R=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id mt8si915804pjb.2.2020.06.03.20.34.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Jun 2020 20:34:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=yzmc=7r=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id CE42C206DC;
	Thu,  4 Jun 2020 03:34:09 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id B2EDE3522946; Wed,  3 Jun 2020 20:34:09 -0700 (PDT)
Date: Wed, 3 Jun 2020 20:34:09 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: tglx@linutronix.de, x86@kernel.org, elver@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200604033409.GX29598@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
 <20200603164600.GQ29598@paulmck-ThinkPad-P72>
 <20200603171320.GE2570@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200603171320.GE2570@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=F8kKGoeQ;       spf=pass
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

On Wed, Jun 03, 2020 at 07:13:20PM +0200, Peter Zijlstra wrote:
> On Wed, Jun 03, 2020 at 09:46:00AM -0700, Paul E. McKenney wrote:
> 
> > > --- a/kernel/rcu/tree.c
> > > +++ b/kernel/rcu/tree.c
> > > @@ -250,7 +250,7 @@ static noinstr void rcu_dynticks_eqs_ent
> > >  	 * next idle sojourn.
> > >  	 */
> > >  	rcu_dynticks_task_trace_enter();  // Before ->dynticks update!
> > > -	seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> > > +	seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> > 
> > To preserve KCSAN's ability to see this, there would be something like
> > instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks)) prior
> > to the instrumentation_end() invoked before rcu_dynticks_eqs_enter()
> > in each of rcu_eqs_enter() and rcu_nmi_exit(), correct?
> 
> Yes.
> 
> > >  	// RCU is no longer watching.  Better be in extended quiescent state!
> > >  	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
> > >  		     (seq & RCU_DYNTICK_CTRL_CTR));
> > > @@ -274,13 +274,13 @@ static noinstr void rcu_dynticks_eqs_exi
> > >  	 * and we also must force ordering with the next RCU read-side
> > >  	 * critical section.
> > >  	 */
> > > -	seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> > > +	seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> > 
> > And same here, but after the instrumentation_begin() following
> > rcu_dynticks_eqs_exit() in both rcu_eqs_exit() and rcu_nmi_enter(),
> > correct?
> 
> Yep.
> 
> > >  	// RCU is now watching.  Better not be in an extended quiescent state!
> > >  	rcu_dynticks_task_trace_exit();  // After ->dynticks update!
> > >  	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
> > >  		     !(seq & RCU_DYNTICK_CTRL_CTR));
> > >  	if (seq & RCU_DYNTICK_CTRL_MASK) {
> > > -		atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
> > > +		arch_atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
> > 
> > This one is gone in -rcu.
> 
> Good, because that would make things 'complicated' with the external
> instrumentation call. And is actually the reason I didn't even attempt
> it this time around.
> 
> > >  		smp_mb__after_atomic(); /* _exit after clearing mask. */
> > >  	}
> > >  }
> > > @@ -313,7 +313,7 @@ static __always_inline bool rcu_dynticks
> > >  {
> > >  	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
> > >  
> > > -	return !(atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
> > > +	return !(arch_atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
> 
> The above is actually instrumented by KCSAN, due to arch_atomic_read()
> being a READ_ONCE() and it now understanding volatile.
> 
> > Also instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks)) as

Right, this should instead be instrument_read(...).

Though if KCSAN is unconditionally instrumenting volatile, how does
this help?  Or does KCSAN's instrumentation of volatile somehow avoid
causing trouble?

> > follows:
> > 
> > o	rcu_nmi_exit(): After each following instrumentation_begin().
> 
> Yes
> 
> > o	In theory in rcu_irq_exit_preempt(), but as this generates code
> > 	only in lockdep builds, it might not be worth worrying about.
> > 
> > o	Ditto for rcu_irq_exit_check_preempt().
> > 
> > o	Ditto for __rcu_irq_enter_check_tick().
> 
> Not these, afaict they're all the above arch_atomic_read(), which is
> instrumented due to volatile in these cases.
> 
> > o	rcu_nmi_enter(): After each following instrumentation_begin().
> 
> Yes
> 
> > o	__rcu_is_watching() is itself noinstr:
> > 
> > 	o	idtentry_enter_cond_rcu(): After each following
> > 		instrumentation_begin().
> > 
> > o	rcu_is_watching(): Either before or after the call to
> > 	rcu_dynticks_curr_cpu_in_eqs().
> 
> Something like that yes.
> 
> > >  }
> > >  
> > >  /*
> > > @@ -692,6 +692,7 @@ noinstr void rcu_nmi_exit(void)
> > >  {
> > >  	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
> > >  
> > > +	instrumentation_begin();
> > >  	/*
> > >  	 * Check for ->dynticks_nmi_nesting underflow and bad ->dynticks.
> > >  	 * (We are exiting an NMI handler, so RCU better be paying attention
> > > @@ -705,7 +706,6 @@ noinstr void rcu_nmi_exit(void)
> > >  	 * leave it in non-RCU-idle state.
> > >  	 */
> > >  	if (rdp->dynticks_nmi_nesting != 1) {
> > > -		instrumentation_begin();
> > >  		trace_rcu_dyntick(TPS("--="), rdp->dynticks_nmi_nesting, rdp->dynticks_nmi_nesting - 2,
> > >  				  atomic_read(&rdp->dynticks));
> > >  		WRITE_ONCE(rdp->dynticks_nmi_nesting, /* No store tearing. */
> > > @@ -714,7 +714,6 @@ noinstr void rcu_nmi_exit(void)
> > >  		return;
> > >  	}
> > >  
> > > -	instrumentation_begin();
> > >  	/* This NMI interrupted an RCU-idle CPU, restore RCU-idleness. */
> > >  	trace_rcu_dyntick(TPS("Startirq"), rdp->dynticks_nmi_nesting, 0, atomic_read(&rdp->dynticks));
> > >  	WRITE_ONCE(rdp->dynticks_nmi_nesting, 0); /* Avoid store tearing. */
> > 
> > This one looks to be having no effect on instrumentation of atomics, but
> > rather coalescing a pair of instrumentation_begin() into one.
> > 
> > Do I understand correctly?
> 
> Almost, it puts the WARN_ON_ONCE()s under instrumentation_begin() too,
> and that makes a differnce, iirc it was the
> rcu_dynticks_curr_cpu_in_eqs() call that stood out. But that could've
> been before I switched it to arch_atomic_read(). In any case, I find
> this form a lot clearer.

Got it, thank you.

						Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604033409.GX29598%40paulmck-ThinkPad-P72.
