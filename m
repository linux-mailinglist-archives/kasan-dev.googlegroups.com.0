Return-Path: <kasan-dev+bncBCV5TUXXRUIBBNFU373AKGQEK2MQFMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id C2A351ED4BD
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 19:13:26 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id o12sf1994181ilf.6
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 10:13:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591204405; cv=pass;
        d=google.com; s=arc-20160816;
        b=sGUBfyrNRx3fCnpux0Dv2EJtpIvmvcJCqukqw0AoynTIhD5AZ1D6uxyTLsF9IqceDQ
         oowXSxYnvBrjr9ob5/lFVsUmix8VYJ+T0Fc8apCDbBJb5W6H7jKs+JqaCMnP0qYaSiDS
         QNkdcTz2+YVbHAmBrknSUjtvx8xWf5iOpT1DmuEYpuEzOVt74BIzd8YuYlhS3m/SY7Ra
         9dKMCTjY8dlFEahuH7FM19at/sgAH55V5UT3ICz31bu9uL/EFp93Isa3dRpkLZCVs0rR
         V0rRJcIROfQSp6O+Z/GHVyqsDtAH0hHXyvzGMETErTAd3k1Vs4PbN1BjFdPrTB9NiJcu
         mfTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bnn8pkTXz/mXPys24nI52YCTeT9K5HEg0xyHH5KArf0=;
        b=DYfi+88TfLLUGRuH+wmgpj+o5dXLV3DnGgCIUpj3nPjQ0mZalZaMHpJaBbV5ZP+mHv
         3vC//qk/aSplXKDgfBhfD+RG2xG3J87DM7wfD798F8nfIvYI0MYAv1MaJRP19yz1I/to
         Fs/JVK2MlfQ/JLo2M3QqwmplfQBzIk5IvBYANdxGOMHIau61QWvGXmNgMkxe8Brs4rt7
         XRBq3QyFXsfbv+GxOwLWIrXaIYvFnptiepwslhVrcp+ZAqS7TZEKjAosIUDjd4bfu5PL
         Mhol13UpbDneuy1A3Nz7NXlK9BV/q5zQ7cFUp5ULOX+Aa0FggwvJDc5G1k7Je5idnnU7
         F8tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=gQYalxlX;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bnn8pkTXz/mXPys24nI52YCTeT9K5HEg0xyHH5KArf0=;
        b=LBqQWZ9yRxmxJ2v7ckLYLEofIhQnOLv7XseGdB/rTMGdprOJI/mS5yyvthICDB9/8v
         8pwf96uj44DA0BVjSIxsxgm+9dRONsQR7OmdpM/x8gcboxYZV4QSsxh3SPI4wL9VgUiO
         csXM9EDaWR5hqBb29WgYsOqUv5gAukdRr1ydr6uJW3XdCstSM5+BLVA6R4tmaHGKsVRh
         D/EYgl7vSaa/clBbDKtqjAIGQE8ztx4zjtgX6BtK9cr97bayliD36DG4XvZhe/WwoZIV
         75FbcnmvxTlE931sjbdHliLFA24sdYvX1ZF5DH+xoVYz6342ZtsKip+sT+ZFGNne5YXK
         nXDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bnn8pkTXz/mXPys24nI52YCTeT9K5HEg0xyHH5KArf0=;
        b=r2/+CzV1IkIm/JgU2hmHEXkWiSHzW/fVlrU/kTJ4djQCnatvKdlG9dkTfb3dysgZyx
         J6B5EkolHbH3R0yKdamAL5kbFf++nwBfAMaYyh1i/nL++r5AbPZZdRD/eIIwb7ckxxsP
         vsVYaUE55y16XOJOHRgMUa/U4xQ2Q7O/JMUO84fZnN5I9Ln47T2cuSOdSF+WKCmSLS+B
         RFBy4ZLoh+Nir9XsrUr+cYZs64F59Br5Dsp7q/fYxcICxmqqdLZZmkhqjy0NIvli+a9G
         +J6fmyMT6B+DfUapxjAJ7ENea3DEOY1G2//JyaDa3giGBHxeFMlEwSRSTAKfymkUh1Om
         nCQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5332oDJZsHShnV7TZspW+t1y1bQ249lJ9rUCWrV+Ma7z4jSgYLon
	iXWoBIx9mPxw4mqNx1FBfuY=
X-Google-Smtp-Source: ABdhPJwZymQASK4qgLNmQT/dpY4SOWYUJiB1PRl8BQiH8w8+LVboo9vhpCmHSk9TtQ7C56jMuSBB9w==
X-Received: by 2002:a02:ca18:: with SMTP id i24mr841223jak.70.1591204404824;
        Wed, 03 Jun 2020 10:13:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:af46:: with SMTP id n67ls827056ili.1.gmail; Wed, 03 Jun
 2020 10:13:24 -0700 (PDT)
X-Received: by 2002:a05:6e02:144:: with SMTP id j4mr507149ilr.214.1591204404480;
        Wed, 03 Jun 2020 10:13:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591204404; cv=none;
        d=google.com; s=arc-20160816;
        b=ORYjMixq1ZMFCChgOXeThhGmPX0k9jsZCZIeuEA+QYNbHHNgl81QGljFZRFmdBkq0z
         JKRaRpoOglDhQrbVyiUVu0CAyxXHyGYRCcqI+s7JFv2/IAS4uFnqGofk1RCKVH0DcjXg
         4RmhDse0CxAdZ2oh1ukS3aqJVd+Ge6cZtz1cd9ePh/4KHD/Hw+0AxQP+08vb17uAoIZL
         WjakId/CxFdGXLa6onUrGocXxp/z/26YZ+aAcc14rIoHecEq1Omelgg+VHObJz+VgNs7
         dNMFH7ZpwlZtTQz43mdeWBm3u3IWmPbqR2r7V2NGfJuFmoYk+W1O3sv79hmiwZRO9dDm
         MFXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=c0f9q7KFHLtUF97X4RtjWgNnpjq+ROwNailvfwoaSyI=;
        b=gO1yKs6qxM2BzrZROgoQw3hWydxFKv7U5+8dQXJoUO9a1ypUYOBkstOt5MzyGCB94q
         YsbcqANiCTFpQnWqXVqCFOW+gcwtYA4dUrGvXaYso9xTwgDnkEjGu5D2GPTJi7F9vbrP
         CNQV/5B/UrlGfNEb3+iXG5OrOGm2GIJRhCLd9oaC2xmtHprUehkbD/rxMi3L519t5FX5
         5o0IB2xUnz7jqb+hBUkVXd0QDSBAWHoIcoFHsTxCBGH7h8Dp9k9TzYdjlYu0Lmb1DOrK
         z87/1RLO0n+Pqu2GucUiTqiNODIAUkUmZxZ+Htch5X7g4huWinUWZtAE6qbtYq0fgvJd
         U7XQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=gQYalxlX;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id k16si34484iov.2.2020.06.03.10.13.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jun 2020 10:13:24 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgWx8-0001a4-TM; Wed, 03 Jun 2020 17:13:23 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 44AAC3006D0;
	Wed,  3 Jun 2020 19:13:20 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 3191120C23592; Wed,  3 Jun 2020 19:13:20 +0200 (CEST)
Date: Wed, 3 Jun 2020 19:13:20 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: tglx@linutronix.de, x86@kernel.org, elver@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200603171320.GE2570@hirez.programming.kicks-ass.net>
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
 <20200603164600.GQ29598@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200603164600.GQ29598@paulmck-ThinkPad-P72>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=gQYalxlX;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Jun 03, 2020 at 09:46:00AM -0700, Paul E. McKenney wrote:

> > --- a/kernel/rcu/tree.c
> > +++ b/kernel/rcu/tree.c
> > @@ -250,7 +250,7 @@ static noinstr void rcu_dynticks_eqs_ent
> >  	 * next idle sojourn.
> >  	 */
> >  	rcu_dynticks_task_trace_enter();  // Before ->dynticks update!
> > -	seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> > +	seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> 
> To preserve KCSAN's ability to see this, there would be something like
> instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks)) prior
> to the instrumentation_end() invoked before rcu_dynticks_eqs_enter()
> in each of rcu_eqs_enter() and rcu_nmi_exit(), correct?

Yes.

> >  	// RCU is no longer watching.  Better be in extended quiescent state!
> >  	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
> >  		     (seq & RCU_DYNTICK_CTRL_CTR));
> > @@ -274,13 +274,13 @@ static noinstr void rcu_dynticks_eqs_exi
> >  	 * and we also must force ordering with the next RCU read-side
> >  	 * critical section.
> >  	 */
> > -	seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> > +	seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> 
> And same here, but after the instrumentation_begin() following
> rcu_dynticks_eqs_exit() in both rcu_eqs_exit() and rcu_nmi_enter(),
> correct?

Yep.

> >  	// RCU is now watching.  Better not be in an extended quiescent state!
> >  	rcu_dynticks_task_trace_exit();  // After ->dynticks update!
> >  	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
> >  		     !(seq & RCU_DYNTICK_CTRL_CTR));
> >  	if (seq & RCU_DYNTICK_CTRL_MASK) {
> > -		atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
> > +		arch_atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
> 
> This one is gone in -rcu.

Good, because that would make things 'complicated' with the external
instrumentation call. And is actually the reason I didn't even attempt
it this time around.

> >  		smp_mb__after_atomic(); /* _exit after clearing mask. */
> >  	}
> >  }
> > @@ -313,7 +313,7 @@ static __always_inline bool rcu_dynticks
> >  {
> >  	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
> >  
> > -	return !(atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
> > +	return !(arch_atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);

The above is actually instrumented by KCSAN, due to arch_atomic_read()
being a READ_ONCE() and it now understanding volatile.

> Also instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks)) as
> follows:
> 
> o	rcu_nmi_exit(): After each following instrumentation_begin().

Yes

> o	In theory in rcu_irq_exit_preempt(), but as this generates code
> 	only in lockdep builds, it might not be worth worrying about.
> 
> o	Ditto for rcu_irq_exit_check_preempt().
> 
> o	Ditto for __rcu_irq_enter_check_tick().

Not these, afaict they're all the above arch_atomic_read(), which is
instrumented due to volatile in these cases.

> o	rcu_nmi_enter(): After each following instrumentation_begin().

Yes

> o	__rcu_is_watching() is itself noinstr:
> 
> 	o	idtentry_enter_cond_rcu(): After each following
> 		instrumentation_begin().
> 
> o	rcu_is_watching(): Either before or after the call to
> 	rcu_dynticks_curr_cpu_in_eqs().

Something like that yes.

> >  }
> >  
> >  /*
> > @@ -692,6 +692,7 @@ noinstr void rcu_nmi_exit(void)
> >  {
> >  	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
> >  
> > +	instrumentation_begin();
> >  	/*
> >  	 * Check for ->dynticks_nmi_nesting underflow and bad ->dynticks.
> >  	 * (We are exiting an NMI handler, so RCU better be paying attention
> > @@ -705,7 +706,6 @@ noinstr void rcu_nmi_exit(void)
> >  	 * leave it in non-RCU-idle state.
> >  	 */
> >  	if (rdp->dynticks_nmi_nesting != 1) {
> > -		instrumentation_begin();
> >  		trace_rcu_dyntick(TPS("--="), rdp->dynticks_nmi_nesting, rdp->dynticks_nmi_nesting - 2,
> >  				  atomic_read(&rdp->dynticks));
> >  		WRITE_ONCE(rdp->dynticks_nmi_nesting, /* No store tearing. */
> > @@ -714,7 +714,6 @@ noinstr void rcu_nmi_exit(void)
> >  		return;
> >  	}
> >  
> > -	instrumentation_begin();
> >  	/* This NMI interrupted an RCU-idle CPU, restore RCU-idleness. */
> >  	trace_rcu_dyntick(TPS("Startirq"), rdp->dynticks_nmi_nesting, 0, atomic_read(&rdp->dynticks));
> >  	WRITE_ONCE(rdp->dynticks_nmi_nesting, 0); /* Avoid store tearing. */
> 
> This one looks to be having no effect on instrumentation of atomics, but
> rather coalescing a pair of instrumentation_begin() into one.
> 
> Do I understand correctly?

Almost, it puts the WARN_ON_ONCE()s under instrumentation_begin() too,
and that makes a differnce, iirc it was the
rcu_dynticks_curr_cpu_in_eqs() call that stood out. But that could've
been before I switched it to arch_atomic_read(). In any case, I find
this form a lot clearer.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603171320.GE2570%40hirez.programming.kicks-ass.net.
