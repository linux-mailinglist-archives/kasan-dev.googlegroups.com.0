Return-Path: <kasan-dev+bncBAABBC4UW34QKGQEAXZOU2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6110B23F1A6
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Aug 2020 19:06:21 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id u3sf1908614plq.1
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Aug 2020 10:06:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596819980; cv=pass;
        d=google.com; s=arc-20160816;
        b=mZiQ9VNSsDuIYDeCC3+2g8kfxzT2miq7HvJgG+MOuZRhEdyTmCxYaRqISqvJa0KMvR
         qhESpBfmPTF2qkdZWTQGNSRvYc4gNQAVnluT08ikGQyDL7HFjAsNAq8rW4UKvX/faz+S
         IfO0TYU2eAZFs83C3uWZt/QdpheufEt7ClzXHTD1KRMJH9oTloN6RzrRVyHf1Rp4LId0
         vfjVkWf2hQAmZx5R1+C1qKRjw0QyZEyCqVPB1Fj5+bB+gvud/3VZmxFmTYDjY8q59wPR
         J2accw7LzREZORUI0lA7/DSqEC24GeQpahXKH4IXgxYeLuDxPSq7JFhekdSnofOmr2vV
         dT3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=2kF9mrJXkWlAVFd3Yz37Xlo9afoI8wT6giuPAbrkKlk=;
        b=JkD2PSUTFDASlIo830b+vLa928UiJta7DkHW7dXCP7wUsQMvkBoJMdV80K7cuMwjxl
         qmSAilhUxeFdirhjZbaD2c7zIgkgMf1+Ln2ET8BoyawUxCx0OzAQ06korU1vEcHSa31x
         UVKqxA+gfB5Fd5ZMSAf4NGFH/Z6vi6UCcHHfXVRCEo2Xrmb9fUfqK6CMaFM9PSKZWW5/
         MPiJ4vJJugfL8mOn53DtIol1PxtlYSRJX+6FvX2AAqz8Y6KqMJFJ/NG6oDeyZ7SrBS+7
         i9OecacZKAr4ShTS/VWBpznscyZuHXSp3q7hBZOgBPr5D9hs21cbLA5015ceIMwpZP7Q
         Yd9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ALbV6Xti;
       spf=pass (google.com: domain of srs0=qp6m=br=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=qp6M=BR=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2kF9mrJXkWlAVFd3Yz37Xlo9afoI8wT6giuPAbrkKlk=;
        b=B/mvHQqkT5rHl5B+OgXKqmO3awwA5MuSDyqmJOMb9cukueQV40DXIt9N0THGYPgrVm
         LmTuW66UQ27MrWaYfTjFfRZkEsxZqQICiVkVgkTtj5FN4BsLVnVlIBPseWmqnSS6XocC
         apijWaz6m7RcAv2zV36xagVJcytwzSTruXtQ5eI2GpN7DOHT6RgyehWbbH4HPBS5wfgn
         VTpc53MdBbEyfr3OxD1SNiEBBLQn7qaPrdS7ipiQ4bliUt2NaRurlrgH6FnqBa0eNL6Z
         yEUVWI3+nBMmbKbDrJ6qH5X8AdAwJXEGIyHPq1KKjBJWFpZyOtLks43unXqbraOSnGSw
         Qcig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2kF9mrJXkWlAVFd3Yz37Xlo9afoI8wT6giuPAbrkKlk=;
        b=pu9Km9iraGVGU0nnRkzx4zeO1mr8WCbBHHzAqx2FEfZun1ks+mJbIUz8WlRybIlWKG
         y4Aa/hODYLrESQiWwIRmaEnTn9iXNhfcH0QLJAaECnc/yZx+cUYxZwwLFhKzWATB9Jaa
         iRdx53iwlt7EwPbhOETLT3RdojxXdXiw0Dhjuduh9St/xfhwbdiuhx1f7XrpdTPw/8ZO
         fLhUbh4MO1QeWD7xh20z6AOGnm1DxMp3g2iWMsYThte5eCfyRAA1EYrs/hFhCoaqhmBF
         o+n7MYaepjZT8NEXZfMvBNhPmpz716p8QsRdLuV1igUPsp0WfWDucK2xcOvf7/hcoX8Z
         kpLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531naF7JZu357u+L1/SfUsz5zE+/iGP0RD9LPh7D//LdyGoLvPAv
	Lu7mXnnV0F1cL+L17yimV88=
X-Google-Smtp-Source: ABdhPJwz0R/M/0n6j7QXzcTurVSJJ7Cppd6hBAlcUrMn4l8yn4kiXbAn/SAn762usFgptujymrbKvA==
X-Received: by 2002:a63:6fcd:: with SMTP id k196mr13055892pgc.251.1596819979865;
        Fri, 07 Aug 2020 10:06:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:130a:: with SMTP id h10ls4044784pja.0.canary-gmail;
 Fri, 07 Aug 2020 10:06:19 -0700 (PDT)
X-Received: by 2002:a17:902:7144:: with SMTP id u4mr519002plm.236.1596819979475;
        Fri, 07 Aug 2020 10:06:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596819979; cv=none;
        d=google.com; s=arc-20160816;
        b=UwsNtKOPelQCx3Z2IXnWkkUPAie4RdZPr0h+ci1Q5bSUQGC29Y7OUHVYSZHxoumtpE
         KaNA+AFsu1nUUa/QCdwLImJgjJn9fL5BN1DDArqf+yXk0m12ACC0TnlMnSuP+bbBugyz
         40FhvEOWBtaC9U+4Xd/Rs174n2JPDhrTynfLDFeUZKo4xViVHfELk/18OAeA80QMjQ4E
         2M6km5s8Bhi0EwWTMqZ+VhocHKlWjW6OFiXFv/sD8rxk/ilIFaKsh3hAtHUn0P8pccI5
         lw/zr8NSYuxMChoXmOo2sODjG9+6+zmceREPU+T/uVtCkmyKTX8zrwqJ6rBo9M4ASWus
         vSrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=T3bqBz+ijkWBH63jWfKgd/9yfTWjP7qvZab5lXdFeo4=;
        b=kgnY9GBtzqyp/mrayTI0hpMiCSj/TJx5oNfv41NMrn+rvzqxr5yyHHb0XFv0grHweZ
         3CSZnXUSO8gmAf02mv20/gn3VOYDg+MzikA3Ugf92M4RxA7YIYHOmkRFy/fcTNutLNmC
         mq2pxEDFOaOPtQFxZAgdamKWEWkltYfO+fclLS08EDPjMUVS90pT8K5zfif96s9EqFDs
         /QyADZ3FsC97t07aPqIS1xxpTDgZjGNuEmaByD+dh+Q9Yw81/xXvoihDZgpOhHPBr3ra
         FS3abVXw6ioebpo/ZBhuzR5bbEel0jV/2ws/Mexy8T9GwXW86WfFdY7frFVjcq4+FsS0
         oOwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ALbV6Xti;
       spf=pass (google.com: domain of srs0=qp6m=br=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=qp6M=BR=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 90si210939plb.3.2020.08.07.10.06.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Aug 2020 10:06:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=qp6m=br=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1644D2086A;
	Fri,  7 Aug 2020 17:06:19 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id D842D3522BB6; Fri,  7 Aug 2020 10:06:18 -0700 (PDT)
Date: Fri, 7 Aug 2020 10:06:18 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: peterz@infradead.org, bp@alien8.de, tglx@linutronix.de,
	mingo@kernel.org, mark.rutland@arm.com, dvyukov@google.com,
	glider@google.com, andreyknvl@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com
Subject: Re: [PATCH] kcsan: Treat runtime as NMI-like with interrupt tracing
Message-ID: <20200807170618.GW4295@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200807090031.3506555-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200807090031.3506555-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=ALbV6Xti;       spf=pass
 (google.com: domain of srs0=qp6m=br=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=qp6M=BR=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Fri, Aug 07, 2020 at 11:00:31AM +0200, Marco Elver wrote:
> Since KCSAN instrumentation is everywhere, we need to treat the hooks
> NMI-like for interrupt tracing. In order to present an as 'normal' as
> possible context to the code called by KCSAN when reporting errors, we
> need to update the IRQ-tracing state.
> 
> Tested: Several runs through kcsan-test with different configuration
> (PROVE_LOCKING on/off), as well as hours of syzbot testing with the
> original config that caught the problem (without CONFIG_PARAVIRT=y,
> which appears to cause IRQ state tracking inconsistencies even when
> KCSAN remains off, see Link).
> 
> Link: https://lkml.kernel.org/r/0000000000007d3b2d05ac1c303e@google.com
> Fixes: 248591f5d257 ("kcsan: Make KCSAN compatible with new IRQ state tracking")
> Reported-by: syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com
> Co-developed-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> Patch Note: This patch applies to latest mainline. While current
> mainline suffers from the above problem, the configs required to hit the
> issue are likely not enabled too often (of course with PROVE_LOCKING on;
> we hit it on syzbot though). It'll probably be wise to queue this as
> normal on -rcu, just in case something is still off, given the
> non-trivial nature of the issue. (If it should instead go to mainline
> right now as a fix, I'd like some more test time on syzbot.)

The usual, please let me know when/if you would like me to apply
to -rcu.  And have a great weekend!

						Thanx, Paul

> ---
>  kernel/kcsan/core.c  | 79 ++++++++++++++++++++++++++++++++++----------
>  kernel/kcsan/kcsan.h |  3 +-
>  2 files changed, 62 insertions(+), 20 deletions(-)
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 9147ff6a12e5..6202a645f1e2 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -291,13 +291,28 @@ static inline unsigned int get_delay(void)
>  				0);
>  }
>  
> -void kcsan_save_irqtrace(struct task_struct *task)
> -{
> +/*
> + * KCSAN instrumentation is everywhere, which means we must treat the hooks
> + * NMI-like for interrupt tracing. In order to present a 'normal' as possible
> + * context to the code called by KCSAN when reporting errors we need to update
> + * the IRQ-tracing state.
> + *
> + * Save and restore the IRQ state trace touched by KCSAN, since KCSAN's
> + * runtime is entered for every memory access, and potentially useful
> + * information is lost if dirtied by KCSAN.
> + */
> +
> +struct kcsan_irq_state {
> +	unsigned long		flags;
>  #ifdef CONFIG_TRACE_IRQFLAGS
> -	task->kcsan_save_irqtrace = task->irqtrace;
> +	int			hardirqs_enabled;
>  #endif
> -}
> +};
>  
> +/*
> + * This is also called by the reporting task for the other task, to generate the
> + * right report with CONFIG_KCSAN_VERBOSE. No harm in restoring more than once.
> + */
>  void kcsan_restore_irqtrace(struct task_struct *task)
>  {
>  #ifdef CONFIG_TRACE_IRQFLAGS
> @@ -305,6 +320,41 @@ void kcsan_restore_irqtrace(struct task_struct *task)
>  #endif
>  }
>  
> +/*
> + * Saves/restores IRQ state (see comment above). Need noinline to work around
> + * unfortunate code-gen upon inlining, resulting in objtool getting confused as
> + * well as losing stack trace information.
> + */
> +static noinline void kcsan_irq_save(struct kcsan_irq_state *irq_state)
> +{
> +#ifdef CONFIG_TRACE_IRQFLAGS
> +	current->kcsan_save_irqtrace = current->irqtrace;
> +	irq_state->hardirqs_enabled = lockdep_hardirqs_enabled();
> +#endif
> +	if (!kcsan_interrupt_watcher) {
> +		kcsan_disable_current(); /* Lockdep might WARN, etc. */
> +		raw_local_irq_save(irq_state->flags);
> +		lockdep_hardirqs_off(_RET_IP_);
> +		kcsan_enable_current();
> +	}
> +}
> +
> +static noinline void kcsan_irq_restore(struct kcsan_irq_state *irq_state)
> +{
> +	if (!kcsan_interrupt_watcher) {
> +		kcsan_disable_current(); /* Lockdep might WARN, etc. */
> +#ifdef CONFIG_TRACE_IRQFLAGS
> +		if (irq_state->hardirqs_enabled) {
> +			lockdep_hardirqs_on_prepare(_RET_IP_);
> +			lockdep_hardirqs_on(_RET_IP_);
> +		}
> +#endif
> +		raw_local_irq_restore(irq_state->flags);
> +		kcsan_enable_current();
> +	}
> +	kcsan_restore_irqtrace(current);
> +}
> +
>  /*
>   * Pull everything together: check_access() below contains the performance
>   * critical operations; the fast-path (including check_access) functions should
> @@ -350,11 +400,13 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
>  	flags = user_access_save();
>  
>  	if (consumed) {
> -		kcsan_save_irqtrace(current);
> +		struct kcsan_irq_state irqstate;
> +
> +		kcsan_irq_save(&irqstate);
>  		kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_MAYBE,
>  			     KCSAN_REPORT_CONSUMED_WATCHPOINT,
>  			     watchpoint - watchpoints);
> -		kcsan_restore_irqtrace(current);
> +		kcsan_irq_restore(&irqstate);
>  	} else {
>  		/*
>  		 * The other thread may not print any diagnostics, as it has
> @@ -387,7 +439,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>  	unsigned long access_mask;
>  	enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
>  	unsigned long ua_flags = user_access_save();
> -	unsigned long irq_flags = 0;
> +	struct kcsan_irq_state irqstate;
>  
>  	/*
>  	 * Always reset kcsan_skip counter in slow-path to avoid underflow; see
> @@ -412,14 +464,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>  		goto out;
>  	}
>  
> -	/*
> -	 * Save and restore the IRQ state trace touched by KCSAN, since KCSAN's
> -	 * runtime is entered for every memory access, and potentially useful
> -	 * information is lost if dirtied by KCSAN.
> -	 */
> -	kcsan_save_irqtrace(current);
> -	if (!kcsan_interrupt_watcher)
> -		local_irq_save(irq_flags);
> +	kcsan_irq_save(&irqstate);
>  
>  	watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
>  	if (watchpoint == NULL) {
> @@ -559,9 +604,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>  	remove_watchpoint(watchpoint);
>  	kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
>  out_unlock:
> -	if (!kcsan_interrupt_watcher)
> -		local_irq_restore(irq_flags);
> -	kcsan_restore_irqtrace(current);
> +	kcsan_irq_restore(&irqstate);
>  out:
>  	user_access_restore(ua_flags);
>  }
> diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
> index 29480010dc30..6eb35a9514d8 100644
> --- a/kernel/kcsan/kcsan.h
> +++ b/kernel/kcsan/kcsan.h
> @@ -24,9 +24,8 @@ extern unsigned int kcsan_udelay_interrupt;
>  extern bool kcsan_enabled;
>  
>  /*
> - * Save/restore IRQ flags state trace dirtied by KCSAN.
> + * Restore IRQ flags state trace dirtied by KCSAN.
>   */
> -void kcsan_save_irqtrace(struct task_struct *task);
>  void kcsan_restore_irqtrace(struct task_struct *task);
>  
>  /*
> -- 
> 2.28.0.236.gb10cc79966-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200807170618.GW4295%40paulmck-ThinkPad-P72.
