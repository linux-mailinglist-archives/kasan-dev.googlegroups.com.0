Return-Path: <kasan-dev+bncBAABBSVH373AKGQE6KLSOGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id CA34C1ED47F
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 18:46:03 +0200 (CEST)
Received: by mail-ua1-x93e.google.com with SMTP id q19sf1304799uad.21
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 09:46:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591202762; cv=pass;
        d=google.com; s=arc-20160816;
        b=IYLgrKADRk8atE4F6lq8EvwdFMwBANFAnEsjBhMcDHM6WA6gbwOuO2fjuc/irXpZms
         /AhEDGZ6oWzf93y1+TQhq0n/XRHqztOS81QrxJh7DYWk93lA8mk6oGe0ZcULEQXszYbr
         TphyzXHu2nBcddZ6naqf0JxbUuAYi/z0kHJRmfjef/ZE5VQ4CvF3LHp6tP4olHUv8Rg6
         Ur3xQ1WwwnIvF6fEB+saAasog3V70+m2SqQyxv8ilSDuItbxSLtWWkS0g0T7ND4+Mr5n
         C3fQYqCWHAQR3g7uV4sXB2fanpy1YF5VrYouvdnfyO71hlv9a+z9oWGuKbZH9HqsETwD
         x16w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=JoiM5UByxx3Ei0so8K+G91thMyczyDN1Ef7M5zOsMQ8=;
        b=SkNoy1txY0Yvzue9ZvDvocwnfq+SyuVvge1jV6+cFrPK7BVVYUP8+HPN6nU+9+yI7J
         gzYY4UYxe/gYVm22WP/EFA61tqPwO4+EHt+9l8RoyXpfR0yIvSB4uiLtW18nQRPHM46u
         0XPIh+FZ5kF8QF3HxmCaXcZ07/LUKXdzWsVotVofnC3WYLYvDpGxWholi2zqNN886txg
         3u8tKBMO74R3gWg+3GZgFyCFZROHHivhLXoqO4/iFlTA2u1JwHLv553I4xOtB5f7VKE6
         jl+KteRvTa4afXPsV6PGIotpdDCopfWFTHvC2zfe5aA5CwCpPpvJNCF815wMrTOifaA1
         YZcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=mJ+0NmXz;
       spf=pass (google.com: domain of srs0=w7he=7q=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=w7he=7Q=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JoiM5UByxx3Ei0so8K+G91thMyczyDN1Ef7M5zOsMQ8=;
        b=nqbdn0F4s3lx1ut+Pz0ZhtThUlx3/3/M0uTqfpwYq7f4Bm4LUE6MaiFe/XVfMbMqPX
         0EN5ADNFcvVBa4CdEVOgjxmWkGlVGGKGplWgT7LnyMKXE8q9AL19MunC0hWhJd+aWwRV
         RZnUO5MR+LH1O0oAlSNzbP7jT6CEwKqvbUQtGwy1cH6st0qGbtEH7D9AYIL88SJJbajz
         mpcvb4WEt0SEuIfez4orzV/spGC9ph5tOWBu0aujqe7TMy0sIU5d5k6cPQPiroLE3OM+
         aXhvW1pYWlLJLL2OUbGp7zUTEq6HB0iq+OqfV+KVGKabnFDE1pPecVdbcU2vIvCLCNMr
         mDdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JoiM5UByxx3Ei0so8K+G91thMyczyDN1Ef7M5zOsMQ8=;
        b=V3+C3O2pG1hpbq3/uB74dL0k3hipiYab7rbxxJixZqh7xImZLlBuNQZDymZnVmRwJm
         CxPsiF8iXT3HNPA7W5z+wiFmTdrAHaLKx7BPbHkY4QQQUloYxQSKCJYM7LdPA1lVxvuQ
         2PgNJ/O9J8/7CqWiVJAECkh8cvcklBwKCoOCAjh6HO+ihpUFvIVSwcuo9JsRPMPfJRSb
         dxCvJOTUqePKooWqvkrjAhLBVJeQIQYA/8LyZb/RRW8f5WKT0SMrhiQr3dJZkxXqO9/z
         qrd6yB32Nn4lHM4csVZHlaU/P3J7jYzOhvhQUBuYR4h2Sz9hFtXeZ1e8xZfRzKB6QeNX
         nISA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533tV8py686ZDxLwN5vYaj+A56xUQ33cReYN1gPyyrS1m75IaUlH
	kmIoV7litMHvHF2LQAfrODc=
X-Google-Smtp-Source: ABdhPJzziOvzwhgGdZPlN/rCDsgcrjRUDWQ66NhKBB1zEPY5dsGDqxY7L78kE3RyFX3XSPH/dCfHTg==
X-Received: by 2002:a05:6102:22ec:: with SMTP id b12mr268516vsh.138.1591202762676;
        Wed, 03 Jun 2020 09:46:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:a14a:: with SMTP id k71ls150409vke.10.gmail; Wed, 03 Jun
 2020 09:46:02 -0700 (PDT)
X-Received: by 2002:a1f:24ce:: with SMTP id k197mr484316vkk.13.1591202762139;
        Wed, 03 Jun 2020 09:46:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591202762; cv=none;
        d=google.com; s=arc-20160816;
        b=RkBxN2IiRCydfDkOsttZL7n3vqvBU5V9/Ts5Z/VUbv4GPCNqY0qiA6GZalYAg0twHg
         G+2fC0rnXvB0aBDk7GaQUdGozQ4n3qQNQNrsRln9+v7U7Yfub7pFElJUBwkaiFYFyOOd
         pWZkYwb5qXm39V1STKiVAWN9MjsF1jTLyd9RzYNEl3Ok6yqBYeVBst5MvKxxdB+kL40Q
         UJTe+hGF2Og/Tj8H+76RocNQ3xRpnyHk0cJChYFp37457fTfMmeS36W24ii6E6/hk+1U
         MSdkBF2lH2bCk3M+NWbGwgxTNMEB127IFB9PeJb87lJt8igWRMWQurh95Uz6fWAR47eG
         Na7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Fh00GlOdH1Ic0ZMLu90djyZgBcfi1dHIAnrOktwdyWA=;
        b=nHvnHihlHFVaQra0bgCF0Cl6grYTKDTyiyGzJ3U+koCtdiyrrw1wZ7QuAAMSG+XH1Z
         YSz+WSysPcm87FXK6ukQFHkfDX9mYI0WOYcGRoGejy91BeHL5rLqS98xXWuL4mwC5N9N
         mmlYE8XjVZmKAiqYnZFd9VFiumQcZLKPjynn67cEFykankoMRKwnM/DqP6MTHWUW/CcZ
         S1GFw4er0T4NzSlrPEE9OUC9w7cp6M6PgSuVk2OedDCYMe9SF3HL34dCHB3D6R078LPK
         Nv/zP4nRu+nnb6waxdZ288fSdAPV7l8V5OKIUnf1z3SEMie2YCdnggTldUwvd27plIj0
         vp1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=mJ+0NmXz;
       spf=pass (google.com: domain of srs0=w7he=7q=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=w7he=7Q=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e10si73460vkp.4.2020.06.03.09.46.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Jun 2020 09:46:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=w7he=7q=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id EBE36206A2;
	Wed,  3 Jun 2020 16:46:00 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 750D335209C5; Wed,  3 Jun 2020 09:46:00 -0700 (PDT)
Date: Wed, 3 Jun 2020 09:46:00 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: tglx@linutronix.de, x86@kernel.org, elver@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200603164600.GQ29598@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200603114051.896465666@infradead.org>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=mJ+0NmXz;       spf=pass
 (google.com: domain of srs0=w7he=7q=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=w7he=7Q=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Jun 03, 2020 at 01:40:16PM +0200, Peter Zijlstra wrote:
> A KCSAN build revealed we have explicit annoations through atomic_*()
> usage, switch to arch_atomic_*() for the respective functions.
> 
> vmlinux.o: warning: objtool: rcu_nmi_exit()+0x4d: call to __kcsan_check_access() leaves .noinstr.text section
> vmlinux.o: warning: objtool: rcu_dynticks_eqs_enter()+0x25: call to __kcsan_check_access() leaves .noinstr.text section
> vmlinux.o: warning: objtool: rcu_nmi_enter()+0x4f: call to __kcsan_check_access() leaves .noinstr.text section
> vmlinux.o: warning: objtool: rcu_dynticks_eqs_exit()+0x2a: call to __kcsan_check_access() leaves .noinstr.text section
> vmlinux.o: warning: objtool: __rcu_is_watching()+0x25: call to __kcsan_check_access() leaves .noinstr.text section
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Link: https://lkml.kernel.org/r/20200603084818.GB2627@hirez.programming.kicks-ass.net
> ---
>  kernel/rcu/tree.c |   11 +++++------
>  1 file changed, 5 insertions(+), 6 deletions(-)
> 
> --- a/kernel/rcu/tree.c
> +++ b/kernel/rcu/tree.c
> @@ -250,7 +250,7 @@ static noinstr void rcu_dynticks_eqs_ent
>  	 * next idle sojourn.
>  	 */
>  	rcu_dynticks_task_trace_enter();  // Before ->dynticks update!
> -	seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> +	seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);

To preserve KCSAN's ability to see this, there would be something like
instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks)) prior
to the instrumentation_end() invoked before rcu_dynticks_eqs_enter()
in each of rcu_eqs_enter() and rcu_nmi_exit(), correct?

>  	// RCU is no longer watching.  Better be in extended quiescent state!
>  	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
>  		     (seq & RCU_DYNTICK_CTRL_CTR));
> @@ -274,13 +274,13 @@ static noinstr void rcu_dynticks_eqs_exi
>  	 * and we also must force ordering with the next RCU read-side
>  	 * critical section.
>  	 */
> -	seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> +	seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);

And same here, but after the instrumentation_begin() following
rcu_dynticks_eqs_exit() in both rcu_eqs_exit() and rcu_nmi_enter(),
correct?

>  	// RCU is now watching.  Better not be in an extended quiescent state!
>  	rcu_dynticks_task_trace_exit();  // After ->dynticks update!
>  	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
>  		     !(seq & RCU_DYNTICK_CTRL_CTR));
>  	if (seq & RCU_DYNTICK_CTRL_MASK) {
> -		atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
> +		arch_atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);

This one is gone in -rcu.

>  		smp_mb__after_atomic(); /* _exit after clearing mask. */
>  	}
>  }
> @@ -313,7 +313,7 @@ static __always_inline bool rcu_dynticks
>  {
>  	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
>  
> -	return !(atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
> +	return !(arch_atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);

Also instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks)) as
follows:

o	rcu_nmi_exit(): After each following instrumentation_begin().

o	In theory in rcu_irq_exit_preempt(), but as this generates code
	only in lockdep builds, it might not be worth worrying about.

o	Ditto for rcu_irq_exit_check_preempt().

o	Ditto for __rcu_irq_enter_check_tick().

o	rcu_nmi_enter(): After each following instrumentation_begin().

o	__rcu_is_watching() is itself noinstr:

	o	idtentry_enter_cond_rcu(): After each following
		instrumentation_begin().

o	rcu_is_watching(): Either before or after the call to
	rcu_dynticks_curr_cpu_in_eqs().

>  }
>  
>  /*
> @@ -692,6 +692,7 @@ noinstr void rcu_nmi_exit(void)
>  {
>  	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
>  
> +	instrumentation_begin();
>  	/*
>  	 * Check for ->dynticks_nmi_nesting underflow and bad ->dynticks.
>  	 * (We are exiting an NMI handler, so RCU better be paying attention
> @@ -705,7 +706,6 @@ noinstr void rcu_nmi_exit(void)
>  	 * leave it in non-RCU-idle state.
>  	 */
>  	if (rdp->dynticks_nmi_nesting != 1) {
> -		instrumentation_begin();
>  		trace_rcu_dyntick(TPS("--="), rdp->dynticks_nmi_nesting, rdp->dynticks_nmi_nesting - 2,
>  				  atomic_read(&rdp->dynticks));
>  		WRITE_ONCE(rdp->dynticks_nmi_nesting, /* No store tearing. */
> @@ -714,7 +714,6 @@ noinstr void rcu_nmi_exit(void)
>  		return;
>  	}
>  
> -	instrumentation_begin();
>  	/* This NMI interrupted an RCU-idle CPU, restore RCU-idleness. */
>  	trace_rcu_dyntick(TPS("Startirq"), rdp->dynticks_nmi_nesting, 0, atomic_read(&rdp->dynticks));
>  	WRITE_ONCE(rdp->dynticks_nmi_nesting, 0); /* Avoid store tearing. */

This one looks to be having no effect on instrumentation of atomics, but
rather coalescing a pair of instrumentation_begin() into one.

Do I understand correctly?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603164600.GQ29598%40paulmck-ThinkPad-P72.
