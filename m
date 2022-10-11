Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBORSWNAMGQEINNBHUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DB0A5FB2BF
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 14:58:46 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id h21-20020a2ea495000000b0026dffd0733asf5552753lji.7
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 05:58:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665493125; cv=pass;
        d=google.com; s=arc-20160816;
        b=tQtf7JQ4u1cjPnMxmniJ9qK49EjHbHIveDnV9HqxfunKu3IYMc61pxVrGJnMdrD5SG
         Q/LrhKDLfIXXbTMBugKoKN8usVhxV8K0mCwVSHooCIWqrBn/rxKtKzeM6adIRmq/JlUP
         a3wg3Xijrzp1gsFwASC1zZeQGMpH4tje2X+nT+Hwu3oFpXuaI63YwlckcQoCir24VZk5
         GsEg+8mZYwPvkrv/j/opkHOnsrwhZggh4ZyH2NvHWU1rpimG17A9n39anDay3Tq8aT1H
         PWFa+fn3pXfh6q3y/Inth4kEa9PjBdwJfaOtDENRF08OyVoYcGUBy3E+9zt+Pby0zmzw
         hMNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=EM2lC0iqBgBsdk93/OVKnw8RJgPN/iIlGXJAuklgE/c=;
        b=ofWzFIpSXEjPn+wNtY6zewGzTnFz6CPCjlCfDLw1BYwZ878CO195St87RGIHx7PGNu
         twairxChb2x+ZZurp4m3bItTIJRRYSsMqfvId2JU1uGEuI6sPccgxjuofSed3SkGCyJJ
         VACrXdqv+yrwu/ysKhOG3v/GXW7WXWk/NmQ7ZbYUEQI1P1qZtQdxnYasmO1Cv2IodWE1
         sGUfG5t61njje2PO6MZno33Xexswnf9W1Ymn4+WyE0QsA50cR5iYYIKV118sO/u1KwdE
         CYHstUc78XMagCqRYrsHiNG+atFWGtrKz4NI3F13oEyoTY3ilCc+n+XoX/2mCvzZzCMu
         LUrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AVd46ZdN;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=EM2lC0iqBgBsdk93/OVKnw8RJgPN/iIlGXJAuklgE/c=;
        b=n0c+EGwi+3zx1rFwpMg9rgnvz9+ANA9OW5EfogPU5k72JN31pyktoNysURWewPPMET
         DGF44qi8UnONmhBku9rvTnlQdWl7jnLEuqR5tBUo2pF1tM0/dulNGLJEgkePQfXPc+Jk
         G6SQvj8NLSTDkYgx5M3Qh+GpbZIyDOaiVLccGp5tX/mU6yIDUYM6ATtS69+qFg6rOml2
         sqc1QeO81ZxZxFn7FMk9i1V/pEf0rWEBXUrQj98Q8GLYfBQQzELz4lI/ZW6PTGToR5l/
         pJkfuBOnhh2uXDK7isvh6OaYcK5RFzmEwjqfMkMM+J0t6PqzIegvXJ1VXQ/1UjuekfRh
         6eng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EM2lC0iqBgBsdk93/OVKnw8RJgPN/iIlGXJAuklgE/c=;
        b=CnvAUrTFsnmbBsZOsQpqdlCMNbFJYfLSApbGGUIthuszW3R+sZdyOq4qTxpNkRpTo/
         unBKoIGE5CROOt6OK3TT08P2QaCHIPJTfTo+NrYKMD/H91hHFOQnOQuCvypTnMvlx4JE
         /UIRlGes/pp5fTGXg5lSf7IL7KrnuqRnPuOQw7YYPfjaEM71pzGQobDTPG+5vZOfZRuu
         A3Qt3B0e7mUi4ZzmcYxPWT8+6nNQ8EqY1WjbgT52BXVKCs7UqBgelxy2cx86rX8pFRXS
         vL2OqubFXXhQfItGiuErmnf1iO2DhrDO6ILbljqXYJUgV7nI9BSRUIeZNKlLMoLShlHi
         2HBQ==
X-Gm-Message-State: ACrzQf25m9L5vEyXaQ70afTtouSvbOXkQNJ7yKXnqVs98AbCTXV7RLhI
	mYQIISZWPgVnkfdw5B9Vb/c=
X-Google-Smtp-Source: AMsMyM5s0Sok+ef8xyTpeadtEYnCqT4ug/ov+haRmUrgSKiEPTEbBcqqfDICYNizK8Bhezpl6RN6Og==
X-Received: by 2002:a05:6512:3606:b0:4a2:71df:7938 with SMTP id f6-20020a056512360600b004a271df7938mr8884266lfs.279.1665493125363;
        Tue, 11 Oct 2022 05:58:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a42:0:b0:26d:cf5c:d952 with SMTP id q63-20020a2e2a42000000b0026dcf5cd952ls2625410ljq.5.-pod-prod-gmail;
 Tue, 11 Oct 2022 05:58:43 -0700 (PDT)
X-Received: by 2002:a2e:7211:0:b0:26d:fea5:c7e3 with SMTP id n17-20020a2e7211000000b0026dfea5c7e3mr8367597ljc.101.1665493123681;
        Tue, 11 Oct 2022 05:58:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665493123; cv=none;
        d=google.com; s=arc-20160816;
        b=CJW8JPAJMxqAxmeq/FTRvRv94q4hnV/PrBVuNheJPUo1oGqmuytI2pebi7IKIrIC2p
         SB9L8dwKqjJHSkOiK+sMDpYxEtaLEYZ0JG2AXCWAGKO+OwawpQKIXvI6NdimGzMLBbsw
         QIE6ss9JPnFQECZ43bB/L92iUaQYBHxK84H8gGdcjHXJCUsCBjJ4Q3L/xPkXqBEvpx61
         fBNXXCl09lV0Fm+J2cfa8OjPaxfNxHP5YgHX18dyEWj1os33jnNl9oCqZveiq1cmFxMh
         p6wi9av45KGO8a0Aij3uWvlpZHTE1iQe/EhUNMX0ptj9v3iGItGJ88tAnWHC3koHngRu
         Mgng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=VV/hIQhepUZ2XwkEHyPDiOkjH23JOcBz1F0l8KuSpds=;
        b=n1J6L/aYujeKyvcAKudMVAXbk9G/0e/7/5uordMpjfiASWPxCG3b7jo8xFrpTinagY
         +govK9mG3gDx4zYM6LqUZRfsnuCNFsaY5iZAwvVh8okvN4KmEpPmlHUjLl4moXum2JRR
         oo4lRUP1FBFU/fm5yVunX+NluAOaM1EN1h6+ZhPqqq4oGl92ME0XxTFFqEb4kaSL9Hko
         IKcIVHa6+jqx3+ct11nuGO2c4PEPlzLOFBEYxlRRXvMvFTGQYaz/XM8l6JSMFXhUgC73
         R9cbWA4o5/PIaaL8L7CKotkiBRFI7hgMxh3b16nqbKjhFMv5smeFWPKl5UUn4fFCn5yw
         Tm7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AVd46ZdN;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x62e.google.com (mail-ej1-x62e.google.com. [2a00:1450:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id v18-20020a2ea612000000b0026e8b14ad83si410887ljp.6.2022.10.11.05.58.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Oct 2022 05:58:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62e as permitted sender) client-ip=2a00:1450:4864:20::62e;
Received: by mail-ej1-x62e.google.com with SMTP id nb11so31217162ejc.5
        for <kasan-dev@googlegroups.com>; Tue, 11 Oct 2022 05:58:43 -0700 (PDT)
X-Received: by 2002:a17:906:5dda:b0:78d:e7d2:7499 with SMTP id p26-20020a1709065dda00b0078de7d27499mr1227435ejv.588.1665493122927;
        Tue, 11 Oct 2022 05:58:42 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:3abd:8519:48e1:da82])
        by smtp.gmail.com with ESMTPSA id r16-20020a170906281000b0078de26f66b9sm827564ejc.114.2022.10.11.05.58.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Oct 2022 05:58:42 -0700 (PDT)
Date: Tue, 11 Oct 2022 14:58:36 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v2] perf: Fix missing SIGTRAPs
Message-ID: <Y0VofNVMBXPOJJr7@elver.google.com>
References: <20220927121322.1236730-1-elver@google.com>
 <Yz7ZLaT4jW3Y9EYS@hirez.programming.kicks-ass.net>
 <Y0Ue2L5CsaQwDrEs@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y0Ue2L5CsaQwDrEs@hirez.programming.kicks-ass.net>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=AVd46ZdN;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62e as
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

On Tue, Oct 11, 2022 at 09:44AM +0200, Peter Zijlstra wrote:
> Subject: perf: Fix missing SIGTRAPs
> From: Peter Zijlstra <peterz@infradead.org>
> Date: Thu Oct 6 15:00:39 CEST 2022
> 
> Marco reported:
> 
> Due to the implementation of how SIGTRAP are delivered if
> perf_event_attr::sigtrap is set, we've noticed 3 issues:
> 
>   1. Missing SIGTRAP due to a race with event_sched_out() (more
>      details below).
> 
>   2. Hardware PMU events being disabled due to returning 1 from
>      perf_event_overflow(). The only way to re-enable the event is
>      for user space to first "properly" disable the event and then
>      re-enable it.
> 
>   3. The inability to automatically disable an event after a
>      specified number of overflows via PERF_EVENT_IOC_REFRESH.
> 
> The worst of the 3 issues is problem (1), which occurs when a
> pending_disable is "consumed" by a racing event_sched_out(), observed
> as follows:
> 
> 		CPU0			|	CPU1
> 	--------------------------------+---------------------------
> 	__perf_event_overflow()		|
> 	 perf_event_disable_inatomic()	|
> 	  pending_disable = CPU0	| ...
> 					| _perf_event_enable()
> 					|  event_function_call()
> 					|   task_function_call()
> 					|    /* sends IPI to CPU0 */
> 	<IPI>				| ...
> 	 __perf_event_enable()		+---------------------------
> 	  ctx_resched()
> 	   task_ctx_sched_out()
> 	    ctx_sched_out()
> 	     group_sched_out()
> 	      event_sched_out()
> 	       pending_disable = -1
> 	</IPI>
> 	<IRQ-work>
> 	 perf_pending_event()
> 	  perf_pending_event_disable()
> 	   /* Fails to send SIGTRAP because no pending_disable! */
> 	</IRQ-work>
> 
> In the above case, not only is that particular SIGTRAP missed, but also
> all future SIGTRAPs because 'event_limit' is not reset back to 1.
> 
> To fix, rework pending delivery of SIGTRAP via IRQ-work by introduction
> of a separate 'pending_sigtrap', no longer using 'event_limit' and
> 'pending_disable' for its delivery.
> 
> Additionally; and different to Marco's proposed patch:
> 
>  - recognise that pending_disable effectively duplicates oncpu for
>    the case where it is set. As such, change the irq_work handler to
>    use ->oncpu to target the event and use pending_* as boolean toggles.
> 
>  - observe that SIGTRAP targets the ctx->task, so the context switch
>    optimization that carries contexts between tasks is invalid. If
>    the irq_work were delayed enough to hit after a context switch the
>    SIGTRAP would be delivered to the wrong task.
> 
>  - observe that if the event gets scheduled out
>    (rotation/migration/context-switch/...) the irq-work would be
>    insufficient to deliver the SIGTRAP when the event gets scheduled
>    back in (the irq-work might still be pending on the old CPU).
> 
>    Therefore have event_sched_out() convert the pending sigtrap into a
>    task_work which will deliver the signal at return_to_user.
> 
> Fixes: 97ba62b27867 ("perf: Add support for SIGTRAP on perf events")
> Reported-by: Marco Elver <elver@google.com>
> Debugged-by: Marco Elver <elver@google.com>

Reviewed-by: Marco Elver <elver@google.com>
Tested-by: Marco Elver <elver@google.com>

.. fuzzing, and lots of concurrent sigtrap_threads with this patch:

	https://lore.kernel.org/all/20221011124534.84907-1-elver@google.com/

> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>

My original patch also attributed Dmitry:

	Reported-by: Dmitry Vyukov <dvyukov@google.com>
	Debugged-by: Dmitry Vyukov <dvyukov@google.com>

... we all melted our brains on this one. :-)

Would be good to get the fix into one of the upcoming 6.1-rc.

Thanks!

-- Marco

> ---
>  include/linux/perf_event.h  |   19 ++++-
>  kernel/events/core.c        |  151 ++++++++++++++++++++++++++++++++------------
>  kernel/events/ring_buffer.c |    2 
>  3 files changed, 129 insertions(+), 43 deletions(-)
> 
> --- a/include/linux/perf_event.h
> +++ b/include/linux/perf_event.h
> @@ -736,11 +736,14 @@ struct perf_event {
>  	struct fasync_struct		*fasync;
>  
>  	/* delayed work for NMIs and such */
> -	int				pending_wakeup;
> -	int				pending_kill;
> -	int				pending_disable;
> +	unsigned int			pending_wakeup;
> +	unsigned int			pending_kill;
> +	unsigned int			pending_disable;
> +	unsigned int			pending_sigtrap;
>  	unsigned long			pending_addr;	/* SIGTRAP */
> -	struct irq_work			pending;
> +	struct irq_work			pending_irq;
> +	struct callback_head		pending_task;
> +	unsigned int			pending_work;
>  
>  	atomic_t			event_limit;
>  
> @@ -857,6 +860,14 @@ struct perf_event_context {
>  #endif
>  	void				*task_ctx_data; /* pmu specific data */
>  	struct rcu_head			rcu_head;
> +
> +	/*
> +	 * Sum (event->pending_sigtrap + event->pending_work)
> +	 *
> +	 * The SIGTRAP is targeted at ctx->task, as such it won't do changing
> +	 * that until the signal is delivered.
> +	 */
> +	local_t				nr_pending;
>  };
>  
>  /*
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -54,6 +54,7 @@
>  #include <linux/highmem.h>
>  #include <linux/pgtable.h>
>  #include <linux/buildid.h>
> +#include <linux/task_work.h>
>  
>  #include "internal.h"
>  
> @@ -2268,11 +2269,26 @@ event_sched_out(struct perf_event *event
>  	event->pmu->del(event, 0);
>  	event->oncpu = -1;
>  
> -	if (READ_ONCE(event->pending_disable) >= 0) {
> -		WRITE_ONCE(event->pending_disable, -1);
> +	if (event->pending_disable) {
> +		event->pending_disable = 0;
>  		perf_cgroup_event_disable(event, ctx);
>  		state = PERF_EVENT_STATE_OFF;
>  	}
> +
> +	if (event->pending_sigtrap) {
> +		bool dec = true;
> +
> +		event->pending_sigtrap = 0;
> +		if (state != PERF_EVENT_STATE_OFF &&
> +		    !event->pending_work) {
> +			event->pending_work = 1;
> +			dec = false;
> +			task_work_add(current, &event->pending_task, TWA_RESUME);
> +		}
> +		if (dec)
> +			local_dec(&event->ctx->nr_pending);
> +	}
> +
>  	perf_event_set_state(event, state);
>  
>  	if (!is_software_event(event))
> @@ -2424,7 +2440,7 @@ static void __perf_event_disable(struct
>   * hold the top-level event's child_mutex, so any descendant that
>   * goes to exit will block in perf_event_exit_event().
>   *
> - * When called from perf_pending_event it's OK because event->ctx
> + * When called from perf_pending_irq it's OK because event->ctx
>   * is the current context on this CPU and preemption is disabled,
>   * hence we can't get into perf_event_task_sched_out for this context.
>   */
> @@ -2463,9 +2479,8 @@ EXPORT_SYMBOL_GPL(perf_event_disable);
>  
>  void perf_event_disable_inatomic(struct perf_event *event)
>  {
> -	WRITE_ONCE(event->pending_disable, smp_processor_id());
> -	/* can fail, see perf_pending_event_disable() */
> -	irq_work_queue(&event->pending);
> +	event->pending_disable = 1;
> +	irq_work_queue(&event->pending_irq);
>  }
>  
>  #define MAX_INTERRUPTS (~0ULL)
> @@ -3420,11 +3435,23 @@ static void perf_event_context_sched_out
>  		raw_spin_lock_nested(&next_ctx->lock, SINGLE_DEPTH_NESTING);
>  		if (context_equiv(ctx, next_ctx)) {
>  
> +			perf_pmu_disable(pmu);
> +
> +			/* PMIs are disabled; ctx->nr_pending is stable. */
> +			if (local_read(&ctx->nr_pending) ||
> +			    local_read(&next_ctx->nr_pending)) {
> +				/*
> +				 * Must not swap out ctx when there's pending
> +				 * events that rely on the ctx->task relation.
> +				 */
> +				raw_spin_unlock(&next_ctx->lock);
> +				rcu_read_unlock();
> +				goto inside_switch;
> +			}
> +
>  			WRITE_ONCE(ctx->task, next);
>  			WRITE_ONCE(next_ctx->task, task);
>  
> -			perf_pmu_disable(pmu);
> -
>  			if (cpuctx->sched_cb_usage && pmu->sched_task)
>  				pmu->sched_task(ctx, false);
>  
> @@ -3465,6 +3492,7 @@ static void perf_event_context_sched_out
>  		raw_spin_lock(&ctx->lock);
>  		perf_pmu_disable(pmu);
>  
> +inside_switch:
>  		if (cpuctx->sched_cb_usage && pmu->sched_task)
>  			pmu->sched_task(ctx, false);
>  		task_ctx_sched_out(cpuctx, ctx, EVENT_ALL);
> @@ -4931,7 +4959,7 @@ static void perf_addr_filters_splice(str
>  
>  static void _free_event(struct perf_event *event)
>  {
> -	irq_work_sync(&event->pending);
> +	irq_work_sync(&event->pending_irq);
>  
>  	unaccount_event(event);
>  
> @@ -6431,7 +6459,8 @@ static void perf_sigtrap(struct perf_eve
>  		return;
>  
>  	/*
> -	 * perf_pending_event() can race with the task exiting.
> +	 * Both perf_pending_task() and perf_pending_irq() can race with the
> +	 * task exiting.
>  	 */
>  	if (current->flags & PF_EXITING)
>  		return;
> @@ -6440,23 +6469,33 @@ static void perf_sigtrap(struct perf_eve
>  		      event->attr.type, event->attr.sig_data);
>  }
>  
> -static void perf_pending_event_disable(struct perf_event *event)
> +/*
> + * Deliver the pending work in-event-context or follow the context.
> + */
> +static void __perf_pending_irq(struct perf_event *event)
>  {
> -	int cpu = READ_ONCE(event->pending_disable);
> +	int cpu = READ_ONCE(event->oncpu);
>  
> +	/*
> +	 * If the event isn't running; we done. event_sched_out() will have
> +	 * taken care of things.
> +	 */
>  	if (cpu < 0)
>  		return;
>  
> +	/*
> +	 * Yay, we hit home and are in the context of the event.
> +	 */
>  	if (cpu == smp_processor_id()) {
> -		WRITE_ONCE(event->pending_disable, -1);
> -
> -		if (event->attr.sigtrap) {
> +		if (event->pending_sigtrap) {
> +			event->pending_sigtrap = 0;
>  			perf_sigtrap(event);
> -			atomic_set_release(&event->event_limit, 1); /* rearm event */
> -			return;
> +			local_dec(&event->ctx->nr_pending);
> +		}
> +		if (event->pending_disable) {
> +			event->pending_disable = 0;
> +			perf_event_disable_local(event);
>  		}
> -
> -		perf_event_disable_local(event);
>  		return;
>  	}
>  
> @@ -6476,35 +6515,62 @@ static void perf_pending_event_disable(s
>  	 *				  irq_work_queue(); // FAILS
>  	 *
>  	 *  irq_work_run()
> -	 *    perf_pending_event()
> +	 *    perf_pending_irq()
>  	 *
>  	 * But the event runs on CPU-B and wants disabling there.
>  	 */
> -	irq_work_queue_on(&event->pending, cpu);
> +	irq_work_queue_on(&event->pending_irq, cpu);
>  }
>  
> -static void perf_pending_event(struct irq_work *entry)
> +static void perf_pending_irq(struct irq_work *entry)
>  {
> -	struct perf_event *event = container_of(entry, struct perf_event, pending);
> +	struct perf_event *event = container_of(entry, struct perf_event, pending_irq);
>  	int rctx;
>  
> -	rctx = perf_swevent_get_recursion_context();
>  	/*
>  	 * If we 'fail' here, that's OK, it means recursion is already disabled
>  	 * and we won't recurse 'further'.
>  	 */
> +	rctx = perf_swevent_get_recursion_context();
>  
> -	perf_pending_event_disable(event);
> -
> +	/*
> +	 * The wakeup isn't bound to the context of the event -- it can happen
> +	 * irrespective of where the event is.
> +	 */
>  	if (event->pending_wakeup) {
>  		event->pending_wakeup = 0;
>  		perf_event_wakeup(event);
>  	}
>  
> +	__perf_pending_irq(event);
> +
>  	if (rctx >= 0)
>  		perf_swevent_put_recursion_context(rctx);
>  }
>  
> +static void perf_pending_task(struct callback_head *head)
> +{
> +	struct perf_event *event = container_of(head, struct perf_event, pending_task);
> +	int rctx;
> +
> +	/*
> +	 * If we 'fail' here, that's OK, it means recursion is already disabled
> +	 * and we won't recurse 'further'.
> +	 */
> +	preempt_disable_notrace();
> +	rctx = perf_swevent_get_recursion_context();
> +
> +	if (event->pending_work) {
> +		event->pending_work = 0;
> +		perf_sigtrap(event);
> +		local_dec(&event->ctx->nr_pending);
> +	}
> +
> +	if (rctx >= 0)
> +		perf_swevent_put_recursion_context(rctx);
> +	preempt_enable_notrace();
> +}
> +
>  #ifdef CONFIG_GUEST_PERF_EVENTS
>  struct perf_guest_info_callbacks __rcu *perf_guest_cbs;
>  
> @@ -9188,8 +9254,8 @@ int perf_event_account_interrupt(struct
>   */
>  
>  static int __perf_event_overflow(struct perf_event *event,
> -				   int throttle, struct perf_sample_data *data,
> -				   struct pt_regs *regs)
> +				 int throttle, struct perf_sample_data *data,
> +				 struct pt_regs *regs)
>  {
>  	int events = atomic_read(&event->event_limit);
>  	int ret = 0;
> @@ -9212,24 +9278,36 @@ static int __perf_event_overflow(struct
>  	if (events && atomic_dec_and_test(&event->event_limit)) {
>  		ret = 1;
>  		event->pending_kill = POLL_HUP;
> -		event->pending_addr = data->addr;
> -
>  		perf_event_disable_inatomic(event);
>  	}
>  
> +	if (event->attr.sigtrap) {
> +		/*
> +		 * Should not be able to return to user space without processing
> +		 * pending_sigtrap (kernel events can overflow multiple times).
> +		 */
> +		WARN_ON_ONCE(event->pending_sigtrap && event->attr.exclude_kernel);
> +		if (!event->pending_sigtrap) {
> +			event->pending_sigtrap = 1;
> +			local_inc(&event->ctx->nr_pending);
> +		}
> +		event->pending_addr = data->addr;
> +		irq_work_queue(&event->pending_irq);
> +	}
> +
>  	READ_ONCE(event->overflow_handler)(event, data, regs);
>  
>  	if (*perf_event_fasync(event) && event->pending_kill) {
>  		event->pending_wakeup = 1;
> -		irq_work_queue(&event->pending);
> +		irq_work_queue(&event->pending_irq);
>  	}
>  
>  	return ret;
>  }
>  
>  int perf_event_overflow(struct perf_event *event,
> -			  struct perf_sample_data *data,
> -			  struct pt_regs *regs)
> +			struct perf_sample_data *data,
> +			struct pt_regs *regs)
>  {
>  	return __perf_event_overflow(event, 1, data, regs);
>  }
> @@ -11537,8 +11615,8 @@ perf_event_alloc(struct perf_event_attr
>  
>  
>  	init_waitqueue_head(&event->waitq);
> -	event->pending_disable = -1;
> -	init_irq_work(&event->pending, perf_pending_event);
> +	init_irq_work(&event->pending_irq, perf_pending_irq);
> +	init_task_work(&event->pending_task, perf_pending_task);
>  
>  	mutex_init(&event->mmap_mutex);
>  	raw_spin_lock_init(&event->addr_filters.lock);
> @@ -11560,9 +11638,6 @@ perf_event_alloc(struct perf_event_attr
>  	if (parent_event)
>  		event->event_caps = parent_event->event_caps;
>  
> -	if (event->attr.sigtrap)
> -		atomic_set(&event->event_limit, 1);
> -
>  	if (task) {
>  		event->attach_state = PERF_ATTACH_TASK;
>  		/*
> --- a/kernel/events/ring_buffer.c
> +++ b/kernel/events/ring_buffer.c
> @@ -22,7 +22,7 @@ static void perf_output_wakeup(struct pe
>  	atomic_set(&handle->rb->poll, EPOLLIN);
>  
>  	handle->event->pending_wakeup = 1;
> -	irq_work_queue(&handle->event->pending);
> +	irq_work_queue(&handle->event->pending_irq);
>  }
>  
>  /*

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0VofNVMBXPOJJr7%40elver.google.com.
