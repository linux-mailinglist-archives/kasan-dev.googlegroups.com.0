Return-Path: <kasan-dev+bncBDBK55H2UQKRB4WUSWNAMGQEAQYPYPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 86B6E5FB2DC
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 15:06:59 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id k21-20020a7bc415000000b003b4fac53006sf3701684wmi.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 06:06:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665493619; cv=pass;
        d=google.com; s=arc-20160816;
        b=NRMls3QVj3HMVFM09N+qLnpD3l2nPNbtfnumQdPq2Baf+E/aprLmdbOc1yrGjWGAux
         dpBdLTtl6lHFNg73kHQAo9Gaai2vVpTC5OwxKPBiU5DoTEYXsJL1uwg67SwnKcnwi+GL
         F7cH+Ok2y9WSe74wUy/A1zY3+NkZ/tzYqmm+PGmGKqWXP6zu3ijgepp9eel2ute5E4ev
         /XXNqhVSXD+XWyGoobAIQBr9oS7Q5VA3K/rf+K/H01kvoIuXmfwRP4j+LomESlOou/fo
         qNhMyko1UOrAu6ofaN1a26SViSFU05o/S69OOJ+RLKxtUsg8zyuWDszVX3spfbkp9ePr
         NtXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=vImK7pU5DTMoadruOT2YT0+ssMAnxcdldGLboplxNhk=;
        b=KMYafIua9CnlH/lcn1e4GhbqTI/Cmcdl0RZwkzG71AQDN4o+tgka4/RtGREmqEIqHQ
         oz/KwVpoBdR6YkFSypEL2296k8J+HIJ6Nr6FbPTpcSaZoBwrLxfVPSvudFjiOnrpZtCO
         iek7lwbEBVwyrZgQETK8XaAhqte/xuPeVWUnYChimk9c1p1ienQBlVkE/dHXc5mdlm0d
         HtPMgWm37SOPFHEkmWXUP2wcpcknojM7WuONpOjDcoUc8EVmdhQKGGq0ZE5Z9DT9ohJ6
         ULPfsqVfjqUFJ+cKFISx8j3EFxtF9zHwyteIc8I8f9deCdtTYch5uYyC1Xzip+thjmSY
         PnSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=PMDKwr0K;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vImK7pU5DTMoadruOT2YT0+ssMAnxcdldGLboplxNhk=;
        b=Cwsz25d6bUkJ6+QPLrX6+aHtN+jkcq0+FMOuzulj+KLZgCCz5v5NXfJ2F/6q6Ik8ZC
         VN1N57cFe3uagzyZUR43Ta58M7dkEG1LJb4olO4ghtKqCM9irb/2K7ilfyuJ1vMSmyS0
         zZv38cD0w6pwApz7axpQKYijyUgpY4Py9FDgvOCBq978Qw0h/hxYrd4Eo79YaNb9vnJc
         4AGz8jgwfn8gj9h9JsPMfEdlODDrkdNDOyZAdSzBdWkGYEMjO7maTQdagH0VV6jvGZ40
         QlZ/k15wpPpGOhuyB0lWq+aeHWCO3CH0hy+c5DfrKs/bV8M91Yc0h/YAT+owhztIXfpW
         gFiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vImK7pU5DTMoadruOT2YT0+ssMAnxcdldGLboplxNhk=;
        b=1yOhN/q84IH9llr9bIxIasviCgAq2wH3Ep75orPyQmbSRoLlhc5/DOn+cWxBRnmVT1
         nvwxi6EKneFFoYIsMiMoNHT95cYHpoW2n7nDJzZ0/i1nN6Am5mQq+Hj/LoCyW603gzF3
         AwOBTcGkn67CweKhxpvlqUxYc+23WSMxXV9IwDPxlll2zm3OFdafOZsq8WDIWSVh9ZzJ
         hFxn4S3mtX63/HzVlwc/XeFDmHyG8TGEZ8V4AsXHkjney+7VicXsmc9UFEfan9Y+o+fI
         iqZYQzLInn0ZEGwXer7zgOpyQydeziqzW/C89lnFZrl1Wrx3/SexvtbzLYVEUb1n3PYz
         iUzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1HzlcMGEXDxxjbheTw8+FAgqhDJ94pg4gaYraPgtaXf1q3459V
	BqgEtunI2gK1VnVi6cijXq8=
X-Google-Smtp-Source: AMsMyM7P1ozB6ajYQ9BjIs4tEM6njaEBQJTF+bM003Shgp1PBZ4xzw/BwOqmDsxHtTw5MPf6MniCJA==
X-Received: by 2002:a05:600c:1586:b0:3c6:bfcf:90a7 with SMTP id r6-20020a05600c158600b003c6bfcf90a7mr5101877wmf.163.1665493619062;
        Tue, 11 Oct 2022 06:06:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6007:b0:3a8:3c9f:7e90 with SMTP id
 az7-20020a05600c600700b003a83c9f7e90ls2202314wmb.1.-pod-canary-gmail; Tue, 11
 Oct 2022 06:06:57 -0700 (PDT)
X-Received: by 2002:a05:600c:35d2:b0:3c6:bf52:24af with SMTP id r18-20020a05600c35d200b003c6bf5224afmr5438754wmq.162.1665493617648;
        Tue, 11 Oct 2022 06:06:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665493617; cv=none;
        d=google.com; s=arc-20160816;
        b=Up6A7v3s/2j/r73cK7jeZmPLrWUvDC5w/EmomRKKenkonFMeIYv+w2G7DDA05AJQvw
         oBoYJIc54b/XO4ew1xVbc1n3+iL/FcI9mH14+UDuCjcR2SqMFu/wRnQ4KfnpGE6/REmV
         cI5RdLNUIbWuE5FCIUI+LJ/cFaGtu5QboBmuSnLsQlBb/02J8LZZSOOalMLBN+hCia0A
         5MrTbnozcbNCg8x14bjqqSzzYv9KlinNlc4sZCdFORxUD4ltgBzwzNmUBe4o8UpPkPG2
         Fn3cD7G8p8X9bCTMaH0Q8UpZXm41QLJcFEBOeYeMSJKN75O7TgrqWzqu4oQkeQTWflGM
         ayZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0kl7dlvjnuqfiBoL2flcqsA/Ux8iLqViAUlVpL1x4Uo=;
        b=pyWZ7Ssjiz2cv1TQB0PDla7psukVg8Nw5wpU2j6OopSjfnmngMJaRMnxUzXm9D8Uau
         Ag81EZn0TUNlLraQ7r2QfLUaheVRqwl087G+xFuqIl3lKcqMJgD7b7+YIpDxCHa8pc+E
         yMdhGRZYvjCV0GLkHPuGpo9wZBOUMWVcLRhdLGB28QI5GPIBlwmGmSjHoZquNcPctHa3
         +KrkOgJTGcuYpUYRchM1WDBGinZ7vo35hYTchRiEKdVnWFkTdR0Qeb2uXAfW+c3Oo2in
         O7ykhvhKrHXaH+/gSNlRlrVFyqkL+rwAYq3B0H7j17ta6DBvaShPbLRfKwb3UAFY0q+M
         LZZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=PMDKwr0K;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id bj8-20020a0560001e0800b0022e04ae3a44si481283wrb.6.2022.10.11.06.06.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Oct 2022 06:06:57 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oiEyI-004yPP-BO; Tue, 11 Oct 2022 13:06:59 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id C2F7830004F;
	Tue, 11 Oct 2022 15:06:52 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id A693029A09944; Tue, 11 Oct 2022 15:06:52 +0200 (CEST)
Date: Tue, 11 Oct 2022 15:06:52 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v2] perf: Fix missing SIGTRAPs
Message-ID: <Y0VqbNDKIHUcC7Ha@hirez.programming.kicks-ass.net>
References: <20220927121322.1236730-1-elver@google.com>
 <Yz7ZLaT4jW3Y9EYS@hirez.programming.kicks-ass.net>
 <Y0Ue2L5CsaQwDrEs@hirez.programming.kicks-ass.net>
 <Y0VofNVMBXPOJJr7@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y0VofNVMBXPOJJr7@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=PMDKwr0K;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Oct 11, 2022 at 02:58:36PM +0200, Marco Elver wrote:
> On Tue, Oct 11, 2022 at 09:44AM +0200, Peter Zijlstra wrote:
> > Subject: perf: Fix missing SIGTRAPs
> > From: Peter Zijlstra <peterz@infradead.org>
> > Date: Thu Oct 6 15:00:39 CEST 2022
> > 
> > Marco reported:
> > 
> > Due to the implementation of how SIGTRAP are delivered if
> > perf_event_attr::sigtrap is set, we've noticed 3 issues:
> > 
> >   1. Missing SIGTRAP due to a race with event_sched_out() (more
> >      details below).
> > 
> >   2. Hardware PMU events being disabled due to returning 1 from
> >      perf_event_overflow(). The only way to re-enable the event is
> >      for user space to first "properly" disable the event and then
> >      re-enable it.
> > 
> >   3. The inability to automatically disable an event after a
> >      specified number of overflows via PERF_EVENT_IOC_REFRESH.
> > 
> > The worst of the 3 issues is problem (1), which occurs when a
> > pending_disable is "consumed" by a racing event_sched_out(), observed
> > as follows:
> > 
> > 		CPU0			|	CPU1
> > 	--------------------------------+---------------------------
> > 	__perf_event_overflow()		|
> > 	 perf_event_disable_inatomic()	|
> > 	  pending_disable = CPU0	| ...
> > 					| _perf_event_enable()
> > 					|  event_function_call()
> > 					|   task_function_call()
> > 					|    /* sends IPI to CPU0 */
> > 	<IPI>				| ...
> > 	 __perf_event_enable()		+---------------------------
> > 	  ctx_resched()
> > 	   task_ctx_sched_out()
> > 	    ctx_sched_out()
> > 	     group_sched_out()
> > 	      event_sched_out()
> > 	       pending_disable = -1
> > 	</IPI>
> > 	<IRQ-work>
> > 	 perf_pending_event()
> > 	  perf_pending_event_disable()
> > 	   /* Fails to send SIGTRAP because no pending_disable! */
> > 	</IRQ-work>
> > 
> > In the above case, not only is that particular SIGTRAP missed, but also
> > all future SIGTRAPs because 'event_limit' is not reset back to 1.
> > 
> > To fix, rework pending delivery of SIGTRAP via IRQ-work by introduction
> > of a separate 'pending_sigtrap', no longer using 'event_limit' and
> > 'pending_disable' for its delivery.
> > 
> > Additionally; and different to Marco's proposed patch:
> > 
> >  - recognise that pending_disable effectively duplicates oncpu for
> >    the case where it is set. As such, change the irq_work handler to
> >    use ->oncpu to target the event and use pending_* as boolean toggles.
> > 
> >  - observe that SIGTRAP targets the ctx->task, so the context switch
> >    optimization that carries contexts between tasks is invalid. If
> >    the irq_work were delayed enough to hit after a context switch the
> >    SIGTRAP would be delivered to the wrong task.
> > 
> >  - observe that if the event gets scheduled out
> >    (rotation/migration/context-switch/...) the irq-work would be
> >    insufficient to deliver the SIGTRAP when the event gets scheduled
> >    back in (the irq-work might still be pending on the old CPU).
> > 
> >    Therefore have event_sched_out() convert the pending sigtrap into a
> >    task_work which will deliver the signal at return_to_user.
> > 
> > Fixes: 97ba62b27867 ("perf: Add support for SIGTRAP on perf events")
> > Reported-by: Marco Elver <elver@google.com>
> > Debugged-by: Marco Elver <elver@google.com>
> 
> Reviewed-by: Marco Elver <elver@google.com>
> Tested-by: Marco Elver <elver@google.com>
> 
> .. fuzzing, and lots of concurrent sigtrap_threads with this patch:
> 
> 	https://lore.kernel.org/all/20221011124534.84907-1-elver@google.com/
> 
> > Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> 
> My original patch also attributed Dmitry:
> 
> 	Reported-by: Dmitry Vyukov <dvyukov@google.com>
> 	Debugged-by: Dmitry Vyukov <dvyukov@google.com>
> 
> ... we all melted our brains on this one. :-)
> 
> Would be good to get the fix into one of the upcoming 6.1-rc.

Updated and yes, I'm planning on queueing this in perf/urgent the moment
-rc1 happens.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0VqbNDKIHUcC7Ha%40hirez.programming.kicks-ass.net.
