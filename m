Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3W5ZWMQMGQEI2HFOQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 818635ECF71
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 23:45:19 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id z15-20020ac25def000000b004a060fcd1d5sf3903133lfq.7
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 14:45:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664315119; cv=pass;
        d=google.com; s=arc-20160816;
        b=QLzRqVk/ysKxD7focT9BbxAm4yz/RYP84QVGkeGOt6BvkFKBYAG+I5K4YHY987Agto
         0QemEgxfXNLQOHygxodbdO9jaCpVSWpVNT+ncaQRQj/py5sOCOIKtxbwuGDv6F+xsVT/
         aneLtzJnxZ4s/nCxTYQZOXNChG6l0S8jE1uAjwbmn/5dSZR9FET6lt7JAIE3+YdNqNt9
         jn6x+/XKX9jbOAOdtjsJ44Kz8qajJZxWNo/ReYftA2A6u0pdklFiNSiZV/bvDwABzY5k
         MftQrJcUn73KLIYBDbgtRQwRN0Ag+S5tctELv+0miThiJcKsKmBBvfz3uqsPxJ1p3yeG
         rkVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=CK8ll6iz7QslRkC8LLe7qiki1pK0rwH3rnN0J0TpvgA=;
        b=zqFTLWNKElSTR1SQHIZn3X6q4KbjWyP/GVrwknaHLVx/XgvoEHKEcYCbrLEdWhwBDV
         tOGT4O7/Gx9kxVX0oK6MzWmobp7BH5m8qlhZhETOEs/1B/C59mtZzwbxqlR/xUcVnRHz
         XbL4o7cken5SRr6ok3ZMekUtovyDeBc/uEc7YFI+pCZFZg/4RGXGl2M6HH6uq5EbyJnK
         hJQ/0HPPGZVh1q+Ob9/i8q4qQhvx6HP844aBRI3GRTlG89wOABHEkmoh3Kw94JaI3Rvn
         Thy3oYVtwMzU+lQd71EdniNozv3b796tkXwmQM+SSIVsreYVN2eZlnXS3FWV8mdUu1xC
         1a1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QS5Fct4O;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date;
        bh=CK8ll6iz7QslRkC8LLe7qiki1pK0rwH3rnN0J0TpvgA=;
        b=GLKEVpx3BuIe6+cNZtDGzuxcwKHsRVLa95qqE3SoVwuvvuQNAygfqQeY3CLJ1RhQo9
         D9r+I0aVJaBnv8jf5bkPxF1NNBmqb0gksHSnBcISJw5d5CtlP5kOERHwRhSJFuCTvW40
         0sElb69pC7n09Uk19Z5HNkwu4OlGk3u32mX33imeqA9dD4wImq1sXMWRrGQHhDSfWoNq
         0uNRYdBEA05avhlJRgn16XoCx8FxMPmy7yE2TysEB99gZOjIpYucIyzN9wIFXPyBSqaQ
         3DVmCzme/dkfIGHHRS96dP13J+C6IS1lcyvTmmPbpyEwoFGAu/3ipeo7gCl3QBzZPgpG
         PZhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=CK8ll6iz7QslRkC8LLe7qiki1pK0rwH3rnN0J0TpvgA=;
        b=0F6kOIsutaK8hsKxafPYt2y/QF4Gc3hrEFvPnpX35zKnL8UOa+qGAe0effq+hGbnpM
         +rVNGlxaWGqZgR9NANF2fOzImvPzLti2TSMYF7l8ZCcyRpyp/+sXxoyv4sFBxMIreYZ5
         fDI5+zmaNn7apOmSC9hsYxS96t0udFLsXoaAte/+Hm97Ab18teOmtt7v/YHUjYtaeVZz
         CBe0Q2bCTen3tFBh37CPVyJyo1NpuSZpz8PTaW0NzVEa/rIa0/IXgnsIxC8WMPgG+dIG
         edrA59RfeQg+M4L9u5zqZPgzNDerT1U2sspeTMHHPUHHYJ1vvzEI0ZY+OCTkTvoEqFxE
         sszA==
X-Gm-Message-State: ACrzQf2PFr9fVRwK5reXKkm7MFzd/tBTCtv0UiY8WaC/ekg+u7dTPcEn
	yv/BtsetZ4BjRnZbgx2+8Zs=
X-Google-Smtp-Source: AMsMyM5lzXEfX5ViMBKuREMGrHKoYBcAXdlz44cAttqQB6/rvU7bt6YF3+zOa9cNZoFe8kyBgzMMzQ==
X-Received: by 2002:a19:f716:0:b0:498:aa7f:32f7 with SMTP id z22-20020a19f716000000b00498aa7f32f7mr12583036lfe.3.1664315118914;
        Tue, 27 Sep 2022 14:45:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc06:0:b0:26b:ff81:b7cb with SMTP id b6-20020a2ebc06000000b0026bff81b7cbls704638ljf.6.-pod-prod-gmail;
 Tue, 27 Sep 2022 14:45:17 -0700 (PDT)
X-Received: by 2002:a05:651c:383:b0:26c:4e23:a4bb with SMTP id e3-20020a05651c038300b0026c4e23a4bbmr10439938ljp.530.1664315117430;
        Tue, 27 Sep 2022 14:45:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664315117; cv=none;
        d=google.com; s=arc-20160816;
        b=ba8aTwmINcDE7hKsQmrI8GMhOPQWkAm0zKvzgCU1kT4Jd3IfcekySWXA+LnEfgwvIH
         gtjPFm9RnvWhTbb9exHh+Y5vvWDq3ID6a5E4jt2hAy9U6ChxUJ1jVDpzZcKhtIVRggMW
         STkXo6O44Ccr5cJVJBRtTvKVTDe/yEMgA88oLPXv+HK24wUaVkH7AH3QBO+k2GFCpnR0
         mhwwWxRCW36GsNk+YOuKOQm56dwYXaofeUUWuKz1zeUBzXk0yatI7tZ1W01dgiQt3BCU
         ODnDXQWt4TcFuYtUZfiOO0QpQ+koTFJt65T9/sqSLwxTowTQ5mUHcFBpAQyWrHYNp0s7
         5GwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=OE70BMzWV5KkigIfgdUJ3KWiPY5Ag5voOlsKOHSQbIc=;
        b=kkjVfn/AH++qEkGnR1FwgcMnlK/6z1zvwi5AX0JdUVcLjKl5dl2RgbVAuaSNkM5Dda
         YQLbcd6iVcvyGwGzKZBm7K2g8ZuehEY31ATsVLzb133fNwKWR8Fg00fOKwpbMHK0mx5d
         3D9pG+0xI3/XjFh7/hfQm9ROioCg/nIQurrR5ddkpq2PIkcLqpKbuhZYrWe+xIK7LqTM
         kSdeQs06MS1d7AISnubTdBd/dfeQwaqeZJ5LYLOF5Lm8xsezcVSb7gWHXDtS7SIsx3Ge
         k2Z3QIfbOeStp3c6KsbuXsni9n9S5iM+kBSb4dGDFx3djLV5n/E7M0Z+uz944zM/rf4+
         m9rA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QS5Fct4O;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x630.google.com (mail-ej1-x630.google.com. [2a00:1450:4864:20::630])
        by gmr-mx.google.com with ESMTPS id 12-20020ac25f4c000000b00492f1480d0fsi126958lfz.13.2022.09.27.14.45.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Sep 2022 14:45:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::630 as permitted sender) client-ip=2a00:1450:4864:20::630;
Received: by mail-ej1-x630.google.com with SMTP id b2so517692eja.6
        for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 14:45:17 -0700 (PDT)
X-Received: by 2002:a17:906:4ac1:b0:780:3448:ff06 with SMTP id u1-20020a1709064ac100b007803448ff06mr24753758ejt.403.1664315116881;
        Tue, 27 Sep 2022 14:45:16 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:dbbc:9ea2:a5f7:571e])
        by smtp.gmail.com with ESMTPSA id h1-20020a056402094100b00457e20cb2e4sm232518edz.48.2022.09.27.14.45.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Sep 2022 14:45:16 -0700 (PDT)
Date: Tue, 27 Sep 2022 23:45:09 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] perf: Fix missing SIGTRAPs due to pending_disable abuse
Message-ID: <YzNu5bgASbuVi0S3@elver.google.com>
References: <20220927121322.1236730-1-elver@google.com>
 <YzM/BUsBnX18NoOG@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YzM/BUsBnX18NoOG@hirez.programming.kicks-ass.net>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QS5Fct4O;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::630 as
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

On Tue, Sep 27, 2022 at 08:20PM +0200, Peter Zijlstra wrote:
> On Tue, Sep 27, 2022 at 02:13:22PM +0200, Marco Elver wrote:
> > Due to the implementation of how SIGTRAP are delivered if
> > perf_event_attr::sigtrap is set, we've noticed 3 issues:
> > 
> > 	1. Missing SIGTRAP due to a race with event_sched_out() (more
> > 	   details below).
> > 
> > 	2. Hardware PMU events being disabled due to returning 1 from
> > 	   perf_event_overflow(). The only way to re-enable the event is
> > 	   for user space to first "properly" disable the event and then
> > 	   re-enable it.
> > 
> > 	3. The inability to automatically disable an event after a
> > 	   specified number of overflows via PERF_EVENT_IOC_REFRESH.
> > 
> > The worst of the 3 issues is problem (1), which occurs when a
> > pending_disable is "consumed" by a racing event_sched_out(), observed as
> > follows:
> > 
> > 		CPU0			| 	CPU1
> > 	--------------------------------+---------------------------
> > 	__perf_event_overflow()		|
> > 	 perf_event_disable_inatomic()	|
> > 	  pending_disable = CPU0	| ...
> > 	  				| _perf_event_enable()
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
> > During testing, this also revealed several more possible races between
> > reschedules and pending IRQ work; see code comments for details.
> 
> Perhaps use task_work_add() for this case? That runs on the
> return-to-user path, so then it doesn't matter how many reschedules
> happen in between.

Hmm, I tried the below (on top of this patch), but then all the tests
fail (including tools/testing/selftests/perf_events/sigtrap_threads.c)
because of lots of missing SIGTRAP. (The missing SIGTRAP happen with or
without the kernel/entry/ change.)

So something is wrong with task_work, and the irq_work solution thus far
is more robust (ran many hours of tests and fuzzing without failure).

Thoughts?

------ >8 ------

diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
index dff3430844a2..928fb9e2b655 100644
--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -743,7 +743,7 @@ struct perf_event {
 	int				pending_sigtrap;
 	unsigned long			pending_addr;	/* SIGTRAP */
 	struct irq_work			pending;
-	struct irq_work			pending_resched;
+	struct callback_head		pending_twork;
 
 	atomic_t			event_limit;
 
diff --git a/kernel/entry/common.c b/kernel/entry/common.c
index 063068a9ea9b..7cacaefc97fe 100644
--- a/kernel/entry/common.c
+++ b/kernel/entry/common.c
@@ -162,12 +162,12 @@ static unsigned long exit_to_user_mode_loop(struct pt_regs *regs,
 		if (ti_work & _TIF_PATCH_PENDING)
 			klp_update_patch_state(current);
 
-		if (ti_work & (_TIF_SIGPENDING | _TIF_NOTIFY_SIGNAL))
-			arch_do_signal_or_restart(regs);
-
 		if (ti_work & _TIF_NOTIFY_RESUME)
 			resume_user_mode_work(regs);
 
+		if (ti_work & (_TIF_SIGPENDING | _TIF_NOTIFY_SIGNAL))
+			arch_do_signal_or_restart(regs);
+
 		/* Architecture specific TIF work */
 		arch_exit_to_user_mode_work(regs, ti_work);
 
diff --git a/kernel/events/core.c b/kernel/events/core.c
index 007a87c1599c..7f93dd91d572 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -17,6 +17,7 @@
 #include <linux/poll.h>
 #include <linux/slab.h>
 #include <linux/hash.h>
+#include <linux/task_work.h>
 #include <linux/tick.h>
 #include <linux/sysfs.h>
 #include <linux/dcache.h>
@@ -2527,14 +2528,6 @@ event_sched_in(struct perf_event *event,
 	if (event->attr.exclusive)
 		cpuctx->exclusive = 1;
 
-	if (event->pending_sigtrap) {
-		/*
-		 * The task and event might have been moved to another CPU:
-		 * queue another IRQ work. See perf_pending_event_sigtrap().
-		 */
-		WARN_ON_ONCE(!irq_work_queue(&event->pending_resched));
-	}
-
 out:
 	perf_pmu_enable(event->pmu);
 
@@ -4942,11 +4935,13 @@ static bool exclusive_event_installable(struct perf_event *event,
 
 static void perf_addr_filters_splice(struct perf_event *event,
 				       struct list_head *head);
+static void perf_pending_event_task_work(struct callback_head *work);
 
 static void _free_event(struct perf_event *event)
 {
 	irq_work_sync(&event->pending);
-	irq_work_sync(&event->pending_resched);
+	if (event->hw.target)
+		task_work_cancel(event->hw.target, perf_pending_event_task_work);
 
 	unaccount_event(event);
 
@@ -6438,15 +6433,7 @@ void perf_event_wakeup(struct perf_event *event)
 static void perf_sigtrap(struct perf_event *event)
 {
 	/*
-	 * We'd expect this to only occur if the irq_work is delayed and either
-	 * ctx->task or current has changed in the meantime. This can be the
-	 * case on architectures that do not implement arch_irq_work_raise().
-	 */
-	if (WARN_ON_ONCE(event->ctx->task != current))
-		return;
-
-	/*
-	 * perf_pending_event() can race with the task exiting.
+	 * Can be called while the task is exiting.
 	 */
 	if (current->flags & PF_EXITING)
 		return;
@@ -6455,35 +6442,22 @@ static void perf_sigtrap(struct perf_event *event)
 		      event->attr.type, event->attr.sig_data);
 }
 
-static void perf_pending_event_sigtrap(struct perf_event *event)
+static void perf_pending_event_task_work(struct callback_head *work)
 {
-	if (!event->pending_sigtrap)
-		return;
+	struct perf_event *event = container_of(work, struct perf_event, pending_twork);
+	int rctx;
 
-	/*
-	 * If we're racing with disabling of the event, consume pending_sigtrap
-	 * and don't send the SIGTRAP. This avoids potentially delaying a signal
-	 * indefinitely (oncpu mismatch) until the event is enabled again, which
-	 * could happen after already returning to user space; in that case the
-	 * signal would erroneously become asynchronous.
-	 */
-	if (event->state == PERF_EVENT_STATE_OFF) {
+	preempt_disable_notrace();
+	rctx = perf_swevent_get_recursion_context();
+
+	if (event->pending_sigtrap) {
 		event->pending_sigtrap = 0;
-		return;
+		perf_sigtrap(event);
 	}
 
-	/*
-	 * Only process this pending SIGTRAP if this IRQ work is running on the
-	 * right CPU: the scheduler is able to run before the IRQ work, which
-	 * moved the task to another CPU. In event_sched_in() another IRQ work
-	 * is scheduled, so that the signal is not lost; given the kernel has
-	 * not yet returned to user space, the signal remains synchronous.
-	 */
-	if (READ_ONCE(event->oncpu) != smp_processor_id())
-		return;
-
-	event->pending_sigtrap = 0;
-	perf_sigtrap(event);
+	if (rctx >= 0)
+		perf_swevent_put_recursion_context(rctx);
+	preempt_enable_notrace();
 }
 
 static void perf_pending_event_disable(struct perf_event *event)
@@ -6533,7 +6507,6 @@ static void perf_pending_event(struct irq_work *entry)
 	 * and we won't recurse 'further'.
 	 */
 
-	perf_pending_event_sigtrap(event);
 	perf_pending_event_disable(event);
 
 	if (event->pending_wakeup) {
@@ -6545,26 +6518,6 @@ static void perf_pending_event(struct irq_work *entry)
 		perf_swevent_put_recursion_context(rctx);
 }
 
-/*
- * If handling of a pending action must occur before returning to user space,
- * and it is possible to reschedule an event (to another CPU) with pending
- * actions, where the moved-from CPU may not yet have run event->pending (and
- * irq_work_queue() would fail on reuse), we'll use a separate IRQ work that
- * runs perf_pending_event_resched().
- */
-static void perf_pending_event_resched(struct irq_work *entry)
-{
-	struct perf_event *event = container_of(entry, struct perf_event, pending_resched);
-	int rctx;
-
-	rctx = perf_swevent_get_recursion_context();
-
-	perf_pending_event_sigtrap(event);
-
-	if (rctx >= 0)
-		perf_swevent_put_recursion_context(rctx);
-}
-
 #ifdef CONFIG_GUEST_PERF_EVENTS
 struct perf_guest_info_callbacks __rcu *perf_guest_cbs;
 
@@ -9274,7 +9227,7 @@ static int __perf_event_overflow(struct perf_event *event,
 		WARN_ON_ONCE(event->pending_sigtrap && event->attr.exclude_kernel);
 		event->pending_sigtrap = 1;
 		event->pending_addr = data->addr;
-		irq_work_queue(&event->pending);
+		task_work_add(current, &event->pending_twork, TWA_RESUME);
 	}
 
 	READ_ONCE(event->overflow_handler)(event, data, regs);
@@ -11599,7 +11552,7 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
 	init_waitqueue_head(&event->waitq);
 	event->pending_disable = -1;
 	init_irq_work(&event->pending, perf_pending_event);
-	init_irq_work(&event->pending_resched, perf_pending_event_resched);
+	init_task_work(&event->pending_twork, perf_pending_event_task_work);
 
 	mutex_init(&event->mmap_mutex);
 	raw_spin_lock_init(&event->addr_filters.lock);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YzNu5bgASbuVi0S3%40elver.google.com.
