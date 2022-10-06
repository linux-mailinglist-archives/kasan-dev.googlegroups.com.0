Return-Path: <kasan-dev+bncBDBK55H2UQKRBM5S7OMQMGQEXOZHQTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id C52DB5F683F
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 15:33:40 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id m20-20020adfa3d4000000b0022e2fa93dd1sf534333wrb.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 06:33:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665063220; cv=pass;
        d=google.com; s=arc-20160816;
        b=KHKXoENVX3sp/00WmOOh6vSjXC309DA3BDlX9JqeFRiyNMZloypuhLj0pW3cwfL8Wy
         l5uXb+U54ChF5V7IL5E+0sy+QcMqV/LTtWN42nqhmSkZZhrbGxYrgY30Tyi7x0Ppinwz
         Qoa2ALAePVBLNiZG0gyX/LrGH1M7IzBQrqZ22I5MURBL3RJ4RnYGKNOu3T8oLym9xkBa
         JWy24XYMOD3fhLG2g/hF1LzUjKQsKDxHWLhLZc9zRnc8bqjmLef++GLD44lG0Im6B5Ld
         zZeGYKpZaKNk5S6OpyaD7pl9Sg8ItwcDbjGeS4Mma/fBXBUdhfp7g/K59LDJL+hh6GJx
         e6mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=kRhiT7deRlYYYNG89tu0ZqqXuTQxKmvv/LDCNyR5fwY=;
        b=FDmAwHbnwUA82xZ5dH0vF9tz0wxM8ycvdtj42j7DxtW8BXYgL8dlQi0avE61e2Wazq
         pbRwOnVjDpT/4z4KczZO36GBhkheyMKnuYo47ZN3MgcKNLvUThyMKbDgoqOEeiKYVHBT
         qy7Vk+QXScUTuucmLlLKlbJOp7SAJ+RUTlWX8ZaZsKs4sx7aIUnWrhQ1Nw6kC7NFHSlD
         q7Xe42XLuKO+maqr8/zsHq3yjGjVfZlCa6XIDrsjsnY+24/OaXad4PzS1d1bPb60TSOM
         sdb1Wjq7NdH9KqKsiPNVRpkWO3T6o1XqKx5+/jsn/a0KP/is5UmZgpV5l8FCwF3V1Qi+
         ziGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=IV9Ux0uK;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=kRhiT7deRlYYYNG89tu0ZqqXuTQxKmvv/LDCNyR5fwY=;
        b=W0FfZ5FFlf05EhdmwWesWB/uveKfL/LR7fvYcyf24NqlZzm+rEf/k207pSD4KyGWce
         lYJcozWATj8zE2HZxPUzucDdeCJyEZBkfdUhz042L1697lyn4gfUm5F/M0mwGbWEv2L4
         qidLFMVibA1HN7bcFDe81pC/WSTsmiYgio+SgRRNLDQsRJQuwjlu0EPVn9SdSzbgJ6ZL
         uW0xRJll/ieU/azfGh1KUzdqDRW5gydriuKszehOLFR+UDWd1c86EjelMSJCWCcR1adT
         OTbyzo7lcXu3RmYCrp0Jiz+MjfzxsD+6yGNRTswzEHJP7xqSC9tQQsR01iL2+LZlMBKb
         0vYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=kRhiT7deRlYYYNG89tu0ZqqXuTQxKmvv/LDCNyR5fwY=;
        b=OE72lcbXBb1s4xOdxViB72KHEr7icGMF6AcniLeOQiEFS4Xofi2W9382mDzzR47fup
         K2blDq9iMP17dNvb2xkPem2TERrIe/t7x0WqjLbkx0pEtXHvQ+uSLB7CVo7djjCw/YSw
         7G7nroO8tLDknTBUrzK9Vv+Wgmcwhwwkwr52fBYeL2c4RoR69YTvkwFm5IFGt8Gh8KLl
         6fVQcmDwVpShgM6xrkkpb6mjbVb1C3gbO5m8Ck8fw1Hsa9yN3cX0nRyw/phrkLnFqlgo
         yHLVd3xjDn+Xj3bL8mILQUyNgtE3Q7VXFCoKbmfaZEYlp9p9pQlcep82heGl/H8TCYE6
         VvIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0OZv0fWBBDFYY52HsNTub79RlPvcHZ8nyH3ULgkOqc3N76vY0a
	R+H9suEXk+VyCIQFnVAlN2A=
X-Google-Smtp-Source: AMsMyM62GbXrQOLqFyOwOi3rL5x6AqXN2zvAp48bhwv8RTIw/K7f8hFjLU4RDXsaYBLch3WxP7Y8DA==
X-Received: by 2002:a7b:c84f:0:b0:3b4:84c1:1e7 with SMTP id c15-20020a7bc84f000000b003b484c101e7mr7026542wml.12.1665063220191;
        Thu, 06 Oct 2022 06:33:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1f0a:b0:225:6559:3374 with SMTP id
 bv10-20020a0560001f0a00b0022565593374ls3522482wrb.2.-pod-prod-gmail; Thu, 06
 Oct 2022 06:33:39 -0700 (PDT)
X-Received: by 2002:a05:6000:4c:b0:22e:48e0:1a0b with SMTP id k12-20020a056000004c00b0022e48e01a0bmr3312777wrx.618.1665063218952;
        Thu, 06 Oct 2022 06:33:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665063218; cv=none;
        d=google.com; s=arc-20160816;
        b=BMKk8hDF2WeIrJ1LYjLa7e7bfH4gU5uxyaVClxEa71d/mvM+l8D7A74J5VzoOxKZ+2
         Y024hvB7y9Gq3l4AX05X9QrXeiyOgzcFcqEt01LAu7qkqMYtuIPyMJxeuNDku6g6a+B5
         wfF/u285rFN4kWbqK1ah8PLUEUEhdACaCLyMlSbgvLhXfOHH3G6gSU0ZZ+MUrchtDpRK
         SJEs3sL3LUBRBmtk8/GD7U6Q0VXiGYpPAGkD4mncikYUYCupHAfjR0KqFvYqE+1SBapn
         UOgm7D+SuscdOGCaB8pRMW6PpxPncks5RfrI9U+OjareDxEPAXb+DXTrBHeQ9YQrGW2/
         zPDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=3l6J/wVjyhOvfZR17W/xBB9YiH/VKXnAufH2rO+yGIQ=;
        b=FbG5ZoosiuI4gFOjcJSwDg9Z85nQT/UnluagyXDfdK+RqwGd4hMJFpCIhGzfzV1LIM
         DSNBhtdQjWyLsFn/zHbCuoCjhr6Aj/3QD0XSCJKjMYBGsAwiIg+Mote8yqDj5wOyroeB
         zJxrnWrixhUXe5JBMMwr8SDjFfUPJ4r+tUGAlXORwoVdKGcFA/XMYhnwRymJBTWvuHKw
         QCGCG4hxz0aeghg9lqNBsGjQQUf4Jt5IHMxmCLAy+Lvbc6Xh2HbAb31Veoe1H9WQObxb
         7janKgy4nCaRIVJFQf2in75yQlLkU9d9Thpgy5XkFqYPSWKIaPHCgqb+21Hs9y5N+vji
         WhYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=IV9Ux0uK;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id az23-20020a05600c601700b003b4924f599bsi235516wmb.2.2022.10.06.06.33.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Oct 2022 06:33:38 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1ogR0I-001Es0-UY; Thu, 06 Oct 2022 13:33:35 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id C9868300137;
	Thu,  6 Oct 2022 15:33:33 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 82560209DB0D1; Thu,  6 Oct 2022 15:33:33 +0200 (CEST)
Date: Thu, 6 Oct 2022 15:33:33 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: [PATCH] perf: Fix missing SIGTRAPs
Message-ID: <Yz7ZLaT4jW3Y9EYS@hirez.programming.kicks-ass.net>
References: <20220927121322.1236730-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220927121322.1236730-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=IV9Ux0uK;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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


OK, so the below seems to pass the concurrent sigtrap_threads test for
me and doesn't have that horrible irq_work_sync hackery.

Does it work for you too?

---
Subject: perf: Fix missing SIGTRAPs
From: Peter Zijlstra <peterz@infradead.org>
Date: Thu Oct  6 15:00:39 CEST 2022

Marco reported:

Due to the implementation of how SIGTRAP are delivered if
perf_event_attr::sigtrap is set, we've noticed 3 issues:

	1. Missing SIGTRAP due to a race with event_sched_out() (more
	   details below).

	2. Hardware PMU events being disabled due to returning 1 from
	   perf_event_overflow(). The only way to re-enable the event is
	   for user space to first "properly" disable the event and then
	   re-enable it.

	3. The inability to automatically disable an event after a
	   specified number of overflows via PERF_EVENT_IOC_REFRESH.

The worst of the 3 issues is problem (1), which occurs when a
pending_disable is "consumed" by a racing event_sched_out(), observed as
follows:

		CPU0			|	CPU1
	--------------------------------+---------------------------
	__perf_event_overflow()		|
	 perf_event_disable_inatomic()	|
	  pending_disable = CPU0	| ...
	  				| _perf_event_enable()
					|  event_function_call()
					|   task_function_call()
					|    /* sends IPI to CPU0 */
	<IPI>				| ...
	 __perf_event_enable()		+---------------------------
	  ctx_resched()
	   task_ctx_sched_out()
	    ctx_sched_out()
	     group_sched_out()
	      event_sched_out()
	       pending_disable = -1
	</IPI>
	<IRQ-work>
	 perf_pending_event()
	  perf_pending_event_disable()
	   /* Fails to send SIGTRAP because no pending_disable! */
	</IRQ-work>

In the above case, not only is that particular SIGTRAP missed, but also
all future SIGTRAPs because 'event_limit' is not reset back to 1.

To fix, rework pending delivery of SIGTRAP via IRQ-work by introduction
of a separate 'pending_sigtrap', no longer using 'event_limit' and
'pending_disable' for its delivery.

Additionally; and different to Marco's proposed patch:

 - recognise that pending_disable effectively duplicates oncpu for
   the case where it is set. As such, change the irq_work handler to
   use ->oncpu to target the event and use pending_* as boolean toggles.

 - observe that SIGTRAP targets the ctx->task, so the context switch
   optimization that carries contexts between tasks is invalid. If
   the irq_work were delayed enough to hit after a context switch the
   SIGTRAP would be delivered to the wrong task.

 - observe that if the event gets scheduled out
   (rotation/migration/context-switch/...) the irq-work would be
   insufficient to deliver the SIGTRAP when the event gets scheduled
   back in (the irq-work might still be pending on the old CPU).

   Therefore have event_sched_out() convert the pending sigtrap into a
   task_work which will deliver the signal at return_to_user.

Fixes: 97ba62b27867 ("perf: Add support for SIGTRAP on perf events")
Reported-by: Marco Elver <elver@google.com>
Debugged-by: Marco Elver <elver@google.com>
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 include/linux/perf_event.h  |   19 ++++-
 kernel/events/core.c        |  149 ++++++++++++++++++++++++++++++++------------
 kernel/events/ring_buffer.c |    2 
 3 files changed, 127 insertions(+), 43 deletions(-)

--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -736,11 +736,14 @@ struct perf_event {
 	struct fasync_struct		*fasync;
 
 	/* delayed work for NMIs and such */
-	int				pending_wakeup;
-	int				pending_kill;
-	int				pending_disable;
+	unsigned int			pending_wakeup;
+	unsigned int			pending_kill;
+	unsigned int			pending_disable;
+	unsigned int			pending_sigtrap;
 	unsigned long			pending_addr;	/* SIGTRAP */
-	struct irq_work			pending;
+	struct irq_work			pending_irq;
+	struct callback_head		pending_task;
+	unsigned int			pending_work;
 
 	atomic_t			event_limit;
 
@@ -857,6 +860,14 @@ struct perf_event_context {
 #endif
 	void				*task_ctx_data; /* pmu specific data */
 	struct rcu_head			rcu_head;
+
+	/*
+	 * Sum (event->pending_sigtrap + event->pending_work)
+	 *
+	 * The SIGTRAP is targeted at ctx->task, as such it won't do changing
+	 * that until the signal is delivered.
+	 */
+	local_t				nr_pending;
 };
 
 /*
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -54,6 +54,7 @@
 #include <linux/highmem.h>
 #include <linux/pgtable.h>
 #include <linux/buildid.h>
+#include <linux/task_work.h>
 
 #include "internal.h"
 
@@ -2268,11 +2269,28 @@ event_sched_out(struct perf_event *event
 	event->pmu->del(event, 0);
 	event->oncpu = -1;
 
-	if (READ_ONCE(event->pending_disable) >= 0) {
-		WRITE_ONCE(event->pending_disable, -1);
+	if (event->pending_disable) {
+		event->pending_disable = 0;
 		perf_cgroup_event_disable(event, ctx);
 		state = PERF_EVENT_STATE_OFF;
 	}
+
+	if (event->pending_sigtrap) {
+		event->pending_sigtrap = 0;
+		if (state == PERF_EVENT_STATE_OFF) {
+			/*
+			 * If we're racing with disabling the event; consume
+			 * the event to avoid it becoming asynchonous by
+			 * mistake.
+			 */
+			local_dec(&event->ctx->nr_pending);
+		} else {
+			WARN_ON_ONCE(event->pending_work);
+			event->pending_work = 1;
+			task_work_add(current, &event->pending_task, TWA_RESUME);
+		}
+	}
+
 	perf_event_set_state(event, state);
 
 	if (!is_software_event(event))
@@ -2424,7 +2442,7 @@ static void __perf_event_disable(struct
  * hold the top-level event's child_mutex, so any descendant that
  * goes to exit will block in perf_event_exit_event().
  *
- * When called from perf_pending_event it's OK because event->ctx
+ * When called from perf_pending_irq it's OK because event->ctx
  * is the current context on this CPU and preemption is disabled,
  * hence we can't get into perf_event_task_sched_out for this context.
  */
@@ -2463,9 +2481,8 @@ EXPORT_SYMBOL_GPL(perf_event_disable);
 
 void perf_event_disable_inatomic(struct perf_event *event)
 {
-	WRITE_ONCE(event->pending_disable, smp_processor_id());
-	/* can fail, see perf_pending_event_disable() */
-	irq_work_queue(&event->pending);
+	event->pending_disable = 1;
+	irq_work_queue(&event->pending_irq);
 }
 
 #define MAX_INTERRUPTS (~0ULL)
@@ -3420,11 +3437,22 @@ static void perf_event_context_sched_out
 		raw_spin_lock_nested(&next_ctx->lock, SINGLE_DEPTH_NESTING);
 		if (context_equiv(ctx, next_ctx)) {
 
+			perf_pmu_disable(pmu);
+
+			/* PMIs are disabled; ctx->nr_pending is stable. */
+			if (local_read(&ctx->nr_pending)) {
+				/*
+				 * Must not swap out ctx when there's pending
+				 * events that rely on the ctx->task relation.
+				 */
+				raw_spin_unlock(&next_ctx->lock);
+				rcu_read_unlock();
+				goto inside_switch;
+			}
+
 			WRITE_ONCE(ctx->task, next);
 			WRITE_ONCE(next_ctx->task, task);
 
-			perf_pmu_disable(pmu);
-
 			if (cpuctx->sched_cb_usage && pmu->sched_task)
 				pmu->sched_task(ctx, false);
 
@@ -3465,6 +3493,7 @@ static void perf_event_context_sched_out
 		raw_spin_lock(&ctx->lock);
 		perf_pmu_disable(pmu);
 
+inside_switch:
 		if (cpuctx->sched_cb_usage && pmu->sched_task)
 			pmu->sched_task(ctx, false);
 		task_ctx_sched_out(cpuctx, ctx, EVENT_ALL);
@@ -4931,7 +4960,7 @@ static void perf_addr_filters_splice(str
 
 static void _free_event(struct perf_event *event)
 {
-	irq_work_sync(&event->pending);
+	irq_work_sync(&event->pending_irq);
 
 	unaccount_event(event);
 
@@ -6431,7 +6460,7 @@ static void perf_sigtrap(struct perf_eve
 		return;
 
 	/*
-	 * perf_pending_event() can race with the task exiting.
+	 * perf_pending_irq() can race with the task exiting.
 	 */
 	if (current->flags & PF_EXITING)
 		return;
@@ -6440,23 +6469,33 @@ static void perf_sigtrap(struct perf_eve
 		      event->attr.type, event->attr.sig_data);
 }
 
-static void perf_pending_event_disable(struct perf_event *event)
+/*
+ * Deliver the pending work in-event-context or follow the context.
+ */
+static void __perf_pending_irq(struct perf_event *event)
 {
-	int cpu = READ_ONCE(event->pending_disable);
+	int cpu = READ_ONCE(event->oncpu);
 
+	/*
+	 * If the event isn't running; we done. event_sched_out() will have
+	 * taken care of things.
+	 */
 	if (cpu < 0)
 		return;
 
+	/*
+	 * Yay, we hit home and are in the context of the event.
+	 */
 	if (cpu == smp_processor_id()) {
-		WRITE_ONCE(event->pending_disable, -1);
-
-		if (event->attr.sigtrap) {
+		if (event->pending_sigtrap) {
+			event->pending_sigtrap = 0;
+			local_dec(&event->ctx->nr_pending);
 			perf_sigtrap(event);
-			atomic_set_release(&event->event_limit, 1); /* rearm event */
-			return;
 		}
-
-		perf_event_disable_local(event);
+		if (event->pending_disable) {
+			event->pending_disable = 0;
+			perf_event_disable_local(event);
+		}
 		return;
 	}
 
@@ -6476,31 +6515,56 @@ static void perf_pending_event_disable(s
 	 *				  irq_work_queue(); // FAILS
 	 *
 	 *  irq_work_run()
-	 *    perf_pending_event()
+	 *    perf_pending_irq()
 	 *
 	 * But the event runs on CPU-B and wants disabling there.
 	 */
-	irq_work_queue_on(&event->pending, cpu);
+	irq_work_queue_on(&event->pending_irq, cpu);
 }
 
-static void perf_pending_event(struct irq_work *entry)
+static void perf_pending_irq(struct irq_work *entry)
 {
-	struct perf_event *event = container_of(entry, struct perf_event, pending);
+	struct perf_event *event = container_of(entry, struct perf_event, pending_irq);
 	int rctx;
 
-	rctx = perf_swevent_get_recursion_context();
 	/*
 	 * If we 'fail' here, that's OK, it means recursion is already disabled
 	 * and we won't recurse 'further'.
 	 */
+	rctx = perf_swevent_get_recursion_context();
 
-	perf_pending_event_disable(event);
-
+	/*
+	 * The wakeup isn't bound to the context of the event -- it can happen
+	 * irrespective of where the event is.
+	 */
 	if (event->pending_wakeup) {
 		event->pending_wakeup = 0;
 		perf_event_wakeup(event);
 	}
 
+	__perf_pending_irq(event);
+
+	if (rctx >= 0)
+		perf_swevent_put_recursion_context(rctx);
+}
+
+static void perf_pending_task(struct callback_head *head)
+{
+	struct perf_event *event = container_of(head, struct perf_event, pending_task);
+	int rctx;
+
+	/*
+	 * If we 'fail' here, that's OK, it means recursion is already disabled
+	 * and we won't recurse 'further'.
+	 */
+	rctx = perf_swevent_get_recursion_context();
+
+	if (event->pending_work) {
+		event->pending_work = 0;
+		local_dec(&event->ctx->nr_pending);
+		perf_sigtrap(event);
+	}
+
 	if (rctx >= 0)
 		perf_swevent_put_recursion_context(rctx);
 }
@@ -9179,8 +9243,8 @@ int perf_event_account_interrupt(struct
  */
 
 static int __perf_event_overflow(struct perf_event *event,
-				   int throttle, struct perf_sample_data *data,
-				   struct pt_regs *regs)
+				 int throttle, struct perf_sample_data *data,
+				 struct pt_regs *regs)
 {
 	int events = atomic_read(&event->event_limit);
 	int ret = 0;
@@ -9203,24 +9267,36 @@ static int __perf_event_overflow(struct
 	if (events && atomic_dec_and_test(&event->event_limit)) {
 		ret = 1;
 		event->pending_kill = POLL_HUP;
-		event->pending_addr = data->addr;
-
 		perf_event_disable_inatomic(event);
 	}
 
+	if (event->attr.sigtrap) {
+		/*
+		 * Should not be able to return to user space without processing
+		 * pending_sigtrap (kernel events can overflow multiple times).
+		 */
+		WARN_ON_ONCE(event->pending_sigtrap && event->attr.exclude_kernel);
+		if (!event->pending_sigtrap) {
+			event->pending_sigtrap = 1;
+			local_inc(&event->ctx->nr_pending);
+		}
+		event->pending_addr = data->addr;
+		irq_work_queue(&event->pending_irq);
+	}
+
 	READ_ONCE(event->overflow_handler)(event, data, regs);
 
 	if (*perf_event_fasync(event) && event->pending_kill) {
 		event->pending_wakeup = 1;
-		irq_work_queue(&event->pending);
+		irq_work_queue(&event->pending_irq);
 	}
 
 	return ret;
 }
 
 int perf_event_overflow(struct perf_event *event,
-			  struct perf_sample_data *data,
-			  struct pt_regs *regs)
+			struct perf_sample_data *data,
+			struct pt_regs *regs)
 {
 	return __perf_event_overflow(event, 1, data, regs);
 }
@@ -11528,8 +11604,8 @@ perf_event_alloc(struct perf_event_attr
 
 
 	init_waitqueue_head(&event->waitq);
-	event->pending_disable = -1;
-	init_irq_work(&event->pending, perf_pending_event);
+	init_irq_work(&event->pending_irq, perf_pending_irq);
+	init_task_work(&event->pending_task, perf_pending_task);
 
 	mutex_init(&event->mmap_mutex);
 	raw_spin_lock_init(&event->addr_filters.lock);
@@ -11551,9 +11627,6 @@ perf_event_alloc(struct perf_event_attr
 	if (parent_event)
 		event->event_caps = parent_event->event_caps;
 
-	if (event->attr.sigtrap)
-		atomic_set(&event->event_limit, 1);
-
 	if (task) {
 		event->attach_state = PERF_ATTACH_TASK;
 		/*
--- a/kernel/events/ring_buffer.c
+++ b/kernel/events/ring_buffer.c
@@ -22,7 +22,7 @@ static void perf_output_wakeup(struct pe
 	atomic_set(&handle->rb->poll, EPOLLIN);
 
 	handle->event->pending_wakeup = 1;
-	irq_work_queue(&handle->event->pending);
+	irq_work_queue(&handle->event->pending_irq);
 }
 
 /*

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz7ZLaT4jW3Y9EYS%40hirez.programming.kicks-ass.net.
