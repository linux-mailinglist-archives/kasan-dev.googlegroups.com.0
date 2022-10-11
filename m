Return-Path: <kasan-dev+bncBDBK55H2UQKRBXV5SSNAMGQEXE2AJ2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E3975FADA2
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 09:44:32 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id bn39-20020a05651c17a700b0026309143eeesf5244781ljb.4
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 00:44:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665474271; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z8p6fn8g+aE1govvGPQIFVctfsNkTIhp2a7VM/hY0CYhXTRqmL+lZWyjH9Nw5ITGfO
         DYIJYQnct1BYrF1yr46wEeo//7CJvuwmXwst6Rzlogm5iKP5MTJfJ0t+AlRBmgiuP8d8
         qBEXg4f4hSgBVrwCgQ8d1KU5Djxx434x6gL2bqbFqTE25Pl+eLxsFXDfKYPaE98r0k1B
         JKWHqPK0wVWEe4rX8GAOJbKVUftrocMnFXoaD7tcv4/vjdKvTthmNnyEc6VpaBwmmuRr
         RY/8YGe31vw4jkUXvhCzUEASvraI0c/Ns+jmpbL875TTEDCL4+JAKBxru4m7p6QYly6s
         WgsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xh4nBp/H26Fpp3t5P0jAasIrnP7ifYap92GBEnkUUcM=;
        b=rhSyqCWkGTzndS5yKIy5np7DrC3sCY/Nq6kVW36gz7ssDV9ci7K49MQLo7oVt5Lvtk
         L99N27xHUU4MiS26SzDJU3AnEJTP4WsQv4NCQ38HDg0dXZEIfBwt1GEUN2oYytoZ2O61
         0d9T11sliGi8CpR/gqDUJNWLQB2CDII9SOibn76310Ceze6lH/cBqxOvo+W2haZhGhZY
         evgWCqyraNqczsNgGEbt8cS/SlQsMILVRekCuonMCzh8E9qWrRl32LZ9LuYPR6Wx5DWX
         J22OhP3PXQvzo0djkTgRwDBmKutWz1LPrFbRAYndMzIz/Wza6xI6NV4WkyZOD4sFxgTj
         Il7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=YLMoLzy0;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xh4nBp/H26Fpp3t5P0jAasIrnP7ifYap92GBEnkUUcM=;
        b=hS52z4WvsmpnkTcNw/NTVOBWJCWuXZYqZBF+3YIcwXVd2N8EsvtLfnTBmuxpoxHAwE
         Cjhw42WU9DG7XjwkQHg6pqnXESFC5CxrRUBVzULHk51OSljim2/CLtC0ll/hhYGNCM2p
         tvVudEGkO+rvlljIcZpGGPW0zaBl6jEMPFmCm+GWfMpXvJg/LG5oyt0uHae1V9/jcky6
         zNT+Ymj87COblj7D/oRZy+TB3Xu2pHZj5jx1pbWkqPBzcsq7SvGZ5nEWJF/hwY3j6xw8
         6ffVvpa7qBnKeukznM0sezZNkpX4OXsbGCfsJ+VyXwcEOVl9QyFsS/MXoc9oPn5KzD74
         ZHdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xh4nBp/H26Fpp3t5P0jAasIrnP7ifYap92GBEnkUUcM=;
        b=Z5AfAz27UXA0+S39uk0ACHfYnxndb9R87OmcPGeVCyd8228LhjHdPX1BX1rnldpg8t
         dgM8hbdKdg5R7NFmvIUd45PqmQsYhDdofI5Nn26LiX7F5WnPx1ltBVc1ohdTzT9IglIj
         eUdVmC+dmUPByhKnZYcna8x3uZzvujNUGrLHu1aCQd5kzSqffOqDf6mF6fdhObtotdVh
         ihsan3zpijv4Mi4v6dLfZuQqFoRgvdzNZBApJeAByTazd89CUNpluSZGbMN2xl7iDH34
         z5zXZVmNUWQAsRjjodHiHkwasFqR2bhbVdbB3JNGT0zdLCGsPiUMw2rxjK8k5yz7HwXm
         fx0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf27I93Q8jJWVWJb5p9ZYWbuYJnlTIDQX1OzqMdpooHhLgbzIY5A
	y2vk10Jqec3OkVfUQOQn9Fw=
X-Google-Smtp-Source: AMsMyM4YmsJXs4xCBzGA0OqS05k7vadQK1lKq29QVzvCVLyJ6kX5NyXMZlhcr4BYM217eYkGSb95ng==
X-Received: by 2002:a2e:a22b:0:b0:26d:fab0:13c9 with SMTP id i11-20020a2ea22b000000b0026dfab013c9mr8341702ljm.201.1665474271342;
        Tue, 11 Oct 2022 00:44:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3689:b0:494:6c7d:cf65 with SMTP id
 d9-20020a056512368900b004946c7dcf65ls2115070lfs.2.-pod-prod-gmail; Tue, 11
 Oct 2022 00:44:29 -0700 (PDT)
X-Received: by 2002:ac2:4f03:0:b0:496:e4:4d16 with SMTP id k3-20020ac24f03000000b0049600e44d16mr7443187lfr.250.1665474269685;
        Tue, 11 Oct 2022 00:44:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665474269; cv=none;
        d=google.com; s=arc-20160816;
        b=m9+/0vmPNZ3rm3vtTndBEmNd6aPKKc2iDLWV3tnaYecVNJFMx+AoDcWqzZtum/2KUy
         Hd5x9kFUsNBPPCFLTIAUV6XW+8m9+7nVdIdlPtkRm+BgcZ5aG4mj1W2wY/cec4nOtmtF
         M9b/vIIEE5/1xl+hwuP76aJEGFNJRNw8fg5g4VjN6qMZHa0QDwF8Gp700nHwzLOsGJ03
         08x9Q/M/+nswf2NmMzAJ6HpsZPlqqKXH53lgxlanzaQve/1qK+aPFMltNYnl+3meB3BM
         qiq5v56NbFp1X5/xvx9bzZyOyz33/e2L9GkXaZuhitg5DCfFQpQyrnqVsYHOVT+MAG8b
         dK1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=K6zHlNPbIu5HIi4rKOHlKec/F8zGlMfONp48Fkqjs+A=;
        b=Qg/qMHvSYNdqKPI1WRKiJpaR1rbwaHBWtw+n8prK1ccGHytGbhEnfdhErPgUVEKdHq
         DL2hU9yQ6hJAyTaCl86tH52UYnyl5q5khQZ3XpgrjTnn5JqSYjPKBXIDk5Jti1XJ0GS3
         cQcJKhDAG2Uzz1Gte52UPiI6DgZfdyMJ5V+WzESmh0F04MAIRJ56e6gQzocqH0unM9Zz
         u2gpLuJSFyXDrQpAicBQvEWpDN7YrN/XFZqRRz7yD57KTCmZGRB4GnHTSJHhVqKS9jnt
         rN3DNUKkAM9prkLhwbUz18aFCgyX0RYo+eBDvAhyTIx9BksVkY5CchgBp3ROb7peDyHA
         gH7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=YLMoLzy0;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id k11-20020a05651210cb00b00492ea683e72si350403lfg.2.2022.10.11.00.44.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Oct 2022 00:44:29 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oi9w9-002WMW-PU; Tue, 11 Oct 2022 07:44:26 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 7D916300209;
	Tue, 11 Oct 2022 09:44:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 52B8920D7E1AB; Tue, 11 Oct 2022 09:44:24 +0200 (CEST)
Date: Tue, 11 Oct 2022 09:44:24 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: [PATCH v2] perf: Fix missing SIGTRAPs
Message-ID: <Y0Ue2L5CsaQwDrEs@hirez.programming.kicks-ass.net>
References: <20220927121322.1236730-1-elver@google.com>
 <Yz7ZLaT4jW3Y9EYS@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Yz7ZLaT4jW3Y9EYS@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=YLMoLzy0;
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

Subject: perf: Fix missing SIGTRAPs
From: Peter Zijlstra <peterz@infradead.org>
Date: Thu Oct 6 15:00:39 CEST 2022

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
pending_disable is "consumed" by a racing event_sched_out(), observed
as follows:

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
 kernel/events/core.c        |  151 ++++++++++++++++++++++++++++++++------------
 kernel/events/ring_buffer.c |    2 
 3 files changed, 129 insertions(+), 43 deletions(-)

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
 
@@ -2268,11 +2269,26 @@ event_sched_out(struct perf_event *event
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
+		bool dec = true;
+
+		event->pending_sigtrap = 0;
+		if (state != PERF_EVENT_STATE_OFF &&
+		    !event->pending_work) {
+			event->pending_work = 1;
+			dec = false;
+			task_work_add(current, &event->pending_task, TWA_RESUME);
+		}
+		if (dec)
+			local_dec(&event->ctx->nr_pending);
+	}
+
 	perf_event_set_state(event, state);
 
 	if (!is_software_event(event))
@@ -2424,7 +2440,7 @@ static void __perf_event_disable(struct
  * hold the top-level event's child_mutex, so any descendant that
  * goes to exit will block in perf_event_exit_event().
  *
- * When called from perf_pending_event it's OK because event->ctx
+ * When called from perf_pending_irq it's OK because event->ctx
  * is the current context on this CPU and preemption is disabled,
  * hence we can't get into perf_event_task_sched_out for this context.
  */
@@ -2463,9 +2479,8 @@ EXPORT_SYMBOL_GPL(perf_event_disable);
 
 void perf_event_disable_inatomic(struct perf_event *event)
 {
-	WRITE_ONCE(event->pending_disable, smp_processor_id());
-	/* can fail, see perf_pending_event_disable() */
-	irq_work_queue(&event->pending);
+	event->pending_disable = 1;
+	irq_work_queue(&event->pending_irq);
 }
 
 #define MAX_INTERRUPTS (~0ULL)
@@ -3420,11 +3435,23 @@ static void perf_event_context_sched_out
 		raw_spin_lock_nested(&next_ctx->lock, SINGLE_DEPTH_NESTING);
 		if (context_equiv(ctx, next_ctx)) {
 
+			perf_pmu_disable(pmu);
+
+			/* PMIs are disabled; ctx->nr_pending is stable. */
+			if (local_read(&ctx->nr_pending) ||
+			    local_read(&next_ctx->nr_pending)) {
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
 
@@ -3465,6 +3492,7 @@ static void perf_event_context_sched_out
 		raw_spin_lock(&ctx->lock);
 		perf_pmu_disable(pmu);
 
+inside_switch:
 		if (cpuctx->sched_cb_usage && pmu->sched_task)
 			pmu->sched_task(ctx, false);
 		task_ctx_sched_out(cpuctx, ctx, EVENT_ALL);
@@ -4931,7 +4959,7 @@ static void perf_addr_filters_splice(str
 
 static void _free_event(struct perf_event *event)
 {
-	irq_work_sync(&event->pending);
+	irq_work_sync(&event->pending_irq);
 
 	unaccount_event(event);
 
@@ -6431,7 +6459,8 @@ static void perf_sigtrap(struct perf_eve
 		return;
 
 	/*
-	 * perf_pending_event() can race with the task exiting.
+	 * Both perf_pending_task() and perf_pending_irq() can race with the
+	 * task exiting.
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
 			perf_sigtrap(event);
-			atomic_set_release(&event->event_limit, 1); /* rearm event */
-			return;
+			local_dec(&event->ctx->nr_pending);
+		}
+		if (event->pending_disable) {
+			event->pending_disable = 0;
+			perf_event_disable_local(event);
 		}
-
-		perf_event_disable_local(event);
 		return;
 	}
 
@@ -6476,35 +6515,62 @@ static void perf_pending_event_disable(s
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
 	if (rctx >= 0)
 		perf_swevent_put_recursion_context(rctx);
 }
 
+static void perf_pending_task(struct callback_head *head)
+{
+	struct perf_event *event = container_of(head, struct perf_event, pending_task);
+	int rctx;
+
+	/*
+	 * If we 'fail' here, that's OK, it means recursion is already disabled
+	 * and we won't recurse 'further'.
+	 */
+	preempt_disable_notrace();
+	rctx = perf_swevent_get_recursion_context();
+
+	if (event->pending_work) {
+		event->pending_work = 0;
+		perf_sigtrap(event);
+		local_dec(&event->ctx->nr_pending);
+	}
+
+	if (rctx >= 0)
+		perf_swevent_put_recursion_context(rctx);
+	preempt_enable_notrace();
+}
+
 #ifdef CONFIG_GUEST_PERF_EVENTS
 struct perf_guest_info_callbacks __rcu *perf_guest_cbs;
 
@@ -9188,8 +9254,8 @@ int perf_event_account_interrupt(struct
  */
 
 static int __perf_event_overflow(struct perf_event *event,
-				   int throttle, struct perf_sample_data *data,
-				   struct pt_regs *regs)
+				 int throttle, struct perf_sample_data *data,
+				 struct pt_regs *regs)
 {
 	int events = atomic_read(&event->event_limit);
 	int ret = 0;
@@ -9212,24 +9278,36 @@ static int __perf_event_overflow(struct
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
@@ -11537,8 +11615,8 @@ perf_event_alloc(struct perf_event_attr
 
 
 	init_waitqueue_head(&event->waitq);
-	event->pending_disable = -1;
-	init_irq_work(&event->pending, perf_pending_event);
+	init_irq_work(&event->pending_irq, perf_pending_irq);
+	init_task_work(&event->pending_task, perf_pending_task);
 
 	mutex_init(&event->mmap_mutex);
 	raw_spin_lock_init(&event->addr_filters.lock);
@@ -11560,9 +11638,6 @@ perf_event_alloc(struct perf_event_attr
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0Ue2L5CsaQwDrEs%40hirez.programming.kicks-ass.net.
