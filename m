Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMNZ2CMQMGQEHNLPYQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 198195ED9CA
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Sep 2022 12:06:42 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id i17-20020a05640242d100b0044f18a5379asf10077479edc.21
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Sep 2022 03:06:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664359601; cv=pass;
        d=google.com; s=arc-20160816;
        b=agN/Zy2NPUjHCIjJUQVteOBVBtS3YCb0D5ozMNXeoyoJvnNmXzkOM0SMyqDPMX+sHR
         HE6vRpIYgOGp7VcLUjfAswYfQ6t94OVc5SOdosa3co8j+igd3HoyuVZi0Q26td3g2h2m
         W7NnczXlAa+cX1UPH/Co3DpbnRJGaE/thV3oPEpSJKNG1USWSD9i4BvH1qu5pxz/92DG
         aB4lbipTd3dhLlMhnYlc+lzzsNwE3Or8PGPkBpuaPVMkDGq3hYzFELrQWvccmNtSCq0T
         D+6pbMFqnVHZqjoQkDuytB1Ba8IbEWGsCoOVY1//fuJ9YZcAbgfLd3J4o0vahBAGdaNM
         9wPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=y4aHGa+93mnf2cOimkfx8/nj+JXMAf6bxRB1GoF1AP4=;
        b=YlmxwnZfB8OMFa0s+KIlp7biPdehAqe0/2YgAYBY1uj4IIIojAWOwKoD8q1U9Rz0VW
         e2Bq8Ktq1Nm393bviLHm7F9hShNYiDiZdkhAMH+HRgASVCyGN76ZwrMxZYBaWbvNn41G
         FHJstEX3ITTCHP3SbH5GsJSJbhhlV/GEbhwdvZK9BftLM4iBCknYoF7MUjUbxOQRNG5N
         jH4RzSeqXyKAoRLN0enJbowEyONqS3JPIEjkkGCwp8DMm1FQ+BcXbAIXr+t+goEioZf3
         gyIgJjc7liMVFCkYLopGwP/2xWgyW5lxobuOTlHQOYZma2mh9ERrZKTm/lszw9hIwdMI
         1sSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=anMJtLd7;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date;
        bh=y4aHGa+93mnf2cOimkfx8/nj+JXMAf6bxRB1GoF1AP4=;
        b=omth4PCdA1DGVOvF+Q4K4TDsEiIQN9Y7SgDtM7VjlOvM42jHtGo8gvH2ClUPdMkIwG
         eX3F9wA82n7LiJc8Ev5y0utO9VRqn1KK+YzpNC60YV3xJWUHD4P2RKizI87Wm3sUSgzF
         uj48E73wOAUbzcz1dAfZ+VoQZSiDmDq2cahysGufX5J/xwHRQ7EEX/GyQoTczllYuiD9
         Mi6S5xrkm14fM1ymf8witJ3AmKfHsN0G8eOG8dMbhNiIv6zRcPVvjpzD/2k10qd5iQIa
         o1wqECWnItUSvJ49+H5Nu6Tzf18REv/991z5rYE2W+h4Vb/yZuzl4rSThy1N0LCJKLEA
         H9wQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=y4aHGa+93mnf2cOimkfx8/nj+JXMAf6bxRB1GoF1AP4=;
        b=D9NcuBUBkGHXCnGKjzWpH+6lEXL0W2AIvW0EgrpdCCCGCwbkQWYB0BPdVBu5ASdGHX
         PaYWteSMUpuyukTQ8buZ0c/BHhdfg3H3/A8GzyuzQQ7+2wzA4I5/CcAgmGyW9VbtZyCf
         a58krG9PhxldZ4bbGCt7K6mmQom1aViElrZ5NIQUWDJN4vj5sW0lyhvxnB5PoRvrwyx0
         wmru1lJqOtvAeCjQ4DXB+IYdFiSN9r5ck9E7XzOEVqsq6ohN/aryM8PftlJRxRJYV3iU
         fh6qsD+VOYgIedQgOebJ1kcpe0scj+81Lp+EK9ZB0VJV7NW19Nnhh6F/DHvpa5su/T6f
         3sVA==
X-Gm-Message-State: ACrzQf0ARSBirPCVmA3TZq8SgvgDhWbziUJRjm991l1WUQLTL4JsVJip
	61ehcCVsoa93iCa5G77DLgQ=
X-Google-Smtp-Source: AMsMyM6eEdJ1hN/plrgamHh1+I1N6kUl0zzwqTUJnUoMOwJxDLczeeGgm5/eO02N2rA804ys6QpBJg==
X-Received: by 2002:aa7:c6c8:0:b0:457:d851:480a with SMTP id b8-20020aa7c6c8000000b00457d851480amr4478148eds.332.1664359601467;
        Wed, 28 Sep 2022 03:06:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:274b:b0:448:77f2:6859 with SMTP id
 z11-20020a056402274b00b0044877f26859ls1255656edd.3.-pod-prod-gmail; Wed, 28
 Sep 2022 03:06:40 -0700 (PDT)
X-Received: by 2002:a05:6402:2141:b0:456:d714:17b6 with SMTP id bq1-20020a056402214100b00456d71417b6mr25868569edb.425.1664359600092;
        Wed, 28 Sep 2022 03:06:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664359600; cv=none;
        d=google.com; s=arc-20160816;
        b=NmwTD7TrvVMq5QaxUMOIaN9zbbwsf6tSda8eM+neTZvNL89wVtqjLmfxkuzHX7H5/7
         rKVrRVt1IC2cvGdtthuB8jKOnTnmKvERB4o6uSBkGNlpY+ATNAK7shvyq4phP4KdOjM9
         ojYnhT81zGpVGQa9Hcvu80oIQhRiMrIJChO1Fdq9Rl/crPiu+fIoAI+2qFhAsAvg4uJU
         UjXUhqdsmxe3aUhKXa00OP2y8MFAq1WkMCHvAI9gQe8EPQUJYamwnXL3LVCN3f8/p0Fv
         S7YCgZvaROkS52DnMzCHrMcRk+qPjMKQ0NJtJm2Tv/KL1uL6Bp7i6Up7dxjxp90EFPte
         lM+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=reAAZ1Fg31aMt0fosaFa3oLFeytHbOA9bmQ9dv1ASJM=;
        b=RnRblzU9W6WwCluPiJJU/kkfbW6AhZtAI7H3faXv/bJ6IYlH8qzCRhA8fo7PWjTF0A
         WGsDBk6+oo8w942ainKzwaSv4OXDGibTaIOqU8NSfPuMp4B2vQG5ZR2fNweLPkcxSoss
         pM3E3gnAjUuq+AEGCXsf+jgTr7KbcZwztjhKw141YrnsQMlmn9e9C8/VkW9j2TcmzoVZ
         k0QWjQkOKbuksj7ddxaPt1DvL9LIjo3LEiMnSeb7GSBmrJDfmLluzoFhVXY6PnWzND3O
         YEtBDKT7p0d89JXdGixOe2k406ZAIm3cxA1CnNzqVmVwv+N1vS5S8pCszZWbelZpNMSc
         CHaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=anMJtLd7;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x62e.google.com (mail-ej1-x62e.google.com. [2a00:1450:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id t11-20020aa7d4cb000000b0045757c7cb91si175879edr.4.2022.09.28.03.06.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Sep 2022 03:06:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62e as permitted sender) client-ip=2a00:1450:4864:20::62e;
Received: by mail-ej1-x62e.google.com with SMTP id dv25so25988674ejb.12
        for <kasan-dev@googlegroups.com>; Wed, 28 Sep 2022 03:06:40 -0700 (PDT)
X-Received: by 2002:a17:907:7245:b0:782:331b:60f4 with SMTP id ds5-20020a170907724500b00782331b60f4mr27443656ejc.594.1664359599590;
        Wed, 28 Sep 2022 03:06:39 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:dbbc:9ea2:a5f7:571e])
        by smtp.gmail.com with ESMTPSA id q1-20020a50cc81000000b00457618d3409sm3055135edi.68.2022.09.28.03.06.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Sep 2022 03:06:38 -0700 (PDT)
Date: Wed, 28 Sep 2022 12:06:33 +0200
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
Message-ID: <YzQcqe9p9C5ZbjZ1@elver.google.com>
References: <20220927121322.1236730-1-elver@google.com>
 <YzM/BUsBnX18NoOG@hirez.programming.kicks-ass.net>
 <YzNu5bgASbuVi0S3@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YzNu5bgASbuVi0S3@elver.google.com>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=anMJtLd7;       spf=pass
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

On Tue, Sep 27, 2022 at 11:45PM +0200, Marco Elver wrote:
> On Tue, Sep 27, 2022 at 08:20PM +0200, Peter Zijlstra wrote:
> > On Tue, Sep 27, 2022 at 02:13:22PM +0200, Marco Elver wrote:
> > > Due to the implementation of how SIGTRAP are delivered if
> > > perf_event_attr::sigtrap is set, we've noticed 3 issues:
> > > 
> > > 	1. Missing SIGTRAP due to a race with event_sched_out() (more
> > > 	   details below).
> > > 
> > > 	2. Hardware PMU events being disabled due to returning 1 from
> > > 	   perf_event_overflow(). The only way to re-enable the event is
> > > 	   for user space to first "properly" disable the event and then
> > > 	   re-enable it.
> > > 
> > > 	3. The inability to automatically disable an event after a
> > > 	   specified number of overflows via PERF_EVENT_IOC_REFRESH.
> > > 
> > > The worst of the 3 issues is problem (1), which occurs when a
> > > pending_disable is "consumed" by a racing event_sched_out(), observed as
> > > follows:
> > > 
> > > 		CPU0			| 	CPU1
> > > 	--------------------------------+---------------------------
> > > 	__perf_event_overflow()		|
> > > 	 perf_event_disable_inatomic()	|
> > > 	  pending_disable = CPU0	| ...
> > > 	  				| _perf_event_enable()
> > > 					|  event_function_call()
> > > 					|   task_function_call()
> > > 					|    /* sends IPI to CPU0 */
> > > 	<IPI>				| ...
> > > 	 __perf_event_enable()		+---------------------------
> > > 	  ctx_resched()
> > > 	   task_ctx_sched_out()
> > > 	    ctx_sched_out()
> > > 	     group_sched_out()
> > > 	      event_sched_out()
> > > 	       pending_disable = -1
> > > 	</IPI>
> > > 	<IRQ-work>
> > > 	 perf_pending_event()
> > > 	  perf_pending_event_disable()
> > > 	   /* Fails to send SIGTRAP because no pending_disable! */
> > > 	</IRQ-work>
> > > 
> > > In the above case, not only is that particular SIGTRAP missed, but also
> > > all future SIGTRAPs because 'event_limit' is not reset back to 1.
> > > 
> > > To fix, rework pending delivery of SIGTRAP via IRQ-work by introduction
> > > of a separate 'pending_sigtrap', no longer using 'event_limit' and
> > > 'pending_disable' for its delivery.
> > > 
> > > During testing, this also revealed several more possible races between
> > > reschedules and pending IRQ work; see code comments for details.
> > 
> > Perhaps use task_work_add() for this case? That runs on the
> > return-to-user path, so then it doesn't matter how many reschedules
> > happen in between.
> 
> Hmm, I tried the below (on top of this patch), but then all the tests
> fail (including tools/testing/selftests/perf_events/sigtrap_threads.c)
> because of lots of missing SIGTRAP. (The missing SIGTRAP happen with or
> without the kernel/entry/ change.)
> 
> So something is wrong with task_work, and the irq_work solution thus far
> is more robust (ran many hours of tests and fuzzing without failure).

My second idea about introducing something like irq_work_raw_sync().
Maybe it's not that crazy if it is actually safe. I expect this case
where we need the irq_work_raw_sync() to be very very rare.

------ >8 ------

diff --git a/include/linux/irq_work.h b/include/linux/irq_work.h
index 8cd11a223260..490adecbb4be 100644
--- a/include/linux/irq_work.h
+++ b/include/linux/irq_work.h
@@ -59,6 +59,7 @@ bool irq_work_queue_on(struct irq_work *work, int cpu);
 
 void irq_work_tick(void);
 void irq_work_sync(struct irq_work *work);
+bool irq_work_raw_sync(struct irq_work *work);
 
 #ifdef CONFIG_IRQ_WORK
 #include <asm/irq_work.h>
diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
index dff3430844a2..c119fa7b70d6 100644
--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -743,7 +743,6 @@ struct perf_event {
 	int				pending_sigtrap;
 	unsigned long			pending_addr;	/* SIGTRAP */
 	struct irq_work			pending;
-	struct irq_work			pending_resched;
 
 	atomic_t			event_limit;
 
diff --git a/kernel/events/core.c b/kernel/events/core.c
index 007a87c1599c..6ba02a1b5c5d 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -2532,7 +2532,8 @@ event_sched_in(struct perf_event *event,
 		 * The task and event might have been moved to another CPU:
 		 * queue another IRQ work. See perf_pending_event_sigtrap().
 		 */
-		WARN_ON_ONCE(!irq_work_queue(&event->pending_resched));
+		irq_work_raw_sync(&event->pending); /* Syncs if pending on other CPU. */
+		irq_work_queue(&event->pending);
 	}
 
 out:
@@ -4946,7 +4947,6 @@ static void perf_addr_filters_splice(struct perf_event *event,
 static void _free_event(struct perf_event *event)
 {
 	irq_work_sync(&event->pending);
-	irq_work_sync(&event->pending_resched);
 
 	unaccount_event(event);
 
@@ -6545,26 +6545,6 @@ static void perf_pending_event(struct irq_work *entry)
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
 
@@ -11599,7 +11579,6 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
 	init_waitqueue_head(&event->waitq);
 	event->pending_disable = -1;
 	init_irq_work(&event->pending, perf_pending_event);
-	init_irq_work(&event->pending_resched, perf_pending_event_resched);
 
 	mutex_init(&event->mmap_mutex);
 	raw_spin_lock_init(&event->addr_filters.lock);
diff --git a/kernel/irq_work.c b/kernel/irq_work.c
index 7afa40fe5cc4..2d21be0c0f3e 100644
--- a/kernel/irq_work.c
+++ b/kernel/irq_work.c
@@ -290,6 +290,40 @@ void irq_work_sync(struct irq_work *work)
 }
 EXPORT_SYMBOL_GPL(irq_work_sync);
 
+/*
+ * Synchronize against the irq_work @work, ensuring the entry is not currently
+ * in use after returning true. If it returns false, it was not possible to
+ * synchronize against the irq_work. Requires that interrupts are already
+ * disabled (prefer irq_work_sync() in all other cases).
+ */
+bool irq_work_raw_sync(struct irq_work *work)
+{
+	struct irq_work *entry;
+	struct llist_head *list;
+
+	lockdep_assert_irqs_disabled();
+
+	if (!irq_work_is_busy(work))
+		return true;
+
+	list = this_cpu_ptr(&raised_list);
+	llist_for_each_entry(entry, list->first, node.llist) {
+		if (entry == work)
+			return false;
+	}
+	list = this_cpu_ptr(&lazy_list);
+	llist_for_each_entry(entry, list->first, node.llist) {
+		if (entry == work)
+			return false;
+	}
+
+	while (irq_work_is_busy(work))
+		cpu_relax();
+
+	return true;
+}
+EXPORT_SYMBOL_GPL(irq_work_raw_sync);
+
 static void run_irq_workd(unsigned int cpu)
 {
 	irq_work_run_list(this_cpu_ptr(&lazy_list));

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YzQcqe9p9C5ZbjZ1%40elver.google.com.
