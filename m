Return-Path: <kasan-dev+bncBDBK55H2UQKRBROR6GMQMGQEKKAAE4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 052FA5F480B
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Oct 2022 19:09:27 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id b17-20020a196451000000b004a259354a35sf627211lfj.5
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Oct 2022 10:09:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664903366; cv=pass;
        d=google.com; s=arc-20160816;
        b=UYbN0CO3n3b0Jh3f4xFT7q045xPAuKpD5mBNW5Ft7OMQXieeT6Jmt7O/sdYROxkiAN
         eU+c5WH6N349JuRPSEXAZ8rBv2Vlu+1XmrMr75skDpfuzRX29/kkk5t6bA/reFZmnFAA
         7Yphz79oP5YDckDF2kMLGLQg8ixuHTklXp53YwwRNO411BqKXP5DlMN4GEV2nvxLN22Q
         yVmDODEIPX5EiXEYvFQvXwGHrDw55OTMmOyNfnEqATqYRDOIUq3ykxMO/H3CtxCOOOdt
         ZdjSmfHEQzU8XKEG5dQCvQDPSjwED0MQNWPIB39w7WxJvTeEX8FQRYmzRB4bpBeBnzp2
         Zd6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zdHyBS5OOtTtz8wBt0LO1wOJtI7N+KSfV243K+LVx/0=;
        b=hkaBV6uWAPGMNKx0Hn7UXWkt2jkWSLh3FdlgtDah9pZgAZkmWod3lQlWnAj8xXEUb9
         E9JEOGY36FGFm5Vnmp0XiVSoLVyK9kE+o4l5xp1RN3AmhOMAgvJDSr0Gjm34sXDFIvNh
         CrkPuRW167UNzfSbF8PFwlB4aqO7K5qPSlXqLzta7ARDGx1PVjxwkVzaSRCJmm68L41g
         Nl4ohRnj7MYpTt58OD+67JBP6rmeXSQq+/8okUzWOxh+9kFexXfFKYH5wvFfSyh0s61f
         041D3wQgxlNy79FFRP2T5aNoDIIhie11DdTmAFRlMoItCAQ7K9ILbR7KhR0hrIFtfekL
         +z9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=QIT+ry9z;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=zdHyBS5OOtTtz8wBt0LO1wOJtI7N+KSfV243K+LVx/0=;
        b=tAQ9RHupk1ZDFc7QbP3XXgNJcBZiU1q/p9RwqTeKxEGkozekZKOjLHOLyhSU/pTfPr
         Fael+5QwMKb46FP4178tr/v6a0Z/3W5RPyzQFg9/sBMhmn54k6mT0cZ63qv/dmTaFwjZ
         nG6QCtYQVATxmuNhEjt/eoTWOsRiW3ByMOFiB1bVlBY4Ldxodx7uvHuOlP4LD/p5I5jR
         Wu4E5w+T78JAMg5xgFVk4XG1YBI9O1YhpJA2kGI+IRJyXJu4b0kLTiz9LZLxhQ6JXxN+
         WmGiNuG71PbS56m1MxkiE7q1cApQESKMmQ134zXDmkLmsgkFVHpG4+sT9YtX55+gG6Bk
         bwSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=zdHyBS5OOtTtz8wBt0LO1wOJtI7N+KSfV243K+LVx/0=;
        b=Qn8B9+AtDdLUXBHr3CF8AKeHge9VAIQsxd6tD1BD+riTVdEuLYLzosWuO3B2GcK4E9
         M7wVUUdUINbl6lisnkfGP959n/bilgWU4yHKXpskgV6wvlz/oAlDWn45hnkTBvkUy+Je
         tApelQwHHOPjZADLhR+FIMvdMV2ucNj9okBY4BmsMevpfb6NINgt2N7avj55du9pSs06
         OgSpKq/Mu4CZaOeQeOV4zh7bGy78LmDi8hpwre1zRgq6x+rUHURZEUQlr8T0OS3Yxd7F
         ix+8eeggNy+5Tm63Xbw77GN2ukOP7VxGlhm6HljxKLpLp4LHIqtSTQ4gL+UwBzFiTlYN
         u0BQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3R8dvncprv1LL+TaDw6P3Z9Ng+RzupdV90EsdZf4mT1J7ICjIM
	hsYuz7NO9CifInsfbZMVOnM=
X-Google-Smtp-Source: AMsMyM6Etc4MP04lGEKhP0Wg58mXgHrV84+lXxI423Tj9xHtO8sexSl3SpUYbBmUOKW3m1i0j8hWzg==
X-Received: by 2002:ac2:46e5:0:b0:4a2:3bf3:91e4 with SMTP id q5-20020ac246e5000000b004a23bf391e4mr4209895lfo.611.1664903366112;
        Tue, 04 Oct 2022 10:09:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9e02:0:b0:261:d944:1ee6 with SMTP id e2-20020a2e9e02000000b00261d9441ee6ls2575702ljk.0.-pod-prod-gmail;
 Tue, 04 Oct 2022 10:09:24 -0700 (PDT)
X-Received: by 2002:a2e:2e10:0:b0:26d:e8cd:509b with SMTP id u16-20020a2e2e10000000b0026de8cd509bmr1619697lju.96.1664903364610;
        Tue, 04 Oct 2022 10:09:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664903364; cv=none;
        d=google.com; s=arc-20160816;
        b=ngRQjj5zpUw5syfxZJ+3kbpMQoBnqdzSOH7AH44+uJTKRsqE1uzgfoFCJQ9jJiVuWX
         7f5MU8RX9EujsyvciZis4izsR8/k7pOvDdf/yg8a1hnQP2f2tDqL/oj25ccRnT5uiq/o
         2xCCGb42CJ1leo63vwyJWl8acFuPgERHaJw9C+qQiFC191F5KvzYY0z+vA8XiMlDesxe
         iCvEhXgtsZR2hnBdTtr7XB+jabSUbSX8nIIIbJOoaan1+xh2ABwn1LGQUPOMC220dnso
         UsITpEABBw4f+bDXqfAASz0RDEjwVEmssorlNvs1F5PiOLPoJMvm1WkxRkZ5E3OC3gQG
         rBEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=HISWwRKFuRO/9DyL6LlzLd2PnC0+qLYEQ5vpRXdvxxs=;
        b=L4JlOykUXzMz5G1eF3SwPjFEJIKaTFXpwAUmVTOFC0NvcBqOGzL97/ibeMXR9nuaOK
         j7h/BnVW31DJVopVDOTfKmC9TH70cVCdESQf3uPgJojCxXvH8b4lixGkkQUv7lr8XbRh
         HN2oBWrKYjthCwPOUsPzPjDstyZO1jjbTcvOf9JdZgsyPr+tpa+1pFJfcqfIiOFsmjDD
         8QO26oKy8nYzIh2KdPpCfcFZxcfqQNMKuN02cBJegS6o42smkz5rumaMhOQt565Hxuvg
         LGqbZ5mSLFN/uru6ykFGj8g5oMKmlY8DaayBSRxAN4rkP0HigUB1g1uF9Uk0F+QeYN4M
         Rt1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=QIT+ry9z;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id bi42-20020a0565120eaa00b0048b38f379d7si396964lfb.0.2022.10.04.10.09.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Oct 2022 10:09:24 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oflQ0-00HKVc-RF; Tue, 04 Oct 2022 17:09:20 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id C80B43001CE;
	Tue,  4 Oct 2022 19:09:15 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 9BF5F209B80F8; Tue,  4 Oct 2022 19:09:15 +0200 (CEST)
Date: Tue, 4 Oct 2022 19:09:15 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] perf: Fix missing SIGTRAPs due to pending_disable abuse
Message-ID: <Yzxou9HB/1XjMXWI@hirez.programming.kicks-ass.net>
References: <20220927121322.1236730-1-elver@google.com>
 <YzM/BUsBnX18NoOG@hirez.programming.kicks-ass.net>
 <YzNu5bgASbuVi0S3@elver.google.com>
 <YzQcqe9p9C5ZbjZ1@elver.google.com>
 <YzRgcnMXWuUZ4rlt@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YzRgcnMXWuUZ4rlt@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=QIT+ry9z;
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

On Wed, Sep 28, 2022 at 04:55:46PM +0200, Marco Elver wrote:
> On Wed, Sep 28, 2022 at 12:06PM +0200, Marco Elver wrote:
> 
> > My second idea about introducing something like irq_work_raw_sync().
> > Maybe it's not that crazy if it is actually safe. I expect this case
> > where we need the irq_work_raw_sync() to be very very rare.
> 
> The previous irq_work_raw_sync() forgot about irq_work_queue_on(). Alas,
> I might still be missing something obvious, because "it's never that
> easy". ;-)
> 
> And for completeness, the full perf patch of what it would look like
> together with irq_work_raw_sync() (consider it v1.5). It's already
> survived some shorter stress tests and fuzzing.

So.... I don't like it. But I cooked up the below, which _almost_ works :-/

For some raisin it sometimes fails with 14999 out of 15000 events
delivered and I've not yet figured out where it goes sideways. I'm
currently thinking it's that sigtrap clear on OFF.

Still, what do you think of the approach?

---
 include/linux/perf_event.h |  8 ++--
 kernel/events/core.c       | 92 +++++++++++++++++++++++++---------------------
 2 files changed, 55 insertions(+), 45 deletions(-)

diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
index ee8b9ecdc03b..c54161719d37 100644
--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -736,9 +736,11 @@ struct perf_event {
 	struct fasync_struct		*fasync;
 
 	/* delayed work for NMIs and such */
-	int				pending_wakeup;
-	int				pending_kill;
-	int				pending_disable;
+	unsigned int			pending_wakeup	:1;
+	unsigned int			pending_disable	:1;
+	unsigned int			pending_sigtrap	:1;
+	unsigned int			pending_kill	:3;
+
 	unsigned long			pending_addr;	/* SIGTRAP */
 	struct irq_work			pending;
 
diff --git a/kernel/events/core.c b/kernel/events/core.c
index 2621fd24ad26..8e5dbe971d9e 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -2268,11 +2268,15 @@ event_sched_out(struct perf_event *event,
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
+	if (event->pending_sigtrap && state == PERF_EVENT_STATE_OFF)
+		event->pending_sigtrap = 0;
+
 	perf_event_set_state(event, state);
 
 	if (!is_software_event(event))
@@ -2463,8 +2467,7 @@ EXPORT_SYMBOL_GPL(perf_event_disable);
 
 void perf_event_disable_inatomic(struct perf_event *event)
 {
-	WRITE_ONCE(event->pending_disable, smp_processor_id());
-	/* can fail, see perf_pending_event_disable() */
+	event->pending_disable = 1;
 	irq_work_queue(&event->pending);
 }
 
@@ -2527,6 +2530,9 @@ event_sched_in(struct perf_event *event,
 	if (event->attr.exclusive)
 		cpuctx->exclusive = 1;
 
+	if (event->pending_disable || event->pending_sigtrap)
+		irq_work_queue(&event->pending);
+
 out:
 	perf_pmu_enable(event->pmu);
 
@@ -6440,47 +6446,40 @@ static void perf_sigtrap(struct perf_event *event)
 		      event->attr.type, event->attr.sig_data);
 }
 
-static void perf_pending_event_disable(struct perf_event *event)
+/*
+ * Deliver the pending work in-event-context or follow the context.
+ */
+static void __perf_pending_event(struct perf_event *event)
 {
-	int cpu = READ_ONCE(event->pending_disable);
+	int cpu = READ_ONCE(event->oncpu);
 
+	/*
+	 * If the event isn't running; we done. event_sched_in() will restart
+	 * the irq_work when needed.
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
 		}
-
-		perf_event_disable_local(event);
-		return;
+		if (event->pending_disable) {
+			event->pending_disable = 0;
+			perf_event_disable_local(event);
+		}
 	}
 
 	/*
-	 *  CPU-A			CPU-B
-	 *
-	 *  perf_event_disable_inatomic()
-	 *    @pending_disable = CPU-A;
-	 *    irq_work_queue();
-	 *
-	 *  sched-out
-	 *    @pending_disable = -1;
-	 *
-	 *				sched-in
-	 *				perf_event_disable_inatomic()
-	 *				  @pending_disable = CPU-B;
-	 *				  irq_work_queue(); // FAILS
-	 *
-	 *  irq_work_run()
-	 *    perf_pending_event()
-	 *
-	 * But the event runs on CPU-B and wants disabling there.
+	 * Requeue if there's still any pending work left, make sure to follow
+	 * where the event went.
 	 */
-	irq_work_queue_on(&event->pending, cpu);
+	if (event->pending_disable || event->pending_sigtrap)
+		irq_work_queue_on(&event->pending, cpu);
 }
 
 static void perf_pending_event(struct irq_work *entry)
@@ -6488,19 +6487,23 @@ static void perf_pending_event(struct irq_work *entry)
 	struct perf_event *event = container_of(entry, struct perf_event, pending);
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
 
+	__perf_pending_event(event);
+
 	if (rctx >= 0)
 		perf_swevent_put_recursion_context(rctx);
 }
@@ -9203,11 +9206,20 @@ static int __perf_event_overflow(struct perf_event *event,
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
+		event->pending_sigtrap = 1;
+		event->pending_addr = data->addr;
+		irq_work_queue(&event->pending);
+	}
+
 	READ_ONCE(event->overflow_handler)(event, data, regs);
 
 	if (*perf_event_fasync(event) && event->pending_kill) {
@@ -11528,7 +11540,6 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
 
 
 	init_waitqueue_head(&event->waitq);
-	event->pending_disable = -1;
 	init_irq_work(&event->pending, perf_pending_event);
 
 	mutex_init(&event->mmap_mutex);
@@ -11551,9 +11562,6 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
 	if (parent_event)
 		event->event_caps = parent_event->event_caps;
 
-	if (event->attr.sigtrap)
-		atomic_set(&event->event_limit, 1);
-
 	if (task) {
 		event->attach_state = PERF_ATTACH_TASK;
 		/*

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yzxou9HB/1XjMXWI%40hirez.programming.kicks-ass.net.
