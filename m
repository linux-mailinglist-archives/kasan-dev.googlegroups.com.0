Return-Path: <kasan-dev+bncBCV5TUXXRUIBBKP646BAMGQENAWZFWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 593933461BA
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 15:46:02 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id r12sf1202977wro.15
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 07:46:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616510762; cv=pass;
        d=google.com; s=arc-20160816;
        b=vwkqFk3LR8fB3MazVWFL6qT7Hk/yAlJ1rtDXzz742Z3OVpVBky8JyiFt2o2yWWt4mF
         Ufx0tb26CVr6VeaLAvklI86G/cWQQwV58YplF8aB/nxO9Qlr3gsPcms5uiiUsPCJriNz
         k/Jk6o5GxYD1HF5b8SUme0eNSxQmGOCOum5RrMoV9fF8kXw1WsJg2Z4WLC80pWCw8mIa
         oN0/sENBc9jwkMhJ2VAldIBR4S+iy4NXFff2wJEJqSqIgYccoIW90tNZ5H1eZbx5wjI+
         KnC/3KA+n1t/f2+CJDbBN4zViStn575DEWcDvEuExyAAnRoY4frGKVOMI1nLLYQrK+VT
         wZVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=uV8bHfb8hnyoE6BV2pYnUwSWCXQLA7jyz4StdBJOIKU=;
        b=Jj24mNhpBv1rbr4/uIaI5Lqw0sCKYP7xK/J/HZo1b9ss1Y0XUKlLls5IzKawVms2RH
         PIaMwnSSgFSUCzJeS3aoIU6tTgDuqik8bGuuTAISCl8gVYEkRbrvVpw6Pm+4gtsld0ip
         1HKTYJ23t/P3gO4Zu8Ttu2M1LvwwReEOAA0UBWJgIUBNecHPhnUzQtDN/qCwtA+qJfLU
         zdZH3v62GNyRXALqnbpFOcIpEkzDg0+Vc3EbyTZj/ptsEoB1vmYLJG1IuSfFU7Rkq5/h
         qK8Sn11PziHtbb9tQWG+O9Gy8OuBWVcTKfE4yktXq6xTtFH31uL9vp7W0wji1xTZUZdF
         ++TQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=kLSH1p6R;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uV8bHfb8hnyoE6BV2pYnUwSWCXQLA7jyz4StdBJOIKU=;
        b=jU6JVWv+Ol8QTzDnsRZzXD087J39nQ/K5CT7Gmrh5WzqcuZ30rEoT74xok49v/VlAu
         OCYQ4m/uVoA6AbraEKHFoRm0B1diREEgHrv8knhG/NLFzD1Vm8Ah53AFre4HAvWYVKrd
         Vyc/Wjo3/+x4Ac4Or0kJuO/cuCcFlpLSVse2M3+AykEvvtJYrzhOrMoiU2t8/B9DWONR
         u+s01CzKSfpkVgODOpK9AsD6+rKdrixuIET1XhCHhNcted78HHunOHiaPvN5eU6YSkc0
         /7TPQNJRJBA/Y/Dkrmt8VGOjuhjBulb0BQHk67I3i8h9RhN+E1p5iD0/WFq09yHrhxsk
         g3JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uV8bHfb8hnyoE6BV2pYnUwSWCXQLA7jyz4StdBJOIKU=;
        b=irYXUWzz+opVsAhRgVvsnMYKVhHpYTM/2kujvxKzBKAYeGHBzvCAY4aRUwEtyaUpmr
         wgYdQEkatrdVOGC35gfEgX7qhUT/++vtcvuI2qsJ8FinojvkaJyXVwK41odKdZ5xxk6j
         WSiq2lEXPOLXpTAGfAnoHGtk4c1vmCEI9zrwf94eZX8c5ZQ2mXfWARKwvoGhU5HRlca4
         gEWOLTkNaFGy45vuDzFUSj9t8Ia7QUpfNRTfSGZSU1/a5jNU5VGhWO5PcbgnKdOmX5ke
         en7aksHIxE/8pVkttF+aQpVr0RV3CXIwD2PsoFq/XPHypDBdLPaLdLvYSFudaTtUTesr
         6zvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530qpaa6TRxINcFugR+H34HCordRqkfFFeNNuNcgwyv0zpYi5P6f
	eXJOysLc4oaMrriigMs5ZSg=
X-Google-Smtp-Source: ABdhPJzK5zlDIjTeyhQGJPWsVbzWx+b/I3hVwnCuOjciWbiMLeKoRZX+pMbwLEVOCUVLGrmKp7HIrg==
X-Received: by 2002:adf:fb05:: with SMTP id c5mr4550872wrr.302.1616510762124;
        Tue, 23 Mar 2021 07:46:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c763:: with SMTP id x3ls1484161wmk.1.canary-gmail; Tue,
 23 Mar 2021 07:46:01 -0700 (PDT)
X-Received: by 2002:a1c:9d51:: with SMTP id g78mr3845772wme.5.1616510761208;
        Tue, 23 Mar 2021 07:46:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616510761; cv=none;
        d=google.com; s=arc-20160816;
        b=zphlrKp55HZ81O34yas5mG5Vgh7IDHFEEQQ9ylw2rc/m/gi91P3xeErzRUEYwuddhA
         /ijyNbUw0n2XedimvjR3NbHiB5oMW/22Thi19Od5cisbDqZ3ivLQOYEe1Woy7heAzWJo
         vQ04BodtPI/JqtaL0haWmFPMiRZ9mvkfodbhBm3tmNQwPbDUBmQXlXE4Ohc19L/wIMXG
         Sc5RCsxRDp6WUxs02KntmPvY+aJlk0aILFDoqCZdIQXMECSZB1RzR/fztx1FQVsxHaLv
         Tn0YE3B9HuHEOmEqHe76Kj5lJoeXXiIA7prHHq1TbfrjmL/Ztmsqb2PcgJKQVUEINUUE
         cMFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=NJf+HZsOodPaZPW38P1Cps8i58xLSQI9qQh/4dJkNeU=;
        b=giEzIghZ7CapfVMvc2hp8EAKo69AgjUHZzzvmlghrtLiQRzVS3bn5ODb30G5BsnGDZ
         UcQFtVfnMzdpCvzkaFvgrfnnxaQTrmkgijEPrPb4y3x0N2F8wH9VpY+81Z7b/I3+QvUm
         00w3cJ9lvjR9eBgj0al3DX2DJ9k/U9pXw3CPxnIrXVp7/75i9QE4x3b5U8OZSAyILhfK
         bDoMhanJY8buTf7F0Vx2gDGF87QtCK7mZ0tYIY+qYUEGZCRG8y6a3Gs5gb4kMs/bcvwr
         8bnR4o2uVCCFXc3wjFG48fxCH8v1WSv5/k4aXxuHCdrjH5pfuOReqqaFyK1ww9MezwvU
         Ye+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=kLSH1p6R;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id r11si729591wrm.1.2021.03.23.07.46.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Mar 2021 07:46:01 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1lOiI8-00FCBz-R0; Tue, 23 Mar 2021 14:45:57 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 7170130477A;
	Tue, 23 Mar 2021 15:45:55 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 4CC4C2D2A4F60; Tue, 23 Mar 2021 15:45:55 +0100 (CET)
Date: Tue, 23 Mar 2021 15:45:55 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: alexander.shishkin@linux.intel.com, acme@kernel.org, mingo@redhat.com,
	jolsa@redhat.com, mark.rutland@arm.com, namhyung@kernel.org,
	tglx@linutronix.de, glider@google.com, viro@zeniv.linux.org.uk,
	arnd@arndb.de, christian@brauner.io, dvyukov@google.com,
	jannh@google.com, axboe@kernel.dk, mascasa@google.com,
	pcc@google.com, irogers@google.com, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org, x86@kernel.org,
	linux-kselftest@vger.kernel.org
Subject: Re: [PATCH RFC v2 8/8] selftests/perf: Add kselftest for
 remove_on_exec
Message-ID: <YFn/I3aKF+TOjGcl@hirez.programming.kicks-ass.net>
References: <20210310104139.679618-1-elver@google.com>
 <20210310104139.679618-9-elver@google.com>
 <YFiamKX+xYH2HJ4E@elver.google.com>
 <YFjI5qU0z3Q7J/jF@hirez.programming.kicks-ass.net>
 <YFm6aakSRlF2nWtu@elver.google.com>
 <YFnDo7dczjDzLP68@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YFnDo7dczjDzLP68@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=kLSH1p6R;
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

On Tue, Mar 23, 2021 at 11:32:03AM +0100, Peter Zijlstra wrote:

> And at that point there's very little value in still using
> perf_event_exit_event()... let me see if there's something to be done
> about that.

I ended up with something like the below. Which then simplifies
remove_on_exec() to:

static void perf_event_remove_on_exec(int ctxn)
{
	struct perf_event_context *ctx, *clone_ctx = NULL;
	struct perf_event *event, *next;
	bool modified = false;
	unsigned long flags;

	ctx = perf_pin_task_context(current, ctxn);
	if (!ctx)
		return;

	mutex_lock(&ctx->mutex);

	if (WARN_ON_ONCE(ctx->task != current))
		goto unlock;

	list_for_each_entry_safe(event, next, &ctx->event_list, event_entry) {
		if (!event->attr.remove_on_exec)
			continue;

		if (!is_kernel_event(event))
			perf_remove_from_owner(event);

		modified = true;

		perf_event_exit_event(event, ctx);
	}

	raw_spin_lock_irqsave(&ctx->lock, flags);
	if (modified)
		clone_ctx = unclone_ctx(ctx);
	--ctx->pin_count;
	raw_spin_unlock_irqrestore(&ctx->lock, flags);

unlock:
	mutex_unlock(&ctx->mutex);

	put_ctx(ctx);
	if (clone_ctx)
		put_ctx(clone_ctx);
}


Very lightly tested with that {1..1000} thing.

---

Subject: perf: Rework perf_event_exit_event()
From: Peter Zijlstra <peterz@infradead.org>
Date: Tue Mar 23 15:16:06 CET 2021

Make perf_event_exit_event() more robust, such that we can use it from
other contexts. Specifically the up and coming remove_on_exec.

For this to work we need to address a few issues. Remove_on_exec will
not destroy the entire context, so we cannot rely on TASK_TOMBSTONE to
disable event_function_call() and we thus have to use
perf_remove_from_context().

When using perf_remove_from_context(), there's two races to consider.
The first is against close(), where we can have concurrent tear-down
of the event. The second is against child_list iteration, which should
not find a half baked event.

To address this, teach perf_remove_from_context() to special case
!ctx->is_active and about DETACH_CHILD.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 include/linux/perf_event.h |    1 
 kernel/events/core.c       |  144 +++++++++++++++++++++++++--------------------
 2 files changed, 81 insertions(+), 64 deletions(-)

--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -607,6 +607,7 @@ struct swevent_hlist {
 #define PERF_ATTACH_TASK_DATA	0x08
 #define PERF_ATTACH_ITRACE	0x10
 #define PERF_ATTACH_SCHED_CB	0x20
+#define PERF_ATTACH_CHILD	0x40
 
 struct perf_cgroup;
 struct perf_buffer;
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -2210,6 +2210,26 @@ static void perf_group_detach(struct per
 	perf_event__header_size(leader);
 }
 
+static void sync_child_event(struct perf_event *child_event);
+
+static void perf_child_detach(struct perf_event *event)
+{
+	struct perf_event *parent_event = event->parent;
+
+	if (!(event->attach_state & PERF_ATTACH_CHILD))
+		return;
+
+	event->attach_state &= ~PERF_ATTACH_CHILD;
+
+	if (WARN_ON_ONCE(!parent_event))
+		return;
+
+	lockdep_assert_held(&parent_event->child_mutex);
+
+	sync_child_event(event);
+	list_del_init(&event->child_list);
+}
+
 static bool is_orphaned_event(struct perf_event *event)
 {
 	return event->state == PERF_EVENT_STATE_DEAD;
@@ -2317,6 +2337,7 @@ group_sched_out(struct perf_event *group
 }
 
 #define DETACH_GROUP	0x01UL
+#define DETACH_CHILD	0x02UL
 
 /*
  * Cross CPU call to remove a performance event
@@ -2340,6 +2361,8 @@ __perf_remove_from_context(struct perf_e
 	event_sched_out(event, cpuctx, ctx);
 	if (flags & DETACH_GROUP)
 		perf_group_detach(event);
+	if (flags & DETACH_CHILD)
+		perf_child_detach(event);
 	list_del_event(event, ctx);
 
 	if (!ctx->nr_events && ctx->is_active) {
@@ -2368,25 +2391,21 @@ static void perf_remove_from_context(str
 
 	lockdep_assert_held(&ctx->mutex);
 
-	event_function_call(event, __perf_remove_from_context, (void *)flags);
-
 	/*
-	 * The above event_function_call() can NO-OP when it hits
-	 * TASK_TOMBSTONE. In that case we must already have been detached
-	 * from the context (by perf_event_exit_event()) but the grouping
-	 * might still be in-tact.
-	 */
-	WARN_ON_ONCE(event->attach_state & PERF_ATTACH_CONTEXT);
-	if ((flags & DETACH_GROUP) &&
-	    (event->attach_state & PERF_ATTACH_GROUP)) {
-		/*
-		 * Since in that case we cannot possibly be scheduled, simply
-		 * detach now.
-		 */
-		raw_spin_lock_irq(&ctx->lock);
-		perf_group_detach(event);
+	 * Because of perf_event_exit_task(), perf_remove_from_context() ought
+	 * to work in the face of TASK_TOMBSTONE, unlike every other
+	 * event_function_call() user.
+	 */
+	raw_spin_lock_irq(&ctx->lock);
+	if (!ctx->is_active) {
+		__perf_remove_from_context(event, __get_cpu_context(ctx),
+					   ctx, (void *)flags);
 		raw_spin_unlock_irq(&ctx->lock);
+		return;
 	}
+	raw_spin_unlock_irq(&ctx->lock);
+
+	event_function_call(event, __perf_remove_from_context, (void *)flags);
 }
 
 /*
@@ -12379,14 +12398,17 @@ void perf_pmu_migrate_context(struct pmu
 }
 EXPORT_SYMBOL_GPL(perf_pmu_migrate_context);
 
-static void sync_child_event(struct perf_event *child_event,
-			       struct task_struct *child)
+static void sync_child_event(struct perf_event *child_event)
 {
 	struct perf_event *parent_event = child_event->parent;
 	u64 child_val;
 
-	if (child_event->attr.inherit_stat)
-		perf_event_read_event(child_event, child);
+	if (child_event->attr.inherit_stat) {
+		struct task_struct *task = child_event->ctx->task;
+
+		if (task)
+			perf_event_read_event(child_event, task);
+	}
 
 	child_val = perf_event_count(child_event);
 
@@ -12401,60 +12423,53 @@ static void sync_child_event(struct perf
 }
 
 static void
-perf_event_exit_event(struct perf_event *child_event,
-		      struct perf_event_context *child_ctx,
-		      struct task_struct *child)
+perf_event_exit_event(struct perf_event *event, struct perf_event_context *ctx)
 {
-	struct perf_event *parent_event = child_event->parent;
+	struct perf_event *parent_event = event->parent;
+	unsigned long detach_flags = 0;
 
-	/*
-	 * Do not destroy the 'original' grouping; because of the context
-	 * switch optimization the original events could've ended up in a
-	 * random child task.
-	 *
-	 * If we were to destroy the original group, all group related
-	 * operations would cease to function properly after this random
-	 * child dies.
-	 *
-	 * Do destroy all inherited groups, we don't care about those
-	 * and being thorough is better.
-	 */
-	raw_spin_lock_irq(&child_ctx->lock);
-	WARN_ON_ONCE(child_ctx->is_active);
+	if (parent_event) {
+		/*
+		 * Do not destroy the 'original' grouping; because of the
+		 * context switch optimization the original events could've
+		 * ended up in a random child task.
+		 *
+		 * If we were to destroy the original group, all group related
+		 * operations would cease to function properly after this
+		 * random child dies.
+		 *
+		 * Do destroy all inherited groups, we don't care about those
+		 * and being thorough is better.
+		 */
+		detach_flags = DETACH_GROUP | DETACH_CHILD;
+		mutex_lock(&parent_event->child_mutex);
+	}
 
-	if (parent_event)
-		perf_group_detach(child_event);
-	list_del_event(child_event, child_ctx);
-	perf_event_set_state(child_event, PERF_EVENT_STATE_EXIT); /* is_event_hup() */
-	raw_spin_unlock_irq(&child_ctx->lock);
+	perf_remove_from_context(event, detach_flags);
+
+	raw_spin_lock_irq(&ctx->lock);
+	if (event->state > PERF_EVENT_STATE_EXIT)
+		perf_event_set_state(event, PERF_EVENT_STATE_EXIT);
+	raw_spin_unlock_irq(&ctx->lock);
 
 	/*
-	 * Parent events are governed by their filedesc, retain them.
+	 * Child events can be freed.
 	 */
-	if (!parent_event) {
-		perf_event_wakeup(child_event);
+	if (parent_event) {
+		mutex_unlock(&parent_event->child_mutex);
+		/*
+		 * Kick perf_poll() for is_event_hup();
+		 */
+		perf_event_wakeup(parent_event);
+		free_event(event);
+		put_event(parent_event);
 		return;
 	}
-	/*
-	 * Child events can be cleaned up.
-	 */
-
-	sync_child_event(child_event, child);
 
 	/*
-	 * Remove this event from the parent's list
-	 */
-	WARN_ON_ONCE(parent_event->ctx->parent_ctx);
-	mutex_lock(&parent_event->child_mutex);
-	list_del_init(&child_event->child_list);
-	mutex_unlock(&parent_event->child_mutex);
-
-	/*
-	 * Kick perf_poll() for is_event_hup().
+	 * Parent events are governed by their filedesc, retain them.
 	 */
-	perf_event_wakeup(parent_event);
-	free_event(child_event);
-	put_event(parent_event);
+	perf_event_wakeup(event);
 }
 
 static void perf_event_exit_task_context(struct task_struct *child, int ctxn)
@@ -12511,7 +12526,7 @@ static void perf_event_exit_task_context
 	perf_event_task(child, child_ctx, 0);
 
 	list_for_each_entry_safe(child_event, next, &child_ctx->event_list, event_entry)
-		perf_event_exit_event(child_event, child_ctx, child);
+		perf_event_exit_event(child_event, child_ctx);
 
 	mutex_unlock(&child_ctx->mutex);
 
@@ -12771,6 +12786,7 @@ inherit_event(struct perf_event *parent_
 	 */
 	raw_spin_lock_irqsave(&child_ctx->lock, flags);
 	add_event_to_ctx(child_event, child_ctx);
+	child_event->attach_state |= PERF_ATTACH_CHILD;
 	raw_spin_unlock_irqrestore(&child_ctx->lock, flags);
 
 	/*

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFn/I3aKF%2BTOjGcl%40hirez.programming.kicks-ass.net.
