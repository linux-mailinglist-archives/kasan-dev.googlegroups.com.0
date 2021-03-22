Return-Path: <kasan-dev+bncBCV5TUXXRUIBBWUS4OBAMGQEY4YLAMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id B74E7344BFF
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 17:44:10 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id n17sf9609wmi.2
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 09:44:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616431450; cv=pass;
        d=google.com; s=arc-20160816;
        b=FA4UFlEGzQhRfIawikQP0Ph+qifOKmAqRO41+CkkhX2XSZ3sF4V1P66tyaJOMWOwnX
         J/ySCbFX6g0ipmxHPlcPyIG+EmDwpxt4TBmO+S6FMyp5OaVsjFK9K4aNYv5acRVmMksN
         Fhfz7IbsAoPGsGmQFGEp8NVE78rWXUcLOFl6tmVDgukBKd8D5JiGUWj1iu1C01+eEiYY
         xaP/2weA9griOjLWS4V5FN6RrfdebbxXvzz9nCx70yfma+hQH4hGSDsuAeDk48rc2Kpf
         082ksXfrEgSvA7qR4E5bWd3jB1m6C+R7vE5XzM8d637X+DYqKwVQn3gmMNu1qPP+czBe
         yvyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HI0hileq5h4cbvxUi+D4P3yN23uM0HbAQd5/UTOqOUQ=;
        b=w7P/EavZJZ057dtHpY/JshW1aY8h2YeFhpH7IHtlmRlRST/5+cygAKoWckA1wV+kQf
         qHV03CUld5MVm36m2XaWX8qkNH46mHHhJ7BU9krMubZfBbe54dT0qks1yBYvrhaeLQ8/
         M1RIA6YT7Jl8TyqPfB6YBRu6MYEuOUtOCnMOIV9O1m8QPTrGId1CukOk3ZB3ZFd4mAKj
         06z1JxvqyoJcHB0rvPgAfCdZN1kXkqQSSoUrbYSOjkWWgInDr3vpxhQJzD+qd6MLPrCh
         ozkLcnpwnavNW+itQKVHmEEyGjbcsUEw2o9v1kLCj04Rvnxq+cj2AzOAKsN5LTLfWbUk
         AcuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=vdjjBNmq;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HI0hileq5h4cbvxUi+D4P3yN23uM0HbAQd5/UTOqOUQ=;
        b=rLfUSEUdFg+gUHOvkli4EQQNO3M2DzooS7r9AR5wSp8OznyysdSCw+Q50s2C71Ci0k
         9g96fXNsP/kozG10O2ySxpk59TKXtHNdT/SmJF4UhAs0n0EYrYMIVIet8iQx6saH5/HG
         o+1uOnBU7eQJ4QH+ew6hGreyIHf61PQkyd8uINJVoMnt5kIFmr57xcJLymJBztJ8mlR5
         bTsJBC3KP2C0ZLHaa+1J1HneC+hF8jAUXRVv4xzHSS/cqNftzZ0mMfUWV8KRE1x1x0Xb
         wcfuAnTCbPtuA9FhzRAr1JXux/Ner1uNZLB/UsuWAmv7mlCM4NfMymZ7wRyqQ9dcv0/0
         f3Rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HI0hileq5h4cbvxUi+D4P3yN23uM0HbAQd5/UTOqOUQ=;
        b=cY+z/WM3ciHyo5o5v8t7CguGhFxztxl5U4s72mFqleqiJYMKuGoJfNoKtXQkVwQF7C
         jkouMVEOmc93Kt6yHPvxdCfBTGbkLC2uFqogKYqLHToPeD5I9hVD9iHLV2ozjL71H/mn
         D/NEBRtQBLPNdgi+FPrXhoTeadgBQzH+5roeHJoII+K79nd40q2ZvLPHufnx1Yt0vBIm
         2qGmeNbSir3Ud+id070GJ/2zuMW2A+85J5LmFMuHxmgJ6YmoILZ7qoq6lRcWRnLgVpx1
         yRCOml2olFPwU6RwdnT5EKhxNNTOY4s2narJZ7M/tz/ImuxpWy+HFpx0xZDzXzYgoW7M
         hG9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532zFboxZIjcRk3rRKiB0KU+EanrX6XV7b/aUoyF1S64Q9EfXpgx
	6gni2B5oEb35FT06waZM3/8=
X-Google-Smtp-Source: ABdhPJwUeK9hzAL/j7iq0xPwfvRn7DDm21ebg1VYv1zv9Wqek44aWN+b5MpiqXMAIn46V4mHFyVoHg==
X-Received: by 2002:a5d:4523:: with SMTP id j3mr456226wra.288.1616431450450;
        Mon, 22 Mar 2021 09:44:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:162d:: with SMTP id v13ls321432wrb.1.gmail; Mon, 22
 Mar 2021 09:44:09 -0700 (PDT)
X-Received: by 2002:adf:fa41:: with SMTP id y1mr437374wrr.256.1616431449616;
        Mon, 22 Mar 2021 09:44:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616431449; cv=none;
        d=google.com; s=arc-20160816;
        b=uvsKSjd1/TI89ZhXrONmEE7Lt94u1UyHiddv1Y17bkKNW0Uomp9ntZueZok0iyw9Mt
         ETX4pbrQbgQhyhvVzD9pJyL1LCYPgzTa+6Uhm4r8lgV8fEvngkgtReNUFG3AZHxzdqI1
         Vf4/lb/2JvAsbs0gSXX6fbR5dgMiz81GWfCCju6/ZuO78+ATIOBmNCtqkQpsimRpX/pa
         c3s6hsiXd6Y9vtXwV3zTEx7CqNR96tjc0+WbWRy8P9J0zM4pjOT8Ra3Sc9uXYuHQiVj8
         8CbfJ7cnNbrNKJaDSRT18w98SbR2M3bOfCY6gXkqFOQ+T29hXtJcNR8AjxuNdgooRiMZ
         xc9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1df6usl2xnnPsrzqbx3EXcAa7CHt7bVOPUkJ821J5Gw=;
        b=ELNj5OAVYN9VlnWQe7magMaQC1F/a9GC39KKIFb6pyC9ksdCbo+UWcRdMkFkSardF8
         Rop11PliqM3pIqjPy/JhnP8oabwiehSZas7VxDNDd8a4B7aWtcBRobPQ18Bw2uy7cz3M
         2KvlW0KOKMu9uZdiTFVcAlgIosA4BWVPcpF3hJyVweSNeMuvgy+rxKqcQBdX55mWofuD
         ZdRKsoSM+LvkblpSQZ9ySsJBXcIW/2hmBh4WaSoFw/+fPQAEieSW8Kj+HIqqU92T1Duw
         kFsgvauv9tWol+Wt+TH0c0q+OsQr5HXoqkGNXCcAmLu2jvWM1a+WMG8EEcwe4YZ3ZUNz
         Rt/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=vdjjBNmq;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id h16si513710wrx.2.2021.03.22.09.44.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Mar 2021 09:44:09 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1lONd9-008nQ9-Ma; Mon, 22 Mar 2021 16:42:49 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id E55BC30377D;
	Mon, 22 Mar 2021 17:42:14 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id C792A2BF3371C; Mon, 22 Mar 2021 17:42:14 +0100 (CET)
Date: Mon, 22 Mar 2021 17:42:14 +0100
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
Message-ID: <YFjI5qU0z3Q7J/jF@hirez.programming.kicks-ass.net>
References: <20210310104139.679618-1-elver@google.com>
 <20210310104139.679618-9-elver@google.com>
 <YFiamKX+xYH2HJ4E@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YFiamKX+xYH2HJ4E@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=vdjjBNmq;
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

On Mon, Mar 22, 2021 at 02:24:40PM +0100, Marco Elver wrote:
> To make compatible with more recent libc, we'll need to fixup the tests
> with the below.

OK, that reprodiced things here, thanks!

The below seems to not explode instantly.... it still has the
alternative version in as well (and I think it might even work too, but
the one I left in seems simpler).

---

 kernel/events/core.c | 154 +++++++++++++++++++++++++++++++++++++--------------
 1 file changed, 111 insertions(+), 43 deletions(-)

diff --git a/kernel/events/core.c b/kernel/events/core.c
index a7220e8c447e..8c0f905cc017 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -2167,8 +2172,9 @@ static void perf_group_detach(struct perf_event *event)
 	 * If this is a sibling, remove it from its group.
 	 */
 	if (leader != event) {
+		leader->nr_siblings--;
 		list_del_init(&event->sibling_list);
-		event->group_leader->nr_siblings--;
+		event->group_leader = event;
 		goto out;
 	}
 
@@ -2182,8 +2188,9 @@ static void perf_group_detach(struct perf_event *event)
 		if (sibling->event_caps & PERF_EV_CAP_SIBLING)
 			perf_remove_sibling_event(sibling);
 
-		sibling->group_leader = sibling;
+		leader->nr_siblings--;
 		list_del_init(&sibling->sibling_list);
+		sibling->group_leader = sibling;
 
 		/* Inherit group flags from the previous leader */
 		sibling->group_caps = event->group_caps;
@@ -2360,10 +2367,19 @@ __perf_remove_from_context(struct perf_event *event,
 static void perf_remove_from_context(struct perf_event *event, unsigned long flags)
 {
 	struct perf_event_context *ctx = event->ctx;
+	bool remove;
 
 	lockdep_assert_held(&ctx->mutex);
 
-	event_function_call(event, __perf_remove_from_context, (void *)flags);
+	/*
+	 * There is concurrency vs remove_on_exec().
+	 */
+	raw_spin_lock_irq(&ctx->lock);
+	remove = (event->attach_state & PERF_ATTACH_CONTEXT);
+	raw_spin_unlock_irq(&ctx->lock);
+
+	if (remove)
+		event_function_call(event, __perf_remove_from_context, (void *)flags);
 
 	/*
 	 * The above event_function_call() can NO-OP when it hits
@@ -4232,41 +4248,92 @@ static void perf_event_enable_on_exec(int ctxn)
 static void perf_remove_from_owner(struct perf_event *event);
 static void perf_event_exit_event(struct perf_event *child_event,
 				  struct perf_event_context *child_ctx,
-				  struct task_struct *child);
+				  struct task_struct *child,
+				  bool removed);
 
 /*
  * Removes all events from the current task that have been marked
  * remove-on-exec, and feeds their values back to parent events.
  */
-static void perf_event_remove_on_exec(void)
+static void perf_event_remove_on_exec(int ctxn)
 {
-	int ctxn;
+	struct perf_event_context *ctx, *clone_ctx = NULL;
+	struct perf_event *event, *next;
+	LIST_HEAD(free_list);
+	unsigned long flags;
+	bool modified = false;
 
-	for_each_task_context_nr(ctxn) {
-		struct perf_event_context *ctx;
-		struct perf_event *event, *next;
+	ctx = perf_pin_task_context(current, ctxn);
+	if (!ctx)
+		return;
 
-		ctx = perf_pin_task_context(current, ctxn);
-		if (!ctx)
+	mutex_lock(&ctx->mutex);
+
+	if (WARN_ON_ONCE(ctx->task != current))
+		goto unlock;
+
+	list_for_each_entry_safe(event, next, &ctx->event_list, event_entry) {
+		if (!event->attr.remove_on_exec)
 			continue;
-		mutex_lock(&ctx->mutex);
 
-		list_for_each_entry_safe(event, next, &ctx->event_list, event_entry) {
-			if (!event->attr.remove_on_exec)
-				continue;
+		if (!is_kernel_event(event))
+			perf_remove_from_owner(event);
 
-			if (!is_kernel_event(event))
-				perf_remove_from_owner(event);
-			perf_remove_from_context(event, DETACH_GROUP);
-			/*
-			 * Remove the event and feed back its values to the
-			 * parent event.
-			 */
-			perf_event_exit_event(event, ctx, current);
-		}
-		mutex_unlock(&ctx->mutex);
-		put_ctx(ctx);
+		modified = true;
+
+		perf_remove_from_context(event, !!event->parent * DETACH_GROUP);
+		perf_event_exit_event(event, ctx, current, true);
+	}
+
+	raw_spin_lock_irqsave(&ctx->lock, flags);
+	if (modified)
+		clone_ctx = unclone_ctx(ctx);
+	--ctx->pin_count;
+	raw_spin_unlock_irqrestore(&ctx->lock, flags);
+
+#if 0
+	struct perf_cpu_context *cpuctx;
+
+	if (!modified) {
+		perf_unpin_context(ctx);
+		goto unlock;
+	}
+
+	local_irq_save(flags);
+	cpuctx = __get_cpu_context(ctx);
+	perf_ctx_lock(cpuctx, ctx);
+	task_ctx_sched_out(cpuctx, ctx, EVENT_ALL);
+
+	list_for_each_entry_safe(event, next, &ctx->event_list, event_entry) {
+		if (!event->attr.remove_on_exec)
+			continue;
+
+		if (event->parent)
+			perf_group_detach(event);
+		list_del_event(event, ctx);
+
+		list_add(&event->active_list, &free_list);
+	}
+
+	ctx_resched(cpuctx, ctx, EVENT_ALL);
+
+	clone_ctx = unclone_ctx(ctx);
+	--ctx->pin_count;
+	perf_ctx_unlock(cpuctx, ctx);
+	local_irq_restore(flags);
+
+	list_for_each_entry_safe(event, next, &free_list, active_entry) {
+		list_del(&event->active_entry);
+		perf_event_exit_event(event, ctx, current, true);
 	}
+#endif
+
+unlock:
+	mutex_unlock(&ctx->mutex);
+
+	put_ctx(ctx);
+	if (clone_ctx)
+		put_ctx(clone_ctx);
 }
 
 struct perf_read_data {
@@ -7615,20 +7682,18 @@ void perf_event_exec(void)
 	struct perf_event_context *ctx;
 	int ctxn;
 
-	rcu_read_lock();
 	for_each_task_context_nr(ctxn) {
-		ctx = current->perf_event_ctxp[ctxn];
-		if (!ctx)
-			continue;
-
 		perf_event_enable_on_exec(ctxn);
+		perf_event_remove_on_exec(ctxn);
 
-		perf_iterate_ctx(ctx, perf_event_addr_filters_exec, NULL,
-				   true);
+		rcu_read_lock();
+		ctx = rcu_dereference(current->perf_event_ctxp[ctxn]);
+		if (ctx) {
+			perf_iterate_ctx(ctx, perf_event_addr_filters_exec,
+					 NULL, true);
+		}
+		rcu_read_unlock();
 	}
-	rcu_read_unlock();
-
-	perf_event_remove_on_exec();
 }
 
 struct remote_output {
@@ -12509,7 +12574,7 @@ static void sync_child_event(struct perf_event *child_event,
 static void
 perf_event_exit_event(struct perf_event *child_event,
 		      struct perf_event_context *child_ctx,
-		      struct task_struct *child)
+		      struct task_struct *child, bool removed)
 {
 	struct perf_event *parent_event = child_event->parent;
 
@@ -12526,12 +12591,15 @@ perf_event_exit_event(struct perf_event *child_event,
 	 * and being thorough is better.
 	 */
 	raw_spin_lock_irq(&child_ctx->lock);
-	WARN_ON_ONCE(child_ctx->is_active);
+	if (!removed) {
+		WARN_ON_ONCE(child_ctx->is_active);
 
-	if (parent_event)
-		perf_group_detach(child_event);
-	list_del_event(child_event, child_ctx);
-	perf_event_set_state(child_event, PERF_EVENT_STATE_EXIT); /* is_event_hup() */
+		if (parent_event)
+			perf_group_detach(child_event);
+		list_del_event(child_event, child_ctx);
+	}
+	if (child_event->state >= PERF_EVENT_STATE_EXIT)
+		perf_event_set_state(child_event, PERF_EVENT_STATE_EXIT); /* is_event_hup() */
 	raw_spin_unlock_irq(&child_ctx->lock);
 
 	/*
@@ -12617,7 +12685,7 @@ static void perf_event_exit_task_context(struct task_struct *child, int ctxn)
 	perf_event_task(child, child_ctx, 0);
 
 	list_for_each_entry_safe(child_event, next, &child_ctx->event_list, event_entry)
-		perf_event_exit_event(child_event, child_ctx, child);
+		perf_event_exit_event(child_event, child_ctx, child, false);
 
 	mutex_unlock(&child_ctx->mutex);
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFjI5qU0z3Q7J/jF%40hirez.programming.kicks-ass.net.
