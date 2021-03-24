Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI6D5SBAMGQEWSJKA5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id B8DE434770D
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 12:25:24 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id l2sf1342079pgi.5
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 04:25:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616585123; cv=pass;
        d=google.com; s=arc-20160816;
        b=V78uxzLS+PT8sM/88tScLW5kxFYenLon7LVMb3TDcftgiCzA7GGD/Wlu7PnW4XeH5b
         BQaXU+4zG45LTrewCbYDnTz5fC9ezbS7zq8t/ZrHSpDqgvnwFszF9K0a5f0vefAOmJdo
         lgtk5jlqnM2Uj/AL4gr5hdesEmdpPMDtuASCkxP9kh/uvYwjx60obtTAZfz1NWVA0MAl
         EwhED7GBNkeio22UeyoCaCOGLD2GU6GnIp3iq9zG8wHhliJvz87Wl4O7NP4n7fvr8qmk
         PNfKgLb4iACt2/diPy4b30bsFK+LsNSC1Dd3X/fkm4f603r7NAY0V65M2xnHMInAM1d3
         2ggw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=5hcK4EMZPAEs/HnUryNjXxI7VT85HKP71KSBFquvxeY=;
        b=f5Of1rzMUMnWCBuliVs8MCqapAI7Rf/K/OZsnvJr95Zzxc8YwMpM8oezB5yTkZflo0
         o56KVA+yZvoKwNytICUEYi6e1rged9zpifA7BufXPXdo8b2jmsHXQvYecjmi7CckCj60
         t1PWP+ZC+JZJodgs2oAumeO23rRCy9HSwnAbavdHuGNy4MraOtd+dJML6yyKl2vThfj/
         Y1dMy4MUHBR1iC7kQURp9XZX8FpsDMtLDiZfUqX4yoc+5wskEmmFqtI9vOpxNAi31c4K
         Pqnk1b6InEMOFsyuaPfq6AWHQ6XaPh2p+7VVFhiGSh/Ems1fU+80s4gYrlWD5wYFLlbr
         na4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kJMYNK+Q;
       spf=pass (google.com: domain of 3oifbyaukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3oiFbYAUKCVs7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5hcK4EMZPAEs/HnUryNjXxI7VT85HKP71KSBFquvxeY=;
        b=sT2n9cHIZR9gh+IGWuSE9Bu4GQkaUMhozIdRfb8TEa+S8sRrzfBNtYXbtWAFGLVVuL
         7nJY8JL5fg9+YPxtvKKbwIEEfpuqvKq4DjQwHxwUD7/rmWyQyHqHutF7+QJU7uaoqo9a
         rYzZLyO9PyRVr4hO7L61ipx8+RWFidR/aDmyLAwwS2S0YQNLbkzWms/1m5rP7TDZ1s9I
         iKT2FwGedEPn9AiqXKlrO2vAHRxxxHh0CJEJ178WGJ6sCqPD/ssOGictH2FAT4i1p9Xg
         jf1zJsDFNbiKH4A+JBjO2TydK0UCa+6huOHYOHlQDVjHUxboCBr0vVGPMgVLSzuB1CF5
         iqZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5hcK4EMZPAEs/HnUryNjXxI7VT85HKP71KSBFquvxeY=;
        b=KYrhXeeTljufd50n3Jh2jPVrH0MnnmCXn2tyFRvVo8toKJQots9Jde/w5SZt9x72C+
         /tTcJBo1Rp62mmx1HjTcCTesjf/St1roJvOHhqKQIq3Gk6OKN0M1XyzvaHDbg3HKt2lJ
         csdWHgb1b/fazb08VYXC7V+Nnltv1HE46Az3hmLZGv48UALzm54IY8U8A6E90ntFZ+cw
         eJYq2Ydbt5rQP40PdEkqs1WRIVjfX2Fge6VEarXYSoyBE0wdViUG42kNknvk+t33zO0e
         90D0kmpJtO94o5XonPx2EASEbMccEyUuUj5cgMQITGQDH2w5SBSLqo3/WiOq9wTnjOEB
         sprQ==
X-Gm-Message-State: AOAM5305cGnB+wJ6TyIhgVJb4Te4O3JHiWCI4qnB2lIzX4mg/4iwKSY0
	WrVD0UOJmiPwbe4bl8jc5MU=
X-Google-Smtp-Source: ABdhPJwcg0DYZ+R0Cl7OztGc4nh+v812umUkDe4NEquv2qQFQtRu6BhcNJ4QbTUhsHtvxDqcZL0GGA==
X-Received: by 2002:a17:90a:9e7:: with SMTP id 94mr2870478pjo.117.1616585123518;
        Wed, 24 Mar 2021 04:25:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ac09:: with SMTP id v9ls822532pfe.2.gmail; Wed, 24 Mar
 2021 04:25:23 -0700 (PDT)
X-Received: by 2002:a63:4e48:: with SMTP id o8mr2619230pgl.420.1616585122948;
        Wed, 24 Mar 2021 04:25:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616585122; cv=none;
        d=google.com; s=arc-20160816;
        b=Cs+tjbhG3P4Lhz3/NSQ1s2cPnnnqQgGJqbHuJoSCx6OfHGBtRJuE3cGvMgJgZ6x6AR
         iuNiWdYX0FqdcRHSK+JosbY/ck4BiFpISjHLfm8dpOLMscC/gQdUe8zG/tbG0v6POqsA
         hjkxywxtZYn8cpbROm9Z7YJF7vdSPQaTMqxCsKHFe+29j911mD7qcvRrdtVfmXzGHVOk
         4p9oBH1CKguHHG2uZF/E6po6M2q85ycnMNsV8czRid7dheaJ1o2ezgcPFudiy9HkjSyP
         +FIpknfvnjd6pst2iYKnUIUCNWeUMveNBllGEan416v1a9IeamRAdxV4HmQwVONo86/l
         vbKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=0RXOU0urSfzaqeg4UkeG1NpS6f1gTiG8ooIM498Ibs0=;
        b=SLhfrftvy61U/AOUBG0Z3zvd+mgz+p5EOtzL6WhMpPaAAXDYgqeopn/qzkeqogR1rr
         dX0z7MonO8ZFL62zRgLBejKO1ut5sBDzJzuK37r3R6X8EwjwHbVEpxp+NYF+DY2W8pN8
         Z2YOxVS8q8qo0URMqwvIHNGT4GCRmqdMCjKGcMJsm6DkvAgIgP+5v622MuzYzIkZMVF1
         K3Nw0hsP4pvvGT318CzmPnPgdXydn+FkwC20/1uGacokfh2UiCsDQkXHmUoGWjPBbPja
         vqeJQaeOPhFzHw16K7GpdIVyoHuUzfb1BsDA/mANDWn6XvkWhrYSxvvo+xbi7hOj/FuV
         aCDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kJMYNK+Q;
       spf=pass (google.com: domain of 3oifbyaukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3oiFbYAUKCVs7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id 131si84096pfa.2.2021.03.24.04.25.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Mar 2021 04:25:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3oifbyaukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id 11so962323qtz.7
        for <kasan-dev@googlegroups.com>; Wed, 24 Mar 2021 04:25:22 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6489:b3f0:4af:af0])
 (user=elver job=sendgmr) by 2002:a0c:d7ca:: with SMTP id g10mr2503240qvj.16.1616585122040;
 Wed, 24 Mar 2021 04:25:22 -0700 (PDT)
Date: Wed, 24 Mar 2021 12:24:53 +0100
In-Reply-To: <20210324112503.623833-1-elver@google.com>
Message-Id: <20210324112503.623833-2-elver@google.com>
Mime-Version: 1.0
References: <20210324112503.623833-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.291.g576ba9dcdaf-goog
Subject: [PATCH v3 01/11] perf: Rework perf_event_exit_event()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kJMYNK+Q;       spf=pass
 (google.com: domain of 3oifbyaukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3oiFbYAUKCVs7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

From: Peter Zijlstra <peterz@infradead.org>

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
Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* New dependency for series:
  https://lkml.kernel.org/r/YFn/I3aKF+TOjGcl@hirez.programming.kicks-ass.net
---
 include/linux/perf_event.h |   1 +
 kernel/events/core.c       | 142 +++++++++++++++++++++----------------
 2 files changed, 80 insertions(+), 63 deletions(-)

diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
index 3f7f89ea5e51..3d478abf411c 100644
--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -607,6 +607,7 @@ struct swevent_hlist {
 #define PERF_ATTACH_TASK_DATA	0x08
 #define PERF_ATTACH_ITRACE	0x10
 #define PERF_ATTACH_SCHED_CB	0x20
+#define PERF_ATTACH_CHILD	0x40
 
 struct perf_cgroup;
 struct perf_buffer;
diff --git a/kernel/events/core.c b/kernel/events/core.c
index 03db40f6cba9..57de8d436efd 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -2204,6 +2204,26 @@ static void perf_group_detach(struct perf_event *event)
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
@@ -2311,6 +2331,7 @@ group_sched_out(struct perf_event *group_event,
 }
 
 #define DETACH_GROUP	0x01UL
+#define DETACH_CHILD	0x02UL
 
 /*
  * Cross CPU call to remove a performance event
@@ -2334,6 +2355,8 @@ __perf_remove_from_context(struct perf_event *event,
 	event_sched_out(event, cpuctx, ctx);
 	if (flags & DETACH_GROUP)
 		perf_group_detach(event);
+	if (flags & DETACH_CHILD)
+		perf_child_detach(event);
 	list_del_event(event, ctx);
 
 	if (!ctx->nr_events && ctx->is_active) {
@@ -2362,25 +2385,21 @@ static void perf_remove_from_context(struct perf_event *event, unsigned long fla
 
 	lockdep_assert_held(&ctx->mutex);
 
-	event_function_call(event, __perf_remove_from_context, (void *)flags);
-
 	/*
-	 * The above event_function_call() can NO-OP when it hits
-	 * TASK_TOMBSTONE. In that case we must already have been detached
-	 * from the context (by perf_event_exit_event()) but the grouping
-	 * might still be in-tact.
+	 * Because of perf_event_exit_task(), perf_remove_from_context() ought
+	 * to work in the face of TASK_TOMBSTONE, unlike every other
+	 * event_function_call() user.
 	 */
-	WARN_ON_ONCE(event->attach_state & PERF_ATTACH_CONTEXT);
-	if ((flags & DETACH_GROUP) &&
-	    (event->attach_state & PERF_ATTACH_GROUP)) {
-		/*
-		 * Since in that case we cannot possibly be scheduled, simply
-		 * detach now.
-		 */
-		raw_spin_lock_irq(&ctx->lock);
-		perf_group_detach(event);
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
@@ -12373,14 +12392,17 @@ void perf_pmu_migrate_context(struct pmu *pmu, int src_cpu, int dst_cpu)
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
 
@@ -12395,60 +12417,53 @@ static void sync_child_event(struct perf_event *child_event,
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
@@ -12505,7 +12520,7 @@ static void perf_event_exit_task_context(struct task_struct *child, int ctxn)
 	perf_event_task(child, child_ctx, 0);
 
 	list_for_each_entry_safe(child_event, next, &child_ctx->event_list, event_entry)
-		perf_event_exit_event(child_event, child_ctx, child);
+		perf_event_exit_event(child_event, child_ctx);
 
 	mutex_unlock(&child_ctx->mutex);
 
@@ -12765,6 +12780,7 @@ inherit_event(struct perf_event *parent_event,
 	 */
 	raw_spin_lock_irqsave(&child_ctx->lock, flags);
 	add_event_to_ctx(child_event, child_ctx);
+	child_event->attach_state |= PERF_ATTACH_CHILD;
 	raw_spin_unlock_irqrestore(&child_ctx->lock, flags);
 
 	/*
-- 
2.31.0.291.g576ba9dcdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324112503.623833-2-elver%40google.com.
