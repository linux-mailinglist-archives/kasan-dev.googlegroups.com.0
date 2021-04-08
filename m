Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQNZXOBQMGQEKJLK2MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 59C993580B6
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 12:36:50 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id d16sf791422otc.5
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 03:36:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617878209; cv=pass;
        d=google.com; s=arc-20160816;
        b=MeIg60JRECIKv0b8x1BNKJeqPUCJndeQ3dKWFDy1t9j2Q5SK5cUms0ocviBs1d8aBV
         UqpJDCZbfdo0DbFF8+J4ygk/6ALEIWwfRQ2hs1oRnJAfXSMI7chQRDy+LvDViSymL7WB
         UUk//kCIpxY7NZiwghcdv6Tjs/50Otsn5jurX7eBZWGBwqbp2Kkwp7t/5hVnI3RpJ9M5
         Gwl7zlJ3ZGWnhbXSIL83Q3fzpYA2iZfgydyoAWlgtZl66oIzLdhecj1kVCykGWn+zTU1
         3CgJ6W83XZYiZJl58OGW0bsOQCu5NtEuFCDbR6DEh+tjgy1gG4064U3Z4fW5SQdTayU7
         EGag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=3HKG/ZPj/rC78EYQpwRJpSZje8J2qSRHx7wprOFzy0k=;
        b=UNwxNDiG/SicPaj0Ya3aEyMC9N6a5H32SO8oYwXwDsvABVgm8fI+ZrW7bAghuuks/r
         nWxxsjW+E+Sx3xNq4HaRQYIiOvnvp4DzdE7pPM6OJuS3Bs8zFfvWAXkUmbUeQZhsM+bI
         Ys0czs3bM6oqWvkDe3/ldQnhYG7a+eGQ1CAH0VoTHs9zDNqVydiXUNSFBDgZJ5McQsh6
         hluITYElwu6q06ctecfI1/65V6n9xGzdfhWr28VAnX00DPUDZS3RcS4/2QEvqom4fxqb
         DNfObUJhk1hDNDSDsbHJ3XUB9s/2ZCOZFI4o01YSohr7FPZe81H+Pgt9a6oTGAlN0rwr
         4xmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H+7dHwPH;
       spf=pass (google.com: domain of 3wnxuyaukct8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3wNxuYAUKCT8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3HKG/ZPj/rC78EYQpwRJpSZje8J2qSRHx7wprOFzy0k=;
        b=O82jLMXaZmIM2Xt66d+qBb1JFhInQA2NDZjKZtBMqt31oCjNaRS0inPAAmKktnGXAf
         y55qDn4Gac0SmvviZWlu2TNXJAS8cOeOj6yFmKJAwu4RgP5EC3U7RPNOe4GxPrSpG/Dt
         /KQtKMJ5xkhWCGvpphy58AoZsIYM5Hu81fYHj6k8UwFR8v0/sGJI0h4UMLzalZLCL2pY
         zJ9hcXqZm7IouyjCOvDrJC9OwCbzFvwnYFi9S2dD7C1kV3whMS6Gv7t5c/273S+wAJ39
         Iqn17Cha7j9lAJ9j8VH+Id6tM1fbsB8fZVL2iFFmW/rnQ7/z44s1NOSHA22TfgiLZP35
         pGfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3HKG/ZPj/rC78EYQpwRJpSZje8J2qSRHx7wprOFzy0k=;
        b=ZDMF2PzIkObTeTr1AvTTm6/EDvR+DWH8QwTYf3vuNo06w0tgqaz1ok43m/EQDh8I8s
         UHM9vq30F2QYsh7y+fz4IwCmNQBIHsscc3vqLg8otxrA0uNXXnZnm3OmMgUXiL/3TF4f
         Fam7ANCb4FLeeipAuqI6S8Ai/N/j4LrZBqU+IplPy/mBR9rkjehjGswPuk2HomvaNQ1b
         46YdqIEPPMEzH/qSdsXYqeWw8qaSb52a1TtBhdrSR51ADh1Wsa/0KSAriD/MVLFmUtsB
         bb1Vy5KwnxEX6nC/8/sWuAw1uUhO/Zpjva2ha6Xy+HohxNea7IK4GfYgEDhUYb+sWyjR
         Sfyw==
X-Gm-Message-State: AOAM533i90AOzKD712d0VgTjTKAztHWxXlvuU3UDQLK79LNBNDFA2Z5h
	mTyRsmk0IcOFkfHLjuuliMA=
X-Google-Smtp-Source: ABdhPJwGxJZf3QkEKsftAAK1E+3uvgKoP9jyQCeWyUt6tOHAVMg8EZntdlJJbqtJ4Pi1qB038S6gLg==
X-Received: by 2002:a9d:1b8:: with SMTP id e53mr6896312ote.97.1617878209185;
        Thu, 08 Apr 2021 03:36:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5551:: with SMTP id h17ls1262085oti.1.gmail; Thu, 08 Apr
 2021 03:36:48 -0700 (PDT)
X-Received: by 2002:a05:6830:1515:: with SMTP id k21mr6879342otp.269.1617878208827;
        Thu, 08 Apr 2021 03:36:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617878208; cv=none;
        d=google.com; s=arc-20160816;
        b=lvt2Y04VSRVYFOQLEueY7cBCGvMjVPHQScFuG4NviWrDMxhzZK1Mfa9Z/kugKqoTJ4
         WL8GdPw9BZZsudkWirurQwTBrdnLVKctr4P6CTWI9M/5ynOvbVCJGvUqF2QA21akigyB
         JwgqkiaUpGmRkch5dDfpm0khUNV7zKixXbIhgZIAHy61zQzTP/i62OsyQpbbEmjwLEV+
         tqxzFVSiK+5LEEa/pMwf4ebzBkfKtPBVR5ymn1kSAnu2KiqRcn92eM3EyqhS03cOluN8
         Jl1xz+3BKjHEXNaLYIqZJuRrjM6uom4Ubn/L4LWaAJU+InIzJRKRfhDd8ih4THT6usR5
         JT0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=9HmcB50z3wsmZOTGVRWLwJaFzCLoR3Qg3FfFsE4P02g=;
        b=Aj3cx+vua735plVFmGUhx17dogLRi7cnmPBd9T6MHZXSHCfiPsQ/yv2RiIR81fVCpj
         wWc8NdGndB41a2p9aFFpEn4/GfG6qwhgDqw0pdn+k17abMC7haQ2kLPwy+1JibXUiufO
         Iiv1bIAD5hn3Lez9uAZ6tgeCSTm1qhYGE0PeAe2W7icDQgbRpMkCVJswOtPpZc8pEZzF
         +lX9/C7h4ZVjt5+09luwamNRyY2vAanagLm5x4FxfsazIehMPoTXE/g2CVmc7yiT/hGW
         aI/SM8dRGYrND2Lk9JWWIEUTaEG8NuGQnkwYf5PF23PVvxtLKh3NJk6XKZLuXMgtu+cX
         JLvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H+7dHwPH;
       spf=pass (google.com: domain of 3wnxuyaukct8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3wNxuYAUKCT8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id b17si26714ooq.2.2021.04.08.03.36.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Apr 2021 03:36:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wnxuyaukct8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id t24so1000476qkg.3
        for <kasan-dev@googlegroups.com>; Thu, 08 Apr 2021 03:36:48 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:9038:bbd3:4a12:abda])
 (user=elver job=sendgmr) by 2002:a0c:f64e:: with SMTP id s14mr7988656qvm.15.1617878208239;
 Thu, 08 Apr 2021 03:36:48 -0700 (PDT)
Date: Thu,  8 Apr 2021 12:35:56 +0200
In-Reply-To: <20210408103605.1676875-1-elver@google.com>
Message-Id: <20210408103605.1676875-2-elver@google.com>
Mime-Version: 1.0
References: <20210408103605.1676875-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.208.g409f899ff0-goog
Subject: [PATCH v4 01/10] perf: Rework perf_event_exit_event()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, oleg@redhat.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=H+7dHwPH;       spf=pass
 (google.com: domain of 3wnxuyaukct8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3wNxuYAUKCT8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
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
[ elver@google.com: fix racing parent/child exit in sync_child_event(). ]
Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Fix for parent and child racing to exit in sync_child_event().

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
index 03db40f6cba9..e77294c7e654 100644
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
+		if (task && task != TASK_TOMBSTONE)
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
2.31.0.208.g409f899ff0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210408103605.1676875-2-elver%40google.com.
