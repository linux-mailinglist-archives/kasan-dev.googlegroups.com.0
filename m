Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4PU42BAMGQEWUWBETY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id C0C58345B63
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 10:52:49 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id a22sf1129998ljq.4
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 02:52:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616493169; cv=pass;
        d=google.com; s=arc-20160816;
        b=vCQ0Js0ElIdypaMDg/OV+Cwy2EBjCOoPRNT6yAH2pVafa1609cT1BWQ4gWA0dFO+9R
         H6Ij460EpsozfNzJK7yAIKFjXOqm/VQ80075MygW1gS3YOQsj0kBqBBDRcksylvuTQMs
         TIs8XiEyxV+IHXB1uT303bGrAJ++u3Yi9sYzCB5A+TiJ1+IuF65V6pQJT7nQxEhldRT7
         Tiao3O472aQq1dkZEULbuph1vgm3Dgf8BLyIRHsl4zLD+sJKdS0PLxvTdtooRpFLesmQ
         2qfVqcYWmSeyexTRBmflyC7N/tlBU60hIei9MqquuRj9slHyi8ooWwQ3/NWYdO0HKVgp
         jB7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=uNbl31zEkK9Ts5ovxfaLPoFCrM7lGIMn2odLyqMhDno=;
        b=JMHiAvEfkyR5AgtIBmeZL73iNznv9sBG5XQVQBLBNsQ7WWoscFiGwzDxw/d4dJYAeC
         ZRZkZVzIZQoGPA8BtXymFYzEY6GkM+KdN04EdJLxkKrEF+6MyiwQBb0427oK9eT1pdQE
         Li5yIed7e6RoitUyFwpJDTXSsYbjri09nkXv+AxWqz6cP+Ovr8PA4pNag74WtsRJ6TgH
         XmT+OzAviGpO5NTQSVZ6jW7aVDQ7nRhjmzIKtl+W36gL6CRObT45hyQcV5T/h0FSZEaC
         UvpVIP5e7NvQfT2hkjn8TaYmuVh0PKkJYYRJQdZO1h6rAJgyS/Qj0aWFBNwewxRrWDVp
         vMtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="nm5ohOy/";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=uNbl31zEkK9Ts5ovxfaLPoFCrM7lGIMn2odLyqMhDno=;
        b=say/3BlDwnkkm8WbiE9jwRHQp7YcJ2K0wwjj5mI3VsRk67OdcWSzNqHhB/7EY68DoT
         kvhs1Yk4vyq0iTtXKThuefgHibeZCIGlvhVK6vkhreQXwms8hLYOU4FSdydGt1XojiiB
         2pcjBoAq+XyePxMAMEmXm5ET3MB28JHXIgOL8Zauraa7ir0AmKmZkk54HAmhfmYHUD3O
         PI2e4aybxfJrKrSbnecbwJexqSdIVi2deZw0ifSV3bkac42wFmstoMUe0D2BwKD77njl
         tvo/mzJWQpSWRBdEjS0F0cN7YjcevmL0ZlUWGpP9yPdzKOOlRFvG3qMJcVwfkE6ZDuWA
         3gdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uNbl31zEkK9Ts5ovxfaLPoFCrM7lGIMn2odLyqMhDno=;
        b=IiUybemlPoLUulvUkljxHTTibFXJ2O5nVKxaV/wgdYFoHZAY/cwlbe3nuRZvg0PinC
         mYd3IoeuLevGHch4q1xTyCs+BmaH0sa4nuY+R5Z5HXMOjMPRcuayZqQrFfvLTvEGNPtA
         yVcRgY21GFsntvXSqS8nF2ilDWzcQOySm/eUiMlycNOYDj535qSrbXlqZ4/xTrzdi8UF
         RoO/V7IS+IX3NkjoHlsl2gIeywqL+EHOZ1zs2mJ1tDhQtz51JPAu6HAGk19jGKYyizRS
         mocwkeBo+3jK36SN8Xfk77bd0bvBz8keHgQJHrtvjSH/syaTyd1rCOVssDOz5I1JSxId
         mN2A==
X-Gm-Message-State: AOAM532winbDJYWb/LM8PqIbiFU+bjMiw7Zp8UIF15nfmkdCrn/Vw+vs
	Xfd0wvTVbl3sBwXzrkVP1oY=
X-Google-Smtp-Source: ABdhPJxRq4HCO1Y1x8F5V+jRBjri5kWllYS4Wg37Rys/Aqy2vEIDEYs+H+miwtJ0mkiC9fenlwdXJQ==
X-Received: by 2002:a05:651c:1055:: with SMTP id x21mr2535565ljm.275.1616493169314;
        Tue, 23 Mar 2021 02:52:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9a48:: with SMTP id k8ls3008943ljj.10.gmail; Tue, 23 Mar
 2021 02:52:48 -0700 (PDT)
X-Received: by 2002:a2e:8e28:: with SMTP id r8mr2703565ljk.156.1616493168157;
        Tue, 23 Mar 2021 02:52:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616493168; cv=none;
        d=google.com; s=arc-20160816;
        b=xL3e4pGr2IofWQCJ4qF30sPWkfC0eeJ8WLxXWAeMlv91DYtUhSSkngIYHTgVcxbkMl
         XskgZNK+n8sXlLoa1dpZ5danep0klso/mZMVLUxyzBLTN+3I3Xkg/Xo4KuAXhdsf8JbI
         6wElcwoRs/1kj0cYx9hAtvl6sXEKLGKaGqvGwTANvZBlpxUsZX6N6bn45AuTaZ3tdeap
         QyMNDofNLP3+RBGIukEpw8msVhO+ySZIrKOFvG+CzpxH/TA8DQWNbckG0UXDmea7benS
         MBfa/Z5JzU1VbTElKattiIbPCTaS7Yh0KqBAoMDImI8xzfEMvwz3GHvV9julDZ9MZthr
         c+Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=NpSzRKLiXLe6KNJ61EsuxfhUG16pLqYRTekTKu3oBUc=;
        b=kQJ3jKFQsh35VU5JHcO1s3oaMN/t2UgoyeS9ihAhOjVWnrWx4F43pZ81TqRotghafw
         Ycz4F2tJu7gDB/SL0yYKCYDDsLGdpyHBS40oxthZzwmsXf+MUCFTbEtjReh7QWcCRbIo
         ciXMiFa7uQOFNyqFsjL4DUdYM/XPIWWR/SfAzW6KHwne+IL94671qVtb56ZmxGejySfo
         jyJtKDG3omYnpwWuRzIfHWNuVZ5pjE6hTxdvcjifTgpNcIZByZmk2dg7kyOLfQUZ629K
         vvhdbposTDy4zb/xYeyZ6rwCCY8M8ag7Z6bGQ5ovZ/EnEZMacgzCOuHlZO6GHu3J+7Kd
         2XUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="nm5ohOy/";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id a10si639406lfs.11.2021.03.23.02.52.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Mar 2021 02:52:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 12so10669908wmf.5
        for <kasan-dev@googlegroups.com>; Tue, 23 Mar 2021 02:52:48 -0700 (PDT)
X-Received: by 2002:a1c:b687:: with SMTP id g129mr2555707wmf.165.1616493167647;
        Tue, 23 Mar 2021 02:52:47 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:4cfd:1405:ab5d:85f8])
        by smtp.gmail.com with ESMTPSA id c9sm22669184wrr.78.2021.03.23.02.52.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Mar 2021 02:52:46 -0700 (PDT)
Date: Tue, 23 Mar 2021 10:52:41 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
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
Message-ID: <YFm6aakSRlF2nWtu@elver.google.com>
References: <20210310104139.679618-1-elver@google.com>
 <20210310104139.679618-9-elver@google.com>
 <YFiamKX+xYH2HJ4E@elver.google.com>
 <YFjI5qU0z3Q7J/jF@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YFjI5qU0z3Q7J/jF@hirez.programming.kicks-ass.net>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="nm5ohOy/";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as
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

On Mon, Mar 22, 2021 at 05:42PM +0100, Peter Zijlstra wrote:
> On Mon, Mar 22, 2021 at 02:24:40PM +0100, Marco Elver wrote:
> > To make compatible with more recent libc, we'll need to fixup the tests
> > with the below.
> 
> OK, that reprodiced things here, thanks!
> 
> The below seems to not explode instantly.... it still has the
> alternative version in as well (and I think it might even work too, but
> the one I left in seems simpler).

Thanks! Unfortunately neither version worked if I tortured it a little
with this:

	for x in {1..1000}; do ( tools/testing/selftests/perf_events/remove_on_exec & ); done

Which resulted in the 2 warnings:

	WARNING: CPU: 1 PID: 795 at kernel/events/core.c:242 event_function+0xf3/0x100
	WARNING: CPU: 1 PID: 795 at kernel/events/core.c:247 event_function+0xef/0x100

with efs->func==__perf_event_enable. I believe it's sufficient to add

	mutex_lock(&parent_event->child_mutex);
	list_del_init(&event->child_list);
	mutex_unlock(&parent_event->child_mutex);

right before removing from context. With the version I have now (below
for completeness), extended torture with the above test results in no
more warnings and the test also passes.


I'd be happy to send a non-RFC v3 with all that squashed in. I'd need
your Signed-off-by for the diff you sent to proceed (and add your
Co-developed-by).

Thanks,
-- Marco

------ >8 ------

diff --git a/kernel/events/core.c b/kernel/events/core.c
index aa47e111435e..cea7c88fe131 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -2165,8 +2165,9 @@ static void perf_group_detach(struct perf_event *event)
 	 * If this is a sibling, remove it from its group.
 	 */
 	if (leader != event) {
+		leader->nr_siblings--;
 		list_del_init(&event->sibling_list);
-		event->group_leader->nr_siblings--;
+		event->group_leader = event;
 		goto out;
 	}
 
@@ -2180,8 +2181,9 @@ static void perf_group_detach(struct perf_event *event)
 		if (sibling->event_caps & PERF_EV_CAP_SIBLING)
 			perf_remove_sibling_event(sibling);
 
-		sibling->group_leader = sibling;
+		leader->nr_siblings--;
 		list_del_init(&sibling->sibling_list);
+		sibling->group_leader = sibling;
 
 		/* Inherit group flags from the previous leader */
 		sibling->group_caps = event->group_caps;
@@ -2358,10 +2360,19 @@ __perf_remove_from_context(struct perf_event *event,
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
@@ -4198,41 +4209,68 @@ static void perf_event_enable_on_exec(int ctxn)
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
+		struct perf_event *parent_event = event->parent;
+
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
+		modified = true;
+
+		if (parent_event) {
 			/*
-			 * Remove the event and feed back its values to the
-			 * parent event.
+			 * Remove event from parent, to avoid race where the
+			 * parent concurrently iterates through its children to
+			 * enable, disable, or otherwise modify an event.
 			 */
-			perf_event_exit_event(event, ctx, current);
+			mutex_lock(&parent_event->child_mutex);
+			list_del_init(&event->child_list);
+			mutex_unlock(&parent_event->child_mutex);
 		}
-		mutex_unlock(&ctx->mutex);
-		put_ctx(ctx);
+
+		perf_remove_from_context(event, !!event->parent * DETACH_GROUP);
+		perf_event_exit_event(event, ctx, current, true);
 	}
+
+	raw_spin_lock_irqsave(&ctx->lock, flags);
+	if (modified)
+		clone_ctx = unclone_ctx(ctx);
+	--ctx->pin_count;
+	raw_spin_unlock_irqrestore(&ctx->lock, flags);
+
+unlock:
+	mutex_unlock(&ctx->mutex);
+
+	put_ctx(ctx);
+	if (clone_ctx)
+		put_ctx(clone_ctx);
 }
 
 struct perf_read_data {
@@ -7581,20 +7619,18 @@ void perf_event_exec(void)
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
@@ -12472,7 +12508,7 @@ static void sync_child_event(struct perf_event *child_event,
 static void
 perf_event_exit_event(struct perf_event *child_event,
 		      struct perf_event_context *child_ctx,
-		      struct task_struct *child)
+		      struct task_struct *child, bool removed)
 {
 	struct perf_event *parent_event = child_event->parent;
 
@@ -12489,12 +12525,15 @@ perf_event_exit_event(struct perf_event *child_event,
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
@@ -12580,7 +12619,7 @@ static void perf_event_exit_task_context(struct task_struct *child, int ctxn)
 	perf_event_task(child, child_ctx, 0);
 
 	list_for_each_entry_safe(child_event, next, &child_ctx->event_list, event_entry)
-		perf_event_exit_event(child_event, child_ctx, child);
+		perf_event_exit_event(child_event, child_ctx, child, false);
 
 	mutex_unlock(&child_ctx->mutex);
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFm6aakSRlF2nWtu%40elver.google.com.
