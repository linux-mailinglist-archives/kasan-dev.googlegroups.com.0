Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSWC4GBAMGQEUMUNIGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 62898343C97
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 10:20:11 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id s17sf21288447ljs.19
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 02:20:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616404811; cv=pass;
        d=google.com; s=arc-20160816;
        b=gC839wtKfWUT/Bwa61/BRku+RqO7kNW/DDBHqLpj5PAJ3bRuYpN5F/awUnVzFEu7BQ
         nXk2sOG63IP3+U0x6wk1KTxT2um7+azRtR2cZmnXMwcHXiIYXieqVnXrV0ENQzBTxGf+
         xDtM8j9/d80KwOjRgxcKcTRBRhqkTbnBoPTJi/jrJKlJ4AQof7CeD5hwZYe8W/eJmzTO
         aKubYKQuAbNmXuR3vLnjBri7FyzxbErfN+D0U7c0ZOhDPGS2vs4AhqBq7eb7TeXLokkF
         bGglXaUZdXdT2iEUEx0NR6AfR7EgKcdmmAALSRSG8LxkLzDKPEBmXEjzV10RJBiz1mtH
         GPVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=QC0N6cOT5FgGJ5J4E8UMMHNqnT9g/W9+hpIQ25rE8p8=;
        b=hQb9csbwyNxEvUlmuyH7/1fg+maeU6ODmv4VOqqxJU4DTer74PP2U0zfx9f8Femqtx
         G8l+zbCG89cg2k2Fy6VlaoVrEp4F1UMa5V7VHAuY3IMvoAs08xbMHCrAkvTcvs0HvS72
         Cb+UXqB0IloXlykyhPjjo6hLx5UWJvBAZqRaDuLWcsVhi+ZiU2n11hYm3PT1+gfmEHVQ
         QW+GJj2brFPNqS39Ysyh8czNvWq2uRmf0QDk1p9H9Pas9LE5VQwmmxLrUVZfpEZzFAt4
         6ftEq0BYULNSajkgRanqepi/uairUapkJobosEDJbgkdbvOAtvaPKWQfSlaqwRp6w4Df
         TWPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LAlde5AA;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=QC0N6cOT5FgGJ5J4E8UMMHNqnT9g/W9+hpIQ25rE8p8=;
        b=OxO6salme4mdu2OjbijK2ja8oZsVgH1nuTh46Y4k/E7dUqVHAN/rXRMsyj3gpWFEaT
         3y9EXFozbVp/owKz7ZwbViSO0HSlT0EJi8/LbhAJBRlT40OTHYwqD3PcJFvn4TF4XDEW
         xl79yhDw3Zt1hmB0NL4OUfRD543s8Pm7ZBTwQzL1zdzB+Rs0i7v3qnJCnP+UwRZYXBvy
         dcFar0QK6XUCcZKqD1Bhri2+E84N1yF6L02HnN/zBAg71/QIceHciQg72KLJA+AF34HM
         kcVORPLbUcJL9H+Oc9SYYUWFE8h+iylTWqmwRtlqAeq8jnZryO2bxXg1OZJ6EVYrkxKW
         P66g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QC0N6cOT5FgGJ5J4E8UMMHNqnT9g/W9+hpIQ25rE8p8=;
        b=uPpAI/rSDW+GQfzrs7BWQ6lBoC7aaMisj7Vf3zXvjXurhz+YHWybFrB5rH4qF3wnaX
         Mn/D1AhqPTZiWLlMLycVSUc8ql2vmdhTFAb24YppChHEPNJrXxHRZ82XLsq8PJ9WRM5v
         OdP6aA8DIkzxzVZ9JzMuIRMFqlDp+8/2XJVTS4NGZVsP2zi48Jle9C0fU/C6jiqgkn16
         IG8Goy/ihGPGI8UndNWhbJm5TTxDKEt9DU+em0XjnBj1hEnYXDVLXm2/bRBaggGe+R7a
         VBY9uUTS3O4hmO5HYeymlpfe1szyvZ/D1ktjRAX2QzY9s2Zoj39DiMMNfStBt8UdVVf0
         oi+w==
X-Gm-Message-State: AOAM533cxpR4GKg+JeQff+EtGxZjPq7neXQTu6A1+Pa2Nb5SLOyQVZ2m
	NgJYMhW3VRnRCYLFeRYNhN4=
X-Google-Smtp-Source: ABdhPJwI3t0mKsdIO5s+NEWfQnu1Ky6LTkxQIuKYfpPSgvSN1fK4u/5ffUBcOSOr4CiuAvzmn6mbgg==
X-Received: by 2002:ac2:5fe6:: with SMTP id s6mr8334782lfg.445.1616404810863;
        Mon, 22 Mar 2021 02:20:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:589:: with SMTP id 131ls2268368ljf.9.gmail; Mon, 22 Mar
 2021 02:20:09 -0700 (PDT)
X-Received: by 2002:a2e:9b10:: with SMTP id u16mr8710744lji.253.1616404809548;
        Mon, 22 Mar 2021 02:20:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616404809; cv=none;
        d=google.com; s=arc-20160816;
        b=MYAPNpbMOqYJxXOXHjQSE0Om48kYPVd6i5ZY4zmulnGXmj86lc0ZR6+ovnyK54n/u5
         O0kg2ueTGGfUqU7Q/WQ6ZmyryqsW3qbd1Mf1JiuC3Qmwf1uNN5/U2uo3H1rqwrGdl8Vo
         eyVCO+Sny7pdkV4iFFjIU21WXhY8drFi9sRm9dktNeqt3V/P6URlfeJM4VLMzpwSKkEg
         lMXuV/cfJ9Ef7AHHyyMk8ee5QIGc7Lf5odF6ic0jgW+k38eiklTFs83Wvt7WiVE32uPt
         EDrGJP6jAnRBA9blwoW+AYzB36MzxX0lubblJVykn5L6CI4UEmCFEGn6AmMAdRin+PGp
         AAGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=F5/VR6ur6ttgORsBImTX+DpB0R63FTk/snr4DsJXf+o=;
        b=0j7TUstZsb3PHNJn5DMpCdyomAtxXlfD4U8WZYJ4QXycneCi1TYsvlRA6cinFTXSiQ
         THIJdalqRkK0GU9ZCNmz09eaCnzbJODke/OZ28nCMJKYhERb/smE93g9rN50tVf7JMnV
         E1OvgapHxvHPAsZlPYhyjC5evl4zh/qqYnsA9SCR9DkjwES5SYHIlnHQLnZLK1pjbtAk
         4Ed1erNJFBmHnpAvQyASs63qfLhuZeWBROH/d4+fu3OftM+oKf7ERxV3Ar4f/ds1ta0t
         z7dton82n01cnhHJzIetGH5YFzVxfttgfJia6uYDcZiJH2VpbOIHSRNDQfy1qkkAiDtV
         v6pg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LAlde5AA;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id i30si609765lfj.6.2021.03.22.02.20.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Mar 2021 02:20:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id g25so9074383wmh.0
        for <kasan-dev@googlegroups.com>; Mon, 22 Mar 2021 02:20:09 -0700 (PDT)
X-Received: by 2002:a05:600c:4013:: with SMTP id i19mr14956538wmm.33.1616404808866;
        Mon, 22 Mar 2021 02:20:08 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:58e2:985b:a5ad:807c])
        by smtp.gmail.com with ESMTPSA id u3sm19133667wrt.82.2021.03.22.02.20.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Mar 2021 02:20:08 -0700 (PDT)
Date: Mon, 22 Mar 2021 10:20:02 +0100
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
Subject: Re: [PATCH RFC v2 3/8] perf/core: Add support for event removal on
 exec
Message-ID: <YFhhQgUzXLSTlcu0@elver.google.com>
References: <20210310104139.679618-1-elver@google.com>
 <20210310104139.679618-4-elver@google.com>
 <YFDbP3obvxn0SL4w@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YFDbP3obvxn0SL4w@hirez.programming.kicks-ass.net>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LAlde5AA;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as
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

On Tue, Mar 16, 2021 at 05:22PM +0100, Peter Zijlstra wrote:
> On Wed, Mar 10, 2021 at 11:41:34AM +0100, Marco Elver wrote:
> > Adds bit perf_event_attr::remove_on_exec, to support removing an event
> > from a task on exec.
> > 
> > This option supports the case where an event is supposed to be
> > process-wide only, and should not propagate beyond exec, to limit
> > monitoring to the original process image only.
> > 
> > Signed-off-by: Marco Elver <elver@google.com>
> 
> > +/*
> > + * Removes all events from the current task that have been marked
> > + * remove-on-exec, and feeds their values back to parent events.
> > + */
> > +static void perf_event_remove_on_exec(void)
> > +{
> > +	int ctxn;
> > +
> > +	for_each_task_context_nr(ctxn) {
> > +		struct perf_event_context *ctx;
> > +		struct perf_event *event, *next;
> > +
> > +		ctx = perf_pin_task_context(current, ctxn);
> > +		if (!ctx)
> > +			continue;
> > +		mutex_lock(&ctx->mutex);
> > +
> > +		list_for_each_entry_safe(event, next, &ctx->event_list, event_entry) {
> > +			if (!event->attr.remove_on_exec)
> > +				continue;
> > +
> > +			if (!is_kernel_event(event))
> > +				perf_remove_from_owner(event);
> > +			perf_remove_from_context(event, DETACH_GROUP);
> 
> There's a comment on this in perf_event_exit_event(), if this task
> happens to have the original event, then DETACH_GROUP will destroy the
> grouping.
> 
> I think this wants to be:
> 
> 			perf_remove_from_text(event,
> 					      child_event->parent ?  DETACH_GROUP : 0);
> 
> or something.
> 
> > +			/*
> > +			 * Remove the event and feed back its values to the
> > +			 * parent event.
> > +			 */
> > +			perf_event_exit_event(event, ctx, current);
> 
> Oooh, and here we call it... but it will do list_del_even() /
> perf_group_detach() *again*.
> 
> So the problem is that perf_event_exit_task_context() doesn't use
> remove_from_context(), but instead does task_ctx_sched_out() and then
> relies on the events not being active.
> 
> Whereas above you *DO* use remote_from_context(), but then
> perf_event_exit_event() will try and remove it more.

AFAIK, we want to deallocate the events and not just remove them, so
doing what perf_event_exit_event() is the right way forward? Or did you
have something else in mind?

I'm still trying to make sense of the zoo of synchronisation mechanisms
at play here. No matter what I try, it seems I get stuck on the fact
that I can't cleanly "pause" the context to remove the events (warnings
in event_function()).

This is what I've been playing with to understand:

diff --git a/kernel/events/core.c b/kernel/events/core.c
index 450ea9415ed7..c585cef284a0 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -4195,6 +4195,88 @@ static void perf_event_enable_on_exec(int ctxn)
 		put_ctx(clone_ctx);
 }
 
+static void perf_remove_from_owner(struct perf_event *event);
+static void perf_event_exit_event(struct perf_event *child_event,
+				  struct perf_event_context *child_ctx,
+				  struct task_struct *child);
+
+/*
+ * Removes all events from the current task that have been marked
+ * remove-on-exec, and feeds their values back to parent events.
+ */
+static void perf_event_remove_on_exec(void)
+{
+	struct perf_event *event, *next;
+	int ctxn;
+
+	/*****************  BROKEN BROKEN BROKEN *****************/
+
+	for_each_task_context_nr(ctxn) {
+		struct perf_event_context *ctx;
+		bool removed = false;
+
+		ctx = perf_pin_task_context(current, ctxn);
+		if (!ctx)
+			continue;
+		mutex_lock(&ctx->mutex);
+
+		raw_spin_lock_irq(&ctx->lock);
+		/*
+		 * WIP: Ok, we will unschedule the context, _and_ tell everyone
+		 * still trying to use that it's dead... even though it isn't.
+		 *
+		 * This can't be right...
+		 */
+		task_ctx_sched_out(__get_cpu_context(ctx), ctx, EVENT_ALL);
+		RCU_INIT_POINTER(current->perf_event_ctxp[ctxn], NULL);
+		WRITE_ONCE(ctx->task, TASK_TOMBSTONE);

This code here is obviously bogus, because it removes the context from
the task: we might still need it since this task is not dead yet.

What's the right way to pause the context to remove the events from it?

+		raw_spin_unlock_irq(&ctx->lock);
+
+		list_for_each_entry_safe(event, next, &ctx->event_list, event_entry) {
+			if (!event->attr.remove_on_exec)
+				continue;
+			removed = true;
+
+			if (!is_kernel_event(event))
+				perf_remove_from_owner(event);
+
+			/*
+			 * WIP: Want to free the event and feed back its values
+			 * to the parent (if any) ...
+			 */
+			perf_event_exit_event(event, ctx, current);
+		}
+

... need to schedule context back in here?

+
+		mutex_unlock(&ctx->mutex);
+		perf_unpin_context(ctx);
+		put_ctx(ctx);
+	}
+}
+
 struct perf_read_data {
 	struct perf_event *event;
 	bool group;
@@ -7553,6 +7635,8 @@ void perf_event_exec(void)
 				   true);
 	}
 	rcu_read_unlock();
+
+	perf_event_remove_on_exec();
 }
 

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFhhQgUzXLSTlcu0%40elver.google.com.
