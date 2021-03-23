Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYFU46BAMGQERGAVOSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id B75BD345DB9
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 13:09:04 +0100 (CET)
Received: by mail-ej1-x63b.google.com with SMTP id e7sf958099ejx.5
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 05:09:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616501344; cv=pass;
        d=google.com; s=arc-20160816;
        b=NrHGkrXbz2oHdXGObdftL5QIxwdp0BE6vD0qmHWtTna8uD0VImE9AdcEFle2+XzITI
         gbjyYsxLA9WusMxXQY9hQJQuTNao0yTWKDNr1zkyQF5OQNzbmCe7kQfCC9bgS19gYph1
         nnWq82lvLn4slFCrf7vHOOuu/rlnb3atf7MVM4mMWB7sRm6BxNUvHFftN1NDgPzFcOMz
         1b+Lb6+49MT8KN7mbesyiXgkeEnx4BS++KtWPM1WJSXr20ae6HPyKuA/UdymK7cY7+mI
         jO0zyPIXKUqVc43zw8OXy6X+H4waT183HxE0h3+6n5i89hQ3FcFL+YtTa2ArTbP4q+ez
         I7Bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=TvIxX3ae8ulje68xBI3uAVsPeFICmmHeV4r4XOVNWSA=;
        b=uIcbaWHa4OE060s5fjIu/YSZn2H6lrAI8kYceYkLc7832xUaVNXTiL0zP+ljWf6eIm
         0NgVuuu1kW5oLrlDwycuTLNZWw2HhraSZvEc9jH57NxpmZf/4pCBgd+ZUK22xZba3Y51
         7nMHSi67hW1i9V6Eg8b8dNVjNnJykJZ+bEeNJok8d2gLimvtX4LAtTrVTb+jknPMptBV
         e6jerDqEiLjTsYpiTO0GUucUBWwPvNw390buv0rUHImEGDCn5jxmQCLxwEBySixgVYoh
         lEN+WLbAt0edwYtDdSZNHghsRRZ69GDkBXsPSiEOm2YS6Do1m8HNC1ft9aY4hDOqRV6b
         Chcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=O0kY6dQA;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=TvIxX3ae8ulje68xBI3uAVsPeFICmmHeV4r4XOVNWSA=;
        b=NxpXgQgoKklqBVrPuBT1Wzt9ICNjEPpMfGKwSxfIPQ2ocZ6YNMdE49FbK7jKZ6AH/B
         h4dAVlUk3pZlPThGsxMAWobE6tH+IDvff3pErbOxEe+EbSX0b6DIXVs7Sib00uCvX2ee
         FsBY3ryVOWXIv261oKKCRJK/GkSP33h3J5hu+hAuKAAgeQgTQRqP+oLMTNuXeJcbjHSM
         F5htnP8PZNTTv8+7btaHrXi1I/YU9AhZZPLFoBBSq6qCRiuGyUPAxkha28SS0maEa1yd
         VoCYL21J0RDT1biQb9Edamz5XAli/6duOcrSHneFtLhDSD7YvsttrunWbwrZeuzOLjfm
         /+8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TvIxX3ae8ulje68xBI3uAVsPeFICmmHeV4r4XOVNWSA=;
        b=LG0nWpXFzERyfaIuyQAlFnV/8n3F+73i44D4MWmvQBZk4WkQ79/Vb12lxEQyTpIhut
         NzfcEp93hm9jAE0vDddpHrd185Vqm1U9qiQ7a5tB0vZfiTwxu2wzsOFY9ws9zqUg906K
         z1Sr1/nJZgjtN5D2zg2QzEf5iKuREol129dmKc8cRtRoiPy20RvxleMF+uJ62WAv1dmD
         vvqSMGtQLb1Sm7ClZwH4z4840UsLpPJRMDah4GaD0lf+ToZv8dxXF2niem6+Oqpc9nCQ
         qe0heFXzCOmHeukwk+6GtzVMpBAnjuKEBBUcmOsl2htppLD6eeXR21yJ7scHd7ksq8rS
         C/tQ==
X-Gm-Message-State: AOAM531SvWh1crPIvm0Hd4jpQgqZKSdVnYuPrIJbTz6d70kM9z8m2Ycp
	tloOCIhGbkHdfafrDgJMD6s=
X-Google-Smtp-Source: ABdhPJwXhsKTQqXvtzixK3XEp5LMe69eRUTQ71Im3mPAWIk2iMHU143HC5zQIrBKq0NcZ7fVeVwwAg==
X-Received: by 2002:a17:906:9442:: with SMTP id z2mr4829965ejx.79.1616501344525;
        Tue, 23 Mar 2021 05:09:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c653:: with SMTP id z19ls4966062edr.2.gmail; Tue, 23 Mar
 2021 05:09:03 -0700 (PDT)
X-Received: by 2002:a50:ec0e:: with SMTP id g14mr4337178edr.264.1616501343535;
        Tue, 23 Mar 2021 05:09:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616501343; cv=none;
        d=google.com; s=arc-20160816;
        b=H0Tto52BellgyK1L4vF8KD+00YXQao3DK18LJP/s76oVwNilSFxNYu9+4/RiLJPOfd
         eS0IAgTdtXGRLZBcd5xHHkxJVEqrZjebxEv1EX0cKgasf5nXRk6Mh4pJUYdfafGgGIqU
         KRfgAM0Os26pLvQxUtuywdzST+HZbjYLhXQ9tbKCcAIUUBcYE07NCcBF1KYCiMFApyM6
         55QG9iUaKPUMHtLOY+flbXbSZzgFe0qTs+nvw8+I0vjHO7HMYYoqippcX7g/JVK/4wmx
         4PKBvCXS5xezocE1Iil2b3yj8Fkn/4g+G75HaZTQGSS145vF5mvf3sQ/JmlsMJHtqOnp
         JvMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=B6h9ZiEvk3OjrxZiLfOl6jy0sUhDT3fazDwCa5g6frs=;
        b=ndiikvStKFx1EaReFiJ6vS/obe5Zt1sd/pl89wq7wMgQNMv7nR1fhGub4k7sGReLH5
         H+rIO16wxZzPEjcd/+9Hezh2w/ig9wEBfWvrqMZjfApUPDBDgB48QyoqZo1P8tDlLU09
         023oLCqGRrrYt+UUVhAxWWMYx2J6KOa+wNI85q+AtIoJCPg0ntLm4R+8Yau4DaZ5LnBJ
         kxh2yYU3H54vMGX3xtCUGyoRPtNfSvFiCbEjk+liN988/QYfee8aarNAnuDTTqAcZaF3
         9t+bxHP3WbgP9kyFmbhnZ/DFk7GEGJOgItf/s0FuL90KQiKCCbIxjKl9hgGCNKas0paP
         nlqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=O0kY6dQA;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id f25si692618edx.4.2021.03.23.05.09.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Mar 2021 05:09:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id v4so20512848wrp.13
        for <kasan-dev@googlegroups.com>; Tue, 23 Mar 2021 05:09:03 -0700 (PDT)
X-Received: by 2002:adf:ea0e:: with SMTP id q14mr3674929wrm.389.1616501343004;
        Tue, 23 Mar 2021 05:09:03 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:4cfd:1405:ab5d:85f8])
        by smtp.gmail.com with ESMTPSA id r26sm2338599wmn.28.2021.03.23.05.09.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Mar 2021 05:09:02 -0700 (PDT)
Date: Tue, 23 Mar 2021 13:08:55 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Namhyung Kim <namhyung@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Alexander Potapenko <glider@google.com>,
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>,
	Christian Brauner <christian@brauner.io>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Jens Axboe <axboe@kernel.dk>, Matt Morehouse <mascasa@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Ian Rogers <irogers@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-arch <linux-arch@vger.kernel.org>,
	linux-fsdevel <linux-fsdevel@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Subject: Re: [PATCH RFC v2 8/8] selftests/perf: Add kselftest for
 remove_on_exec
Message-ID: <YFnaV/uY/fN9WI5+@elver.google.com>
References: <20210310104139.679618-1-elver@google.com>
 <20210310104139.679618-9-elver@google.com>
 <YFiamKX+xYH2HJ4E@elver.google.com>
 <YFjI5qU0z3Q7J/jF@hirez.programming.kicks-ass.net>
 <YFm6aakSRlF2nWtu@elver.google.com>
 <YFnDo7dczjDzLP68@hirez.programming.kicks-ass.net>
 <CANpmjNO1mRBFBQ6Rij-6ojVPKkaB6JLHD2WOVxhQeqxsqit2-Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNO1mRBFBQ6Rij-6ojVPKkaB6JLHD2WOVxhQeqxsqit2-Q@mail.gmail.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=O0kY6dQA;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as
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

On Tue, Mar 23, 2021 at 11:41AM +0100, Marco Elver wrote:
> On Tue, 23 Mar 2021 at 11:32, Peter Zijlstra <peterz@infradead.org> wrote:
[...]
> > > +             if (parent_event) {
> > >                       /*
> > > +                      * Remove event from parent, to avoid race where the
> > > +                      * parent concurrently iterates through its children to
> > > +                      * enable, disable, or otherwise modify an event.
> > >                        */
> > > +                     mutex_lock(&parent_event->child_mutex);
> > > +                     list_del_init(&event->child_list);
> > > +                     mutex_unlock(&parent_event->child_mutex);
> > >               }
> >
> >                 ^^^ this, right?
> >
> > But that's something perf_event_exit_event() alread does. So then you're
> > worried about the order of things.
> 
> Correct. We somehow need to prohibit the parent from doing an
> event_function_call() while we potentially deactivate the context with
> perf_remove_from_context().
> 
> > > +
> > > +             perf_remove_from_context(event, !!event->parent * DETACH_GROUP);
> > > +             perf_event_exit_event(event, ctx, current, true);
> > >       }
> >
> > perf_event_release_kernel() first does perf_remove_from_context() and
> > then clears the child_list, and that makes sense because if we're there,
> > there's no external access anymore, the filedesc is gone and nobody will
> > be iterating child_list anymore.
> >
> > perf_event_exit_task_context() and perf_event_exit_event() OTOH seem to
> > rely on ctx->task == TOMBSTONE to sabotage event_function_call() such
> > that if anybody is iterating the child_list, it'll NOP out.
> >
> > But here we don't have neither, and thus need to worry about the order
> > vs child_list iteration.
> >
> > I suppose we should stick sync_child_event() in there as well.
> >
> > And at that point there's very little value in still using
> > perf_event_exit_event()... let me see if there's something to be done
> > about that.
> 
> I don't mind dropping use of perf_event_exit_event() and open coding
> all of this. That would also avoid modifying perf_event_exit_event().
> 
> But I leave it to you what you think is nicest.

I played a bit more with it, and the below would be the version without
using perf_event_exit_event(). Perhaps it isn't too bad.

Thanks,
-- Marco

------ >8 ------

diff --git a/kernel/events/core.c b/kernel/events/core.c
index aa47e111435e..288b61820dab 100644
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
@@ -4196,43 +4207,86 @@ static void perf_event_enable_on_exec(int ctxn)
 }
 
 static void perf_remove_from_owner(struct perf_event *event);
-static void perf_event_exit_event(struct perf_event *child_event,
-				  struct perf_event_context *child_ctx,
-				  struct task_struct *child);
+static void sync_child_event(struct perf_event *child_event,
+			     struct task_struct *child);
+static void free_event(struct perf_event *event);
 
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
+
+		modified = true;
 
-			if (!is_kernel_event(event))
-				perf_remove_from_owner(event);
-			perf_remove_from_context(event, DETACH_GROUP);
+		if (parent_event) {
 			/*
-			 * Remove the event and feed back its values to the
-			 * parent event.
+			 * Remove event from parent *before* modifying contexts,
+			 * to avoid race where the parent concurrently iterates
+			 * through its children to enable, disable, or otherwise
+			 * modify an event.
 			 */
-			perf_event_exit_event(event, ctx, current);
+
+			sync_child_event(event, current);
+
+			WARN_ON_ONCE(parent_event->ctx->parent_ctx);
+			mutex_lock(&parent_event->child_mutex);
+			list_del_init(&event->child_list);
+			mutex_unlock(&parent_event->child_mutex);
+
+			perf_event_wakeup(parent_event);
+			put_event(parent_event);
 		}
-		mutex_unlock(&ctx->mutex);
-		put_ctx(ctx);
+
+		perf_remove_from_context(event, !!event->parent * DETACH_GROUP);
+
+		raw_spin_lock_irq(&ctx->lock);
+		WARN_ON_ONCE(ctx->is_active);
+		perf_event_set_state(event, PERF_EVENT_STATE_EXIT); /* is_event_hup() */
+		raw_spin_unlock_irq(&ctx->lock);
+
+		if (parent_event)
+			free_event(event);
+		else
+			perf_event_wakeup(event);
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
@@ -7581,20 +7635,18 @@ void perf_event_exec(void)
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFnaV/uY/fN9WI5%2B%40elver.google.com.
