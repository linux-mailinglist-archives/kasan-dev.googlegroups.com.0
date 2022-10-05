Return-Path: <kasan-dev+bncBDBK55H2UQKRBKPI6SMQMGQEWGLNRNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 943645F5066
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Oct 2022 09:37:14 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id u2-20020ac25182000000b004a24f3189fesf1651065lfi.15
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Oct 2022 00:37:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664955434; cv=pass;
        d=google.com; s=arc-20160816;
        b=qUFA2H4OPxMSNIaEUickCOwSF/YmrmAO+g1++4v6MulrI2+XEvhwCK0lWgH7+baxX4
         D/QCBSPQI10FiuXUZUhPf7xFXfvuvl1q6jIGFd8AbGqoVyBvqngYTLR4rnyfZZdk6wR6
         qbllfW7Vr6Qs2UK02wqa8fibS0athlTyyT1O9tqs2fuzqeIarKtjYFHWDoGo4tmA2cqo
         Wzh0+rNeZJpqsmYDPOMb5ou76TteD3nrriJ4t3q8Dep7U1Z2u1S/PcgQbq1s0GORSQax
         h0/u4ApTcTwoZOmMSUxQ6lAJWecgc82gE0QwQoEM4BHE1bqIi1UrhSTCoWblPo7Rgs2V
         wgEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=itF95HaB0lwW/l5jrpX6eQH7kj/IXaBSzf/ohv3aKvI=;
        b=Sv1L9J678YL3+cXd+O9FnMG/UTBTJoL5hMrgOCE/DcNfo4be0xnYFJvjPPABG5YeRA
         IAgM1ya40EeSljJvKIRoDmY2SeY1h04Zs57qmTGjYUNWh/qt6WXd4k8j7c34qVePf0q8
         lGfDUfgUherWOO5SuQXgxNdWmLZEgDHyuswF8vGlRIyIhA4TO0metAN+Xsw1BY+9xKrG
         Je8uU6Gst8G/4Z9Z0TSXJIlpnAuPubZ+aZkIHdz1plKO+3UbCXSpN8yBYNv23MWSK/aq
         fLRFOx4TzCMdm+6hFvMTs/fTB1BPVq0CuVUXpicTSRIyGmygpNmZfg1kgdrBG/83NtRR
         UmFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=EMpd1ufP;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=itF95HaB0lwW/l5jrpX6eQH7kj/IXaBSzf/ohv3aKvI=;
        b=jF9N/hmjPHhhi0tW7zwL1ymq2Wil62n1NucO/Hw18eHrPPU5CH+dQXlaBcdNNkQxna
         TI8a4H+I6IgpKgSsZFz3TM7GD+4WzrKO0d3kQMfcDSVY1aF7gBwirTQFb/OL6fFYayW5
         waXR3Cg3dq2eKtWQIBK+BYw6YrogoAhrElQfuwB5FRP4av32Hqc7Z5VsjemfB9Mx3oUg
         reCol15OZilqHbxKVAv8GAtktnoQR8axo1Nm34nlKjCn+nKBkQgS+F19ejVW7u2ryPCM
         MF2tYv/Kg7bHgH2ybNeXN1KcCshp1K6H8UZod5WFtddqQEFGw2loomt5k3ypE9WJ/YL2
         Gixw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=itF95HaB0lwW/l5jrpX6eQH7kj/IXaBSzf/ohv3aKvI=;
        b=cyBF6L+z9RqFEoSWeTCXzKQEQ4vwsA5eoOzYLiVd9xPCfCLvqUX2jiLSfJJ8vv8OF0
         qcc9y9Uujk/M4yZWSBICJcL1FDzHhZqWVQz2B8gDXUStNUhcSZ2jv/GQw3usMX1OJjHU
         QRtrmo7Ff1htiK+SUCcw0rg0gShE/yR0Je1nXpmOcC5Sd4SbKlutJY+nSIozYBFzqcyV
         lVPtzTRzN4TKh63JtvSjSkAAhV4FVmCVy/4lO2Xk8zMKvWrooqJrgsEuIRn8jyBo/3om
         g1DiPRuw1SM0Xmqtg5d2TbTdUEZcf6nZVJa3G+q4LkwcBIMTqbuxRael1oc/SHuTyPp8
         wS1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1IglZO7LjlfqpsF5OYD/FI4WHMtthUQf0kNJ5eY+qjCrVZwjaW
	MLuQ5iqdGylU3+rzX0eTdYY=
X-Google-Smtp-Source: AMsMyM6NwYISk+EyKeRv80uhWCPSpBiJ2ZmhLfbdvTmSjF76IKfKxCdxTSwscP89/dk7SN5OlzKPtA==
X-Received: by 2002:a05:651c:4c9:b0:26c:79cd:2819 with SMTP id e9-20020a05651c04c900b0026c79cd2819mr10026535lji.159.1664955433654;
        Wed, 05 Oct 2022 00:37:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4d13:0:b0:48b:2227:7787 with SMTP id r19-20020ac24d13000000b0048b22277787ls1566014lfi.3.-pod-prod-gmail;
 Wed, 05 Oct 2022 00:37:12 -0700 (PDT)
X-Received: by 2002:a05:6512:c0d:b0:4a2:4129:366e with SMTP id z13-20020a0565120c0d00b004a24129366emr4571230lfu.328.1664955432045;
        Wed, 05 Oct 2022 00:37:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664955432; cv=none;
        d=google.com; s=arc-20160816;
        b=WIl/GAU4vYpNCHV0U2375wUZAa0iLAL1n31sz8JW3th+V/dwrpWwIw5FA1s31tkD5d
         8SPzCDZ8dqbQ1nAwRL90yrtutPyKXT8FDOUzwRo+bBymj6kp7yVpTN0En7i0vGhybpOc
         R0+D6yHS70iEgK4MWvoC685jlsD4ixp995yu4z8PC/UCO0AqMAk4iMXlYDZBp9dHQC/B
         9FSYS4nFqBu1OYznnE0NNrmKIqGF2KJkwWAN+Ag26AjhKOYyuealUNNFmCoUsBRkrOOb
         RvpZU7eKCSutl+vRooHG7pJ02Zk005wP/ZTGeQzts/pqgbMkpwOvMP13ANI3zeiPj9lg
         eRNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=XqDfzIvXSelkrbDlyQ1vmQ7mysva9wlo/4eb4beEi2g=;
        b=NqyWIAidQ97xegWqEoJG7cr5OKGt/XsiAFrNY6H2WsE2wPCsv+s3U+mkqrMF6UAOod
         V9qQfS8p+nYdAmQ49nSOepL5vOFRit0QeVU/btAO4GMsqHvsPcRw2JgfOsK03yW7qgqi
         xeUHohAkHAeuu7z9aNucYDXWKyfqjRbsBvJctbc2QdpLpYvIiyEt1UnoI0F8luz+EBuo
         Vn4IiYmINdpc/ZFwTaLXr85YwORvu8DN0b0lFz8+cEE8dOF8KBQV/TPotYGXgxYVMsAo
         8+BSqYwImXfGvN3+ZAh0zJZW6bf8n2KSWYNhs+dqg8D/RXTdXcnER/dEq8nZz949iuoF
         wTVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=EMpd1ufP;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id v10-20020a2ea44a000000b0026d92a5f977si515812ljn.1.2022.10.05.00.37.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Oct 2022 00:37:11 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1ofyxq-000CCB-H4; Wed, 05 Oct 2022 07:37:10 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 5E45D3001CE;
	Wed,  5 Oct 2022 09:37:06 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 3A04520181465; Wed,  5 Oct 2022 09:37:06 +0200 (CEST)
Date: Wed, 5 Oct 2022 09:37:06 +0200
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
Message-ID: <Yz00IjTZjlsKlNvy@hirez.programming.kicks-ass.net>
References: <20220927121322.1236730-1-elver@google.com>
 <YzM/BUsBnX18NoOG@hirez.programming.kicks-ass.net>
 <YzNu5bgASbuVi0S3@elver.google.com>
 <YzQcqe9p9C5ZbjZ1@elver.google.com>
 <YzRgcnMXWuUZ4rlt@elver.google.com>
 <Yzxou9HB/1XjMXWI@hirez.programming.kicks-ass.net>
 <CANpmjNPwiL279B5id5dPF821aXYdTUqsfDNAtB4q7jXX+41Qgg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPwiL279B5id5dPF821aXYdTUqsfDNAtB4q7jXX+41Qgg@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=EMpd1ufP;
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

On Tue, Oct 04, 2022 at 07:33:55PM +0200, Marco Elver wrote:
> It looks reasonable, but obviously needs to pass tests. :-)

Ikr :-)

> Also, see comment below (I think you're still turning signals
> asynchronous, which we shouldn't do).

Indeed so; I tried fixing that this morning, but so far that doesn't
seem to want to actually cure things :/ I'll need to stomp on this
harder.

Current hackery below. The main difference is that instead of trying to
restart the irq_work on sched_in, sched_out will now queue a task-work.

The event scheduling is done from 'regular' IRQ context and as such
there should be a return-to-userspace for the relevant task in the
immediate future (either directly or after scheduling).

Alas, something still isn't right...

---
 include/linux/perf_event.h |   9 ++--
 kernel/events/core.c       | 115 ++++++++++++++++++++++++++++-----------------
 2 files changed, 79 insertions(+), 45 deletions(-)

diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
index 853f64b6c8c2..f15726a6c127 100644
--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -756,11 +756,14 @@ struct perf_event {
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
+	struct callback_head		pending_sig;
 
 	atomic_t			event_limit;
 
diff --git a/kernel/events/core.c b/kernel/events/core.c
index b981b879bcd8..e28257fb6f00 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -54,6 +54,7 @@
 #include <linux/highmem.h>
 #include <linux/pgtable.h>
 #include <linux/buildid.h>
+#include <linux/task_work.h>
 
 #include "internal.h"
 
@@ -2276,11 +2277,19 @@ event_sched_out(struct perf_event *event,
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
+		if (state != PERF_EVENT_STATE_OFF)
+			task_work_add(current, &event->pending_sig, TWA_NONE);
+		else
+			event->pending_sigtrap = 0;
+	}
+
 	perf_event_set_state(event, state);
 
 	if (!is_software_event(event))
@@ -2471,8 +2480,7 @@ EXPORT_SYMBOL_GPL(perf_event_disable);
 
 void perf_event_disable_inatomic(struct perf_event *event)
 {
-	WRITE_ONCE(event->pending_disable, smp_processor_id());
-	/* can fail, see perf_pending_event_disable() */
+	event->pending_disable = 1;
 	irq_work_queue(&event->pending);
 }
 
@@ -6448,47 +6456,40 @@ static void perf_sigtrap(struct perf_event *event)
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
@@ -6496,19 +6497,43 @@ static void perf_pending_event(struct irq_work *entry)
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
+	if (rctx >= 0)
+		perf_swevent_put_recursion_context(rctx);
+}
+
+static void perf_pending_sig(struct callback_head *head)
+{
+	struct perf_event *event = container_of(head, struct perf_event, pending_sig);
+	int rctx;
+
+	/*
+	 * If we 'fail' here, that's OK, it means recursion is already disabled
+	 * and we won't recurse 'further'.
+	 */
+	rctx = perf_swevent_get_recursion_context();
+
+	if (event->pending_sigtrap) {
+		event->pending_sigtrap = 0;
+		perf_sigtrap(event);
+	}
+
 	if (rctx >= 0)
 		perf_swevent_put_recursion_context(rctx);
 }
@@ -9227,11 +9252,20 @@ static int __perf_event_overflow(struct perf_event *event,
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
@@ -11560,8 +11594,8 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
 
 
 	init_waitqueue_head(&event->waitq);
-	event->pending_disable = -1;
 	init_irq_work(&event->pending, perf_pending_event);
+	init_task_work(&event->pending_sig, perf_pending_sig);
 
 	mutex_init(&event->mmap_mutex);
 	raw_spin_lock_init(&event->addr_filters.lock);
@@ -11583,9 +11617,6 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz00IjTZjlsKlNvy%40hirez.programming.kicks-ass.net.
