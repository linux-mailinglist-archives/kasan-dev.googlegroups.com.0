Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3ORZOMQMGQE2S7UX3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id DD7205EC225
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 14:13:33 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id k38-20020a05600c1ca600b003b49a809168sf8520350wms.5
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 05:13:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664280813; cv=pass;
        d=google.com; s=arc-20160816;
        b=W8XfP4W/6Hq4Tn9nCoAEl9shCUgxekoWmUVhN0OznYUPv7tkhI5+kTcA7gn4ow0C0x
         TS4iRr1RYV6SuU9ZT1xebtpF5I8kBfJSDCCNlmt3XRFsD+aGN7moCR0Wme+CdGS/YWbi
         RPtiTbkuT89o187ssyR7tUr1ko634xeWW9E0VGZDVtO8Y94lBgUmKWSsglc9sabgj3Oo
         H9grdaFjzThSEa5BycwYVU5uUgBDtZmQRTUSBiFHABBKpCNA87VcyFyY/EPfFCH7KqxK
         xIegF31J4vxSZCdkNDfmNXabCpMR15JFKydVTOC+thoZmH1yy5taV65RZkbiWEcfnSwH
         G+IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=owVDeUGRcBrPKVN1OqtTlxIzE/FpPh8j5CHGZlwAgTk=;
        b=dkDkigkU08Bje7jHFH1p6c4h/HljSGRqH0/SMvHFbwIjp49wJ1KSi01JlbUtjOXjTJ
         FgJqfh8PdYL9kvBF0uLXSF4a84thhRiUWKxJZ7QaCGTTw2ewESEWwAPMYHlYGjlmZllS
         mywDqvZG67B7IngxBMb/gYLQl8AppRy9TxEOlAdiH92OQUyXxU1CijCK1PmV0QZYpdDi
         IzuOiD366MDM/fp0VpK2kcFPGg9p5K0cWP47YICZqEE2gfec1udKmMOzYqZcpf0c6pI2
         4SIIAI7xv0wsF1uxbRjPlRbOWbUOa8a7k5d+8apjv8VEFgDWV4WOXb9o4PmKxYPj0pie
         V+CA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Js35UYBG;
       spf=pass (google.com: domain of 36-gyywukcagmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=36-gyYwUKCagMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date;
        bh=owVDeUGRcBrPKVN1OqtTlxIzE/FpPh8j5CHGZlwAgTk=;
        b=saV0pRksDIbz30iP8wuJ+/hnYYTtLvFwLDslgC8ItAXe6Vzd7WDAlV3F6yXwkks2i8
         NjLSYLhCVEmB58Sf5cPC5k7PkIF5bhXbFcfLCbyQKdoe9eMyqESsJoPUjMStioqokbj7
         NlGg8YbahVFDvLsZjFrwqbYaON39PggZJUpUSgmxW6TpFHuQ3r+94+bsbwBzQ0nj7lVI
         +8kiT+4FUju5gp1xAwqWhq9Ee0HjpVQO6v3zicxSSr4RKckPyaf7/wViok0jtIBVKsUt
         QS1RRf7Jza+OODYWk0EKIiW8b9y01LAsRcnsL4ROx3B/osRCMSDH0YsPy5KHlBp+LS0s
         +CqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date;
        bh=owVDeUGRcBrPKVN1OqtTlxIzE/FpPh8j5CHGZlwAgTk=;
        b=KmRCG6nSDjDCasgotEJdXgaVHyavrlnA7CnjYL22wN0ruCBgt9692zIX/mX1wpNGwD
         C/RZZQRTMrjyfrr7peDzIs7XBM5Cpkf50SrFWwsyii+Mzhdovk0pvqjxd8sncmR6OwZs
         +irE03TQdCJRoMG+7x1FA1tp2AoeBLKwuEjd55x4R9QayLa7jYGFnTqJIZhB3yk3mgtU
         I7h8JIeBuX0gj9Sb1QH7m0+7QyYMTtUf5fW2UosDE+ACtEQIB0gVk2t/ah9HOs849gNP
         R8x3ofxK2JRL+fASMg+cAsKc7QBzigrjX/dM2O6jc0U5UsK49lo2V5h5TWno2W2AOEN6
         0o6w==
X-Gm-Message-State: ACrzQf2gYqy9220KQ5zrkrnOQg9AXj3Awo9xxxXEHlDh8Z57lN9bYJdF
	eKGlbKbkz/Bnm7VmwszjqHk=
X-Google-Smtp-Source: AMsMyM4uEKq2BmX9gDSW6H9L3nY2kuYfCD8MsH7Yo5Tva3wRRWWA1KtAEjquinnnMHz42ROxooeKYg==
X-Received: by 2002:a05:6000:384:b0:22a:5d05:c562 with SMTP id u4-20020a056000038400b0022a5d05c562mr16621421wrf.701.1664280813383;
        Tue, 27 Sep 2022 05:13:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f209:0:b0:225:6559:3374 with SMTP id p9-20020adff209000000b0022565593374ls2571106wro.2.-pod-prod-gmail;
 Tue, 27 Sep 2022 05:13:32 -0700 (PDT)
X-Received: by 2002:adf:fd05:0:b0:22a:292f:1908 with SMTP id e5-20020adffd05000000b0022a292f1908mr16285783wrr.85.1664280812109;
        Tue, 27 Sep 2022 05:13:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664280812; cv=none;
        d=google.com; s=arc-20160816;
        b=p2JLaARWZsSXBuBcHsPeVf7/+0FgjMygZ7TD2WYWUaTEOzewhTSFpimNMfcpdA6gfZ
         ScRhUuPrcLOZx6JFlbx5HIxxc/lWN7iI59UflLn0XBOxSLAOfNS3zv/FWRgXwl5RkkWS
         MEfsaUHcDDaRkcGL5NZ9JxSJ9V58IzDcjZevTjigUdrsXyU1mw033oROCc8VhbnXRGBf
         +3j4lowRIRMSEEzNqw0+UwhdKaK0BJ/dx6WL5t4mBE7228WYawlUsf46S9PNstgqzxPz
         42nRvxDGtFpMcdxbU6E6g2j2SU3/Y+lcLbyJdgAz1dNvintuspkuVo4K1SklxX1x4Ywb
         oDHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=O1OHV9/ebX3PFCvVx/+I7boFWMH1Mc6xsGvoR42Opk4=;
        b=OJv+uQpmCtiQp7OobRlftXKK1fW/u8siyQwBE4Fd8a6oJhgdYwNcS9rHRolwI/LKJt
         Td1dNuIf/Hgdoa10w/pNGUDtdTlfaYuziS5vidQUneIIJdqEC5dcu4MXXlJHUmVKZJvB
         Dyf6pwYPtMaxmRJICYOsYQeCXAyWvUZbT/RhogQVNRARCebO1aGZPY1p0IV0k3gxK261
         0ku7XeI/jHFAc+t4QJ2WIoiHOXbw4tYDCVWysJP1Tg/5ECIKbkIzyMNLh27CLoai+3by
         56pDGJS2Yplu40kcWKdtZjgrTJ00PX6CTvMccHFT5Oll6X+pzc14Ygeh8tHH9oGYH7s8
         39XQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Js35UYBG;
       spf=pass (google.com: domain of 36-gyywukcagmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=36-gyYwUKCagMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id l129-20020a1c2587000000b003a5a534292csi74734wml.3.2022.09.27.05.13.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Sep 2022 05:13:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36-gyywukcagmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id f9-20020adfc989000000b0022b3bbc7a7eso2098454wrh.13
        for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 05:13:32 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:693c:15a1:a531:bb4e])
 (user=elver job=sendgmr) by 2002:a5d:6d07:0:b0:22a:3f21:3b56 with SMTP id
 e7-20020a5d6d07000000b0022a3f213b56mr16261810wrq.679.1664280811693; Tue, 27
 Sep 2022 05:13:31 -0700 (PDT)
Date: Tue, 27 Sep 2022 14:13:22 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.3.998.g577e59143f-goog
Message-ID: <20220927121322.1236730-1-elver@google.com>
Subject: [PATCH] perf: Fix missing SIGTRAPs due to pending_disable abuse
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@kernel.org>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Js35UYBG;       spf=pass
 (google.com: domain of 36-gyywukcagmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=36-gyYwUKCagMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
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

Due to the implementation of how SIGTRAP are delivered if
perf_event_attr::sigtrap is set, we've noticed 3 issues:

	1. Missing SIGTRAP due to a race with event_sched_out() (more
	   details below).

	2. Hardware PMU events being disabled due to returning 1 from
	   perf_event_overflow(). The only way to re-enable the event is
	   for user space to first "properly" disable the event and then
	   re-enable it.

	3. The inability to automatically disable an event after a
	   specified number of overflows via PERF_EVENT_IOC_REFRESH.

The worst of the 3 issues is problem (1), which occurs when a
pending_disable is "consumed" by a racing event_sched_out(), observed as
follows:

		CPU0			| 	CPU1
	--------------------------------+---------------------------
	__perf_event_overflow()		|
	 perf_event_disable_inatomic()	|
	  pending_disable = CPU0	| ...
	  				| _perf_event_enable()
					|  event_function_call()
					|   task_function_call()
					|    /* sends IPI to CPU0 */
	<IPI>				| ...
	 __perf_event_enable()		+---------------------------
	  ctx_resched()
	   task_ctx_sched_out()
	    ctx_sched_out()
	     group_sched_out()
	      event_sched_out()
	       pending_disable = -1
	</IPI>
	<IRQ-work>
	 perf_pending_event()
	  perf_pending_event_disable()
	   /* Fails to send SIGTRAP because no pending_disable! */
	</IRQ-work>

In the above case, not only is that particular SIGTRAP missed, but also
all future SIGTRAPs because 'event_limit' is not reset back to 1.

To fix, rework pending delivery of SIGTRAP via IRQ-work by introduction
of a separate 'pending_sigtrap', no longer using 'event_limit' and
'pending_disable' for its delivery.

During testing, this also revealed several more possible races between
reschedules and pending IRQ work; see code comments for details.

Doing so makes it possible to use 'event_limit' normally (thereby
enabling use of PERF_EVENT_IOC_REFRESH), perf_event_overflow() no longer
returns 1 on SIGTRAP causing disabling of hardware PMUs, and finally the
race is no longer possible due to event_sched_out() not consuming
'pending_disable'.

Fixes: 97ba62b27867 ("perf: Add support for SIGTRAP on perf events")
Reported-by: Dmitry Vyukov <dvyukov@google.com>
Debugged-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/perf_event.h |  2 +
 kernel/events/core.c       | 85 ++++++++++++++++++++++++++++++++------
 2 files changed, 75 insertions(+), 12 deletions(-)

diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
index 907b0e3f1318..dff3430844a2 100644
--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -740,8 +740,10 @@ struct perf_event {
 	int				pending_wakeup;
 	int				pending_kill;
 	int				pending_disable;
+	int				pending_sigtrap;
 	unsigned long			pending_addr;	/* SIGTRAP */
 	struct irq_work			pending;
+	struct irq_work			pending_resched;
 
 	atomic_t			event_limit;
 
diff --git a/kernel/events/core.c b/kernel/events/core.c
index 75f5705b6892..df90777262bf 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -2527,6 +2527,14 @@ event_sched_in(struct perf_event *event,
 	if (event->attr.exclusive)
 		cpuctx->exclusive = 1;
 
+	if (event->pending_sigtrap) {
+		/*
+		 * The task and event might have been moved to another CPU:
+		 * queue another IRQ work. See perf_pending_event_sigtrap().
+		 */
+		WARN_ON_ONCE(!irq_work_queue(&event->pending_resched));
+	}
+
 out:
 	perf_pmu_enable(event->pmu);
 
@@ -4938,6 +4946,7 @@ static void perf_addr_filters_splice(struct perf_event *event,
 static void _free_event(struct perf_event *event)
 {
 	irq_work_sync(&event->pending);
+	irq_work_sync(&event->pending_resched);
 
 	unaccount_event(event);
 
@@ -6446,6 +6455,37 @@ static void perf_sigtrap(struct perf_event *event)
 		      event->attr.type, event->attr.sig_data);
 }
 
+static void perf_pending_event_sigtrap(struct perf_event *event)
+{
+	if (!event->pending_sigtrap)
+		return;
+
+	/*
+	 * If we're racing with disabling of the event, consume pending_sigtrap
+	 * and don't send the SIGTRAP. This avoids potentially delaying a signal
+	 * indefinitely (oncpu mismatch) until the event is enabled again, which
+	 * could happen after already returning to user space; in that case the
+	 * signal would erroneously become asynchronous.
+	 */
+	if (event->state == PERF_EVENT_STATE_OFF) {
+		event->pending_sigtrap = 0;
+		return;
+	}
+
+	/*
+	 * Only process this pending SIGTRAP if this IRQ work is running on the
+	 * right CPU: the scheduler is able to run before the IRQ work, which
+	 * moved the task to another CPU. In event_sched_in() another IRQ work
+	 * is scheduled, so that the signal is not lost; given the kernel has
+	 * not yet returned to user space, the signal remains synchronous.
+	 */
+	if (READ_ONCE(event->oncpu) != smp_processor_id())
+		return;
+
+	event->pending_sigtrap = 0;
+	perf_sigtrap(event);
+}
+
 static void perf_pending_event_disable(struct perf_event *event)
 {
 	int cpu = READ_ONCE(event->pending_disable);
@@ -6455,13 +6495,6 @@ static void perf_pending_event_disable(struct perf_event *event)
 
 	if (cpu == smp_processor_id()) {
 		WRITE_ONCE(event->pending_disable, -1);
-
-		if (event->attr.sigtrap) {
-			perf_sigtrap(event);
-			atomic_set_release(&event->event_limit, 1); /* rearm event */
-			return;
-		}
-
 		perf_event_disable_local(event);
 		return;
 	}
@@ -6500,6 +6533,7 @@ static void perf_pending_event(struct irq_work *entry)
 	 * and we won't recurse 'further'.
 	 */
 
+	perf_pending_event_sigtrap(event);
 	perf_pending_event_disable(event);
 
 	if (event->pending_wakeup) {
@@ -6511,6 +6545,26 @@ static void perf_pending_event(struct irq_work *entry)
 		perf_swevent_put_recursion_context(rctx);
 }
 
+/*
+ * If handling of a pending action must occur before returning to user space,
+ * and it is possible to reschedule an event (to another CPU) with pending
+ * actions, where the moved-from CPU may not yet have run event->pending (and
+ * irq_work_queue() would fail on reuse), we'll use a separate IRQ work that
+ * runs perf_pending_event_resched().
+ */
+static void perf_pending_event_resched(struct irq_work *entry)
+{
+	struct perf_event *event = container_of(entry, struct perf_event, pending_resched);
+	int rctx;
+
+	rctx = perf_swevent_get_recursion_context();
+
+	perf_pending_event_sigtrap(event);
+
+	if (rctx >= 0)
+		perf_swevent_put_recursion_context(rctx);
+}
+
 #ifdef CONFIG_GUEST_PERF_EVENTS
 struct perf_guest_info_callbacks __rcu *perf_guest_cbs;
 
@@ -9209,11 +9263,20 @@ static int __perf_event_overflow(struct perf_event *event,
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
@@ -11536,6 +11599,7 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
 	init_waitqueue_head(&event->waitq);
 	event->pending_disable = -1;
 	init_irq_work(&event->pending, perf_pending_event);
+	init_irq_work(&event->pending_resched, perf_pending_event_resched);
 
 	mutex_init(&event->mmap_mutex);
 	raw_spin_lock_init(&event->addr_filters.lock);
@@ -11557,9 +11621,6 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
 	if (parent_event)
 		event->event_caps = parent_event->event_caps;
 
-	if (event->attr.sigtrap)
-		atomic_set(&event->event_limit, 1);
-
 	if (task) {
 		event->attach_state = PERF_ATTACH_TASK;
 		/*
-- 
2.37.3.998.g577e59143f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220927121322.1236730-1-elver%40google.com.
