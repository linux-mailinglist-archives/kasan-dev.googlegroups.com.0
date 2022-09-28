Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7GA2GMQMGQEHEU5XFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0434D5EDF44
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Sep 2022 16:55:57 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id k30-20020adfb35e000000b0022cc5ecd872sf801813wrd.8
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Sep 2022 07:55:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664376956; cv=pass;
        d=google.com; s=arc-20160816;
        b=esHHhOXlZ0Ow8Veo1G66rP+W/YwTpD4Xkltb6mqg1DjEc9kqbpSVM6trIHCtHWp3vr
         WSYzM8fR55otC4HIEE58HZkNea/SwmM97/HWy7Qk11wUp+NCRYXyXp//TegA76UZplWn
         Jt0k0XxTUS4Ql2URQN+AN9SRjQge6Phfi+1tmBAwNMM/ZavZJTxN8SJTwivexLI28l6s
         B5ovamzcRe/K6uMtT66mJ8/jWvimmZEpYoDojsRjgG/1Xh+BpFqSzWI+Qw5nca/V9Ha8
         SbhzafEw9F0O3dfjNnsEyBpj60T4HqSO9scjopg18AE5vj3WXY9FIgNiSA066yMNedfx
         xx+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=lTINrvx+iK4Bk+8FNkkzfvVh2iJGlzkRgX8ahTJux/A=;
        b=hS3IDxmEg5fZTnrw4ZuFr2cTYHhM6EUYyPzvwHuCG35v4GaL0P7Sf9GLPN65qiP7/u
         vHJpRRgkT8qKOLnmGY/WOQ6ebF2VM33ZdYCfRIjWykY6fg0GVbzRMwZc6r1bNjt0Tvoh
         Xyx+3OI5C5TpsLsR7NKJK3jQxy3ZhZ1Sv2FzUoH5htOeSAYPnCtevkqunZSlxPhkgGxu
         MOxdM4rA31CwW+fYTVBesKO+OdBjRKhDLBEZbmfXdFU0vVsL/Lx5PjRPwYqcE1+vJqHP
         4sW0Bft/YkdqoxoxpH2Gwtn7xp+zX6uV/SQKVWqrwxEIZfC6L30J3mxAZcFk+pDms8mO
         miNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bHTJmWYv;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date;
        bh=lTINrvx+iK4Bk+8FNkkzfvVh2iJGlzkRgX8ahTJux/A=;
        b=nu4WltumsonqvZKzM52bkKv0v1qLGtuUogKIa3t+FQghizB+nJ5e/DyUoHU+sl6nRH
         c0H4Mw5hb9GihL4TBRQmnDiOBzX0WlCuYwBap2MRihDDNv4ric3O8e1QWYaN7nUtsDuN
         7z59ON6t+l8Ma0l5PoB/jGx096sLXx/p/ZkzMvYP8liqGhnuuCCL+H73NB4U3+7/ORce
         2tapJ1DS3WG9kz+T9Q7G8PyHaQmCKv22zyCPMSTR1myw2W1pm8aYsxk7VFXKgBRro31M
         uwUzWhtmSschGmhS4rE707ZGxG4Vhc1SQ6r/cPuy6a+gzMt2vXEPbpEDJPURPORq+hRH
         RCsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=lTINrvx+iK4Bk+8FNkkzfvVh2iJGlzkRgX8ahTJux/A=;
        b=gh4h1HRaiSYAj2674Qpv/Qz1vjSQMKoA1/QM9OGoYgBvWEg/VtVfmYC7IvaUQ9R49R
         zL5UsGTkVr8xGKWRt7H6EW8CdJujNtMsmpnWNS2O/FfYzAOvFE/fYCv3CyYTrcqUXnKG
         vv+8zSL63goXpiRpVwpyvEUqoAyK5uUsQK4w/HPyg+nOIFcuTCWeNxBGUfU9I91yxrFR
         sclUf/fM+bsirMPyBxdRE/S/W7DvLxu/hseKozXCSqOEL76cg06j/ska+xsnFnTcoL9+
         hDTdyNeDZ4UIZotvpicey26UCv1gER65o1JrdBYurXOWwRTyelIFpor1cogkEQNAFfWI
         83Ew==
X-Gm-Message-State: ACrzQf0YcY5Guk68z/DfCM7a7i0Ev8lscCkhoSHj02esUFocNJZvCDD9
	ASNF0s16ICjoshwcmOVYaIQ=
X-Google-Smtp-Source: AMsMyM4K6Q1BEq9rl69u8kJHrUBKSo33cpvx3/J+IqIhSqJlWMddriVdid9s7IF1/LLed04dFpsZjg==
X-Received: by 2002:a05:6000:144c:b0:22b:dda:eeb0 with SMTP id v12-20020a056000144c00b0022b0ddaeeb0mr21924741wrx.335.1664376956341;
        Wed, 28 Sep 2022 07:55:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c4c4:0:b0:3a5:24fe:28ff with SMTP id g4-20020a7bc4c4000000b003a524fe28ffls763078wmk.0.-pod-control-gmail;
 Wed, 28 Sep 2022 07:55:55 -0700 (PDT)
X-Received: by 2002:a05:600c:4f11:b0:3b4:bf6c:4566 with SMTP id l17-20020a05600c4f1100b003b4bf6c4566mr7321357wmq.34.1664376954816;
        Wed, 28 Sep 2022 07:55:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664376954; cv=none;
        d=google.com; s=arc-20160816;
        b=C8cP5oWUQxCHteHMT2j3wPmP7WrIIU2n2QXlOaCOSK/AaIPyB68o8pZrXRoM1h17zI
         NkrqkJp/pi3UhSyn3v/QQ8T/POAyC/pQowxXDgk9sTYNygb7tx1+hsDTNyJ2+LPIg/Pz
         CfY0th9vqL24Eq8hLtT3OK1eMKLQC/GPF8binOL2ZXbRB1Ze3HX6HckW/W/NqYfDtmr3
         EmJw47gELnFcrLfNyLIrU9win0G+piE06wmOuxf2w9j9xcdZCFhqSHN8J80Pvu9jWcXd
         9GrLsAAUnxCnOxx9/acAaZsnVsUi6QxI7OM2ODIg5JvuLFvknh9VHKV0RWwJXGf6FqUz
         74lQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=jD41RBwsQAO8F9W6wPajIDr+uexC/n3UBb3DBn/vWVE=;
        b=do9S3Ks6SQtDNJ3iTm2KKNd96R188lUjXy3tbqrXwlCo6AZ9mHeJDzAYcYS5Ospkjr
         6Xsopx2tEa/v+g1AvB89IIVoD7bGLls1T3iyPnwmUs5zUx6qOHiY2cXkhABo2iOtesyR
         JsJa+ZkCSVjyakCQLIWNYZyH/dSib2eI+BJw93f1CfnVgJvL7/OlOO8PC6uaVk3pOosC
         Xyrs2ODZgKntQ7QWBERiw5imiDyl7kP5hyrv0nVIg2ZqEl5Yt9Ij5mHY+3omawQonqWd
         ZW/foCiHFKnglyKhIcvnWrJ1i5YkYl/Jjv0dHST8a27ol//xI8zjGaFptCaK1Sz5zgez
         H2+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bHTJmWYv;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x636.google.com (mail-ej1-x636.google.com. [2a00:1450:4864:20::636])
        by gmr-mx.google.com with ESMTPS id n24-20020a7bcbd8000000b003a5ce2af2c7si125888wmi.1.2022.09.28.07.55.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Sep 2022 07:55:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::636 as permitted sender) client-ip=2a00:1450:4864:20::636;
Received: by mail-ej1-x636.google.com with SMTP id sd10so27746029ejc.2
        for <kasan-dev@googlegroups.com>; Wed, 28 Sep 2022 07:55:54 -0700 (PDT)
X-Received: by 2002:a17:906:9749:b0:782:287f:d217 with SMTP id o9-20020a170906974900b00782287fd217mr27395588ejy.259.1664376954293;
        Wed, 28 Sep 2022 07:55:54 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:dbbc:9ea2:a5f7:571e])
        by smtp.gmail.com with ESMTPSA id 18-20020a170906219200b0073de0506745sm2489691eju.197.2022.09.28.07.55.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Sep 2022 07:55:53 -0700 (PDT)
Date: Wed, 28 Sep 2022 16:55:46 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] perf: Fix missing SIGTRAPs due to pending_disable abuse
Message-ID: <YzRgcnMXWuUZ4rlt@elver.google.com>
References: <20220927121322.1236730-1-elver@google.com>
 <YzM/BUsBnX18NoOG@hirez.programming.kicks-ass.net>
 <YzNu5bgASbuVi0S3@elver.google.com>
 <YzQcqe9p9C5ZbjZ1@elver.google.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="bwaiqnhq9mMzxU4e"
Content-Disposition: inline
In-Reply-To: <YzQcqe9p9C5ZbjZ1@elver.google.com>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=bHTJmWYv;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::636 as
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


--bwaiqnhq9mMzxU4e
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Wed, Sep 28, 2022 at 12:06PM +0200, Marco Elver wrote:

> My second idea about introducing something like irq_work_raw_sync().
> Maybe it's not that crazy if it is actually safe. I expect this case
> where we need the irq_work_raw_sync() to be very very rare.

The previous irq_work_raw_sync() forgot about irq_work_queue_on(). Alas,
I might still be missing something obvious, because "it's never that
easy". ;-)

And for completeness, the full perf patch of what it would look like
together with irq_work_raw_sync() (consider it v1.5). It's already
survived some shorter stress tests and fuzzing.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YzRgcnMXWuUZ4rlt%40elver.google.com.

--bwaiqnhq9mMzxU4e
Content-Type: text/x-diff; charset=us-ascii
Content-Disposition: attachment;
	filename="0001-irq_work-Introduce-irq_work_raw_sync.patch"

From 5fcc38d87b2cd8c05c5306c0140ccc076c5bf963 Mon Sep 17 00:00:00 2001
From: Marco Elver <elver@google.com>
Date: Wed, 28 Sep 2022 16:33:27 +0200
Subject: [PATCH 1/2] irq_work: Introduce irq_work_raw_sync()

Introduce a non-sleeping spinning variant of irq_work_sync(), called
irq_work_raw_sync(). Its usage is limited to contexts where interrupts
are disabled, and unlike irq_work_sync(), may fail if the work is
pending in the current CPU.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* New patch.
---
 include/linux/irq_work.h |  1 +
 kernel/irq_work.c        | 41 ++++++++++++++++++++++++++++++++++++++++
 2 files changed, 42 insertions(+)

diff --git a/include/linux/irq_work.h b/include/linux/irq_work.h
index 8cd11a223260..490adecbb4be 100644
--- a/include/linux/irq_work.h
+++ b/include/linux/irq_work.h
@@ -59,6 +59,7 @@ bool irq_work_queue_on(struct irq_work *work, int cpu);
 
 void irq_work_tick(void);
 void irq_work_sync(struct irq_work *work);
+bool irq_work_raw_sync(struct irq_work *work);
 
 #ifdef CONFIG_IRQ_WORK
 #include <asm/irq_work.h>
diff --git a/kernel/irq_work.c b/kernel/irq_work.c
index 7afa40fe5cc4..b251b3437db1 100644
--- a/kernel/irq_work.c
+++ b/kernel/irq_work.c
@@ -290,6 +290,47 @@ void irq_work_sync(struct irq_work *work)
 }
 EXPORT_SYMBOL_GPL(irq_work_sync);
 
+/*
+ * Synchronize against the irq_work @work, ensuring the entry is not currently
+ * in use after returning true; returns false if it's impossible to synchronize
+ * due to being queued on the current CPU. Requires that interrupts are already
+ * disabled (prefer irq_work_sync() in all other cases).
+ */
+bool irq_work_raw_sync(struct irq_work *work)
+{
+	struct llist_node *head;
+	struct irq_work *entry;
+
+	/*
+	 * Interrupts should be disabled, so that we can be sure the current
+	 * CPU's work queues aren't concurrently run, cleared, and potentially
+	 * some of its entries becoming invalid in the below iterations.
+	 */
+	lockdep_assert_irqs_disabled();
+
+	while (irq_work_is_busy(work)) {
+		/*
+		 * It is only safe to wait if the work is not on this CPU's work
+		 * queues. Also beware of concurrent irq_work_queue_on(), so we
+		 * need to keep re-checking this CPU's queues in this busy loop.
+		 */
+		head = READ_ONCE(this_cpu_ptr(&raised_list)->first);
+		llist_for_each_entry(entry, head, node.llist) {
+			if (entry == work)
+				return false;
+		}
+		head = READ_ONCE(this_cpu_ptr(&lazy_list)->first);
+		llist_for_each_entry(entry, head, node.llist) {
+			if (entry == work)
+				return false;
+		}
+		cpu_relax();
+	}
+
+	return true;
+}
+EXPORT_SYMBOL_GPL(irq_work_raw_sync);
+
 static void run_irq_workd(unsigned int cpu)
 {
 	irq_work_run_list(this_cpu_ptr(&lazy_list));
-- 
2.37.3.998.g577e59143f-goog


--bwaiqnhq9mMzxU4e
Content-Type: text/x-diff; charset=us-ascii
Content-Disposition: attachment;
	filename="0002-perf-Fix-missing-SIGTRAPs-due-to-pending_disable-abu.patch"

From 4467a6520c8f59065220a651167c4cd8da7a6e9b Mon Sep 17 00:00:00 2001
From: Marco Elver <elver@google.com>
Date: Fri, 23 Sep 2022 16:43:19 +0200
Subject: [PATCH 2/2] perf: Fix missing SIGTRAPs due to pending_disable abuse

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
v2:
* Use irq_work_raw_sync().
---
 include/linux/perf_event.h |  1 +
 kernel/events/core.c       | 64 +++++++++++++++++++++++++++++++-------
 2 files changed, 53 insertions(+), 12 deletions(-)

diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
index 907b0e3f1318..c119fa7b70d6 100644
--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -740,6 +740,7 @@ struct perf_event {
 	int				pending_wakeup;
 	int				pending_kill;
 	int				pending_disable;
+	int				pending_sigtrap;
 	unsigned long			pending_addr;	/* SIGTRAP */
 	struct irq_work			pending;
 
diff --git a/kernel/events/core.c b/kernel/events/core.c
index c37ba0909078..6ba02a1b5c5d 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -2527,6 +2527,15 @@ event_sched_in(struct perf_event *event,
 	if (event->attr.exclusive)
 		cpuctx->exclusive = 1;
 
+	if (event->pending_sigtrap) {
+		/*
+		 * The task and event might have been moved to another CPU:
+		 * queue another IRQ work. See perf_pending_event_sigtrap().
+		 */
+		irq_work_raw_sync(&event->pending); /* Syncs if pending on other CPU. */
+		irq_work_queue(&event->pending);
+	}
+
 out:
 	perf_pmu_enable(event->pmu);
 
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
@@ -9209,11 +9243,20 @@ static int __perf_event_overflow(struct perf_event *event,
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
@@ -11557,9 +11600,6 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
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


--bwaiqnhq9mMzxU4e--
