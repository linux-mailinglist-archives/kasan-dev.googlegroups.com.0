Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTVZXOBQMGQEIIBZU3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C5C6C3580BE
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 12:37:03 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id v124sf779464ooa.11
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 03:37:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617878222; cv=pass;
        d=google.com; s=arc-20160816;
        b=OxOPCExJSBhgyGkaQjztun2zjzhc4gfuxcgn+NylUkBFX11Q9CNOtQEnZiGgbtZE7T
         hckbBysy6kTE2tJvQdH1GS/LwxT62PzOjYEMeXvsOQKPhHKFDlWwHXT+so/QGy6lfF4c
         u3bUZicf1944PxGMmuwBUAr07SMZ/UFEuZ2YQ4Jelo6IHgMT2CLb4azVWrxNPoYjQF/B
         YdqFNURawzPwNTCM2tngINM9CtgcxC8biDkkJ6HWr40LRFehspFGZh/cjJi3e56tuycX
         aDR+Cxp2BGESWA+JDEWf5Be1g9EPwdyTpVX3Sz/h2bm8jiirgQm6TQ1+oVPA+eGoTLjb
         2sQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=FV7UnFmLRvvH/+nDNO0ciDAhb252HS2b3+CKL6JjuJc=;
        b=aE7cQNDugT21CSyrekohseivIR9geTporzn8kG90+VTbbw0iG3dot91/NxRVdQxsL9
         KTsh/rK4PNM9Apzvo0eIDXhDDKWOR/SNCGo5/nZppKoossT7zIo8D6R7UlvfqWFkdWBq
         tBa32+hiTON5LSmpcRUsfs1v5vRk1ApOKqU9dq4GQNR7OP4Zj0rtR7DCGWZcTcKV9iBI
         nImTJgE8AvP3AazOfDXs4VQ+ha41vcc7anlxnNMGTdpwM9KXaTcmVKIu9gR3QWsHL+wQ
         SZPEET9bPkmR9GkNJ2kQmWCapdzSz7Th95JOGPoh4HvGt2ifdwqb4HQIaKB3UivCwNqr
         dpMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UNw+Kg5t;
       spf=pass (google.com: domain of 3y9xuyaukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3y9xuYAUKCUoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FV7UnFmLRvvH/+nDNO0ciDAhb252HS2b3+CKL6JjuJc=;
        b=XEpZ43qXudLz/vaZvEYtVRGUKFJbGS6bChYY34ubGfoUbGayTP//iOeSNtAtjzDyky
         C98wpaJzfNKeMs8CTkQVVwp34WK/octcEOXBTAIoET6lrPqZqoxfanRlbfni8x9EVAo8
         ZYQnwIA2JyJ5nrOLpQhSAO/+qsvjZGYwGpTEwu2ksx2Lds95ATbbx7SlhPIpsYJakwVy
         7I85i5tX7fHJkedjyMypWLS/F9Jammkc4LwoXLisarCoc/Uin3Qdp2u/2kOb7o5PfYHO
         69mJjnD9uitGmLPFzeiCg8mIz16ZrMZiCk2c94TJO7H7+J4grfsmMsmhJ05VivqzZ9v5
         gyLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FV7UnFmLRvvH/+nDNO0ciDAhb252HS2b3+CKL6JjuJc=;
        b=nywfL1GADJD7yOLmaoyfWyFvr5R3hoNX7lMCHUVUpNMR13cSpSvdPPdqyCvQnciCab
         05ndBIBSW1ajQnZNqJwbakiq4CaIwvhI1o05TZ0esZD84+6el+P69QVM7qi4Ep/nust5
         a55kEP7fVgcnIwuaNtGsc5mscqAEuvjALT64d8r5SgT5DM/BxCKHWuwOmE7rdm7Zy7GR
         A4L7ZixdATjqT/bR0gTp/z4PzqNgUECjHR1ixBbU47nfl3MN9F/ad9bBmHSSl2lxrjKc
         OIlcHfoAP76++Ko9Foxj9jQ9IEYZOtWH2s0CoYD15NpvwZ0iwiH7LaFZdNvL5YsabOmN
         QjuQ==
X-Gm-Message-State: AOAM5319HZ+dAjyhjyV7v3POsTi00Rj76+V/sBMQ6DtRhZMlqfxoq0jW
	ke/QgPsH5fnbcuE4iJFnBBw=
X-Google-Smtp-Source: ABdhPJzHnYGDlNkR55NJv1zvn6kOb0U6LPDuJNps4aXNtkleDN7IVsBhR0uwURhj4OdjAcKhEdnqMw==
X-Received: by 2002:a05:6808:5c2:: with SMTP id d2mr5714064oij.60.1617878222784;
        Thu, 08 Apr 2021 03:37:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:95c7:: with SMTP id p7ls316404ooi.0.gmail; Thu, 08 Apr
 2021 03:37:01 -0700 (PDT)
X-Received: by 2002:a4a:4005:: with SMTP id n5mr6932145ooa.61.1617878220951;
        Thu, 08 Apr 2021 03:37:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617878220; cv=none;
        d=google.com; s=arc-20160816;
        b=AF1jpZG8oHCQj+oo2CQLZBExbF7M0+vaVNcBh+QzOB35vXeK0wLl8R0lIgWLpt9RFa
         BB/ATJVGZ0SFCrA+h06izDvkhi26+JQlDfmWGsgWIJuKWjzvc5447tDF//O2VUMUqu+K
         qCNYR3T04JjCGDCd9VTrPGflvyAIDMuPT6Wc9bKk/uhTEg0MXD1cKwWs6rAyno46+NLo
         iUr6Sxhn/s/9KL2BaTGDWNxtPhIpVlOg6kRwihzjBkDT1iXw1ayAS4mCkdwKIuY0TbVu
         GP1ecdoEHMijvBxuCx8UqXgD37Qavp3fXKPzSIMQ21WZqUOJcpCHfeUBELnsNuKzOqiC
         V6YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=p4IAv4qy7NYDvKdM7TwKfxu2qzw/9tstIJL5I3FPPz8=;
        b=quprrnvWQb3P044CSMDDoPVX5UApl8gpEU4pmZWcLK42DZTtLLQlK2mH1m/GrcAew2
         tF4B189mEuFGF0YJAo2WNw6DahUD3CQOc69f+qkrJt7672HVBSjJYeOyiBuqVpzIZh97
         /X1zkwKhBf+yYlnQu823XIFg+Ixsd4GwYqvEXQG5XSk6AU2yCn/I1fnB7NpCNijxr+wQ
         bgtG737nQeKCPrHiYfr2GVk/EV2NES7RgOkKub44FPdzGcWovrGr/fGoSE4vhohE9sH7
         is9+dK0hLNP0zPJR4/JiaMOWowLk+rL2EDQiYguB8+xCv0ZboGdTnZRsrnqk0oro6T5h
         z8xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UNw+Kg5t;
       spf=pass (google.com: domain of 3y9xuyaukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3y9xuYAUKCUoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id i14si1948672ots.4.2021.04.08.03.37.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Apr 2021 03:37:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3y9xuyaukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id bl6so816194qvb.9
        for <kasan-dev@googlegroups.com>; Thu, 08 Apr 2021 03:37:00 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:9038:bbd3:4a12:abda])
 (user=elver job=sendgmr) by 2002:a0c:908d:: with SMTP id p13mr8445880qvp.11.1617878219837;
 Thu, 08 Apr 2021 03:36:59 -0700 (PDT)
Date: Thu,  8 Apr 2021 12:36:01 +0200
In-Reply-To: <20210408103605.1676875-1-elver@google.com>
Message-Id: <20210408103605.1676875-7-elver@google.com>
Mime-Version: 1.0
References: <20210408103605.1676875-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.208.g409f899ff0-goog
Subject: [PATCH v4 06/10] perf: Add support for SIGTRAP on perf events
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
 header.i=@google.com header.s=20161025 header.b=UNw+Kg5t;       spf=pass
 (google.com: domain of 3y9xuyaukcuoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3y9xuYAUKCUoqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
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

Adds bit perf_event_attr::sigtrap, which can be set to cause events to
send SIGTRAP (with si_code TRAP_PERF) to the task where the event
occurred. The primary motivation is to support synchronous signals on
perf events in the task where an event (such as breakpoints) triggered.

To distinguish perf events based on the event type, the type is set in
si_errno. For events that are associated with an address, si_addr is
copied from perf_sample_data.

The new field perf_event_attr::sig_data is copied to si_perf, which
allows user space to disambiguate which event (of the same type)
triggered the signal. For example, user space could encode the relevant
information it cares about in sig_data.

We note that the choice of an opaque u64 provides the simplest and most
flexible option. Alternatives where a reference to some user space data
is passed back suffer from the problem that modification of referenced
data (be it the event fd, or the perf_event_attr) can race with the
signal being delivered (of course, the same caveat applies if user space
decides to store a pointer in sig_data, but the ABI explicitly avoids
prescribing such a design).

Link: https://lore.kernel.org/lkml/YBv3rAT566k+6zjg@hirez.programming.kicks-ass.net/
Suggested-by: Peter Zijlstra <peterz@infradead.org>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Generalize setting si_perf and si_addr independent of event type;
  introduces perf_event_attr::sig_data, which can be set by user space to
  be propagated to si_perf.
* Fix race between irq_work running and task's sighand being released by
  release_task().
* Warning in perf_sigtrap() if ctx->task and current mismatch; we expect
  this on architectures that do not properly implement
  arch_irq_work_raise().
* Require events that want sigtrap to be associated with a task.

v2:
* Use atomic_set(&event_count, 1), since it must always be 0 in
  perf_pending_event_disable().
* Implicitly restrict inheriting events if sigtrap, but the child was
  cloned with CLONE_CLEAR_SIGHAND, because it is not generally safe if
  the child cleared all signal handlers to continue sending SIGTRAP.
---
 include/linux/perf_event.h      |  3 ++
 include/uapi/linux/perf_event.h | 10 ++++++-
 kernel/events/core.c            | 49 ++++++++++++++++++++++++++++++++-
 3 files changed, 60 insertions(+), 2 deletions(-)

diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
index 1660039199b2..18ba1282c5c7 100644
--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -778,6 +778,9 @@ struct perf_event {
 	void *security;
 #endif
 	struct list_head		sb_list;
+
+	/* Address associated with event, which can be passed to siginfo_t. */
+	u64				sig_addr;
 #endif /* CONFIG_PERF_EVENTS */
 };
 
diff --git a/include/uapi/linux/perf_event.h b/include/uapi/linux/perf_event.h
index 8c5b9f5ad63f..31b00e3b69c9 100644
--- a/include/uapi/linux/perf_event.h
+++ b/include/uapi/linux/perf_event.h
@@ -311,6 +311,7 @@ enum perf_event_read_format {
 #define PERF_ATTR_SIZE_VER4	104	/* add: sample_regs_intr */
 #define PERF_ATTR_SIZE_VER5	112	/* add: aux_watermark */
 #define PERF_ATTR_SIZE_VER6	120	/* add: aux_sample_size */
+#define PERF_ATTR_SIZE_VER7	128	/* add: sig_data */
 
 /*
  * Hardware event_id to monitor via a performance monitoring event:
@@ -391,7 +392,8 @@ struct perf_event_attr {
 				build_id       :  1, /* use build id in mmap2 events */
 				inherit_thread :  1, /* children only inherit if cloned with CLONE_THREAD */
 				remove_on_exec :  1, /* event is removed from task on exec */
-				__reserved_1   : 27;
+				sigtrap        :  1, /* send synchronous SIGTRAP on event */
+				__reserved_1   : 26;
 
 	union {
 		__u32		wakeup_events;	  /* wakeup every n events */
@@ -443,6 +445,12 @@ struct perf_event_attr {
 	__u16	__reserved_2;
 	__u32	aux_sample_size;
 	__u32	__reserved_3;
+
+	/*
+	 * User provided data if sigtrap=1, passed back to user via
+	 * siginfo_t::si_perf, e.g. to permit user to identify the event.
+	 */
+	__u64	sig_data;
 };
 
 /*
diff --git a/kernel/events/core.c b/kernel/events/core.c
index 19c045ff2b9c..1d2077389c0c 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -6391,6 +6391,33 @@ void perf_event_wakeup(struct perf_event *event)
 	}
 }
 
+static void perf_sigtrap(struct perf_event *event)
+{
+	struct kernel_siginfo info;
+
+	/*
+	 * We'd expect this to only occur if the irq_work is delayed and either
+	 * ctx->task or current has changed in the meantime. This can be the
+	 * case on architectures that do not implement arch_irq_work_raise().
+	 */
+	if (WARN_ON_ONCE(event->ctx->task != current))
+		return;
+
+	/*
+	 * perf_pending_event() can race with the task exiting.
+	 */
+	if (current->flags & PF_EXITING)
+		return;
+
+	clear_siginfo(&info);
+	info.si_signo = SIGTRAP;
+	info.si_code = TRAP_PERF;
+	info.si_errno = event->attr.type;
+	info.si_perf = event->attr.sig_data;
+	info.si_addr = (void *)event->sig_addr;
+	force_sig_info(&info);
+}
+
 static void perf_pending_event_disable(struct perf_event *event)
 {
 	int cpu = READ_ONCE(event->pending_disable);
@@ -6400,6 +6427,13 @@ static void perf_pending_event_disable(struct perf_event *event)
 
 	if (cpu == smp_processor_id()) {
 		WRITE_ONCE(event->pending_disable, -1);
+
+		if (event->attr.sigtrap) {
+			perf_sigtrap(event);
+			atomic_set_release(&event->event_limit, 1); /* rearm event */
+			return;
+		}
+
 		perf_event_disable_local(event);
 		return;
 	}
@@ -9102,6 +9136,7 @@ static int __perf_event_overflow(struct perf_event *event,
 	if (events && atomic_dec_and_test(&event->event_limit)) {
 		ret = 1;
 		event->pending_kill = POLL_HUP;
+		event->sig_addr = data->addr;
 
 		perf_event_disable_inatomic(event);
 	}
@@ -11382,6 +11417,10 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
 		if (!task || cpu != -1)
 			return ERR_PTR(-EINVAL);
 	}
+	if (attr->sigtrap && !task) {
+		/* Requires a task: avoid signalling random tasks. */
+		return ERR_PTR(-EINVAL);
+	}
 
 	event = kzalloc(sizeof(*event), GFP_KERNEL);
 	if (!event)
@@ -11428,6 +11467,9 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
 
 	event->state		= PERF_EVENT_STATE_INACTIVE;
 
+	if (event->attr.sigtrap)
+		atomic_set(&event->event_limit, 1);
+
 	if (task) {
 		event->attach_state = PERF_ATTACH_TASK;
 		/*
@@ -11706,6 +11748,9 @@ static int perf_copy_attr(struct perf_event_attr __user *uattr,
 	if (attr->remove_on_exec && attr->enable_on_exec)
 		return -EINVAL;
 
+	if (attr->sigtrap && !attr->remove_on_exec)
+		return -EINVAL;
+
 out:
 	return ret;
 
@@ -12932,7 +12977,9 @@ inherit_task_group(struct perf_event *event, struct task_struct *parent,
 	struct perf_event_context *child_ctx;
 
 	if (!event->attr.inherit ||
-	    (event->attr.inherit_thread && !(clone_flags & CLONE_THREAD))) {
+	    (event->attr.inherit_thread && !(clone_flags & CLONE_THREAD)) ||
+	    /* Do not inherit if sigtrap and signal handlers were cleared. */
+	    (event->attr.sigtrap && (clone_flags & CLONE_CLEAR_SIGHAND))) {
 		*inherited_all = 0;
 		return 0;
 	}
-- 
2.31.0.208.g409f899ff0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210408103605.1676875-7-elver%40google.com.
