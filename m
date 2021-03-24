Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLWD5SBAMGQESWTLS5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id E3032347714
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 12:25:35 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id a63sf1920858yba.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 04:25:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616585135; cv=pass;
        d=google.com; s=arc-20160816;
        b=iX3uG1Z+Cs+FT+pKAhlkgWwwukPA5NTtGKraHahBl7Lzmk1t+SDs5XAQl91rx8F09l
         Ad5EzLZn9GIYb5e5AhwfHyXuxQQGS+YXaTx/EhelomzOUXaa1Mw/tEuxWy5pGAkAZNSB
         ul/RUi26dPZ7FLYNQbjf8yK02qqeWJI9mUIzM2JhpiJe9pC9hl+4Hg85876yjwbwERkh
         UXmthEDQzgb72Fdy4JDrfIc7gDxot4oV2rYvDY2g66cl6j5xOI4fd3vZluJ+4ynJ5XVl
         4uT/u/kKo8MxTIe83p/ipF5LF9NUazN0n0AQK5iWFKZCGBuUbfKoNSbXckAJiYmKOeOL
         UiSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Ov3RKDUpVlYzEMgw2zXmYqdzYBRKSUhJZGsPh00RRt8=;
        b=bRQc0deO+P8MwYxfzktKemM/nvRyJtT78/Cdm5szLMOIbNRFboW4rnPR4DHOAQHBck
         ANb+XGIjzfyqQDKJZRdrQlasWANANPcApuTF8RG2HmjSZsxCC6ppuUzKF7nF+J9l+u1A
         ZjDkLKhcxkLpdXiLDpQy+vjRZ3L/SbaEcZHHYr7mgsE27F59bcPssMxmDzQbQm0P4eRE
         iabxCm5jYLi0P9m6ENP0FXabxDPesZR9TBbQyghV5DvP38BQqqK8UtUvlUBh6sF3ECcG
         6i24I1bDJGXf2ygTuy3S9yxTasDIhUFMb+Q9gQ6CkjQHtsOXZmZbZ9Hix2HrdIgYcq2v
         vy8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=INRWAnDF;
       spf=pass (google.com: domain of 3rsfbyaukcwyipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3rSFbYAUKCWYIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ov3RKDUpVlYzEMgw2zXmYqdzYBRKSUhJZGsPh00RRt8=;
        b=i5IsuFFgKzO5GV0E4/3xqBtsl2GUCqOsFtI2YNJ6yDxs/xglpaMTqnSmuwBIGgM2Iy
         F+3Kn7jCeiZKiLCNNOOG8Ca3mzehnps4IB+kJj8L8U81xpv4bOo3Vx3RlRWOQUmqFeqZ
         zieNxCIuASqO4m5sMw2AxygQ5V+Xs6xr9/8/wMrgrmXUvn1603ANA6AicNbPgugXIizO
         1NDxqr62A5Qb9L6WYBbbP3/WL6KkS91m9JkAoMf3UFoOTU7Aad9T7IqWPsCpH4yHHYB2
         PexGEMIwuQO0y8/zXF9bvc/1p+NWC7hZiKrzhiMNY3ArgU+IfMtF9gu3s9Kzci1nAgXz
         jUZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ov3RKDUpVlYzEMgw2zXmYqdzYBRKSUhJZGsPh00RRt8=;
        b=dJ4y3tyDpTxxPYRp5SgrIgOA8l5lqLVmuxqErSk2n1NO0haZqEwb1P/FHOA6VNyPrk
         2x77cyXlMzbaYMY5hx9z0HSdIEo1/nMYnwlQ9hSyNgb8Pd00+8/VhYUs5pNn1Rp30TIw
         DuORVIVCkS1JNRJSck8EERmfQDLIJxTOP3M/rnS+Eg5k+tdV3hQeiW9bgE8SahqdSmhU
         /FpK3ZryCXji12sliETD651XnPfxH0KJR8kICihtTPtRWaoylV1h8Y/btM3BjLGAzDVH
         /2Pm80OiuHeU8QIKeS0OSRpEfY4MjKcyWK27O3HUCqeaRna9vi0bSzrJfJV5hmvIIQeO
         NoKQ==
X-Gm-Message-State: AOAM5332E+bq5f3+MMzuGQZBR/m++A/Bty4QZ6hO44a4/foy5PyXeAqg
	k/9uHNuhPYogYWERDRswjt4=
X-Google-Smtp-Source: ABdhPJxD9cYoiR0TSIMl42i/qTkjspnxQDmxUaJzHJJkVwH67n1sknUMIZ9X/RiJ8PbjtEYKZc26mQ==
X-Received: by 2002:a25:ae28:: with SMTP id a40mr4004081ybj.400.1616585134853;
        Wed, 24 Mar 2021 04:25:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ec02:: with SMTP id j2ls926549ybh.2.gmail; Wed, 24 Mar
 2021 04:25:34 -0700 (PDT)
X-Received: by 2002:a25:bac5:: with SMTP id a5mr4019807ybk.174.1616585134356;
        Wed, 24 Mar 2021 04:25:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616585134; cv=none;
        d=google.com; s=arc-20160816;
        b=W+LpB18jHpArzzTIHMSDMaSgdX8iLtEi0wrn07vDUL20BYXdGuvXmQOMioif44EtAg
         x7BjnAk3rwvNctXsxUTlTF/Jzt3qXVlkzG4j0yIOop8w0vC35RtS1RJbKf43FMPtJZFb
         sDgpI3sppejghkQO0KUofwjrf+ftIkOCbzd/oZTj1NHpsX59yU9Fe2ra5wcjvPWovaZZ
         zafNR9WEuVhu/lEp4ubvdVxvRN17NAsb2SGI++4S2zB37irEAwvu0S6t2zlIuUGP7t9s
         8IgNOgKeAuXi+l7JifEwbe3VvtLx6vfv5XWrfFOWa6LKlcuapp83iv6RyPIxfodlMtvz
         dfZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ZaFjuV65eN1OuecHxLplhRFaC9JE/oD9gdApL7zOyoc=;
        b=E+vgOt6mSropAvE+86mkJBAdG8gVuF93f+l8VyCzLQn2SwG3e7np0u7OEvNxmSnXGg
         p0y1WBIkXuwlfDNJl4gtyZtWB4l2aeK+jF2GdwmWddxA/0YMMxmMNhe1a6JlRc1gAj/f
         P01B4LNT0Aoh1HhbQ/gfJ10GhOWXKbk5lOk5bSAJRPNyB4UlsCByvLAsIuF42poQ16rh
         XxOiRnWVA+47FxOQBTkyCuW4TrRpzYj0jwGWKJF+UJFpaBx0fubTlxArrHUtpBfj4tCg
         yisopEw5Tj3R7gsMfSQe7tTT+KLPTjUuCxiUK6tNBafQ6ylHdPdSX7ikXAByU5xGDdMr
         BFzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=INRWAnDF;
       spf=pass (google.com: domain of 3rsfbyaukcwyipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3rSFbYAUKCWYIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id l14si119097ybp.4.2021.03.24.04.25.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Mar 2021 04:25:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rsfbyaukcwyipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id b127so1315039qkf.19
        for <kasan-dev@googlegroups.com>; Wed, 24 Mar 2021 04:25:34 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6489:b3f0:4af:af0])
 (user=elver job=sendgmr) by 2002:a0c:f7d1:: with SMTP id f17mr2286719qvo.38.1616585133964;
 Wed, 24 Mar 2021 04:25:33 -0700 (PDT)
Date: Wed, 24 Mar 2021 12:24:58 +0100
In-Reply-To: <20210324112503.623833-1-elver@google.com>
Message-Id: <20210324112503.623833-7-elver@google.com>
Mime-Version: 1.0
References: <20210324112503.623833-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.291.g576ba9dcdaf-goog
Subject: [PATCH v3 06/11] perf: Add support for SIGTRAP on perf events
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
 header.i=@google.com header.s=20161025 header.b=INRWAnDF;       spf=pass
 (google.com: domain of 3rsfbyaukcwyipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3rSFbYAUKCWYIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
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
occurred. To distinguish perf events and allow user space to decode
si_perf (if set), the event type is set in si_errno.

The primary motivation is to support synchronous signals on perf events
in the task where an event (such as breakpoints) triggered.

Link: https://lore.kernel.org/lkml/YBv3rAT566k+6zjg@hirez.programming.kicks-ass.net/
Suggested-by: Peter Zijlstra <peterz@infradead.org>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Use atomic_set(&event_count, 1), since it must always be 0 in
  perf_pending_event_disable().
* Implicitly restrict inheriting events if sigtrap, but the child was
  cloned with CLONE_CLEAR_SIGHAND, because it is not generally safe if
  the child cleared all signal handlers to continue sending SIGTRAP.
---
 include/uapi/linux/perf_event.h |  3 ++-
 kernel/events/core.c            | 28 +++++++++++++++++++++++++++-
 2 files changed, 29 insertions(+), 2 deletions(-)

diff --git a/include/uapi/linux/perf_event.h b/include/uapi/linux/perf_event.h
index 8c5b9f5ad63f..3a4dbb1688f0 100644
--- a/include/uapi/linux/perf_event.h
+++ b/include/uapi/linux/perf_event.h
@@ -391,7 +391,8 @@ struct perf_event_attr {
 				build_id       :  1, /* use build id in mmap2 events */
 				inherit_thread :  1, /* children only inherit if cloned with CLONE_THREAD */
 				remove_on_exec :  1, /* event is removed from task on exec */
-				__reserved_1   : 27;
+				sigtrap        :  1, /* send synchronous SIGTRAP on event */
+				__reserved_1   : 26;
 
 	union {
 		__u32		wakeup_events;	  /* wakeup every n events */
diff --git a/kernel/events/core.c b/kernel/events/core.c
index b6434697c516..1e4c949bf75f 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -6391,6 +6391,17 @@ void perf_event_wakeup(struct perf_event *event)
 	}
 }
 
+static void perf_sigtrap(struct perf_event *event)
+{
+	struct kernel_siginfo info;
+
+	clear_siginfo(&info);
+	info.si_signo = SIGTRAP;
+	info.si_code = TRAP_PERF;
+	info.si_errno = event->attr.type;
+	force_sig_info(&info);
+}
+
 static void perf_pending_event_disable(struct perf_event *event)
 {
 	int cpu = READ_ONCE(event->pending_disable);
@@ -6400,6 +6411,13 @@ static void perf_pending_event_disable(struct perf_event *event)
 
 	if (cpu == smp_processor_id()) {
 		WRITE_ONCE(event->pending_disable, -1);
+
+		if (event->attr.sigtrap) {
+			atomic_set(&event->event_limit, 1); /* rearm event */
+			perf_sigtrap(event);
+			return;
+		}
+
 		perf_event_disable_local(event);
 		return;
 	}
@@ -11428,6 +11446,9 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
 
 	event->state		= PERF_EVENT_STATE_INACTIVE;
 
+	if (event->attr.sigtrap)
+		atomic_set(&event->event_limit, 1);
+
 	if (task) {
 		event->attach_state = PERF_ATTACH_TASK;
 		/*
@@ -11706,6 +11727,9 @@ static int perf_copy_attr(struct perf_event_attr __user *uattr,
 	if (attr->remove_on_exec && attr->enable_on_exec)
 		return -EINVAL;
 
+	if (attr->sigtrap && !attr->remove_on_exec)
+		return -EINVAL;
+
 out:
 	return ret;
 
@@ -12932,7 +12956,9 @@ inherit_task_group(struct perf_event *event, struct task_struct *parent,
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
2.31.0.291.g576ba9dcdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324112503.623833-7-elver%40google.com.
