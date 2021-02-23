Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDVF2SAQMGQEM4QTZXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E2DE322C6E
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 15:34:57 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id r79sf386677lff.20
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 06:34:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614090896; cv=pass;
        d=google.com; s=arc-20160816;
        b=cYHBEbpUEF1d89pMg5KNSeLf+pjj45ZppWiObX4ykxXfAHho61gQCdaujvYYz9T82e
         rRXGNY4ScQYvMQTzM0W5JVivkm/BkxbPscnxEJry0FSO5dLvPgO0YvmZc8h4TToGU0jW
         NzRTt3vMUF8FzZxgP9Abh1prBo65TVhXiZNc1qIviumyjGiWNTh3qcjmztrQoLX8GrgM
         nucyZJ982dLQrIAl6Cf6l9JFBer2B65xog5f7JPj5ppbqA/btAx2FLPL0OJ3r0iKtYab
         dWizyN8mmwfc0Lw57PS193mBuPDLWl6bCCBvhgIBQjimNw9n2bpSgF1SGZ3vyU3IuYz2
         5oxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=c2vZgkWfd0MhJx0DfqF2p5C0zY94RUrwiSjd0Q9bCWw=;
        b=0zRgcW8Lx2fxVOvpzlfcnFso4l3Nwyv+H7tnqpSoNEL4HE1nP5pxyKS5vrLAdr4ZyW
         mQPHovGzRi8vaF92JtVjXnOfVZipFqFRduqFnjX74QP7KIdjfSp/s4pStCexXJlzdIBC
         dewSJNtrmZe9vhyXY3xMQbiCjT2FZHtOLZA+D7DbE420ajPacbfProYjfaTTfdzzfnE8
         efKNQKV5JC9IGWILjLA3wneFbpZ3V7OlIr71c7eNLmanFRV8ANmG0aSa4lGFccPmfUwd
         hrUXch0DEEO3OiqZC0qYlXszUw9QnjyMr4nvfKiU0Y0/llPIhCpZ0urVPtplM26SSDMX
         4WGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pvodb754;
       spf=pass (google.com: domain of 3jbi1yaukcy0v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3jBI1YAUKCY0v2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=c2vZgkWfd0MhJx0DfqF2p5C0zY94RUrwiSjd0Q9bCWw=;
        b=qpPyoHhvyVtEWvHT62CbcV/CmpwvMjZWxMTCSkpki4GtnVRYv8qAHGT+c44zS8p2Ow
         sy/nCmPvtDNiatmoAJnGBk/m8tpcDhNPGCpI0BgtnV15l1CXqiK3MMjBbwYKG20uyNf5
         a5Iut4bJJvdLo+RC1fEdiVrUFVHo2CP7L6PJ2wGZV8wVpEs8hpuTJDmpo0V6/xxbNPl7
         zyXskOFl4KCcBI5MksbD0aInyzDKxHgcCzS0EL8B5WfuREoj1jotGjzuqiLmNi9WvkUY
         FbnLnqD/aShB3hNkYpeGJL4v5iK6GhS+fQuF6nOaf/5huW9AP4dZ2OgmErJqr/Ly6tQM
         j6sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c2vZgkWfd0MhJx0DfqF2p5C0zY94RUrwiSjd0Q9bCWw=;
        b=KUPABbpie0aVT791rwPRhMR/m+1cjFLSNfSK1yqbinooaF5CFsiEs++ekQ6utsQIx8
         ZmChwbWdjdZEmaspZq4C0nFfKdSo1VgSpkDpL0LN1BwlWew69mbP0YHQPwesKLSZYMqX
         BsQ2C10A4e/piCdaRM34a2nJp8qDIgC/ZmD9+qbidT+l6R/kHWasgkqcRxvEsx9D5Okj
         MgNtEK7aS92/iMc+2EMR8XlPHTPCe9eeyenapCOoh2ihQ8dL9lqPzVGOgxVncwRAPi+1
         /DC67GSP3otH3OwZbrU9c63KJKIi2r36YG7XstR2NHbTAxdM7h9t0oTgW9hVgRYUtff7
         5Syw==
X-Gm-Message-State: AOAM530002LbPEb1Pl+tB3lVnp1UhbHAhS/IJCzG70dU5itSjQL3X6OK
	Ynhv/NkOtZdlGofoJwJVSrM=
X-Google-Smtp-Source: ABdhPJxjlZ4PSQi8ezFMyEPjTLYIfEMb7SIeI27F8lfa97I083DxJli8rasb+6clhHJOIJgQ8RXbAg==
X-Received: by 2002:a05:6512:1054:: with SMTP id c20mr15965764lfb.170.1614090895097;
        Tue, 23 Feb 2021 06:34:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:211f:: with SMTP id a31ls622651ljq.3.gmail; Tue, 23
 Feb 2021 06:34:52 -0800 (PST)
X-Received: by 2002:a2e:9755:: with SMTP id f21mr7829788ljj.357.1614090892537;
        Tue, 23 Feb 2021 06:34:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614090892; cv=none;
        d=google.com; s=arc-20160816;
        b=V5vo/oEF+8SnHlS9YfnVhP3RQIeWxddzbjWkLQdtcE5cVsJID0HS74FBiuCvk8O/D/
         xQ/VDoGlebTL1Wi2D3KGoRAruIv3v/fqjay9oDrjfGFHaI9OeLSqUUVyh3bE/H9hk1GK
         EobAcnwin6zLJHlRRcI8wxciygsqFtnMVjG913SOTQn/qfJZdFMW1ZNByAJsTREWOLr5
         RtneEnZ+wn9oujaZeS821z6i76F0hlkXjFcsKN2eW0CFrk6pHihf3MAFUp+nPwICbUQp
         7Z1E4zg4VDGLf0Cn7i/60grXwvHjPJjKG/iZIM5xKa3O9DyU/Qpwg6+WfavUWS8v0T1j
         hK9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=M7IgukK9IFY6YerKyONO0wWjLsd7r1LevWvp+F7nZVo=;
        b=CpFPDzg0oHGOzYFw7p7chxhciHWnCm4LkI9DcHViRN2/VBg3gcPxI23wTCOw1c7AvT
         dfrdmHis2CMni6JrixkvQJIEGssuqzu3cFD6AKhQKiIdd3iVy54fpUREXQEoqGpVVUc9
         04nBRRit5McgMl+S8jf/FRhTbyBE+gOQBF0Tfz3W2aWDvPO2qnS+mT8fwDhWYrLv8c1d
         fdocfttjfG9+OEP4VBd0S5RoGyF/rd7sTshHpsfoHOdNd9aYaSJXaPl5iTpmG+yxPZ+F
         l7tgwpbci+LQk2/LnINmyYbPkfZ2zyTjh0ixh5YU1Tb1zFa3KkwCPh2VstEKMkQ1lhbu
         R9KA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pvodb754;
       spf=pass (google.com: domain of 3jbi1yaukcy0v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3jBI1YAUKCY0v2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x24a.google.com (mail-lj1-x24a.google.com. [2a00:1450:4864:20::24a])
        by gmr-mx.google.com with ESMTPS id y3si833570lfb.6.2021.02.23.06.34.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Feb 2021 06:34:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jbi1yaukcy0v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) client-ip=2a00:1450:4864:20::24a;
Received: by mail-lj1-x24a.google.com with SMTP id l8so638815ljc.14
        for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 06:34:52 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:855b:f924:6e71:3d5d])
 (user=elver job=sendgmr) by 2002:ac2:5184:: with SMTP id u4mr11572002lfi.487.1614090892105;
 Tue, 23 Feb 2021 06:34:52 -0800 (PST)
Date: Tue, 23 Feb 2021 15:34:25 +0100
In-Reply-To: <20210223143426.2412737-1-elver@google.com>
Message-Id: <20210223143426.2412737-4-elver@google.com>
Mime-Version: 1.0
References: <20210223143426.2412737-1-elver@google.com>
X-Mailer: git-send-email 2.30.0.617.g56c4b15f3c-goog
Subject: [PATCH RFC 3/4] perf/core: Add support for SIGTRAP on perf events
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-m68k@lists.linux-m68k.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pvodb754;       spf=pass
 (google.com: domain of 3jbi1yaukcy0v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3jBI1YAUKCY0v2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
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
Signed-off-by: Marco Elver <elver@google.com>
---
 include/uapi/linux/perf_event.h |  3 ++-
 kernel/events/core.c            | 21 +++++++++++++++++++++
 2 files changed, 23 insertions(+), 1 deletion(-)

diff --git a/include/uapi/linux/perf_event.h b/include/uapi/linux/perf_event.h
index ad15e40d7f5d..b9cc6829a40c 100644
--- a/include/uapi/linux/perf_event.h
+++ b/include/uapi/linux/perf_event.h
@@ -389,7 +389,8 @@ struct perf_event_attr {
 				cgroup         :  1, /* include cgroup events */
 				text_poke      :  1, /* include text poke events */
 				build_id       :  1, /* use build id in mmap2 events */
-				__reserved_1   : 29;
+				sigtrap        :  1, /* send synchronous SIGTRAP on event */
+				__reserved_1   : 28;
 
 	union {
 		__u32		wakeup_events;	  /* wakeup every n events */
diff --git a/kernel/events/core.c b/kernel/events/core.c
index 37a8297be164..8718763045fd 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -6288,6 +6288,17 @@ void perf_event_wakeup(struct perf_event *event)
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
@@ -6297,6 +6308,13 @@ static void perf_pending_event_disable(struct perf_event *event)
 
 	if (cpu == smp_processor_id()) {
 		WRITE_ONCE(event->pending_disable, -1);
+
+		if (event->attr.sigtrap) {
+			atomic_inc(&event->event_limit); /* rearm event */
+			perf_sigtrap(event);
+			return;
+		}
+
 		perf_event_disable_local(event);
 		return;
 	}
@@ -11325,6 +11343,9 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
 
 	event->state		= PERF_EVENT_STATE_INACTIVE;
 
+	if (event->attr.sigtrap)
+		atomic_set(&event->event_limit, 1);
+
 	if (task) {
 		event->attach_state = PERF_ATTACH_TASK;
 		/*
-- 
2.30.0.617.g56c4b15f3c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210223143426.2412737-4-elver%40google.com.
