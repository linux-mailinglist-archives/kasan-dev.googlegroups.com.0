Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUFZXOBQMGQEVK5SU6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 861EA3580BF
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 12:37:04 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id d25sf198437ejb.14
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 03:37:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617878224; cv=pass;
        d=google.com; s=arc-20160816;
        b=VCsIwVTrkcOnB+HSnUiac07/RNBE5ZdByrjU/Bx9i4rldse13QZAwje2Ze7N3Z0Dfm
         fbo2fKOAzWHEa/XaD1yaVw2GOVN7cTRUnANdGsR6OhvM9En+M2rA8diA71oCgeqMSzhE
         g+lo1szRScxo5sqy1VgvkVjoEau5bjoiGeVF/qjPWeWRioE+Lj45H2vuE4SF0YZkyG+G
         v69Y5M+YREypwsjnSYYZ3dTNLqWnEuABWT4USDdpMa2GxFHbZDf4TM9icqZS8IB24m+A
         624/R1bczfSDtmg/Ux8Z3HlUAXyumPVLV5QBCye7sreKCPb/yaNj+Odcvy7z4aZk9oq+
         ne0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=PQ6es/I0qQ6BbdRmZfZHb2FFvFcygRsh4IF7lj4ElTo=;
        b=KB3w+Ac6qYkY/OPoS9uyfEissRjwLp2wZHdfWRQItYcuH/171WDp4uE8zOv51QQsb0
         OrV4qMSWBJ0UDK4egTvcyxpCTMqufT8OtUJHcU4p3rzAg7MoG1WCvMzRbcLRTwGS56fn
         uDMZia4VoZmNa3sJCkLPQNL7qe4XkXF1w6hesJ1fwdO/BhzozHNgSfVNHKPFO2m2I5nS
         CJX0dKDyaPJNlfR4YTtp0XpFCjIxC8lgCHDzQU9Qkj6NhxXg0QyRDfdmvCnkRREzp71j
         w/3RYycro77f1NItWG1M2utS3oZzXA3klAkYv1lHh5pfbBOyds7xF3Xc4bp/vE71UhtU
         bSrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZQEHMvhT;
       spf=pass (google.com: domain of 3ztxuyaukcu0t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ztxuYAUKCU0t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PQ6es/I0qQ6BbdRmZfZHb2FFvFcygRsh4IF7lj4ElTo=;
        b=elO1zgNfSNnUBvHZEKpOkOCRyFUHgpCTNNSl7WHzShS69asvbMPIJFtPTc63zK8uEK
         fsEGJsLBopEQswsRdKkJuS3L5AsEECyUOWXFPg/Zm7MLjYeIOzFPGdgnyvjO3d++mlSv
         KHHm7zqNTLfU+BCe56wY4t+tigXcG/3WPkdGMmhyCS84r1g05nOJPYNzrWy4Na3xYBxj
         4H2hkfWzIkHGVIWcvHSTNQ/FygMYqVn0jl0gb5LHA/zzG/OzD+dEmotM5/n4OwNJnwcE
         YO5WKZsT32XI9XSTQVTlVKEGLeiud4DelTFhq4JAKhlyo+bOcqqF5iWBkkzGlSp1SmZD
         cdlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PQ6es/I0qQ6BbdRmZfZHb2FFvFcygRsh4IF7lj4ElTo=;
        b=L0M5uksm0NJf4jhMkG37oBnMRG3oYC06rtHuv1kTkWfz5+irKHoK/mjPCF7lLsQ7lE
         l3zs9HUqWi/pa9oOKsukQ+RF2T85E0WVgHgOaNvoTNXQvysIijTs7kKYyzIxt8V22udK
         GmQUPFq1Mu7z2z3Fc6J6KDeAC43blU5o0beXO9Lrno94MfnvyS9dQNdwFw/awbnTjpEj
         Yai71B5pIHjCmx6h0RFDl7qfyg7AxZpEN2jr5w5cNtzt5pU7zEbeYChMHP/KIVkEMonH
         QuJ8TzF9nnhv0BcmWtqeU8PqUgNZGsvGTTldMZS2++GuAmHl3LstA6VFESQ+FajlHPUD
         DdWw==
X-Gm-Message-State: AOAM530L7EWkGOXIfHsfaPtBDNDBAPZmdqm0uksn4DNDyn6Ppj+AWZPo
	o8k1T2aO1b+oqP2JV4lobMk=
X-Google-Smtp-Source: ABdhPJyuCM5G2WeVmtUyr0Mkuv6/a3kZ9W+tr+Wz3Uhjw1/URzXxw5Tmn+ceIxJrm7EzwbWg7HOHjg==
X-Received: by 2002:aa7:d688:: with SMTP id d8mr3720846edr.294.1617878224307;
        Thu, 08 Apr 2021 03:37:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:22c9:: with SMTP id q9ls2924188eja.11.gmail; Thu, 08
 Apr 2021 03:37:03 -0700 (PDT)
X-Received: by 2002:a17:907:6282:: with SMTP id nd2mr9233360ejc.173.1617878223422;
        Thu, 08 Apr 2021 03:37:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617878223; cv=none;
        d=google.com; s=arc-20160816;
        b=uoO/wnkwEGhYNaqenpTOMhY41k8dko8BhsuEeaAeAVsgVle/nDIPWGUsUdYOwv84UI
         jqyJonE3hZP8N9ExOGFtB+fZPidyQVNmupeRn0d++Y3BFTgmQbKGW2Wq9zVO61/Duoqu
         PWw6skF4ng2EGUQXxf0ofHLRe1duI6hxIFlePSyU89yCD0d20PbZ8ORjuhkSdJOqAPAW
         spEz1COVMt8VW1IH1RdFHRurcD02GhFM1LLav1pWl1KjgYW+FC5T1YSWHDPEiM8W+EvN
         j7Pf2UTA0ODhqdMdMZHlMlbIJPRvU1FAA4X9c2pg8AWDnQWwYMltMiVH9IAFTW6rb6nw
         z9Kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ovZor/YA8Mn2bsdM5I3c9xRpJwXvNo3zi3skLZLNZKI=;
        b=D53zba8QcgGNUizHTxRS860sBfOrq6K6ZLWCUNtZnRpUW83p582KeS3DKEHX66qsQp
         N8G73MNCh7kfIwncBuqoLzlObVJDl3xON1wC3DZFXYm1BxkF409/NAuEnrdSlN99ImWP
         eiPEGXDnD8AyUtNlzv32dYjTMn8ASYltJEhMAKBgrQgYeTN98Dol4X8RJvQ7xVBootXb
         7B0fyEkWeDUuGU88TSeLCcF0tKz6XNiIqMZUQk5yprk6TyMMIwKEFS3QpL9dHdZqyGGg
         uAfidv6rKGN9VrzwHGcakI786tN/yHV792kV4Ig6Jq+Z+4iweQ0uErKk6evVhEIv197T
         vktg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZQEHMvhT;
       spf=pass (google.com: domain of 3ztxuyaukcu0t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ztxuYAUKCU0t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id m18si2827459edd.5.2021.04.08.03.37.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Apr 2021 03:37:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ztxuyaukcu0t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id b20-20020a7bc2540000b029010f7732a35fso3168984wmj.1
        for <kasan-dev@googlegroups.com>; Thu, 08 Apr 2021 03:37:03 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:9038:bbd3:4a12:abda])
 (user=elver job=sendgmr) by 2002:a7b:c159:: with SMTP id z25mr476087wmi.1.1617878222309;
 Thu, 08 Apr 2021 03:37:02 -0700 (PDT)
Date: Thu,  8 Apr 2021 12:36:02 +0200
In-Reply-To: <20210408103605.1676875-1-elver@google.com>
Message-Id: <20210408103605.1676875-8-elver@google.com>
Mime-Version: 1.0
References: <20210408103605.1676875-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.208.g409f899ff0-goog
Subject: [PATCH v4 07/10] selftests/perf_events: Add kselftest for
 process-wide sigtrap handling
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
 header.i=@google.com header.s=20161025 header.b=ZQEHMvhT;       spf=pass
 (google.com: domain of 3ztxuyaukcu0t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ztxuYAUKCU0t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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

Add a kselftest for testing process-wide perf events with synchronous
SIGTRAP on events (using breakpoints). In particular, we want to test
that changes to the event propagate to all children, and the SIGTRAPs
are in fact synchronously sent to the thread where the event occurred.

Note: The "signal_stress" test case is also added later in the series to
perf tool's built-in tests. The test here is more elaborate in that
respect, which on one hand avoids bloating the perf tool unnecessarily,
but we also benefit from structured tests with TAP-compliant output that
the kselftest framework provides.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Update for new perf_event_attr::sig_data / si_perf handling.

v3:
* Fix for latest libc signal.h.

v2:
* Patch added to series.
---
 .../testing/selftests/perf_events/.gitignore  |   2 +
 tools/testing/selftests/perf_events/Makefile  |   6 +
 tools/testing/selftests/perf_events/config    |   1 +
 tools/testing/selftests/perf_events/settings  |   1 +
 .../selftests/perf_events/sigtrap_threads.c   | 210 ++++++++++++++++++
 5 files changed, 220 insertions(+)
 create mode 100644 tools/testing/selftests/perf_events/.gitignore
 create mode 100644 tools/testing/selftests/perf_events/Makefile
 create mode 100644 tools/testing/selftests/perf_events/config
 create mode 100644 tools/testing/selftests/perf_events/settings
 create mode 100644 tools/testing/selftests/perf_events/sigtrap_threads.c

diff --git a/tools/testing/selftests/perf_events/.gitignore b/tools/testing/selftests/perf_events/.gitignore
new file mode 100644
index 000000000000..4dc43e1bd79c
--- /dev/null
+++ b/tools/testing/selftests/perf_events/.gitignore
@@ -0,0 +1,2 @@
+# SPDX-License-Identifier: GPL-2.0-only
+sigtrap_threads
diff --git a/tools/testing/selftests/perf_events/Makefile b/tools/testing/selftests/perf_events/Makefile
new file mode 100644
index 000000000000..973a2c39ca83
--- /dev/null
+++ b/tools/testing/selftests/perf_events/Makefile
@@ -0,0 +1,6 @@
+# SPDX-License-Identifier: GPL-2.0
+CFLAGS += -Wl,-no-as-needed -Wall -I../../../../usr/include
+LDFLAGS += -lpthread
+
+TEST_GEN_PROGS := sigtrap_threads
+include ../lib.mk
diff --git a/tools/testing/selftests/perf_events/config b/tools/testing/selftests/perf_events/config
new file mode 100644
index 000000000000..ba58ff2203e4
--- /dev/null
+++ b/tools/testing/selftests/perf_events/config
@@ -0,0 +1 @@
+CONFIG_PERF_EVENTS=y
diff --git a/tools/testing/selftests/perf_events/settings b/tools/testing/selftests/perf_events/settings
new file mode 100644
index 000000000000..6091b45d226b
--- /dev/null
+++ b/tools/testing/selftests/perf_events/settings
@@ -0,0 +1 @@
+timeout=120
diff --git a/tools/testing/selftests/perf_events/sigtrap_threads.c b/tools/testing/selftests/perf_events/sigtrap_threads.c
new file mode 100644
index 000000000000..9c0fd442da60
--- /dev/null
+++ b/tools/testing/selftests/perf_events/sigtrap_threads.c
@@ -0,0 +1,210 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Test for perf events with SIGTRAP across all threads.
+ *
+ * Copyright (C) 2021, Google LLC.
+ */
+
+#define _GNU_SOURCE
+
+/* We need the latest siginfo from the kernel repo. */
+#include <sys/types.h>
+#include <asm/siginfo.h>
+#define __have_siginfo_t 1
+#define __have_sigval_t 1
+#define __have_sigevent_t 1
+#define __siginfo_t_defined
+#define __sigval_t_defined
+#define __sigevent_t_defined
+#define _BITS_SIGINFO_CONSTS_H 1
+#define _BITS_SIGEVENT_CONSTS_H 1
+
+#include <stdbool.h>
+#include <stddef.h>
+#include <stdint.h>
+#include <stdio.h>
+#include <linux/hw_breakpoint.h>
+#include <linux/perf_event.h>
+#include <pthread.h>
+#include <signal.h>
+#include <sys/ioctl.h>
+#include <sys/syscall.h>
+#include <unistd.h>
+
+#include "../kselftest_harness.h"
+
+#define NUM_THREADS 5
+
+/* Data shared between test body, threads, and signal handler. */
+static struct {
+	int tids_want_signal;		/* Which threads still want a signal. */
+	int signal_count;		/* Sanity check number of signals received. */
+	volatile int iterate_on;	/* Variable to set breakpoint on. */
+	siginfo_t first_siginfo;	/* First observed siginfo_t. */
+} ctx;
+
+/* Unique value to check si_perf is correctly set from perf_event_attr::sig_data. */
+#define TEST_SIG_DATA(addr) (~(uint64_t)(addr))
+
+static struct perf_event_attr make_event_attr(bool enabled, volatile void *addr)
+{
+	struct perf_event_attr attr = {
+		.type		= PERF_TYPE_BREAKPOINT,
+		.size		= sizeof(attr),
+		.sample_period	= 1,
+		.disabled	= !enabled,
+		.bp_addr	= (unsigned long)addr,
+		.bp_type	= HW_BREAKPOINT_RW,
+		.bp_len		= HW_BREAKPOINT_LEN_1,
+		.inherit	= 1, /* Children inherit events ... */
+		.inherit_thread = 1, /* ... but only cloned with CLONE_THREAD. */
+		.remove_on_exec = 1, /* Required by sigtrap. */
+		.sigtrap	= 1, /* Request synchronous SIGTRAP on event. */
+		.sig_data	= TEST_SIG_DATA(addr),
+	};
+	return attr;
+}
+
+static void sigtrap_handler(int signum, siginfo_t *info, void *ucontext)
+{
+	if (info->si_code != TRAP_PERF) {
+		fprintf(stderr, "%s: unexpected si_code %d\n", __func__, info->si_code);
+		return;
+	}
+
+	/*
+	 * The data in siginfo_t we're interested in should all be the same
+	 * across threads.
+	 */
+	if (!__atomic_fetch_add(&ctx.signal_count, 1, __ATOMIC_RELAXED))
+		ctx.first_siginfo = *info;
+	__atomic_fetch_sub(&ctx.tids_want_signal, syscall(__NR_gettid), __ATOMIC_RELAXED);
+}
+
+static void *test_thread(void *arg)
+{
+	pthread_barrier_t *barrier = (pthread_barrier_t *)arg;
+	pid_t tid = syscall(__NR_gettid);
+	int iter;
+	int i;
+
+	pthread_barrier_wait(barrier);
+
+	__atomic_fetch_add(&ctx.tids_want_signal, tid, __ATOMIC_RELAXED);
+	iter = ctx.iterate_on; /* read */
+	for (i = 0; i < iter - 1; i++) {
+		__atomic_fetch_add(&ctx.tids_want_signal, tid, __ATOMIC_RELAXED);
+		ctx.iterate_on = iter; /* idempotent write */
+	}
+
+	return NULL;
+}
+
+FIXTURE(sigtrap_threads)
+{
+	struct sigaction oldact;
+	pthread_t threads[NUM_THREADS];
+	pthread_barrier_t barrier;
+	int fd;
+};
+
+FIXTURE_SETUP(sigtrap_threads)
+{
+	struct perf_event_attr attr = make_event_attr(false, &ctx.iterate_on);
+	struct sigaction action = {};
+	int i;
+
+	memset(&ctx, 0, sizeof(ctx));
+
+	/* Initialize sigtrap handler. */
+	action.sa_flags = SA_SIGINFO | SA_NODEFER;
+	action.sa_sigaction = sigtrap_handler;
+	sigemptyset(&action.sa_mask);
+	ASSERT_EQ(sigaction(SIGTRAP, &action, &self->oldact), 0);
+
+	/* Initialize perf event. */
+	self->fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
+	ASSERT_NE(self->fd, -1);
+
+	/* Spawn threads inheriting perf event. */
+	pthread_barrier_init(&self->barrier, NULL, NUM_THREADS + 1);
+	for (i = 0; i < NUM_THREADS; i++)
+		ASSERT_EQ(pthread_create(&self->threads[i], NULL, test_thread, &self->barrier), 0);
+}
+
+FIXTURE_TEARDOWN(sigtrap_threads)
+{
+	pthread_barrier_destroy(&self->barrier);
+	close(self->fd);
+	sigaction(SIGTRAP, &self->oldact, NULL);
+}
+
+static void run_test_threads(struct __test_metadata *_metadata,
+			     FIXTURE_DATA(sigtrap_threads) *self)
+{
+	int i;
+
+	pthread_barrier_wait(&self->barrier);
+	for (i = 0; i < NUM_THREADS; i++)
+		ASSERT_EQ(pthread_join(self->threads[i], NULL), 0);
+}
+
+TEST_F(sigtrap_threads, remain_disabled)
+{
+	run_test_threads(_metadata, self);
+	EXPECT_EQ(ctx.signal_count, 0);
+	EXPECT_NE(ctx.tids_want_signal, 0);
+}
+
+TEST_F(sigtrap_threads, enable_event)
+{
+	EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_ENABLE, 0), 0);
+	run_test_threads(_metadata, self);
+
+	EXPECT_EQ(ctx.signal_count, NUM_THREADS);
+	EXPECT_EQ(ctx.tids_want_signal, 0);
+	EXPECT_EQ(ctx.first_siginfo.si_addr, &ctx.iterate_on);
+	EXPECT_EQ(ctx.first_siginfo.si_errno, PERF_TYPE_BREAKPOINT);
+	EXPECT_EQ(ctx.first_siginfo.si_perf, TEST_SIG_DATA(&ctx.iterate_on));
+
+	/* Check enabled for parent. */
+	ctx.iterate_on = 0;
+	EXPECT_EQ(ctx.signal_count, NUM_THREADS + 1);
+}
+
+/* Test that modification propagates to all inherited events. */
+TEST_F(sigtrap_threads, modify_and_enable_event)
+{
+	struct perf_event_attr new_attr = make_event_attr(true, &ctx.iterate_on);
+
+	EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_MODIFY_ATTRIBUTES, &new_attr), 0);
+	run_test_threads(_metadata, self);
+
+	EXPECT_EQ(ctx.signal_count, NUM_THREADS);
+	EXPECT_EQ(ctx.tids_want_signal, 0);
+	EXPECT_EQ(ctx.first_siginfo.si_addr, &ctx.iterate_on);
+	EXPECT_EQ(ctx.first_siginfo.si_errno, PERF_TYPE_BREAKPOINT);
+	EXPECT_EQ(ctx.first_siginfo.si_perf, TEST_SIG_DATA(&ctx.iterate_on));
+
+	/* Check enabled for parent. */
+	ctx.iterate_on = 0;
+	EXPECT_EQ(ctx.signal_count, NUM_THREADS + 1);
+}
+
+/* Stress test event + signal handling. */
+TEST_F(sigtrap_threads, signal_stress)
+{
+	ctx.iterate_on = 3000;
+
+	EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_ENABLE, 0), 0);
+	run_test_threads(_metadata, self);
+	EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_DISABLE, 0), 0);
+
+	EXPECT_EQ(ctx.signal_count, NUM_THREADS * ctx.iterate_on);
+	EXPECT_EQ(ctx.tids_want_signal, 0);
+	EXPECT_EQ(ctx.first_siginfo.si_addr, &ctx.iterate_on);
+	EXPECT_EQ(ctx.first_siginfo.si_errno, PERF_TYPE_BREAKPOINT);
+	EXPECT_EQ(ctx.first_siginfo.si_perf, TEST_SIG_DATA(&ctx.iterate_on));
+}
+
+TEST_HARNESS_MAIN
-- 
2.31.0.208.g409f899ff0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210408103605.1676875-8-elver%40google.com.
