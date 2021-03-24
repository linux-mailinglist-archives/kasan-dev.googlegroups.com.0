Return-Path: <kasan-dev+bncBC7OBJGL2MHBBM6D5SBAMGQEXCB45CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EAC5347716
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 12:25:40 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id 13sf1114355otu.22
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 04:25:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616585139; cv=pass;
        d=google.com; s=arc-20160816;
        b=F7XTQWB0UZGVPTqMELsJ9qxpRDSZpchmhYk7U+qbZkB7/W8HqfbCWPvWuA8b8xSwR/
         O5NKCzp9kVkkvOamj0lxa6sWMgq4cOjpRiblPcDBtFb257CmcjjDItpEBHYoSp6ZaUfD
         rvbeik7SJhlmddTvUeNNDzC27F9Q34xMcrpfG6Dv3gKas9iMjA87M6TZiwkKYtv0InBP
         +qj5OIupRS4cJQlBLWyR27yCD/WgkePoHgQ091A0GAbfpF3kRIU1POR5M6yBojZ3bvLP
         a4U2eyJesskgIwZk3JpD+8upfYWGcAdzsgbRiDIY66ehjb8RYtgydEPs/Awa5lrKajQs
         I5hQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=kZh0nVRHq49G6UHd15YAm+XZ/WlGNa93v1PJeLx0HFM=;
        b=BmvHzEtnuy2XDCl+ckAI89LKQuIxF17ekeaTesOItEBjVkZe4+ldHmOVOSIaZ8cxQI
         PXuREhJNT+ycPQT7UW7kh03Np7opKfxXU6mFBJcUbFO1A2aqvKtFb3bHDo8uLJkuY7h2
         8ZHka2P3AaqO5TE07ImKCW6nq0xPiStbrJ9EvItnlDPBFy1LB9//jCedjb6NUL3+It3J
         jp3CDSXRvtnlOi3R41DLWcB4VOEkCAs+BN3yNVDTt+GoBf2R/OIkc0QhnCE9YVHGmotB
         o9xBY3hwoFn14rJ4f+VxAsBqLbh+71kgK6MXWtILsz/O8+q8b12zaKzADpYWGPsntfoy
         Z2Ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Py8NGJoF;
       spf=pass (google.com: domain of 3sifbyaukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3siFbYAUKCWsNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kZh0nVRHq49G6UHd15YAm+XZ/WlGNa93v1PJeLx0HFM=;
        b=OAH6IoE6jxwZx264M35n6vucgDHcgWHoU1jjjRUmZ6a9YGmh6JcKY4PPhldEMh6A9J
         rBuaRXUI41NFD3QlCktJpGI2QfCcAWkBpu2gnpDHEKCvKewSFDskSKmqq1PD+8ICvuE2
         mvNC80q7NHiPJwbD8Cmooz+YqZRpmLj6IBtN6bxFu5gl5z0fTVRwm7OTjc6CucGy6QvM
         9Ohrfycc6m36nDQdAI1kbTUe3s8tk2P+vW+qnrVgGraeHxVXDCIcdhhEfxO2rm5vvZ5n
         jR6wA1TL+zsMcz3i1+9pafXOG1k1CfgorloEzqCik+BHux3yy0ceUKmoNdEIHwY+Salt
         1gkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kZh0nVRHq49G6UHd15YAm+XZ/WlGNa93v1PJeLx0HFM=;
        b=rl+vDBXpjJva+2NL0IA0o9fTX7CGGR9rqhuAvSUeQDIwQYbRzTDuI2OjjKQlnN0UHm
         VHPiKfjCTPHcEsb94lqOGz/eW3jLjuFAHiZ+XSgi4XQEh4X6RwycyH8wWeGYU56dB71p
         9aaPONAsSVdEXaug6AAg5jZ2nGINZYxex+WSzajqhNpipP6LtU3oeRBgTocGeWKbBMv3
         zLxmoF8NMov5dAHI4NUe01b3vBq0SOSsF3PTkvSA7nmHbhDQ/c93+IxGI8I9iNwDXbA3
         KnFSxwVLZNDlFJ8VoH8deyZ28HiBJ1WsquZxY5U3RfbQw9xGd0ZLhlthCldg6xNepd8x
         8CKQ==
X-Gm-Message-State: AOAM533ugYQLFLZEMmsHmcKQw0KaEjWQKvN5IgWKJoQmZKpAXd+4TRFC
	1cK3ooocXjrdsnzuFxum/ow=
X-Google-Smtp-Source: ABdhPJydmlVcwL2uKLkeFYUHTCeUyRJEHde2bLBmT/QUM4+jKpnCb9pGNb0koQOAL5vFgujvOltKkA==
X-Received: by 2002:a4a:d1da:: with SMTP id a26mr2457190oos.58.1616585139239;
        Wed, 24 Mar 2021 04:25:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ead1:: with SMTP id s17ls121414ooh.9.gmail; Wed, 24 Mar
 2021 04:25:38 -0700 (PDT)
X-Received: by 2002:a4a:d24c:: with SMTP id e12mr2439200oos.73.1616585138838;
        Wed, 24 Mar 2021 04:25:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616585138; cv=none;
        d=google.com; s=arc-20160816;
        b=bZJI09iwegoGqqwySB8HUb65/1nnHBdna6Iy6V+yOCot36WcGW5srsvclmkvNQMauD
         qAD7Ir8U7kjvxRN3Cw248vtbEGpY4kmJb0ZkCycuyjT/Np7Rc/HtDwmib0lGaqkL2CmD
         jFur9aCXbNonepDGaCIJ4z6G7kTqdPRRjlz1Z6hjhoxeRknLeaQSFbwgaBJLrU1Vzn0p
         5IYNSnY5uvedSy5beqqU1qza2z+bCkaQszU/9btPDWizcJaZ+nfBcVBT4OGL59ir56xE
         VzN2XYpmfJoS3CSKyCzHxuZmW5PSwPfNDvU+DSY4mD8tYfjmmrkl6+X1f/kx4vmHD6eD
         hz4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=HS48mvwd8rP5r5QtY6Nl7hL+mujJTvxqfvePWFa/JD8=;
        b=HoJsLObY5NV4YkaHfJBxlgOenebquSqxqPuC6gat8mynLVVAS7tX52LcPUVgdy3IyH
         SllZYZtp16ap2AeH1cw20DwBuwQl2gHOoRnsdnd+Fh4HMWJ1FXiRYFCk/jZRVA9RZrzZ
         3dN755R/yLyCySfTqErAXi/J57yupCZxALGYtPCROd5QNN+r/HjsKSe2+9AVnaum4YPw
         QSAW9qnDz25+VKNZKzcmUPCUdUiUTBfWgrMhuHdqr7Uj316RjT1zDRVZ9A11hDGq2kQO
         YDt4ht5UUEoPoJZX59bFrrl0BmwmK+43BWyojM2iT7VPVKABWEnNAgTKk5JryxN/Nzxt
         67ZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Py8NGJoF;
       spf=pass (google.com: domain of 3sifbyaukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3siFbYAUKCWsNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id y26si116410ooy.1.2021.03.24.04.25.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Mar 2021 04:25:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3sifbyaukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id j14so1333701qka.7
        for <kasan-dev@googlegroups.com>; Wed, 24 Mar 2021 04:25:38 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6489:b3f0:4af:af0])
 (user=elver job=sendgmr) by 2002:a0c:bf12:: with SMTP id m18mr2542326qvi.40.1616585138327;
 Wed, 24 Mar 2021 04:25:38 -0700 (PDT)
Date: Wed, 24 Mar 2021 12:25:00 +0100
In-Reply-To: <20210324112503.623833-1-elver@google.com>
Message-Id: <20210324112503.623833-9-elver@google.com>
Mime-Version: 1.0
References: <20210324112503.623833-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.291.g576ba9dcdaf-goog
Subject: [PATCH v3 08/11] selftests/perf_events: Add kselftest for
 process-wide sigtrap handling
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
 header.i=@google.com header.s=20161025 header.b=Py8NGJoF;       spf=pass
 (google.com: domain of 3sifbyaukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3siFbYAUKCWsNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
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
v3:
* Fix for latest libc signal.h.

v2:
* Patch added to series.
---
 .../testing/selftests/perf_events/.gitignore  |   2 +
 tools/testing/selftests/perf_events/Makefile  |   6 +
 tools/testing/selftests/perf_events/config    |   1 +
 tools/testing/selftests/perf_events/settings  |   1 +
 .../selftests/perf_events/sigtrap_threads.c   | 206 ++++++++++++++++++
 5 files changed, 216 insertions(+)
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
index 000000000000..398717e2991a
--- /dev/null
+++ b/tools/testing/selftests/perf_events/sigtrap_threads.c
@@ -0,0 +1,206 @@
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
+static struct perf_event_attr make_event_attr(bool enabled, volatile void *addr)
+{
+	struct perf_event_attr attr = {
+		.type		= PERF_TYPE_BREAKPOINT,
+		.size		= sizeof(attr),
+		.sample_period	= 1,
+		.disabled	= !enabled,
+		.bp_addr	= (long)addr,
+		.bp_type	= HW_BREAKPOINT_RW,
+		.bp_len		= HW_BREAKPOINT_LEN_1,
+		.inherit	= 1, /* Children inherit events ... */
+		.inherit_thread = 1, /* ... but only cloned with CLONE_THREAD. */
+		.remove_on_exec = 1, /* Required by sigtrap. */
+		.sigtrap	= 1, /* Request synchronous SIGTRAP on event. */
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
+	EXPECT_EQ(ctx.first_siginfo.si_perf, (HW_BREAKPOINT_LEN_1 << 16) | HW_BREAKPOINT_RW);
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
+	EXPECT_EQ(ctx.first_siginfo.si_perf, (HW_BREAKPOINT_LEN_1 << 16) | HW_BREAKPOINT_RW);
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
+	EXPECT_EQ(ctx.first_siginfo.si_perf, (HW_BREAKPOINT_LEN_1 << 16) | HW_BREAKPOINT_RW);
+}
+
+TEST_HARNESS_MAIN
-- 
2.31.0.291.g576ba9dcdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324112503.623833-9-elver%40google.com.
