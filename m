Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAGFUKBAMGQEB4YY3NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3799F333A45
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 11:42:09 +0100 (CET)
Received: by mail-ua1-x93d.google.com with SMTP id k10sf3264287uag.12
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 02:42:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615372928; cv=pass;
        d=google.com; s=arc-20160816;
        b=V5ukZm7rKGA+SnMmYTrIDhh2NUsGPIn5fUwEqz9yFSD85mb1i/mp2xoVZwN/9ddXVq
         qanswW5mMDcCswx3m4tq7lTiWcXWSOjtVjnLW5e5/d1xtK+EttcI2uEYROBOgSgUDslV
         nPEQNnmRac4YzeSOOxPaznytwIZIHqUJroahU5HYCp1CP8GNGPJVeEJ86dbMKi1EgJBO
         ELBwTstDnW4S3mPxHYxArjIf4uQrnuFWAqx4x75FsMIR2Kngf1qN6URxhx1bukzRYpB2
         Gb5Z2AyivE4RlQBnsOlpG6eMLRZhBPbYRs5p8hgSFYawUNFzBRBX2Bh4yPwbcwNKKc9C
         nePQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=WHDB63VPTu8HoG2/yQU6h3iavkR1tfJhkIQVRIAjm4k=;
        b=YmgWguHyilreD0Eu638W3z9ibfT0WfgT68D9Zch6JMa4NOH7opG8OR5Shg2Sxp+Rdg
         JoWEdmgTkz59sY5kTnRY6CvWhpCK0pGZS+tCBDaNbNswHcNPkUr3CaB0HIReylgE6C75
         jN1WjtB6n0xBgMj93btSLoFasRru7poeFV/WEcnDkbsvSkmZjQuUASDaSGM/3Xj4zW4m
         b2oAMA0sG4HF4vyRcrvP4EJMhBaF1qlY09trKTZG97N0Fxw1Nr6Ie83CiMxpxZ9gJI4A
         RZ+fc8tGVGp8z2oJibR05zItc/PC7iM4Xi0ppoBFSsQWdC6UOszOHORoPD+utuNwmFje
         iriQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="XG/AL71q";
       spf=pass (google.com: domain of 3f6jiyaukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3f6JIYAUKCe4UblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WHDB63VPTu8HoG2/yQU6h3iavkR1tfJhkIQVRIAjm4k=;
        b=lwh1dsNhqe8OSXNH1dWCQDKDWm0JWhpAT6DxdqW2M5JZG/8iRsL0PMI5z//wUlolQY
         wDpGAZITABRrH8ad4LrcH6CVgYeov2fndYGzXxY/590rFKSnZZOIUDTa9HU+/xpcW3rG
         u+Y+UTw1lYS4Z54etrajm17wejurbep/CWnyL18T0vuAuW8Fhnghl988WobqyeNlnmbF
         gVQxJV9Y5nJLgCeku/Yrz1WLyUCovsaqYDJR8trU5J6o0ywHIviT63R4eygoW4d3safN
         9gChqtbNo+tyt4LM4/93F+K2mTk/QNZkiPTUSrgxs1DqekrN4QGqa1qZ2tWH+E/7dRPX
         uVyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WHDB63VPTu8HoG2/yQU6h3iavkR1tfJhkIQVRIAjm4k=;
        b=FjrjBqNaRIBNoCmr0a+2BN+c+DWEjo56HxWNVntJqyh0r6yptIPHReXa0SpN1JiQHH
         HsuvAVD8f0t+m4E63oeYsenNg606Z0F1ILb5Zz3GVHgbbKJnZoEvZU34NGHUvumIDo4J
         HR6Ny9JgoEOdL+EfB9PAvIWxgwERL1Io1DrbPYWJ9rsQbX6yWha4tZmGfxXlNRuPrWxr
         2OHJYnS6I1yClLj4b11q/NuR37eam8cRpOpGRXsiN96X0Q2+Z9IktYQKonQR4w4RA1Kk
         Qb8+brAPRXNB/2Euu6V4fYsdvhvV973lF493RB5sxIMdjzINe9f37wGXnQwqxF7krrNG
         l8jA==
X-Gm-Message-State: AOAM531FjprmxDYfDpvDIzC6S8r7QgI0x3YqFXkTjM5J/YoMQsRRujtv
	4ptX5mABJlkA0CrFcwR8Ip4=
X-Google-Smtp-Source: ABdhPJxcCd0QmflN1q+WuLEJJ4jxTGXVobCXU01GKj8RIWQ7eoefGNEW6pqsskRzostA1gMG3qNweg==
X-Received: by 2002:a67:c09b:: with SMTP id x27mr1107786vsi.33.1615372928317;
        Wed, 10 Mar 2021 02:42:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:21c4:: with SMTP id r4ls175728vsg.5.gmail; Wed, 10
 Mar 2021 02:42:07 -0800 (PST)
X-Received: by 2002:a67:ee08:: with SMTP id f8mr1162476vsp.35.1615372927682;
        Wed, 10 Mar 2021 02:42:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615372927; cv=none;
        d=google.com; s=arc-20160816;
        b=vB5CN95CyLbqPctpkZA8ox4srhSRnUkvaAL8DpgnaFzE/BxfV3n6GbmO+xo+Rlh6Ho
         gZQPRJhD6zdDm+txc4d4FNY8lHRD9/KQOS3F+21Km6zQBlYfUsvHK1jMQCdHKs5WazxO
         okxp8tYaz56FMgkiZ3cN5nVm4Hs5AUZBhTB1cdYDQ6Ty9PGpzlMO3lB/SkItvVdlfYKa
         zrMWWfuY7IHpOmdkWW3GG4cEmyMkth0cx0UWvYVplcYbEMyx4bf+KqDaJhxIjnO4JHBt
         WCuQPUFf90AS2WPoBgMAEJY1wnhTgR1xpD956Y48UOLk1Ks7wwi3CX/kuNMtA2q18hJv
         7Sdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=NKxCcYzNapnhBc0c8bTeezMWyMgR4Ia19sYvvDoOw3g=;
        b=Cpn9qtU6QDi+cNdEw2g349kzA0R/OZxtTTQwqOSJWvH075ReLO1ZLwTBNdjpWZ+MRA
         zP8c/gZaWL3vE7TzV2jAhrOwPBb074lrhsDy9sRluk7EWWGWC1nmYL27J3W7Bao2kwnP
         ewxY4PwQZ2hhSSvmhf/SQ2zDfcQWQaQ/Km9BsMEjy/iTYEAtlnVACwbfWJqaZm8OegYA
         YUxRawJ/RLLRVgcp/uP3uAFNMLu9Olxj3zEFzphhOt+ARMBMMdzwFnA9y8JSKdD+bquX
         l5DGjCTthVZWmwVW2WndhnjjCquRDNTZQ2B18dM0bkHXONmLfi1udiVYrd4QmNa89dcF
         sBFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="XG/AL71q";
       spf=pass (google.com: domain of 3f6jiyaukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3f6JIYAUKCe4UblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id i18si1367669ual.1.2021.03.10.02.42.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Mar 2021 02:42:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 3f6jiyaukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id k68so12399295qke.2
        for <kasan-dev@googlegroups.com>; Wed, 10 Mar 2021 02:42:07 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e995:ac0b:b57c:49a4])
 (user=elver job=sendgmr) by 2002:a05:6214:248a:: with SMTP id
 gi10mr2189822qvb.35.1615372927193; Wed, 10 Mar 2021 02:42:07 -0800 (PST)
Date: Wed, 10 Mar 2021 11:41:38 +0100
In-Reply-To: <20210310104139.679618-1-elver@google.com>
Message-Id: <20210310104139.679618-8-elver@google.com>
Mime-Version: 1.0
References: <20210310104139.679618-1-elver@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH RFC v2 7/8] selftests/perf: Add kselftest for process-wide
 sigtrap handling
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
 header.i=@google.com header.s=20161025 header.b="XG/AL71q";       spf=pass
 (google.com: domain of 3f6jiyaukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3f6JIYAUKCe4UblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
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

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Patch added to series.
---
 .../testing/selftests/perf_events/.gitignore  |   2 +
 tools/testing/selftests/perf_events/Makefile  |   6 +
 tools/testing/selftests/perf_events/config    |   1 +
 tools/testing/selftests/perf_events/settings  |   1 +
 .../selftests/perf_events/sigtrap_threads.c   | 202 ++++++++++++++++++
 5 files changed, 212 insertions(+)
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
index 000000000000..7ebb9bb34c2e
--- /dev/null
+++ b/tools/testing/selftests/perf_events/sigtrap_threads.c
@@ -0,0 +1,202 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Test for perf events with SIGTRAP across all threads.
+ *
+ * Copyright (C) 2021, Google LLC.
+ */
+
+#define _GNU_SOURCE
+#include <sys/types.h>
+
+/* We need the latest siginfo from the kernel repo. */
+#include <asm/siginfo.h>
+#define __have_siginfo_t 1
+#define __have_sigval_t 1
+#define __have_sigevent_t 1
+
+#include <linux/hw_breakpoint.h>
+#include <linux/perf_event.h>
+#include <pthread.h>
+#include <signal.h>
+#include <stdatomic.h>
+#include <stdbool.h>
+#include <stddef.h>
+#include <stdint.h>
+#include <stdio.h>
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
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210310104139.679618-8-elver%40google.com.
