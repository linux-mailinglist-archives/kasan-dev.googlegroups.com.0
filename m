Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7EIZGGAMGQETFKSJCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 65A7F45036B
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 12:29:01 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id d20-20020a05651c111400b00218c6372b7esf5015714ljo.16
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 03:29:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636975741; cv=pass;
        d=google.com; s=arc-20160816;
        b=qGeF3AbAlx329xdHzQWcKMcZSIGhdceSpRqUr/0BALeRpMOktSnTHM6wm9+TmycNYR
         E1kKaPWP1YFaiXMG5uBD7XbMEIuWMHwZQE5Updz5mQQRFBhqcrU13O+6Do5+2TmaTBUH
         9/w9jzZwl6Awgrp3RqHaH4Pt6fQ/ezraytrU4kw5lkHZ9Gxmi1onLMqzefhUBRxT/Cxl
         rtu99px9TW3WbnnAxO2feXJ1PhsbCz2cNmT2VzyO6MTdip6zbSjjaxMp3rvMoOeQbzxT
         YyTk+hBBVWC4HZgQVeN+1SqYErF4xYyoYTsVHE2LIO1/9Bs8P4zJFlxNzL7jZuRf7HBp
         d0xA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=uTBbTXYFGNCpYUwVobhOIlz/Mhz77ivOPjCkAtB5xU4=;
        b=CrxxCHKfNPrd0SBpkJmmOrcWIe7nPXGf4qoRqdzHt/JZziFdgNNk/canhmeV50HMLH
         OFJqJ2k0UQS6jbTyz7FolrwyWtUJt/+cO2nKe6/qM7xtWtvdMezE6jbwgmjt8xaR9ovp
         fH/bCKpaIu740SpUdKuui8CAosiuxlCwbvheZYCrlsBoYMpexk8WCxs31eWULfrdO7sy
         m3y7ID/GRqueNm26HzHmQlPCX/IMXZvCpRBoK+tbn4m0D1ePbdZV9V/spegn6IXHWdzX
         xvMNKOFqT0eAPvXGhu0JXnUmfsvjtUi3/MWG4cGWMeqFdtOwKUmDRS1pos+qGaZYsJx5
         KELw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lCCgT0Pg;
       spf=pass (google.com: domain of 3e0ssyqukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3e0SSYQUKCWACJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=uTBbTXYFGNCpYUwVobhOIlz/Mhz77ivOPjCkAtB5xU4=;
        b=AyRroVUk/YLpqGrBsuoYKhS3y0vQEW5ZDYD9liWLVGtq6zbIk2gB9+LYsGPFysetpm
         pO8QBC6FK9hwxjChJW8bPIMMllCo/mp6Bu8MZGh/jEe59lejLelBuExM/4GYO05Km782
         RWmedOTA018kRI04403aB3DPW4Jpx/ObXQbUhxOpOn4ZWICNaKKggM4vzoKGC4+gEt8m
         oBh1ogYkfNt299iWbKamsAmElomW+TN3ci2xGo/XbNxXcH6x8l649aOJ/dqll8FD8rNz
         n83uu4cynLJGjhLAlx7xZ5So5uT5QE1Mv0NI1vOHh3rbxPRSkreYKuipJ1yTLfH6nCoN
         QGeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uTBbTXYFGNCpYUwVobhOIlz/Mhz77ivOPjCkAtB5xU4=;
        b=yn1f08lfwi5UwvWu+z04Bu7UcRK8azp1obhcVAqqWtvAleZpc0ppk4idln8uAsecDE
         RUu7mNgR2Qqpa4Ol3/VUqFNQMW1xGKjNHcj9Ija/5PdQeN1Eq6k54JG2q3P2iFelWMwo
         /6uQTr68ggNafY+g1KOi0YbBK5of97c/PzFxgoqjCFJJRR6XZAauzCxZqdnAmE5gi3Q7
         1f9Luv0FryC+c9oiKX+OWFKZ8oKZjbAj8/zmh2WKLSzYipMCpIp5/R45FwVm+7PmXSmF
         pG59QewrtJ9065YGFWkPeif1eXk/1hxgls41G/uRq4trE4xT9V9GPm4qlimEncqC4vLI
         a0VQ==
X-Gm-Message-State: AOAM530iOWDfNIHDOuYGT1yNFGNT6VgdWS638SK0BKVzIoCaknUvI80P
	2UKlbnYrt5LQSh9byj6HOw0=
X-Google-Smtp-Source: ABdhPJxmdklkfR9hOxx4ju61ZbGdSdZU/nHHQvdpTzUWMX785Zen1bqIogOmCskIW39VjToePPmt1g==
X-Received: by 2002:a05:6512:3d07:: with SMTP id d7mr34967060lfv.233.1636975740918;
        Mon, 15 Nov 2021 03:29:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2610:: with SMTP id bt16ls222583lfb.2.gmail; Mon,
 15 Nov 2021 03:28:59 -0800 (PST)
X-Received: by 2002:a05:6512:234c:: with SMTP id p12mr33509547lfu.157.1636975739707;
        Mon, 15 Nov 2021 03:28:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636975739; cv=none;
        d=google.com; s=arc-20160816;
        b=nvYHhU3qXB02/4uTJHExzG27yEoNa0i3kYNiC9nJFQjw2tcY9ncrQunJoGJX5eRvj7
         10mD3H7S/jNbLoX3tNfZ4VnNdIKm/uTrHEOk2I4QJbSCgQ+FJsGCig967YCTj/a7zELc
         KRmCPgnBw72Dmijygpuwj9Zt5xduvt4Jk7+qQdJfq62YCbJ41SncRGZjPLD/ntkdalWR
         rWbaVPWPvPQssJKrJ0mCUuXPE6xSWJNhtuFfJ76fwsk6bBHm6ByobzggBvHJuACeUvav
         hGIGqfxJTLcv9tt36ARZ051R6+8dWRPuAQ0OyARrAji69jGQqTO196bYsiQNY6Yl7IqQ
         BolQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=xf9u2CscKkkxKfWTXnB3UoCYnr7mB7Mfxpso9hhGJvU=;
        b=EOG3Vi+VY0o6FJt48NnO/snx28gPzMrQkiLK6umU4tyLmXqOhG1/DzLnv87Tu53RgS
         xJrBZE3Utxvpiqv5Cd1meJJd0d0qx2PhMldOPUZaq8RaAHXrqNlxSczf4gqHTj9iI2gO
         ldn9XqXNIZkXG4f/om1pNyGhtVy746j5dvdFmr6doV66mRHJGyAXEaCGgCvMyYwVVJ1r
         Eotta/igGmX90pNNq+ZqoMPtjigNzyvrJxBpUh6FneFwgfJDvnPdUBmC9zuPhHPSPiIA
         fsky+8452fD0+H8u+egXD4Gejiu6Lh7D29VDtgA5PBedK9CGwl8RT80je7jCofAAQPym
         Y2fA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lCCgT0Pg;
       spf=pass (google.com: domain of 3e0ssyqukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3e0SSYQUKCWACJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id z1si1073432lfu.5.2021.11.15.03.28.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Nov 2021 03:28:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 3e0ssyqukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id m18-20020a05600c3b1200b0033283ea5facso3340673wms.1
        for <kasan-dev@googlegroups.com>; Mon, 15 Nov 2021 03:28:59 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6385:6bd0:4ede:d8c6])
 (user=elver job=sendgmr) by 2002:a05:600c:104b:: with SMTP id
 11mr60511649wmx.54.1636975739083; Mon, 15 Nov 2021 03:28:59 -0800 (PST)
Date: Mon, 15 Nov 2021 12:28:23 +0100
Message-Id: <20211115112822.4077224-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.34.0.rc1.387.gb447b232ab-goog
Subject: [PATCH] perf test: Add basic stress test for sigtrap handling
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Arnaldo Carvalho de Melo <acme@kernel.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Adrian Hunter <adrian.hunter@intel.com>, 
	Fabian Hemmer <copy@copy.sh>, Ian Rogers <irogers@google.com>, linux-kernel@vger.kernel.org, 
	linux-perf-users@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lCCgT0Pg;       spf=pass
 (google.com: domain of 3e0ssyqukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3e0SSYQUKCWACJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
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

Add basic stress test for sigtrap handling as a perf tool built-in test.
This allows sanity checking the basic sigtrap functionality from within
the perf tool.

Signed-off-by: Marco Elver <elver@google.com>
---
 tools/perf/tests/Build          |   1 +
 tools/perf/tests/builtin-test.c |   1 +
 tools/perf/tests/sigtrap.c      | 154 ++++++++++++++++++++++++++++++++
 tools/perf/tests/tests.h        |   1 +
 4 files changed, 157 insertions(+)
 create mode 100644 tools/perf/tests/sigtrap.c

diff --git a/tools/perf/tests/Build b/tools/perf/tests/Build
index 803ca426f8e6..af2b37ef7c70 100644
--- a/tools/perf/tests/Build
+++ b/tools/perf/tests/Build
@@ -65,6 +65,7 @@ perf-y += pe-file-parsing.o
 perf-y += expand-cgroup.o
 perf-y += perf-time-to-tsc.o
 perf-y += dlfilter-test.o
+perf-y += sigtrap.o
 
 $(OUTPUT)tests/llvm-src-base.c: tests/bpf-script-example.c tests/Build
 	$(call rule_mkdir)
diff --git a/tools/perf/tests/builtin-test.c b/tools/perf/tests/builtin-test.c
index 8cb5a1c3489e..f1e6d2a3a578 100644
--- a/tools/perf/tests/builtin-test.c
+++ b/tools/perf/tests/builtin-test.c
@@ -107,6 +107,7 @@ static struct test_suite *generic_tests[] = {
 	&suite__expand_cgroup_events,
 	&suite__perf_time_to_tsc,
 	&suite__dlfilter,
+	&suite__sigtrap,
 	NULL,
 };
 
diff --git a/tools/perf/tests/sigtrap.c b/tools/perf/tests/sigtrap.c
new file mode 100644
index 000000000000..febfa1609356
--- /dev/null
+++ b/tools/perf/tests/sigtrap.c
@@ -0,0 +1,154 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Basic test for sigtrap support.
+ *
+ * Copyright (C) 2021, Google LLC.
+ */
+
+#include <stdint.h>
+#include <stdlib.h>
+#include <linux/hw_breakpoint.h>
+#include <pthread.h>
+#include <signal.h>
+#include <sys/ioctl.h>
+#include <sys/syscall.h>
+#include <unistd.h>
+
+#include "cloexec.h"
+#include "debug.h"
+#include "event.h"
+#include "tests.h"
+#include "../perf-sys.h"
+
+#define NUM_THREADS 5
+
+static struct {
+	int tids_want_signal;		/* Which threads still want a signal. */
+	int signal_count;		/* Sanity check number of signals received. */
+	volatile int iterate_on;	/* Variable to set breakpoint on. */
+	siginfo_t first_siginfo;	/* First observed siginfo_t. */
+} ctx;
+
+#define TEST_SIG_DATA (~(unsigned long)(&ctx.iterate_on))
+
+static struct perf_event_attr make_event_attr(void)
+{
+	struct perf_event_attr attr = {
+		.type		= PERF_TYPE_BREAKPOINT,
+		.size		= sizeof(attr),
+		.sample_period	= 1,
+		.disabled	= 1,
+		.bp_addr	= (unsigned long)&ctx.iterate_on,
+		.bp_type	= HW_BREAKPOINT_RW,
+		.bp_len		= HW_BREAKPOINT_LEN_1,
+		.inherit	= 1, /* Children inherit events ... */
+		.inherit_thread = 1, /* ... but only cloned with CLONE_THREAD. */
+		.remove_on_exec = 1, /* Required by sigtrap. */
+		.sigtrap	= 1, /* Request synchronous SIGTRAP on event. */
+		.sig_data	= TEST_SIG_DATA,
+	};
+	return attr;
+}
+
+static void
+sigtrap_handler(int signum __maybe_unused, siginfo_t *info, void *ucontext __maybe_unused)
+{
+	if (!__atomic_fetch_add(&ctx.signal_count, 1, __ATOMIC_RELAXED))
+		ctx.first_siginfo = *info;
+	__atomic_fetch_sub(&ctx.tids_want_signal, syscall(SYS_gettid), __ATOMIC_RELAXED);
+}
+
+static void *test_thread(void *arg)
+{
+	pthread_barrier_t *barrier = (pthread_barrier_t *)arg;
+	pid_t tid = syscall(SYS_gettid);
+	int i;
+
+	pthread_barrier_wait(barrier);
+
+	__atomic_fetch_add(&ctx.tids_want_signal, tid, __ATOMIC_RELAXED);
+	for (i = 0; i < ctx.iterate_on - 1; i++)
+		__atomic_fetch_add(&ctx.tids_want_signal, tid, __ATOMIC_RELAXED);
+
+	return NULL;
+}
+
+static int run_test_threads(pthread_t *threads, pthread_barrier_t *barrier)
+{
+	int i;
+
+	pthread_barrier_wait(barrier);
+	for (i = 0; i < NUM_THREADS; i++)
+		TEST_ASSERT_EQUAL("pthread_join() failed", pthread_join(threads[i], NULL), 0);
+
+	return TEST_OK;
+}
+
+static int run_stress_test(int fd, pthread_t *threads, pthread_barrier_t *barrier)
+{
+	int ret;
+
+	ctx.iterate_on = 3000;
+
+	TEST_ASSERT_EQUAL("misfired signal?", ctx.signal_count, 0);
+	TEST_ASSERT_EQUAL("enable failed", ioctl(fd, PERF_EVENT_IOC_ENABLE, 0), 0);
+	ret = run_test_threads(threads, barrier);
+	TEST_ASSERT_EQUAL("disable failed", ioctl(fd, PERF_EVENT_IOC_DISABLE, 0), 0);
+
+	TEST_ASSERT_EQUAL("unexpected sigtraps", ctx.signal_count, NUM_THREADS * ctx.iterate_on);
+	TEST_ASSERT_EQUAL("missing signals or incorrectly delivered", ctx.tids_want_signal, 0);
+	TEST_ASSERT_VAL("unexpected si_addr", ctx.first_siginfo.si_addr == &ctx.iterate_on);
+#if 0 /* FIXME: enable when libc's signal.h has si_perf_{type,data} */
+	TEST_ASSERT_EQUAL("unexpected si_perf_type", ctx.first_siginfo.si_perf_type,
+			  PERF_TYPE_BREAKPOINT);
+	TEST_ASSERT_EQUAL("unexpected si_perf_data", ctx.first_siginfo.si_perf_data,
+			  TEST_SIG_DATA);
+#endif
+
+	return ret;
+}
+
+static int test__sigtrap(struct test_suite *test __maybe_unused, int subtest __maybe_unused)
+{
+	struct perf_event_attr attr = make_event_attr();
+	struct sigaction action = {};
+	struct sigaction oldact;
+	pthread_t threads[NUM_THREADS];
+	pthread_barrier_t barrier;
+	int i, fd, ret = TEST_FAIL;
+
+	pthread_barrier_init(&barrier, NULL, NUM_THREADS + 1);
+
+	action.sa_flags = SA_SIGINFO | SA_NODEFER;
+	action.sa_sigaction = sigtrap_handler;
+	sigemptyset(&action.sa_mask);
+	if (sigaction(SIGTRAP, &action, &oldact)) {
+		pr_debug("FAILED sigaction()\n");
+		goto out;
+	}
+
+	fd = sys_perf_event_open(&attr, 0, -1, -1, perf_event_open_cloexec_flag());
+	if (fd < 0) {
+		pr_debug("FAILED sys_perf_event_open()\n");
+		goto out_restore_sigaction;
+	}
+
+	for (i = 0; i < NUM_THREADS; i++) {
+		if (pthread_create(&threads[i], NULL, test_thread, &barrier)) {
+			pr_debug("FAILED pthread_create()");
+			goto out_close_perf_event;
+		}
+	}
+
+	ret = run_stress_test(fd, threads, &barrier);
+
+out_close_perf_event:
+	close(fd);
+out_restore_sigaction:
+	sigaction(SIGTRAP, &oldact, NULL);
+out:
+	pthread_barrier_destroy(&barrier);
+	return ret;
+}
+
+DEFINE_SUITE("Sigtrap", sigtrap);
diff --git a/tools/perf/tests/tests.h b/tools/perf/tests/tests.h
index 8f65098110fc..5bbb8f6a48fc 100644
--- a/tools/perf/tests/tests.h
+++ b/tools/perf/tests/tests.h
@@ -146,6 +146,7 @@ DECLARE_SUITE(pe_file_parsing);
 DECLARE_SUITE(expand_cgroup_events);
 DECLARE_SUITE(perf_time_to_tsc);
 DECLARE_SUITE(dlfilter);
+DECLARE_SUITE(sigtrap);
 
 /*
  * PowerPC and S390 do not support creation of instruction breakpoints using the
-- 
2.34.0.rc1.387.gb447b232ab-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211115112822.4077224-1-elver%40google.com.
