Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV5ZXOBQMGQE64MVPPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id F1C0A3580D2
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 12:37:11 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id c12sf668872lfm.4
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 03:37:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617878231; cv=pass;
        d=google.com; s=arc-20160816;
        b=wPtLDoU0T8GrJbt+FqsB9moEq1jqUZj/bfuUwsOl8/exaLx0fCrR7Rk54ow0yC/zr8
         Eg2AMrLuQN1c0FpX4Cp2sBIEq7spIe10j+/rRLPPG123/s5GbkEePPYxspllEGHmWfPD
         L46lqQy9TRFN5fgLcOCH2s99hHyg/EedMqSYhfboh0R8v8ISxqaz7EBZxg7Y7GbhXKXo
         6yL0aKLm2pTnkggwH6SMcBVoBu1m/eEM6WNr0G061HUu7lncHCe20cyj9JC/wBqyrjJN
         7EQBAk18aWfx4qgjhV3m5yjDW4XAXloBh4pKMHQ/+dF3TMGg9B6ejH5mVkA69LTW77kz
         B1fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=vPz3dTFb0geYbLqfzlEy+0PIKPwi6fUvInVxWegCq2M=;
        b=JOUm2AUL+MntgF0l1EAwDO7xKMxrCzFPik8vlDH7wnk8qaqtJVQvmRzXxLpR0X5izB
         cyqrlx2lMWhZVesFJ6XzT1n1r3s4/HJ53Y1r0wWlSYze7aEMVPEAsInwl4s7VbUlIz7i
         Kev8TjbpKFTXEZ2dzMl5OAo2C47iC2by2BYs3LMMa+pvvWOJxcvONPVrQlBI977yIDoY
         HnlB4kjnXoSS7GI1PMKjvShgX7Y/7NbA63uTsFYpb/97FXsq0XU4upn2N/TN03rE7Giv
         rCbKUOT0q2OQahgGP9uXdJKAojkNLnhQtY44n20KZScOaMfIvz7doBqCV/b2z8lL8cyn
         FsNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Abilg05W;
       spf=pass (google.com: domain of 31dxuyaukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=31dxuYAUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vPz3dTFb0geYbLqfzlEy+0PIKPwi6fUvInVxWegCq2M=;
        b=KQYkhOms7ujKoSET6xWswUWVPBGRtn2fbBdv/MP/6Nz9LXk7yTD7FQ3ji4FC64/K5L
         Fz0H9fqpTZlvwSByhoC9VRE1dQFo7Snl4Pg+3uzsyFJ8IkK2f6jrQCrkW6CTd1EH+Xmm
         IkULA87zw1X5lJHGACkU1LFZGVM+TX+cHiYHrkbxYwPGt7w5Rr5CHKenzkyS2ja+rPg5
         7L6NuD8BinIeGZuAjJ7cQOx2FZ/d/zxQMeGx8czxtfcNbEBM0Q/GJEu2TrCuOjtPpDBz
         bctwvxrpUlWI99R9Zy20oqX7BKldeWdu0yTSg6QPhd57MFNkVFCiXyzK5Cl/vKrrFmVi
         btMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vPz3dTFb0geYbLqfzlEy+0PIKPwi6fUvInVxWegCq2M=;
        b=hzikSdtHZSzEEvyN7IIl8DVm9yR5T9OoIX+OVSVmQNU5bRgfZR3rKX7jSiwcD2ZpDz
         pnbpsTuFIYVtZbBtFmFZ4Tq5opVP0cag/W7xwx8VI6orF89hmhAmXaRMpmIevBdBgckK
         Ufq1e+MQSAyZdZkSNw7vbtSaIpX3f0EyVUQK/vqc46eNLfVb+/mHn4qU0nBJ3rQN7U0h
         XBOCkyTRHqa5XlFYsYk8g+44HsOVsB3yvSNSAs/GgJfSYOKdDkZjB4ow2Jkn1Og+Od7N
         bdxRWgVWf5vS1jG3x+QSP3408uPo4Xhpw8jsJFtsvcreWPwFk3XjZBamRfs06SAgJIdl
         akQQ==
X-Gm-Message-State: AOAM530WIvmhmlXfZGOMYYRs6ogzai193YA24rXFk8y8hewXDYYskTSH
	o89scGUDIYNt0JzPKJfnckM=
X-Google-Smtp-Source: ABdhPJz0mJ5AoOceYMZgEx9C5vvG6h7ohIhflY87cD7tRuVjI6FVUZFHqajiKD2Pn8LomHaIkUU3Uw==
X-Received: by 2002:ac2:43a3:: with SMTP id t3mr5591262lfl.340.1617878231594;
        Thu, 08 Apr 2021 03:37:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d16:: with SMTP id d22ls4507076lfv.1.gmail; Thu,
 08 Apr 2021 03:37:10 -0700 (PDT)
X-Received: by 2002:a05:6512:3ca0:: with SMTP id h32mr5889147lfv.184.1617878230381;
        Thu, 08 Apr 2021 03:37:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617878230; cv=none;
        d=google.com; s=arc-20160816;
        b=QBQEBh6GCBX/D98r85xoLUVDlmq3fJdhSGV5V1URBhaYsQkkTT/4GEHSycoBQg/MW4
         CL/joPfYA+dHCnOxvPwt5JvvdTAPKaEl6grCY9g92UQv+OO4sOGs3xL6FgzIzc/gPQMS
         lJMZDgf93HzcXVZV33IrMmsE4th2YJ4vG/va48kUhR+F21WgwwbuItehy5p+QhZIBFEh
         ojMKibtdncSKktkWvHH7kkL2wFm8AtAJw7KOSIWIjGc+IYuTnxVVGK+Mlm4qOmelW5rM
         ZU5Dq2FcW6CA3miOkSV/JMTgPbHy3IhwE4DxPVG/okZ3EWanw58E4TYhSm8tdBCXRIBv
         JHVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=BCBGbOGg89seqk0GJ8e7eMRxQa1aJCiARfAN/gtOasU=;
        b=EP5gYEcHoyNRxgDd7VhojLbEr80JU7Yttte6rxGCJTUhPlg9R8uuX3t1+JmU9GcS0q
         XPNezKPdLaYV/tKQloxmkikSEMPDKvRBrRk+PiMwWsch0iQ2Plninsmq1Ez18fcAQJBd
         PNKzbQzVj7Ghjj10eLKcV6BYnAHoXz16u5lKNcvEkAio/iMEUZ7iZ03cqhHT4umxAwGG
         iFs0jR3BMr7E4R2aAvlrz4n33jWcCOlQICX4JiNBN6Jrv6c4qnZN2cBKXQTynQ/4tuK5
         hjuDtS9WKw+dn198fZsTV3qfl7i9T+QrhVbg/hdirJQNQhXnK8CZFR9iJnQ0cwCTTkRg
         biCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Abilg05W;
       spf=pass (google.com: domain of 31dxuyaukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=31dxuYAUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id z3si519749lfu.12.2021.04.08.03.37.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Apr 2021 03:37:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31dxuyaukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id d25so198516ejb.14
        for <kasan-dev@googlegroups.com>; Thu, 08 Apr 2021 03:37:10 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:9038:bbd3:4a12:abda])
 (user=elver job=sendgmr) by 2002:a17:906:ce4e:: with SMTP id
 se14mr9777476ejb.54.1617878229875; Thu, 08 Apr 2021 03:37:09 -0700 (PDT)
Date: Thu,  8 Apr 2021 12:36:05 +0200
In-Reply-To: <20210408103605.1676875-1-elver@google.com>
Message-Id: <20210408103605.1676875-11-elver@google.com>
Mime-Version: 1.0
References: <20210408103605.1676875-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.208.g409f899ff0-goog
Subject: [PATCH v4 10/10] perf test: Add basic stress test for sigtrap handling
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
 header.i=@google.com header.s=20161025 header.b=Abilg05W;       spf=pass
 (google.com: domain of 31dxuyaukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=31dxuYAUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
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

Note: A more elaborate kselftest version of this test can also be found
in tools/testing/selftests/perf_events/sigtrap_threads.c.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Update for new perf_event_attr::sig_data / si_perf handling.

v3:
* Added to series (per suggestion from Ian Rogers).
---
 tools/perf/tests/Build          |   1 +
 tools/perf/tests/builtin-test.c |   5 ++
 tools/perf/tests/sigtrap.c      | 150 ++++++++++++++++++++++++++++++++
 tools/perf/tests/tests.h        |   1 +
 4 files changed, 157 insertions(+)
 create mode 100644 tools/perf/tests/sigtrap.c

diff --git a/tools/perf/tests/Build b/tools/perf/tests/Build
index 650aec19d490..a429c7a02b37 100644
--- a/tools/perf/tests/Build
+++ b/tools/perf/tests/Build
@@ -64,6 +64,7 @@ perf-y += parse-metric.o
 perf-y += pe-file-parsing.o
 perf-y += expand-cgroup.o
 perf-y += perf-time-to-tsc.o
+perf-y += sigtrap.o
 
 $(OUTPUT)tests/llvm-src-base.c: tests/bpf-script-example.c tests/Build
 	$(call rule_mkdir)
diff --git a/tools/perf/tests/builtin-test.c b/tools/perf/tests/builtin-test.c
index c4b888f18e9c..28a1cb5eaa77 100644
--- a/tools/perf/tests/builtin-test.c
+++ b/tools/perf/tests/builtin-test.c
@@ -359,6 +359,11 @@ static struct test generic_tests[] = {
 		.func = test__perf_time_to_tsc,
 		.is_supported = test__tsc_is_supported,
 	},
+	{
+		.desc = "Sigtrap support",
+		.func = test__sigtrap,
+		.is_supported = test__wp_is_supported, /* uses wp for test */
+	},
 	{
 		.func = NULL,
 	},
diff --git a/tools/perf/tests/sigtrap.c b/tools/perf/tests/sigtrap.c
new file mode 100644
index 000000000000..c367cc2f64d5
--- /dev/null
+++ b/tools/perf/tests/sigtrap.c
@@ -0,0 +1,150 @@
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
+#define TEST_SIG_DATA (~(uint64_t)(&ctx.iterate_on))
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
+	TEST_ASSERT_EQUAL("unexpected si_errno", ctx.first_siginfo.si_errno, PERF_TYPE_BREAKPOINT);
+#if 0 /* FIXME: test build and enable when libc's signal.h has si_perf. */
+	TEST_ASSERT_VAL("unexpected si_perf", ctx.first_siginfo.si_perf == TEST_SIG_DATA);
+#endif
+
+	return ret;
+}
+
+int test__sigtrap(struct test *test __maybe_unused, int subtest __maybe_unused)
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
diff --git a/tools/perf/tests/tests.h b/tools/perf/tests/tests.h
index b85f005308a3..c3f2e2ecbfd6 100644
--- a/tools/perf/tests/tests.h
+++ b/tools/perf/tests/tests.h
@@ -127,6 +127,7 @@ int test__parse_metric(struct test *test, int subtest);
 int test__pe_file_parsing(struct test *test, int subtest);
 int test__expand_cgroup_events(struct test *test, int subtest);
 int test__perf_time_to_tsc(struct test *test, int subtest);
+int test__sigtrap(struct test *test, int subtest);
 
 bool test__bp_signal_is_supported(void);
 bool test__bp_account_is_supported(void);
-- 
2.31.0.208.g409f899ff0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210408103605.1676875-11-elver%40google.com.
