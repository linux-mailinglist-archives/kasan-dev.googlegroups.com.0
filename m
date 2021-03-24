Return-Path: <kasan-dev+bncBC7OBJGL2MHBBO6D5SBAMGQEZN4WSAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AC3A347719
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 12:25:47 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id b6sf922962wrq.22
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 04:25:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616585147; cv=pass;
        d=google.com; s=arc-20160816;
        b=qlppds+v0QfxsCPx52N6UqbjD+z5n70dPMO0LCltPkD+oney2XFeHyX5JUwurKZdgh
         GcP4G7S99VBa0MqbHuWcNN8Q5e6R2DzasfHB+7lYyXpcufyBcqMYbrIlhI8TX8HUge7z
         cYYgW87Xonf2NlRoZPf7YvUs3AKNpIR/vl83FhYIgTzr/Lhv6hk8IXqNiSsZx9bSKwf7
         u9twjOl1jyUdjsNwsyc7W+/Ljb8Zi1kaAicKpraDlr8dmsSba4x4wb4hTB0vXNH9Qix3
         BfK5UtfmOySBbFshrsElqmmy6uZqXd/gfFrmiMS9Gi5/CsSJQkx7K0AKpxtAjNeg2Q3w
         /eLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=oVDn9tANp3Bg0RBv5f/K/lFbAzq1RSXsi3wTKJu40XI=;
        b=h/OdrjwO9yj0q4VNgmoNNWROPBLyOjFEl3jJHm1m2fmaZRCLtSBaGOAQTnjutcFGC3
         0408gUFvSE08ibZAmUEtdEQwgtt2fjhc62dYi282mAej6G6xn9g3mANYKnPJGM0rZQ6Y
         JzM+T1Z/pLp1sAfTI9oavY1xKRfyPMoYcWHipoKwV1Zo4aAkB4BrA3/lQQJk/FRc+pNo
         8Qigon/CaG5msqsWdnbBnoGPCwevFzH6fEupgoR7b/m+V0i0vYEg210qZQnt5j0/nOuC
         08yoEQug42hrSwzYouwvbBFYWR8szouS+t9h2YPP4jGEeFwdnUN+N+OpUwZuBBclqfi5
         Lb+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vvCpa9HN;
       spf=pass (google.com: domain of 3usfbyaukcxiubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3uSFbYAUKCXIUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oVDn9tANp3Bg0RBv5f/K/lFbAzq1RSXsi3wTKJu40XI=;
        b=JSIsIW0DTrRkdml1YsmX3VSOdXGHN6OCnHIzarySY5ycA6i3pU53U6jX1ygP1Xi39W
         b0m6iyDb8AHImZ5iQuYHwwDaQSzfjrzTMecBVMMjK21LWf0jengZNBmvybSyIvYx6CKH
         jZ6TMixOl120pftsIZais7xYKOzh7FlG5K4BIfaAl1om2eQv6+aIN9Wm/4nPqXPRo3nx
         Hawaw24kTLSJHyjAeegin+LaFs4RZ9OSqNAB3S9ofyAviMiwC+l47cYhWi0Y7Heaziwi
         w7STefmHkXPXS8FS/+XAmw0WAKA699Iv6awR2d2RpPwIHEX8TFSMiKy6oS42aIkcsKfm
         0TzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oVDn9tANp3Bg0RBv5f/K/lFbAzq1RSXsi3wTKJu40XI=;
        b=GbIzxTSoxGD5/mLeXEnrcuXhQx/xneRCPgEybsT2/M8EqE0YhE0F/EPP6ufYaLqq4V
         NDb3IRG/LiF35YqhNz9hy4eVwSLLhBXivhiDNsndbjiimlyJiDiHMJ3wKy2Pn8sH2qjU
         /jF/09iJLlK62GIc930i5mmARD7RT5kN8C5b2zHO5sxIQe2r1Krc15YHtfAacsMzXS72
         toM/4dO1Sbd4RsZE9boBgTZZewOIYLO9MZ4RAsOf5CPhzZ/E/ejYHfLVO6zMJZgY+ZTk
         rGQ+MCUMKtpJNdlGBcTSi1lRDkXD10Pl7fk2h56oBbsqOOVc50e3D10ZkR2TbrnHegXQ
         0eRg==
X-Gm-Message-State: AOAM531Aw4qM4BH4w8I9b8X5eaKEkY2oAzLR+SxBhjHMS0dT9nYoQEkD
	qEKItj9kwz5Ow3smMKsPsYQ=
X-Google-Smtp-Source: ABdhPJxsB0qflib8q8DhRG0hOKuh/VQ93sfuvsLgwh3Rb9Mm9hhv1zceJRma5eIfN8WYrmZdZ5euYQ==
X-Received: by 2002:a5d:64af:: with SMTP id m15mr2903092wrp.231.1616585147320;
        Wed, 24 Mar 2021 04:25:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:58f0:: with SMTP id f16ls2199522wrd.0.gmail; Wed, 24 Mar
 2021 04:25:46 -0700 (PDT)
X-Received: by 2002:adf:f303:: with SMTP id i3mr2908788wro.67.1616585146290;
        Wed, 24 Mar 2021 04:25:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616585146; cv=none;
        d=google.com; s=arc-20160816;
        b=lO1znM3qK+w5DCBr+GZw5u41auMU0ciqaEatUIg5uNxwrG2phEy9MGI9Ut5Y+f9uh1
         JN/+uga6bJWiiPp6647tQir2t4y0I1L8VLGk67cYfiWsANLADdQ8VU8PGkYPQaYCRgTp
         7xWK+6oTCM+rxr11NL7G2Ba2aza0xtiZavrIc8F8K8xTIJDhuOWG4BS0GQrVApu7njqc
         34+gu+CQ2Nm77ojHl0dYdRWeqyvRVoHeglEuAjYrPwTEvYZ8TVOe/6cl5BDtvvlo+/CW
         c+QZYZ6avD6Zq2426s7TAwk1OApI8A05N34y9xsyOqfqRZXdKk2uFD8hYORjYIKOZfs9
         Ci9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=SXHD/uvUmQlMKu8n5JwtEEFXBwNpAPsrMpvny8SPQ1E=;
        b=mwvIRMiVFODuHnS9ufo0yqVJUZNkgfBY0YL+ux7M6OMtVXr9oI7KkxPSti/yLr/bW2
         IP6DmfQC62D4uTplTgnXi3m6ak5YbOPPW8sV4AlrBgxhSIBPdI8AWFkIG5Ts0FTWREiC
         Y18nYa0IJH7CBlaJoNgxkRcj5undWwS6o6z9RYXcmrCy7Teo4fOjUV+X7d2eCF0FQbDx
         /oAE34dUSpE20EswSj/0Tf+T36+CpqoO+Kx+Tvn9hnfWa6798ICeb7urP+7ZTA3DmCVu
         FyU6rucAkJ6XV8xveMfEnJmTSzbpWXo3Hk+7WESxtS9smsd+6HI/b+mOBr9/U3IKyhJw
         rTCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vvCpa9HN;
       spf=pass (google.com: domain of 3usfbyaukcxiubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3uSFbYAUKCXIUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id s8si93767wrn.5.2021.03.24.04.25.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Mar 2021 04:25:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3usfbyaukcxiubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id gv58so768745ejc.6
        for <kasan-dev@googlegroups.com>; Wed, 24 Mar 2021 04:25:46 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6489:b3f0:4af:af0])
 (user=elver job=sendgmr) by 2002:a17:906:ecb8:: with SMTP id
 qh24mr3238409ejb.162.1616585145705; Wed, 24 Mar 2021 04:25:45 -0700 (PDT)
Date: Wed, 24 Mar 2021 12:25:03 +0100
In-Reply-To: <20210324112503.623833-1-elver@google.com>
Message-Id: <20210324112503.623833-12-elver@google.com>
Mime-Version: 1.0
References: <20210324112503.623833-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.291.g576ba9dcdaf-goog
Subject: [PATCH v3 11/11] perf test: Add basic stress test for sigtrap handling
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
 header.i=@google.com header.s=20161025 header.b=vvCpa9HN;       spf=pass
 (google.com: domain of 3usfbyaukcxiubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3uSFbYAUKCXIUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
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
v3:
* Added to series (per suggestion from Ian Rogers).
---
 tools/perf/tests/Build          |   1 +
 tools/perf/tests/builtin-test.c |   5 ++
 tools/perf/tests/sigtrap.c      | 148 ++++++++++++++++++++++++++++++++
 tools/perf/tests/tests.h        |   1 +
 4 files changed, 155 insertions(+)
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
index 000000000000..b3f4006c22fd
--- /dev/null
+++ b/tools/perf/tests/sigtrap.c
@@ -0,0 +1,148 @@
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
+static struct perf_event_attr make_event_attr(void)
+{
+	struct perf_event_attr attr = {
+		.type		= PERF_TYPE_BREAKPOINT,
+		.size		= sizeof(attr),
+		.sample_period	= 1,
+		.disabled	= 1,
+		.bp_addr	= (long)&ctx.iterate_on,
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
+	TEST_ASSERT_VAL("unexpected si_perf", ctx.first_siginfo.si_perf ==
+			((HW_BREAKPOINT_LEN_1 << 16) | HW_BREAKPOINT_RW));
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
2.31.0.291.g576ba9dcdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324112503.623833-12-elver%40google.com.
