Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV4DRSLAMGQE4KBQ2MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 73F71565934
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 17:06:00 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id m20-20020a056402431400b0043a699cdd6esf1539522edc.9
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 08:06:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656947160; cv=pass;
        d=google.com; s=arc-20160816;
        b=r9Nf4eptCfd6UJiXbjoAm3nF+/k5fVKWLpzNH6TDxIH1npWLe/Te0xjEE9514DJDn5
         0P8gRVNB/yIHg8Bt2WuhSqvChGmVkk+EjDM/2oGiv+YUvpFJEs91ivpNPjrb5779RTXh
         kKt4VTq7Fv/u0BWvQ9IQb5KyWO8+abOwsAfws1rgy85CSqjR6V1kxBkW7CaleYCy2vp1
         16QVhX5ol5deX28a85+ZcQ5uYOT2ccE+i4lD4I/YdeVilsyVFhrVdMztPMwDKh2dGtiU
         EzHP81vhkKsfjZlgXJiOrpLnH1686abplID1eDy4dJwUNdgLHEU6CplU8HzHmikyAziW
         DujQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=UISV1NBvs/OFNAK2jCccgbTbHMFv3o36dsm85incOfA=;
        b=zRLpMATFzIsk03BsjQ5zKYNSIfBOyfBmXTCMUhWF1tMosGMXAm35reKEq3O7PLVxBV
         G7fsqtkUwFrXq2gURk/TdSYx/44mgGOUrWgsACdgqH2AbOQRR7jkm3eLyDCxUlAh43Ig
         9eVtJNrz/oiZoz11j9RVPxtQLkUxreSqFYFXUaygRaOgCuSpV23uqDOfbDXBlqdvclK3
         hkY2yTUURXPBZxC54FTEo2ti1HQ+EqM6mjvSQupq9DjxkNWEYRACfe3iPjOqbr4G56EJ
         OQmlEmKNkkmCm26vPatNRnma7Wq554VXyPlwTz/CGF1m+zrcH8xBv8vTWW1uqJC00FyP
         xQAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oQXvqnJR;
       spf=pass (google.com: domain of 31ghdygukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=31gHDYgUKCQMhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UISV1NBvs/OFNAK2jCccgbTbHMFv3o36dsm85incOfA=;
        b=oG++XShBFuXytPus1GBvU6mPyI4UvSA0VRyTvm5OHLnBDOfouV6cH6bWMT/pLDY6o7
         7sUfbznBB3xWTpKlrg/t3z09OK2BQ+bKrAXzBLgaJdJQrjzE4UM68DH1uf1T2FIm8k6G
         KNwM50TJqPsEZEI5pBPyfCR+Yx5ZmwyCxY7BK2zusT+h8VAnzE4odp65ps/8h8tU6kVh
         Hn4aWtFVASa0WfW0AsGhg2kWk3LbQHVnd5k+AtJey6tDHvs1n6aqazQrAksIrCOoafFe
         RGxmZOl8Np8Fo4SKwwozLIE+CrfHIBzXPu000yMOUNvZQ0QfkPPYimdDEBOdhJnVkrwY
         8xSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UISV1NBvs/OFNAK2jCccgbTbHMFv3o36dsm85incOfA=;
        b=p+8Wc13/ZKtUKz0QFRu6pu+7dK+/NGUxvEJ8butNqm9ROYrfC1cLbkd5vmWoMKW1pl
         0lYOOYE8o5FzxqohYZW7LtZ205q/3Fb/P7BlQkAvGsytBiMWpl5mjon2O8PZXqTyaLqC
         M3GgtGvasQkaMivKnQXVTCUApXLxZAoqCVpwnRmoT8Bq8/LxuwgTEaSX6/oTuoaWq2he
         he18V3JzjgyMSuZI8ASXgmm4YrnfNCFNMJPIKB66je09QZLZYG8OtN0ZJpc8OsfdWciL
         Y1JmenYt64FrvtgqfXfwJakRhXI/ObQpMhuzrdTJpKhEhDFw+p8IB0GnnR9RPCvmlXQp
         zVcA==
X-Gm-Message-State: AJIora9FMKyu0Ml2t+2GsEFObObXFlYQAGge9tT2VRMnxXmPfKGJePEU
	wzzXzOJ1Qrc/QM1+H9vN5Sk=
X-Google-Smtp-Source: AGRyM1vDWTNacqggQBaCxWKPGqcPAC3fEJxbEuxWx122FwM8cWWSOaVX0A7dDiONCiCJzWE5DCIVrg==
X-Received: by 2002:a05:6402:2b88:b0:43a:6c58:6c64 with SMTP id fj8-20020a0564022b8800b0043a6c586c64mr4848230edb.348.1656947160076;
        Mon, 04 Jul 2022 08:06:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:50cf:b0:435:9b77:f6e3 with SMTP id
 h15-20020a05640250cf00b004359b77f6e3ls1574763edb.0.gmail; Mon, 04 Jul 2022
 08:05:58 -0700 (PDT)
X-Received: by 2002:a05:6402:5192:b0:435:b3c3:af89 with SMTP id q18-20020a056402519200b00435b3c3af89mr39276324edd.390.1656947158882;
        Mon, 04 Jul 2022 08:05:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656947158; cv=none;
        d=google.com; s=arc-20160816;
        b=zeS5rG6ti8YPJsNZ6xz9l9Qy4bRzijllHcvDgSwX3ywJ5UdifkQiCmfONKEa2u28Ry
         aeaMYm9IaoVkw0j15Ct78LSZade57mR2JDn9UoYAeThfR1AA9EhtXmpGr3QjqZFJcrVw
         7I3gH85kxDEXfhECev98h/6ODFuh2fWrr0oNjWDUxU1McMHcMw4k4FGK+I7N++XYvMm0
         tpzMqE73SBuEgs2k6W1R2sVj/cfanWxNGHqE4jNP8iCfXLp8hgwi56HMD+zf/vqLDP2W
         6wACncmkwDGnYxcMvS7Bx/WAtl2nfiqPmFWE8K1CGrU/5eRFUai1nWpS+XeUvXHILfz5
         iS4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=uSL64WbpOB0aGBID+htWF2mgmyKhVinUXMU6W5OQm+c=;
        b=zMxZCKLWsDN2tZQJieK7EEvf5UXgU+azNQi1163khMO5RThIB9Rjy0FFUoi7dnUZJq
         ZuzmMIlLNBurNwP9/7aPQVsPkQuZDJDNw+1HMkDrukdXxbHsIy0t2oILo+uGoxixA3Ai
         YdsEFFQ26sAWn2cButswIhqkRIrbEQ+fysMKBkdkm7cOFfc0bfHggYGNy9f5SH26kGJV
         jVgrtr9LzEiUHwha9xStOaQi9iqetkqNrX6cyt4pJWkMX3G1OfLe7NfvcpiZ8nHJqtoM
         rACsPGE5BbyyWwTKYI1g9MSrYyCKebBOpp9OQmQGoWDLz4ws1qR73UKv87kK4ZHqvTye
         LcUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oQXvqnJR;
       spf=pass (google.com: domain of 31ghdygukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=31gHDYgUKCQMhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id i24-20020a0564020f1800b004319ce84356si1199829eda.4.2022.07.04.08.05.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 08:05:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31ghdygukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id y18-20020a056402441200b0043564cdf765so7393706eda.11
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 08:05:58 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:6edf:e1bc:9a92:4ad0])
 (user=elver job=sendgmr) by 2002:a05:6402:350a:b0:435:df44:30aa with SMTP id
 b10-20020a056402350a00b00435df4430aamr38465413edd.403.1656947158542; Mon, 04
 Jul 2022 08:05:58 -0700 (PDT)
Date: Mon,  4 Jul 2022 17:05:01 +0200
In-Reply-To: <20220704150514.48816-1-elver@google.com>
Message-Id: <20220704150514.48816-2-elver@google.com>
Mime-Version: 1.0
References: <20220704150514.48816-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v3 01/14] perf/hw_breakpoint: Add KUnit test for constraints accounting
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=oQXvqnJR;       spf=pass
 (google.com: domain of 31ghdygukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=31gHDYgUKCQMhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
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

Add KUnit test for hw_breakpoint constraints accounting, with various
interesting mixes of breakpoint targets (some care was taken to catch
interesting corner cases via bug-injection).

The test cannot be built as a module because it requires access to
hw_breakpoint_slots(), which is not inlinable or exported on all
architectures.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Don't use raw_smp_processor_id().

v2:
* New patch.
---
 kernel/events/Makefile             |   1 +
 kernel/events/hw_breakpoint_test.c | 323 +++++++++++++++++++++++++++++
 lib/Kconfig.debug                  |  10 +
 3 files changed, 334 insertions(+)
 create mode 100644 kernel/events/hw_breakpoint_test.c

diff --git a/kernel/events/Makefile b/kernel/events/Makefile
index 8591c180b52b..91a62f566743 100644
--- a/kernel/events/Makefile
+++ b/kernel/events/Makefile
@@ -2,4 +2,5 @@
 obj-y := core.o ring_buffer.o callchain.o
 
 obj-$(CONFIG_HAVE_HW_BREAKPOINT) += hw_breakpoint.o
+obj-$(CONFIG_HW_BREAKPOINT_KUNIT_TEST) += hw_breakpoint_test.o
 obj-$(CONFIG_UPROBES) += uprobes.o
diff --git a/kernel/events/hw_breakpoint_test.c b/kernel/events/hw_breakpoint_test.c
new file mode 100644
index 000000000000..433c5c45e2a5
--- /dev/null
+++ b/kernel/events/hw_breakpoint_test.c
@@ -0,0 +1,323 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * KUnit test for hw_breakpoint constraints accounting logic.
+ *
+ * Copyright (C) 2022, Google LLC.
+ */
+
+#include <kunit/test.h>
+#include <linux/cpumask.h>
+#include <linux/hw_breakpoint.h>
+#include <linux/kthread.h>
+#include <linux/perf_event.h>
+#include <asm/hw_breakpoint.h>
+
+#define TEST_REQUIRES_BP_SLOTS(test, slots)						\
+	do {										\
+		if ((slots) > get_test_bp_slots()) {					\
+			kunit_skip((test), "Requires breakpoint slots: %d > %d", slots,	\
+				   get_test_bp_slots());				\
+		}									\
+	} while (0)
+
+#define TEST_EXPECT_NOSPC(expr) KUNIT_EXPECT_EQ(test, -ENOSPC, PTR_ERR(expr))
+
+#define MAX_TEST_BREAKPOINTS 512
+
+static char break_vars[MAX_TEST_BREAKPOINTS];
+static struct perf_event *test_bps[MAX_TEST_BREAKPOINTS];
+static struct task_struct *__other_task;
+
+static struct perf_event *register_test_bp(int cpu, struct task_struct *tsk, int idx)
+{
+	struct perf_event_attr attr = {};
+
+	if (WARN_ON(idx < 0 || idx >= MAX_TEST_BREAKPOINTS))
+		return NULL;
+
+	hw_breakpoint_init(&attr);
+	attr.bp_addr = (unsigned long)&break_vars[idx];
+	attr.bp_len = HW_BREAKPOINT_LEN_1;
+	attr.bp_type = HW_BREAKPOINT_RW;
+	return perf_event_create_kernel_counter(&attr, cpu, tsk, NULL, NULL);
+}
+
+static void unregister_test_bp(struct perf_event **bp)
+{
+	if (WARN_ON(IS_ERR(*bp)))
+		return;
+	if (WARN_ON(!*bp))
+		return;
+	unregister_hw_breakpoint(*bp);
+	*bp = NULL;
+}
+
+static int get_test_bp_slots(void)
+{
+	static int slots;
+
+	if (!slots)
+		slots = hw_breakpoint_slots(TYPE_DATA);
+
+	return slots;
+}
+
+static void fill_one_bp_slot(struct kunit *test, int *id, int cpu, struct task_struct *tsk)
+{
+	struct perf_event *bp = register_test_bp(cpu, tsk, *id);
+
+	KUNIT_ASSERT_NOT_NULL(test, bp);
+	KUNIT_ASSERT_FALSE(test, IS_ERR(bp));
+	KUNIT_ASSERT_NULL(test, test_bps[*id]);
+	test_bps[(*id)++] = bp;
+}
+
+/*
+ * Fills up the given @cpu/@tsk with breakpoints, only leaving @skip slots free.
+ *
+ * Returns true if this can be called again, continuing at @id.
+ */
+static bool fill_bp_slots(struct kunit *test, int *id, int cpu, struct task_struct *tsk, int skip)
+{
+	for (int i = 0; i < get_test_bp_slots() - skip; ++i)
+		fill_one_bp_slot(test, id, cpu, tsk);
+
+	return *id + get_test_bp_slots() <= MAX_TEST_BREAKPOINTS;
+}
+
+static int dummy_kthread(void *arg)
+{
+	return 0;
+}
+
+static struct task_struct *get_other_task(struct kunit *test)
+{
+	struct task_struct *tsk;
+
+	if (__other_task)
+		return __other_task;
+
+	tsk = kthread_create(dummy_kthread, NULL, "hw_breakpoint_dummy_task");
+	KUNIT_ASSERT_FALSE(test, IS_ERR(tsk));
+	__other_task = tsk;
+	return __other_task;
+}
+
+static int get_test_cpu(int num)
+{
+	int cpu;
+
+	WARN_ON(num < 0);
+
+	for_each_online_cpu(cpu) {
+		if (num-- <= 0)
+			break;
+	}
+
+	return cpu;
+}
+
+/* ===== Test cases ===== */
+
+static void test_one_cpu(struct kunit *test)
+{
+	int idx = 0;
+
+	fill_bp_slots(test, &idx, get_test_cpu(0), NULL, 0);
+	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
+}
+
+static void test_many_cpus(struct kunit *test)
+{
+	int idx = 0;
+	int cpu;
+
+	/* Test that CPUs are independent. */
+	for_each_online_cpu(cpu) {
+		bool do_continue = fill_bp_slots(test, &idx, cpu, NULL, 0);
+
+		TEST_EXPECT_NOSPC(register_test_bp(cpu, NULL, idx));
+		if (!do_continue)
+			break;
+	}
+}
+
+static void test_one_task_on_all_cpus(struct kunit *test)
+{
+	int idx = 0;
+
+	fill_bp_slots(test, &idx, -1, current, 0);
+	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
+	/* Remove one and adding back CPU-target should work. */
+	unregister_test_bp(&test_bps[0]);
+	fill_one_bp_slot(test, &idx, get_test_cpu(0), NULL);
+}
+
+static void test_two_tasks_on_all_cpus(struct kunit *test)
+{
+	int idx = 0;
+
+	/* Test that tasks are independent. */
+	fill_bp_slots(test, &idx, -1, current, 0);
+	fill_bp_slots(test, &idx, -1, get_other_task(test), 0);
+
+	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(-1, get_other_task(test), idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), get_other_task(test), idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
+	/* Remove one from first task and adding back CPU-target should not work. */
+	unregister_test_bp(&test_bps[0]);
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
+}
+
+static void test_one_task_on_one_cpu(struct kunit *test)
+{
+	int idx = 0;
+
+	fill_bp_slots(test, &idx, get_test_cpu(0), current, 0);
+	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
+	/*
+	 * Remove one and adding back CPU-target should work; this case is
+	 * special vs. above because the task's constraints are CPU-dependent.
+	 */
+	unregister_test_bp(&test_bps[0]);
+	fill_one_bp_slot(test, &idx, get_test_cpu(0), NULL);
+}
+
+static void test_one_task_mixed(struct kunit *test)
+{
+	int idx = 0;
+
+	TEST_REQUIRES_BP_SLOTS(test, 3);
+
+	fill_one_bp_slot(test, &idx, get_test_cpu(0), current);
+	fill_bp_slots(test, &idx, -1, current, 1);
+	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
+
+	/* Transition from CPU-dependent pinned count to CPU-independent. */
+	unregister_test_bp(&test_bps[0]);
+	unregister_test_bp(&test_bps[1]);
+	fill_one_bp_slot(test, &idx, get_test_cpu(0), NULL);
+	fill_one_bp_slot(test, &idx, get_test_cpu(0), NULL);
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
+}
+
+static void test_two_tasks_on_one_cpu(struct kunit *test)
+{
+	int idx = 0;
+
+	fill_bp_slots(test, &idx, get_test_cpu(0), current, 0);
+	fill_bp_slots(test, &idx, get_test_cpu(0), get_other_task(test), 0);
+
+	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(-1, get_other_task(test), idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), get_other_task(test), idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
+	/* Can still create breakpoints on some other CPU. */
+	fill_bp_slots(test, &idx, get_test_cpu(1), NULL, 0);
+}
+
+static void test_two_tasks_on_one_all_cpus(struct kunit *test)
+{
+	int idx = 0;
+
+	fill_bp_slots(test, &idx, get_test_cpu(0), current, 0);
+	fill_bp_slots(test, &idx, -1, get_other_task(test), 0);
+
+	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(-1, get_other_task(test), idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), get_other_task(test), idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
+	/* Cannot create breakpoints on some other CPU either. */
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(1), NULL, idx));
+}
+
+static void test_task_on_all_and_one_cpu(struct kunit *test)
+{
+	int tsk_on_cpu_idx, cpu_idx;
+	int idx = 0;
+
+	TEST_REQUIRES_BP_SLOTS(test, 3);
+
+	fill_bp_slots(test, &idx, -1, current, 2);
+	/* Transitioning from only all CPU breakpoints to mixed. */
+	tsk_on_cpu_idx = idx;
+	fill_one_bp_slot(test, &idx, get_test_cpu(0), current);
+	fill_one_bp_slot(test, &idx, -1, current);
+
+	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
+
+	/* We should still be able to use up another CPU's slots. */
+	cpu_idx = idx;
+	fill_one_bp_slot(test, &idx, get_test_cpu(1), NULL);
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(1), NULL, idx));
+
+	/* Transitioning back to task target on all CPUs. */
+	unregister_test_bp(&test_bps[tsk_on_cpu_idx]);
+	/* Still have a CPU target breakpoint in get_test_cpu(1). */
+	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
+	/* Remove it and try again. */
+	unregister_test_bp(&test_bps[cpu_idx]);
+	fill_one_bp_slot(test, &idx, -1, current);
+
+	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(1), NULL, idx));
+}
+
+static struct kunit_case hw_breakpoint_test_cases[] = {
+	KUNIT_CASE(test_one_cpu),
+	KUNIT_CASE(test_many_cpus),
+	KUNIT_CASE(test_one_task_on_all_cpus),
+	KUNIT_CASE(test_two_tasks_on_all_cpus),
+	KUNIT_CASE(test_one_task_on_one_cpu),
+	KUNIT_CASE(test_one_task_mixed),
+	KUNIT_CASE(test_two_tasks_on_one_cpu),
+	KUNIT_CASE(test_two_tasks_on_one_all_cpus),
+	KUNIT_CASE(test_task_on_all_and_one_cpu),
+	{},
+};
+
+static int test_init(struct kunit *test)
+{
+	/* Most test cases want 2 distinct CPUs. */
+	return num_online_cpus() < 2 ? -EINVAL : 0;
+}
+
+static void test_exit(struct kunit *test)
+{
+	for (int i = 0; i < MAX_TEST_BREAKPOINTS; ++i) {
+		if (test_bps[i])
+			unregister_test_bp(&test_bps[i]);
+	}
+
+	if (__other_task) {
+		kthread_stop(__other_task);
+		__other_task = NULL;
+	}
+}
+
+static struct kunit_suite hw_breakpoint_test_suite = {
+	.name = "hw_breakpoint",
+	.test_cases = hw_breakpoint_test_cases,
+	.init = test_init,
+	.exit = test_exit,
+};
+
+kunit_test_suites(&hw_breakpoint_test_suite);
+
+MODULE_LICENSE("GPL");
+MODULE_AUTHOR("Marco Elver <elver@google.com>");
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 2e24db4bff19..4c87a6edf046 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -2513,6 +2513,16 @@ config STACKINIT_KUNIT_TEST
 	  CONFIG_GCC_PLUGIN_STRUCTLEAK, CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF,
 	  or CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL.
 
+config HW_BREAKPOINT_KUNIT_TEST
+	bool "Test hw_breakpoint constraints accounting" if !KUNIT_ALL_TESTS
+	depends on HAVE_HW_BREAKPOINT
+	depends on KUNIT=y
+	default KUNIT_ALL_TESTS
+	help
+	  Tests for hw_breakpoint constraints accounting.
+
+	  If unsure, say N.
+
 config TEST_UDELAY
 	tristate "udelay test driver"
 	help
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220704150514.48816-2-elver%40google.com.
