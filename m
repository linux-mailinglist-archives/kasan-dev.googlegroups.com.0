Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAXLWKMAMGQECYX2PFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 52F815A4C36
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 14:48:03 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id d11-20020adfc08b000000b002207555c1f6sf1106907wrf.7
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 05:48:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661777283; cv=pass;
        d=google.com; s=arc-20160816;
        b=RuE35l+tcVrusWO2DigTkbVpsXJPC7Ni+FYXLyhZ6TezCU0xpVR6fE8ciTouJc63ES
         qlBSXRdRExQIRTZDHpX/6J5THkeNilXbyM7FJ+/cp2815EUxTUhj/M0I9skFIZo1t7vk
         uQ5m/+QJqnfOHAicB7giHetS6Pfd00h3BdLtCOia1nROzBJFIQXOpVd4OVJyZxIhvMZt
         xzIUOMQM0JjdYkIUjGX4Qj3warswVV+s5b+Gpih5kkUhVli9sUpxBGkKpnna/S5DMUli
         sUh1ohCrc8uV5HbpphlYUJx8Vzqtx3/xszyLpV+Paqfpiy1pgkeumhGsGZUz+3Hevgq0
         W99Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=fYNioHV4t/I3ZwUCeBS4g7CoxnaCpBX6VWUf4XWPHvk=;
        b=LDRkZYX22XHSg5F0BwCqdrVSbgyPfAsTHTA1jdx32PVztg+k7+Iku3Vq1oqjQy6HEj
         KLH2SRMBMa33JXQ8BXIFQZ/K4rddM98eO84tVyRgpdIYVd9ZdxPkoHK1B9oxurbHqeNJ
         JgQiQU0HT0xk2Z21Eq6jxHPDVKX0n0ejNcsBFruwgBpfEk9pMREqEa1bIzpxsDrunJVG
         OQl1whoXlP4XMU8pOUtY4wdl1YYdw5jOMMr3eSP2Td76S6k8x8z7sKqP9wKIgNCPcpMg
         RrlUetamLP990FEuizA6bBvourHiZSiTUu917DBO0+2ywXmDD2Hxi0elVyxaUU3XYgCK
         WYRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=M9Rqk2DZ;
       spf=pass (google.com: domain of 3gbumywukct4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3gbUMYwUKCT4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=fYNioHV4t/I3ZwUCeBS4g7CoxnaCpBX6VWUf4XWPHvk=;
        b=rOCi02Cr7AP3jpRhfjnWt6h+RAz0DbJKLXqqLPQbo3+Oy0SoCybpUO8P/BFyd1K/vC
         OWyZz3IxiTW2NMXZ9GhiCZgmjG33JbhhMnWvJmvmKHO5plqIk0r/lIopEiLoziYWRHUh
         ROhq5Ue3cqdGGs3Yp9wzmOGTtVUl7acoRfBWkdmFrTG/LARSxyJMM/jEjJeZTFgAdVR2
         WC3aLcRFszHRmRqe2FgmT1Esov8QwyeJx9IPCftZsawshd522kT6JqfpEINmalsU+uB9
         0MyD5X83n9l2cmmdSmhlIomVZqB+w+JOwJNff6WSW2DLYLYJVLS4CSnEEJYBCt73p9Ru
         h5mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=fYNioHV4t/I3ZwUCeBS4g7CoxnaCpBX6VWUf4XWPHvk=;
        b=LA2WJu/vOtPQh0bhr/shJntY43Jv2jGeBGAer1y94ehTXGCl9e4AMHzSjzzGVRD24y
         Nt8wnesIggNYlCGlsKmnsPBCc+rrW68lpXWF39SzAPN/B2cOMEb9UF21RNRy/fj494Jo
         44qFlt0ozXbUMgJhgdsaHFp4rQplpnHRUJ5OWT1QXkJE0Gx3PDLEmQRWFaXqCkaoxG/Z
         hU/tIsAAp270cltoHzF7Qq8YBiEXMhsBKzWxVlxHTVIF4IWynuB7WxJlufUgyMxGMGps
         wNw4W8JJE9ERMy+1+zOhq3uaK88Gm9qOWEtr3QKnDS9QFlOv1gz1F/lqkTGi0GQszAu3
         LwDA==
X-Gm-Message-State: ACgBeo1ad+ACYNoWwTn0oqAAV5dw6XMvgnSmwFhBZ+sgTLpKgGJH3XBD
	WGhhsnPRxF8nB0O+WPfG9Bg=
X-Google-Smtp-Source: AA6agR6gYypx0wDFec9zC2hrLxb/NiUs2zGL89WvhhxW+W/uasTcfeWf5OnRlKqkO4pT48TgBFBtPg==
X-Received: by 2002:a05:6000:1292:b0:225:4a8c:3ad with SMTP id f18-20020a056000129200b002254a8c03admr6086247wrx.684.1661777282932;
        Mon, 29 Aug 2022 05:48:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d234:0:b0:225:26dd:8b59 with SMTP id k20-20020adfd234000000b0022526dd8b59ls1690517wrh.3.-pod-prod-gmail;
 Mon, 29 Aug 2022 05:48:01 -0700 (PDT)
X-Received: by 2002:a5d:69c4:0:b0:226:dde6:a1d7 with SMTP id s4-20020a5d69c4000000b00226dde6a1d7mr1643694wrw.618.1661777281640;
        Mon, 29 Aug 2022 05:48:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661777281; cv=none;
        d=google.com; s=arc-20160816;
        b=Rdj7q/RuAOdyrrfqv8Eiyp7qeYRo7DZDKx3b33fMk8Au8QA+cbnjLVBvGWGLIx5rVn
         Vzih93s+PH67P8q4g2plmIirybe5PnUoG2q6kRDOKgM0RbGhIY7jf00Hkx6Qc7XlkzIh
         ThYMnISG8PgPNbBSfr9GJwxefcHYn7jz2xuQVhZN2CnPIh99TRVOWtXyVhXJWGJvVbRi
         SZtPrBuioml+8yoRG7jktXeaOvmxEWX85acPNpdb5ksmZrbbEy6JAqfrJ1pFw3s7rnVK
         ROrQQVa5mqJ/iELhhLJNLb5jKe7zWxa76K713lYcBIeEjCWV2xoGTSea9ff7Rtyqy3HA
         3TXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=2wzFsLYHBSO+bSg9K3lLWWvk30GMleRrtWDuIqbsYXA=;
        b=Pjm0tX/hJBmdd723X0rksAO/jFJIf+IcsWJDBMCscsAEnmjHMI6Sg6NRsmN5ivjA2l
         ZSBj6dKz/qkpZsEpYd7mIqpYUiZfnUVGQjnD+t2hiP1SakpfJ1MTSGgKpfHj/id2usc+
         qcqIVLeG7itjDUU1VlX2LGV2E+35dyMJJWLtJB47uj6T1zQvjkEtk4KPsKTZ/3JIlsVU
         bpcD0CjcTWkrJ6Eyy5n/bbtJ4G2Z5VZ+oAJBtOrKbcHKdd3g5lfkM3nHMRY/R1oGmNAH
         v8zKKS739A+O66whM/xh1ltDrmDLUJi5CB3o5YFvD9pNlXKzKm+7SCxhOAxglGyjGzIk
         HKaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=M9Rqk2DZ;
       spf=pass (google.com: domain of 3gbumywukct4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3gbUMYwUKCT4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id cc18-20020a5d5c12000000b00226df38c2f0si35407wrb.4.2022.08.29.05.48.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Aug 2022 05:48:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gbumywukct4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id sd6-20020a1709076e0600b0073315809fb5so2253631ejc.10
        for <kasan-dev@googlegroups.com>; Mon, 29 Aug 2022 05:48:01 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:196d:4fc7:fa9c:62e3])
 (user=elver job=sendgmr) by 2002:a17:907:97d3:b0:73d:8b9b:a6c1 with SMTP id
 js19-20020a17090797d300b0073d8b9ba6c1mr13449067ejc.71.1661777281218; Mon, 29
 Aug 2022 05:48:01 -0700 (PDT)
Date: Mon, 29 Aug 2022 14:47:06 +0200
In-Reply-To: <20220829124719.675715-1-elver@google.com>
Mime-Version: 1.0
References: <20220829124719.675715-1-elver@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220829124719.675715-2-elver@google.com>
Subject: [PATCH v4 01/14] perf/hw_breakpoint: Add KUnit test for constraints accounting
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Ian Rogers <irogers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=M9Rqk2DZ;       spf=pass
 (google.com: domain of 3gbumywukct4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3gbUMYwUKCT4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
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
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Ian Rogers <irogers@google.com>
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
index bcbe60d6c80c..84309a00f9aa 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -2533,6 +2533,16 @@ config STACKINIT_KUNIT_TEST
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220829124719.675715-2-elver%40google.com.
