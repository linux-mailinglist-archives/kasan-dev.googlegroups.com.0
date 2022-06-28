Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ5B5OKQMGQEK56E4MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id E1C2555BFF3
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 11:59:03 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id m8-20020a2eb6c8000000b0025aa0530107sf1466645ljo.6
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 02:59:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656410343; cv=pass;
        d=google.com; s=arc-20160816;
        b=nnk3zUFr2twwOQSn5tR/MJKiJ5WU7iquTsRVCLlhPhXNPJSCx3Np33xh8HdPw3Jv6s
         x+oOAawtYobIt+nhui4izUA7cQnycBPw+a9SwWrx6r7Vrwcg0yAUloofypp+cbi2L5W6
         sxt7xRmsZO8rIZ+LtVU/hHnZGaajf4jbDERcqgIwlyCq7UjlMN1ZUI4eq2xwjkH10yTo
         OJapNv3JbpJOVqBYlqk7StYJFXxVR69Z2wA/6Fg1DzUTWn9JvzE3BAZm/Yd+aGE66sbT
         NHGaCuokvJX4XaadjmviwsEX5lUZ9ntgPTdU7xAWoPNGo7PFFMlitlEyyvIBTCFoJTrj
         9f6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=R33fTpFjEgyICkVIHGAYjn82ytz2ceb9zWRv/XfdF7Q=;
        b=TucZVPWJraObyAtz4zwtMZBQr3irPOX7AfAxDVrpNIkc+JRG0xbOdju+ptAfEB4HuA
         JsacTSPo68grUaYEOM5qbHBQ/dnAKzrkfwsDzUL3n1Xzx6fn5ZVpR2yoAr8Ehu6ti4LC
         vCIqG9kTL19XslCfKs4hBA4cXCnjwzo/R9+xuEyzuH+r8zqwoEfhCYKOXsiVUHMBlYnG
         er5oznX6pMGBRQyRNL9LrotjHmSIgn82Inuwctbr35Nq2uLn+W+ZNjZIyzkQWOltJ80H
         kSaui174+F1xIKZQCIHwdjZoHjWqVcr15F3b3s0yxcKJDzNtspvoHhv8KpZKwhmMVozS
         iq9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VJizrG6i;
       spf=pass (google.com: domain of 35dc6ygukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=35dC6YgUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R33fTpFjEgyICkVIHGAYjn82ytz2ceb9zWRv/XfdF7Q=;
        b=Ma+SX0CpvgUzD5wuC5yzHrFjtlGtXNHQAD9nC6+8UI6GJrVQPEo3vrlUj3oSMLYgSr
         hxf3JMW+jWkUijE0a+I8lnlIpfnSIzhwDEmqapTyYdgplOVxPP2WcAgezQzNBz3gtNQq
         x5VO2es0MJntZUuiv8cwg8A/Bvx2OZWbGbxL8e5HAdXeAuD4lPhBEy9NhioJ2efd82N4
         /YICumqUmtcM7WZSDdMmSGIJbP6dbgdzrUh/LqmojsT4TAZzxFgKYevfq+QxAa1QPBik
         3MmP2BFDm0DEbsoY3bc1ObLtI44GnRoAyIXMp+ix1lTjvqe1peVFbocF9qfGGzBNMqUm
         AT/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R33fTpFjEgyICkVIHGAYjn82ytz2ceb9zWRv/XfdF7Q=;
        b=p8ePlZSTrHn1T50o9wtw9CpitfEhT5rJIPXQwxHP09oImBgmEt9tBvjQVAKdHfmGIx
         DVYD78Ofc+4fe4P+Iu+6QUIW3GrNjc0vDY3GSX2mnr9j5AUDBqZG+ueB26tCVPqj5KwQ
         rotFz37HIF1OEw6/coq9qRByusLTuFYllqKYODgO2aBqh7D1eOaLhpY8jUdlBrmHT3LC
         iQNK5LDJU3E2uRVeIRMAzSwNgNTqwgRQDUrbePxIQ5+h4Hlfn6PLhsKfD3tyS5ailIMy
         Fa4fy9KS+0jGs9wEErXPuQ3PJR1GWVxzdwaBEoSZY2XhA7abOsdZJJavr1wKMjHz4bPU
         jHmQ==
X-Gm-Message-State: AJIora+Top4jZNrdPRw4z/3292AMDEJwBorNHeD7vUDRkN79dMSZ6x0g
	hC3P5MFOAL0lsh4OADOwSGA=
X-Google-Smtp-Source: AGRyM1tDlDIoVkQhmz2c5+ttxpzXRdh8HYkld1eY68lcxQbMjolJGGgYA8qNwVjOir5ux8cece7HVQ==
X-Received: by 2002:a2e:a7c7:0:b0:25b:b72d:aa3c with SMTP id x7-20020a2ea7c7000000b0025bb72daa3cmr7091832ljp.318.1656410343288;
        Tue, 28 Jun 2022 02:59:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:81d1:0:b0:25b:c342:b0dd with SMTP id s17-20020a2e81d1000000b0025bc342b0ddls901298ljg.5.gmail;
 Tue, 28 Jun 2022 02:59:01 -0700 (PDT)
X-Received: by 2002:a2e:390e:0:b0:25a:9763:d2dd with SMTP id g14-20020a2e390e000000b0025a9763d2ddmr8950310lja.210.1656410341853;
        Tue, 28 Jun 2022 02:59:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656410341; cv=none;
        d=google.com; s=arc-20160816;
        b=RVsP5d8MirpTdxCpv6JFTz+wlHKCuvYgt3EW3dJVp6Bknbmok4ar3hCffrS3PnWUHt
         lUBeMdRQryoDRQ9qQrdEOTOAonaMuR3alW+2gyEAs5N5Xo0qtg9ehsQAKmvFE+kBgUJ3
         vwk5XzA9HBVCe8KUeXTykWo6Uu1bZuLXMeE8KPZuNux30IRu+5b8hoB6N6CU0ZjlkNRR
         ur07ZNesOXrKHvYAMgAjwrOH4gwAgWT8hlnqyUkW7OHfUxXeirPFxvLljHp2bo12tdzy
         j1e+bW/xmV1A7F9JDIcSr/ATArVKnMh/SBANV3YUyFJrkFK3dwd2ANZIzOr0YSDls643
         nrYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=xK4e9VEyJDIzbUo67C06P/12U8vcat3CTuB5T8upBGY=;
        b=lOzA5UOCZYN/e1Ug0drubyUk/3GS42BOLl0VYSzF7c89an+WisrlJ20tDo4g/VB7ib
         kISQM0umtK9CWjFiC29xWPNXJHg7Phk93mgG7f7smKmNDXOVfrBsrijFaTAF4TrJNtrz
         SGuMT0+Uiu8LB8sM5Wy+H1CnPUGI+ji+e9s3EJMM7o+JzNtSW7Y88zb1mxPHo/JMrirr
         5ZU8VvCMiFGHhDL4pBN3BOiptmJsqthpl7LcxcEOErGO6EqAnobIW95WrD1zRXNoDt9R
         zz7W4xyLmYxPiCShBI23wEobmyc51B4XrdjIQqg7l+p05j+AG+KiYWsUxwtARX52fGBU
         PDDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VJizrG6i;
       spf=pass (google.com: domain of 35dc6ygukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=35dC6YgUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id o9-20020ac25e29000000b0047f8e0add59si611221lfg.10.2022.06.28.02.59.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 02:59:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35dc6ygukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id g7-20020a056402424700b00435ac9c7a8bso9201163edb.14
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 02:59:01 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:3496:744e:315a:b41b])
 (user=elver job=sendgmr) by 2002:a17:906:3f09:b0:712:466:e04a with SMTP id
 c9-20020a1709063f0900b007120466e04amr16934750ejj.719.1656410341300; Tue, 28
 Jun 2022 02:59:01 -0700 (PDT)
Date: Tue, 28 Jun 2022 11:58:21 +0200
In-Reply-To: <20220628095833.2579903-1-elver@google.com>
Message-Id: <20220628095833.2579903-2-elver@google.com>
Mime-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v2 01/13] perf/hw_breakpoint: Add KUnit test for constraints accounting
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
 header.i=@google.com header.s=20210112 header.b=VJizrG6i;       spf=pass
 (google.com: domain of 35dc6ygukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=35dC6YgUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
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
v2:
* New patch.
---
 kernel/events/Makefile             |   1 +
 kernel/events/hw_breakpoint_test.c | 321 +++++++++++++++++++++++++++++
 lib/Kconfig.debug                  |  10 +
 3 files changed, 332 insertions(+)
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
index 000000000000..747a0249a606
--- /dev/null
+++ b/kernel/events/hw_breakpoint_test.c
@@ -0,0 +1,321 @@
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
+static int get_other_cpu(void)
+{
+	int cpu;
+
+	for_each_online_cpu(cpu) {
+		if (cpu != raw_smp_processor_id())
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
+	fill_bp_slots(test, &idx, raw_smp_processor_id(), NULL, 0);
+	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
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
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
+	/* Remove one and adding back CPU-target should work. */
+	unregister_test_bp(&test_bps[0]);
+	fill_one_bp_slot(test, &idx, raw_smp_processor_id(), NULL);
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
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), get_other_task(test), idx));
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
+	/* Remove one from first task and adding back CPU-target should not work. */
+	unregister_test_bp(&test_bps[0]);
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
+}
+
+static void test_one_task_on_one_cpu(struct kunit *test)
+{
+	int idx = 0;
+
+	fill_bp_slots(test, &idx, raw_smp_processor_id(), current, 0);
+	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
+	/*
+	 * Remove one and adding back CPU-target should work; this case is
+	 * special vs. above because the task's constraints are CPU-dependent.
+	 */
+	unregister_test_bp(&test_bps[0]);
+	fill_one_bp_slot(test, &idx, raw_smp_processor_id(), NULL);
+}
+
+static void test_one_task_mixed(struct kunit *test)
+{
+	int idx = 0;
+
+	TEST_REQUIRES_BP_SLOTS(test, 3);
+
+	fill_one_bp_slot(test, &idx, raw_smp_processor_id(), current);
+	fill_bp_slots(test, &idx, -1, current, 1);
+	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
+
+	/* Transition from CPU-dependent pinned count to CPU-independent. */
+	unregister_test_bp(&test_bps[0]);
+	unregister_test_bp(&test_bps[1]);
+	fill_one_bp_slot(test, &idx, raw_smp_processor_id(), NULL);
+	fill_one_bp_slot(test, &idx, raw_smp_processor_id(), NULL);
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
+}
+
+static void test_two_tasks_on_one_cpu(struct kunit *test)
+{
+	int idx = 0;
+
+	fill_bp_slots(test, &idx, raw_smp_processor_id(), current, 0);
+	fill_bp_slots(test, &idx, raw_smp_processor_id(), get_other_task(test), 0);
+
+	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(-1, get_other_task(test), idx));
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), get_other_task(test), idx));
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
+	/* Can still create breakpoints on some other CPU. */
+	fill_bp_slots(test, &idx, get_other_cpu(), NULL, 0);
+}
+
+static void test_two_tasks_on_one_all_cpus(struct kunit *test)
+{
+	int idx = 0;
+
+	fill_bp_slots(test, &idx, raw_smp_processor_id(), current, 0);
+	fill_bp_slots(test, &idx, -1, get_other_task(test), 0);
+
+	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(-1, get_other_task(test), idx));
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), get_other_task(test), idx));
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
+	/* Cannot create breakpoints on some other CPU either. */
+	TEST_EXPECT_NOSPC(register_test_bp(get_other_cpu(), NULL, idx));
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
+	fill_one_bp_slot(test, &idx, raw_smp_processor_id(), current);
+	fill_one_bp_slot(test, &idx, -1, current);
+
+	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
+
+	/* We should still be able to use up another CPU's slots. */
+	cpu_idx = idx;
+	fill_one_bp_slot(test, &idx, get_other_cpu(), NULL);
+	TEST_EXPECT_NOSPC(register_test_bp(get_other_cpu(), NULL, idx));
+
+	/* Transitioning back to task target on all CPUs. */
+	unregister_test_bp(&test_bps[tsk_on_cpu_idx]);
+	/* Still have a CPU target breakpoint in get_other_cpu(). */
+	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
+	/* Remove it and try again. */
+	unregister_test_bp(&test_bps[cpu_idx]);
+	fill_one_bp_slot(test, &idx, -1, current);
+
+	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), current, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
+	TEST_EXPECT_NOSPC(register_test_bp(get_other_cpu(), NULL, idx));
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220628095833.2579903-2-elver%40google.com.
