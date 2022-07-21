Return-Path: <kasan-dev+bncBDV37XP3XYDRBPP24WLAMGQEPADEDBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 206FF57D169
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jul 2022 18:22:23 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id o20-20020ac24c54000000b0048a286ed00dsf909463lfk.14
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jul 2022 09:22:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658420542; cv=pass;
        d=google.com; s=arc-20160816;
        b=vLmQZmWU9VKeupkRKkAWVPQbUKwDJdQGYw34pFuTxFGiaPG9ZpbON2UQ4NJu4yAvJF
         SJO+0qL+SvD63MDWyJPUQwDdI4FxUnyDZUr19plXFsUgFjb6HWlXrddserTqeHBk+/Xr
         vWduphMRD72BHmMD8u7eHbYv6drEFMqR/p0tiB5W5EPAn9tP3Z2V+j0nAKcsB/0i5/+1
         wAFeM8VDdjbiSKryj1h/a4nxUBAMXLtHWBUH/40qKOf+muaWv4KnARF6BgWfUHJ9DDBb
         f+Oab1jGUhdOxJh3fECvOXkxzCBvXV3VYG4Lwostn3IqfJVmtqN3aPeewTSLI9potNRN
         y7hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=JWFEn51W5QSgLDRAfV6H8GPnCHZeSP4pLG0mUOJDJ0A=;
        b=q4sS5z5NEhky/iaqzhVJBI/rmMoBhs11lCF+mIhWLqcfq6lkVYcsGN7W8vViCTDhQH
         WuZ2bLJ77y5rPGGzOdXo8myVjZkT8dV0R4f1G9T2MXdQsLotzuFhyckui7S2bHwBagWu
         Cva16BXLjhNrIMAN+ZA96mL1LUZRfwhsJqSyvUyp8vP/uU0/4RVTx8XuF6z2mK0BdfOO
         SMLrQImzpiUCei8kD9hW3Y+RmHtdbuQ5myHl3u5yeMvqYL+Oc9zoc1kjFC3oECNQkN0J
         hkLD7s3Wtt48a+SYbTD58NEBpMU23+yDxOrMuDY5OX3YWKx0Gndx/APbxrRI1vx9RtPn
         V4uA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JWFEn51W5QSgLDRAfV6H8GPnCHZeSP4pLG0mUOJDJ0A=;
        b=UOUw13eKxTqUS2zEtTm87HzOXyvLziKoWmfIadhwKDKDvKPv9XnaxiasjmYVvLYzD2
         x2ch36iPHT4tR3BnSqut61uxLj4gcCurUhjkA35IUSEsIHv2v2Ey4gepz8t5nMzz7j7L
         VXYL80Jif+Ax90A71zdEybTiZ0DTtiYugflpbgHt1m/HodDLK8vtX7W86THTroSGoTmm
         wC7GtHSRYob1It8vY6EJQ/MlPS3D9Y7XGU7gqMcOj2JVZ/89/cGGO5K05qO0B+IGXJFc
         1XCHIMEs+ItoFbI9Knqp7gBc9GmMiOZYKlQslYns6k+vGNgwgQEctbri1j2EaRO9h/SH
         s3CA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JWFEn51W5QSgLDRAfV6H8GPnCHZeSP4pLG0mUOJDJ0A=;
        b=qwoMMpnw8o7LDMxPqsriJ4io8NI7s7fBWkMQ9wm9PQAcDxvY+Mwh11NldYX0ruEwDt
         sDf3f5/u0iZRd8TilwLG84zUVIDeFaiO2slDO5HIyKrOCeY5W9UebjVbXvP8DsjMdLjX
         X4e4PtkkCqgEhoBlOs63yO1Qr+EkSxHtzFvBL5xp/kCCd3W9dphEN/9ZAp+5Ct9Sm3oV
         8iMvMxmhoC+vB2ffLxWtIJTIxmPXYIIlP3Kll1Q6WeWp5Ub9tIh59y+OrITy/h1a0sgZ
         opFfNcnOyBRa2A5TTJnavaEY/XckFpkZAvpC1UcPAoiy6BRtkpyQjvLgngsSIQ1BYJpn
         /x2A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9Yb9/gyMTy8aB44OVJy0CIXCzD54gAm7iX0WzM3zjihu6uCDp4
	R32bO+Yz00HUk7uf956qnvA=
X-Google-Smtp-Source: AGRyM1vDaW7/Vc6pRXYVCoM+BkPMqf6A++BRcIpNuUkeWTDN7o3KrK8S3MAlbKoiljYLgYOb17TdeQ==
X-Received: by 2002:a05:651c:246:b0:25a:3420:735d with SMTP id x6-20020a05651c024600b0025a3420735dmr20388294ljn.515.1658420542041;
        Thu, 21 Jul 2022 09:22:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:78f:b0:488:e60f:2057 with SMTP id
 x15-20020a056512078f00b00488e60f2057ls124166lfr.2.-pod-prod-gmail; Thu, 21
 Jul 2022 09:22:20 -0700 (PDT)
X-Received: by 2002:a19:7410:0:b0:48a:735c:33cb with SMTP id v16-20020a197410000000b0048a735c33cbmr825580lfe.186.1658420540607;
        Thu, 21 Jul 2022 09:22:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658420540; cv=none;
        d=google.com; s=arc-20160816;
        b=Ybe5vkLQQPzBExO+8upXdjc2cJ27HvLQvXJHY7s5nMu4DN4gXatMZ9g3p3idLisvuh
         Wc0qNe2d3dViljXKA+kdWruYtWm5tMPvBL166B+Yx8R4+Lge6fy/ThQud+FpWUvJxTHS
         HqiSuBm4tH0hH6rPifkicJUC0/io2XqDVV8cDBhzRoSIERlpgPg3TIsZM5UGtm4Fuyxc
         CC+fnyxWCkkOJRWWI13Pz08nh1juIJQQawRN8wqOWZHmeyV7Kb7B3iTEBmA+C2j2MmeJ
         EQdjF6/R0JshukUlLjmwQnEp5q+RVKPrFw+cR/BqHMiBdbCQlMkZ7Bpy3iEeLYu1B0Vx
         mvNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=MvZ31pgadktkXaKEp8g63S4iD1LbDvfVpg3VY8w1dLk=;
        b=Rnz+ib3u8xKNWpcWmpQv+2fFD2qPpuHNRzAMBdP//HXOrMR6Hqf2vLqGqkbnnEj2Xb
         qayTOOlmlxtqVPNkCM8rcwMWDOrVsIL6vnd5IWMcx4E1GzyauYPCY4DzucNiaZzMamRm
         00kGjoTHOH0OG8M/h9E+V3Jzox0qFkbmEFQ3gY4Ir/uZ/gaDiBMdtgazuQM4lc0UXn2t
         eah7eGxXJFZXo9WKV1h6slocCbLW/csWhW6Ia+18kLHzruSpf+OicGcAXrDysRChFjNo
         /dpt3f4gHTIxWcujp0SyBz7A/L2VazMbGVI+bLyumsDjzhgBvgOPMGFC5GNkojgjgJgG
         cmfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z3-20020a05651c11c300b0025d8f98aed4si100110ljo.8.2022.07.21.09.22.20
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jul 2022 09:22:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9F57B13D5;
	Thu, 21 Jul 2022 09:22:19 -0700 (PDT)
Received: from FVFF77S0Q05N.cambridge.arm.com (FVFF77S0Q05N.cambridge.arm.com [10.1.34.166])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id CAA2A3F766;
	Thu, 21 Jul 2022 09:22:16 -0700 (PDT)
Date: Thu, 21 Jul 2022 17:22:07 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	linuxppc-dev@lists.ozlabs.org, linux-perf-users@vger.kernel.org,
	x86@kernel.org, linux-sh@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Will Deacon <will@kernel.org>
Subject: Re: [PATCH v3 01/14] perf/hw_breakpoint: Add KUnit test for
 constraints accounting
Message-ID: <Ytl9L0Zn1PVuL1cB@FVFF77S0Q05N.cambridge.arm.com>
References: <20220704150514.48816-1-elver@google.com>
 <20220704150514.48816-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220704150514.48816-2-elver@google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Marco,

[adding Will]

On Mon, Jul 04, 2022 at 05:05:01PM +0200, Marco Elver wrote:
> Add KUnit test for hw_breakpoint constraints accounting, with various
> interesting mixes of breakpoint targets (some care was taken to catch
> interesting corner cases via bug-injection).
> 
> The test cannot be built as a module because it requires access to
> hw_breakpoint_slots(), which is not inlinable or exported on all
> architectures.
> 
> Signed-off-by: Marco Elver <elver@google.com>

As mentioned on IRC, I'm seeing these tests fail on arm64 when applied atop
v5.19-rc7:

| TAP version 14
| 1..1
|     # Subtest: hw_breakpoint
|     1..9
|     ok 1 - test_one_cpu
|     ok 2 - test_many_cpus
|     # test_one_task_on_all_cpus: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
|     Expected IS_ERR(bp) to be false, but is true
|     not ok 3 - test_one_task_on_all_cpus
|     # test_two_tasks_on_all_cpus: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
|     Expected IS_ERR(bp) to be false, but is true
|     not ok 4 - test_two_tasks_on_all_cpus
|     # test_one_task_on_one_cpu: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
|     Expected IS_ERR(bp) to be false, but is true
|     not ok 5 - test_one_task_on_one_cpu
|     # test_one_task_mixed: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
|     Expected IS_ERR(bp) to be false, but is true
|     not ok 6 - test_one_task_mixed
|     # test_two_tasks_on_one_cpu: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
|     Expected IS_ERR(bp) to be false, but is true
|     not ok 7 - test_two_tasks_on_one_cpu
|     # test_two_tasks_on_one_all_cpus: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
|     Expected IS_ERR(bp) to be false, but is true
|     not ok 8 - test_two_tasks_on_one_all_cpus
|     # test_task_on_all_and_one_cpu: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
|     Expected IS_ERR(bp) to be false, but is true
|     not ok 9 - test_task_on_all_and_one_cpu
| # hw_breakpoint: pass:2 fail:7 skip:0 total:9
| # Totals: pass:2 fail:7 skip:0 total:9

... which seems to be becasue arm64 currently forbids per-task
breakpoints/watchpoints in hw_breakpoint_arch_parse(), where we have:

        /*
         * Disallow per-task kernel breakpoints since these would
         * complicate the stepping code.
         */
        if (hw->ctrl.privilege == AARCH64_BREAKPOINT_EL1 && bp->hw.target)
                return -EINVAL;

... which has been the case since day one in commit:

  478fcb2cdb2351dc ("arm64: Debugging support")

I'm not immediately sure what would be necessary to support per-task kernel
breakpoints, but given a lot of that state is currently per-cpu, I imagine it's
invasive.

Mark.

> ---
> v3:
> * Don't use raw_smp_processor_id().
> 
> v2:
> * New patch.
> ---
>  kernel/events/Makefile             |   1 +
>  kernel/events/hw_breakpoint_test.c | 323 +++++++++++++++++++++++++++++
>  lib/Kconfig.debug                  |  10 +
>  3 files changed, 334 insertions(+)
>  create mode 100644 kernel/events/hw_breakpoint_test.c
> 
> diff --git a/kernel/events/Makefile b/kernel/events/Makefile
> index 8591c180b52b..91a62f566743 100644
> --- a/kernel/events/Makefile
> +++ b/kernel/events/Makefile
> @@ -2,4 +2,5 @@
>  obj-y := core.o ring_buffer.o callchain.o
>  
>  obj-$(CONFIG_HAVE_HW_BREAKPOINT) += hw_breakpoint.o
> +obj-$(CONFIG_HW_BREAKPOINT_KUNIT_TEST) += hw_breakpoint_test.o
>  obj-$(CONFIG_UPROBES) += uprobes.o
> diff --git a/kernel/events/hw_breakpoint_test.c b/kernel/events/hw_breakpoint_test.c
> new file mode 100644
> index 000000000000..433c5c45e2a5
> --- /dev/null
> +++ b/kernel/events/hw_breakpoint_test.c
> @@ -0,0 +1,323 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * KUnit test for hw_breakpoint constraints accounting logic.
> + *
> + * Copyright (C) 2022, Google LLC.
> + */
> +
> +#include <kunit/test.h>
> +#include <linux/cpumask.h>
> +#include <linux/hw_breakpoint.h>
> +#include <linux/kthread.h>
> +#include <linux/perf_event.h>
> +#include <asm/hw_breakpoint.h>
> +
> +#define TEST_REQUIRES_BP_SLOTS(test, slots)						\
> +	do {										\
> +		if ((slots) > get_test_bp_slots()) {					\
> +			kunit_skip((test), "Requires breakpoint slots: %d > %d", slots,	\
> +				   get_test_bp_slots());				\
> +		}									\
> +	} while (0)
> +
> +#define TEST_EXPECT_NOSPC(expr) KUNIT_EXPECT_EQ(test, -ENOSPC, PTR_ERR(expr))
> +
> +#define MAX_TEST_BREAKPOINTS 512
> +
> +static char break_vars[MAX_TEST_BREAKPOINTS];
> +static struct perf_event *test_bps[MAX_TEST_BREAKPOINTS];
> +static struct task_struct *__other_task;
> +
> +static struct perf_event *register_test_bp(int cpu, struct task_struct *tsk, int idx)
> +{
> +	struct perf_event_attr attr = {};
> +
> +	if (WARN_ON(idx < 0 || idx >= MAX_TEST_BREAKPOINTS))
> +		return NULL;
> +
> +	hw_breakpoint_init(&attr);
> +	attr.bp_addr = (unsigned long)&break_vars[idx];
> +	attr.bp_len = HW_BREAKPOINT_LEN_1;
> +	attr.bp_type = HW_BREAKPOINT_RW;
> +	return perf_event_create_kernel_counter(&attr, cpu, tsk, NULL, NULL);
> +}
> +
> +static void unregister_test_bp(struct perf_event **bp)
> +{
> +	if (WARN_ON(IS_ERR(*bp)))
> +		return;
> +	if (WARN_ON(!*bp))
> +		return;
> +	unregister_hw_breakpoint(*bp);
> +	*bp = NULL;
> +}
> +
> +static int get_test_bp_slots(void)
> +{
> +	static int slots;
> +
> +	if (!slots)
> +		slots = hw_breakpoint_slots(TYPE_DATA);
> +
> +	return slots;
> +}
> +
> +static void fill_one_bp_slot(struct kunit *test, int *id, int cpu, struct task_struct *tsk)
> +{
> +	struct perf_event *bp = register_test_bp(cpu, tsk, *id);
> +
> +	KUNIT_ASSERT_NOT_NULL(test, bp);
> +	KUNIT_ASSERT_FALSE(test, IS_ERR(bp));
> +	KUNIT_ASSERT_NULL(test, test_bps[*id]);
> +	test_bps[(*id)++] = bp;
> +}
> +
> +/*
> + * Fills up the given @cpu/@tsk with breakpoints, only leaving @skip slots free.
> + *
> + * Returns true if this can be called again, continuing at @id.
> + */
> +static bool fill_bp_slots(struct kunit *test, int *id, int cpu, struct task_struct *tsk, int skip)
> +{
> +	for (int i = 0; i < get_test_bp_slots() - skip; ++i)
> +		fill_one_bp_slot(test, id, cpu, tsk);
> +
> +	return *id + get_test_bp_slots() <= MAX_TEST_BREAKPOINTS;
> +}
> +
> +static int dummy_kthread(void *arg)
> +{
> +	return 0;
> +}
> +
> +static struct task_struct *get_other_task(struct kunit *test)
> +{
> +	struct task_struct *tsk;
> +
> +	if (__other_task)
> +		return __other_task;
> +
> +	tsk = kthread_create(dummy_kthread, NULL, "hw_breakpoint_dummy_task");
> +	KUNIT_ASSERT_FALSE(test, IS_ERR(tsk));
> +	__other_task = tsk;
> +	return __other_task;
> +}
> +
> +static int get_test_cpu(int num)
> +{
> +	int cpu;
> +
> +	WARN_ON(num < 0);
> +
> +	for_each_online_cpu(cpu) {
> +		if (num-- <= 0)
> +			break;
> +	}
> +
> +	return cpu;
> +}
> +
> +/* ===== Test cases ===== */
> +
> +static void test_one_cpu(struct kunit *test)
> +{
> +	int idx = 0;
> +
> +	fill_bp_slots(test, &idx, get_test_cpu(0), NULL, 0);
> +	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +}
> +
> +static void test_many_cpus(struct kunit *test)
> +{
> +	int idx = 0;
> +	int cpu;
> +
> +	/* Test that CPUs are independent. */
> +	for_each_online_cpu(cpu) {
> +		bool do_continue = fill_bp_slots(test, &idx, cpu, NULL, 0);
> +
> +		TEST_EXPECT_NOSPC(register_test_bp(cpu, NULL, idx));
> +		if (!do_continue)
> +			break;
> +	}
> +}
> +
> +static void test_one_task_on_all_cpus(struct kunit *test)
> +{
> +	int idx = 0;
> +
> +	fill_bp_slots(test, &idx, -1, current, 0);
> +	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +	/* Remove one and adding back CPU-target should work. */
> +	unregister_test_bp(&test_bps[0]);
> +	fill_one_bp_slot(test, &idx, get_test_cpu(0), NULL);
> +}
> +
> +static void test_two_tasks_on_all_cpus(struct kunit *test)
> +{
> +	int idx = 0;
> +
> +	/* Test that tasks are independent. */
> +	fill_bp_slots(test, &idx, -1, current, 0);
> +	fill_bp_slots(test, &idx, -1, get_other_task(test), 0);
> +
> +	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(-1, get_other_task(test), idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), get_other_task(test), idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +	/* Remove one from first task and adding back CPU-target should not work. */
> +	unregister_test_bp(&test_bps[0]);
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +}
> +
> +static void test_one_task_on_one_cpu(struct kunit *test)
> +{
> +	int idx = 0;
> +
> +	fill_bp_slots(test, &idx, get_test_cpu(0), current, 0);
> +	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +	/*
> +	 * Remove one and adding back CPU-target should work; this case is
> +	 * special vs. above because the task's constraints are CPU-dependent.
> +	 */
> +	unregister_test_bp(&test_bps[0]);
> +	fill_one_bp_slot(test, &idx, get_test_cpu(0), NULL);
> +}
> +
> +static void test_one_task_mixed(struct kunit *test)
> +{
> +	int idx = 0;
> +
> +	TEST_REQUIRES_BP_SLOTS(test, 3);
> +
> +	fill_one_bp_slot(test, &idx, get_test_cpu(0), current);
> +	fill_bp_slots(test, &idx, -1, current, 1);
> +	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +
> +	/* Transition from CPU-dependent pinned count to CPU-independent. */
> +	unregister_test_bp(&test_bps[0]);
> +	unregister_test_bp(&test_bps[1]);
> +	fill_one_bp_slot(test, &idx, get_test_cpu(0), NULL);
> +	fill_one_bp_slot(test, &idx, get_test_cpu(0), NULL);
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +}
> +
> +static void test_two_tasks_on_one_cpu(struct kunit *test)
> +{
> +	int idx = 0;
> +
> +	fill_bp_slots(test, &idx, get_test_cpu(0), current, 0);
> +	fill_bp_slots(test, &idx, get_test_cpu(0), get_other_task(test), 0);
> +
> +	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(-1, get_other_task(test), idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), get_other_task(test), idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +	/* Can still create breakpoints on some other CPU. */
> +	fill_bp_slots(test, &idx, get_test_cpu(1), NULL, 0);
> +}
> +
> +static void test_two_tasks_on_one_all_cpus(struct kunit *test)
> +{
> +	int idx = 0;
> +
> +	fill_bp_slots(test, &idx, get_test_cpu(0), current, 0);
> +	fill_bp_slots(test, &idx, -1, get_other_task(test), 0);
> +
> +	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(-1, get_other_task(test), idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), get_other_task(test), idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +	/* Cannot create breakpoints on some other CPU either. */
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(1), NULL, idx));
> +}
> +
> +static void test_task_on_all_and_one_cpu(struct kunit *test)
> +{
> +	int tsk_on_cpu_idx, cpu_idx;
> +	int idx = 0;
> +
> +	TEST_REQUIRES_BP_SLOTS(test, 3);
> +
> +	fill_bp_slots(test, &idx, -1, current, 2);
> +	/* Transitioning from only all CPU breakpoints to mixed. */
> +	tsk_on_cpu_idx = idx;
> +	fill_one_bp_slot(test, &idx, get_test_cpu(0), current);
> +	fill_one_bp_slot(test, &idx, -1, current);
> +
> +	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +
> +	/* We should still be able to use up another CPU's slots. */
> +	cpu_idx = idx;
> +	fill_one_bp_slot(test, &idx, get_test_cpu(1), NULL);
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(1), NULL, idx));
> +
> +	/* Transitioning back to task target on all CPUs. */
> +	unregister_test_bp(&test_bps[tsk_on_cpu_idx]);
> +	/* Still have a CPU target breakpoint in get_test_cpu(1). */
> +	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +	/* Remove it and try again. */
> +	unregister_test_bp(&test_bps[cpu_idx]);
> +	fill_one_bp_slot(test, &idx, -1, current);
> +
> +	TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +	TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(1), NULL, idx));
> +}
> +
> +static struct kunit_case hw_breakpoint_test_cases[] = {
> +	KUNIT_CASE(test_one_cpu),
> +	KUNIT_CASE(test_many_cpus),
> +	KUNIT_CASE(test_one_task_on_all_cpus),
> +	KUNIT_CASE(test_two_tasks_on_all_cpus),
> +	KUNIT_CASE(test_one_task_on_one_cpu),
> +	KUNIT_CASE(test_one_task_mixed),
> +	KUNIT_CASE(test_two_tasks_on_one_cpu),
> +	KUNIT_CASE(test_two_tasks_on_one_all_cpus),
> +	KUNIT_CASE(test_task_on_all_and_one_cpu),
> +	{},
> +};
> +
> +static int test_init(struct kunit *test)
> +{
> +	/* Most test cases want 2 distinct CPUs. */
> +	return num_online_cpus() < 2 ? -EINVAL : 0;
> +}
> +
> +static void test_exit(struct kunit *test)
> +{
> +	for (int i = 0; i < MAX_TEST_BREAKPOINTS; ++i) {
> +		if (test_bps[i])
> +			unregister_test_bp(&test_bps[i]);
> +	}
> +
> +	if (__other_task) {
> +		kthread_stop(__other_task);
> +		__other_task = NULL;
> +	}
> +}
> +
> +static struct kunit_suite hw_breakpoint_test_suite = {
> +	.name = "hw_breakpoint",
> +	.test_cases = hw_breakpoint_test_cases,
> +	.init = test_init,
> +	.exit = test_exit,
> +};
> +
> +kunit_test_suites(&hw_breakpoint_test_suite);
> +
> +MODULE_LICENSE("GPL");
> +MODULE_AUTHOR("Marco Elver <elver@google.com>");
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index 2e24db4bff19..4c87a6edf046 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -2513,6 +2513,16 @@ config STACKINIT_KUNIT_TEST
>  	  CONFIG_GCC_PLUGIN_STRUCTLEAK, CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF,
>  	  or CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL.
>  
> +config HW_BREAKPOINT_KUNIT_TEST
> +	bool "Test hw_breakpoint constraints accounting" if !KUNIT_ALL_TESTS
> +	depends on HAVE_HW_BREAKPOINT
> +	depends on KUNIT=y
> +	default KUNIT_ALL_TESTS
> +	help
> +	  Tests for hw_breakpoint constraints accounting.
> +
> +	  If unsure, say N.
> +
>  config TEST_UDELAY
>  	tristate "udelay test driver"
>  	help
> -- 
> 2.37.0.rc0.161.g10f37bed90-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ytl9L0Zn1PVuL1cB%40FVFF77S0Q05N.cambridge.arm.com.
