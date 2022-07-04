Return-Path: <kasan-dev+bncBCMIZB7QWENRBXMFRSLAMGQEUKV4KMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BB47565980
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 17:10:22 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id v123-20020a1cac81000000b003a02a3f0beesf3120062wme.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 08:10:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656947422; cv=pass;
        d=google.com; s=arc-20160816;
        b=jxEhX1COuxSKnvxqN4NxaU8S+J+rieVDfOTiCY2IUp6V2MtVKIYKqBgBngygiROip6
         M+FdEx5hP+KFI9rbnEoUd17S3nVYq6s6INKdDQ/V1PFLNNJIMdqOPO8q6SrG1Xqjytil
         AY08gMzaaWkP2Uo2IPcamCrq9l/SBjZJ6arqcr6Q9s03uYw5WE/H4A9lP4HFO2e8B7lQ
         1TD+Gy2SkrKPlKRQB3c0wazbwy3sentRYcIyquN/62etY4idUN/NOEF+pTXY+GVt7CSK
         ggNBfYM9C+XsZAG6B9afeuzw3ngB4Os9pNtF8IKnooXIR2uwUKv+qyA7QFoHQ1AbXfyZ
         W4vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GivPBMeK3VKM390hVmLJfnx44JnzckCE7i0/MmYKLGc=;
        b=zy4HIzZtLxjl05ONAxCNk+dc9Cbri12TjMHSOoJrTduZxjMn12YH9HQUGKnpUN0VSq
         ydVlhvJywJXSFSrwnJc21G5NUMEmLuoeCvnxBlXViyCbST5M74l8y9+JEsf2EpleId4O
         vhQpAFEgxv1n/Hoc8sCc3uUUy0dVWOObGnEb3Ylol98qz6qqzrRP59vA2rAdtbYV+a/P
         T1rgDCFWWi6Z3gHWPBqVnNTKpecNwxLRkjwH/GjqCMVbpHRmn8wZIg8QF/2i6RHx2aqo
         stG7Bf2QCCO61jBJNwo9UwlJ0yDeJqSKkPSIcIAslAAO9aBkqOlmoWmW1N9O7IjLvCHN
         23ZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EGhlAFrH;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GivPBMeK3VKM390hVmLJfnx44JnzckCE7i0/MmYKLGc=;
        b=ZSWf80AIIiMldXo4Xux0J0br2n88KU7NVa1RanaX1EPKcjfwUabsy1pRVYuOYad+3s
         uJF/Pb67KSgikdaTgak5GS/JfNAH1Ao04obJZO9BVO8SCxozFCw8Ns6UK2ws96mxEChD
         FYwAokYjYifO+tykVTuPb8Jj5lMVadP9VpgWw5fiIOetAjI/M+IIYsWzuRQa8Z1mnFnK
         GLCUv2DzYL5a03PFnORXb26qwNLehxy7N8jlIGJmALTAwfKycqpqupET5FHssb5WZ1Vc
         Q8DVmtBNEHZHGsJIFC47O/5UmUvkkzmElVPMIPU7j7KtfeAv6j4cTVXKCjck00bvSxIX
         7xjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GivPBMeK3VKM390hVmLJfnx44JnzckCE7i0/MmYKLGc=;
        b=gliOq/jhjcsYtUkg4luoIdlOXxbilagIP17KkdEwhHugUfu5YW4uYWud0YLEReQlLn
         YzB+zID0vWbfhZzkqQTSpON/lOM+O6IO6grprdXy4KIuKShfn97zOZs5Ed2EJZvISsOj
         BmJ3kHy0+vexyW8q/8OT5wbfesPr/QwJYg98dss1MywtCdAwCGUXkiYT2CabXX4TXJ0y
         olLSJLRqZHoIwlASJ82uShOBbambHSEqYnGUQPyvsTpHh1+t0DbOi6y6LsxHnIJj5S0r
         xZ5H7PJQAvhAVAfivP88IGvXTGNTvm4xtjf+QNQ74RCjzPx7c0w6NXBQj271NteKH5pX
         lllg==
X-Gm-Message-State: AJIora8zb2k7S+fQxotZHgifciNzVSemJXtFVyWv5H9VNNtNOidTHxU7
	urtNm/SKriICS5+OPU4+drU=
X-Google-Smtp-Source: AGRyM1v7sHCp6Z25pPS5H/RDjaWOSa7Tg7xZkFAJBUAX8VIxdSWuvHAe7VA4Bx1mM0rvOpKiZ/b6PA==
X-Received: by 2002:a05:600c:5014:b0:3a0:4867:d234 with SMTP id n20-20020a05600c501400b003a04867d234mr30992465wmr.35.1656947422103;
        Mon, 04 Jul 2022 08:10:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:184a:b0:21d:2802:2675 with SMTP id
 c10-20020a056000184a00b0021d28022675ls23008926wri.1.gmail; Mon, 04 Jul 2022
 08:10:21 -0700 (PDT)
X-Received: by 2002:adf:fa84:0:b0:21b:9668:4148 with SMTP id h4-20020adffa84000000b0021b96684148mr27801304wrr.398.1656947421231;
        Mon, 04 Jul 2022 08:10:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656947421; cv=none;
        d=google.com; s=arc-20160816;
        b=XYgqODsmT5xLwwtLpHazlvBG3b4sjWTXeYrbPk5WrmD2XS704CBjnho3L+zrerxwOV
         2wCYGnOl3IGuxhdxMXAKpWaamrrFeTyHtl2oJvYa6EpGmA2oBxEPAguxZsIPCIqcI/WO
         sMll/abkI3zKO1gy9qbVtv6OiHLA+hbnlH2Cmf357/yBI+z+lGW+zWx/lmAmEkoJEKQ0
         Eh8Dea3IkRBvyDyvvXf7L/H5TgqZq+Ne1myznWnLXgSMXOUIf8oa4UhoSx74a8onBzjS
         9MP9JNV/DbZ3myTRHOUlRF3D6fOTA0Ll72wvfwSdFUKaamvGomK0TNUpJ7d2YYy60/f7
         UN8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=L/r42YfcYvrG556t3Zy5OHgKS1LSmaAIBUOTsb6/fKw=;
        b=tahmBttbBi4b0V9/GxzHXhbiB5kb3WYcn+frOxPLHijAnFvuOkMl54R28J4WcOqWr3
         919Tv3GDFRxMZPklaejQWEfVtKTw4Md0/B0Qb7SgB15fupKWEcptn+tcVHZ5lLvXQmOF
         OiOHi4wv47Dvp0TCLI0LsrASu6Wk8ivE9JjgWeO40Q2OjmOw9bhCO/vSS7u2sfrKqRig
         B5POvk4RN/8RSfrsfHy9qNQ5hf3nLio9uE0dL5ZHWVdLeWaXsxVWnC7tgMIiX2D5Eguh
         u9wdb9NIzwmYVQTJthMOLvql4N9piQ09QJervG7kRWGmn1geDEIGkKbapVHwG2akyM3m
         u8Tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EGhlAFrH;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id r68-20020a1c2b47000000b003a19123bf95si361452wmr.2.2022.07.04.08.10.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 08:10:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id t25so16266761lfg.7
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 08:10:21 -0700 (PDT)
X-Received: by 2002:ac2:4906:0:b0:47f:6c71:6de5 with SMTP id
 n6-20020ac24906000000b0047f6c716de5mr20311086lfi.137.1656947420719; Mon, 04
 Jul 2022 08:10:20 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-2-elver@google.com>
In-Reply-To: <20220704150514.48816-2-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 4 Jul 2022 17:10:09 +0200
Message-ID: <CACT4Y+aA7QkAsufv6EMQ1O8mZaVd-eNOqRrx2a7qvPR4Tt=izA@mail.gmail.com>
Subject: Re: [PATCH v3 01/14] perf/hw_breakpoint: Add KUnit test for
 constraints accounting
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=EGhlAFrH;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::133
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 4 Jul 2022 at 17:06, Marco Elver <elver@google.com> wrote:
>
> Add KUnit test for hw_breakpoint constraints accounting, with various
> interesting mixes of breakpoint targets (some care was taken to catch
> interesting corner cases via bug-injection).
>
> The test cannot be built as a module because it requires access to
> hw_breakpoint_slots(), which is not inlinable or exported on all
> architectures.
>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

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
> +#define TEST_REQUIRES_BP_SLOTS(test, slots)                                            \
> +       do {                                                                            \
> +               if ((slots) > get_test_bp_slots()) {                                    \
> +                       kunit_skip((test), "Requires breakpoint slots: %d > %d", slots, \
> +                                  get_test_bp_slots());                                \
> +               }                                                                       \
> +       } while (0)
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
> +       struct perf_event_attr attr = {};
> +
> +       if (WARN_ON(idx < 0 || idx >= MAX_TEST_BREAKPOINTS))
> +               return NULL;
> +
> +       hw_breakpoint_init(&attr);
> +       attr.bp_addr = (unsigned long)&break_vars[idx];
> +       attr.bp_len = HW_BREAKPOINT_LEN_1;
> +       attr.bp_type = HW_BREAKPOINT_RW;
> +       return perf_event_create_kernel_counter(&attr, cpu, tsk, NULL, NULL);
> +}
> +
> +static void unregister_test_bp(struct perf_event **bp)
> +{
> +       if (WARN_ON(IS_ERR(*bp)))
> +               return;
> +       if (WARN_ON(!*bp))
> +               return;
> +       unregister_hw_breakpoint(*bp);
> +       *bp = NULL;
> +}
> +
> +static int get_test_bp_slots(void)
> +{
> +       static int slots;
> +
> +       if (!slots)
> +               slots = hw_breakpoint_slots(TYPE_DATA);
> +
> +       return slots;
> +}
> +
> +static void fill_one_bp_slot(struct kunit *test, int *id, int cpu, struct task_struct *tsk)
> +{
> +       struct perf_event *bp = register_test_bp(cpu, tsk, *id);
> +
> +       KUNIT_ASSERT_NOT_NULL(test, bp);
> +       KUNIT_ASSERT_FALSE(test, IS_ERR(bp));
> +       KUNIT_ASSERT_NULL(test, test_bps[*id]);
> +       test_bps[(*id)++] = bp;
> +}
> +
> +/*
> + * Fills up the given @cpu/@tsk with breakpoints, only leaving @skip slots free.
> + *
> + * Returns true if this can be called again, continuing at @id.
> + */
> +static bool fill_bp_slots(struct kunit *test, int *id, int cpu, struct task_struct *tsk, int skip)
> +{
> +       for (int i = 0; i < get_test_bp_slots() - skip; ++i)
> +               fill_one_bp_slot(test, id, cpu, tsk);
> +
> +       return *id + get_test_bp_slots() <= MAX_TEST_BREAKPOINTS;
> +}
> +
> +static int dummy_kthread(void *arg)
> +{
> +       return 0;
> +}
> +
> +static struct task_struct *get_other_task(struct kunit *test)
> +{
> +       struct task_struct *tsk;
> +
> +       if (__other_task)
> +               return __other_task;
> +
> +       tsk = kthread_create(dummy_kthread, NULL, "hw_breakpoint_dummy_task");
> +       KUNIT_ASSERT_FALSE(test, IS_ERR(tsk));
> +       __other_task = tsk;
> +       return __other_task;
> +}
> +
> +static int get_test_cpu(int num)
> +{
> +       int cpu;
> +
> +       WARN_ON(num < 0);
> +
> +       for_each_online_cpu(cpu) {
> +               if (num-- <= 0)
> +                       break;
> +       }
> +
> +       return cpu;
> +}
> +
> +/* ===== Test cases ===== */
> +
> +static void test_one_cpu(struct kunit *test)
> +{
> +       int idx = 0;
> +
> +       fill_bp_slots(test, &idx, get_test_cpu(0), NULL, 0);
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +}
> +
> +static void test_many_cpus(struct kunit *test)
> +{
> +       int idx = 0;
> +       int cpu;
> +
> +       /* Test that CPUs are independent. */
> +       for_each_online_cpu(cpu) {
> +               bool do_continue = fill_bp_slots(test, &idx, cpu, NULL, 0);
> +
> +               TEST_EXPECT_NOSPC(register_test_bp(cpu, NULL, idx));
> +               if (!do_continue)
> +                       break;
> +       }
> +}
> +
> +static void test_one_task_on_all_cpus(struct kunit *test)
> +{
> +       int idx = 0;
> +
> +       fill_bp_slots(test, &idx, -1, current, 0);
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +       /* Remove one and adding back CPU-target should work. */
> +       unregister_test_bp(&test_bps[0]);
> +       fill_one_bp_slot(test, &idx, get_test_cpu(0), NULL);
> +}
> +
> +static void test_two_tasks_on_all_cpus(struct kunit *test)
> +{
> +       int idx = 0;
> +
> +       /* Test that tasks are independent. */
> +       fill_bp_slots(test, &idx, -1, current, 0);
> +       fill_bp_slots(test, &idx, -1, get_other_task(test), 0);
> +
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, get_other_task(test), idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), get_other_task(test), idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +       /* Remove one from first task and adding back CPU-target should not work. */
> +       unregister_test_bp(&test_bps[0]);
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +}
> +
> +static void test_one_task_on_one_cpu(struct kunit *test)
> +{
> +       int idx = 0;
> +
> +       fill_bp_slots(test, &idx, get_test_cpu(0), current, 0);
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +       /*
> +        * Remove one and adding back CPU-target should work; this case is
> +        * special vs. above because the task's constraints are CPU-dependent.
> +        */
> +       unregister_test_bp(&test_bps[0]);
> +       fill_one_bp_slot(test, &idx, get_test_cpu(0), NULL);
> +}
> +
> +static void test_one_task_mixed(struct kunit *test)
> +{
> +       int idx = 0;
> +
> +       TEST_REQUIRES_BP_SLOTS(test, 3);
> +
> +       fill_one_bp_slot(test, &idx, get_test_cpu(0), current);
> +       fill_bp_slots(test, &idx, -1, current, 1);
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +
> +       /* Transition from CPU-dependent pinned count to CPU-independent. */
> +       unregister_test_bp(&test_bps[0]);
> +       unregister_test_bp(&test_bps[1]);
> +       fill_one_bp_slot(test, &idx, get_test_cpu(0), NULL);
> +       fill_one_bp_slot(test, &idx, get_test_cpu(0), NULL);
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +}
> +
> +static void test_two_tasks_on_one_cpu(struct kunit *test)
> +{
> +       int idx = 0;
> +
> +       fill_bp_slots(test, &idx, get_test_cpu(0), current, 0);
> +       fill_bp_slots(test, &idx, get_test_cpu(0), get_other_task(test), 0);
> +
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, get_other_task(test), idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), get_other_task(test), idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +       /* Can still create breakpoints on some other CPU. */
> +       fill_bp_slots(test, &idx, get_test_cpu(1), NULL, 0);
> +}
> +
> +static void test_two_tasks_on_one_all_cpus(struct kunit *test)
> +{
> +       int idx = 0;
> +
> +       fill_bp_slots(test, &idx, get_test_cpu(0), current, 0);
> +       fill_bp_slots(test, &idx, -1, get_other_task(test), 0);
> +
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, get_other_task(test), idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), get_other_task(test), idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +       /* Cannot create breakpoints on some other CPU either. */
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(1), NULL, idx));
> +}
> +
> +static void test_task_on_all_and_one_cpu(struct kunit *test)
> +{
> +       int tsk_on_cpu_idx, cpu_idx;
> +       int idx = 0;
> +
> +       TEST_REQUIRES_BP_SLOTS(test, 3);
> +
> +       fill_bp_slots(test, &idx, -1, current, 2);
> +       /* Transitioning from only all CPU breakpoints to mixed. */
> +       tsk_on_cpu_idx = idx;
> +       fill_one_bp_slot(test, &idx, get_test_cpu(0), current);
> +       fill_one_bp_slot(test, &idx, -1, current);
> +
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +
> +       /* We should still be able to use up another CPU's slots. */
> +       cpu_idx = idx;
> +       fill_one_bp_slot(test, &idx, get_test_cpu(1), NULL);
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(1), NULL, idx));
> +
> +       /* Transitioning back to task target on all CPUs. */
> +       unregister_test_bp(&test_bps[tsk_on_cpu_idx]);
> +       /* Still have a CPU target breakpoint in get_test_cpu(1). */
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +       /* Remove it and try again. */
> +       unregister_test_bp(&test_bps[cpu_idx]);
> +       fill_one_bp_slot(test, &idx, -1, current);
> +
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(1), NULL, idx));
> +}
> +
> +static struct kunit_case hw_breakpoint_test_cases[] = {
> +       KUNIT_CASE(test_one_cpu),
> +       KUNIT_CASE(test_many_cpus),
> +       KUNIT_CASE(test_one_task_on_all_cpus),
> +       KUNIT_CASE(test_two_tasks_on_all_cpus),
> +       KUNIT_CASE(test_one_task_on_one_cpu),
> +       KUNIT_CASE(test_one_task_mixed),
> +       KUNIT_CASE(test_two_tasks_on_one_cpu),
> +       KUNIT_CASE(test_two_tasks_on_one_all_cpus),
> +       KUNIT_CASE(test_task_on_all_and_one_cpu),
> +       {},
> +};
> +
> +static int test_init(struct kunit *test)
> +{
> +       /* Most test cases want 2 distinct CPUs. */
> +       return num_online_cpus() < 2 ? -EINVAL : 0;
> +}
> +
> +static void test_exit(struct kunit *test)
> +{
> +       for (int i = 0; i < MAX_TEST_BREAKPOINTS; ++i) {
> +               if (test_bps[i])
> +                       unregister_test_bp(&test_bps[i]);
> +       }
> +
> +       if (__other_task) {
> +               kthread_stop(__other_task);
> +               __other_task = NULL;
> +       }
> +}
> +
> +static struct kunit_suite hw_breakpoint_test_suite = {
> +       .name = "hw_breakpoint",
> +       .test_cases = hw_breakpoint_test_cases,
> +       .init = test_init,
> +       .exit = test_exit,
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
>           CONFIG_GCC_PLUGIN_STRUCTLEAK, CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF,
>           or CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL.
>
> +config HW_BREAKPOINT_KUNIT_TEST
> +       bool "Test hw_breakpoint constraints accounting" if !KUNIT_ALL_TESTS
> +       depends on HAVE_HW_BREAKPOINT
> +       depends on KUNIT=y
> +       default KUNIT_ALL_TESTS
> +       help
> +         Tests for hw_breakpoint constraints accounting.
> +
> +         If unsure, say N.
> +
>  config TEST_UDELAY
>         tristate "udelay test driver"
>         help
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaA7QkAsufv6EMQ1O8mZaVd-eNOqRrx2a7qvPR4Tt%3DizA%40mail.gmail.com.
