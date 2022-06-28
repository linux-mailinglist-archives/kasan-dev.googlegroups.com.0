Return-Path: <kasan-dev+bncBCMIZB7QWENRBT7T5OKQMGQECUU3WWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B55055C70D
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 14:53:36 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id bp15-20020a056512158f00b0047f603e5f92sf6181775lfb.20
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 05:53:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656420816; cv=pass;
        d=google.com; s=arc-20160816;
        b=ABexReF49S+HzdHFl9TCMUFDb6j1gyqvIedcnblVCUBM9IYPpJRb6AfRYB8zd9p7Xb
         pTgzttDAiUhc5rgiBIycAiWjpKNzeRroYwyO2x5sB/fPcsCFRH/Jxj5yTYT/iC2sOWZ5
         pekAa788vKsr8h1+zle2Os7hNpDW1uR4MmW1x23+qmavXmZA1EUEoiclOWi+TRK/+393
         BUsYjABbwp0BUFaScjVvNA10qb0NC7cb/3rNC02FUYIehNIMRihLRPtNJtEH5bsY1p/c
         31YxF+r37Bb/X6aj2iRuq478c2lGeAOF8akf/Db1sNUzqs2ZEIsaa/3O9xEnD/QCDewF
         09iA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AIKa/eUBi5zcUcxGR39w7UBjnU6WkKCnQF3gp9bOzV0=;
        b=Q5S8zK6lZ9M62QBxGUNPwKsA6w3nP4oRqvHlxsJBO+Bl08YMMIh8h4dA5fNMFbp+R6
         XoZgqO/VcaqMbyPSKIV9mpG9S94OWpDVB/Tq0dMm5PI/hw76KSUCeqKGhPWZZOSwdNGt
         bOJ+bD7eM5JTUVMRA354FvjFX6ffMmjisCwkvd1zdPdMMBD9g1HWKNN9wqC47bInsliT
         TsUeJ72Fymut8sZPr9KY/HprXa0BkmpUhQGSbrD6lQySSgJn4gUsgTkBagsBlVG9tEA1
         66eTtUMFchA0AJNhApR21TYSqreatQ1eTrQHMpzepsjfvL7/tM4MFM07T4q/1TaTIhUG
         y1zQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="O/eDFTpZ";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AIKa/eUBi5zcUcxGR39w7UBjnU6WkKCnQF3gp9bOzV0=;
        b=O2wDs1iVVnYPqBBb3VwNGyaZX35iyHzj118pmP3qZBEDlBHH46Hj8XI1/mnXji5YFd
         dC1qa9geB+C+Q2UBymlRkBX8unzfKdLgBCkoMkoU2ieLF+mjDS6osGWwey7uhDILu2CX
         vdJXWmsP+LYVkstJlmL0RSdEJ4jfkSYfxUxP8b2HKWVgcUxr5YyYU/hNV4qS+HyQdL1m
         zz63SKdIqVy+1Ps7HB4D3Bn1A+SWHVw4YrnVT0iHJebHYqTRbXfG9G6N6wEgZyS/+Dd9
         dMlh1mjohbYKWGOIw5ZH/urdiT9xw2nxCq8FBCSW7knmo7NbxMqvSz021dIPq0VlO+6m
         2EIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AIKa/eUBi5zcUcxGR39w7UBjnU6WkKCnQF3gp9bOzV0=;
        b=sgedike6bUt0qpC4p5Re4HOJPysy48vNlnisU7Dvz/g6MTsPZNNHQ8Rtt/y68oHnnu
         ksy3qC38e7FRZ79DkJXDtG+lM2Za5kVBcAwgvZpU1zM9Q2hrlaYNAdMm6I+TRL4cZyFK
         gfZWCT47mIXJQS6xUKc3WUQns40KIIO1cKuUugdoaYpsKyfZsZ3nEqbKEj0KFCadj4Vd
         yC4KA5/CDD6wwiu1r7yK62b1TFPd9Y4wZaiYaFsNG2AkLL5WPhXbRVrCNsKY9TjeoohZ
         WkS3cDbvmOsg0nqse8WUHd22X4jPGpmxMOq+FkyghP893DneQmrexXtKZPY0iaB5sQoj
         XnPA==
X-Gm-Message-State: AJIora9pmROp0uFgJKy84hYKjkgih8DDXowDTxiH2/UHSU5bADSE5uKS
	d3zL6dG2lVLtdjKdsDyBxPc=
X-Google-Smtp-Source: AGRyM1tL9cezBvyAzfj4wqK8aVf4OSEHZLcrMkJBucMMG5o2sBZijj91KUpaK9X7NWF0pkzIduyS5Q==
X-Received: by 2002:a05:6512:3c8e:b0:47f:b6fa:8da1 with SMTP id h14-20020a0565123c8e00b0047fb6fa8da1mr13227411lfv.553.1656420815687;
        Tue, 28 Jun 2022 05:53:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls647731lfb.1.gmail; Tue, 28 Jun 2022
 05:53:34 -0700 (PDT)
X-Received: by 2002:a19:6717:0:b0:47f:8d32:cd02 with SMTP id b23-20020a196717000000b0047f8d32cd02mr12715978lfc.375.1656420814438;
        Tue, 28 Jun 2022 05:53:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656420814; cv=none;
        d=google.com; s=arc-20160816;
        b=TF5QNH15wXBev89yPCFhmes1jQ6Gk7vH6WmJI/DZxrX4jzzYOkBmZI+DIBcB5I+cWW
         H+z3Ziig/c01q6NdPukXaqFiZwV0CN6Mdm9Jcdmld3u4iqyyFbbudem+ZlOOu+QPe0fH
         G711RNr4YscVXq12C86t15bkWMpkoYHpcVQ+h5MIumCPuiRQAqfrkZYNByO+ykGlreCA
         +jpX6rH5V3qYhR+tmu/3VUYFU9eRtN7MsuWEZ+z3QFOOgTxcKXbCBbtS3UBWtcMSpC1G
         zf2fG/fKGQl8+cM45BL4wPvIAJZPMK5l+XOsF6nX5PEGd6zhpOpBs7zYWrPbPvkHq6mv
         KOgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ME9ogYLhPCZuFXLa1q13oIt/WDr6DICnKX+45BprLvQ=;
        b=ngdRBkYk6+P2btAFbbPBo8vIuGWOJCrpSBF50+Fyc8U5mHhGDNR0mF8pIi/kJGnRlq
         VosnHyJ29HPy/HTZRnAsS7T9dk/qAIMdZeafjsTtOTxvebjf+dpAWvHWXqkU5wSI1OVG
         ZqkjfFXcaFi+XVB8Or1tRB17hiecoANTYHlMeekwr2LvApaftALqYQMrxmrrkCSHRzaY
         WucS0LqrTF3cjp4FNbjYg3vKgJb44KqWCj+emrUza13bU4wxFxMJ7i09Y01siZwS4P+G
         xNZBlAYX2Mqy6vyNLQE3lO4Q0hxBIEUkceYpqcjf8M0UwEYjalfLefLmr/O6F7/CUbpV
         sSBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="O/eDFTpZ";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id g14-20020a0565123b8e00b004810be25317si312107lfv.4.2022.06.28.05.53.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 05:53:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id z21so22060030lfb.12
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 05:53:34 -0700 (PDT)
X-Received: by 2002:a05:6512:10c3:b0:47f:a97e:35c with SMTP id
 k3-20020a05651210c300b0047fa97e035cmr11411428lfg.417.1656420813860; Tue, 28
 Jun 2022 05:53:33 -0700 (PDT)
MIME-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com> <20220628095833.2579903-2-elver@google.com>
In-Reply-To: <20220628095833.2579903-2-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jun 2022 14:53:22 +0200
Message-ID: <CACT4Y+brMfpe1_T5eaki8YLRVeCsFqJ6WbUCAe2+ALNTT=By0w@mail.gmail.com>
Subject: Re: [PATCH v2 01/13] perf/hw_breakpoint: Add KUnit test for
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
 header.i=@google.com header.s=20210112 header.b="O/eDFTpZ";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132
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

 On Tue, 28 Jun 2022 at 11:59, Marco Elver <elver@google.com> wrote:
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
> ---
> v2:
> * New patch.
> ---
>  kernel/events/Makefile             |   1 +
>  kernel/events/hw_breakpoint_test.c | 321 +++++++++++++++++++++++++++++
>  lib/Kconfig.debug                  |  10 +
>  3 files changed, 332 insertions(+)
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
> index 000000000000..747a0249a606
> --- /dev/null
> +++ b/kernel/events/hw_breakpoint_test.c
> @@ -0,0 +1,321 @@
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

Why is this function needed? Is hw_breakpoint_slots() very slow?

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
> +static int get_other_cpu(void)
> +{
> +       int cpu;
> +
> +       for_each_online_cpu(cpu) {
> +               if (cpu != raw_smp_processor_id())

Are we guaranteed to not be rescheduled in the middle of a test?
If not, can't get_other_cpu() return the same CPU that was returned by
raw_smp_processor_id() earlier in the test?

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
> +       fill_bp_slots(test, &idx, raw_smp_processor_id(), NULL, 0);
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
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
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
> +       /* Remove one and adding back CPU-target should work. */
> +       unregister_test_bp(&test_bps[0]);
> +       fill_one_bp_slot(test, &idx, raw_smp_processor_id(), NULL);
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
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), get_other_task(test), idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
> +       /* Remove one from first task and adding back CPU-target should not work. */
> +       unregister_test_bp(&test_bps[0]);
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
> +}
> +
> +static void test_one_task_on_one_cpu(struct kunit *test)
> +{
> +       int idx = 0;
> +
> +       fill_bp_slots(test, &idx, raw_smp_processor_id(), current, 0);
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
> +       /*
> +        * Remove one and adding back CPU-target should work; this case is
> +        * special vs. above because the task's constraints are CPU-dependent.
> +        */
> +       unregister_test_bp(&test_bps[0]);
> +       fill_one_bp_slot(test, &idx, raw_smp_processor_id(), NULL);
> +}
> +
> +static void test_one_task_mixed(struct kunit *test)
> +{
> +       int idx = 0;
> +
> +       TEST_REQUIRES_BP_SLOTS(test, 3);
> +
> +       fill_one_bp_slot(test, &idx, raw_smp_processor_id(), current);
> +       fill_bp_slots(test, &idx, -1, current, 1);
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
> +
> +       /* Transition from CPU-dependent pinned count to CPU-independent. */
> +       unregister_test_bp(&test_bps[0]);
> +       unregister_test_bp(&test_bps[1]);
> +       fill_one_bp_slot(test, &idx, raw_smp_processor_id(), NULL);
> +       fill_one_bp_slot(test, &idx, raw_smp_processor_id(), NULL);
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
> +}
> +
> +static void test_two_tasks_on_one_cpu(struct kunit *test)
> +{
> +       int idx = 0;
> +
> +       fill_bp_slots(test, &idx, raw_smp_processor_id(), current, 0);
> +       fill_bp_slots(test, &idx, raw_smp_processor_id(), get_other_task(test), 0);
> +
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, get_other_task(test), idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), get_other_task(test), idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
> +       /* Can still create breakpoints on some other CPU. */
> +       fill_bp_slots(test, &idx, get_other_cpu(), NULL, 0);
> +}
> +
> +static void test_two_tasks_on_one_all_cpus(struct kunit *test)
> +{
> +       int idx = 0;
> +
> +       fill_bp_slots(test, &idx, raw_smp_processor_id(), current, 0);
> +       fill_bp_slots(test, &idx, -1, get_other_task(test), 0);
> +
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, get_other_task(test), idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), get_other_task(test), idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
> +       /* Cannot create breakpoints on some other CPU either. */
> +       TEST_EXPECT_NOSPC(register_test_bp(get_other_cpu(), NULL, idx));
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
> +       fill_one_bp_slot(test, &idx, raw_smp_processor_id(), current);
> +       fill_one_bp_slot(test, &idx, -1, current);
> +
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
> +
> +       /* We should still be able to use up another CPU's slots. */
> +       cpu_idx = idx;
> +       fill_one_bp_slot(test, &idx, get_other_cpu(), NULL);
> +       TEST_EXPECT_NOSPC(register_test_bp(get_other_cpu(), NULL, idx));
> +
> +       /* Transitioning back to task target on all CPUs. */
> +       unregister_test_bp(&test_bps[tsk_on_cpu_idx]);
> +       /* Still have a CPU target breakpoint in get_other_cpu(). */
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +       /* Remove it and try again. */
> +       unregister_test_bp(&test_bps[cpu_idx]);
> +       fill_one_bp_slot(test, &idx, -1, current);
> +
> +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), current, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(raw_smp_processor_id(), NULL, idx));
> +       TEST_EXPECT_NOSPC(register_test_bp(get_other_cpu(), NULL, idx));
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbrMfpe1_T5eaki8YLRVeCsFqJ6WbUCAe2%2BALNTT%3DBy0w%40mail.gmail.com.
