Return-Path: <kasan-dev+bncBDPPFIEASMFBBLV34CLAMGQEQ7FOW5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 321EE57B973
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 17:22:23 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id z5-20020a05640235c500b0043ae18edeeesf12297667edc.5
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 08:22:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658330542; cv=pass;
        d=google.com; s=arc-20160816;
        b=d/1JLclINbZvmPe8/Aa7y/m4MWol8azbPzxpnqAhsFOsX8Rmh/7sE1NVLU7NX4xw1r
         B7azELu01B2JJ/rOMsreMq7gT3mIRpESj0Yg+lwazGI6GC61Y4prpq8sZDfuVJFiqCaR
         ES2RZMRGejHrpwDQRTcBeqcREx+mqSQo6s8+o4zj1CEcaUzouG3qUx8G7PXbcIM2Gfsr
         zmGjwjB/+pKSpIuqYNKH7Dz7D1UppbjBxFmLVZ7CdmUiHqGJZ68lCIeuAh1ThJ5h9JzF
         ha17TfE8BmTxUbxco9zxzSvB5pE6UrTPYo8qKkI82gbAskv+D6JG1Q+/mTqlyuNgAG/u
         Zu+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZTbNmy2/zKupz67YAzCWwKVehuGastqIAhDsgZ/tzJo=;
        b=KPaxMp4h6r2eRrIDxMkI05Xfh8V+EG7f3j0W9hSI8zUx6O6mBlD590kAhH9RRunTWR
         ladsL7JkbwOHw8EHvTZRW/KOKNHMfm+9Xs7fLS6pktHDoNYQWeJo4xwmI2ANo08A+/Fi
         ZfGrJhGTF4L8OZ+ColeB8fapDOyoWVNoEpQ3UM9pVzjNYBgyZ2IGJF6pOlo2TNIR+A9U
         hHkj3O18WtUNZhhqB7KrWgRod2PD5qSbi0XTK0kSfIPpNF2olwCPXCndiWgfMytCfmeN
         9PWv2JeWZv+JSckpttQ9uG//ukpsITIJTb7aQ6Xv0YTfNXTH4xsd8pr1s5epfkOr2fL3
         0LCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="q/XN4+mo";
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZTbNmy2/zKupz67YAzCWwKVehuGastqIAhDsgZ/tzJo=;
        b=UjqicEAUBSBLw4Pht7kY0u6Nny1yWDhlrpFrJvnf9jEm7rBmpRDkzXL5Pw7qftDNoE
         B/DN5QEilO2RHciY7kdOZsRRpYTt+JCm6x2osuP1y0ltkhlhICH3srGRU8+kMfwPYhYW
         p8TGZlw6f//pgMJYBy9pbKzp9StMDXUMVWzfY23elnl5L7vKqimhkJABY81W5MmZ4b2K
         mUhq8vYybIaiUL5RTIdNRFgvgd9ArmSz43uftJCb5qMVcTYgEhDYGEKOeyHQPLEwiS7n
         4exxjgGZYOxNTqs1xpsDXMqg8lR4UvKzAVyKKFZ2aPZ0G9zDWfBMXO3nWilqMDGTdTYQ
         UgkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZTbNmy2/zKupz67YAzCWwKVehuGastqIAhDsgZ/tzJo=;
        b=Y453xeZGYbHPuSgZxHo86mPdWrGtCmA2Zaum9G1GeXiwyC0sGHZIjejDwHDqLyKioU
         0WiMbrG9Twjut2nKSCZxEW+z9SxecCg+eSdwQTA4xFIjjp4Qj/yPCstK6/6uw+rNEbNX
         8NAQDKcnSAxCZA+2v8EjAyZzDsMVfM9jchLDoRL5XHDb4XEjlpJTisAP+uCEa5G7cwxA
         H87KvDTzkcJkQrw5W40deHcCmKxGyX0obvVmT6lACY90MU7qYiXX2lqwm3+X0f7/8C48
         ZfqoASuvnFmJJfrCuzwcJSd2UJ1dbKVsJ2ZCpBx8mSeFszM5G4RHZIsSBkb/4UvxpZ6x
         4//Q==
X-Gm-Message-State: AJIora/7B1UEWIXeiN3SQoDvn065+nPYpeW4wuQQ+kwQALH9aaEik7sA
	3BO6oCKb071Utg3+DBBoIZQ=
X-Google-Smtp-Source: AGRyM1uCxccsfhCjkoYqnqEqHq0b/ROpZ4nn7xdV2LADGVkl/z++uTOzlHcNN3Ko3kWcC/QDSzjfVQ==
X-Received: by 2002:a17:906:6a0a:b0:72b:60b8:d2e7 with SMTP id qw10-20020a1709066a0a00b0072b60b8d2e7mr34375663ejc.607.1658330542735;
        Wed, 20 Jul 2022 08:22:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:cb91:b0:726:d068:52af with SMTP id
 mf17-20020a170906cb9100b00726d06852afls290638ejb.1.-pod-prod-gmail; Wed, 20
 Jul 2022 08:22:21 -0700 (PDT)
X-Received: by 2002:a17:907:3e0e:b0:72b:568f:7fa7 with SMTP id hp14-20020a1709073e0e00b0072b568f7fa7mr36811274ejc.119.1658330541726;
        Wed, 20 Jul 2022 08:22:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658330541; cv=none;
        d=google.com; s=arc-20160816;
        b=mMLW88YQtR6+eD2wN71hxzwx2nYikZHMmrfxeCPUuGKJTiDvemKXllDk1XYjMM+Vy7
         z9h2PPWHf1+5XGhgax1o7R6c3qx1Kxf0wWasFnnpJiTm0yYwpiPO8eSyzYDg7ZsQBcQq
         lU7pLU/F9IJPuS0pWrSPkiUIe8+lJtpbzTlvKwIPUqIGvzYoviC5W7ny5wrOSoQnuZA9
         wolYSgDNW5P3ZjDyE+k3wsPaz4D/3ZEANvgZ4Thl8s4W8rmYu+q2nSWGu5oydj23Mmby
         mFgW7af6Vz9NtcZtJ1camCVJZTa4Fu15bmeBISjqvvJWC7KX8AYsZAT55dJD2w4/hFo6
         zw7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=10mCB1p9QXZ5hMNLpf9Atm/lE/ONgYcPbZJGAy+BbTE=;
        b=anxIBQNvmgrMXNpqJ01kIyJcL7qOr7IObgxlL294ffLDgO8Pd34KkldBkICvFfJhcP
         hjQ2YIVrQTES2nj8+2x4bPv3+nk4Jfy9QYk+cC2GYZJUciYC0z17GEodUxh3u0nLAoKe
         iINWzAOJowX8Uktg5RPNlrmDnOMOwW7knm1qLK/V4r5aqK27mzPAefL3+xkHRIqXLnB2
         rSuPqHBNnTp0X81j1yJs4k+ZVlIJ4iXK649tRTS8iGsRGxKE99oFlS9WbEMaPEkP02rL
         cq0FdF8CM67JsqpQWDXNCLpGyDqmyB9m3a5OgGymeHY2ZuWRSkMfDUhKRe+FINjSrvCf
         VQqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="q/XN4+mo";
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id n26-20020aa7c45a000000b004359bd2b6c9si538861edr.3.2022.07.20.08.22.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Jul 2022 08:22:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id bv24so2729042wrb.3
        for <kasan-dev@googlegroups.com>; Wed, 20 Jul 2022 08:22:21 -0700 (PDT)
X-Received: by 2002:a5d:4d8e:0:b0:21d:68d4:56eb with SMTP id
 b14-20020a5d4d8e000000b0021d68d456ebmr30086604wru.40.1658330541254; Wed, 20
 Jul 2022 08:22:21 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-2-elver@google.com>
 <CACT4Y+aA7QkAsufv6EMQ1O8mZaVd-eNOqRrx2a7qvPR4Tt=izA@mail.gmail.com>
In-Reply-To: <CACT4Y+aA7QkAsufv6EMQ1O8mZaVd-eNOqRrx2a7qvPR4Tt=izA@mail.gmail.com>
From: "'Ian Rogers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Jul 2022 08:22:08 -0700
Message-ID: <CAP-5=fWKM09_cgOjEyDjLrs5KgvXv1vLbyBgTFAEV0Sr3f_3YA@mail.gmail.com>
Subject: Re: [PATCH v3 01/14] perf/hw_breakpoint: Add KUnit test for
 constraints accounting
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: irogers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="q/XN4+mo";       spf=pass
 (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::42e
 as permitted sender) smtp.mailfrom=irogers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Ian Rogers <irogers@google.com>
Reply-To: Ian Rogers <irogers@google.com>
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

On Mon, Jul 4, 2022 at 8:11 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, 4 Jul 2022 at 17:06, Marco Elver <elver@google.com> wrote:
> >
> > Add KUnit test for hw_breakpoint constraints accounting, with various
> > interesting mixes of breakpoint targets (some care was taken to catch
> > interesting corner cases via bug-injection).
> >
> > The test cannot be built as a module because it requires access to
> > hw_breakpoint_slots(), which is not inlinable or exported on all
> > architectures.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Acked-by: Ian Rogers <irogers@google.com>

Thanks,
Ian

> > ---
> > v3:
> > * Don't use raw_smp_processor_id().
> >
> > v2:
> > * New patch.
> > ---
> >  kernel/events/Makefile             |   1 +
> >  kernel/events/hw_breakpoint_test.c | 323 +++++++++++++++++++++++++++++
> >  lib/Kconfig.debug                  |  10 +
> >  3 files changed, 334 insertions(+)
> >  create mode 100644 kernel/events/hw_breakpoint_test.c
> >
> > diff --git a/kernel/events/Makefile b/kernel/events/Makefile
> > index 8591c180b52b..91a62f566743 100644
> > --- a/kernel/events/Makefile
> > +++ b/kernel/events/Makefile
> > @@ -2,4 +2,5 @@
> >  obj-y := core.o ring_buffer.o callchain.o
> >
> >  obj-$(CONFIG_HAVE_HW_BREAKPOINT) += hw_breakpoint.o
> > +obj-$(CONFIG_HW_BREAKPOINT_KUNIT_TEST) += hw_breakpoint_test.o
> >  obj-$(CONFIG_UPROBES) += uprobes.o
> > diff --git a/kernel/events/hw_breakpoint_test.c b/kernel/events/hw_breakpoint_test.c
> > new file mode 100644
> > index 000000000000..433c5c45e2a5
> > --- /dev/null
> > +++ b/kernel/events/hw_breakpoint_test.c
> > @@ -0,0 +1,323 @@
> > +// SPDX-License-Identifier: GPL-2.0
> > +/*
> > + * KUnit test for hw_breakpoint constraints accounting logic.
> > + *
> > + * Copyright (C) 2022, Google LLC.
> > + */
> > +
> > +#include <kunit/test.h>
> > +#include <linux/cpumask.h>
> > +#include <linux/hw_breakpoint.h>
> > +#include <linux/kthread.h>
> > +#include <linux/perf_event.h>
> > +#include <asm/hw_breakpoint.h>
> > +
> > +#define TEST_REQUIRES_BP_SLOTS(test, slots)                                            \
> > +       do {                                                                            \
> > +               if ((slots) > get_test_bp_slots()) {                                    \
> > +                       kunit_skip((test), "Requires breakpoint slots: %d > %d", slots, \
> > +                                  get_test_bp_slots());                                \
> > +               }                                                                       \
> > +       } while (0)
> > +
> > +#define TEST_EXPECT_NOSPC(expr) KUNIT_EXPECT_EQ(test, -ENOSPC, PTR_ERR(expr))
> > +
> > +#define MAX_TEST_BREAKPOINTS 512
> > +
> > +static char break_vars[MAX_TEST_BREAKPOINTS];
> > +static struct perf_event *test_bps[MAX_TEST_BREAKPOINTS];
> > +static struct task_struct *__other_task;
> > +
> > +static struct perf_event *register_test_bp(int cpu, struct task_struct *tsk, int idx)
> > +{
> > +       struct perf_event_attr attr = {};
> > +
> > +       if (WARN_ON(idx < 0 || idx >= MAX_TEST_BREAKPOINTS))
> > +               return NULL;
> > +
> > +       hw_breakpoint_init(&attr);
> > +       attr.bp_addr = (unsigned long)&break_vars[idx];
> > +       attr.bp_len = HW_BREAKPOINT_LEN_1;
> > +       attr.bp_type = HW_BREAKPOINT_RW;
> > +       return perf_event_create_kernel_counter(&attr, cpu, tsk, NULL, NULL);
> > +}
> > +
> > +static void unregister_test_bp(struct perf_event **bp)
> > +{
> > +       if (WARN_ON(IS_ERR(*bp)))
> > +               return;
> > +       if (WARN_ON(!*bp))
> > +               return;
> > +       unregister_hw_breakpoint(*bp);
> > +       *bp = NULL;
> > +}
> > +
> > +static int get_test_bp_slots(void)
> > +{
> > +       static int slots;
> > +
> > +       if (!slots)
> > +               slots = hw_breakpoint_slots(TYPE_DATA);
> > +
> > +       return slots;
> > +}
> > +
> > +static void fill_one_bp_slot(struct kunit *test, int *id, int cpu, struct task_struct *tsk)
> > +{
> > +       struct perf_event *bp = register_test_bp(cpu, tsk, *id);
> > +
> > +       KUNIT_ASSERT_NOT_NULL(test, bp);
> > +       KUNIT_ASSERT_FALSE(test, IS_ERR(bp));
> > +       KUNIT_ASSERT_NULL(test, test_bps[*id]);
> > +       test_bps[(*id)++] = bp;
> > +}
> > +
> > +/*
> > + * Fills up the given @cpu/@tsk with breakpoints, only leaving @skip slots free.
> > + *
> > + * Returns true if this can be called again, continuing at @id.
> > + */
> > +static bool fill_bp_slots(struct kunit *test, int *id, int cpu, struct task_struct *tsk, int skip)
> > +{
> > +       for (int i = 0; i < get_test_bp_slots() - skip; ++i)
> > +               fill_one_bp_slot(test, id, cpu, tsk);
> > +
> > +       return *id + get_test_bp_slots() <= MAX_TEST_BREAKPOINTS;
> > +}
> > +
> > +static int dummy_kthread(void *arg)
> > +{
> > +       return 0;
> > +}
> > +
> > +static struct task_struct *get_other_task(struct kunit *test)
> > +{
> > +       struct task_struct *tsk;
> > +
> > +       if (__other_task)
> > +               return __other_task;
> > +
> > +       tsk = kthread_create(dummy_kthread, NULL, "hw_breakpoint_dummy_task");
> > +       KUNIT_ASSERT_FALSE(test, IS_ERR(tsk));
> > +       __other_task = tsk;
> > +       return __other_task;
> > +}
> > +
> > +static int get_test_cpu(int num)
> > +{
> > +       int cpu;
> > +
> > +       WARN_ON(num < 0);
> > +
> > +       for_each_online_cpu(cpu) {
> > +               if (num-- <= 0)
> > +                       break;
> > +       }
> > +
> > +       return cpu;
> > +}
> > +
> > +/* ===== Test cases ===== */
> > +
> > +static void test_one_cpu(struct kunit *test)
> > +{
> > +       int idx = 0;
> > +
> > +       fill_bp_slots(test, &idx, get_test_cpu(0), NULL, 0);
> > +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> > +}
> > +
> > +static void test_many_cpus(struct kunit *test)
> > +{
> > +       int idx = 0;
> > +       int cpu;
> > +
> > +       /* Test that CPUs are independent. */
> > +       for_each_online_cpu(cpu) {
> > +               bool do_continue = fill_bp_slots(test, &idx, cpu, NULL, 0);
> > +
> > +               TEST_EXPECT_NOSPC(register_test_bp(cpu, NULL, idx));
> > +               if (!do_continue)
> > +                       break;
> > +       }
> > +}
> > +
> > +static void test_one_task_on_all_cpus(struct kunit *test)
> > +{
> > +       int idx = 0;
> > +
> > +       fill_bp_slots(test, &idx, -1, current, 0);
> > +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> > +       /* Remove one and adding back CPU-target should work. */
> > +       unregister_test_bp(&test_bps[0]);
> > +       fill_one_bp_slot(test, &idx, get_test_cpu(0), NULL);
> > +}
> > +
> > +static void test_two_tasks_on_all_cpus(struct kunit *test)
> > +{
> > +       int idx = 0;
> > +
> > +       /* Test that tasks are independent. */
> > +       fill_bp_slots(test, &idx, -1, current, 0);
> > +       fill_bp_slots(test, &idx, -1, get_other_task(test), 0);
> > +
> > +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(-1, get_other_task(test), idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), get_other_task(test), idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> > +       /* Remove one from first task and adding back CPU-target should not work. */
> > +       unregister_test_bp(&test_bps[0]);
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> > +}
> > +
> > +static void test_one_task_on_one_cpu(struct kunit *test)
> > +{
> > +       int idx = 0;
> > +
> > +       fill_bp_slots(test, &idx, get_test_cpu(0), current, 0);
> > +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> > +       /*
> > +        * Remove one and adding back CPU-target should work; this case is
> > +        * special vs. above because the task's constraints are CPU-dependent.
> > +        */
> > +       unregister_test_bp(&test_bps[0]);
> > +       fill_one_bp_slot(test, &idx, get_test_cpu(0), NULL);
> > +}
> > +
> > +static void test_one_task_mixed(struct kunit *test)
> > +{
> > +       int idx = 0;
> > +
> > +       TEST_REQUIRES_BP_SLOTS(test, 3);
> > +
> > +       fill_one_bp_slot(test, &idx, get_test_cpu(0), current);
> > +       fill_bp_slots(test, &idx, -1, current, 1);
> > +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> > +
> > +       /* Transition from CPU-dependent pinned count to CPU-independent. */
> > +       unregister_test_bp(&test_bps[0]);
> > +       unregister_test_bp(&test_bps[1]);
> > +       fill_one_bp_slot(test, &idx, get_test_cpu(0), NULL);
> > +       fill_one_bp_slot(test, &idx, get_test_cpu(0), NULL);
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> > +}
> > +
> > +static void test_two_tasks_on_one_cpu(struct kunit *test)
> > +{
> > +       int idx = 0;
> > +
> > +       fill_bp_slots(test, &idx, get_test_cpu(0), current, 0);
> > +       fill_bp_slots(test, &idx, get_test_cpu(0), get_other_task(test), 0);
> > +
> > +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(-1, get_other_task(test), idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), get_other_task(test), idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> > +       /* Can still create breakpoints on some other CPU. */
> > +       fill_bp_slots(test, &idx, get_test_cpu(1), NULL, 0);
> > +}
> > +
> > +static void test_two_tasks_on_one_all_cpus(struct kunit *test)
> > +{
> > +       int idx = 0;
> > +
> > +       fill_bp_slots(test, &idx, get_test_cpu(0), current, 0);
> > +       fill_bp_slots(test, &idx, -1, get_other_task(test), 0);
> > +
> > +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(-1, get_other_task(test), idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), get_other_task(test), idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> > +       /* Cannot create breakpoints on some other CPU either. */
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(1), NULL, idx));
> > +}
> > +
> > +static void test_task_on_all_and_one_cpu(struct kunit *test)
> > +{
> > +       int tsk_on_cpu_idx, cpu_idx;
> > +       int idx = 0;
> > +
> > +       TEST_REQUIRES_BP_SLOTS(test, 3);
> > +
> > +       fill_bp_slots(test, &idx, -1, current, 2);
> > +       /* Transitioning from only all CPU breakpoints to mixed. */
> > +       tsk_on_cpu_idx = idx;
> > +       fill_one_bp_slot(test, &idx, get_test_cpu(0), current);
> > +       fill_one_bp_slot(test, &idx, -1, current);
> > +
> > +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> > +
> > +       /* We should still be able to use up another CPU's slots. */
> > +       cpu_idx = idx;
> > +       fill_one_bp_slot(test, &idx, get_test_cpu(1), NULL);
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(1), NULL, idx));
> > +
> > +       /* Transitioning back to task target on all CPUs. */
> > +       unregister_test_bp(&test_bps[tsk_on_cpu_idx]);
> > +       /* Still have a CPU target breakpoint in get_test_cpu(1). */
> > +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> > +       /* Remove it and try again. */
> > +       unregister_test_bp(&test_bps[cpu_idx]);
> > +       fill_one_bp_slot(test, &idx, -1, current);
> > +
> > +       TEST_EXPECT_NOSPC(register_test_bp(-1, current, idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), current, idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(0), NULL, idx));
> > +       TEST_EXPECT_NOSPC(register_test_bp(get_test_cpu(1), NULL, idx));
> > +}
> > +
> > +static struct kunit_case hw_breakpoint_test_cases[] = {
> > +       KUNIT_CASE(test_one_cpu),
> > +       KUNIT_CASE(test_many_cpus),
> > +       KUNIT_CASE(test_one_task_on_all_cpus),
> > +       KUNIT_CASE(test_two_tasks_on_all_cpus),
> > +       KUNIT_CASE(test_one_task_on_one_cpu),
> > +       KUNIT_CASE(test_one_task_mixed),
> > +       KUNIT_CASE(test_two_tasks_on_one_cpu),
> > +       KUNIT_CASE(test_two_tasks_on_one_all_cpus),
> > +       KUNIT_CASE(test_task_on_all_and_one_cpu),
> > +       {},
> > +};
> > +
> > +static int test_init(struct kunit *test)
> > +{
> > +       /* Most test cases want 2 distinct CPUs. */
> > +       return num_online_cpus() < 2 ? -EINVAL : 0;
> > +}
> > +
> > +static void test_exit(struct kunit *test)
> > +{
> > +       for (int i = 0; i < MAX_TEST_BREAKPOINTS; ++i) {
> > +               if (test_bps[i])
> > +                       unregister_test_bp(&test_bps[i]);
> > +       }
> > +
> > +       if (__other_task) {
> > +               kthread_stop(__other_task);
> > +               __other_task = NULL;
> > +       }
> > +}
> > +
> > +static struct kunit_suite hw_breakpoint_test_suite = {
> > +       .name = "hw_breakpoint",
> > +       .test_cases = hw_breakpoint_test_cases,
> > +       .init = test_init,
> > +       .exit = test_exit,
> > +};
> > +
> > +kunit_test_suites(&hw_breakpoint_test_suite);
> > +
> > +MODULE_LICENSE("GPL");
> > +MODULE_AUTHOR("Marco Elver <elver@google.com>");
> > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > index 2e24db4bff19..4c87a6edf046 100644
> > --- a/lib/Kconfig.debug
> > +++ b/lib/Kconfig.debug
> > @@ -2513,6 +2513,16 @@ config STACKINIT_KUNIT_TEST
> >           CONFIG_GCC_PLUGIN_STRUCTLEAK, CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF,
> >           or CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL.
> >
> > +config HW_BREAKPOINT_KUNIT_TEST
> > +       bool "Test hw_breakpoint constraints accounting" if !KUNIT_ALL_TESTS
> > +       depends on HAVE_HW_BREAKPOINT
> > +       depends on KUNIT=y
> > +       default KUNIT_ALL_TESTS
> > +       help
> > +         Tests for hw_breakpoint constraints accounting.
> > +
> > +         If unsure, say N.
> > +
> >  config TEST_UDELAY
> >         tristate "udelay test driver"
> >         help
> > --
> > 2.37.0.rc0.161.g10f37bed90-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP-5%3DfWKM09_cgOjEyDjLrs5KgvXv1vLbyBgTFAEV0Sr3f_3YA%40mail.gmail.com.
