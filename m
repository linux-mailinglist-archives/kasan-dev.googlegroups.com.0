Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFUD5SKQMGQEYVGLCRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 54A6E55DCEA
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 15:26:48 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id z4-20020a056a001d8400b005251a1d6bdasf5291971pfw.18
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 06:26:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656422807; cv=pass;
        d=google.com; s=arc-20160816;
        b=kcIarG+bz1+cjNAAA1WNbvqitfOpbgQcS0XpalBDPV7plrAiK0c+TAj++DwjiYMPLD
         FNSDDnU7gJfL+1bS3BwY7duxvl5GqLnDY7IgPWS3Eph0s15JrLekq55ZFXK4jlsGfdC1
         bAnI9bIDXEOuDwzOfui3pPfxanvnSD8dcBv3objC2WcjqK+dF9FhVBUaGw7Uy+TuFdlW
         nAfxHsY9jo++qbh6nU4nnuxR91KJUy0sto1V3bQkK6XEXwwX1xunFiEu0Cpw+MFVKqQH
         t6MO54PBVTQ/NyLX97fdHWZnLM64WeG7uzNw367ouE4UVNRII/iTJxZlCpZFeS4juVxX
         dIsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Pqdao3TrA0khLTNDJQlVtBLyGHhKdz2SwukxJarV2P8=;
        b=VoeCLwHx7fOSHvVjnVNCv4HW/wTEFHyYUgx4amkYAl9QeKcWi1DttEvB2JcdNq55w6
         cUNY8TaKXdm3ujQMjH7aEAQtMrtHogUdrs638GivTKlnXov2NwHXSUw9bmATJLP0XxzA
         0FGwFob153e5Pu9YXBgLahChh7wHXPR9JjoH1EaVOh/k14LlEKxOZyFQrGLKuxPv7qN9
         cy3DtNV7Zd9PizZaNbPoYq302GvCluhuUJDbHqKv7W4/3uz/sYJuBFSHdplHUOpN38gz
         fFP1nBgWS1uGPwrcQkTSVDYcOeGFl3CjTIjzvYOCzJi0o3CQaBOno7wRqNxjD4EJsQgk
         NqJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NSkLxKlt;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pqdao3TrA0khLTNDJQlVtBLyGHhKdz2SwukxJarV2P8=;
        b=EZovS2apl3DgD8RhpSv0u0IIZ2d+5PAYazMCXDUC8cN0RbK6GZd0/sESHEQNaZPU0i
         vxeZjeeNUGceAiC1QlFs6LdMQ55w6LhUJgdeKHabVPzZi2hHpF7fjfI1S4MsGEJuwvG5
         yIkVksbgkZi+kpHcRX2iLKr9CDt8xzJCWqs3x5ebvYPZdiuhTU9P37cOGD4ENFUawR5X
         LFb2C+YiIP9zVzM8PfPFIrAByVJXEvBoLGoSJ9llEmKm4+qVgjYns52PIsunQTxdvM2/
         lykihbq+6gOHU6g5RpWbB/vpqJhJOyXo11EtynWXU3sKmIwf5syPCIhG4zK6FreCfPWY
         P14A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pqdao3TrA0khLTNDJQlVtBLyGHhKdz2SwukxJarV2P8=;
        b=OYlkRW9D7GkyB2qXGaoi7Cd9if89PGJTD4MsWcFe0vztWww/DqKJbuID34vGyZxw7m
         jk8SZCO3W46YT39OTSwyh0ZiF6Tqv8RcXEMI9K3HLivs/0DpKEfX8FQ2sUsymLuoHCAn
         MiRmzyoQ5f5uA6726o5WkLDYGoI0FuZhYNMX6vs4I5AIqUplP60sgsUVRbiLlXDRd5Gj
         IzKHHKKIpH7AicLdOzPcqxVOHVLrLTytzS22bOZ2SXP1Hq7zfnUVBIUQbY/4CDas68tJ
         uoJEgvR50sVJu2DIef3WEdnX6E9Zm7bG83ZPU7j3rRjxf2B5XSyePXJfpx/SnSEG3oeR
         oT/A==
X-Gm-Message-State: AJIora8MZa9f92DEsJH1otDXpBfboY/UXfmvdfkqEzQaZq4aOCfUNcRT
	L1Ui7Za+KfDXTgV5aoAdpd8=
X-Google-Smtp-Source: AGRyM1txAjd/qoFeATt/LpjEkhVwoNO2bvwiRSQki6/rSWRGyfKbyPv3yozJaZAZQ1eg3WuSEEj1EA==
X-Received: by 2002:a17:90b:4a4c:b0:1ec:9036:8f91 with SMTP id lb12-20020a17090b4a4c00b001ec90368f91mr21971334pjb.33.1656422807046;
        Tue, 28 Jun 2022 06:26:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1542:0:b0:525:1d9a:edb3 with SMTP id 63-20020a621542000000b005251d9aedb3ls11288744pfv.3.gmail;
 Tue, 28 Jun 2022 06:26:46 -0700 (PDT)
X-Received: by 2002:a63:6942:0:b0:40d:b8a:c55f with SMTP id e63-20020a636942000000b0040d0b8ac55fmr17304154pgc.542.1656422806178;
        Tue, 28 Jun 2022 06:26:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656422806; cv=none;
        d=google.com; s=arc-20160816;
        b=ukf5MvD799CETmYPWkTmTVDxpJPlLj1Tpn9LvSIbPFr3RRzfiP/Vx+4Z3JgYy9fl+3
         LAiliHMWAvH7dbTQDpZxUOgy6838NJE+FvCyFkrDlFh1WO4HT5dL7arkYdtytU6ygLV/
         7nri3vvgNo4sT1Wa/xZRXeQ7QkeO1ULLRh7l442seg00X44NyrSg3haKkC6IpfIVvyi5
         uxidNPGKmoRrfKk7x4kZ2Gd3GdCHvxiS7CUH0pg7HehQr34YKcK1uDkiQ5BrbGChL6FK
         6NjuMPRJu3IejirMCWBn6Cae4DN31jv+J7YXhO3EcktqTY7wQ2hjdX+bI91BQmQl8CdN
         U70g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=x1PdxBEhFalOAWbRKx82ZqW3VRMTFx8BscKp2q1d2zQ=;
        b=ewI8iOJQK3/6KMzZBXEz/IllfRekDCxRGpMtrofP2sRFz5bhni1ffSyI98DtqdTD9d
         A49UwKRiEMtNVuVvxNLT69gzNhT8wJA23YcgOcYXmnVj60uitcZMytxHm3f0EqgAUPwP
         QV5DAOZRco0CCM9fiyOU/e3g6WIZM1E/D7K9jMt1wHfu9NQdsNVAaeo4fEbTPWh5yDqt
         D+XxNW4dnqfOKwuSYwx7kaeMIyJQ/LqhAVF/lHpkB1FotrieyeeAsrrJ4VkrJfusGoCR
         WS4GvEdoeNQKmJdpu5FQjpviz4q70dTSr3Vy5lZ3U1J+lNPWKgo2VBs/iS1caaBrQRBu
         41Cw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NSkLxKlt;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id s1-20020a656901000000b0040c9274bc0csi320579pgq.5.2022.06.28.06.26.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 06:26:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id p136so16001197ybg.4
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 06:26:46 -0700 (PDT)
X-Received: by 2002:a25:cc56:0:b0:66c:d0f6:2f0e with SMTP id
 l83-20020a25cc56000000b0066cd0f62f0emr11356145ybf.168.1656422805211; Tue, 28
 Jun 2022 06:26:45 -0700 (PDT)
MIME-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com> <20220628095833.2579903-2-elver@google.com>
 <CACT4Y+brMfpe1_T5eaki8YLRVeCsFqJ6WbUCAe2+ALNTT=By0w@mail.gmail.com>
In-Reply-To: <CACT4Y+brMfpe1_T5eaki8YLRVeCsFqJ6WbUCAe2+ALNTT=By0w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jun 2022 15:26:09 +0200
Message-ID: <CANpmjNPYMSWOFa5mG9HZnjZUGg7DhGDcLN2dsATZFZh1y5C36Q@mail.gmail.com>
Subject: Re: [PATCH v2 01/13] perf/hw_breakpoint: Add KUnit test for
 constraints accounting
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=NSkLxKlt;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, 28 Jun 2022 at 14:53, Dmitry Vyukov <dvyukov@google.com> wrote:
>
>  On Tue, 28 Jun 2022 at 11:59, Marco Elver <elver@google.com> wrote:
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
> > ---
> > v2:
> > * New patch.
> > ---
> >  kernel/events/Makefile             |   1 +
> >  kernel/events/hw_breakpoint_test.c | 321 +++++++++++++++++++++++++++++
> >  lib/Kconfig.debug                  |  10 +
> >  3 files changed, 332 insertions(+)
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
> > index 000000000000..747a0249a606
> > --- /dev/null
> > +++ b/kernel/events/hw_breakpoint_test.c
> > @@ -0,0 +1,321 @@
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
>
> Why is this function needed? Is hw_breakpoint_slots() very slow?

It seems non-trivial on some architectures (e.g.
arch/arm64/kernel/hw_breakpoint.c). Also the reason why
hw_breakpoint.c itself caches it, so I decided to follow the same
because it's called very often in the tests.

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
> > +static int get_other_cpu(void)
> > +{
> > +       int cpu;
> > +
> > +       for_each_online_cpu(cpu) {
> > +               if (cpu != raw_smp_processor_id())
>
> Are we guaranteed to not be rescheduled in the middle of a test?
> If not, can't get_other_cpu() return the same CPU that was returned by
> raw_smp_processor_id() earlier in the test?

Yes, good point. I think I'll change it to just not use
raw_smp_processor_id() and instead have get_test_cpu(int num) and it
tries to find the 'num' online CPU. In the tests I'll just use CPU
#num 0 and 1.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPYMSWOFa5mG9HZnjZUGg7DhGDcLN2dsATZFZh1y5C36Q%40mail.gmail.com.
