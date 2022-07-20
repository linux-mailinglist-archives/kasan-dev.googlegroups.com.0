Return-Path: <kasan-dev+bncBDPPFIEASMFBBXN34CLAMGQE3IIMQIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id E62B457B97E
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 17:23:09 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id h20-20020a05640250d400b0043b6a4a2f11sf5873025edb.23
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 08:23:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658330589; cv=pass;
        d=google.com; s=arc-20160816;
        b=nvbKkreoaPg26uVJ+EquX9tKS3NsI063tr7IryB0vXLBoctawQdLvjISOAQyIK37S7
         hWi0jGUG3sRGIKOPCLeUM1ucvdXIUq+UXSZazDafWZHduAiedL0W5saMDxH0AKeXKu9C
         vbg2deu3uF8F34P67jOYWOQ/3Tg7wWQzsrVdFxEJj+DE3cMYcQ2nxfH11Dk0q+DovDHV
         fs3AFglzD8zc/bXuIvsYFUoP7bAulEKHaEMAx49aF5UgB1CASYB4liClNfLIOepJ1W2X
         M+ioOcgieAS8HM65gOwElZPu9mj1umeRuN2BqZszo5rZkJK83JPFs87GnODT/pFqBbpI
         etcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=yaJRVW6w2hA6DS06X0q9G34+AJ/BpxznOw3pmZvioHI=;
        b=WYoFokC1Mz6dJEA6/1xLgFfByJp1rDWuHHUvv9hfCqg9xRAvmt6hNY7+h/bxIHGmfP
         3xY6GzeSqA7JduafN70o7s3lUcdtNXYSEklPTvGtdIKLTrTBG+I57Svv6X055xJ9louO
         Kj6duqQxl9TfK97iG3v4jSfXiFT0WuEIrpwOLwr4E45GwNuGIQ1ZsISFXufzOwwy5Kqo
         Cg3ST23q4tvEFGYZKbFE6m2Zrjhf2qpJJEa3tAeAAjwtj5QgGygd99SK0fjvNJtWLeEr
         gIGZFtYYICGenUJcxp//VQP6PNfOZVL4NpnuGO2bl5s5kPEYtNoByB1qFkemN42okU7D
         T6qQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gJKMaw7O;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yaJRVW6w2hA6DS06X0q9G34+AJ/BpxznOw3pmZvioHI=;
        b=j0FiACAS8NXkP0hyQXJ1d2LnKEXIeizGf3oy2TZWBqEVzheTNI41OAj3SzFlr1eJ3L
         lAgSssFVBpQhSbx7bROo+kGmWFNtuCbqnoWKB0r4dXAqjb6ra3kNKR5fHKUxi69ZBMrL
         G08/yhEEgoe+DAV6c5W82TuSBJEEGVCATJI0WgQzP+P530waq8uQE7tpntV0TR5j9suS
         c55QbBbboKblV1yzA+WREgEd9KlhbqqPL2xzgCJj+jnDwc8cufVHdd4MINtmrhqYHzfZ
         sTRTvbLkS2q5NWcJiD3VhVCmyS6PWyjOR47APo56lGIsPxcd2L+rk8FAtNiwUvYLLkzd
         sqYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yaJRVW6w2hA6DS06X0q9G34+AJ/BpxznOw3pmZvioHI=;
        b=S8WkLfIMDCdxhNRITJvxPihlNaz7gyUO3Sekwz6bgt7/QZagnVgAmHRdmdWzr7LqLn
         Saa7kE68pCT8mvTURuA2x0UQ0EmKZsLpEDweXM5YH+8G4+dfEtDmW51X9doFdA3DovLn
         6BZKIWZwn9M2Bt00Xb10cRjjbK4rkzcIfKlyecddU20fRCEZjU4A+/cGigEimWjYQU2o
         +quZOCe+tGA6Qe4UNGPNxKonThcJbjNaYIBi67whMeCFbA+zbnQTtEmoOmfljXFFRo3O
         cEbriunL0O2KmNrIaZt9vawJoWKgnLdCzvihv6XLqs6Atina5wfMKeFGSWOunSWqgm37
         5ZPg==
X-Gm-Message-State: AJIora9uII79/evI8xOS3li/9wg8k4ab+kLVTIeDDdd4XR0CQDYVj/6E
	8JCWePUgsJv01e/WtV8H2HU=
X-Google-Smtp-Source: AGRyM1vY0UYta1T3cPhHci9JsjupZnMTP/fnnK7JvD2r2HbZ3UIZe0L4pUYpuL20eLwjfWQXBqy9ow==
X-Received: by 2002:a17:907:6e90:b0:72b:8205:9e68 with SMTP id sh16-20020a1709076e9000b0072b82059e68mr35540996ejc.767.1658330589572;
        Wed, 20 Jul 2022 08:23:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2551:b0:43a:77a6:b0d with SMTP id
 l17-20020a056402255100b0043a77a60b0dls69073edb.3.-pod-prod-gmail; Wed, 20 Jul
 2022 08:23:08 -0700 (PDT)
X-Received: by 2002:a05:6402:438d:b0:43a:ae23:b77e with SMTP id o13-20020a056402438d00b0043aae23b77emr51756218edc.233.1658330588633;
        Wed, 20 Jul 2022 08:23:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658330588; cv=none;
        d=google.com; s=arc-20160816;
        b=Jy4sYoTxKXXf5PNTBTFqrOLYVvNEVuy3EqWMn/F/pqQIBHm3ygPbgD7DLeUhF3urL1
         JW6avkYZpDkbx8Uvgn2VdliOygKMIy/0INTf+egWfVgR3z0RLaPE3+VJQ+6GKQG6QVtM
         1dCwqHDE2iEDVIjGtwt5OoRx0HnxZQU/zrC8xjjvfxJaInyMPPONVoEnzD6gwUDF33ua
         94BfdYgr4yRSyJBHcwKnfwmihDpY34/QyeEtqal1PewLkI87Phr+hCgZ1I2Ca7IRe8tM
         KRdXi2wuKVvGIa9mIsG7VO2miijM15Vh5TP97hmGl/9tcTN+OQQyaSTWE65UBEamVttW
         xbnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vOU8fNK31UdaRFTxZH7uUNE10MhT+gyU0GxNesrMTbk=;
        b=vsDTDlOe5ST/WlgmbWpY8UWXIV07TDEtgpCDKgbwBawhhKzhzslAbo46FwmZVJncwp
         qlwHhhJSwI3c5+5bfY9AypV3RUgoZu47uIjg0PH0xOfR+KU3lhLkxj5JA9IAUdWQomHe
         kH2ZO+/iitkNn/fzIY9I6M6NxCkpquWdwJkuvyhqjlHdwGwk783NDtQgFl6+vT2tJZvD
         GMESDwGVrkmbOTbIhxnTaLId7pipcLHpMBs8F71toN+yOdfvhyUHtSTfyhbsIHZ9fEza
         pKWR7rHkbNo1Qh3EXGP3vd0B8y9SaDgnR9x6Gsw8Wo78g53qCcp2kyQI3skEQl1fddjP
         JFiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gJKMaw7O;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id l6-20020a056402124600b0043a8ea6fc8dsi617799edw.4.2022.07.20.08.23.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Jul 2022 08:23:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id u5so3559377wrm.4
        for <kasan-dev@googlegroups.com>; Wed, 20 Jul 2022 08:23:08 -0700 (PDT)
X-Received: by 2002:a05:6000:8e:b0:21d:7e97:67ed with SMTP id
 m14-20020a056000008e00b0021d7e9767edmr30017427wrx.343.1658330588252; Wed, 20
 Jul 2022 08:23:08 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-3-elver@google.com>
 <CACT4Y+aYCkTWu+vBdX2d5GNB9z8oZ+8=a330sK9s18FS8t+6=Q@mail.gmail.com>
In-Reply-To: <CACT4Y+aYCkTWu+vBdX2d5GNB9z8oZ+8=a330sK9s18FS8t+6=Q@mail.gmail.com>
From: "'Ian Rogers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Jul 2022 08:22:56 -0700
Message-ID: <CAP-5=fWBVm08LetcyRUh6MK+_gQmyJYxR2sfeZ8LvXfeeJs=zg@mail.gmail.com>
Subject: Re: [PATCH v3 02/14] perf/hw_breakpoint: Provide hw_breakpoint_is_used()
 and use in test
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
 header.i=@google.com header.s=20210112 header.b=gJKMaw7O;       spf=pass
 (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::42b
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

On Mon, Jul 4, 2022 at 8:10 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, 4 Jul 2022 at 17:06, Marco Elver <elver@google.com> wrote:
> >
> > Provide hw_breakpoint_is_used() to check if breakpoints are in use on
> > the system.
> >
> > Use it in the KUnit test to verify the global state before and after a
> > test case.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Acked-by: Ian Rogers <irogers@google.com>

Thanks,
Ian

> > ---
> > v3:
> > * New patch.
> > ---
> >  include/linux/hw_breakpoint.h      |  3 +++
> >  kernel/events/hw_breakpoint.c      | 29 +++++++++++++++++++++++++++++
> >  kernel/events/hw_breakpoint_test.c | 12 +++++++++++-
> >  3 files changed, 43 insertions(+), 1 deletion(-)
> >
> > diff --git a/include/linux/hw_breakpoint.h b/include/linux/hw_breakpoint.h
> > index 78dd7035d1e5..a3fb846705eb 100644
> > --- a/include/linux/hw_breakpoint.h
> > +++ b/include/linux/hw_breakpoint.h
> > @@ -74,6 +74,7 @@ register_wide_hw_breakpoint(struct perf_event_attr *attr,
> >  extern int register_perf_hw_breakpoint(struct perf_event *bp);
> >  extern void unregister_hw_breakpoint(struct perf_event *bp);
> >  extern void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events);
> > +extern bool hw_breakpoint_is_used(void);
> >
> >  extern int dbg_reserve_bp_slot(struct perf_event *bp);
> >  extern int dbg_release_bp_slot(struct perf_event *bp);
> > @@ -121,6 +122,8 @@ register_perf_hw_breakpoint(struct perf_event *bp)  { return -ENOSYS; }
> >  static inline void unregister_hw_breakpoint(struct perf_event *bp)     { }
> >  static inline void
> >  unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events)        { }
> > +static inline bool hw_breakpoint_is_used(void)         { return false; }
> > +
> >  static inline int
> >  reserve_bp_slot(struct perf_event *bp)                 {return -ENOSYS; }
> >  static inline void release_bp_slot(struct perf_event *bp)              { }
> > diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> > index f32320ac02fd..fd5cd1f9e7fc 100644
> > --- a/kernel/events/hw_breakpoint.c
> > +++ b/kernel/events/hw_breakpoint.c
> > @@ -604,6 +604,35 @@ void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events)
> >  }
> >  EXPORT_SYMBOL_GPL(unregister_wide_hw_breakpoint);
> >
> > +/**
> > + * hw_breakpoint_is_used - check if breakpoints are currently used
> > + *
> > + * Returns: true if breakpoints are used, false otherwise.
> > + */
> > +bool hw_breakpoint_is_used(void)
> > +{
> > +       int cpu;
> > +
> > +       if (!constraints_initialized)
> > +               return false;
> > +
> > +       for_each_possible_cpu(cpu) {
> > +               for (int type = 0; type < TYPE_MAX; ++type) {
> > +                       struct bp_cpuinfo *info = get_bp_info(cpu, type);
> > +
> > +                       if (info->cpu_pinned)
> > +                               return true;
> > +
> > +                       for (int slot = 0; slot < nr_slots[type]; ++slot) {
> > +                               if (info->tsk_pinned[slot])
> > +                                       return true;
> > +                       }
> > +               }
> > +       }
> > +
> > +       return false;
> > +}
> > +
> >  static struct notifier_block hw_breakpoint_exceptions_nb = {
> >         .notifier_call = hw_breakpoint_exceptions_notify,
> >         /* we need to be notified first */
> > diff --git a/kernel/events/hw_breakpoint_test.c b/kernel/events/hw_breakpoint_test.c
> > index 433c5c45e2a5..5ced822df788 100644
> > --- a/kernel/events/hw_breakpoint_test.c
> > +++ b/kernel/events/hw_breakpoint_test.c
> > @@ -294,7 +294,14 @@ static struct kunit_case hw_breakpoint_test_cases[] = {
> >  static int test_init(struct kunit *test)
> >  {
> >         /* Most test cases want 2 distinct CPUs. */
> > -       return num_online_cpus() < 2 ? -EINVAL : 0;
> > +       if (num_online_cpus() < 2)
> > +               return -EINVAL;
> > +
> > +       /* Want the system to not use breakpoints elsewhere. */
> > +       if (hw_breakpoint_is_used())
> > +               return -EBUSY;
> > +
> > +       return 0;
> >  }
> >
> >  static void test_exit(struct kunit *test)
> > @@ -308,6 +315,9 @@ static void test_exit(struct kunit *test)
> >                 kthread_stop(__other_task);
> >                 __other_task = NULL;
> >         }
> > +
> > +       /* Verify that internal state agrees that no breakpoints are in use. */
> > +       KUNIT_EXPECT_FALSE(test, hw_breakpoint_is_used());
> >  }
> >
> >  static struct kunit_suite hw_breakpoint_test_suite = {
> > --
> > 2.37.0.rc0.161.g10f37bed90-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP-5%3DfWBVm08LetcyRUh6MK%2B_gQmyJYxR2sfeZ8LvXfeeJs%3Dzg%40mail.gmail.com.
