Return-Path: <kasan-dev+bncBCMIZB7QWENRBQUFRSLAMGQEINJJXVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id AAF0C565975
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 17:09:55 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id k6-20020a2e9206000000b0025a8ce1a22esf2810709ljg.9
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 08:09:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656947395; cv=pass;
        d=google.com; s=arc-20160816;
        b=U0TLfapJ7TqYXBV2Dqyrk4/h7oBecsHskXh7WwbOz20ZoS7D2rhVxYH+KZ1slXh+C4
         6KWfaCxcC/5e1pdQK869wOlO3HK/1S0EVvTVsCqsh4UIGEHFZejEcndfVPoNl8aXIsWm
         3SxJvZyhlEDJgYAMZ/rDqpARlIvzL3U82/ttmjSeF7zqNwLZpb6JFfM8+MrVgQfAKVU0
         XtMZx5cozGTRKNS+Dn0V3r3uKX3faCIQMDs7nob54PYi1TBzFn44ttvkhSq8ewyn9y6w
         /fgM69g9KYpM287e0zMwQiSDObGWwArz96pjmfgIZQcEUhT9jS5T4QW9RdsuY2L521Rd
         AfAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+qkh/cP5kayMvk1TbIkj/ljU59SbWAcflNUPT7lyKiA=;
        b=WNeylcaHepTUpX40AlLgANRcGOE0hvvCeFLvUSRMBArmATuL8DwcHYhURvef6QmrS5
         2eTMuzlg8y60UJ0FYIW4szXyLuEx8nXt86LgjiBSpGP83NHQFPfWY6dupGXyp6KqzUZG
         H6NXt5JveSoKG5nwG4DEcRyjxorH78NWyf/OfLP3KLAU5ZLBXe20J1Bu5nqAKbEGFp7+
         0gjhD0RIcpr4lokiCmXrljQ9+hhJdO18n5PEp5V65CaBCD5/MQFDQoREAkrHlEwdz4OD
         gTE598TPCbjbs6orTg0OHk3g2kxRMwLQhRfzvwukpBSnZ3zL/ej1aPiFL5vQUrR8p/St
         PpLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="ThmQg/xx";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+qkh/cP5kayMvk1TbIkj/ljU59SbWAcflNUPT7lyKiA=;
        b=JOkpzwvFZ+lRCRKu8P64Y0JAyOav0qWYslS8Bb0FjsR474FKY/0QrQySCvPc5KChpZ
         IjwarXxjsmMw0c6MyTjhJUUxgzuECsUPYoAQC7sM3tF2Rniw/UUzzfEIhz4rIiZRiIp6
         JfqReu5JKKybOomsi9TJlCrwIxqtXU0PYVKtssVEHYt/KNee3CVnrD2vvLbUk3qHS1kU
         fMWS0uHyVlWS+WZCubt2k2ZVKOVeQbHy00bbmfJ9rZ+dvJuDIPVS/f5+S+sh0ha2VU+h
         OxaHbhtDEKkG0r4iAZg7+ys0NokNONWC8D9pHFqz5SnKOLYDURmNExiYR+TCQBLnrFKz
         +wSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+qkh/cP5kayMvk1TbIkj/ljU59SbWAcflNUPT7lyKiA=;
        b=ld3tjS9xRPh4dOjbUIlTzJu840x6QUTRWpDISYwxx/JYV36bTpqzcI5sUr3M2q8FXD
         QTLtI6DNgmjJV4+umx09HJyHcPpSpD2poIoHBG6GzjePWv/3+1zJVIbuZVhbEEgnmt5J
         oaWxsz6vzA/rjsLAUAcAiiEsn0HABrax5872FQ9NpNzeUKUG5T/5AmeSP25NxMytdH5p
         Ntw3nRob0EkDOASiDK/dwdn85FRCuSQrILZc5c+Unw0e/cki2vhGF5XOGV+tMeJmQhem
         hBMYoxOTL+67pQ//2AywNKs3HnaH8dVO5m5x/ubb/eNySRrO6BZElA8SpR1cHXrYtiaK
         JIJQ==
X-Gm-Message-State: AJIora/zYiydEmduu3uaiwbO7R4hYhr/qJi2c0ltrEDaxjzJnc03aWza
	3heP69BvWIigK6yO2vu6zLo=
X-Google-Smtp-Source: AGRyM1scfXNSdzsSjohBOWAZ/+bZxF7j/IkjqMXGb6YRcUQ8sF/Oi4W8DJh7lFgTEwytg8WM5hxDtQ==
X-Received: by 2002:a2e:a793:0:b0:25a:74f4:b377 with SMTP id c19-20020a2ea793000000b0025a74f4b377mr16972387ljf.177.1656947395181;
        Mon, 04 Jul 2022 08:09:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0c:b0:47f:9907:2b50 with SMTP id
 f12-20020a0565123b0c00b0047f99072b50ls788301lfv.3.gmail; Mon, 04 Jul 2022
 08:09:54 -0700 (PDT)
X-Received: by 2002:a05:6512:2611:b0:478:da8f:e2d8 with SMTP id bt17-20020a056512261100b00478da8fe2d8mr18567121lfb.460.1656947394231;
        Mon, 04 Jul 2022 08:09:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656947394; cv=none;
        d=google.com; s=arc-20160816;
        b=A5LvrXYS5dirxASHMLGAobdvk4CowZS6zYH1ubfHBbDmETLDDKYxyppc4DlPHFmb8c
         XAoUIrClMR6Qpr1dPreCw7ek4NOeBI5ybDZX6JiegyTKND05lYH4XGMPr6fMrnKD1wJJ
         7COR86D/nCA5/w2eGLvHipZ+x8GUYj7BqLrdnXt3QZTyKr2TuBnut3/EVZOSq64ulJtd
         XQUy1POd+KZR/OSgbKbuW058dqIYE7yFc39aU/1Dja2ficoPhC6rg9hPHga47xDB03gd
         KL4d/V1cSYS7ldRBEfuoqJZQUS1KGuhVsg2eZvfkkNHFBR3VQSNrlcDv0DSxZ3clS/44
         gPMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7hCwDytAsB4d/o82PG/imXl6AB+798LjkY2ZfHNBYrI=;
        b=vOwKdm48wO2UvDwGXhbN3NaV12/ETarqf1VDpRItpN86IPEKrxaQWUAxC+31e0vpPC
         LTKpKNdRVsnRkpeN+/44kyROzv7L55t3NuQzhs9cPtsdbjYGmd977VKH2L19HxKMt1Ex
         6jvnINLNpt5VedvS9IkwEJ/F9ityzUEclRU+kbZmhQuq1w0873OY/dsVlr0gJmmSmao3
         +dBQbFoZnaeDVIf33cG1PD2iTEx7ob/ML/LFHQJVmGOlCJout/fKGLQMKuXBm1Cl6f2x
         VbtMRLuHdTCvb8EF3Ccj3O6F3dC6fnpUbtQjk8OzS5goBusFbuFQUHVoSdSVWE/zKt6k
         hLow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="ThmQg/xx";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12a.google.com (mail-lf1-x12a.google.com. [2a00:1450:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id o19-20020ac24c53000000b004810d3e125csi1075727lfk.11.2022.07.04.08.09.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 08:09:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) client-ip=2a00:1450:4864:20::12a;
Received: by mail-lf1-x12a.google.com with SMTP id y16so16235563lfb.9
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 08:09:54 -0700 (PDT)
X-Received: by 2002:a05:6512:1056:b0:47f:6f00:66c2 with SMTP id
 c22-20020a056512105600b0047f6f0066c2mr18349441lfb.410.1656947393715; Mon, 04
 Jul 2022 08:09:53 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-3-elver@google.com>
In-Reply-To: <20220704150514.48816-3-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 4 Jul 2022 17:09:42 +0200
Message-ID: <CACT4Y+aYCkTWu+vBdX2d5GNB9z8oZ+8=a330sK9s18FS8t+6=Q@mail.gmail.com>
Subject: Re: [PATCH v3 02/14] perf/hw_breakpoint: Provide hw_breakpoint_is_used()
 and use in test
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
 header.i=@google.com header.s=20210112 header.b="ThmQg/xx";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a
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
> Provide hw_breakpoint_is_used() to check if breakpoints are in use on
> the system.
>
> Use it in the KUnit test to verify the global state before and after a
> test case.
>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> v3:
> * New patch.
> ---
>  include/linux/hw_breakpoint.h      |  3 +++
>  kernel/events/hw_breakpoint.c      | 29 +++++++++++++++++++++++++++++
>  kernel/events/hw_breakpoint_test.c | 12 +++++++++++-
>  3 files changed, 43 insertions(+), 1 deletion(-)
>
> diff --git a/include/linux/hw_breakpoint.h b/include/linux/hw_breakpoint.h
> index 78dd7035d1e5..a3fb846705eb 100644
> --- a/include/linux/hw_breakpoint.h
> +++ b/include/linux/hw_breakpoint.h
> @@ -74,6 +74,7 @@ register_wide_hw_breakpoint(struct perf_event_attr *attr,
>  extern int register_perf_hw_breakpoint(struct perf_event *bp);
>  extern void unregister_hw_breakpoint(struct perf_event *bp);
>  extern void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events);
> +extern bool hw_breakpoint_is_used(void);
>
>  extern int dbg_reserve_bp_slot(struct perf_event *bp);
>  extern int dbg_release_bp_slot(struct perf_event *bp);
> @@ -121,6 +122,8 @@ register_perf_hw_breakpoint(struct perf_event *bp)  { return -ENOSYS; }
>  static inline void unregister_hw_breakpoint(struct perf_event *bp)     { }
>  static inline void
>  unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events)        { }
> +static inline bool hw_breakpoint_is_used(void)         { return false; }
> +
>  static inline int
>  reserve_bp_slot(struct perf_event *bp)                 {return -ENOSYS; }
>  static inline void release_bp_slot(struct perf_event *bp)              { }
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index f32320ac02fd..fd5cd1f9e7fc 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -604,6 +604,35 @@ void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events)
>  }
>  EXPORT_SYMBOL_GPL(unregister_wide_hw_breakpoint);
>
> +/**
> + * hw_breakpoint_is_used - check if breakpoints are currently used
> + *
> + * Returns: true if breakpoints are used, false otherwise.
> + */
> +bool hw_breakpoint_is_used(void)
> +{
> +       int cpu;
> +
> +       if (!constraints_initialized)
> +               return false;
> +
> +       for_each_possible_cpu(cpu) {
> +               for (int type = 0; type < TYPE_MAX; ++type) {
> +                       struct bp_cpuinfo *info = get_bp_info(cpu, type);
> +
> +                       if (info->cpu_pinned)
> +                               return true;
> +
> +                       for (int slot = 0; slot < nr_slots[type]; ++slot) {
> +                               if (info->tsk_pinned[slot])
> +                                       return true;
> +                       }
> +               }
> +       }
> +
> +       return false;
> +}
> +
>  static struct notifier_block hw_breakpoint_exceptions_nb = {
>         .notifier_call = hw_breakpoint_exceptions_notify,
>         /* we need to be notified first */
> diff --git a/kernel/events/hw_breakpoint_test.c b/kernel/events/hw_breakpoint_test.c
> index 433c5c45e2a5..5ced822df788 100644
> --- a/kernel/events/hw_breakpoint_test.c
> +++ b/kernel/events/hw_breakpoint_test.c
> @@ -294,7 +294,14 @@ static struct kunit_case hw_breakpoint_test_cases[] = {
>  static int test_init(struct kunit *test)
>  {
>         /* Most test cases want 2 distinct CPUs. */
> -       return num_online_cpus() < 2 ? -EINVAL : 0;
> +       if (num_online_cpus() < 2)
> +               return -EINVAL;
> +
> +       /* Want the system to not use breakpoints elsewhere. */
> +       if (hw_breakpoint_is_used())
> +               return -EBUSY;
> +
> +       return 0;
>  }
>
>  static void test_exit(struct kunit *test)
> @@ -308,6 +315,9 @@ static void test_exit(struct kunit *test)
>                 kthread_stop(__other_task);
>                 __other_task = NULL;
>         }
> +
> +       /* Verify that internal state agrees that no breakpoints are in use. */
> +       KUNIT_EXPECT_FALSE(test, hw_breakpoint_is_used());
>  }
>
>  static struct kunit_suite hw_breakpoint_test_suite = {
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaYCkTWu%2BvBdX2d5GNB9z8oZ%2B8%3Da330sK9s18FS8t%2B6%3DQ%40mail.gmail.com.
