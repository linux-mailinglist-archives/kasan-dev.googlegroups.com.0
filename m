Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7UD272AKGQE7HPRVIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id E34A41A7F0D
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 16:00:31 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id r28sf3891987pfl.23
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 07:00:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586872830; cv=pass;
        d=google.com; s=arc-20160816;
        b=u0cfNod4ciyfHoUdSvqS+BXYiUBacrTyJ3zgMQ7HooL6vi8ORFvZuDi2X3i0kP9mQs
         URxD+LgRKy1+5HQxhJAyumbIZeUFkh0IWW4CKBUE6pqG5ua6igEch9jp0Jh1tDRYj1d2
         hqPlwZmkFNXdbyaQ/pqP4DyHQI8LgbSG1nDCkhg4lCL3iCalBgJUjzkTg06+9Tc6DQkt
         nnuF9cDVQwlhp/5dX9z4H10F6mQKsxxuwN1Ia8NqaOLt/L2U5aaCzIlJjfhQxPXAgyTy
         r9W53lTxWYQloplQCrcLgtMvk2oE60k8G41i4/Ut7ZuTFu6MwmKnKJ4w6L00XPywo49+
         67RQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=45k66+1DSrmd6as1kM0NPS9Qh0+bz7AJSIp0MSqyiS4=;
        b=rmy7kvTZvg+gt+Q8PAYPAskvMsGdv/QG++ZpWiNb1Y0pxq72xX8DyQN9ddai4NCbAv
         mKOBkBGaRlD70S1krOk9XBieRVzXJabijZUz5bjrbO4HndZ8eFtbS5kXPuMPOiBa4E+W
         SXWZRHiakXIaZW3jZESthH/gjPMXW4hZ2/pSHD/1/6LKfitKaonBtjHusCl1kytNuwu2
         UUyCru6aJ6cH9HyqRYqj+BwNXEQEVOkFeJZy+jC95Y3tGiekw63ExqnmLbcpb66h8Ya+
         WuEE25QO4wohx6SWN+jrbZy5TX2o4GkI4nBQ4udYPR8GECdRrnK2MW2eKjcc4GhrShJo
         nOug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=twdTfWjV;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=45k66+1DSrmd6as1kM0NPS9Qh0+bz7AJSIp0MSqyiS4=;
        b=YSC1JE5JQvMcRX7ovB8y90++Ob4JMUOpyDdX+x03k1EImqfPANV0LzGXHxRtiyPshB
         tFgjqlP6RpU2UagpPdaQfOQMQrqk5obvdLr9vYcRCgDY4Xp1DFSOIXU7cge4ABB4WS+b
         2JcLzKR78GGSiAoDv2UQ24bfKW2igCp30xlrw513tv8silARN5EXo7qd57Hw9wYCIgqN
         oRLr/98jJhnRYph9GF9VH55PAUyzS3Tp8QCH/gnUKF8EMlxhLhB67S4y2ej9EJrgiikX
         8a4VDYidOC4JjGT+Cx2D1i+3SDsDvsRPUAVtzGh+xKHnuUhuDQWnoT1Wh9P73xaolOfZ
         m66Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=45k66+1DSrmd6as1kM0NPS9Qh0+bz7AJSIp0MSqyiS4=;
        b=s9ttAdDH3r6CJx0k4jd7nMbXJ7HzKKiukk7Hjbt3apX420ZU3N5szyel8cp+MYyqwp
         zSNOkxC1FkLP0/gpl2VwCFmq/KgfDDJ7CT5PgS62teXkCe/EwW4rcbhNbee9SePT1Cgn
         NDPhR4LfVuichhsx8HqT3CbztwQQS3/P1bpnVeB3nETZJWOcf1/pIjOAfLyv4mkMxbWS
         wM/5I818xham7m2qnehEbu/RQ+7Oe2isBLh9pFukHG9AFA5gU7Z62e3y1d0JzCbEHwjl
         l8XEElig1qfpCD5SBD+N40C5w4PDiIVHRAN997zWYD1nfPRjCAwVzvJGxIomrAdLgGIU
         9dfw==
X-Gm-Message-State: AGi0PubXqdAzEjqlnZaNWQc1Mn/CaXlJ9RviUbzpxyHNtVNS/YvrLKtN
	hCr2i+HNQhUJ2Xo0Z1JiSzU=
X-Google-Smtp-Source: APiQypJkcsAEVKZWtO9O0N7NezvdqVpCmJikcmoHySOXiU2BOWtZR74vvWBcs8rlypp1ts9xjPbjFQ==
X-Received: by 2002:a63:6f4c:: with SMTP id k73mr6364978pgc.241.1586872830279;
        Tue, 14 Apr 2020 07:00:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a701:: with SMTP id w1ls3450781plq.7.gmail; Tue, 14
 Apr 2020 07:00:29 -0700 (PDT)
X-Received: by 2002:a17:902:b097:: with SMTP id p23mr81701plr.195.1586872829800;
        Tue, 14 Apr 2020 07:00:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586872829; cv=none;
        d=google.com; s=arc-20160816;
        b=xsIALsbQlRu5WENkc4IlftMEPQw2QTpZZlNUdcwcIAs38jFEzCszSW/JIrtzqPjwsh
         OPhqsYTHrBbuW5daV2guDsu9cDKTEGeCvJTmVUJq6V5LlEdAsUnVRyuBU5hh4aISQggf
         84YM95GGWHVXNjVxdwUpkZELtb24hO3N5QJz1f5g3JCvtiHAXTp+RJScmBE6N+mwehj4
         DZBkVt20qwTyBUr8183vynnP0I5BnO4NUMyaZnNKHvHVsVTKB8XACl8N3so+TY1yIUBE
         yEn8GgNshtJqqe3DQrXm4nmY4DoAmH9zgO2KCbumDF0J/LIa+gb040BNXEUFJbxUWk4y
         QWWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FXAHgZfY/WDAJS22zqOeVPqoXgR7iYMdLBK+n2JKck8=;
        b=QX6hTMnO6FernzgQixdcgE/vI/axn8HwSNSkZ7o3Cz/muz/Mjkqy1aGxa0PKxzVkMk
         Thz8sYB61PJkjqqr0NdrmCjBn7cTuK8mpvCHRCWK31977KCA5zFiZVaT4nRnO46NIIfY
         /2sFdLYqew2Y0R/v1KdfoBMUrWTWSiePSIUd9QOi7v9jjLqji0Gski1DzIpszv1G2hEn
         eaBeFOs6xmDIZ5YWT+Km0SfdwTc/y98dLL9AYIOw/UqRj7DakPZb7xIv085Y4BdWyzkv
         TpS62PHBLIVhMchtMXbr45Bq0eg4ZThS5+wFAUzXBlRDCTnhkbQqRoNTSTmAN3WPhenO
         CSYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=twdTfWjV;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id g23si1084357pgi.5.2020.04.14.07.00.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Apr 2020 07:00:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id u65so6094330pfb.4
        for <kasan-dev@googlegroups.com>; Tue, 14 Apr 2020 07:00:29 -0700 (PDT)
X-Received: by 2002:a63:cf02:: with SMTP id j2mr22304641pgg.130.1586872829015;
 Tue, 14 Apr 2020 07:00:29 -0700 (PDT)
MIME-Version: 1.0
References: <20200414031647.124664-1-davidgow@google.com> <20200414031647.124664-3-davidgow@google.com>
In-Reply-To: <20200414031647.124664-3-davidgow@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Apr 2020 16:00:18 +0200
Message-ID: <CAAeHK+yT+hPK6Vcj+KWv-7vPk=OQUGvODJUUO3atqHcoVTXvSQ@mail.gmail.com>
Subject: Re: [PATCH v5 2/4] KUnit: KASAN Integration
To: David Gow <davidgow@google.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=twdTfWjV;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Apr 14, 2020 at 5:17 AM 'David Gow' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> From: Patricia Alfonso <trishalfonso@google.com>
>
> Integrate KASAN into KUnit testing framework.
>         - Fail tests when KASAN reports an error that is not expected
>         - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN
>         tests
>         - Expected KASAN reports pass tests and are still printed when run
>         without kunit_tool (kunit_tool still bypasses the report due to the
>         test passing)
>         - KUnit struct in current task used to keep track of the current
>         test from KASAN code
>         - Also make KASAN no-longer panic when panic_on_warn and
>         kasan_multi_shot are enabled (as multi-shot does nothing
>         otherwise)
>
> Make use of "[PATCH v3 kunit-next 1/2] kunit: generalize
> kunit_resource API beyond allocated resources" and "[PATCH v3
> kunit-next 2/2] kunit: add support for named resources" from Alan
> Maguire [1]
>         - A named resource is added to a test when a KASAN report is
>          expected
>         - This resource contains a struct for kasan_data containing
>         booleans representing if a KASAN report is expected and if a
>         KASAN report is found
>
> [1] (https://lore.kernel.org/linux-kselftest/1583251361-12748-1-git-send-email-alan.maguire@oracle.com/T/#t)
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> Signed-off-by: David Gow <davidgow@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> ---
>  include/kunit/test.h  |  5 +++++
>  include/linux/kasan.h |  6 ++++++
>  lib/kunit/test.c      | 13 ++++++++-----
>  lib/test_kasan.c      | 44 +++++++++++++++++++++++++++++++++++++++----
>  mm/kasan/report.c     | 34 ++++++++++++++++++++++++++++++++-
>  5 files changed, 92 insertions(+), 10 deletions(-)
>
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index ac59d18e6bab..1dc3d118f64b 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -225,6 +225,11 @@ struct kunit {
>         struct list_head resources; /* Protected by lock. */
>  };
>
> +static inline void kunit_set_failure(struct kunit *test)
> +{
> +       WRITE_ONCE(test->success, false);
> +}
> +
>  void kunit_init_test(struct kunit *test, const char *name, char *log);
>
>  int kunit_run_tests(struct kunit_suite *suite);
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 5cde9e7c2664..148eaef3e003 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -14,6 +14,12 @@ struct task_struct;
>  #include <asm/kasan.h>
>  #include <asm/pgtable.h>
>
> +/* kasan_data struct is used in KUnit tests for KASAN expected failures */
> +struct kunit_kasan_expectation {
> +       bool report_expected;
> +       bool report_found;
> +};
> +
>  extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
>  extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
>  extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
> diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> index 2cb7c6220a00..030a3281591e 100644
> --- a/lib/kunit/test.c
> +++ b/lib/kunit/test.c
> @@ -10,16 +10,12 @@
>  #include <linux/kernel.h>
>  #include <linux/kref.h>
>  #include <linux/sched/debug.h>
> +#include <linux/sched.h>
>
>  #include "debugfs.h"
>  #include "string-stream.h"
>  #include "try-catch-impl.h"
>
> -static void kunit_set_failure(struct kunit *test)
> -{
> -       WRITE_ONCE(test->success, false);
> -}
> -
>  static void kunit_print_tap_version(void)
>  {
>         static bool kunit_has_printed_tap_version;
> @@ -288,6 +284,10 @@ static void kunit_try_run_case(void *data)
>         struct kunit_suite *suite = ctx->suite;
>         struct kunit_case *test_case = ctx->test_case;
>
> +#if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT))
> +       current->kunit_test = test;
> +#endif /* IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT) */
> +
>         /*
>          * kunit_run_case_internal may encounter a fatal error; if it does,
>          * abort will be called, this thread will exit, and finally the parent
> @@ -603,6 +603,9 @@ void kunit_cleanup(struct kunit *test)
>                 spin_unlock(&test->lock);
>                 kunit_remove_resource(test, res);
>         }
> +#if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT))
> +       current->kunit_test = NULL;
> +#endif /* IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT)*/
>  }
>  EXPORT_SYMBOL_GPL(kunit_cleanup);
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 3872d250ed2c..7b4cb107b387 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -23,12 +23,48 @@
>
>  #include <asm/page.h>
>
> -/*
> - * Note: test functions are marked noinline so that their names appear in
> - * reports.
> +#include <kunit/test.h>
> +
> +static struct kunit_resource resource;
> +static struct kunit_kasan_expectation fail_data;
> +static bool multishot;
> +
> +static int kasan_test_init(struct kunit *test)
> +{
> +       /*
> +        * Temporarily enable multi-shot mode and set panic_on_warn=0.
> +        * Otherwise, we'd only get a report for the first case.
> +        */
> +       multishot = kasan_save_enable_multi_shot();
> +
> +       return 0;
> +}
> +
> +static void kasan_test_exit(struct kunit *test)
> +{
> +       kasan_restore_multi_shot(multishot);
> +}
> +
> +/**
> + * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
> + * not cause a KASAN error. This uses a KUnit resource named "kasan_data." Do
> + * Do not use this name for a KUnit resource outside here.
> + *
>   */
> +#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do { \
> +       fail_data.report_expected = true; \
> +       fail_data.report_found = false; \
> +       kunit_add_named_resource(test, \
> +                               NULL, \
> +                               NULL, \
> +                               &resource, \
> +                               "kasan_data", &fail_data); \
> +       condition; \
> +       KUNIT_EXPECT_EQ(test, \
> +                       fail_data.report_expected, \
> +                       fail_data.report_found); \
> +} while (0)
>

[...]

> -static noinline void __init kmalloc_oob_right(void)

Actually this also needs to be fixed. You remove this line in this
patch and add it back in the next one. Please test that the kernel
builds with your patches applied one by one.

>  {
>         char *ptr;
>         size_t size = 123;
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 5ef9f24f566b..a58a9f3b7f2c 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -32,6 +32,8 @@
>
>  #include <asm/sections.h>
>
> +#include <kunit/test.h>
> +
>  #include "kasan.h"
>  #include "../slab.h"
>
> @@ -92,7 +94,7 @@ static void end_report(unsigned long *flags)
>         pr_err("==================================================================\n");
>         add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
>         spin_unlock_irqrestore(&report_lock, *flags);
> -       if (panic_on_warn)
> +       if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
>                 panic("panic_on_warn set ...\n");
>         kasan_enable_current();
>  }
> @@ -455,12 +457,37 @@ static bool report_enabled(void)
>         return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
>  }
>
> +#if IS_ENABLED(CONFIG_KUNIT)
> +static void kasan_update_kunit_status(struct kunit *cur_test)
> +{
> +       struct kunit_resource *resource;
> +       struct kunit_kasan_expectation *kasan_data;
> +
> +       resource = kunit_find_named_resource(cur_test, "kasan_data");
> +
> +       if (!resource) {
> +               kunit_set_failure(cur_test);
> +               return;
> +       }
> +
> +       kasan_data = (struct kunit_kasan_expectation *)resource->data;
> +       kasan_data->report_found = true;
> +       kunit_put_resource(resource);
> +}
> +#endif /* IS_ENABLED(CONFIG_KUNIT) */
> +
>  void kasan_report_invalid_free(void *object, unsigned long ip)
>  {
>         unsigned long flags;
>         u8 tag = get_tag(object);
>
>         object = reset_tag(object);
> +
> +#if IS_ENABLED(CONFIG_KUNIT)
> +       if (current->kunit_test)
> +               kasan_update_kunit_status(current->kunit_test);
> +#endif /* IS_ENABLED(CONFIG_KUNIT) */
> +
>         start_report(&flags);
>         pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
>         print_tags(tag, object);
> @@ -481,6 +508,11 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
>         if (likely(!report_enabled()))
>                 return;
>
> +#if IS_ENABLED(CONFIG_KUNIT)
> +       if (current->kunit_test)
> +               kasan_update_kunit_status(current->kunit_test);
> +#endif /* IS_ENABLED(CONFIG_KUNIT) */
> +
>         disable_trace_on_warning();
>
>         tagged_addr = (void *)addr;
> --
> 2.26.0.110.g2183baf09c-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200414031647.124664-3-davidgow%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByT%2BhPK6Vcj%2BKWv-7vPk%3DOQUGvODJUUO3atqHcoVTXvSQ%40mail.gmail.com.
