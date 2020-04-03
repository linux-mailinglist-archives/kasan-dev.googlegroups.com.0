Return-Path: <kasan-dev+bncBDX4HWEMTEBRBB7QTT2AKGQEMY7WSCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id D721019D774
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Apr 2020 15:20:08 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id i26sf5921137pfk.20
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Apr 2020 06:20:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585920007; cv=pass;
        d=google.com; s=arc-20160816;
        b=dfZ4PFvLxm9agrI6ox55eS5RKhdpPR9D4RRzmz5Cyusuy1PQpG9lXR1gt4E4Z0k6NF
         vhXnXOYQvQI8BECCXbG16KCbtWsqGx8vzQ7oR+vrkcecm/FXzUDh48y7c4V664wPO4/d
         SHk30yA3AADluao+qUqjzl64QYl4i66hJezvi5z49M2dq6t/QypOY9Y1y+mj2WIQ/XmC
         rbLi3iOPgwlK+wwQz54HrLK9kXTuczGy2bnGVCeMsU2QyWm3+41V25KGSmSCCOPlJaEM
         wyFzQVtk0o4Wv712tntdHLePx5pss6rqa1xTmnUDANf6yZs8XFzaWlBYXUHUjKaxd9Za
         yobQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=O39m1rLoqI/bvoDeTe7Y+GxGwXJimHTFW8r1LGXXsoc=;
        b=Haad82fq5NEu+et2LP0sv7Ji6ddJR4ZV+V57MkyCghkVXqkixNQ0h/OPvPGCssAyrH
         SIlVQhSwLr6lw895XCNFm2FJh8jCa7bqHuBFuK+YctpCJOXZxwD8gH94hF85Z+gKEOnw
         s/Q6T0LpumGU6B89VW0PKFn+oKlxr24BOYjSu78E8FP241HTQMlstn3N8OzhfTiiv1a3
         DdjiUpuPXlk9ZvQng9AYKASfLQb70V3VtFgKyrwsL0zK3ZMpCGTYekxLQxz0VQ/cK1F5
         FjXOe+lWwrl2oJ9wRLmAT+J8qpACxDdNAFbn42fY5A8sr2mzVmHKW2X0NMduSAlzh2mt
         uZ4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I02BS8Cl;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O39m1rLoqI/bvoDeTe7Y+GxGwXJimHTFW8r1LGXXsoc=;
        b=pFGDEQ9BR0d1tP2COkOvzO7BjMOOp/572NfN77hawFl7keLMo24Em8qCAFWQoUPOXZ
         oIBop0Y4HJPVmP2PPL9THOa3XB4DoXCABE5DR+FBbIuy4o4ollW56ZZxJhmrQg48ZxME
         MhwLofcdTBrjRr+71kWqSJnc2Vmy35RzgVCeqHL63n+jJ8wKqDINiBfEsXJu2+qwpXp4
         WC8q6WVCqyYkZs0sTLNFMMIHBq3ISMwNjZaF9smGIhpAA1ftDsmbZHNw/U0U6dS8JaPy
         4Gw13nZ9y34voGwojI9+xMzzrNNUGhMlMdwUCQajiAlEMxzFu3SiGYOzwjHEe2brmC75
         KBMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O39m1rLoqI/bvoDeTe7Y+GxGwXJimHTFW8r1LGXXsoc=;
        b=I9qp5yEd2yoWz4jnCecsEZoRADSiPUOR0uDq4aywKReFPUw8OuhpSuHQhcNZj5S9SL
         xsDkTjYiEcmYdG7GVIBnCo1L/OJGRAzy43Me10mJ/ZDlXbqP0AlPiNTEnYLSEos1xeiD
         fzvBXXwIutIm/YHvDMzpV/NYEkao8nMadnItf7v9h0/mHqQ5Yf3ZN9rppzsW/r2R5lsW
         fH70UczfNrJZCHuuD2QM0FtLK+2bcMqKJIh3hXAQtefTmLH5mWydLCWkW3F86FHIQMGA
         15P9hIu+8okftO8bamnPB2wsUHPqedDcn8YTVgpkb2E4dzMHEn/vzxBftXp4DswOCCzE
         hVug==
X-Gm-Message-State: AGi0PubNnYsUEHCLMpdzxqpB62qoR/5JuLV0qfWQ9582fgQ5+8TAoAiX
	Oxvwo4HJeYeJ1fGBLwFNOJs=
X-Google-Smtp-Source: APiQypI/P5UaE5NYJ25zCuYhKGUwmO9vYLLm+YIyDcu0W2pCCy6tz4Wgc4UvcKyraiML+pAgTjkF5A==
X-Received: by 2002:a65:5249:: with SMTP id q9mr8083224pgp.150.1585920007494;
        Fri, 03 Apr 2020 06:20:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1853:: with SMTP id 80ls5078855pfy.11.gmail; Fri, 03 Apr
 2020 06:20:07 -0700 (PDT)
X-Received: by 2002:a63:6f0c:: with SMTP id k12mr8326389pgc.142.1585920006931;
        Fri, 03 Apr 2020 06:20:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585920006; cv=none;
        d=google.com; s=arc-20160816;
        b=eGCCp3MLqSTusmxjqiKB8luxfOdhwjAu2g/9rjYgMEybMh1ZH2fnROUf8twcOBOo2n
         gzShOLssBeUi+zOFAKVI1BI8zgnh39A5f4872yjDEM48vP0EGeQwcuc5LDDCtTKI2cmg
         VJ/8uRBuwZaHEzyLYjzn0/BHppr/LVhCN+ZdRMvZNyq5bvhZMKh9YPHdhBkl1HnlIdMy
         zvy8jWpW/kKR7EnXTbiCA01gEf1bEa+N8yygzOw58LsCyg1JytWIxrZ31RUb2ycby6Ze
         zi4ToE1wENl3MEMLpSdXFITfsy8vytextrnrK/TENkPS31Uw9U8LnCke/1Q52wLmaBaO
         NjDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sfmb+P5Q77bDNWXkgWIIUyRAWn0S17E7eS1KF2xpWtg=;
        b=jDjFG4/zd2F+ZSKsC/uFcQeH/SiJ7WKbJJGYWpYPVqk1VVd/3xMbo0/dLHmAKyjLLA
         f1z4XNy2swqLB0trsFmed20aqGcfTtD9DZfNXgrSxps7YH/KEn8UgSHiJw9OCcXz3oWs
         rXk86cWm8kdIGqtikCCzKrqGEoAF0MCsJ/GPpm6UfLu6Y2oR5nrxq6M+/61ztlFVxbBU
         K6HYGPxZAM44d6mPWNL9+qpf7MUmtTEypPKv/MmGEC5VNv/l6gdIC6hTWs5qci/e9vJx
         GirvYfEB4M/hCbtAYazhtP5smu6gbVVw6gJTZRsDJ5M+6hzA652muChlLVEsuXBlwCG6
         6zNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I02BS8Cl;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id f8si613733pjw.3.2020.04.03.06.20.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Apr 2020 06:20:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id c23so3507113pgj.3
        for <kasan-dev@googlegroups.com>; Fri, 03 Apr 2020 06:20:06 -0700 (PDT)
X-Received: by 2002:a63:b52:: with SMTP id a18mr8295803pgl.130.1585920006196;
 Fri, 03 Apr 2020 06:20:06 -0700 (PDT)
MIME-Version: 1.0
References: <20200402204639.161637-1-trishalfonso@google.com> <20200402204639.161637-2-trishalfonso@google.com>
In-Reply-To: <20200402204639.161637-2-trishalfonso@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 3 Apr 2020 15:19:55 +0200
Message-ID: <CAAeHK+xFLmnAHPPCrmmqb1of7+cZmvKKPgAMACjArrLChG=xDw@mail.gmail.com>
Subject: Re: [PATCH v4 2/4] KUnit: KASAN Integration
To: Patricia Alfonso <trishalfonso@google.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=I02BS8Cl;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544
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

On Thu, Apr 2, 2020 at 10:46 PM 'Patricia Alfonso' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
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
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> ---
>  include/kunit/test.h  |  5 ++++
>  include/linux/kasan.h |  6 +++++
>  lib/kunit/test.c      | 13 ++++++----
>  lib/test_kasan.c      | 56 +++++++++++++++++++++++++++++++++++++++----
>  mm/kasan/report.c     | 30 +++++++++++++++++++++++
>  5 files changed, 101 insertions(+), 9 deletions(-)
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
> index 3872d250ed2c..dbfa0875ee09 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -23,12 +23,60 @@
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
> +static int orig_panic_on_warn;
> +
> +static int kasan_test_init(struct kunit *test)
> +{
> +       /*
> +        * Temporarily enable multi-shot mode and set panic_on_warn=0.
> +        * Otherwise, we'd only get a report for the first case.
> +        */
> +       multishot = kasan_save_enable_multi_shot();
> +
> +       orig_panic_on_warn = panic_on_warn;
> +       panic_on_warn = 0;
> +
> +       return 0;
> +}
> +
> +static void kasan_test_exit(struct kunit *test)
> +{
> +       kasan_restore_multi_shot(multishot);
> +
> +       /* Restore panic_on_warn */

Nit: no need for this comment, I think it's clear that here we're
restoring stuff we saved in kasan_test_init().

> +       panic_on_warn = orig_panic_on_warn;
> +}
> +
> +/**
> + * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
> + * not cause a KASAN error. This uses a KUnit resource named "kasan_data." Do
> + * Do not use this name for a KUnit resource outside here.
> + *
>   */
> +#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do { \
> +       struct kunit_resource *res; \
> +       struct kunit_kasan_expectation *kasan_data; \
> +       fail_data.report_expected = true; \
> +       fail_data.report_found = false; \
> +       kunit_add_named_resource(test, \
> +                               NULL, \
> +                               NULL, \
> +                               &resource, \
> +                               "kasan_data", &fail_data); \
> +       condition; \
> +       res = kunit_find_named_resource(test, "kasan_data"); \

Is res going to be == &resource here? If so, no need to call
kunit_find_named_resource().

> +       kasan_data = res->data; \
> +       KUNIT_EXPECT_EQ(test, \
> +                       kasan_data->report_expected, \
> +                       kasan_data->report_found); \

Nit: no need to add kasan_data var, just use resource.data->report_expected.

> +       kunit_put_resource(res); \
> +} while (0)
>
> -static noinline void __init kmalloc_oob_right(void)
>  {
>         char *ptr;
>         size_t size = 123;
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 5ef9f24f566b..497477c4b679 100644
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
> @@ -455,12 +457,35 @@ static bool report_enabled(void)
>         return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
>  }
>
> +#if IS_ENABLED(CONFIG_KUNIT)
> +void kasan_update_kunit_status(struct kunit *cur_test)

This isn't used outside of report.c, right? Then _static_ void
kasan_update_kunit_status().

> +{
> +       struct kunit_resource *resource;
> +       struct kunit_kasan_expectation *kasan_data;
> +
> +       if (!kunit_find_named_resource(cur_test, "kasan_data")) {
> +               kunit_set_failure(cur_test);
> +               return;
> +       }
> +
> +       resource = kunit_find_named_resource(cur_test, "kasan_data");

Do this before the if above, and then check if (!resource), will save
you a call to kunit_find_named_resource().

> +       kasan_data = resource->data;
> +       kasan_data->report_found = true;

No need for kasan_data var (if it can't be NULL or something), just do:

resource->data->report_found = true;

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
> @@ -481,6 +506,11 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
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
> 2.26.0.292.g33ef6b2f38-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200402204639.161637-2-trishalfonso%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxFLmnAHPPCrmmqb1of7%2BcZmvKKPgAMACjArrLChG%3DxDw%40mail.gmail.com.
