Return-Path: <kasan-dev+bncBDX4HWEMTEBRBT77232AKGQELRI5TOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id 876B41A7ED0
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 15:51:12 +0200 (CEST)
Received: by mail-vs1-xe37.google.com with SMTP id r11sf2128580vso.6
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 06:51:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586872271; cv=pass;
        d=google.com; s=arc-20160816;
        b=rBGsxTf9SKB9KGyBw8DLJE+Ns+z+praVEdG8q9QI3MujwLwZlmBR9e/VY0ht2bGfua
         VMiQD1sOV6iUXxHXkZdPCYacDLN96mErwtw7UbWD39tG3MyfBecSmWRkkOQgDIrCxfLP
         HBoqDjiU77GA469p7YG9N4vxlMx/54VlrQ4VcveiYjjYl4x4yFRwO+lai4Y+Gw+SVL7A
         ClPjm2Kn1GyN+uIOsxLjE9g5JJoGHUMYT+VpXySfhF61iTeFxwUzaxUap4tm1DftCezE
         TfpaEGNTZjFTouIOZ2BCOQ4bBYlWRH3dVkp5X/GzEKK7uZ9wdw5UuWlU+zsF4zHRpvJ4
         007w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+nZewnhyyKBqdEEGah4RImkikLiPd/ZmaIS9DUjOQrQ=;
        b=vGtaIG7BrXjNC30VEnNg1iOjKQ8Tr1HHFE5ypYM0dps/FWzCQ/D9LjJ0SGhXg0OrmN
         cFHiKtDYq8bvFMc8VDD9L11g6p9T5s9y94DVMh2HDiWMlCYt/WtRfvHfEP/uH+BJK8Ub
         +2ewGaiZuXs6nsRsocojYgenLx+aiEsZ7j/GaeK2dQqmULxwZnsBbWeVU2ftF4hD5vYb
         tjmljNSNOwExYgku8ji2gdYiiFCLhir9pISsQdVDjs/ei/3uWO4zSoDu8BcO0JDsoS2V
         h5CWH7c3W7BqDg81nWV5h+hJRvhjLCjK1KSYJNR94wOvewp/iD2SsnvwXjuX6fzy27op
         4BeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H3wKu80S;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+nZewnhyyKBqdEEGah4RImkikLiPd/ZmaIS9DUjOQrQ=;
        b=PDyGJSQ9VH71tkaNalYWamfiNFqOc9lI9dAWffByqwUF0dhsVtoYDCfJK/Uf+CA3PY
         FKDeF9A+sY3VuKF9WL+Ipld2+wIifyFynyAhFMktDMNF1Yx3G7Hn47JhrY+oI6GTuaVH
         Ojar7ap/jlS+xSpwuyzZT7GRCDmgZpBeM7qrS6av0wpguU/NHrGCKAmywSgUK/YmlmiD
         nVlYwxzCLYohjxRTUPhyOBx7QWypc6Zh8rvQ2te+EIHrj7jg3SPkmrrLucdDtpFU0g+K
         U64sRiqA0/UScwoDqUsPuIJt5Qbd16XztDKoLtJijvnsMTZeNsfYxAKitmrRYZjYCrWp
         pj1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+nZewnhyyKBqdEEGah4RImkikLiPd/ZmaIS9DUjOQrQ=;
        b=s7m7F8l6o7K2t+8IHHRxdoMMkOClV6THE70SCLNxZD3shsaA80NbgPxaa4uDblqqF1
         46sa3o+zEnxXaL010nuC5IhUQgAvOo4WFYxzQRKV4w0EmBwKFrSge5CKpieFvyhOdc7d
         p6Txhj5taekYqLLYibsdSxZRfBrECHrke6RixWHiukN+daTnNDE1D7Dvzg84nuXjIogK
         lvjhIUzH+WZvaAjMjHDccTVaJLFomHtgHupBnGejiSYLQJiIX5fYgUslt0Jq8thLdN0k
         EEyHrhLYCoQKJ8Vy4omQ6S+mGYPIhj94OuTalxC/InunjbCLBmZ2BMU9PxHvORPrq/+K
         zT5Q==
X-Gm-Message-State: AGi0PubcjiBUTl3//r5/IdxYDWbvDvlGSS1rwJA6rgx//RHZ7tOhK1SS
	+czDd4539dOZ+ISt50XDGZM=
X-Google-Smtp-Source: APiQypIwvh/Bixak5EIiV3WpNFCRZXs8oHhvac8xYFcluFBDheOxR1GRgq4jo8BeNY8UrrNN/mLHwA==
X-Received: by 2002:a67:eec3:: with SMTP id o3mr206999vsp.184.1586872271358;
        Tue, 14 Apr 2020 06:51:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2f07:: with SMTP id v7ls445858vsv.3.gmail; Tue, 14 Apr
 2020 06:51:11 -0700 (PDT)
X-Received: by 2002:a05:6102:3204:: with SMTP id r4mr136898vsf.109.1586872270938;
        Tue, 14 Apr 2020 06:51:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586872270; cv=none;
        d=google.com; s=arc-20160816;
        b=rBNj6fLUET5miM2B7wB6Xi4Of6jB5ld42nQ+WHYXpn42Brck9Ld5GJiQgFwzNpLgCU
         bMBBtEN2yzXkLIDcxsTl5EZPf6kNsksHrnSKYSOeFTxeSC5hm1eYXYJZuxBC+vwdRH02
         CRHHvJM8rDDgoSWDeAFy7tCuvibrTCZzo0kMgN/ZKIQoaZNo9RgiK07uASMoX71s2d+J
         0/4rTMdct5yBUOUg9zeBpiJ9EkK2AdLGVrkMMYvayWrSJjFNzRuJetNyeyD27MkWZiwZ
         dq7zx0ttkPK8Qz/gML/6/7RiD/ysnsjRHmffYNIs3fHR7ra+q9By3Nh8a4VNcgjqJJ8J
         BGLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fqFfkj/oSmruqF3cM8sR0s4wL8mmluh/5CuVwXsrTFM=;
        b=Z0/xWppjzHq0VONbR6n3PbmeFbyI3qEcrODqk+fmJs80DdQQpz+iarBiwo1WOLZKLF
         GOfMym2KN9Qt277jkJYyMoWg2S7irDi4BIIUaZ+TNQQx+q83V/4UnDhsQyVmMomJlqT5
         qxvlhWQKcyscXpvKAGJ7abr8557qOk/JOMDMFOOA8xiuNXWW53JCXcJeegM/9V55OKKr
         JXEN8mwlTNZbIJnyNGoheI6sPoVbyt8vHqZQaaGmu+/HFb9cancaMpH3Dv9XOPTevFLe
         kuPAOci+JO7IIZ07FbaA8QbuO0nygdr+cTNjeDL606zN7EJx/utihn2bsxdk9A/+VV6R
         BQnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H3wKu80S;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id q67si407908vkb.1.2020.04.14.06.51.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Apr 2020 06:51:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id a32so5291767pje.5
        for <kasan-dev@googlegroups.com>; Tue, 14 Apr 2020 06:51:10 -0700 (PDT)
X-Received: by 2002:a17:90a:9af:: with SMTP id 44mr224966pjo.128.1586872269584;
 Tue, 14 Apr 2020 06:51:09 -0700 (PDT)
MIME-Version: 1.0
References: <20200414031647.124664-1-davidgow@google.com> <20200414031647.124664-3-davidgow@google.com>
In-Reply-To: <20200414031647.124664-3-davidgow@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Apr 2020 15:50:58 +0200
Message-ID: <CAAeHK+z8AXQuTAPc20kmR0i7Ny1LU1ghWrUf6gOAMdSop+NjgA@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=H3wKu80S;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042
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
> -static noinline void __init kmalloc_oob_right(void)
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

[...]

> -       if (panic_on_warn)
> +       if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
>                 panic("panic_on_warn set ...\n");

Please move this change into a separate commit.

With that:

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz8AXQuTAPc20kmR0i7Ny1LU1ghWrUf6gOAMdSop%2BNjgA%40mail.gmail.com.
