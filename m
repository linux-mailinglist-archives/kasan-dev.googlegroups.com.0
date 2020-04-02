Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTUVTD2AKGQESMJ4SYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BAF719C686
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Apr 2020 17:54:55 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e5sf3735084ilg.3
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Apr 2020 08:54:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585842894; cv=pass;
        d=google.com; s=arc-20160816;
        b=V9LsMNt4twH2IlhtX1OteZQOReh7sVceU/eOBlpD+f7Iu1iS4d3uuUfthFk+Rjih8E
         I1JAAF4JCYSNwDm+ybC5JyWkToQigeOioszMjxzxAZ0uJKSw5OIT8pIV9z4teDEpVlxu
         7GiepJqdYFFynYrq6FK6jcmG14zP087yYlBKP/b7ScbTqf+QeAhG7rjzg4fqusPKTc3F
         P+wcjGF0cTRSFiqcx9GWzmfISGQaZmyS6J9/uwlgozjYXjO1QXHtJiSn7ohL+HaKSNE3
         DL1H2exeVvZbvo/2Ozn6hJZyeA2apXQm+3aeG3YVHuMGzEmvhJcHCpFmowoesIAILK2z
         WQZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=g6eqjyXSmHgrVKffxHWM5LuvIRMTk/uSPtWP/VDZ9zM=;
        b=e+PIqEcWibiGN+xZoyrEMbaERUV2SQS21zIIZe0GoF6LnNFh4JNLXrqT0fvT0HSyZf
         ykc1cXJYPwhphZRledrv4GjHctdrg8Z1anNrXmYVnc5nln3lMDoid5kZsU7Q+k3BFynD
         iLR4rNF6rT5q6oXGky9kozRC8CqQt/VCvfVD3tQLNN8bWN1+GWZucSewV5ydbwU7TkhX
         CdSr45hjhYkmeu/XmnXMJnuQctAWgFoJjA0eh/QGDn/LKhTvlOBRpyPlRGQUeY4mGOjP
         C/soAPx7GA5IRxdGTC4slzfd3KYC3iXfkGI7TEIKnjZCMqOKCMfQTiC1u5AUOW3qWYNV
         sdCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=n3aMvS+D;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g6eqjyXSmHgrVKffxHWM5LuvIRMTk/uSPtWP/VDZ9zM=;
        b=HZTZ9l4vfWWxjlyhQRX8C2O7Wdi11OACdDOwQADjVvsQohJnZjkY5Coxvi7k+F8A1O
         OqmqN4zbr0H5fs/DaABp7aElpChhcbXvZ2RS9bydAhld69YRwr2GsFlz8Ez5bXxENB81
         ziWu3Kgmk4AHvhedlUlt6fnjG8i1rz4vgc7qCZFLAZk+TUTvN5ZpzE6QFO1y52X9D21f
         BkYzq/8peY4ME/yB0nugU7Dg1JMWkC3gk1pU2S4/Da0s75yHwDp4sJKiovsNKnu/OfQc
         EfOAnyWTOv9LcoZU2B9iTjlc4RT19CKw9TljPpXJtyT+pTeCtd1Oj6fO4PF/5RbIUX7O
         GLhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g6eqjyXSmHgrVKffxHWM5LuvIRMTk/uSPtWP/VDZ9zM=;
        b=J4qt+wffL0Y6ogzjiP4hAKdiAAgy8PzcGlM0t9ceUmwHfVDv4TycwF7urgUtr+Dh16
         /i5R3HJlwfKyVc02TQn1qQqapYunpDNYz7cvEhCJSkJSVqK0urhyaZtg34ja5kmE0AL/
         YZyXjTIIonngZJX1WtaRxgPmZ8BM8ji1WTdnhGSIwysARjZp5z3tVEXeTMdwkvKi0mdP
         gkjNUP9vTAVv2KNazDwd1iV99ZGJpy/Z3L66z8CiaTDpp2g5LvsUBqNYiklZRrcxBlfp
         iZPKkeQO9K9dXTg6k+NO6fcsPI+rGLqKbJscPfx2nISI46Vq3R50Ozfb3iD9CyGRRXAO
         MB0g==
X-Gm-Message-State: AGi0PubuVtAC4rq5tjWe3zoLoeltX2Rl58FiYMVMUO77ZW0ByRrHZWnx
	yOensTRbMJhVE/olmBsjL/E=
X-Google-Smtp-Source: APiQypIFiNZemDu49dttFPr9FOsJsMLH+vX7wRgyX7CxQLKBskQJPbBIl0BymartLeK3Do77gQnUjQ==
X-Received: by 2002:a92:99d1:: with SMTP id t78mr3667622ilk.18.1585842894153;
        Thu, 02 Apr 2020 08:54:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:3d8d:: with SMTP id k13ls1949417ilf.5.gmail; Thu, 02 Apr
 2020 08:54:53 -0700 (PDT)
X-Received: by 2002:a92:8151:: with SMTP id e78mr4181549ild.227.1585842893709;
        Thu, 02 Apr 2020 08:54:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585842893; cv=none;
        d=google.com; s=arc-20160816;
        b=mDNpWTEWhw/DsQRmiiqnFvok/DCZd1wOzOOEKwqCRjjjtkCXXKzhZelWltUzGLCN83
         rZRECTib/enbxJ5mQ1yt8rfxhN3iYX9CxvywIcihi+bhEr/OSPYmKb5m2G/YK/0BeJIF
         PYZsrlLSv/OjkBJsFFdsK9C90vrnIsOhPZ6OqRVDHwZmXYonzgwUioUJK70vrTp/LSpf
         50sqDOMYNzNqNPXb5KqH1n3I/c3j4pYj95fpIqSl4NdHd6jN1zOBu0LYqRQ7BGLBJtEO
         8BGoo4fORX49CQyooEo/libsh7j/6+bmfVTPxhUr11slIkFEulsJvM+/G3BPrvWsQkH4
         ialw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=o/lxIYMh8c2UvHtmzN4mf0MmO/F42Wr/0+uCtOsBhVg=;
        b=hlGC1n8MJm/6ftgNyMf9NXz34PXzmWRtSLoz+KNLtK9GUkz6WcYpyIjcm55VHXDdOv
         vlaS69XHxDwjylu9uZglb3ee3Pu5Gc1we8oqP3obbB3bu91+usdNwp3hEQFygg74kzsk
         jp5rvqdes61o2zEqKBSZ3DIMKkSV7lCYNWuoCzgLsxCldCczdKwKQMZaDQLQMDjoyGCt
         GRjbiXUy0YfJEh7kHn3LIGrgnYfr0yOZUg0AYF4MyyZLVRd4Yn0X+q/aS6VkI7c4qkbU
         pwxq09jk5UeRT7GgRk4TjQId8h6tD4emEsfudZ/6a/aE4xijTYaYRexXvQbx67cgTNtd
         xNxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=n3aMvS+D;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id d207si459099iof.3.2020.04.02.08.54.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Apr 2020 08:54:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id l14so2046206pgb.1
        for <kasan-dev@googlegroups.com>; Thu, 02 Apr 2020 08:54:53 -0700 (PDT)
X-Received: by 2002:a63:b52:: with SMTP id a18mr3992928pgl.130.1585842892630;
 Thu, 02 Apr 2020 08:54:52 -0700 (PDT)
MIME-Version: 1.0
References: <20200401180907.202604-1-trishalfonso@google.com> <20200401180907.202604-2-trishalfonso@google.com>
In-Reply-To: <20200401180907.202604-2-trishalfonso@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Apr 2020 17:54:41 +0200
Message-ID: <CAAeHK+zwshOOfnS3QNRcysF+KbTVK6=9yavj18GFkGF1tw0X4g@mail.gmail.com>
Subject: Re: [PATCH v3 2/4] KUnit: KASAN Integration
To: Patricia Alfonso <trishalfonso@google.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, juri.lelli@redhat.com, 
	Vincent Guittot <vincent.guittot@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=n3aMvS+D;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541
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

On Wed, Apr 1, 2020 at 8:09 PM 'Patricia Alfonso' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Integrate KASAN into KUnit testing framework.
>         - Fail tests when KASAN reports an error that is not expected
>         - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN tests
>         - Expected KASAN reports pass tests and are still printed when run
>         without kunit_tool (kunit_tool still bypasses the report due to the
>         test passing)
>         - KUnit struct in current task used to keep track of the current test
>         from KASAN code
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
> ---
>  include/kunit/test.h  |  5 +++++
>  include/linux/kasan.h |  6 ++++++
>  lib/kunit/test.c      | 13 ++++++++-----
>  lib/test_kasan.c      | 37 +++++++++++++++++++++++++++++++++++++
>  mm/kasan/report.c     | 33 +++++++++++++++++++++++++++++++++
>  5 files changed, 89 insertions(+), 5 deletions(-)
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
> index 3872d250ed2c..cf73c6bee81b 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -23,6 +23,43 @@
>
>  #include <asm/page.h>
>
> +#include <kunit/test.h>
> +
> +struct kunit_resource resource;
> +struct kunit_kasan_expectation fail_data;
> +
> +#define KUNIT_SET_KASAN_DATA(test) do { \
> +       fail_data.report_expected = true; \
> +       fail_data.report_found = false; \
> +       kunit_add_named_resource(test, \
> +                               NULL, \
> +                               NULL, \
> +                               &resource, \
> +                               "kasan_data", &fail_data); \
> +} while (0)
> +
> +#define KUNIT_DO_EXPECT_KASAN_FAIL(test, condition) do { \
> +       struct kunit_resource *resource; \
> +       struct kunit_kasan_expectation *kasan_data; \
> +       condition; \
> +       resource = kunit_find_named_resource(test, "kasan_data"); \
> +       kasan_data = resource->data; \
> +       KUNIT_EXPECT_EQ(test, \
> +                       kasan_data->report_expected, \
> +                       kasan_data->report_found); \
> +       kunit_put_resource(resource); \
> +} while (0)
> +
> +/**
> + * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
> + * not cause a KASAN error.
> + *
> + */
> +#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do { \
> +       KUNIT_SET_KASAN_DATA(test); \
> +       KUNIT_DO_EXPECT_KASAN_FAIL(test, condition); \
> +} while (0)

Any reason to split this macro into two parts? Do we call any of them
separately?

> +
>  /*
>   * Note: test functions are marked noinline so that their names appear in
>   * reports.
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 5ef9f24f566b..87330ef3a99a 100644
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
> @@ -455,12 +457,38 @@ static bool report_enabled(void)
>         return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
>  }
>
> +#if IS_ENABLED(CONFIG_KUNIT)
> +void kasan_update_kunit_status(struct kunit *cur_test)
> +{
> +       struct kunit_resource *resource;
> +       struct kunit_kasan_expectation *kasan_data;
> +
> +       if (kunit_find_named_resource(cur_test, "kasan_data")) {
> +               resource = kunit_find_named_resource(cur_test, "kasan_data");
> +               kasan_data = resource->data;
> +               kasan_data->report_found = true;
> +
> +               if (!kasan_data->report_expected)
> +                       kunit_set_failure(current->kunit_test);

Hm, we only call KUNIT_SET_KASAN_DATA() for KASAN tests that we expect
to fail AFAICS. Then we end up calling kunit_set_failure twice, once
here and the other time when we do KUNIT_EXPECT_EQ() in
KUNIT_DO_EXPECT_KASAN_FAIL(). Or maybe there's something I
misunderstand.

> +               else
> +                       return;

Nit: "else return;" can be dropped.

You can actually reorder the code a bit to make it easier to read:

if (!kunit_find_named_resource(cur_test, "kasan_data")) {
  kunit_set_failure(current->kunit_test);
  return;
}
// here comes kasan tests checks





> +       } else
> +               kunit_set_failure(current->kunit_test);
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
> @@ -481,6 +509,11 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
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
> 2.26.0.rc2.310.g2932bb562d-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200401180907.202604-2-trishalfonso%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzwshOOfnS3QNRcysF%2BKbTVK6%3D9yavj18GFkGF1tw0X4g%40mail.gmail.com.
