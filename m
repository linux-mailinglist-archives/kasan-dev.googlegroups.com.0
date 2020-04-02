Return-Path: <kasan-dev+bncBCMIZB7QWENRBSH2S32AKGQER7IA6RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F8A719BF46
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Apr 2020 12:24:10 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id g25sf2619864qka.0
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Apr 2020 03:24:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585823048; cv=pass;
        d=google.com; s=arc-20160816;
        b=r9x/eVAr6MgWNK9+8bYnGIi62BLYmeZBYBDwVOP796ZFoVov5ugkfrjQCGUF5teuzE
         PlPxaK0lHL9lZuQmEUkYNKgT0hcY+ru8qHdkS2/oGmfdIX4vv14Xw6PKZ8z/q2UMyZ/U
         mf6ZDkUsVE8iiTHXAZ1OPWWn6PpVW3eIb+QUzP2bkz3R+4/gBjlNdqAAXCAzHywGhTim
         TvIlGkAQpwMfnz4ojgzQDijbpx75JsGkj6zfJW4pAWb/qVgGCZ5EVHpuiOr+qpR0si1a
         LYVktGBI5qdpk5z01MLWngmwiRp16NKCN9Zq++Vf4SBhnIFOmRi7dyJkjwXb63LqRk2o
         wqyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cNhf8YqKvTCCKyU8WuyviHpzEeIy6IUXrkRdTN/dpkk=;
        b=h8CMkhqxLyrmr7Ds1nxg0w4EXyP6568/W01J3dTzhqIaPPYDxpjNJEApd37p0Cjl8v
         SdEVbtFvg9Uu7dwAye9ZE5lTjSMG62d8cfbr93KsJYPNKSCXvVLHloL3KZbub++sAB0/
         a4+IdhuEa+M/z15osll/cO2zwlCvzDEGP+4CQnBGYvxbcM0FUMALf2O5rBBsl+l28fWJ
         YczqqkPy/oDiUFkxsqm0z+wt9VxhtUFHPTy+ZlAjtVi6TV//lOFwmbe9VQI0opbSOWLf
         pPCKwMPJwuPiO4jAYY4w3pd+w7PcrqGuZksMgi3XDHS4YUEt90PzqsXe05OwLU1UuZw7
         LLMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=snORBZBy;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cNhf8YqKvTCCKyU8WuyviHpzEeIy6IUXrkRdTN/dpkk=;
        b=b6AXyI7ahMGaLSYUhIP9bygq6nz9hm+EfONWwocscQv8UdGm8Ec7uK1PkwjYNwhzOk
         s74Xj+BRGNMVdURm5Wv90bnBQvV1xQyAMq80bwYg5Sbp+ieb/FkU3FeVRFFWAoBuoY71
         e5ikEHTvSnG+zTSsxrDcn0vTu21VfKjByDXdvEZZCkflITYGUmE7JXajGnayrJgZcWgm
         IIg7I+5wKEVvPJNz228t+M1cewDmrWFBfMmYSSHSP8u8O85J3dHnAcvq79FqmEI1k1iN
         F8WaJM66hzxBnoELoXQxjSZD1yRZ/MgFSa+SdApzMfHIftBoxXpg8C7353gf7Xom5pys
         2J7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cNhf8YqKvTCCKyU8WuyviHpzEeIy6IUXrkRdTN/dpkk=;
        b=dS9Pwx052ZlNCDEHs79RXh66waqsWE+SEDucn5Xqib51y8KVrrNsHQWZOlWNGnBq3v
         /JBz0efJSUVX4pTwqfBsU15FwCUWOvUrxxaMyswWnOyO0nvaS9Lyrgx8rryf0yHqrTqN
         kyQwNe+4lg6p3qApU7u+F3bRYIsFz6hSzwC4mgwbuzS5qpIbqkVJsoKfrqHphnbPEiGH
         jiPoKRjpnPKzhq/RpgqitLJJzHu64LFg9zV/T85sCvcM9THAe5QzGiSd8EZWFd1kfOtG
         XXtoo4XwPEegmvAtn0UZ+l3D/5nCWBUR10y5YBC+1IVMtiHD5m3fZT2dil2wYvpc+Af+
         5QYA==
X-Gm-Message-State: AGi0PuZzIv2/vYpy7Pzqb5G1Y/HneCOlnxfTpA0q44h/yPn6HJjTBcyC
	60jXEfrk0lj8b3aU8N8Z2tQ=
X-Google-Smtp-Source: APiQypKmP4WvhyjRjjl4odXSphPhCq05POr2PWdn3kWI6/qVAMahfKbs0IWmIZ612WO2PsfULV+4HQ==
X-Received: by 2002:ac8:10f:: with SMTP id e15mr2078579qtg.355.1585823048687;
        Thu, 02 Apr 2020 03:24:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:5084:: with SMTP id e126ls2011635qkb.7.gmail; Thu, 02
 Apr 2020 03:24:08 -0700 (PDT)
X-Received: by 2002:a05:620a:2222:: with SMTP id n2mr2805181qkh.5.1585823048300;
        Thu, 02 Apr 2020 03:24:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585823048; cv=none;
        d=google.com; s=arc-20160816;
        b=bQVb8oI6lgWu2Y39vLNh9HZOknuSfW+MVdkgVa0YQn3hvqY27fCZuZWDk61mFZnpUi
         T36o8LKblTpK1QPrfDd+X1M90B1aSZLiOx5X7gCjic7WqgTe7e4m8IjLYo3UrH5fiTvP
         CANaSdmjhSaJCTEoFIVJf9qQNS4xygI3KqFTbsUqoO4TcPTnmKpxFW50ETD+3kYiRqjf
         CW3mWqkgvbtNcPAUYxc25QAiZP0glNOICQlSzsAQSB92xn3zR/U9UETTTYuka4RBDhIk
         Ny+qMN7iO9AIDvGbc2SUY+7uCwvO3gFByEl1l8Cy5/loDb9p9yzNPDqAH5EscSbbs0hv
         PmyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=h0nNqe1kbgvwHQ8vMqd1sXLiQtqiwKluQ6SNG74jh9k=;
        b=D9QOWo52Qk1VSrbBA3DF3J8GQ0kgKLEtVCPoChWMxNKDu1JKTGPZywj1JGT9DZBJwy
         r6j41Ubcf/yuYrT2Se801TkhnGSk4dRZuj/87eIQwYhz9y5HxtNcs8sICzxw+ZptROZR
         0dPtLMIV+vNDaTyk1OvPOjOL8B7h0yldEZEcWt/JdKQuIelyKKSRyimsNAikMAKc+CVG
         zfD8Yl0Ba+sWdIgPheWvUa8ZgsqABrb/Fe7CajQWFSXSPpLDaFxvFWb65FpkEOsFY2pR
         uVHvPV2gQBEwD6r5b/wzICbKTCLJ1kBeR171ZAov9SpVrHCeZQPF7swOafCLb0l4Ij/W
         Petw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=snORBZBy;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id z126si314095qkd.2.2020.04.02.03.24.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Apr 2020 03:24:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id m33so2770981qtb.3
        for <kasan-dev@googlegroups.com>; Thu, 02 Apr 2020 03:24:08 -0700 (PDT)
X-Received: by 2002:aed:25f4:: with SMTP id y49mr2126724qtc.50.1585823047508;
 Thu, 02 Apr 2020 03:24:07 -0700 (PDT)
MIME-Version: 1.0
References: <20200401180907.202604-1-trishalfonso@google.com> <20200401180907.202604-2-trishalfonso@google.com>
In-Reply-To: <20200401180907.202604-2-trishalfonso@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Apr 2020 12:23:56 +0200
Message-ID: <CACT4Y+ZWQtAZb_D3MsAvO6fFJiH+eYid+ZuFYMRpWDr07Fxgkw@mail.gmail.com>
Subject: Re: [PATCH v3 2/4] KUnit: KASAN Integration
To: Patricia Alfonso <trishalfonso@google.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=snORBZBy;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

On Wed, Apr 1, 2020 at 8:09 PM Patricia Alfonso <trishalfonso@google.com> wrote:
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

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

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
> +               else
> +                       return;
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZWQtAZb_D3MsAvO6fFJiH%2BeYid%2BZuFYMRpWDr07Fxgkw%40mail.gmail.com.
