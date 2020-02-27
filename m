Return-Path: <kasan-dev+bncBCMIZB7QWENRBO5J37ZAKGQEZMG5VCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id EB305171FD0
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 15:39:56 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id w11sf2079131plp.22
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 06:39:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582814395; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ywy+EYDcFBpixUJRssYM1H+Krl2r1vhYdfKwe1vMH1+HLtLbEIu11xC5xiVr/lAAyM
         8jum+4rzxBOjSBuU3RIlNUJi6w7Ju3D2Y9RSHUvvfl6q7cAcxwljZgAk3qy7xV8RkIRw
         VzejVdDWdqbWdLTaiZsZqL5bZ3qzVjnxJiFn17BeDDEGuJN4mVOu7+B8iagG/PKucRgs
         EsSPfYTY9aHPG2g/86BEPeeD4oMYNgktQUcSzMm/K2S5m24ZfydOPnolRhaGD68BT7xq
         i03dX5y9qYHVJgENXTCw3znaenxbwk807edpk8OJLcK42854eaBl41IjY3EaRDAkultc
         3dJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lPxp9ruIwBFyL9dsVHJfe62BnQoKCKw/KYXgn5HLvC8=;
        b=VX1b2r/5YwWVPnUJviMnVKHSaHmMQXOWWW3GpB7XPIfAoeo/VTZlL2Vn9R72q1jNlk
         2fv9PXBY04HpNvjapUPgUvM8G9EtebNzkprPX4gVPA/N/NRyHszgfKlMEKHY6TGqK937
         /nkaW5gLuDQtuqzqmjeFr5lrgOIGRX7dKLKTjkIvwVNRiQOTyjLqoolGZJYR9qeXlRp0
         7gQePObXKfg7hTOSQirKMx26/YYsS/AfNfPRrauTCgEJemgmV1xSMH4T05qbI/llyF7m
         nzo9HG7K9XplfcjfkjmR2xAahRBvf/fgkkSiAuWvDe+NbZ8HOnY1mz20MEiptRAOL7eP
         rXKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=M9lph58w;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::a44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lPxp9ruIwBFyL9dsVHJfe62BnQoKCKw/KYXgn5HLvC8=;
        b=G2l6gwZGFyItH+wrvunv1Rv3Xq7ctMlY7VzGjhU0BLfWig8rJBmO8IwUC4TJ2Kx+F0
         Mp5Re23928tlAorBq3RvvasGVqy3AvAZ/K9AgecNkm1hnH+3//UyJ+r99zWPTXPlijZ9
         JyiishuDz2UhGZeoJCa3ZxDvEDSUMHcagv+1lCc/2IY1wif6OrYgmD0tL13kT8NL3XnL
         YyE6auVXjuiZ4ZAlJgqj3cy158usWRv9NBv6w629suBfTcBVp3Plb9TEMiEzdmnvDcDk
         Ktwu7iREdylisPkc5rDq7JXV0ZobrnY7l+BSJvh6Q4W5kQ1rKZ6N9bcv6zyFepEELhJF
         P4iQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lPxp9ruIwBFyL9dsVHJfe62BnQoKCKw/KYXgn5HLvC8=;
        b=CWeVOnux6SJ0a5SG4gRdoEeHfv6Z0cBIdaXd01/bUZdYqtkEEZdU1bzpGf/7WXhnVZ
         l427Nl2qtonpuosCNY1bWbjGNf5ZCWHqSRbR/bmEt4pY2i4yUXRpj51XgRuwRRifM1NF
         RIBNNxP7f1l49USOWHbRv7tPGb7Ys7mCRZWdLFsU8cFQ/FpvpxfBi8KtAa7j7hxTthwg
         zR41TVWB1CVtdDIkCcr3itp3TrfFSVML/KIawZalpnhh9Cbx9D9JDQ9UuiWoi41EIc39
         yKbnDQpRn6DthtOTRFksJH7Wf0UxsmYWf8ANrQbpm+RBQU1P55+DKdC7/pnwDH5QwzX+
         aVJw==
X-Gm-Message-State: APjAAAWp7Jv1/qZNcMk/0xiChv5IIIgHt9sgXXQHV9HjKPzQxiHUZV1o
	tx8fBaOXIE4IZfDRejWr9v0=
X-Google-Smtp-Source: APXvYqxCcwRl3hwB7Gn2sW2YSJx+OK3kNw/yAcg6/ceNAKcy7+2jmiFU+nYJwcLtrtv3MaPFGRcPww==
X-Received: by 2002:a17:90a:fe02:: with SMTP id ck2mr98881pjb.10.1582814395587;
        Thu, 27 Feb 2020 06:39:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1c49:: with SMTP id c70ls753486pfc.4.gmail; Thu, 27 Feb
 2020 06:39:55 -0800 (PST)
X-Received: by 2002:aa7:957c:: with SMTP id x28mr4387858pfq.157.1582814395109;
        Thu, 27 Feb 2020 06:39:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582814395; cv=none;
        d=google.com; s=arc-20160816;
        b=kJj9u3WDg56aHXMCZZGGwOw33RU7YTeExlxU0KI1Xvf3nFI12WNqHG6IT30IkCkGeY
         ciw7oZLgxLP/u17etbxXwZLEnOp9c5X/FJpOP0qc+3dUUeyybMYmzNcDDwNQlWkRN0V3
         Sfn9OXp633NLXNPTNZBQx9FFZQBCzaHl8IeZUjgaTxha9IOGM2EyBke47AErRy3Ij0yu
         FpJMtv7jkEY+cxx+aLegHoXlMJYDLyRgPtdfIPf2yoE0TPygBTEuOpzNRKfrAkPOxwlW
         3Oj83SYPHhf9mTaRcV8f3kakAGPqqrE2zIUEGX3PIx8M8WzGaTKYg6omJvPAMQmaApct
         07KA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bk5HqSpXBd3ouVZHOHridtfmdB0hMUKbQEQgHMhA+40=;
        b=Y1eIVkuCaMpVx6G/v1Ovsc3CR88gcXSeW5hiaqYhu8O7jWa7pKEtgAO4mORWKgdwsI
         P5fHjm68CghCtTqRfQwZM4KDI+VHrT2eLPn1hXrAqjjFTUvkXNslRyBXiHxHMv8ED0EC
         59AK6ZxO/bsjGVKXUnDZt52UhNTnK0Rb/1wOUK8JuPa17vW6J6o0VKOy60HU5eAdCu9/
         cA+nJh3hyC4tRY3QrnobN0hkL9q+RplQsIF+IMGdpUs/W6iUgcm5qzBk9j56KLchCt/M
         hc13zyQoO+onZJvPwnBq6zV7lrpC0+ZT14hcLAwh8m4vKR5Yd2+oqYDn8VK4Sk/odX7z
         p3OA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=M9lph58w;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::a44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa44.google.com (mail-vk1-xa44.google.com. [2607:f8b0:4864:20::a44])
        by gmr-mx.google.com with ESMTPS id c13si194256pfi.3.2020.02.27.06.39.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 06:39:55 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::a44 as permitted sender) client-ip=2607:f8b0:4864:20::a44;
Received: by mail-vk1-xa44.google.com with SMTP id g7so781673vkl.12
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 06:39:55 -0800 (PST)
X-Received: by 2002:a05:6122:1185:: with SMTP id x5mr2810329vkn.38.1582814393627;
 Thu, 27 Feb 2020 06:39:53 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com> <20200227024301.217042-2-trishalfonso@google.com>
In-Reply-To: <20200227024301.217042-2-trishalfonso@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Feb 2020 15:39:41 +0100
Message-ID: <CACT4Y+bO7N_80N7NkjOstp=dxGnV1GZUoH3sh6XU90ro0_7M0A@mail.gmail.com>
Subject: Re: [RFC PATCH 2/2] KUnit: KASAN Integration
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, vincent.guittot@linaro.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=M9lph58w;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::a44
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

On Thu, Feb 27, 2020 at 3:44 AM 'Patricia Alfonso' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Integrate KASAN into KUnit testing framework.
>  - Fail tests when KASAN reports an error that is not expected
>  - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN tests
>  - KUnit struct added to current task to keep track of the current test
> from KASAN code
>  - Booleans representing if a KASAN report is expected and if a KASAN
>  report is found added to kunit struct
>  - This prints "line# has passed" or "line# has failed"
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> ---
> If anyone has any suggestions on how best to print the failure
> messages, please share!
>
> One issue I have found while testing this is the allocation fails in
> kmalloc_pagealloc_oob_right() sometimes, but not consistently. This
> does cause the test to fail on the KUnit side, as expected, but it
> seems to skip all the tests before this one because the output starts
> with this failure instead of with the first test, kmalloc_oob_right().
>
>  include/kunit/test.h                | 24 ++++++++++++++++++++++++
>  include/linux/sched.h               |  7 ++++++-
>  lib/kunit/test.c                    |  7 ++++++-
>  mm/kasan/report.c                   | 19 +++++++++++++++++++
>  tools/testing/kunit/kunit_kernel.py |  2 +-
>  5 files changed, 56 insertions(+), 3 deletions(-)
>
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index 2dfb550c6723..2e388f8937f3 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -21,6 +21,8 @@ struct kunit_resource;
>  typedef int (*kunit_resource_init_t)(struct kunit_resource *, void *);
>  typedef void (*kunit_resource_free_t)(struct kunit_resource *);
>
> +void kunit_set_failure(struct kunit *test);
> +
>  /**
>   * struct kunit_resource - represents a *test managed resource*
>   * @allocation: for the user to store arbitrary data.
> @@ -191,6 +193,9 @@ struct kunit {
>          * protect it with some type of lock.
>          */
>         struct list_head resources; /* Protected by lock. */
> +
> +       bool kasan_report_expected;
> +       bool kasan_report_found;
>  };
>
>  void kunit_init_test(struct kunit *test, const char *name);
> @@ -941,6 +946,25 @@ do {                                                                              \
>                                                 ptr,                           \
>                                                 NULL)
>
> +/**
> + * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
> + * not cause a KASAN error.

Oh, I see, this is not a test, but rather an ASSERT-like macro.
Then maybe we should use it for actual expressions that are supposed
to trigger KASAN errors?

E.g. KUNIT_EXPECT_KASAN_FAIL(test, *(volatile int*)p);


> + *
> + */
> +#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do {  \

s/condition/expression/

> +       test->kasan_report_expected = true;     \

Check that kasan_report_expected is unset. If these are nested things
will break in confusing ways.
Or otherwise we need to restore the previous value at the end.

> +       test->kasan_report_found = false; \
> +       condition; \
> +       if (test->kasan_report_found == test->kasan_report_expected) { \

We know that kasan_report_expected is true here, so we could just said:

if (!test->kasan_report_found)

> +               pr_info("%d has passed", __LINE__); \
> +       } else { \
> +               kunit_set_failure(test); \
> +               pr_info("%d has failed", __LINE__); \

This needs a more readable error.

> +       } \
> +       test->kasan_report_expected = false;    \
> +       test->kasan_report_found = false;       \
> +} while (0)
> +
>  /**
>   * KUNIT_EXPECT_TRUE() - Causes a test failure when the expression is not true.
>   * @test: The test context object.
> diff --git a/include/linux/sched.h b/include/linux/sched.h
> index 04278493bf15..db23d56061e7 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -32,6 +32,8 @@
>  #include <linux/posix-timers.h>
>  #include <linux/rseq.h>
>
> +#include <kunit/test.h>
> +
>  /* task_struct member predeclarations (sorted alphabetically): */
>  struct audit_context;
>  struct backing_dev_info;
> @@ -1178,7 +1180,10 @@ struct task_struct {
>
>  #ifdef CONFIG_KASAN
>         unsigned int                    kasan_depth;
> -#endif
> +#ifdef CONFIG_KUNIT
> +       struct kunit *kasan_kunit_test;

I would assume we will use this for other things as well (failing
tests on LOCKDEP errors, WARNINGs, etc).
So I would call this just kunit_test and make non-dependent on KASAN right away.


> +#endif /* CONFIG_KUNIT */
> +#endif /* CONFIG_KASAN */
>
>  #ifdef CONFIG_FUNCTION_GRAPH_TRACER
>         /* Index of current stored address in ret_stack: */
> diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> index 9242f932896c..d266b9495c67 100644
> --- a/lib/kunit/test.c
> +++ b/lib/kunit/test.c
> @@ -9,11 +9,12 @@
>  #include <kunit/test.h>
>  #include <linux/kernel.h>
>  #include <linux/sched/debug.h>
> +#include <linux/sched.h>
>
>  #include "string-stream.h"
>  #include "try-catch-impl.h"
>
> -static void kunit_set_failure(struct kunit *test)
> +void kunit_set_failure(struct kunit *test)
>  {
>         WRITE_ONCE(test->success, false);
>  }
> @@ -236,6 +237,10 @@ static void kunit_try_run_case(void *data)
>         struct kunit_suite *suite = ctx->suite;
>         struct kunit_case *test_case = ctx->test_case;
>
> +#ifdef CONFIG_KASAN
> +       current->kasan_kunit_test = test;
> +#endif
> +
>         /*
>          * kunit_run_case_internal may encounter a fatal error; if it does,
>          * abort will be called, this thread will exit, and finally the parent
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 5ef9f24f566b..5554d23799a5 100644
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
> @@ -461,6 +463,15 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
>         u8 tag = get_tag(object);
>
>         object = reset_tag(object);
> +
> +       if (current->kasan_kunit_test) {
> +               if (current->kasan_kunit_test->kasan_report_expected) {
> +                       current->kasan_kunit_test->kasan_report_found = true;
> +                       return;
> +               }
> +               kunit_set_failure(current->kasan_kunit_test);
> +       }
> +
>         start_report(&flags);
>         pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
>         print_tags(tag, object);
> @@ -481,6 +492,14 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
>         if (likely(!report_enabled()))
>                 return;
>
> +       if (current->kasan_kunit_test) {

Strictly saying, this also needs to check in_task().

> +               if (current->kasan_kunit_test->kasan_report_expected) {
> +                       current->kasan_kunit_test->kasan_report_found = true;
> +                       return;
> +               }
> +               kunit_set_failure(current->kasan_kunit_test);
> +       }

This chunk is duplicated 2 times. I think it will be more reasonable
for KASAN code to just notify KUNIT that the error has happened, and
then KUNIT will figure out what it means and what to do.


> +
>         disable_trace_on_warning();
>
>         tagged_addr = (void *)addr;
> diff --git a/tools/testing/kunit/kunit_kernel.py b/tools/testing/kunit/kunit_kernel.py
> index cc5d844ecca1..63eab18a8c34 100644
> --- a/tools/testing/kunit/kunit_kernel.py
> +++ b/tools/testing/kunit/kunit_kernel.py
> @@ -141,7 +141,7 @@ class LinuxSourceTree(object):
>                 return True
>
>         def run_kernel(self, args=[], timeout=None, build_dir=''):
> -               args.extend(['mem=256M'])
> +               args.extend(['mem=256M', 'kasan_multi_shot'])
>                 process = self._ops.linux_bin(args, timeout, build_dir)
>                 with open(os.path.join(build_dir, 'test.log'), 'w') as f:
>                         for line in process.stdout:
> --
> 2.25.0.265.gbab2e86ba0-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227024301.217042-2-trishalfonso%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbO7N_80N7NkjOstp%3DdxGnV1GZUoH3sh6XU90ro0_7M0A%40mail.gmail.com.
