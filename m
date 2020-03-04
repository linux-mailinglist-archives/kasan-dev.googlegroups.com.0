Return-Path: <kasan-dev+bncBCMIZB7QWENRBI4Y7XZAKGQEIY2GJ5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A0AE178AA4
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Mar 2020 07:35:16 +0100 (CET)
Received: by mail-vs1-xe3b.google.com with SMTP id x16sf105870vsh.6
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2020 22:35:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583303715; cv=pass;
        d=google.com; s=arc-20160816;
        b=mdPIUm9rKhud+na40qOu6pko8kW1o1AT3/Trn8GRpOFkA1OcoqPvu5YNJOzA/ihBoC
         TRRcAL0GCYGf34j72S/xPoyZ0Ymy17UMWph3lnu798r101aae1BsdVuR/bVwes1zWpa3
         kM6ZElUI/wLSbZr7eKsGxWwBY0Y8ljFdP2b1J8ZahPN21+XhYPYMtYJSNv66+vMskjBG
         b8sKEnrRKCDCoW+5QftncNG1LK+MGirSz8INsjREY0/ocU0lyj7MQbz2s9EkQ2smqG7T
         AAApBmZ2t/LFUXUR7bEheZncZBFcyA/YuTrgJYzae1JeJACj1MuLcayWKXf6eBujkBCC
         lWIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BBlaT2lehkaA+A2P0TRTKyulbrmCjJYLEbB8i/Yt6gU=;
        b=RCgALLVK4i76nTym8h38+xAFrYdMDjdLMa1NqqQjLt45cFucBuAo2H+vEeIJaBuJJt
         lRs7dAtHFZzW64x1ngb3bQunIXVsObhjFPlz3oupTTjfe+47Eu5vmfAkvzxfmCw4MIvd
         WnuXWpiBbmhJvW58bOTPSnT9Mz2Qy3pUEhzkgo5ZyYQbZkJZCllFwNO1HxXPulPSD663
         uNY/OHnW+qhE8kXMReYS08I7l68ci1htYX+P0ouTEDM1kQA7RJmb9uzLQFwB6+SgX5aV
         ItytHmjvbYhgpLd3ykbp/FZMNP6U2H60wUfwfmxAW9y2HDa6gg+TxrNsnTLoOZ+3gQ6d
         oh0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vHlVS1j7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BBlaT2lehkaA+A2P0TRTKyulbrmCjJYLEbB8i/Yt6gU=;
        b=guqbkdKZnf/ialVfv5SAEt1/tPsgpwTE7rv8my3Rnm7e7WmMkIqPxoRvJCJQ40H3Rh
         U5/ghqF31PNToK149VoChFNE6RWYtMMWPkTyw70SrSw6ztatOmHclNIR4hwXzTrC/q8c
         WZtHcwDoSt7evyyCcpGjObl+ZU2ylKfDTEQ45rHYq70D3UUy6DO4N2D1ETm/P5nft1KV
         FzEqjce0qcfI8gmVgoVPjLi4TU0bm7a7XCaYBIw8a6sHV/6zieiuOTBBp08swl63XKQS
         rXDL4Ru5mD6AP+hxAHurcYFhw27W72ZRzFY75nke3M6EtnlHO5j5gk+kYWzzMScZ0SKs
         JhkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BBlaT2lehkaA+A2P0TRTKyulbrmCjJYLEbB8i/Yt6gU=;
        b=g25CkbxRgnwEKxO4s7FsxnokXpv27wzmEmEzQvsHCTJ/j1zvxpAoKx9XQl5hRJFYKA
         M3c9FNtgfmCUIquFrRKgW+RI1S1R8C+Zer776FYvQHLVk1iyhaBY6nHM+JxwMiJQifTi
         rlrJpgmtixqJoRfqdNHat7ylL0nCvf8ROMJSrKSKLSf08Kqpgwfd1Ew3cABizPjr0pSj
         Q18Lneo627blKbLlKStBF5y4tRDrcoYn71bAun2zhfh6vbgmlLPC+SiP7t2Gd3nkQTNn
         GdMnaTtD5M2yLLk2H9o1SQ5o+sd7j6muutxvwWbXaYuF9kVkY6ROGflw09lBwxykGip1
         wroQ==
X-Gm-Message-State: ANhLgQ2xmvo78w750JvvxAj2Unlfn4CL23vA+Jdqk9UdFWfM8ck2CMC7
	rHU2wLZeaLrkfSbbxcIy7As=
X-Google-Smtp-Source: ADFU+vsBRhDJ5KOKdfcqjJbdWVnZFcC0WuKRbaDmLqnbNW5wgR066riN3ctNoMWxqzaaTwO68f7PlA==
X-Received: by 2002:a67:f847:: with SMTP id b7mr919817vsp.40.1583303715176;
        Tue, 03 Mar 2020 22:35:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:4e02:: with SMTP id g2ls98907uah.0.gmail; Tue, 03 Mar
 2020 22:35:14 -0800 (PST)
X-Received: by 2002:ab0:6796:: with SMTP id v22mr655743uar.41.1583303714817;
        Tue, 03 Mar 2020 22:35:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583303714; cv=none;
        d=google.com; s=arc-20160816;
        b=pamt6n80bPMyIWZkcjzVYiWp1uyXRFPJ5tQaDdr4cw2CJ5Ox3DA0eGfBxI2xUZAVbx
         iBx6bc/A6Bf1bQ5H+KdJBjdlPJ4rI5flMQOTVvtfj5NfneRr+CypoqtPNxUC7by3KBqs
         uMrOc5yOA7foH8TEQI/4OCuuCEyhsQia+y2bBhXbqrVi8PKrp9Ur4AaLs3wyEJfer24A
         jJmrO3rM+5o7ThymyO8aizYCHYEe5oHhOEHKpWeBxI8UxTzMASqXbQBSAXHayp8UBwbc
         abayjtfk44ARFK5ddl6E6AoxqMK4Q99v4kwHWPDuO3PUk+Koq/ZEaJjvETr5apxUXAqX
         UoKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pRV4q0RECloAIigH1EtXD7ojzqVokhP4l3P7T2qRJSc=;
        b=sqi7S9yblRL2mRxqc5ZGzYi1mWK+gZy900Lm7CEpMJda0J/v4TKHEsWg3X4GPtARoL
         uAj/rTOspn6XY+b42Sm57YEOGFqOY4LUvaQsMh0Sc55yL6xlOj4nyPUof5yrxhDjCvvb
         Hz2khhrB9H8rJcQNVCDvb1y0MJfAWcFltYJvMcq8eTkUqHseO933qflkujvVBlT6cfu0
         a9K/biUC9uL9gBAMgBbWr8AL87t5j6r1vIIFF+dLjpI5qZxIyh8qRTby+nAfkv09SdqS
         hn3PO92nenOR3YNxovqj1IQUPnHBj1s3ZqLb5JBZZf/rPJdXSKdnAZjz2KeAT3gUHjya
         oWbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vHlVS1j7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id u25si67446vsn.1.2020.03.03.22.35.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Mar 2020 22:35:14 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id e20so577106qto.5
        for <kasan-dev@googlegroups.com>; Tue, 03 Mar 2020 22:35:14 -0800 (PST)
X-Received: by 2002:ac8:1846:: with SMTP id n6mr1102349qtk.257.1583303714054;
 Tue, 03 Mar 2020 22:35:14 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com> <20200227024301.217042-2-trishalfonso@google.com>
In-Reply-To: <20200227024301.217042-2-trishalfonso@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Mar 2020 07:35:02 +0100
Message-ID: <CACT4Y+avZ5ZdTUPQy7as3PAvdYd0NcSsyUukiumHa_Ah9ZYCFA@mail.gmail.com>
Subject: Re: [RFC PATCH 2/2] KUnit: KASAN Integration
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vHlVS1j7;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
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
> + *
> + */
> +#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do {  \
> +       test->kasan_report_expected = true;     \
> +       test->kasan_report_found = false; \
> +       condition; \
> +       if (test->kasan_report_found == test->kasan_report_expected) { \
> +               pr_info("%d has passed", __LINE__); \
> +       } else { \
> +               kunit_set_failure(test); \
> +               pr_info("%d has failed", __LINE__); \
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

I think we need to continue and print KASAN report even in this case.
2 reasons:
 - tests don't check validity of printed reports, but at least human
can verify sanity of the report
 - report printing code also needs to be tested, at least that it does
not crash/hang
If we don't print reports, it may look nicer, but will be less useful.

> +               }
> +               kunit_set_failure(current->kasan_kunit_test);
> +       }
> +

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BavZ5ZdTUPQy7as3PAvdYd0NcSsyUukiumHa_Ah9ZYCFA%40mail.gmail.com.
