Return-Path: <kasan-dev+bncBDK3TPOVRULBBWMR5HZQKGQEKMTFOKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CD1619182C
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Mar 2020 18:52:25 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id d17sf9502466wrs.7
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Mar 2020 10:52:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585072345; cv=pass;
        d=google.com; s=arc-20160816;
        b=spw3PfZaX8KYuBQmxO6ZcdKwFnaTsrEnncYJwLogNoDUP5GglRW+EQHwf0kMjXXv8+
         HG1apxTAJA+RkgEtOHtRRTlXR+ZptfibTTdSe8a81wIZBSm0c9IdBxnfS1rlLzTRb51J
         eaD01qZW+oRbZpmhacU2+qK4fWiHOx925jy8NYg4H6q+C7Et75UhhHW79ZDjJN3sM4/C
         8W6qZQYKa/3bKPyhrXw42qXHMsXGntJLEEFpTFyIyLTDRfFVJJnarxbOFqA5F8c9kFJ0
         wPDDVyNeTbZ8hH46E2Lv2DmNaTjfVNaKJbPkpCe/ZuU1EVJQZkVrfz1iSzQTKVxBHk4z
         UIsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hpvR+3HmQXM9LTwUA4X7yXZQ7Nt6YK2ElHCGchcN/xs=;
        b=t9Q7pDwqnlow45q7b8Jux5IoBtBR74VCVFRK+Ti/mK9f/M+bGAlpnfLznM/mL8+hsg
         aU2S+6YzpJqOJjdTJ8sWTgAbMrRAjuH0Lx9z3Xf0ziThC3E2xGEUeLhrkYo4/jBDkBCp
         RFCZk39mVfjyHjwE0NX9Ap9ZI4rwIj97qAgZ45eU9+kKqhWd2HtlYIgOShTYOiM80rcL
         lw8IqGRdrHtMl/RSTToGCtqYIBfy6KqGu0Px4gxAEm9gGEiMz+smZurlgiyyc6qHHdVh
         BQ1PuGtDU2Hg3+sv0jho8tCPEhy4abAypW+kjCuPFr/STB6vCrTR5FA803qKj5hSdCQP
         LLmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bj6HMXIt;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hpvR+3HmQXM9LTwUA4X7yXZQ7Nt6YK2ElHCGchcN/xs=;
        b=YF+ixH0za0D3l77vMCNSTe0FwLT4+ls+NKKJgbGMO7GuD11u8GRYzSU1Kp3BBaYOr3
         izEOKHmk/d274IChVj0ZvfGVNlXphLYAnnewJCLaFD2rsLQGhH3fls1CM7QE3fwxMFtB
         580lOIiJ2t5AG1Ee8ZyxNakga0Q3VFLu3716nSBDxSx0o7VIuXOP1ZTCvqEopQBAYJjM
         uqT2m9oyEEAqOx7gP8SG0HkxCE5cUOXkn334y3Z3CwZFdUMZKKz78InRe3xMLmDlpR6l
         AqzDvTgp2OR06cw3iYgAbeT1YzV6Rv1UNeJ589cg7CYhi6YBhVEABNpkIAFaZC2z2kqp
         vQdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hpvR+3HmQXM9LTwUA4X7yXZQ7Nt6YK2ElHCGchcN/xs=;
        b=aP6S3F+S8zfO01k0QMWfOt6jp75Ngyqy9K8RwMnFinsdfZSr8FCbyTm5PwOf48oW9S
         4VaUKiL+SLwX0y3/9QScSliHDBRMsgXu1ymHAWoGfG+TyId4KO12sCC3PKMTOlABJ9ly
         1+92TNrfTPRDszJzfelP1AD6WNvmcRycdaZ8tVQ5MkLwQbbuO5/pTYOUZT2XjH4J5oAs
         y4dxNkPK2jMnwM1FdNpff41RzGoLT3wXaRublAxB4zgWKiQ9qOa1nTL041iE2AiWuzhG
         oGX/cGSOsnrkbLsywNuWqBg4Ct1OpfDYn718bH3g/RnBPk5JBOc30OosnONaC++ElYet
         6L2Q==
X-Gm-Message-State: ANhLgQ0JhnidiFVkttayYEG/d8WEfLIj6ueJ32AtlDHp9rk5vcjd+Jxf
	HYGoPB2YX2dlH1rgPeA8T9M=
X-Google-Smtp-Source: ADFU+vv9gX/hC5zYJHtJDdW81952BxLYJ+uYmlbn0WSDrekdJ8RgNjbaxtLelDc7+GnbwMkZ6Zsqfg==
X-Received: by 2002:a7b:c343:: with SMTP id l3mr2435561wmj.38.1585072345047;
        Tue, 24 Mar 2020 10:52:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:104d:: with SMTP id 13ls2215226wmx.1.gmail; Tue, 24
 Mar 2020 10:52:24 -0700 (PDT)
X-Received: by 2002:a1c:7919:: with SMTP id l25mr7334759wme.12.1585072344405;
        Tue, 24 Mar 2020 10:52:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585072344; cv=none;
        d=google.com; s=arc-20160816;
        b=JcxfKOE+xQQc406RTqNkw25bwIPkWZA9jnTft1Ww5Y1c4wVQ7omH7/gC1ll0HIjyRO
         IuXsNeuWLBfbA7KKZWifFMgRcc1cQUrNiN89nl4skAndfspX6xy0+a2nV8tULjjy1niE
         yBXrlperh8HrnZA1dF6AcTS/5lRYFx7PoJWF26sQBGQGNEMnS5daNfZnMFXG9oHFVnj5
         +QsVY2B7Z2tSlIOemri3Btkl9hlwwzIAPqgecOHkQ8jt9bDJ3zGJOxJZdY08iR2NTVXW
         5gtSyYffpiVuXtlWIZ/59kq0XE5iE3Z1yqPmrbTVQ/abW1EBFTcNTxYUv/qz0Tya8t1A
         +Y4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=T9S//YvyNBQfByQlDnk2B8Cvfv/r3ZCCHx4URU4hecs=;
        b=s5FHZzpa3G8TpBtfPQqzVa6zfGnl+OCpwPmz+oVo/eDetCvEYyB/MbBwNgB6f9ATtH
         2cSRuwbqtuyrcj/Gm3kJE81sIt0ltP7ShJzZDtOomKn+VJVUjT62py6XqG3xLt5ao/Y6
         YnEcDkJinMMWAB+vHSmmO4+EvoXQHxEfZRupcnWAI4Bcj6MNsQC178/fM/Aicdq7kMSl
         tcKpAGTO1cMmIKR6/MaDEqa2oZ/TUJUAeUhQtJ2qbsUVK7SwTzkiXEr2FpW04FmDc2CP
         ubLTFHJ0TbUn8C3uZGBleaqVO0MhS6Aayss2+/Yqw6OVlwAJ7f56hN1Hw1ITch4gqNFE
         DmtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bj6HMXIt;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id l2si249331wmg.3.2020.03.24.10.52.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Mar 2020 10:52:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id w25so276189wmi.0
        for <kasan-dev@googlegroups.com>; Tue, 24 Mar 2020 10:52:24 -0700 (PDT)
X-Received: by 2002:a1c:750f:: with SMTP id o15mr1450742wmc.110.1585072342875;
 Tue, 24 Mar 2020 10:52:22 -0700 (PDT)
MIME-Version: 1.0
References: <20200319164227.87419-1-trishalfonso@google.com>
 <20200319164227.87419-4-trishalfonso@google.com> <alpine.LRH.2.21.2003241645240.30637@localhost>
In-Reply-To: <alpine.LRH.2.21.2003241645240.30637@localhost>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 24 Mar 2020 10:52:11 -0700
Message-ID: <CAKFsvUJsonsrru+N18ZzY5hCiRp5OtS7GYtRoewooOJCzTr0qA@mail.gmail.com>
Subject: Re: [RFC PATCH v2 3/3] KASAN: Port KASAN Tests to KUnit
To: Alan Maguire <alan.maguire@oracle.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bj6HMXIt;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::344
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

On Tue, Mar 24, 2020 at 9:48 AM Alan Maguire <alan.maguire@oracle.com> wrote:
>
> On Thu, 19 Mar 2020, Patricia Alfonso wrote:
>
> > Transfer all previous tests for KASAN to KUnit so they can be run
> > more easily. Using kunit_tool, developers can run these tests with their
> > other KUnit tests and see "pass" or "fail" with the appropriate KASAN
> > report instead of needing to parse each KASAN report to test KASAN
> > functionalities. All KASAN reports are still printed to dmesg.
> >
> > Stack tests do not work in UML so those tests are protected inside an
> > "#if IS_ENABLED(CONFIG_KASAN_STACK)" so this only runs if stack
> > instrumentation is enabled.
> >
> > copy_user_test cannot be run in KUnit so there is a separate test file
> > for those tests, which can be run as before as a module.
> >
> > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > ---
> >  lib/Kconfig.kasan          |  13 +-
> >  lib/Makefile               |   1 +
> >  lib/test_kasan.c           | 606 ++++++++++++++-----------------------
> >  lib/test_kasan_copy_user.c |  75 +++++
> >  4 files changed, 309 insertions(+), 386 deletions(-)
> >  create mode 100644 lib/test_kasan_copy_user.c
> >
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index 5b54f3c9a741..f026c2e62b1d 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -159,9 +159,16 @@ config KASAN_VMALLOC
> >         stacks), but at the cost of higher memory usage.
> >
> >  config TEST_KASAN
> > -     tristate "Module for testing KASAN for bug detection"
> > -     depends on m && KASAN
> > +     tristate "KUnit testing KASAN for bug detection"
> > +     depends on KASAN && KUNIT=y
>
> could just be depends on KASAN && KUNIT I think.
>
This depends on KUNIT=y because KASAN is built-in and therefore cannot
use code from KUnit if it is built as a module.

> >       help
> > -       This is a test module doing various nasty things like
> > +       This is a test suite doing various nasty things like
> >         out of bounds accesses, use after free. It is useful for testing
> >         kernel debugging features like KASAN.
> > +
> > +config TEST_KASAN_USER
> > +     tristate "Module testing KASAN for bug detection on copy user tests"
> > +     depends on m && KASAN
> > +     help
> > +       This is a test module for copy_user_tests because these functions
> > +       cannot be tested by KUnit so they must be their own module.
> > diff --git a/lib/Makefile b/lib/Makefile
> > index 5d64890d6b6a..e0dc4430e405 100644
> > --- a/lib/Makefile
> > +++ b/lib/Makefile
> > @@ -62,6 +62,7 @@ obj-$(CONFIG_TEST_IDA) += test_ida.o
> >  obj-$(CONFIG_TEST_KASAN) += test_kasan.o
> >  CFLAGS_test_kasan.o += -fno-builtin
> >  CFLAGS_test_kasan.o += $(call cc-disable-warning, vla)
> > +obj-$(CONFIG_TEST_KASAN_USER) += test_kasan_copy_user.o
> >  obj-$(CONFIG_TEST_UBSAN) += test_ubsan.o
> >  CFLAGS_test_ubsan.o += $(call cc-disable-warning, vla)
> >  UBSAN_SANITIZE_test_ubsan.o := y
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index cf73c6bee81b..c255495e6ce3 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -5,8 +5,6 @@
> >   * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
> >   */
> >
> > -#define pr_fmt(fmt) "kasan test: %s " fmt, __func__
> > -
> >  #include <linux/bitops.h>
> >  #include <linux/delay.h>
> >  #include <linux/kasan.h>
> > @@ -25,8 +23,26 @@
> >
> >  #include <kunit/test.h>
> >
> > +#if IS_BUILTIN(CONFIG_KUNIT)
>
> fix here to be IS_ENABLED(CONFIG_KUNIT)
>
Same comment as above. This relies on KUnit being built-in.

> > +
> >  struct kunit_resource resource;
> >  struct kunit_kasan_expectation fail_data;
> > +bool multishot;
> > +
> > +int kasan_multi_shot_init(struct kunit *test)
> > +{
> > +     /*
> > +      * Temporarily enable multi-shot mode. Otherwise, we'd only get a
> > +      * report for the first case.
> > +      */
> > +     multishot = kasan_save_enable_multi_shot();
> > +     return 0;
> > +}
> > +
> > +void kasan_multi_shot_exit(struct kunit *test)
> > +{
> > +     kasan_restore_multi_shot(multishot);
> > +}
> >
> >  #define KUNIT_SET_KASAN_DATA(test) do { \
> >       fail_data.report_expected = true; \
> > @@ -60,61 +76,44 @@ struct kunit_kasan_expectation fail_data;
> >       KUNIT_DO_EXPECT_KASAN_FAIL(test, condition); \
> >  } while (0)
> >
> > -/*
> > - * Note: test functions are marked noinline so that their names appear in
> > - * reports.
> > - */
> > -
> > -static noinline void __init kmalloc_oob_right(void)
> > +static void kmalloc_oob_right(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = 123;
> >
> > -     pr_info("out-of-bounds to right\n");
> >       ptr = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > -     ptr[size] = 'x';
> > +     KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 'x');
> >       kfree(ptr);
> >  }
> >
> > -static noinline void __init kmalloc_oob_left(void)
> > +static void kmalloc_oob_left(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = 15;
> >
> > -     pr_info("out-of-bounds to left\n");
> >       ptr = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > -     *ptr = *(ptr - 1);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, *ptr = *(ptr - 1));
> >       kfree(ptr);
> >  }
> >
> > -static noinline void __init kmalloc_node_oob_right(void)
> > +static void kmalloc_node_oob_right(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = 4096;
> >
> > -     pr_info("kmalloc_node(): out-of-bounds to right\n");
> >       ptr = kmalloc_node(size, GFP_KERNEL, 0);
> > -     if (!ptr) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > -     ptr[size] = 0;
> > +     KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
> >       kfree(ptr);
> >  }
> >
> >  #ifdef CONFIG_SLUB
> > -static noinline void __init kmalloc_pagealloc_oob_right(void)
> > +static void kmalloc_pagealloc_oob_right(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
> > @@ -122,324 +121,253 @@ static noinline void __init kmalloc_pagealloc_oob_right(void)
> >       /* Allocate a chunk that does not fit into a SLUB cache to trigger
> >        * the page allocator fallback.
> >        */
> > -     pr_info("kmalloc pagealloc allocation: out-of-bounds to right\n");
> >       ptr = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > -     ptr[size] = 0;
> > +     KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
> >       kfree(ptr);
> >  }
> >
> > -static noinline void __init kmalloc_pagealloc_uaf(void)
> > +static void kmalloc_pagealloc_uaf(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
> >
> > -     pr_info("kmalloc pagealloc allocation: use-after-free\n");
> >       ptr = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> >       kfree(ptr);
> > -     ptr[0] = 0;
> > +     KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
> >  }
> >
> > -static noinline void __init kmalloc_pagealloc_invalid_free(void)
> > +static void kmalloc_pagealloc_invalid_free(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
> >
> > -     pr_info("kmalloc pagealloc allocation: invalid-free\n");
> >       ptr = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > -     kfree(ptr + 1);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, kfree(ptr + 1));
> >  }
> > -#endif
> > +#endif /* CONFIG_SLUB */
> >
> > -static noinline void __init kmalloc_large_oob_right(void)
> > +static void kmalloc_large_oob_right(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = KMALLOC_MAX_CACHE_SIZE - 256;
> >       /* Allocate a chunk that is large enough, but still fits into a slab
> >        * and does not trigger the page allocator fallback in SLUB.
> >        */
> > -     pr_info("kmalloc large allocation: out-of-bounds to right\n");
> >       ptr = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > -     ptr[size] = 0;
> > +     KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
> >       kfree(ptr);
> >  }
> >
> > -static noinline void __init kmalloc_oob_krealloc_more(void)
> > +static void kmalloc_oob_krealloc_more(struct kunit *test)
> >  {
> >       char *ptr1, *ptr2;
> >       size_t size1 = 17;
> >       size_t size2 = 19;
> >
> > -     pr_info("out-of-bounds after krealloc more\n");
> >       ptr1 = kmalloc(size1, GFP_KERNEL);
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
> > +
> >       ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
> > -     if (!ptr1 || !ptr2) {
> > -             pr_err("Allocation failed\n");
> > -             kfree(ptr1);
> > -             kfree(ptr2);
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
> >
> > -     ptr2[size2] = 'x';
> > +     KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2] = 'x');
> >       kfree(ptr2);
> >  }
> >
> > -static noinline void __init kmalloc_oob_krealloc_less(void)
> > +static void kmalloc_oob_krealloc_less(struct kunit *test)
> >  {
> >       char *ptr1, *ptr2;
> >       size_t size1 = 17;
> >       size_t size2 = 15;
> >
> > -     pr_info("out-of-bounds after krealloc less\n");
> >       ptr1 = kmalloc(size1, GFP_KERNEL);
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
> > +
> >       ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
> > -     if (!ptr1 || !ptr2) {
> > -             pr_err("Allocation failed\n");
> > -             kfree(ptr1);
> > -             return;
> > -     }
> > -     ptr2[size2] = 'x';
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
> > +
> > +     KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2] = 'x');
> >       kfree(ptr2);
> >  }
> >
> > -static noinline void __init kmalloc_oob_16(void)
> > +static void kmalloc_oob_16(struct kunit *test)
> >  {
> >       struct {
> >               u64 words[2];
> >       } *ptr1, *ptr2;
> >
> > -     pr_info("kmalloc out-of-bounds for 16-bytes access\n");
> >       ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
> > +
> >       ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
> > -     if (!ptr1 || !ptr2) {
> > -             pr_err("Allocation failed\n");
> > -             kfree(ptr1);
> > -             kfree(ptr2);
> > -             return;
> > -     }
> > -     *ptr1 = *ptr2;
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
> > +
> > +     KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
> >       kfree(ptr1);
> >       kfree(ptr2);
> >  }
> >
> > -static noinline void __init kmalloc_oob_memset_2(void)
> > +static void kmalloc_oob_memset_2(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = 8;
> >
> > -     pr_info("out-of-bounds in memset2\n");
> >       ptr = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > -     memset(ptr+7, 0, 2);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr+7, 0, 2));
> >       kfree(ptr);
> >  }
> >
> > -static noinline void __init kmalloc_oob_memset_4(void)
> > +static void kmalloc_oob_memset_4(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = 8;
> >
> > -     pr_info("out-of-bounds in memset4\n");
> >       ptr = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > -     memset(ptr+5, 0, 4);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr+5, 0, 4));
> >       kfree(ptr);
> >  }
> >
> >
> > -static noinline void __init kmalloc_oob_memset_8(void)
> > +static void kmalloc_oob_memset_8(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = 8;
> >
> > -     pr_info("out-of-bounds in memset8\n");
> >       ptr = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > -     memset(ptr+1, 0, 8);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr+1, 0, 8));
> >       kfree(ptr);
> >  }
> >
> > -static noinline void __init kmalloc_oob_memset_16(void)
> > +static void kmalloc_oob_memset_16(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = 16;
> >
> > -     pr_info("out-of-bounds in memset16\n");
> >       ptr = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > -     memset(ptr+1, 0, 16);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr+1, 0, 16));
> >       kfree(ptr);
> >  }
> >
> > -static noinline void __init kmalloc_oob_in_memset(void)
> > +static void kmalloc_oob_in_memset(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = 666;
> >
> > -     pr_info("out-of-bounds in memset\n");
> >       ptr = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > -     memset(ptr, 0, size+5);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr, 0, size+5));
> >       kfree(ptr);
> >  }
> >
> > -static noinline void __init kmalloc_uaf(void)
> > +static void kmalloc_uaf(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = 10;
> >
> > -     pr_info("use-after-free\n");
> >       ptr = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> >       kfree(ptr);
> > -     *(ptr + 8) = 'x';
> > +     KUNIT_EXPECT_KASAN_FAIL(test, *(ptr + 8) = 'x');
> >  }
> >
> > -static noinline void __init kmalloc_uaf_memset(void)
> > +static void kmalloc_uaf_memset(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = 33;
> >
> > -     pr_info("use-after-free in memset\n");
> >       ptr = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> >       kfree(ptr);
> > -     memset(ptr, 0, size);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr, 0, size));
> >  }
> >
> > -static noinline void __init kmalloc_uaf2(void)
> > +static void kmalloc_uaf2(struct kunit *test)
> >  {
> >       char *ptr1, *ptr2;
> >       size_t size = 43;
> >
> > -     pr_info("use-after-free after another kmalloc\n");
> >       ptr1 = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr1) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
> >
> >       kfree(ptr1);
> > +
> >       ptr2 = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr2) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
> > +
> > +     KUNIT_EXPECT_KASAN_FAIL(test, ptr1[40] = 'x');
> > +     KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
> >
> > -     ptr1[40] = 'x';
> > -     if (ptr1 == ptr2)
> > -             pr_err("Could not detect use-after-free: ptr1 == ptr2\n");
> >       kfree(ptr2);
> >  }
> >
> > -static noinline void __init kfree_via_page(void)
> > +static void kfree_via_page(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = 8;
> >       struct page *page;
> >       unsigned long offset;
> >
> > -     pr_info("invalid-free false positive (via page)\n");
> >       ptr = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> >       page = virt_to_page(ptr);
> >       offset = offset_in_page(ptr);
> >       kfree(page_address(page) + offset);
> >  }
> >
> > -static noinline void __init kfree_via_phys(void)
> > +static void kfree_via_phys(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = 8;
> >       phys_addr_t phys;
> >
> > -     pr_info("invalid-free false positive (via phys)\n");
> >       ptr = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> >       phys = virt_to_phys(ptr);
> >       kfree(phys_to_virt(phys));
> >  }
> >
> > -static noinline void __init kmem_cache_oob(void)
> > +static void kmem_cache_oob(struct kunit *test)
> >  {
> >       char *p;
> >       size_t size = 200;
> >       struct kmem_cache *cache = kmem_cache_create("test_cache",
> >                                               size, 0,
> >                                               0, NULL);
> > -     if (!cache) {
> > -             pr_err("Cache allocation failed\n");
> > -             return;
> > -     }
> > -     pr_info("out-of-bounds in kmem_cache_alloc\n");
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
> >       p = kmem_cache_alloc(cache, GFP_KERNEL);
> >       if (!p) {
> > -             pr_err("Allocation failed\n");
> > +             kunit_err(test, "Allocation failed: %s\n", __func__);
> >               kmem_cache_destroy(cache);
> >               return;
> >       }
> >
> > -     *p = p[size];
> > +     KUNIT_EXPECT_KASAN_FAIL(test, *p = p[size]);
> >       kmem_cache_free(cache, p);
> >       kmem_cache_destroy(cache);
> >  }
> >
> > -static noinline void __init memcg_accounted_kmem_cache(void)
> > +static void memcg_accounted_kmem_cache(struct kunit *test)
> >  {
> >       int i;
> >       char *p;
> > @@ -447,12 +375,8 @@ static noinline void __init memcg_accounted_kmem_cache(void)
> >       struct kmem_cache *cache;
> >
> >       cache = kmem_cache_create("test_cache", size, 0, SLAB_ACCOUNT, NULL);
> > -     if (!cache) {
> > -             pr_err("Cache allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
> >
> > -     pr_info("allocate memcg accounted object\n");
> >       /*
> >        * Several allocations with a delay to allow for lazy per memcg kmem
> >        * cache creation.
> > @@ -472,134 +396,80 @@ static noinline void __init memcg_accounted_kmem_cache(void)
> >
> >  static char global_array[10];
> >
> > -static noinline void __init kasan_global_oob(void)
> > +static void kasan_global_oob(struct kunit *test)
> >  {
> >       volatile int i = 3;
> >       char *p = &global_array[ARRAY_SIZE(global_array) + i];
> >
> > -     pr_info("out-of-bounds global variable\n");
> > -     *(volatile char *)p;
> > -}
> > -
> > -static noinline void __init kasan_stack_oob(void)
> > -{
> > -     char stack_array[10];
> > -     volatile int i = 0;
> > -     char *p = &stack_array[ARRAY_SIZE(stack_array) + i];
> > -
> > -     pr_info("out-of-bounds on stack\n");
> > -     *(volatile char *)p;
> > +     KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
> >  }
> >
> > -static noinline void __init ksize_unpoisons_memory(void)
> > +static void ksize_unpoisons_memory(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = 123, real_size;
> >
> > -     pr_info("ksize() unpoisons the whole allocated chunk\n");
> >       ptr = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >       real_size = ksize(ptr);
> >       /* This access doesn't trigger an error. */
> >       ptr[size] = 'x';
> >       /* This one does. */
> > -     ptr[real_size] = 'y';
> > +     KUNIT_EXPECT_KASAN_FAIL(test, ptr[real_size] = 'y');
> >       kfree(ptr);
> >  }
> >
> > -static noinline void __init copy_user_test(void)
> > +#if (IS_ENABLED(CONFIG_KASAN_STACK))
> > +static void kasan_stack_oob(struct kunit *test)
> >  {
> > -     char *kmem;
> > -     char __user *usermem;
> > -     size_t size = 10;
> > -     int unused;
> > -
> > -     kmem = kmalloc(size, GFP_KERNEL);
> > -     if (!kmem)
> > -             return;
> > -
> > -     usermem = (char __user *)vm_mmap(NULL, 0, PAGE_SIZE,
> > -                         PROT_READ | PROT_WRITE | PROT_EXEC,
> > -                         MAP_ANONYMOUS | MAP_PRIVATE, 0);
> > -     if (IS_ERR(usermem)) {
> > -             pr_err("Failed to allocate user memory\n");
> > -             kfree(kmem);
> > -             return;
> > -     }
> > -
> > -     pr_info("out-of-bounds in copy_from_user()\n");
> > -     unused = copy_from_user(kmem, usermem, size + 1);
> > -
> > -     pr_info("out-of-bounds in copy_to_user()\n");
> > -     unused = copy_to_user(usermem, kmem, size + 1);
> > -
> > -     pr_info("out-of-bounds in __copy_from_user()\n");
> > -     unused = __copy_from_user(kmem, usermem, size + 1);
> > -
> > -     pr_info("out-of-bounds in __copy_to_user()\n");
> > -     unused = __copy_to_user(usermem, kmem, size + 1);
> > -
> > -     pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
> > -     unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
> > -
> > -     pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
> > -     unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
> > -
> > -     pr_info("out-of-bounds in strncpy_from_user()\n");
> > -     unused = strncpy_from_user(kmem, usermem, size + 1);
> > +     char stack_array[10];
> > +     volatile int i = 0;
> > +     char *p = &stack_array[ARRAY_SIZE(stack_array) + i];
> >
> > -     vm_munmap((unsigned long)usermem, PAGE_SIZE);
> > -     kfree(kmem);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
> >  }
> >
> > -static noinline void __init kasan_alloca_oob_left(void)
> > +static void kasan_alloca_oob_left(struct kunit *test)
> >  {
> >       volatile int i = 10;
> >       char alloca_array[i];
> >       char *p = alloca_array - 1;
> >
> > -     pr_info("out-of-bounds to left on alloca\n");
> > -     *(volatile char *)p;
> > +     KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
> >  }
> >
> > -static noinline void __init kasan_alloca_oob_right(void)
> > +static void kasan_alloca_oob_right(struct kunit *test)
> >  {
> >       volatile int i = 10;
> >       char alloca_array[i];
> >       char *p = alloca_array + i;
> >
> > -     pr_info("out-of-bounds to right on alloca\n");
> > -     *(volatile char *)p;
> > +     KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
> >  }
> > +#endif /* CONFIG_KASAN_STACK */
> >
> > -static noinline void __init kmem_cache_double_free(void)
> > +static void kmem_cache_double_free(struct kunit *test)
> >  {
> >       char *p;
> >       size_t size = 200;
> >       struct kmem_cache *cache;
> >
> >       cache = kmem_cache_create("test_cache", size, 0, 0, NULL);
> > -     if (!cache) {
> > -             pr_err("Cache allocation failed\n");
> > -             return;
> > -     }
> > -     pr_info("double-free on heap object\n");
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
> > +
> >       p = kmem_cache_alloc(cache, GFP_KERNEL);
> >       if (!p) {
> > -             pr_err("Allocation failed\n");
> > +             kunit_err(test, "Allocation failed: %s\n", __func__);
> >               kmem_cache_destroy(cache);
> >               return;
> >       }
> >
> >       kmem_cache_free(cache, p);
> > -     kmem_cache_free(cache, p);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_free(cache, p));
> >       kmem_cache_destroy(cache);
> >  }
> >
> > -static noinline void __init kmem_cache_invalid_free(void)
> > +static void kmem_cache_invalid_free(struct kunit *test)
> >  {
> >       char *p;
> >       size_t size = 200;
> > @@ -607,20 +477,17 @@ static noinline void __init kmem_cache_invalid_free(void)
> >
> >       cache = kmem_cache_create("test_cache", size, 0, SLAB_TYPESAFE_BY_RCU,
> >                                 NULL);
> > -     if (!cache) {
> > -             pr_err("Cache allocation failed\n");
> > -             return;
> > -     }
> > -     pr_info("invalid-free of heap object\n");
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
> > +
> >       p = kmem_cache_alloc(cache, GFP_KERNEL);
> >       if (!p) {
> > -             pr_err("Allocation failed\n");
> > +             kunit_err(test, "Allocation failed: %s\n", __func__);
> >               kmem_cache_destroy(cache);
> >               return;
> >       }
> >
> >       /* Trigger invalid free, the object doesn't get freed */
> > -     kmem_cache_free(cache, p + 1);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_free(cache, p + 1));
> >
> >       /*
> >        * Properly free the object to prevent the "Objects remaining in
> > @@ -631,45 +498,39 @@ static noinline void __init kmem_cache_invalid_free(void)
> >       kmem_cache_destroy(cache);
> >  }
> >
> > -static noinline void __init kasan_memchr(void)
> > +static void kasan_memchr(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = 24;
> >
> > -     pr_info("out-of-bounds in memchr\n");
> >       ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
> > -     if (!ptr)
> > -             return;
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > -     memchr(ptr, '1', size + 1);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, memchr(ptr, '1', size + 1));
> >       kfree(ptr);
> >  }
> >
> > -static noinline void __init kasan_memcmp(void)
> > +static void kasan_memcmp(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = 24;
> >       int arr[9];
> >
> > -     pr_info("out-of-bounds in memcmp\n");
> >       ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
> > -     if (!ptr)
> > -             return;
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> >       memset(arr, 0, sizeof(arr));
> > -     memcmp(ptr, arr, size+1);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, memcmp(ptr, arr, size+1));
> >       kfree(ptr);
> >  }
> >
> > -static noinline void __init kasan_strings(void)
> > +static void kasan_strings(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = 24;
> >
> > -     pr_info("use-after-free in strchr\n");
> >       ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
> > -     if (!ptr)
> > -             return;
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> >       kfree(ptr);
> >
> > @@ -680,188 +541,167 @@ static noinline void __init kasan_strings(void)
> >        * will likely point to zeroed byte.
> >        */
> >       ptr += 16;
> > -     strchr(ptr, '1');
> > +     KUNIT_EXPECT_KASAN_FAIL(test, strchr(ptr, '1'));
> >
> > -     pr_info("use-after-free in strrchr\n");
> > -     strrchr(ptr, '1');
> > +     KUNIT_EXPECT_KASAN_FAIL(test, strrchr(ptr, '1'));
> >
> > -     pr_info("use-after-free in strcmp\n");
> > -     strcmp(ptr, "2");
> > +     KUNIT_EXPECT_KASAN_FAIL(test, strcmp(ptr, "2"));
> >
> > -     pr_info("use-after-free in strncmp\n");
> > -     strncmp(ptr, "2", 1);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, strncmp(ptr, "2", 1));
> >
> > -     pr_info("use-after-free in strlen\n");
> > -     strlen(ptr);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, strlen(ptr));
> >
> > -     pr_info("use-after-free in strnlen\n");
> > -     strnlen(ptr, 1);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, strnlen(ptr, 1));
> >  }
> >
> > -static noinline void __init kasan_bitops(void)
> > +static void kasan_bitops(struct kunit *test)
> >  {
> >       /*
> >        * Allocate 1 more byte, which causes kzalloc to round up to 16-bytes;
> >        * this way we do not actually corrupt other memory.
> >        */
> >       long *bits = kzalloc(sizeof(*bits) + 1, GFP_KERNEL);
> > -     if (!bits)
> > -             return;
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, bits);
> >
> >       /*
> >        * Below calls try to access bit within allocated memory; however, the
> >        * below accesses are still out-of-bounds, since bitops are defined to
> >        * operate on the whole long the bit is in.
> >        */
> > -     pr_info("out-of-bounds in set_bit\n");
> > -     set_bit(BITS_PER_LONG, bits);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, set_bit(BITS_PER_LONG, bits));
> >
> > -     pr_info("out-of-bounds in __set_bit\n");
> > -     __set_bit(BITS_PER_LONG, bits);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, __set_bit(BITS_PER_LONG, bits));
> >
> > -     pr_info("out-of-bounds in clear_bit\n");
> > -     clear_bit(BITS_PER_LONG, bits);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, clear_bit(BITS_PER_LONG, bits));
> >
> > -     pr_info("out-of-bounds in __clear_bit\n");
> > -     __clear_bit(BITS_PER_LONG, bits);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, __clear_bit(BITS_PER_LONG, bits));
> >
> > -     pr_info("out-of-bounds in clear_bit_unlock\n");
> > -     clear_bit_unlock(BITS_PER_LONG, bits);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, clear_bit_unlock(BITS_PER_LONG, bits));
> >
> > -     pr_info("out-of-bounds in __clear_bit_unlock\n");
> > -     __clear_bit_unlock(BITS_PER_LONG, bits);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, __clear_bit_unlock(BITS_PER_LONG, bits));
> >
> > -     pr_info("out-of-bounds in change_bit\n");
> > -     change_bit(BITS_PER_LONG, bits);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, change_bit(BITS_PER_LONG, bits));
> >
> > -     pr_info("out-of-bounds in __change_bit\n");
> > -     __change_bit(BITS_PER_LONG, bits);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, __change_bit(BITS_PER_LONG, bits));
> >
> >       /*
> >        * Below calls try to access bit beyond allocated memory.
> >        */
> > -     pr_info("out-of-bounds in test_and_set_bit\n");
> > -     test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> > +     KUNIT_EXPECT_KASAN_FAIL(test,
> > +             test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
> >
> > -     pr_info("out-of-bounds in __test_and_set_bit\n");
> > -     __test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> > +     KUNIT_EXPECT_KASAN_FAIL(test,
> > +             __test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
> >
> > -     pr_info("out-of-bounds in test_and_set_bit_lock\n");
> > -     test_and_set_bit_lock(BITS_PER_LONG + BITS_PER_BYTE, bits);
> > +     KUNIT_EXPECT_KASAN_FAIL(test,
> > +             test_and_set_bit_lock(BITS_PER_LONG + BITS_PER_BYTE, bits));
> >
> > -     pr_info("out-of-bounds in test_and_clear_bit\n");
> > -     test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> > +     KUNIT_EXPECT_KASAN_FAIL(test,
> > +             test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
> >
> > -     pr_info("out-of-bounds in __test_and_clear_bit\n");
> > -     __test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> > +     KUNIT_EXPECT_KASAN_FAIL(test,
> > +             __test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
> >
> > -     pr_info("out-of-bounds in test_and_change_bit\n");
> > -     test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> > +     KUNIT_EXPECT_KASAN_FAIL(test,
> > +             test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
> >
> > -     pr_info("out-of-bounds in __test_and_change_bit\n");
> > -     __test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> > +     KUNIT_EXPECT_KASAN_FAIL(test,
> > +             __test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
> >
> > -     pr_info("out-of-bounds in test_bit\n");
> > -     (void)test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> > +     KUNIT_EXPECT_KASAN_FAIL(test,
> > +             (void)test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
> >
> >  #if defined(clear_bit_unlock_is_negative_byte)
> > -     pr_info("out-of-bounds in clear_bit_unlock_is_negative_byte\n");
> > -     clear_bit_unlock_is_negative_byte(BITS_PER_LONG + BITS_PER_BYTE, bits);
> > +     KUNIT_EXPECT_KASAN_FAIL(test,
> > +             clear_bit_unlock_is_negative_byte(BITS_PER_LONG + BITS_PER_BYTE,
> > +                                             bits));
> >  #endif
> >       kfree(bits);
> >  }
> >
> > -static noinline void __init kmalloc_double_kzfree(void)
> > +static void kmalloc_double_kzfree(struct kunit *test)
> >  {
> >       char *ptr;
> >       size_t size = 16;
> >
> > -     pr_info("double-free (kzfree)\n");
> >       ptr = kmalloc(size, GFP_KERNEL);
> > -     if (!ptr) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> >       kzfree(ptr);
> > -     kzfree(ptr);
> > +     KUNIT_EXPECT_KASAN_FAIL(test, kzfree(ptr));
> >  }
> >
> >  #ifdef CONFIG_KASAN_VMALLOC
> > -static noinline void __init vmalloc_oob(void)
> > +static void vmalloc_oob(struct kunit *test)
> >  {
> >       void *area;
> >
> > -     pr_info("vmalloc out-of-bounds\n");
> > -
> >       /*
> >        * We have to be careful not to hit the guard page.
> >        * The MMU will catch that and crash us.
> >        */
> >       area = vmalloc(3000);
> > -     if (!area) {
> > -             pr_err("Allocation failed\n");
> > -             return;
> > -     }
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, area);
> >
> > -     ((volatile char *)area)[3100];
> > +     KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)area)[3100]);
> >       vfree(area);
> >  }
> >  #else
> > -static void __init vmalloc_oob(void) {}
> > +static void vmalloc_oob(struct kunit *test) {}
> >  #endif
> >
> > -static int __init kmalloc_tests_init(void)
> > -{
> > -     /*
> > -      * Temporarily enable multi-shot mode. Otherwise, we'd only get a
> > -      * report for the first case.
> > -      */
> > -     bool multishot = kasan_save_enable_multi_shot();
> > -
> > -     kmalloc_oob_right();
> > -     kmalloc_oob_left();
> > -     kmalloc_node_oob_right();
> > +static struct kunit_case kasan_kunit_test_cases[] = {
> > +     KUNIT_CASE(kmalloc_oob_right),
> > +     KUNIT_CASE(kmalloc_oob_left),
> > +     KUNIT_CASE(kmalloc_node_oob_right),
> >  #ifdef CONFIG_SLUB
> > -     kmalloc_pagealloc_oob_right();
> > -     kmalloc_pagealloc_uaf();
> > -     kmalloc_pagealloc_invalid_free();
> > -#endif
> > -     kmalloc_large_oob_right();
> > -     kmalloc_oob_krealloc_more();
> > -     kmalloc_oob_krealloc_less();
> > -     kmalloc_oob_16();
> > -     kmalloc_oob_in_memset();
> > -     kmalloc_oob_memset_2();
> > -     kmalloc_oob_memset_4();
> > -     kmalloc_oob_memset_8();
> > -     kmalloc_oob_memset_16();
> > -     kmalloc_uaf();
> > -     kmalloc_uaf_memset();
> > -     kmalloc_uaf2();
> > -     kfree_via_page();
> > -     kfree_via_phys();
> > -     kmem_cache_oob();
> > -     memcg_accounted_kmem_cache();
> > -     kasan_stack_oob();
> > -     kasan_global_oob();
> > -     kasan_alloca_oob_left();
> > -     kasan_alloca_oob_right();
> > -     ksize_unpoisons_memory();
> > -     copy_user_test();
> > -     kmem_cache_double_free();
> > -     kmem_cache_invalid_free();
> > -     kasan_memchr();
> > -     kasan_memcmp();
> > -     kasan_strings();
> > -     kasan_bitops();
> > -     kmalloc_double_kzfree();
> > -     vmalloc_oob();
> > -
> > -     kasan_restore_multi_shot(multishot);
> > -
> > -     return -EAGAIN;
> > -}
> > +     KUNIT_CASE(kmalloc_pagealloc_oob_right),
> > +     KUNIT_CASE(kmalloc_pagealloc_uaf),
> > +     KUNIT_CASE(kmalloc_pagealloc_invalid_free),
> > +#endif /* CONFIG_SLUB */
> > +     KUNIT_CASE(kmalloc_large_oob_right),
> > +     KUNIT_CASE(kmalloc_oob_krealloc_more),
> > +     KUNIT_CASE(kmalloc_oob_krealloc_less),
> > +     KUNIT_CASE(kmalloc_oob_16),
> > +     KUNIT_CASE(kmalloc_oob_in_memset),
> > +     KUNIT_CASE(kmalloc_oob_memset_2),
> > +     KUNIT_CASE(kmalloc_oob_memset_4),
> > +     KUNIT_CASE(kmalloc_oob_memset_8),
> > +     KUNIT_CASE(kmalloc_oob_memset_16),
> > +     KUNIT_CASE(kmalloc_uaf),
> > +     KUNIT_CASE(kmalloc_uaf_memset),
> > +     KUNIT_CASE(kmalloc_uaf2),
> > +     KUNIT_CASE(kfree_via_page),
> > +     KUNIT_CASE(kfree_via_phys),
> > +     KUNIT_CASE(kmem_cache_oob),
> > +     KUNIT_CASE(memcg_accounted_kmem_cache),
> > +     KUNIT_CASE(kasan_global_oob),
> > +#if (IS_ENABLED(CONFIG_KASAN_STACK))
> > +     KUNIT_CASE(kasan_stack_oob), // need stack protection
> > +     KUNIT_CASE(kasan_alloca_oob_left),
> > +     KUNIT_CASE(kasan_alloca_oob_right),
> > +#endif /*CONFIG_KASAN_STACK*/
> > +     KUNIT_CASE(ksize_unpoisons_memory),
> > +     KUNIT_CASE(kmem_cache_double_free),
> > +     KUNIT_CASE(kmem_cache_invalid_free),
> > +     KUNIT_CASE(kasan_memchr),
> > +     KUNIT_CASE(kasan_memcmp),
> > +     KUNIT_CASE(kasan_strings),
> > +     KUNIT_CASE(kasan_bitops),
> > +     KUNIT_CASE(kmalloc_double_kzfree),
> > +     KUNIT_CASE(vmalloc_oob),
> > +     {}
> > +};
> > +
> > +static struct kunit_suite kasan_kunit_test_suite = {
> > +     .name = "kasan_kunit_test",
> > +     .init = kasan_multi_shot_init,
> > +     .test_cases = kasan_kunit_test_cases,
> > +     .exit = kasan_multi_shot_exit,
> > +};
> > +
> > +kunit_test_suite(kasan_kunit_test_suite);
> > +
> > +#endif /* BUILTIN(CONFIG_KUNIT) */
> >
> > -module_init(kmalloc_tests_init);
> >  MODULE_LICENSE("GPL");
> > diff --git a/lib/test_kasan_copy_user.c b/lib/test_kasan_copy_user.c
> > new file mode 100644
> > index 000000000000..9523cbc332ec
> > --- /dev/null
> > +++ b/lib/test_kasan_copy_user.c
> > @@ -0,0 +1,75 @@
> > +// SPDX-License-Identifier: GPL-2.0-only
> > +/*
> > + *
> > + * Copyright (c) 2014 Samsung Electronics Co., Ltd.
> > + * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
> > + */
> > +
> > +#define pr_fmt(fmt) "kasan test: %s " fmt, __func__
> > +
> > +#include <linux/mman.h>
> > +#include <linux/module.h>
> > +#include <linux/printk.h>
> > +#include <linux/slab.h>
> > +#include <linux/uaccess.h>
> > +
> > +static noinline void __init copy_user_test(void)
> > +{
> > +     char *kmem;
> > +     char __user *usermem;
> > +     size_t size = 10;
> > +     int unused;
> > +
> > +     kmem = kmalloc(size, GFP_KERNEL);
> > +     if (!kmem)
> > +             return;
> > +
> > +     usermem = (char __user *)vm_mmap(NULL, 0, PAGE_SIZE,
> > +                         PROT_READ | PROT_WRITE | PROT_EXEC,
> > +                         MAP_ANONYMOUS | MAP_PRIVATE, 0);
> > +     if (IS_ERR(usermem)) {
> > +             pr_err("Failed to allocate user memory\n");
> > +             kfree(kmem);
> > +             return;
> > +     }
> > +
> > +     pr_info("out-of-bounds in copy_from_user()\n");
> > +     unused = copy_from_user(kmem, usermem, size + 1);
> > +
> > +     pr_info("out-of-bounds in copy_to_user()\n");
> > +     unused = copy_to_user(usermem, kmem, size + 1);
> > +
> > +     pr_info("out-of-bounds in __copy_from_user()\n");
> > +     unused = __copy_from_user(kmem, usermem, size + 1);
> > +
> > +     pr_info("out-of-bounds in __copy_to_user()\n");
> > +     unused = __copy_to_user(usermem, kmem, size + 1);
> > +
> > +     pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
> > +     unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
> > +
> > +     pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
> > +     unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
> > +
> > +     pr_info("out-of-bounds in strncpy_from_user()\n");
> > +     unused = strncpy_from_user(kmem, usermem, size + 1);
> > +
> > +     vm_munmap((unsigned long)usermem, PAGE_SIZE);
> > +     kfree(kmem);
> > +}
> > +
> > +static int __init copy_user_tests_init(void)
> > +{
> > +     /*
> > +      * Temporarily enable multi-shot mode. Otherwise, we'd only get a
> > +      * report for the first case.
> > +      */
> > +     bool multishot = kasan_save_enable_multi_shot();
> > +
> > +     copy_user_test();
> > +     kasan_restore_multi_shot(multishot);
> > +     return -EAGAIN;
> > +}
> > +
> > +module_init(copy_user_tests_init);
> > +MODULE_LICENSE("GPL");
> > --
> > 2.25.1.696.g5e7596f4ac-goog
> >
> >

-- 
Best,
Patricia

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvUJsonsrru%2BN18ZzY5hCiRp5OtS7GYtRoewooOJCzTr0qA%40mail.gmail.com.
