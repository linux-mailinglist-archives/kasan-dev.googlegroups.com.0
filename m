Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFNLTD2AKGQECG7QW3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id 819C019C73E
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Apr 2020 18:40:55 +0200 (CEST)
Received: by mail-ua1-x93f.google.com with SMTP id a9sf1442875uan.18
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Apr 2020 09:40:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585845654; cv=pass;
        d=google.com; s=arc-20160816;
        b=XFHIqk5BjpI957VMl7pC71mjSV3RDoaEE74TKy5rnSqQVGiJs0BkqPdeyBsiv9CtXp
         FjiHf2qPHnSz+uMa1uad0LlGNri/MiMw/Yt4ASqm+W5T9l7gVQ3BOc0WjIDzngkam2bs
         nhhmCZWwA76EkWgTf7lo23uXeq/OKMmjWUJte5PJbIdQhuqxQkBV54dHz+3NeeO219Es
         dPMuqCKAOn3LfPn6t+ePYkiOJPKbPTPorbKCPBxdg51imRsul2HbReY6xKvhTOuSs6pC
         0S5jXtpKRep+SjfPTWZLxgN3ErWxYLLIrMdYEdzKKvF6VQG/hxhKz58jSjll8OLaFH+c
         4OMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0Efi1Ox9fYYIF8fuktMdRQo5wODhlMb/I7CMFWw3VJQ=;
        b=eQ71TL+4hunsYJ0a6yeW151nq2GcN6TemYAeiXmMNpdZyONT+uFOjTAjsRsOIcMSjR
         ESbpJUwuXx0qUk2pIkaScrG7DGOOZji4UqsuAdJbAvhOOm2i0qeAVmR9cns4uxIYElvA
         U/+i0poOgPY4Uw8Ftv9km6apwz1CG4nPuO8c8NPMTk8xjdz14k829F0bCpI/tSwDxeax
         A5Qhbq7sWv2az7npAMEuBAkF76593JJlk2sxuGNIxm7dAEPghoAolF27kN1QgwuVG//0
         Tk+I5qNHR+vpNZnHOPh0xeHnY0FuOoiDtrfd7ZINr5EEm7REfLlAM6ugv1UBLA0gLOeH
         vDhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kGejEdLz;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0Efi1Ox9fYYIF8fuktMdRQo5wODhlMb/I7CMFWw3VJQ=;
        b=Vi/v3fnItqsdl/BpwkDCwf8kfWeR4dLPUaQJWL6+syoaP54rSwuEruejheeGRoXWIw
         MSdbndJfeZynhjnNDr3xWp76THv+NGQ+3fYPVoBVpvukwCp7SOWP0bp2NlVvK/sMwYMp
         chRtspDUSrw7ug5zXSScIo4GmRNGlZjTdpQfnFIQbIpYdkZMLsc2kgyKv1qI71iWtYtM
         N5Gumaw1hN3zpcsVmoMD3wIM9JBfii3AoYq/6iUurqA259w3/dvylIzgGJLzyQ2TGUiV
         ZUo4g8UjyTiF0u7Gur8bxbP7cdBGYw2/K3FnlzRHGiSVOmMb4Msxo229GJEgQ+4qt9qE
         ayXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0Efi1Ox9fYYIF8fuktMdRQo5wODhlMb/I7CMFWw3VJQ=;
        b=N5qMLFLaTJ0m2fB7CDyLlkn3F+ts3dZZm2t1LaE6T3N6fgDeAQa5yLjJBXv68cJwNz
         5/TTUOX4wriLgyoc/tQhZ8Nle1EaSJK/tT2W0OG5tKIGMs0nlgUDJ1TlC0mnaxbuS6Md
         WMzWUGFHpdBKtuvZHothWuoOPEkbnLVTmEz/3ordRrZttWF+b+Fu2HzFJ8O+kdyMZ1q1
         lIn3P2410TAyT0BkUYyyHkAROyiLmGqO4GcCx32qBvbmJKUPaKhFk4w7DbpqSU/0YamO
         +RS2x3v3k/jPp99XsKqvM7GWzeDoeVqvKqgrFB8Sj7wTc9DRWZCs5OlhHk6nht2HXJFh
         ASvg==
X-Gm-Message-State: AGi0PuZDBlGkGCORQD23E/mTHG2RihmRx2MZI7tcfkdGZr3sfmzbUcxR
	/EffuW5fNDWVNThAM6IUDo8=
X-Google-Smtp-Source: APiQypJL+G9JCWTd4DgbHZWEa5pA1JPpL52BPTyqpqR0RNy9LxKo4j/QhI1AAnIQTHbBacpS7dApQQ==
X-Received: by 2002:a1f:8ccf:: with SMTP id o198mr2925387vkd.53.1585845654073;
        Thu, 02 Apr 2020 09:40:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:737:: with SMTP id u23ls378221vsg.1.gmail; Thu, 02
 Apr 2020 09:40:53 -0700 (PDT)
X-Received: by 2002:a67:2ecf:: with SMTP id u198mr2970226vsu.29.1585845653541;
        Thu, 02 Apr 2020 09:40:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585845653; cv=none;
        d=google.com; s=arc-20160816;
        b=s6J8krdqsrby3gJektb2hiusqK7dyaRnKLJP5F6ljRaLhwyn9iR7Llaxh/ee36O94F
         pQByjv3aRaJ4CQWR58WNi7W68gYyNwkSA86XUHx0wG5NFpyXjfwNW2UgscIbrW0LzR3y
         vrSwAr4kcaIXzWSQ++jKRIpSwhMES9PSfXUXHJfdy2RfdNCu7/25zx+udbB841hMM0FX
         FauhQSrQN/UOXDMnPqxifyKMJGlmaIf9VtnwOCjI/hU4oNJLW8uaH0Z3zgqzSbNusdSZ
         33kkhpuLN3iMae6BgMCMDr8vFu9ukHzIQkf7jbitJn2H912fwbpdkGq1SrBaOlqxnSUf
         h/aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4FzclJGrxe0sBGhzxk/JNHh6pg2AnQtz+q6DvHj5q10=;
        b=y2aPWda4t9cXfCl3fLrmQhPsv7LpzI4WQeoVsihbxk6wVW0TVQ3t2NTpO7IDGtIjU8
         0h8285tWhgO+PB+1zvY1VAJ1zx1/Nzeh0gUvgBu2b/EWVHg5aK68gPc9HqTl0igzwhlI
         n9lXodHJP7tb7czErHkTN0iB7fE0GUK5jALvsICZCOuMMdX4I4zzHYhxPXdx1Iws/MbA
         DhcNR0QZAGuqWakekzKqaOaXZfwfkrSV0efAP4SwoogfYLDtJOU+uGBtr3o5OcbN2LNc
         zlb7vMRkPJLd22ADuQXzarXwblFUvtLj+i/pbmaaOfKtAdwbrnY5w0ii6JWU7efLQsdy
         eJXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kGejEdLz;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id s124si447106vka.1.2020.04.02.09.40.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Apr 2020 09:40:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id h11so1538281plk.7
        for <kasan-dev@googlegroups.com>; Thu, 02 Apr 2020 09:40:53 -0700 (PDT)
X-Received: by 2002:a17:90b:1985:: with SMTP id mv5mr4787168pjb.69.1585845652159;
 Thu, 02 Apr 2020 09:40:52 -0700 (PDT)
MIME-Version: 1.0
References: <20200401180907.202604-1-trishalfonso@google.com>
 <20200401180907.202604-2-trishalfonso@google.com> <CAAeHK+zwshOOfnS3QNRcysF+KbTVK6=9yavj18GFkGF1tw0X4g@mail.gmail.com>
 <CAKFsvU+Ro2zazrd_BdLsn4z6JAR4rmvn5pHkNTw=CvWFMjseFQ@mail.gmail.com>
In-Reply-To: <CAKFsvU+Ro2zazrd_BdLsn4z6JAR4rmvn5pHkNTw=CvWFMjseFQ@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Apr 2020 18:40:40 +0200
Message-ID: <CAAeHK+zWEPvALVhZWfs0vfWHeyfWv9tv_OGArnfVG4UMRk3ucQ@mail.gmail.com>
Subject: Re: [PATCH v3 2/4] KUnit: KASAN Integration
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
 header.i=@google.com header.s=20161025 header.b=kGejEdLz;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644
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

On Thu, Apr 2, 2020 at 6:37 PM Patricia Alfonso <trishalfonso@google.com> wrote:
>
> On Thu, Apr 2, 2020 at 8:54 AM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > On Wed, Apr 1, 2020 at 8:09 PM 'Patricia Alfonso' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > >
> > > Integrate KASAN into KUnit testing framework.
> > >         - Fail tests when KASAN reports an error that is not expected
> > >         - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN tests
> > >         - Expected KASAN reports pass tests and are still printed when run
> > >         without kunit_tool (kunit_tool still bypasses the report due to the
> > >         test passing)
> > >         - KUnit struct in current task used to keep track of the current test
> > >         from KASAN code
> > >
> > > Make use of "[PATCH v3 kunit-next 1/2] kunit: generalize
> > > kunit_resource API beyond allocated resources" and "[PATCH v3
> > > kunit-next 2/2] kunit: add support for named resources" from Alan
> > > Maguire [1]
> > >         - A named resource is added to a test when a KASAN report is
> > >          expected
> > >         - This resource contains a struct for kasan_data containing
> > >         booleans representing if a KASAN report is expected and if a
> > >         KASAN report is found
> > >
> > > [1] (https://lore.kernel.org/linux-kselftest/1583251361-12748-1-git-send-email-alan.maguire@oracle.com/T/#t)
> > >
> > > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > > ---
> > >  include/kunit/test.h  |  5 +++++
> > >  include/linux/kasan.h |  6 ++++++
> > >  lib/kunit/test.c      | 13 ++++++++-----
> > >  lib/test_kasan.c      | 37 +++++++++++++++++++++++++++++++++++++
> > >  mm/kasan/report.c     | 33 +++++++++++++++++++++++++++++++++
> > >  5 files changed, 89 insertions(+), 5 deletions(-)
> > >
> > > diff --git a/include/kunit/test.h b/include/kunit/test.h
> > > index ac59d18e6bab..1dc3d118f64b 100644
> > > --- a/include/kunit/test.h
> > > +++ b/include/kunit/test.h
> > > @@ -225,6 +225,11 @@ struct kunit {
> > >         struct list_head resources; /* Protected by lock. */
> > >  };
> > >
> > > +static inline void kunit_set_failure(struct kunit *test)
> > > +{
> > > +       WRITE_ONCE(test->success, false);
> > > +}
> > > +
> > >  void kunit_init_test(struct kunit *test, const char *name, char *log);
> > >
> > >  int kunit_run_tests(struct kunit_suite *suite);
> > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > index 5cde9e7c2664..148eaef3e003 100644
> > > --- a/include/linux/kasan.h
> > > +++ b/include/linux/kasan.h
> > > @@ -14,6 +14,12 @@ struct task_struct;
> > >  #include <asm/kasan.h>
> > >  #include <asm/pgtable.h>
> > >
> > > +/* kasan_data struct is used in KUnit tests for KASAN expected failures */
> > > +struct kunit_kasan_expectation {
> > > +       bool report_expected;
> > > +       bool report_found;
> > > +};
> > > +
> > >  extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
> > >  extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
> > >  extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
> > > diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> > > index 2cb7c6220a00..030a3281591e 100644
> > > --- a/lib/kunit/test.c
> > > +++ b/lib/kunit/test.c
> > > @@ -10,16 +10,12 @@
> > >  #include <linux/kernel.h>
> > >  #include <linux/kref.h>
> > >  #include <linux/sched/debug.h>
> > > +#include <linux/sched.h>
> > >
> > >  #include "debugfs.h"
> > >  #include "string-stream.h"
> > >  #include "try-catch-impl.h"
> > >
> > > -static void kunit_set_failure(struct kunit *test)
> > > -{
> > > -       WRITE_ONCE(test->success, false);
> > > -}
> > > -
> > >  static void kunit_print_tap_version(void)
> > >  {
> > >         static bool kunit_has_printed_tap_version;
> > > @@ -288,6 +284,10 @@ static void kunit_try_run_case(void *data)
> > >         struct kunit_suite *suite = ctx->suite;
> > >         struct kunit_case *test_case = ctx->test_case;
> > >
> > > +#if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT))
> > > +       current->kunit_test = test;
> > > +#endif /* IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT) */
> > > +
> > >         /*
> > >          * kunit_run_case_internal may encounter a fatal error; if it does,
> > >          * abort will be called, this thread will exit, and finally the parent
> > > @@ -603,6 +603,9 @@ void kunit_cleanup(struct kunit *test)
> > >                 spin_unlock(&test->lock);
> > >                 kunit_remove_resource(test, res);
> > >         }
> > > +#if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT))
> > > +       current->kunit_test = NULL;
> > > +#endif /* IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT)*/
> > >  }
> > >  EXPORT_SYMBOL_GPL(kunit_cleanup);
> > >
> > > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > > index 3872d250ed2c..cf73c6bee81b 100644
> > > --- a/lib/test_kasan.c
> > > +++ b/lib/test_kasan.c
> > > @@ -23,6 +23,43 @@
> > >
> > >  #include <asm/page.h>
> > >
> > > +#include <kunit/test.h>
> > > +
> > > +struct kunit_resource resource;
> > > +struct kunit_kasan_expectation fail_data;
> > > +
> > > +#define KUNIT_SET_KASAN_DATA(test) do { \
> > > +       fail_data.report_expected = true; \
> > > +       fail_data.report_found = false; \
> > > +       kunit_add_named_resource(test, \
> > > +                               NULL, \
> > > +                               NULL, \
> > > +                               &resource, \
> > > +                               "kasan_data", &fail_data); \
> > > +} while (0)
> > > +
> > > +#define KUNIT_DO_EXPECT_KASAN_FAIL(test, condition) do { \
> > > +       struct kunit_resource *resource; \
> > > +       struct kunit_kasan_expectation *kasan_data; \
> > > +       condition; \
> > > +       resource = kunit_find_named_resource(test, "kasan_data"); \
> > > +       kasan_data = resource->data; \
> > > +       KUNIT_EXPECT_EQ(test, \
> > > +                       kasan_data->report_expected, \
> > > +                       kasan_data->report_found); \
> > > +       kunit_put_resource(resource); \
> > > +} while (0)
> > > +
> > > +/**
> > > + * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
> > > + * not cause a KASAN error.
> > > + *
> > > + */
> > > +#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do { \
> > > +       KUNIT_SET_KASAN_DATA(test); \
> > > +       KUNIT_DO_EXPECT_KASAN_FAIL(test, condition); \
> > > +} while (0)
> >
> > Any reason to split this macro into two parts? Do we call any of them
> > separately?
> >
> They are not called anywhere else... honestly, it was just a style
> choice to make it clear that there are 2 parts to the expectation. I
> don't think they have to be split if there's enough reason to smash
> them together.

I think squashing them together will look cleaner.

>
> > > +
> > >  /*
> > >   * Note: test functions are marked noinline so that their names appear in
> > >   * reports.
> > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > index 5ef9f24f566b..87330ef3a99a 100644
> > > --- a/mm/kasan/report.c
> > > +++ b/mm/kasan/report.c
> > > @@ -32,6 +32,8 @@
> > >
> > >  #include <asm/sections.h>
> > >
> > > +#include <kunit/test.h>
> > > +
> > >  #include "kasan.h"
> > >  #include "../slab.h"
> > >
> > > @@ -455,12 +457,38 @@ static bool report_enabled(void)
> > >         return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
> > >  }
> > >
> > > +#if IS_ENABLED(CONFIG_KUNIT)
> > > +void kasan_update_kunit_status(struct kunit *cur_test)
> > > +{
> > > +       struct kunit_resource *resource;
> > > +       struct kunit_kasan_expectation *kasan_data;
> > > +
> > > +       if (kunit_find_named_resource(cur_test, "kasan_data")) {
> > > +               resource = kunit_find_named_resource(cur_test, "kasan_data");
> > > +               kasan_data = resource->data;
> > > +               kasan_data->report_found = true;
> > > +
> > > +               if (!kasan_data->report_expected)
> > > +                       kunit_set_failure(current->kunit_test);
> >
> > Hm, we only call KUNIT_SET_KASAN_DATA() for KASAN tests that we expect
> > to fail AFAICS. Then we end up calling kunit_set_failure twice, once
> > here and the other time when we do KUNIT_EXPECT_EQ() in
> > KUNIT_DO_EXPECT_KASAN_FAIL(). Or maybe there's something I
> > misunderstand.
> >
>
> You are right. I didn't realize, but yes. If the report_expected is
> false, KUNIT_DO_EXPECT_KASAN_FAIL() will set the test failure in
> KUNIT_EXPECT_EQ(). I think this is just leftover logic from before I
> thought to use KUNIT_EXPECT_EQ().
>
> > > +               else
> > > +                       return;
> >
> > Nit: "else return;" can be dropped.
> >
> > You can actually reorder the code a bit to make it easier to read:
> >
> > if (!kunit_find_named_resource(cur_test, "kasan_data")) {
> >   kunit_set_failure(current->kunit_test);
> >   return;
> > }
> > // here comes kasan tests checks
> >
>
> I agree. This looks much cleaner. The thing to note is that anyone can
> add a named resource to a test. I doubt anyone will name their
> resource "kasan_data" outside of this file, but it may be worth adding
> a comment advising against it.
>
> >
> >
> >
> >
> > > +       } else
> > > +               kunit_set_failure(current->kunit_test);
> > > +}
> > > +#endif /* IS_ENABLED(CONFIG_KUNIT) */
> > > +
> > >  void kasan_report_invalid_free(void *object, unsigned long ip)
> > >  {
> > >         unsigned long flags;
> > >         u8 tag = get_tag(object);
> > >
> > >         object = reset_tag(object);
> > > +
> > > +#if IS_ENABLED(CONFIG_KUNIT)
> > > +       if (current->kunit_test)
> > > +               kasan_update_kunit_status(current->kunit_test);
> > > +#endif /* IS_ENABLED(CONFIG_KUNIT) */
> > > +
> > >         start_report(&flags);
> > >         pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
> > >         print_tags(tag, object);
> > > @@ -481,6 +509,11 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
> > >         if (likely(!report_enabled()))
> > >                 return;
> > >
> > > +#if IS_ENABLED(CONFIG_KUNIT)
> > > +       if (current->kunit_test)
> > > +               kasan_update_kunit_status(current->kunit_test);
> > > +#endif /* IS_ENABLED(CONFIG_KUNIT) */
> > > +
> > >         disable_trace_on_warning();
> > >
> > >         tagged_addr = (void *)addr;
> > > --
>
> Thanks for the comments!
>
> Best,
> Patricia

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzWEPvALVhZWfs0vfWHeyfWv9tv_OGArnfVG4UMRk3ucQ%40mail.gmail.com.
