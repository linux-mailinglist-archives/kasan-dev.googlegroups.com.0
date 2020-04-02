Return-Path: <kasan-dev+bncBDK3TPOVRULBBUFJTD2AKGQEPJAJAQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 14D6819C72F
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Apr 2020 18:37:37 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id q29sf3209229edc.1
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Apr 2020 09:37:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585845456; cv=pass;
        d=google.com; s=arc-20160816;
        b=VIW6U83IDOQjK6Pr68rsM0Z0AajDWEMLQqTCjiIJ2WTa8cJk1aMFsGSlUCihRKQSnD
         fp8nBh/G6yijYuXDBWMpvqQPZD+nCQ9plu2+JTfxjypKV+bpE0iU0vouGD+1zDOaGmn0
         4GchJ102c2kjRPFDuqfpjH5H7kFIHqiLUthP1rfgXMC9f/Ucd8nAzRVgXZn2D2QBmYe0
         gHh0MKgn6r3QttQci+UT53OGiZah3Cm3HXpUv99gJ9LtIz4lx9cO2nvPwigdMorTVprW
         UItTFaTp8W89jj/T3dKS4nsHuDlTpALHGL4FrRQMMY+IU9neb+9eKzfP4pQrEyzDRKB6
         EPtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6REhPsQrT/typeXj85/unJPIa57L+hHFA8Ojj2jnYRw=;
        b=rapSQ3S9Wi2STy9W/m443O3JUobEzgbUyOXUp2eXip2Fr0MwGfj1Mds7dkpySyFSXe
         an853WQ4UXh7BvEfLuwQBdZUsT53lg5qAoivSThEWzaaMtFIi2YedI33yIDB5Mylbie4
         80B7U1d+5VnIgJwd+rLcw/DuZ4wYKhAKLiYPCNJ3/C1fP4V1E7I4jMdR/l43kqiU8Z+m
         sruthBV1o7oQ8L0bR0WBQQ5nZvP4yz3Hb7wQ5uZddiEZP93X6uzLstA9JCe0RCZS0py5
         J4m+R/yK4QPYKHVE1GhiYEAWpZ4okFXsOX1TdrpcPfdOIPkdz7m7sULo+ncuoONbqFCu
         Pt3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PDpfcrr3;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6REhPsQrT/typeXj85/unJPIa57L+hHFA8Ojj2jnYRw=;
        b=mvQQaPhNjkKzMDcoQ1PiXxLZq28EftC36vjaK+LlLzn3pl8/+mPCYpfLxRMy1AD/W7
         YwtdM7R3nGxGSLWxbqN0XyXp/078B+RjOvmgmNB0t6TCuNdjRJ+sqGe2KoRfhLpMkiXh
         xcTlesjGTpPHztOtOhCnJUkKyyYDjf94t7RHO1T/HwG1xUOAQ5WrzZQFk3zpA9Yne/N/
         VR0i/wSfE9o4y12pkCd+KuVc0Q9BZIAW1a6XD1wtnkA9/3aSg6f2BlG0vOoVVcqQcrhV
         /CVs9lXMaaFWA7nHIGAYBv/EBsX4CnPlji3g3e6Y+zfYzyYqJ8AKxyAl3SEOeFeuyExQ
         jdkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6REhPsQrT/typeXj85/unJPIa57L+hHFA8Ojj2jnYRw=;
        b=NP9bXOaq24vqD2y+WW3iN3AaGyGZO5MlKMJmeaf/iB7hu/nYcEfRqMf56MSUfxqw4v
         XWepPCNyqGyZ3FDdHuMddFjY0VqkyW4bxnyYYKDUOiJ/t2GYczfOi6u6kweZ6hA+zh0B
         757BRv9pyPvnXE3s7HRdtFplPR/v/tBxCrkipDuFAx7AMYON91yNc6vkLnanfeLBwcjA
         C4t/k+Fa/1sDlOoZhWJrd+1fxLN4CYcA+7vfot5T0jgfq+OUjQ/cwFWtM91lNiCqolKB
         9Yf9yZI6UCcJjI6IA6cjyH9riikj5WG7jEa3JXNjFGJEa9ynTjpu1aCGxPS6yPTcyLCx
         zzxw==
X-Gm-Message-State: AGi0PubCIMfa4V+buJMqeyPvlVeO4iuH6hUcTpHV5YizKgAMe+ppxKHU
	oEQPpGWJYzG6lDtR/qk4H9I=
X-Google-Smtp-Source: APiQypJgJaMMy6kz+rNpFsTUIKR7bG2pRtXKxS8odYQkO2me7lb0lUX3sy4dn298+Kc0BCdVKGnCxA==
X-Received: by 2002:a50:c043:: with SMTP id u3mr3843249edd.253.1585845456719;
        Thu, 02 Apr 2020 09:37:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:f290:: with SMTP id f16ls1961916edm.6.gmail; Thu, 02 Apr
 2020 09:37:36 -0700 (PDT)
X-Received: by 2002:a05:6402:1619:: with SMTP id f25mr2903361edv.201.1585845456237;
        Thu, 02 Apr 2020 09:37:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585845456; cv=none;
        d=google.com; s=arc-20160816;
        b=eRzCz1AOkonBNT+EAD0pAVWXHRLraS46BMObmqp7mCQZ0YPoPeko+HhH5beDmVpJ4v
         nHJzRlQuqBoJEPJY+e6oNPF7qdXJnCdiCzxFHqRr+nNvWWsvM+/JyECZ/7vzt9p+S+JD
         7lm5T3QJ9E08qEaAoTo2gXLi5WxPRcTZYPVuJ5ycLH5jMALFGbA8aIL6ndWAmfP5T5uZ
         XP7VdSjP8DKC/TEBS6YycXEe81KvMXmC9wJA7EYKOE26ugv2v9+fMp6AiB/Gy2AoQ0kU
         f+muQ5QQtPTDdC8sVP4V8GjjnVXQuz89LnXb5FIky4uJUuyEh3kGoHgTTr0aUbN1dnUm
         pWKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EuexIUKHQSUPT9xt92hh8SwnfR0UxyKHCq8Fheii9A8=;
        b=DaZSnmI1GuSCF5Hzov1TSaxXM2AeGKCgUyfAJuSLsGAVjF3bmsMjJvx+Tuc5CqeUxR
         1Aazmlqq/L2b1tsaRamAuwFobzbq05vT/dTHnYuyh2RMwHegB16gfItJbSBzQyIqEH+w
         pH45iGAIzxbRqCSuoAdIo8z2xR7Nn4qEdquQMWfO6ah05u03RGqlWi29nzyK/Cad1TjB
         4IqaOSlVqKSEOnvBwVBCBsyGTCaIusYJXJmXVjQubZ3mAdjg3yaVdBFDOZvuUwn3AaPz
         Kbl1anq8PMAZLzz+9WEIHs1M0P3EmPB/4CntwwxFxc0HEraI5EO85nGEd0sutWOALYUz
         80HA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PDpfcrr3;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id w13si279755edv.2.2020.04.02.09.37.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Apr 2020 09:37:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id 65so5055195wrl.1
        for <kasan-dev@googlegroups.com>; Thu, 02 Apr 2020 09:37:36 -0700 (PDT)
X-Received: by 2002:adf:fb0a:: with SMTP id c10mr4299437wrr.272.1585845449761;
 Thu, 02 Apr 2020 09:37:29 -0700 (PDT)
MIME-Version: 1.0
References: <20200401180907.202604-1-trishalfonso@google.com>
 <20200401180907.202604-2-trishalfonso@google.com> <CAAeHK+zwshOOfnS3QNRcysF+KbTVK6=9yavj18GFkGF1tw0X4g@mail.gmail.com>
In-Reply-To: <CAAeHK+zwshOOfnS3QNRcysF+KbTVK6=9yavj18GFkGF1tw0X4g@mail.gmail.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Apr 2020 09:37:18 -0700
Message-ID: <CAKFsvU+Ro2zazrd_BdLsn4z6JAR4rmvn5pHkNTw=CvWFMjseFQ@mail.gmail.com>
Subject: Re: [PATCH v3 2/4] KUnit: KASAN Integration
To: Andrey Konovalov <andreyknvl@google.com>
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
 header.i=@google.com header.s=20161025 header.b=PDpfcrr3;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443
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

On Thu, Apr 2, 2020 at 8:54 AM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Wed, Apr 1, 2020 at 8:09 PM 'Patricia Alfonso' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > Integrate KASAN into KUnit testing framework.
> >         - Fail tests when KASAN reports an error that is not expected
> >         - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN tests
> >         - Expected KASAN reports pass tests and are still printed when run
> >         without kunit_tool (kunit_tool still bypasses the report due to the
> >         test passing)
> >         - KUnit struct in current task used to keep track of the current test
> >         from KASAN code
> >
> > Make use of "[PATCH v3 kunit-next 1/2] kunit: generalize
> > kunit_resource API beyond allocated resources" and "[PATCH v3
> > kunit-next 2/2] kunit: add support for named resources" from Alan
> > Maguire [1]
> >         - A named resource is added to a test when a KASAN report is
> >          expected
> >         - This resource contains a struct for kasan_data containing
> >         booleans representing if a KASAN report is expected and if a
> >         KASAN report is found
> >
> > [1] (https://lore.kernel.org/linux-kselftest/1583251361-12748-1-git-send-email-alan.maguire@oracle.com/T/#t)
> >
> > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > ---
> >  include/kunit/test.h  |  5 +++++
> >  include/linux/kasan.h |  6 ++++++
> >  lib/kunit/test.c      | 13 ++++++++-----
> >  lib/test_kasan.c      | 37 +++++++++++++++++++++++++++++++++++++
> >  mm/kasan/report.c     | 33 +++++++++++++++++++++++++++++++++
> >  5 files changed, 89 insertions(+), 5 deletions(-)
> >
> > diff --git a/include/kunit/test.h b/include/kunit/test.h
> > index ac59d18e6bab..1dc3d118f64b 100644
> > --- a/include/kunit/test.h
> > +++ b/include/kunit/test.h
> > @@ -225,6 +225,11 @@ struct kunit {
> >         struct list_head resources; /* Protected by lock. */
> >  };
> >
> > +static inline void kunit_set_failure(struct kunit *test)
> > +{
> > +       WRITE_ONCE(test->success, false);
> > +}
> > +
> >  void kunit_init_test(struct kunit *test, const char *name, char *log);
> >
> >  int kunit_run_tests(struct kunit_suite *suite);
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 5cde9e7c2664..148eaef3e003 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -14,6 +14,12 @@ struct task_struct;
> >  #include <asm/kasan.h>
> >  #include <asm/pgtable.h>
> >
> > +/* kasan_data struct is used in KUnit tests for KASAN expected failures */
> > +struct kunit_kasan_expectation {
> > +       bool report_expected;
> > +       bool report_found;
> > +};
> > +
> >  extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
> >  extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
> >  extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
> > diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> > index 2cb7c6220a00..030a3281591e 100644
> > --- a/lib/kunit/test.c
> > +++ b/lib/kunit/test.c
> > @@ -10,16 +10,12 @@
> >  #include <linux/kernel.h>
> >  #include <linux/kref.h>
> >  #include <linux/sched/debug.h>
> > +#include <linux/sched.h>
> >
> >  #include "debugfs.h"
> >  #include "string-stream.h"
> >  #include "try-catch-impl.h"
> >
> > -static void kunit_set_failure(struct kunit *test)
> > -{
> > -       WRITE_ONCE(test->success, false);
> > -}
> > -
> >  static void kunit_print_tap_version(void)
> >  {
> >         static bool kunit_has_printed_tap_version;
> > @@ -288,6 +284,10 @@ static void kunit_try_run_case(void *data)
> >         struct kunit_suite *suite = ctx->suite;
> >         struct kunit_case *test_case = ctx->test_case;
> >
> > +#if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT))
> > +       current->kunit_test = test;
> > +#endif /* IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT) */
> > +
> >         /*
> >          * kunit_run_case_internal may encounter a fatal error; if it does,
> >          * abort will be called, this thread will exit, and finally the parent
> > @@ -603,6 +603,9 @@ void kunit_cleanup(struct kunit *test)
> >                 spin_unlock(&test->lock);
> >                 kunit_remove_resource(test, res);
> >         }
> > +#if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT))
> > +       current->kunit_test = NULL;
> > +#endif /* IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT)*/
> >  }
> >  EXPORT_SYMBOL_GPL(kunit_cleanup);
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index 3872d250ed2c..cf73c6bee81b 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -23,6 +23,43 @@
> >
> >  #include <asm/page.h>
> >
> > +#include <kunit/test.h>
> > +
> > +struct kunit_resource resource;
> > +struct kunit_kasan_expectation fail_data;
> > +
> > +#define KUNIT_SET_KASAN_DATA(test) do { \
> > +       fail_data.report_expected = true; \
> > +       fail_data.report_found = false; \
> > +       kunit_add_named_resource(test, \
> > +                               NULL, \
> > +                               NULL, \
> > +                               &resource, \
> > +                               "kasan_data", &fail_data); \
> > +} while (0)
> > +
> > +#define KUNIT_DO_EXPECT_KASAN_FAIL(test, condition) do { \
> > +       struct kunit_resource *resource; \
> > +       struct kunit_kasan_expectation *kasan_data; \
> > +       condition; \
> > +       resource = kunit_find_named_resource(test, "kasan_data"); \
> > +       kasan_data = resource->data; \
> > +       KUNIT_EXPECT_EQ(test, \
> > +                       kasan_data->report_expected, \
> > +                       kasan_data->report_found); \
> > +       kunit_put_resource(resource); \
> > +} while (0)
> > +
> > +/**
> > + * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
> > + * not cause a KASAN error.
> > + *
> > + */
> > +#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do { \
> > +       KUNIT_SET_KASAN_DATA(test); \
> > +       KUNIT_DO_EXPECT_KASAN_FAIL(test, condition); \
> > +} while (0)
>
> Any reason to split this macro into two parts? Do we call any of them
> separately?
>
They are not called anywhere else... honestly, it was just a style
choice to make it clear that there are 2 parts to the expectation. I
don't think they have to be split if there's enough reason to smash
them together.

> > +
> >  /*
> >   * Note: test functions are marked noinline so that their names appear in
> >   * reports.
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 5ef9f24f566b..87330ef3a99a 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -32,6 +32,8 @@
> >
> >  #include <asm/sections.h>
> >
> > +#include <kunit/test.h>
> > +
> >  #include "kasan.h"
> >  #include "../slab.h"
> >
> > @@ -455,12 +457,38 @@ static bool report_enabled(void)
> >         return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
> >  }
> >
> > +#if IS_ENABLED(CONFIG_KUNIT)
> > +void kasan_update_kunit_status(struct kunit *cur_test)
> > +{
> > +       struct kunit_resource *resource;
> > +       struct kunit_kasan_expectation *kasan_data;
> > +
> > +       if (kunit_find_named_resource(cur_test, "kasan_data")) {
> > +               resource = kunit_find_named_resource(cur_test, "kasan_data");
> > +               kasan_data = resource->data;
> > +               kasan_data->report_found = true;
> > +
> > +               if (!kasan_data->report_expected)
> > +                       kunit_set_failure(current->kunit_test);
>
> Hm, we only call KUNIT_SET_KASAN_DATA() for KASAN tests that we expect
> to fail AFAICS. Then we end up calling kunit_set_failure twice, once
> here and the other time when we do KUNIT_EXPECT_EQ() in
> KUNIT_DO_EXPECT_KASAN_FAIL(). Or maybe there's something I
> misunderstand.
>

You are right. I didn't realize, but yes. If the report_expected is
false, KUNIT_DO_EXPECT_KASAN_FAIL() will set the test failure in
KUNIT_EXPECT_EQ(). I think this is just leftover logic from before I
thought to use KUNIT_EXPECT_EQ().

> > +               else
> > +                       return;
>
> Nit: "else return;" can be dropped.
>
> You can actually reorder the code a bit to make it easier to read:
>
> if (!kunit_find_named_resource(cur_test, "kasan_data")) {
>   kunit_set_failure(current->kunit_test);
>   return;
> }
> // here comes kasan tests checks
>

I agree. This looks much cleaner. The thing to note is that anyone can
add a named resource to a test. I doubt anyone will name their
resource "kasan_data" outside of this file, but it may be worth adding
a comment advising against it.

>
>
>
>
> > +       } else
> > +               kunit_set_failure(current->kunit_test);
> > +}
> > +#endif /* IS_ENABLED(CONFIG_KUNIT) */
> > +
> >  void kasan_report_invalid_free(void *object, unsigned long ip)
> >  {
> >         unsigned long flags;
> >         u8 tag = get_tag(object);
> >
> >         object = reset_tag(object);
> > +
> > +#if IS_ENABLED(CONFIG_KUNIT)
> > +       if (current->kunit_test)
> > +               kasan_update_kunit_status(current->kunit_test);
> > +#endif /* IS_ENABLED(CONFIG_KUNIT) */
> > +
> >         start_report(&flags);
> >         pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
> >         print_tags(tag, object);
> > @@ -481,6 +509,11 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
> >         if (likely(!report_enabled()))
> >                 return;
> >
> > +#if IS_ENABLED(CONFIG_KUNIT)
> > +       if (current->kunit_test)
> > +               kasan_update_kunit_status(current->kunit_test);
> > +#endif /* IS_ENABLED(CONFIG_KUNIT) */
> > +
> >         disable_trace_on_warning();
> >
> >         tagged_addr = (void *)addr;
> > --

Thanks for the comments!

Best,
Patricia

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvU%2BRo2zazrd_BdLsn4z6JAR4rmvn5pHkNTw%3DCvWFMjseFQ%40mail.gmail.com.
