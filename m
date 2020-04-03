Return-Path: <kasan-dev+bncBDK3TPOVRULBBJ67TX2AKGQEL4UJRRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id BA1D019DC81
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Apr 2020 19:17:27 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id n16sf2699994lfq.18
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Apr 2020 10:17:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585934247; cv=pass;
        d=google.com; s=arc-20160816;
        b=p0rirSOhcx8SoFF4qTJ3aAhTDHb2BDwHGBjOyZ2OgKo4dfUyGmyKh3eZy2dKxgV5LQ
         a3TSIDL6sabkHZQnNOyDGgzRfUQv9mRuPyMvvt0yIdO2wQtdviPgEhWS+YGoKDQySrAL
         hBmbzax0/P51fl149pvAFI5qT4vl6eNUpl5Y9YT9gWq7p7TvXxspkVHBqGTnigCzLuaz
         HzuJBPr/M2T/YJl4IcIrW6ijGVwZe6el28tlz75AtsCmQG6hd4klYnijJfW7yxbnSsme
         ij+O+5AYxRCRBIVML8l8plz4Y9c96lmrMGElPznNY0n9pceS5u9/7spC0Lhg/Y3EuJfH
         DY/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uPl9UmndMqnBkaa7w7LfNKnUzezwFTPDwKixABYiobw=;
        b=ZSRKZUmn7eAlqNrhmesoxNsmEc1i5oGWhbN+SR+9P9yCkZgKeriR0H3uV2YlAArKzW
         XgIoCL5vV2FKtK2P5Glq6giLZRTp3KKaQNi/aArch1NL8xf8I4swiqnZ8NIXPPKLwWEd
         Ya0PEYnMloPff8PYEv0qo+dSAr39aL7G4uQv4Dp1e0MHtjYs8DhPJNEbswGuD7PbPdHy
         0rWm5l22vOTLZasLGyo+CdeaHQzgduce9ErEGW+oAHoFSZELv7bLb9HP4qMWPPKH7Xe7
         fGhLsdBSat6upeQSA/OQ/xx44uL92O0DGYmmhY8t+Ez+nTl2xsL0mfRLB+HN3BMe76Y4
         BJzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p8ulibXM;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=uPl9UmndMqnBkaa7w7LfNKnUzezwFTPDwKixABYiobw=;
        b=lq9cJNF/d9pwBMTHUkfPkBIFziWroZskdoJ1XdyT7CBXCQRt2LwzNkb6UfYAJRhVDb
         AJ0RON/Biswx1Xhvbjk2WOxqLlsI82zgksfMHS277tYegeAHdu4tZw/eNyVVnWeKI5B/
         MPhgch7EiJVLL41QJ1gvBPXGWNRnluu9tjcuNObh2kVbS2EzBHD5MQ9oTm+cFiYfA9Rn
         Y5Ub8ZnZxk9eLfbN6oPoEWdisPuQFK8JX1PcI4UrlLzd3ZqjUkU4oIBvz6W3paIOt0yt
         dmuMEB0qwMQy5nFPwTxVLDdYeGjy1O8WjbaXxDtKPFqVqL6zjlmymocasBsQhONsS1zR
         yMgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uPl9UmndMqnBkaa7w7LfNKnUzezwFTPDwKixABYiobw=;
        b=FaaDP8EG2QZhZiIfxRNRpiyfSqu974tETuLtVjia6zgbkYKqHDlJWp0CQq8mlSGS5i
         qL6ycecKJiwYVphnM25e+8IeTtVkGx9r2dOX0mQWkn6B6GkaxamFrIgPJU01cFsAmdqK
         Idd5O9vIeWyrHuBRYNVobUq9YKPvAXqeHO6eh6J+7fBAr8pDmeSmZErW9dSF7Brng9wv
         8sFKSZuhrEeHg6biI6UuCDERNb11pC+Wx0BDsFSrJiN2y0X+o0t+8grByyFbpdai0wv1
         XWfSGiUvwUpYg1RM/kZLBC1hx+1N5jceUREKMEW6lEDAdWzOzosAVa1EQKJWB/uH001W
         aiVw==
X-Gm-Message-State: AGi0PuZR44KW5TDiVJXyeClj3FmYg6zeWXuAQB/BbVCLFBM+MPqT//C8
	SkkPNr2SQ23oQdEeUgTZBrs=
X-Google-Smtp-Source: APiQypKbrxUijCQbetcYMLvra/uZSsupd6OsOFam9QyXR2BUHkiRAOs11pKf4UYP33Slef9nX2YdNg==
X-Received: by 2002:a2e:a548:: with SMTP id e8mr5446680ljn.151.1585934247109;
        Fri, 03 Apr 2020 10:17:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:550:: with SMTP id q16ls1330016ljp.1.gmail; Fri, 03
 Apr 2020 10:17:26 -0700 (PDT)
X-Received: by 2002:a2e:9194:: with SMTP id f20mr5608096ljg.33.1585934246436;
        Fri, 03 Apr 2020 10:17:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585934246; cv=none;
        d=google.com; s=arc-20160816;
        b=A0Zlr/SNWwMBCdh3VRD5+M2EghZT2ziJl96Mantv8e+7By053S5zXd8CDGoaoHcm5T
         qJ/4RFh4zDRpd0Il7GmKoO9fQfvRscZ9jnN8MlUnTcWozimC68pL1cOU9wGg7YBjrZ4M
         FBZFrzu/K8CN0Iy86HIzuk7f0zyHG27FmxGu+QQxw1iV+TO7QgHcLZ6lAyV3Ii/U4M0h
         yYDUG6KSKkEBRkwRizmQxkBY239+wekWR58LCfrB0STH9iw9Wstl177EIyo7IMw0LdHN
         8/ZgcweT7ShTKCy1+Ot7MjkYkqwExKymzgYFmE8WwJTxrTALmdhhbiSUrTbZJozna5jM
         6khg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fiyLiEQCjzFCZ/HdRdxYlu8TdBvUIdiFWSO5Ut+t7qk=;
        b=XTr41VakAHjNc6X17pse3+zE/fhBq3tcAnIb/h2HZV5UzQQxCVI0TQ7nKFieJc1Urm
         rey8u+xQZ5kBFWxRSIX3TPB6P2SoOphsdWcbe8UZvK6A86wz9Qs0apF4eaZ3o3OhdEe9
         tTelv5hmvM3zFR9VsmFl6WutzJabo/0pUT1gZTiBiiOI71RRhbZQM9/NKBup1RYuTZ2m
         sK9FdJpM6ZItCiE8WNv0jpF3DWqTADxU+Ozt9JRKGeEzElJTux4FtKqL4hmaVonrOkwC
         aE+qGwf9kW6msBJvS1w92Qe6zSau9gLNTamSFt7/gFd7saI6QMugYCbF14shAN1xGXYr
         A32Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p8ulibXM;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id c18si412719lji.4.2020.04.03.10.17.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Apr 2020 10:17:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id d77so7933179wmd.3
        for <kasan-dev@googlegroups.com>; Fri, 03 Apr 2020 10:17:26 -0700 (PDT)
X-Received: by 2002:a1c:750f:: with SMTP id o15mr10014390wmc.110.1585934245587;
 Fri, 03 Apr 2020 10:17:25 -0700 (PDT)
MIME-Version: 1.0
References: <20200402204639.161637-1-trishalfonso@google.com>
 <20200402204639.161637-2-trishalfonso@google.com> <CAAeHK+xFLmnAHPPCrmmqb1of7+cZmvKKPgAMACjArrLChG=xDw@mail.gmail.com>
In-Reply-To: <CAAeHK+xFLmnAHPPCrmmqb1of7+cZmvKKPgAMACjArrLChG=xDw@mail.gmail.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 3 Apr 2020 10:17:14 -0700
Message-ID: <CAKFsvUKZFiiLFGcFykLoXhK1ehc-T=c6EkHf1UNmQRJc=uBQXg@mail.gmail.com>
Subject: Re: [PATCH v4 2/4] KUnit: KASAN Integration
To: Andrey Konovalov <andreyknvl@google.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=p8ulibXM;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::342
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

On Fri, Apr 3, 2020 at 6:20 AM Andrey Konovalov <andreyknvl@google.com> wro=
te:
>
> On Thu, Apr 2, 2020 at 10:46 PM 'Patricia Alfonso' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > Integrate KASAN into KUnit testing framework.
> >         - Fail tests when KASAN reports an error that is not expected
> >         - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN
> >         tests
> >         - Expected KASAN reports pass tests and are still printed when =
run
> >         without kunit_tool (kunit_tool still bypasses the report due to=
 the
> >         test passing)
> >         - KUnit struct in current task used to keep track of the curren=
t
> >         test from KASAN code
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
> > [1] (https://lore.kernel.org/linux-kselftest/1583251361-12748-1-git-sen=
d-email-alan.maguire@oracle.com/T/#t)
> >
> > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > ---
> >  include/kunit/test.h  |  5 ++++
> >  include/linux/kasan.h |  6 +++++
> >  lib/kunit/test.c      | 13 ++++++----
> >  lib/test_kasan.c      | 56 +++++++++++++++++++++++++++++++++++++++----
> >  mm/kasan/report.c     | 30 +++++++++++++++++++++++
> >  5 files changed, 101 insertions(+), 9 deletions(-)
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
> > +/* kasan_data struct is used in KUnit tests for KASAN expected failure=
s */
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
> >         struct kunit_suite *suite =3D ctx->suite;
> >         struct kunit_case *test_case =3D ctx->test_case;
> >
> > +#if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT))
> > +       current->kunit_test =3D test;
> > +#endif /* IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT) */
> > +
> >         /*
> >          * kunit_run_case_internal may encounter a fatal error; if it d=
oes,
> >          * abort will be called, this thread will exit, and finally the=
 parent
> > @@ -603,6 +603,9 @@ void kunit_cleanup(struct kunit *test)
> >                 spin_unlock(&test->lock);
> >                 kunit_remove_resource(test, res);
> >         }
> > +#if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT))
> > +       current->kunit_test =3D NULL;
> > +#endif /* IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT)*/
> >  }
> >  EXPORT_SYMBOL_GPL(kunit_cleanup);
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index 3872d250ed2c..dbfa0875ee09 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -23,12 +23,60 @@
> >
> >  #include <asm/page.h>
> >
> > -/*
> > - * Note: test functions are marked noinline so that their names appear=
 in
> > - * reports.
> > +#include <kunit/test.h>
> > +
> > +static struct kunit_resource resource;
> > +static struct kunit_kasan_expectation fail_data;
> > +static bool multishot;
> > +static int orig_panic_on_warn;
> > +
> > +static int kasan_test_init(struct kunit *test)
> > +{
> > +       /*
> > +        * Temporarily enable multi-shot mode and set panic_on_warn=3D0=
.
> > +        * Otherwise, we'd only get a report for the first case.
> > +        */
> > +       multishot =3D kasan_save_enable_multi_shot();
> > +
> > +       orig_panic_on_warn =3D panic_on_warn;
> > +       panic_on_warn =3D 0;
> > +
> > +       return 0;
> > +}
> > +
> > +static void kasan_test_exit(struct kunit *test)
> > +{
> > +       kasan_restore_multi_shot(multishot);
> > +
> > +       /* Restore panic_on_warn */
>
> Nit: no need for this comment, I think it's clear that here we're
> restoring stuff we saved in kasan_test_init().
>
Okay!

> > +       panic_on_warn =3D orig_panic_on_warn;
> > +}
> > +
> > +/**
> > + * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expressi=
on does
> > + * not cause a KASAN error. This uses a KUnit resource named "kasan_da=
ta." Do
> > + * Do not use this name for a KUnit resource outside here.
> > + *
> >   */
> > +#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do { \
> > +       struct kunit_resource *res; \
> > +       struct kunit_kasan_expectation *kasan_data; \
> > +       fail_data.report_expected =3D true; \
> > +       fail_data.report_found =3D false; \
> > +       kunit_add_named_resource(test, \
> > +                               NULL, \
> > +                               NULL, \
> > +                               &resource, \
> > +                               "kasan_data", &fail_data); \
> > +       condition; \
> > +       res =3D kunit_find_named_resource(test, "kasan_data"); \
>
> Is res going to be =3D=3D &resource here? If so, no need to call
> kunit_find_named_resource().
>

You're right. Thanks for the suggestion!

> > +       kasan_data =3D res->data; \
> > +       KUNIT_EXPECT_EQ(test, \
> > +                       kasan_data->report_expected, \
> > +                       kasan_data->report_found); \
>
> Nit: no need to add kasan_data var, just use resource.data->report_expect=
ed.
>

I can probably just use fail_data->report_expected, actually.

> > +       kunit_put_resource(res); \
> > +} while (0)
> >
> > -static noinline void __init kmalloc_oob_right(void)
> >  {
> >         char *ptr;
> >         size_t size =3D 123;
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 5ef9f24f566b..497477c4b679 100644
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
> > @@ -455,12 +457,35 @@ static bool report_enabled(void)
> >         return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
> >  }
> >
> > +#if IS_ENABLED(CONFIG_KUNIT)
> > +void kasan_update_kunit_status(struct kunit *cur_test)
>
> This isn't used outside of report.c, right? Then _static_ void
> kasan_update_kunit_status().
>

Correct.

> > +{
> > +       struct kunit_resource *resource;
> > +       struct kunit_kasan_expectation *kasan_data;
> > +
> > +       if (!kunit_find_named_resource(cur_test, "kasan_data")) {
> > +               kunit_set_failure(cur_test);
> > +               return;
> > +       }
> > +
> > +       resource =3D kunit_find_named_resource(cur_test, "kasan_data");
>
> Do this before the if above, and then check if (!resource), will save
> you a call to kunit_find_named_resource().
>
> > +       kasan_data =3D resource->data;
> > +       kasan_data->report_found =3D true;
>
> No need for kasan_data var (if it can't be NULL or something), just do:
>
> resource->data->report_found =3D true;
>

The compiler seems to really hate this...
mm/kasan/report.c: In function =E2=80=98kasan_update_kunit_status=E2=80=99:
mm/kasan/report.c:471:16: warning: dereferencing =E2=80=98void *=E2=80=99 p=
ointer
  471 |  resource->data->report_found =3D true;
      |                ^~
mm/kasan/report.c:471:16: error: request for member =E2=80=98report_found=
=E2=80=99 in
something not a structure or union

Do you know how to fix this? I don't think I fully understand the error.

> > +}
> > +#endif /* IS_ENABLED(CONFIG_KUNIT) */
> > +
> >  void kasan_report_invalid_free(void *object, unsigned long ip)
> >  {
> >         unsigned long flags;
> >         u8 tag =3D get_tag(object);
> >
> >         object =3D reset_tag(object);
> > +
> > +#if IS_ENABLED(CONFIG_KUNIT)
> > +       if (current->kunit_test)
> > +               kasan_update_kunit_status(current->kunit_test);
> > +#endif /* IS_ENABLED(CONFIG_KUNIT) */
> > +
> >         start_report(&flags);
> >         pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (voi=
d *)ip);
> >         print_tags(tag, object);
> > @@ -481,6 +506,11 @@ void __kasan_report(unsigned long addr, size_t siz=
e, bool is_write, unsigned lon
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
> >         tagged_addr =3D (void *)addr;

--=20
Best,
Patricia

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAKFsvUKZFiiLFGcFykLoXhK1ehc-T%3Dc6EkHf1UNmQRJc%3DuBQXg%40mail.gm=
ail.com.
