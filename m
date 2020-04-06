Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7WUVX2AKGQEXBJKHBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 830EE19FBDE
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Apr 2020 19:44:31 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id j7sf466359qtd.22
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Apr 2020 10:44:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586195070; cv=pass;
        d=google.com; s=arc-20160816;
        b=GOkM9x+vYPfJoZH9adpWIo/dnAed4Q+fiyQWlZcdx7VJKykPX7PR343wb/8fCCODEO
         ebtGet8LQ8Xq8/a9tZ2i5mJbljqUE0i2pOXEEh5tCGRMQcuAF6zUWv6VELI/jjZIFrra
         IoP3y7C0aXUl9M5GbdBeuFHAgjL1omRpoZ7nW0YcQXvovp6PFsgBf4YbLs7BzceOVyOS
         OtsKzmjCAXd9BxtDeqJkD/5+C3wLxNl2ktteiWrl2wF0+5zcjR57KNEU4BGjHq5L7e+o
         2NB8SxqXmAlIzlzLG7D5PldqtN/MB6jgPJWUgJY9l0Bt1St4Pe6yKvFpLGwwd5qF9ae6
         pgnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Yce7hURZaJwSmzXXv2+s7lDLm540Fo+wesg/sYrTmHo=;
        b=SS7Dt1PIklXy5OKPi6hjH0qJa2kOX1MdesxVeL3gKc9qo+YHumEp4QfOSY9DyBKtFW
         R2aFvH9jYE2PyMd80o9MBXccoy1/n8jvCWqCIbEn1HxOzEhfprEeT6RjkjLH/qLHrhmX
         4UszGviC+o1b61mAKJME5zwz3cGNcjIcC/4LU6R34IVdLz6+LU30RIOOWiTzMxZMGUaZ
         UCVjguytQbOILHBgCjMXiP0Z8xuRWMurMPbm62gjyLfxk8henHPHah/Gt4R4b82SFupt
         OGufs2w8PfQdbZHOoL/1GwM+7BqhAMnxXu5SgF/TFVZS5XHSrPz4Q9z3BLQPb/cac6BM
         iEfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vGJISjtW;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Yce7hURZaJwSmzXXv2+s7lDLm540Fo+wesg/sYrTmHo=;
        b=hRd8GaJX4rg+VW+Wo7ESVK25FsxIGpaP7BvETzYDGimjLnphyDJNO8oE7wAamgUJwE
         1gsOUKjtbMrTHZGjRl/ydeNiVFNSbba2MuUEwjlr3jXXqOQXPS8pveggTp6inrRLZ64m
         Iy19voihZYxxR9lbXVCX7jN+zITx/mTf3U64Q2AzCroEm8fnmhMHhI7vW2B3/nBfg6pa
         ON1Brm5dZcEcrbskjC4Qp8WuBdeCxOqDCTR8KdUwpx+4RTAoxFzCt7EI2Yee7GHo2oAi
         XpKvW/f5AiJSRit+K0dtbP9+lE65QBhPb85/vH0Rq4mwDn7iDmHhORTGt4i7BhT22MEz
         fhww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Yce7hURZaJwSmzXXv2+s7lDLm540Fo+wesg/sYrTmHo=;
        b=XbDV05OwUt61eMAa+V4jBf3FlhYrIfvNoL9czxC/giVrOJpG3yBMfK91VsitkYyfaI
         DL71Gblu9iDlN9wHdCwzt6qCir88866Q1ubw5+V50Dcq8fizuJg/Vr8NlfHte9M+gETs
         BWTX64genLzE9clgt0Rr9D8y6uzyZkmmpZkZ+6ef566x5u+HIjr9eqAKCgQ9tbLG5zzy
         AIqfZdKze+roxyx0Yer404PHakYP+fqKF1GxxDvncF1gAfZHs/fBmussRhiYe4lnJFHc
         jr66xY+1hy+mTRqhlaWLMJ/NkK90oWbm8uaAMRaNgs2plPTjK55OGUv2GeJ+7d1XCgvh
         UFeQ==
X-Gm-Message-State: AGi0PuZ8w4DskHRuwwIXytjLEDh0g91aOXNExDw85QVe1z+cbh+74OEs
	GWBeqXsJWet4s/OetOrof/k=
X-Google-Smtp-Source: APiQypLbGsGUKUyx4feVfLi1nVll28Of+AOx48mMngJKjJEv3I3YSw8krsVVPCbnwd4zWpr/nh4xUQ==
X-Received: by 2002:a37:6244:: with SMTP id w65mr23155448qkb.350.1586195070557;
        Mon, 06 Apr 2020 10:44:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e808:: with SMTP id y8ls65811qvn.6.gmail; Mon, 06 Apr
 2020 10:44:30 -0700 (PDT)
X-Received: by 2002:ad4:498c:: with SMTP id t12mr850232qvx.27.1586195070011;
        Mon, 06 Apr 2020 10:44:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586195070; cv=none;
        d=google.com; s=arc-20160816;
        b=dRqE+MNnyswXnKjBD475b+KXSfvZQ9+gdTMRv0cdBoSC54m5LsH7a+o97xdGxjWsmQ
         11cAzfu1HB1Od3CsUPpuYwOMMmz2C911Q30RBzt/E2mlMCOWLyQRg0wbDZsIX9QaWOtY
         dxFH3hif87PaurfFK42wDnKqXlB+bBsQ+FUzo30ysb1MspVlxW/IqFTsDW6AGCIHeKcu
         Rs03y8/1ZF5sM6qGPQDtKvQ3EQQ6XNnvJI7djfLdJVT9l5emUS/0sCZEGfZ7xCSWaxy2
         g4Tgqz7PWt8dap5FZE+ZX6FZI0bSs+a44m5ozu0K7ZcPlFohh2u+SIffirLRbUZTbWx+
         OPXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9mmQaEU7pWx/GoSk4QgZnyNRh/7RdOmSGmaGx7v/l+8=;
        b=W8UppD2sHZ/RjMVUvsFK0wBKi++GenAIICxpzvmFYPi1LsvQSxl9v1Wxx6YSepYhGZ
         FRXJhQ6vvrAxMgEQ4SVSLVpNPIlIeD/vPu5ekXneX5YuW5os5l+u70fMzTHtI/460dxV
         GdHr5QFj9qAf2Gc7/iG6nEXVsFsB1AewrTL8c5LvXT1FUsKnbWG2zcdJyL9Qg5DMXeTy
         dpV8uNfArHZwoXiGZlx21nZeB+19FUjvH6J+nUi3pifrgsyo92ym7eH9ZpPuY/IFRP1W
         NF+gTaNc8liCrpb7efL7HZPs40MwKrflhMDOmX0eq1j3OeonJ6eqLrFTBcdm7dHz137x
         FgWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vGJISjtW;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1044.google.com (mail-pj1-x1044.google.com. [2607:f8b0:4864:20::1044])
        by gmr-mx.google.com with ESMTPS id e7si13895qtc.5.2020.04.06.10.44.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Apr 2020 10:44:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) client-ip=2607:f8b0:4864:20::1044;
Received: by mail-pj1-x1044.google.com with SMTP id z3so132361pjr.4
        for <kasan-dev@googlegroups.com>; Mon, 06 Apr 2020 10:44:29 -0700 (PDT)
X-Received: by 2002:a17:902:8c94:: with SMTP id t20mr20830697plo.336.1586195068761;
 Mon, 06 Apr 2020 10:44:28 -0700 (PDT)
MIME-Version: 1.0
References: <20200402204639.161637-1-trishalfonso@google.com>
 <20200402204639.161637-2-trishalfonso@google.com> <CAAeHK+xFLmnAHPPCrmmqb1of7+cZmvKKPgAMACjArrLChG=xDw@mail.gmail.com>
 <CAKFsvUKZFiiLFGcFykLoXhK1ehc-T=c6EkHf1UNmQRJc=uBQXg@mail.gmail.com>
In-Reply-To: <CAKFsvUKZFiiLFGcFykLoXhK1ehc-T=c6EkHf1UNmQRJc=uBQXg@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 6 Apr 2020 19:44:17 +0200
Message-ID: <CAAeHK+y=apWCBPPG7MiBF7qq57a4b4GGXfLVSEukQ4DKOY-ZNg@mail.gmail.com>
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
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vGJISjtW;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044
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

On Fri, Apr 3, 2020 at 7:17 PM Patricia Alfonso <trishalfonso@google.com> w=
rote:
>
> On Fri, Apr 3, 2020 at 6:20 AM Andrey Konovalov <andreyknvl@google.com> w=
rote:
> >
> > On Thu, Apr 2, 2020 at 10:46 PM 'Patricia Alfonso' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > >
> > > Integrate KASAN into KUnit testing framework.
> > >         - Fail tests when KASAN reports an error that is not expected
> > >         - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASA=
N
> > >         tests
> > >         - Expected KASAN reports pass tests and are still printed whe=
n run
> > >         without kunit_tool (kunit_tool still bypasses the report due =
to the
> > >         test passing)
> > >         - KUnit struct in current task used to keep track of the curr=
ent
> > >         test from KASAN code
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
> > > [1] (https://lore.kernel.org/linux-kselftest/1583251361-12748-1-git-s=
end-email-alan.maguire@oracle.com/T/#t)
> > >
> > > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > > ---
> > >  include/kunit/test.h  |  5 ++++
> > >  include/linux/kasan.h |  6 +++++
> > >  lib/kunit/test.c      | 13 ++++++----
> > >  lib/test_kasan.c      | 56 +++++++++++++++++++++++++++++++++++++++--=
--
> > >  mm/kasan/report.c     | 30 +++++++++++++++++++++++
> > >  5 files changed, 101 insertions(+), 9 deletions(-)
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
> > >  void kunit_init_test(struct kunit *test, const char *name, char *log=
);
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
> > > +/* kasan_data struct is used in KUnit tests for KASAN expected failu=
res */
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
> > >         struct kunit_suite *suite =3D ctx->suite;
> > >         struct kunit_case *test_case =3D ctx->test_case;
> > >
> > > +#if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT))
> > > +       current->kunit_test =3D test;
> > > +#endif /* IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT) */
> > > +
> > >         /*
> > >          * kunit_run_case_internal may encounter a fatal error; if it=
 does,
> > >          * abort will be called, this thread will exit, and finally t=
he parent
> > > @@ -603,6 +603,9 @@ void kunit_cleanup(struct kunit *test)
> > >                 spin_unlock(&test->lock);
> > >                 kunit_remove_resource(test, res);
> > >         }
> > > +#if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT))
> > > +       current->kunit_test =3D NULL;
> > > +#endif /* IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT)*/
> > >  }
> > >  EXPORT_SYMBOL_GPL(kunit_cleanup);
> > >
> > > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > > index 3872d250ed2c..dbfa0875ee09 100644
> > > --- a/lib/test_kasan.c
> > > +++ b/lib/test_kasan.c
> > > @@ -23,12 +23,60 @@
> > >
> > >  #include <asm/page.h>
> > >
> > > -/*
> > > - * Note: test functions are marked noinline so that their names appe=
ar in
> > > - * reports.
> > > +#include <kunit/test.h>
> > > +
> > > +static struct kunit_resource resource;
> > > +static struct kunit_kasan_expectation fail_data;
> > > +static bool multishot;
> > > +static int orig_panic_on_warn;
> > > +
> > > +static int kasan_test_init(struct kunit *test)
> > > +{
> > > +       /*
> > > +        * Temporarily enable multi-shot mode and set panic_on_warn=
=3D0.
> > > +        * Otherwise, we'd only get a report for the first case.
> > > +        */
> > > +       multishot =3D kasan_save_enable_multi_shot();
> > > +
> > > +       orig_panic_on_warn =3D panic_on_warn;
> > > +       panic_on_warn =3D 0;
> > > +
> > > +       return 0;
> > > +}
> > > +
> > > +static void kasan_test_exit(struct kunit *test)
> > > +{
> > > +       kasan_restore_multi_shot(multishot);
> > > +
> > > +       /* Restore panic_on_warn */
> >
> > Nit: no need for this comment, I think it's clear that here we're
> > restoring stuff we saved in kasan_test_init().
> >
> Okay!
>
> > > +       panic_on_warn =3D orig_panic_on_warn;
> > > +}
> > > +
> > > +/**
> > > + * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expres=
sion does
> > > + * not cause a KASAN error. This uses a KUnit resource named "kasan_=
data." Do
> > > + * Do not use this name for a KUnit resource outside here.
> > > + *
> > >   */
> > > +#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do { \
> > > +       struct kunit_resource *res; \
> > > +       struct kunit_kasan_expectation *kasan_data; \
> > > +       fail_data.report_expected =3D true; \
> > > +       fail_data.report_found =3D false; \
> > > +       kunit_add_named_resource(test, \
> > > +                               NULL, \
> > > +                               NULL, \
> > > +                               &resource, \
> > > +                               "kasan_data", &fail_data); \
> > > +       condition; \
> > > +       res =3D kunit_find_named_resource(test, "kasan_data"); \
> >
> > Is res going to be =3D=3D &resource here? If so, no need to call
> > kunit_find_named_resource().
> >
>
> You're right. Thanks for the suggestion!
>
> > > +       kasan_data =3D res->data; \
> > > +       KUNIT_EXPECT_EQ(test, \
> > > +                       kasan_data->report_expected, \
> > > +                       kasan_data->report_found); \
> >
> > Nit: no need to add kasan_data var, just use resource.data->report_expe=
cted.
> >
>
> I can probably just use fail_data->report_expected, actually.
>
> > > +       kunit_put_resource(res); \
> > > +} while (0)
> > >
> > > -static noinline void __init kmalloc_oob_right(void)
> > >  {
> > >         char *ptr;
> > >         size_t size =3D 123;
> > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > index 5ef9f24f566b..497477c4b679 100644
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
> > > @@ -455,12 +457,35 @@ static bool report_enabled(void)
> > >         return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
> > >  }
> > >
> > > +#if IS_ENABLED(CONFIG_KUNIT)
> > > +void kasan_update_kunit_status(struct kunit *cur_test)
> >
> > This isn't used outside of report.c, right? Then _static_ void
> > kasan_update_kunit_status().
> >
>
> Correct.
>
> > > +{
> > > +       struct kunit_resource *resource;
> > > +       struct kunit_kasan_expectation *kasan_data;
> > > +
> > > +       if (!kunit_find_named_resource(cur_test, "kasan_data")) {
> > > +               kunit_set_failure(cur_test);
> > > +               return;
> > > +       }
> > > +
> > > +       resource =3D kunit_find_named_resource(cur_test, "kasan_data"=
);
> >
> > Do this before the if above, and then check if (!resource), will save
> > you a call to kunit_find_named_resource().
> >
> > > +       kasan_data =3D resource->data;
> > > +       kasan_data->report_found =3D true;
> >
> > No need for kasan_data var (if it can't be NULL or something), just do:
> >
> > resource->data->report_found =3D true;
> >
>
> The compiler seems to really hate this...
> mm/kasan/report.c: In function =E2=80=98kasan_update_kunit_status=E2=80=
=99:
> mm/kasan/report.c:471:16: warning: dereferencing =E2=80=98void *=E2=80=99=
 pointer
>   471 |  resource->data->report_found =3D true;
>       |                ^~
> mm/kasan/report.c:471:16: error: request for member =E2=80=98report_found=
=E2=80=99 in
> something not a structure or union
>
> Do you know how to fix this? I don't think I fully understand the error.

Ah, resource->data is a void *, missed that. Let's keep the kasan_data
var then, but do explicit casting:

kasan_data =3D (struct kunit_kasan_expectation *)resource->data;
kasan_data->report_found =3D true;

>
> > > +}
> > > +#endif /* IS_ENABLED(CONFIG_KUNIT) */
> > > +
> > >  void kasan_report_invalid_free(void *object, unsigned long ip)
> > >  {
> > >         unsigned long flags;
> > >         u8 tag =3D get_tag(object);
> > >
> > >         object =3D reset_tag(object);
> > > +
> > > +#if IS_ENABLED(CONFIG_KUNIT)
> > > +       if (current->kunit_test)
> > > +               kasan_update_kunit_status(current->kunit_test);
> > > +#endif /* IS_ENABLED(CONFIG_KUNIT) */
> > > +
> > >         start_report(&flags);
> > >         pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (v=
oid *)ip);
> > >         print_tags(tag, object);
> > > @@ -481,6 +506,11 @@ void __kasan_report(unsigned long addr, size_t s=
ize, bool is_write, unsigned lon
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
> > >         tagged_addr =3D (void *)addr;
>
> --
> Best,
> Patricia

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAeHK%2By%3DapWCBPPG7MiBF7qq57a4b4GGXfLVSEukQ4DKOY-ZNg%40mail.gm=
ail.com.
