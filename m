Return-Path: <kasan-dev+bncBDK3TPOVRULBBBUQ5HZQKGQE6GHMZOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F84D191817
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Mar 2020 18:48:55 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 144sf3147487lfj.1
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Mar 2020 10:48:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585072134; cv=pass;
        d=google.com; s=arc-20160816;
        b=ETliQqsmZZG+GKOWcMorlK6Xh1MDzV6vIqmnldn9NzpxMMdoKoWl4Vq+PwaZtG15Q7
         nR2bTWTdYAcnemr1ToKy7UHDdKnY3Kw28xZxfJjH9LYtg8j9c1BY3hYdOkjlmJ6eB+rC
         +tu0+8pPEkvn05O5oS8pWKvugOvlN6FofDl/cDaRJWZihITG2ui3b7jelzmsrFQWvZpN
         qk4NMYrym0ThtP6B3nkSQhuRjdgFo/6NJaeWabhAFsN7+VcyTpgIcpx1rlSKDSjjtp15
         ndty3bOKlHDMilmgD4NSAmCXbu3tifxEP4LvXz0HUjHLdrnxo24/abf4wwsuUqj+LIoC
         VfxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KtP8w6U5vjvDtXAutCnWy3W/dsJbcf0cTWJYlfnJu9U=;
        b=Yee1WQH0MgXCNJCRnWeTlVltxUzlZ+cC/Anp+oScUc9N/cTC495QNaIby2DRmUm9Wz
         GOmeERSyXjyL6hVDuTogHVDWrbiF1vNz43JQA9OyDQnsq8ihDpKd1IwEAidvMngtmhB9
         FHvJFGhvaee9d2eFnS+q4275EZuiKZblFjhlzzFsrcXlSVyuSTJyWx/9VxLZufsgFQ+s
         o/Sv1TqhNpj6W56rSqWMZi3J9rbE/L/HV3j+/kmG3LSFIVYJ5IyH7G2L2yIPVUuIw1uH
         d2Q81JepqFlH/33s2KVTce9S150R4Ga79Dd6g2Ulg/StON8rgzZMfco/irlbClOPey2R
         qhaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UzoH2I2F;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KtP8w6U5vjvDtXAutCnWy3W/dsJbcf0cTWJYlfnJu9U=;
        b=qLW1vLedgljngbAoVDOxUr9/Gb/o+VRZMGbHVK8KAYkrNNaf/3yJq3hFL/UemTupZu
         wN9Rh9kGlUaXGT1+zSb7G7aUNc2Eg7lMv811c0cBtMwIcI6Srajpux17dNXbjZ0Eq8qg
         j06it0WHykZS0MhBi0bVsR+61d3MFoc8lUjd1dFQqyktOCLj8K6Xj+4Q41ARP8g7TuwN
         a3Qao3wEchrdKYPFpOmZlwsYlEKSlGbybGT9etURzlWWKgS/6xPowNp+PzhDOqRJFy+F
         LP0Ts49DWIjkaHTWVMnyT837VRel8u7mmHkqlLIXSw3KOEPwPQiSJyJfVlrRixKixV5V
         HjLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KtP8w6U5vjvDtXAutCnWy3W/dsJbcf0cTWJYlfnJu9U=;
        b=pgzMi9XVRBnnU4j64OX+Grpy+OyhOVeFHRpW5YmuIy9uUQek6DE1GLz63v48Z7HHos
         b8kRuCSaUZnN2ft3hZBS75PaZJ2r3UtuvINMd1/aZgxxEeOGz61YTSq4CpiZDN6sVea2
         vnXPF3gQOQZUSMSELUzDjOCsoSdK6gbY6MV8l2Apf8vFN+INQz6StOvm7RqxDcByfCTT
         r9YwBzgA0kdc1Mpp4I+iZJC8RVpHRuKxoZP98rcrm+JYWVXw/hPwSfbqz07il7pStD+y
         4JM9q3KT0nBRLBhMPraYSPfA/28dq2F1mibUbD5AmDvcZwH9fYd1or2JFDn/XsgMGepP
         vG4A==
X-Gm-Message-State: ANhLgQ00ohO8j4S+FySK8yeKsVrRXn9KMPYCrtenvir5rVQgWw6NOxoM
	xYbYHdnGDM0y7Xhd47BKlqk=
X-Google-Smtp-Source: ADFU+vtKTnELqElCR2C3cC1OTpdW2tm+bolz0EFU/IoTRl4riaPUTUiwuG3eDahlXMlDZPZwccCpbA==
X-Received: by 2002:a2e:9ed6:: with SMTP id h22mr18785875ljk.211.1585072134666;
        Tue, 24 Mar 2020 10:48:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:91d5:: with SMTP id u21ls1094307ljg.5.gmail; Tue, 24 Mar
 2020 10:48:54 -0700 (PDT)
X-Received: by 2002:a2e:80cd:: with SMTP id r13mr18266479ljg.224.1585072134050;
        Tue, 24 Mar 2020 10:48:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585072134; cv=none;
        d=google.com; s=arc-20160816;
        b=XjWZkNKqcodgazc5WFNPQXo0P1NdaSQD5LA7GRVPo2nmAVW4nmmnFrnkcBlwIZM3Ae
         WizfFOZIPmWh/7DwmYYTJO8pJisU9OQcvgivLLWEYZd5UnSSWIwANoy+asPL2U1Dg6oV
         LEdCqkjHgIh7kS+w3s+4DfBh0pN66KLT9z6llyCBFKq5OYPE8IpMXRlog0flugLBoH7X
         RaSGwZjqUDHMP6D5qTf+jkOjTt7F/Dll6CeNLH+kuMOhVcDFxel+n9jQxQB8lkAQLzNh
         VmZ0syw3xC/mhOe9GvYQeBn7t3KD9rG4arfTOqUnRUqTtPl9NvDSG7eJMqVNPj0xVRUK
         I4jA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TzOHB9g3KOGeLI2ijxAL8EBdgHfC4lrNr/2ltbuc77Y=;
        b=skj0JAlzjUcaDZakpvZ8uJKn3kGxHKK9WKVRc06bAXJ4SZn6rrQ1PcwhHZWy3onRXJ
         HSoRHMz2+leDoYyNMeT78hqtZP+imHTCw+in955du5ygFxQgeoihLFUr1BkzPWhwJaGL
         hoULuDEhejGwwJFOpiXyCivVs+VdHqCM2vsIZgl0XHuxqUMHyp5piwgl+vKFzku2taYk
         D4K0e4mlN/W/bC67o3tBasgtYog6Xrjt2wWoV45sPgp1dItS1e48v+Ld3z/RVzhPXXA+
         Ed+WUiDxJOYcPfB7mlXfsfzZDxXUL5mJHxe27u/gfYpuigSrjWb+NWNQ56AJWC2IMpLU
         KLkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UzoH2I2F;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id s17si1520791ljm.5.2020.03.24.10.48.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Mar 2020 10:48:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id 31so16609750wrs.3
        for <kasan-dev@googlegroups.com>; Tue, 24 Mar 2020 10:48:53 -0700 (PDT)
X-Received: by 2002:adf:efc9:: with SMTP id i9mr17429674wrp.23.1585072133363;
 Tue, 24 Mar 2020 10:48:53 -0700 (PDT)
MIME-Version: 1.0
References: <20200319164227.87419-1-trishalfonso@google.com>
 <20200319164227.87419-3-trishalfonso@google.com> <alpine.LRH.2.21.2003241640150.30637@localhost>
In-Reply-To: <alpine.LRH.2.21.2003241640150.30637@localhost>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 24 Mar 2020 10:48:42 -0700
Message-ID: <CAKFsvUKog1m77u+Jx58OHCXuxNNmw=joDZ-0VZ93FT4H7s0zSQ@mail.gmail.com>
Subject: Re: [RFC PATCH v2 2/3] KUnit: KASAN Integration
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
 header.i=@google.com header.s=20161025 header.b=UzoH2I2F;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::444
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

On Tue, Mar 24, 2020 at 9:45 AM Alan Maguire <alan.maguire@oracle.com> wrote:
>
>
> On Thu, 19 Mar 2020, Patricia Alfonso wrote:
>
> > Integrate KASAN into KUnit testing framework.
> >       - Fail tests when KASAN reports an error that is not expected
> >       - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN tests
> >       - Expected KASAN reports pass tests and are still printed when run
> >       without kunit_tool (kunit_tool still bypasses the report due to the
> >       test passing)
> >       - KUnit struct in current task used to keep track of the current test
> >       from KASAN code
> >
> > Make use of "[RFC PATCH kunit-next 1/2] kunit: generalize
> > kunit_resource API beyond allocated resources" and "[RFC PATCH
> > kunit-next 2/2] kunit: add support for named resources" from Alan
> > Maguire [1]
> >       - A named resource is added to a test when a KASAN report is
> >        expected
> >         - This resource contains a struct for kasan_data containing
> >         booleans representing if a KASAN report is expected and if a
> >         KASAN report is found
> >
> > [1] (https://lore.kernel.org/linux-kselftest/1583251361-12748-1-git-send-email-alan.maguire@oracle.com/T/#t)
> >
> > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > ---
> >  include/kunit/test.h | 10 ++++++++++
> >  lib/kunit/test.c     | 10 +++++++++-
> >  lib/test_kasan.c     | 37 +++++++++++++++++++++++++++++++++++++
> >  mm/kasan/report.c    | 33 +++++++++++++++++++++++++++++++++
> >  4 files changed, 89 insertions(+), 1 deletion(-)
> >
> > diff --git a/include/kunit/test.h b/include/kunit/test.h
> > index 70ee581b19cd..2ab265f4f76c 100644
> > --- a/include/kunit/test.h
> > +++ b/include/kunit/test.h
> > @@ -19,9 +19,19 @@
> >
> >  struct kunit_resource;
> >
> > +#ifdef CONFIG_KASAN
> > +/* kasan_data struct is used in KUnit tests for KASAN expected failures */
> > +struct kunit_kasan_expectation {
> > +     bool report_expected;
> > +     bool report_found;
> > +};
> > +#endif /* CONFIG_KASAN */
> > +
>
> Above should be moved to mm/kasan/kasan.h I think.
>
> >  typedef int (*kunit_resource_init_t)(struct kunit_resource *, void *);
> >  typedef void (*kunit_resource_free_t)(struct kunit_resource *);
> >
> > +void kunit_set_failure(struct kunit *test);
> > +
>
> Can you explain a bit more about why we need this exported?
> I see where it's used but I'd just like to make sure I
> understand what you're trying to do. Thanks!
>
I need the ability to set a KUnit test failure from outside the KUnit
code so that a test that does not expect a KASAN failure, but reaches
the point in the KASAN code where a report is printed will properly
fail due to this found KASAN failure.

> >  /**
> >   * struct kunit_resource - represents a *test managed resource*
> >   * @data: for the user to store arbitrary data.
> > diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> > index 86a4d9ca0a45..3f927ef45827 100644
> > --- a/lib/kunit/test.c
> > +++ b/lib/kunit/test.c
> > @@ -10,11 +10,12 @@
> >  #include <linux/kernel.h>
> >  #include <linux/kref.h>
> >  #include <linux/sched/debug.h>
> > +#include <linux/sched.h>
> >
> >  #include "string-stream.h"
> >  #include "try-catch-impl.h"
> >
> > -static void kunit_set_failure(struct kunit *test)
> > +void kunit_set_failure(struct kunit *test)
> >  {
> >       WRITE_ONCE(test->success, false);
> >  }
> > @@ -237,6 +238,10 @@ static void kunit_try_run_case(void *data)
> >       struct kunit_suite *suite = ctx->suite;
> >       struct kunit_case *test_case = ctx->test_case;
> >
> > +#if (IS_ENABLED(CONFIG_KASAN) && IS_BUILTIN(CONFIG_KUNIT))
> > +     current->kunit_test = test;
> > +#endif /* IS_ENABLED(CONFIG_KASAN) && IS_BUILTIN(CONFIG_KUNIT) */
> > +
> >       /*
> >        * kunit_run_case_internal may encounter a fatal error; if it does,
> >        * abort will be called, this thread will exit, and finally the parent
> > @@ -590,6 +595,9 @@ void kunit_cleanup(struct kunit *test)
> >               spin_unlock(&test->lock);
> >               kunit_remove_resource(test, res);
> >       }
> > +#if (IS_ENABLED(CONFIG_KASAN) && IS_BUILTIN(CONFIG_KUNIT))
> > +     current->kunit_test = NULL;
>
> As per patch 1, I'd suggest changing here and elsewhere to
> "IS_ENABLED(CONFIG_KUNIT)".
>
"IS_ENABLED(CONFIG_KUNIT)" does not work because KASAN is built-in so
it can't rely on modules so this patchset relies on KUnit being
built-in.

> > +#endif /* IS_ENABLED(CONFIG_KASAN) && IS_BUILTIN(CONFIG_KUNIT)*/
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
> > +     fail_data.report_expected = true; \
> > +     fail_data.report_found = false; \
> > +     kunit_add_named_resource(test, \
> > +                             NULL, \
> > +                             NULL, \
> > +                             &resource, \
> > +                             "kasan_data", &fail_data); \
> > +} while (0)
> > +
> > +#define KUNIT_DO_EXPECT_KASAN_FAIL(test, condition) do { \
> > +     struct kunit_resource *resource; \
> > +     struct kunit_kasan_expectation *kasan_data; \
> > +     condition; \
> > +     resource = kunit_find_named_resource(test, "kasan_data"); \
> > +     kasan_data = resource->data; \
> > +     KUNIT_EXPECT_EQ(test, \
> > +                     kasan_data->report_expected, \
> > +                     kasan_data->report_found); \
> > +     kunit_put_resource(resource); \
> > +} while (0)
> > +
> > +/**
> > + * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
> > + * not cause a KASAN error.
> > + *
> > + */
> > +#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do { \
> > +     KUNIT_SET_KASAN_DATA(test); \
> > +     KUNIT_DO_EXPECT_KASAN_FAIL(test, condition); \
> > +} while (0)
> > +
> >  /*
> >   * Note: test functions are marked noinline so that their names appear in
> >   * reports.
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 5ef9f24f566b..ef3d0f54097e 100644
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
> >       return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
> >  }
> >
> > +#if IS_BUILTIN(CONFIG_KUNIT)
>
> again we could tweak this to IS_ENABLED(CONFIG_KUNIT); BTW
> the reason we can compile kunit as a module for these tests
> is the KASAN tests are tristate themselves. If they were
> builtin only it wouldn't be possible to build kunit as
> a module.
>
> > +void kasan_update_kunit_status(struct kunit *cur_test)
> > +{
> > +     struct kunit_resource *resource;
> > +     struct kunit_kasan_expectation *kasan_data;
> > +
> > +     if (kunit_find_named_resource(cur_test, "kasan_data")) {
> > +             resource = kunit_find_named_resource(cur_test, "kasan_data");
> > +             kasan_data = resource->data;
> > +             kasan_data->report_found = true;
> > +
> > +             if (!kasan_data->report_expected)
> > +                     kunit_set_failure(current->kunit_test);
> > +             else
> > +                     return;
> > +     } else
> > +             kunit_set_failure(current->kunit_test);
> > +}
> > +#endif /* IS_BUILTIN(CONFIG_KUNIT) */
> > +
> >  void kasan_report_invalid_free(void *object, unsigned long ip)
> >  {
> >       unsigned long flags;
> >       u8 tag = get_tag(object);
> >
> >       object = reset_tag(object);
> > +
> > +#if IS_BUILTIN(CONFIG_KUNIT)
>
> same comment as above.
>
> > +     if (current->kunit_test)
> > +             kasan_update_kunit_status(current->kunit_test);
> > +#endif /* IS_BUILTIN(CONFIG_KUNIT) */
> > +
> >       start_report(&flags);
> >       pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
> >       print_tags(tag, object);
> > @@ -481,6 +509,11 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
> >       if (likely(!report_enabled()))
> >               return;
> >
> > +#if IS_BUILTIN(CONFIG_KUNIT)
>
> here too.
>
> > +     if (current->kunit_test)
> > +             kasan_update_kunit_status(current->kunit_test);
> > +#endif /* IS_BUILTIN(CONFIG_KUNIT) */
> > +
> >       disable_trace_on_warning();
> >
> >       tagged_addr = (void *)addr;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvUKog1m77u%2BJx58OHCXuxNNmw%3DjoDZ-0VZ93FT4H7s0zSQ%40mail.gmail.com.
