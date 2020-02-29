Return-Path: <kasan-dev+bncBDK3TPOVRULBBW7T43ZAKGQEU5SUKGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 85453174411
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Feb 2020 02:09:47 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id r1sf2109971wrc.15
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 17:09:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582938587; cv=pass;
        d=google.com; s=arc-20160816;
        b=y3dpWkzhmHYNHeD5x3l+sAkUXYOAYFwjwX0yqJXMZxI+dvKEywDuADECHeUw8qi4a7
         jxXDufnz9lJH6rhYLXJSS8h+oiKQGDdgsOz8umL3n1L1qqB+lIfDAR4gLU/ua3ez0P8n
         D2hecswLwiIEO3+HB73O/UKqLXC5l1zZ8r96inJyjpCEcPIDd0F+QYSnf1WsYNtsNYOd
         SyPl8SNQjnwWGToiO+BDT0Dy/BRcys6QYIzsglHKT3VoluKytnBhVnv6VAXtxaL2QNf2
         33RAVN4xoxzqzxS212oAP6uCiwxoRj+8A9y7bGKNgFwIVsuURHUPT3JHtpUoLcVnUV0d
         uckg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xzwhGKws036MypBN7uggD8H6UCJQv51e8h0SekHsVuw=;
        b=Qv0gLT0nCyt7B/6yL+E/jCCjx5/siefaKMUPanlbPj3J0KnSCK8PrsY4/wtygshE9v
         6yoekElXrXMUfZsuBeEsRxP9p2QHMhj+RzSgVq61QtsASRJkQ1yeMXZC3sfrHM/m03ia
         sWOPYoQronB7XVVtwptaBuJht3drtscKiMiFIZiNZDz0CsljVT2cKTD1Y3f1almip/qr
         PZ5AxeIc/rkI+yhxAxhDpfMEtMP9i3dGzxDweMk652qe9+I+TzidfjffLeyWOf++TKxw
         llbjLYhbXw3nvZcj9O+oHrteK/RQXd/SlAIQjPn4bimmIeGtuixpCjWKODY3eBODU9Oc
         UEgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WKqJxdxa;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xzwhGKws036MypBN7uggD8H6UCJQv51e8h0SekHsVuw=;
        b=XSoU3xFET6RRCjRFlSHTAKZQG9UDJX7ga/gUj8hM6s5kQQrtEhqCuA+6BR7XvwROw5
         Ea1lNWgE/wWmvAqXhw0FHpa5OhzcZ1rheTlJbuihNLPoAHoey2hijEQeN8M3SAa6uCzz
         nqKZcFscM0V/iMrvmDwkPsCdfKnDtvD69DDnS03VRbpM22JcoAFLwjF71yPePWKgzOBk
         M/JsmWNKAWqvUvqNRYVL1NauSuZRU/Qi11Vf1fSNlYC2Sfruawr9wRT1uvN0/IKQoQ/x
         Y8OzSt5v2nQ4Djiorbbv1MTDhe66dgZjFMYd39PzO22l0r4jYSYDfGCbpXoDb/3mPfrf
         fvhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xzwhGKws036MypBN7uggD8H6UCJQv51e8h0SekHsVuw=;
        b=LsQHSJunGaJpGaQkg3oLwIFrXV+uGu+pCBI+agKTp7mQT02MCUh93443aHCwlGS42B
         tLiqJ07cMYWhNgEgBDr+ZlFfweI1x+pzaau36vqsS1r88xGT2a/mRgRg8cDUvEQ8qi2/
         6e8JCPmGk7MtvSiCjfn9eqJeWaWMMbrD7wyw2Ard/kN1UwIuliSCte5OiRPNf+bKO4U7
         ADdVPRg6BAFF1HOySbUBljWR1O8t6hzJNOwQRrqUc/y11PfFYt5qZzwrk1S8mV1/y1kc
         uLp0+QKVGnXCB+8C3LJpVXewUhR5+zlEXRvRBmGlYepO+ZAf3cTkkE92JPfFI4ChjGNF
         jpaQ==
X-Gm-Message-State: APjAAAWAAhACwFBk7DzFy87ypEsiPT6A7qCDuZAcn6gz8AT+xZydYTKs
	0E/lzjh5YXjWJ+WvGFc3s68=
X-Google-Smtp-Source: APXvYqyr/AGh8PvYKd+tlItxGUeDx9iLCXVo8otwmHiEtWIKHl2hskvUUEsGAJ7BwzyHjUqt2MuulQ==
X-Received: by 2002:adf:e542:: with SMTP id z2mr7722319wrm.150.1582938587186;
        Fri, 28 Feb 2020 17:09:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7e50:: with SMTP id z77ls2631920wmc.2.canary-gmail; Fri,
 28 Feb 2020 17:09:46 -0800 (PST)
X-Received: by 2002:a1c:6085:: with SMTP id u127mr7626255wmb.144.1582938586548;
        Fri, 28 Feb 2020 17:09:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582938586; cv=none;
        d=google.com; s=arc-20160816;
        b=TZFwFRuPZX7WAV+GNRRF4zoUR0ndmjh06kZW+t+yoyHTqtSwyrouD61dZdpyoh0dpy
         8fbfp7xJOUBgtTEnTanYpvAqcQ9UrsAWiLP924yvG0X7eImPTVsufJRXY7ReFEst7fhF
         TnUrFbYUSM/e/j4UhEkxhpArRPehRtKfP33G96+z3vVDvfE0MhIFlgG+z5qnYGaV0qal
         +2lKPewWprsIcmcCpRSu71Bd5ptKzjsqtfsvA0teabuHcUZX/r6DuBUqWAUwtY2dKr7j
         hQdUwKfPUT3nAix6zqeJ+R3qM4RIlUVDFtOB3fDlHdKtDaGO2G2p4a7f7GgObYag1Gte
         oVlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SN7G4tCYEshnaGRAM2db2SQakrRhJKUvOkKXHESfWSo=;
        b=auwyZkG+BOY5Bhapn0vlsXazdoDRN2w8GlVNQubvtyKhwBA1xus8qWP/WpiZ22XbNF
         T7DSMJuQR7Np0T0O1gSVYz2citvEcnUnVjiTRrl2AyeOUo8Cvo/m4XUm5MfifWg9dD2h
         oRz+WCFXNJ19tZllduzmGUb8HeUvNOnCfPkH2yhBpp5YH2Jyofxx4f2D4F+A0sC9jL6X
         2r4TXXy8xj1gk8HpjXD7rwJB8NbL/Z0wckHBjBNC2t7AOdcHaf7M26cK9eayKQI2CcNg
         6F+Ot+Ai8OENtyGVvOC5clym+y6NCi6oBTaRCpZtV6t//MRC73i4BJz2u2D7+/752JEk
         gXWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WKqJxdxa;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id f1si6007wme.1.2020.02.28.17.09.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Feb 2020 17:09:46 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id y17so5308079wrn.6
        for <kasan-dev@googlegroups.com>; Fri, 28 Feb 2020 17:09:46 -0800 (PST)
X-Received: by 2002:adf:82ef:: with SMTP id 102mr6964889wrc.23.1582938585758;
 Fri, 28 Feb 2020 17:09:45 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com>
 <20200227024301.217042-2-trishalfonso@google.com> <CACT4Y+bO7N_80N7NkjOstp=dxGnV1GZUoH3sh6XU90ro0_7M0A@mail.gmail.com>
In-Reply-To: <CACT4Y+bO7N_80N7NkjOstp=dxGnV1GZUoH3sh6XU90ro0_7M0A@mail.gmail.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Feb 2020 17:09:34 -0800
Message-ID: <CAKFsvUKB=S9p6JjRHg=h9d2MM_kb+BoRYO8-wkWPEQex2W1vZA@mail.gmail.com>
Subject: Re: [RFC PATCH 2/2] KUnit: KASAN Integration
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, vincent.guittot@linaro.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WKqJxdxa;       spf=pass
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

On Thu, Feb 27, 2020 at 6:39 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Feb 27, 2020 at 3:44 AM 'Patricia Alfonso' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > Integrate KASAN into KUnit testing framework.
> >  - Fail tests when KASAN reports an error that is not expected
> >  - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN tests
> >  - KUnit struct added to current task to keep track of the current test
> > from KASAN code
> >  - Booleans representing if a KASAN report is expected and if a KASAN
> >  report is found added to kunit struct
> >  - This prints "line# has passed" or "line# has failed"
> >
> > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > ---
> > If anyone has any suggestions on how best to print the failure
> > messages, please share!
> >
> > One issue I have found while testing this is the allocation fails in
> > kmalloc_pagealloc_oob_right() sometimes, but not consistently. This
> > does cause the test to fail on the KUnit side, as expected, but it
> > seems to skip all the tests before this one because the output starts
> > with this failure instead of with the first test, kmalloc_oob_right().
> >
> >  include/kunit/test.h                | 24 ++++++++++++++++++++++++
> >  include/linux/sched.h               |  7 ++++++-
> >  lib/kunit/test.c                    |  7 ++++++-
> >  mm/kasan/report.c                   | 19 +++++++++++++++++++
> >  tools/testing/kunit/kunit_kernel.py |  2 +-
> >  5 files changed, 56 insertions(+), 3 deletions(-)
> >
> > diff --git a/include/kunit/test.h b/include/kunit/test.h
> > index 2dfb550c6723..2e388f8937f3 100644
> > --- a/include/kunit/test.h
> > +++ b/include/kunit/test.h
> > @@ -21,6 +21,8 @@ struct kunit_resource;
> >  typedef int (*kunit_resource_init_t)(struct kunit_resource *, void *);
> >  typedef void (*kunit_resource_free_t)(struct kunit_resource *);
> >
> > +void kunit_set_failure(struct kunit *test);
> > +
> >  /**
> >   * struct kunit_resource - represents a *test managed resource*
> >   * @allocation: for the user to store arbitrary data.
> > @@ -191,6 +193,9 @@ struct kunit {
> >          * protect it with some type of lock.
> >          */
> >         struct list_head resources; /* Protected by lock. */
> > +
> > +       bool kasan_report_expected;
> > +       bool kasan_report_found;
> >  };
> >
> >  void kunit_init_test(struct kunit *test, const char *name);
> > @@ -941,6 +946,25 @@ do {                                                                              \
> >                                                 ptr,                           \
> >                                                 NULL)
> >
> > +/**
> > + * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
> > + * not cause a KASAN error.
>
> Oh, I see, this is not a test, but rather an ASSERT-like macro.
> Then maybe we should use it for actual expressions that are supposed
> to trigger KASAN errors?
>
> E.g. KUNIT_EXPECT_KASAN_FAIL(test, *(volatile int*)p);
>

This is one possible approach. I wasn't sure what would be the most
useful. Would it be most useful to assert an error is reported on a
function or assert an error is reported at a specific address?

>
> > + *
> > + */
> > +#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do {  \
>
> s/condition/expression/
>
> > +       test->kasan_report_expected = true;     \
>
> Check that kasan_report_expected is unset. If these are nested things
> will break in confusing ways.
> Or otherwise we need to restore the previous value at the end.
>
Good point! I think I was just unsure of where I should set this value
and what the default should be.

> > +       test->kasan_report_found = false; \
> > +       condition; \
> > +       if (test->kasan_report_found == test->kasan_report_expected) { \
>
> We know that kasan_report_expected is true here, so we could just said:
>
> if (!test->kasan_report_found)
>
Good point! This is much more readable

> > +               pr_info("%d has passed", __LINE__); \
> > +       } else { \
> > +               kunit_set_failure(test); \
> > +               pr_info("%d has failed", __LINE__); \
>
> This needs a more readable error.
>
Yes, this was just a stand-in. I was wondering if you might have a
suggestion for the best way to print this failure message? Alan
suggested reusing the KUNIT_EXPECT_EQ() macro so the error message
would look something like:
"Expected kasan_report_expected == kasan_report_found, but
kasan_report_expected == true
kasan_report_found == false"

What do you think of this?

> > +       } \
> > +       test->kasan_report_expected = false;    \
> > +       test->kasan_report_found = false;       \
> > +} while (0)
> > +
> >  /**
> >   * KUNIT_EXPECT_TRUE() - Causes a test failure when the expression is not true.
> >   * @test: The test context object.
> > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > index 04278493bf15..db23d56061e7 100644
> > --- a/include/linux/sched.h
> > +++ b/include/linux/sched.h
> > @@ -32,6 +32,8 @@
> >  #include <linux/posix-timers.h>
> >  #include <linux/rseq.h>
> >
> > +#include <kunit/test.h>
> > +
> >  /* task_struct member predeclarations (sorted alphabetically): */
> >  struct audit_context;
> >  struct backing_dev_info;
> > @@ -1178,7 +1180,10 @@ struct task_struct {
> >
> >  #ifdef CONFIG_KASAN
> >         unsigned int                    kasan_depth;
> > -#endif
> > +#ifdef CONFIG_KUNIT
> > +       struct kunit *kasan_kunit_test;
>
> I would assume we will use this for other things as well (failing
> tests on LOCKDEP errors, WARNINGs, etc).
> So I would call this just kunit_test and make non-dependent on KASAN right away.
>
Yeah, I think I just wanted to make it clear that this is only used
for KASAN, but I believe that was before we talked about extending
this.

> > +       if (current->kasan_kunit_test) {
>
> Strictly saying, this also needs to check in_task().
>

I was not aware of in_task()... can you explain its importance to me?

> > +               if (current->kasan_kunit_test->kasan_report_expected) {
> > +                       current->kasan_kunit_test->kasan_report_found = true;
> > +                       return;
> > +               }
> > +               kunit_set_failure(current->kasan_kunit_test);
> > +       }
>
> This chunk is duplicated 2 times. I think it will be more reasonable
> for KASAN code to just notify KUNIT that the error has happened, and
> then KUNIT will figure out what it means and what to do.
>
>
Yeah, I think moving this to the KUnit files is best too. I would like
to keep kunit_set_failure a static function as well.


-- 
Thank you for the comments!

Patricia Alfonso

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvUKB%3DS9p6JjRHg%3Dh9d2MM_kb%2BBoRYO8-wkWPEQex2W1vZA%40mail.gmail.com.
