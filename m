Return-Path: <kasan-dev+bncBCMIZB7QWENRBEVL5XZAKGQEFDDJSCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id A0B46174C09
	for <lists+kasan-dev@lfdr.de>; Sun,  1 Mar 2020 07:26:27 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id j15sf6250931qvp.21
        for <lists+kasan-dev@lfdr.de>; Sat, 29 Feb 2020 22:26:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583043986; cv=pass;
        d=google.com; s=arc-20160816;
        b=wx6fl+HlRUssOQHdt0CaOcCHoo0WMh//xRAkMyIhUy1s87o2myqIMVYMCFM40lubXh
         CRA3nPiVb7macnKG9Og4CZ5Xtb9mF79hqRfgsAzEMPBfvZrlRLcxpWft7l1ZC5nyRgLX
         Bk8gTRqX6kanKxEAcm8PRbntI2GMmCTkyTUwlNcIrayP/ox0v/HNoZYhIKjP6l8rvAS7
         BjvO2JpuB/ShmkKFSY3iaZ9uOCsnnxnEVgss0ZkDDZds+g+Nm5mssUZb4V7HndXGXKFl
         BjAPxqEaWriOpfLHun4sUHqhU1SKhJx2KgNhzg7pQjDsYvVFf78zsB5urASRmE2XOrVJ
         1sqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ya59dtWrfG1gh4xhHg3u3ejED79cZxza6Xf1/lVlbI4=;
        b=ip4biV299+A0ynx2QeiX2iOt33ocxJWn1XfSvrF3Oz7A54SIm/FZxi9Gy6x4z38owJ
         Nfd98eJJYDMp2ULwhKwjp5C/JR5xQ2RAhBDrBDzaIgyTa2VySaRFd98YQ/WpiGejxFjx
         BO+iEGYwLRLVDaqRaHzt4sVF4HQtzp/SNzLdJygMf3ZLT0q/Qt7u152PuaFk61zVhKOx
         HxBRMqbEd3zqOHUCW2pkJ5qaZBi6JKCBXh1bzwpLyOHZXl/Y/CTvpPUHRIt5rd6cm//e
         5yFwtBl/6gsF+PZ7di8m+S7j2yqLdy2GWg+pfjTB33db687PsXU/HoN897xpt4fl3wYm
         45mA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="og/ZsUC1";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ya59dtWrfG1gh4xhHg3u3ejED79cZxza6Xf1/lVlbI4=;
        b=jRlNFypAmsocfJBCiTHpDC9WI8Otb3/scBfmrh+a6RIxBECRjw9qlTyMwa3/Gz67tV
         7kMab7WEbo0/hwxN6rFbjBLk8+vJPF9NNGRcJEWaRT+syrOPyZlZNI4UcypOUXhNlcUV
         YzBHubSdtIT/HU9lGO5mvpiYBnLxsZN2s8YN7bm90ImGuEz0TiCPi5ANFd7ZMsaYqTzj
         AG+OoMxsHWQdRpT6NPRL4uw/8gekefdhkVwLyVfo0zIBfywHVrj4re6jy+PXhFBZGVtE
         bfITygUDbXEoNVpBHH5B6roerNSk6lwvYR2UE52mzXyG/oQ9ItBk0pvNhX8qUOyZCqy3
         cQkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ya59dtWrfG1gh4xhHg3u3ejED79cZxza6Xf1/lVlbI4=;
        b=p6PwNY2U18Ib9BnFeEcMvbhIsyVjv1lCq1olau2oOmmqYP2gkcgg16EOGcZr0izjIB
         mSIP6Z4UCdb785jiN62lRycaMDWNbRDgif1DkJj4ByeLyVswnwcbaLj9MGUTmWMnfEwg
         DV4WkI5nV4c738gZg9rRtaGiLx5JCVE1t6QUqzItAGKa44SJ3viGe8DkXcwJuLLZup+y
         BDV1Yv6KrVn8TFCdLDiYjkKZ3YBtJxQYK7bEUbvApDwPhh4ZYFSvXZ7BiA0VNLItE3FK
         1PwW5qOaJkrJvodl8Xe3/uiy807XNMwAmxZ2/x/+0QNWG9gzQz2uBxXf993JHeclVCVV
         S3JA==
X-Gm-Message-State: APjAAAX5yKqByD79OpjuU2p0BFtn/Acsiyw0jVOQ2peIQkvxJgP5Tvn6
	OAazQx2q/FT/SM5Rfa4eiZw=
X-Google-Smtp-Source: APXvYqy+YIJerOWvoHGd0oBgNZ3CWvll6qjUumj4CDlHQ2DgN8/5RiPQqDuSbSL03TGg9R9u0/fuPQ==
X-Received: by 2002:a0c:b38a:: with SMTP id t10mr10230756qve.198.1583043986224;
        Sat, 29 Feb 2020 22:26:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:514c:: with SMTP id g12ls119535qvq.7.gmail; Sat, 29 Feb
 2020 22:26:25 -0800 (PST)
X-Received: by 2002:ad4:5a48:: with SMTP id ej8mr10326380qvb.187.1583043985863;
        Sat, 29 Feb 2020 22:26:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583043985; cv=none;
        d=google.com; s=arc-20160816;
        b=YQj/h/rJIzmasC7XDDPRBGjyScHrm4XpP7LVdYuDrmNm1huFOiI107f24EN4PmSrLu
         VrrYmUP7mtTOWQHFvknOlotOdBvwjakpGN5TJW3oERJb1qwzUcnmuX2mItipQFzmz7xE
         5orrx8WRcRwDBXJoCXOV8WXC+y6tQTmoDcYElwo0AjfRKi4L/J9W8FMuNvBkrKJ/JGZB
         LhibFDy1vfIryd7h36Fpxsc/jOd7jxMivgLIxhqgWxbApwE57bFiDha+tlo73uhbiA7S
         UD56phN0eKHC1CUZE4DmIkpDG+/JOCrrxKH20B4fGZAnLC8IGc4VpiLGiJL3EZZZ3H7Y
         QcEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BRep1qguHHkmLxwYD+6cFGCRXS41eBwvWn4zagrZWyo=;
        b=a0R5VIRROa3DoBmvI8hL+5u5oD4gwf/R3QdImZgc9pb6md6ERuUjS282fZWPOb/Qam
         c/4YKsgGDqKHbcbChJlOtPc2wEJt5F8uvhM6DIfxy3od4nPPJZ39sTgbv6FqXAfTmJI6
         Gby9afdMe/hJmb2sSCPzg/skSEa0sy4vg7n88d485tZfLpc3mPjlcTSS/5kGgBiJvqi6
         wKYNApo8qDU84SLksY6J5Jj5JkaMRIvK1mVYyT8hGPsA6YjbRoBTPdkQCTx5FXkW86Og
         OtCpDCluKgCMly9Rf/9Gnvcf/eK27VNgTWkk3FlbGlRgXPN651VU4ZzjfMAlG4bJDmZ6
         sbtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="og/ZsUC1";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id i26si478026qki.1.2020.02.29.22.26.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 29 Feb 2020 22:26:25 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id q18so7094071qki.10
        for <kasan-dev@googlegroups.com>; Sat, 29 Feb 2020 22:26:25 -0800 (PST)
X-Received: by 2002:a37:4755:: with SMTP id u82mr10933256qka.43.1583043985190;
 Sat, 29 Feb 2020 22:26:25 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com>
 <20200227024301.217042-2-trishalfonso@google.com> <CACT4Y+bO7N_80N7NkjOstp=dxGnV1GZUoH3sh6XU90ro0_7M0A@mail.gmail.com>
 <CAKFsvUKB=S9p6JjRHg=h9d2MM_kb+BoRYO8-wkWPEQex2W1vZA@mail.gmail.com>
In-Reply-To: <CAKFsvUKB=S9p6JjRHg=h9d2MM_kb+BoRYO8-wkWPEQex2W1vZA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 1 Mar 2020 07:26:14 +0100
Message-ID: <CACT4Y+aNfb8sOtD9nOAYU0fML6hxgcbF7=0xDPHbiMqWyOTZjg@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b="og/ZsUC1";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
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

On Sat, Feb 29, 2020 at 2:09 AM Patricia Alfonso
<trishalfonso@google.com> wrote:
> > <kasan-dev@googlegroups.com> wrote:
> > >
> > > Integrate KASAN into KUnit testing framework.
> > >  - Fail tests when KASAN reports an error that is not expected
> > >  - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN tests
> > >  - KUnit struct added to current task to keep track of the current test
> > > from KASAN code
> > >  - Booleans representing if a KASAN report is expected and if a KASAN
> > >  report is found added to kunit struct
> > >  - This prints "line# has passed" or "line# has failed"
> > >
> > > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > > ---
> > > If anyone has any suggestions on how best to print the failure
> > > messages, please share!
> > >
> > > One issue I have found while testing this is the allocation fails in
> > > kmalloc_pagealloc_oob_right() sometimes, but not consistently. This
> > > does cause the test to fail on the KUnit side, as expected, but it
> > > seems to skip all the tests before this one because the output starts
> > > with this failure instead of with the first test, kmalloc_oob_right().
> > >
> > >  include/kunit/test.h                | 24 ++++++++++++++++++++++++
> > >  include/linux/sched.h               |  7 ++++++-
> > >  lib/kunit/test.c                    |  7 ++++++-
> > >  mm/kasan/report.c                   | 19 +++++++++++++++++++
> > >  tools/testing/kunit/kunit_kernel.py |  2 +-
> > >  5 files changed, 56 insertions(+), 3 deletions(-)
> > >
> > > diff --git a/include/kunit/test.h b/include/kunit/test.h
> > > index 2dfb550c6723..2e388f8937f3 100644
> > > --- a/include/kunit/test.h
> > > +++ b/include/kunit/test.h
> > > @@ -21,6 +21,8 @@ struct kunit_resource;
> > >  typedef int (*kunit_resource_init_t)(struct kunit_resource *, void *);
> > >  typedef void (*kunit_resource_free_t)(struct kunit_resource *);
> > >
> > > +void kunit_set_failure(struct kunit *test);
> > > +
> > >  /**
> > >   * struct kunit_resource - represents a *test managed resource*
> > >   * @allocation: for the user to store arbitrary data.
> > > @@ -191,6 +193,9 @@ struct kunit {
> > >          * protect it with some type of lock.
> > >          */
> > >         struct list_head resources; /* Protected by lock. */
> > > +
> > > +       bool kasan_report_expected;
> > > +       bool kasan_report_found;
> > >  };
> > >
> > >  void kunit_init_test(struct kunit *test, const char *name);
> > > @@ -941,6 +946,25 @@ do {                                                                              \
> > >                                                 ptr,                           \
> > >                                                 NULL)
> > >
> > > +/**
> > > + * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
> > > + * not cause a KASAN error.
> >
> > Oh, I see, this is not a test, but rather an ASSERT-like macro.
> > Then maybe we should use it for actual expressions that are supposed
> > to trigger KASAN errors?
> >
> > E.g. KUNIT_EXPECT_KASAN_FAIL(test, *(volatile int*)p);
> >
>
> This is one possible approach. I wasn't sure what would be the most
> useful. Would it be most useful to assert an error is reported on a
> function or assert an error is reported at a specific address?

I would say assert on a specific line of code/expression for locality reasons.
This will also solve the problem for tests that trigger several
reports, this way we can check that we get N reports.


> > > + *
> > > + */
> > > +#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do {  \
> >
> > s/condition/expression/
> >
> > > +       test->kasan_report_expected = true;     \
> >
> > Check that kasan_report_expected is unset. If these are nested things
> > will break in confusing ways.
> > Or otherwise we need to restore the previous value at the end.
> >
> Good point! I think I was just unsure of where I should set this value
> and what the default should be.
>
> > > +       test->kasan_report_found = false; \
> > > +       condition; \
> > > +       if (test->kasan_report_found == test->kasan_report_expected) { \
> >
> > We know that kasan_report_expected is true here, so we could just said:
> >
> > if (!test->kasan_report_found)
> >
> Good point! This is much more readable
>
> > > +               pr_info("%d has passed", __LINE__); \
> > > +       } else { \
> > > +               kunit_set_failure(test); \
> > > +               pr_info("%d has failed", __LINE__); \
> >
> > This needs a more readable error.
> >
> Yes, this was just a stand-in. I was wondering if you might have a
> suggestion for the best way to print this failure message? Alan
> suggested reusing the KUNIT_EXPECT_EQ() macro so the error message
> would look something like:
> "Expected kasan_report_expected == kasan_report_found, but
> kasan_report_expected == true
> kasan_report_found == false"
>
> What do you think of this?

I will be able to understand why the test has failed reading this error message.
A more human-friendly message may be better, but if this makes for
better consistency I am fine with this.

> > > +       } \
> > > +       test->kasan_report_expected = false;    \
> > > +       test->kasan_report_found = false;       \
> > > +} while (0)
> > > +
> > >  /**
> > >   * KUNIT_EXPECT_TRUE() - Causes a test failure when the expression is not true.
> > >   * @test: The test context object.
> > > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > > index 04278493bf15..db23d56061e7 100644
> > > --- a/include/linux/sched.h
> > > +++ b/include/linux/sched.h
> > > @@ -32,6 +32,8 @@
> > >  #include <linux/posix-timers.h>
> > >  #include <linux/rseq.h>
> > >
> > > +#include <kunit/test.h>
> > > +
> > >  /* task_struct member predeclarations (sorted alphabetically): */
> > >  struct audit_context;
> > >  struct backing_dev_info;
> > > @@ -1178,7 +1180,10 @@ struct task_struct {
> > >
> > >  #ifdef CONFIG_KASAN
> > >         unsigned int                    kasan_depth;
> > > -#endif
> > > +#ifdef CONFIG_KUNIT
> > > +       struct kunit *kasan_kunit_test;
> >
> > I would assume we will use this for other things as well (failing
> > tests on LOCKDEP errors, WARNINGs, etc).
> > So I would call this just kunit_test and make non-dependent on KASAN right away.
> >
> Yeah, I think I just wanted to make it clear that this is only used
> for KASAN, but I believe that was before we talked about extending
> this.
>
> > > +       if (current->kasan_kunit_test) {
> >
> > Strictly saying, this also needs to check in_task().
> >
>
> I was not aware of in_task()... can you explain its importance to me?
>
> > > +               if (current->kasan_kunit_test->kasan_report_expected) {
> > > +                       current->kasan_kunit_test->kasan_report_found = true;
> > > +                       return;
> > > +               }
> > > +               kunit_set_failure(current->kasan_kunit_test);
> > > +       }
> >
> > This chunk is duplicated 2 times. I think it will be more reasonable
> > for KASAN code to just notify KUNIT that the error has happened, and
> > then KUNIT will figure out what it means and what to do.
> >
> >
> Yeah, I think moving this to the KUnit files is best too. I would like
> to keep kunit_set_failure a static function as well.
>
>
> --
> Thank you for the comments!
>
> Patricia Alfonso

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaNfb8sOtD9nOAYU0fML6hxgcbF7%3D0xDPHbiMqWyOTZjg%40mail.gmail.com.
