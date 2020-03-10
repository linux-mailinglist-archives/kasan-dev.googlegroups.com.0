Return-Path: <kasan-dev+bncBCA2BG6MWAHBBEMSUDZQKGQERQM5PGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 521EE180A9B
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Mar 2020 22:39:30 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id s15sf41936otk.7
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Mar 2020 14:39:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583876369; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yz6Z1/SHsn5dt11haTdZzf5nKiXHGPsbq/Rf13Bc1h/jTqdcyoewCzMN14XlngAPLm
         HSRVcgskJEP7mOStDCEBlz0BoVgqKAmMRvNRJYB8IxzSzQSocHQ6qBCHGCo7dIc9HdfZ
         92qb+AjPw8+FqjCsstWA5dYIiPYxTsX/NfGEdSEWecFyNucfH1yFZxVXaBGdqBtJ4Q5S
         H4naQeYzJ1Qigf8z3rp6DDDI+d5NdcTFsbmIBshg+fgzoZkyXhjWCXYAwYMqLTbNdKeN
         zryhJWcDpCpN/dE7MUFhmLnjbNRMjuUg+BgxJ+vc+E3Hn/CdskrVguSLZ5bfnjaMb7fP
         gNEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nJ6W5hXIWynbyZRj6pt2lDoB60hWB2QRwIs7kwfuwdM=;
        b=tUxc1SsbKEyLVc3AbNQ8op47P5zcd7vv0PlR80VqWn8WmmES9jLxx5MSLN+U7+igNL
         JuRp+gAvQfiK+RTKNJrtRq+6XfIQkiLZBHyoCoDo53ld/L00LrBZuRgFbUtbTI+dskts
         d8NaOYRar/LGmZ8BMN4ebNEH7Ek1wpJzu+jJ1GldUshAaM4rW93/jAOcUYZ986C+bpP5
         z0icOJWJMflN7i78DKsA73xByHVZHhkGw4u7tv66D7AFkPqX4X4RdEJUTYbJgJz4APMk
         oJuaai7vTde9DWv4o9pkqiGSB4jyD3FZCBQ/QrZfc2hqAXV9L+NNtoOl1sk644F/uNfg
         kfXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UlVfj8z2;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nJ6W5hXIWynbyZRj6pt2lDoB60hWB2QRwIs7kwfuwdM=;
        b=Il/JkLf7G0DCXb/TmydejlRKuDUOI5PFdnLWIGe4+4OZGWOZWF2dkA53UI6L1OXavo
         X/H302cbSGsDQFFX43NLlQmjsS+ecy1FVGAzguomslqdDiedlawymmvoyit/TKkgJ/7S
         X+gnAsmCeMtv21R79AIvwPC8CRp8Js7qIa3AEGaDEaupMizCJhPIXDCNGZYaj7WQv1L/
         sVXMOT+KNg4F43atpoPvzdH07CYqpN4rzyjZWt7rszaTdmiDOVGMTBEJNKovanTSJ0Qv
         jxrjFHjhsysZv7AXQOtVFRxJI+0h1TNzpeca26/KoTeMBTXHcDGDUdCy7g2A/5NqJn4R
         isTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nJ6W5hXIWynbyZRj6pt2lDoB60hWB2QRwIs7kwfuwdM=;
        b=pMvRSLaY/h2ZnuKJ2o+yz2JWymDhv53YaCz3eZrRJa3p28+bdOg49o/KDukUnQmPiJ
         7ZZIR1e90BQDE1rBTiiLlJi6KcWV9lNLzPrXgdmz30jKwSTkX8QVQnrTNyf6xGXKklby
         usWhaq4EwOiSztUe1L98UvxwpvhXnPbwP7fuixtdNCakFE5HI8STtUKnOmM1AAz1Belw
         v6VEPZcVha56iPDXEy0YGyXUFT6YeCJhtexRjkZdvFH9ed4Sfrn72HAlmeKSio4XT33O
         pTqXFJCkujLK/PdiR7hUg6w/2LrTnoP1fbQHdQRWNcGNsxbnVvnyqmN4l1ddUez0zPCX
         9T0g==
X-Gm-Message-State: ANhLgQ0lsxdCGTlmKeI/BtLe9j8EfyD9QWI3uIpJ6J0VpJYVaEVpJeOA
	yoMkwwD+CiYypHeT1FptCbc=
X-Google-Smtp-Source: ADFU+vvi0rYK9/7ynsctB8DlsuYV9OR8/CDPk6Qhg0+JHhMgUr+Z+TLbr9mnYhIJPMtkbj1iZOxJBA==
X-Received: by 2002:a9d:404b:: with SMTP id o11mr17677381oti.368.1583876369194;
        Tue, 10 Mar 2020 14:39:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:4a96:: with SMTP id i22ls4843294otf.9.gmail; Tue, 10 Mar
 2020 14:39:28 -0700 (PDT)
X-Received: by 2002:a9d:4810:: with SMTP id c16mr18981889otf.248.1583876368822;
        Tue, 10 Mar 2020 14:39:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583876368; cv=none;
        d=google.com; s=arc-20160816;
        b=JvW/rx/s4Li385JomR3QSD1W6A3LQGTGYoIPeBvlDHRZxRFmT8/v8/cmfmL0LfONGr
         ljC25loUFMlIyJY0NvcGjadJhwZp7SRm4ISCqcnezjNFvAD06CCHQdiLzbUSrfYj3p9g
         8olC/XydHNsJ8WQ3roHC723H6BbIorwT3QephviJ2qoThMyj2GiwublAPZeYkRho6Ftq
         ybRFzg6RDdNJ0Ojl6tQ5AFFMw0v7Eur3GsZtk3xFvm/jTq/RP36d2cLp+x8iwyB5eeay
         dp7DGB7wubqUiaZ7iSZ25nqExzfaokue0jLaVtLs708xmxEnhBNt5y2q6ST4MuxJ623Q
         ooXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=T26zcDKa3B8Ccgr/TpJ2S305/X5TIZGyLp36trF+POo=;
        b=giSi0ceNFcx2jIugjQvfgZdusBn8pB8Lsy9pwohzcWOEVteqVcciNEJpMewRPsW8iU
         UFZkce+QxSVm6aWqFX51KjjcaXGVzKkkbGAMNejTZWol900Y2QzbBZHLsWQ3kvztPcBX
         rvXG+WPUkZgTjlDpKyDA9hrlkc0/71PjkgNo9AZjvuCZ2LLqZrr9rggG9tI/pKBDlUHU
         kKszBGEyyRv+jXLnmOcOH+AtgCQZIbSaxHvcd9ZBK5qXUT/iG8Pqax7Qy/0lCHPc7N+V
         uQS5X825DQZiPcOw7HfQeWaEdzwzmzzxwYEVa/KTzEdjzuwM2wN9sDzDa4Ruvx9UIk/d
         lPKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UlVfj8z2;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id b1si4451ots.2.2020.03.10.14.39.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Mar 2020 14:39:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id w3so52529plz.5
        for <kasan-dev@googlegroups.com>; Tue, 10 Mar 2020 14:39:28 -0700 (PDT)
X-Received: by 2002:a17:90a:a587:: with SMTP id b7mr33452pjq.18.1583876367719;
 Tue, 10 Mar 2020 14:39:27 -0700 (PDT)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com>
 <20200227024301.217042-2-trishalfonso@google.com> <alpine.LRH.2.20.2002271136160.12417@dhcp-10-175-190-15.vpn.oracle.com>
In-Reply-To: <alpine.LRH.2.20.2002271136160.12417@dhcp-10-175-190-15.vpn.oracle.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Mar 2020 14:39:16 -0700
Message-ID: <CAFd5g44gVFyxwo4r=7gpPGdvPQoynfEjHhLfyC3_6uaU2oA0Lg@mail.gmail.com>
Subject: Re: [RFC PATCH 2/2] KUnit: KASAN Integration
To: Alan Maguire <alan.maguire@oracle.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, David Gow <davidgow@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	KUnit Development <kunit-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UlVfj8z2;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Thu, Feb 27, 2020 at 6:04 AM Alan Maguire <alan.maguire@oracle.com> wrote:

Sorry for the delay in reviews. I have been preoccupied by some Google
internal stuff.

> On Wed, 26 Feb 2020, Patricia Alfonso wrote:
>
> > Integrate KASAN into KUnit testing framework.
>
> This is a great idea! Some comments/suggestions below...
>
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
> >        * protect it with some type of lock.
> >        */
> >       struct list_head resources; /* Protected by lock. */
> > +
> > +     bool kasan_report_expected;
> > +     bool kasan_report_found;
> >  };
> >
>
> Is this needed here? You're testing something pretty
> specific so it seems wrong to add to the generic
> kunit resource unless there's a good reason. I see the
> code around setting these values in mm/kasan/report.c,
> but I wonder if we could do something more generic.
>
> How about the concept of a static resource (assuming a
> dynamically allocated one is out because it messes
> with memory allocation tests)? Something like this:
>
> #define kunit_add_static_resource(test, resource_ptr, resource_field)   \
>         do {                                                            \
>                 spin_lock(&test->lock);                                 \
>                 (resource_ptr)->resource_field.init = NULL;             \
>                 (resource_ptr)->resource_field.free = NULL;             \
>                 list_add_tail(&(resource_ptr)->resource_field,          \
>                               &test->resources);                        \
>                 spin_unlock(&test->lock);                               \
>         } while (0)
>
>
> Within your kasan code you could then create a kasan-specific
> structure that embends a kunit_resource, and contains the
> values you need:
>
> struct kasan_report_resource {
>         struct kunit_resource res;
>         bool kasan_report_expected;
>         bool kasan_report_found;
> };
>
> (One thing we'd need to do for such static resources is fix
> kunit_resource_free() to check if there's a free() function,
> and if not assume a static resource)
>
> If you then create an init() function associated with your
> kunit suite (which will be run for every case) it can do this:
>
> int kunit_kasan_test_init(struct kunit *test)
> {
>         kunit_add_static_resource(test, &my_kasan_report_resource, res);
>         ...
> }
>
> The above should also be used to initialize current->kasan_unit_test
> instead of doing that in kunit_try_run_case().  With those
> changes, you don't (I think) need to change anything in core
> kunit (assuming support for static resources).
>
> To retrieve the resource during tests or in kasan context, the
> method seems to be to use kunit_resource_find(). However, that
> requires a match function which seems a bit heavyweight for the
> static case.  We should probably have a default "find by name"
> or similar function here, and add an optional "name" field
> to kunit resources to simplify things.  Anyway here you'd
> use something like:
>
>         kasan_report_resource = kunit_resource_find(test, matchfn,
>                                                     NULL, matchdata);
>
>
> Are there any barriers to taking this sort of approach (apart
> from the support for static resources not being there yet)?

This is a really interesting idea, Alan! I never imagined
kunit_resources being used this way, and I like it. I saw you sent
some patches to implement this stuff, so I will withhold further
comments on that here.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g44gVFyxwo4r%3D7gpPGdvPQoynfEjHhLfyC3_6uaU2oA0Lg%40mail.gmail.com.
