Return-Path: <kasan-dev+bncBDK3TPOVRULBB4PI43ZAKGQE3IHTGFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 025831743E5
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Feb 2020 01:46:42 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id y28sf2076402wrd.23
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 16:46:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582937201; cv=pass;
        d=google.com; s=arc-20160816;
        b=F3G+dU41fZg1AHyWPcmUcD+YAi7NRUdpXh3DBWqVHPXw/6Uc+OeRLIwcbWmSoMAjvb
         3XMpkHYoOOOD8dnFDDHTVBj+pj0SBndTO8ztoHq7XCEHUP6bTmcG8O1ooDOI09Tjvb2l
         ySm4j/XQe0RxzbmdZEpThtBop9UY/AaxMWbePbUTs3lsqeEtX4JqL3m0OvXBUwk6mvyE
         M/PWbcdAoRuOAqAGWt/nQblUncENn8JmS8ZOcI/9avSSoRUfpt/7oAPI/JlrVmDOw9ms
         z1iS9vLuJ0HMZE9z+l7PrbDmMBvPfeCqbY6KwFFGwLZOs/qjoM9asDF6KGwURJRwtk8p
         aIFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/zVDEr8Ba9vYrLjryf/KGoowMZeZQEti/epx2BnDGT0=;
        b=eURTHCIuHZ1YM2kNbxQ3JshbERtqlVmkiTtmcXsphB5NT/nxBKFP4T3/kfCEohMIPe
         vDYVKMFIDZdjlPV2EHZQr/HyXGyVz5g2RozKwpQkuFP6iraQsF4DZ8QXnrX9o1SRqvZS
         cniLjuc/VIXJ2gA8XfZcHbya9NhaaBuhYeSnbyYx+8TRSOTk/sSph3qImwo4HiidCL5Z
         +UTczojNPfqex5VXtUut23D9MuyyMYD5LWVLyJGVHzG/XtcxK/24qudVGdg/G2FOm/bh
         C4l98sVkQNq2T6OirYoMPXrc2cJ+eplZuDUs+GgUiz5AdB4wK9lvzlgiXV32wfDObZM7
         cOEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YXZEgik5;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/zVDEr8Ba9vYrLjryf/KGoowMZeZQEti/epx2BnDGT0=;
        b=E+jVxYZctgZIFm/XJwUOWrrXHrRegQedgm5d4DjbViKWczRaoCEdKLqrX7//AhLNdJ
         aAc7UVIgPm8eap9d9Kw8NnDDvo+dwmwvya0Ilhk9Bcng6jDiP8uw2qB7mFJ19QDbHMtS
         RTdmGAykN5VKBdVrx1TWHpb3xxKcVJGl9RaqT8YJ2+Z2lnI/3P2rwX9aU3W3EPB1c/3f
         r+1W/unBioUicd8dcmSglhtp0sitqg232NNcDAB1KsbUGRaiSWIu1OIfeVP3hxZrBlmv
         CYgvxE+n3L5DtGyQk6Nb93pwTfVEhihOxiDH5YDh6nFaWjOixXjWB4Xl+6xlnjft9mH9
         zsug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/zVDEr8Ba9vYrLjryf/KGoowMZeZQEti/epx2BnDGT0=;
        b=Lo65qW5mWQR+g2S9QaAyPgm8VATB3s6Z1Kbr+irFvT2OyIJxiao76qeoRhRAlUBDnz
         /gsV2qxsh3z6VvLifUDYPaL2KtgjgZp3BJKpgoZglzqXuGj0UcV51DvXQJCDoUWs3pXX
         2oaFYHT/sjGwAzMmPceJqCrJYpbASH+evJQS+yZYU4KVOTDXjCtBzudhXCSlbIWxqkfz
         7vza6nmj6AQ+3eDxgWMNhZj1G7WM+Mbx7LUqXBU0XDmW1MWbpIIGEAVWNRAdEyr9XDo+
         Bng4Jiq0Fn9DsUbk8Aad2rd9Mt9BJX+1t9VqehXopFrbcu3SKiYelg24GfqvLNeuT7zy
         UcmA==
X-Gm-Message-State: APjAAAWx7YXonCTZG5pN0sqwGRcZAMIyV0sq8CcT0CPKOnVUmwfxoGJR
	AgAshIyfbiIPf6iKkrt+Btg=
X-Google-Smtp-Source: APXvYqxyAWNgYpgrSUBw3bEa4JUevQJM/fOHrKucUKHIPtIcEHv727PmQJ9Wra9C9UWNUCFZ7AKAqQ==
X-Received: by 2002:adf:ec50:: with SMTP id w16mr7426594wrn.9.1582937201713;
        Fri, 28 Feb 2020 16:46:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:670d:: with SMTP id o13ls2045222wru.3.gmail; Fri, 28 Feb
 2020 16:46:41 -0800 (PST)
X-Received: by 2002:adf:b60f:: with SMTP id f15mr7588078wre.372.1582937201110;
        Fri, 28 Feb 2020 16:46:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582937201; cv=none;
        d=google.com; s=arc-20160816;
        b=JdR6a00lmLjDw5IvOGnXeQNBcolpEaSSPZ0qIuFXDkKAE6/w1OCXb5BYf34Dcbx+h1
         eOLv+0oFMNStlWhV7Dd9zOcdDz1k+13okjpa0/jq9Xf0VK06PxwhmGOHIp9Rn1XvjTkV
         pR7acroTDVu/bg1qTTxig53vF4pAXbhweC7vKp3eylWM0Aw2zRaz6tD4uDUBagyVFq0Q
         S0QuOo2mJIW2IZ7pxPa2AyyXbUR2+cc2n2bpMQB/o09HhBWMoF61Au2aZ3BCwU8w07bN
         leyWP+GzqvxOYHlEbGk5fUotYUQuPc4Z/X4LHP+EOdL+NfvU8holPos8v+I3qyzbnI2w
         QiZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/gye8NnXX01dBefa/oC7avRZ2adDaseOwvTMjQU5Cy0=;
        b=p37q+x5O9mH0snzQiGnjL1SLJNpd5Slcn9tIBFXtvJMVbdknMqlFPN20WS96ibKlCB
         FJVKmgHotkfod7QKUnohKd2cQ/QwfFdHVDnhgCz4eIyoHLb+7NVe1cs49sP6oKfXIgHc
         vk6ycaSCyujalW5HfpVYg0JyVzRQPocX1wrAa2LiieozI2Wtx1ZrYwr8+CkM6lqRra/7
         T26eWdz7lFXGTaqQqCjK8IdQSFqQQd/KsdBjUczKUT8SNeccT8R4pDWERpnRvsX9eNZM
         woIKq1VUeVZ9/Oa9El8N0WyVO62HZZJu/laQdWXRZooZ1XfNthIPAwnHFd+Wt7g8REwF
         3H2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YXZEgik5;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id y185si135307wmd.2.2020.02.28.16.46.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Feb 2020 16:46:41 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id m16so5189867wrx.11
        for <kasan-dev@googlegroups.com>; Fri, 28 Feb 2020 16:46:41 -0800 (PST)
X-Received: by 2002:a5d:638b:: with SMTP id p11mr7372612wru.338.1582937200260;
 Fri, 28 Feb 2020 16:46:40 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com>
 <20200227024301.217042-2-trishalfonso@google.com> <alpine.LRH.2.20.2002271136160.12417@dhcp-10-175-190-15.vpn.oracle.com>
In-Reply-To: <alpine.LRH.2.20.2002271136160.12417@dhcp-10-175-190-15.vpn.oracle.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Feb 2020 16:46:28 -0800
Message-ID: <CAKFsvUK2hFV3LePxwBXO_ubrgYoOk7fuKMOy+vSAH5Tf3SrMOA@mail.gmail.com>
Subject: Re: [RFC PATCH 2/2] KUnit: KASAN Integration
To: Alan Maguire <alan.maguire@oracle.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, David Gow <davidgow@google.com>, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YXZEgik5;       spf=pass
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

On Thu, Feb 27, 2020 at 6:04 AM Alan Maguire <alan.maguire@oracle.com> wrote:
>
> On Wed, 26 Feb 2020, Patricia Alfonso wrote:
>
> > Integrate KASAN into KUnit testing framework.
>
> This is a great idea! Some comments/suggestions below...
>

Thank you so much for your suggestions!

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
>

I'm not sure. I don't have any experience with kunit resources so I
would have to put some more effort into understanding how this would
work for myself. I wonder if this might be a bit of an over
complicated way of eliminating an extraneous boolean... maybe we can
find a simpler solution for the first version of this patch and add
the notion of a static resource for generic use later.

> >  void kunit_init_test(struct kunit *test, const char *name);
> > @@ -941,6 +946,25 @@ do {                                                                            \
> >                                               ptr,                           \
> >                                               NULL)
> >
> > +/**
> > + * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
> > + * not cause a KASAN error.
> > + *
> > + */
> > +#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do {        \
> > +     test->kasan_report_expected = true;     \
> > +     test->kasan_report_found = false; \
> > +     condition; \
> > +     if (test->kasan_report_found == test->kasan_report_expected) { \
> > +             pr_info("%d has passed", __LINE__); \
> > +     } else { \
> > +             kunit_set_failure(test); \
> > +             pr_info("%d has failed", __LINE__); \
> > +     } \
> > +     test->kasan_report_expected = false;    \
> > +     test->kasan_report_found = false;       \
> > +} while (0)
> > +
>
> Feels like this belongs in test_kasan.c, and could be reworked
> to avoid adding test->kasan_report_[expected|found] as described
> above.

You're right. Since I don't see any reason why any other tests should
want to expect a KASAN error, it does make sense to move this logic
inside test_kasan.c. If, in the future, there is a need for this
elsewhere, we can always move it back then.

>  Instead of having your own pass/fail logic couldn't you
> do this:
>
>         KUNIT_EXPECT_EQ(test, expected, found);
>
> ? That will set the failure state too so no need to export
> a separate function for that, and no need to log anything
> as KUNIT_EXPECT_EQ() should do that for you.
>

This is a great idea - I feel a little silly that I didn't think of
that myself! Do we think the failure message for the KUNIT_EXPECT_EQ()
would be sufficient for KASAN developers?
i.e. "Expected kasan_report_expected == kasan_report_found, but
kasan_report_expected == true
kasan_report_found == false"

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
>
> This feels like the wrong place to add this #include, and
> when I attempted to build to test I ran into a bunch of
> compilation errors; for example:
>
>  CC      kernel/sched/core.o
> In file included from ./include/linux/uaccess.h:11,
>                  from ./arch/x86/include/asm/fpu/xstate.h:5,
>                  from ./arch/x86/include/asm/pgtable.h:26,
>                  from ./include/linux/kasan.h:16,
>                  from ./include/linux/slab.h:136,
>                  from ./include/kunit/test.h:16,
>                  from ./include/linux/sched.h:35,
>                  from init/do_mounts.c:3:
> ./arch/x86/include/asm/uaccess.h: In function 'set_fs':
> ./arch/x86/include/asm/uaccess.h:32:9: error: dereferencing pointer to
> incomplete type 'struct task_struct'
>   current->thread.addr_limit = fs;
>
> (I'm testing with CONFIG_SLUB). Removing this #include
> resolves these errors, but then causes problems for
> lib/test_kasan.c. I'll dig around a bit more.
>

Yes, I was only testing with UML. Removing that #include fixed the
problem for me for both x86 and UML. Could you share more about the
errors you have encountered in lib/test_kasan.c?

> >  /* task_struct member predeclarations (sorted alphabetically): */
> >  struct audit_context;
> >  struct backing_dev_info;
> > @@ -1178,7 +1180,10 @@ struct task_struct {
> >
> >  #ifdef CONFIG_KASAN
> >       unsigned int                    kasan_depth;
> > -#endif
> > +#ifdef CONFIG_KUNIT
> > +     struct kunit *kasan_kunit_test;
> > +#endif /* CONFIG_KUNIT */
> > +#endif /* CONFIG_KASAN */
> >
> >  #ifdef CONFIG_FUNCTION_GRAPH_TRACER
> >       /* Index of current stored address in ret_stack: */
> > diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> > index 9242f932896c..d266b9495c67 100644
> > --- a/lib/kunit/test.c
> > +++ b/lib/kunit/test.c
> > @@ -9,11 +9,12 @@
> >  #include <kunit/test.h>
> >  #include <linux/kernel.h>
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
> > @@ -236,6 +237,10 @@ static void kunit_try_run_case(void *data)
> >       struct kunit_suite *suite = ctx->suite;
> >       struct kunit_case *test_case = ctx->test_case;
> >
> > +#ifdef CONFIG_KASAN
> > +     current->kasan_kunit_test = test;
> > +#endif
> > +
> >       /*
> >        * kunit_run_case_internal may encounter a fatal error; if it does,
> >        * abort will be called, this thread will exit, and finally the parent
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 5ef9f24f566b..5554d23799a5 100644
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
> > @@ -461,6 +463,15 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
> >       u8 tag = get_tag(object);
> >
> >       object = reset_tag(object);
> > +
> > +     if (current->kasan_kunit_test) {
> > +             if (current->kasan_kunit_test->kasan_report_expected) {
> > +                     current->kasan_kunit_test->kasan_report_found = true;
> > +                     return;
> > +             }
> > +             kunit_set_failure(current->kasan_kunit_test);
> > +     }
> > +
> >       start_report(&flags);
> >       pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
> >       print_tags(tag, object);
> > @@ -481,6 +492,14 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
> >       if (likely(!report_enabled()))
> >               return;
> >
> > +     if (current->kasan_kunit_test) {
> > +             if (current->kasan_kunit_test->kasan_report_expected) {
> > +                     current->kasan_kunit_test->kasan_report_found = true;
> > +                     return;
> > +             }
> > +             kunit_set_failure(current->kasan_kunit_test);
> > +     }
> > +
> >       disable_trace_on_warning();
> >
> >       tagged_addr = (void *)addr;
> > diff --git a/tools/testing/kunit/kunit_kernel.py b/tools/testing/kunit/kunit_kernel.py
> > index cc5d844ecca1..63eab18a8c34 100644
> > --- a/tools/testing/kunit/kunit_kernel.py
> > +++ b/tools/testing/kunit/kunit_kernel.py
> > @@ -141,7 +141,7 @@ class LinuxSourceTree(object):
> >               return True
> >
> >       def run_kernel(self, args=[], timeout=None, build_dir=''):
> > -             args.extend(['mem=256M'])
> > +             args.extend(['mem=256M', 'kasan_multi_shot'])
> >               process = self._ops.linux_bin(args, timeout, build_dir)
> >               with open(os.path.join(build_dir, 'test.log'), 'w') as f:
> >                       for line in process.stdout:
>
> I tried applying this to the "kunit" branch of linux-kselftest, and
> the above failed. Which branch are you building with? Probably
> best to use the kunit branch I think. Thanks!
>
I believe I am on Torvalds/master. There was some debate as to which
branch I should be developing on when I started, but it probably makes
sense for me to move to the "kunit" branch.

> Alan
>
> > --
> > 2.25.0.265.gbab2e86ba0-goog
> >
> >

-- 
Thank you for all your comments!
Patricia Alfonso

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvUK2hFV3LePxwBXO_ubrgYoOk7fuKMOy%2BvSAH5Tf3SrMOA%40mail.gmail.com.
