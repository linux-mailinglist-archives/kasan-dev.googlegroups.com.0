Return-Path: <kasan-dev+bncBDK3TPOVRULBB7GAQHZQKGQEIDBQ2BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 647DB179DBC
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 03:14:21 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id u20sf1359672lfu.18
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Mar 2020 18:14:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583374461; cv=pass;
        d=google.com; s=arc-20160816;
        b=mDhMJEcnTYmiWg0yhI99pCMGBAVSvI2YRRekTpULCNl15spax5wE05xVkbjgFlFxRl
         2j2tm1C7ZGRL3SHfN1exoI9uhFdB8yOx6wOEVL/7aQwfW5AY39vf7xwS6xwR/0slMuo/
         SyLqxz4lwf+eOT1gmqseRaed/iGeTbN6NE+W/kD6SzgmMYF61ZzESqF2BgzhEFa0aobP
         yMKvJ5L/jvDxC52VQUpMTGaWjc8wR3mUS0qHsxC9Nk5w1zoxJ9o5Bz9iQ+2O6805pl4u
         +DQndlTfcyOQwFKKEWwcbyfk2vk94aGCBnPSC3LiCtr10SeutdH9ujGAgYsEGBTSedXl
         eXYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PbyiSo3qK8IF0wHyd9JlwGFSnQAZqxxJNqLQ/8QtZ7g=;
        b=wNDiezC917gKFSO90I9iy/G/lspPG07EzxbM+jTDm5y6jGDaAE3j4nONLtSAmSzUCn
         j2+Fmk4kkmgs1y5ia1JyiOkJE+LRra1R0L4XfhzEHyEcYJZjArb+jYF6/7chn13ry9X8
         GSpe+RCegERS04FbbuOf9ZOqXXgXaJ+DIDTfNds+y3AtegELcptMQTgqzR+ItOqTIQVL
         p/ngDklPjhRkDVsPHbDfpUwPeNaZ5AEJKHdXq3myy1mFCmmz01e+s4dMvpzAMbtfU2GH
         Lj92XJHnY/fx8OX46iyPdNJOdsNDFE8wuM/tR82I51wL1a/F779wmddtSmx7IC3lK89X
         yRCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eqjIqyy1;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PbyiSo3qK8IF0wHyd9JlwGFSnQAZqxxJNqLQ/8QtZ7g=;
        b=U3FQpi5lWj2TXlvBQLrQC+p7tRF6BaFbQ0sfMb4/CS2aZiPF6rOs+xJ3uSjbBFyw8Q
         qyeQi/hp7MG7+ABPtZl70eZb28vJyBmttMPQYo4qx/NpC6kUEcZKIcyt0D7IGM8bSXxo
         E18m61TTPVQncqJPmdy4tH8hoKsYslHgHDCJgpX3b3KvBPaWHsEmdIYVqE41UddjIK73
         4w3NysgGGqj+7bLLzYp4HAsawvaqeEA/Vo/MFRuQhZt7c/UD78qoKxt4TP2q6Xae+OZA
         KYknerQuFwrr6JqH8LSmpej00QIEW9Le0S8D+LCpgJ53ivHkz3bGLXRBdoqTa0MU7ffP
         Ubbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PbyiSo3qK8IF0wHyd9JlwGFSnQAZqxxJNqLQ/8QtZ7g=;
        b=r1rYlLuEquMT8HoJs9n/FpbzgIgz1gczdZWDPWbyZnLiAg6cpkN81NjV4rJISE3ItF
         saZ4i8kXxLPXtsua0bWx+SUIpzTuLY1dZrxztmPT3EQq1e7m9Eh+s5LOnhF3V/Bgc3Gp
         B8HcoOj0IeMNPCTU4gPvPIVXbEJrJQBnoM/YJ/5HLQoik2fipmLOWZsdoNKEq0WMJv1e
         GAa2bhhYd1dYBUhFMp2i5zVwHvrqegLlB7WNdob4yJYUzP17Mu7wT1tOx5LblUC+gSKq
         jpS0WojWFgeVmrm5wcEzWh7VG6hPnidk/OoJVBKeFKXAEWq6mIMckLyjHtNdY4+afeTW
         qtRQ==
X-Gm-Message-State: ANhLgQ34eQKM0NP5x7+3eyn+Ot7CjnnzAv0FuxSxmXOuoqsHsymejD9V
	Hs+7qj0p6z2AvKHTUxMbJjs=
X-Google-Smtp-Source: ADFU+vtu3myv88IFgQrKYdySeJDaYzUr2Aj17bPEgauxYZsganpWhDsRNE4CNXqzAjHyEVqmn9TtuQ==
X-Received: by 2002:a19:700e:: with SMTP id h14mr3832249lfc.86.1583374460870;
        Wed, 04 Mar 2020 18:14:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:550:: with SMTP id q16ls121083ljp.2.gmail; Wed, 04
 Mar 2020 18:14:20 -0800 (PST)
X-Received: by 2002:a05:651c:1021:: with SMTP id w1mr2786025ljm.96.1583374460123;
        Wed, 04 Mar 2020 18:14:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583374460; cv=none;
        d=google.com; s=arc-20160816;
        b=QKO5Jt1H781u85P/QNvmdVJQJwMUlkQnlEXFUNJS4GEqrVl7gEgscK0DuhL1UvdgVf
         WotUDDDdrNQ3FJ4dOp7gelaWvEkTBK0IhTWZf+RnRrVv5c8vg7K5oR0/BV2gzVTpTZfi
         26L73+S7N0driRCrdzbBtfKCF+FHaYzaRsr2beCzlrXTRlzXxBZeCpuX66ej9rexWblh
         Jq86WyZsZq7uER9NsmxEz6tZJS7W3m7JAHVvDgwozPyzrrO8vMnBsK1F1Uc+qK9nA/XY
         QQ8q6bAnvCQEDgeE3IvYYQtC03OXbkUWsXoJR1/IZmEASytLjKbazcmGqCXyjueZXYk+
         oJtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=h8I1xecVxNNi5tFU1gGTG9NyoLTUy5gavjvckL+7Wvw=;
        b=fD4JSX2yGG/s1dcPftC8QhDpo8Il0xFIILyAp4AfpbWEQcypSwPf/8SSYgrVw++OAT
         JkGtuiyWyBjxWkyaL9APM6xWD4zFmqJp1dQSNR5GPTcijqtQRk1UxbqJNThKtiNnyRVK
         SZPPZg6DEFNwF3aIyMVh5KpTiJCTdqbXkYVTehvxVIFgzCeSUZ/SMLuIKbj2IMpCG66t
         i0jFbmODwv5T4z9ZcFGluTrz41+RLjEWwDISYjAUuTQ6Ip/ig9QsFOA/Wz8cFfZdOPpa
         A4+zuUZliXSqGExSCriGNun5DwZpVLtK/E2hLJZQQONFYqgoEIpPfkxWXCoA+POQT04c
         Y05Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eqjIqyy1;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id j11si206556lfe.4.2020.03.04.18.14.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Mar 2020 18:14:20 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id r17so5075551wrj.7
        for <kasan-dev@googlegroups.com>; Wed, 04 Mar 2020 18:14:20 -0800 (PST)
X-Received: by 2002:adf:e38d:: with SMTP id e13mr6821734wrm.133.1583374458990;
 Wed, 04 Mar 2020 18:14:18 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com>
 <20200227024301.217042-2-trishalfonso@google.com> <alpine.LRH.2.20.2002271136160.12417@dhcp-10-175-190-15.vpn.oracle.com>
 <CAKFsvUK2hFV3LePxwBXO_ubrgYoOk7fuKMOy+vSAH5Tf3SrMOA@mail.gmail.com> <alpine.LRH.2.20.2003031617400.13146@dhcp-10-175-165-222.vpn.oracle.com>
In-Reply-To: <alpine.LRH.2.20.2003031617400.13146@dhcp-10-175-165-222.vpn.oracle.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Mar 2020 18:14:07 -0800
Message-ID: <CAKFsvUKk=ggYsRcaDrrtRuW3-A5cQh1Q5uA3NBMsnAL1nEUsLg@mail.gmail.com>
Subject: Re: [RFC PATCH 2/2] KUnit: KASAN Integration
To: Alan Maguire <alan.maguire@oracle.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, David Gow <davidgow@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eqjIqyy1;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441
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

On Tue, Mar 3, 2020 at 8:40 AM Alan Maguire <alan.maguire@oracle.com> wrote:
>
> On Fri, 28 Feb 2020, Patricia Alfonso wrote:
>
> > On Thu, Feb 27, 2020 at 6:04 AM Alan Maguire <alan.maguire@oracle.com> wrote:
> > >
> > > On Wed, 26 Feb 2020, Patricia Alfonso wrote:
> > >
> > > > Integrate KASAN into KUnit testing framework.
> > >
> > > This is a great idea! Some comments/suggestions below...
> > >
> >
> > Thank you so much for your suggestions!
> >
>
> No problem! Extending KUnit to test things like KASAN
> is really valuable, as it shows us ways we can improve
> the framework. More below...
>
> > > >  - Fail tests when KASAN reports an error that is not expected
> > > >  - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN tests
> > > >  - KUnit struct added to current task to keep track of the current test
> > > > from KASAN code
> > > >  - Booleans representing if a KASAN report is expected and if a KASAN
> > > >  report is found added to kunit struct
> > > >  - This prints "line# has passed" or "line# has failed"
> > > >
> > > > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > > > ---
> > > > If anyone has any suggestions on how best to print the failure
> > > > messages, please share!
> > > >
> > > > One issue I have found while testing this is the allocation fails in
> > > > kmalloc_pagealloc_oob_right() sometimes, but not consistently. This
> > > > does cause the test to fail on the KUnit side, as expected, but it
> > > > seems to skip all the tests before this one because the output starts
> > > > with this failure instead of with the first test, kmalloc_oob_right().
> > > >
> > > >  include/kunit/test.h                | 24 ++++++++++++++++++++++++
> > > >  include/linux/sched.h               |  7 ++++++-
> > > >  lib/kunit/test.c                    |  7 ++++++-
> > > >  mm/kasan/report.c                   | 19 +++++++++++++++++++
> > > >  tools/testing/kunit/kunit_kernel.py |  2 +-
> > > >  5 files changed, 56 insertions(+), 3 deletions(-)
> > > >
> > > > diff --git a/include/kunit/test.h b/include/kunit/test.h
> > > > index 2dfb550c6723..2e388f8937f3 100644
> > > > --- a/include/kunit/test.h
> > > > +++ b/include/kunit/test.h
> > > > @@ -21,6 +21,8 @@ struct kunit_resource;
> > > >  typedef int (*kunit_resource_init_t)(struct kunit_resource *, void *);
> > > >  typedef void (*kunit_resource_free_t)(struct kunit_resource *);
> > > >
> > > > +void kunit_set_failure(struct kunit *test);
> > > > +
> > > >  /**
> > > >   * struct kunit_resource - represents a *test managed resource*
> > > >   * @allocation: for the user to store arbitrary data.
> > > > @@ -191,6 +193,9 @@ struct kunit {
> > > >        * protect it with some type of lock.
> > > >        */
> > > >       struct list_head resources; /* Protected by lock. */
> > > > +
> > > > +     bool kasan_report_expected;
> > > > +     bool kasan_report_found;
> > > >  };
> > > >
> > >
> > > Is this needed here? You're testing something pretty
> > > specific so it seems wrong to add to the generic
> > > kunit resource unless there's a good reason. I see the
> > > code around setting these values in mm/kasan/report.c,
> > > but I wonder if we could do something more generic.
> > >
> > > How about the concept of a static resource (assuming a
> > > dynamically allocated one is out because it messes
> > > with memory allocation tests)? Something like this:
> > >
> > > #define kunit_add_static_resource(test, resource_ptr, resource_field)   \
> > >         do {                                                            \
> > >                 spin_lock(&test->lock);                                 \
> > >                 (resource_ptr)->resource_field.init = NULL;             \
> > >                 (resource_ptr)->resource_field.free = NULL;             \
> > >                 list_add_tail(&(resource_ptr)->resource_field,          \
> > >                               &test->resources);                        \
> > >                 spin_unlock(&test->lock);                               \
> > >         } while (0)
> > >
> > >
> > > Within your kasan code you could then create a kasan-specific
> > > structure that embends a kunit_resource, and contains the
> > > values you need:
> > >
> > > struct kasan_report_resource {
> > >         struct kunit_resource res;
> > >         bool kasan_report_expected;
> > >         bool kasan_report_found;
> > > };
> > >
> > > (One thing we'd need to do for such static resources is fix
> > > kunit_resource_free() to check if there's a free() function,
> > > and if not assume a static resource)
> > >
> > > If you then create an init() function associated with your
> > > kunit suite (which will be run for every case) it can do this:
> > >
> > > int kunit_kasan_test_init(struct kunit *test)
> > > {
> > >         kunit_add_static_resource(test, &my_kasan_report_resource, res);
> > >         ...
> > > }
> > >
> > > The above should also be used to initialize current->kasan_unit_test
> > > instead of doing that in kunit_try_run_case().  With those
> > > changes, you don't (I think) need to change anything in core
> > > kunit (assuming support for static resources).
> > >
> > > To retrieve the resource during tests or in kasan context, the
> > > method seems to be to use kunit_resource_find(). However, that
> > > requires a match function which seems a bit heavyweight for the
> > > static case.  We should probably have a default "find by name"
> > > or similar function here, and add an optional "name" field
> > > to kunit resources to simplify things.  Anyway here you'd
> > > use something like:
> > >
> > >         kasan_report_resource = kunit_resource_find(test, matchfn,
> > >                                                     NULL, matchdata);
> > >
> > >
> > > Are there any barriers to taking this sort of approach (apart
> > > from the support for static resources not being there yet)?
> > >
> >
> > I'm not sure. I don't have any experience with kunit resources so I
> > would have to put some more effort into understanding how this would
> > work for myself. I wonder if this might be a bit of an over
> > complicated way of eliminating an extraneous boolean... maybe we can
> > find a simpler solution for the first version of this patch and add
> > the notion of a static resource for generic use later.
> >
>
> My personal preference would be to try and learn what's needed
> by KASAN and improve the KUnit APIs so the next developer finds
> life a bit easier. More hassle for you I know, but actual use cases
> like this are invaluable for improving the API.  I've sent
> out an RFC patchset which has the functionality I _think_ you
> need but I may be missing something:
>
> https://lore.kernel.org/linux-kselftest/1583251361-12748-1-git-send-email-alan.maguire@oracle.com/T/#t
>
> The idea is your test can do something like this:
>
> struct kasan_data {
>         bool report_expected;
>         bool report_found;
> };
>
>
> my_kasan_test(struct kunit *test)
> {
>         struct kunit_resource resource;
>         struct kasan_data kasan_data;
>
> ...
>         // add our named resource using static resource/data
>         kunit_add_named_resource(test, NULL, NULL, &resource,
>                                  "kasan_data", &kasan_data);
> ...
>
> }
Does this require the user to set up this kasan_data resource in each
KASAN test? Or can we set up the resource on the KUnit side whenever a
user writes a test that expects a KASAN failure? I've been playing
around with it and I can only seem to get it to work when I add the
resource within the test, but I could be missing something.

>
> (The NULLs in the function arguments above reflect the fact we
> don't require initialization or cleanup for such static resources)
>
> Then, in KASAN context you can look the above resource up like so:
>
>         struct kunit_resource *resource;
>         struct kasan_data *kasan_data;
>
>         resource = kunit_find_named_resource(test, "kasan_data");
>         kasan_data = resource->data;
>
>         // when finished, reduce reference count on resource
>         kunit_put_resource(resource);
>
> Does that work for your use case?
>
> > > >  void kunit_init_test(struct kunit *test, const char *name);
> > > > @@ -941,6 +946,25 @@ do {                                                                            \
> > > >                                               ptr,                           \
> > > >                                               NULL)
> > > >
> > > > +/**
> > > > + * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
> > > > + * not cause a KASAN error.
> > > > + *
> > > > + */
> > > > +#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do {        \
> > > > +     test->kasan_report_expected = true;     \
> > > > +     test->kasan_report_found = false; \
> > > > +     condition; \
> > > > +     if (test->kasan_report_found == test->kasan_report_expected) { \
> > > > +             pr_info("%d has passed", __LINE__); \
> > > > +     } else { \
> > > > +             kunit_set_failure(test); \
> > > > +             pr_info("%d has failed", __LINE__); \
> > > > +     } \
> > > > +     test->kasan_report_expected = false;    \
> > > > +     test->kasan_report_found = false;       \
> > > > +} while (0)
> > > > +
> > >
> > > Feels like this belongs in test_kasan.c, and could be reworked
> > > to avoid adding test->kasan_report_[expected|found] as described
> > > above.
> >
> > You're right. Since I don't see any reason why any other tests should
> > want to expect a KASAN error, it does make sense to move this logic
> > inside test_kasan.c. If, in the future, there is a need for this
> > elsewhere, we can always move it back then.
> >
> > >  Instead of having your own pass/fail logic couldn't you
> > > do this:
> > >
> > >         KUNIT_EXPECT_EQ(test, expected, found);
> > >
> > > ? That will set the failure state too so no need to export
> > > a separate function for that, and no need to log anything
> > > as KUNIT_EXPECT_EQ() should do that for you.
> > >
> >
> > This is a great idea - I feel a little silly that I didn't think of
> > that myself! Do we think the failure message for the KUNIT_EXPECT_EQ()
> > would be sufficient for KASAN developers?
> > i.e. "Expected kasan_report_expected == kasan_report_found, but
> > kasan_report_expected == true
> > kasan_report_found == false"
> >
>
> I guess the missing piece above is the line number where
> the test failure was encountered, is that the concern?
>
> > > >  /**
> > > >   * KUNIT_EXPECT_TRUE() - Causes a test failure when the expression is not true.
> > > >   * @test: The test context object.
> > > > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > > > index 04278493bf15..db23d56061e7 100644
> > > > --- a/include/linux/sched.h
> > > > +++ b/include/linux/sched.h
> > > > @@ -32,6 +32,8 @@
> > > >  #include <linux/posix-timers.h>
> > > >  #include <linux/rseq.h>
> > > >
> > > > +#include <kunit/test.h>
> > > > +
> > >
> > > This feels like the wrong place to add this #include, and
> > > when I attempted to build to test I ran into a bunch of
> > > compilation errors; for example:
> > >
> > >  CC      kernel/sched/core.o
> > > In file included from ./include/linux/uaccess.h:11,
> > >                  from ./arch/x86/include/asm/fpu/xstate.h:5,
> > >                  from ./arch/x86/include/asm/pgtable.h:26,
> > >                  from ./include/linux/kasan.h:16,
> > >                  from ./include/linux/slab.h:136,
> > >                  from ./include/kunit/test.h:16,
> > >                  from ./include/linux/sched.h:35,
> > >                  from init/do_mounts.c:3:
> > > ./arch/x86/include/asm/uaccess.h: In function 'set_fs':
> > > ./arch/x86/include/asm/uaccess.h:32:9: error: dereferencing pointer to
> > > incomplete type 'struct task_struct'
> > >   current->thread.addr_limit = fs;
> > >
> > > (I'm testing with CONFIG_SLUB). Removing this #include
> > > resolves these errors, but then causes problems for
> > > lib/test_kasan.c. I'll dig around a bit more.
> > >
> >
> > Yes, I was only testing with UML. Removing that #include fixed the
> > problem for me for both x86 and UML. Could you share more about the
> > errors you have encountered in lib/test_kasan.c?
> >
>
> I'll try this again and send details.
>
> I think broadly the issue is that if we #include kunit headers
> in the kasan headers, we end up creating all kinds of problems
> for ourselves, since the kasan headers are in turn included
> in so many places (including the kunit headers themselves, since
> kunit uses memory allocation APIs). I suspect the way forward is
> to try and ensure that we don't utilize the kunit headers in any
> of the kasan headers, but rather just include kunit headers
> in test_kasan.c, and any other kasan .c files we need KUnit APIs
> for. Not sure if that's possible, but it's likely the best way to
> go if it is.
>
> > > >  /* task_struct member predeclarations (sorted alphabetically): */
> > > >  struct audit_context;
> > > >  struct backing_dev_info;
> > > > @@ -1178,7 +1180,10 @@ struct task_struct {
> > > >
> > > >  #ifdef CONFIG_KASAN
> > > >       unsigned int                    kasan_depth;
> > > > -#endif
> > > > +#ifdef CONFIG_KUNIT
> > > > +     struct kunit *kasan_kunit_test;
> > > > +#endif /* CONFIG_KUNIT */
> > > > +#endif /* CONFIG_KASAN */
> > > >
> > > >  #ifdef CONFIG_FUNCTION_GRAPH_TRACER
> > > >       /* Index of current stored address in ret_stack: */
> > > > diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> > > > index 9242f932896c..d266b9495c67 100644
> > > > --- a/lib/kunit/test.c
> > > > +++ b/lib/kunit/test.c
> > > > @@ -9,11 +9,12 @@
> > > >  #include <kunit/test.h>
> > > >  #include <linux/kernel.h>
> > > >  #include <linux/sched/debug.h>
> > > > +#include <linux/sched.h>
> > > >
> > > >  #include "string-stream.h"
> > > >  #include "try-catch-impl.h"
> > > >
> > > > -static void kunit_set_failure(struct kunit *test)
> > > > +void kunit_set_failure(struct kunit *test)
> > > >  {
> > > >       WRITE_ONCE(test->success, false);
> > > >  }
> > > > @@ -236,6 +237,10 @@ static void kunit_try_run_case(void *data)
> > > >       struct kunit_suite *suite = ctx->suite;
> > > >       struct kunit_case *test_case = ctx->test_case;
> > > >
> > > > +#ifdef CONFIG_KASAN
> > > > +     current->kasan_kunit_test = test;
> > > > +#endif
> > > > +
> > > >       /*
> > > >        * kunit_run_case_internal may encounter a fatal error; if it does,
> > > >        * abort will be called, this thread will exit, and finally the parent
> > > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > > index 5ef9f24f566b..5554d23799a5 100644
> > > > --- a/mm/kasan/report.c
> > > > +++ b/mm/kasan/report.c
> > > > @@ -32,6 +32,8 @@
> > > >
> > > >  #include <asm/sections.h>
> > > >
> > > > +#include <kunit/test.h>
> > > > +
> > > >  #include "kasan.h"
> > > >  #include "../slab.h"
> > > >
> > > > @@ -461,6 +463,15 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
> > > >       u8 tag = get_tag(object);
> > > >
> > > >       object = reset_tag(object);
> > > > +
> > > > +     if (current->kasan_kunit_test) {
> > > > +             if (current->kasan_kunit_test->kasan_report_expected) {
> > > > +                     current->kasan_kunit_test->kasan_report_found = true;
> > > > +                     return;
> > > > +             }
> > > > +             kunit_set_failure(current->kasan_kunit_test);
> > > > +     }
> > > > +
> > > >       start_report(&flags);
> > > >       pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
> > > >       print_tags(tag, object);
> > > > @@ -481,6 +492,14 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
> > > >       if (likely(!report_enabled()))
> > > >               return;
> > > >
> > > > +     if (current->kasan_kunit_test) {
> > > > +             if (current->kasan_kunit_test->kasan_report_expected) {
> > > > +                     current->kasan_kunit_test->kasan_report_found = true;
> > > > +                     return;
> > > > +             }
> > > > +             kunit_set_failure(current->kasan_kunit_test);
> > > > +     }
> > > > +
> > > >       disable_trace_on_warning();
> > > >
> > > >       tagged_addr = (void *)addr;
> > > > diff --git a/tools/testing/kunit/kunit_kernel.py b/tools/testing/kunit/kunit_kernel.py
> > > > index cc5d844ecca1..63eab18a8c34 100644
> > > > --- a/tools/testing/kunit/kunit_kernel.py
> > > > +++ b/tools/testing/kunit/kunit_kernel.py
> > > > @@ -141,7 +141,7 @@ class LinuxSourceTree(object):
> > > >               return True
> > > >
> > > >       def run_kernel(self, args=[], timeout=None, build_dir=''):
> > > > -             args.extend(['mem=256M'])
> > > > +             args.extend(['mem=256M', 'kasan_multi_shot'])
> > > >               process = self._ops.linux_bin(args, timeout, build_dir)
> > > >               with open(os.path.join(build_dir, 'test.log'), 'w') as f:
> > > >                       for line in process.stdout:
> > >
> > > I tried applying this to the "kunit" branch of linux-kselftest, and
> > > the above failed. Which branch are you building with? Probably
> > > best to use the kunit branch I think. Thanks!
> > >
> > I believe I am on Torvalds/master. There was some debate as to which
> > branch I should be developing on when I started, but it probably makes
> > sense for me to move to the "kunit" branch.
> >
>
> I think for this case - given that we may need some new KUnit
> functionality - that would be best. Thanks!
>
> Alan
>
> > > Alan
> > >
> > > > --
> > > > 2.25.0.265.gbab2e86ba0-goog
> > > >
> > > >
> >
> > --
> > Thank you for all your comments!
> > Patricia Alfonso
> >



-- 

Patricia Alfonso
Software Engineer
trishalfonso@google.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvUKk%3DggYsRcaDrrtRuW3-A5cQh1Q5uA3NBMsnAL1nEUsLg%40mail.gmail.com.
