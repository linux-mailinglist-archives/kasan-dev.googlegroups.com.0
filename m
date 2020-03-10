Return-Path: <kasan-dev+bncBCA2BG6MWAHBBYETUDZQKGQEVFKLSIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc40.google.com (mail-yw1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A4A3180AAC
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Mar 2020 22:42:57 +0100 (CET)
Received: by mail-yw1-xc40.google.com with SMTP id c125sf383060ywf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Mar 2020 14:42:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583876576; cv=pass;
        d=google.com; s=arc-20160816;
        b=oonYgeGqX6uyjBnTDNfBkii7+G95Ka5esaBXnNbxLBCgL0ywFcBqQLyY3/9x4lWNFk
         5nNrcaaSZMN9Tw5zymZhAunRODgwvUrkdO54z2ZfSU2OG0hFYeDBDrLmOKHvcraF3RNz
         vJV9iS89Cde9bKVZGmYxsdjflSmLz4jMLGWlo6bD1Pq5R1gdfHO7hpU/EmqO8bRU+Sc4
         k3FxeMi7v4qM5kOrhkrVGY2Kc3Lo/KKB/cSgaqCpHQKNsoh/6ktl7eMs1koL06TZfOnQ
         ibb6rTtkCHy9JlAVwhh5dOYEf9GeiTEixNPcUhoi9jg9ITADhGsNm4fCpUhNC8AY18ll
         Lt0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=B+USWs2KAMMJlr52tqztxMDIXM+ZERufnaHrSnsRPxY=;
        b=p8Zfh12WbjfgsdeFqLeH0t9i8gme0Rkqvjw21m9FEIhZvrp55L7Lmf0Otl6E+ufCVA
         Gu8sK8NCSFLYCQAt5Zwnolqe1vrwGgRTR25R6FZaGM+P5qRWoSlKYgM08QoCcKYCYKvD
         Yw/HZ7hEzGM+n8c/c1PqcuXC5fRHF3S//d4YmDjIZttyv1NW3gkVa7lCUo4ea/IQEhlb
         tUueKU/CjChjei2bPBvSmAN9YIlgQGZg5NFnrGS/MzGdTBQ6Zn51kdPwko1RiBLXZ6jt
         /DiwRyULEY0jl12r6jwSBhfKxG1tZezl+wiP9CJK1xfNj4vc+bog8OM9LLK9qQ+Mdi1+
         aWEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=okzgk5iR;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B+USWs2KAMMJlr52tqztxMDIXM+ZERufnaHrSnsRPxY=;
        b=UJkJqQYqeBFvB+AoR+ve8oJttXO9AqxCAODU+WbGuhTmKEsaWvnWIThFEobMwI3Ol/
         YxwrNM/GnUUxBdjwlolD2/FkZm/zYwyDQHrqD1NkBIRpVFYigSAijJiOORbGBsoJRLOE
         2aYX86cpLjvXquTl2dqOgdmXCklAtcMGadnx03iBeXhW+KCHvZevIz7Lkf0KwH23BNKh
         h7cEvE0AeiiyLNx/nkd2lKCTTiB4K8582pqicjBXhwnhQv37c9lq5cC5diNmb181Z42A
         YXykHG5nYMJazrMHbXwWpKC1NxyYVBbAT7LiClU75FYXQjTWuwp6r1sRWllcRJUYvX4t
         Um3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B+USWs2KAMMJlr52tqztxMDIXM+ZERufnaHrSnsRPxY=;
        b=aSCwbPefVgst9WljL1VqACMkDA8LWg0EO8gRaxHSi7depcAMlW89dQJJWhUXTPEAwV
         c/SpKTD72I+47CSbyOyxAjd4K/gVCnUn5624DIcmAf9tLVIl/M7X5VWDLDFVLltxCOmN
         ETShp1XGqXfXbyRhj98oirFpPCKLTl7ur1BjU59JLxyVcsicUeg5yXpbPoXKU3K8itk5
         fHYzsba8b7QAvccWJslL8olZ2JRJqMxrpWdO0vVGwOExjYxSAdM1DoLF71Fg7GHRTyoL
         SUPkzZcAl1PFthnX4fkR7jEv7X188s/mR2GE7dOR35GKIMXR6VdYiz4UTf91nSWSmn+z
         b3gA==
X-Gm-Message-State: ANhLgQ3ANlvwjWTHMVSGc63sMEKP7GrXZuXhpJT8Ztq+RLWH8N1a3j2y
	r7jgHxU3CE1X6Ld2elm+f6M=
X-Google-Smtp-Source: ADFU+vtKIf7Z0iwcJp/Wqn+w1IkSo8aK5Ts4KvbQo4/etrsIZYXW97eJ4z34FPNbHLOJgebzsbZ34A==
X-Received: by 2002:a25:13c7:: with SMTP id 190mr24681203ybt.153.1583876576559;
        Tue, 10 Mar 2020 14:42:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ae04:: with SMTP id a4ls4043999ybj.10.gmail; Tue, 10 Mar
 2020 14:42:56 -0700 (PDT)
X-Received: by 2002:a25:c482:: with SMTP id u124mr26136537ybf.286.1583876576054;
        Tue, 10 Mar 2020 14:42:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583876576; cv=none;
        d=google.com; s=arc-20160816;
        b=0bhgRn62//V4ZcBxWQ6HckpWzp1Fxl8gyu6/cY7k+puEchMIeOJdEmxVER9HNl4z2t
         13dySGNYEgzCbaGHoWZdUiM72ndR8521zlZvvBw+ifYfc6skirfYJj1TW2CkatBOYI5v
         NJnGAdr8ciuunzHRpAtvidTKy0SzzyiBkRdQJspcc5Rr78aL+WbDvPq5bwtTjw8gxiOG
         4EqwpBgWNZogmFhc2zdlX52grSv35vKK1kE33CsoOES++cAK7qg4RmqeNhmf3/R5mAnG
         Bg6K01lWznpuXGtXk8SZb1Q5dKpY4E/VqJjjCLPUuATCvoYzcWA5ATzWGpY5yPIaPAQ2
         sxiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=u8S0xt9zGk63HhTITzK6CBJ11aBQXn7zIA733l18/vY=;
        b=e1ZXkGDlDVW83xp1FePWx6sMmi614klnX1XFWs7/qp6jazQuYkykFgOOPbjPQ0Us7V
         gEBa7Y9VTD4C0EtopYOh7pLp0gRbFiGKo0O7szroPS8FlWjDNp95Af8ctFC1jd9qbyxW
         Hco2YGKj5ow3Sm334L1vOokeWKvA3iGVoCmx4bBdYd95P6Fs81MDNobqMjYG2b93lGw+
         kEAkpbHPvTwKsPJ2U6/2X3A6ZvDAks565OPXuULjBW17mLfZp0NtBwAAB78sQgaJwPgl
         dNu/hZ64HFTOF0ckfH2Eaa1S27qsjk+dxLFVOXc3DXTk6bHCLz8coMsDUMdXoaxMbOj7
         5RLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=okzgk5iR;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id b130si924696ywe.2.2020.03.10.14.42.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Mar 2020 14:42:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id z12so20891pgl.4
        for <kasan-dev@googlegroups.com>; Tue, 10 Mar 2020 14:42:56 -0700 (PDT)
X-Received: by 2002:a62:1b51:: with SMTP id b78mr17127409pfb.23.1583876574800;
 Tue, 10 Mar 2020 14:42:54 -0700 (PDT)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com>
 <20200227024301.217042-2-trishalfonso@google.com> <alpine.LRH.2.20.2002271136160.12417@dhcp-10-175-190-15.vpn.oracle.com>
 <CAKFsvUK2hFV3LePxwBXO_ubrgYoOk7fuKMOy+vSAH5Tf3SrMOA@mail.gmail.com>
 <alpine.LRH.2.20.2003031617400.13146@dhcp-10-175-165-222.vpn.oracle.com>
 <CAKFsvUKk=ggYsRcaDrrtRuW3-A5cQh1Q5uA3NBMsnAL1nEUsLg@mail.gmail.com> <alpine.LRH.2.20.2003050736090.2979@dhcp-10-175-220-65.vpn.oracle.com>
In-Reply-To: <alpine.LRH.2.20.2003050736090.2979@dhcp-10-175-220-65.vpn.oracle.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Mar 2020 14:42:43 -0700
Message-ID: <CAFd5g47hRetvP3Y262MXbnExcsQ_BXi9RYRPObAVvjJPVKCKDw@mail.gmail.com>
Subject: Re: [RFC PATCH 2/2] KUnit: KASAN Integration
To: Alan Maguire <alan.maguire@oracle.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, David Gow <davidgow@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	KUnit Development <kunit-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=okzgk5iR;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
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

On Wed, Mar 4, 2020 at 11:47 PM Alan Maguire <alan.maguire@oracle.com> wrote:
>
> On Wed, 4 Mar 2020, Patricia Alfonso wrote:
>
> > On Tue, Mar 3, 2020 at 8:40 AM Alan Maguire <alan.maguire@oracle.com> wrote:
> > >
> > > On Fri, 28 Feb 2020, Patricia Alfonso wrote:
> > >
> > > > On Thu, Feb 27, 2020 at 6:04 AM Alan Maguire <alan.maguire@oracle.com> wrote:
> > > > >
> > > > > On Wed, 26 Feb 2020, Patricia Alfonso wrote:
> > > > >
> > > > > > Integrate KASAN into KUnit testing framework.
> > > > >
> > > > > This is a great idea! Some comments/suggestions below...
> > > > >
> > > >
> > > > Thank you so much for your suggestions!
> > > >
> > >
> > > No problem! Extending KUnit to test things like KASAN
> > > is really valuable, as it shows us ways we can improve
> > > the framework. More below...
> > >
> > > > > >  - Fail tests when KASAN reports an error that is not expected
> > > > > >  - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN tests
> > > > > >  - KUnit struct added to current task to keep track of the current test
> > > > > > from KASAN code
> > > > > >  - Booleans representing if a KASAN report is expected and if a KASAN
> > > > > >  report is found added to kunit struct
> > > > > >  - This prints "line# has passed" or "line# has failed"
> > > > > >
> > > > > > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > > > > > ---
> > > > > > If anyone has any suggestions on how best to print the failure
> > > > > > messages, please share!
> > > > > >
> > > > > > One issue I have found while testing this is the allocation fails in
> > > > > > kmalloc_pagealloc_oob_right() sometimes, but not consistently. This
> > > > > > does cause the test to fail on the KUnit side, as expected, but it
> > > > > > seems to skip all the tests before this one because the output starts
> > > > > > with this failure instead of with the first test, kmalloc_oob_right().
> > > > > >
> > > > > >  include/kunit/test.h                | 24 ++++++++++++++++++++++++
> > > > > >  include/linux/sched.h               |  7 ++++++-
> > > > > >  lib/kunit/test.c                    |  7 ++++++-
> > > > > >  mm/kasan/report.c                   | 19 +++++++++++++++++++
> > > > > >  tools/testing/kunit/kunit_kernel.py |  2 +-
> > > > > >  5 files changed, 56 insertions(+), 3 deletions(-)
> > > > > >
> > > > > > diff --git a/include/kunit/test.h b/include/kunit/test.h
> > > > > > index 2dfb550c6723..2e388f8937f3 100644
> > > > > > --- a/include/kunit/test.h
> > > > > > +++ b/include/kunit/test.h
> > > > > > @@ -21,6 +21,8 @@ struct kunit_resource;
> > > > > >  typedef int (*kunit_resource_init_t)(struct kunit_resource *, void *);
> > > > > >  typedef void (*kunit_resource_free_t)(struct kunit_resource *);
> > > > > >
> > > > > > +void kunit_set_failure(struct kunit *test);
> > > > > > +
> > > > > >  /**
> > > > > >   * struct kunit_resource - represents a *test managed resource*
> > > > > >   * @allocation: for the user to store arbitrary data.
> > > > > > @@ -191,6 +193,9 @@ struct kunit {
> > > > > >        * protect it with some type of lock.
> > > > > >        */
> > > > > >       struct list_head resources; /* Protected by lock. */
> > > > > > +
> > > > > > +     bool kasan_report_expected;
> > > > > > +     bool kasan_report_found;
> > > > > >  };
> > > > > >
> > > > >
> > > > > Is this needed here? You're testing something pretty
> > > > > specific so it seems wrong to add to the generic
> > > > > kunit resource unless there's a good reason. I see the
> > > > > code around setting these values in mm/kasan/report.c,
> > > > > but I wonder if we could do something more generic.
> > > > >
> > > > > How about the concept of a static resource (assuming a
> > > > > dynamically allocated one is out because it messes
> > > > > with memory allocation tests)? Something like this:
> > > > >
> > > > > #define kunit_add_static_resource(test, resource_ptr, resource_field)   \
> > > > >         do {                                                            \
> > > > >                 spin_lock(&test->lock);                                 \
> > > > >                 (resource_ptr)->resource_field.init = NULL;             \
> > > > >                 (resource_ptr)->resource_field.free = NULL;             \
> > > > >                 list_add_tail(&(resource_ptr)->resource_field,          \
> > > > >                               &test->resources);                        \
> > > > >                 spin_unlock(&test->lock);                               \
> > > > >         } while (0)
> > > > >
> > > > >
> > > > > Within your kasan code you could then create a kasan-specific
> > > > > structure that embends a kunit_resource, and contains the
> > > > > values you need:
> > > > >
> > > > > struct kasan_report_resource {
> > > > >         struct kunit_resource res;
> > > > >         bool kasan_report_expected;
> > > > >         bool kasan_report_found;
> > > > > };
> > > > >
> > > > > (One thing we'd need to do for such static resources is fix
> > > > > kunit_resource_free() to check if there's a free() function,
> > > > > and if not assume a static resource)
> > > > >
> > > > > If you then create an init() function associated with your
> > > > > kunit suite (which will be run for every case) it can do this:
> > > > >
> > > > > int kunit_kasan_test_init(struct kunit *test)
> > > > > {
> > > > >         kunit_add_static_resource(test, &my_kasan_report_resource, res);
> > > > >         ...
> > > > > }
> > > > >
> > > > > The above should also be used to initialize current->kasan_unit_test
> > > > > instead of doing that in kunit_try_run_case().  With those
> > > > > changes, you don't (I think) need to change anything in core
> > > > > kunit (assuming support for static resources).
> > > > >
> > > > > To retrieve the resource during tests or in kasan context, the
> > > > > method seems to be to use kunit_resource_find(). However, that
> > > > > requires a match function which seems a bit heavyweight for the
> > > > > static case.  We should probably have a default "find by name"
> > > > > or similar function here, and add an optional "name" field
> > > > > to kunit resources to simplify things.  Anyway here you'd
> > > > > use something like:
> > > > >
> > > > >         kasan_report_resource = kunit_resource_find(test, matchfn,
> > > > >                                                     NULL, matchdata);
> > > > >
> > > > >
> > > > > Are there any barriers to taking this sort of approach (apart
> > > > > from the support for static resources not being there yet)?
> > > > >
> > > >
> > > > I'm not sure. I don't have any experience with kunit resources so I
> > > > would have to put some more effort into understanding how this would
> > > > work for myself. I wonder if this might be a bit of an over
> > > > complicated way of eliminating an extraneous boolean... maybe we can
> > > > find a simpler solution for the first version of this patch and add
> > > > the notion of a static resource for generic use later.
> > > >
> > >
> > > My personal preference would be to try and learn what's needed
> > > by KASAN and improve the KUnit APIs so the next developer finds
> > > life a bit easier. More hassle for you I know, but actual use cases
> > > like this are invaluable for improving the API.  I've sent
> > > out an RFC patchset which has the functionality I _think_ you
> > > need but I may be missing something:
> > >
> > > https://lore.kernel.org/linux-kselftest/1583251361-12748-1-git-send-email-alan.maguire@oracle.com/T/#t
> > >
> > > The idea is your test can do something like this:
> > >
> > > struct kasan_data {
> > >         bool report_expected;
> > >         bool report_found;
> > > };
> > >
> > >
> > > my_kasan_test(struct kunit *test)
> > > {
> > >         struct kunit_resource resource;
> > >         struct kasan_data kasan_data;
> > >
> > > ...
> > >         // add our named resource using static resource/data
> > >         kunit_add_named_resource(test, NULL, NULL, &resource,
> > >                                  "kasan_data", &kasan_data);
> > > ...
> > >
> > > }
> > Does this require the user to set up this kasan_data resource in each
> > KASAN test? Or can we set up the resource on the KUnit side whenever a
> > user writes a test that expects a KASAN failure? I've been playing
> > around with it and I can only seem to get it to work when I add the
> > resource within the test, but I could be missing something.
> >
>
> The current model of resources is they are associated with
> the running state of a test for the lifetime of that test.
> If it's a resource common to many/most tests, I'd suggest
> creating an init() function for the associated suite; this
> will get run prior to executing each test, and in it you
> could initialize your resource. If the resource isn't
> used in the test, it doesn't really matter so this might be
> the simplest way to handle things:
>
> struct kasan_data {
>          bool report_expected;
>          bool report_found;
> };
>
> struct kasan_data kasan_data;
> struct kunit_resource resource;
>
> kasan_init(struct kunit *test)
> {
>
>          // add our named resource using static resource/data
>          kunit_add_named_resource(test, NULL, NULL, &resource,
>                                   "kasan_data", &kasan_data);
>
>         return 0;
> }
>
> static struct kunit_suite kasan_suite = {
>         .name = "kasan",
>         .init = kasan_init,
>         ...
> };
>
>
> This all presumes however that KASAN will only need access to the
> resource during the lifetime of each test.  There's currently
> no concept of free-floating resources outside of test execution
> context.

So we do have some patches lying around that add support for resources
associated with a suite of tests that I can send out if anyone is
interested; nevertheless, I think it makes sense for KASAN to only
care about tests cases; you still get the KASAN report either way and
KUnit isn't really supposed to care what happens outside of KUnit.

Cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g47hRetvP3Y262MXbnExcsQ_BXi9RYRPObAVvjJPVKCKDw%40mail.gmail.com.
