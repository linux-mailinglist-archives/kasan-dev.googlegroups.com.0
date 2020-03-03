Return-Path: <kasan-dev+bncBAABB6UQ7LZAKGQEBBK6W7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 04CBB177C17
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Mar 2020 17:40:28 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id c6sf632745pjs.2
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2020 08:40:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583253626; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zc6XXScbfe9MgQ9xeUCUJPimzc0DayDzmw8S9ZnkS9bsFfuEj1cBcof0HLZj2E5PAS
         dLJiyO8TvWFtPcG9Kp5IIFvZR4NKHYeuwLMrrSIz0oOkJwdvOcz0zstwgyik8lmhbB+g
         dW++3UrfvG642QR4PxQ+/0+6m7tY1DkAfexBATsgaY5qI0lAmTm46EDMNotQJX78iTRA
         XUX/+6q2UDsEEJ/PtcJwEiO5o9mcM5zSBn9UND4fGIyc4fcQbFEniNnZX0CESog3KJAr
         xeDOftrfshIZze9K25Mk9Tvyi3aejs3j59SI7Zc8E0P9l24AbXGyMcnd2PWz/QSqpmIj
         YX7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=AGzCB2AO5BCfSd9dlvxHZd0XxV0o2nmErEyLsLqHwVs=;
        b=xWStkjJchfeFAH3cD7rRxUTqOdPmOopJGAbFYeuR5wEDMmqtKHfjmUMe2SM53YgiQL
         BAjHugd3Y1zjmbkzRcVWXLSqAVp0v7dpsKaDrIrV/RuAt14URGOwReh9u/Um++S81z8o
         w/BLs1DjO8DgzgRYAQhc5LvMLA6qvbreEII8j38JRKDu7X0HT6rITix85+y0x65XSiCu
         sVgf3c6boGh/tc1pbVPDMhTYUsb+jvhRY45dGlbPsFRaYpAL5SXvTvb3ims4kguLLnp7
         j6wcVvqXPhl8ASQWPipTJr9EeJvViTRSavsCwWZdw/PfMxCG4Cg/LTM2fZAmxWPxJtLu
         jUMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=cEk7U3AW;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AGzCB2AO5BCfSd9dlvxHZd0XxV0o2nmErEyLsLqHwVs=;
        b=TyZ5+Vd+SA9gV9EOpwetr6Q65HmO2ODKoJC9eQQZRB/qYvt0xSlOd2HaoKq0lbESBl
         Wr8zBm0JZweDu7f59eJcpqTaZ4f1isutcHuA5leGihemcPSJ2m0obi9alfwLIvjkMSI4
         0IMgJHXOv7lhBA9m8bIgXalI3EQUbUrpF0exU6jY0oF6xTWdJApdOq5uAUqfqsaU/wmV
         Nekl6kbwycZE64H9q51nI47uhNYetR40VUCnkGUjDb3gj7GexMufbWPSTl/gBhR17cYE
         31Jr9N6hnxnUjJnoS7boEUlFnVWuAVHH52ayvjkeN6Y+lJKdnwTIqi1KXUB/NLSJ1byy
         Qn8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AGzCB2AO5BCfSd9dlvxHZd0XxV0o2nmErEyLsLqHwVs=;
        b=p2qbg3KPhrGLqUmoXlIYv+Chka0VhuqdUTcsVicabSNULYn9T9ZDe3snCHe135a8Nx
         k53ppsCmETiguvANb2pyTKNfByWTX8mBqyS+ezVhdaZbwl1DMTYZmap4SL/ITv4vLXqL
         fJ2ogmUE9x+JLucOLpWdSG5vch17JvI+nbX7cG4L82uHWojp0VTRJ1qX5my6o3RPiT+/
         DxImDSW8UK1rBp8nzMIn4fHOGpW6LE8MBHG9V7EYBouqhmsYeoilpSV89Lq+GqBm12EF
         AbRGiS8KoQ9M9mFy2AsmV440tHmVTMsdr62VKJnMMYFTD4Is6xwmX3urzkUY2FFlelEL
         BALA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2C5+94CZtdVq/VhOD5eF3hHkVmsqskdqgHPna3ivXUPmzTGaCz
	GRtJzRkR0EMwR1BZd0d6WGA=
X-Google-Smtp-Source: ADFU+vu6E+i/Z8Tag8O0Q+z6y0vWKDpgjs6OnqMqRyPQhBipQWIZ93Tfr8irJjCUYEaQkap+xSngCA==
X-Received: by 2002:a63:1051:: with SMTP id 17mr4667315pgq.291.1583253626352;
        Tue, 03 Mar 2020 08:40:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5c3:: with SMTP id 186ls170394pff.7.gmail; Tue, 03 Mar
 2020 08:40:25 -0800 (PST)
X-Received: by 2002:a63:7e09:: with SMTP id z9mr4855215pgc.383.1583253625877;
        Tue, 03 Mar 2020 08:40:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583253625; cv=none;
        d=google.com; s=arc-20160816;
        b=Ezu89tGy9CaO+JruhTjz2/3pCFM1tzJ765djE7NLYEwb3EdtXeV5ABULc8E/nh/aCq
         Sb78/lROm5ezVwNlcJYy9H513hQNyxnVyPYEoDn/YcVr8LU2KG3akknqWRrfAA9qfB59
         xu23ucDdFtXYDmZIBVwthKzyfT+zBkQdqYt4LNxUlGXMAe2tA79sVWnFJqVN630MA2ed
         7T2hOOlB7zsCUjK22/5Sv6PGdrA1IT1oNla7pYyMAJv72nAiUhRsL+J0zS/2fYcwCaA4
         GVJ2to9HjJIDx98QbkMIL4fb2fjoviZrCbqi2CYx1DCAu++bf0xrfyFe/La2RP7T0hf7
         q/uQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date:dkim-signature;
        bh=x4CwZHak73B27uGiTrPt9ArseHlYfUqsJkiKLYedkxY=;
        b=TLfZs+H6xXmdhDVJjLOpQLToOU1Ix0EpY9819J0CvSQgbRGB6dic8cBlRB6tw3DgBJ
         ORTZJHtycXg/LZh2hwGpuSSDlXHuIw7UrLhCoKkl+pCyL0N1mvN6887rm/FU9KPgc7N/
         4wDlJeirt9nU/FA6S67/ObHCC0sxMWkRc/y50qwO/1Y2ftwOLxdoZhfAg6eHWNa4f9io
         wXCMuU1eh64El4cKbsb7H0LOxUB2fQksiRKVTK81fMh4oQIUFN9s4PLH+ARMvqd71msa
         WvGvAXrBsj+v+AYZ8OkdwghUjgCwp2xygGFjSKuWxra52yFXG/DIM3F0IyOMPVuY4HXb
         /j+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=cEk7U3AW;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from aserp2120.oracle.com (aserp2120.oracle.com. [141.146.126.78])
        by gmr-mx.google.com with ESMTPS id l12si689319plt.5.2020.03.03.08.40.25
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 03 Mar 2020 08:40:25 -0800 (PST)
Received-SPF: pass (google.com: domain of alan.maguire@oracle.com designates 141.146.126.78 as permitted sender) client-ip=141.146.126.78;
Received: from pps.filterd (aserp2120.oracle.com [127.0.0.1])
	by aserp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 023GOdVw043795;
	Tue, 3 Mar 2020 16:40:22 GMT
Received: from aserp3020.oracle.com (aserp3020.oracle.com [141.146.126.70])
	by aserp2120.oracle.com with ESMTP id 2yffwqrf8x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 03 Mar 2020 16:40:22 +0000
Received: from pps.filterd (aserp3020.oracle.com [127.0.0.1])
	by aserp3020.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 023GNGCK029835;
	Tue, 3 Mar 2020 16:40:22 GMT
Received: from userv0121.oracle.com (userv0121.oracle.com [156.151.31.72])
	by aserp3020.oracle.com with ESMTP id 2yg1rmf5m0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 03 Mar 2020 16:40:22 +0000
Received: from abhmp0006.oracle.com (abhmp0006.oracle.com [141.146.116.12])
	by userv0121.oracle.com (8.14.4/8.13.8) with ESMTP id 023GeJeX021569;
	Tue, 3 Mar 2020 16:40:19 GMT
Received: from dhcp-10-175-165-222.vpn.oracle.com (/10.175.165.222)
	by default (Oracle Beehive Gateway v4.0)
	with ESMTP ; Tue, 03 Mar 2020 08:40:18 -0800
Date: Tue, 3 Mar 2020 16:40:06 +0000 (GMT)
From: Alan Maguire <alan.maguire@oracle.com>
X-X-Sender: alan@dhcp-10-175-165-222.vpn.oracle.com
To: Patricia Alfonso <trishalfonso@google.com>
cc: Alan Maguire <alan.maguire@oracle.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Brendan Higgins <brendanhiggins@google.com>,
        David Gow <davidgow@google.com>, mingo@redhat.com,
        peterz@infradead.org, juri.lelli@redhat.com,
        vincent.guittot@linaro.org, LKML <linux-kernel@vger.kernel.org>,
        kasan-dev <kasan-dev@googlegroups.com>,
        linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com
Subject: Re: [RFC PATCH 2/2] KUnit: KASAN Integration
In-Reply-To: <CAKFsvUK2hFV3LePxwBXO_ubrgYoOk7fuKMOy+vSAH5Tf3SrMOA@mail.gmail.com>
Message-ID: <alpine.LRH.2.20.2003031617400.13146@dhcp-10-175-165-222.vpn.oracle.com>
References: <20200227024301.217042-1-trishalfonso@google.com> <20200227024301.217042-2-trishalfonso@google.com> <alpine.LRH.2.20.2002271136160.12417@dhcp-10-175-190-15.vpn.oracle.com> <CAKFsvUK2hFV3LePxwBXO_ubrgYoOk7fuKMOy+vSAH5Tf3SrMOA@mail.gmail.com>
User-Agent: Alpine 2.20 (LRH 67 2015-01-07)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9549 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 mlxlogscore=999
 suspectscore=1 malwarescore=0 adultscore=0 spamscore=0 phishscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2001150001 definitions=main-2003030115
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9549 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 lowpriorityscore=0 spamscore=0
 impostorscore=0 malwarescore=0 mlxlogscore=999 mlxscore=0 suspectscore=1
 phishscore=0 clxscore=1015 bulkscore=0 adultscore=0 priorityscore=1501
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2001150001
 definitions=main-2003030115
X-Original-Sender: alan.maguire@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=cEk7U3AW;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates
 141.146.126.78 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
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

On Fri, 28 Feb 2020, Patricia Alfonso wrote:

> On Thu, Feb 27, 2020 at 6:04 AM Alan Maguire <alan.maguire@oracle.com> wrote:
> >
> > On Wed, 26 Feb 2020, Patricia Alfonso wrote:
> >
> > > Integrate KASAN into KUnit testing framework.
> >
> > This is a great idea! Some comments/suggestions below...
> >
> 
> Thank you so much for your suggestions!
>

No problem! Extending KUnit to test things like KASAN
is really valuable, as it shows us ways we can improve
the framework. More below...
 
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
> > >        * protect it with some type of lock.
> > >        */
> > >       struct list_head resources; /* Protected by lock. */
> > > +
> > > +     bool kasan_report_expected;
> > > +     bool kasan_report_found;
> > >  };
> > >
> >
> > Is this needed here? You're testing something pretty
> > specific so it seems wrong to add to the generic
> > kunit resource unless there's a good reason. I see the
> > code around setting these values in mm/kasan/report.c,
> > but I wonder if we could do something more generic.
> >
> > How about the concept of a static resource (assuming a
> > dynamically allocated one is out because it messes
> > with memory allocation tests)? Something like this:
> >
> > #define kunit_add_static_resource(test, resource_ptr, resource_field)   \
> >         do {                                                            \
> >                 spin_lock(&test->lock);                                 \
> >                 (resource_ptr)->resource_field.init = NULL;             \
> >                 (resource_ptr)->resource_field.free = NULL;             \
> >                 list_add_tail(&(resource_ptr)->resource_field,          \
> >                               &test->resources);                        \
> >                 spin_unlock(&test->lock);                               \
> >         } while (0)
> >
> >
> > Within your kasan code you could then create a kasan-specific
> > structure that embends a kunit_resource, and contains the
> > values you need:
> >
> > struct kasan_report_resource {
> >         struct kunit_resource res;
> >         bool kasan_report_expected;
> >         bool kasan_report_found;
> > };
> >
> > (One thing we'd need to do for such static resources is fix
> > kunit_resource_free() to check if there's a free() function,
> > and if not assume a static resource)
> >
> > If you then create an init() function associated with your
> > kunit suite (which will be run for every case) it can do this:
> >
> > int kunit_kasan_test_init(struct kunit *test)
> > {
> >         kunit_add_static_resource(test, &my_kasan_report_resource, res);
> >         ...
> > }
> >
> > The above should also be used to initialize current->kasan_unit_test
> > instead of doing that in kunit_try_run_case().  With those
> > changes, you don't (I think) need to change anything in core
> > kunit (assuming support for static resources).
> >
> > To retrieve the resource during tests or in kasan context, the
> > method seems to be to use kunit_resource_find(). However, that
> > requires a match function which seems a bit heavyweight for the
> > static case.  We should probably have a default "find by name"
> > or similar function here, and add an optional "name" field
> > to kunit resources to simplify things.  Anyway here you'd
> > use something like:
> >
> >         kasan_report_resource = kunit_resource_find(test, matchfn,
> >                                                     NULL, matchdata);
> >
> >
> > Are there any barriers to taking this sort of approach (apart
> > from the support for static resources not being there yet)?
> >
> 
> I'm not sure. I don't have any experience with kunit resources so I
> would have to put some more effort into understanding how this would
> work for myself. I wonder if this might be a bit of an over
> complicated way of eliminating an extraneous boolean... maybe we can
> find a simpler solution for the first version of this patch and add
> the notion of a static resource for generic use later.
>

My personal preference would be to try and learn what's needed
by KASAN and improve the KUnit APIs so the next developer finds
life a bit easier. More hassle for you I know, but actual use cases
like this are invaluable for improving the API.  I've sent
out an RFC patchset which has the functionality I _think_ you
need but I may be missing something:

https://lore.kernel.org/linux-kselftest/1583251361-12748-1-git-send-email-alan.maguire@oracle.com/T/#t

The idea is your test can do something like this:

struct kasan_data {
	bool report_expected;
	bool report_found;
};


my_kasan_test(struct kunit *test)
{
	struct kunit_resource resource;
	struct kasan_data kasan_data;

...
	// add our named resource using static resource/data
	kunit_add_named_resource(test, NULL, NULL, &resource, 
				 "kasan_data", &kasan_data);
...

}

(The NULLs in the function arguments above reflect the fact we
don't require initialization or cleanup for such static resources)

Then, in KASAN context you can look the above resource up like so:

	struct kunit_resource *resource;
	struct kasan_data *kasan_data;

	resource = kunit_find_named_resource(test, "kasan_data");
	kasan_data = resource->data;

	// when finished, reduce reference count on resource
	kunit_put_resource(resource);
 
Does that work for your use case?

> > >  void kunit_init_test(struct kunit *test, const char *name);
> > > @@ -941,6 +946,25 @@ do {                                                                            \
> > >                                               ptr,                           \
> > >                                               NULL)
> > >
> > > +/**
> > > + * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
> > > + * not cause a KASAN error.
> > > + *
> > > + */
> > > +#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do {        \
> > > +     test->kasan_report_expected = true;     \
> > > +     test->kasan_report_found = false; \
> > > +     condition; \
> > > +     if (test->kasan_report_found == test->kasan_report_expected) { \
> > > +             pr_info("%d has passed", __LINE__); \
> > > +     } else { \
> > > +             kunit_set_failure(test); \
> > > +             pr_info("%d has failed", __LINE__); \
> > > +     } \
> > > +     test->kasan_report_expected = false;    \
> > > +     test->kasan_report_found = false;       \
> > > +} while (0)
> > > +
> >
> > Feels like this belongs in test_kasan.c, and could be reworked
> > to avoid adding test->kasan_report_[expected|found] as described
> > above.
> 
> You're right. Since I don't see any reason why any other tests should
> want to expect a KASAN error, it does make sense to move this logic
> inside test_kasan.c. If, in the future, there is a need for this
> elsewhere, we can always move it back then.
> 
> >  Instead of having your own pass/fail logic couldn't you
> > do this:
> >
> >         KUNIT_EXPECT_EQ(test, expected, found);
> >
> > ? That will set the failure state too so no need to export
> > a separate function for that, and no need to log anything
> > as KUNIT_EXPECT_EQ() should do that for you.
> >
> 
> This is a great idea - I feel a little silly that I didn't think of
> that myself! Do we think the failure message for the KUNIT_EXPECT_EQ()
> would be sufficient for KASAN developers?
> i.e. "Expected kasan_report_expected == kasan_report_found, but
> kasan_report_expected == true
> kasan_report_found == false"
>

I guess the missing piece above is the line number where
the test failure was encountered, is that the concern?
 
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
> >
> > This feels like the wrong place to add this #include, and
> > when I attempted to build to test I ran into a bunch of
> > compilation errors; for example:
> >
> >  CC      kernel/sched/core.o
> > In file included from ./include/linux/uaccess.h:11,
> >                  from ./arch/x86/include/asm/fpu/xstate.h:5,
> >                  from ./arch/x86/include/asm/pgtable.h:26,
> >                  from ./include/linux/kasan.h:16,
> >                  from ./include/linux/slab.h:136,
> >                  from ./include/kunit/test.h:16,
> >                  from ./include/linux/sched.h:35,
> >                  from init/do_mounts.c:3:
> > ./arch/x86/include/asm/uaccess.h: In function 'set_fs':
> > ./arch/x86/include/asm/uaccess.h:32:9: error: dereferencing pointer to
> > incomplete type 'struct task_struct'
> >   current->thread.addr_limit = fs;
> >
> > (I'm testing with CONFIG_SLUB). Removing this #include
> > resolves these errors, but then causes problems for
> > lib/test_kasan.c. I'll dig around a bit more.
> >
> 
> Yes, I was only testing with UML. Removing that #include fixed the
> problem for me for both x86 and UML. Could you share more about the
> errors you have encountered in lib/test_kasan.c?
> 

I'll try this again and send details.

I think broadly the issue is that if we #include kunit headers
in the kasan headers, we end up creating all kinds of problems
for ourselves, since the kasan headers are in turn included
in so many places (including the kunit headers themselves, since
kunit uses memory allocation APIs). I suspect the way forward is
to try and ensure that we don't utilize the kunit headers in any
of the kasan headers, but rather just include kunit headers
in test_kasan.c, and any other kasan .c files we need KUnit APIs
for. Not sure if that's possible, but it's likely the best way to
go if it is.

> > >  /* task_struct member predeclarations (sorted alphabetically): */
> > >  struct audit_context;
> > >  struct backing_dev_info;
> > > @@ -1178,7 +1180,10 @@ struct task_struct {
> > >
> > >  #ifdef CONFIG_KASAN
> > >       unsigned int                    kasan_depth;
> > > -#endif
> > > +#ifdef CONFIG_KUNIT
> > > +     struct kunit *kasan_kunit_test;
> > > +#endif /* CONFIG_KUNIT */
> > > +#endif /* CONFIG_KASAN */
> > >
> > >  #ifdef CONFIG_FUNCTION_GRAPH_TRACER
> > >       /* Index of current stored address in ret_stack: */
> > > diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> > > index 9242f932896c..d266b9495c67 100644
> > > --- a/lib/kunit/test.c
> > > +++ b/lib/kunit/test.c
> > > @@ -9,11 +9,12 @@
> > >  #include <kunit/test.h>
> > >  #include <linux/kernel.h>
> > >  #include <linux/sched/debug.h>
> > > +#include <linux/sched.h>
> > >
> > >  #include "string-stream.h"
> > >  #include "try-catch-impl.h"
> > >
> > > -static void kunit_set_failure(struct kunit *test)
> > > +void kunit_set_failure(struct kunit *test)
> > >  {
> > >       WRITE_ONCE(test->success, false);
> > >  }
> > > @@ -236,6 +237,10 @@ static void kunit_try_run_case(void *data)
> > >       struct kunit_suite *suite = ctx->suite;
> > >       struct kunit_case *test_case = ctx->test_case;
> > >
> > > +#ifdef CONFIG_KASAN
> > > +     current->kasan_kunit_test = test;
> > > +#endif
> > > +
> > >       /*
> > >        * kunit_run_case_internal may encounter a fatal error; if it does,
> > >        * abort will be called, this thread will exit, and finally the parent
> > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > index 5ef9f24f566b..5554d23799a5 100644
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
> > > @@ -461,6 +463,15 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
> > >       u8 tag = get_tag(object);
> > >
> > >       object = reset_tag(object);
> > > +
> > > +     if (current->kasan_kunit_test) {
> > > +             if (current->kasan_kunit_test->kasan_report_expected) {
> > > +                     current->kasan_kunit_test->kasan_report_found = true;
> > > +                     return;
> > > +             }
> > > +             kunit_set_failure(current->kasan_kunit_test);
> > > +     }
> > > +
> > >       start_report(&flags);
> > >       pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
> > >       print_tags(tag, object);
> > > @@ -481,6 +492,14 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
> > >       if (likely(!report_enabled()))
> > >               return;
> > >
> > > +     if (current->kasan_kunit_test) {
> > > +             if (current->kasan_kunit_test->kasan_report_expected) {
> > > +                     current->kasan_kunit_test->kasan_report_found = true;
> > > +                     return;
> > > +             }
> > > +             kunit_set_failure(current->kasan_kunit_test);
> > > +     }
> > > +
> > >       disable_trace_on_warning();
> > >
> > >       tagged_addr = (void *)addr;
> > > diff --git a/tools/testing/kunit/kunit_kernel.py b/tools/testing/kunit/kunit_kernel.py
> > > index cc5d844ecca1..63eab18a8c34 100644
> > > --- a/tools/testing/kunit/kunit_kernel.py
> > > +++ b/tools/testing/kunit/kunit_kernel.py
> > > @@ -141,7 +141,7 @@ class LinuxSourceTree(object):
> > >               return True
> > >
> > >       def run_kernel(self, args=[], timeout=None, build_dir=''):
> > > -             args.extend(['mem=256M'])
> > > +             args.extend(['mem=256M', 'kasan_multi_shot'])
> > >               process = self._ops.linux_bin(args, timeout, build_dir)
> > >               with open(os.path.join(build_dir, 'test.log'), 'w') as f:
> > >                       for line in process.stdout:
> >
> > I tried applying this to the "kunit" branch of linux-kselftest, and
> > the above failed. Which branch are you building with? Probably
> > best to use the kunit branch I think. Thanks!
> >
> I believe I am on Torvalds/master. There was some debate as to which
> branch I should be developing on when I started, but it probably makes
> sense for me to move to the "kunit" branch.
>

I think for this case - given that we may need some new KUnit
functionality - that would be best. Thanks!

Alan
 
> > Alan
> >
> > > --
> > > 2.25.0.265.gbab2e86ba0-goog
> > >
> > >
> 
> -- 
> Thank you for all your comments!
> Patricia Alfonso
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.LRH.2.20.2003031617400.13146%40dhcp-10-175-165-222.vpn.oracle.com.
