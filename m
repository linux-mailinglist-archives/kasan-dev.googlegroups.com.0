Return-Path: <kasan-dev+bncBAABB564QLZQKGQEQJPQEII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 2622F17A0A6
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 08:47:05 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id bn20sf2583433qvb.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Mar 2020 23:47:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583394424; cv=pass;
        d=google.com; s=arc-20160816;
        b=1HXT02M1z1ORxgPx3Mr//38q5vidz7oT8Gof7H5pjgiFtLYOzFs3wrFllAytqHIC5E
         sYZsT4Uqdq2r+NvVoBCuwWJM1vuoL+VxdAmhXnKelVuSuoGLwc0XYIf8QhRH9OABym4W
         iMWFFO/iKV8VyLvnSgcXQs0UahIUxbHhQe6J/88CPiWKUSFuN/C8UDrlr0tFjy+PMzaB
         I1riC0smGcCiRKr6QCyGrjHlOcB7bK6jkHurftsfdv0w3umr+m6uhtZkSdRKmJ3s+XIT
         0mKNKPyKGeb/FZI9iUAv/LiR4jX8thX2Et1L1WSroyYsZ9OpimXpokIIKxD31By584hU
         d1eQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=LupCMvTyxDJfGx4jaLwTq6xQfn4JHOuiWukZqTY+EnY=;
        b=G5nM/R2YQSHfnQBBJ0I4vxQq5jaiIOiyOgr8fSO3ieYtJ+/Vgm9E2Ikebb+sJ4x9Fj
         Qx6VAsKXn8n1r5oVu2CfT+anLKoxHKvgU17U9s+T1Xw/D60wXbQbOhZqFbGkW1AGeM2z
         CmA+s2ngtvdN8q65xBJKbI9qwGoi/6pyp/NrW9AZFS9mX1q/crlVsQKcn1xAVAutYZJF
         pyJy7VRAD7LEZl9yNr3LoBIRKFVgr5F48ZuwJ07Q/g8whSh0J0IqLnQsfWmGbGtA5XeF
         Sw+kz5aKG9+u+fCcjQ8qAAjhu1fmdj7LhjsDYCMNm5yGnNkceN9GUKuFPu7TNxxhA/Po
         k/CQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=kONePS3+;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LupCMvTyxDJfGx4jaLwTq6xQfn4JHOuiWukZqTY+EnY=;
        b=cmxlCYOs/AT71hE8Xokt56cK21TvxL6msBSw/8rppi+riTzpLrFZnABilifYlLw3xA
         SagZU6KY3Vb7NnnK06PiCwmh4evDOZE3GtduvmrOB8gRb3Ugr8hWJctO5jEz0Wav8vkD
         +Xv7+r5RMaqVcJ5Eh+g+mYAOWCXxd5xaOJf+R1Xy7O5STYWpUwkHmcqTEumbMjfI0fvI
         J0g7RNtLc++TspnW7Vdt7FPD7g+Gz4aOokGDm4nFSWn8TADyIrnPJ+AmnDAYzNDkq01l
         0STSZYtnUEHnwdXKUecnOyubUCOWVnVKVuFxK0baJCjSsklisGoWAn6G3KDe7MkZGn9F
         GmGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LupCMvTyxDJfGx4jaLwTq6xQfn4JHOuiWukZqTY+EnY=;
        b=mgzzIbqw1HDhecY9VNHPgxK+vTD6QWzXRnYEKsRSiQev16TrAqAw0brNAaHPsVbuWO
         Yqr4Uk/RHpQy5FoC8CMKD2ARNIajHbtRZxbcgkq3UtmCYHWQiO5FumWNaXQA80w5rcTx
         aDho8H5JaIvGja+6sG0Bm4vTmen2Mt3MEYJp5KzkpLOkSm6psZn+EXpjAthVm1TA4S2R
         rdUq8zT0ZbwbFRaReVxojxqPg4Pzd60Kv5TSfeJs9Ypfr8UkgoXrjmXtk8kzDL2zTVNb
         1xKbf2j6a4wZ2UFzCmFVa436fT4RLSqcnMZ9OJ1V9qUGQFsd0dGBMiD4tERjVAOAbrOC
         rebQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1MuXhxgjxM9w3xNkRTGK28DC8NxAzQqzylF6t43mMUX4a96Exv
	mHR6LP3YaKmKLW3xVA3WIJ8=
X-Google-Smtp-Source: ADFU+vsF5t3w1xIyKbukPhPgdGT66F+0MEobapA0Xpb2fYgBZ8mamFpJUJj39RZKcGulAwPvMM3jvg==
X-Received: by 2002:a37:9a87:: with SMTP id c129mr6850523qke.356.1583394423796;
        Wed, 04 Mar 2020 23:47:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:b8b:: with SMTP id 133ls616091qkl.0.gmail; Wed, 04 Mar
 2020 23:47:03 -0800 (PST)
X-Received: by 2002:a37:86c1:: with SMTP id i184mr6567598qkd.386.1583394423322;
        Wed, 04 Mar 2020 23:47:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583394423; cv=none;
        d=google.com; s=arc-20160816;
        b=xY9PENqDjiy/NNNiqfcuKgGVhul9XlNrYLTUPvzddCo4hZu/AVx9HC2MCoq/LWALkA
         im3y91f0JoTohAhoCd+W8h1T41n4hYeTX/7P8mydNze8bj5ix2DZCaPrqFFi/vAevX2a
         JzVoUZ8vZ1XESYp2UAk1ZjUrOqqBaBRJHUCF42u+2RY3CVwIyiJ6A0LBNSKwPG0Mmuyl
         01LSStcCzZ6qg1YiSst0HS5j5yUl2PL8ie8S0cQVmuKIL4wVQCH+Uwt5qLZWtybHrYeh
         zoHdaBuW2KWgUXWKW8DjokTc8+hjtMMCf3/6/cLLRVkwzg3Bkh3moDuulVeNYIuxWa2w
         6Bcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date:dkim-signature;
        bh=ux8x2r/kPf0fKcTFlJFy8iR0yHnfEg1qzmsC8j4kgJ8=;
        b=EOsRRMBvz2okaPRV3zLyRrVujLBcO+1vDEKgozngEURv0IeuxHjgVaWswwmuhGo9yO
         ScsZFCzOAjJ5FccXhR5fh7PaiUwei4yAQFX0prNh5k536NAfGtMowq5DXsXsLMY9OfpA
         6LcBcgqvTeYrb9Tnp8DWE2EFysqzV1SunxICPDCAcm/OGYErnEa0etC4ZKyeyL3dntmo
         sRNYBDcwCBUITS77mEVgOUXmw5+MWpVRxh3t4s3/TZ288jmNXGs2y1lVpeNJHb66YN75
         0PBqL0e1IpuRT/3HO6KMzQKUW4+/esSmdlJhESMI1vF5lxrte54+rebkj2J3sBtynMjk
         ck1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=kONePS3+;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from aserp2120.oracle.com (aserp2120.oracle.com. [141.146.126.78])
        by gmr-mx.google.com with ESMTPS id e26si313183qka.2.2020.03.04.23.47.03
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Mar 2020 23:47:03 -0800 (PST)
Received-SPF: pass (google.com: domain of alan.maguire@oracle.com designates 141.146.126.78 as permitted sender) client-ip=141.146.126.78;
Received: from pps.filterd (aserp2120.oracle.com [127.0.0.1])
	by aserp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 0257i7BN034537;
	Thu, 5 Mar 2020 07:47:00 GMT
Received: from aserp3020.oracle.com (aserp3020.oracle.com [141.146.126.70])
	by aserp2120.oracle.com with ESMTP id 2yffwr3cqp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 05 Mar 2020 07:47:00 +0000
Received: from pps.filterd (aserp3020.oracle.com [127.0.0.1])
	by aserp3020.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 0257kl7q116951;
	Thu, 5 Mar 2020 07:46:59 GMT
Received: from userv0121.oracle.com (userv0121.oracle.com [156.151.31.72])
	by aserp3020.oracle.com with ESMTP id 2yg1ru92rv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 05 Mar 2020 07:46:59 +0000
Received: from abhmp0005.oracle.com (abhmp0005.oracle.com [141.146.116.11])
	by userv0121.oracle.com (8.14.4/8.13.8) with ESMTP id 0257kvfZ009274;
	Thu, 5 Mar 2020 07:46:57 GMT
Received: from dhcp-10-175-220-65.vpn.oracle.com (/10.175.220.65)
	by default (Oracle Beehive Gateway v4.0)
	with ESMTP ; Wed, 04 Mar 2020 23:46:56 -0800
Date: Thu, 5 Mar 2020 07:46:48 +0000 (GMT)
From: Alan Maguire <alan.maguire@oracle.com>
X-X-Sender: alan@dhcp-10-175-220-65.vpn.oracle.com
To: Patricia Alfonso <trishalfonso@google.com>
cc: Alan Maguire <alan.maguire@oracle.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Brendan Higgins <brendanhiggins@google.com>,
        David Gow <davidgow@google.com>, Ingo Molnar <mingo@redhat.com>,
        Peter Zijlstra <peterz@infradead.org>,
        Juri Lelli <juri.lelli@redhat.com>,
        Vincent Guittot <vincent.guittot@linaro.org>,
        LKML <linux-kernel@vger.kernel.org>,
        kasan-dev <kasan-dev@googlegroups.com>,
        "open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>,
        kunit-dev@googlegroups.com
Subject: Re: [RFC PATCH 2/2] KUnit: KASAN Integration
In-Reply-To: <CAKFsvUKk=ggYsRcaDrrtRuW3-A5cQh1Q5uA3NBMsnAL1nEUsLg@mail.gmail.com>
Message-ID: <alpine.LRH.2.20.2003050736090.2979@dhcp-10-175-220-65.vpn.oracle.com>
References: <20200227024301.217042-1-trishalfonso@google.com> <20200227024301.217042-2-trishalfonso@google.com> <alpine.LRH.2.20.2002271136160.12417@dhcp-10-175-190-15.vpn.oracle.com> <CAKFsvUK2hFV3LePxwBXO_ubrgYoOk7fuKMOy+vSAH5Tf3SrMOA@mail.gmail.com>
 <alpine.LRH.2.20.2003031617400.13146@dhcp-10-175-165-222.vpn.oracle.com> <CAKFsvUKk=ggYsRcaDrrtRuW3-A5cQh1Q5uA3NBMsnAL1nEUsLg@mail.gmail.com>
User-Agent: Alpine 2.20 (LRH 67 2015-01-07)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9550 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 mlxlogscore=999
 suspectscore=1 malwarescore=0 adultscore=0 spamscore=0 phishscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2001150001 definitions=main-2003050049
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9550 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 lowpriorityscore=0 spamscore=0
 impostorscore=0 malwarescore=0 mlxlogscore=999 mlxscore=0 suspectscore=1
 phishscore=0 clxscore=1015 bulkscore=0 adultscore=0 priorityscore=1501
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2001150001
 definitions=main-2003050048
X-Original-Sender: alan.maguire@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=kONePS3+;
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

On Wed, 4 Mar 2020, Patricia Alfonso wrote:

> On Tue, Mar 3, 2020 at 8:40 AM Alan Maguire <alan.maguire@oracle.com> wrote:
> >
> > On Fri, 28 Feb 2020, Patricia Alfonso wrote:
> >
> > > On Thu, Feb 27, 2020 at 6:04 AM Alan Maguire <alan.maguire@oracle.com> wrote:
> > > >
> > > > On Wed, 26 Feb 2020, Patricia Alfonso wrote:
> > > >
> > > > > Integrate KASAN into KUnit testing framework.
> > > >
> > > > This is a great idea! Some comments/suggestions below...
> > > >
> > >
> > > Thank you so much for your suggestions!
> > >
> >
> > No problem! Extending KUnit to test things like KASAN
> > is really valuable, as it shows us ways we can improve
> > the framework. More below...
> >
> > > > >  - Fail tests when KASAN reports an error that is not expected
> > > > >  - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN tests
> > > > >  - KUnit struct added to current task to keep track of the current test
> > > > > from KASAN code
> > > > >  - Booleans representing if a KASAN report is expected and if a KASAN
> > > > >  report is found added to kunit struct
> > > > >  - This prints "line# has passed" or "line# has failed"
> > > > >
> > > > > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > > > > ---
> > > > > If anyone has any suggestions on how best to print the failure
> > > > > messages, please share!
> > > > >
> > > > > One issue I have found while testing this is the allocation fails in
> > > > > kmalloc_pagealloc_oob_right() sometimes, but not consistently. This
> > > > > does cause the test to fail on the KUnit side, as expected, but it
> > > > > seems to skip all the tests before this one because the output starts
> > > > > with this failure instead of with the first test, kmalloc_oob_right().
> > > > >
> > > > >  include/kunit/test.h                | 24 ++++++++++++++++++++++++
> > > > >  include/linux/sched.h               |  7 ++++++-
> > > > >  lib/kunit/test.c                    |  7 ++++++-
> > > > >  mm/kasan/report.c                   | 19 +++++++++++++++++++
> > > > >  tools/testing/kunit/kunit_kernel.py |  2 +-
> > > > >  5 files changed, 56 insertions(+), 3 deletions(-)
> > > > >
> > > > > diff --git a/include/kunit/test.h b/include/kunit/test.h
> > > > > index 2dfb550c6723..2e388f8937f3 100644
> > > > > --- a/include/kunit/test.h
> > > > > +++ b/include/kunit/test.h
> > > > > @@ -21,6 +21,8 @@ struct kunit_resource;
> > > > >  typedef int (*kunit_resource_init_t)(struct kunit_resource *, void *);
> > > > >  typedef void (*kunit_resource_free_t)(struct kunit_resource *);
> > > > >
> > > > > +void kunit_set_failure(struct kunit *test);
> > > > > +
> > > > >  /**
> > > > >   * struct kunit_resource - represents a *test managed resource*
> > > > >   * @allocation: for the user to store arbitrary data.
> > > > > @@ -191,6 +193,9 @@ struct kunit {
> > > > >        * protect it with some type of lock.
> > > > >        */
> > > > >       struct list_head resources; /* Protected by lock. */
> > > > > +
> > > > > +     bool kasan_report_expected;
> > > > > +     bool kasan_report_found;
> > > > >  };
> > > > >
> > > >
> > > > Is this needed here? You're testing something pretty
> > > > specific so it seems wrong to add to the generic
> > > > kunit resource unless there's a good reason. I see the
> > > > code around setting these values in mm/kasan/report.c,
> > > > but I wonder if we could do something more generic.
> > > >
> > > > How about the concept of a static resource (assuming a
> > > > dynamically allocated one is out because it messes
> > > > with memory allocation tests)? Something like this:
> > > >
> > > > #define kunit_add_static_resource(test, resource_ptr, resource_field)   \
> > > >         do {                                                            \
> > > >                 spin_lock(&test->lock);                                 \
> > > >                 (resource_ptr)->resource_field.init = NULL;             \
> > > >                 (resource_ptr)->resource_field.free = NULL;             \
> > > >                 list_add_tail(&(resource_ptr)->resource_field,          \
> > > >                               &test->resources);                        \
> > > >                 spin_unlock(&test->lock);                               \
> > > >         } while (0)
> > > >
> > > >
> > > > Within your kasan code you could then create a kasan-specific
> > > > structure that embends a kunit_resource, and contains the
> > > > values you need:
> > > >
> > > > struct kasan_report_resource {
> > > >         struct kunit_resource res;
> > > >         bool kasan_report_expected;
> > > >         bool kasan_report_found;
> > > > };
> > > >
> > > > (One thing we'd need to do for such static resources is fix
> > > > kunit_resource_free() to check if there's a free() function,
> > > > and if not assume a static resource)
> > > >
> > > > If you then create an init() function associated with your
> > > > kunit suite (which will be run for every case) it can do this:
> > > >
> > > > int kunit_kasan_test_init(struct kunit *test)
> > > > {
> > > >         kunit_add_static_resource(test, &my_kasan_report_resource, res);
> > > >         ...
> > > > }
> > > >
> > > > The above should also be used to initialize current->kasan_unit_test
> > > > instead of doing that in kunit_try_run_case().  With those
> > > > changes, you don't (I think) need to change anything in core
> > > > kunit (assuming support for static resources).
> > > >
> > > > To retrieve the resource during tests or in kasan context, the
> > > > method seems to be to use kunit_resource_find(). However, that
> > > > requires a match function which seems a bit heavyweight for the
> > > > static case.  We should probably have a default "find by name"
> > > > or similar function here, and add an optional "name" field
> > > > to kunit resources to simplify things.  Anyway here you'd
> > > > use something like:
> > > >
> > > >         kasan_report_resource = kunit_resource_find(test, matchfn,
> > > >                                                     NULL, matchdata);
> > > >
> > > >
> > > > Are there any barriers to taking this sort of approach (apart
> > > > from the support for static resources not being there yet)?
> > > >
> > >
> > > I'm not sure. I don't have any experience with kunit resources so I
> > > would have to put some more effort into understanding how this would
> > > work for myself. I wonder if this might be a bit of an over
> > > complicated way of eliminating an extraneous boolean... maybe we can
> > > find a simpler solution for the first version of this patch and add
> > > the notion of a static resource for generic use later.
> > >
> >
> > My personal preference would be to try and learn what's needed
> > by KASAN and improve the KUnit APIs so the next developer finds
> > life a bit easier. More hassle for you I know, but actual use cases
> > like this are invaluable for improving the API.  I've sent
> > out an RFC patchset which has the functionality I _think_ you
> > need but I may be missing something:
> >
> > https://lore.kernel.org/linux-kselftest/1583251361-12748-1-git-send-email-alan.maguire@oracle.com/T/#t
> >
> > The idea is your test can do something like this:
> >
> > struct kasan_data {
> >         bool report_expected;
> >         bool report_found;
> > };
> >
> >
> > my_kasan_test(struct kunit *test)
> > {
> >         struct kunit_resource resource;
> >         struct kasan_data kasan_data;
> >
> > ...
> >         // add our named resource using static resource/data
> >         kunit_add_named_resource(test, NULL, NULL, &resource,
> >                                  "kasan_data", &kasan_data);
> > ...
> >
> > }
> Does this require the user to set up this kasan_data resource in each
> KASAN test? Or can we set up the resource on the KUnit side whenever a
> user writes a test that expects a KASAN failure? I've been playing
> around with it and I can only seem to get it to work when I add the
> resource within the test, but I could be missing something.
> 

The current model of resources is they are associated with
the running state of a test for the lifetime of that test.
If it's a resource common to many/most tests, I'd suggest
creating an init() function for the associated suite; this
will get run prior to executing each test, and in it you
could initialize your resource. If the resource isn't
used in the test, it doesn't really matter so this might be
the simplest way to handle things:

struct kasan_data {
         bool report_expected;
         bool report_found;
};

struct kasan_data kasan_data;
struct kunit_resource resource;

kasan_init(struct kunit *test)
{                                

         // add our named resource using static resource/data
         kunit_add_named_resource(test, NULL, NULL, &resource,
                                  "kasan_data", &kasan_data);

	return 0;
}

static struct kunit_suite kasan_suite = {
	.name = "kasan",
	.init = kasan_init,
	...
};


This all presumes however that KASAN will only need access to the
resource during the lifetime of each test.  There's currently
no concept of free-floating resources outside of test execution
context.

Alan

> >
> > (The NULLs in the function arguments above reflect the fact we
> > don't require initialization or cleanup for such static resources)
> >
> > Then, in KASAN context you can look the above resource up like so:
> >
> >         struct kunit_resource *resource;
> >         struct kasan_data *kasan_data;
> >
> >         resource = kunit_find_named_resource(test, "kasan_data");
> >         kasan_data = resource->data;
> >
> >         // when finished, reduce reference count on resource
> >         kunit_put_resource(resource);
> >
> > Does that work for your use case?
> >
> > > > >  void kunit_init_test(struct kunit *test, const char *name);
> > > > > @@ -941,6 +946,25 @@ do {                                                                            \
> > > > >                                               ptr,                           \
> > > > >                                               NULL)
> > > > >
> > > > > +/**
> > > > > + * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
> > > > > + * not cause a KASAN error.
> > > > > + *
> > > > > + */
> > > > > +#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do {        \
> > > > > +     test->kasan_report_expected = true;     \
> > > > > +     test->kasan_report_found = false; \
> > > > > +     condition; \
> > > > > +     if (test->kasan_report_found == test->kasan_report_expected) { \
> > > > > +             pr_info("%d has passed", __LINE__); \
> > > > > +     } else { \
> > > > > +             kunit_set_failure(test); \
> > > > > +             pr_info("%d has failed", __LINE__); \
> > > > > +     } \
> > > > > +     test->kasan_report_expected = false;    \
> > > > > +     test->kasan_report_found = false;       \
> > > > > +} while (0)
> > > > > +
> > > >
> > > > Feels like this belongs in test_kasan.c, and could be reworked
> > > > to avoid adding test->kasan_report_[expected|found] as described
> > > > above.
> > >
> > > You're right. Since I don't see any reason why any other tests should
> > > want to expect a KASAN error, it does make sense to move this logic
> > > inside test_kasan.c. If, in the future, there is a need for this
> > > elsewhere, we can always move it back then.
> > >
> > > >  Instead of having your own pass/fail logic couldn't you
> > > > do this:
> > > >
> > > >         KUNIT_EXPECT_EQ(test, expected, found);
> > > >
> > > > ? That will set the failure state too so no need to export
> > > > a separate function for that, and no need to log anything
> > > > as KUNIT_EXPECT_EQ() should do that for you.
> > > >
> > >
> > > This is a great idea - I feel a little silly that I didn't think of
> > > that myself! Do we think the failure message for the KUNIT_EXPECT_EQ()
> > > would be sufficient for KASAN developers?
> > > i.e. "Expected kasan_report_expected == kasan_report_found, but
> > > kasan_report_expected == true
> > > kasan_report_found == false"
> > >
> >
> > I guess the missing piece above is the line number where
> > the test failure was encountered, is that the concern?
> >
> > > > >  /**
> > > > >   * KUNIT_EXPECT_TRUE() - Causes a test failure when the expression is not true.
> > > > >   * @test: The test context object.
> > > > > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > > > > index 04278493bf15..db23d56061e7 100644
> > > > > --- a/include/linux/sched.h
> > > > > +++ b/include/linux/sched.h
> > > > > @@ -32,6 +32,8 @@
> > > > >  #include <linux/posix-timers.h>
> > > > >  #include <linux/rseq.h>
> > > > >
> > > > > +#include <kunit/test.h>
> > > > > +
> > > >
> > > > This feels like the wrong place to add this #include, and
> > > > when I attempted to build to test I ran into a bunch of
> > > > compilation errors; for example:
> > > >
> > > >  CC      kernel/sched/core.o
> > > > In file included from ./include/linux/uaccess.h:11,
> > > >                  from ./arch/x86/include/asm/fpu/xstate.h:5,
> > > >                  from ./arch/x86/include/asm/pgtable.h:26,
> > > >                  from ./include/linux/kasan.h:16,
> > > >                  from ./include/linux/slab.h:136,
> > > >                  from ./include/kunit/test.h:16,
> > > >                  from ./include/linux/sched.h:35,
> > > >                  from init/do_mounts.c:3:
> > > > ./arch/x86/include/asm/uaccess.h: In function 'set_fs':
> > > > ./arch/x86/include/asm/uaccess.h:32:9: error: dereferencing pointer to
> > > > incomplete type 'struct task_struct'
> > > >   current->thread.addr_limit = fs;
> > > >
> > > > (I'm testing with CONFIG_SLUB). Removing this #include
> > > > resolves these errors, but then causes problems for
> > > > lib/test_kasan.c. I'll dig around a bit more.
> > > >
> > >
> > > Yes, I was only testing with UML. Removing that #include fixed the
> > > problem for me for both x86 and UML. Could you share more about the
> > > errors you have encountered in lib/test_kasan.c?
> > >
> >
> > I'll try this again and send details.
> >
> > I think broadly the issue is that if we #include kunit headers
> > in the kasan headers, we end up creating all kinds of problems
> > for ourselves, since the kasan headers are in turn included
> > in so many places (including the kunit headers themselves, since
> > kunit uses memory allocation APIs). I suspect the way forward is
> > to try and ensure that we don't utilize the kunit headers in any
> > of the kasan headers, but rather just include kunit headers
> > in test_kasan.c, and any other kasan .c files we need KUnit APIs
> > for. Not sure if that's possible, but it's likely the best way to
> > go if it is.
> >
> > > > >  /* task_struct member predeclarations (sorted alphabetically): */
> > > > >  struct audit_context;
> > > > >  struct backing_dev_info;
> > > > > @@ -1178,7 +1180,10 @@ struct task_struct {
> > > > >
> > > > >  #ifdef CONFIG_KASAN
> > > > >       unsigned int                    kasan_depth;
> > > > > -#endif
> > > > > +#ifdef CONFIG_KUNIT
> > > > > +     struct kunit *kasan_kunit_test;
> > > > > +#endif /* CONFIG_KUNIT */
> > > > > +#endif /* CONFIG_KASAN */
> > > > >
> > > > >  #ifdef CONFIG_FUNCTION_GRAPH_TRACER
> > > > >       /* Index of current stored address in ret_stack: */
> > > > > diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> > > > > index 9242f932896c..d266b9495c67 100644
> > > > > --- a/lib/kunit/test.c
> > > > > +++ b/lib/kunit/test.c
> > > > > @@ -9,11 +9,12 @@
> > > > >  #include <kunit/test.h>
> > > > >  #include <linux/kernel.h>
> > > > >  #include <linux/sched/debug.h>
> > > > > +#include <linux/sched.h>
> > > > >
> > > > >  #include "string-stream.h"
> > > > >  #include "try-catch-impl.h"
> > > > >
> > > > > -static void kunit_set_failure(struct kunit *test)
> > > > > +void kunit_set_failure(struct kunit *test)
> > > > >  {
> > > > >       WRITE_ONCE(test->success, false);
> > > > >  }
> > > > > @@ -236,6 +237,10 @@ static void kunit_try_run_case(void *data)
> > > > >       struct kunit_suite *suite = ctx->suite;
> > > > >       struct kunit_case *test_case = ctx->test_case;
> > > > >
> > > > > +#ifdef CONFIG_KASAN
> > > > > +     current->kasan_kunit_test = test;
> > > > > +#endif
> > > > > +
> > > > >       /*
> > > > >        * kunit_run_case_internal may encounter a fatal error; if it does,
> > > > >        * abort will be called, this thread will exit, and finally the parent
> > > > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > > > index 5ef9f24f566b..5554d23799a5 100644
> > > > > --- a/mm/kasan/report.c
> > > > > +++ b/mm/kasan/report.c
> > > > > @@ -32,6 +32,8 @@
> > > > >
> > > > >  #include <asm/sections.h>
> > > > >
> > > > > +#include <kunit/test.h>
> > > > > +
> > > > >  #include "kasan.h"
> > > > >  #include "../slab.h"
> > > > >
> > > > > @@ -461,6 +463,15 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
> > > > >       u8 tag = get_tag(object);
> > > > >
> > > > >       object = reset_tag(object);
> > > > > +
> > > > > +     if (current->kasan_kunit_test) {
> > > > > +             if (current->kasan_kunit_test->kasan_report_expected) {
> > > > > +                     current->kasan_kunit_test->kasan_report_found = true;
> > > > > +                     return;
> > > > > +             }
> > > > > +             kunit_set_failure(current->kasan_kunit_test);
> > > > > +     }
> > > > > +
> > > > >       start_report(&flags);
> > > > >       pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
> > > > >       print_tags(tag, object);
> > > > > @@ -481,6 +492,14 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
> > > > >       if (likely(!report_enabled()))
> > > > >               return;
> > > > >
> > > > > +     if (current->kasan_kunit_test) {
> > > > > +             if (current->kasan_kunit_test->kasan_report_expected) {
> > > > > +                     current->kasan_kunit_test->kasan_report_found = true;
> > > > > +                     return;
> > > > > +             }
> > > > > +             kunit_set_failure(current->kasan_kunit_test);
> > > > > +     }
> > > > > +
> > > > >       disable_trace_on_warning();
> > > > >
> > > > >       tagged_addr = (void *)addr;
> > > > > diff --git a/tools/testing/kunit/kunit_kernel.py b/tools/testing/kunit/kunit_kernel.py
> > > > > index cc5d844ecca1..63eab18a8c34 100644
> > > > > --- a/tools/testing/kunit/kunit_kernel.py
> > > > > +++ b/tools/testing/kunit/kunit_kernel.py
> > > > > @@ -141,7 +141,7 @@ class LinuxSourceTree(object):
> > > > >               return True
> > > > >
> > > > >       def run_kernel(self, args=[], timeout=None, build_dir=''):
> > > > > -             args.extend(['mem=256M'])
> > > > > +             args.extend(['mem=256M', 'kasan_multi_shot'])
> > > > >               process = self._ops.linux_bin(args, timeout, build_dir)
> > > > >               with open(os.path.join(build_dir, 'test.log'), 'w') as f:
> > > > >                       for line in process.stdout:
> > > >
> > > > I tried applying this to the "kunit" branch of linux-kselftest, and
> > > > the above failed. Which branch are you building with? Probably
> > > > best to use the kunit branch I think. Thanks!
> > > >
> > > I believe I am on Torvalds/master. There was some debate as to which
> > > branch I should be developing on when I started, but it probably makes
> > > sense for me to move to the "kunit" branch.
> > >
> >
> > I think for this case - given that we may need some new KUnit
> > functionality - that would be best. Thanks!
> >
> > Alan
> >
> > > > Alan
> > > >
> > > > > --
> > > > > 2.25.0.265.gbab2e86ba0-goog
> > > > >
> > > > >
> > >
> > > --
> > > Thank you for all your comments!
> > > Patricia Alfonso
> > >
> 
> 
> 
> -- 
> 
> Patricia Alfonso
> Software Engineer
> trishalfonso@google.com
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.LRH.2.20.2003050736090.2979%40dhcp-10-175-220-65.vpn.oracle.com.
