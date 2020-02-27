Return-Path: <kasan-dev+bncBAABB5V237ZAKGQEOHNPVZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3e.google.com (mail-yw1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C10017220D
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 16:17:12 +0100 (CET)
Received: by mail-yw1-xc3e.google.com with SMTP id a16sf5205423ywa.18
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 07:17:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582816631; cv=pass;
        d=google.com; s=arc-20160816;
        b=Du/dhyQmsqTIgPs4ivDOj4o5rAO5tOxJNaDujxGhH85h7XrZsGpOrnCTHuHSyVsi8Y
         Az7SSwnM9+DnvQoYYEFvPZKx+LeUwP9GIeB6wU+EMmUJSwmvHnlRzhIsqxZfFtpYl6LI
         A57hNDl+8LpFO3bK07FpueBSOBhEvcatd44cXb+6B80HRMO9VAIEIPsbCVNJyjRt/Ojy
         YEPQcoE8QSKPnoZf/H9zWzHdoPWnDDM81TSiH69rkgUxiKTXZ7OhJ/nBsmwhE8H5aCPK
         GXi2KkcbmU7+RweJq7GiZd5M2i8zHol0RVeXP6ByLb6fYJyhhI97Thyj67eFab8iHhvR
         7ydg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=N9JVyhWe3nxxZVFQ7ReVHhuBt+ga1x/z9+RRGqFN4TI=;
        b=hOvRJ4UUhpMaQYie+gL19IoS8YA/mSqjTZAW/gOisKoVE1SwatpfhmANAwRCOMVQs0
         tvIKVj9BLYm25W/goC/Ag6AdJZ28hrLX07dooOWsncqXjagd8dK0h2zNlJIquvlRKcJr
         gkgHNKvGsBn241oNalEAxLpK8o/3kpWVxn4qdF4UYManvirPOnjJcr7LKJWGe1CtKfbb
         TXc8EDQotMgvHqcKvwH0YRZ87gKWet4Xy1tMPCncRa+T24V0PrbXLWrH6prM6mvGsrDs
         klXYjglbbTxZcaQeDlr7Ma/OAGMqpQPb2SGDYGC68tMnwyCQ9N8Et/BKsNutvg+aLfI5
         bDbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=yxuYR0lP;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates 156.151.31.85 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=N9JVyhWe3nxxZVFQ7ReVHhuBt+ga1x/z9+RRGqFN4TI=;
        b=U8BC0XwKy5aE1Zdy1Tia2PLcCHXjOGDeXiR8qIMn9obg6paWJVE6Uqt/LOtgVr8Be8
         GHWFY/YboadwFt4f9LHkuk+bJh+chT5ILc3RsrMBbd8XB/yJNim4PqlGnXJM2S0MxN5n
         3EO7gHlK7BEHwrlTK+FrYiM3DkJIPQQptnkS+i/k68Ry1FTs7Oz5b0FQ3Rn7G/tJuGAY
         0Mt8vigiJiCtlLaCMfS82G3npq2+Xa5qkBotLDYv3D4kcuSlqc39gdauapVU0I3rW9wC
         1FDEdB6aTt28YVB6UED3DkkRrrktmPNpqgVQaXdttcUKTG0+z5C0BMOEiTEhUu9B9l+A
         TgEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N9JVyhWe3nxxZVFQ7ReVHhuBt+ga1x/z9+RRGqFN4TI=;
        b=qARKyrFEgEfqV3DXxxTscP1t6Eji6/f90gGWoCmBN/4CdX5Xx38oxoCf3PQ40hrE8w
         mvCJniH/1+mXe336F89JWwKruGo73bCVBZ239l2Pg3Zq1DQzDxHslT1Q18xaq621nLZ9
         iOQHGvPzoeY/UhSEKe0KStdt1zlDlYld5dnj/LNMZhpzCUFwoAL+NvbZgy8KbwtZQkHS
         kBp30hMdpyiYxc6P3yJVv0rJU8TjuNOqRQ3CHJvDnyte6ZHE+oNeQHtmF7y+D3sStV1E
         ZHD02tL8xnFRdwVXPFi/bawes7z61POcSbvDgR+KqGX5sA7sQuwHvZsubSTFzOGew4R+
         02sQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX745hJojCmROdZxKcTjZ5axK5EmkMoKR98Ym3V9IK6EUlqLzor
	nhydGZakjElXJYQMFQyUyXM=
X-Google-Smtp-Source: APXvYqxF3T/RVesgXF6rrksUDLwlFCp0p+ZQZ0daeC/5n25pkAxIORegL4HHLjZEwC7wNbhXXpZrZg==
X-Received: by 2002:a25:7489:: with SMTP id p131mr203200ybc.311.1582816630915;
        Thu, 27 Feb 2020 07:17:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ae04:: with SMTP id a4ls415570ybj.10.gmail; Thu, 27 Feb
 2020 07:17:10 -0800 (PST)
X-Received: by 2002:a25:e02:: with SMTP id 2mr209668ybo.279.1582816630384;
        Thu, 27 Feb 2020 07:17:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582816630; cv=none;
        d=google.com; s=arc-20160816;
        b=ib2/wJnLnjPu1aOXNJp8gRsRAzJSJGBz7SpYCcb7UCHJozGN43MEy9NZKHqoryvcoo
         Vi8yxAdTGc30mCdOFgvMwBw7Th92jtmb+szoqBt/kw13/2DSuXB00ASN5IDt3xo/yPBZ
         tyV3bDOBr60Ff53Q5VBhs/t1vKe4YUhBsGsly1v67f3MENIwzebk8UlZwVsmNX4xndVC
         HH6h66wDL6vcF+q7k7uhp3bfBTvb+rYirDehT9V6kmI0EnhayLjzoZaW+ryJOheZFf9H
         9UEpofmRPL+4N5YMgp7uC8svc2Z6mYN0i/4JkBnH5EgQmTs8rsYsmsPhFvb7wNertzAg
         5Abw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date:dkim-signature;
        bh=NIrt8DLOTCiTn1u43oa8BpUGmklEw/eKmX+oORZyk04=;
        b=X0V5azCyKOjkE8TQcTbzObNrKpEWRvhM8a//yv+Q7m6QAgSDqhnIgwZwazsbm9La1z
         579IUHgomGCFAqqrmdwS6yfCaWdGSzgEkK956TrZ98w6av3aGKrJU/srbWN18DZFr4P6
         PNwe/cDk3qjioO1UoZO0tMBNgrgcMHykEhnx+WFFwG4paYX9QIXNKxX8PHj2uc2EoVuj
         oMWXyKoVm0uodxB7rBjW8WBxs8jFPtSEsi7mqfVPoThc02nOQPmDykt2a7eK2XKAiiCg
         l56P4g5LCfowGdU9416lf+FNSac/vuofv4zm5Nf4+bkSrS2g+DXD/PWwXwgjI17KPKtC
         ghCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=yxuYR0lP;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates 156.151.31.85 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from userp2120.oracle.com (userp2120.oracle.com. [156.151.31.85])
        by gmr-mx.google.com with ESMTPS id u71si292997ywe.1.2020.02.27.07.17.10
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Feb 2020 07:17:10 -0800 (PST)
Received-SPF: pass (google.com: domain of alan.maguire@oracle.com designates 156.151.31.85 as permitted sender) client-ip=156.151.31.85;
Received: from pps.filterd (userp2120.oracle.com [127.0.0.1])
	by userp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 01RFCfhH189143;
	Thu, 27 Feb 2020 15:17:07 GMT
Received: from userp3020.oracle.com (userp3020.oracle.com [156.151.31.79])
	by userp2120.oracle.com with ESMTP id 2ydct3bjwu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 27 Feb 2020 15:17:07 +0000
Received: from pps.filterd (userp3020.oracle.com [127.0.0.1])
	by userp3020.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 01RFETgV127100;
	Thu, 27 Feb 2020 15:17:06 GMT
Received: from aserv0121.oracle.com (aserv0121.oracle.com [141.146.126.235])
	by userp3020.oracle.com with ESMTP id 2ydj4mssye-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 27 Feb 2020 15:17:06 +0000
Received: from abhmp0010.oracle.com (abhmp0010.oracle.com [141.146.116.16])
	by aserv0121.oracle.com (8.14.4/8.13.8) with ESMTP id 01RFH3tW003664;
	Thu, 27 Feb 2020 15:17:03 GMT
Received: from dhcp-10-175-190-15.vpn.oracle.com (/10.175.190.15)
	by default (Oracle Beehive Gateway v4.0)
	with ESMTP ; Thu, 27 Feb 2020 07:17:02 -0800
Date: Thu, 27 Feb 2020 15:16:53 +0000 (GMT)
From: Alan Maguire <alan.maguire@oracle.com>
X-X-Sender: alan@dhcp-10-175-190-15.vpn.oracle.com
To: Andrey Konovalov <andreyknvl@google.com>
cc: Patricia Alfonso <trishalfonso@google.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Brendan Higgins <brendanhiggins@google.com>, davidgow@google.com,
        Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>,
        juri.lelli@redhat.com, vincent.guittot@linaro.org,
        LKML <linux-kernel@vger.kernel.org>,
        kasan-dev <kasan-dev@googlegroups.com>,
        "open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>,
        kunit-dev@googlegroups.com
Subject: Re: [RFC PATCH 1/2] Port KASAN Tests to KUnit
In-Reply-To: <CAAeHK+yA1ibD2yYT++==pc5PLKfisFv3ieru54PDDYF4EE_Hfg@mail.gmail.com>
Message-ID: <alpine.LRH.2.20.2002271507110.17675@dhcp-10-175-190-15.vpn.oracle.com>
References: <20200227024301.217042-1-trishalfonso@google.com> <CAAeHK+yA1ibD2yYT++==pc5PLKfisFv3ieru54PDDYF4EE_Hfg@mail.gmail.com>
User-Agent: Alpine 2.20 (LRH 67 2015-01-07)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9543 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 bulkscore=0 phishscore=0 suspectscore=3
 spamscore=0 adultscore=0 malwarescore=0 mlxlogscore=999 mlxscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2001150001
 definitions=main-2002270121
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9543 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 lowpriorityscore=0 bulkscore=0
 impostorscore=0 spamscore=0 priorityscore=1501 malwarescore=0 adultscore=0
 phishscore=0 mlxlogscore=999 mlxscore=0 suspectscore=3 clxscore=1011
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2001150001
 definitions=main-2002270121
X-Original-Sender: alan.maguire@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=yxuYR0lP;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates
 156.151.31.85 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
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

On Thu, 27 Feb 2020, Andrey Konovalov wrote:

> On Thu, Feb 27, 2020 at 3:44 AM 'Patricia Alfonso' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > Transfer all previous tests for KASAN to KUnit so they can be run
> > more easily. With proper KASAN integration into KUnit, developers can
> > run these tests with their other KUnit tests and see "pass" or "fail"
> > with the appropriate KASAN report instead of needing to parse each KASAN
> > report to test KASAN functionalities.
> >
> > Stack tests do not work in UML so those tests are protected inside an
> > "#if (CONFIG_KASAN_STACK == 1)" so this only runs if stack
> > instrumentation is enabled.
> >
> > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > ---
> > The KUnit version of these tests could be in addition to the existing
> > tests if that is preferred.
> 
> Will it be possible to run KASAN tests with KUnit on arbitrary
> hardware/vm with arbitrary architecture (like it is possible now by
> loading test_kasan.ko)?
>

Yep - KUnit tests can be run on bare metal/VMs as
well as within a UML instance.  In the bare metal/VM
case we're working to add some ease-of-use features
such as results avaiable in /sys/kernel/debug/kunit.
Looks like CONFIG_TEST_KASAN is tristate too, so that
means it can be built as a module (KUnit itself can be
built as a module too) so running the tests becomes
a matter of executing "modprobe test_kasan.ko"; presumably
similar to what is done with non-KUnit test_kasan?

The tests execute on module loading automatically, and
results are retrievable via dmesg, and soon hopefully
via debugfs also.

I'd be really interested in any feedback regarding running
KUnit tests this way, so if you get a chance to try it
out do let us know if you see things that are missing.

Thanks!

Alan

> >
> >  lib/Kconfig.kasan |   2 +-
> >  lib/test_kasan.c  | 352 +++++++++++++++++++++-------------------------
> >  2 files changed, 161 insertions(+), 193 deletions(-)
> >
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index 5b54f3c9a741..f8cc9ed60677 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -160,7 +160,7 @@ config KASAN_VMALLOC
> >
> >  config TEST_KASAN
> >         tristate "Module for testing KASAN for bug detection"
> > -       depends on m && KASAN
> > +       depends on KASAN && KUNIT
> >         help
> >           This is a test module doing various nasty things like
> >           out of bounds accesses, use after free. It is useful for testing
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index 3872d250ed2c..988650387a2a 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -23,17 +23,18 @@
> >
> >  #include <asm/page.h>
> >
> > +#include <kunit/test.h>
> > +
> >  /*
> >   * Note: test functions are marked noinline so that their names appear in
> >   * reports.
> >   */
> >
> > -static noinline void __init kmalloc_oob_right(void)
> > +static noinline void kmalloc_oob_right(void)
> >  {
> >         char *ptr;
> >         size_t size = 123;
> >
> > -       pr_info("out-of-bounds to right\n");
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -44,12 +45,11 @@ static noinline void __init kmalloc_oob_right(void)
> >         kfree(ptr);
> >  }
> >
> > -static noinline void __init kmalloc_oob_left(void)
> > +static noinline void kmalloc_oob_left(void)
> >  {
> >         char *ptr;
> >         size_t size = 15;
> >
> > -       pr_info("out-of-bounds to left\n");
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -60,12 +60,11 @@ static noinline void __init kmalloc_oob_left(void)
> >         kfree(ptr);
> >  }
> >
> > -static noinline void __init kmalloc_node_oob_right(void)
> > +static noinline void kmalloc_node_oob_right(void)
> >  {
> >         char *ptr;
> >         size_t size = 4096;
> >
> > -       pr_info("kmalloc_node(): out-of-bounds to right\n");
> >         ptr = kmalloc_node(size, GFP_KERNEL, 0);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -77,7 +76,7 @@ static noinline void __init kmalloc_node_oob_right(void)
> >  }
> >
> >  #ifdef CONFIG_SLUB
> > -static noinline void __init kmalloc_pagealloc_oob_right(void)
> > +static noinline void kmalloc_pagealloc_oob_right(void)
> >  {
> >         char *ptr;
> >         size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
> > @@ -85,7 +84,6 @@ static noinline void __init kmalloc_pagealloc_oob_right(void)
> >         /* Allocate a chunk that does not fit into a SLUB cache to trigger
> >          * the page allocator fallback.
> >          */
> > -       pr_info("kmalloc pagealloc allocation: out-of-bounds to right\n");
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -96,12 +94,11 @@ static noinline void __init kmalloc_pagealloc_oob_right(void)
> >         kfree(ptr);
> >  }
> >
> > -static noinline void __init kmalloc_pagealloc_uaf(void)
> > +static noinline void kmalloc_pagealloc_uaf(void)
> >  {
> >         char *ptr;
> >         size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
> >
> > -       pr_info("kmalloc pagealloc allocation: use-after-free\n");
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -112,12 +109,11 @@ static noinline void __init kmalloc_pagealloc_uaf(void)
> >         ptr[0] = 0;
> >  }
> >
> > -static noinline void __init kmalloc_pagealloc_invalid_free(void)
> > +static noinline void kmalloc_pagealloc_invalid_free(void)
> >  {
> >         char *ptr;
> >         size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
> >
> > -       pr_info("kmalloc pagealloc allocation: invalid-free\n");
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -128,14 +124,13 @@ static noinline void __init kmalloc_pagealloc_invalid_free(void)
> >  }
> >  #endif
> >
> > -static noinline void __init kmalloc_large_oob_right(void)
> > +static noinline void kmalloc_large_oob_right(void)
> >  {
> >         char *ptr;
> >         size_t size = KMALLOC_MAX_CACHE_SIZE - 256;
> >         /* Allocate a chunk that is large enough, but still fits into a slab
> >          * and does not trigger the page allocator fallback in SLUB.
> >          */
> > -       pr_info("kmalloc large allocation: out-of-bounds to right\n");
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -146,13 +141,12 @@ static noinline void __init kmalloc_large_oob_right(void)
> >         kfree(ptr);
> >  }
> >
> > -static noinline void __init kmalloc_oob_krealloc_more(void)
> > +static noinline void kmalloc_oob_krealloc_more(void)
> >  {
> >         char *ptr1, *ptr2;
> >         size_t size1 = 17;
> >         size_t size2 = 19;
> >
> > -       pr_info("out-of-bounds after krealloc more\n");
> >         ptr1 = kmalloc(size1, GFP_KERNEL);
> >         ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
> >         if (!ptr1 || !ptr2) {
> > @@ -166,13 +160,12 @@ static noinline void __init kmalloc_oob_krealloc_more(void)
> >         kfree(ptr2);
> >  }
> >
> > -static noinline void __init kmalloc_oob_krealloc_less(void)
> > +static noinline void kmalloc_oob_krealloc_less(void)
> >  {
> >         char *ptr1, *ptr2;
> >         size_t size1 = 17;
> >         size_t size2 = 15;
> >
> > -       pr_info("out-of-bounds after krealloc less\n");
> >         ptr1 = kmalloc(size1, GFP_KERNEL);
> >         ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
> >         if (!ptr1 || !ptr2) {
> > @@ -184,13 +177,12 @@ static noinline void __init kmalloc_oob_krealloc_less(void)
> >         kfree(ptr2);
> >  }
> >
> > -static noinline void __init kmalloc_oob_16(void)
> > +static noinline void kmalloc_oob_16(void)
> >  {
> >         struct {
> >                 u64 words[2];
> >         } *ptr1, *ptr2;
> >
> > -       pr_info("kmalloc out-of-bounds for 16-bytes access\n");
> >         ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
> >         ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
> >         if (!ptr1 || !ptr2) {
> > @@ -204,12 +196,11 @@ static noinline void __init kmalloc_oob_16(void)
> >         kfree(ptr2);
> >  }
> >
> > -static noinline void __init kmalloc_oob_memset_2(void)
> > +static noinline void kmalloc_oob_memset_2(void)
> >  {
> >         char *ptr;
> >         size_t size = 8;
> >
> > -       pr_info("out-of-bounds in memset2\n");
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -220,12 +211,11 @@ static noinline void __init kmalloc_oob_memset_2(void)
> >         kfree(ptr);
> >  }
> >
> > -static noinline void __init kmalloc_oob_memset_4(void)
> > +static noinline void kmalloc_oob_memset_4(void)
> >  {
> >         char *ptr;
> >         size_t size = 8;
> >
> > -       pr_info("out-of-bounds in memset4\n");
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -237,12 +227,11 @@ static noinline void __init kmalloc_oob_memset_4(void)
> >  }
> >
> >
> > -static noinline void __init kmalloc_oob_memset_8(void)
> > +static noinline void kmalloc_oob_memset_8(void)
> >  {
> >         char *ptr;
> >         size_t size = 8;
> >
> > -       pr_info("out-of-bounds in memset8\n");
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -253,12 +242,11 @@ static noinline void __init kmalloc_oob_memset_8(void)
> >         kfree(ptr);
> >  }
> >
> > -static noinline void __init kmalloc_oob_memset_16(void)
> > +static noinline void kmalloc_oob_memset_16(void)
> >  {
> >         char *ptr;
> >         size_t size = 16;
> >
> > -       pr_info("out-of-bounds in memset16\n");
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -269,12 +257,11 @@ static noinline void __init kmalloc_oob_memset_16(void)
> >         kfree(ptr);
> >  }
> >
> > -static noinline void __init kmalloc_oob_in_memset(void)
> > +static noinline void kmalloc_oob_in_memset(void)
> >  {
> >         char *ptr;
> >         size_t size = 666;
> >
> > -       pr_info("out-of-bounds in memset\n");
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -285,12 +272,11 @@ static noinline void __init kmalloc_oob_in_memset(void)
> >         kfree(ptr);
> >  }
> >
> > -static noinline void __init kmalloc_uaf(void)
> > +static noinline void kmalloc_uaf(void)
> >  {
> >         char *ptr;
> >         size_t size = 10;
> >
> > -       pr_info("use-after-free\n");
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -301,12 +287,11 @@ static noinline void __init kmalloc_uaf(void)
> >         *(ptr + 8) = 'x';
> >  }
> >
> > -static noinline void __init kmalloc_uaf_memset(void)
> > +static noinline void kmalloc_uaf_memset(void)
> >  {
> >         char *ptr;
> >         size_t size = 33;
> >
> > -       pr_info("use-after-free in memset\n");
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -317,12 +302,11 @@ static noinline void __init kmalloc_uaf_memset(void)
> >         memset(ptr, 0, size);
> >  }
> >
> > -static noinline void __init kmalloc_uaf2(void)
> > +static noinline void kmalloc_uaf2(void)
> >  {
> >         char *ptr1, *ptr2;
> >         size_t size = 43;
> >
> > -       pr_info("use-after-free after another kmalloc\n");
> >         ptr1 = kmalloc(size, GFP_KERNEL);
> >         if (!ptr1) {
> >                 pr_err("Allocation failed\n");
> > @@ -342,14 +326,13 @@ static noinline void __init kmalloc_uaf2(void)
> >         kfree(ptr2);
> >  }
> >
> > -static noinline void __init kfree_via_page(void)
> > +static noinline void kfree_via_page(void)
> >  {
> >         char *ptr;
> >         size_t size = 8;
> >         struct page *page;
> >         unsigned long offset;
> >
> > -       pr_info("invalid-free false positive (via page)\n");
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -361,13 +344,12 @@ static noinline void __init kfree_via_page(void)
> >         kfree(page_address(page) + offset);
> >  }
> >
> > -static noinline void __init kfree_via_phys(void)
> > +static noinline void kfree_via_phys(void)
> >  {
> >         char *ptr;
> >         size_t size = 8;
> >         phys_addr_t phys;
> >
> > -       pr_info("invalid-free false positive (via phys)\n");
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -378,7 +360,7 @@ static noinline void __init kfree_via_phys(void)
> >         kfree(phys_to_virt(phys));
> >  }
> >
> > -static noinline void __init kmem_cache_oob(void)
> > +static noinline void kmem_cache_oob(void)
> >  {
> >         char *p;
> >         size_t size = 200;
> > @@ -389,7 +371,6 @@ static noinline void __init kmem_cache_oob(void)
> >                 pr_err("Cache allocation failed\n");
> >                 return;
> >         }
> > -       pr_info("out-of-bounds in kmem_cache_alloc\n");
> >         p = kmem_cache_alloc(cache, GFP_KERNEL);
> >         if (!p) {
> >                 pr_err("Allocation failed\n");
> > @@ -402,7 +383,7 @@ static noinline void __init kmem_cache_oob(void)
> >         kmem_cache_destroy(cache);
> >  }
> >
> > -static noinline void __init memcg_accounted_kmem_cache(void)
> > +static noinline void memcg_accounted_kmem_cache(void)
> >  {
> >         int i;
> >         char *p;
> > @@ -415,7 +396,6 @@ static noinline void __init memcg_accounted_kmem_cache(void)
> >                 return;
> >         }
> >
> > -       pr_info("allocate memcg accounted object\n");
> >         /*
> >          * Several allocations with a delay to allow for lazy per memcg kmem
> >          * cache creation.
> > @@ -435,31 +415,19 @@ static noinline void __init memcg_accounted_kmem_cache(void)
> >
> >  static char global_array[10];
> >
> > -static noinline void __init kasan_global_oob(void)
> > +static noinline void kasan_global_oob(void)
> >  {
> >         volatile int i = 3;
> >         char *p = &global_array[ARRAY_SIZE(global_array) + i];
> >
> > -       pr_info("out-of-bounds global variable\n");
> > -       *(volatile char *)p;
> > -}
> > -
> > -static noinline void __init kasan_stack_oob(void)
> > -{
> > -       char stack_array[10];
> > -       volatile int i = 0;
> > -       char *p = &stack_array[ARRAY_SIZE(stack_array) + i];
> > -
> > -       pr_info("out-of-bounds on stack\n");
> >         *(volatile char *)p;
> >  }
> >
> > -static noinline void __init ksize_unpoisons_memory(void)
> > +static noinline void ksize_unpoisons_memory(void)
> >  {
> >         char *ptr;
> >         size_t size = 123, real_size;
> >
> > -       pr_info("ksize() unpoisons the whole allocated chunk\n");
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -473,72 +441,36 @@ static noinline void __init ksize_unpoisons_memory(void)
> >         kfree(ptr);
> >  }
> >
> > -static noinline void __init copy_user_test(void)
> > +#if (CONFIG_KASAN_STACK == 1)
> > +static noinline void kasan_stack_oob(void)
> >  {
> > -       char *kmem;
> > -       char __user *usermem;
> > -       size_t size = 10;
> > -       int unused;
> > -
> > -       kmem = kmalloc(size, GFP_KERNEL);
> > -       if (!kmem)
> > -               return;
> > -
> > -       usermem = (char __user *)vm_mmap(NULL, 0, PAGE_SIZE,
> > -                           PROT_READ | PROT_WRITE | PROT_EXEC,
> > -                           MAP_ANONYMOUS | MAP_PRIVATE, 0);
> > -       if (IS_ERR(usermem)) {
> > -               pr_err("Failed to allocate user memory\n");
> > -               kfree(kmem);
> > -               return;
> > -       }
> > -
> > -       pr_info("out-of-bounds in copy_from_user()\n");
> > -       unused = copy_from_user(kmem, usermem, size + 1);
> > -
> > -       pr_info("out-of-bounds in copy_to_user()\n");
> > -       unused = copy_to_user(usermem, kmem, size + 1);
> > -
> > -       pr_info("out-of-bounds in __copy_from_user()\n");
> > -       unused = __copy_from_user(kmem, usermem, size + 1);
> > -
> > -       pr_info("out-of-bounds in __copy_to_user()\n");
> > -       unused = __copy_to_user(usermem, kmem, size + 1);
> > -
> > -       pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
> > -       unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
> > -
> > -       pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
> > -       unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
> > -
> > -       pr_info("out-of-bounds in strncpy_from_user()\n");
> > -       unused = strncpy_from_user(kmem, usermem, size + 1);
> > +       char stack_array[10];
> > +       volatile int i = 0;
> > +       char *p = &stack_array[ARRAY_SIZE(stack_array) + i];
> >
> > -       vm_munmap((unsigned long)usermem, PAGE_SIZE);
> > -       kfree(kmem);
> > +       *(volatile char *)p;
> >  }
> >
> > -static noinline void __init kasan_alloca_oob_left(void)
> > +static noinline void kasan_alloca_oob_left(void)
> >  {
> >         volatile int i = 10;
> >         char alloca_array[i];
> >         char *p = alloca_array - 1;
> >
> > -       pr_info("out-of-bounds to left on alloca\n");
> >         *(volatile char *)p;
> >  }
> >
> > -static noinline void __init kasan_alloca_oob_right(void)
> > +static noinline void kasan_alloca_oob_right(void)
> >  {
> >         volatile int i = 10;
> >         char alloca_array[i];
> >         char *p = alloca_array + i;
> >
> > -       pr_info("out-of-bounds to right on alloca\n");
> >         *(volatile char *)p;
> >  }
> > +#endif /* CONFIG_KASAN_STACK */
> >
> > -static noinline void __init kmem_cache_double_free(void)
> > +static noinline void kmem_cache_double_free(void)
> >  {
> >         char *p;
> >         size_t size = 200;
> > @@ -549,7 +481,6 @@ static noinline void __init kmem_cache_double_free(void)
> >                 pr_err("Cache allocation failed\n");
> >                 return;
> >         }
> > -       pr_info("double-free on heap object\n");
> >         p = kmem_cache_alloc(cache, GFP_KERNEL);
> >         if (!p) {
> >                 pr_err("Allocation failed\n");
> > @@ -562,7 +493,7 @@ static noinline void __init kmem_cache_double_free(void)
> >         kmem_cache_destroy(cache);
> >  }
> >
> > -static noinline void __init kmem_cache_invalid_free(void)
> > +static noinline void kmem_cache_invalid_free(void)
> >  {
> >         char *p;
> >         size_t size = 200;
> > @@ -574,7 +505,6 @@ static noinline void __init kmem_cache_invalid_free(void)
> >                 pr_err("Cache allocation failed\n");
> >                 return;
> >         }
> > -       pr_info("invalid-free of heap object\n");
> >         p = kmem_cache_alloc(cache, GFP_KERNEL);
> >         if (!p) {
> >                 pr_err("Allocation failed\n");
> > @@ -594,12 +524,11 @@ static noinline void __init kmem_cache_invalid_free(void)
> >         kmem_cache_destroy(cache);
> >  }
> >
> > -static noinline void __init kasan_memchr(void)
> > +static noinline void kasan_memchr(void)
> >  {
> >         char *ptr;
> >         size_t size = 24;
> >
> > -       pr_info("out-of-bounds in memchr\n");
> >         ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
> >         if (!ptr)
> >                 return;
> > @@ -608,13 +537,12 @@ static noinline void __init kasan_memchr(void)
> >         kfree(ptr);
> >  }
> >
> > -static noinline void __init kasan_memcmp(void)
> > +static noinline void kasan_memcmp(void)
> >  {
> >         char *ptr;
> >         size_t size = 24;
> >         int arr[9];
> >
> > -       pr_info("out-of-bounds in memcmp\n");
> >         ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
> >         if (!ptr)
> >                 return;
> > @@ -624,12 +552,11 @@ static noinline void __init kasan_memcmp(void)
> >         kfree(ptr);
> >  }
> >
> > -static noinline void __init kasan_strings(void)
> > +static noinline void kasan_strings(void)
> >  {
> >         char *ptr;
> >         size_t size = 24;
> >
> > -       pr_info("use-after-free in strchr\n");
> >         ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
> >         if (!ptr)
> >                 return;
> > @@ -645,23 +572,18 @@ static noinline void __init kasan_strings(void)
> >         ptr += 16;
> >         strchr(ptr, '1');
> >
> > -       pr_info("use-after-free in strrchr\n");
> >         strrchr(ptr, '1');
> >
> > -       pr_info("use-after-free in strcmp\n");
> >         strcmp(ptr, "2");
> >
> > -       pr_info("use-after-free in strncmp\n");
> >         strncmp(ptr, "2", 1);
> >
> > -       pr_info("use-after-free in strlen\n");
> >         strlen(ptr);
> >
> > -       pr_info("use-after-free in strnlen\n");
> >         strnlen(ptr, 1);
> >  }
> >
> > -static noinline void __init kasan_bitops(void)
> > +static noinline void kasan_bitops(void)
> >  {
> >         /*
> >          * Allocate 1 more byte, which causes kzalloc to round up to 16-bytes;
> > @@ -676,70 +598,52 @@ static noinline void __init kasan_bitops(void)
> >          * below accesses are still out-of-bounds, since bitops are defined to
> >          * operate on the whole long the bit is in.
> >          */
> > -       pr_info("out-of-bounds in set_bit\n");
> >         set_bit(BITS_PER_LONG, bits);
> >
> > -       pr_info("out-of-bounds in __set_bit\n");
> >         __set_bit(BITS_PER_LONG, bits);
> >
> > -       pr_info("out-of-bounds in clear_bit\n");
> >         clear_bit(BITS_PER_LONG, bits);
> >
> > -       pr_info("out-of-bounds in __clear_bit\n");
> >         __clear_bit(BITS_PER_LONG, bits);
> >
> > -       pr_info("out-of-bounds in clear_bit_unlock\n");
> >         clear_bit_unlock(BITS_PER_LONG, bits);
> >
> > -       pr_info("out-of-bounds in __clear_bit_unlock\n");
> >         __clear_bit_unlock(BITS_PER_LONG, bits);
> >
> > -       pr_info("out-of-bounds in change_bit\n");
> >         change_bit(BITS_PER_LONG, bits);
> >
> > -       pr_info("out-of-bounds in __change_bit\n");
> >         __change_bit(BITS_PER_LONG, bits);
> >
> >         /*
> >          * Below calls try to access bit beyond allocated memory.
> >          */
> > -       pr_info("out-of-bounds in test_and_set_bit\n");
> >         test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> >
> > -       pr_info("out-of-bounds in __test_and_set_bit\n");
> >         __test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> >
> > -       pr_info("out-of-bounds in test_and_set_bit_lock\n");
> >         test_and_set_bit_lock(BITS_PER_LONG + BITS_PER_BYTE, bits);
> >
> > -       pr_info("out-of-bounds in test_and_clear_bit\n");
> >         test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> >
> > -       pr_info("out-of-bounds in __test_and_clear_bit\n");
> >         __test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> >
> > -       pr_info("out-of-bounds in test_and_change_bit\n");
> >         test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> >
> > -       pr_info("out-of-bounds in __test_and_change_bit\n");
> >         __test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> >
> > -       pr_info("out-of-bounds in test_bit\n");
> >         (void)test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
> >
> >  #if defined(clear_bit_unlock_is_negative_byte)
> > -       pr_info("out-of-bounds in clear_bit_unlock_is_negative_byte\n");
> >         clear_bit_unlock_is_negative_byte(BITS_PER_LONG + BITS_PER_BYTE, bits);
> >  #endif
> >         kfree(bits);
> >  }
> >
> > -static noinline void __init kmalloc_double_kzfree(void)
> > +static noinline void kmalloc_double_kzfree(void)
> >  {
> >         char *ptr;
> >         size_t size = 16;
> >
> > -       pr_info("double-free (kzfree)\n");
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         if (!ptr) {
> >                 pr_err("Allocation failed\n");
> > @@ -750,29 +654,130 @@ static noinline void __init kmalloc_double_kzfree(void)
> >         kzfree(ptr);
> >  }
> >
> > -#ifdef CONFIG_KASAN_VMALLOC
> > -static noinline void __init vmalloc_oob(void)
> > +static void kunit_test_oob(struct kunit *test)
> > +{
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_right());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_left());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_node_oob_right());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_large_oob_right());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_krealloc_more());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_krealloc_less());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_16());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_in_memset());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_memset_2());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_memset_4());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_memset_8());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_oob_memset_16());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_oob());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_global_oob());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, ksize_unpoisons_memory());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_memchr());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_memcmp());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_strings());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_bitops());
> > +#ifdef CONFIG_SLUB
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_pagealloc_oob_right());
> > +#endif /* CONFIG_SLUB */
> > +
> > +#if (CONFIG_KASAN_STACK == 1)
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_stack_oob());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_alloca_oob_right());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kasan_alloca_oob_left());
> > +#endif /*CONFIG_KASAN_STACK*/
> > +}
> > +
> > +static void kunit_test_uaf(struct kunit *test)
> > +{
> > +#ifdef CONFIG_SLUB
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_pagealloc_uaf());
> > +#endif
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_uaf());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_uaf_memset());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_uaf2());
> > +}
> > +
> > +static void kunit_test_invalid_free(struct kunit *test)
> >  {
> > -       void *area;
> > +#ifdef CONFIG_SLUB
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_pagealloc_invalid_free());
> > +#endif
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_invalid_free());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_double_free());
> > +       KUNIT_EXPECT_KASAN_FAIL(test, kmalloc_double_kzfree());
> > +}
> >
> > -       pr_info("vmalloc out-of-bounds\n");
> > +static void kunit_test_false_positives(struct kunit *test)
> > +{
> > +       kfree_via_page();
> > +       kfree_via_phys();
> > +}
> >
> > -       /*
> > -        * We have to be careful not to hit the guard page.
> > -        * The MMU will catch that and crash us.
> > -        */
> > -       area = vmalloc(3000);
> > -       if (!area) {
> > -               pr_err("Allocation failed\n");
> > +static void kunit_test_memcg(struct kunit *test)
> > +{
> > +       memcg_accounted_kmem_cache();
> > +}
> > +
> > +static struct kunit_case kasan_kunit_test_cases[] = {
> > +       KUNIT_CASE(kunit_test_oob),
> > +       KUNIT_CASE(kunit_test_uaf),
> > +       KUNIT_CASE(kunit_test_invalid_free),
> > +       KUNIT_CASE(kunit_test_false_positives),
> > +       KUNIT_CASE(kunit_test_memcg),
> > +       {}
> > +};
> > +
> > +static struct kunit_suite kasan_kunit_test_suite = {
> > +       .name = "kasan_kunit_test",
> > +       .test_cases = kasan_kunit_test_cases,
> > +};
> > +
> > +kunit_test_suite(kasan_kunit_test_suite);
> > +
> > +#if IS_MODULE(CONFIG_TEST_KASAN)
> > +static noinline void __init copy_user_test(void)
> > +{
> > +       char *kmem;
> > +       char __user *usermem;
> > +       size_t size = 10;
> > +       int unused;
> > +
> > +       kmem = kmalloc(size, GFP_KERNEL);
> > +       if (!kmem)
> > +               return;
> > +
> > +       usermem = (char __user *)vm_mmap(NULL, 0, PAGE_SIZE,
> > +                           PROT_READ | PROT_WRITE | PROT_EXEC,
> > +                           MAP_ANONYMOUS | MAP_PRIVATE, 0);
> > +       if (IS_ERR(usermem)) {
> > +               pr_err("Failed to allocate user memory\n");
> > +               kfree(kmem);
> >                 return;
> >         }
> >
> > -       ((volatile char *)area)[3100];
> > -       vfree(area);
> > +       pr_info("out-of-bounds in copy_from_user()\n");
> > +       unused = copy_from_user(kmem, usermem, size + 1);
> > +
> > +       pr_info("out-of-bounds in copy_to_user()\n");
> > +       unused = copy_to_user(usermem, kmem, size + 1);
> > +
> > +       pr_info("out-of-bounds in __copy_from_user()\n");
> > +       unused = __copy_from_user(kmem, usermem, size + 1);
> > +
> > +       pr_info("out-of-bounds in __copy_to_user()\n");
> > +       unused = __copy_to_user(usermem, kmem, size + 1);
> > +
> > +       pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
> > +       unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
> > +
> > +       pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
> > +       unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
> > +
> > +       pr_info("out-of-bounds in strncpy_from_user()\n");
> > +       unused = strncpy_from_user(kmem, usermem, size + 1);
> > +
> > +       vm_munmap((unsigned long)usermem, PAGE_SIZE);
> > +       kfree(kmem);
> >  }
> > -#else
> > -static void __init vmalloc_oob(void) {}
> > -#endif
> >
> >  static int __init kmalloc_tests_init(void)
> >  {
> > @@ -782,44 +787,7 @@ static int __init kmalloc_tests_init(void)
> >          */
> >         bool multishot = kasan_save_enable_multi_shot();
> >
> > -       kmalloc_oob_right();
> > -       kmalloc_oob_left();
> > -       kmalloc_node_oob_right();
> > -#ifdef CONFIG_SLUB
> > -       kmalloc_pagealloc_oob_right();
> > -       kmalloc_pagealloc_uaf();
> > -       kmalloc_pagealloc_invalid_free();
> > -#endif
> > -       kmalloc_large_oob_right();
> > -       kmalloc_oob_krealloc_more();
> > -       kmalloc_oob_krealloc_less();
> > -       kmalloc_oob_16();
> > -       kmalloc_oob_in_memset();
> > -       kmalloc_oob_memset_2();
> > -       kmalloc_oob_memset_4();
> > -       kmalloc_oob_memset_8();
> > -       kmalloc_oob_memset_16();
> > -       kmalloc_uaf();
> > -       kmalloc_uaf_memset();
> > -       kmalloc_uaf2();
> > -       kfree_via_page();
> > -       kfree_via_phys();
> > -       kmem_cache_oob();
> > -       memcg_accounted_kmem_cache();
> > -       kasan_stack_oob();
> > -       kasan_global_oob();
> > -       kasan_alloca_oob_left();
> > -       kasan_alloca_oob_right();
> > -       ksize_unpoisons_memory();
> >         copy_user_test();
> > -       kmem_cache_double_free();
> > -       kmem_cache_invalid_free();
> > -       kasan_memchr();
> > -       kasan_memcmp();
> > -       kasan_strings();
> > -       kasan_bitops();
> > -       kmalloc_double_kzfree();
> > -       vmalloc_oob();
> >
> >         kasan_restore_multi_shot(multishot);
> >
> > @@ -827,4 +795,4 @@ static int __init kmalloc_tests_init(void)
> >  }
> >
> >  module_init(kmalloc_tests_init);
> > -MODULE_LICENSE("GPL");
> > +#endif /* IS_MODULE(CONFIG_TEST_KASAN) */
> > --
> > 2.25.0.265.gbab2e86ba0-goog
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227024301.217042-1-trishalfonso%40google.com.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.LRH.2.20.2002271507110.17675%40dhcp-10-175-190-15.vpn.oracle.com.
