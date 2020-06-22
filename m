Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2F6YP3QKGQEFERXIPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id E0E0B203CC3
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 18:42:17 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id z17sf7738812pfc.10
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 09:42:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592844136; cv=pass;
        d=google.com; s=arc-20160816;
        b=V1W4rrgZPzTuAR5LTnAFa2qUh7oJGJLm05qXrYhAf1iVoPG3abw+cUQqW0nTK0E04Y
         Ej3q/L9QCeNN8CP9R0tqyygMG065uiAHn1eFHrcR4dATg8kxC0jYufDl9PXmGTin4xwV
         i/KCgmkC/zkrcWCapSFJztGeEH46hunWop5UfPh6pGePzKezxM0U3LzCGi8+6Th7ckSo
         R74abj9GN1pXBlxpHYzNvYu9g9I+cXLJ3TrVge3o3uSextmR9tuE+e7/XEfIjJ+9epMy
         IECIzdYjg8tfNITYdHxNFL5WVzctJknyc5dh9x5MJKKX/bjVDbe2OCC4SCXEzgC05hfd
         Ul1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ma53x1ImZcLeCsCYEM4/161FMOGpRigf/7kEgroFAPk=;
        b=PRocEnH87td6V+XzO42vXCFP30Dqiw4SYUh0Jl3oiW2wITe39XjIzkvZUqjnuIA22U
         o03rw4zftBrPm0spglz2+UX6Q82GFT5CisF5qhj4hLtrCqkl3RAuQTV/GYCLF+VThenW
         gI/5QHIFS5cHHXtvGnCa7bw/JD4RzumVOFUcNsyNUdNhz1/SqX81dxnYtaRhfqG1IWcX
         IkKacyhvzI+t3j7ocpLvmuuQEvVZc/XxTwEbxGxVpzB273xZnYOiFM0j5TH6l5ixVDVL
         49u8q+nLev/WveM7wFvinEngtdqKcTCQWv1fz9SyK72+iJfPihH6b4rk06mjwE/JXkDW
         VOiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="SN/6KR4R";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ma53x1ImZcLeCsCYEM4/161FMOGpRigf/7kEgroFAPk=;
        b=TIn+7GAnhjI93NRfqjT9UDmLojcpmvdk4Kn4kUgLZJOHtDvzsg0fkI/dMRWH6LYCLP
         2w21f/GATOPRW/UtGq+1LLGj+FjQH0gs7/RMglvnz1PLnwhWNwOPIcMZ+V1+UR37/Zrw
         fp9sVMbesRjeDYO/ulCuaNMeMQy4Vg0ivXowuKL9Vc3qQI3PnZr8Qe7eexftN4E8NHLh
         zHIxB1R8Es6c2ryBDx3cf/KBLzJVM1a3ZxMDmu/kGgYuJwOYGbPDmC7FbPsGa0uiHa2P
         FGNE65+J0ebzhIfpwHzCUWpWn9r/OKdsuC33rDyWE1jv86KP+l2LTguqDLukMx20EGej
         uCLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ma53x1ImZcLeCsCYEM4/161FMOGpRigf/7kEgroFAPk=;
        b=ilvt5M6J9Xeu2UbE6LCAhlh4vgV72gmXJ6IUryqGQW6bLJdBMHWMb0/jX1HRJkzEMV
         S3EgGnH+cp8nfadiOPFC5gcyzWqqZfgSDIrfDhAnjYtO0MDEDbaASNcdcmvKV0XQ5eIE
         cQgAACOpkasPd4mzp28LhWUzukpKK3ZFm6dn8pLixu7A0V+FE9bm99rc/jHie3sOoLFM
         yDa6+uM+Re6PxLmoJYcnzXcrxRJBEkBc9RIaLOXmEUkZh3Ji7tMEtLBbLyhoj7skgn4h
         oSa6wEtMUyOOGJr29tPKvGxC4XhpQBN9sYpwts+0nxpzR9lz4SOi68yRX5pDQnKGM+dq
         /Jdg==
X-Gm-Message-State: AOAM531UpPCzSX7WTs+rZXvm7hSYjDDTXPX35wTJd3gvqARPPOGXy/Eo
	91mHIt2FsV/xjugQw27mBao=
X-Google-Smtp-Source: ABdhPJxZ21ai3PNBVF0ti3+qyaO1O51pCWi95VIgaUQNoC1ejqPSvZlq08hwL6e2mRS6NTzvcsUNkQ==
X-Received: by 2002:a63:d250:: with SMTP id t16mr426621pgi.51.1592844136259;
        Mon, 22 Jun 2020 09:42:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:3c0d:: with SMTP id j13ls4134007pga.8.gmail; Mon, 22 Jun
 2020 09:42:15 -0700 (PDT)
X-Received: by 2002:a65:4807:: with SMTP id h7mr13921160pgs.123.1592844135764;
        Mon, 22 Jun 2020 09:42:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592844135; cv=none;
        d=google.com; s=arc-20160816;
        b=GTYCRNJulG0nK3lwtMVUVBhfwXXGMCrTxzHVHoh0Qfjr34udxOFci4/1G2KjCYgRvm
         3CmGLvuqwS1nECCh0axuwDKE4pGxXfkfeUMDKI1bz/ZQ8avpp+q5DIV1BDpqgEGERd6H
         1c/YRJWV1mSTeHFDS4j08j6c5U0G14bskVWxrCJAVFv2eJNz2DrDC8Tf13kFFp4xBeIe
         1ASCNoAlqfqRgFAPPpyt8mO/OLsoYNs9rK7tQc2FOdsnKZfU0KicqeQiH6VUS8BalQ7I
         IZNacqf6JDp2P/FBKYgKMwrXc91bszjXBNfjhIE8LtRQJMlK90YZVQR++66prguPFmnK
         V4hA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3w1YEYVA5zf1FjXYc6l2ppC9+AyiEWZII1bwI7+dIi8=;
        b=jTBoc6hDPwrbQdStxcxQSPCa86h3xKJolrHkPWuVhWTRGg/jBdmJHp5Vd91mDXbVKB
         paIPWmlSb+wmSg1uz//SrxEyLWpidraNbjQXxJ4aUqPsGE45F4bDcmpx6SFpVOSK+CrO
         m2YHze8VSlC9GZlcFUDStRaoGvyHBXyHTV2VQl1BJEyY6Fc7gwbWy/54LPlK4NRiRhep
         k6Zd85ilMfNIRNa+qOYy9VWq+MY8Ykl5DvSxUKqZW237Wtejhz+LsB5YPIE5H2YJa/y1
         845/Q1lyDOSlUd1dxlGJ6TqhFn6Iw8d/MW47KoFTeHCPw7YoZDQGyxi01zEJz6AP9Ih9
         d8tw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="SN/6KR4R";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id q1si757593pgg.5.2020.06.22.09.42.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Jun 2020 09:42:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id d4so13589079otk.2
        for <kasan-dev@googlegroups.com>; Mon, 22 Jun 2020 09:42:15 -0700 (PDT)
X-Received: by 2002:a9d:638c:: with SMTP id w12mr12026689otk.251.1592844134762;
 Mon, 22 Jun 2020 09:42:14 -0700 (PDT)
MIME-Version: 1.0
References: <20200618011657.hCkkO%akpm@linux-foundation.org>
 <20200618081736.4uvvc3lrvaoigt3w@wittgenstein> <20200618082632.c2diaradzdo2val2@wittgenstein>
 <263d23f1-fe38-8cb4-71ee-62a6a189b095@huawei.com> <9BFEC318-05AE-40E1-8A1F-215A9F78EDC2@ubuntu.com>
 <20200618121545.GA61498@elver.google.com> <20200618165035.wpu7n7bud7rwczyt@wittgenstein>
 <20200619112006.GB222848@elver.google.com> <20200622090421.cw5r2ta3juizvkmq@wittgenstein>
In-Reply-To: <20200622090421.cw5r2ta3juizvkmq@wittgenstein>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 22 Jun 2020 18:42:03 +0200
Message-ID: <CANpmjNMUrPpc9+opgFC46P0MKkzkZD3cZ3c72TGoTNnGrTKQLw@mail.gmail.com>
Subject: Re: + kernel-forkc-annotate-data-races-for-copy_process.patch added
 to -mm tree
To: Christian Brauner <christian.brauner@ubuntu.com>
Cc: Weilong Chen <chenweilong@huawei.com>, Andrew Morton <akpm@linux-foundation.org>, 
	mm-commits@vger.kernel.org, Thomas Gleixner <tglx@linutronix.de>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Oleg Nesterov <oleg@redhat.com>, lizefan@huawei.com, 
	Qian Cai <cai@lca.pw>, Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="SN/6KR4R";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 22 Jun 2020 at 11:04, Christian Brauner
<christian.brauner@ubuntu.com> wrote:
>
> On Fri, Jun 19, 2020 at 01:20:06PM +0200, Marco Elver wrote:
> > On Thu, Jun 18, 2020 at 06:50PM +0200, Christian Brauner wrote:
> > > On Thu, Jun 18, 2020 at 02:15:45PM +0200, Marco Elver wrote:
> > > > On Thu, Jun 18, 2020 at 01:38PM +0200, Christian Brauner wrote:
> > [...]
> > > > >
> > > > > Both mails seem to have been caught by spam at least I don't see them anywhere in my mails.
> > > > > I'd also need to check what protects nr_threads and I'm confused why that data race would exist if it's protected by the lock pointed at in the second response but I'm not near a computer until late tonight.
> > > > >
> > > > > That commit log still isn't anywhere near clear enough for this to be included.
> > > > >
> > > > > The report also isn't coming from kcsan upstream and apparently based on a local test.
> > > > > What does that test look like and how can it be reproduced?
> > > > > Unless we see a proper report from syzbot/kcsan upstream about this I think we can simply ignore this.
> > > >
> > > > We have this report, back from January:
> > > >
> > > >   https://syzkaller.appspot.com/bug?extid=52fced2d288f8ecd2b20
> > > >   https://groups.google.com/forum/#!msg/syzkaller-upstream-moderation/thvp7AHs5Ew/aPdYLXfYBQAJ
> > > >
> > > > So if this patch is amended, it'd be useful to also add for syzbot's
> > > > benefit:
> > > >
> > > >   Reported-by: syzbot+52fced2d288f8ecd2b20@syzkaller.appspotmail.com
> > > >
> > > > The line numbers of that report match what's shown in the patch (they
> > > > seem to be from 5.7-rc1), but definitely don't match mainline anymore!
> > > >
> > > > We're in the process of switching the syzbot KCSAN instance to use
> > > > mainline, because all the reports right now are out-of-date (either they
> > > > moved or some were fixed, etc.). Once that's done, more reports should
> > > > be sent to LKML directly again.
> > >
> > > Hey Marco,
> > >
> > > Ok, good. What's the overall strategy here? This seems to be a generic
> > > problem with sysctls and a quite few global variables too. Is the
> > > strategy to amend these all with data_race() most of the time where we
> > > don't care? Has there been some discussion around this already and
> > > should there be some before we start doing this?
> >
> > For the change here, I would almost say 'data_race(nr_threads)' is
> > adequate, because it seems to be a best-effort check as suggested by the
> > comment above it. All other accesses are under the lock, and if they
>
> If we take this patch it needs to:
> - have a link to the upstream KCSAN bug report (see below why I think
>   that's important)
> - explain in clear terms why marking this as data_race() makes sense
>   (Doesn't need to be perfect, I'm happy to end up editing commit
>   messages when necessary.)

That sounds very reasonable.

FWIW, checkpatch.pl already warns if data_race() doesn't have a comment.

> > weren't KCSAN would tell you.
> >
> > But, for most of the apparently "benign" races like here, it's back to
> > the question about assumptions we make about the architecture and
> > compiler.  Although it's nearly impossible to prove that on all
> > architectures with all compilers, a data race won't break intended
> > behaviour, a simple question I would ask is:
> >
> >       If 'data_race(nr_threads)' was replaced with
> >       'random_if_concurrent_writers(nr_threads)', what will break?
> >
> > Even if the data race is meant to stay today, IMHO simply marking it
> > 'data_race()' is better than leaving it alone, because at least then we
> > have a list of accesses we should be suspicious of in case things break
> > around there.
> >
> > In an ideal world we end up eliminating all unintentional data races by
> > marking (whether it be *ONCE, data_race, atomic, etc.) because it makes
> > the code more readable and the tools then know what the intent is.
>
> Right, the problem is that in quite a few places this also means a lot
> of additional information needs to be processed when reading kernel
> code. So there needs to be some balance.

True, there are 2 sides to this: either 1) mark/annotate/comment and
readers/reviewers have to process this information when changing
things around, or 2) don't mark, but then the information has to be
inferred or re-established at the very least when things went wrong.

> > Some of what I said above is probably better discussed in
> > https://lwn.net/Articles/816854/ in the section "Developer/Maintainer
> > data-race strategies".
> >
> > Thoughts?
> >
> > Another thing that would be good to figure out is, if we send individual
> > reports one-by-one to LKML, or some alternative. One alternative would
>
> I'm not sure I can answer this. It seems like something that could be a
> great kernel summit discussion.

Definitely would be good to discuss. Let me try and figure out some ideas.

> > be to go check the syzbot dashboard and have a look through reports in
> > code that is of interest before they're sent to LKML. Although a lot of
> > the data races are still hidden in some moderation queue, would it be
> > useful to somehow make this visible?
>
> Yes, I think it would help to have them visible or at least let people
> request access?

Let me figure out what the best thing to do here is. We could just
pipe all of them straight to public moderation.

Those can already be seen here:
https://syzkaller.appspot.com/upstream?manager=ci2-upstream-kcsan-gce
("open" being those sent to LKML, and "moderation" those in
https://groups.google.com/forum/#!forum/syzkaller-upstream-moderation).

> The problem that I have right now is when I receive a data-race patch
> like this I'm not inclined to ack and take it unless I see this is a bug
> report from an agreed upon upstream tool like syzbot or kcsan. Not just
> can I then link to a standard bug report that everyone recognizes, I can
> also be sure that this is based on a consensus that these types of bugs
> are worth fixing. The latter part is quite important, I think. Most of
> these (benign) races have existed for such a long time that sending
> patches for them better be thoroughly justified.

My guess is we need some better structure for reports, fixes, commit
logs. Would it be useful to come up with some concrete
recommendations?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMUrPpc9%2BopgFC46P0MKkzkZD3cZ3c72TGoTNnGrTKQLw%40mail.gmail.com.
