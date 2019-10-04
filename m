Return-Path: <kasan-dev+bncBCMIZB7QWENRBZ4633WAKGQEQ33RSSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EDE8CC2AA
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2019 20:28:56 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id i10sf7342062qtq.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2019 11:28:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570213735; cv=pass;
        d=google.com; s=arc-20160816;
        b=0Laj+NKIMKL3iFuh/GTwLyiV914nb/e+QRl3SCxbsInU7RLDLdfSefkbFjbflMgCjx
         c3Q5+3M2SVcbyCbWQg8D0zcT2n5kALPmALk2ssF7YSv4yyvTlTHTb5w3sZdJyU6MpkTb
         0CqvZoqmCK3Yvqy5nslyGjPAe3HUzU0Gsc/2vK+dYHPDWnjBtpTTWOQY0Z2sOmR7gcCo
         a8sZF43SQF30nv24dSvFRXIolS8NA2V9pwoWRNpQuqXaZ2MrvVvz3Pb9UAemcWh8M46B
         ZrVLCIoEk7n8qj6bgwsLPX0XYCagVSFnKLApLTmnngpJLC2PkNJ/vjYZLi17LiUmzS9o
         tCbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qLiNjKadlu9WkjbOz6JIp+86PvKC98lNCwV95S6XNhE=;
        b=RsiTNRYOyk0nPi7QO0ykSR1v88ru97Fxf+7KW5K2moEurpLkLSK3KNC/ojc5leTQcL
         Fn3bacobs/S/40lwwn4w251PughkHvW7uaV7V+I0+v6mkqWrWkAIk/qJLxpPEFBXvaXC
         iKIBFje6Don4QxMZ7MJ+kwOWBzzNKoAvA9UC5819ltaUuK32vVsM40GZOE58xTUMMxKo
         BV8PbyzCmsDIhdUjB+tP9lZ14RoB034CFPrJ8mlFqrJ6BJw6Q1bNntEo6gQc9YZ7/Ytj
         jC1fiUPQNRrKm5q6QE6m11dKCdnwW5b3/cS0zyVCVuW5yl9s7LhyQfw+G8b5k8ecSQXw
         m7Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Zm45PcY2;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qLiNjKadlu9WkjbOz6JIp+86PvKC98lNCwV95S6XNhE=;
        b=A5cimzTPL9/hpI8MNQLnNojOmwiUSUWiZAzA8SmezsGtyGu+OczMlnat4HkXpc2xJk
         eo31t/z+Rsjj5+3r7MLMd1vZ9B/XxOUEtTdQ1jnrslH3QYad0Se6/UEVqq4y9g68xsxy
         5v5xb00efmGILYd1SlHxEGFuikKlwuhkRH2E73LklZJLcehyrrgNFeB1hkXNDbN5Ar0R
         XN1z/Mpn/oQJ32WMK/7Iq6PNF8SRFHlPT0YGiugf8A08WtCrVuTLC51OHv/7pORzU3M7
         Y55lakMgwNbSMpN+aNM6WjZc2IsJxJ4FrJiL3x9GJL5Of3YRcpz3QSPt+pEA52pwLJev
         Cs/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qLiNjKadlu9WkjbOz6JIp+86PvKC98lNCwV95S6XNhE=;
        b=mPHdukNJ4524s+FRtstsQGgUCcQKuNcfQ0yKrc3OHoXZ1Yd7gSg0tkr9HwSU6iqKhJ
         K5PFuHUF7vKAACEkpjh1a3Nzaj7ZazGwVUlfWeJrxBCStOlnypdN0g3LRX2p5jXKC3rx
         4OT0PS89vYMVSNWs+6pDyaDV0Zrk2m7heJfQTgn/Tui6hF+6FyN3kXIp9SWAMiRE+4Wp
         zTfLfhBKPBgdEvraMflN4719XT9hSVe3HyiYpD6Cg+n3oHGra/ruadUC08isgbazuBOP
         WzciBdSg3Y2369A4sV4J/SYtAEN0ssRtF8ua20x5j2JDHGhXtDarYJQpGlUi5d9QEgEr
         QLiw==
X-Gm-Message-State: APjAAAUH1sKfzYslDXy0+VeKltkfoEwFOutP8gGTivDGEgMsZj0fukGS
	jZ5dG2458T6jkMWKW0GWnsw=
X-Google-Smtp-Source: APXvYqxkdprCC1Lxg8eaHGQufxiIMBeklG+SYGogAEwjMp/Ty6VW9efVpQjxA9MDD5iDNGMCVvc1Ow==
X-Received: by 2002:ac8:70c8:: with SMTP id g8mr17724831qtp.272.1570213735196;
        Fri, 04 Oct 2019 11:28:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:45b4:: with SMTP id y20ls1766693qvu.4.gmail; Fri, 04 Oct
 2019 11:28:54 -0700 (PDT)
X-Received: by 2002:a05:6214:281:: with SMTP id l1mr15212303qvv.224.1570213734819;
        Fri, 04 Oct 2019 11:28:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570213734; cv=none;
        d=google.com; s=arc-20160816;
        b=jvRiROhjdJED/TV+MXtFOrZFdvJEbWVfMAbZyk1bdwVU0pGUVYp7mnqAHA1mk6o2/K
         iJ+Rr5LrehOSkW2hXlSgWH4W4GxPdMASx7mGd8rTtNdUCZU7GB8WlGa+9/33kodGwFp8
         LdlBaf1l22hSltvmxPaapXJ6K8R/pFtn/GpWVWqicnVz2CktDdklWBKm4ixjEVZj08Qt
         pEfRJQSMKLUn0LG2nPxo/sJl4hEMleb/V4aCJ1ho7D/C/j7Wc0naroh2zLrF2xQgULT0
         rOWrT+t4IUs1z8u7kE4Mwevzk152W0rtknj7JFmM+5ZVbP8X7YSmOuievhdhRCCVE/sm
         wncA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XKTE+CPRe5jd94ICvF2hQ8zNqLxfi/uYBmbl92O68Kw=;
        b=qkWBwzUzczHyZ3Y56i+fui4U5sjp6dFUmit+c44sT+BtsMmkdVr09XkTchRghKSGNu
         ZW/8q5rVyssvokteMgim3qlA9ORGCB8gf5zvLBWLkiCy2F6gSuBVpiFKYDl43dthNOXf
         sxkthyR/XhCJidosPDm1ZXQ/4vJWSz9bMPEQqUd0HcvMmH0Friykms0NIQ2tVSR9PYGn
         iFdgGqQIqchwvf+clWJeh5o46hpSDYn9Mg785V4iRPnQ/g6WgJ5w/oGPbW5NBFn+r9vR
         zFZNTYWBT5QsDyF+BIOp68sAm09BkIxL/2F4WhDtZPg5t1RB3YO+O8bb29IQaKPcwrYw
         111A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Zm45PcY2;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id t187si192916qkd.0.2019.10.04.11.28.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Oct 2019 11:28:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id c21so9787413qtj.12
        for <kasan-dev@googlegroups.com>; Fri, 04 Oct 2019 11:28:54 -0700 (PDT)
X-Received: by 2002:a0c:facc:: with SMTP id p12mr15620694qvo.80.1570213733780;
 Fri, 04 Oct 2019 11:28:53 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20191001211948.GA42035@google.com> <CANpmjNNp=zVzM2iGcQwVYxzNHYjBo==_2nito4Dw=kHopy=0Sg@mail.gmail.com>
 <20191004164859.GD253167@google.com> <CACT4Y+bPZOb=h9m__Uo0feEshdGzPz0qGK7f2omsUc6-kEvwZA@mail.gmail.com>
 <20191004165736.GF253167@google.com> <CACT4Y+aEHmbLin_5Od++WVqgiFX7hkjARGgVK0QUj7eUpFLVeg@mail.gmail.com>
 <20191004180848.GH253167@google.com>
In-Reply-To: <20191004180848.GH253167@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Oct 2019 20:28:42 +0200
Message-ID: <CACT4Y+aHQGHaeX4EkD=HeK5j9968BH+zHnVxs6k_c1XvVMGAoQ@mail.gmail.com>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Joel Fernandes <joel@joelfernandes.org>
Cc: Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, Paul Turner <pjt@google.com>, 
	Daniel Axtens <dja@axtens.net>, Anatol Pomazau <anatol@google.com>, Will Deacon <willdeacon@google.com>, 
	Andrea Parri <parri.andrea@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Nicholas Piggin <npiggin@gmail.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Daniel Lustig <dlustig@nvidia.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Luc Maranget <luc.maranget@inria.fr>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Zm45PcY2;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
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

" On Fri, Oct 4, 2019 at 8:08 PM Joel Fernandes <joel@joelfernandes.org> wrote:
> > > > > > > > Hi all,
> > > > > > > >
> > > > > > > > We would like to share a new data-race detector for the Linux kernel:
> > > > > > > > Kernel Concurrency Sanitizer (KCSAN) --
> > > > > > > > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > > > > > > > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> > > > > > > >
> > > > > > > > To those of you who we mentioned at LPC that we're working on a
> > > > > > > > watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> > > > > > > > renamed it to KCSAN to avoid confusion with KTSAN).
> > > > > > > > [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
> > > > > > > >
> > > > > > > > In the coming weeks we're planning to:
> > > > > > > > * Set up a syzkaller instance.
> > > > > > > > * Share the dashboard so that you can see the races that are found.
> > > > > > > > * Attempt to send fixes for some races upstream (if you find that the
> > > > > > > > kcsan-with-fixes branch contains an important fix, please feel free to
> > > > > > > > point it out and we'll prioritize that).
> > > > > > > >
> > > > > > > > There are a few open questions:
> > > > > > > > * The big one: most of the reported races are due to unmarked
> > > > > > > > accesses; prioritization or pruning of races to focus initial efforts
> > > > > > > > to fix races might be required. Comments on how best to proceed are
> > > > > > > > welcome. We're aware that these are issues that have recently received
> > > > > > > > attention in the context of the LKMM
> > > > > > > > (https://lwn.net/Articles/793253/).
> > > > > > > > * How/when to upstream KCSAN?
> > > > > > >
> > > > > > > Looks exciting. I think based on our discussion at LPC, you mentioned
> > > > > > > one way of pruning is if the compiler generated different code with _ONCE
> > > > > > > annotations than what would have otherwise been generated. Is that still on
> > > > > > > the table, for the purposing of pruning the reports?
> > > > > >
> > > > > > This might be interesting at first, but it's not entirely clear how
> > > > > > feasible it is. It's also dangerous, because the real issue would be
> > > > > > ignored. It may be that one compiler version on a particular
> > > > > > architecture generates the same code, but any change in compiler or
> > > > > > architecture and this would no longer be true. Let me know if you have
> > > > > > any more ideas.
> > > > >
> > > > > My thought was this technique of looking at compiler generated code can be
> > > > > used for prioritization of the reports.  Have you tested it though? I think
> > > > > without testing such technique, we could not know how much of benefit (or
> > > > > lack thereof) there is to the issue.
> > > > >
> > > > > In fact, IIRC, the compiler generating different code with _ONCE annotation
> > > > > can be given as justification for patches doing such conversions.
> > > >
> > > >
> > > > We also should not forget about "missed mutex" races (e.g. unprotected
> > > > radix tree), which are much worse and higher priority than a missed
> > > > atomic annotation. If we look at codegen we may discard most of them
> > > > as non important.
> > >
> > > Sure. I was not asking to look at codegen as the only signal. But to use the
> > > signal for whatever it is worth.
> >
> > But then we need other, stronger signals. We don't have any.
> > So if the codegen is the only one and it says "this is not important",
> > then we conclude "this is not important".
>
> I didn't mean for codegen to say "this is not important", but rather "this IS
> important". And for the other ones, "this may not be important, or it may
> be very important, I don't know".
>
> Why do you say a missed atomic anotation is lower priority? A bug is a bug,

You started talking about prioritization ;)

> and ought to be fixed IMHO. Arguably missing lock acquisition can be detected
> more easily due to lockdep assertions and using lockdep, than missing _ONCE
> annotations. The latter has no way of being detected at runtime easily and
> can be causing failures in mysterious ways.
>
> I think you can divide the problem up.. One set of bugs that are because of
> codegen changes and data races and are "important" for that reason. Another
> one that is less clear whether they are important or not -- until you have a
> better way of providing a signal for categorizing those.
>
> Did I miss something?

We have:
1. missed annotation with changing codegen.
2. missed annotation with non-changing codegen.
3. missed mutex with changing codegen.
4. missed mutex with non-changing codegen.

One can arguably say that 2 is less important than 1. But then both 3
and 4 are not low priority under any circumstances. And we don't have
any means to distinguish 1/2 from 3/4.
In this situation I don't see how "changing codegen" vs "non-changing
codegen" gives us any useful signal.

Assuming we have some signal for lower priority, the only useful way
of using this signal that I see is throwing lower priority bugs away
automatically for now (not reporting on syzbot). Because if we do
report all bugs and humans need to look at all of them anyway, this
signal is not too useful. If am already spending time on a report, I
can as well quickly prioritize it much more precisely than any
automatic scheme.

If we are not reporting lower priority bugs, we cannot offer to
classify "missed mutexes" as lower priority.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaHQGHaeX4EkD%3DHeK5j9968BH%2BzHnVxs6k_c1XvVMGAoQ%40mail.gmail.com.
