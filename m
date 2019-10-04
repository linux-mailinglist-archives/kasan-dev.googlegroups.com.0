Return-Path: <kasan-dev+bncBCMIZB7QWENRB3XR3XWAKGQE3FGWK2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BB20CC117
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2019 18:53:03 +0200 (CEST)
Received: by mail-yw1-xc39.google.com with SMTP id o204sf6223263ywc.12
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2019 09:53:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570207982; cv=pass;
        d=google.com; s=arc-20160816;
        b=JKONuGGKNXEZytulEP5hqugskDtZA0evYHdrqRzJalFKWboI1cU9Xi1MiFxQnttSDn
         g1UlynSpBMqhB2v49MlyMT719EKkL8K5iuD5q+bmBCzEsUK0B56EtJbiUPNfCXhFqsti
         2BMaZn/Ext0BrAj1pFK2LzuR1ak8/0cUCfizFfB2z0e+X7X3MHpyqLkk5pqy4HWur+yB
         qBWfxCWMpfD6Hk/Ei8x/VKpB9qANjpwY7zgZRJJogK+BND41PcaQjD6X/VdjMxc48aeC
         fOVhX9NnGQvypVXf30YF6qaFd27Xq5RSpRCPWfBfmenn/E03wwSi2XmJWtKg/hMpOThc
         NMMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=By5zWQ71Wa8nYB1LYNQ/lRPeupWDIJoI7WM4uoY6Obw=;
        b=iUo8+u/wMMvV8aE/6XS8G08lJHWFJYOJ64a2GuEB1HS+78IyFdE68AS4CqYdKLYjF/
         nfcccoONzbH7FKvz9kl0WoyLkOPMbbBEDTEn5Ww6TAjns55lxSh3qiFu8xnHzTmI7O1u
         JpkMp8DT3JOIYHvCFY5pujN8HBC6oOYM95BmhvAVx4hf3/rud4SbQo24gvZITC9JGwfj
         UrLFHVoTOIO+OZHHBifSfGOUcJIvW9JMkac7dJbjGMftMHGxMVILevyOYIOurhbgAKma
         z7U1U/NndaKSdjdSCDJ2cWEKnO8jESxb78D/XKIV9BtMKIKempaTDue6wL+yy1KFdE97
         9UWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Yx4qOeKm;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=By5zWQ71Wa8nYB1LYNQ/lRPeupWDIJoI7WM4uoY6Obw=;
        b=NshSIpqrhl5JikGjgJebBRMF3hEoBQ7Y+U2xWcNdGhMydBFWtHJV+Ena+IK0EHX7Sj
         TYJzj8zWAW20Ya6O1FGuqnzgp6B+fN+cQHy9SOrprCDiV0+y6dLh6Y4y1DSWINTenkmq
         Cg64cqCA14bl4uvwWrjpQZTbQbAunu9C1g5GqAD8Pbd4HdQKflHN3hSBDw2Lvco3MUcN
         NPab0+6ZNoL+qbEQNH0AU1yW4RkDkMbkOQD89CBJU13TuD6Kbb9y7gyaINQHF0tGnqwS
         CC+E7ZUSUob2v2AgphmQ1+O3CGTdA+uMLJMC2azWPYJ0ggP5Tw/Mqe8sGwfe3R0DRsj2
         pAUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=By5zWQ71Wa8nYB1LYNQ/lRPeupWDIJoI7WM4uoY6Obw=;
        b=ftnZ61XHja1luE7PL2gjMCSy0XHaSwLIUz3F5eDAexkoHrWMTkpmyciYpRCYEb+OAG
         KKkHFjOR5qRa54y2AJbdSzebS6YL9V5zNABNRKc14yOvCJ7UVal6hjGfme+CtuQUFXeI
         ifnDSj/QAhatJ2uku8t6qQsKaaqYrogILOtckKv5n7rNn0G6Xd4G3rwgDriXn+e4jxl9
         oUvGpI6G2EKS2hJDzGfEfScnyHNkoGkpo8jWz1Fk7fL4RipJ/JnSTdmYUlAZQp/Wojta
         9F35jwqOPIn12D+jaziT44yc60JUhvZo23fBLN4DYuafzxJfxdysr+hX564cDBQZKqZv
         /sIw==
X-Gm-Message-State: APjAAAXdKK2xLslKMAvXdBTvTT7SjYrNYR0vVMR2cF8jGfuHFni09tZm
	9v4PbHblpr4MZI1TA5oHuB0=
X-Google-Smtp-Source: APXvYqw63+uJ0g1H3dlUIb/HHqqe6iWHg8aVjxpUeNRDRERdqom+S6vVAkmTisXMeGIYjkW9vkGVDA==
X-Received: by 2002:a81:704e:: with SMTP id l75mr12200320ywc.507.1570207982205;
        Fri, 04 Oct 2019 09:53:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9d84:: with SMTP id v4ls1085473ybp.0.gmail; Fri, 04 Oct
 2019 09:53:01 -0700 (PDT)
X-Received: by 2002:a25:a003:: with SMTP id x3mr1482408ybh.302.1570207981773;
        Fri, 04 Oct 2019 09:53:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570207981; cv=none;
        d=google.com; s=arc-20160816;
        b=cnWDMuQN/IdNAF+02vdYa326Wi1Z8xDys34lnJrAsr+VRqZUEI+CYundglKPtfrZCs
         lVNYCKk+MlaF6kNGytLG5vFfrRnsykfW9p+Dw/MWFM9NZCADGHwo2KquR/e0YIdYVLoN
         ePNnF574RQu/8Y8kutOiii9B7daKwS6jj/4l2l68l0ucZAuH8DHzbtcme5gYdcLe2FIc
         50anyRNg7XZr3+ma2OVboZx845Fg/gUYD4Y8ZHXnUQDjsioaza05bTRJ1xAToAE4157U
         yL/260ipkBJUTIuZeveiSJ4WG+9DKu+PaobvHIrhBB6HbUkyLnkA5iIbTgeFz0bxWubS
         b+GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=szbrEQ+44GjFscMv1BfBPhkqI0C+sNQmLHo22e0JAFc=;
        b=uuW7lo4YaEfcF05DytQsF+OfITHVSmro+WG7rs8EQUxkZDmxhzI9JWqOJtMXpbCrv5
         L3l0ERFDd1WyfK6RRsX3uDtLmKPUGeTdKXQ2IvTGm0sBbLXlMTPRLUe+h1noOve2mqMg
         K66PoX12LLywSQ2mPpR8Eu00n9rkXccLGqOXk63Lo+A2a9Jf0fPYoVJkq4Qj5mdIk8lI
         3ZmngUvAi07JHbjNl4wjkPgwYhrryQW2yhYIjeDU+wXeeZ91fCQb7P11uMWIi7GMG8Ux
         vwYK8IyUlB6VXVYwGIA7cMPNu1Vs7etaVC1ax+0Z0jQf/6eGxkOPva7XDu/ntUFUFVQm
         HSnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Yx4qOeKm;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id j136si88470ybj.3.2019.10.04.09.53.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Oct 2019 09:53:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id z67so6382155qkb.12
        for <kasan-dev@googlegroups.com>; Fri, 04 Oct 2019 09:53:01 -0700 (PDT)
X-Received: by 2002:a37:d84:: with SMTP id 126mr10177395qkn.407.1570207980784;
 Fri, 04 Oct 2019 09:53:00 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20191001211948.GA42035@google.com> <CANpmjNNp=zVzM2iGcQwVYxzNHYjBo==_2nito4Dw=kHopy=0Sg@mail.gmail.com>
 <20191004164859.GD253167@google.com>
In-Reply-To: <20191004164859.GD253167@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Oct 2019 18:52:49 +0200
Message-ID: <CACT4Y+bPZOb=h9m__Uo0feEshdGzPz0qGK7f2omsUc6-kEvwZA@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=Yx4qOeKm;       spf=pass
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

On Fri, Oct 4, 2019 at 6:49 PM Joel Fernandes <joel@joelfernandes.org> wrote:
>
> On Wed, Oct 02, 2019 at 09:51:58PM +0200, Marco Elver wrote:
> > Hi Joel,
> >
> > On Tue, 1 Oct 2019 at 23:19, Joel Fernandes <joel@joelfernandes.org> wrote:
> > >
> > > On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> > > > Hi all,
> > > >
> > > > We would like to share a new data-race detector for the Linux kernel:
> > > > Kernel Concurrency Sanitizer (KCSAN) --
> > > > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > > > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> > > >
> > > > To those of you who we mentioned at LPC that we're working on a
> > > > watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> > > > renamed it to KCSAN to avoid confusion with KTSAN).
> > > > [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
> > > >
> > > > In the coming weeks we're planning to:
> > > > * Set up a syzkaller instance.
> > > > * Share the dashboard so that you can see the races that are found.
> > > > * Attempt to send fixes for some races upstream (if you find that the
> > > > kcsan-with-fixes branch contains an important fix, please feel free to
> > > > point it out and we'll prioritize that).
> > > >
> > > > There are a few open questions:
> > > > * The big one: most of the reported races are due to unmarked
> > > > accesses; prioritization or pruning of races to focus initial efforts
> > > > to fix races might be required. Comments on how best to proceed are
> > > > welcome. We're aware that these are issues that have recently received
> > > > attention in the context of the LKMM
> > > > (https://lwn.net/Articles/793253/).
> > > > * How/when to upstream KCSAN?
> > >
> > > Looks exciting. I think based on our discussion at LPC, you mentioned
> > > one way of pruning is if the compiler generated different code with _ONCE
> > > annotations than what would have otherwise been generated. Is that still on
> > > the table, for the purposing of pruning the reports?
> >
> > This might be interesting at first, but it's not entirely clear how
> > feasible it is. It's also dangerous, because the real issue would be
> > ignored. It may be that one compiler version on a particular
> > architecture generates the same code, but any change in compiler or
> > architecture and this would no longer be true. Let me know if you have
> > any more ideas.
>
> My thought was this technique of looking at compiler generated code can be
> used for prioritization of the reports.  Have you tested it though? I think
> without testing such technique, we could not know how much of benefit (or
> lack thereof) there is to the issue.
>
> In fact, IIRC, the compiler generating different code with _ONCE annotation
> can be given as justification for patches doing such conversions.


We also should not forget about "missed mutex" races (e.g. unprotected
radix tree), which are much worse and higher priority than a missed
atomic annotation. If we look at codegen we may discard most of them
as non important.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbPZOb%3Dh9m__Uo0feEshdGzPz0qGK7f2omsUc6-kEvwZA%40mail.gmail.com.
