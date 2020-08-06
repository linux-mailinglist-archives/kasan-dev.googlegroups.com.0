Return-Path: <kasan-dev+bncBAABBP4OWD4QKGQEJYPU4VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 8881B23DACC
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Aug 2020 15:36:00 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id f22sf26610058iof.20
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Aug 2020 06:36:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596720959; cv=pass;
        d=google.com; s=arc-20160816;
        b=M7PdujIXnwk0Y39bejGbdQbai4fVtu1JhCmji7EIoyzl0TZRb42wrN5tOYY4Yv+Adn
         eDTJGf1bu9ejxARv+QTgOhM7SIkLwDyujPg6vg7z4RtOx6e+tqJA8tsqOvyuf/BTbkmB
         g730ODCYFq7NqgrFpElEBopVr/cfRk8kVn/XpG0JZhWxrJSZQaVmfX7SrFKdf9/X1Mhl
         IN2oejvydvpWUQ6kCLcFxatHek3TU58oiFDeRBQCAysaZoHkNf0trsbGvWnTI2T/bW2g
         /nLK45mTO/i9Z70tAbbyiJlqhutEzQznY53Q+lkVu3tOK/f1j0El3kUcBcDMLUnK/LQa
         H5WQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=RzWF9QffmQV2lajVqnzd6c1jJyZkBsdJkUe9oDJ2iVY=;
        b=0CuT2HSfGyyc8rpuOKOZIvoddXWYScEwgJ9FogxiaE/ulzAOioTEYh1VZuRHHgdLSK
         mz5GJKpWxSqJT6S4MWzqRBBNhhxpUtZAWSnCBxsWnznl9d3Vzcake4BIFFdEANKRemf0
         6VU4QLMIwYIoR2ybfEzXj9VM69C5DaaZYw37udmx/ozFNn+Lk459cYG/ap5Te3TphX5q
         eVQmPU1Ohded/KJ/LCjrtLNrxWiS8oZosPyA+Dqkx28NMBSNB6ixF/yci+4A2G7uzrzu
         Hyyr5zXb37vjcXmMoLTEz1XJ52SkCrtSePOJXr7zilT0bdnGHThB3fdZE+j/XRfdw9bq
         0Yww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=bwBKTPBB;
       spf=pass (google.com: domain of srs0=bxfg=bq=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BXfg=BQ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RzWF9QffmQV2lajVqnzd6c1jJyZkBsdJkUe9oDJ2iVY=;
        b=EaR5FF1s3TTiBMpHwdy+fuKx91rEMYCk/DD2M2g55lZs1W4GzJeUJH04i0QXNkIqzt
         Y5IxROagFobQwvsq5WYCaIyohZJmkdzHq0oSoHneJtfHxS/48gAIQ+SrN/O5BwxUaxca
         e9ApjFIqP1pJ3B9VhzO5JRPLfAYTdgN0m2YIp/lCQrR8Nnj5p4I+8s00RIzIhmhmymZG
         tueqEm7P8aYoZDtKiIw0tJRKExNDDwoNnYLO7avbg/73OH0p5WBqKI1a+RQfPFU9YoLC
         zTG1psRyWoTeXajSXWcxpq/AObT/gMKqpRGDEEWpesMc7dRkpGuwgQ7okPdYlCuNC3z9
         S+uA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RzWF9QffmQV2lajVqnzd6c1jJyZkBsdJkUe9oDJ2iVY=;
        b=N3T6a0bW4DZF7Hdxwr5OLLpB6F8ovT0BVjniuXrv6eZluHJZegL88JG6BIC8PwfNzC
         QJ22qmigc5R8oCVH/vZ7ARZxTIrY6CPO5TB/h9d69Xo9l0zP9fXa5omL46gSxSFnuaCA
         gy7Y9eP7yBjnvesAzjqsJnDAYrFM++iA7LBflxL9cPOnoe1k5gZ0D5u9QfQ9sUo4P1jp
         vCCFtC7WpU5JkwHaUfvGb3O3RTd6HKdKKuLQGaiX6LH5LiQ6XZ5aJ73GR7iItgj7HCPg
         Wpqqwon+dhroe1y8MbdS4SW1wRsJif0YxmXw4g/bN3Ntd4z4bqjNum4Q3GtQULq0fj6L
         Ndnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531pfLFq3bPTRTZKt5RCZ4kg5ZKkbslsJP9oUSctVSr+L+2CjasP
	i0L1ZLlkf41+EwlAzY5/yik=
X-Google-Smtp-Source: ABdhPJzs2kAWUHCZvIFhUVugZyCoWMIGdSCHro0OM3naEjj2kKiGun/kArjJz3gsyhkU8v7goC/QjQ==
X-Received: by 2002:a02:95ab:: with SMTP id b40mr11603678jai.14.1596720959220;
        Thu, 06 Aug 2020 06:35:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1389:: with SMTP id w9ls868339jad.11.gmail; Thu, 06
 Aug 2020 06:35:58 -0700 (PDT)
X-Received: by 2002:a02:7092:: with SMTP id f140mr11918581jac.8.1596720958950;
        Thu, 06 Aug 2020 06:35:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596720958; cv=none;
        d=google.com; s=arc-20160816;
        b=S1X/K2v6x9uEfjvCuPOJRJJX+CsbNU2IDjZCCha/3JGGbs8Q5s2pArZZDrE/A7KuNM
         4KAJRYVTsKAvKZnK2rxvhepm4be+VBVm0vAwjqNcipMBlq5l66cs6u3zx3kn74VvOvIj
         n4qdjcqXDmlHkPAE04wsIhF/gUeHi96QSQpRul8jnMR6k2/bVVCw3DYtuVVPRG5ANfZQ
         mPGDA/+M2V2gTO+Ltd50Z2nasO/04g1Pb908YEAPbsSW5BbMsV4URgr115cVH6ykuyRO
         iik2ET3ndIWTY4d/B2Q8pmUGV9I4mLactD9lWphafdNpy+/ku+C8jKF51/ErqLVToIGD
         hEkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Aw4AbLIFIPAA4+aHbtnYzZ9xzYo2Ga8ch7V4G7qsZt4=;
        b=qPidSKayMU/7Kxtc2zM+6dF2F2Gpwg7u+npMlCLl5+wYMVceI+zcu0frczyIZ03/y4
         liVD0UwZ+uYi08dsbhy/vXNO+HNzLAP2y7SeHVdj9mWAogXChXdnRgZ6T2Z8bEq3J5eQ
         8MCYATkuyRHzxHMhwQ0O3MGdf20UY9szPx41wEGO3s0g1yTClFQScLIuTu2kDeZX1wcu
         ZC7gmOYn9L2Wl8XU4qCdrkSQjqxOF09lwqMqT9VqLWxAtyAJ60csfnHm2xluJkxvaONf
         PebBhsb6KJPTkL6zOK/mJm9Avcvg7KwLPvwQHTWI5x/WTL36jAZFilMOD3iz6VqmQHcT
         BaVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=bwBKTPBB;
       spf=pass (google.com: domain of srs0=bxfg=bq=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BXfg=BQ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k88si261385ilg.0.2020.08.06.06.35.58
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Aug 2020 06:35:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=bxfg=bq=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 5477A2310A;
	Thu,  6 Aug 2020 13:35:58 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id F1BA135206C1; Thu,  6 Aug 2020 06:35:57 -0700 (PDT)
Date: Thu, 6 Aug 2020 06:35:57 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Kostya Serebryany <kcc@google.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	'Dmitry Vyukov' via syzkaller-upstream-moderation <syzkaller-upstream-moderation@googlegroups.com>,
	Jann Horn <jannh@google.com>
Subject: Re: Finally starting on short RCU grace periods, but...
Message-ID: <20200806133557.GM4295@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200805230852.GA28727@paulmck-ThinkPad-P72>
 <CANpmjNPxzOFC+VQujipFaPmAV8evU2LnB4X-iXuHah45o-7pfw@mail.gmail.com>
 <CACT4Y+Ye7j-scb-thp2ubORCoEnuJPHL7W6Wh_DLP_4cux-0SQ@mail.gmail.com>
 <CACT4Y+aF=Y-b7Lm7+UAD7Zb1kS1uWF+G_3yBbXsY6YO3k2dBuw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+aF=Y-b7Lm7+UAD7Zb1kS1uWF+G_3yBbXsY6YO3k2dBuw@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=bwBKTPBB;       spf=pass
 (google.com: domain of srs0=bxfg=bq=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BXfg=BQ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Thu, Aug 06, 2020 at 03:25:57PM +0200, Dmitry Vyukov wrote:
> On Thu, Aug 6, 2020 at 3:22 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Thu, Aug 6, 2020 at 12:31 PM Marco Elver <elver@google.com> wrote:
> > >
> > > +Cc kasan-dev

Thank you!

> > > On Thu, 6 Aug 2020 at 01:08, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > >
> > > > Hello!
> > > >
> > > > If I remember correctly, one of you asked for a way to shorten RCU
> > > > grace periods so that KASAN would have a better chance of detecting bugs
> > > > such as pointers being leaked out of RCU read-side critical sections.
> > > > I am finally starting entering and testing code for this, but realized
> > > > that I had forgotten a couple of things:
> > > >
> > > > 1.      I don't remember exactly who asked, but I suspect that it was
> > > >         Kostya.  I am using his Reported-by as a placeholder for the
> > > >         moment, but please let me know if this should be adjusted.
> > >
> > > It certainly was not me.
> > >
> > > > 2.      Although this work is necessary to detect situtions where
> > > >         call_rcu() is used to initiate a grace period, there already
> > > >         exists a way to make short grace periods that are initiated by
> > > >         synchronize_rcu(), namely, the rcupdate.rcu_expedited kernel
> > > >         boot parameter.  This will cause all calls to synchronize_rcu()
> > > >         to act like synchronize_rcu_expedited(), resulting in about 2-3
> > > >         orders of magnitude reduction in grace-period latency on small
> > > >         systems (say 16 CPUs).
> > > >
> > > > In addition, I plan to make a few other adjustments that will
> > > > increase the probability of KASAN spotting a pointer leak even in the
> > > > rcupdate.rcu_expedited case.
> > >
> > > Thank you, that'll be useful I think.
> > >
> > > > But if you would like to start this sort of testing on current mainline,
> > > > rcupdate.rcu_expedited is your friend!
> >
> > Hi Paul,
> >
> > This is great!
> >
> > I understand it's not a sufficiently challenging way of tracking
> > things, but it's simply here ;)
> > https://bugzilla.kernel.org/show_bug.cgi?id=208299
> > (now we also know who asked for this, +Jann)

Thank you, and I will update the Reported-by lines accordingly.

> > I've tested on the latest mainline and with rcupdate.rcu_expedited=1
> > it boots to ssh successfully and I see:
> > [    0.369258][    T0] All grace periods are expedited (rcu_expedited).
> >
> > I have created https://github.com/google/syzkaller/pull/2021 to enable
> > it on syzbot.
> > On syzbot we generally use only 2-4 CPUs per VM, so it should be even better.

Sounds good, and perhaps this will answer Marco's question below.  ;-)

> > > Do any of you remember some bugs we missed due to this? Can we find
> > > them if we add this option?
> >
> > The problem is that it's hard to remember bugs that were not caught :)
> > Here is an approximation of UAFs with free in rcu callback:
> > https://groups.google.com/forum/#!searchin/syzkaller-bugs/KASAN$20use-after-free$20rcu_do_batch%7Csort:date
> > The ones with low hit count are the ones that we almost did not catch.
> > That's the best estimation I can think of. Also potentially we can get
> > reproducers for such bugs without reproducers.
> > Maybe we will be able to correlate some bugs/reproducers that appear
> > soon with this change.
> 
> Wait, it was added in 2012?
> https://github.com/torvalds/linux/commit/3705b88db0d7cc4

Indeed it was, which is my current excuse for having failed to immediately
mention it to Jann during our IRC discussion.

The purpose back then was to make battery-powered systems go faster,
I think mostly focused on CPU hotplug operations.  At least that would
explain the commit log being indefinite on the exact benefit.  ;-)

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200806133557.GM4295%40paulmck-ThinkPad-P72.
