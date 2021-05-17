Return-Path: <kasan-dev+bncBCJZRXGY5YJBBXF2RKCQMGQEPSCBHKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B86D383A44
	for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 18:44:13 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id s21-20020a6569150000b0290216803bf41csf4758013pgq.0
        for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 09:44:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621269852; cv=pass;
        d=google.com; s=arc-20160816;
        b=YkU9LbLi7yr78C2M3tpCG7YaS8b2x7F+j1YFKDJZvkOVqaPquly8HgT2Ei58K8H0aN
         l5iKDIztBored0NOf62GH8kIKJGcqbWzuW/NBeouhZAQCSTEgR7iO2qtH0EoaS7yfurI
         CjkJHtTCMRAegNQkYIeVG9S7/c3FpmHS4iy1UStOsBylO43zgEZcw3hPTQuTltmjChOO
         C/KmH0mo3qRNZHYh5r6iY5+JfwsxkJGkrpwkkbh5dytJjSxAEbI3f3CbRyXTao3I+oxc
         j3bKG/5Cck29Ke5dvLBvYI9DlRW9SOsY5rtH84o/AzQSTAdvBjuh5ikgafZ1ophILl0r
         szsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=zXxs5G26jTcj0iXUsd72/440jsB8z7uF8zs6H3FiG+o=;
        b=LLvIFyb29H7y5D5tV2NftusRLkjc10w2N8ErnI5vBAbLPOKhdbeXC/9aRuk6xUzcwe
         7c7TsrvnF/3laaYcUOd0zp6fQPJ1QEzOz6NxhLhz3T7n+rms8wEDU7Fhuer2ITzgpjih
         FYJxwlWxzBALd5Vm8wkMKMLfFvbTEjCUQv1yUGcODhbKa7/5UOt5BDUd3vRoDyoTSyq5
         4nM1MRDOuWuQdujJFGsnvoWhmLvaU/AyMw9X6ZAvjMu+gnHhpNOKf9q3H8ciMCqvb04l
         RzCE2jGhHqKdmffMIWEHu/Z6dKgqlTPNkW/oDCg1O3PGkUzwPAv2Aa3sCJGBcjonah20
         N4pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ay5t6SML;
       spf=pass (google.com: domain of srs0=btmv=km=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BtMV=KM=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zXxs5G26jTcj0iXUsd72/440jsB8z7uF8zs6H3FiG+o=;
        b=TQ3qy3C+zHclRSZjkP/W1/6VgFE8tIIXq0EuKZ0lWnz+O8ao8or8MqvpvRTD/MLIUN
         NM6OwkTateanH0eH2hDnpiYDtzFuEYD5hvraPJqT7Rtt1tdAYtN35MbIz1eJ3TVPp5BE
         8cDT+HCG0ER+Zu1qRm8GHHWg/MhnHmh+Ui38imjnB+Ig7I7NaUaE7U1DeqgSyNOYSYkU
         KGfc2lkWkTAppcwQoPg9pbPcTmx250KA3IZZC60jEk03ququCB/qVaJFmu9ZJsKgQzQM
         pmssacx8oRL80amRyNnAYRJOOud59KYShKVY+xzWovViyYNLWLlJWP0kVzeKrE/+fdc0
         kH/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zXxs5G26jTcj0iXUsd72/440jsB8z7uF8zs6H3FiG+o=;
        b=t+3bQUbuxwrW8bjzlAwCZ3xLtBgo0sSphUmmCBXGHyiNSjb5fluUIe3CvMZu2P5u+V
         LJnvKe9bzO3EgkLtcuwvscqRmYmJckXmmI4ChdQpqoA61AZoUBpir2r2UBM85TfxheQj
         dA1smEzGaNpQd+/K7szzILh9ggntPs6ebvC6DeXjOKHelkQklauZwS9y8NSsvKfu8WxF
         EyT9x/9zANyteLQjxgfMnNz+ZADdtZy4noxeWzq1vO0PxnETGs32Um7pen5rEwFtEYJr
         DtpJ3E3tDfGwWPukWLY/VcFfsPLfg6slmMtN7GO8N+jNkdGZ4TcbauMtuHXc67cpAX8c
         Nr1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533w7Zu9tTksgFPkUllDp7v1XdrJcdB6HC/+GYDCNvaFfq0SXLj7
	hw6CiyQVn8F0erru8YuzjuM=
X-Google-Smtp-Source: ABdhPJxJCma3hmwVx6VqV691ikQ6oU1sWETK59B1jetCA9YcORbRgrmQslYgndTwf6UZvPn6xRXY7A==
X-Received: by 2002:a17:902:b903:b029:ed:4a5e:6bf7 with SMTP id bf3-20020a170902b903b02900ed4a5e6bf7mr948576plb.82.1621269852273;
        Mon, 17 May 2021 09:44:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7b8b:: with SMTP id w11ls7389209pll.0.gmail; Mon, 17
 May 2021 09:44:11 -0700 (PDT)
X-Received: by 2002:a17:903:4106:b029:e9:244f:9aca with SMTP id r6-20020a1709034106b02900e9244f9acamr761280pld.58.1621269851732;
        Mon, 17 May 2021 09:44:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621269851; cv=none;
        d=google.com; s=arc-20160816;
        b=Mi0yw0HGnk7vRsauwQOkHA6eySHSw3kQTncvikvEflndaDdi1OE7MSc0md+tIYMjtP
         HK1h3SDbXpyOjGZ0zQ+odrk9Pe4cUB9MggzBStM123bf+5/sJqaHWcwFPGPgOGW8Hlr6
         SsAopQ1KMI2XbpQ0+ZcV9QjjDjxzueNYKsKgvh4w1JmoaN7mPpgmQWgDhjOcuIiLIALV
         NMQpZ/ebbMXXCMrAjCqZC5qi2uJjvjibV+xPSiGuBYJTBUe1Hui2Un40PvorW0Gll9e9
         tgtahF08hDHoiWcKf7MGQPuZX/7JxoXDP1uvhrEpZi0+pMPV+Pp1uK0DOa1vCUSxJvko
         pdjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=PywpuuEadfT1SRUHq3VsFEgPA0bhI6L75VVqKdX1Jno=;
        b=X8SNhlEDIY1zK9O7bzyWoeDUFvQvZCpm+tycs1B4eBTmkaX1AKsldiMC8iS2okXbCd
         /ITfBeeouXmX7dqmM0lSxpgejmeePiyVfqdDBdc2WEhSYGHBkz7rTR5Ce+rdTMSsdT9h
         bQ1SR/r7INXJOWHEeMCr7gWAJ+G+DUn7HZbkPe9JpDeDNurY31xfWANfWxZClnQnIsUN
         aDRSFYNREys5qm+Q/e+ETWDjuiVq14mgC+GMOxxEqY1DNnECnobG5XgUpH5WDvaRy2wB
         AvM4AzYoW43IHl4dK7J/CvoFE/gfq+I2knZHBkeKyxKrOg9arOj1ns6kgZHMajHvppJT
         sh/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ay5t6SML;
       spf=pass (google.com: domain of srs0=btmv=km=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BtMV=KM=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j5si7148pjs.0.2021.05.17.09.44.11
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 May 2021 09:44:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=btmv=km=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 726D0610FA;
	Mon, 17 May 2021 16:44:11 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 33ECB5C00C6; Mon, 17 May 2021 09:44:11 -0700 (PDT)
Date: Mon, 17 May 2021 09:44:11 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: syzkaller <syzkaller@googlegroups.com>, Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: "Learning-based Controlled Concurrency Testing"
Message-ID: <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ay5t6SML;       spf=pass
 (google.com: domain of srs0=btmv=km=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BtMV=KM=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Mon, May 17, 2021 at 05:36:16PM +0200, Dmitry Vyukov wrote:
> On Wed, May 12, 2021 at 8:18 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > Hello, Dmitry!
> >
> > On the perhaps-unlikely off-chance that this is useful new news, there
> > is a paper by Mukherjee et al. entitled "Learning-based Controlled
> > Concurrency Testing" that suggests use of an augmented coverage state
> > as a goal driving random testing.  The meat of this discussion is on
> > the eighth page, the one labeled as "230:8".
> >
> > This builds on tools such as American Fuzzy Lop (AFL) that use straight
> > coverage as a testing goal by adding carefully abstracted concurrency
> > state, such as which locks are held and which threads are blocked/spinning
> > on which lock.  This of course does not help for lockless algorithms,
> > but there are plenty of bugs involving straight locking.
> >
> > Thoughts?
> >
> >                                                         Thanx, Paul
> 
> 
> +syzkaller, kasan-dev
> 
> Hi Paul,
> 
> Thanks for notifying me, I wasn't aware of this work.
> 
> FTR here is a link to the paper I found:
> https://www.microsoft.com/en-us/research/uploads/prod/2019/12/QL-OOPSLA-2020.pdf
> 
> That's an interesting approach. Initially how they obtain the program
> "state" and calculate the reward, but the "default observation" thing
> answered my question.
> I think such approaches may be useful for the SPIN-territory where we
> verify a reasonably local and isolated algorithm, e.g. RAFT
> verification they used for benchmarking.
> But if we take, say, whole Linux kernel then such approaches become
> somewhat fragile, inefficient and impractical, e.g. capturing all
> tasks and mutexes may be impractical and inefficient (state
> explosion), or controlling all sources of non-determinism may be
> infeasible. And at the same time it's unnecessary because we still
> don't have even the most basic implementation, the random scheduler,
> which is not even what they are trying to improve on, it's several
> steps back.
> I would start with a random scheduler, maybe with few simple
> heuristics. That should be simple and robust and I am sure it will
> give us enough low hanging fruits to keep us busy for a prolonged
> period of time :) Here are tracking issues for that:
> https://bugzilla.kernel.org/show_bug.cgi?id=209219
> https://github.com/google/syzkaller/issues/1891
> 
> Maybe you did not mean Linux kernel at all, I don't know. For
> something like RCU verification (like what you did with SPIN) it's
> definitely more suitable.
> Interestingly, if we have a notion of "state" we can use
> coverage-guided fuzzing techniques as well. Though, I don't see it
> mentioned in the text explicitly. But you mentioned AFL, did you see
> this mentioned in the paper?
> They set a goal of maximizing state coverage, but they don't seem to
> preserve a "corpus" of schedules that give maximum coverage. If we do
> this, we can mutate schedules in the corpus, splice them, or prime the
> corpus with context-bound schedules (see CHESS, another seminal paper
> MS research). Generally, the more technique we include into the same
> feedback loop, the better, because they all start helping each other
> progress deeper.

My hope is that some very clever notion of "state" would allow
coverage-guided fuzzing techniques to be applied across the full kernel.
Here are a few not-so-clever notions I have thought of, in the hope that
they inspire some notion that is within the realm of sanity:

1.	The current coverage state plus the number of locks held by the
	current CPU/task.  This is not so clever because the PC value
	normally implies the number of locks.

	It might be possible to do a little bit better by using the
	lockdep hash instead of the number of locks, which could help
	with code that is protected by a lock selected by the caller.

2.	#1 above, but the number of locks held globally, not just by
	the current CPU/task.  This is not so clever because maintaining
	the global number of locks held is quite expensive.

3.	#2 above, but approximate the number of locks held.  The
	question is whether there is an approximation that is
	both efficient and useful to fuzzing.

4.	Run lockdep and periodically stop all the CPUs to gather the
	hashes of their current lock state plus PC.  The result is a set
	of states, one for each pair of CPUs, consisting of the first
	CPU's PC and both CPU's lockdep hash.  Combine this with the
	usual PC-only state.

	I could probably talk myself into believing that this one is
	clever, but who knows?	One not-so-clever aspect is the size of
	the state space, but perhaps bloom-filter techniques can help.

5.	KCSAN-like techniques, but where marking accesses forgives
	nothing.  No splats, but instead hash the "conflicting" accesses,
	preferably abstracting with type information, and add this hash
	to the notion of state.  This might not be so clever given how
	huge the state space would be, but again, perhaps bloom-filter
	techniques can help.

6.	Your more-clever ideas here!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210517164411.GH4441%40paulmck-ThinkPad-P17-Gen-1.
