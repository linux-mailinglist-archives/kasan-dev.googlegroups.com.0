Return-Path: <kasan-dev+bncBAABBNOG6XZAKGQEGAQD5QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 655DC17643F
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Mar 2020 20:49:10 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id k194sf459152qke.10
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2020 11:49:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583178549; cv=pass;
        d=google.com; s=arc-20160816;
        b=cpCpljNonCEfyYRvrREpVPgmjNbSC47TPQw6XcRK9z/efEmU7p5ddS+QrPlwJ8OTgL
         tUDjpi4aojL2vmbOpNUx+5U3ZadLX5GEE17xdVA8zewQyYT4hSZLZVy2RFNr6KK0VKc7
         5Y7IP3/Y2KkC8JAIeVou87kUBb1U3TdT0i3gFsH3iCVANYn09Xh8OvVFgOGoTdISRb9Q
         rJsunipTPSN/uXxrkWCVtDEqu8BUubu9uryKM6qge9kzJtHhiBWuArbANJlgLq1zot2t
         t/02qQU+4aOxYgfi25fBbJqOUws8OON1O8dqJLbno6T1zp9gd44pPoJ6dbOAZ6+ziIlf
         Fmbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=jC2HZnrjMhX1UcBoIN5xosQpNgAgGvTvS39xOMh+FvE=;
        b=i+FScICnse3SrPSCKDoSoxdUsPS+1SPBEuo34AmvcaxNxSKUfBfLLxu2A7ErlVnlTJ
         j7yq9Wevv7cbuXa0VErnZDyhuU9ZtTWq/7J9FhtG81bsVKX05VgHLhHZ9/EN2Dbf02tb
         0eaPOzg6tkFly3MYTWfbhj5+6bcXHKHaSGxHtaUu0F8h2YYMxVW+SEPxjXlBnDq0h1uX
         t87+cuAlQfmS4w5KtYNy7NCicLBOlPbFk9NhyKsSG0/cLEG+vbwepdvT+FPUdKKdNSC4
         39CmakMU2w2o8dxHRRZ+ePlx3UkaTiGWVuVbQ5M8siUJAISgKRJvYcF3QvshJjtkU6xK
         2IHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=BrzLSRNS;
       spf=pass (google.com: domain of srs0=afxj=4t=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=afxJ=4T=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jC2HZnrjMhX1UcBoIN5xosQpNgAgGvTvS39xOMh+FvE=;
        b=lLp4rwoKbqrqprQtDL90cq8SeB2ZfTlxGk5DKlp6AlQcCS7lNTJ7fdKb7hMB91eWvm
         fMigVhcoWCnqtNGUfA6V9VCMcLsyQzoHN7OezvvzDd4Bi8ux3dTTGjbVIMW7T3DjHQqI
         A7DiVi5qwr0O/x6VjGLDIBRP81AsuYI3WXajbWZoAzTmYzok3Q/6jaKXd9UJBlQJzNZ8
         k1FwUGzgUhcJHibNdNdKNBfihts6teGnWBsxk95YvCpJ0sLYZRyLcmxe0u290NkScE8V
         Ir5Ej49/UzpYLd3Y0CzI6JRyYT2eKN/bXAklPJb5N/lhXdw9aJJiEfKxhMyu5ycf4G9c
         6uEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jC2HZnrjMhX1UcBoIN5xosQpNgAgGvTvS39xOMh+FvE=;
        b=mGXWajkGQoOhh5633wahpDgSgfW6jORrGX1qQ9/Cz3Vom2qtU0CpUJb5pJAPAC/pLT
         9DbvBI9jdBLxEaq0OMJ+E7z4mEvtVZfoK72owllWNsFWrUaOh3r+BKAHEO/uT+UjUbeF
         OFAXY36jP9c+ZfFr0yqxAWgLd3ZbRdBllw5bbR/7VCiecr1w4EUSNiuW+GH0dhVL6sFB
         n+2UxMY3HgqorV+hzE0luShuLeqaQSm0PlkhBwS45wScUS3DpxUuOAIEmAyfDKuhmy+H
         XXzbJaN5mZ3kKgJLsvwepYGnX0vsZu2R74j3GrQV/ktkZHrmepJUckZ0+rMQjADgx+nA
         eGlg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3GTjAx055pzcCfPtEb3z+FSBJeRKDXWHY0WyHjoHvFoSnZ5ENh
	ro4uHXBZUCJyztusr5h6t2Y=
X-Google-Smtp-Source: ADFU+vvMB2TYSchL0Yi7UPcBTG8wdCYfbHOdZmY1vIs0/SbwvKq1oZ7c14QskkIQMTDgudOaA3iQug==
X-Received: by 2002:aed:2667:: with SMTP id z94mr1221781qtc.96.1583178549410;
        Mon, 02 Mar 2020 11:49:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a991:: with SMTP id s139ls422774qke.4.gmail; Mon, 02 Mar
 2020 11:49:09 -0800 (PST)
X-Received: by 2002:a05:620a:893:: with SMTP id b19mr826694qka.247.1583178549054;
        Mon, 02 Mar 2020 11:49:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583178549; cv=none;
        d=google.com; s=arc-20160816;
        b=zjj2hVWzO73AK9ci50EB+jtcON0/tCC49w3ELyrq1BjOL5ltbNNL21xfiikXmutNrF
         ImdD9eWozUA4prIxepeISjKvCkFQd0XltD4zfmTggZEo+HMPE4dCWujdDb5yhs5a/sj9
         Snrpl+UdnR/95Gmbngyfhxp0kwumGGeJNxCt2Bo9wpBDY2k1bETRgo/mTsQq4Ler7At3
         dsdZu2Qpl90sCq9BGtvMa2m6kgTiuFv/JTmWhQE+zkpt4SMV3AbD8M1Pr0NidUXYo113
         YKMCw2a0ZlMmkQU/tr2ilAAok0MEuQlakBJE4Ao/ekI4+m22vCSTg939bWEcSVZVtSvN
         uCUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=6bMz7D5nC5zLm9TZ3JFZbE5XaELOM4Mr6y+QdKFvYlE=;
        b=EMeqrp5VDgvjPIKfO8POwJUPmw5AwlJg4NOVAYpaA0ir39oiAAJKsSWaGkzBHQr3+7
         ++u7wOpw6l9vvoVabm78mGfEguZ6a6ZE2FyCtd6Fbl7cAnBdukbBUmRXxaF9KeML/9iO
         GjQgdrAAadPcYcC4db1RrElRN4DeNkJw4Hk22BknQBj/ertw6EWJPb9RXKAdF0YlSarh
         FPAUeK9nMGItbM4PRx+swqpJY68T+QINDuexAs2AT41zw1hKsekwzo2FPlH809hO4P8j
         vnsXWOcrhZVUztdHGMtdbZZcg18/XlEb1/8bXZTxcfWdzlBK2u+gYk3MTiZYKo2i0SFB
         /Wbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=BrzLSRNS;
       spf=pass (google.com: domain of srs0=afxj=4t=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=afxJ=4T=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x18si751207qtk.0.2020.03.02.11.49.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 02 Mar 2020 11:49:08 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=afxj=4t=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1C30124673;
	Mon,  2 Mar 2020 19:49:08 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id E4C7535226C8; Mon,  2 Mar 2020 11:49:07 -0800 (PST)
Date: Mon, 2 Mar 2020 11:49:07 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Andrea Parri <parri.andrea@gmail.com>
Cc: Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, stern@rowland.harvard.edu,
	will@kernel.org, peterz@infradead.org, boqun.feng@gmail.com,
	npiggin@gmail.com, dhowells@redhat.com, j.alglave@ucl.ac.uk,
	luc.maranget@inria.fr, akiyks@gmail.com, dlustig@nvidia.com,
	joel@joelfernandes.org, linux-arch@vger.kernel.org
Subject: Re: [PATCH v3] tools/memory-model/Documentation: Fix "conflict"
 definition
Message-ID: <20200302194907.GM2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200302172101.157917-1-elver@google.com>
 <20200302185216.GA5320@andrea>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200302185216.GA5320@andrea>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=BrzLSRNS;       spf=pass
 (google.com: domain of srs0=afxj=4t=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=afxJ=4T=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Mar 02, 2020 at 07:52:16PM +0100, Andrea Parri wrote:
> On Mon, Mar 02, 2020 at 06:21:01PM +0100, Marco Elver wrote:
> > The definition of "conflict" should not include the type of access nor
> > whether the accesses are concurrent or not, which this patch addresses.
> > The definition of "data race" remains unchanged.
> > 
> > The definition of "conflict" as we know it and is cited by various
> > papers on memory consistency models appeared in [1]: "Two accesses to
> > the same variable conflict if at least one is a write; two operations
> > conflict if they execute conflicting accesses."
> > 
> > The LKMM as well as the C11 memory model are adaptations of
> > data-race-free, which are based on the work in [2]. Necessarily, we need
> > both conflicting data operations (plain) and synchronization operations
> > (marked). For example, C11's definition is based on [3], which defines a
> > "data race" as: "Two memory operations conflict if they access the same
> > memory location, and at least one of them is a store, atomic store, or
> > atomic read-modify-write operation. In a sequentially consistent
> > execution, two memory operations from different threads form a type 1
> > data race if they conflict, at least one of them is a data operation,
> > and they are adjacent in <T (i.e., they may be executed concurrently)."
> > 
> > [1] D. Shasha, M. Snir, "Efficient and Correct Execution of Parallel
> >     Programs that Share Memory", 1988.
> > 	URL: http://snir.cs.illinois.edu/listed/J21.pdf
> > 
> > [2] S. Adve, "Designing Memory Consistency Models for Shared-Memory
> >     Multiprocessors", 1993.
> > 	URL: http://sadve.cs.illinois.edu/Publications/thesis.pdf
> > 
> > [3] H.-J. Boehm, S. Adve, "Foundations of the C++ Concurrency Memory
> >     Model", 2008.
> > 	URL: https://www.hpl.hp.com/techreports/2008/HPL-2008-56.pdf
> > 
> > Signed-off-by: Marco Elver <elver@google.com>
> > Co-developed-by: Alan Stern <stern@rowland.harvard.edu>
> > Signed-off-by: Alan Stern <stern@rowland.harvard.edu>
> 
> LGTM:
> 
> Acked-by: Andrea Parri <parri.andrea@gmail.com>

Applied, and thank you as well!

							Thanx, Paul

> Thank you both,
> 
>   Andrea
> 
> 
> > ---
> > v3:
> > * Apply Alan's suggestion.
> > * s/two race candidates/race candidates/
> > 
> > v2: http://lkml.kernel.org/r/20200302141819.40270-1-elver@google.com
> > * Apply Alan's suggested version.
> >   - Move "from different CPUs (or threads)" from "conflict" to "data
> >     race" definition. Update "race candidate" accordingly.
> > * Add citations to commit message.
> > 
> > v1: http://lkml.kernel.org/r/20200228164621.87523-1-elver@google.com
> > ---
> >  .../Documentation/explanation.txt             | 83 ++++++++++---------
> >  1 file changed, 45 insertions(+), 38 deletions(-)
> > 
> > diff --git a/tools/memory-model/Documentation/explanation.txt b/tools/memory-model/Documentation/explanation.txt
> > index e91a2eb19592a..993f800659c6a 100644
> > --- a/tools/memory-model/Documentation/explanation.txt
> > +++ b/tools/memory-model/Documentation/explanation.txt
> > @@ -1987,28 +1987,36 @@ outcome undefined.
> >  
> >  In technical terms, the compiler is allowed to assume that when the
> >  program executes, there will not be any data races.  A "data race"
> > -occurs when two conflicting memory accesses execute concurrently;
> > -two memory accesses "conflict" if:
> > +occurs when there are two memory accesses such that:
> >  
> > -	they access the same location,
> > +1.	they access the same location,
> >  
> > -	they occur on different CPUs (or in different threads on the
> > -	same CPU),
> > +2.	at least one of them is a store,
> >  
> > -	at least one of them is a plain access,
> > +3.	at least one of them is plain,
> >  
> > -	and at least one of them is a store.
> > +4.	they occur on different CPUs (or in different threads on the
> > +	same CPU), and
> >  
> > -The LKMM tries to determine whether a program contains two conflicting
> > -accesses which may execute concurrently; if it does then the LKMM says
> > -there is a potential data race and makes no predictions about the
> > -program's outcome.
> > +5.	they execute concurrently.
> >  
> > -Determining whether two accesses conflict is easy; you can see that
> > -all the concepts involved in the definition above are already part of
> > -the memory model.  The hard part is telling whether they may execute
> > -concurrently.  The LKMM takes a conservative attitude, assuming that
> > -accesses may be concurrent unless it can prove they cannot.
> > +In the literature, two accesses are said to "conflict" if they satisfy
> > +1 and 2 above.  We'll go a little farther and say that two accesses
> > +are "race candidates" if they satisfy 1 - 4.  Thus, whether or not two
> > +race candidates actually do race in a given execution depends on
> > +whether they are concurrent.
> > +
> > +The LKMM tries to determine whether a program contains race candidates
> > +which may execute concurrently; if it does then the LKMM says there is
> > +a potential data race and makes no predictions about the program's
> > +outcome.
> > +
> > +Determining whether two accesses are race candidates is easy; you can
> > +see that all the concepts involved in the definition above are already
> > +part of the memory model.  The hard part is telling whether they may
> > +execute concurrently.  The LKMM takes a conservative attitude,
> > +assuming that accesses may be concurrent unless it can prove they
> > +are not.
> >  
> >  If two memory accesses aren't concurrent then one must execute before
> >  the other.  Therefore the LKMM decides two accesses aren't concurrent
> > @@ -2171,8 +2179,8 @@ again, now using plain accesses for buf:
> >  	}
> >  
> >  This program does not contain a data race.  Although the U and V
> > -accesses conflict, the LKMM can prove they are not concurrent as
> > -follows:
> > +accesses are race candidates, the LKMM can prove they are not
> > +concurrent as follows:
> >  
> >  	The smp_wmb() fence in P0 is both a compiler barrier and a
> >  	cumul-fence.  It guarantees that no matter what hash of
> > @@ -2326,12 +2334,11 @@ could now perform the load of x before the load of ptr (there might be
> >  a control dependency but no address dependency at the machine level).
> >  
> >  Finally, it turns out there is a situation in which a plain write does
> > -not need to be w-post-bounded: when it is separated from the
> > -conflicting access by a fence.  At first glance this may seem
> > -impossible.  After all, to be conflicting the second access has to be
> > -on a different CPU from the first, and fences don't link events on
> > -different CPUs.  Well, normal fences don't -- but rcu-fence can!
> > -Here's an example:
> > +not need to be w-post-bounded: when it is separated from the other
> > +race-candidate access by a fence.  At first glance this may seem
> > +impossible.  After all, to be race candidates the two accesses must
> > +be on different CPUs, and fences don't link events on different CPUs.
> > +Well, normal fences don't -- but rcu-fence can!  Here's an example:
> >  
> >  	int x, y;
> >  
> > @@ -2367,7 +2374,7 @@ concurrent and there is no race, even though P1's plain store to y
> >  isn't w-post-bounded by any marked accesses.
> >  
> >  Putting all this material together yields the following picture.  For
> > -two conflicting stores W and W', where W ->co W', the LKMM says the
> > +race-candidate stores W and W', where W ->co W', the LKMM says the
> >  stores don't race if W can be linked to W' by a
> >  
> >  	w-post-bounded ; vis ; w-pre-bounded
> > @@ -2380,8 +2387,8 @@ sequence, and if W' is plain then they also have to be linked by a
> >  
> >  	w-post-bounded ; vis ; r-pre-bounded
> >  
> > -sequence.  For a conflicting load R and store W, the LKMM says the two
> > -accesses don't race if R can be linked to W by an
> > +sequence.  For race-candidate load R and store W, the LKMM says the
> > +two accesses don't race if R can be linked to W by an
> >  
> >  	r-post-bounded ; xb* ; w-pre-bounded
> >  
> > @@ -2413,20 +2420,20 @@ is, the rules governing the memory subsystem's choice of a store to
> >  satisfy a load request and its determination of where a store will
> >  fall in the coherence order):
> >  
> > -	If R and W conflict and it is possible to link R to W by one
> > -	of the xb* sequences listed above, then W ->rfe R is not
> > -	allowed (i.e., a load cannot read from a store that it
> > +	If R and W are race candidates and it is possible to link R to
> > +	W by one of the xb* sequences listed above, then W ->rfe R is
> > +	not allowed (i.e., a load cannot read from a store that it
> >  	executes before, even if one or both is plain).
> >  
> > -	If W and R conflict and it is possible to link W to R by one
> > -	of the vis sequences listed above, then R ->fre W is not
> > -	allowed (i.e., if a store is visible to a load then the load
> > -	must read from that store or one coherence-after it).
> > +	If W and R are race candidates and it is possible to link W to
> > +	R by one of the vis sequences listed above, then R ->fre W is
> > +	not allowed (i.e., if a store is visible to a load then the
> > +	load must read from that store or one coherence-after it).
> >  
> > -	If W and W' conflict and it is possible to link W to W' by one
> > -	of the vis sequences listed above, then W' ->co W is not
> > -	allowed (i.e., if one store is visible to a second then the
> > -	second must come after the first in the coherence order).
> > +	If W and W' are race candidates and it is possible to link W
> > +	to W' by one of the vis sequences listed above, then W' ->co W
> > +	is not allowed (i.e., if one store is visible to a second then
> > +	the second must come after the first in the coherence order).
> >  
> >  This is the extent to which the LKMM deals with plain accesses.
> >  Perhaps it could say more (for example, plain accesses might
> > -- 
> > 2.25.0.265.gbab2e86ba0-goog
> > 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200302194907.GM2935%40paulmck-ThinkPad-P72.
