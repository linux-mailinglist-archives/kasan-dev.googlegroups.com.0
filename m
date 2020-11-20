Return-Path: <kasan-dev+bncBAABBEP6376QKGQETC6LLLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id D87AE2BB18C
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 18:38:26 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id a13sf12575412ybj.3
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 09:38:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605893906; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZlR1K5f2DQDvBLUQCONPWZhSsYMbr5dXP0AMNTnxx6zbeYcHrXdm3ZzFPzs9sYntUt
         M7tUtw2kjuEgk0GuhVNfz7l/DEK3f+CMNLrAo7VXA7nGv0iy5uuPI/tQzg4/266zbBAn
         qz2SgzRDvAgUTWyWyFjjU5/Y6q+u9TsLmd8aQ29nZYrJp+w3HD/upISItod5S+7To/BS
         hFvCBvYpo8yhaC+lEViZUQbV5npJvsv+3S/P8SgSC++d1DwYiGYNzrk7KbNPGGWCGutP
         yCw7iR4JBdZafnR5cwOgbl1kIDq9YD7YDZ+piGqAHJpW1O7jwq5L5K5fD97gzvi8lhM9
         0eJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=ahJ1aSNowkBEnmmzhotm/9p4vtKKjikR1xhGhop/Odo=;
        b=ph6iFLH/B5328C52bI9FGMn1olSeKGDhdE5dDaprm84V3KIZiA0eh3cRzaw7Jlo0Fq
         q2vAruZD/B3K8v2JNlHeMT5Vu2AcQDQZqwYwcB1yUC5vwDTlMtpj5rYaKFEok5TD6lTU
         p2JZjp3olKCOTa++Y4TOyk6YL49X6mq6DJs5dG/M0kRxQx1KMIMkvMS3g/4bnzYxSAiN
         D/OfaAJLqzTv2marNqfZWgedf5xIFMaAqrAb4hAhHTIRaCQ6DQCPoGQSbM9oTBnowlqX
         Yf+OAjcj7STb4G0XpDPgoEVMsQj+8rYydrnbzrrLcpzijA3MwSD1fGJwLdIh7Lg5bnX2
         6ctA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=UIJVTAM6;
       spf=pass (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZHLA=E2=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ahJ1aSNowkBEnmmzhotm/9p4vtKKjikR1xhGhop/Odo=;
        b=NhFi4LdKKv/XsKZs22r/O7U/cc2ltiFCEehjsFcbOdHM3JxL9qnYGt+Oo0pLMkZvwd
         +xEzqNAb+n8jNRzB7hDGvTZXj+lZmdWyW5jnaL72IkQMDcUywbR+qp2SEJ2AHZ4bsNpu
         /ZIeiUpLWZOnoniIONtLrwKXJjGGBJwsaITzbjrkzhIllkWq5fSbMFfmn0GSyPlhP0j0
         xcZDhsrMT696fimNYkvYZOpa/oWEC0O5PwO1GrjerLS70KcVmPOw5UFDjqRRbGicWEwi
         cuarUfCOJ4JZ2lBC6UtvjDr+WInhprx0nv2nhIMmiI4sNKeOLLeApJKkno8L1euU/ET7
         wT7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ahJ1aSNowkBEnmmzhotm/9p4vtKKjikR1xhGhop/Odo=;
        b=E8WBPisqy2sTmIZhEopDlERGx0OXZjIFr/+bdE/rMC62Xsg7oinGPMe+3OCQPLW22v
         imfIOO32ivvGbIr9eU3hjVy3RmqswamXzOSLgcFi2G+Xq18pK96XpU8hfPAMM5VoM6Wl
         mQJP2F4aqoolRwTUqcTuQywsZNAmUG29dSthI9jt7vl+k98/ny3qOfiOjh+yO2O8Zsqk
         FMxWDS0GKwl3NOWCCt0t/LTPsIoG/56cfwHbRu2liHwRdgSyPc72BeHNOPCn4PXMStdB
         MUbrj2OnICAQFyecd98/1we9MNZA1JFAo1nO2wlvnLh3kIP2/wN8URBKcRf9AiYV5EiJ
         j2xQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533hC+JluRABKkeSk2aRYh+t+MjAe27iVZd18P3/Y6h0KfYhMj5H
	xWT+SsbKMEuVo6obVx7Js7s=
X-Google-Smtp-Source: ABdhPJwUVsT0EsHrI9t6DQf0gA2Ohn+afgrJefS3k5lCnotB8Kt7VBqv8xsoicZPRDkAKOrPN0PfXQ==
X-Received: by 2002:a25:d981:: with SMTP id q123mr26147335ybg.50.1605893905906;
        Fri, 20 Nov 2020 09:38:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3f81:: with SMTP id m123ls3698503yba.1.gmail; Fri, 20
 Nov 2020 09:38:25 -0800 (PST)
X-Received: by 2002:a25:df05:: with SMTP id w5mr32427912ybg.20.1605893905480;
        Fri, 20 Nov 2020 09:38:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605893905; cv=none;
        d=google.com; s=arc-20160816;
        b=UtnD+5cyH6tT6HgfPaHgtDkkjAsXmhoisyXSV6TiZCnZiHPk5jUgi709YS6fEi82Qz
         ktkH91FPPnyCog/EJI6e+iv5VMXPyYd0vr+XYuLh2ITANhnKvV6kPT51bNazuHYd0NbF
         wBR7dgL3gVDn5DeVojzeFQQS6spRGNiwkvSz0gM++xI2Pzot98JW71mSmwB7AfSLafLg
         QuU+oRSN8mt1pNDKOvxt2vDPR42tI02+Or90ezYTgbkD07UNxc3xHVVnRjLexUWEr+io
         +eav6UlmVq/iaa5AqpZrB35tjO72YgK9VdkCTwbRpoO/Ux5BMubRWhYGZtn/gVIjVGnh
         Tepg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=seiG7NI4zk4v/x+XH14eZuezfoSoqaOr3U8s/ftvKWI=;
        b=w2gRQ+yWcHBcLQIGaYDZYoRF0W8neQcvvvpqdTA0NCQHpSfkWjtFghtMJX1hDzNe5w
         jS6NegYuGJkS1Er+UZe4wOCckZ2cqbtDcL/PeIJJBys8lImfN9WrinsSLBLhuwtUq10J
         WAFmMkvD3NHXB2ySUNIk7AVHmShaVpiOWFq8bK9pyvQybCTIKnBA2YzkQZ+B/J83KfVl
         EhAUhcdZElUEMfaKDq3+EHZN+wQ5TaqA8zTv49G0TdKsuyTuMa0asa/X/ofS1P+arISf
         yXNocgfB8P1LB4CBlNic+0Vwujc6Db0eeFVQLE9q3m9yLMdUB83FsrgHr3yT4ksrFJ5g
         yhYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=UIJVTAM6;
       spf=pass (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZHLA=E2=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n185si270959yba.3.2020.11.20.09.38.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 20 Nov 2020 09:38:25 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 5CC512222F;
	Fri, 20 Nov 2020 17:38:24 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 1B2603522637; Fri, 20 Nov 2020 09:38:24 -0800 (PST)
Date: Fri, 20 Nov 2020 09:38:24 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Marco Elver <elver@google.com>, Steven Rostedt <rostedt@goodmis.org>,
	Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>, Tejun Heo <tj@kernel.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	linux-arm-kernel@lists.infradead.org
Subject: Re: linux-next: stall warnings and deadlock on Arm64 (was: [PATCH]
 kfence: Avoid stalling...)
Message-ID: <20201120173824.GJ1437@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201118233841.GS1437@paulmck-ThinkPad-P72>
 <20201119125357.GA2084963@elver.google.com>
 <20201119151409.GU1437@paulmck-ThinkPad-P72>
 <20201119170259.GA2134472@elver.google.com>
 <20201119184854.GY1437@paulmck-ThinkPad-P72>
 <20201119193819.GA2601289@elver.google.com>
 <20201119213512.GB1437@paulmck-ThinkPad-P72>
 <20201120141928.GB3120165@elver.google.com>
 <20201120143928.GH1437@paulmck-ThinkPad-P72>
 <20201120152200.GD2328@C02TD0UTHF1T.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201120152200.GD2328@C02TD0UTHF1T.local>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=UIJVTAM6;       spf=pass
 (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZHLA=E2=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Fri, Nov 20, 2020 at 03:22:00PM +0000, Mark Rutland wrote:
> On Fri, Nov 20, 2020 at 06:39:28AM -0800, Paul E. McKenney wrote:
> > On Fri, Nov 20, 2020 at 03:19:28PM +0100, Marco Elver wrote:
> > > I found that disabling ftrace for some of kernel/rcu (see below) solved
> > > the stalls (and any mention of deadlocks as a side-effect I assume),
> > > resulting in successful boot.
> > > 
> > > Does that provide any additional clues? I tried to narrow it down to 1-2
> > > files, but that doesn't seem to work.
> > 
> > There were similar issues during the x86/entry work.  Are the ARM guys
> > doing arm64/entry work now?
> 
> I'm currently looking at it. I had been trying to shift things to C for
> a while, and right now I'm trying to fix the lockdep state tracking,
> which is requiring untangling lockdep/rcu/tracing.
> 
> The main issue I see remaining atm is that we don't save/restore the
> lockdep state over exceptions taken from kernel to kernel. That could
> result in lockdep thinking IRQs are disabled when they're actually
> enabled (because code in the nested context might do a save/restore
> while IRQs are disabled, then return to a context where IRQs are
> enabled), but AFAICT shouldn't result in the inverse in most cases since
> the non-NMI handlers all call lockdep_hardirqs_disabled().
> 
> I'm at a loss to explaim the rcu vs ftrace bits, so if you have any
> pointers to the issuies ween with the x86 rework that'd be quite handy.

There were several over a number of months.  I especially recall issues
with the direct-from-idle execution of smp_call_function*() handlers,
and also with some of the special cases in the entry code, for example,
reentering the kernel from the kernel.  This latter could cause RCU to
not be watching when it should have been or vice versa.

I would of course be most aware of the issues that impinged on RCU
and that were located by rcutorture.  This is actually not hard to run,
especially if the ARM bits in the scripting have managed to avoid bitrot.
The "modprobe rcutorture" approach has fewer dependencies.  Either way:
https://paulmck.livejournal.com/57769.html and later posts.

							Thanx, Paul

> Thanks,
> Mark.
> 
> > 
> > 							Thanx, Paul
> > 
> > > Thanks,
> > > -- Marco
> > > 
> > > ------ >8 ------
> > > 
> > > diff --git a/kernel/rcu/Makefile b/kernel/rcu/Makefile
> > > index 0cfb009a99b9..678b4b094f94 100644
> > > --- a/kernel/rcu/Makefile
> > > +++ b/kernel/rcu/Makefile
> > > @@ -3,6 +3,13 @@
> > >  # and is generally not a function of system call inputs.
> > >  KCOV_INSTRUMENT := n
> > >  
> > > +ifdef CONFIG_FUNCTION_TRACER
> > > +CFLAGS_REMOVE_update.o = $(CC_FLAGS_FTRACE)
> > > +CFLAGS_REMOVE_sync.o = $(CC_FLAGS_FTRACE)
> > > +CFLAGS_REMOVE_srcutree.o = $(CC_FLAGS_FTRACE)
> > > +CFLAGS_REMOVE_tree.o = $(CC_FLAGS_FTRACE)
> > > +endif
> > > +
> > >  ifeq ($(CONFIG_KCSAN),y)
> > >  KBUILD_CFLAGS += -g -fno-omit-frame-pointer
> > >  endif

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201120173824.GJ1437%40paulmck-ThinkPad-P72.
