Return-Path: <kasan-dev+bncBDV37XP3XYDRBJMJ4D6QKGQEZK2ZWJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BA082BB1E1
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 19:02:14 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id s9sf8578755qks.2
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 10:02:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605895333; cv=pass;
        d=google.com; s=arc-20160816;
        b=I5wnpnGAo4oXvxvhYo7f9sWtGQGV7ZWx/vi3NZHaeenx0poXAkrC40Gdfjzz1pOsSN
         seiovWB2uftFgZNLLMmUNO9wLuxzxNJqF6wzfsvF4LIw6SVOgF1l1Dj/mLHTDLIiWahD
         YKviAawBaK9p8rClNnqsr5U3xrEdDGTGm05FlK3u34V5p1MAmu12Av0cGSu11k+4kt2Q
         1p1COqdYjPdQ3N9yiCCHg/fLn4CiX3Gj9CuVeUdlXWJ3JKSvWU2Hs8nl0Iz//8uRB5HX
         r2PU4xtCs84Q+i8ywZK9Y8sRLZSEz+QvNxlhmE5DL2m0hcsnOPCjz8BVkx0DJCY3fCfT
         K93g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=otqlRxORShVM2AHvSn0QV8qCQmIkRlewsOTrAfcDtBY=;
        b=wjW2715ugdqxwAWwiy1xF+VnP1s7ESUJQfMGPiAcGhmhaRA95ndrZuPuvGJhJPJ9aD
         JHZfuNbWO+pyRS4/nYmeWOgWQw9MMeBbQ1qVXcWOkkqoq8g7dxBpcLSIOgK/VuNOmhuQ
         6PCtZE8HCX0SeRIrYGhB2UwHw4YNbZWDdVpd3xbinmIyrUp4ALzWsu4AO6I3shkPH1cm
         5Pc7z0hUFFpZCTDrY+FZ8k9/O2d7tq6c+SrnlhIQHf71JgV5W007nQKrjIFLUXfDrjh5
         qnVQt9hPi170tT1/s8rt6eGBfmd2CHz1BNbuPLDJHFz2KIa9Fiz/Eft1ioYJNQC/1oXA
         VLzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=otqlRxORShVM2AHvSn0QV8qCQmIkRlewsOTrAfcDtBY=;
        b=ROdHv9qiYxkK8lwhm3wehRLruUuOXEcCuRN3hggNf2q3/RePwHsYFHO1NDActrdVlj
         m9kiT+C/b57mRozmB/l+h2b5TUwMBZ2VWUrQhSWXDEHU1AsfoQOe64h/BmMFIIan/O7M
         kgiiAXcWU1th2Pn1t12HsbbLqeAqyF9LK04d4nipj3d1VjU1QfkWATIoLXZ85miPYXXu
         CpHyofApSybw2bLPXPbBz3YpbBC0dF9q3sJzB+W8UdC+Yf+hp+rkB8r/oDyrLt2bvpQL
         s4I3Oe8FqKu2xa5OaQ4QECi73jSW4fr/GzWRksJkXHIg1WzFHs2rHACenf0wovq001ys
         FqjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=otqlRxORShVM2AHvSn0QV8qCQmIkRlewsOTrAfcDtBY=;
        b=JMJDLcYinrR5EVH9woAKsqsasUwA+7R3EDDkzLSWtgeGQCHWnDY73Sdr3Xj1ujemO5
         IE8iCPbpoadHujQgy1ERTr1H+QUK+eQAcy3MEfysGushNQ7i6YGEawcU53CfrxLEnfdi
         lel1Qmmm2IB+wLvK7U3B6dPsKzJkfqOFePV1UPPclt87EFdvIWhfjD4g5wRUgTGVUW4y
         n6/hJW58Q7AiAm846bQad80RTgdxBnymzssb5FBDEA2WGNxvreWHxue5cfUKop3H8Fv4
         UL2WIg/NiWV6+HjHSBFwmdxqny/DJMXokpSkhmad0FS0KNoa5zInzvhXGiRsQ2K5PvT8
         n1fQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532YsExqw22kFDK3uRrlkPFBhEFK9hJq3SPE0+6o/y2+0iIf6EHO
	x8vRkr3EJc58s8D3Oy2+zFw=
X-Google-Smtp-Source: ABdhPJyvVSNq/Zw88n2xnNykdStPLmDpmxds4PlSTgrdfSg/MlDfNqGQA+MD01y7prSaRvtwk6kfZQ==
X-Received: by 2002:a37:e86:: with SMTP id 128mr18275635qko.450.1605895333546;
        Fri, 20 Nov 2020 10:02:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4973:: with SMTP id p19ls212024qvy.1.gmail; Fri, 20 Nov
 2020 10:02:13 -0800 (PST)
X-Received: by 2002:a05:6214:20a3:: with SMTP id 3mr17624186qvd.13.1605895333003;
        Fri, 20 Nov 2020 10:02:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605895333; cv=none;
        d=google.com; s=arc-20160816;
        b=mkQ9L6Eq7WAQBi3BCoTRPiX51Zdc5z1KO6tzT50m21S989ZHgnzTW/Wc0Fn5+0nfFY
         mYuHRQuY6e2M+IWgP71IZMp7T8yl9qxgc4+HwZRS7wX/6oMg+3nNPp8sEua+EYyRP0J/
         Ss66o2T6AIX+nWWleTo9CZVR89JEd844m1+U+HnUuPHbqExv3r57TDIl5Hlcw3w06JD4
         3U37NowJ9dTjcDzK+C73cnNeIckW1Pgy9diLJuDAVjU96tCFqpL9K+nCPZ3iKhtHL8te
         oUfSC0TFg0YD35G+a4pguTW96MIRjevnCEglRljbCgChJQHjSHKo54otw9pfIYRXZbbz
         Bxcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=T6Ny12LejOUwlk5/Sg7jt3BAZ1fQGXEY5388cNoUQ8c=;
        b=tRYs6TIMICdYeIIDcrhILgyKnDL1n517kBQHdx3DgdHvWg4CBm8gqcESzIc09mCBWd
         z41NeNO7uSY267eQqn7p/HdCIXxf0xxLGp19PLZ2xCDeeuvlwzJBhXMtBtCRxlhJON/b
         LGWe1in+ASgBcl4wb0h2GaTgP5rCbxt4pfRchwjOSWz2YW7QenzTnchW1H+247U5fcpb
         xVs7PUeRGSP1EZHTGgxhu2W03RiGLUvflUtbHK2R2z7SN4517J0y1DsdWLPVASZnVCeo
         lKdGX3p41cScOo7jqZDPdBmpqJQAkdnoWWHWTXAeX+Pu3Wyxc07oiSqU3PjtFaqXySvN
         OITg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s190si303708qkf.4.2020.11.20.10.02.12
        for <kasan-dev@googlegroups.com>;
        Fri, 20 Nov 2020 10:02:12 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 483481042;
	Fri, 20 Nov 2020 10:02:12 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.27.176])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id DBCEC3F719;
	Fri, 20 Nov 2020 10:02:08 -0800 (PST)
Date: Fri, 20 Nov 2020 18:02:06 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
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
Message-ID: <20201120180206.GF2328@C02TD0UTHF1T.local>
References: <20201119125357.GA2084963@elver.google.com>
 <20201119151409.GU1437@paulmck-ThinkPad-P72>
 <20201119170259.GA2134472@elver.google.com>
 <20201119184854.GY1437@paulmck-ThinkPad-P72>
 <20201119193819.GA2601289@elver.google.com>
 <20201119213512.GB1437@paulmck-ThinkPad-P72>
 <20201120141928.GB3120165@elver.google.com>
 <20201120143928.GH1437@paulmck-ThinkPad-P72>
 <20201120152200.GD2328@C02TD0UTHF1T.local>
 <20201120173824.GJ1437@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201120173824.GJ1437@paulmck-ThinkPad-P72>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Fri, Nov 20, 2020 at 09:38:24AM -0800, Paul E. McKenney wrote:
> On Fri, Nov 20, 2020 at 03:22:00PM +0000, Mark Rutland wrote:
> > On Fri, Nov 20, 2020 at 06:39:28AM -0800, Paul E. McKenney wrote:
> > > On Fri, Nov 20, 2020 at 03:19:28PM +0100, Marco Elver wrote:
> > > > I found that disabling ftrace for some of kernel/rcu (see below) solved
> > > > the stalls (and any mention of deadlocks as a side-effect I assume),
> > > > resulting in successful boot.
> > > > 
> > > > Does that provide any additional clues? I tried to narrow it down to 1-2
> > > > files, but that doesn't seem to work.
> > > 
> > > There were similar issues during the x86/entry work.  Are the ARM guys
> > > doing arm64/entry work now?
> > 
> > I'm currently looking at it. I had been trying to shift things to C for
> > a while, and right now I'm trying to fix the lockdep state tracking,
> > which is requiring untangling lockdep/rcu/tracing.
> > 
> > The main issue I see remaining atm is that we don't save/restore the
> > lockdep state over exceptions taken from kernel to kernel. That could
> > result in lockdep thinking IRQs are disabled when they're actually
> > enabled (because code in the nested context might do a save/restore
> > while IRQs are disabled, then return to a context where IRQs are
> > enabled), but AFAICT shouldn't result in the inverse in most cases since
> > the non-NMI handlers all call lockdep_hardirqs_disabled().
> > 
> > I'm at a loss to explaim the rcu vs ftrace bits, so if you have any
> > pointers to the issuies ween with the x86 rework that'd be quite handy.
> 
> There were several over a number of months.  I especially recall issues
> with the direct-from-idle execution of smp_call_function*() handlers,
> and also with some of the special cases in the entry code, for example,
> reentering the kernel from the kernel.  This latter could cause RCU to
> not be watching when it should have been or vice versa.

Ah; those are precisely the cases I'm currently fixing, so if we're
lucky this is an indirect result of one of those rather than a novel
source of pain...

> I would of course be most aware of the issues that impinged on RCU
> and that were located by rcutorture.  This is actually not hard to run,
> especially if the ARM bits in the scripting have managed to avoid bitrot.
> The "modprobe rcutorture" approach has fewer dependencies.  Either way:
> https://paulmck.livejournal.com/57769.html and later posts.

That is a very good idea. I'd been relying on Syzkaller to tickle the
issue, but the torture infrastructure is a much better fit for this
problem. I hadn't realise how comprehensive the scripting was, thanks
for this!

I'll see about giving that a go once I have the irq-from-idle cases
sorted, as those are very obviously broken if you hack
trace_hardirqs_{on,off}() to check that RCU is watching.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201120180206.GF2328%40C02TD0UTHF1T.local.
