Return-Path: <kasan-dev+bncBAABBW5IW36QKGQELWI5QPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id F35272B0EA2
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 21:00:28 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id z69sf1677913otb.23
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 12:00:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605211227; cv=pass;
        d=google.com; s=arc-20160816;
        b=E6V6HG7Kl8d3N4TCsSvlVqozUgaMcJsKA+jH4Qudx+cB9dIaF8ngEhfL3BLErW2aa5
         WkvXOJH8jsQo0lMo4BgQvgvYYe8bQdxyLqDQeMRHBwU7EPFqHePmmRGzGt2eRT4qPQDY
         tCmUE1h3mO1WuhWEPqHLPCCqm4x2AfGsd6U10PjGPPjCbcN/dw/BxlRe0Pu1SKh+TerN
         pqv4P24I+xy0J/ErcCxJZOLQVXJ8zxLYXiub2W6TqcAr3+IXn9a9nxxlD/O5TiC9alBX
         SeUoEFYeii0h/qCKbxFLnSXGH4AyVGAAAdOHKNW80hvsFkLkvH7tuYljNBAkQLqLjRya
         RFMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=Xic/59haF9ywNg0eitFauG85R+73SofRm9yj8AVC9No=;
        b=UdBKk28Xs54BnllZ7QsbvYjsYAtaefAyFOUndrZE4Lc7Vk53oAnGXOJQDEc2vdiVmW
         LhF4g3IRwKPO972waSNrhDR0eZ+6Nu+Vm6fBUGL3CEuDDKM8/vNvKY7fIY84EJflyone
         XwfjGzsXW72OUadxtzLd9c7oUpQKe9SzIOBNmHKw4mbNobUDprKAINcpnwzV/TuBaYrl
         Q/yYbjrTO7V7/GHs9Df2IBqm0XTW49D2YOTavCa9YW7+pT4wyinUXLy5UAqvPEv2KTnI
         bVTbUfAKD3uMnlXOe/WmJqJoBrwg+cSE0gPY3gDhhbHzzwc7uSfBP0anat9PCi0ZLnBr
         x8RQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=iugo8+5r;
       spf=pass (google.com: domain of srs0=btsi=es=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BTSi=ES=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xic/59haF9ywNg0eitFauG85R+73SofRm9yj8AVC9No=;
        b=I6xGCc93FL/vElD+kP80BC1q4r6tvxf6Y3EVuURcTY/HPvlMUNdaJMpAsxC4nzZOas
         LGsBgbm9NIX/fn+1AAa+0xLfbg34zLn7UcmSX2xvcqUuKDpdkkW7fj+atuKNbQZV9bbt
         PGGrxSFFexRd2Re2bRRijGh6pQVXj15CoD0SjxVgEy+TuXpedHyoNFxweksekdexUXia
         TZoYGO2Y0MR6wCtsRcHAL+kDCeFoMtDk7FBPZwSsKva0XrvwagfNE9VeusHA210mQ0mR
         dTDXkudjWNA0hvknr4lVDIf80abJHMeO6CKBz2wLKNGz97L8ba/qCwEzQ2NBAICksuOQ
         VWLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Xic/59haF9ywNg0eitFauG85R+73SofRm9yj8AVC9No=;
        b=F8hgupwSxfeS8yT9X6fEedRmR5n4OVPdVCIGOHZ/8xYibboV9iq8QQyLpCRMrMSLge
         hI+DTKuUuPwLSCaiqOV3tklYRKqBTkw1MvEvSaZyjIMLneaH2MAYVXJHHAuG9FiKVUo4
         Mx1YJOjB4BtttQH1/y6u2nCVQKQkHNTSaG8oumhHXkoDyzjMCTL2OGnOeQ2gVRmhxzjL
         dc0r1wH86sVTBHekjJbUn9Fqb9AxeUrjXXbPK1n2cBe4o5IG2PuH4r+G0fQFVdrVAgQw
         no/755Jz1QXjAavIG170xs7oKD1lPSBxKL2bqmwxHszxvKVwTJM1DYHxhJ9rTKqRDxxK
         0Kqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5321cidUmutde4WV6mtaWL+Gjo9EyLYyrAMX9R4G4+Ua3BsnlobC
	YBwcNkePvCTAKp042VC4yQg=
X-Google-Smtp-Source: ABdhPJzGDyB+A2JR3y3j5W8c1tDnnW7Oke5wv0GYSiqOze4Gik59c5JIi3hWt5EBRxOTWPpvCVE6ng==
X-Received: by 2002:aca:3704:: with SMTP id e4mr922475oia.76.1605211227516;
        Thu, 12 Nov 2020 12:00:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:51cd:: with SMTP id d13ls998041oth.11.gmail; Thu, 12 Nov
 2020 12:00:27 -0800 (PST)
X-Received: by 2002:a9d:6419:: with SMTP id h25mr660619otl.79.1605211226918;
        Thu, 12 Nov 2020 12:00:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605211226; cv=none;
        d=google.com; s=arc-20160816;
        b=k/zxgvnExckFQhXDzwUGlvpWVUV2+bUL7xJtx4hGGDQ7GlhcSCuIPHLDmeHXJQATWD
         vGMEhNhyJQNsv5475ybQ2n+j8FGNegM7dCnW7E5yJ7pejCnDUbJai6V146wyoixCrv4H
         EzsiqeWnX1h1t0lpjiAlgg4SwwvbomSFGuXyf/QZzRT6ZS0L4BIuHyXcRonXhcC0xS7Q
         wu0m5iRrFaFvFIEapNTsxWDYDVuVPODRv8UNrcfbPqPq4nN3k41wTYuC+GA45jMboCnz
         kyMYIjuphi5bqCEbX/pGxf4AE4apiZxtwHZNsAf+rIJC4ieJFxR2lIxwVcy/UboaJCBY
         xeAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Q8BV6V8NOFWwRI81VohcaWOL95AkWw57gfCUCKSd2tc=;
        b=XWmkGn+oG8kXJLfeCbwEL0IgB86HhyGdABkcMaFdVNX70cY4Hc0IdKaW4DZzMifyOx
         hIuGVK4vvB/fWjvSbG0wBQoTNVSucCw11weqTtLlG4yayyHRZQKbP/KkVIsbm6gbWayQ
         VtJgwdwtSSjBuzErOt4emFCUA9selnxsmnwXfBETx334+SMj8bwZQCYizyYVoyie6Bce
         tXSdPVo2BXPMD/9xf11tkwYbJnrGAl40uLAz9tusuYzaSdPAeNbSrDUM0YxcBBaH7lay
         WKD+xN0egaDFuOIn9oCsyBkBRLBfuRMLWhlVuBge5WGtaSyuLF94jvdvsU26C4FmCV1R
         bQOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=iugo8+5r;
       spf=pass (google.com: domain of srs0=btsi=es=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BTSi=ES=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r6si942627oth.4.2020.11.12.12.00.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Nov 2020 12:00:26 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=btsi=es=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id D127520791;
	Thu, 12 Nov 2020 20:00:25 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 6E8443522B37; Thu, 12 Nov 2020 12:00:25 -0800 (PST)
Date: Thu, 12 Nov 2020 12:00:25 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Steven Rostedt <rostedt@goodmis.org>,
	Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without
 allocations
Message-ID: <20201112200025.GG3249@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201111130543.27d29462@gandalf.local.home>
 <20201111182333.GA3249@paulmck-ThinkPad-P72>
 <20201111183430.GN517454@elver.google.com>
 <20201111192123.GB3249@paulmck-ThinkPad-P72>
 <20201111202153.GT517454@elver.google.com>
 <20201112001129.GD3249@paulmck-ThinkPad-P72>
 <CANpmjNNyZs6NrHPmomC4=9MPEvCy1bFA5R2pRsMhG7=c3LhL_Q@mail.gmail.com>
 <20201112161439.GA2989297@elver.google.com>
 <20201112175406.GF3249@paulmck-ThinkPad-P72>
 <20201112181254.GA3113918@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201112181254.GA3113918@elver.google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=iugo8+5r;       spf=pass
 (google.com: domain of srs0=btsi=es=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BTSi=ES=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Thu, Nov 12, 2020 at 07:12:54PM +0100, Marco Elver wrote:
> On Thu, Nov 12, 2020 at 09:54AM -0800, Paul E. McKenney wrote:
> > On Thu, Nov 12, 2020 at 05:14:39PM +0100, Marco Elver wrote:
> > > On Thu, Nov 12, 2020 at 01:49PM +0100, Marco Elver wrote:
> > > > On Thu, 12 Nov 2020 at 01:11, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > [...]
> > > > > > This assert didn't fire yet, I just get more of the below. I'll keep
> > > > > > rerunning, but am not too hopeful...
> > > > >
> > > > > Is bisection a possibility?
> > > > 
> > > > I've been running a bisection for past ~12h, and am making slow
> > > > progress. It might be another 12h, but I think it'll get there.
> > > 
> > > Bisection gave me this:
> > > 
> > > | git bisect start
> > > | # bad: [c07b306d7fa5680777e2132662d2e6c19fb53579] kfence: Avoid stalling work queue task without allocations
> > > | git bisect bad c07b306d7fa5680777e2132662d2e6c19fb53579
> > > | # good: [3cea11cd5e3b00d91caf0b4730194039b45c5891] Linux 5.10-rc2
> > > | git bisect good 27598e7e73260ed0b2917eb02d4a515ebb578313
> > > | # good: [3e5acbea719e66ef3be64fe74c99cc905ca697dc] Merge remote-tracking branch 'wireless-drivers-next/master' into master
> > > | git bisect good 3e5acbea719e66ef3be64fe74c99cc905ca697dc
> > > | # good: [491a5a9a2fea28353d99621b8abb83b6928b4e36] Merge remote-tracking branch 'sound-asoc/for-next' into master
> > > | git bisect good 491a5a9a2fea28353d99621b8abb83b6928b4e36
> > > | # bad: [502f8643d6e21c7e370a0b75131130cc51609055] Merge remote-tracking branch 'phy-next/next' into master
> > > | git bisect bad 502f8643d6e21c7e370a0b75131130cc51609055
> > > | # good: [6693cb1fa5ea7b91ec00f9404776a095713face5] Merge remote-tracking branch 'tip/auto-latest' into master
> > > | git bisect good 6693cb1fa5ea7b91ec00f9404776a095713face5
> > > | # bad: [b790e3afead9357195b6d1e1b6cd9b3521503ad2] Merge branch 'tglx-pc.2020.10.30a' into HEAD
> > > | git bisect bad b790e3afead9357195b6d1e1b6cd9b3521503ad2
> > > | # bad: [765b512bb3d639bfad7dd43c288ee085236c7267] Merge branches 'cpuinfo.2020.11.06a', 'doc.2020.11.06a', 'fixes.2020.11.02a', 'lockdep.2020.11.02a', 'tasks.2020.11.06a' and 'torture.2020.11.06a' into HEAD
> > > | git bisect bad 765b512bb3d639bfad7dd43c288ee085236c7267
> > > | # good: [01f9e708d9eae6335ae9ff25ab09893c20727a55] tools/rcutorture: Fix BUG parsing of console.log
> > 
> > So torture.2020.11.06a is OK.
> > 
> > > | git bisect good 01f9e708d9eae6335ae9ff25ab09893c20727a55
> > > | # good: [1be6ab91e2db157faedb7f16ab0636a80745a073] srcu: Take early exit on memory-allocation failure
> > 
> > As is fixes.2020.11.02a.
> > 
> > > | git bisect good 1be6ab91e2db157faedb7f16ab0636a80745a073
> > > | # good: [65e9eb1ccfe56b41a0d8bfec651ea014968413cb] rcu: Prevent RCU_LOCKDEP_WARN() from swallowing the condition
> > 
> > And lockdep.2020.11.02a.
> > 
> > > | git bisect good 65e9eb1ccfe56b41a0d8bfec651ea014968413cb
> > > | # good: [c386e29d43728778ddd642fa73cc582bee684171] docs/rcu: Update the call_rcu() API
> > 
> > And doc.2020.11.06a.
> > 
> > > | git bisect good c386e29d43728778ddd642fa73cc582bee684171
> > > | # good: [27c0f1448389baf7f309b69e62d4b531c9395e88] rcutorture: Make grace-period kthread report match RCU flavor being tested
> > 
> > And the first three commits of tasks.2020.11.06a.
> > 
> > > | git bisect good 27c0f1448389baf7f309b69e62d4b531c9395e88
> > > | # good: [3fcd6a230fa7d03bffcb831a81b40435c146c12b] x86/cpu: Avoid cpuinfo-induced IPIing of idle CPUs
> > 
> > And cpuinfo.2020.11.06a.
> > 
> > > | git bisect good 3fcd6a230fa7d03bffcb831a81b40435c146c12b
> > > | # good: [75dc2da5ecd65bdcbfc4d59b9d9b7342c61fe374] rcu-tasks: Make the units of ->init_fract be jiffies
> > 
> > And the remaining commit of tasks.2020.11.06a.
> > 
> > > | git bisect good 75dc2da5ecd65bdcbfc4d59b9d9b7342c61fe374
> > > | # first bad commit: [765b512bb3d639bfad7dd43c288ee085236c7267] Merge branches 'cpuinfo.2020.11.06a', 'doc.2020.11.06a', 'fixes.2020.11.02a', 'lockdep.2020.11.02a', 'tasks.2020.11.06a' and 'torture.2020.11.06a' into HEAD
> > > 
> > > This doesn't look very satisfying, given it's the merge commit. :-/
> > 
> > So each individual branch is just fine, but the merge of them is not.  Fun.
> > 
> > These have been passing quite a bit of rcutorture over here, including
> > preemptible kernels running !SMP, but admittedly on x86 rather than ARMv8.
> 
> Note that this is ARMv8 on QEMU on an x86 host i.e. emulated. And it's
> really slow as a result. Together with a bunch of debug tools including
> lockdep.

Then I don't envy you the bisection process!  ;-)

> > One approach would be to binary-search the combinations of merges.
> > Except that there are six of them, so there are 64 combinations, of
> > which you have tested only 8 thus far (none, one each, and all).
> > 
> > But are you sure that the bisection points labeled "good" really are good?
> > For example, what is the distribution of first failure times in the
> > points labeled "bad" vs. the runtime used to make a "good" determination?
> > Alternatively, just try a longer run on each of the commits feeding into
> > the merge point.
> 
> Yeah, I'm having doubts, and this might be even more non-deterministic
> that I thought and some 'good' could maybe be 'bad' if I had re-run
> them? I don't know. One thing I can try is to make sure I run it more
> than once, but I'm definitely not doing that manually, so let me try and
> script something so I don't have to hand-hold the bisection overnight.
> :-)

I know that feeling.  A similar experience motivated me to upgrade my
tooling, with more upgrades in the queue.

> > > > > Failing that, please see the updated patch below.  This adds a few more
> > > > > calls to lockdep_assert_irqs_disabled(), but perhaps more helpfully dumps
> > > > > the current stack of the CPU that the RCU grace-period kthread wants to
> > > > > run on in the case where this kthread has been starved of CPU.
> > > > 
> > > > Thanks, I will apply that after the bisection runs.
> > > 
> > > Here's a new log with it applied:
> > 
> > Even more strangeness!  ;-)
> > 
> > > | [  118.480959] Key type dns_resolver registered
> > > | [  118.487752] registered taskstats version 1
> > > | [  118.489798] Running tests on all trace events:
> > > | [  118.490164] Testing all events: OK
> > > | [  173.304186] Running tests again, along with the function tracer
> > > | [  173.320155] Running tests on all trace events:
> > > | [  173.331638] Testing all events: 
> > > | [  173.485044] hrtimer: interrupt took 14340976 ns
> > 
> > Fourteen milliseconds, so annoying from a real-time perspective, but
> > unlikely to be the cause of this.
> > 
> > Was the system responsive at this point, between three and ten minutes
> > after boot?  Similar question for the other gaps in the dmesg log.
> > The reason for the question is that workqueue's reported stall times
> > don't span these intervals.
> 
> The system is so slow at this point that I can't get much out of it
> either way, other than waiting and seeing if it proceeds...

Hey, I had to ask!

> > > | [  334.160218] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 15s!
> > 
> > It might be instructive to cause this code to provoke a backtrace.
> > I suggest adding something like "trigger_single_cpu_backtrace(cpu)"
> > in kernel/workqueue.c's function named wq_watchdog_timer_fn()
> > somewhere within its "if" statement that is preceded with the "did we
> > stall?" comment.  Or just search for "BUG: workqueue lockup - pool"
> > within kernel/workqueue.c.
> > 
> > > | [  334.259490] Showing busy workqueues and worker pools:
> > > | [  334.265398] workqueue events: flags=0x0
> > > | [  334.289070]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
> > > | [  334.300659]     pending: vmstat_shepherd
> > > | [  453.541827] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 10s!
> > > | [  453.655731] BUG: workqueue lockup - pool cpus=0 flags=0x4 nice=0 stuck for 10s!
> > > | [  453.759839] Showing busy workqueues and worker pools:
> > > | [  453.784294] workqueue events: flags=0x0
> > > | [  453.812207]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
> > > | [  453.822108]     pending: vmstat_shepherd
> > > | [  453.839855] workqueue events_power_efficient: flags=0x82
> > > | [  453.865152]   pwq 2: cpus=0 flags=0x4 nice=0 active=2/256 refcnt=4
> > > | [  453.874553]     pending: neigh_periodic_work, do_cache_clean
> > > | [  481.424362] BUG: workqueue lockup - pool cpus=0 flags=0x4 nice=0 stuck for 10s!
> > > | [  481.508136] Showing busy workqueues and worker pools:
> > > | [  481.524265] workqueue events: flags=0x0
> > > | [  481.550480]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
> > > | [  481.560690]     pending: vmstat_shepherd
> > > | [  481.571255] workqueue events_power_efficient: flags=0x82
> > > | [  481.592515]   pwq 2: cpus=0 flags=0x4 nice=0 active=1/256 refcnt=3
> > > | [  481.601153]     pending: neigh_periodic_work
> > > | [  532.108407] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 10s!
> > > | [  532.203476] Showing busy workqueues and worker pools:
> > > | [  532.215930] workqueue events: flags=0x0
> > > | [  532.244203]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
> > > | [  532.254428]     pending: vmstat_shepherd
> > > | [  739.567892] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 19s!
> > > | [  739.656419] Showing busy workqueues and worker pools:
> > > | [  739.699514] workqueue events: flags=0x0
> > > | [  739.705111]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
> > > | [  739.715393]     pending: vmstat_shepherd
> > > | [  739.733403] workqueue events_power_efficient: flags=0x82
> > > | [  739.739433]   pwq 2: cpus=0 flags=0x4 nice=0 active=2/256 refcnt=4
> > > | [  739.748156]     pending: check_lifetime, neigh_periodic_work
> > > | [  811.578165] BUG: workqueue lockup - pool cpus=0 flags=0x5 nice=0 stuck for 14s!
> > > | [  811.602913] Showing busy workqueues and worker pools:
> > > | [  811.620424] workqueue events: flags=0x0
> > > | [  811.652479]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
> > > | [  811.662686]     pending: vmstat_shepherd
> > > | [  811.683811] workqueue events_power_efficient: flags=0x82
> > > | [  811.716123]   pwq 2: cpus=0 flags=0x5 nice=0 active=1/256 refcnt=3
> > > | [  811.724857]     pending: neigh_periodic_work
> > > | [  811.749989] pool 2: cpus=0 flags=0x5 nice=0 hung=14s workers=2 manager: 61 idle: 7
> > > | [  822.456290] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 11s!
> > > | [  822.600359] BUG: workqueue lockup - pool cpus=0 flags=0x5 nice=0 stuck for 25s!
> > > | [  822.675814] Showing busy workqueues and worker pools:
> > > | [  822.720098] workqueue events: flags=0x0
> > > | [  822.747304]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
> > > | [  822.757174]     pending: vmstat_shepherd
> > > | [  822.768047] workqueue events_power_efficient: flags=0x82
> > > | [  822.799954]   pwq 2: cpus=0 flags=0x5 nice=0 active=1/256 refcnt=3
> > > | [  822.808488]     pending: neigh_periodic_work
> > > | [  822.831900] pool 2: cpus=0 flags=0x5 nice=0 hung=25s workers=2 manager: 61 idle: 7
> > > | [  834.116239] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 22s!
> > > | [  834.246557] BUG: workqueue lockup - pool cpus=0 flags=0x5 nice=0 stuck for 37s!
> > > | [  834.271069] Showing busy workqueues and worker pools:
> > > | [  834.276687] workqueue events: flags=0x0
> > > | [  834.296267]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
> > > | [  834.306148]     pending: vmstat_shepherd
> > > | [  834.324273] workqueue events_power_efficient: flags=0x82
> > > | [  834.344433]   pwq 2: cpus=0 flags=0x5 nice=0 active=2/256 refcnt=4
> > > | [  834.352891]     pending: neigh_periodic_work, do_cache_clean
> > > | [  834.384530] pool 2: cpus=0 flags=0x5 nice=0 hung=37s workers=2 manager: 61 idle: 7
> > > | [  840.906940] rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
> > > | [  840.912685] 	(detected by 0, t=3752 jiffies, g=2709, q=1)
> > 
> > CPU 0 detected the stall.
> > 
> > > | [  840.914587] rcu: All QSes seen, last rcu_preempt kthread activity 620 (4295099794-4295099174), jiffies_till_next_fqs=1, root ->qsmask 0x0
> > 
> > As before, the grace period is not stalled, but instead the grace-period
> > kthread is failing to detect the end of an already-ended grace period.
> > 
> > > | [  840.925016] rcu: rcu_preempt kthread starved for 620 jiffies! g2709 f0x2 RCU_GP_CLEANUP(7) ->state=0x0 ->cpu=0
> > 
> > And CPU 0 is where the RCU grace-period kthread was last seen running.
> > 
> > > | [  840.930687] rcu: 	Unless rcu_preempt kthread gets sufficient CPU time, OOM is now expected behavior.
> > > | [  840.936056] rcu: RCU grace-period kthread stack dump:
> > > | [  840.940433] task:rcu_preempt     state:R  running task     stack:    0 pid:   10 ppid:     2 flags:0x00000428
> > > | [  840.949160] Call trace:
> > > | [  840.952822]  dump_backtrace+0x0/0x278
> > > | [  840.956816]  show_stack+0x30/0x80
> > > | [  840.960643]  sched_show_task+0x1a8/0x240
> > > | [  840.964684]  rcu_check_gp_kthread_starvation+0x170/0x358
> > > | [  840.969113]  rcu_sched_clock_irq+0x744/0xd18
> > > | [  840.973232]  update_process_times+0x68/0x98
> > > | [  840.977308]  tick_sched_handle.isra.16+0x54/0x80
> > > | [  840.981504]  tick_sched_timer+0x64/0xd8
> > > | [  840.985500]  __hrtimer_run_queues+0x2a4/0x750
> > > | [  840.989628]  hrtimer_interrupt+0xf4/0x2a0
> > > | [  840.993669]  arch_timer_handler_virt+0x44/0x70
> > > | [  840.997841]  handle_percpu_devid_irq+0xfc/0x4d0
> > > | [  841.002043]  generic_handle_irq+0x50/0x70
> > > | [  841.006098]  __handle_domain_irq+0x9c/0x120
> > > | [  841.010188]  gic_handle_irq+0xcc/0x108
> > > | [  841.014132]  el1_irq+0xbc/0x180
> > > | [  841.017935]  arch_local_irq_restore+0x4/0x8
> > > | [  841.021993]  trace_preempt_on+0xf4/0x190
> > > | [  841.026016]  preempt_schedule_common+0x12c/0x1b0
> > > | [  841.030193]  preempt_schedule.part.88+0x20/0x28
> > > | [  841.034373]  preempt_schedule+0x20/0x28
> > > | [  841.038369]  _raw_spin_unlock_irq+0x80/0x90
> > > | [  841.042498]  rcu_gp_kthread+0xe5c/0x19a8
> > > | [  841.046504]  kthread+0x174/0x188
> > > | [  841.050320]  ret_from_fork+0x10/0x18
> > > | [  841.054312] rcu: Stack dump where RCU grace-period kthread last ran:
> > > | [  841.058980] Task dump for CPU 0:
> > > | [  841.062736] task:rcu_preempt     state:R  running task     stack:    0 pid:   10 ppid:     2 flags:0x00000428
> > 
> > And RCU's grace-period kthread really is running on CPU 0 right now.
> > It is just not making any forward progress.
> > 
> > > | [  841.071073] Call trace:
> > > | [  841.074662]  dump_backtrace+0x0/0x278
> > > | [  841.078596]  show_stack+0x30/0x80
> > > | [  841.082386]  sched_show_task+0x1a8/0x240
> > > | [  841.086367]  dump_cpu_task+0x48/0x58
> > > | [  841.090311]  rcu_check_gp_kthread_starvation+0x214/0x358
> > > | [  841.094736]  rcu_sched_clock_irq+0x744/0xd18
> > > | [  841.098852]  update_process_times+0x68/0x98
> > > | [  841.102949]  tick_sched_handle.isra.16+0x54/0x80
> > > | [  841.107119]  tick_sched_timer+0x64/0xd8
> > > | [  841.111127]  __hrtimer_run_queues+0x2a4/0x750
> > > | [  841.115264]  hrtimer_interrupt+0xf4/0x2a0
> > > | [  841.119319]  arch_timer_handler_virt+0x44/0x70
> > > | [  841.123525]  handle_percpu_devid_irq+0xfc/0x4d0
> > > | [  841.127690]  generic_handle_irq+0x50/0x70
> > > | [  841.131702]  __handle_domain_irq+0x9c/0x120
> > > | [  841.135779]  gic_handle_irq+0xcc/0x108
> > > | [  841.139743]  el1_irq+0xbc/0x180
> > 
> > The code above this point was detecting and printing the RCU CPU stall
> > warning.  The code below this point was doing what?
> > 
> > Any chance of getting file names and line numbers for the rest of this
> > stack?
> 
> I've attached a version of the log with line numbers.

Thank you!

> > > | [  841.143527]  arch_local_irq_restore+0x4/0x8
> > 
> > So we are just now restoring interrupts, hence our getting the
> > interrupt at this point..
> > 
> > > | [  841.147612]  trace_preempt_on+0xf4/0x190
> > 
> > From within the trace code, which is apparently recording the fact
> > that preemption is being enabled.
> > 
> > > | [  841.151656]  preempt_schedule_common+0x12c/0x1b0
> > > | [  841.155869]  preempt_schedule.part.88+0x20/0x28
> > > | [  841.160036]  preempt_schedule+0x20/0x28
> > 
> > I was not aware that releasing a raw spinlock could result in a direct
> > call to preempt_schedule().
> > 
> > > | [  841.164051]  _raw_spin_unlock_irq+0x80/0x90
> > > | [  841.168139]  rcu_gp_kthread+0xe5c/0x19a8
> > 
> > So the RCU grace-period kthread has spent many seconds attempting to
> > release a lock?  Am I reading this correctly?  Mark Rutland, am I missing
> > something here?

And yes, this is the RCU grace-period kthread releasing a lock.

I have no idea why that would take so long.  It is acting like a
self-deadlock or similar hang, except that in that case, lockdep should
have complained before the RCU CPU stall warning rather than after.

The only thing I can suggest is sprinkling lockdep_assert_irqs_disabled()
calls hither and yon.  All of the code that lockdep is complaining about
runs in the context of the scheduling-clock interrupt, so interrupts
had jolly well be disabled!  ;-)

Rerunning some of the allegedly good bisects might be more productive.

							Thanx, Paul

> > > | [  841.172134]  kthread+0x174/0x188
> > > | [  841.175953]  ret_from_fork+0x10/0x18
> > > | [  841.191371] 
> > > | [  841.193648] ================================
> > > | [  841.196605] WARNING: inconsistent lock state
> > > | [  841.199764] 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #23 Not tainted
> > > | [  841.203564] --------------------------------
> > 
> > Has lockdep recorded the fact that the lock is actually released?
> > It had better, given that interrupts are now enabled.
> > 
> > > | [  841.206550] inconsistent {IN-HARDIRQ-W} -> {HARDIRQ-ON-W} usage.
> > > | [  841.210074] rcu_preempt/10 [HC0[0]:SC0[0]:HE0:SE1] takes:
> > > | [  841.213453] ffffd787e91d4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x4a0/0xd18
> > > | [  841.221240] {IN-HARDIRQ-W} state was registered at:
> > > | [  841.224538]   __lock_acquire+0x7bc/0x15b8
> > > | [  841.227541]   lock_acquire+0x244/0x498
> > > | [  841.230442]   _raw_spin_lock_irqsave+0x78/0x144
> > > | [  841.233555]   rcu_sched_clock_irq+0x4a0/0xd18
> > > | [  841.236621]   update_process_times+0x68/0x98
> > > | [  841.239645]   tick_sched_handle.isra.16+0x54/0x80
> > > | [  841.242801]   tick_sched_timer+0x64/0xd8
> > > | [  841.245745]   __hrtimer_run_queues+0x2a4/0x750
> > > | [  841.248842]   hrtimer_interrupt+0xf4/0x2a0
> > > | [  841.251846]   arch_timer_handler_virt+0x44/0x70
> > > | [  841.254976]   handle_percpu_devid_irq+0xfc/0x4d0
> > > | [  841.258131]   generic_handle_irq+0x50/0x70
> > > | [  841.261146]   __handle_domain_irq+0x9c/0x120
> > > | [  841.264169]   gic_handle_irq+0xcc/0x108
> > > | [  841.267096]   el1_irq+0xbc/0x180
> > > | [  841.269844]   arch_local_irq_restore+0x4/0x8
> > > | [  841.272881]   trace_preempt_on+0xf4/0x190
> > > | [  841.275847]   preempt_schedule_common+0x12c/0x1b0
> > > | [  841.279017]   preempt_schedule.part.88+0x20/0x28
> > > | [  841.282149]   preempt_schedule+0x20/0x28
> > > | [  841.285112]   _raw_spin_unlock_irq+0x80/0x90
> > > | [  841.288154]   rcu_gp_kthread+0xe5c/0x19a8
> > > | [  841.291175]   kthread+0x174/0x188
> > > | [  841.293952]   ret_from_fork+0x10/0x18
> > > | [  841.296780] irq event stamp: 39750
> > > | [  841.299604] hardirqs last  enabled at (39749): [<ffffd787e6d85738>] rcu_irq_enter_irqson+0x48/0x68
> > > | [  841.303961] hardirqs last disabled at (39750): [<ffffd787e6c122bc>] el1_irq+0x7c/0x180
> > > | [  841.308042] softirqs last  enabled at (36704): [<ffffd787e6c10b58>] __do_softirq+0x650/0x6a4
> > > | [  841.312250] softirqs last disabled at (36683): [<ffffd787e6cc0b80>] irq_exit+0x1a8/0x1b0
> > > | [  841.316257] 
> > > | [  841.316257] other info that might help us debug this:
> > > | [  841.319834]  Possible unsafe locking scenario:
> > > | [  841.319834] 
> > > | [  841.323217]        CPU0
> > > | [  841.325656]        ----
> > > | [  841.328097]   lock(rcu_node_0);
> > > | [  841.332433]   <Interrupt>
> > > | [  841.334966]     lock(rcu_node_0);
> > > | [  841.339379] 
> > > | [  841.339379]  *** DEADLOCK ***
> > > | [  841.339379] 
> > > | [  841.342829] 1 lock held by rcu_preempt/10:
> > > | [  841.345794]  #0: ffffd787e91d4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x4a0/0xd18
> > > | [  841.354415] 
> > > | [  841.354415] stack backtrace:
> > > | [  841.357664] CPU: 0 PID: 10 Comm: rcu_preempt Not tainted 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #23
> > > | [  841.362249] Hardware name: linux,dummy-virt (DT)
> > > | [  841.365352] Call trace:
> > > | [  841.367862]  dump_backtrace+0x0/0x278
> > > | [  841.370745]  show_stack+0x30/0x80
> > > | [  841.373517]  dump_stack+0x138/0x1b0
> > > | [  841.376339]  print_usage_bug+0x2d8/0x2f8
> > > | [  841.379288]  mark_lock.part.46+0x370/0x480
> > > | [  841.382304]  mark_held_locks+0x58/0x90
> > > | [  841.385228]  lockdep_hardirqs_on_prepare+0xdc/0x298
> > > | [  841.388452]  trace_hardirqs_on+0x90/0x388
> > > | [  841.391434]  el1_irq+0xd8/0x180
> > > | [  841.394178]  arch_local_irq_restore+0x4/0x8
> > > | [  841.397186]  trace_preempt_on+0xf4/0x190
> > > | [  841.400127]  preempt_schedule_common+0x12c/0x1b0
> > > | [  841.403246]  preempt_schedule.part.88+0x20/0x28
> > > | [  841.406347]  preempt_schedule+0x20/0x28
> > > | [  841.409278]  _raw_spin_unlock_irq+0x80/0x90
> > > | [  841.412290]  rcu_gp_kthread+0xe5c/0x19a8
> > > | [  841.415237]  kthread+0x174/0x188
> > > | [  841.418011]  ret_from_fork+0x10/0x18
> > > | [  841.423450] BUG: scheduling while atomic: rcu_preempt/10/0x00000002
> > > | [  841.431367] INFO: lockdep is turned off.
> > > | [  841.439132] Modules linked in:
> > > | [  841.450608] Preemption disabled at:
> > > | [  841.452261] [<ffffd787e7fffec0>] preempt_schedule.part.88+0x20/0x28
> > > | [  841.467324] CPU: 0 PID: 10 Comm: rcu_preempt Not tainted 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #23
> > > | [  841.471926] Hardware name: linux,dummy-virt (DT)
> > > | [  841.475030] Call trace:
> > > | [  841.477581]  dump_backtrace+0x0/0x278
> > > | [  841.480451]  show_stack+0x30/0x80
> > > | [  841.483220]  dump_stack+0x138/0x1b0
> > > | [  841.486057]  __schedule_bug+0x8c/0xe8
> > > | [  841.488949]  __schedule+0x7e8/0x890
> > > | [  841.491801]  preempt_schedule_common+0x44/0x1b0
> > > | [  841.494927]  preempt_schedule.part.88+0x20/0x28
> > > | [  841.498048]  preempt_schedule+0x20/0x28
> > > | [  841.500963]  _raw_spin_unlock_irq+0x80/0x90
> > > | [  841.503988]  rcu_gp_kthread+0xe5c/0x19a8
> > > | [  841.506965]  kthread+0x174/0x188
> > > | [  841.509732]  ret_from_fork+0x10/0x18

> Testing all events: OK
> Running tests again, along with the function tracer
> Running tests on all trace events:
> Testing all events: 
> hrtimer: interrupt took 14340976 ns
> BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 15s!
> Showing busy workqueues and worker pools:
> workqueue events: flags=0x0
>   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
>     pending: vmstat_shepherd
> BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 10s!
> BUG: workqueue lockup - pool cpus=0 flags=0x4 nice=0 stuck for 10s!
> Showing busy workqueues and worker pools:
> workqueue events: flags=0x0
>   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
>     pending: vmstat_shepherd
> workqueue events_power_efficient: flags=0x82
>   pwq 2: cpus=0 flags=0x4 nice=0 active=2/256 refcnt=4
>     pending: neigh_periodic_work, do_cache_clean
> BUG: workqueue lockup - pool cpus=0 flags=0x4 nice=0 stuck for 10s!
> Showing busy workqueues and worker pools:
> workqueue events: flags=0x0
>   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
>     pending: vmstat_shepherd
> workqueue events_power_efficient: flags=0x82
>   pwq 2: cpus=0 flags=0x4 nice=0 active=1/256 refcnt=3
>     pending: neigh_periodic_work
> BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 10s!
> Showing busy workqueues and worker pools:
> workqueue events: flags=0x0
>   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
>     pending: vmstat_shepherd
> BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 19s!
> Showing busy workqueues and worker pools:
> workqueue events: flags=0x0
>   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
>     pending: vmstat_shepherd
> workqueue events_power_efficient: flags=0x82
>   pwq 2: cpus=0 flags=0x4 nice=0 active=2/256 refcnt=4
>     pending: check_lifetime, neigh_periodic_work
> BUG: workqueue lockup - pool cpus=0 flags=0x5 nice=0 stuck for 14s!
> Showing busy workqueues and worker pools:
> workqueue events: flags=0x0
>   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
>     pending: vmstat_shepherd
> workqueue events_power_efficient: flags=0x82
>   pwq 2: cpus=0 flags=0x5 nice=0 active=1/256 refcnt=3
>     pending: neigh_periodic_work
> pool 2: cpus=0 flags=0x5 nice=0 hung=14s workers=2 manager: 61 idle: 7
> BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 11s!
> BUG: workqueue lockup - pool cpus=0 flags=0x5 nice=0 stuck for 25s!
> Showing busy workqueues and worker pools:
> workqueue events: flags=0x0
>   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
>     pending: vmstat_shepherd
> workqueue events_power_efficient: flags=0x82
>   pwq 2: cpus=0 flags=0x5 nice=0 active=1/256 refcnt=3
>     pending: neigh_periodic_work
> pool 2: cpus=0 flags=0x5 nice=0 hung=25s workers=2 manager: 61 idle: 7
> BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 22s!
> BUG: workqueue lockup - pool cpus=0 flags=0x5 nice=0 stuck for 37s!
> Showing busy workqueues and worker pools:
> workqueue events: flags=0x0
>   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
>     pending: vmstat_shepherd
> workqueue events_power_efficient: flags=0x82
>   pwq 2: cpus=0 flags=0x5 nice=0 active=2/256 refcnt=4
>     pending: neigh_periodic_work, do_cache_clean
> pool 2: cpus=0 flags=0x5 nice=0 hung=37s workers=2 manager: 61 idle: 7
> rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
> 	(detected by 0, t=3752 jiffies, g=2709, q=1)
> rcu: All QSes seen, last rcu_preempt kthread activity 620 (4295099794-4295099174), jiffies_till_next_fqs=1, root ->qsmask 0x0
> rcu: rcu_preempt kthread starved for 620 jiffies! g2709 f0x2 RCU_GP_CLEANUP(7) ->state=0x0 ->cpu=0
> rcu: 	Unless rcu_preempt kthread gets sufficient CPU time, OOM is now expected behavior.
> rcu: RCU grace-period kthread stack dump:
> task:rcu_preempt     state:R  running task     stack:    0 pid:   10 ppid:     2 flags:0x00000428
> Call trace:
>  dump_backtrace+0x0/0x278 arch/arm64/kernel/stacktrace.c:100
>  show_stack+0x30/0x80 arch/arm64/kernel/stacktrace.c:196
>  sched_show_task+0x1a8/0x240 kernel/sched/core.c:6445
>  rcu_check_gp_kthread_starvation+0x170/0x358 kernel/rcu/tree_stall.h:469
>  print_other_cpu_stall kernel/rcu/tree_stall.h:544 [inline]
>  check_cpu_stall kernel/rcu/tree_stall.h:664 [inline]
>  rcu_pending kernel/rcu/tree.c:3752 [inline]
>  rcu_sched_clock_irq+0x744/0xd18 kernel/rcu/tree.c:2581
>  update_process_times+0x68/0x98 kernel/time/timer.c:1709
>  tick_sched_handle.isra.16+0x54/0x80 kernel/time/tick-sched.c:176
>  tick_sched_timer+0x64/0xd8 kernel/time/tick-sched.c:1328
>  __run_hrtimer kernel/time/hrtimer.c:1519 [inline]
>  __hrtimer_run_queues+0x2a4/0x750 kernel/time/hrtimer.c:1583
>  hrtimer_interrupt+0xf4/0x2a0 kernel/time/hrtimer.c:1645
>  timer_handler drivers/clocksource/arm_arch_timer.c:647 [inline]
>  arch_timer_handler_virt+0x44/0x70 drivers/clocksource/arm_arch_timer.c:658
>  handle_percpu_devid_irq+0xfc/0x4d0 kernel/irq/chip.c:930
>  generic_handle_irq_desc include/linux/irqdesc.h:152 [inline]
>  generic_handle_irq+0x50/0x70 kernel/irq/irqdesc.c:650
>  __handle_domain_irq+0x9c/0x120 kernel/irq/irqdesc.c:687
>  handle_domain_irq include/linux/irqdesc.h:170 [inline]
>  gic_handle_irq+0xcc/0x108 drivers/irqchip/irq-gic.c:370
>  el1_irq+0xbc/0x180 arch/arm64/kernel/entry.S:651
>  arch_local_irq_restore+0x4/0x8 arch/arm64/include/asm/irqflags.h:124
>  trace_preempt_enable_rcuidle include/trace/events/preemptirq.h:55 [inline]
>  trace_preempt_on+0xf4/0x190 kernel/trace/trace_preemptirq.c:123
>  preempt_latency_stop kernel/sched/core.c:4197 [inline]
>  preempt_schedule_common+0x12c/0x1b0 kernel/sched/core.c:4682
>  preempt_schedule.part.88+0x20/0x28 kernel/sched/core.c:4706
>  preempt_schedule+0x20/0x28 kernel/sched/core.c:4707
>  __raw_spin_unlock_irq include/linux/spinlock_api_smp.h:169 [inline]
>  _raw_spin_unlock_irq+0x80/0x90 kernel/locking/spinlock.c:199
>  rcu_gp_cleanup kernel/rcu/tree.c:2046 [inline]
>  rcu_gp_kthread+0xe5c/0x19a8 kernel/rcu/tree.c:2119
>  kthread+0x174/0x188 kernel/kthread.c:292
>  ret_from_fork+0x10/0x18 arch/arm64/kernel/entry.S:961
> rcu: Stack dump where RCU grace-period kthread last ran:
> Task dump for CPU 0:
> task:rcu_preempt     state:R  running task     stack:    0 pid:   10 ppid:     2 flags:0x00000428
> Call trace:
>  dump_backtrace+0x0/0x278 arch/arm64/kernel/stacktrace.c:100
>  show_stack+0x30/0x80 arch/arm64/kernel/stacktrace.c:196
>  sched_show_task+0x1a8/0x240 kernel/sched/core.c:6445
>  dump_cpu_task+0x48/0x58 kernel/sched/core.c:8428
>  rcu_check_gp_kthread_starvation+0x214/0x358 kernel/rcu/tree_stall.h:474
>  print_other_cpu_stall kernel/rcu/tree_stall.h:544 [inline]
>  check_cpu_stall kernel/rcu/tree_stall.h:664 [inline]
>  rcu_pending kernel/rcu/tree.c:3752 [inline]
>  rcu_sched_clock_irq+0x744/0xd18 kernel/rcu/tree.c:2581
>  update_process_times+0x68/0x98 kernel/time/timer.c:1709
>  tick_sched_handle.isra.16+0x54/0x80 kernel/time/tick-sched.c:176
>  tick_sched_timer+0x64/0xd8 kernel/time/tick-sched.c:1328
>  __run_hrtimer kernel/time/hrtimer.c:1519 [inline]
>  __hrtimer_run_queues+0x2a4/0x750 kernel/time/hrtimer.c:1583
>  hrtimer_interrupt+0xf4/0x2a0 kernel/time/hrtimer.c:1645
>  timer_handler drivers/clocksource/arm_arch_timer.c:647 [inline]
>  arch_timer_handler_virt+0x44/0x70 drivers/clocksource/arm_arch_timer.c:658
>  handle_percpu_devid_irq+0xfc/0x4d0 kernel/irq/chip.c:930
>  generic_handle_irq_desc include/linux/irqdesc.h:152 [inline]
>  generic_handle_irq+0x50/0x70 kernel/irq/irqdesc.c:650
>  __handle_domain_irq+0x9c/0x120 kernel/irq/irqdesc.c:687
>  handle_domain_irq include/linux/irqdesc.h:170 [inline]
>  gic_handle_irq+0xcc/0x108 drivers/irqchip/irq-gic.c:370
>  el1_irq+0xbc/0x180 arch/arm64/kernel/entry.S:651
>  arch_local_irq_restore+0x4/0x8 arch/arm64/include/asm/irqflags.h:124
>  trace_preempt_enable_rcuidle include/trace/events/preemptirq.h:55 [inline]
>  trace_preempt_on+0xf4/0x190 kernel/trace/trace_preemptirq.c:123
>  preempt_latency_stop kernel/sched/core.c:4197 [inline]
>  preempt_schedule_common+0x12c/0x1b0 kernel/sched/core.c:4682
>  preempt_schedule.part.88+0x20/0x28 kernel/sched/core.c:4706
>  preempt_schedule+0x20/0x28 kernel/sched/core.c:4707
>  __raw_spin_unlock_irq include/linux/spinlock_api_smp.h:169 [inline]
>  _raw_spin_unlock_irq+0x80/0x90 kernel/locking/spinlock.c:199
>  rcu_gp_cleanup kernel/rcu/tree.c:2046 [inline]
>  rcu_gp_kthread+0xe5c/0x19a8 kernel/rcu/tree.c:2119
>  kthread+0x174/0x188 kernel/kthread.c:292
>  ret_from_fork+0x10/0x18 arch/arm64/kernel/entry.S:961
> 
> ================================
> WARNING: inconsistent lock state
> 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #23 Not tainted
> --------------------------------
> inconsistent {IN-HARDIRQ-W} -> {HARDIRQ-ON-W} usage.
> rcu_preempt/10 [HC0[0]:SC0[0]:HE0:SE1] takes:
> ffffd787e91d4358 (rcu_node_0){?.-.}-{2:2}, at: print_other_cpu_stall kernel/rcu/tree_stall.h:505 [inline]
> ffffd787e91d4358 (rcu_node_0){?.-.}-{2:2}, at: check_cpu_stall kernel/rcu/tree_stall.h:664 [inline]
> ffffd787e91d4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_pending kernel/rcu/tree.c:3752 [inline]
> ffffd787e91d4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x4a0/0xd18 kernel/rcu/tree.c:2581
> {IN-HARDIRQ-W} state was registered at:
>   mark_lock kernel/locking/lockdep.c:4293 [inline]
>   mark_usage kernel/locking/lockdep.c:4302 [inline]
>   __lock_acquire+0x7bc/0x15b8 kernel/locking/lockdep.c:4785
>   lock_acquire+0x244/0x498 kernel/locking/lockdep.c:5436
>   __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inline]
>   _raw_spin_lock_irqsave+0x78/0x144 kernel/locking/spinlock.c:159
>   print_other_cpu_stall kernel/rcu/tree_stall.h:505 [inline]
>   check_cpu_stall kernel/rcu/tree_stall.h:664 [inline]
>   rcu_pending kernel/rcu/tree.c:3752 [inline]
>   rcu_sched_clock_irq+0x4a0/0xd18 kernel/rcu/tree.c:2581
>   update_process_times+0x68/0x98 kernel/time/timer.c:1709
>   tick_sched_handle.isra.16+0x54/0x80 kernel/time/tick-sched.c:176
>   tick_sched_timer+0x64/0xd8 kernel/time/tick-sched.c:1328
>   __run_hrtimer kernel/time/hrtimer.c:1519 [inline]
>   __hrtimer_run_queues+0x2a4/0x750 kernel/time/hrtimer.c:1583
>   hrtimer_interrupt+0xf4/0x2a0 kernel/time/hrtimer.c:1645
>   timer_handler drivers/clocksource/arm_arch_timer.c:647 [inline]
>   arch_timer_handler_virt+0x44/0x70 drivers/clocksource/arm_arch_timer.c:658
>   handle_percpu_devid_irq+0xfc/0x4d0 kernel/irq/chip.c:930
>   generic_handle_irq_desc include/linux/irqdesc.h:152 [inline]
>   generic_handle_irq+0x50/0x70 kernel/irq/irqdesc.c:650
>   __handle_domain_irq+0x9c/0x120 kernel/irq/irqdesc.c:687
>   handle_domain_irq include/linux/irqdesc.h:170 [inline]
>   gic_handle_irq+0xcc/0x108 drivers/irqchip/irq-gic.c:370
>   el1_irq+0xbc/0x180 arch/arm64/kernel/entry.S:651
>   arch_local_irq_restore+0x4/0x8 arch/arm64/include/asm/irqflags.h:124
>   trace_preempt_enable_rcuidle include/trace/events/preemptirq.h:55 [inline]
>   trace_preempt_on+0xf4/0x190 kernel/trace/trace_preemptirq.c:123
>   preempt_latency_stop kernel/sched/core.c:4197 [inline]
>   preempt_schedule_common+0x12c/0x1b0 kernel/sched/core.c:4682
>   preempt_schedule.part.88+0x20/0x28 kernel/sched/core.c:4706
>   preempt_schedule+0x20/0x28 kernel/sched/core.c:4707
>   __raw_spin_unlock_irq include/linux/spinlock_api_smp.h:169 [inline]
>   _raw_spin_unlock_irq+0x80/0x90 kernel/locking/spinlock.c:199
>   rcu_gp_cleanup kernel/rcu/tree.c:2046 [inline]
>   rcu_gp_kthread+0xe5c/0x19a8 kernel/rcu/tree.c:2119
>   kthread+0x174/0x188 kernel/kthread.c:292
>   ret_from_fork+0x10/0x18 arch/arm64/kernel/entry.S:961
> irq event stamp: 39750
> hardirqs last  enabled at (39749): [<ffffd787e6d85738>] rcu_irq_enter_irqson+0x48/0x68 kernel/rcu/tree.c:1078
> hardirqs last disabled at (39750): [<ffffd787e6c122bc>] el1_irq+0x7c/0x180 arch/arm64/kernel/entry.S:648
> softirqs last  enabled at (36704): [<ffffd787e6c10b58>] __do_softirq+0x650/0x6a4 kernel/softirq.c:325
> softirqs last disabled at (36683): [<ffffd787e6cc0b80>] do_softirq_own_stack include/linux/interrupt.h:568 [inline]
> softirqs last disabled at (36683): [<ffffd787e6cc0b80>] invoke_softirq kernel/softirq.c:393 [inline]
> softirqs last disabled at (36683): [<ffffd787e6cc0b80>] __irq_exit_rcu kernel/softirq.c:423 [inline]
> softirqs last disabled at (36683): [<ffffd787e6cc0b80>] irq_exit+0x1a8/0x1b0 kernel/softirq.c:447
> 
> other info that might help us debug this:
>  Possible unsafe locking scenario:
> 
>        CPU0
>        ----
>   lock(rcu_node_0);
>   <Interrupt>
>     lock(rcu_node_0);
> 
>  *** DEADLOCK ***
> 
> 1 lock held by rcu_preempt/10:
>  #0: ffffd787e91d4358 (rcu_node_0){?.-.}-{2:2}, at: print_other_cpu_stall kernel/rcu/tree_stall.h:505 [inline]
>  #0: ffffd787e91d4358 (rcu_node_0){?.-.}-{2:2}, at: check_cpu_stall kernel/rcu/tree_stall.h:664 [inline]
>  #0: ffffd787e91d4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_pending kernel/rcu/tree.c:3752 [inline]
>  #0: ffffd787e91d4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x4a0/0xd18 kernel/rcu/tree.c:2581
> 
> stack backtrace:
> CPU: 0 PID: 10 Comm: rcu_preempt Not tainted 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #23
> Hardware name: linux,dummy-virt (DT)
> Call trace:
>  dump_backtrace+0x0/0x278 arch/arm64/kernel/stacktrace.c:100
>  show_stack+0x30/0x80 arch/arm64/kernel/stacktrace.c:196
>  __dump_stack lib/dump_stack.c:77 [inline]
>  dump_stack+0x138/0x1b0 lib/dump_stack.c:118
>  print_usage_bug+0x2d8/0x2f8 kernel/locking/lockdep.c:3739
>  valid_state kernel/locking/lockdep.c:3750 [inline]
>  mark_lock_irq kernel/locking/lockdep.c:3953 [inline]
>  mark_lock.part.46+0x370/0x480 kernel/locking/lockdep.c:4410
>  mark_lock kernel/locking/lockdep.c:4008 [inline]
>  mark_held_locks+0x58/0x90 kernel/locking/lockdep.c:4011
>  __trace_hardirqs_on_caller kernel/locking/lockdep.c:4029 [inline]
>  lockdep_hardirqs_on_prepare+0xdc/0x298 kernel/locking/lockdep.c:4097
>  trace_hardirqs_on+0x90/0x388 kernel/trace/trace_preemptirq.c:49
>  el1_irq+0xd8/0x180 arch/arm64/kernel/entry.S:685
>  arch_local_irq_restore+0x4/0x8 arch/arm64/include/asm/irqflags.h:124
>  trace_preempt_enable_rcuidle include/trace/events/preemptirq.h:55 [inline]
>  trace_preempt_on+0xf4/0x190 kernel/trace/trace_preemptirq.c:123
>  preempt_latency_stop kernel/sched/core.c:4197 [inline]
>  preempt_schedule_common+0x12c/0x1b0 kernel/sched/core.c:4682
>  preempt_schedule.part.88+0x20/0x28 kernel/sched/core.c:4706
>  preempt_schedule+0x20/0x28 kernel/sched/core.c:4707
>  __raw_spin_unlock_irq include/linux/spinlock_api_smp.h:169 [inline]
>  _raw_spin_unlock_irq+0x80/0x90 kernel/locking/spinlock.c:199
>  rcu_gp_cleanup kernel/rcu/tree.c:2046 [inline]
>  rcu_gp_kthread+0xe5c/0x19a8 kernel/rcu/tree.c:2119
>  kthread+0x174/0x188 kernel/kthread.c:292
>  ret_from_fork+0x10/0x18 arch/arm64/kernel/entry.S:961
> BUG: scheduling while atomic: rcu_preempt/10/0x00000002
> INFO: lockdep is turned off.
> Modules linked in:
> Preemption disabled at:
> [<ffffd787e7fffec0>] preempt_schedule.part.88+0x20/0x28 kernel/sched/core.c:4706
> CPU: 0 PID: 10 Comm: rcu_preempt Not tainted 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #23
> Hardware name: linux,dummy-virt (DT)
> Call trace:
>  dump_backtrace+0x0/0x278 arch/arm64/kernel/stacktrace.c:100
>  show_stack+0x30/0x80 arch/arm64/kernel/stacktrace.c:196
>  __dump_stack lib/dump_stack.c:77 [inline]
>  dump_stack+0x138/0x1b0 lib/dump_stack.c:118
>  __schedule_bug+0x8c/0xe8 kernel/sched/core.c:4262
>  schedule_debug kernel/sched/core.c:4289 [inline]
>  __schedule+0x7e8/0x890 kernel/sched/core.c:4417
>  preempt_schedule_common+0x44/0x1b0 kernel/sched/core.c:4681
>  preempt_schedule.part.88+0x20/0x28 kernel/sched/core.c:4706
>  preempt_schedule+0x20/0x28 kernel/sched/core.c:4707
>  __raw_spin_unlock_irq include/linux/spinlock_api_smp.h:169 [inline]
>  _raw_spin_unlock_irq+0x80/0x90 kernel/locking/spinlock.c:199
>  rcu_gp_cleanup kernel/rcu/tree.c:2046 [inline]
>  rcu_gp_kthread+0xe5c/0x19a8 kernel/rcu/tree.c:2119
>  kthread+0x174/0x188 kernel/kthread.c:292
>  ret_from_fork+0x10/0x18 arch/arm64/kernel/entry.S:961

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201112200025.GG3249%40paulmck-ThinkPad-P72.
