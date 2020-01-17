Return-Path: <kasan-dev+bncBAABBYEDRHYQKGQEZ63DBXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 511B71414CF
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Jan 2020 00:23:14 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id l13sf20116234ilj.4
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 15:23:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579303393; cv=pass;
        d=google.com; s=arc-20160816;
        b=YPqAHufQ/lIjjEmLrVQAV1gAmkJtK84KkCa2ZnY6n9wqQFkyLHHZJNFt34OxJsboWn
         QswaBI6fy6qMD8Pperk9T6Rm0+ZWLVMfdxr2AH8KO/0X0+TwPUDTS6wl8CTFk+VSeHQI
         pIAOz2d5yS+7FGOQcRnKXGk5ZMwFwG72bZagl0GPIq7EShEFR/VranL0Gr9AZFS/SVEW
         y0rGunDw1C3b2OwQLdpFqBxpw6wdN9Pfv56Ik49L8Q/YChccpu44m4Hpw/otAtSsOBxw
         c7l/f5oCtpNaVUDXQjVN5L4aPaQh0Oci/aoGuklxJY183xT68Yj7dTqsSbCt2hQyYcxc
         Lq1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=1sOsMksHZOhgEvoHGs+Fi4rRjKbyp/3JuFZzAxDo92Q=;
        b=SDQIP7dxdD+8r+3LYdj55ITihURPwr76ivK8zzICmyE23lw1wzDThn0CSlUwe7Rc/2
         Yubr6AqymJnqHwHwW6WBtGYvh71PrnkhyLC6bBpL2tc8EnML9rBD960Y+JT3C3V72ZuS
         3N/O3PBv0dG29xfd92TvXkEYWz13aVopGaX8CKI2uorNKSyneGxxLFJlQFyrV0ntdtU6
         VAfFOIDr0HkYqHfU8CzNVJtByjRYUB/0MTOS5qo2jODxQIfaqWkjh02FgTMkwAgpOOi4
         R5164/v3/7g5yTrjWDZfqEdzNR9x3SnUKGjOsP68EyPhdWCeKtkvUgbPp4e0epkuvCMG
         3ngQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=c0PK9QjL;
       spf=pass (google.com: domain of srs0=uzqh=3g=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Uzqh=3G=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1sOsMksHZOhgEvoHGs+Fi4rRjKbyp/3JuFZzAxDo92Q=;
        b=Ao3i2PcefwAcA9F/Bi5/53SUs4JU5jg4Ww2/2u9vzIJjChrfQS2Fkh2mQ75UPszI/m
         wNPjhy7CNuka4gxEb7JYiUMeKNTOVvDRqsYphcgCMV0vrjVmtb37ejV+7yjuJewyXKb4
         InqKdyvfNQ3fr9t2YvvdwSCP5SHu7m7CXARpbzHs5U/iqALOT1cXIBO4VAEuZDpkRRdJ
         t5BxLmpfAIec+ErRMUmaSU26t7mnsnwt3A1cSBASzUb+NGIfPoJ0wts4N6xxeRennE4z
         nLbxZ1TAL3Iz3XGCD56zoeLtV9euB/2UvlKztqQz30yRKcHmLsnrekDbFjYB/mGj9fiE
         R/RQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1sOsMksHZOhgEvoHGs+Fi4rRjKbyp/3JuFZzAxDo92Q=;
        b=moDrd3BPS4HUOXi95+KWkfNpoKkX6K7YRGMwLnWjJdBzm2/uXPa9uIYgE87+B1TIlX
         rXWL0vc86crF2/OSmYYz5M7axSZ/GudkzJ23RTL4+vo+sZGibH6raHQ/xPDiGAOpSsXx
         5S/1nU6jB96qS6Ul58QSIidYNUdvbKGV9Rytg/5Ln/K49caVgfSzlz48OtMAHh1+bXsl
         jJmnt7iF0lhg8ivEjsZBi1uWjOirl1UugmUPdZa1CR1tlFGOmRZBAS7742jqAFJMtYMR
         gq1fcKuUo04i/RA8D8WRXnPxuCW8JBqG5vTxRMBzd1f5DYGAayOorSHHA8gCIopZYrdL
         X+sA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVuS/ayctcRK8Jz3Zt6Gsz21hgSoDFcE+Zm0DcUGkf0FuJYQwdY
	Q2coU+xcHDDOlbMHhD6lXn8=
X-Google-Smtp-Source: APXvYqx8uaLGoL+XMyrX2/c6fAY2Bok9wXIzgKiKvH2VQUBU2sNjBGopVVCIcezIHPVpQDV9Cy8byQ==
X-Received: by 2002:a02:bb02:: with SMTP id y2mr34416712jan.99.1579303392785;
        Fri, 17 Jan 2020 15:23:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:7f85:: with SMTP id r127ls2274298jac.14.gmail; Fri, 17
 Jan 2020 15:23:12 -0800 (PST)
X-Received: by 2002:a02:856a:: with SMTP id g97mr3142295jai.97.1579303392375;
        Fri, 17 Jan 2020 15:23:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579303392; cv=none;
        d=google.com; s=arc-20160816;
        b=BFt88quyt32bunf6j68PDiEZdp3bHbLHFqfC3kxV1O70vGPQH8JJfj/4xn8FPyU9WZ
         +nT+P3vja/mBka3MwH15j1XtVHNm7yj2d69X81Cp25FTiH/XUejACzJ4wHfeDUgb2/+/
         oxfy3eGc4+/flIcwvasWkLCQUovP7PalRHagPX8nt4IQY5DRyhMfq0nUrTVXKnos/CSk
         5ZbO9iIH14lzr2L3JvGukifKlSvF/GetkgOPXztyyTPAez5HWPQaszAjTSMmhGhZMbcL
         3qI5e/KFqC7XVN7Y7fKEdcPIHD1r6ditzrO3Bp8u65mU13cNOZ002QqxO7Gx7oLq8Imd
         6I+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=e9Tk8IijtZVVuLAz8z3+3XCT0Cx3J2owC39fYub6qfs=;
        b=Lgk4XA1aChHg7Tt/K1hOIU/HcimiRerYP+uvVV2Hq0keVaLG5sU1cJ2MhuEGePGUuP
         zgFgIPE8lWuAM/DDlmvCXAyM1r+HgWfgrUskmjP24j7GFTAW/W5o/mtuyPd3tzYrDODp
         8rt6FHpScvPAuslLZ9BUgTPYTyapYlCS0bx6yuCSw9zY1AxaCklxJ3dxZonfCBShzfKA
         0oCWp8iRsedg4SjqTi75oaBrO9UJEoIYRy0CmoeAy3f2Dec0MFbbWIo8u2K73ggeFmPZ
         Bq/3/HyLp3SNP1VvQVizs4vqABLKYoX1l2/30EUXvRyq41QA9zx7gDIlrT8CZ2Cax5iR
         VKpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=c0PK9QjL;
       spf=pass (google.com: domain of srs0=uzqh=3g=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Uzqh=3G=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z6si1074911iof.2.2020.01.17.15.23.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Jan 2020 15:23:12 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=uzqh=3g=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id A737E22464;
	Fri, 17 Jan 2020 23:23:11 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 7C24935228BF; Fri, 17 Jan 2020 15:23:11 -0800 (PST)
Date: Fri, 17 Jan 2020 15:23:11 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Qian Cai <cai@lca.pw>, Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Dmitriy Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>
Subject: Re: [PATCH -rcu] kcsan: Make KCSAN compatible with lockdep
Message-ID: <20200117232311.GP2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200114124919.11891-1-elver@google.com>
 <CAG_fn=X1rFGd1gfML3D5=uiLKTmMbPUm0UD6D0+bg+_hJtQMqA@mail.gmail.com>
 <CANpmjNP6+NTr7_rkNPVDbczst5vutW2K6FXXqkqFg6GGbQC31Q@mail.gmail.com>
 <20200115163754.GA2935@paulmck-ThinkPad-P72>
 <B2717BA1-B964-4B0A-BE4F-5B244087B9E5@lca.pw>
 <CANpmjNNfJ=n-yUfUByLfXvHc3GfUGaECZLbu7Hh05z38WSgd4g@mail.gmail.com>
 <20200117164017.GA21582@paulmck-ThinkPad-P72>
 <CANpmjNOetNDfuAu6eaDap=S0tTL5qaOz_Vh18EQ3uEfuCmFLWg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOetNDfuAu6eaDap=S0tTL5qaOz_Vh18EQ3uEfuCmFLWg@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=c0PK9QjL;       spf=pass
 (google.com: domain of srs0=uzqh=3g=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Uzqh=3G=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Fri, Jan 17, 2020 at 11:54:47PM +0100, Marco Elver wrote:
> On Fri, 17 Jan 2020 at 17:40, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Thu, Jan 16, 2020 at 07:57:30PM +0100, Marco Elver wrote:
> > > On Thu, 16 Jan 2020 at 04:39, Qian Cai <cai@lca.pw> wrote:
> > > > > On Jan 15, 2020, at 11:37 AM, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > > On Wed, Jan 15, 2020 at 05:26:55PM +0100, Marco Elver wrote:
> > > > >> On Tue, 14 Jan 2020 at 18:24, Alexander Potapenko <glider@google.com> wrote:
> > > > >>>
> > > > >>>> --- a/kernel/kcsan/core.c
> > > > >>>> +++ b/kernel/kcsan/core.c
> > > > >>>> @@ -337,7 +337,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
> > > > >>>>         *      detection point of view) to simply disable preemptions to ensure
> > > > >>>>         *      as many tasks as possible run on other CPUs.
> > > > >>>>         */
> > > > >>>> -       local_irq_save(irq_flags);
> > > > >>>> +       raw_local_irq_save(irq_flags);
> > > > >>>
> > > > >>> Please reflect the need to use raw_local_irq_save() in the comment.
> > > > >>>
> > > > >>>>
> > > > >>>>        watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
> > > > >>>>        if (watchpoint == NULL) {
> > > > >>>> @@ -429,7 +429,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
> > > > >>>>
> > > > >>>>        kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
> > > > >>>> out_unlock:
> > > > >>>> -       local_irq_restore(irq_flags);
> > > > >>>> +       raw_local_irq_restore(irq_flags);
> > > > >>>
> > > > >>> Ditto
> > > > >>
> > > > >> Done. v2: http://lkml.kernel.org/r/20200115162512.70807-1-elver@google.com
> > > > >
> > > > > Alexander and Qian, could you please let me know if this fixes things
> > > > > up for you?
> > > >
> > > > The lockdep warning is gone, so feel free to add,
> > > >
> > > > Tested-by: Qian Cai <cai@lca.pw>
> > >
> > > Thank you for testing!
> > >
> > > > for that patch, but the system is still unable to boot due to spam of
> > > > warnings due to incompatible with debug_pagealloc, debugobjects, so
> > > > the warning rate limit does not help.
> > >
> > > You may also try to set CONFIG_KCSAN_REPORT_ONCE_IN_MS to something
> > > large, say 1000000000 (effectively reporting each data race once).
> > >
> > > That being said, there are 2 options here:
> > >
> > > Option 1. If that still isn't satisfactory, we can try to make the
> > > system somehow tolerate the excessive number of data race reports
> > > (there may indeed be other printk limits based on rate or context we
> > > are hitting). More important appears to be the below...
> > >
> > > Option 2. Investigate and fix the bugs, or declare them "benign" to
> > > the tool. Compared to option (1) this will have much bigger impact on
> > > the kernel, as it not only improves the kernel with all the debugging
> > > tools enabled, but more importantly, improves the kernel *without* the
> > > debugging tools. This is what should be our goal here.
> >
> > True enough, but even if we reach the nirvana state where there is general
> > agreement on what constitutes a data race in need of fixing and KCSAN
> > faithfully checks based on that data-race definition, we need to handle
> > the case where someone introduces a bug that results in a destructive
> > off-CPU access to a per-CPU variable, which is exactly the sort of thing
> > that KCSAN is supposed to detect.  But suppose that this variable is
> > frequently referenced from functions that are inlined all over the place.
> >
> > Then that one bug might result in huge numbers of data-race reports in
> > a very short period of time, especially on a large system.
> >
> > So, yes, option 2 is important, but it is in no way a substitute for
> > KCSAN doing a good job of handling of option 1.
> >
> > And given limited console bandwidth, there will be cases where data-race
> > reports
> > must be dropped.  After all, in such cases, the only other option is to
> > hang the system.  There are ways to reduce the number of such cases, and
> > of course your recent (and much appreciated!) patches merging identical
> > reports is a great example of this.  But Qian's experience indicates that
> > this does not cover all cases -- nor would I expect it to have done so.
> 
> Agreed. And I'll keep looking into this.

Very good, thank you!

> > > With that in mind, I tried to fix debugobjects data races:
> > >   http://lkml.kernel.org/r/20200116185529.11026-1-elver@google.com
> > > Feel free to test, and reply to that patch with comments.
> >
> > Very good!
> >
> > For my part, I am quite a bit closer to having RCU free of KCSAN reports.
> > One of the remaining ones looks related to a bug in rcu_barrier()'s
> > handling of no-CBs CPUs that shows up once per few hundred hours
> > of rcutorture testing of TREE04.  KCSAN did find some real bugs, so
> > thank you!  Sadly, it does not (yet) find this one, but it does find
> > consequences of it, which will at least reduce the testing burden once
> > I do get it fixed.
> 
> Interesting.  I wonder if it doesn't find it because of missing
> instrumentation of some arch asm?

The problem is that the large system has a gcc that is too old to
do KCSAN, and the system with a newer gcc has only 12 CPUs, and would
thus need to run for about a week and a half to have a 50% chance of
catching an actual failure.

At some point, I install a newer gcc on the large system, but I need
to do bulk testing to confirm/invalidate my guesses as to what Kconfig
options and kernel versions are needed to trigger this bug.

Good clean fun!  ;-)

							Thanx, Paul

> Thanks,
> -- Marco
> 
> 
> > (So, yes, if anyone is seeing rcu_barrier() returning too soon on systems
> > with CONFIG_RCU_NOCB_CPU=y on a system whose console output includes the
> > string "Offload RCU callbacks from CPUs" with at least one CPU listed
> > (as opposed to the string "(none)", please do let me know!  My best
> > guess is that this was introduced in v5.4.)
> >
> >                                                         Thanx, Paul
> >
> > > Thanks,
> > > -- Marco
> > >
> > >
> > >
> > >
> > >
> > >
> > > > [   28.992752][  T394] Reported by Kernel Concurrency Sanitizer on:
> > > > [   28.992752][  T394] CPU: 0 PID: 394 Comm: pgdatinit0 Not tainted 5.5.0-rc6-next-20200115+ #3
> > > > [   28.992752][  T394] Hardware name: HP ProLiant XL230a Gen9/ProLiant XL230a Gen9, BIOS U13 01/22/2018
> > > > [   28.992752][  T394] ===============================================================
> > > > [   28.992752][  T394] ==================================================================
> > > > [   28.992752][  T394] BUG: KCSAN: data-race in __change_page_attr / __change_page_attr
> > > > [   28.992752][  T394]
> > > > [   28.992752][  T394] read to 0xffffffffa01a6de0 of 8 bytes by task 395 on cpu 16:
> > > > [   28.992752][  T394]  __change_page_attr+0xe81/0x1620
> > > > [   28.992752][  T394]  __change_page_attr_set_clr+0xde/0x4c0
> > > > [   28.992752][  T394]  __set_pages_np+0xcc/0x100
> > > > [   28.992752][  T394]  __kernel_map_pages+0xd6/0xdb
> > > > [   28.992752][  T394]  __free_pages_ok+0x1a8/0x730
> > > > [   28.992752][  T394]  __free_pages+0x51/0x90
> > > > [   28.992752][  T394]  __free_pages_core+0x1c7/0x2c0
> > > > [   28.992752][  T394]  deferred_free_range+0x59/0x8f
> > > > [   28.992752][  T394]  deferred_init_max21d
> > > > [   28.992752][  T394]  deferred_init_memmap+0x14a/0x1c1
> > > > [   28.992752][  T394]  kthread+0x1e0/0x200
> > > > [   28.992752][  T394]  ret_from_fork+0x3a/0x50
> > > > [   28.992752][  T394]
> > > > [   28.992752][  T394] write to 0xffffffffa01a6de0 of 8 bytes by task 394 on cpu 0:
> > > > [   28.992752][  T394]  __change_page_attr+0xe9c/0x1620
> > > > [   28.992752][  T394]  __change_page_attr_set_clr+0xde/0x4c0
> > > > [   28.992752][  T394]  __set_pages_np+0xcc/0x100
> > > > [   28.992752][  T394]  __kernel_map_pages+0xd6/0xdb
> > > > [   28.992752][  T394]  __free_pages_ok+0x1a8/0x730
> > > > [   28.992752][  T394]  __free_pages+0x51/0x90
> > > > [   28.992752][  T394]  __free_pages_core+0x1c7/0x2c0
> > > > [   28.992752][  T394]  deferred_free_range+0x59/0x8f
> > > > [   28.992752][  T394]  deferred_init_maxorder+0x1d6/0x21d
> > > > [   28.992752][  T394]  deferred_init_memmap+0x14a/0x1c1
> > > > [   28.992752][  T394]  kthread+0x1e0/0x200
> > > > [   28.992752][  T394]  ret_from_fork+0x3a/0x50
> > > >
> > > >
> > > > [   93.233621][  T349] Reported by Kernel Concurrency Sanitizer on:
> > > > [   93.261902][  T349] CPU: 19 PID: 349 Comm: kworker/19:1 Not tainted 5.5.0-rc6-next-20200115+ #3
> > > > [   93.302634][  T349] Hardware name: HP ProLiant XL230a Gen9/ProLiant XL230a Gen9, BIOS U13 01/22/2018
> > > > [   93.345413][  T349] Workqueue: memcg_kmem_cache memcg_kmem_cache_create_func
> > > > [   93.378715][  T349] ==================================================================
> > > > [   93.416183][  T616] ==================================================================
> > > > [   93.453415][  T616] BUG: KCSAN: data-race in __debug_object_init / fill_pool
> > > > [   93.486775][  T616]
> > > > [   93.497644][  T616] read to 0xffffffff9ff33b78 of 4 bytes by task 617 on cpu 12:
> > > > [   93.534139][  T616]  fill_pool+0x38/0x700
> > > > [   93.554913][  T616]  __debug_object_init+0x3f/0x900
> > > > [   93.579459][  T616]  debug_object_init+0x39/0x50
> > > > [   93.601952][  T616]  __init_work+0x3e/0x50
> > > > [   93.620611][  T616]  memcg_kmem_get_cache+0x3c8/0x480
> > > > [   93.643619][  T616]  slab_pre_alloc_hook+0x5d/0xa0
> > > > [   93.665134][  T616]  __kmalloc_node+0x60/0x300
> > > > [   93.685094][  T616]  kvmalloc_node+0x83/0xa0
> > > > [   93.704235][  T616]  seq_read+0x57c/0x7a0
> > > > [   93.722460][  T616]  proc_reg_read+0x11a/0x160
> > > > [   93.743570][  T616]  __vfs_read+0x59/0xa0
> > > > [   93.761660][  T616]  vfs_read+0xcf/0x1c0
> > > > [   93.779269][  T616]  ksys_read+0x9d/0x130
> > > > [   93.797267][  T616]  __x64_sys_read+0x4c/0x60
> > > > [   93.817205][  T616]  do_syscall_64+0x91/0xb47
> > > > [   93.837590][  T616]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> > > > [   93.864425][  T616]
> > > > [   93.874830][  T616] write to 0xffffffff9ff33b78 of 4 bytes by task 616 on cpu 61:
> > > > [   93.908534][  T616]  __debug_object_init+0x6e5/0x900
> > > > [   93.931018][  T616]  debug_object_activate+0x1fc/0x350
> > > > [   93.954131][  T616]  call_rcu+0x4c/0x4e0
> > > > [   93.971959][  T616]  put_object+0x6a/0x90
> > > > [   93.989955][  T616]  __delete_object+0xb9/0xf0
> > > > [   94.009996][  T616]  delete_object_full+0x2d/0x40
> > > > [   94.031812][  T616]  kmemleak_free+0x5f/0x90
> > > > [   94.054671][  T616]  slab_free_freelist_hook+0x124/0x1c0
> > > > [   94.082027][  T616]  kmem_cache_free+0x10c/0x3a0
> > > > [   94.103806][  T616]  vm_area_free+0x31/0x40
> > > > [   94.124587][  T616]  remove_vma+0xb0/0xc0
> > > > [   94.143484][  T616]  exit_mmap+0x14c/0x220
> > > > [   94.163826][  T616]  mmput+0x10e/0x270
> > > > [   94.181736][  T616]  flush_old_exec+0x572/0xfe0
> > > > [   94.202760][  T616]  load_elf_binary+0x467/0x2180
> > > > [   94.224819][  T616]  search_binary_handler+0xd8/0x2b0
> > > > [   94.248735][  T616]  __do_execve_file+0xb61/0x1080
> > > > [   94.270943][  T616]  __x64_sys_execve+0x5f/0x70
> > > > [   94.292254][  T616]  do_syscall_64+0x91/0xb47
> > > > [   94.312712][  T616]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> > > >
> > > > [  103.455945][   C22] Reported by Kernel Concurrency Sanitizer on:
> > > > [  103.483032][   C22] CPU: 22 PID: 0 Comm: swapper/22 Not tainted 5.5.0-rc6-next-20200115+ #3
> > > > [  103.520563][   C22] Hardware name: HP ProLiant XL230a Gen9/ProLiant XL230a Gen9, BIOS U13 01/22/2018
> > > > [  103.561771][   C22] ==================================================================
> > > > [  103.598005][   C41] ==================================================================
> > > > [  103.633820][   C41] BUG: KCSAN: data-race in intel_pstate_update_util / intel_pstate_update_util
> > > > [  103.673408][   C41]
> > > > [  103.683214][   C41] read to 0xffffffffa9098a58 of 2 bytes by interrupt on cpu 2:
> > > > [  103.716645][   C41]  intel_pstate_update_util+0x580/0xb40
> > > > [  103.740609][   C41]  cpufreq_update_util+0xb0/0x160
> > > > [  103.762611][   C41]  update_blocked_averages+0x585/0x630
> > > > [  103.786435][   C41]  run_rebalance_domains+0xd5/0x240
> > > > [  103.812821][   C41]  __do_softirq+0xd9/0x57c
> > > > [  103.834438][   C41]  irq_exit+0xa2/0xc0
> > > > [  103.851773][   C41]  smp_apic_timer_interrupt+0x190/0x480
> > > > [  103.876005][   C41]  apic_timer_interrupt+0xf/0x20
> > > > [  103.897495][   C41]  cpuidle_enter_state+0x18a/0x9b0
> > > > [  103.919324][   C41]  cpuidle_enter+0x69/0xc0
> > > > [  103.938405][   C41]  call_cpuidle+0x23/0x40
> > > > [  103.957152][   C41]  do_idle+0x248/0x280
> > > > [  103.974728][   C41]  cpu_startup_entry+0x1d/0x1f
> > > > [  103.995059][   C41]  start_secondary+0x1ad/0x230
> > > > [  104.015920][   C41]  secondary_startup_64+0xb6/0xc0
> > > > [  104.037376][   C41]
> > > > [  104.047144][   C41] write to 0xffffffffa9098a59 of 1 bytes by interrupt on cpu 41:
> > > > [  104.081113][   C41]  intel_pstate_update_util+0x4cf/0xb40
> > > > [  104.105862][   C41]  cpufreq_update_util+0xb0/0x160
> > > > [  104.127759][   C41]  update_load_avg+0x70e/0x800
> > > > [  104.148400][   C41]  task_tick_fair+0x5c/0x680
> > > > [  104.168325][   C41]  scheduler_tick+0xab/0x120
> > > > [  104.188881][   C41]  update_process_times+0x44/0x60
> > > > [  104.210811][   C41]  tick_sched_handle+0x4f/0xb0
> > > > [  104.231137][   C41]  tick_sched_timer+0x45/0xc0
> > > > [  104.251431][   C41]  __hrtimer_run_queues+0x243/0x800
> > > > [  104.274362][   C41]  hrtimer_interrupt+0x1d4/0x3e0
> > > > [  104.295860][   C41]  smp_apic_timer_interrupt+0x11d/0x480
> > > > [  104.325136][   C41]  apic_timer_interrupt+0xf/0x20
> > > > [  104.347864][   C41]  __kcsan_check_access+0x1a/0x120
> > > > [  104.370100][   C41]  __read_once_size+0x1f/0xe0
> > > > [  104.390064][   C41]  smp_call_function_many+0x4b0/0x5d0
> > > > [  104.413591][   C41]  on_each_cpu+0x46/0x90
> > > > [  104.431954][   C41]  flush_tlb_kernel_range+0x97/0xc0
> > > > [  104.454702][   C41]  free_unmap_vmap_area+0xaa/0xe0
> > > > [  104.476699][   C41]  remove_vm_area+0xf4/0x100
> > > > [  104.496763][   C41]  __vunmap+0x10a/0x460
> > > > [  104.514807][   C41]  __vfree+0x33/0x90
> > > > [  104.531597][   C41]  vfree+0x47/0x80
> > > > [  104.547600][   C41]  n_tty_close+0x56/0x80
> > > > [  104.565988][   C41]  tty_ldisc_close+0x76/0xa0
> > > > [  104.585912][   C41]  tty_ldisc_kill+0x51/0xa0
> > > > [  104.605864][   C41]  tty_ldisc_release+0xf4/0x1a0
> > > > [  104.627098][   C41]  tty_release_struct+0x23/0x60
> > > > [  104.648268][   C41]  tty_release+0x673/0x9c0
> > > > [  104.667517][   C41]  __fput+0x187/0x410
> > > > [  104.684357][   C41]  ____fput+0x1e/0x30
> > > > [  104.701542][   C41]  task_work_run+0xed/0x140
> > > > [  104.721358][   C41]  do_syscall_64+0x803/0xb47
> > > > [  104.740872][   C41]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> > > >
> > > > [  136.745789][   C34] Reported by Kernel Concurrency Sanitizer on:
> > > > [  136.774278][   C34] CPU: 34 PID: 0 Comm: swapper/34 Not tainted 5.5.0-rc6-next-20200115+ #3
> > > > [  136.814948][   C34] Hardware name: HP ProLiant XL230a Gen9/ProLiant XL230a Gen9, BIOS U13 01/22/2018
> > > > [  136.861974][   C34] ==================================================================
> > > > [  136.911354][    T1] ==================================================================
> > > > [  136.948491][    T1] BUG: KCSAN: data-race in __debug_object_init / fill_pool
> > > > [  136.981645][    T1]
> > > > [  136.992045][    T1] read to 0xffffffff9ff33b78 of 4 bytes by task 762 on cpu 25:
> > > > [  137.026513][    T1]  fill_pool+0x38/0x700
> > > > [  137.045575][    T1]  __debug_object_init+0x3f/0x900
> > > > [  137.068826][    T1]  debug_object_activate+0x1fc/0x350
> > > > [  137.093102][    T1]  call_rcu+0x4c/0x4e0
> > > > [  137.111520][    T1]  __fput+0x23a/0x410
> > > > [  137.129618][    T1]  ____fput+0x1e/0x30
> > > > [  137.147627][    T1]  task_work_run+0xed/0x140
> > > > [  137.168322][    T1]  do_syscall_64+0x803/0xb47
> > > > [  137.188572][    T1]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> > > > [  137.215309][    T1]
> > > > [  137.225579][    T1] write to 0xffffffff9ff33b78 of 4 bytes by task 1 on cpu 7:
> > > > [  137.259867][    T1]  __debug_object_init+0x6e5/0x900
> > > > [  137.283065][    T1]  debug_object_activate+0x1fc/0x350
> > > > [  137.306988][    T1]  call_rcu+0x4c/0x4e0
> > > > [  137.326804][    T1]  dentry_free+0x70/0xe0
> > > > [  137.347208][    T1]  __dentry_kill+0x1db/0x300
> > > > [  137.369468][    T1]  shrink_dentry_list+0x153/0x2e0
> > > > [  137.393437][    T1]  shrink_dcache_parent+0x1ee/0x320
> > > > [  137.417174][    T1]  d_invalidate+0x80/0x130
> > > > [  137.437280][    T1]  proc_flush_task+0x14c/0x2b0
> > > > [  137.459263][    T1]  release_task.part.21+0x156/0xb50
> > > > [  137.483580][    T1]  wait_consider_task+0x17a8/0x1960
> > > > [  137.507550][    T1]  do_wait+0x25b/0x560
> > > > [  137.526175][    T1]  kernel_waitid+0x194/0x270
> > > > [  137.547105][    T1]  __do_sys_waitid+0x18e/0x1e0
> > > > [  137.568951][    T1]  __x64_sys_waitid+0x70/0x90
> > > > [  137.590291][    T1]  do_syscall_64+0x91/0xb47
> > > > [  137.610681][    T1]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> > > >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200117232311.GP2935%40paulmck-ThinkPad-P72.
