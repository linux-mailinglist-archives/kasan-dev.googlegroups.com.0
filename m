Return-Path: <kasan-dev+bncBAABBGNGXH7AKGQEZCHXVOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B61A2D1577
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 17:06:51 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id t8sf9949821pfl.17
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 08:06:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607357210; cv=pass;
        d=google.com; s=arc-20160816;
        b=0zbeceXxi6GAdeXKxAIv4apdxdwDALWJioEl91JY/UVTGZMOSxyInBwTqmQO2+u/oa
         JZMv4n/D85s5kk+bO0bft6zsuOZBAOIgSnOc/PxgvJGSDo5Mv2xG/AKXvnLyY4Pnlrkd
         TSx5eSqjBqIVmObQ9RTgBpDPcflmgh11UqqAdyxpDRxFxnXtHKYOx1MND61vEI3CEtD8
         QUGWUyjcumC82eOwH1tjpteHAfLoCJV5Y84iMeXQuHyKWEfwmhgMCDOIPJRFhx1cCsGX
         N20891czFKG24IB338mwhD2zTuvvfVzwHUvkE7xqMZfdfDPyaigkdohu2ZaRQm4BhIKq
         IMaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=gTTvWFvyk4JYyw39NBuASOeXmB4jtaIku81GTf3pkfo=;
        b=DI1xxO7Z6icf3hyH1rHXd1z1L18n46ZEMa3YkqQYQdpUSx7wAj6INKp9IMMmfWAn+w
         8gScQktp4GfzglGIQsuWGluLuRPMfivq0pZGPGLIstHKJ7wsfL0yrN5Ni/boPLv4PZbm
         FBWXUqzYulB2qihccaeywy6jLADOO7LjnxqntQIKytR+Jw0ZNeKC6pWWst69jfuqIk5a
         cWf1fEzQIsXcHTVdhwUod3AlSS2TqhjmlucE9aMH/6/j9mSa+QHzeR3cyRpNZKRCsc6v
         PYZ8w8ISfzp/+MmaTQHHj/oGHd7sP5adygjCVC8koO18F8Wt6kMPQP2dA06HFB188Lw0
         EQZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cL8X5GJd;
       spf=pass (google.com: domain of srs0=y2i0=fl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Y2I0=FL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gTTvWFvyk4JYyw39NBuASOeXmB4jtaIku81GTf3pkfo=;
        b=tbJCKMWqC5qwu0KtO5NrvjOLvuxfxVAwVRvnW9PsX9YQJbNU3RbAn2LEYztRsbQkAq
         IM//XlzFSYXPdgFoDn/JhgZbs9x3lf3K1ecvWVbTq1Kpcb0diYA/mwO/sFcJQAbsvqa9
         MsS9xqqO4YP11uTNPh+QKwVhugSfia3TnkOZ2CuacPg89r2Dz0u1wIzaB7xc98JDE6/Q
         6/pBYX1leNM05O/HkvzwbELjQPDYn9TOaySqjp2FWMmGUnu1gkd7ORFSAl8lbxykrhEn
         wnyhL0k00nSNMk+BwTjtOosdolDzTFcXauYssMD4oBn5QZMG6wCu6b6MNBgTLfZ5K/in
         omaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gTTvWFvyk4JYyw39NBuASOeXmB4jtaIku81GTf3pkfo=;
        b=nUiM7kH2p01f2+1/jpXCXPDfAlDxiFK1YxZxg2GNo3OmhIsc/oD8alokAb6V2nCBi3
         5fGTMkIM2Su86Sn8wqU4J2H6p6WHH336xIJ6EbGnVxB+BROAT7M45j1pv54KMB0y8sGF
         7X3YS/cVartiJBGqcj3+oXAelz1OrxJ9PJkqpQoqj8egyUj7kC2LhtXFFUb6BYv5Q+2U
         fLy0hVZGnXpA0eZdNOywLHcTAuhDPWX8NAdqDm/rccqtsNll5s/Yq77+dyie4nGbsYj4
         GtMIjMP58Wknf2uIHkKuAYmwWWxzadAEFybi6DoONSN4LuthM4UwOKfTBJCtKxy3yixq
         DzqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5303IkLFqWrDRS2R3PJGQJu5T7DaHbzqoVI+YszHFecRIDzvgiLT
	/CscybJsOdR13sDLGQ4KF0Y=
X-Google-Smtp-Source: ABdhPJwKwer7QTzKW8xFb0J6CNQ7xhhpF31GuXyTDG6zCCdJJWwO3vj+q5SzsxyjoiPJ1WbelxzyXw==
X-Received: by 2002:a62:ce8a:0:b029:19e:3bfe:eac0 with SMTP id y132-20020a62ce8a0000b029019e3bfeeac0mr1516399pfg.69.1607357210146;
        Mon, 07 Dec 2020 08:06:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:174c:: with SMTP id 12ls372413pgx.2.gmail; Mon, 07 Dec
 2020 08:06:49 -0800 (PST)
X-Received: by 2002:a63:9217:: with SMTP id o23mr344887pgd.268.1607357209627;
        Mon, 07 Dec 2020 08:06:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607357209; cv=none;
        d=google.com; s=arc-20160816;
        b=tcTnR/8z0IP+/pnjWQV73gcsUQUDlK9WR9PtYj8WTQzT11a3HIpSABiGvqJsnXlWLK
         neSQRZLMveVSX4NXPSqq6EPILS3c2wd1evLx8J3QZiXP15gi8DHN3aNzVMkGRZqRsiPz
         bHdnEtvZ1cYn24GtFPakn4MT8HeI2oFNrXBP6On1ohNRjLe21fSg/7G9TowOvyTMVNcG
         azKUB4uLaJM8tTToRKeSh48NopROvcTE5qGb5kW8Z2f1UZF+ExELrCTGjty3HcyCZ7Dq
         lzr/zJYumNGModNo8e5SyA3T14tkNUTZsfeXFY+gmx5dQRKtxzXxjZIf7S1VSMnYvlyF
         AJJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:dkim-signature:date;
        bh=1sPDPfYx60px5PiaQosmcFBvOMlZ0ie209jszOUqn/Y=;
        b=scGEWFOwFjgoK28wGaqAcCBsmlc1zEIlqoJ5kAHgUjIL/x+dvgSj/LLwZ+qWN0Aq/b
         FRe8wGPXKdpqvnDxn7ur2GIw7BD5qEqummA851pHleN9QLspfsfQYOdLWDUPdlwmRABm
         SwGLXT+DWrPLrimL5375jjEaB9VM0zzTe/ni7/KW+VeO1E8twtpt2bB7smwslO6oPB8J
         arOvQREAhu6NCTm2wsV8w26stYjoaZju4wYChHhJdo0ymhduzq1Hi/8wufyvw36pMG7p
         0S6x57+KxKRkDM3sctsdzGxaSvRI/3rgY/K6oZRPxoLC+mn8aLieFK+eDVku0weQnnkx
         5GOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cL8X5GJd;
       spf=pass (google.com: domain of srs0=y2i0=fl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Y2I0=FL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e19si941306pgv.4.2020.12.07.08.06.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Dec 2020 08:06:49 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=y2i0=fl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Mon, 7 Dec 2020 08:06:48 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Anna-Maria Behnsen <anna-maria@linutronix.de>
Subject: Re: timers: Move clearing of base::timer_running under base::lock
Message-ID: <20201207160648.GF2657@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <87lfea7gw8.fsf@nanos.tec.linutronix.de>
 <20201207130753.kpxf2ydroccjzrge@linutronix.de>
 <87a6up7kpt.fsf@nanos.tec.linutronix.de>
 <20201207152533.rybefuzd57kxxv57@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201207152533.rybefuzd57kxxv57@linutronix.de>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=cL8X5GJd;       spf=pass
 (google.com: domain of srs0=y2i0=fl=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Y2I0=FL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Dec 07, 2020 at 04:25:33PM +0100, Sebastian Andrzej Siewior wrote:
> On 2020-12-07 15:29:50 [+0100], Thomas Gleixner wrote:
> > On Mon, Dec 07 2020 at 14:07, Sebastian Andrzej Siewior wrote:
> > > One thing I noticed while testing it is that the "corner" case in
> > > timer_sync_wait_running() is quite reliably hit by rcu_preempt
> > > rcu_gp_fqs_loop() -> swait_event_idle_timeout_exclusive() invocation.
> > 
> > I assume it's something like this:
> > 
> >      timeout -> wakeup
> > 
> > ->preemption
> >         del_timer_sync()
> >                 .....
> 
> Yes, but it triggers frequently. Like `rcuc' is somehow is aligned with
> the timeout.

Given that a lot of RCU processing is event-driven based on timers,
and given that the scheduling-clock interrupts are synchronized for
energy-efficiency reasons on many configs, maybe this alignment is
expected behavior?

							Thanx, Paul

> |          <idle>-0       [007] dN.h4..    46.299705: sched_wakeup: comm=rcuc/7 pid=53 prio=98 target_cpu=007
> |          <idle>-0       [007] d...2..    46.299728: sched_switch: prev_comm=swapper/7 prev_pid=0 prev_prio=120 prev_state=R ==> next_comm=rcuc/7 next_pid=53 next_prio=98
> |          rcuc/7-53      [007] d...2..    46.299742: sched_switch: prev_comm=rcuc/7 prev_pid=53 prev_prio=98 prev_state=S ==> next_comm=ksoftirqd/7 next_pid=54 next_prio=120
> |     ksoftirqd/7-54      [007] .....13    46.299750: timer_expire_entry: timer=000000003bd1e045 function=process_timeout now=4294903802 baseclk=4294903802
> |     ksoftirqd/7-54      [007] d...213    46.299750: sched_waking: comm=rcu_preempt pid=11 prio=98 target_cpu=007
> |     ksoftirqd/7-54      [007] dN..313    46.299754: sched_wakeup: comm=rcu_preempt pid=11 prio=98 target_cpu=007
> |     ksoftirqd/7-54      [007] dN..213    46.299756: sched_stat_runtime: comm=ksoftirqd/7 pid=54 runtime=13265 [ns] vruntime=3012610540 [ns]
> |     ksoftirqd/7-54      [007] d...213    46.299760: sched_switch: prev_comm=ksoftirqd/7 prev_pid=54 prev_prio=120 prev_state=R+ ==> next_comm=rcu_preempt next_pid=11 next_prio=98
> |     rcu_preempt-11      [007] d...311    46.299766: sched_pi_setprio: comm=ksoftirqd/7 pid=54 oldprio=120 newprio=98
> del_timer_sync()
> |     rcu_preempt-11      [007] d...211    46.299773: sched_switch: prev_comm=rcu_preempt prev_pid=11 prev_prio=98 prev_state=R+ ==> next_comm=ksoftirqd/7 next_pid=54 next_prio=98
> |     ksoftirqd/7-54      [007] .....13    46.299774: timer_expire_exit: timer=000000003bd1e045
> |     ksoftirqd/7-54      [007] dN..311    46.299784: sched_pi_setprio: comm=ksoftirqd/7 pid=54 oldprio=98 newprio=120
> |     ksoftirqd/7-54      [007] dN..311    46.299788: sched_waking: comm=rcu_preempt pid=11 prio=98 target_cpu=007
> |     ksoftirqd/7-54      [007] dN..411    46.299790: sched_wakeup: comm=rcu_preempt pid=11 prio=98 target_cpu=007
> |     ksoftirqd/7-54      [007] dN..311    46.299792: sched_stat_runtime: comm=ksoftirqd/7 pid=54 runtime=7404 [ns] vruntime=3012617944 [ns]
> |     ksoftirqd/7-54      [007] d...2..    46.299797: sched_switch: prev_comm=ksoftirqd/7 prev_pid=54 prev_prio=120 prev_state=S ==> next_comm=rcu_preempt next_pid=11 next_prio=98
> 
> 
> > Thanks,
> > 
> >         tglx
> 
> Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201207160648.GF2657%40paulmck-ThinkPad-P72.
