Return-Path: <kasan-dev+bncBAABBA7B236QKGQEWLNYL6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id A07962B8875
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 00:38:44 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id g129sf4855655ybf.20
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 15:38:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605742723; cv=pass;
        d=google.com; s=arc-20160816;
        b=fYGxplLzGtQACUKGCkctyc4GJgKpnK2eKf8/JrjjdjHp8l1CJgEmADyaytvaxCfOYs
         oVlr36JsKuG2nUfaFT7NAOeaRG3Oa7o4CkAz9ZOl2rDZVRCF9TU71AwT91ERYfpRfwlG
         NuIhuWsQncGB/r5eFf91TqjI11ctV5zpJeZacAnjKnw1nUL5X1E9LpkOaXvO122GB1cb
         oMDaqrzv2xJ27KYkw6+Kzn48sIK31EAPhGSuYuZpsPp2SFq9yA4APcEuOZ4HXXaAzjky
         BDTwRLFItQDQ8XYjeJra07107/80NDO+MpXHjkx21wiI3/AC+5iX7ZC0b/B7ZLmRDJfh
         rvQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=qzHkMvabiG/CiSczZkSe35LT0+heSSTGkMtbtvZKVCI=;
        b=BA/MINbpf0ZRj+TUYDODn5Vm5DJM318jJB46Q6cWOr7rfaY90ygJZp+xApuEezrLcq
         ifWi+G4DV41PZZGv/UDnKl79TIFKxeJGS13qOEvDh6TYYzWiyVAbJAIpxQ7DXKVYwMhZ
         DHync9F07g3bSGH7tbu90E2SFTHX5lxCBsq9np9JsnHFQMg7018p6RB17jlks3I6CZ3X
         MQnstFdhp71ipz0PjPd/WuiOcxz4xq2AMmbRphFQ6nu1dnC15i6tBJFo9T73PDCVbb6/
         xmb5n7xYlPHjVZqAC8hCRuTH/zs10bcxJfSm3klETMIRDxNOtewRUQPDdXW7ZfCz2DFO
         45FQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=AoMx8dVR;
       spf=pass (google.com: domain of srs0=neah=ey=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NEaH=EY=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qzHkMvabiG/CiSczZkSe35LT0+heSSTGkMtbtvZKVCI=;
        b=L6l5e/VTo+PVOWnYVXDYt7Q6eQDEeKnTzpEUG5uPacRUcILoCVe7si/a4c5jy3hc1V
         3V3xOwsDyAn79y6e3MaQxCkm/3vPwkH4gaMpdA2up5Oac7PemI5QLMW8DCK97ttp5pPL
         jyGRs8mwm5DjZ99onV7OXHGKE3M9Bi46/wi40j0KmqGAYIN6Xc6jnbCoL4jO2Yhxi5Sm
         8xbEPKBOKk11PQ94/n3CMvXC77voqYGRpXWamdSRcgvS1Hov7y6nVbgwj/qKn2rxbZTy
         njkazOYZxGEmx/EFHTvA9l/gmlrZ17Vncq9wO51f3Iaif68KlsiqC86NLy1impfiRwWM
         h+Ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qzHkMvabiG/CiSczZkSe35LT0+heSSTGkMtbtvZKVCI=;
        b=MbfiRzLuwZQViI3i19N56wgpZf5NTf/B0zigq90yxtv1Jd6Q/ZCfitFkqNu7sms+M+
         b1gx0L/WJGA2dXClA+caCmVSkelpqr2ZFInhg+ee3P6xPP4M55RfgNUUk43J9svx/UiJ
         Txlpfj+YnJUl8VaNGK+jNkjnWE28uOG192z6FI7HTWcl4uaj2bdH+NsbDN6OFNFf5i9a
         8XoJjBbA9yafaGRaDktdKunvyTePdKhsS6RFWaK43Ho3SGDFAEUzSD7sTBcHxKOfTreW
         c0K/O6e/CQHvtCsYb+EJQ1aaaGh08S6K+ifrnfoINbh2lb32nqQ4y8RgEowfQDXT086P
         tnWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5312Ux+2WVygHb6tjUnbBZr/wo8tOj+dHydCqsG5g9dryXzJZl55
	J6Wd3Fff5UHCp+oqU7bNwvA=
X-Google-Smtp-Source: ABdhPJxUbR6yKiB2ij+yZwP9l5LiARB9NPDMUMq0CA9Vh0QxPSmGgW7t1SWY39HWjn+GhcY9vSlmCg==
X-Received: by 2002:a25:7542:: with SMTP id q63mr13742969ybc.176.1605742723674;
        Wed, 18 Nov 2020 15:38:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:19c3:: with SMTP id 186ls716095ybz.7.gmail; Wed, 18 Nov
 2020 15:38:43 -0800 (PST)
X-Received: by 2002:a25:d10f:: with SMTP id i15mr9536730ybg.60.1605742723179;
        Wed, 18 Nov 2020 15:38:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605742723; cv=none;
        d=google.com; s=arc-20160816;
        b=f9bELPQw2IT7sGBIdotNtWIuofHQaLBWIjSCjexreyTxVaCXvdJciKewDsCwhftvP3
         TJTkbFHeABGVuac2eJ1ihckmNTbFRjnxyF02iMVaobS5CljLM+Md+DDO9Uspqo8J5SuT
         jzlifZOPMhjHRZIcW2bQu2CSD/Q3bFRmXwVWd5pOJoIuMeInZvbaVPdjIqeHwlTF7UhQ
         RMgf+OrL9X+rMDfWfeisDWTD2hDH10mlRy9KiulvTPFlSA+zr6Rc9niwolIPjzSlmh80
         m2YFkdO3+evaSoegy37vLplrpBXks0lZ089r3i2yY83nXwJiuiELeELHVOdAP0PAozxH
         DfQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=vxjwJ/giZfGWM7QhdiB4a8mIJE3iozSrvs8N62HDNoI=;
        b=qzWr8obxPYkN7wlzcZ5Dm0pCLyPU95NIIkCgOZjoA9eSkZ0VaTkvkGJkKPW+pWFEMk
         IttQOrAPn7dBlmEHBWB4N3op5073LQKX6TNN7cCNqWhcKqm1YNwHvh+EDocsy+33PIqm
         ejWUn0gWCpskSj7joa4x9bI4dU1JlDybdLUzbhgtN0aLwLrw22MA5e7btlMbshDxiSNG
         Keh8e1fYLw1v9xYWCZvZz46hdbJna0tWsLYFsLcJXHTZUxS7nyxy7tgtIDEjhpcClztC
         7OVc4xQF5kWkePg8OlzXJJwWwr1G0crrWJhUdfPLRd2/25HE0yJktbK+PD5Rb2hVbWEe
         GtaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=AoMx8dVR;
       spf=pass (google.com: domain of srs0=neah=ey=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NEaH=EY=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l7si689835ybt.4.2020.11.18.15.38.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 18 Nov 2020 15:38:43 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=neah=ey=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id D7B52246BB;
	Wed, 18 Nov 2020 23:38:41 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 755523522614; Wed, 18 Nov 2020 15:38:41 -0800 (PST)
Date: Wed, 18 Nov 2020 15:38:41 -0800
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
	Peter Zijlstra <peterz@infradead.org>, Tejun Heo <tj@kernel.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without
 allocations
Message-ID: <20201118233841.GS1437@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201111192123.GB3249@paulmck-ThinkPad-P72>
 <20201111202153.GT517454@elver.google.com>
 <20201112001129.GD3249@paulmck-ThinkPad-P72>
 <CANpmjNNyZs6NrHPmomC4=9MPEvCy1bFA5R2pRsMhG7=c3LhL_Q@mail.gmail.com>
 <20201112161439.GA2989297@elver.google.com>
 <20201112175406.GF3249@paulmck-ThinkPad-P72>
 <20201113175754.GA6273@paulmck-ThinkPad-P72>
 <20201117105236.GA1964407@elver.google.com>
 <20201117182915.GM1437@paulmck-ThinkPad-P72>
 <20201118225621.GA1770130@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201118225621.GA1770130@elver.google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=AoMx8dVR;       spf=pass
 (google.com: domain of srs0=neah=ey=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NEaH=EY=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Nov 18, 2020 at 11:56:21PM +0100, Marco Elver wrote:
> On Tue, Nov 17, 2020 at 10:29AM -0800, Paul E. McKenney wrote:
> [...] 
> > But it would be good to get the kcompactd() people to look at this (not
> > immediately seeing who they are in MAINTAINERS).  Perhaps preemption is
> > disabled somehow and I am failing to see it.
> > 
> > Failing that, maybe someone knows of a way to check for overly long
> > timeout handlers.
> 
> I think I figured out one piece of the puzzle. Bisection keeps pointing
> me at some -rcu merge commit, which kept throwing me off. Nor did it
> help that reproduction is a bit flaky. However, I think there are 2
> independent problems, but the manifestation of 1 problem triggers the
> 2nd problem:
> 
> 1. problem: slowed forward progress (workqueue lockup / RCU stall reports)
> 
> 2. problem: DEADLOCK which causes complete system lockup
> 
> 	| ...
> 	|        CPU0
> 	|        ----
> 	|   lock(rcu_node_0);
> 	|   <Interrupt>
> 	|     lock(rcu_node_0);
> 	| 
> 	|  *** DEADLOCK ***
> 	| 
> 	| 1 lock held by event_benchmark/105:
> 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: print_other_cpu_stall kernel/rcu/tree_stall.h:493 [inline]
> 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: check_cpu_stall kernel/rcu/tree_stall.h:652 [inline]
> 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: rcu_pending kernel/rcu/tree.c:3752 [inline]
> 	|  #0: ffffbb6e0b804458 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x428/0xd40 kernel/rcu/tree.c:2581
> 	| ...
> 
> Problem 2 can with reasonable confidence (5 trials) be fixed by reverting:
> 
> 	rcu: Don't invoke try_invoke_on_locked_down_task() with irqs disabled
> 
> At which point the system always boots to user space -- albeit with a
> bunch of warnings still (attached). The supposed "good" version doesn't
> end up with all those warnings deterministically, so I couldn't say if
> the warnings are expected due to recent changes or not (Arm64 QEMU
> emulation, 1 CPU, and lots of debugging tools on).
> 
> Does any of that make sense?

Marco, it makes all too much sense!  :-/

Does the patch below help?

							Thanx, Paul

------------------------------------------------------------------------

commit 444ef3bbd0f243b912fdfd51f326704f8ee872bf
Author: Peter Zijlstra <peterz@infradead.org>
Date:   Sat Aug 29 10:22:24 2020 -0700

    sched/core: Allow try_invoke_on_locked_down_task() with irqs disabled
    
    The try_invoke_on_locked_down_task() function currently requires
    that interrupts be enabled, but it is called with interrupts
    disabled from rcu_print_task_stall(), resulting in an "IRQs not
    enabled as expected" diagnostic.  This commit therefore updates
    try_invoke_on_locked_down_task() to use raw_spin_lock_irqsave() instead
    of raw_spin_lock_irq(), thus allowing use from either context.
    
    Link: https://lore.kernel.org/lkml/000000000000903d5805ab908fc4@google.com/
    Link: https://lore.kernel.org/lkml/20200928075729.GC2611@hirez.programming.kicks-ass.net/
    Reported-by: syzbot+cb3b69ae80afd6535b0e@syzkaller.appspotmail.com
    Signed-off-by: Peter Zijlstra <peterz@infradead.org>
    Signed-off-by: Paul E. McKenney <paulmck@kernel.org>

diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index e172f2d..09ef5cf 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -2984,7 +2984,7 @@ try_to_wake_up(struct task_struct *p, unsigned int state, int wake_flags)
 
 /**
  * try_invoke_on_locked_down_task - Invoke a function on task in fixed state
- * @p: Process for which the function is to be invoked.
+ * @p: Process for which the function is to be invoked, can be @current.
  * @func: Function to invoke.
  * @arg: Argument to function.
  *
@@ -3002,12 +3002,11 @@ try_to_wake_up(struct task_struct *p, unsigned int state, int wake_flags)
  */
 bool try_invoke_on_locked_down_task(struct task_struct *p, bool (*func)(struct task_struct *t, void *arg), void *arg)
 {
-	bool ret = false;
 	struct rq_flags rf;
+	bool ret = false;
 	struct rq *rq;
 
-	lockdep_assert_irqs_enabled();
-	raw_spin_lock_irq(&p->pi_lock);
+	raw_spin_lock_irqsave(&p->pi_lock, rf.flags);
 	if (p->on_rq) {
 		rq = __task_rq_lock(p, &rf);
 		if (task_rq(p) == rq)
@@ -3024,7 +3023,7 @@ bool try_invoke_on_locked_down_task(struct task_struct *p, bool (*func)(struct t
 				ret = func(p, arg);
 		}
 	}
-	raw_spin_unlock_irq(&p->pi_lock);
+	raw_spin_unlock_irqrestore(&p->pi_lock, rf.flags);
 	return ret;
 }
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201118233841.GS1437%40paulmck-ThinkPad-P72.
