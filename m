Return-Path: <kasan-dev+bncBDV37XP3XYDRBVGE6X6QKGQE5I4I6IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id B3F0B2C30D1
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 20:43:17 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id q10sf13758019ile.1
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 11:43:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606246996; cv=pass;
        d=google.com; s=arc-20160816;
        b=fcCyCbKbrVeCNjvdbihhyDK90tCZEE4/8IuKKyswWKmMDIBxZO1H4mqlGiqRAFIaI1
         oO8xUJl9e3We7plNus6I7O1tWHU+TVJ1pkxhcC94EpuyoRNwSt4wiaAEG13laylnFZTe
         VUuRedIqtH141SfmAqMacVpbMFm7z8KtRyCv8DdJG4YJlin33ULn/0iOLjgXFu0HAlrA
         UGqe7mI5cyjtwtHE77J/oFemAPQNNXDPLvOacZcQ7oH2NVwl1G+X/j76LroPSvaxG+Qb
         foO0XVmLkCJ3/cvAc1uEVIr3UjdrJmqnkgsBGDDdN57+QXjZwUTLTp5vVyPo8nQjkyWE
         pItQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6TaASZIrZ7ZY+1GmMpS6B4YYQ05lizP7RIxr5jBwqxM=;
        b=rsgL2jfMlfanG/bYAx+0q1ugFYNi+2oJAnC0cTUESzqqyeaNTuGhPt3P6RMctxTrV1
         N3zOKWkJUSfUaztnhPo50BlqyXP5tp48DMCeqdR2m0abdohy1cjL/0eL7/SFSEdlBmZI
         Cx5uMYGga28qolFrPOD76rEajMTjZM+ObHoVUcUyXMRPBDx2r8OIysuZb9/BWTEaX+Qp
         dCzlE/mZdW1IqGJ1xkACMomc4CHf26vjcH7dzKaRWeD0+GOj9cb4ziZbz2pJVpBRZFbY
         Lmv8ukA4uR83fbt6O09TWonX186FMxPO19FqvAND5HPv8UvA2hGsFFIt7Kkr8YyB5olR
         Z20A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6TaASZIrZ7ZY+1GmMpS6B4YYQ05lizP7RIxr5jBwqxM=;
        b=djs7IsbbL/zYf47/rXIEWjtOxukNQblpHTlfsoKEKuGwXDrpAEqMfokRsb+jsz4hda
         7AXPCUWXiE8ox3IjyNKrHSNK0d2+tKgPbpbv+SlYNNmNeHKIBPJd8CX3Snuo9lBy6MUK
         0GHcCaFzqWBHANxKyeEaTcqZfjk3+5FOhIfqlgdMo+ps9PszVYHL11jqKGbzet688Ux7
         4UCK+g1iDoAO+kf+/Y65bAUnEg271iZXPhyBvK8KhWWqBII350DaaC1K2/0yiA7Q4SuI
         jwM8brq/JSYUPJ8Jobbp668qSTSTQBndVwmUEC1p6OZjbyH9TXRmDKAMbxWCaHJENbkN
         eXqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6TaASZIrZ7ZY+1GmMpS6B4YYQ05lizP7RIxr5jBwqxM=;
        b=g+/A9zs5kpaLkUh7TNepDmt5V2Y4YyEJlWvK2+nU5KuUYXbYljOOQrqXkyGienpL4G
         7qqofPjObY11l0wOkYNCzIpZLR8QkcE9G5nnjnTxm824+GfrznQKUm4vd+mJ71A9PfiN
         f73Ramn5Gr2ED/YhVGM8FqShVP1Y0WS9MASi8FPL3ClMTfXVT7KNJzebGIGsyAESmGtd
         AOZaDOaSUD6Q266em3cggql03Qhp8K4TyjbA8N7LteavLlCOb+U/28D58n0je5bDqjkO
         WJ+3lWKAVNmCqoIYbz2Lv2h16AYi/qbVe/ky0A/mc97SGytMXfZ6AV00swzVSRLYdyal
         BF/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531kvSLOXXZLDXCOTzxdoELPwdi2nPC3SVxxFq/4hRBrZ2mjqDPR
	jhawYXoj8w6r+KJLqh81zQ0=
X-Google-Smtp-Source: ABdhPJwHmFoYSuR9a++tAsMOZEv/E0h9kbhfsS1ZrGM+5RinQmjd+0ygxsCyJFLXP6m09inS4n1/RA==
X-Received: by 2002:a92:6410:: with SMTP id y16mr3663ilb.126.1606246996725;
        Tue, 24 Nov 2020 11:43:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:d83:: with SMTP id i3ls21633ilj.11.gmail; Tue, 24
 Nov 2020 11:43:16 -0800 (PST)
X-Received: by 2002:a92:d588:: with SMTP id a8mr5994143iln.79.1606246996242;
        Tue, 24 Nov 2020 11:43:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606246996; cv=none;
        d=google.com; s=arc-20160816;
        b=SC4phcDbYy8RHsBGKE+803FarncFOuVrgD2oCbJbwYnOZt2x83ZKvyPxH+OQm+ATk/
         34B5aAn7RSR+ms774hL56hFfB2SRj7g+4KAe7edi/WZRzxt4TAJtZLtG85s5avxkzVz7
         T9QO6w9GGPod6dU7LDNt4EKDQ8qbTzFEmCwTCnUgJNyhhrGuiINORnu8QlU5GT0qDqlY
         H1oATdTTV2TXynE2Alrq+xm1nj9LTAemXYcbUNUu/6aY74N+Lw6EKGfZTlj2VygGSgq0
         XFhv1lAVFjGi32by6Xxcsmc/yx1REAg/HNqTzM1l2uruvJK53hCKYcyW8cprJ1VlBA+y
         qv8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=f6GG+0wYAI3YPvyuVcPO8/nDoqxaNZqJwcbz8OA6slg=;
        b=oFZVm/ZFrkat3iQOou3ax810+DtTUxAySmG0XMscSJu+KHLMPYe7abSe2y8R6dqm9C
         q1CIJVK3qJKBJ2NPhulyyvOz3qs2Hve5ylrKSmXxt8FB61vSQJVpxFr/pWV6gQmCIPjF
         iQefen8qcGwPamhm6+k4SysUqcb5DUCUgp5xBE4AEl4bEvoIiaaBgTo8QpT6x586ayfR
         Z3IwbPkfy+1xxicghf6jHtmhePuhIGz8r0uXExhSD2otci76QkS1AVG+Rmz4mY0ErJBW
         XXQJqpn5unHfTQe6DgubEEvJPEQBZvUSgFmRG9l94A1nPZhkKmLgjTItowEXpG1CVchT
         pkxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b14si4632ios.2.2020.11.24.11.43.16
        for <kasan-dev@googlegroups.com>;
        Tue, 24 Nov 2020 11:43:16 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9D2441396;
	Tue, 24 Nov 2020 11:43:15 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.26.92])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id B2D9D3F718;
	Tue, 24 Nov 2020 11:43:11 -0800 (PST)
Date: Tue, 24 Nov 2020 19:43:08 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>, Will Deacon <will@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>, Tejun Heo <tj@kernel.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	linux-arm-kernel@lists.infradead.org, boqun.feng@gmail.com,
	tglx@linutronix.de
Subject: Re: linux-next: stall warnings and deadlock on Arm64 (was: [PATCH]
 kfence: Avoid stalling...)
Message-ID: <20201124194308.GC8957@C02TD0UTHF1T.local>
References: <20201119170259.GA2134472@elver.google.com>
 <20201119184854.GY1437@paulmck-ThinkPad-P72>
 <20201119193819.GA2601289@elver.google.com>
 <20201119213512.GB1437@paulmck-ThinkPad-P72>
 <20201119225352.GA5251@willie-the-truck>
 <20201120103031.GB2328@C02TD0UTHF1T.local>
 <20201120140332.GA3120165@elver.google.com>
 <20201123193241.GA45639@C02TD0UTHF1T.local>
 <20201124140310.GA811510@elver.google.com>
 <20201124150146.GH1437@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201124150146.GH1437@paulmck-ThinkPad-P72>
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

On Tue, Nov 24, 2020 at 07:01:46AM -0800, Paul E. McKenney wrote:
> On Tue, Nov 24, 2020 at 03:03:10PM +0100, Marco Elver wrote:
> > [   91.184432] =============================
> > [   91.188301] WARNING: suspicious RCU usage
> > [   91.192316] 5.10.0-rc4-next-20201119-00002-g51c2bf0ac853 #25 Tainted: G        W        
> > [   91.197536] -----------------------------
> > [   91.201431] kernel/trace/trace_preemptirq.c:78 RCU not watching trace_hardirqs_off()!
> > [   91.206546] 
> > [   91.206546] other info that might help us debug this:
> > [   91.206546] 
> > [   91.211790] 
> > [   91.211790] rcu_scheduler_active = 2, debug_locks = 0
> > [   91.216454] RCU used illegally from extended quiescent state!
> > [   91.220890] no locks held by swapper/0/0.
> > [   91.224712] 
> > [   91.224712] stack backtrace:
> > [   91.228794] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G        W         5.10.0-rc4-next-20201119-00002-g51c2bf0ac853 #25
> > [   91.234877] Hardware name: linux,dummy-virt (DT)
> > [   91.239032] Call trace:
> > [   91.242587]  dump_backtrace+0x0/0x240
> > [   91.246500]  show_stack+0x34/0x88
> > [   91.250295]  dump_stack+0x140/0x1bc
> > [   91.254159]  lockdep_rcu_suspicious+0xe4/0xf8
> > [   91.258332]  trace_hardirqs_off+0x214/0x330
> > [   91.262462]  trace_graph_return+0x1ac/0x1d8
> > [   91.266564]  ftrace_return_to_handler+0xa4/0x170
> > [   91.270809]  return_to_handler+0x1c/0x38
> > [   91.274826]  default_idle_call+0x94/0x38c
> > [   91.278869]  do_idle+0x240/0x290
> > [   91.282633]  rest_init+0x1e8/0x2dc
> > [   91.286529]  arch_call_rest_init+0x1c/0x28
> > [   91.290585]  start_kernel+0x638/0x670

> This looks like tracing in the idle loop in a place where RCU is not
> watching.  Historically, this has been addressed by using _rcuidle()
> trace events, but the portion of the idle loop that RCU is watching has
> recently increased.  Last I checked, there were still a few holdouts (that
> would splat like this) in x86, though perhaps those have since been fixed.

Yup! I think this is a latent issue my debug hacks revealed (in addition
to a couple of other issues in the idle path), and still affects x86 and
others. It's only noticeable if you hack trace_hardirqs_{on,off}() to
check rcu_is_watching(), which I had at the tip of my tree.

AFAICT, the issue is that arch_cpu_idle() can be dynamically traced with
ftrace, and hence the tracing code can unexpectedly run without RCU
watching. Since that's dynamic tracing, we can avoid it by marking
arch_cpu_idle() and friends as noinstr.

I'll see about getting this fixed before we upstream the debug hack.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201124194308.GC8957%40C02TD0UTHF1T.local.
