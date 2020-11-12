Return-Path: <kasan-dev+bncBAABBNH3WH6QKGQEDKBJKVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id B3C7A2AFBBF
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 01:11:33 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id f4sf1661659ote.15
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 16:11:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605139892; cv=pass;
        d=google.com; s=arc-20160816;
        b=vsFmlDWltmFuOdOBWTF9fW/+XJquaHYxI3VuaW8tsH1u3fMzU9QGecPgsS/mIsUap/
         sCZdjXq9Pv5V2fkL8egRZbSZPqPBPaF+iCRqSqSgd8JuHm/XBXRQwVBol7EOrbN1luv5
         4+LxBVNNaTa4hCD9GZqKgyBSRag4TPbXh72rFlYV53IBeGa1VWIk0H3yuyG+d1IwQGlm
         EWrYlJ57uaOQ9rxpOmClqg/u7Ih0qf55PqWNYO3VOICZfPoBt27t4YNIPtyC3xcZJq3S
         mfK0gkUIvjumG3ubbOD/5rwg6g1jl/QbJaaNQNFRaKPloC2caUN5FnkpVWDAgX+pXbpG
         Sp3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=iY31FW0x7gqhWs5j75OhQ7d8YpQ8gU5T6PSPq1ke7A8=;
        b=EZ33oZLAZl2LDvtWUGTR2ZgQKaiw5Qe+EcX6mHFAfqoaLTYCyFP4yCv4SxxhDTbkCU
         cj+n0nm6bPSi0oKTAunn0/odJN3DwlTUAVRXzXbKvZ58ktTCg273Axfz+hpAGgdOSIZR
         4vBNlg3BkmbXlsVhiwnOAmz+YN3QAdE1favET4biUyKpfPziLyUocD2D+/vlCfrzaQgY
         ek5XdfW2uXpsEK/r3P3n9LpI8Q8rDeQsZyUDgXAhpjxIxfT4dvce/1JzrvBvly49czWH
         wflfocZN/ly9M1RMUZZXm83GYTjLtgeBqyjK9JBMGGEa5b9DZVXv1N98OGPI/fAYd0Zt
         KBoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=yuHOwueL;
       spf=pass (google.com: domain of srs0=btsi=es=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BTSi=ES=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iY31FW0x7gqhWs5j75OhQ7d8YpQ8gU5T6PSPq1ke7A8=;
        b=bTmZAzshfFPhaI3KJ1qL4qX6+bk+chUqVrW98EXv6POLpeU4hn7EiEQ2BRmoXoN1dB
         tf8cKVcpZK36ytivEgjvq8Vj4TfW043auuJ6VtgHhNsoCXVpD369tghL7La3qckFpCML
         /nVci/XnrlXzlTRNvtGLNUg/fOZFuY6BIOlOkThl+ZF7Hd3nYdUSm3akfiyRVZWiA3da
         0mfmFh7Z0m6VXfJfqeQ0aSOKLpiFvyE3h0k3QoN9stnR4jezCKXtxqtaTwAAV/5M32x7
         i2Es9PRno1iZP/HJ26ZWRCcxM8iMIpJPR6ny6d+1thLqgroBHfuLfIAT0YvsAZXmplnq
         pbHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iY31FW0x7gqhWs5j75OhQ7d8YpQ8gU5T6PSPq1ke7A8=;
        b=Nt9Jxuf3Cz9UiBoSt2xxYJyEblQzQEX/v4SnDBMdr7XXRPsUQdWJHR9WoQafJVEC02
         OojY5xvKl6+QOfjMkqPXuW17ANgr08Drw7t5kRnI5tdTxXdw4FenLxhFs7oway++q+OA
         SsBNfN0V/iRJP3UzcUn2WIlfWomzcnNWyS28q7x/5ATKMLFVxnKlyQmuoB44Xi67qvms
         UwrxNAdkJn18+dbbmwJh/aLxe61Wr/Nq42OP3Vv9+Tbahh/X6AZMTr6kryMDq7SYQGGY
         rfL56LJJ93i8TsVcZUcEDrL1OoMmh8Wpqbdbp/gNWBTN8llgPDEq/EW6yTcREnSXKagM
         0flw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530/VOSyNewhGFvVI2nam5LhzsAaMa96Si2m3geNVK697rfIPaCj
	rZmpA3BlxpL/nRjshdldRUk=
X-Google-Smtp-Source: ABdhPJx5qSJhL4oXEeZ2eKyEib/vw+7MdiRm+jeobhVfF/6t5plSgT4aH9CgpA3kDjyT9w7xxY7esA==
X-Received: by 2002:a05:6808:d0:: with SMTP id t16mr3698992oic.79.1605139892205;
        Wed, 11 Nov 2020 16:11:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7e9a:: with SMTP id m26ls308229otp.7.gmail; Wed, 11 Nov
 2020 16:11:31 -0800 (PST)
X-Received: by 2002:a05:6830:2412:: with SMTP id j18mr20800493ots.100.1605139891685;
        Wed, 11 Nov 2020 16:11:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605139891; cv=none;
        d=google.com; s=arc-20160816;
        b=sLGZA/wpL8DNfRHNtG4TM2WSnKcvwhW3MbYxSzuUxZFMIZ2UWAl7MGxYGcJiw0kn0e
         N2UYgNTTN32IhWIDFsyf/yDCNb1m6k9Rvhk3WaDJPGM5gVEZPQ1CV4+lHADD8CL0swZY
         Q3hdafIb11BO6jHTfE88uS8SvhzbbqPekupF5o+4cRyOEEt63KJvZx/NLr+mylABoBfb
         qaM+Kg7Pe/wH47O8PAQZMqJR1wImplf/kNIMlg7pjdzp70tNej87wcEprLF/ny+1Ojlg
         3maNKrBkPxXS0mU0l+vdFl2O/QOZgRYXeJKV48mULFU+yf3/L3FNbQ7HOSBokq0nKCdb
         MpPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=4pSyW3mlRQ8n31x6jOCP224mmj8cLcrLJSpYD732ias=;
        b=qvySEcOw6+GUN2dAJoJY/vy93lWrbn/1CpPzS1KV27z/aiW4t3kT1M2OJ2g/+BvNEt
         h3eZhJ4YZzgFkOE5RJksA7roMjriU58nJrytPXy/4rCOgeuRFmNx3YrcoWkLK2AGTQwx
         afeXvQLBV59MWxiFE+4UVGtjhLt4xkPqPuj/T5XtGaygmzVwukl3tbgGgyoMn0WmJrNH
         +mpOCT7GhSZ2jxQniUQr9v80iOtiINkfUZmCIAVpDh4yW60poEszHHEOhe0uRdH2cjBY
         T4Rd8nwD9oFy9XHxKA9p0HITP1lFTcLIkM6Z3QLuvc+hHQzuEAm73HXGqTBnK3667B6+
         nZzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=yuHOwueL;
       spf=pass (google.com: domain of srs0=btsi=es=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BTSi=ES=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n185si213319oih.3.2020.11.11.16.11.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Nov 2020 16:11:31 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=btsi=es=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 61F942072C;
	Thu, 12 Nov 2020 00:11:30 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id F0BFF352287B; Wed, 11 Nov 2020 16:11:29 -0800 (PST)
Date: Wed, 11 Nov 2020 16:11:29 -0800
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
	peterz@infradead.org
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without
 allocations
Message-ID: <20201112001129.GD3249@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201110135320.3309507-1-elver@google.com>
 <CADYN=9+=-ApMi_eEdAeHU6TyuQ7ZJSTQ8F-FCSD33kZH8HR+xg@mail.gmail.com>
 <CANpmjNM8MZphvkTSo=KgCBXQ6fNY4qo6NZD5SBHjNse_L9i5FQ@mail.gmail.com>
 <20201111133813.GA81547@elver.google.com>
 <20201111130543.27d29462@gandalf.local.home>
 <20201111182333.GA3249@paulmck-ThinkPad-P72>
 <20201111183430.GN517454@elver.google.com>
 <20201111192123.GB3249@paulmck-ThinkPad-P72>
 <20201111202153.GT517454@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201111202153.GT517454@elver.google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=yuHOwueL;       spf=pass
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

On Wed, Nov 11, 2020 at 09:21:53PM +0100, Marco Elver wrote:
> On Wed, Nov 11, 2020 at 11:21AM -0800, Paul E. McKenney wrote:
> [...]
> > > >     rcu: Don't invoke try_invoke_on_locked_down_task() with irqs disabled
> > > 
> > > Sadly, no, next-20201110 already included that one, and that's what I
> > > tested and got me all those warnings above.
> > 
> > Hey, I had to ask!  The only uncertainty I seee is the acquisition of
> > the lock in rcu_iw_handler(), for which I add a lockdep check in the
> > (untested) patch below.  The other thing I could do is sprinkle such
> > checks through the stall-warning code on the assumption that something
> > RCU is calling is enabling interrupts.
> > 
> > Other thoughts?
> > 
> > 							Thanx, Paul
> > 
> > ------------------------------------------------------------------------
> > 
> > diff --git a/kernel/rcu/tree_stall.h b/kernel/rcu/tree_stall.h
> > index 70d48c5..3d67650 100644
> > --- a/kernel/rcu/tree_stall.h
> > +++ b/kernel/rcu/tree_stall.h
> > @@ -189,6 +189,7 @@ static void rcu_iw_handler(struct irq_work *iwp)
> >  
> >  	rdp = container_of(iwp, struct rcu_data, rcu_iw);
> >  	rnp = rdp->mynode;
> > +	lockdep_assert_irqs_disabled();
> >  	raw_spin_lock_rcu_node(rnp);
> >  	if (!WARN_ON_ONCE(!rdp->rcu_iw_pending)) {
> >  		rdp->rcu_iw_gp_seq = rnp->gp_seq;
> 
> This assert didn't fire yet, I just get more of the below. I'll keep
> rerunning, but am not too hopeful...

Is bisection a possibility?

Failing that, please see the updated patch below.  This adds a few more
calls to lockdep_assert_irqs_disabled(), but perhaps more helpfully dumps
the current stack of the CPU that the RCU grace-period kthread wants to
run on in the case where this kthread has been starved of CPU.

							Thanx, Paul

------------------------------------------------------------------------

diff --git a/kernel/rcu/tree_stall.h b/kernel/rcu/tree_stall.h
index 70d48c5..d203ea0 100644
--- a/kernel/rcu/tree_stall.h
+++ b/kernel/rcu/tree_stall.h
@@ -189,6 +189,7 @@ static void rcu_iw_handler(struct irq_work *iwp)
 
 	rdp = container_of(iwp, struct rcu_data, rcu_iw);
 	rnp = rdp->mynode;
+	lockdep_assert_irqs_disabled();
 	raw_spin_lock_rcu_node(rnp);
 	if (!WARN_ON_ONCE(!rdp->rcu_iw_pending)) {
 		rdp->rcu_iw_gp_seq = rnp->gp_seq;
@@ -449,21 +450,32 @@ static void print_cpu_stall_info(int cpu)
 /* Complain about starvation of grace-period kthread.  */
 static void rcu_check_gp_kthread_starvation(void)
 {
+	int cpu;
 	struct task_struct *gpk = rcu_state.gp_kthread;
 	unsigned long j;
 
 	if (rcu_is_gp_kthread_starving(&j)) {
+		cpu = gpk ? task_cpu(gpk) : -1;
 		pr_err("%s kthread starved for %ld jiffies! g%ld f%#x %s(%d) ->state=%#lx ->cpu=%d\n",
 		       rcu_state.name, j,
 		       (long)rcu_seq_current(&rcu_state.gp_seq),
 		       data_race(rcu_state.gp_flags),
 		       gp_state_getname(rcu_state.gp_state), rcu_state.gp_state,
-		       gpk ? gpk->state : ~0, gpk ? task_cpu(gpk) : -1);
+		       gpk ? gpk->state : ~0, cpu);
 		if (gpk) {
 			pr_err("\tUnless %s kthread gets sufficient CPU time, OOM is now expected behavior.\n", rcu_state.name);
 			pr_err("RCU grace-period kthread stack dump:\n");
+			lockdep_assert_irqs_disabled();
 			sched_show_task(gpk);
+			lockdep_assert_irqs_disabled();
+			if (cpu >= 0) {
+				pr_err("Stack dump where RCU grace-period kthread last ran:\n");
+				if (!trigger_single_cpu_backtrace(cpu))
+					dump_cpu_task(cpu);
+			}
+			lockdep_assert_irqs_disabled();
 			wake_up_process(gpk);
+			lockdep_assert_irqs_disabled();
 		}
 	}
 }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201112001129.GD3249%40paulmck-ThinkPad-P72.
