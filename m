Return-Path: <kasan-dev+bncBCV5TUXXRUIBBPWBT33QKGQEWLAZWNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id 04BB31F9D48
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 18:24:32 +0200 (CEST)
Received: by mail-vs1-xe37.google.com with SMTP id u123sf1861786vsb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 09:24:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592238271; cv=pass;
        d=google.com; s=arc-20160816;
        b=pnTjokxA5N+TyMB1HWh+qwKsBvFBoVL4FNJuT6ftgAtUeb6eNQczW7niO8nZiecdmK
         N5A+egB+zx4CN+5ixXnkVl8q92eFrMUbt9xd8KVR2OW7joDwF+DAIsvBdmtOIsOaferH
         Z2jotbK0v+nPU31luwllfBzWI7EEysguHywFwABjhJgsxqwHq+VuCDEc9Mv5Jv5V45Iw
         tq7kIb86Fcw3KWE1Ss3Vw2dPgMQujCnaIzHe2eLpujt5GvlisSSB5zueXj68pD7PAk//
         iF+V+Wm7Lw2hczArGnqPfR6npWvXc+rOvQybOVql3034u2807d5Mgq5Ycc0jyf77TpeC
         H71g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=2eM8+AU0Qm3xjEDL8Z2nm45wG06fP/ITnSG/QmQl//w=;
        b=K8usdfsHoYIlYsPLhvSTheWly09+gtH5Xl9dV3pdgVp0Mt60Wbca3haerPXusW1Pws
         cPcW3bo937VKRonPgCJFw2a6hp6Pfy+eXkXucCQHOfcwXObIrPYoCu/pqUHAGL1wkW5s
         Q5fwjIenxOtpLCO8InOELBvEdJR9IH0MBIVOjrOdEx/BUfTwi/6bnZtPaIY1z68YDm/M
         oqX5H55PlJyFZxyP63pYXPLDxGPHiCNo3zKL47eZTnuyMtjlSB7lEblXhDsg0aaRgKt4
         9cGQDqQg7N6LakW6A/yIWph6dyAY0NxTqlHhhY5208YR/zgYckeAhbBGFCcCKPcWesHd
         Kbog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=kVqXru94;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2eM8+AU0Qm3xjEDL8Z2nm45wG06fP/ITnSG/QmQl//w=;
        b=WP3WUCfcM1V7qom2Mww5RpOdc7Cgf5jheQavE7y4lrbXuve24gj0fdUEwr2s+qJ6L6
         Wibxvf08RsTcpljVdRn6py7yOG/ZovvSDEP9eAZcnl5wezb++aWq9VnqazAx3NmiasFE
         icq7jTkly9Jkh6aW3ad6KOe3gmTkF49fF00HQYG8HxoOOU6NhouLJ4EPtq3QfA/wA2EH
         Z1i30lWNXwRUxJFp2IhowMdRZz9pPqui+LT7ti+bQ9ULU3H4OpZ0rDeAB4mFm1YnV3k3
         9u2YU+o8O7w7fg8Q1aFjjmgYDoT9OAZsIWGwYnFgghFq2FR8SPQBCIESEB2vNJIxemud
         RCSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2eM8+AU0Qm3xjEDL8Z2nm45wG06fP/ITnSG/QmQl//w=;
        b=YfLFJVpPVR1St9MbXai10fjyn5c5LiMnlErk2+cH3pidmsatz7BQFKMWJZKYIGMtM/
         Ta5RBsybDtQ88VEdQc4j8X7/p89HQdOkmF5xzpGsYbZAD80xDbarz85moEChD4yzJsH/
         UJWeOaP3bYMRYU00jZt6FIoTtWxlwJXLtbrNhsm5bSOat5fVzFBkrgq6Hjo8/jB97Ifz
         D2Vf3cuM/H9IGAUtuygGT+DBwHKQNJu92JJaQ65UCst59M687RLxfpUmn0SV9J3pb0Yj
         eF/a/gP+1BYyS9kP0gscHCcd1aLZrzw+HHADzMh+uvawPnfEmP2G1perA6cXQ9G/EiBh
         Xw9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530OlAWLZ7mpNX1EmgObNdUQPEQxdeQ1M3JdQ69zFrSYGnSMB+LY
	1cUFxglbXkJPq4oyWfYY2/4=
X-Google-Smtp-Source: ABdhPJwA9uEplQbEDQo7CgzqAWWuUEWOYEshg/LWZWwrAV/HejavHYV/Sib0+YhlXKaigGFURJvSyQ==
X-Received: by 2002:a67:903:: with SMTP id 3mr19889282vsj.191.1592238270952;
        Mon, 15 Jun 2020 09:24:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7c0b:: with SMTP id x11ls1530791vsc.2.gmail; Mon, 15 Jun
 2020 09:24:30 -0700 (PDT)
X-Received: by 2002:a67:2d16:: with SMTP id t22mr20819794vst.160.1592238270588;
        Mon, 15 Jun 2020 09:24:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592238270; cv=none;
        d=google.com; s=arc-20160816;
        b=0DJM7McO2Gc9MAUU70nDY2C5KBLqJM8qwTWVgiYHeRYe1jhUyXJeo7REZTe2URwvVg
         hgIl6XzSja/vPhaR51EaAdgcG7alSdKwalUt7yHowPAKSAa66SHFEvJbtt0SaEQYBVWF
         x8cdeS1Kf6YVn+H+RHM21+cE83qDklD3Qy1XWVEe3V1tjlWaQENVWPIznm2YHF2rzHhU
         KPjwgxcq2ymadDxe3b7tH5ZLYL6tDd3OZX61FMaXVRIRaUaDvHQcWl8vqakic0zqV8az
         vyqrP7OmK9Qnf5QG1wvdOOBd/pXKzJV/7buzOSHwbmIo9uDz7bgUxW0SGIRZ1RRfwQV0
         1Tkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=UJfkIp8eAX3oRf38KIcxAmyB5E1JmZKm235O+JB/jIk=;
        b=Wh7KhyWxxr0VOnUzqMuvSHXXwcq4jVFJHVniW/WMvF9NziJb/F59QTeDV7lM2cdLHt
         E5Qfjrpr9CbsJyR3DRl1+SFlanVCWuZP0Cj6p5S9qwswk+MH8NbVs4a938aNrshlXVHy
         LZVT43vKdOlBSHBCJ1fCy9EgSwmvEkdVifygbbgZzfkB8ibszVeE2ZB4QqUC5A8foI85
         +1r4fGyc/a6xMTHEUy2ZAWwZRBa3W99TyzjINGMqQNFINwAbd+VxtXaTSn/GHTdnLv2l
         yrH/iw/fkAOeaaeXwEgsSbMCLC18TKDfdWO2T/KrZvBfXuzIAkAn/j05hXiee7kxOBpm
         iTsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=kVqXru94;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id v13si635142vsk.1.2020.06.15.09.24.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 09:24:30 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jkruP-0005t4-9S; Mon, 15 Jun 2020 16:24:29 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 4F96230753E;
	Mon, 15 Jun 2020 18:24:27 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 36565203C3762; Mon, 15 Jun 2020 18:24:27 +0200 (CEST)
Date: Mon, 15 Jun 2020 18:24:27 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org, elver@google.com, paulmck@kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200615162427.GI2554@hirez.programming.kicks-ass.net>
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
 <20200615154905.GZ2531@hirez.programming.kicks-ass.net>
 <20200615155513.GG2554@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200615155513.GG2554@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=kVqXru94;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Mon, Jun 15, 2020 at 05:55:13PM +0200, Peter Zijlstra wrote:
> On Mon, Jun 15, 2020 at 05:49:05PM +0200, Peter Zijlstra wrote:
> > @@ -983,13 +993,17 @@ noinstr void rcu_nmi_enter(void)
> >  		if (!in_nmi())
> >  			rcu_cleanup_after_idle();
> >  
> > +		instrumentation_begin();
> > +		// instrumentation for the noinstr rcu_dynticks_curr_cpu_in_eqs()
> > +		instrument_atomic_read(&rdp->dynticks, sizeof(rdp->dynticks));
> > +		// instrumentation for the noinstr rcu_dynticks_eqs_exit()
> > +		instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks));
> > +
> >  		incby = 1;
> >  	} else if (!in_nmi()) {
> >  		instrumentation_begin();
> >  		rcu_irq_enter_check_tick();
> > -		instrumentation_end();
> >  	}
> > -	instrumentation_begin();
> >  	trace_rcu_dyntick(incby == 1 ? TPS("Endirq") : TPS("++="),
> >  			  rdp->dynticks_nmi_nesting,
> >  			  rdp->dynticks_nmi_nesting + incby, atomic_read(&rdp->dynticks));
> 
> Oh, that's lost a possible instrumentation_begin() :/ But weirdly
> objtool didn't complain about that... Let me poke at that.

Like so then...

---
Subject: rcu: Fixup noinstr warnings

A KCSAN build revealed we have explicit annoations through atomic_*()
usage, switch to arch_atomic_*() for the respective functions.

vmlinux.o: warning: objtool: rcu_nmi_exit()+0x4d: call to __kcsan_check_access() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_dynticks_eqs_enter()+0x25: call to __kcsan_check_access() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_nmi_enter()+0x4f: call to __kcsan_check_access() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_dynticks_eqs_exit()+0x2a: call to __kcsan_check_access() leaves .noinstr.text section
vmlinux.o: warning: objtool: __rcu_is_watching()+0x25: call to __kcsan_check_access() leaves .noinstr.text section

Additionally, without the NOP in instrumentation_begin(), objtool would
not detect the lack of the 'else instrumentation_begin();' branch in
rcu_nmi_enter().

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 include/linux/compiler.h |    2 +-
 kernel/rcu/tree.c        |   33 +++++++++++++++++++++++++--------
 2 files changed, 26 insertions(+), 9 deletions(-)

--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -123,7 +123,7 @@ void ftrace_likely_update(struct ftrace_
 #ifdef CONFIG_DEBUG_ENTRY
 /* Begin/end of an instrumentation safe region */
 #define instrumentation_begin() ({					\
-	asm volatile("%c0:\n\t"						\
+	asm volatile("%c0: nop\n\t"						\
 		     ".pushsection .discard.instr_begin\n\t"		\
 		     ".long %c0b - .\n\t"				\
 		     ".popsection\n\t" : : "i" (__COUNTER__));		\
--- a/kernel/rcu/tree.c
+++ b/kernel/rcu/tree.c
@@ -250,7 +250,7 @@ static noinstr void rcu_dynticks_eqs_ent
 	 * next idle sojourn.
 	 */
 	rcu_dynticks_task_trace_enter();  // Before ->dynticks update!
-	seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
+	seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
 	// RCU is no longer watching.  Better be in extended quiescent state!
 	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
 		     (seq & RCU_DYNTICK_CTRL_CTR));
@@ -274,13 +274,13 @@ static noinstr void rcu_dynticks_eqs_exi
 	 * and we also must force ordering with the next RCU read-side
 	 * critical section.
 	 */
-	seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
+	seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
 	// RCU is now watching.  Better not be in an extended quiescent state!
 	rcu_dynticks_task_trace_exit();  // After ->dynticks update!
 	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
 		     !(seq & RCU_DYNTICK_CTRL_CTR));
 	if (seq & RCU_DYNTICK_CTRL_MASK) {
-		atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
+		arch_atomic_andnot(RCU_DYNTICK_CTRL_MASK, &rdp->dynticks);
 		smp_mb__after_atomic(); /* _exit after clearing mask. */
 	}
 }
@@ -313,7 +313,7 @@ static __always_inline bool rcu_dynticks
 {
 	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
 
-	return !(atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
+	return !(arch_atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
 }
 
 /*
@@ -633,6 +633,10 @@ static noinstr void rcu_eqs_enter(bool u
 	do_nocb_deferred_wakeup(rdp);
 	rcu_prepare_for_idle();
 	rcu_preempt_deferred_qs(current);
+
+	// instrumentation for the noinstr rcu_dynticks_eqs_enter()
+	instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks));
+
 	instrumentation_end();
 	WRITE_ONCE(rdp->dynticks_nesting, 0); /* Avoid irq-access tearing. */
 	// RCU is watching here ...
@@ -692,6 +696,7 @@ noinstr void rcu_nmi_exit(void)
 {
 	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
 
+	instrumentation_begin();
 	/*
 	 * Check for ->dynticks_nmi_nesting underflow and bad ->dynticks.
 	 * (We are exiting an NMI handler, so RCU better be paying attention
@@ -705,7 +710,6 @@ noinstr void rcu_nmi_exit(void)
 	 * leave it in non-RCU-idle state.
 	 */
 	if (rdp->dynticks_nmi_nesting != 1) {
-		instrumentation_begin();
 		trace_rcu_dyntick(TPS("--="), rdp->dynticks_nmi_nesting, rdp->dynticks_nmi_nesting - 2,
 				  atomic_read(&rdp->dynticks));
 		WRITE_ONCE(rdp->dynticks_nmi_nesting, /* No store tearing. */
@@ -714,13 +718,15 @@ noinstr void rcu_nmi_exit(void)
 		return;
 	}
 
-	instrumentation_begin();
 	/* This NMI interrupted an RCU-idle CPU, restore RCU-idleness. */
 	trace_rcu_dyntick(TPS("Startirq"), rdp->dynticks_nmi_nesting, 0, atomic_read(&rdp->dynticks));
 	WRITE_ONCE(rdp->dynticks_nmi_nesting, 0); /* Avoid store tearing. */
 
 	if (!in_nmi())
 		rcu_prepare_for_idle();
+
+	// instrumentation for the noinstr rcu_dynticks_eqs_enter()
+	instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks));
 	instrumentation_end();
 
 	// RCU is watching here ...
@@ -838,6 +844,10 @@ static void noinstr rcu_eqs_exit(bool us
 	rcu_dynticks_eqs_exit();
 	// ... but is watching here.
 	instrumentation_begin();
+
+	// instrumentation for the noinstr rcu_dynticks_eqs_exit()
+	instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks));
+
 	rcu_cleanup_after_idle();
 	trace_rcu_dyntick(TPS("End"), rdp->dynticks_nesting, 1, atomic_read(&rdp->dynticks));
 	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) && !user && !is_idle_task(current));
@@ -983,13 +993,20 @@ noinstr void rcu_nmi_enter(void)
 		if (!in_nmi())
 			rcu_cleanup_after_idle();
 
+		instrumentation_begin();
+		// instrumentation for the noinstr rcu_dynticks_curr_cpu_in_eqs()
+		instrument_atomic_read(&rdp->dynticks, sizeof(rdp->dynticks));
+		// instrumentation for the noinstr rcu_dynticks_eqs_exit()
+		instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks));
+
 		incby = 1;
 	} else if (!in_nmi()) {
 		instrumentation_begin();
 		rcu_irq_enter_check_tick();
-		instrumentation_end();
+	} else {
+		instrumentation_begin();
 	}
-	instrumentation_begin();
+
 	trace_rcu_dyntick(incby == 1 ? TPS("Endirq") : TPS("++="),
 			  rdp->dynticks_nmi_nesting,
 			  rdp->dynticks_nmi_nesting + incby, atomic_read(&rdp->dynticks));

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615162427.GI2554%40hirez.programming.kicks-ass.net.
