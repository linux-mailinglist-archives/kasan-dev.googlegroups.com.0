Return-Path: <kasan-dev+bncBCV5TUXXRUIBBWWH3X3AKGQEZ3BRHAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 571921ECBD8
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 10:48:28 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id 88sf1030711otw.21
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 01:48:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591174107; cv=pass;
        d=google.com; s=arc-20160816;
        b=sg8O8pUNDr8eiq6CtzZEwsyFW5fMlUQ/CsmhUjHP2hNweMKQEhhK7z7VJbhG6k6u7K
         e9rKuqVOZObUV+IdhNmTUuMK9cE8rgjOG7ucQ8EzlQ5h7M0kdxtIaSOGsHn2lXbYeGy+
         s17+7LYcuc5S4pH1RRuYbPExAajEwAX/qkE7dazBRBFlGQKPLCSPP2Xr5QuqWG8sHzsI
         SU8pfbD0KQYIyPJFGx58XNICWHhPD9kcNjziNLnQdb4tNgFj9HNP9kLArnDgK5Xj8aLJ
         kiFzQ+PlIAEBlCL3y/lCqMRaKHPfEDePM1bPF6B3Y92KCW/e8FCjOQNcPJnNArVDG2Zl
         fTuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=OUCWWdw21WGIWc3sffj+QNL5Ynz6w8sNxRi6DSv74gc=;
        b=EN8eu7/rrdaDMoxH6GK+bIPBMYPR860WiFn06GFTJN/E+rnndKsOZIzpvh6MsGN908
         ScHgcGVzv+83juQL5267cPRfY5WCATvoARhHqlnqDs7dX/tSRLglZQZX62WGBCEDN5Oq
         RPeFa32Y/QB1oMcywHJ0Vh+U5O3h4+ON8feeNzaIXEkfXR6I7Rtk8vxVztZpaVwQqYWZ
         BPQ3ecvf4wK0nEFzcbk3K4U22PQLbuJuULh406bOiH6rdpkC2N4H3U3uKiq4F2axfcaV
         PcRuxlMG76y09k+sopA/14cZkVc3+p4WCH1O7Q0gH7aq4bXOUF9xVDxAkNhxf/oVaQWh
         p/Dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b="dSB/FFMv";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OUCWWdw21WGIWc3sffj+QNL5Ynz6w8sNxRi6DSv74gc=;
        b=GMzZfASBu5mJoQnAxJ1ueLZcejKMclabgy35ID8UKXJBJQH+1qcUKSs10fabfUok20
         TA3ODd+yjkKH72K6t0RBIK6BNW3un8jVMbfo84Xz3Ruq8rxeUSuIFeA3RYpz0yhWqZVO
         ty10X4WqRZfGjm94YrJUTryxhzDJD93T/MGLX8N9s+ZlEW2Em+epJy7ViUptbU6MB6+I
         Cdq3z0QUAkZhUnwmdnR9MI7h8zmHBLZxGNbZrCZADsum8F9BP3zqa6J5geHFeMJ4qgxQ
         +k/Jf4zbLOEgWhqqmRTv0eODfIcW7Kx3ALKTRudZ7R96R1ZirUIKHPRN4FXn0wlHBrps
         rGpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OUCWWdw21WGIWc3sffj+QNL5Ynz6w8sNxRi6DSv74gc=;
        b=BuLQ29jKTwavwObk7eu4G2unW+mIm9wS2RxhGpG5uPm/Q2uhj4eFwJY4KaULqAPOMP
         6dcQydiHzrJ6Hxer9iwRoPlhqd72e7HZ1+he5nm/Tcj4QY58IuA44zbmuIy6VF2Vt+3U
         dXyXnMekU/JHcqoHhbkOEnrXhF3Rwhft6AOZzimjmgPCFQJGJwSDZ8I0flqvgUi6D4/Z
         EsUikDkLQnr4AhEI52ZVWYwGvPSEzRxLpxfK+nd+h586WzR3BBax+BzhDKhhtQGIBix0
         lpVbssuyDNAFMPCHflm9ADM/4JcgrGVRX2jlaDqnAoANnDFXf6bP/iWrDfZMNOYA22QV
         wvSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531T+YvFYXDbBx6Yd2Rv6k2jrGXE0D+sPe9WjmPvZnCybFgMM9j2
	hiHpU4hMSIsC1R0eLj2HmOg=
X-Google-Smtp-Source: ABdhPJz/ROXJjRxpIyuoE6sPtEdkXduEATeRjTEJoFW8ubzCABIEQ0uVjj1d4xNcJaCgtDXvssmltw==
X-Received: by 2002:a05:6830:60c:: with SMTP id w12mr2239230oti.45.1591174106923;
        Wed, 03 Jun 2020 01:48:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3987:: with SMTP id y7ls287814otb.11.gmail; Wed, 03 Jun
 2020 01:48:26 -0700 (PDT)
X-Received: by 2002:a9d:7cc2:: with SMTP id r2mr2444805otn.25.1591174106562;
        Wed, 03 Jun 2020 01:48:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591174106; cv=none;
        d=google.com; s=arc-20160816;
        b=pDuBJcQ0WckZGtASNLLJ1PYa7oARe5u91wQ46FOOze3Uxk79AxFBiaQHDZon2Ftp5y
         dhs/ySC/S9KsT3kk5s5/CT1NkQfc5E+wzn5AVzbMYmvcxUvVUuh3RM725qNZ2xWFzvvt
         wSmKKY++Lig+APQ3oAQ0TsJuAkIEspbHI0VPuNEhwUTm97LQIlupXbDNp97VYk2krJ9G
         jwUM0z+Bs2u9xAbAosslNBec7YiEX7Qr3+oQ/8j1vrL9ibOy750LhDlRshugguFaygFr
         aw5asfrHKNg6UhTVrLeu+XEh3zmpBeghEZh+dbkZJ2gbm52X/VvesEJWPrJfqFu2fdXT
         hHTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BFvkRQdilbHJpPYwzqAswTtjQYRfuGDRfAkqNIhsFDs=;
        b=QTOJPS9JoWyMFVKHI8lTBuQVt3CeNfkt6cjRoGUOzr9T/nH2rfGWy5wRcYdwmx5iQz
         of2++2m4kill3zwwLTwbWCkB6DgbQFo0Z24Y9AWusmOQ2Uni57KS66XPUwT0va2qUomL
         RAGQJEdOx+ENQdrg28AA4ixXJ+ZOSV6BNRnZNj0bbx8FOd9AYqIxyJsaP4shD4+fpgKG
         PteRi80U4DZOSByOzFLUo2fRKnOMkb+7r5JU1ruL3Vwmlxe2n/y5NkvHT10q0xVujW+v
         1U+And/UE5wUy+fSOf4qsRJXQmGMOAavdAx1Ehsnnbc+hbynxryZci3SFHwwgJas0deM
         Op5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b="dSB/FFMv";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id e23si132426oti.4.2020.06.03.01.48.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jun 2020 01:48:26 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgP4O-0005yL-7P; Wed, 03 Jun 2020 08:48:20 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 5BA243035D4;
	Wed,  3 Jun 2020 10:48:18 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 5128B205F7349; Wed,  3 Jun 2020 10:48:18 +0200 (CEST)
Date: Wed, 3 Jun 2020 10:48:18 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Nick Desaulniers <ndesaulniers@google.com>,
	Will Deacon <will@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: [PATCH] rcu: Fixup noinstr warnings
Message-ID: <20200603084818.GB2627@hirez.programming.kicks-ass.net>
References: <20200602184409.22142-1-elver@google.com>
 <CAKwvOd=5_pgx2+yQt=V_6h7YKiCnVp_L4nsRhz=EzawU1Kf1zg@mail.gmail.com>
 <20200602191936.GE2604@hirez.programming.kicks-ass.net>
 <CANpmjNP3kAZt3kXuABVqJLAJAW0u9-=kzr-QKDLmO6V_S7qXvQ@mail.gmail.com>
 <20200602193853.GF2604@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200602193853.GF2604@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b="dSB/FFMv";
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

On Tue, Jun 02, 2020 at 09:38:53PM +0200, Peter Zijlstra wrote:

> That said; noinstr's __no_sanitize combined with atomic_t might be
> 'interesting', because the regular atomic things have explicit
> annotations in them. That should give validation warnings for the right
> .config, I'll have to go try -- so far I've made sure to never enable
> the *SAN stuff.

---
Subject: rcu: Fixup noinstr warnings

A KCSAN build revealed we have explicit annoations through atomic_t
usage, switch to arch_atomic_*() for the respective functions.

vmlinux.o: warning: objtool: rcu_nmi_exit()+0x4d: call to __kcsan_check_access() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_dynticks_eqs_enter()+0x25: call to __kcsan_check_access() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_nmi_enter()+0x4f: call to __kcsan_check_access() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_dynticks_eqs_exit()+0x2a: call to __kcsan_check_access() leaves .noinstr.text section
vmlinux.o: warning: objtool: __rcu_is_watching()+0x25: call to __kcsan_check_access() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 kernel/rcu/tree.c | 11 +++++------
 1 file changed, 5 insertions(+), 6 deletions(-)

diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
index c716eadc7617..162656b80db9 100644
--- a/kernel/rcu/tree.c
+++ b/kernel/rcu/tree.c
@@ -250,7 +250,7 @@ static noinstr void rcu_dynticks_eqs_enter(void)
 	 * next idle sojourn.
 	 */
 	rcu_dynticks_task_trace_enter();  // Before ->dynticks update!
-	seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
+	seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
 	// RCU is no longer watching.  Better be in extended quiescent state!
 	WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) &&
 		     (seq & RCU_DYNTICK_CTRL_CTR));
@@ -274,13 +274,13 @@ static noinstr void rcu_dynticks_eqs_exit(void)
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
@@ -313,7 +313,7 @@ static __always_inline bool rcu_dynticks_curr_cpu_in_eqs(void)
 {
 	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
 
-	return !(atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
+	return !(arch_atomic_read(&rdp->dynticks) & RCU_DYNTICK_CTRL_CTR);
 }
 
 /*
@@ -692,6 +692,7 @@ noinstr void rcu_nmi_exit(void)
 {
 	struct rcu_data *rdp = this_cpu_ptr(&rcu_data);
 
+	instrumentation_begin();
 	/*
 	 * Check for ->dynticks_nmi_nesting underflow and bad ->dynticks.
 	 * (We are exiting an NMI handler, so RCU better be paying attention
@@ -705,7 +706,6 @@ noinstr void rcu_nmi_exit(void)
 	 * leave it in non-RCU-idle state.
 	 */
 	if (rdp->dynticks_nmi_nesting != 1) {
-		instrumentation_begin();
 		trace_rcu_dyntick(TPS("--="), rdp->dynticks_nmi_nesting, rdp->dynticks_nmi_nesting - 2,
 				  atomic_read(&rdp->dynticks));
 		WRITE_ONCE(rdp->dynticks_nmi_nesting, /* No store tearing. */
@@ -714,7 +714,6 @@ noinstr void rcu_nmi_exit(void)
 		return;
 	}
 
-	instrumentation_begin();
 	/* This NMI interrupted an RCU-idle CPU, restore RCU-idleness. */
 	trace_rcu_dyntick(TPS("Startirq"), rdp->dynticks_nmi_nesting, 0, atomic_read(&rdp->dynticks));
 	WRITE_ONCE(rdp->dynticks_nmi_nesting, 0); /* Avoid store tearing. */

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603084818.GB2627%40hirez.programming.kicks-ass.net.
