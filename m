Return-Path: <kasan-dev+bncBCV5TUXXRUIBBJMZ333AKGQEZVDZC4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DD831ECEAA
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 13:42:31 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id c7sf1739510pfi.21
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 04:42:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591184550; cv=pass;
        d=google.com; s=arc-20160816;
        b=du8fMr98cgDaYRranoIrVu5kOk/VQocA5aUgjNPo1Xmz/o9YpA+UO3IBKlNx3i7Dl8
         PaN/oL79LF77zVxYY1xG2GNDVyyJ/Y/29v9/OyDy4HFHPWGJ/bkkccec4WI5q0w5TBBq
         KpsFdX3bugoG6lFCaapJTs5RsgyJhbFtgwTimW9pt7aTePRQvLO53/6oV46Ca8uB78FC
         0SBZq1rPT/eL9OpTgoYRaH+A/lv+BeROLd3arwldHe1MzKFqgRVGnPm4hJBJ8tz20cMI
         /9o8VQrMNtt4Ste6ri/SyPmOC4g0xfPjVdsf6fIaQHBd6kMWcfiBA2MeCYuF1YP/vg6m
         Fg4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=YuNONZSOsk2qWOwqOLHuOByJwemR6MyTdOqA8CCc620=;
        b=XMFKtyRZuMC9H9CfUhnRG2JTU35BvpTx8aSaO1s3eVaH+8REDcextA5xqr/peVPpvJ
         0gKhxwU7W4tK2KlVUN+NkeAxIN1klEyao1bNugb81LdD/+zO/rbEAlgfgFhQ/2lpULwf
         SAUWK1zSKuwmrayVAFB97CU478pUskuC7HrcB2/rzqaFUNoBxMX+Z25YT2sETOwTF0om
         SZX30kWqoGAgp2qnt0pxUDBMVnUdwuJEY5ukC4mg9jf79aSgS6GFcj9qqewhpnXWOjfM
         QAiYTCZLFISp+LCmtVwqAgkONjUAJsBQ4TL8A9Z8ZyuKD1F/UWfJWtTCZjmTCZrdB4So
         BUpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=POFaItYR;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YuNONZSOsk2qWOwqOLHuOByJwemR6MyTdOqA8CCc620=;
        b=TD00VjRnxUpyoTkamPYgyx9OhEBtNil0eDDY3cWu2OeGXRGO2wNVo42JOCKWsJNxXe
         u1/Cy+YCbQJsBFdDRxWw/Qswx9lJu4fpfyD7dQeEx8gv+ReZwrYPRQ+2WrMab/hAUgL7
         Mae580YF1Q8DZYMXbVWYobSvL1RNQkQlYJjO20HuWMkKeweJWwd63/aCElF+x5XpUYCP
         Jx58KwU/AmeKWAChBr/R39esgphxWdh9OEga6Z25gmJALeUwgwJOGdQPnjbDejWRsFIi
         cLS+ZA6sGstSwrQWmOQ+skJadBi+U9clAVt9i1PY13xboU9DrXP6qEjBGEATAbxYIsbt
         H45w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YuNONZSOsk2qWOwqOLHuOByJwemR6MyTdOqA8CCc620=;
        b=pQeCtDn//UZeCscu8bgVeJI0KlcmjvKYuD19ybuiPIXrTMReR5dZv+w9zWfOIqxtxG
         qzBdIUEhROXJUq13UnJbWOXoX8vDdPNzHkjBAlBh+T7vYH3kFOQMfzadR9FZplxifNa2
         hUJt72c482vJejeR26jEztxSezd3LWF0NY8jJT9D6+bXMz+GVbEq11bBROLWm+ryTRrw
         6UnBE+Rtl4DWP6ZfYirQYYWfM7fzTgYj+R6akJnrqJ46r5ixuN09uwgT+XH04a0giUUk
         kwzkKyBKWvq4vbTJi8ilFe1u0z428tyM+kgh3WI5rujjsdFscjl6cTK1Ei6mKSLZbUxi
         /xJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530bHsCAvoORovOwmca0F2TzjvamF6N6/tpSGv66BwPZ79cDUfRQ
	UmZGqmYZh6FoNshfh/JrQTY=
X-Google-Smtp-Source: ABdhPJzuLieHgAf2ufUQ8yu6gTZTRxHF4SFZgo2Ghew/Xk21NSNa70ZwtbloFj1W6I4YjQ/+qkSzgw==
X-Received: by 2002:a63:c58:: with SMTP id 24mr28778662pgm.246.1591184549892;
        Wed, 03 Jun 2020 04:42:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:178e:: with SMTP id 136ls640486pfx.2.gmail; Wed, 03 Jun
 2020 04:42:29 -0700 (PDT)
X-Received: by 2002:a62:504:: with SMTP id 4mr5686607pff.67.1591184549456;
        Wed, 03 Jun 2020 04:42:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591184549; cv=none;
        d=google.com; s=arc-20160816;
        b=fCOYxIzAAL9vP3aTQyDpVt723vb9L2xT+RGjPtAYp/pPrS6B+Q761Xk3/WbOOE1H0Q
         arc5GbAwFzEObJsxRS59g3OYRq4HVA7RzjkN28s7kaJpxYSytN+wvYSC8vhp3Al+jk9X
         QOSZYZsqZj/CHXrwQYEOPeSVYBGK6mTEI+D5taE5YsQQl21gBnceK+oZuPfTIohVWrTe
         IGkVpvG5VWi8DFXqVvAOH5ru7/90cp5RQZ99DKy3kjiGaNNahL8f9cYFEU/6FMIEc6dn
         qN+s1N39kdrLsYnlUOUJUlccKh2/T6/zpYgwP1U7uWxF0I7RjC219QYD74C+9jQnG6RG
         1GRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=eh6qLnMP01li+GkyBkwrzOvionWO+kwixZvAmy7LHzM=;
        b=nGBGAKjOirrQKcA+HjOrY/G6lxVcvC4eWu0e03+x8sh9WSoosOLLqwTuEg5gohS+PU
         IMnnYcEqXt2IzvqPvnralbrIt3XoXoFTDHuHRuA6664M3ZFMjlNhOc2uz9kCK57Cx+An
         CHcLnLxN3eOGRNv8dQ445P4jI0A/S5yHqGTWw8kGj992a7VGSR1f0/EoILuI2rb1yT2G
         CI4+wR8PpKxjn3gwAg6xeOQ8v4PUj+EjRmZIn6l2SiI7iSCVoDYfegacvg+2EaYKMVrG
         foE/xpekpSfDx+OFHr520s5x3kwfQss6lJetxyc5ndWkOQ/ivydCw/EisZJUEpkpdUm5
         FFCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=POFaItYR;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id r17si79206pgu.4.2020.06.03.04.42.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jun 2020 04:42:29 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgRmt-0005jt-8m; Wed, 03 Jun 2020 11:42:27 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id BC2D9306064;
	Wed,  3 Jun 2020 13:42:23 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id A8020209DB0C0; Wed,  3 Jun 2020 13:42:23 +0200 (CEST)
Message-ID: <20200603114051.896465666@infradead.org>
User-Agent: quilt/0.66
Date: Wed, 03 Jun 2020 13:40:16 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org,
 elver@google.com,
 paulmck@kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 peterz@infradead.org,
 will@kernel.org,
 dvyukov@google.com,
 glider@google.com,
 andreyknvl@google.com
Subject: [PATCH 2/9] rcu: Fixup noinstr warnings
References: <20200603114014.152292216@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=POFaItYR;
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

A KCSAN build revealed we have explicit annoations through atomic_*()
usage, switch to arch_atomic_*() for the respective functions.

vmlinux.o: warning: objtool: rcu_nmi_exit()+0x4d: call to __kcsan_check_access() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_dynticks_eqs_enter()+0x25: call to __kcsan_check_access() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_nmi_enter()+0x4f: call to __kcsan_check_access() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_dynticks_eqs_exit()+0x2a: call to __kcsan_check_access() leaves .noinstr.text section
vmlinux.o: warning: objtool: __rcu_is_watching()+0x25: call to __kcsan_check_access() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Link: https://lkml.kernel.org/r/20200603084818.GB2627@hirez.programming.kicks-ass.net
---
 kernel/rcu/tree.c |   11 +++++------
 1 file changed, 5 insertions(+), 6 deletions(-)

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603114051.896465666%40infradead.org.
