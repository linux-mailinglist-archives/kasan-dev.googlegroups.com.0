Return-Path: <kasan-dev+bncBCV5TUXXRUIBBJMZ333AKGQEZVDZC4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id 408721ECEA6
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 13:42:30 +0200 (CEST)
Received: by mail-ua1-x940.google.com with SMTP id n22sf1009160uaq.10
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 04:42:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591184549; cv=pass;
        d=google.com; s=arc-20160816;
        b=SyJ0dxtCeuTQyPTz3dWAd1Ku00SDJDheARYFjjC1FtQgjbQnmqbGUZYmnWk9WYDa52
         wCi4p9U0g8rRSaAceP66LRM1atrp+zrNDjPJADG1mzffyeDWadkWXQjydiwj10ely7vM
         UxcMJnELnw2AFS/KM/UqAmtFMB+wdzX4rUMfi0pB0DBydpIi7CNBLIYcYcosGiXGy96Y
         yNp8HqOEHxxpgziB4e0b8jVAdR4aoCTptOihiGyHr3rMpceh7uLV8tMcWwe3D8VK5k8a
         lKKOQmsGZlxEnvyp6lvOyaVzEl7PFYbaoGXK+YuuU77nFFM4v1yXAIKSx95EhF22mTFL
         N4kQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=6LzcwtX+/S0U2+Zkt6u7gzXJTjHMayHHTOwRtjNlDf0=;
        b=0RL+xHoBpil0o6zHz/Rf3NKItHTED7He7B6lMwi9Se14dy9LYgvDF00sIkpVMPuvUE
         UxNAP1J7K6VHnXw5X5i8g7yn+8SyU847ZpVj7EhDYfmFgPcnBsuo8I7KOPmWIqGhlhm4
         /gK+wmARx/hcxIb2pbrJWvmp7EuAYAmuVYDlW78AWd75+C17Gs3f00SIPDKTk6f2jKN/
         j94imEKQ7QuNCQnyeehAPpdHfp65NFPhSLZsj6nKxylkYrkZOMlidERzM8GInmyxiNHq
         PYvhgMtnAk6UGoGzqoL/KZM4jZ3HhgP2f0mjU9A9eJwFdjUh2U4nnVBYh1H3FiP64PId
         EHwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=SlUqS3YP;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6LzcwtX+/S0U2+Zkt6u7gzXJTjHMayHHTOwRtjNlDf0=;
        b=FJTExol+ZAFLH2FLGdxyRGioLyERYsGgTpIZDtbfrzq3mA0tW+ng28sLfhvmjilUsV
         JhCI/GL3vBdJNwhMzWdhBj94R3nqWdlHPKSnLXdTI4erPLWxsPi5o6asMfI6uuHIRgxI
         PIUl7PNMt/pIHeKTnvBzswFUUH8mZLnbzCHamPfaHy0MSrbH84tnTUWdktwJqNnwDg4l
         2p3xchDSTz6sOo1OgOh9bfkbd40VupyV0aQan2IaEGP2IKUBMZOBhSmbP5rvMsyviWsZ
         O0BWzRGU0iwGdrs27iLPL+8WTFsckxRwvUInZke8V4wpSrFO1lx5l3lvJPjvHKYGY/1G
         pU4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6LzcwtX+/S0U2+Zkt6u7gzXJTjHMayHHTOwRtjNlDf0=;
        b=cLGuimyOTRHnYpJ+RerKQNS7l/iVWX/M3ObqlwO7IapKJab9CaqId7qoUh65zLKJuu
         F8DdoELpCnve7PKax59kvXwm1AYxwwMa4FsA8Fm86OUTmUp3c2QbbBHYp4QAQ1eXWMdy
         PeLy+Nf0c6qm72IXrS9xPKN55dG1ZumRNcBgg0A6O3yvFm09q4RuE/gF1RiIkdiP+eMK
         r/1he5OA473aedSGfewA0bhZ1bFmTPm+eTmDjTnSIOVTpfqygUSnGQSKnLfQJb+63UyL
         i4Tg9XPXNZ/1MRNRxbsHzYftaoXFsJKoPHa0wzOUDi9kY8uJKesWUU70zw7Xw+0TkuT7
         pFTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533hxCgIjmgSj0L6eNc2fcrSX1ubzUDzsCpC4kDi0ir+lunD0Wdn
	3R/aB1E5XJ6YkaGNKC/ZR7Y=
X-Google-Smtp-Source: ABdhPJzoS1uqEG0Flus2fEDcjMLKaSX7bpE7Ub7JJx9cVUtBEE4ndOoUxKYAKKUQQZ9cHDPPIsTpXQ==
X-Received: by 2002:a67:a64c:: with SMTP id r12mr2239611vsh.127.1591184549263;
        Wed, 03 Jun 2020 04:42:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:5bc6:: with SMTP id z6ls146524uae.10.gmail; Wed, 03 Jun
 2020 04:42:28 -0700 (PDT)
X-Received: by 2002:a9f:318b:: with SMTP id v11mr22217886uad.46.1591184548888;
        Wed, 03 Jun 2020 04:42:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591184548; cv=none;
        d=google.com; s=arc-20160816;
        b=u8TrRK9wMzWlsqTCLoIeH++mPdR1fXS5L0zoBt2cZWFiKaAJkastVKxHDorE7spYrh
         85zefWWsK+b9dzErGHb/OMTW3Wf51luQ+nLmQQumvnpdphwg2XxWT3fFjcHIuG6KER+l
         gy85aWo/jZrLXFrnghdjssAJiXAO8wO/hCmqsTgrNuAEMMTIqbMny3KGac2ToAdL/v6V
         ZVJ5iYfRSpa7Dkv/pgvD+qvLM4JUFbR5dFeCG2cRaDaigd1UBU5lYjaey5M3rx/6je+v
         /Xba38RzC90qrwuzLIVDByEgYFTM1fdlh40ZoD4M+QRqo3ZBbdmEULgJxRNcfyj/6rhK
         WaSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=YtDsltKEuKDuBSNGU0EYICMCiPeDra4uCaDiVXYzdZw=;
        b=IdtkpG6woH9QEXitK4T04ONAnvR0r+Ww1SUk33FNE+3peNX/9aDIlpmRnXG4UBjojb
         VuJ2A7j76aibgWSUO3qkTrH/slE2QzhnTkKziMGj8xEH119MZsC/k8mSF7p2cLDTn0VN
         u1hWTj5WcPx9FxbKfFbBVJy9jbTZ+fKz7GykrxAq0rVwUOX4EeDSlpMahrRca21NfhD0
         Y4StK510imILWVtrfG9XizEkhejCtPf4yCAPADxyFaPC9/v1ABRDpCfmWTHoZmu4o+Zl
         yLq9bLWvJtGmCl/dHb/rHwARASqMaSXxLCQ5Eq094AWzjuvfIA8dIPJtx14sHGEyObus
         x9pg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=SlUqS3YP;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id q20si160455uas.1.2020.06.03.04.42.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jun 2020 04:42:28 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgRmr-0005jm-RH; Wed, 03 Jun 2020 11:42:26 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 0342C306E4A;
	Wed,  3 Jun 2020 13:42:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id B6147209DB0CC; Wed,  3 Jun 2020 13:42:23 +0200 (CEST)
Message-ID: <20200603114052.127756554@infradead.org>
User-Agent: quilt/0.66
Date: Wed, 03 Jun 2020 13:40:20 +0200
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
Subject: [PATCH 6/9] x86/entry: Re-order #DB handler to avoid *SAN instrumentation
References: <20200603114014.152292216@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=SlUqS3YP;
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

vmlinux.o: warning: objtool: exc_debug()+0xbb: call to clear_ti_thread_flag.constprop.0() leaves .noinstr.text section
vmlinux.o: warning: objtool: noist_exc_debug()+0x55: call to clear_ti_thread_flag.constprop.0() leaves .noinstr.text section

Rework things so that handle_debug() looses the noinstr and move the
clear_thread_flag() into that.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 arch/x86/kernel/traps.c |   55 +++++++++++++++++++++++-------------------------
 1 file changed, 27 insertions(+), 28 deletions(-)

--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -775,26 +775,44 @@ static __always_inline void debug_exit(u
  *
  * May run on IST stack.
  */
-static void noinstr handle_debug(struct pt_regs *regs, unsigned long dr6,
-				 bool user_icebp)
+static void handle_debug(struct pt_regs *regs, unsigned long dr6, bool user)
 {
 	struct task_struct *tsk = current;
+	bool user_icebp;
 	int si_code;
 
+	/*
+	 * The SDM says "The processor clears the BTF flag when it
+	 * generates a debug exception."  Clear TIF_BLOCKSTEP to keep
+	 * TIF_BLOCKSTEP in sync with the hardware BTF flag.
+	 */
+	clear_thread_flag(TIF_BLOCKSTEP);
+
+	/*
+	 * If DR6 is zero, no point in trying to handle it. The kernel is
+	 * not using INT1.
+	 */
+	if (!user && !dr6)
+		return;
+
+	/*
+	 * If dr6 has no reason to give us about the origin of this trap,
+	 * then it's very likely the result of an icebp/int01 trap.
+	 * User wants a sigtrap for that.
+	 */
+	user_icebp = user && !dr6;
+
 	/* Store the virtualized DR6 value */
 	tsk->thread.debugreg6 = dr6;
 
-	instrumentation_begin();
 #ifdef CONFIG_KPROBES
 	if (kprobe_debug_handler(regs)) {
-		instrumentation_end();
 		return;
 	}
 #endif
 
 	if (notify_die(DIE_DEBUG, "debug", regs, (long)&dr6, 0,
 		       SIGTRAP) == NOTIFY_STOP) {
-		instrumentation_end();
 		return;
 	}
 
@@ -825,7 +843,6 @@ static void noinstr handle_debug(struct
 
 out:
 	cond_local_irq_disable(regs);
-	instrumentation_end();
 }
 
 static __always_inline void exc_debug_kernel(struct pt_regs *regs,
@@ -834,14 +851,6 @@ static __always_inline void exc_debug_ke
 	nmi_enter();
 	instrumentation_begin();
 	trace_hardirqs_off_finish();
-	instrumentation_end();
-
-	/*
-	 * The SDM says "The processor clears the BTF flag when it
-	 * generates a debug exception."  Clear TIF_BLOCKSTEP to keep
-	 * TIF_BLOCKSTEP in sync with the hardware BTF flag.
-	 */
-	clear_thread_flag(TIF_BLOCKSTEP);
 
 	/*
 	 * Catch SYSENTER with TF set and clear DR_STEP. If this hit a
@@ -850,14 +859,8 @@ static __always_inline void exc_debug_ke
 	if ((dr6 & DR_STEP) && is_sysenter_singlestep(regs))
 		dr6 &= ~DR_STEP;
 
-	/*
-	 * If DR6 is zero, no point in trying to handle it. The kernel is
-	 * not using INT1.
-	 */
-	if (dr6)
-		handle_debug(regs, dr6, false);
+	handle_debug(regs, dr6, false);
 
-	instrumentation_begin();
 	if (regs->flags & X86_EFLAGS_IF)
 		trace_hardirqs_on_prepare();
 	instrumentation_end();
@@ -868,14 +871,10 @@ static __always_inline void exc_debug_us
 					   unsigned long dr6)
 {
 	idtentry_enter_user(regs);
-	clear_thread_flag(TIF_BLOCKSTEP);
+	instrumentation_begin();
 
-	/*
-	 * If dr6 has no reason to give us about the origin of this trap,
-	 * then it's very likely the result of an icebp/int01 trap.
-	 * User wants a sigtrap for that.
-	 */
-	handle_debug(regs, dr6, !dr6);
+	handle_debug(regs, dr6, true);
+	instrumentation_end();
 	idtentry_exit_user(regs);
 }
 


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603114052.127756554%40infradead.org.
