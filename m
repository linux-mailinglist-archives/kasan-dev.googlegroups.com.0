Return-Path: <kasan-dev+bncBCV5TUXXRUIBB5FQT33QKGQELTEU3ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id C7A401F9C3B
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 17:49:09 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id t140sf8204856oot.8
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 08:49:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592236148; cv=pass;
        d=google.com; s=arc-20160816;
        b=vSPwMTHqYBpV7IMui5CSyBhzLVEwSrXNK++2v/SlYUDWcJGxXNnt/IFUHzaDn7froq
         ZAIELAJn0qP56lVVRgf6oCIspy1DY2906zMZNx7H93Ih2tVDuH5/xFthgDcZcrGtjk1u
         htoHSc5BdHyW/Id+Na1luz0hP5ps8vXw/BCnXryIUvIv9SsY+jUYlTBS7+eaYuvQQ4+w
         XmjuACvQ5U+hDb04Cfa6zt/SlQuqk+fjcRODSAJAcU6ALX04SXym+L/RaXfacPHk+vpK
         g0XpYwO+7eEoUvIPfLTG7Rs3/Xxf7QYbjpWYUV0i0/C2gYvGkdsoo0ZUOo1C+lihKuda
         /kmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ubngOr+3O4LmKpHwYu7Gc/vNcqEAhN6wrhvns0X3NO0=;
        b=weKnlNDyJrfjkhtEDV8b2DvIWgi4lEDFUfJBSDtqiYzDA218hhgUyEJDnNT1WNd7Se
         FBCdwvfvwwtbKkM1D3nbXSOWKGP6775n8JJdX453RZbS2ZnezjOSGXpwJ2F7LSH8FW3N
         XIVvpvHSEKetEMYe08o1GVsLTcN+k/UpEZIA//BjRg/68msYg0i6KS3aV3dM5wTH1ja4
         uCXqnJ18mrOr2ouMZDXbK0zVIQUMdnG+ics5ZQ9HgbaKUcjzt7gyIlgmRm/8i1NLGbOO
         9AKu1E/IZoRuc9m1ujpE0xtIowsqfRfgw5vrMnQH2SDA6lTdNg0lJXOcxyvmwKoXaWa0
         mPIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b="nSl/WYg9";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ubngOr+3O4LmKpHwYu7Gc/vNcqEAhN6wrhvns0X3NO0=;
        b=B2I1RDMOO3i/DuZE00YVmounmikSwfUiZ1tcvwGhvhZe7xTzet1kjQIeXkjo3y2KQD
         QvSD70E8Wx8gHMPol4GCUc17pnA+QtydydsVhXESPjJBiucSaPrrSI9b+EGFlegUZbVT
         tmUN3qZ6Zet9lvRR+2KWmxbw2dO4sCAL/YMpQGlzxRB1ysmjZT7TKkqHdFFirT1S3gpD
         2nOWUYafUsbDZ/3xFnhBYHkAaWoQSEK+G7pgg4T7Z6841kmXFHZuZKwqHgIuj52YXNya
         wh9UzGuCFYoHCWS7bhoUk589kSfhB6btwTXernJUAuE2QihC/wk65AFf4Ya8UhqrGqqc
         NGLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ubngOr+3O4LmKpHwYu7Gc/vNcqEAhN6wrhvns0X3NO0=;
        b=Tz7Z/cplbF9u2+gEg4D6SCwD1lnKfKMtDRu5Gy5JmZ9Fsr7G72CJv/PMsQOtlsUsiC
         fHuF/r6NL2tr5sa9ubumgTwh4ktHTxVw8h8XdrYTSUTXuHPXqL/+CZEcaIu4xKSbMig/
         chraM89G+OuTuVydMYooxVlxDDyjQXD6yRaG7LEpo1vDSBI4YQb8ReOW0oH0+zhF4lvT
         xt1ajYV1HhUn1LV8z+OsIyU2XoB7d7EVWW4EMaDY1nmK5B9fuXiODKGtjYsNEN3Is4Dt
         4pheh3ZKj+Kzn0rTWwTBaG3AFYz6j+Lb3d8KCvQs59ZMpCaKGCyGiSi1jDihGlMUJqBH
         pw3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533mwuLcbaYXR5tf/RoS7+89iIWNqxUCEFP30Jd383zyBupBemVK
	LgLA2q6xa0IiLhHqrSgEyC0=
X-Google-Smtp-Source: ABdhPJxutu/4usDo26dYlh6RBGDWk2gwKOYBfxv7NkPTggJH1JnRO4rArHIAAk9VFL9hB+aCWoQGkw==
X-Received: by 2002:a05:6808:988:: with SMTP id a8mr9929733oic.19.1592236148719;
        Mon, 15 Jun 2020 08:49:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:2c46:: with SMTP id f64ls3079971otb.2.gmail; Mon, 15 Jun
 2020 08:49:08 -0700 (PDT)
X-Received: by 2002:a9d:14c:: with SMTP id 70mr22349932otu.239.1592236148383;
        Mon, 15 Jun 2020 08:49:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592236148; cv=none;
        d=google.com; s=arc-20160816;
        b=tEc6U3FY//+swZP6RedMENMsuCTkIdSZclDyiY6j7Px2Zl+EVIWQqdwNZGCSX4L4R2
         8JfcubFdFSMi/HwOngl36OGU6B6qR8h1ovon4kpkO02/bCW8aGMSgVQqaiGCNV+DKnB5
         6hyYBc5cYP9d1D+JNLu5w59dnGOjpU6KwW9z4XGum3OpCwj6milsmnNXsvoAhRInXizz
         ldjDEzmyiQZQ5Af5CkQZxCfxnLiUjgmU+ajxu1lq4LZ4U+YWl5w17pwuRp6UmubwV24O
         VraD0l9eC1rRuyv31hxvbuX4KqlmUBv9iJ2+g7QnttRip9RDGHeQYvuDJeYWviOoEzAC
         Kn9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=/aTpc7TE2Si6G86LJEN2yNkL/a/l/Clrfw1nJF9mG7s=;
        b=lqOHwje9kMFV6dcAEZzpUtNiAm+9KTQTv8eoPdojBax5jozyeY4vvO/CYPy/KME3Fz
         KTaZQTwQEaldFJ7we2pFOEKo6keGWGrjRs6tmdf5SR2s8OHXUppdN+IxuBpEmarSgUWB
         oem1I9yZbnxHX2cLsPbnG3/ahFVI5y5Vd60nKzn4ugfpXz25qE7BHKFwZThx866NdNkR
         ikYwD/3Cx2njEjpFVaLghCieT64Ybgc63CaiswXdudXlAdbtoCLf6EWZTbXQu2qzY+5N
         /eH5PxTtkOZHKM7KT4fwTYYB5XyleSf+RObFpTk5+2H2edZCo9XRrjlV76+Vv/Q/VVoV
         N+Sg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b="nSl/WYg9";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id c26si735705otn.4.2020.06.15.08.49.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 08:49:08 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jkrMB-0005VA-7y; Mon, 15 Jun 2020 15:49:07 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 79534306102;
	Mon, 15 Jun 2020 17:49:05 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 5BB7920E05A91; Mon, 15 Jun 2020 17:49:05 +0200 (CEST)
Date: Mon, 15 Jun 2020 17:49:05 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org, elver@google.com, paulmck@kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200615154905.GZ2531@hirez.programming.kicks-ass.net>
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200603114051.896465666@infradead.org>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b="nSl/WYg9";
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

On Wed, Jun 03, 2020 at 01:40:16PM +0200, Peter Zijlstra wrote:
> A KCSAN build revealed we have explicit annoations through atomic_*()
> usage, switch to arch_atomic_*() for the respective functions.
> 
> vmlinux.o: warning: objtool: rcu_nmi_exit()+0x4d: call to __kcsan_check_access() leaves .noinstr.text section
> vmlinux.o: warning: objtool: rcu_dynticks_eqs_enter()+0x25: call to __kcsan_check_access() leaves .noinstr.text section
> vmlinux.o: warning: objtool: rcu_nmi_enter()+0x4f: call to __kcsan_check_access() leaves .noinstr.text section
> vmlinux.o: warning: objtool: rcu_dynticks_eqs_exit()+0x2a: call to __kcsan_check_access() leaves .noinstr.text section
> vmlinux.o: warning: objtool: __rcu_is_watching()+0x25: call to __kcsan_check_access() leaves .noinstr.text section
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Link: https://lkml.kernel.org/r/20200603084818.GB2627@hirez.programming.kicks-ass.net
> ---

How's this then? It anticipiates the removal of that andnot thing.

---
 kernel/rcu/tree.c |   30 ++++++++++++++++++++++--------
 1 file changed, 22 insertions(+), 8 deletions(-)

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
@@ -983,13 +993,17 @@ noinstr void rcu_nmi_enter(void)
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
 	}
-	instrumentation_begin();
 	trace_rcu_dyntick(incby == 1 ? TPS("Endirq") : TPS("++="),
 			  rdp->dynticks_nmi_nesting,
 			  rdp->dynticks_nmi_nesting + incby, atomic_read(&rdp->dynticks));

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615154905.GZ2531%40hirez.programming.kicks-ass.net.
