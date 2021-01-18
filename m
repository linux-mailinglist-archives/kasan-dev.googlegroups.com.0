Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBYFHS6AAMGQEUIEYZLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id C5DFA2FA8DA
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 19:30:57 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id a11sf15981082qto.16
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 10:30:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610994656; cv=pass;
        d=google.com; s=arc-20160816;
        b=ieE1Au72yzqNUsi+UXKPKONMyGo9vmtObz6v0VSyLAsRUR4N2+/8lVcTNk8xXwVYxV
         IYO0ir4bjICm6yKafYVTQKx5TXtIX/8/stUJUq569p9Sf8mK9c50ZkBTEs2L5jf/EiDA
         wkqz2bfYyQeJfeBhpflWoHfcAciGmunCdosGZFy2mxHg+vvk05dLkx1aTslrrdUo17ok
         Kj8kKE45vY3SjQwzt7Le7mkw3uRDxz0bevLoyW8zSvWiuryYvXOl1A/0SeDZCw6tpBqd
         Xs0TFKhnTo+pQQSTRaiLbC7sFOQBGL7EeEw30ewlXYe90+7ijwcHUzvV81JoLQlev55i
         jggw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2rfdWyd27OqdPLaEmDV7UkYy38Gy81o9urgE+493Fpo=;
        b=kKovJT0Qut4Fhnj0StV3szH7Fl4Y3n8DhNpTcsASqJkRgG+eFMfcL7feGUZFRvADku
         Q32k9z3p+02fId7LxPQlQPQ9/6FOctX6yqghoAL9Y+EAZgfoj84jqon4QdVw9sU4KGAh
         3mJCzpTeuL3i5b8WthaWYu0p519nGkNf9U+rLbadbNn5CpxX/MAg8FGD2yVwOBSTZCAY
         H3pH0pHa7mMsvFx8qHeQIvg6dT1z7jEtE2DrzInkdXEazeqdswo9I3wPotbnEY8uWZfD
         O3cmOvfZColQwRCC8fhY8qiGmL4iC6atCVx9YKnqOabust0r6wJLdtSblk99JJffD2Jc
         V6ZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2rfdWyd27OqdPLaEmDV7UkYy38Gy81o9urgE+493Fpo=;
        b=qvupcOmLztPTZulBWdIpSTleMQKsqLZt4zQc/pIhnk+T+nB8hgK0vfolb1FHozzjDg
         XdZvjZOEOSvd5gTa1dotBxrQ3d2Low6kOSbhJYBnAmDPQ20X5an3LSDOM8M6y9DnlBE/
         KFBflLHHk28tWI/GMECa1xTBJdEkp0GB8vaZm9qClLCnMtXwk8FfKlC99HQD7iCjWxOD
         3MdW8wOaYaNFIPo0mWNuth27r6t9hRaO394fuv6jOmb5wdvJCt+iCk/yJPLOqVNzG8a8
         OIZIybECVkji4wrgdSHgOYxIoJxklb9lpH3w6pwHUS4jy+tO6RF750uW0HJNftTqVkti
         8fNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2rfdWyd27OqdPLaEmDV7UkYy38Gy81o9urgE+493Fpo=;
        b=LNPzW2j0KfniUL7Uhm3fwfZCFiq19JTg9Fu4W5g6SeF+To+OhB+I3Ao+P2Q5631j4k
         umaiPBpL3PxL2fw6yC5d2oY8Hvf5mjE3yDkay3BUxBIDL3ALVYubKHyuWVpSIP/Le9iC
         AbabraAFB9F5GrHi9o+q8O+t7SEjk33bzNiIVTskXnSuUTGp6FwCI/h+TzlslRZeq2UE
         F4Nq+0wP3nV16WRCvVDYzvwH/51d0wTF/7HwyGAVi5ErnBNhNwqKKSgbMM9rpSwSD9cb
         QjfBHVZ4gtK8bpXBLwK/FKQ7DVM6Vfu7mSmRj6RzFb/gLGukshvpWMW2jRzNaJjZ5cFb
         Shcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532q6FJEoVKHHfIvoh6hXmi6iX9eBcnrgWJ/ltVSBALd/Ycdm3dr
	Vaave0ut9heFovZcGCSwMrE=
X-Google-Smtp-Source: ABdhPJzuzKYEXkvufc1sxwxWuPCU0NU/jPtVssLkTKwjymLgfHWe00vY+4+F62h3dty1gQw1PKR+jA==
X-Received: by 2002:a37:6897:: with SMTP id d145mr858531qkc.281.1610994656677;
        Mon, 18 Jan 2021 10:30:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:ea19:: with SMTP id f25ls9455856qkg.7.gmail; Mon, 18 Jan
 2021 10:30:56 -0800 (PST)
X-Received: by 2002:ae9:e64d:: with SMTP id x13mr877703qkl.464.1610994656205;
        Mon, 18 Jan 2021 10:30:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610994656; cv=none;
        d=google.com; s=arc-20160816;
        b=R7/Qpy2B5lxnxTgB44CZFCvPb3bWO06eW2KylgtjKxy8DeZ0br79f05o+xbqwqn5cR
         KHRJWIUppH/T//Y6WQ3aPPAdV9eXxK9UgZzhvhHFP+C6ZeBG0bjtfuU9c9i16dySUtr7
         FbSp5pGlkyqa880LXDJ7LN0i8wqqRoWXALhfLTgME0k24TkyKjK7i4je74//H//WQzPz
         0B2pVI2NFCiiHliNR9FIkDVf8513DmaXwWpffNjhVxhvpGYIJV+DsXz5jfvq7H0jC408
         ZHsfDV8J34vcNhte+P3t4eBNz2OreVhqsVKhdAhEC4XbbZNQoyo3R02EBy0j2yBqCeuM
         lpWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Xv3LVMajEOvBJ5bXAi39WY0fIqq6nWVMFwyrFI72wg8=;
        b=k1P66hLGa5p3qlPat6afHN13dFzvhRa0TsEPOjY1f0C8quAQGALnEVj12OKZePuj1b
         di0YPAO43VxG0zDHe3ksWr8OMhzzi7Nvp6T6fhAon0k0rPpXhiie1Noq3W9Iw+sIC6Uq
         1V29GkUEDN199z2x44pPTE/H/ygOfTliy/1+NoCZt2C3EjpV580xG9g447kFcPyGM6al
         MPcrdiY3hdm+qoQ1kQBV9v/bYDmOgdY5/dT+B9lSEn0J4Gikhw/jEQrlmiE9zRKzf8GS
         qdGJck6ejKf3CUgLNthIKoqMPcTY1lnnAsKr+F4MouFVSCwWDDnqKyCM955CTMLuMdjX
         p9Dw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p55si2087872qtc.2.2021.01.18.10.30.56
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Jan 2021 10:30:56 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 979111063;
	Mon, 18 Jan 2021 10:30:55 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E93AA3F719;
	Mon, 18 Jan 2021 10:30:53 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v4 4/5] arm64: mte: Enable async tag check fault
Date: Mon, 18 Jan 2021 18:30:32 +0000
Message-Id: <20210118183033.41764-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210118183033.41764-1-vincenzo.frascino@arm.com>
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Content-Type: text/plain; charset="UTF-8"
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

MTE provides a mode that asynchronously updates the TFSR_EL1 register
when a tag check exception is detected.

To take advantage of this mode the kernel has to verify the status of
the register at:
  1. Context switching
  2. Return to user/EL0 (Not required in entry from EL0 since the kernel
  did not run)
  3. Kernel entry from EL1
  4. Kernel exit to EL1

If the register is non-zero a trace is reported.

Add the required features for EL1 detection and reporting.

Note: ITFSB bit is set in the SCTLR_EL1 register hence it guaranties that
the indirect writes to TFSR_EL1 are synchronized at exception entry to
EL1. On the context switch path the synchronization is guarantied by the
dsb() in __switch_to().
The dsb(nsh) in mte_check_tfsr_exit() is provisional pending
confirmation by the architects.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/mte.h     | 32 ++++++++++++++++++++++
 arch/arm64/kernel/entry-common.c |  6 ++++
 arch/arm64/kernel/mte.c          | 47 ++++++++++++++++++++++++++++++++
 3 files changed, 85 insertions(+)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index d02aff9f493d..237bb2f7309d 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -92,5 +92,37 @@ static inline void mte_assign_mem_tag_range(void *addr, size_t size)
 
 #endif /* CONFIG_ARM64_MTE */
 
+#ifdef CONFIG_KASAN_HW_TAGS
+void mte_check_tfsr_el1(void);
+
+static inline void mte_check_tfsr_entry(void)
+{
+	mte_check_tfsr_el1();
+}
+
+static inline void mte_check_tfsr_exit(void)
+{
+	/*
+	 * The asynchronous faults are sync'ed automatically with
+	 * TFSR_EL1 on kernel entry but for exit an explicit dsb()
+	 * is required.
+	 */
+	dsb(nsh);
+	isb();
+
+	mte_check_tfsr_el1();
+}
+#else
+static inline void mte_check_tfsr_el1(void)
+{
+}
+static inline void mte_check_tfsr_entry(void)
+{
+}
+static inline void mte_check_tfsr_exit(void)
+{
+}
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 #endif /* __ASSEMBLY__ */
 #endif /* __ASM_MTE_H  */
diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
index 5346953e4382..31666511ba67 100644
--- a/arch/arm64/kernel/entry-common.c
+++ b/arch/arm64/kernel/entry-common.c
@@ -37,6 +37,8 @@ static void noinstr enter_from_kernel_mode(struct pt_regs *regs)
 	lockdep_hardirqs_off(CALLER_ADDR0);
 	rcu_irq_enter_check_tick();
 	trace_hardirqs_off_finish();
+
+	mte_check_tfsr_entry();
 }
 
 /*
@@ -47,6 +49,8 @@ static void noinstr exit_to_kernel_mode(struct pt_regs *regs)
 {
 	lockdep_assert_irqs_disabled();
 
+	mte_check_tfsr_exit();
+
 	if (interrupts_enabled(regs)) {
 		if (regs->exit_rcu) {
 			trace_hardirqs_on_prepare();
@@ -243,6 +247,8 @@ asmlinkage void noinstr enter_from_user_mode(void)
 
 asmlinkage void noinstr exit_to_user_mode(void)
 {
+	mte_check_tfsr_exit();
+
 	trace_hardirqs_on_prepare();
 	lockdep_hardirqs_on_prepare(CALLER_ADDR0);
 	user_enter_irqoff();
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 78fc079a3b1e..0a9cc82a5301 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -170,6 +170,44 @@ void mte_enable_kernel_async(void)
 	__mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
+static inline void mte_report_async(void)
+{
+	u64 pc = (u64)__builtin_return_address(0);
+
+	kasan_report_async(0, 0, false, pc);
+}
+
+void mte_check_tfsr_el1(void)
+{
+	u64 tfsr_el1;
+
+	if (!system_supports_mte())
+		return;
+
+	tfsr_el1 = read_sysreg_s(SYS_TFSR_EL1);
+
+	/*
+	 * The kernel should never trigger an asynchronous fault on a
+	 * TTBR0 address, so we should never see TF0 set.
+	 * For futexes we disable checks via PSTATE.TCO.
+	 */
+	WARN_ONCE(tfsr_el1 & SYS_TFSR_EL1_TF0,
+		  "Kernel async tag fault on TTBR0 address");
+
+	if (unlikely(tfsr_el1 & SYS_TFSR_EL1_TF1)) {
+		/*
+		 * Note: isb() is not required after this direct write
+		 * because there is no indirect read subsequent to it
+		 * (per ARM DDI 0487F.c table D13-1).
+		 */
+		write_sysreg_s(0, SYS_TFSR_EL1);
+
+		mte_report_async();
+	}
+}
+#endif
+
 static void update_sctlr_el1_tcf0(u64 tcf0)
 {
 	/* ISB required for the kernel uaccess routines */
@@ -235,6 +273,15 @@ void mte_thread_switch(struct task_struct *next)
 	/* avoid expensive SCTLR_EL1 accesses if no change */
 	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
 		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
+
+	/*
+	 * Check if an async tag exception occurred at EL1.
+	 *
+	 * Note: On the context switch path we rely on the dsb() present
+	 * in __switch_to() to guarantee that the indirect writes to TFSR_EL1
+	 * are synchronized before this point.
+	 */
+	mte_check_tfsr_el1();
 }
 
 void mte_suspend_exit(void)
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210118183033.41764-5-vincenzo.frascino%40arm.com.
