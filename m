Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBLHSVWBAMGQE5MDYS6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id AE0B6338FBE
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:22:37 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id r133sf10925284oia.14
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:22:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615558956; cv=pass;
        d=google.com; s=arc-20160816;
        b=G5VYrGZc/Bf88/NNbsSL/l3RJgaHUf1Dc+N2JW4QJEiDFYBfmeJ99TXNp5XtgFyyZq
         RHEH9VtV5YzAclIMxv+hoRcb6S4U5AE+Ji1dh4borVVAoQVmHd3nBTnelD1jF1VhsVGa
         jO1YrBRsFut1GDhCJ+TCerzrvUJL8fkgN9Fri7TNc84AXdvh98mkEASg8ksSdtNrQm4h
         E18QA6w2NyFTUwYOCNFjRuEI/0olpPKltr4lmmCRYLXXDJsuqLS+J03mlxAM0Jcw4RwQ
         BTxBC23+sXPmXPacjiR2WDqTaDZyU0kTDxmHKuJK/Yx1T8SPOhPfFfgK7sZhjEj/W+FM
         M3uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=RKWFWYPXH0e5DsTi/ryO/thAURFB/UaAXCHx6VUzZZg=;
        b=WjyBCYaQDCfj+xxWxQmEnxhy1CWUY4xfblQGyo/MBfnUQ3ECTj1ISgELgwb5VA3+NL
         40mpfrmbn0BB9oDVpIfvEQB9+aSfOhBk+IPl3Cpembk8hnHyvVFnTb6dJ0c+6pYDyT+m
         TRL+GCg4QVUm6rxVL7NehnNxPvcqdEzc+76KY1BRyg42WnKSBvpJDwFnSWJuOVg54WHy
         vlEdoyHzil7MUTEFg+96kWkmZlrO//S2b4kl7rU1P22ZIOGDz8USX7oKJMXUWnAlGmDS
         R98QSI6usK47gr8F6QOEX7+a/zZdn7uweGy+1Ewbl89HfPFcZWmck0conpmwyS6L+2Ko
         fsvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RKWFWYPXH0e5DsTi/ryO/thAURFB/UaAXCHx6VUzZZg=;
        b=mwmOKKBYhu9D/GiyF9Ka0F9vib9YC3S0ASaIsal/eoevPF03tggXpvI1tO/vMCTFdF
         C0O4f5CCrNdRLT2w43SQHKLVVRDis//39MHo3p7SyE6OoR9ZZ3BgPjOgovCo1YwmsYnQ
         zWVMBcAV27P+JFyxW3G4yKFFu0bGTyPcXXlMT0unoZIzHboLqDRCstVJciBlgzeGxsBi
         rJQUgkHfZJvZ0PGMsuHC622rNk8bQf8hd8YghnBgpivXxLop9FTirL4npKygXHZbmxn+
         dIoCTPSWOSf+6MORd7nBf0QHl+JAKjp+x7QLqD3rVbaKFIUzpvcDZ0uJzPHUKg1uJzSo
         zoew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RKWFWYPXH0e5DsTi/ryO/thAURFB/UaAXCHx6VUzZZg=;
        b=CyLKcu2jgVRT3ST9ce0yGu6dCBTsPMAIZ3hM5uuBt8m4ye8HnwXKNx1wao7RtFPXQ8
         n9T8HeqdmVKNpOEVjndoUaLPulC70UHcgZOdWapga48IoLItPH3cMamIMe1644dIBi/B
         viVkrQMdaI80521QZdTiuuLYpZ65EBpBAmSQzx8Obgpu4k1sud2fzw+vOrfa4/YDKvgP
         GiWvhvcCPtqelUHrrXoi7mDLU27cxi+1LDzVFYVona2W2V+JLv/KQRQf7Ly3qdrun0bW
         KEEl47fR+reRPZJFQVhtF1juSLk2rUgz0sDFi0vrynt5aYuvhLbctUoq9PYpZd7wAWD7
         D4wg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5321CLRMeSU2fnWzq/2p9VMWjVTAZCdckN0krHR1QoI63oljXJfH
	LadNtYGvzcW3fIbxUY991Ig=
X-Google-Smtp-Source: ABdhPJwnsBoMRsig6qf1AEOwiR+Vh0ih7AEEuZ6pBypoJJFih2CGyJiiZRDi1UQWhJ4xX05muq19Ow==
X-Received: by 2002:a9d:2f24:: with SMTP id h33mr3773230otb.128.1615558956156;
        Fri, 12 Mar 2021 06:22:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b303:: with SMTP id c3ls2217872oif.11.gmail; Fri, 12 Mar
 2021 06:22:35 -0800 (PST)
X-Received: by 2002:aca:d883:: with SMTP id p125mr10195185oig.114.1615558955813;
        Fri, 12 Mar 2021 06:22:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615558955; cv=none;
        d=google.com; s=arc-20160816;
        b=PCf//sBecUw3zGcQ3zcF/fnCpl1oJHvbZQOAX6uz/gV+YHjHCP17DbKmn+CWYgaSQZ
         eykK6e6NHPQjOL3CH6SZBgTKSFWf+/zoQo1ry4TLli3tNjZjR6EjU8BWF3p8YDe4m2nr
         DQ3avbhcrLqZg0rWG7zaLXfN+Nn1PXAEKn2cpZT/6NihaKS3IP/0r3yWMLI1vi6sh8Km
         3M6dUaTgcwRfQa3PywXswsgG3BHVvJvprWpMJGOMS4ypcxYUt8BSiPHEczxjTLH73etR
         es3asGJA8ikKoD47zuG8tXmAFaRnBQB0TdnS4nSBnuECbDGjfYpANURUn0CxXgb0wNOc
         gFaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=PKCabkbBZWMiW6hQLSxg+DT+bnEtnmYrdXudoMFYnug=;
        b=A66YjNkRpoMQNKBaN0Q0DQEH0/BTqkfxyjZ5kAZhR/lEswD45tNtkymW20OLba1QrP
         0RdBjXmSCONx5AkAeV3r2+ORnxIAOoDrTbzji+zsT3nsxT34+/G54894i/keUgtuWhkT
         WjQIbXK5ZNGkNh2yb68NLEAUyTQadHpN9z/M12MTHDrMt1iD1KEW999pLphZqC7T2i8R
         pLZtH4UFrYh4otB4zsDXZjYmv9r0fDQhY9fLE3tVdPEJmKOkMRd1eQ8kODfdMW2cl3Af
         AnZOedJlAjwIat4+1Myg8TLCIoGAHHvYsBYwxJEcoscN+0OoEnhAAUM5InrIUNfd5JUT
         9vKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l7si381278oih.0.2021.03.12.06.22.35
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Mar 2021 06:22:35 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8537011B3;
	Fri, 12 Mar 2021 06:22:35 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 9D5253F793;
	Fri, 12 Mar 2021 06:22:33 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v15 6/8] arm64: mte: Enable async tag check fault
Date: Fri, 12 Mar 2021 14:22:08 +0000
Message-Id: <20210312142210.21326-7-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210312142210.21326-1-vincenzo.frascino@arm.com>
References: <20210312142210.21326-1-vincenzo.frascino@arm.com>
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
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Acked-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/mte.h     | 29 +++++++++++++++++++++++++
 arch/arm64/kernel/entry-common.c |  6 ++++++
 arch/arm64/kernel/mte.c          | 36 ++++++++++++++++++++++++++++++++
 3 files changed, 71 insertions(+)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 8603c6636a7d..9a929620ca5d 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -98,11 +98,40 @@ static inline bool system_uses_mte_async_mode(void)
 {
 	return static_branch_unlikely(&mte_async_mode);
 }
+
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
 #else
 static inline bool system_uses_mte_async_mode(void)
 {
 	return false;
 }
+static inline void mte_check_tfsr_el1(void)
+{
+}
+static inline void mte_check_tfsr_entry(void)
+{
+}
+static inline void mte_check_tfsr_exit(void)
+{
+}
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 #endif /* __ASSEMBLY__ */
diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
index 9d3588450473..a1ec351c36bd 100644
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
@@ -293,6 +297,8 @@ asmlinkage void noinstr enter_from_user_mode(void)
 
 asmlinkage void noinstr exit_to_user_mode(void)
 {
+	mte_check_tfsr_exit();
+
 	trace_hardirqs_on_prepare();
 	lockdep_hardirqs_on_prepare(CALLER_ADDR0);
 	user_enter_irqoff();
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 9362928ba0d5..ef6664979533 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -158,6 +158,29 @@ bool mte_report_once(void)
 	return READ_ONCE(report_fault_once);
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
+void mte_check_tfsr_el1(void)
+{
+	u64 tfsr_el1;
+
+	if (!system_supports_mte())
+		return;
+
+	tfsr_el1 = read_sysreg_s(SYS_TFSR_EL1);
+
+	if (unlikely(tfsr_el1 & SYS_TFSR_EL1_TF1)) {
+		/*
+		 * Note: isb() is not required after this direct write
+		 * because there is no indirect read subsequent to it
+		 * (per ARM DDI 0487F.c table D13-1).
+		 */
+		write_sysreg_s(0, SYS_TFSR_EL1);
+
+		kasan_report_async();
+	}
+}
+#endif
+
 static void update_sctlr_el1_tcf0(u64 tcf0)
 {
 	/* ISB required for the kernel uaccess routines */
@@ -223,6 +246,19 @@ void mte_thread_switch(struct task_struct *next)
 	/* avoid expensive SCTLR_EL1 accesses if no change */
 	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
 		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
+	else
+		isb();
+
+	/*
+	 * Check if an async tag exception occurred at EL1.
+	 *
+	 * Note: On the context switch path we rely on the dsb() present
+	 * in __switch_to() to guarantee that the indirect writes to TFSR_EL1
+	 * are synchronized before this point.
+	 * isb() above is required for the same reason.
+	 *
+	 */
+	mte_check_tfsr_el1();
 }
 
 void mte_suspend_exit(void)
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210312142210.21326-7-vincenzo.frascino%40arm.com.
