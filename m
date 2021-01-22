Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBBW7VOAAMGQEXIQH7XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id C63AB300744
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 16:30:15 +0100 (CET)
Received: by mail-ua1-x93b.google.com with SMTP id r13sf2075578uao.5
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 07:30:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611329414; cv=pass;
        d=google.com; s=arc-20160816;
        b=jqFBP4IyuES5zk5fHs9OlgRtKq/nx3B8LWoLbq0Dl6Q0xLMQ1HVicU80/sAZuRwwtt
         v49SMv1RF6MSZOwb2pIQo6XotQVcQyMOIA6XNa6yQnBO3edkhXpzkbP+b8fk1o4wpzt2
         Ag2xOD0zaFNYXjs5ZZTtWpoJ1TlZRY3Tuc6/Hvrxno7rtc13695ozZNrDPdLzyMVu5mx
         i2BCrDHhyvLFSRikZU2ttQOP5PzC88GGdJ4z9IHe8mZPb7US5fQMcZwqUYf+lc+g0PVz
         roYGRTe4IU5iDjm/fnPwbGD7ZpYMdlW6RVWvW8pdZjBcgmPmhC4so6BMNgekCDNDKMPs
         uMVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WJtslG1jiJkrWNWnDtzi9D9ZaET4fBuhQM6Poq9t0CE=;
        b=K280Xj8kZ9hDPxITwNKqRIj2ZFAWQTiNzPaNhOj1jFzedQ2KX4un+Zwoa/7Sz0ofbp
         uZFbbo/qKONvwiPllyTiO6ngMfww06VzcNY1GHQYUyKh6J9mk79vI26keoS2hyDymJb6
         jqE1P8vLFe89f/4Nuqv30kEFkLM+qa8XSqekW1TR06colWl7kZ6zR+qIY9ytkyYZQt+N
         QiN9IjBsFFVLMWfWLc2T8dKFGr2Adqz264UHd+Vy2RV8IaA2KnmCWCMgPnBNxD2cKWHz
         n4TX7H8p0CHC19ExYa8H5idSSYp2IslQYPIQ7EzhmNBIbAJNoJyYKZLHY6JQWeEdO5q5
         GULg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WJtslG1jiJkrWNWnDtzi9D9ZaET4fBuhQM6Poq9t0CE=;
        b=f1DWIFnls6eXL+SxQL8RLgr+rilK3X7URg5er5sv1xutJFuLVB2yGcAm3BtVAnWJHb
         2zKu6pIy3ipOJk3/Rrja8ir9KYw43P6F2ZTX5Xfu7HgAo/BsA2nnDaSDgd2TLqa8f/S0
         zRaFnBk3nxDw/piDoSGaEE+OPvC5Gl9zOlEdNdKsRPAGHiEHmekeFrm8BJy5WuAKwY5T
         ZF5RaJJKXGan2UEt016rJk7UkX4GcN5kZzGIIlnd/ubWIDZ8cOvZ1dEY09eg3oN/caRM
         QbSdDr2+hBp/A2FzoTC+di6EYjqeTqywsnPAhO/N/kDs5A0tu1tAAZ2BZ5QPrHsWWH3O
         pMZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WJtslG1jiJkrWNWnDtzi9D9ZaET4fBuhQM6Poq9t0CE=;
        b=ERyKRGLrMWKMPmdg5ejSsD99Yb9Id7NgM7SvOUZWVTE4kWBBn5VSwPMCxAXXjF/VeV
         7zj1dtD2BTaXtz6433Wah7ezLoOavOEyAPapjeKNbFtlceZth4XPQRXfo/BzAWs74zxI
         sTxz2rKwj69qCuTnEgbhWrv8bSCbRZW9ioLjB1X385rdFwWuzlzyWHj4RkSQLtd/HNuM
         mjstxKkjedW32MMpMcfnGCLBkeJ/H9tvTPZOStsy/R2VHHJ15mKYelX6z3XFRdB1R5FA
         OtocAMHUEJL/nb+EwTy82E9EVxlhU1HJdBTHif8DY6uHVIo3JgWL7mbbZ/UXieMYUKFD
         rA0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530S+8fboWGxxQTKBZRMBA86siOVvZSr0tV6cg23zsw8wP7j55gh
	CDcyOhRDhs6JhldnkvuFREY=
X-Google-Smtp-Source: ABdhPJykdpsjo8BrFQGrFgbkHxdBkCRld2+DrpYt/FNMuAj0Y77lykVdXHxnKr+u0Eb6Kuf6vO/Ysw==
X-Received: by 2002:a67:f794:: with SMTP id j20mr3566043vso.1.1611329414736;
        Fri, 22 Jan 2021 07:30:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f902:: with SMTP id t2ls834357vsq.1.gmail; Fri, 22 Jan
 2021 07:30:14 -0800 (PST)
X-Received: by 2002:a67:d60f:: with SMTP id n15mr118464vsj.37.1611329414213;
        Fri, 22 Jan 2021 07:30:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611329414; cv=none;
        d=google.com; s=arc-20160816;
        b=lnTRywSxdehz5Ir41lZlawzDkUGkRefodcElX8L+++ToOcnBEFNZkuw2HPX3ShiEjd
         Xu/VGtu3JI0l5nv5VbkW/oOYpT3ghmucrODKtPA2CGkgZdZcoFy1jorF6O5lMqD9dt18
         HY+yAiaWhSfr77un1sKgCmR7akqTsiMbR88neZA68NVTanAgh81uPhl58Q8p0nDLgW1+
         DRYJzyeCje46+PTLmxyAQhpsml+tE+4lBXnIXq28SJKwoUC3poThFC/XD5nG2zRW+/p4
         vFSKMInzXMOe8HdQdlXmDJF7LRnaSF63rOBCiYvo9SWn4M1aoMXTdkKOFlrLY3olzLO+
         OF3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=8GEY5x2mRfKMFo4MiYnbonG9ay76RYjGKWUnyeBgCqA=;
        b=bZLObZtLAPLSCt5lOF6o7QKmsPWDmLmw/SQ9vRqM9xAPVM6cSY5dUAixczhhGU81A0
         ZZ5U7F9sKJcV76nYy185xugApv46hxRjAY3rswK8wpiuZmjsF95eGkmZO+r2btsvW3Wf
         J6NGxB0DxHJzxnFvgyVAv1DK9gRP8gvrxmf2MZ4Vapn/dF+ZubDdeCREQZA44bkiauWM
         vfXl0nzPG+dya1oQBcIzc0dkKUGXkPDIktEksYyMHvmYLUhXRv7qsF3q7lyd5t1pdTjz
         uSMZ7fB0XJ12wDICCgE08XlunHnAmm5AR2aRxuu/1pKjk595kARGTOv5X15P5KCZQ0Ob
         bfJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id h123si593704vkg.0.2021.01.22.07.30.14
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 07:30:14 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 763E31596;
	Fri, 22 Jan 2021 07:30:13 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id BF4B43F66E;
	Fri, 22 Jan 2021 07:30:11 -0800 (PST)
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
Subject: [PATCH v8 4/4] arm64: mte: Enable async tag check fault
Date: Fri, 22 Jan 2021 15:29:56 +0000
Message-Id: <20210122152956.9896-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210122152956.9896-1-vincenzo.frascino@arm.com>
References: <20210122152956.9896-1-vincenzo.frascino@arm.com>
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
 arch/arm64/include/asm/mte.h     | 32 +++++++++++++++++++++++
 arch/arm64/kernel/entry-common.c |  6 +++++
 arch/arm64/kernel/mte.c          | 44 ++++++++++++++++++++++++++++++++
 3 files changed, 82 insertions(+)

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
index 92078e1eb627..7763ac1f2917 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -182,6 +182,37 @@ bool mte_report_once(void)
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
+		kasan_report_async();
+	}
+}
+#endif
+
 static void update_sctlr_el1_tcf0(u64 tcf0)
 {
 	/* ISB required for the kernel uaccess routines */
@@ -247,6 +278,19 @@ void mte_thread_switch(struct task_struct *next)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122152956.9896-5-vincenzo.frascino%40arm.com.
