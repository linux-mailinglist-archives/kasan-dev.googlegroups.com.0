Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB35UVOAAMGQEU53LBRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B9A73004AF
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:00:17 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id l17sf3433104pff.17
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:00:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611324015; cv=pass;
        d=google.com; s=arc-20160816;
        b=OGY/m4JMRS2dIU/tlziS4/qyAJld9CDcPR92+rQoPfNsYK8+KHq3AI6paMIKnv5R0i
         CNeasqrwiQ8rAiVDNI3yn8yotUQkmbpF2FKrJAR0c68Cd6gYQhkNJm+Y1nCVe+tkWy9q
         v8cWejtb0KVZ13xehE2bGemDBGO3XAefkzyQ2b5EijLGXtqxEC9fhl6+xln2AkvAYhch
         25QcpIH8M8DLOzu8SIbwn83ckD+RwI3EU76yemmfFdFn1IhQxptDt+vJRXHdivaZBLUh
         9tcGj0ikvii5rVlxWpbhEvRz2u58RnkBtAzi0IgLOT/et8ulanDWoySUo26I6A/x9tpt
         IeQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=e+VAZ3ow0qqnkX3Af/BB5jfBGC+hUlQ15l6ReZ34OVI=;
        b=q8gqfB8CfkQMNwzDjhE1wmLsybLmJZsDak8roqq1D3b9u0HJc3T7tnL863dgeEcHFY
         /puU8bb+S94wYV2bRzN/K/qO6IC+A2Q0w4gdXBUcfz9gjYj42zkk7/hcVKYjeyVc7d/O
         L7Tx3JaZAVXoQh3LFCguSf5TjAxZZSNYdTMQEn0CPhlnLi3laHPUFNuyTpcNijXZdinp
         NyRdbp8rOrjKyqzHfdZOV4DyLrd0G+qYTXZDPZg4YMx3sqfpPCi993Njf0wPgB0iwdjQ
         8XQmvC6AibKKOzudoMSJdDmtNZdHoziTGgBy5B2UNcsdCX8K5MbCK45essQO4QQQFONA
         obkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e+VAZ3ow0qqnkX3Af/BB5jfBGC+hUlQ15l6ReZ34OVI=;
        b=em34QgMvfSK2lhphlAR/SV1IwToZpX0C8wSN1Cov/dEVmDW8sc+Cn5t/MKY9zO4adj
         daJsdaxJiRH54DsbXMlNR9UvfRP/SF0RTTdTlUnymu1eo7UDJUxTijGyqTJ8BLhbh1BE
         UukC1NCX22ETaWO6ZEIeMkV1rSPtWWpioU3Ml5t78fdrEQFAHcDxvRxaVcPSn1fjoWxB
         0Og9ANUa5LDNz1ltr4eTK1NDuxOXzJz526+go7JOBe5D3FNSWOVP4HqRY6hgmTJXFaAt
         G7nTyh1n7Q/fKKHp4qOu2JhhUj0793BcDTK3NmGsasDqiBtgF/yMQrcHLkIWimqA7YNI
         JSyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e+VAZ3ow0qqnkX3Af/BB5jfBGC+hUlQ15l6ReZ34OVI=;
        b=MxONIlhXBC1VCCad4tkm7/7D3E9jCcQa7/afOeeuII4ESMqgPXAVDAKjR0hnHPTf6s
         uFS3Jmi3K6zb2FsdBR2u7BgBsHMJqosJvtBDnGTjaNE9gLWUi4dSveGORHW5skO9CYwN
         Egt1xnNESq3Oj4Jd/u3PbQQ/jFt3vZ5B15LeL3/NqfNeqjSUTV5Vj9/gGwg0e3HKf/zm
         UEdw+JtbaGGXdSB5ZAPJUy328ndHYLP7VyFAGV60HnCRBcsH/7d9rVz+SAjr3NFTBCTE
         SZEAQkDU7isizIWpcr0QBW+NyE2FbYi08bTBPwESGfkH62307SPOgrXu4mQjQYBaQU2Q
         CNRw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532nTwG/FZw+vQKEWtcktGPGIbo5MxSEL8Q5GQRvTMpEZFHUSCdt
	WqTuvOsl+YX2UzgwwWFffi8=
X-Google-Smtp-Source: ABdhPJxDuLquwj+Np/6f36mWHWZxYiKgY2VQq/8o5hLl4jAwpY62sl8dYFLpcza+QGscnx9+0dPDLQ==
X-Received: by 2002:a63:cf06:: with SMTP id j6mr4741724pgg.195.1611324015830;
        Fri, 22 Jan 2021 06:00:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ed85:: with SMTP id e5ls774458plj.2.gmail; Fri, 22
 Jan 2021 06:00:13 -0800 (PST)
X-Received: by 2002:a17:90a:2ec1:: with SMTP id h1mr5693050pjs.18.1611324012918;
        Fri, 22 Jan 2021 06:00:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611324012; cv=none;
        d=google.com; s=arc-20160816;
        b=SD5fm/TOInaytbFSNlJ1boNQQEKa6/33+h9WHacZmpse4/mKtq53tpXi/YPJa40k+7
         d/rvu2FDZ33MUsmHgRMslb/WsZI7jPyqPRrhTjFYYQYvrsvYyRARVK53c1Tq4KUEOKJf
         cZNki/ZNBOg3VPIGmB6CN3ko8tvi55OWdGpYdZyJZX0+Ri1K1UDyWyOhwV80j7KjxbJM
         n6/HwKuMg2TnUwtn4n6yNCB3o8NeTEF9rLyWA6NIbgRsHdEgCo8MxBwTaHMhmtaXWbFi
         xb78E3VH+OuPgMgyV+px9prQwmS7Yb5XfzSulSpMsntSn7GQX2mxdhEH8fN+bHE4mhsS
         4GAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=IV38BDhbyazmRnMadcaCmVSMFIlIOiNTDhCTGiUXPrQ=;
        b=Fjh9rftuOV7w7hQ+44kdHFt8AVkZEUjbTZ12z39AbzO24kf3cIu9kjcsUuIAjVbVQV
         ePiWCQBq3z6BtfCo7UQiZYaiB7q0cohz7cbJRg0qr6NC4wLXuOJRAbZXhmLhvsYzAiZ1
         jFUnWb0lkp+NfdaRrbKW/WTMApS+aeamxWg2bM6KEKB+UWDbtZ3+GyuzFQ+0TFAbVilo
         LdwFV3Ax+c8n2V4RkNrF6WCN4xx85/rfsuHbZMm/+YvOM+3g6OuggiLGk7Vh1XXMHHd+
         teab5Lpt6FjmkD63eIwH1f7/07osBgq1ExWbbNDw4nGBbCvimuw6XPoZYT3YhpQQDX3+
         Bd3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d2si582831pfr.4.2021.01.22.06.00.12
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 06:00:12 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 3E68D1596;
	Fri, 22 Jan 2021 06:00:12 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 9350A3F66E;
	Fri, 22 Jan 2021 06:00:10 -0800 (PST)
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
Subject: [PATCH v6 4/4] arm64: mte: Enable async tag check fault
Date: Fri, 22 Jan 2021 13:59:55 +0000
Message-Id: <20210122135955.30237-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210122135955.30237-1-vincenzo.frascino@arm.com>
References: <20210122135955.30237-1-vincenzo.frascino@arm.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122135955.30237-5-vincenzo.frascino%40arm.com.
