Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBNFR2GAAMGQEXV2RAWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 73C7A308CBE
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 19:49:25 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id t127sf1186027iof.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 10:49:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611946164; cv=pass;
        d=google.com; s=arc-20160816;
        b=OXbaDgrd9yUro6qu99P7GkhI23kIyrAZBYH32BQ2gH1LBTuOLIvrEmXr8YYArKHQ6U
         V+D8zZc5CMSx4/Ohk/qWogNMhW5jJ4L+pLx6JGR+gJdONaO5NkWQd9iF0ZfFH6c6MMCt
         1enjRG8/08mEEfC3cJ793xwWzhpbYSfX7OYoJVg26TUI+0V7e8AgMOA5Q3zcURqnAi8U
         0psV+Q0D5CqGYwtkaDS+Ggf5FLt9AIGkI+5ivuXCJOOD5S5Ac8yGSVbAFlFrwN5SPAa5
         TP0/3QFy6zd5f3ec9+US1fcNH0AU3QD1fxG5y3Bm7eQm/R6pUwhb+S8TCZc1NRSjfHWE
         7Uww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ruHgiMFZkhsRfV5hdhCAUIFwdMj1QRsCTJXvfuKbvkA=;
        b=GEOIj4N9eON22zLhJN7V0/wZzZFrDGZOvtNlonfVBfGd0RojppsbIFFdTjYv5p0r1M
         t9ql3LwE/suo1Xldhbzrs9hxoMrKzyTgLt9lCDNue+k1oigz6/9tmRASFkKeJYIhG92t
         GEXPkK3ZG/3SqfLX9JTz8MuPf7hAduV/ZJy2Rv1AnYaZSrLAByJ9nCUWBnaGAEYrjOTM
         t2RB4RLmAR8Gt+5qe6/cxJFSN90fQoZXTCrVCA9iYYMaUYmNBnQlYkzglM2rcZqFrJRQ
         yFb8/pelGPQPDTxsQi7JFX+8XvcKvZUd1NCQCocELKEYc/ZA4CTUIXaxsv2k2kZgx6+t
         Yn/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ruHgiMFZkhsRfV5hdhCAUIFwdMj1QRsCTJXvfuKbvkA=;
        b=GTr+FM4F6bhDTdlK3n2KuH3NbhoXEh/JblNaHv+c4nI/+2XAzNqjwdlow1r6KG2PtV
         6uy6R7BufCefepeeeyF3f5j2pyMr0vsSxXT8i9rKgdSmLHI4eEQbyaltcs0E24edg1Dg
         alts8vX0vDDHR0+PRd8WhdAY/czf9p0OX9RCX8creuQnvUicBSeycuQo2OAVQJoqG5Eg
         DYK1mqF/LehxoxQuACoOkLWd4rB1jxhUJLDvIGBKV9vRAeBhgQV9/sczexjxv1gvRdo0
         XRL/dWKA0BfswuG5d7AoNAKi397P50HoN1pmigGVQSsQ8HOH1x3IDPYg7aG6j1Tie8hR
         OEpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ruHgiMFZkhsRfV5hdhCAUIFwdMj1QRsCTJXvfuKbvkA=;
        b=FotyU+WgGm8JmrE6HgOkhcz7Rf4YCzf1IhjoQuZ2u0SW9Hy++s5mTuDlEOhRlmd1OL
         GauNxroGRX9cnhWohKg12UG/lT0d0xOZxaQpAnwU08j7me/IvW6M0BRoOTfdgLBa/jhZ
         pvoEcxiI13wiLEE7ueTCmaBWTam+1/6bv1Zj7z8/3y7p2Wy5IQmpajcwfqBlefBJH9EF
         vjB6VbPgBtEk5GUYbaf1vVy+FD6x/Ts/lytkSsvjIQS1EHszgYd1CC7scxEIMxT38V0r
         ci+wPXxjPwmIIvVeAu90XvxeQwLoTkYAeN3os9++xfoio3fZagll+xnuWDLRYbgW3EUH
         fEvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530tiyX7T7DtovXNgUffWr5/EmRtI2fVAtNaBnGO4icTv84GDvVw
	4p1IkU9a+s3OsIKgfwytrAU=
X-Google-Smtp-Source: ABdhPJzy19ThC0v1erUrXrdOzXxeZH9VsmSFt47YXe2RK7XK9obEZvoVYEb8reodMME4+6r7wTcf5A==
X-Received: by 2002:a02:1dca:: with SMTP id 193mr4790066jaj.39.1611946164336;
        Fri, 29 Jan 2021 10:49:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:4b06:: with SMTP id m6ls2430032ilg.0.gmail; Fri, 29 Jan
 2021 10:49:23 -0800 (PST)
X-Received: by 2002:a92:48d2:: with SMTP id j79mr4625095ilg.201.1611946163891;
        Fri, 29 Jan 2021 10:49:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611946163; cv=none;
        d=google.com; s=arc-20160816;
        b=uv9bybmBgFOgYO92Moyky00NC8HLZeahF9lvitCPJVu1L/U6yHZvg1u750ODkpKvcl
         tjuYukUunjm3Aw2pgfBvTI+o786Ac0UtCt0d+FA9UqdsaI6y1diA3eW6mG220YoiLCSW
         QeAn4ppD+CK3CyV/Vcfree5ch5R1U8MbkAklPjeUHmBKod8BInBJAun1ojCMF4NnLncm
         Bk5+hL4gzOVbKq4m7vOeWbaEX82oR24lo5Z3EBWIem3lRetc3no5cew6eHuxcdgCzH+Z
         a2IOXz2jrt5TU1voUrMu0rHaypvEwTBahgO/WYfHSEuA6tTVautasDr9m+KgVtNO4HBL
         W3rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Zq3MK+RFzdUSCX2hAEQ7OvvjFLWIVrPueHySjya5KQs=;
        b=SqDctlif4kLRvNbyNy+tX4w7von94cjEefz4b0v1azxRnwDQBd6PHNymPjUhdLQE/Z
         O1bwrqnO/PiYPaILbG4mWJGXBziuc2ToJrCmWrc5Yj6K/Uh5aVmXcz5l0xeGguYNtg2j
         pZ8jpEmAY9dY6jrfw+hJObwDjOWTdXYoyjIbVUY5p3tWPhKcyvdX8LokefkpXYMAOZgd
         ehlCy5RDMzl5DT05dxOjlshI1CjzQZ94CZqBxb0f7hD9Sp4e80DpMHwZ76O8VOkTEQKV
         MJcYIIfKU11wY7nSd0pFP+uYQa8A0+nT2jJOwLsujao3cSvQGIG3ANAxVPbBKObIY2T8
         NiKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id k6si499854ioq.1.2021.01.29.10.49.23
        for <kasan-dev@googlegroups.com>;
        Fri, 29 Jan 2021 10:49:23 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 446DA152B;
	Fri, 29 Jan 2021 10:49:23 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 7DA7C3F885;
	Fri, 29 Jan 2021 10:49:21 -0800 (PST)
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
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v10 4/4] arm64: mte: Enable async tag check fault
Date: Fri, 29 Jan 2021 18:49:05 +0000
Message-Id: <20210129184905.29760-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210129184905.29760-1-vincenzo.frascino@arm.com>
References: <20210129184905.29760-1-vincenzo.frascino@arm.com>
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
Tested-by: Andrey Konovalov <andreyknvl@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210129184905.29760-5-vincenzo.frascino%40arm.com.
