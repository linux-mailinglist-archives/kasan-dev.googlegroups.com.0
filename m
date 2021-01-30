Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBYU522AAMGQERO24GYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 74F933096EA
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Jan 2021 17:52:51 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id i11sf9583650qkn.21
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Jan 2021 08:52:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612025570; cv=pass;
        d=google.com; s=arc-20160816;
        b=itfqXxUq+JPhdZS/pmEPnOkiFU5lj6mqF2OutNyCHUytfr/X+iE+NJLMX2vES/yvMx
         OgLTvlNPhT+f+jHOawQlIETRdvlDWUYamJ804RPdehNU0kpn4/Qz1QtSGo8J7kxRZ3Tp
         FLHketiOuWu/ogjZoVpqk2AcX4onBn4vcUS+s7mLbawKPM/JIJGbpbAstjuVkNa22paZ
         pVZLJhYm0FlHvXTRVcLgFY0vVoePJybzl4XpstBcwLfyWkCDThVJoVY8h4SD9CR9eQ/W
         ul/ywz0BfjTTUr7Rg8Qld+Zfq3uE1UgzEJAHOG4TJN+X4Iddulg5bY23ZV3aMmjkHKOl
         1+PA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tK28fMjhNDOWdXPRomsrBTrZSRRL+ARoelVl84mBSaY=;
        b=bBWKU5pQzivaFZf4cy3L6ep7KvrJLN/yHY6F6fDoXeekE8t8dfOkEQAh8RbC4M18Mp
         i+Ojd+RPAXZfFbw3sIoC+Y3cjFnJcAI0y7AkBqtqb8hGu8Soi1jfbb4jRFrLZDk8he++
         pCL2ZfZguuKJicNfm11nbF4UQReylLSMNhDgSfigPHDRbt/JVUnYdQQHDCiGQV/KFW9c
         OVU5/A8WZgNw04nyiB9kBbPnouxnV2D970WRtJ2P0NFOfNRiUHD8QhsXTJMgC1suQKbG
         Wudc0MpiS8G18kZd3nuQcs3r3qRujsaVrSM/YX50nnzm90Or6rcgS0CMaEUa3va6xjeb
         x9ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tK28fMjhNDOWdXPRomsrBTrZSRRL+ARoelVl84mBSaY=;
        b=NkRgqGeiTH0UUdZSV4TDE6XLWNQcu/pQ/7timPyBldZvK9fBaTNNhtKkvWo/+OAeRC
         ZNaWaQzc3pM7hPEpEekkZRl9aaqxt07if3vPskROZP+6b8Pr+CA5Ci+Or1YYg37TZw3t
         OQ57D+Pb4ca7/MM0+FTon9awFx9z9GE8ncR9IDIB6wd5aFtYJOcoPmM0MDLA29e/hcjW
         fNDIoA/KP+CPMZ7gfkXYDXUcmhRBjg6s5YOvHjzPmDOo8Di/HHv1hZfR4wyMYnQm5sBG
         Fj96GNMnbKTCSNwwscACaLZlTWfl9Chm5N+YAknNvCZLjCWpseFEGfxqgwCoUfuZZzfW
         E8Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tK28fMjhNDOWdXPRomsrBTrZSRRL+ARoelVl84mBSaY=;
        b=OElImvvjZeo1yes7zv6vUpOlydk+zwuOKOrd+CAqGjJBUQ8+eRkKgIujWMhAEpXOgq
         HwYV/UBmKO4gzfxOf63lszXaCOhe80Em00RZoIN8488mcJOayGCvQqFQ5MTGheFbCz34
         NFzqPgdhTWCt9L+SKesvyptrc6JKpF0/qtHouH0c/yv3bDUj2wc+XZPA1po/kZKg/P+H
         0rV1Q8VQ7nmUFV5UEXgbgxKroiPHCAPnXj+L5HaFsfHCOUxNAUSG7WYDb2f1sAESiuiX
         ywkvt3retLoElh4OsGS+GfsPmcpm9toiONLqMOaRXIRPDn8j75gB5CfX7BpNqb8g1Xox
         3k+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533VkQ+iz67SSBZIvHqr2nSldlOSEw7VAYQRNVJulwCAd/Xp41nA
	CmyIljeKaOrmOp4xTtAG1Uk=
X-Google-Smtp-Source: ABdhPJw1271JodLZWyTmGFiOfTYARdCohgr2M4veSPWG5RS3qBn47ZeGX2SxLgZPT0fOl9dpP9oIZQ==
X-Received: by 2002:a37:4d8e:: with SMTP id a136mr8693472qkb.317.1612025570598;
        Sat, 30 Jan 2021 08:52:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a307:: with SMTP id m7ls6358904qke.3.gmail; Sat, 30 Jan
 2021 08:52:50 -0800 (PST)
X-Received: by 2002:a37:9bd3:: with SMTP id d202mr9113875qke.163.1612025570278;
        Sat, 30 Jan 2021 08:52:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612025570; cv=none;
        d=google.com; s=arc-20160816;
        b=AX2H9Y5IKxIlieva6m3SajlOti39q2n7FlwtLqE8dgcz3gz2AKOgruChR5sCjQ+lDS
         FxEr+CNPsaMiajgLAtJj0Xm5AnUvsfWbpmnuV12CfpHuW4tG0nM/VyTaGE7QnV6BFj6O
         FOCx5cvvMcLbNBmzuKxGsPZzFt6H42fV1ABd9jMRkFjC8aMoWoaC+e/Z/CDKJTq/0ap7
         1m9Eb0oNXiZbCZDuxf9vIGe4Hh2YmWt8V8yE/3qbnuNABnpfN+AxPc8X1pmaqfRdB1Px
         fiAGYmfW8wF+dlleM5e5+ZqBNmDSV7Q6v0AFhn6C3bttOVho1o+37XnwFAKysa1JgreI
         Vp5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=8GEY5x2mRfKMFo4MiYnbonG9ay76RYjGKWUnyeBgCqA=;
        b=MDSEdgCMn7co+HLW7v1MZZi9tg4eBUrQF/uXjZU31nK1XM27/6pgOGpJokQvywfRuR
         taE1LcgtZxM+p+C8OeoeHdr+H291nqoMUf++mzjLR8qEwYQ2ABcmpbd116Pp8nekoBVI
         sqboIaoYpPH3zFc1tn389IaGj00cySB1xj7X2GQ+fXeNPdIHTcAA9BxGtFUUgGz8RWd/
         WwtSU2TNquLWeF9JB6jWEu1CVpmQ3FYFYgDn/y4DUvKO5YSWA5UCB/elnKvDji8otTVJ
         gy16vbo/CM2rRfvM2jCRqTzWgltWSYlz0GPp92qmECKkSSiBJ8W/higI4xSH3hhWeaEV
         Vehw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a26si665760qkl.1.2021.01.30.08.52.50
        for <kasan-dev@googlegroups.com>;
        Sat, 30 Jan 2021 08:52:50 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id CF2511509;
	Sat, 30 Jan 2021 08:52:49 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E145A3F73D;
	Sat, 30 Jan 2021 08:52:47 -0800 (PST)
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
Subject: [PATCH v11 4/5] arm64: mte: Enable async tag check fault
Date: Sat, 30 Jan 2021 16:52:24 +0000
Message-Id: <20210130165225.54047-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210130165225.54047-1-vincenzo.frascino@arm.com>
References: <20210130165225.54047-1-vincenzo.frascino@arm.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210130165225.54047-5-vincenzo.frascino%40arm.com.
