Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBYO4U2AAMGQE5QVN6VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id D888A2FF095
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 17:40:02 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id o24sf961381uap.15
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 08:40:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611247201; cv=pass;
        d=google.com; s=arc-20160816;
        b=mk0NZWcSS3yuk2ptSTaFL7P1M8jzdwebgzbnsWVIG6nzud/v0witZxbJLzjjtc0ahn
         62RmnC9D3ma8y4Caz41KnEJj2MJPU7S/tDAgfnSZvUpvDUmI/FKBcKl65YluvRDcz5jT
         +YBsiJw2oVl7y5hDafMbVQLnEQGW5fAXPSNd6vEp7XAQnL3P/0b4EFxBQt+ZBNAumNhc
         dU8E/iExJiZVunctwr8TI29I0Ew3TNP6hZRCSPFWySsUe7EsPsqNiAXwGzzGmIK1g0rW
         sFPjHeklNu/ywGUo1dtEZMXKegJqXuJybRWJJuXHqJKWub3ADK/w0aoApyQNgqx/erDH
         yQtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=aIlxHSooK/MhBmoJqm5MIg1gH4G80OIqkXlZ/bTLzWA=;
        b=Jx7x8pIElfvJ7NFqBvOZL9Eask2lQs4xIcT+OK4++0OOOxhmpwhMsWeHWvl1zTmaTH
         whtmCGoWuYX7t95sCqbRN5rBVfj8Q8D0oHFSU1kQ+vbLeH6ZF+TMtHjM+3vEZgycWIfw
         gjKX4OF+TyaIBZSQa9Rmiy9bpO5+bo83vf3DDy29nCq63bkNjqL67h+VDH+AtJR6nCW5
         bntD59gT37CSQ2If5hB5/FwwGaSBFsaO6MYxabYgs86iIoRalvM1wXDWxHV6opP/+6Th
         E+AAfM1mE4ie9f3ZG8ZSrzIa5bfCDZezhUWXM+F0PfzkjEzUubyJdrToQpV5xbxN+eM5
         ntUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aIlxHSooK/MhBmoJqm5MIg1gH4G80OIqkXlZ/bTLzWA=;
        b=qP+MzIGBX9vYEYBYUhOpaq9Qzd/6RVLkW8SzOyyv1YGXgNbXTo6UMBBhDHgniz68KX
         sA2e+O3Exl9yAgkmbLf5lpGfPLRKaIRk25ngWVogSkeqCz2ZomGL6vni8aG+l/akDYKs
         MJMa1/6MA87VZw5YgTbfZEPTD4NQRiO9t5uZcwgiSnstIZhJZYCrwXKennu9Ys7i2OJr
         P9cAHVBmSuLS5L50FINHF30YWx/KVvAOX+JxhLWleXRGbTMeLGuhujRHgarHO61q4oFx
         oiJcdi5SGovY067ZfQ1Lpboq9hb/2r/ReJCnsWTWHQtHcVqGkV66fiTNj06muhZyBu4J
         +JDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aIlxHSooK/MhBmoJqm5MIg1gH4G80OIqkXlZ/bTLzWA=;
        b=SxGROmMsS4AV554iMXyRr6ydkXUTEmBSo8GZqJ71akLZttl4ALiBBUH3Q+CSweXCSw
         NN+BBHvwZFKTc832ZD8INdp7pviImzM5wOP3FNLNN8MJuhHixXdr4pc8GvyxDtBuhDHu
         C3IWwGii1F1R3vWqHQr1mTupSxj8TDYHjQtaEhtYFzteI85ery7HWVE0Nbrezx2exD0f
         qCsE00iaXxG3IY9IpkgwakvYYu4eSaAiFHwSJYo5B72UXJUoCQnUWkv1gN0zLKDBW4IW
         S3mjBruru7fXZcyAVEqi1AWHPbhkaQNEYAhxfS+RSPqs7hpzzJGgzok2RS9gJwT0Nwzo
         PDOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5327TtoWG0FNvsEMBUnUAR+V628bnMX3c6IDjs5/RzZfyqyYfEhw
	NqSustKLitWdVLqlm3fnMpE=
X-Google-Smtp-Source: ABdhPJzh4F6SHfYrFj04623DmNHBebeMsKa1tjjw3fGzRhognb08Y2EBoYuY5x8nnz/ps8bHpnJ1ww==
X-Received: by 2002:a1f:2b58:: with SMTP id r85mr278740vkr.6.1611247201616;
        Thu, 21 Jan 2021 08:40:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:8d45:: with SMTP id p66ls381215vsd.11.gmail; Thu, 21 Jan
 2021 08:40:01 -0800 (PST)
X-Received: by 2002:a67:8012:: with SMTP id b18mr362937vsd.32.1611247201088;
        Thu, 21 Jan 2021 08:40:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611247201; cv=none;
        d=google.com; s=arc-20160816;
        b=0GIjR2buIYICT7KpzBtifh4O80pw9GFO4QlFPWS6sHG7ZDmNPrKKwtXV6UkxXIVnrp
         JzFyra/cJXqPKtJyqyPC0+Xn7YclYpkGY7KMdKIoyxoVZ+reRJQicgjyWF746fWDRoz+
         b8LuHbTvTDzgzKnbIIQQnucIIlsm+StVuNmY3Q4mr/ppLcZMvmUz1al7ddsSJC+FZQDS
         qIXJAgRoiJYEDymblmXXVuNM1WNxNhamrtj1BAmWjaPKF27z4lIg1Dy4/SPbRfh/ZuQZ
         UccLLzmSdt6GorygUiDIIXAbXNHVRCaKsZNds/7kCQV21cfCqmO8+AxP2hAGbs+uQHRH
         hQfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=xkDsRRnRR6pFGEIukaSDYA9/KpfirLW1/gG2s5uaXMY=;
        b=Wa7Y78LZiGAkUFwUkP0IFky/fORAHRA5SXYw2FxljrD5N5iTENSnLPWFJVDklHWLUk
         r2LBSIW+HdgVODFeeF9+oTiwtEQzU65sw7Rdim+9lF24ElMZP3jI9PxzK18tYE7VoQHu
         00ou6Lt3YLKy8umzQGiOP+igRP9Qc5sHRXktqBxDt2uh+CW3b0g1AKL9hsEGx7Hhk/ZU
         S6nf7p2YFJbvt3jDQUDNsQmj1pRjj9KyVQF7BT/eifICsFF+yjjQ2GluQc0RglXNre05
         4VGJgFDegPVQJj14pIB+YWUyIDKn2T05Q6EZWQ9DAXwbH9mZUCApnhZtDSkGQeEQPJlp
         tdhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id h123si428269vkg.0.2021.01.21.08.40.00
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 08:40:00 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 579041570;
	Thu, 21 Jan 2021 08:40:00 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A2F023F68F;
	Thu, 21 Jan 2021 08:39:58 -0800 (PST)
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
Subject: [PATCH v5 4/6] arm64: mte: Enable async tag check fault
Date: Thu, 21 Jan 2021 16:39:41 +0000
Message-Id: <20210121163943.9889-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210121163943.9889-1-vincenzo.frascino@arm.com>
References: <20210121163943.9889-1-vincenzo.frascino@arm.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210121163943.9889-5-vincenzo.frascino%40arm.com.
