Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBDE3TGBAMGQEVPHCQ7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CBBC33131E
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 17:15:09 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id v196sf13326446ybv.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 08:15:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615220108; cv=pass;
        d=google.com; s=arc-20160816;
        b=zakrkQsOnMJ5RdKhnze8wbWBmbUib0a2ntNq2Cyku2cwGAHjOIk1ZDK8zBT6tOd26C
         WDzrGGykLZCR/6cTVk/o56xmRjcwc4xEXNX7qQzlGDMTHxr1myLE/sObmiUo/Itzf4B3
         BkWQa+SJuDgoxwy1nU7Uu6MIZ5Jz0AE3wNeK2ughNkn5jRkSjyOJc+uGTw5TcOV0CyqF
         Xe0KhrBOmdL/rVyqraLWVKOhRl+jiLNss1h7xQWrQTw+HEY2Cmg93ma3GlmWsFhdjE+a
         leRH+b/Cx2dbX8J07fRbpcQFmHDNxFIL6yKQbu10Mx7aQXI7bHGbuq/RkjNHOWZljwkg
         N70Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SU7wS6DNtjcL8t32mffQ4BXDKbpOZCX1jmqtdMSz9z8=;
        b=Ee8gsdtTbqt59l4rzwL6yQ53w75eqrTXzkqry3tYkkoqJ9NjJmS0hf+igBWDgRK41n
         QT6Sb56/Q/MxTle3VNBgqgaye8FYOUBCI9m/baOZmhaZzdYJBp9bWznBjNij9Mf6Gxcg
         o9JIFRoxW1Gh7exe2GHlmMZZZMxm5wTkrUngJKJ51ePXRq2++ofPV9h/CHBInRspE/EC
         KT4Iox9KtcPTr4CfqgBdC1j1rv45t/s2HrdA7o7yvdp5hc73/XW1iiktSiU0NsboOhvi
         mdGcyZx/k3sKfmGdeP/2jLkx9Ev0f+Z9CI9O6HaMHJBLY7KHxLRLYnB4sZRSNDY2CzCg
         9HAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SU7wS6DNtjcL8t32mffQ4BXDKbpOZCX1jmqtdMSz9z8=;
        b=WwiWMukT/DnvoCt+8Ckhj2srI/t9ToxScrgjWActvzQEESiHZA175fP8tElfphfN2w
         1tsb0M0oJdmdgZxb7D3eu/WrJ/a1tG8hxBeUU6ZroMHy0IYk9UNRMOy86nxlpqSEq11l
         /LWiMN+UFcddqbozZg8Bls8CE63gVzwh8A9z5wAHzY6AL8/fZbNn38V29ZZq7Di10MuT
         lYw/Dx85GfuWK000pikzM/vcNReUEDrGcHdnCTHZuBUKFBiPBEHlZYv1YFEo9lqbXxuq
         LQF1NoNGcdzDTZEOW33BHEFgMmGMZuYUqD0uZrIC2UWDg9L0Mm5929Xd6ND+GCKporY4
         vP1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SU7wS6DNtjcL8t32mffQ4BXDKbpOZCX1jmqtdMSz9z8=;
        b=RjGZhGKIuUiT+/u9Z8JpXNrgceQIS2nT9m1HvrJRX5UkgAOlaMTj55Ypps8bbCChv/
         ynNG1yz3B5Nbtq4+fajfT5SkwYNGl4rLO8yI/4MWNi7sZPZSfbASgiJW8O/68AjsUOYD
         qqyPkN44z+Y2buHX9FLop37TJrJvBsYC8lK5c1D/hZx7vzkxhHcmjfTkNell4aY39mMQ
         9VhLcZddaqLvCqpWD3DhgTdLpdNU3ajZaB0M1SRHu/D7HrREWnGKNGDG4drDKErOyckv
         93f5eMPRZW/2wcAXjsKREXKsdoUNMwOt84P5qyvPpIU29B9oSdjSMMYCT4fFYX6v12cd
         NRqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532m2nct9dhO/peR6rU+25+asZRGdu2ARSbnr8nHCDtrhYLShmrM
	pqiIw4v0Kq3OKAetTmtZVuI=
X-Google-Smtp-Source: ABdhPJwbdXkfBCs9LgkG3LMSinsIBTLbhRtYqLgQ7Hn/Fx/QaYCckfMrtM7DRMtrrgyicIjk+My99g==
X-Received: by 2002:a25:d74b:: with SMTP id o72mr33880484ybg.190.1615220108607;
        Mon, 08 Mar 2021 08:15:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:bc4c:: with SMTP id d12ls8924670ybk.0.gmail; Mon, 08 Mar
 2021 08:15:08 -0800 (PST)
X-Received: by 2002:a25:e403:: with SMTP id b3mr32539389ybh.503.1615220108200;
        Mon, 08 Mar 2021 08:15:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615220108; cv=none;
        d=google.com; s=arc-20160816;
        b=JiG0xclojFXXhbmssuhYkUZ8PUvfyGgWZAQm4CZJAIiwAOHbapTZnZ4tTsPJXFfXWP
         4mH30p/Zkz/SwoaWsYDOB2FMwzP7O4zXSmDo8UDfR+Ku5ufegbYenAekS5PiV/BkpXHy
         8r68vpii5Lhjq+CcagM/bDr3vjwCi47em157YazaefJ+BYZnzD1NlxSXOh0LDN+Qd7g9
         LPpLvfigEba/6bP+umnjHYWJKOGnXiJYzSLiJ8dz/0oQ++8uYF5iKoz/c0dTMMG9AzkC
         pSm22kaQZMBR+plaGKLhe4OLxpqKF7l3fLQlEZ1cEtDCO4UIzGaDrxYRO7ossNCZmbxZ
         MHJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=VqHWTBuTNsOcT/PkMM/6cFmPGuaq78xD69ysOtKlGeQ=;
        b=phaZtYApoZQzY/GCfuBcb4TJVV+HyCbGYb5lMQ7gddMiVGUvefgtHAlhbHSTB6qoZ/
         yRdNshvur7nZ3tru6tlv3/AtGSdFTjH/Cm0cuZLT4YZmPYmF5sn3mY3qiDCcP+J6mTAa
         qynSrSSAJFjD0qhpW4KlyZZ9XLjHas46QwNMgO70eIFbqGKUhcPl+SI4HRDEyKCsKr2I
         UEuhCiidZA7BYVkTgtJcJtMchdRdJF/V4Pe1zRgXULjD+Oto7OueXdilIexPg8pEvl1B
         Nc3jtbUjIWZGrjuGZ3sguUexmNZXRFIt25kW6ffs6XPzYpP3aQ6MwEpUgZjKZOk/VHv6
         sOWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l14si1067296ybp.4.2021.03.08.08.15.08
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Mar 2021 08:15:08 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8EC20139F;
	Mon,  8 Mar 2021 08:15:07 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id AB5513F73C;
	Mon,  8 Mar 2021 08:15:05 -0800 (PST)
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
Subject: [PATCH v14 6/8] arm64: mte: Enable async tag check fault
Date: Mon,  8 Mar 2021 16:14:32 +0000
Message-Id: <20210308161434.33424-7-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210308161434.33424-1-vincenzo.frascino@arm.com>
References: <20210308161434.33424-1-vincenzo.frascino@arm.com>
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
 arch/arm64/include/asm/mte.h     | 32 ++++++++++++++++++++++++++++
 arch/arm64/kernel/entry-common.c |  6 ++++++
 arch/arm64/kernel/mte.c          | 36 ++++++++++++++++++++++++++++++++
 3 files changed, 74 insertions(+)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 9b557a457f24..43169b978cd3 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -90,5 +90,37 @@ static inline void mte_assign_mem_tag_range(void *addr, size_t size)
 
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
index 1ad9be4c8376..d6456f2d2306 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210308161434.33424-7-vincenzo.frascino%40arm.com.
