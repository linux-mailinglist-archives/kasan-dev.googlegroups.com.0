Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBIF2VOAAMGQET6VAAOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 79DC33004F4
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:11:45 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id o20sf3508971pgu.16
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:11:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611324704; cv=pass;
        d=google.com; s=arc-20160816;
        b=0eNuwTWUereDgpmy7yTOXEgFu3Q/OEBV7OO4uVEB5qgcc8rRYCLPAXqO2TUML1s82C
         YUiJXdL9OQokC2dXiaQ/rwZ23lfm8ylccySo2x/JT0SrAQKCFMvnnrUXM7wmdjo5KYF5
         jMFe7YUs8P7M2zpo+pONjcgWUB/CQScrAdtJV3x3xaT8BfNRAJjYZ5qKe2W/n9j+7Q4r
         ZeH+pFg7uPFb3i/ubxF4Yb/vhPLgrzCQOb+VDEpffM7WgfPKIwRXpRXQVZx65Za/aF/t
         s28oKM4dPWYOl3orGcwI+79e/NsV9DZv7wIwUFWhm4MXTK0QqoISl/4g2//dQjvCNPy4
         OVpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ayZlIVBh0h4Xl351SMTwZEYd2MijdzvP7pO3GBlZeVo=;
        b=n7Kd9xR3nh/YirbuhRsHXnv7lfCr7CSOWTaLRhoLblTtlz21kzfAXR5senE5TNCVEY
         +qTFmen4y9FRiUBZaJtV5c+vKmq7/NI0Fb2nsJ0HzAMfoPFcDLNxDfwBeHAqLQGL09wV
         jTJR54Vr8YOVXD/2+YDY3ahBeyjS3Y5efumqz2Y5lwnbORTaX/k7AjRlXo91jManV+iH
         qPoY+9MAqyBNADJfcbEq8Igx+ATMFU7brGrbINh8CeXErL2eH3C9wvsQRcWmab+12PoT
         N+eYRAZ30jzE/chJnkIGrUgVjdslWglIfs5PytnHjyv1bpI4emH26fvj5r0vtbN4qnLA
         NhPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ayZlIVBh0h4Xl351SMTwZEYd2MijdzvP7pO3GBlZeVo=;
        b=Rs3eYPW+0Ky/casQ+L69WdQK84eQGcErVVdx1sH5O4XyyZ/HNs4w+CU+q3gWyzMqsj
         zgj1ZgZZSA0ySP+qO54fSuyz7Mupb57MereGS6z+VSOgEYETcuUVb+YpDHD4UgslQsOi
         XMJu8qQF3xx845JXXahSguMn919lZgiubIMhkowLVreZRHNTmpp5SncdmA7n/8zhF3fK
         lh7f8Zv2hink0cBBVDBqZKy0Bjm3/TkhV9Dev04Xa45+MT70x76fCIbhsujoz1GBnRed
         R1m5ia0NXeZNxE/E3esrGWL0plmMUv6VEiBMf1UAW8Yu4hhgLgTBfOmSjCJCGApZyru3
         blLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ayZlIVBh0h4Xl351SMTwZEYd2MijdzvP7pO3GBlZeVo=;
        b=pUMFebN0IIaEKbjIwelvnM2ryHWQmIX0Rgq1vx0LRyA+8aaPKxCbhcigwWvLjRn/si
         iYRfSsiC9EMWK2GU6/EgrIkf2eRVQXKAIV/9/7PEd7PI4sWMa6U7cLS96NIW8CgUjTJV
         nO6uBLkxcVgzZ9obEiSoOgo96SA0VL1x1W/GQ/JpkS8pO0fXKFkuGU261zAV3ddoMaN+
         L21XiTDvKw3C7LCuA5Vgo+LBVDEdq4dGfST1+nlPR6Ng3hpvQTRq1nRzawuRQPvJEc6L
         Et+n8f4gJLCUMTN/IrnYgZGNVUGS0TfWdWhG0UhxwWyJCMbFNTBDwy0SggdWagL8RZaC
         KviQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530MgG1F3gZ4ahvGFSX1MwbHB4ZgAxfE0lBMGIEla3hLilzrYcgE
	SSGvoRTI+Tp3bYWnFWcjAXM=
X-Google-Smtp-Source: ABdhPJwzJblSyP3PxIt5ehGvBS+uZ4Wxp6C40YqbU6KcOn3zdoKxQxK9GImgVeup/ShK61uxQ79Lqw==
X-Received: by 2002:a17:90a:4314:: with SMTP id q20mr5735027pjg.87.1611324704228;
        Fri, 22 Jan 2021 06:11:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7047:: with SMTP id h7ls544499plt.8.gmail; Fri, 22
 Jan 2021 06:11:43 -0800 (PST)
X-Received: by 2002:a17:902:9a03:b029:dc:31af:8dc2 with SMTP id v3-20020a1709029a03b02900dc31af8dc2mr4756472plp.39.1611324703596;
        Fri, 22 Jan 2021 06:11:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611324703; cv=none;
        d=google.com; s=arc-20160816;
        b=Dx8WHFVXrEtd5UKF/kxv841NFufiYw8fOUk3IASWGbB03fAfYN+iB60BXWzHaRMUzo
         Rwf4teKEFYrkBPM5x23HZ9C3EPX2Kp/mJ4itKKkcyKNp5mfey7gfap8r2XzZ6UYGNr+g
         VK7p5SztLXhFhC2NP9Q+Yrydb7xfbvqKvF3q1NpqGzFM028x3IboFS1lev+15XrWJAJ7
         qEz17QdLjNeuLG/leuONX+HDMcyNStO9CdqhDcvJJISYtGimnCn2wTPEwAfYqUXkK+Pc
         1Cqlkz8jZXhiNpi1SwECeis+FcJH+XL5i9fqOFGGNSsdFYuGtsxGgL8orWQvWftPWpSB
         twgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=IV38BDhbyazmRnMadcaCmVSMFIlIOiNTDhCTGiUXPrQ=;
        b=u69Bo6FZnK+3g7FzbEaLQUMMpfnYcs9vyKzdMT3Jd9pzQ8XVhfGDrrNthMlwD+0UZp
         1CGshTiYChwO9acQT+Ea1c4sbnGvF6iUw2ILm9iz5MdTXAftTDfZq4WWvYJAGJplaNAk
         nvpuIEUu5QHWQyrjSDdolTr7vWCGjqwSti2FJo5oqkOf6+v6i1ThCL4k3VF+T53MBMNT
         bitqqciERXd4b47eAZ+af7u/HJHxp5B5ssFvLSrMmPI9K1eNaEuYK2NDDO7Fs+tI801L
         gyyFnBA/nPeTTgPXd8P5EYi5h200Z2kKyfCgoabQW5OVr2KCEEpL1sAvOWnUN92wqN5H
         EatQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i12si409901plt.3.2021.01.22.06.11.43
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 06:11:43 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 1483E1595;
	Fri, 22 Jan 2021 06:11:43 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 6970D3F66E;
	Fri, 22 Jan 2021 06:11:41 -0800 (PST)
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
Subject: [PATCH v7 4/4] arm64: mte: Enable async tag check fault
Date: Fri, 22 Jan 2021 14:11:25 +0000
Message-Id: <20210122141125.36166-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210122141125.36166-1-vincenzo.frascino@arm.com>
References: <20210122141125.36166-1-vincenzo.frascino@arm.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122141125.36166-5-vincenzo.frascino%40arm.com.
