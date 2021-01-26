Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBMN2YCAAMGQETRR53HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 5998D303F27
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 14:46:26 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id r190sf1472835qkf.19
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 05:46:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611668785; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vfn2FXlT92nDUZ2kNTVaPPDDikLZ5l7eajvu4PdfjNjz/ecWiCAyi/9QWHl538jqdT
         VNl/tTEmH7qF3FN/cQWcXgWqs7z7ZhrQ/fher+JMvJQCtlY9y2RczNdcjx2AId9pULOl
         NxmA2Fa15cbNCerRoHkLVjp6khMl3WdXmuxoe4q58X5TGjyB1/rGcENEo3ik0sFlJBj9
         m0pKTCSveON2q2/V+seW7LV2pW2Vc4MWYe0Dks4MK8BbfonlIMeX+m4eQYu5h345P8eD
         QbAIe/CF6Azf14MEKgULQCjjH39H7ctYF8ACemDZ5gqOTCzRURBP+4manbRjt8OnYYfd
         QmLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kjPjVpdU+tDKvJ491BYwhC1Ko3AlweMdi8dDB9WgKeQ=;
        b=Asb4gh8nh3IosYAHY2XDrFsZRVu5x85SduGfXpSb/H6LJY2EIChJ43ttislNAOOBvH
         57U0YCM3FexsCtWwHyDjYYRwI80+fNOd8k4jOLJPd1bZv80kX4PkSs6Tvt1Y2i1/14B/
         90G5tWBnInqkTud1eX0fh5ZrL31eX2Eag34Frhb7X3VoiOWHg9uyAA7Bw+NVFJ55n27C
         ddbGmLMNHXpIc9cmmKpzCB2FejhXJh724nGYUT2rZqU5nycoTaxSi2iceLz5rRlrrJUb
         VYfo2uj60PkOeKDOovzscSdw29LyoxahUHvH6fUSQpZ7TkNI3naoWbspYKeRa9c35pHF
         JH6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kjPjVpdU+tDKvJ491BYwhC1Ko3AlweMdi8dDB9WgKeQ=;
        b=FQrxqh18ELJipNhuXkr3Rro2lmlVLP+K8FJpfUv7jg8rtXWkbAI9xYZEvEGHxzzBdu
         0QOGLTJ978gJZslJdXtncvS1Kh19QvBGXeaubrP2Q5TnOZjFIkqUhA9V77T4BnQV55Vi
         8HWM/Wcc9p+Pw6VzlyD5aK6b6EdHPtb74KDV5LMMrj0cgnODEvLq5oB7ezDxFTjvxdlr
         +oFZ0+4oqRbMhYbTfU0gKcWadOSVdt8TnIA7kFB7tbERhfjvVlWrFJI6ln4ZnnL5CSA8
         dOCmSnLhXlIV8NWyy5eevP9hz/FUppLKV6XSIHGDK/A2utUQVaLo+57tfIzoy/BXoPYZ
         RnyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kjPjVpdU+tDKvJ491BYwhC1Ko3AlweMdi8dDB9WgKeQ=;
        b=EoGQfrjk4iKV3lJk9AFxIRwX0EMYRWTv9sy3h5vYLtnZNLfRfga1PzLTCjNhGxGFZJ
         MWe3OczlJ7CnE5qfiKT20f2F7B08GMf54gjkHQwMg2DNwp5ryArcgAW5e+nTCKdfCfsr
         drkiDDCMDAlWQy1R0K2GeAGSdXy+rye/QLTJVk+KObp3rEwGeATi4aV96kfKnAv+cekf
         pYFVIYkraVaAL3gw8PalgPrD/bGPUZCkTWtkQzZZjezYNCOyRdzPajFj+kmuh+fIVj+A
         wEiagTgrZ2MRRWuY3IjLVamdlgQkFJMAhbSvkez5aJxsPl0tkP+Qlex72eogklosv/Ay
         N72Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533kKZuK4RDO7zQ5q3f9bzzmggOcFbnKI5kfxAewrcXSfODvFEdq
	Ii0nNk2pS/yXbiPe9rVIAsY=
X-Google-Smtp-Source: ABdhPJyPONXNiBrfq0zcufor8RkVjmF/qJVb7e7HWffr0DIXe+1+lFl4e0MHA1G4dxsK9GGCYiOHgQ==
X-Received: by 2002:aed:31c2:: with SMTP id 60mr4947258qth.218.1611668785418;
        Tue, 26 Jan 2021 05:46:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1c91:: with SMTP id f17ls6397575qtl.9.gmail; Tue, 26 Jan
 2021 05:46:25 -0800 (PST)
X-Received: by 2002:ac8:5cd0:: with SMTP id s16mr4983535qta.309.1611668784931;
        Tue, 26 Jan 2021 05:46:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611668784; cv=none;
        d=google.com; s=arc-20160816;
        b=gwUxt8OhTCSmfXB7T7BHFGkUDklgsClaGt+Br669S9dcR8Cd75aY1RsKhsppWVZtZQ
         BlXZ3EBFXrh3DxKTq5PQ3KvBMKJ/QhLD+yIFvQaLRxmZ4UyV4tGiAuSY8IrbNO69nBje
         3X/fYAoQ7DAuu+5wsFuTYXTBPBTElYitEUhPLLqJGQkjGPJ+IARYjNScATGo0y9TUsq2
         nEGU96C1ECpahyL3OTJ1f+bK9kEtTTVKl1XTJon0ECnCMBcbHd7iwKuHa5kW5nwO0jlJ
         5yLV5SXyOnyixGZHeO5n1iH5FqsQN6Sr0WB5aBxb0RuEKq0hbaKrau1xGBHoSjyDWagb
         +ytA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=8GEY5x2mRfKMFo4MiYnbonG9ay76RYjGKWUnyeBgCqA=;
        b=PXXI5++2RD5plL5w8JnEwd6bqgGpp9DkzX3OLk0bXlqME0um/FYsuOpvv6lMFQXxvq
         GfJmdJa4fr1AMIsm9YbU1PUfhV/+1FqaK+2wNaJgzVxLx1Cdjkb8px0EMTemmHYDTEUS
         aabqs0WYNu7dZ1N4FracFrx1BAjv/358Y6C6enrd43nKH1Ks6cl/7kWjnJOQQf6GPBjb
         S3FCV5TbuczKQUGSlGeX9kOo3ue6EXMq0GQyW7OiB2CtsM/UhvJKMMuTjYlxPVzsnpT6
         127n+ARxFLMss/BJLcE8CYoMKk2Ql4+Vybi7DOaimLyslDFMLTB6ie00PffrjwXw2KJ4
         0KEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id o33si440178qtc.5.2021.01.26.05.46.24
        for <kasan-dev@googlegroups.com>;
        Tue, 26 Jan 2021 05:46:24 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 7F79813A1;
	Tue, 26 Jan 2021 05:46:24 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id B88CE3F68F;
	Tue, 26 Jan 2021 05:46:22 -0800 (PST)
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
Subject: [PATCH v9 4/4] arm64: mte: Enable async tag check fault
Date: Tue, 26 Jan 2021 13:46:03 +0000
Message-Id: <20210126134603.49759-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210126134603.49759-1-vincenzo.frascino@arm.com>
References: <20210126134603.49759-1-vincenzo.frascino@arm.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210126134603.49759-5-vincenzo.frascino%40arm.com.
