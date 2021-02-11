Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB744SWAQMGQETOD65RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id BCAF6318EB9
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 16:34:28 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id c63sf4553343qkd.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 07:34:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613057664; cv=pass;
        d=google.com; s=arc-20160816;
        b=LFUjTlRFdAOfv7lXARNwE58fmumGiYdRTojX6PPP+wqoyTszTJ+y5iFP4VzlwYTJAD
         hpI4FV1Ei8DgxRK9EXiELSu77Pge10+YV+2rJMv0ZgIFomtF/7QB0HVWbvsMCk+2Q3M3
         LHDfoIxlgeriD780m3OCW0BIfF8ysOvC6C9KD22XB68KqQQ+/bsXIQPgqaO8CQiowYzu
         1PQONgJ1da5TsN0X2gszSRzDI0+CtxKc+DA2o2bE+HO3/xocmfsPaLli7hd6fV5RXTNQ
         CiAkedyvXEpxJlX4FfAJ0U+gj6yp5O7sA9FnXW4mhfsX2qmUi3WK8HcMRSEq4aazrq/Y
         t1kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kdY0JtFCuHxLI7i5lJwbmMZzs80hgtOEDd0kbjq1+hA=;
        b=F/7MwMj/LxEdPNMHR3FLOpsA8Mz5WGAApBXqSdLAdHHzcRlWZ9QoP3QSlqiCVjRi7V
         ZB87JmIAsatCUuSkIiQacEoxAQ9ATOPNBZ7uD1cjDJtdCw2Px+YC+KZgxfdhGXRJTStB
         X77C/EJprAeFYq0hVg+qV7ZG5/6FV4zAyJPYpUDuqa60UzXM3glBo1SenZ07+4VJ74ma
         KJdNlgokdhEVSjr8CJq8FaFyiGlgtHjC6Rpz90SVgJIqD4pwMeYGsWvsgCz/3n0+7hkT
         8K+3+2/ZVyFxF1obgUNpWTav2nuQs78JHNfRBZ9RM3E34Rnv/eV6ivjUUdWjT4Ew/8WQ
         2JcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kdY0JtFCuHxLI7i5lJwbmMZzs80hgtOEDd0kbjq1+hA=;
        b=p2jOql8pN3/RLxwh3CfH0Et5/4J602g6r21Zvs0ujCY5q9THELTSLDQ1eJC95AgC35
         v7ittc1SWC659Kay1Yzc4C+fuVMcyU8D/Vwbl9HoYagMztbZ0CoixCJGL+A1h+kcdeLd
         i6MhejqinHcj1hb/huu17ZzPQa6Cg2RJEuc8IwPK+m4mLvYIJK2NIkRS/r2AdA0kID98
         STuAb4hrSFH8cfqKvg3kkBHpvpPChOQojexehTvA8/RtFZoRvuSPDwkNaOqL+IR7cvST
         Mx62w8Oc5vgVwnx807vNVDyf6PzlB3q2QnUAucE3yBXHJ/9Vud46Lq/vTgLxadVbFrhA
         kPvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kdY0JtFCuHxLI7i5lJwbmMZzs80hgtOEDd0kbjq1+hA=;
        b=jUtPFq6jdplpDZK/ja3sqr9L3frHnKpIkZdfWSd0PMW6ewr6c5irjt6R+XXfqBDzfH
         d+GvqHtF/HNlBy5lPXy/nDxYLDSvg62dC54k6NOMfHSEVPwqRzwZreawpOMwAxVSjbc9
         MHAfQHs9QOvcOYpkzDBI3YkSFOpx3+f0un0i11flOB7kLocbLbcQYU+/XujyOCtkIyd4
         kgg5oxWYYA99ayM8qoONYc2CJWCLDf1zCYme+SvPyNH3f5FxtNIYMgyUCHu3wciCAf7v
         KYpl6UBNw4rPGg2xbybMq58Gih02LKiTWE2ckh0RWI9HUrTRPKAhkFGju1Z4kIa8mLC0
         7K7A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5335/FnfrwQHw/D6iOujmB2g6URaMxBy4mWe5CwEmHxBURCkcvFU
	Vmmk3SL/YCqxifEt9sDl0CA=
X-Google-Smtp-Source: ABdhPJz5SGF9QMdKn24TSGpZZafHAcFJzD5froIjrIcyz8vUL8gc42lX/HMexjYV6mQJ8EpX4K1AIw==
X-Received: by 2002:a0c:f1d1:: with SMTP id u17mr6607312qvl.26.1613057663628;
        Thu, 11 Feb 2021 07:34:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:d2:: with SMTP id p18ls2153313qtw.3.gmail; Thu, 11
 Feb 2021 07:34:23 -0800 (PST)
X-Received: by 2002:ac8:5e89:: with SMTP id r9mr8096723qtx.338.1613057663208;
        Thu, 11 Feb 2021 07:34:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613057663; cv=none;
        d=google.com; s=arc-20160816;
        b=bZtzPsv9Re+trRmEGlnehL9Vj6cHT4Yju4myEliOD+FzkAkFsSDxQXGVnH+WD431kg
         JZgNG/6yRtekangXtTLA7+cW8SIJDleU4rn+yrcVtBAngJeYcEuAU4o98mubb02SNj97
         WpNU9xZ8n7QMoz/8FoliTfDz8mRh4m2ueQnqqPmwmchqpAImiVnTjFbRNGRTBFA4Xtb3
         9HklxNOn6Dveu3zuQC9XI9+OkqOg0iABDpg9s8z1fssBlMfn5+imUvay2ME3Gn5IqxYQ
         aW97Ailmsi/cJMGcAN3AQE2uMoRJ3QV+wgCqnDs4J7rgHBZNQ0yNcDwkywQ8oHK22lDr
         rCGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=GB8cWGtGu2is0ziTNsZwaooo01hwy1iLg25j8Ci8pY8=;
        b=GwxqxSkLHhtiIOxTshvbOEpIzETQsT4iaAhLJb8HnMmE8VCdYyr/9lRZr0xwu+PZzf
         4U4+pvaPxDdFEAC3EaTlVAqv73FZbK4GvEUU/iZ04rTCW8ta2Ox5/5DY9rhOHD2n8dq9
         3jbQaxdUvl6OB8dI+6+6SlZVfTOq1osZxxkxwJpFqRUr0b+RS3b2rbto3/0uZQztkehz
         +7ZOw7GpQcjD872ls6HoPjSLiOAZQoSIIx9LTUF1A2QEpfCB12jWaPG8tuJgHLMzm2W3
         GzynjUmFSXaojtZuDYyM0g/5fBvMEPPKpu3ztWUFasfdmhdugw8CqHFW4M4k+eIyiLT6
         oGKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id h123si340267qkf.6.2021.02.11.07.34.23
        for <kasan-dev@googlegroups.com>;
        Thu, 11 Feb 2021 07:34:23 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 3025A142F;
	Thu, 11 Feb 2021 07:34:17 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 3B7943F73D;
	Thu, 11 Feb 2021 07:34:15 -0800 (PST)
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
Subject: [PATCH v13 5/7] arm64: mte: Enable async tag check fault
Date: Thu, 11 Feb 2021 15:33:51 +0000
Message-Id: <20210211153353.29094-6-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210211153353.29094-1-vincenzo.frascino@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
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
index 65ecb86dd886..f5aa5bea6dfe 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -155,6 +155,29 @@ bool mte_report_once(void)
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
@@ -220,6 +243,19 @@ void mte_thread_switch(struct task_struct *next)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210211153353.29094-6-vincenzo.frascino%40arm.com.
