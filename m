Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBR62QWAQMGQE7G7XKYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DFBD313A2F
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 17:56:41 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id v16sf11184612pgl.23
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 08:56:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612803399; cv=pass;
        d=google.com; s=arc-20160816;
        b=ve+XhiafeP8KS1eD7n657FZ5XyLdc99EkQaSrXjNX8Khd+34WSLubljU/f/ZeqQz+q
         MbY+5B2iNu5Pew9iI04iHrLQze7d/UUETPNA60wmKEf8n0Bb8/U1Tw+JQH24b4O8nC1S
         GGZYfoqLqMOn7ioinpwb4+14paJsoxwjNFe6HCVESLT8Yq6fV01++n/Jxu7THA+wXzhP
         7wHKgy/JxZG4eq/G3Bd+N3Oaf6fv3UxnWl7Z6wH4/sWlNYOWCtA6yj491BJEuz0OkYZl
         Nsw2CtdJLKLVVmo37VTsLfF8nS3aPYyt8+7QZ5ZUdjGkHZuH4y60fbU1KaUk/F1kTfyL
         lufA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=g5UVzlGaPWdgyc2KarW9Sw/zy5DrO3IUXk1/hF0M+E4=;
        b=sw6uDFNyNX+riXubOucrxZDNf+2/782U7AZBWlZVR3bCmIa6iMeDJ4yygVHphpIeH1
         NPuMuzBVg2UBIj3X3xQ8el/nEoIM20P5tUVARRveRYW0yjUjTj282eY8jB3gw7TbAR54
         NPgl4plc4sNhn7opj2L9iJgOXuVJDYxVpkSqkQej0bswFhTy7fFt1ZxQE1e9G3ndRlXl
         RyhzYVBPF3/c5BIGh6AD9OFvBqEqhacfmGmChNjacpTVsTqrV0ZpKmEduIiqSLRboLOU
         m6kcKck3RJ51KyWKaJyVo+Adt5HeG/Dt5PKj6RHBxyyA/BUlwS31VAZ+ihJ4M2oQ9OmT
         2IaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g5UVzlGaPWdgyc2KarW9Sw/zy5DrO3IUXk1/hF0M+E4=;
        b=kvvLsWXlYMBrXf9smFw+KPC6XkdxQadOWiUjlyfxObkI8BleQSNAHlgSiYuW64/ko6
         aNq1CphiROBhiwbjWOUjaa+5NFglJDs6xxUxAm9slry3DmFB2ALOAmM9cstp1Htb5X6D
         RULbSdDCHRwdnCCizitlsAZCpwseG/wNFr6dYoV9y6PVNE8Ha4LYx3q5UhmlPBLJ55ph
         tMsiUmSR5LCOaiKfKRb8VGf+RS7nk0+cI4D9PFZyn365SU1zNEr3iS5m6wDWWbDL0rOH
         LFyagMhHnuAR2op/uyUF8gffijxBagj4H/escHCJJmiz+a9vI2At4Y2lupOKeES/glGX
         hgOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g5UVzlGaPWdgyc2KarW9Sw/zy5DrO3IUXk1/hF0M+E4=;
        b=lXZELA8ohhDget5Fy4mpPvTPZGXvmPgywqGsTyHcy4pHGLx03OOcMiB5fuET/vktoR
         f3gQ+QItHCuIK7+0xdy28SyCU8Pe4AIGjTpTYefkl5DAiHXgUvtYGLLLL8y10D7rvDdO
         dQLOPvl4hHgNNezyvFVA6fpfpKhYbYGMJb7CobKO5UcD4B689MiN2jAiWA93f7whWrYJ
         jXsy25LyKjCrY00/wJz1X9SFewEoBh9IZBJYDm9NjipmA/pMPfwElSnPhWcUdb/Mun+t
         vkYcXJKQcvnPibU2vpesTgYkmMEU5+n+aBtXkrOA5TxAgPEslWXcNdeOfhmZX2fD0MPt
         UvBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533WRkWoVI/4CdhVrEjF8vWI3lwIOGjxNieBRc/thLMNvEQa2wSi
	9apdU5IBw36Nzt7/2rhm+L0=
X-Google-Smtp-Source: ABdhPJxcpqCo3RFKgWG12LXmx9/6VTVx20RmeJqqkzUgUBrEGc8lRpLV+zXllE4tQMSFKpRJ2+jnyw==
X-Received: by 2002:a62:3852:0:b029:1da:7238:1cb1 with SMTP id f79-20020a6238520000b02901da72381cb1mr11274789pfa.11.1612803399605;
        Mon, 08 Feb 2021 08:56:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4c89:: with SMTP id m9ls3766057pgt.8.gmail; Mon, 08 Feb
 2021 08:56:39 -0800 (PST)
X-Received: by 2002:a65:4788:: with SMTP id e8mr17470909pgs.72.1612803398915;
        Mon, 08 Feb 2021 08:56:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612803398; cv=none;
        d=google.com; s=arc-20160816;
        b=0LVm7uKsUueFG37xVg0lSRN2AOaOWjNUKniQYoIFqucgItaZ0d2rmlkqwAoWL3gQTU
         uIFSbbVbG9U9bKdD/2w9D7f/UOGxUMzLwq53SNXbKwPM/jSMKFVsQoatkK+0QYHVholx
         m/LAqthrlqT1pM0adrNoxDD1nJQN68gudWd8qkzw/qYnLuggBz9aS0nntwXMfrUFhtnW
         tLXvxYb4Zlfc0117J7TwZFzUb0dPDzH0EHYjL3fxG2ASgHviWPUsxahKfCvQtkP/Jw2D
         pxEytmmHYFBZSC/9+RaOPEdq3BPWv9QANOwlTWdIJ5Svp9O4cfR6LLvDLgZpKld7UnZb
         yZjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=mmIeO9LBiszpqRjTxhyfZPatPGyunCykD4hw63s/6A8=;
        b=n+oaey/+GoVXKLxConkNh6YuDNWin/TwSAOD4RQxYsXsNqaCdYnn6SJoD0AJqg0tG/
         7GOH8WJ6Ie693k5dC1rfDMaZ9qYzoKHA/TVXrw0hRwHcWG/DCxAPRJkepGOYFKJ6WdJD
         HvDvDfUe07NhT1EaBwIVbqCu5ypS1f8Egh5IKRaIsoakAwVEPz5/9zkLMO7nNP3wBdq6
         jcX/WMANLMBOWa9auKpaC2CNfch5yLTtbivtW44zGg6VcJYt5o3qeU+5rJeaCruhTWWH
         8/KxU03Hi5K8+LJvoO3zKYM4wvK4HKuF6FVe8mv0sT3GYEJjBIID6++7d0XyCgoOCGsc
         liDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id r142si866907pfr.0.2021.02.08.08.56.38
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Feb 2021 08:56:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 03B4D139F;
	Mon,  8 Feb 2021 08:56:38 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 218AA3F719;
	Mon,  8 Feb 2021 08:56:36 -0800 (PST)
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
Subject: [PATCH v12 5/7] arm64: mte: Enable async tag check fault
Date: Mon,  8 Feb 2021 16:56:15 +0000
Message-Id: <20210208165617.9977-6-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210208165617.9977-1-vincenzo.frascino@arm.com>
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
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
index 60531afc706e..3332aabda466 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -192,6 +192,29 @@ bool mte_report_once(void)
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
@@ -257,6 +280,19 @@ void mte_thread_switch(struct task_struct *next)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210208165617.9977-6-vincenzo.frascino%40arm.com.
