Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB64HQ2AAMGQEBF2AYAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id B81A32F7827
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 13:01:00 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id z7sf4026044oic.21
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 04:01:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610712059; cv=pass;
        d=google.com; s=arc-20160816;
        b=0QNjVyZGTlM+3swuRUq7S4QE/J7Gmb3FGNGVwUFfFK62enZBSo7rLjdVZJKsRm1Okw
         KHXUHTOEXCc9sEFQHXJezUDexVlKouYGCh6spPixA/ohCrrJg/eo56VaAccSoql9v2ii
         HZS0U1X080WdjWyNIzzbj8WItYRkFIsSG6fhstrkV20MxY5cPuUIpzuJ1hplZFJsXWWm
         rFAaRplU2SOHRsx8azLR1FEagbseOmhlx7CIzWiAIbEchidLaKTQ7CHQnf9ZctXRGmGs
         S+5FUxvF3O0zxPHWjS0Mg1fhlsaF2G/OaNvwTV8Q7jyJDq1fIi91KsvTjT/I7rzDzXGw
         DLiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Dh0kMQE/khThme0Dn64m5x/SdWDf0EN3FKTwcS9vm1M=;
        b=aaysuP/PaRGcIDalRwasZV6GTfPUPmNEJPnefk1M9R4UWpNOeM6Fop10k2ESEUnA79
         cVWu+PcVSz79ywc4yFuDgBiLhwQ/3xnc1fLYRsryxClqWRgqxU4lF25XsYv8yPw1o5N0
         4nc5uS2E50PldKlTidC1gUml/3GRf2QlHSw10/+qayA6ZYbKSkRaUZihoZASKGObS4nk
         Wu6SVjZhLfmdjJ6o5/9hbQRen4wZLi6sWF3i+LeITIEoTTDroR+Q2TlfsqDChK19kE/O
         6LK2URC6fb2SMNJlN9qYz5EoMn4VoZKTK3zOw20a1ZyBM7zp1ZQ8s27Auj3944vgzCfl
         9WNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dh0kMQE/khThme0Dn64m5x/SdWDf0EN3FKTwcS9vm1M=;
        b=huIPvHgmx1xEn5ew3EhXlEwhmRS3XAs3+XIEbCJBeRqTn6O4Jn99P+Gd7fYRerpVCD
         XA2GfiA+NcrOSvKWXkOrUd7kpTN4aeVT/3xgxF5XWL2nrkzCaGO0TwArccsdGnR0h9IT
         KFz1cWJhGQ7AGMShMEc28GTSMuYN0rzqpxy1/9y6EwIxnDWDpEhODJNuO4D9X7+du72Z
         pJ6WmPAvDZGXgxpkrKR4SI6Jc53BJ7yO61zxLliYAfmhJcwLoEe4fDdBa06mfsfFZDak
         BQckuK1a9IN6ZpnWCCuurX30hON8IJjo4Uj0E9jhl38+8W6fkh4fltMAVySVzV4gvZNP
         /XCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dh0kMQE/khThme0Dn64m5x/SdWDf0EN3FKTwcS9vm1M=;
        b=f//f3n43B+KzHsJCIWtYV3+LZaFJF4Q9jaOmehRSIG0GWUTgrxmAiTejDgq07pC0l9
         BHd5lAUqLzkEMOiDFqKB5aedbd62slT5Jp6OtgLxMBQg3pyLQO8Dke2FAYj4biib0pVz
         pkALrXv5HJAytl87sfE/g88sUFdMCy8bGlhqRo8q3PtFMxNr1nTYjM4tRmkvbpi4yjs9
         uRpU6SRGrOLLl1fj/zS2SLwGhfweK6PC7pMGmuVVIgQViNKYtR9ujIfd0vdj4e87QhJQ
         zy76/BlXbOkCZcL5kTy3ePuL362WACE+3t5Zo4pufw27wW3tr7GyvUM2pKBhuaGy3nl6
         JBQg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5308iKTpoCugcoRsE86bCuU1lThulcT8iAd8TDg9Vs0C6O6+km8U
	TRil/vVRGAADWhCpk/rl16Y=
X-Google-Smtp-Source: ABdhPJzZ9PObtK8i7NNanNMycdriSGaqNMB9MOy5vyUbIZZ+aLtvaXffUj395xjuBX16nn/APXglBA==
X-Received: by 2002:a4a:520f:: with SMTP id d15mr7815854oob.29.1610712059702;
        Fri, 15 Jan 2021 04:00:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:758a:: with SMTP id q132ls2111136oic.4.gmail; Fri, 15
 Jan 2021 04:00:59 -0800 (PST)
X-Received: by 2002:aca:b06:: with SMTP id 6mr5311171oil.74.1610712059337;
        Fri, 15 Jan 2021 04:00:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610712059; cv=none;
        d=google.com; s=arc-20160816;
        b=vT2YkWl96Rx8EPFeHrlQEhlEl1dAMC6IeEhPOBWNdCFuFAJHJ+lh+eFEvFriecoH3r
         uvKn2MbixYAGmi9bkhi9yv36ZOBSsFifaLbKLqd4d+8TAmQmT/KnwfZxjjHuU5A27flS
         Ic8Wj6G50FUscV8bhaOO+AioZ01fr2jIrXI5NC2rw6O9Zrdbz+1hc5W0f7X3X3OfqdEZ
         qSrJC64ZtH/W6xvpBSWfsrLXI0AlSFCKi76CGvLRkRr8v7BrP9v67QBeTIDfcZ7UlX9j
         taMgrRb8nsNFtg2lRVA6xqeGlNOu96iR2C3EaX5P7PK1EHZeZEAwIdNveQmcj7yB+QKz
         yyDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=FtoRJ9ugxxizqPBWVAlKyS6Hv+99Nbu8Z/uFbTooh4g=;
        b=O3Kp3TI7nbA5lHEbTk+oPJSzYPY6Y4kMIjzPMHdaq/JWyrrZHz7U2oyCK2VKYOURbr
         0Alm+cSx2WGEAIAoej3L4X4bmEM0CfBafoOpWr5XLTP8ppYm0SZVAr9gVSmGcePhMpGz
         HL0okgfyUW7KCYQIX6Sv/lWS2eW4F9R87SN+2M2pe2/T7CEWFcROPUVPq0YYuYrgyK+Y
         jXDFHzJkCz4x82sfsKW7tw3xeQc06cVl4lHqDobskswzZhjiRI4kyRIlLtDol44mu73V
         vi6SS8QEVpHzVs0IuzzNIH9UlnGQVJVNzzpZSmMc5dkYhyGBziraqpkw1b4ti/FzONnB
         Culg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id r8si685807otp.4.2021.01.15.04.00.59
        for <kasan-dev@googlegroups.com>;
        Fri, 15 Jan 2021 04:00:59 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 17C8C12FC;
	Fri, 15 Jan 2021 04:00:59 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 6D3303F70D;
	Fri, 15 Jan 2021 04:00:57 -0800 (PST)
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
Subject: [PATCH v3 3/4] arm64: mte: Enable async tag check fault
Date: Fri, 15 Jan 2021 12:00:42 +0000
Message-Id: <20210115120043.50023-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210115120043.50023-1-vincenzo.frascino@arm.com>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
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

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/mte.h     | 21 +++++++++++++++++++
 arch/arm64/kernel/entry-common.c | 11 ++++++++++
 arch/arm64/kernel/mte.c          | 35 ++++++++++++++++++++++++++++++++
 3 files changed, 67 insertions(+)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index d02aff9f493d..1a715963d909 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -92,5 +92,26 @@ static inline void mte_assign_mem_tag_range(void *addr, size_t size)
 
 #endif /* CONFIG_ARM64_MTE */
 
+#ifdef CONFIG_KASAN_HW_TAGS
+void mte_check_tfsr_el1_no_sync(void);
+static inline void mte_check_tfsr_el1(void)
+{
+	mte_check_tfsr_el1_no_sync();
+	/*
+	 * The asynchronous faults are synch'ed automatically with
+	 * TFSR_EL1 on kernel entry but for exit an explicit dsb()
+	 * is required.
+	 */
+	dsb(ish);
+}
+#else
+static inline void mte_check_tfsr_el1_no_sync(void)
+{
+}
+static inline void mte_check_tfsr_el1(void)
+{
+}
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 #endif /* __ASSEMBLY__ */
 #endif /* __ASM_MTE_H  */
diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
index 5346953e4382..c6dfe8a525b0 100644
--- a/arch/arm64/kernel/entry-common.c
+++ b/arch/arm64/kernel/entry-common.c
@@ -37,6 +37,8 @@ static void noinstr enter_from_kernel_mode(struct pt_regs *regs)
 	lockdep_hardirqs_off(CALLER_ADDR0);
 	rcu_irq_enter_check_tick();
 	trace_hardirqs_off_finish();
+
+	mte_check_tfsr_el1_no_sync();
 }
 
 /*
@@ -47,6 +49,13 @@ static void noinstr exit_to_kernel_mode(struct pt_regs *regs)
 {
 	lockdep_assert_irqs_disabled();
 
+	/*
+	 * The dsb() in mte_check_tfsr_el1() is required to relate
+	 * the asynchronous tag check fault to the context in which
+	 * it happens.
+	 */
+	mte_check_tfsr_el1();
+
 	if (interrupts_enabled(regs)) {
 		if (regs->exit_rcu) {
 			trace_hardirqs_on_prepare();
@@ -243,6 +252,8 @@ asmlinkage void noinstr enter_from_user_mode(void)
 
 asmlinkage void noinstr exit_to_user_mode(void)
 {
+	mte_check_tfsr_el1();
+
 	trace_hardirqs_on_prepare();
 	lockdep_hardirqs_on_prepare(CALLER_ADDR0);
 	user_enter_irqoff();
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index df7a1ae26d7c..6cb92e9d6ad1 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -180,6 +180,32 @@ void mte_enable_kernel(enum kasan_hw_tags_mode mode)
 	isb();
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
+void mte_check_tfsr_el1_no_sync(void)
+{
+	u64 tfsr_el1;
+
+	if (!system_supports_mte())
+		return;
+
+	tfsr_el1 = read_sysreg_s(SYS_TFSR_EL1);
+
+	/*
+	 * The kernel should never hit the condition TF0 == 1
+	 * at this point because for the futex code we set
+	 * PSTATE.TCO.
+	 */
+	WARN_ON(tfsr_el1 & SYS_TFSR_EL1_TF0);
+
+	if (tfsr_el1 & SYS_TFSR_EL1_TF1) {
+		write_sysreg_s(0, SYS_TFSR_EL1);
+		isb();
+
+		pr_err("MTE: Asynchronous tag exception detected!");
+	}
+}
+#endif
+
 static void update_sctlr_el1_tcf0(u64 tcf0)
 {
 	/* ISB required for the kernel uaccess routines */
@@ -245,6 +271,15 @@ void mte_thread_switch(struct task_struct *next)
 	/* avoid expensive SCTLR_EL1 accesses if no change */
 	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
 		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
+
+	/*
+	 * Check if an async tag exception occurred at EL1.
+	 *
+	 * Note: On the context switch path we rely on the dsb() present
+	 * in __switch_to() to guarantee that the indirect writes to TFSR_EL1
+	 * are synchronized before this point.
+	 */
+	mte_check_tfsr_el1_no_sync();
 }
 
 void mte_suspend_exit(void)
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210115120043.50023-4-vincenzo.frascino%40arm.com.
