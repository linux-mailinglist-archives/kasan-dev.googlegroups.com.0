Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB7GK237QKGQERTEGVHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 292532EBD5B
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jan 2021 12:56:46 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id t12sf1638714ilq.11
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jan 2021 03:56:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609934205; cv=pass;
        d=google.com; s=arc-20160816;
        b=ANCuVuRzn+ZvzNUbWqEvQFWp6jWb4XRKxgf+RR3JhL3xjKMY5z7m3g1Alfe8DBJnEG
         JnNjujD9Grbfgo11Po6kJttlJryQ4GyBYXX6ig/Y2M3tsD/LxNpxx5tnsOkuso+D9eEO
         T0G/btUpFEw611kcDbenyC2lFp9blojFe/8DOLWSJQ7sNagWHBOlCUDwM1BkwdC0fyoq
         yCcv4RL/ZsgHqAAL4efbCYK/pRY8p2jmrRBpxFDsV3H0sGXbBgsWPNaSi+vX9WNDw5yB
         IFlQs+3Bc3hPS25hqv00u6DjVDlC0/N/hj+7ikg2JoD5HvWClOm0wAsYh3nI8KejA6GD
         Cfcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ScMsAwGU16VNH3hGSFstQuPFADWqZqgThtWnWCKXR2s=;
        b=rybNTaC9d3ntkN7DVIKN0+hWhBbcWTWv3dAT2Sy0dfAqyl2CnzJpEJduEFLdSJRZJu
         rdtJiNQ51z4ZAg07owFvhjpipypmw3cu7pwTioQwjS4LBOeoO7kM7asGYUbUN9kg0Hag
         1U9Cm4EKACFNQKuVyY/WraViX1/n8dflHc4sttaV+vWrZem1XOkvjC32aNHBqsG1DFtG
         hbJtH6jT9zPWD0WCcGs9hycM8eNyu3nZc3KbxSW3IfIuIunAM0nSbROgG2tJpP+Lf/rY
         5KfuOpip7b6r/DpCDhLWP+2gdqB5/2fihwJWZWWLMfGBegc9MipUQVsu9g9H+ZUYozyf
         H8fA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ScMsAwGU16VNH3hGSFstQuPFADWqZqgThtWnWCKXR2s=;
        b=iXjzdgi17Xndh2gUBsxd9RiiZOSXmDxKYXbAMd2M3BjmyqC2rpsPudjjoqvvYEdOAp
         vng6RfPA/JWdoR7tIyo3CYTkI97Vyra1UW/IYj2a6OwD9Tq5t5TZW3W/2PyyRPUciPhB
         nXzId/y006EIfH9z7n19l5d1XqHEM9U6e1Lm6zbIAntAwpIVh1LFFo9Ul7Fb8uRPm5wA
         6EbubVeK49tAAQQv/PIFgvi8ybavSzTj9A8XyJQHuC+YDwKxP0CQ/AqF+L8sjhMICpO/
         nY6xf30pvmrQapsWdOeQ5ClJF5LHm7MbGJC9FSIad6CzsKfOKy7uF8oeErBv9fDj0Dwc
         jMIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ScMsAwGU16VNH3hGSFstQuPFADWqZqgThtWnWCKXR2s=;
        b=eciu54IMUEuDlu5I7uCI+/FWIm+RrcQ4qVV2wmBm1s6ODyiRePPnL5ZJOC2LgjxTcN
         +btgL/JWO5ZUdKSbuMuJUm7YAASAamiCTwwGrHl0OInBcdaWEGljEowJGRO8vNqmpnLZ
         /cyvLazbdGUhuniaYcOrfy/aBFmnsf1nC9bXRAj0i9BWmOA7YHZCGKk0UDRsu0FO+sdt
         yc+zmonvu75rzb4H3aBmvnGMMZJTrvdd2Ujx8rs0QHlRRN0XE6XqS3LKZPpHPhMvOF2t
         NRWrtHGr3+AymRl0j2ANglpmzCkT2WzIeSp3YNLxOnQqmTEup0/JEvkxtG1hP1l0VhGS
         S0kA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533e44bPQs1ZgMTENhf61/fzTfpx3rR3x5vsgGblP5yQe5H5glKx
	eI05qeE4FqvBw2JIs3evlzo=
X-Google-Smtp-Source: ABdhPJxwNYeQYwyoB6KAqoe3kKVbECnpOW0OypnFaSXTjibYd6yhqG6RRMp3FFpq4y2Rr05ZHT7zGg==
X-Received: by 2002:a92:9eda:: with SMTP id s87mr3886397ilk.85.1609934205025;
        Wed, 06 Jan 2021 03:56:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:d83:: with SMTP id i3ls753348ilj.1.gmail; Wed, 06
 Jan 2021 03:56:44 -0800 (PST)
X-Received: by 2002:a92:cd8c:: with SMTP id r12mr3708695ilb.221.1609934204728;
        Wed, 06 Jan 2021 03:56:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609934204; cv=none;
        d=google.com; s=arc-20160816;
        b=qKJHsa0wCrWdGkzFzpBK2QwCQrzKrzaYeuiihb7Q/F0QxE+1t3tnHDjQ9BZb+ce1rn
         ZfJNhM9NGFeVjs2r7hui7tclh4PpMOuH0OGqTENtXbFM6A2Ug0dgCXeZySBWCg0NtieS
         dS6O+7z4CDcNQBeDRBxsKlTFkWzDWYMyaXiOExtTdZ3WGX3UWYIbnBUiQtUMP76nznlZ
         2yrfoxRMmomphDyHd4IUNI/HQlf5b1ARCoyJNiXrvpAko2tKm/IE3qhb2/4Iud5AgZaf
         EvkVlVJReb+RRE44IFxb7Ho/qKMQWpFt0dBuKAttAp36uYsOTu0DRg6TMSHI5hnF5gzV
         sRaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=7ueT0iAqR5orIIu8gGDytXs8gFMdeaUpNkXvm3VydNA=;
        b=QwY1xfKOEfv0MRElv8Auxv4yKeQHkCuggnK+heyrQRVaS7+3aUoBvsAGurDO0m/Ft+
         mmLcoOlA8WmTHQDUV7G5YiDk2QbdqXW2D3rjWUmknKHkT5Idesg7cGul/MFopU+Yo+Oj
         N2jylYeNyyF2EzRKPu2s/9Q3jCdnYuSfHZWaFSjewU/bBuJfWhz5LhVzo8BWSIwqZ105
         C3i2usbXPCClCMuTXZR0UHklzeepTYSPEKLc5VTsyj9NHVgUEc0EE95GslQ+pEJJrSnB
         0UJ/fqjpRrKDJ03m5MZHiNfdzx2804YvdzvwbxWqhn0KrFoi39vyfDd5qcZHycgMckUX
         HJEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id t69si165991ill.3.2021.01.06.03.56.44
        for <kasan-dev@googlegroups.com>;
        Wed, 06 Jan 2021 03:56:44 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 7116011D4;
	Wed,  6 Jan 2021 03:56:44 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id C62B43F70D;
	Wed,  6 Jan 2021 03:56:42 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 3/4] arm64: mte: Enable async tag check fault
Date: Wed,  6 Jan 2021 11:55:18 +0000
Message-Id: <20210106115519.32222-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.29.2
In-Reply-To: <20210106115519.32222-1-vincenzo.frascino@arm.com>
References: <20210106115519.32222-1-vincenzo.frascino@arm.com>
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
Cc: Will Deacon <will.deacon@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/mte.h     |  1 +
 arch/arm64/kernel/entry-common.c |  6 ++++++
 arch/arm64/kernel/mte.c          | 34 ++++++++++++++++++++++++++++++++
 3 files changed, 41 insertions(+)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index d02aff9f493d..c757ff756e09 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -33,6 +33,7 @@ void mte_invalidate_tags(int type, pgoff_t offset);
 void mte_invalidate_tags_area(int type);
 void *mte_allocate_tag_storage(void);
 void mte_free_tag_storage(char *storage);
+void mte_check_tfsr_el1(void);
 
 #ifdef CONFIG_ARM64_MTE
 
diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
index 5346953e4382..74b020ce72d7 100644
--- a/arch/arm64/kernel/entry-common.c
+++ b/arch/arm64/kernel/entry-common.c
@@ -37,6 +37,8 @@ static void noinstr enter_from_kernel_mode(struct pt_regs *regs)
 	lockdep_hardirqs_off(CALLER_ADDR0);
 	rcu_irq_enter_check_tick();
 	trace_hardirqs_off_finish();
+
+	mte_check_tfsr_el1();
 }
 
 /*
@@ -47,6 +49,8 @@ static void noinstr exit_to_kernel_mode(struct pt_regs *regs)
 {
 	lockdep_assert_irqs_disabled();
 
+	mte_check_tfsr_el1();
+
 	if (interrupts_enabled(regs)) {
 		if (regs->exit_rcu) {
 			trace_hardirqs_on_prepare();
@@ -243,6 +247,8 @@ asmlinkage void noinstr enter_from_user_mode(void)
 
 asmlinkage void noinstr exit_to_user_mode(void)
 {
+	mte_check_tfsr_el1();
+
 	trace_hardirqs_on_prepare();
 	lockdep_hardirqs_on_prepare(CALLER_ADDR0);
 	user_enter_irqoff();
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 5d992e16b420..7082fc287635 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -185,6 +185,31 @@ void mte_enable_kernel(enum kasan_arg_mode mode)
 	isb();
 }
 
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
+NOKPROBE_SYMBOL(mte_check_tfsr_el1);
+
 static void update_sctlr_el1_tcf0(u64 tcf0)
 {
 	/* ISB required for the kernel uaccess routines */
@@ -250,6 +275,15 @@ void mte_thread_switch(struct task_struct *next)
 	/* avoid expensive SCTLR_EL1 accesses if no change */
 	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
 		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
+
+	/*
+	 * Check if an async tag exception occurred at EL1.
+	 *
+	 * Note: On the context switch patch we rely on the dsb() present
+	 * in __switch_to() to guaranty that the indirect writes to TFSR_EL1
+	 * are synchronized before this point.
+	 */
+	mte_check_tfsr_el1();
 }
 
 void mte_suspend_exit(void)
-- 
2.29.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210106115519.32222-4-vincenzo.frascino%40arm.com.
