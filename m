Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBDFLYGBQMGQEME5R4JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 80AC0359FBE
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Apr 2021 15:24:29 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id a16sf3093714qtw.1
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Apr 2021 06:24:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617974668; cv=pass;
        d=google.com; s=arc-20160816;
        b=rNkQMPPo7IIZlYUZHbKcNjFnI/y7rn4zgDGQeNAy/ziF+9ObkLDcq0SAByxQ0Xm4LV
         ku3CwRDQPD5yGjeKAMlqVtY9LBaUi7+RIAz0YA8oBKC42UviDHI3hbqlahRWqLXinE8K
         uVfX7IhehekKxZIRwX5t3NGbKwSPnWIFQ4mQFG6ml5GaAD5lwIPWxlIdwMd9XCqFaNyN
         w3OtoTVXXoP2a2ZrY2pzmdksYQPfe2VP1+E2ZJ22hF7twwt0rLQuF+7xSEvN59tLakDA
         /wldAT6089BocATw1807Gl78y6Y/NFXHhXKZ9culTUA7rsl0DP2vPMLiZfgeBKqYqmNA
         W0MA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=HOipSIN4YyrNOp0J+QzCpBgUwpHJxXQ1U+yUntzL08Y=;
        b=L8dVo7YBcAEMOLz51UOLxjxxlob5sG6rmmMCIlN8RFezyBffkExXvcQW6xRVuUlFkT
         8zuyORJmUyON/sIXte1ZthgqRjSrVvF8q9csYt5ZG5XG3AUd7g+F0AXoExlijrv7LtKA
         DHZDRwTMZnmGrPIrqdfYoppqQzlRfaEaYayqMUtVuXDvCcCu7UQ1agvTu9FtC8pNhpyB
         qRQkf2bloR6bdcgwkb1IuBWpIG/TvzAwBtrI8tA6XHdh8jc+UJWo7NQSUzUO6FWU47HR
         Lxva2RsGmvCeR64z2vELblDys2u3Vq8Kn7GZK6Wdtr/yTfPAD4vins6l/y8LJ03MpJAD
         c0iQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HOipSIN4YyrNOp0J+QzCpBgUwpHJxXQ1U+yUntzL08Y=;
        b=kKEZaCeNf1sEpduZOcUVSoIeexhc9dUd6FwHpxiKs98t+7ehTdkc3auWpgZEEVxHrh
         UBasm847Qc6ezRFUXIbyaaN8kDknccwuDAEJe+vkGxwc2LHjfaaCjuGmTrCnDmyOK4Q2
         yjOpnMd11eIuHf3XR2uUo/PpsusphcRWqS3Vc2BBm8ztIpCTY2sfUCr4aDlSP/gKcxp+
         nG8jqJzkQcldl9LDkwsLtHMfNeRWwbgSyxLQXx7YUO2hFJAhU/KQtiaD/6isHuTIUTnh
         5tHjJO4nlsGP/iwPRfOxXoyAf7c5gbqtl59bZ8uP8ws5eh3H9sZJyhAUHjkwGBxJDlSy
         HwzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HOipSIN4YyrNOp0J+QzCpBgUwpHJxXQ1U+yUntzL08Y=;
        b=nWfFZYCOkR7pYybSW0Je2JRM7V2RfdTTeK7WoRrBQK1e/nGR1scL6k/wVnX0Bq7q87
         66fTKYv4Xpaw2hjU9hD7EDNahub1caZUCrg+COWIPUNQGL7WUrBHRAzJASKmbxcOux5d
         rRORkPh1AMANfWq9ay6fHXR9BTBV8V4yxYDKHY1XVgVK5d106mlEcD4kRZqSabverNW0
         mi9eypLrYF9jNIirF9F9Nhm0MAmuonZ68cPytAkNpXaToyuvMHHialADZzOq9lDNGnPa
         1/zlW2e8BWyegxMsgQMsnplkJ8OkkhD+okH8ymWY+HR6d77w5MY8aIrfePM0+T16aVHs
         H7CQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533tjMwwbnwiSjsrKojUPUYiBGw8vmIOSB1s20oahidlDJpHByMc
	l9he7M+IQKS3PEGNpbP9riM=
X-Google-Smtp-Source: ABdhPJwZy0Sl/Ca7+bF04BoefsJaswn8+v1+VdXsTOUI4z9NMjOUlhiEI56MfgTcorsB4R6Zh3FZUw==
X-Received: by 2002:ac8:6d17:: with SMTP id o23mr3831743qtt.275.1617974668486;
        Fri, 09 Apr 2021 06:24:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:fc09:: with SMTP id z9ls2561631qvo.4.gmail; Fri, 09 Apr
 2021 06:24:28 -0700 (PDT)
X-Received: by 2002:a05:6214:d65:: with SMTP id 5mr14335364qvs.56.1617974668066;
        Fri, 09 Apr 2021 06:24:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617974668; cv=none;
        d=google.com; s=arc-20160816;
        b=or/QU2ycJ3kIv5beX6x18++iNGpBn3e2WFf6AswEHI8CbIgiMklxC4DDtY4GX3rCDd
         5OL+A5G8LQKh4nt4+bgCBWx8DQr7TaYbg7NyQhl50BR8Lx7CHnBA7FGrjkxVH5a6oCmA
         oSv2TIGit9e/iE1Z9niYeIlLETu3N0jhK0inOC3MX4hqfqWBgahrOeOC3C7TPBwxyU31
         b42Dv4iqWZANH62oKzDIvZ2yPE7JUUBCAx8MjO4Npdfmt6WOlCDWElx/46HiuJPI2zxd
         EfTEoI+ooYGfcy10okkEzbSecX0blifjQHjVgdfcuKUVNh0ZSSNY2X5Q291q5TNvx9+h
         uYlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=NluZiwv49NXqZER+0T6Haj9/RQ114oeVnbMR0z5Jpis=;
        b=UCr8U/zWMp3lrYAN/rWfRhvW1gwesOizHlfNzIepktZCsjsmHNRWy/guwx/Wc3Z+xP
         HAgkWEa9UcankNkhvpPeQmeTcF0vyGFLjoLxl1v4WmqsG6Ofy7D5j7jegxikjh8NofYP
         pi1VS8gJ7HXUHuJr33NOz+K/tQM0pzcndhK+5BZPFIhJvgXW/lXIryJ1RPuVdidcfKhv
         aAWmslt5/A73CKpcsnQUSZlTHYhmJ5p+tamfsHvu6ErRl9eYnbBfguu7UucFf4Hd3Hcn
         uwX+s0oVo9YISQFLvkOEyC9bhE3bo1z2eY/bGg9iGF1MnSOU9jI5JbhWCYeS8kHZNrcN
         veOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b201si201683qkg.6.2021.04.09.06.24.27
        for <kasan-dev@googlegroups.com>;
        Fri, 09 Apr 2021 06:24:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 31B231FB;
	Fri,  9 Apr 2021 06:24:27 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2F5283F694;
	Fri,  9 Apr 2021 06:24:26 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	stable@vger.kernel.org
Subject: [PATCH v3] arm64: mte: Move MTE TCF0 check in entry-common
Date: Fri,  9 Apr 2021 14:24:19 +0100
Message-Id: <20210409132419.29965-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.2
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

The check_mte_async_tcf macro sets the TIF flag non-atomically. This can
race with another CPU doing a set_tsk_thread_flag() and all the other flags
can be lost in the process.

Move the tcf0 check to enter_from_user_mode() and clear tcf0 in
exit_to_user_mode() to address the problem.

Note: Moving the check in entry-common allows to use set_thread_flag()
which is safe.

Fixes: 637ec831ea4f ("arm64: mte: Handle synchronous and asynchronous tag check faults")
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: stable@vger.kernel.org
Reported-by: Will Deacon <will@kernel.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/mte.h     |  9 +++++++++
 arch/arm64/kernel/entry-common.c |  6 ++++++
 arch/arm64/kernel/entry.S        | 34 --------------------------------
 arch/arm64/kernel/mte.c          | 33 +++++++++++++++++++++++++++++--
 4 files changed, 46 insertions(+), 36 deletions(-)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 9b557a457f24..c7ab681a95c3 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -49,6 +49,9 @@ int mte_ptrace_copy_tags(struct task_struct *child, long request,
 
 void mte_assign_mem_tag_range(void *addr, size_t size);
 
+void noinstr check_mte_async_tcf0(void);
+void noinstr clear_mte_async_tcf0(void);
+
 #else /* CONFIG_ARM64_MTE */
 
 /* unused if !CONFIG_ARM64_MTE, silence the compiler */
@@ -83,6 +86,12 @@ static inline int mte_ptrace_copy_tags(struct task_struct *child,
 {
 	return -EIO;
 }
+static inline void check_mte_async_tcf0(void)
+{
+}
+static inline void clear_mte_async_tcf0(void)
+{
+}
 
 static inline void mte_assign_mem_tag_range(void *addr, size_t size)
 {
diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
index 9d3588450473..837d3624a1d5 100644
--- a/arch/arm64/kernel/entry-common.c
+++ b/arch/arm64/kernel/entry-common.c
@@ -289,10 +289,16 @@ asmlinkage void noinstr enter_from_user_mode(void)
 	CT_WARN_ON(ct_state() != CONTEXT_USER);
 	user_exit_irqoff();
 	trace_hardirqs_off_finish();
+
+	/* Check for asynchronous tag check faults in user space */
+	check_mte_async_tcf0();
 }
 
 asmlinkage void noinstr exit_to_user_mode(void)
 {
+	/* Ignore asynchronous tag check faults in the uaccess routines */
+	clear_mte_async_tcf0();
+
 	trace_hardirqs_on_prepare();
 	lockdep_hardirqs_on_prepare(CALLER_ADDR0);
 	user_enter_irqoff();
diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
index a31a0a713c85..fb57df0d453f 100644
--- a/arch/arm64/kernel/entry.S
+++ b/arch/arm64/kernel/entry.S
@@ -34,15 +34,11 @@
  * user and kernel mode.
  */
 	.macro user_exit_irqoff
-#if defined(CONFIG_CONTEXT_TRACKING) || defined(CONFIG_TRACE_IRQFLAGS)
 	bl	enter_from_user_mode
-#endif
 	.endm
 
 	.macro user_enter_irqoff
-#if defined(CONFIG_CONTEXT_TRACKING) || defined(CONFIG_TRACE_IRQFLAGS)
 	bl	exit_to_user_mode
-#endif
 	.endm
 
 	.macro	clear_gp_regs
@@ -147,32 +143,6 @@ alternative_cb_end
 .L__asm_ssbd_skip\@:
 	.endm
 
-	/* Check for MTE asynchronous tag check faults */
-	.macro check_mte_async_tcf, flgs, tmp
-#ifdef CONFIG_ARM64_MTE
-alternative_if_not ARM64_MTE
-	b	1f
-alternative_else_nop_endif
-	mrs_s	\tmp, SYS_TFSRE0_EL1
-	tbz	\tmp, #SYS_TFSR_EL1_TF0_SHIFT, 1f
-	/* Asynchronous TCF occurred for TTBR0 access, set the TI flag */
-	orr	\flgs, \flgs, #_TIF_MTE_ASYNC_FAULT
-	str	\flgs, [tsk, #TSK_TI_FLAGS]
-	msr_s	SYS_TFSRE0_EL1, xzr
-1:
-#endif
-	.endm
-
-	/* Clear the MTE asynchronous tag check faults */
-	.macro clear_mte_async_tcf
-#ifdef CONFIG_ARM64_MTE
-alternative_if ARM64_MTE
-	dsb	ish
-	msr_s	SYS_TFSRE0_EL1, xzr
-alternative_else_nop_endif
-#endif
-	.endm
-
 	.macro mte_set_gcr, tmp, tmp2
 #ifdef CONFIG_ARM64_MTE
 	/*
@@ -243,8 +213,6 @@ alternative_else_nop_endif
 	ldr	x19, [tsk, #TSK_TI_FLAGS]
 	disable_step_tsk x19, x20
 
-	/* Check for asynchronous tag check faults in user space */
-	check_mte_async_tcf x19, x22
 	apply_ssbd 1, x22, x23
 
 	ptrauth_keys_install_kernel tsk, x20, x22, x23
@@ -775,8 +743,6 @@ SYM_CODE_START_LOCAL(ret_to_user)
 	cbnz	x2, work_pending
 finish_ret_to_user:
 	user_enter_irqoff
-	/* Ignore asynchronous tag check faults in the uaccess routines */
-	clear_mte_async_tcf
 	enable_step_tsk x19, x2
 #ifdef CONFIG_GCC_PLUGIN_STACKLEAK
 	bl	stackleak_erase
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index b3c70a612c7a..84a942c25870 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -166,14 +166,43 @@ static void set_gcr_el1_excl(u64 excl)
 	 */
 }
 
-void flush_mte_state(void)
+void noinstr check_mte_async_tcf0(void)
+{
+	u64 tcf0;
+
+	if (!system_supports_mte())
+		return;
+
+	/*
+	 * dsb(ish) is not required before the register read
+	 * because the TFSRE0_EL1 is automatically synchronized
+	 * by the hardware on exception entry as SCTLR_EL1.ITFSB
+	 * is set.
+	 */
+	tcf0 = read_sysreg_s(SYS_TFSRE0_EL1);
+
+	if (tcf0 & SYS_TFSR_EL1_TF0)
+		set_thread_flag(TIF_MTE_ASYNC_FAULT);
+
+	write_sysreg_s(0, SYS_TFSRE0_EL1);
+}
+
+void noinstr clear_mte_async_tcf0(void)
 {
 	if (!system_supports_mte())
 		return;
 
-	/* clear any pending asynchronous tag fault */
 	dsb(ish);
 	write_sysreg_s(0, SYS_TFSRE0_EL1);
+}
+
+void flush_mte_state(void)
+{
+	if (!system_supports_mte())
+		return;
+
+	/* clear any pending asynchronous tag fault */
+	clear_mte_async_tcf0();
 	clear_thread_flag(TIF_MTE_ASYNC_FAULT);
 	/* disable tag checking */
 	set_sctlr_el1_tcf0(SCTLR_EL1_TCF0_NONE);
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210409132419.29965-1-vincenzo.frascino%40arm.com.
