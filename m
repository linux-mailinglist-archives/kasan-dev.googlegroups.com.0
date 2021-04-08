Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBLVKXSBQMGQEPGLXTVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DB89358743
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 16:37:36 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id p24sf1345696pff.8
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 07:37:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617892654; cv=pass;
        d=google.com; s=arc-20160816;
        b=NCjXSwIj71QOBLsSQSr6Uq9mPjvgwB9+jzMTRAkhBx4kobKr9+83rOSuqmqRtWRfLY
         4QhEdYc4yVgQP5hOs13RwTRK6JBypQwxwyVQFgx2SQMpm7AqBQ5G+IxIK1ZJNrYUq4VQ
         v90ml4wEdPU9ByjgGXhe2VDLY5aYqB+bfqBFl729wfCy7stUbkeWl6dU/LE93UxoPIhK
         TOHlXwfRFaOItQWn5t//vTSt/zt5Ozx6gw45ZlkFXa93xJPemom+aIUaivyMBqSRqLeD
         VOtL3ekrimkFvbqt3qN1bUWsoQauWHYHRAsGlIm30kLNcVE20Q94l/DCp+j/8am3anO8
         Uilg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=OSNo51feCuFj92ld7hFh9G+Odf9OMcQBr11Hm9W085I=;
        b=ZBK4pXCp6sy+uAo1Vb81it/qazHv8YiOHdpwxv0s0cnrSekwNJjGZNI0hfZvx0Yc1W
         zR3e2EWGosoYowvsb4K4h/6Mv20VfY/beTQC47UNu+y7gGUHJ1kYHNf8t/2H0XHt7MBD
         KQ9sMu9mepL9VUpgU+/MEB+Awyph04OmJV3nXZXr5u5YEW88q63w5srf6bcEo7TqZ5sy
         G3aaddOz2SY/wHx/MFcRYw4WOskvmamGBWrQmdZkMeQQpcG31Tqk4r+He0cvFx221+0G
         cVzL4XkrS4+CmOk3Bs1o0zNlQhZbT2J6ZQnOXRjcRHJ7mlexrS80GFhxU7joX8nG9sq6
         3izw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OSNo51feCuFj92ld7hFh9G+Odf9OMcQBr11Hm9W085I=;
        b=Lq7lcYhK/PKwBpSGZV/02FYXCrb9H4yP/Y0NGcQcZ4lCyn9pCvMWs2jcl9FJPHS0Jb
         eT6RKzS+WT5+SK/afl0jw/KOXtYyu/TwF+8sgAIZlkL6eejEQWlj6LpQXT0PhCKw7ErC
         DHcw5/8m1e9S9NQlRiH5hQnhK6gu1onvjrIi6f9xEyNwK3wk7EMkfnie9E+KUlsFrhuy
         ub+BEqna4kpmhQeZKqDemygDCYTtd9ScETJSZhqTvPwfXh2ULo6QvdJF/wQujK2OukLa
         LSqqJLlS2UeG8AYh9Wf4U284fHKASnFpnbxdzpFuRA5ENsVqgO3wzCHo+UOUXkFQxpZ7
         JfkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OSNo51feCuFj92ld7hFh9G+Odf9OMcQBr11Hm9W085I=;
        b=kdY60a57q3qqbCDLIVTT0cq6ALdHaydPsWSE9Bm6prd5HfUttyGVBWzYfTH7jCg85W
         Ek7YhxF5sstfOzY38YinXy8YLBLPa4orACn3CqdyJ0Mlcp/9biotElhKF38Q3RRHWqm9
         U1Z2QX+tY076YykyjvW/1dTI1VnOHwkw462COdei1oKkavrki381BQ0n7kbBZys4tUjS
         QrQH2Ty833xG4nZQ2yMH3bZR43EYrT2503hcejUfWYuKBRp+4ouEAxxqaBg9y6pz7BFj
         UKe5L5maHV7DN5h4fQPZtWUKrdyRpMXfDkhwqpK1R87T+WkrZBeRjkcXYT3nPGix928C
         cMhw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531VY+A0mvk7FJdX7JA13QpV/obgTwCpmTrIdKeCbvmrg84GWCUd
	oVHX5FFt3xCkLijulPFC2/0=
X-Google-Smtp-Source: ABdhPJxwwPvgHHB08MJv9DMsNT4ZKpIn08mpltrl13Zg7ucMEtDyJ7IvcOjF8CEO7T2KS+YhF0fgFw==
X-Received: by 2002:aa7:9190:0:b029:22d:6789:cc83 with SMTP id x16-20020aa791900000b029022d6789cc83mr7884286pfa.9.1617892654564;
        Thu, 08 Apr 2021 07:37:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:547:: with SMTP id 68ls2192807pff.7.gmail; Thu, 08 Apr
 2021 07:37:34 -0700 (PDT)
X-Received: by 2002:a62:e119:0:b029:245:8e0:820 with SMTP id q25-20020a62e1190000b029024508e00820mr2230898pfh.4.1617892654038;
        Thu, 08 Apr 2021 07:37:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617892654; cv=none;
        d=google.com; s=arc-20160816;
        b=JM+Sa9BU29niUM5xPnkUoysaX6jmmkskjgH5Eidk/dIo1EFTJvo1b88d6qhoWGx+c2
         JTeJ3BBP7A3cnvw2sYPNML4/l9dvTVA7Qp0gQrqm6ZVcVfDKKB8q+nNEUiDttLvKXDo2
         9MW6YaowAvLBlCtAWA7I98fRTUy6z5MkAmh1894rwmKLzZYnUNbvG3cahy+F3era+LZy
         gkfazxoe3yCp1UAndAYLPmI+Zv2n/7kg+dmOsfNBAiaAsJKV0JwOJnVXkvFhjN+Lh0+K
         qABQ1EY7iZ3orESRZsOfpBqMV9p2yO4G5szpmt4CJQTtJSBq86hceOTBKlfocODL4ZwD
         NhAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=ygOKIh6vshx9O9riO9+7p96cTNfbt3ai6WSDPefQmrw=;
        b=mACTvjg1wJE1Ucy1dyQeMbRGRsgVT7c9O+iJwu4HNAiISHYEpYHomRAHhXp0DAFqhk
         vaHFmtFWsWx0wUBbWoTFG0Hr/GO7dVDzxU4qNsDdUH1MVHMH6rF/L3UvUvTfC/6QbqJl
         AbbFMLGhiW7YrzN3VDByi0cwdHjeLV8Glyv7pQjbEG8VGeN9C9pyrDBwS21b6SF0jzOU
         HKn3F+B9PpEMv5KsbMamY7xpp81lpRP9cSslCsqIwmeMjHr7MUyd2GFygqNfP+pJkVot
         Ic6tmO+9Qy/csvgGYLLRUlVq4mljY/zFf7sywaXc72wto+IS0HSdCEvDjLE3bbeHXo86
         gOoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j6si463625pjg.0.2021.04.08.07.37.33
        for <kasan-dev@googlegroups.com>;
        Thu, 08 Apr 2021 07:37:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 08229D6E;
	Thu,  8 Apr 2021 07:37:33 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 1F32A3F694;
	Thu,  8 Apr 2021 07:37:32 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>
Subject: [PATCH] arm64: mte: Move MTE TCF0 check in entry-common
Date: Thu,  8 Apr 2021 15:37:23 +0100
Message-Id: <20210408143723.13024-1-vincenzo.frascino@arm.com>
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
race with another CPU doing a set_tsk_thread_flag() and the flag can be
lost in the process.

Move the tcf0 check to enter_from_user_mode() and clear tcf0 in
exit_to_user_mode() to address the problem.

Note: Moving the check in entry-common allows to use set_thread_flag()
which is safe.

Fixes: 637ec831ea4f ("arm64: mte: Handle synchronous and asynchronous
tag check faults")
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Reported-by: Will Deacon <will@kernel.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/mte.h     |  8 ++++++++
 arch/arm64/kernel/entry-common.c |  6 ++++++
 arch/arm64/kernel/entry.S        | 30 ------------------------------
 arch/arm64/kernel/mte.c          | 25 +++++++++++++++++++++++--
 4 files changed, 37 insertions(+), 32 deletions(-)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 9b557a457f24..188f778c6f7b 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -31,6 +31,8 @@ void mte_invalidate_tags(int type, pgoff_t offset);
 void mte_invalidate_tags_area(int type);
 void *mte_allocate_tag_storage(void);
 void mte_free_tag_storage(char *storage);
+void check_mte_async_tcf0(void);
+void clear_mte_async_tcf0(void);
 
 #ifdef CONFIG_ARM64_MTE
 
@@ -83,6 +85,12 @@ static inline int mte_ptrace_copy_tags(struct task_struct *child,
 {
 	return -EIO;
 }
+void check_mte_async_tcf0(void)
+{
+}
+void clear_mte_async_tcf0(void)
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
index a31a0a713c85..fafd74ae5021 100644
--- a/arch/arm64/kernel/entry.S
+++ b/arch/arm64/kernel/entry.S
@@ -147,32 +147,6 @@ alternative_cb_end
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
@@ -243,8 +217,6 @@ alternative_else_nop_endif
 	ldr	x19, [tsk, #TSK_TI_FLAGS]
 	disable_step_tsk x19, x20
 
-	/* Check for asynchronous tag check faults in user space */
-	check_mte_async_tcf x19, x22
 	apply_ssbd 1, x22, x23
 
 	ptrauth_keys_install_kernel tsk, x20, x22, x23
@@ -775,8 +747,6 @@ SYM_CODE_START_LOCAL(ret_to_user)
 	cbnz	x2, work_pending
 finish_ret_to_user:
 	user_enter_irqoff
-	/* Ignore asynchronous tag check faults in the uaccess routines */
-	clear_mte_async_tcf
 	enable_step_tsk x19, x2
 #ifdef CONFIG_GCC_PLUGIN_STACKLEAK
 	bl	stackleak_erase
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index b3c70a612c7a..e759b0eca47e 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -166,14 +166,35 @@ static void set_gcr_el1_excl(u64 excl)
 	 */
 }
 
+void check_mte_async_tcf0(void)
+{
+	/*
+	 * dsb(ish) is not required before the register read
+	 * because the TFSRE0_EL1 is automatically synchronized
+	 * by the hardware on exception entry as SCTLR_EL1.ITFSB
+	 * is set.
+	 */
+	u64 tcf0 = read_sysreg_s(SYS_TFSRE0_EL1);
+
+	if (tcf0 & SYS_TFSR_EL1_TF0)
+		set_thread_flag(TIF_MTE_ASYNC_FAULT);
+
+	write_sysreg_s(0, SYS_TFSRE0_EL1);
+}
+
+void clear_mte_async_tcf0(void)
+{
+	dsb(ish);
+	write_sysreg_s(0, SYS_TFSRE0_EL1);
+}
+
 void flush_mte_state(void)
 {
 	if (!system_supports_mte())
 		return;
 
 	/* clear any pending asynchronous tag fault */
-	dsb(ish);
-	write_sysreg_s(0, SYS_TFSRE0_EL1);
+	clear_mte_async_tcf0();
 	clear_thread_flag(TIF_MTE_ASYNC_FAULT);
 	/* disable tag checking */
 	set_sctlr_el1_tcf0(SCTLR_EL1_TCF0_NONE);
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210408143723.13024-1-vincenzo.frascino%40arm.com.
