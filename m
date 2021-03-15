Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBLN6XWBAMGQETWAAYHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 13D0E33B3B7
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 14:20:46 +0100 (CET)
Received: by mail-vk1-xa3a.google.com with SMTP id e188sf9058548vke.18
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 06:20:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615814445; cv=pass;
        d=google.com; s=arc-20160816;
        b=BRkgtulHgbpkcLJEwwtAcBjK2LMjH9vvBWYWna78+bk3r/n/Flo2QNNLvKwvif6kUc
         ZxJ5Go74NJLTZbwSlfzkA50PeZ4ujt8KB7+673CTe+9drpouD3PWS675e+iLNJHBIUhY
         5DUAr09um+BPsI6rF5kRniQ8YGBb5kf3vJY3cH0y6k7EEL3eA+4wrRWbH/ObUysKYzGK
         XSiKAJwHsrNdJwJd44N53iwBwM02rRyMXpxpCttNO1yUfUr+vu1q2CMGJ+fpqSo4WLyZ
         DvoKJ6sICr/13izp5k8K+6TjAboUcWMz4LbhyjMxYjtab0rTRcf94KM49LdKDRkYDbVK
         LL0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=dEfBMpKSQfsOYVgpvJWfYFU0IjM4UIRzXmgbH+KsM/I=;
        b=eiQd3CtNsvMl1eQp43H5JulK+uTd9U1h3NkimFVYFGwcLNS5nG27b98W+1V1EFMLha
         s4UacjOuY9a5AR8fdHmMbORv10JfYM0BdGHOjD/qjBkODaFAVpVWWQf8RGIwwgotOffr
         gsh1gTkD1hqPH0fPx77jfQ9GvWLoptCNBXeLo52Wisxai+I1Bur2evIU0JdVnOb6E/A3
         lMTvoCZTDQ52gHuZPRYAETacOOFuSSlGUWshuh4+aTqEZogSqwnW2AB4ZQ63kUFoqikq
         cthnSPC3GUrRXp01eO5rXeJYaI8h5p9VKl5jYROYxiUI6WInDEYUp8lV1RNnEKu3rLcK
         ayNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dEfBMpKSQfsOYVgpvJWfYFU0IjM4UIRzXmgbH+KsM/I=;
        b=jwKu4/zzkgr8zKDfQRB+8ClZZ2RV3vsUrfuKW3jDYvVk8DhCw38aPTsZLj8EU+G9n6
         aaQdu11KUgFniLMuG1Of0+bZg36J2c8LGiUTX9i3lzV9lts/IBQArpff1wegGCoikjDG
         trNBNtepURFXRL195+RtyONxC3MHImcFPTMLpaU5yrnYgCRVdDHp234I5iKdP5gXVpC7
         8ejdn8B0YsUZEKFCmdZZ+H0vopu96x2ANL9vS7wLguj8gXMqPpiCinfTxtaLv+r1IbFO
         kmwCPlcpNtnD9MZf7A8RFZrtenRayY26au7pUC6s0tiANlDvegVZaqPAUW6eGmr8CX5C
         fBQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dEfBMpKSQfsOYVgpvJWfYFU0IjM4UIRzXmgbH+KsM/I=;
        b=dQtDDN74cLQm+dhybPqSiQ4F9yzUy7zO3WLmoXc81Ivw0JpcAAG/F9GGaK6OCO75O9
         sy+g8W+6QDibmScb/g+7ivTZt/oFt6RymswxyU0g6wzuSZ5KrS/Tfrhz6TrJC9pLRjNg
         rQVg4TV+GQVw7VeIKIdsmnoASXQaIXlQCZUoN8BUOTm3owvoPGrNPZj64j+ahnwLvZ1p
         U1q08zGaNCGYYDMrD+XkyQu7LUHK18TYafrOb3aROlxLGwfV1zBeNy1cLTXG3SznLwSm
         daAhZbbecWcAD6/1Mm8sC0bq5naO4VUSsgFfFv2WcZheXwnjOJYuXwYELN6rCvalwBz5
         dCQg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531f9JmAUFN5Sgl996+AXzZokVcail1NZGj1slqTP4EL2i7nPf3s
	b15PrlAFy5t1V0/XOt8k4XI=
X-Google-Smtp-Source: ABdhPJwgFc5/Ib7CaxXsoLr7gtkXWrtVVN4TNm5VYnu5KZJqeePWIORgbqSYseUcA6ec2VxoShqttA==
X-Received: by 2002:a05:6102:3102:: with SMTP id e2mr4393534vsh.50.1615814445098;
        Mon, 15 Mar 2021 06:20:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:64d0:: with SMTP id j16ls1258213uaq.11.gmail; Mon, 15
 Mar 2021 06:20:44 -0700 (PDT)
X-Received: by 2002:ab0:382:: with SMTP id 2mr5059503uau.46.1615814444547;
        Mon, 15 Mar 2021 06:20:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615814444; cv=none;
        d=google.com; s=arc-20160816;
        b=XMHMRO5yLP7QcqnDIMMUpUAaEB+5xtegceChkBiw7pTGru6Wr1CAo93FjivFyDMfbC
         whC50dFyFaP9Yah8/QDcDnyU4NSjAU2MnpHqtSsCPrQism6W+cSMDNj4AwB3gFFhZ4ww
         I5yHghzbdZKkd8zSnql/jH6do/DRQ5pizftgUo5bgDM2/wMideHJ9UoqHXYbxr+2hwR4
         UMyXcehLugXokziByNRZjvJZdYVqS8lBMVL3gNBgfGt5Lafx5TQl7Aojz9LvK58uiQBt
         UEu05xKzY1yjJSn52e89clgpS3FDiJ7kKQuX3vO6O+azvpCYDdNxgXHcqSkCuPWieGuT
         Tofw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=BtH/In7gmOnmvlQG4rG12QQzP/SAoJCfp5n0CJPcjy8=;
        b=DOSgnLvqWCmsajTCuHnbMbEeRw9AivfjMogqiNvG8qwOTvMQN3p6Ao/3Utxw6annwX
         XioNp9z6VW07ppkX7uyvq3q+Vmc9OmfhcQ5dI6+g/OQpgsnwA2gV0tbofYp+ga6OnVA2
         3NrV9aX9XCVBIxIYTAdRAgcTF2GXvwZru+UbVj8L6ltF14edofcJl1paIAGFLEfGbCIN
         omjFN3ZeX6bcbjk2DnBoiT4cBJP8YqwbB0QMnYjAPtKRH4c0mQ4xGglvRizx2USiQG69
         K45Hl38y26MgX2g4Z1QiJPIngR193SxS5kqGom1k/A1OAw9zJvOv+qMiKDPe98qjzDkR
         sX7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i8si777775vko.4.2021.03.15.06.20.44
        for <kasan-dev@googlegroups.com>;
        Mon, 15 Mar 2021 06:20:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id EC4FA1424;
	Mon, 15 Mar 2021 06:20:43 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 16A163F792;
	Mon, 15 Mar 2021 06:20:41 -0700 (PDT)
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
Subject: [PATCH v16 7/9] arm64: mte: Enable async tag check fault
Date: Mon, 15 Mar 2021 13:20:17 +0000
Message-Id: <20210315132019.33202-8-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210315132019.33202-1-vincenzo.frascino@arm.com>
References: <20210315132019.33202-1-vincenzo.frascino@arm.com>
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
Tested-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/mte.h     | 29 +++++++++++++++++++++++++
 arch/arm64/kernel/entry-common.c |  6 ++++++
 arch/arm64/kernel/mte.c          | 36 ++++++++++++++++++++++++++++++++
 3 files changed, 71 insertions(+)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 8603c6636a7d..9a929620ca5d 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -98,11 +98,40 @@ static inline bool system_uses_mte_async_mode(void)
 {
 	return static_branch_unlikely(&mte_async_mode);
 }
+
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
 #else
 static inline bool system_uses_mte_async_mode(void)
 {
 	return false;
 }
+static inline void mte_check_tfsr_el1(void)
+{
+}
+static inline void mte_check_tfsr_entry(void)
+{
+}
+static inline void mte_check_tfsr_exit(void)
+{
+}
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 #endif /* __ASSEMBLY__ */
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
index 50f0724c8d8f..b6336fbe4c14 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -162,6 +162,29 @@ bool mte_report_once(void)
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
@@ -227,6 +250,19 @@ void mte_thread_switch(struct task_struct *next)
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
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210315132019.33202-8-vincenzo.frascino%40arm.com.
