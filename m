Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBM4K3X7QKGQERR4C5NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F3C62ED5A6
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Jan 2021 18:30:28 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id l126sf11661866ybl.10
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Jan 2021 09:30:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610040627; cv=pass;
        d=google.com; s=arc-20160816;
        b=DGiSwdjiw4E+HsbL7stMxJfqqJ9/q5IpQ0dMXQ9RZuqsVAHfA+KuB0V+gfIYsYdOBa
         tiMhhxzHlSA2ISXZYOndZdstxsGlFSeZWp/J1GvruDjdKa6cm6kwchANt0U2QxZAH8R5
         72P0J0Z32b9TmiBUgVe07X+7AHWsStGqhkGBW31RkX/OkSXtF6h8IqjQYRBTYLxTB+x6
         2iwZBQ2rq4wMCirDGk9sF9ub86XXMyynfY5Sa8ZJeXaP7+SMryUePC9muHJQs65Z1uCJ
         Kieukb7b+0+LQ5jlIcaZH2BQkUul7gXo4oSWNbRUNgVdJTOXRa8CxDkQ3KVanQlL3abQ
         xCXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vCZK79IhTXJDzN2vK+6aSFKApCGMEFDenuFerVH8UdQ=;
        b=UWEVh7Brl7NdObXj4VRz0TQWGhx2HO5K4iqPPzMuZF5ePB0Y5xG6jMy64dH+rZ4oDs
         QFMb16DDTwxjLy8nUwL4+e4LMtI0P4Q634KY5mBqrzT+tiZ2bSQ86fLY4SdCGzVxAatd
         GUiBckssWXL0Eab/qCPVwbqSgaIO2TlIbehYQMbnnTVs2x5UQlcftvBWgAOYUIfzNy2A
         16jl/y18Z5s/930swyJEwALJ6iq/li+IarNWFB0g1RAZ7aPtzDFfMwsAiaOsmjYARmdH
         sYcnwWRYdfvKgYe747SNq7Op5jeqNra1GjVLzpXSgTC3WkdRjmPEHPRSp5+eb+82Rz8A
         CNmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vCZK79IhTXJDzN2vK+6aSFKApCGMEFDenuFerVH8UdQ=;
        b=aJl5eumNKlrow2nVjMbgoFHH5pZv7E9NQA+z646xRN46URkYv2aEmx6isjiMIOUzZI
         YnlZQoJfmU59rHD3xRLc1LvrRGRH+dRY8QYckBhaVcCZfL+Pbv1Qxcvabz6kf2PBcMNS
         Nnpz3xqSmv6TXK0IwwuKJotPOPrPXLAvRd3oEdTHzGSiP2XR7PMe9RBeLQxJrbJbTXFu
         MISwdMzm0IlrtZdVlvPU0QwliOAeSDNtRNc+t5YNeSHBXW676imOkSbHt6vH5xnepPrc
         LfP8CKNsFCzBJZE74m179/5iPDqoKd0yzxPIRFlJ4I0yx3vDRDtOHeMwBa68kFMl0Z59
         6+tQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vCZK79IhTXJDzN2vK+6aSFKApCGMEFDenuFerVH8UdQ=;
        b=Y3cqls8SM7u8zfNwY+X3Vg1y9PsCCekW4iwqqdPwTOPmhRCt94+GNQSCGF8tIhsSZd
         CMO7Snf7Oa4CIQ1dUaTnEYu/T/YE/tuBkg9ZBohHurKbSpV3vzynMzFNgzKrAshpMTpC
         HI8LitKjEGo9kicowWWj4zShJhz3y0O2TEOwanaf7kLO0FPnTDLW6gXNfYPxVtmxLJ9Y
         CLhlx0EkLAVkDgcE69VyP6b+hmRXEhwfPpyDQL8i84ImeI4lluzVxFEiuK/JaKsVNlVO
         RGAnYso9jh8bujtP7+pECPMF0rWMoT+EPdjzt5bUaUmn5hN+MU4RSw4nG+1BrXWCFROO
         uZUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533OmeltOBBhPCHolJ8dqAwMv1C0Qc0slmzrmD2h4KwEDWpImB0k
	H+AdM/oMg8Pj/fDEgZ7H/CE=
X-Google-Smtp-Source: ABdhPJzN4GSYnKfQ2AvpYhR26kFU1HvX4TThSf7YX8yXdcv0Nw/LcoCEdybJqt6gTs8PzLfGxoXuqg==
X-Received: by 2002:a25:ef47:: with SMTP id w7mr13569715ybm.509.1610040627394;
        Thu, 07 Jan 2021 09:30:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:20e:: with SMTP id 14ls4099633ybc.0.gmail; Thu, 07 Jan
 2021 09:30:26 -0800 (PST)
X-Received: by 2002:a25:d806:: with SMTP id p6mr15092773ybg.68.1610040626918;
        Thu, 07 Jan 2021 09:30:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610040626; cv=none;
        d=google.com; s=arc-20160816;
        b=zloL8mD5HKD8039BgkSSl+D9A0MkNVIb4cb8jvQRO/WVXYfq5MLT9ByZ3Cp5Ll3L1B
         jeH1hJMGz/AWkorWAQOwf+FNpT4Ps00u62k4qLWG1yBRS9bdkG4EI9Sj08LuvfJP6Ocm
         ScdQXiBEf9bSs0hoPDpwJz4ltxXWFXFwRT5DyJaMl3g4e/MW1xYKPOXHL61zwzz5+sll
         8Vx2ZxahP0h2vWcTbT3ma12XIdST/ebUgmYB+GL3G1c8IJiWiQi7tUZEIGSETDyrirWY
         G3DeCMhkfsZiql9qoqvRJ3sezC9KNd4FhafhD7VV/eN/pjpwzKGGN08+YaRGeLpLeiIx
         pTVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=YZ6PdBLiH2yEFHQJC7poVinMXYYqgsiblFLhorRbuUw=;
        b=v517ESlKCK5x584JrhSwSN2RyUqHJrCRNNnXXMqrTT97YhN+rr1ARPP20gvHy4so6E
         4oIQG1FXec/b1TGijQxt3iZa5wa3FCSvhTpLBe/NjtNOT8sm8GE5/18CM+2LHDcSh6Bj
         chA8PM8tzJvc7FphOh7YL0zMRAzDVD3II6GXz3uWyanObKglxpHLqCQmgoMilsPNmTwC
         qZZQkegPdMzJdigbgL6cn5Evix1s/+hv7Md3bHn507qa/oeuTP4xd8mvOh8KhquuThaz
         hvAqJcgMTPLyJK47jawAX8A4hByEaRE0rHB5RbqptH6PwbaPrwEKoA9SfOFM55KYPmDz
         voLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i70si623159ybg.1.2021.01.07.09.30.26
        for <kasan-dev@googlegroups.com>;
        Thu, 07 Jan 2021 09:30:26 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 59D58113E;
	Thu,  7 Jan 2021 09:30:26 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id AA6C83F719;
	Thu,  7 Jan 2021 09:30:24 -0800 (PST)
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
Subject: [PATCH v2 3/4] arm64: mte: Enable async tag check fault
Date: Thu,  7 Jan 2021 17:29:07 +0000
Message-Id: <20210107172908.42686-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210107172908.42686-1-vincenzo.frascino@arm.com>
References: <20210107172908.42686-1-vincenzo.frascino@arm.com>
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
 arch/arm64/include/asm/mte.h     |  4 ++++
 arch/arm64/kernel/entry-common.c |  6 ++++++
 arch/arm64/kernel/mte.c          | 37 ++++++++++++++++++++++++++++++++
 3 files changed, 47 insertions(+)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index d02aff9f493d..a60d3718baae 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -39,6 +39,7 @@ void mte_free_tag_storage(char *storage);
 /* track which pages have valid allocation tags */
 #define PG_mte_tagged	PG_arch_2
 
+void mte_check_tfsr_el1(void);
 void mte_sync_tags(pte_t *ptep, pte_t pte);
 void mte_copy_page_tags(void *kto, const void *kfrom);
 void flush_mte_state(void);
@@ -56,6 +57,9 @@ void mte_assign_mem_tag_range(void *addr, size_t size);
 /* unused if !CONFIG_ARM64_MTE, silence the compiler */
 #define PG_mte_tagged	0
 
+static inline void mte_check_tfsr_el1(void)
+{
+}
 static inline void mte_sync_tags(pte_t *ptep, pte_t pte)
 {
 }
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
index 5d992e16b420..26030f0b79fe 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -185,6 +185,34 @@ void mte_enable_kernel(enum kasan_arg_mode mode)
 	isb();
 }
 
+void mte_check_tfsr_el1(void)
+{
+	u64 tfsr_el1;
+
+	if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS))
+		return;
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
@@ -250,6 +278,15 @@ void mte_thread_switch(struct task_struct *next)
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
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210107172908.42686-4-vincenzo.frascino%40arm.com.
