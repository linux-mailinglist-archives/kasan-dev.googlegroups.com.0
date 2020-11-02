Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGG4QD6QKGQECXKPYJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 461D42A2EF9
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:04:41 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id s8sf8431524qvv.18
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:04:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333080; cv=pass;
        d=google.com; s=arc-20160816;
        b=0v3IOx3NGZHq7W7tHkyve6LlD7h8/IzEjT3qmmxS9vVKORRdihbYtqI46mDD+V39cc
         ViDk8HuIKxBk9w31slVs0EAWej1BxbxFy5uilVTQ3/YtEvrVJz4EvT2Iua6Xng+gSauh
         0lUngdkKKBzn+pi+NkiqaieDRxu6KfADKRTZiXXbfmg5tnXWMa1h3+QfTfzk24x88TbN
         ootPZT0L8fXkNC48/kbmzVA5jL8VJns9tUWNF25ytdM9AmHhJMb3cBr9qMq+U5Wsrerd
         53zT7Tk9cuc588CZpnCSaf+lAf2ZJmMneh+JlpIch1OHY+QiRqNYDc4nVa/Q6auGtFxP
         R/6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=bWV7RTdHZG/hf7seSeVZVagJ5A1LPE7lO1KegvERvCE=;
        b=Sy6N9C8j+XdpOvkundqs5d7T8b87lkLPtmETPnWs36olWVUdAu6f/Oyfs6caM2H+oc
         hdReH2IPFhAjo2FGtE5ZRszOAGfFW658aHvXTVjRJK1P84c+TKaoR7pVPfA4m4xK1hH1
         2Io12QaliCO6YcbYIcblzFs/t3HQoTnGFCl2R5t8GZ0+QWDpDMbPjSEVqso4WHqLlx9j
         XfFKo67j+Qcsq2mMJ5d/NqSOrVykMg6l8SMnEE6h7i8JiaJtAw3n0Utq4hG1FYPARitT
         r4J1MpdVpFRsRgOrapt8h8K6R2zFHa34yH1G1hT4Pgw3nyiUPE5U3nmxYKwDiMBEKwXX
         kscg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VBijlmKw;
       spf=pass (google.com: domain of 3fi6gxwokcfuxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Fi6gXwoKCfUXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bWV7RTdHZG/hf7seSeVZVagJ5A1LPE7lO1KegvERvCE=;
        b=PB/7UyB3EZDzZmwidz7Iz87fkYs+N/tYABEZL1CZMwCsy0v2dTdU3CDm7r2g7iYqdk
         NdCI5oGP2236gdilXsmFmc3HYxWHomsL6rfLsDwZbUvsg0XLxDeoL+9qoOQnX9KS2BNy
         cYjY3PvX/P8mAB6QTelFndOv1f3VcRFg/FQ0jgoYG3J0kq/4GCO+tcGF7HygQYYNcxMm
         NJB8IxMRau0GFCSU3k8K4a53LyuZUMcjov3stPyRgLY4ErzZjBIt7nhfyP71Ehd7SwlX
         p3Ou82k7JAx6xX7wHdRz269Umv8cFlVZlhwDUrENkl4qCG7t1yrGUkK2AgsQ1jIKLEug
         4LOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bWV7RTdHZG/hf7seSeVZVagJ5A1LPE7lO1KegvERvCE=;
        b=FX6NCyAXekuaJ1JbWCeQtc4Hy53TmNRqH+7yX9CJ3GpgXDxWGftkCZP+VrJ/HrXxYO
         Zv5HXpEUoRDb6fUaha1735cD7syHAvn7sswU4QuYmEx93+dSnwvsSL9jwMellkYSoAep
         H50VXPU3awpc+Q1VbIDNe19/uUwVT9PslcB10LTnyEGHC3gyrPzv9RtaeDBdjSmnm5hp
         gA2iYA4H0CBmYqbb0RlSMVyP21U7w7TjefJir3o/QlphhSTG2JYbwUhozLH3Zxwo8tXJ
         FdqSh9aJKiIlmHInYNmZ6dAhMc7fZdbzrRUYJl5P+ytaJep11QiimZE7MuTp+N+uMRuW
         6iUQ==
X-Gm-Message-State: AOAM533glVsqjw8+wa+b54jwicppCD1EIxrYufF8PSpE5/YhGjB0fgi2
	0fNZD7jqOlr7TGmp3iYtuD4=
X-Google-Smtp-Source: ABdhPJxgefve+WluWEZJDjiBVpdSZ7l0cLf3I2mAGcBQcj9y3bNcM/SIwdl2jp0rktGdbsWQir/bjQ==
X-Received: by 2002:a05:620a:1510:: with SMTP id i16mr14696687qkk.363.1604333080140;
        Mon, 02 Nov 2020 08:04:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1248:: with SMTP id a8ls7026705qkl.11.gmail; Mon,
 02 Nov 2020 08:04:39 -0800 (PST)
X-Received: by 2002:a37:401:: with SMTP id 1mr15807003qke.285.1604333079219;
        Mon, 02 Nov 2020 08:04:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333079; cv=none;
        d=google.com; s=arc-20160816;
        b=xv9V1X6LiXageFhk9h3KSOrVDh7NEpYDXjWJPtV03S0hrpTQJQEpmoycnSmZZtKS1a
         RkJ+y3v5Qsni5SuY7AH22hgihGFO+bhqbpRoADyP2zpTH+Ram5HYvknecxBcm3tvIkV1
         /G94a6bNsNqBVEgffr6xE4yHdSkexgrm+s7CUTJXRe5xZ2fvMI980oCZOgiY+k9Qq885
         MDH+Kd25WC2OVWUjWM1ipPL7TQ4g+M2y5TGGPKI1Mqrhj3YHRyrgzJ2R5mOEehRSDznB
         oKT81EEfWLDcj/wgcsvSMvvbUeLZa6xP2AbOg/tQj66Q7jOvfw+I6whf5DYhgCQI3xUB
         uYGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=SHQTTAC6Hd6Fbj5acE+XjHaNfSSfd6dVM7XrjREAdfI=;
        b=IJBURcXwNiZxzFNbgQ9DxXRB4/nwD8gDw9SeXJhrilhTH0dbzHm0zNcT2gH3l1iith
         ulucpsUwm1zwp2TlVlcGQMAITy82dcAJz/BbrDPN7BoiAkHdvBpFkly1NeHwsDXu15up
         ebcVVcY9bktYH4bRaNia6mZa1atO0ErzJJsGZCPZLUVcc9Z9Qp5VDsQ22f3GEo1cp1eF
         3LuyOCxvxXOUsGklnQn6DqLuY3ExSwCPoTu4PCct/q85QT4SW5vCYK5wMB8bc+e4UMjM
         OAxgBukAYyXmJkAY8HBHu8i5DJnPF/0Nj/hpmv9SpectEzkgSY73XPYmMLd/GVGcjPJI
         8jFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VBijlmKw;
       spf=pass (google.com: domain of 3fi6gxwokcfuxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Fi6gXwoKCfUXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id g16si861522qtp.0.2020.11.02.08.04.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:04:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fi6gxwokcfuxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id s8so8431478qvv.18
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:04:39 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4e6d:: with SMTP id
 ec13mr19043114qvb.41.1604333078854; Mon, 02 Nov 2020 08:04:38 -0800 (PST)
Date: Mon,  2 Nov 2020 17:03:45 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <94b6b7faeb6741a712ea6357c103e02260caa770.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 05/41] arm64: mte: Add in-kernel tag fault handler
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VBijlmKw;       spf=pass
 (google.com: domain of 3fi6gxwokcfuxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Fi6gXwoKCfUXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

Add the implementation of the in-kernel fault handler.

When a tag fault happens on a kernel address:
* MTE is disabled on the current CPU,
* the execution continues.

When a tag fault happens on a user address:
* the kernel executes do_bad_area() and panics.

The tag fault handler for kernel addresses is currently empty and will be
filled in by a future commit.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: I9b8aa79567f7c45f4d6a1290efcf34567e620717
---
 arch/arm64/include/asm/uaccess.h | 23 ++++++++++++++++
 arch/arm64/mm/fault.c            | 45 ++++++++++++++++++++++++++++++++
 2 files changed, 68 insertions(+)

diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 991dd5f031e4..c7fff8daf2a7 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -200,13 +200,36 @@ do {									\
 				CONFIG_ARM64_PAN));			\
 } while (0)
 
+/*
+ * The Tag Check Flag (TCF) mode for MTE is per EL, hence TCF0
+ * affects EL0 and TCF affects EL1 irrespective of which TTBR is
+ * used.
+ * The kernel accesses TTBR0 usually with LDTR/STTR instructions
+ * when UAO is available, so these would act as EL0 accesses using
+ * TCF0.
+ * However futex.h code uses exclusives which would be executed as
+ * EL1, this can potentially cause a tag check fault even if the
+ * user disables TCF0.
+ *
+ * To address the problem we set the PSTATE.TCO bit in uaccess_enable()
+ * and reset it in uaccess_disable().
+ *
+ * The Tag check override (TCO) bit disables temporarily the tag checking
+ * preventing the issue.
+ */
 static inline void uaccess_disable(void)
 {
+	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(0),
+				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
+
 	__uaccess_disable(ARM64_HAS_PAN);
 }
 
 static inline void uaccess_enable(void)
 {
+	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(1),
+				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
+
 	__uaccess_enable(ARM64_HAS_PAN);
 }
 
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index 1ee94002801f..fbceb14d93b1 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -33,6 +33,7 @@
 #include <asm/debug-monitors.h>
 #include <asm/esr.h>
 #include <asm/kprobes.h>
+#include <asm/mte.h>
 #include <asm/processor.h>
 #include <asm/sysreg.h>
 #include <asm/system_misc.h>
@@ -296,6 +297,44 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
 	do_exit(SIGKILL);
 }
 
+static void report_tag_fault(unsigned long addr, unsigned int esr,
+			     struct pt_regs *regs)
+{
+}
+
+static void do_tag_recovery(unsigned long addr, unsigned int esr,
+			   struct pt_regs *regs)
+{
+	static bool reported = false;
+
+	if (!READ_ONCE(reported)) {
+		report_tag_fault(addr, esr, regs);
+		WRITE_ONCE(reported, true);
+	}
+
+	/*
+	 * Disable MTE Tag Checking on the local CPU for the current EL.
+	 * It will be done lazily on the other CPUs when they will hit a
+	 * tag fault.
+	 */
+	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_NONE);
+	isb();
+}
+
+static bool is_el1_mte_sync_tag_check_fault(unsigned int esr)
+{
+	unsigned int ec = ESR_ELx_EC(esr);
+	unsigned int fsc = esr & ESR_ELx_FSC;
+
+	if (ec != ESR_ELx_EC_DABT_CUR)
+		return false;
+
+	if (fsc == ESR_ELx_FSC_MTE)
+		return true;
+
+	return false;
+}
+
 static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 			      struct pt_regs *regs)
 {
@@ -312,6 +351,12 @@ static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 	    "Ignoring spurious kernel translation fault at virtual address %016lx\n", addr))
 		return;
 
+	if (is_el1_mte_sync_tag_check_fault(esr)) {
+		do_tag_recovery(addr, esr, regs);
+
+		return;
+	}
+
 	if (is_el1_permission_fault(addr, esr, regs)) {
 		if (esr & ESR_ELx_WNR)
 			msg = "write to read-only memory";
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/94b6b7faeb6741a712ea6357c103e02260caa770.1604333009.git.andreyknvl%40google.com.
