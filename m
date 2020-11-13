Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4MLXT6QKGQE33WOMCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CF8A2B2821
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:22 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id z62sf5877500wmb.1
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305841; cv=pass;
        d=google.com; s=arc-20160816;
        b=blGzhXvaKkRr+GNVYRi/qHoTmKrolDn2yuRyqAqKbXp5qMtfcUM2pCcCMhfC2Jy+9n
         UJOKcCQW99J+wNY7ZqfeV/A/WczHvXZN9PElGfn7xn7g9VSySWeNfZC09libcUDcNTAf
         esGrhEtIC6N3K8+D8nylVfVyj7j4VQM74LYb0OZv5Aik4XhEb3DMB8w8z/w1afFqUiAH
         GOQC60YFjF1u9Y60d6+cn+jIBpT8eJa6seMfH67IQmhNF72sKuDgjtzErPl/AH28TCQW
         OyX2IwU7sXnAzNLjAaHf/ZHuuE3JuhuNlIxClCVF4EXm/mf3DhLHMUn+SLwC4XPNnq0a
         3gNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Cw8ut3qBRtviT0/vwChOGYMAVdKXsKbVJYmiKplEK64=;
        b=ls+TBo7TtIWtW8J7i47lCmI2meyLtygBc+PubP5k9bGC6xzclAZNkopxyM/cMRXeUs
         vNbvjG/aruRUbrQMnasRpM4PIZsBM8c6KChVBnnVbJ2obEmWOODToa5WGnYyrICFkJ9E
         LdSOkXVXwKTDaFdJtuE7MhDS0UatIaAZflcoONcB2oxoHrjHXm5Lns8rDj2MFNMaefpc
         cuW467Qcq9OQs1mSc6CaybtR2tC91WTcG5By4Sa1Yx7xPYPl6nj554YdWpIF6Ihv3oUe
         e47dq1146vYB1AZ4ZjZTiOSlrfmYyPRpp+9iRJisjYGJI140pFR7cenorB0P2edXC3+U
         WWTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SynBjZ9o;
       spf=pass (google.com: domain of 38awvxwokcbsboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=38AWvXwoKCbsboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Cw8ut3qBRtviT0/vwChOGYMAVdKXsKbVJYmiKplEK64=;
        b=ep9fWNIX47QuzepFiaYB/Gmh5sUYQVympM95FLYoH7U4xqrKuJQQIq05XUDTv27Byq
         rWADTsmJdxkrhdei+8qC8GBDruwmqBTAzHfNzU8HyeeT7+kEOnRiDaewXeyS7ibbPHvw
         2WTyR901JIYU2EcpLouk8k2OEHYppLpymnVdyjRwHHTDzGn+9vU1P6tm0QU1JwffbpN5
         NTpUhugvcyDOY0R6aJ9AIt5+jELgYc5arjAJryKSPSMq3zdILk1d1bfdmgkY7DPXMNxc
         Gj9Omg8Ssz6125Gge9kJ28UgU6JolaN/4+gELlxZtJ0td63dDPhYMNsgslcofxN1zkjS
         c73w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Cw8ut3qBRtviT0/vwChOGYMAVdKXsKbVJYmiKplEK64=;
        b=FwlZoxx+jTBBtMwk1Rb8Y7uN7JFnGbChxCx9x3VKbyeoRU+P2UIw2jfIjWSq13J8NV
         eZZ4/Nj/vOzNY6RM2xjQ4v2CMLETNz3MgSGHWQtCWgFjEgREX6slgRUHWBEEXpfZJQe3
         gqAS0JpktPpmdhvoOmtYzOeprlZBjYOJnOQp34PnTPA8lOgHM3v0Pd3B3kbvFf+MQdXP
         2IBY5kP7aAa9TZXMeV9eWQqfM03gkiz2z0ck7V3/Y9p1Dljt5x+IISCrGndaZxkcohyZ
         u+ZrVOxSa7roxGFd5beYKQRUP1L2B5ofEfk4nSYdViDo1oQIQUtu9ajB1VQN5Z6TdjbM
         uZsg==
X-Gm-Message-State: AOAM533zRrdSelO76xXEFor3eSJVqbV9MzqAe4ByFq48NgLNcC4KHe3V
	0ywdLvs++r4Slg5LCZ7Fe9c=
X-Google-Smtp-Source: ABdhPJySy3ehDo3buSAQFDWGkAPw+1WDfiRDktNfNN46PGDfg2WHwEw7djPOpFrDNLvbBxsIlxmhcA==
X-Received: by 2002:adf:e5d0:: with SMTP id a16mr6465082wrn.340.1605305841816;
        Fri, 13 Nov 2020 14:17:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f70d:: with SMTP id r13ls7241565wrp.1.gmail; Fri, 13 Nov
 2020 14:17:21 -0800 (PST)
X-Received: by 2002:adf:e5c4:: with SMTP id a4mr6496459wrn.56.1605305841064;
        Fri, 13 Nov 2020 14:17:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305841; cv=none;
        d=google.com; s=arc-20160816;
        b=iqwe0qX01T6i2stmafd2bjqErjRjXw10IfWbmk6oYuRTExwEy0ve002tP8MxFpHxbM
         lrLEk0CALYEB9ByPM5S450WbatlXU3MIKwAD8pbvm93ccuhFqYhF0YdaT3Fnc8QbX03l
         dJRnGAUm8+cO5yMgrKxTMS81WldE9f7jKPyhf1puMvRdq0odyW2vZhkhP+cyyPNtudH0
         K9HjGltcyKnh/rdOrV5Ub1Sj0HnoLo1mS+89Ol2svNYn9or0QEZRPiRVP7q0d1AfPiyh
         THxAaCGODiClgGdC66ifk65zF/2gJLGtKPCNvWjNuFhT3IkKJNbAGRlEm5DtFlsvgGt9
         E3Eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=f330gwtucMwyJOv1r7QkUx5rGmL++YWUBK25FbPW7AY=;
        b=QEOLVO6gHyurLMx4ll5eevQGkJ/s8dQtsvVR5wv622f6P0qSTJXzhvhbtg4D8xFN1W
         ZnMnlkz5LiQZFkh0KPGSY0D/SA25iWfiod8DEfqe7HAVL9Jp0dUldYypCqxoKi+lngyF
         7TdOH6LNpiUnAQhfi08r67rmK3sIiP+5nIo4H+7WOsl0MRFCpGNf8W08wg4H0dV9hKpF
         8DQqary8j/gO9P7qgLIExLlvyQl9K29dCfTARDzul9kxhiYfmWjzVW3JpFmw5//dEr98
         Um382Gn3B36PFJrri9VPB6AlO4rFRgywL7L1pwFusz/sj2UVVDb8JtGOQwbQpybrCOTt
         jm5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SynBjZ9o;
       spf=pass (google.com: domain of 38awvxwokcbsboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=38AWvXwoKCbsboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id f18si331838wme.2.2020.11.13.14.17.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:21 -0800 (PST)
Received-SPF: pass (google.com: domain of 38awvxwokcbsboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id gx12so4858818ejb.18
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:21 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:4742:: with SMTP id
 j2mr4014622ejs.247.1605305840612; Fri, 13 Nov 2020 14:17:20 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:55 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <86f8a9be5ab50af11e5b1203157a39f0d9902024.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 27/42] arm64: mte: Add in-kernel tag fault handler
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SynBjZ9o;       spf=pass
 (google.com: domain of 38awvxwokcbsboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=38AWvXwoKCbsboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I9b8aa79567f7c45f4d6a1290efcf34567e620717
---
 arch/arm64/include/asm/uaccess.h | 23 ++++++++++++++++
 arch/arm64/mm/fault.c            | 45 ++++++++++++++++++++++++++++++++
 2 files changed, 68 insertions(+)

diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 385a189f7d39..d841a560fae7 100644
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
index 183d1e6dd9e0..1e4b9353c68a 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -34,6 +34,7 @@
 #include <asm/debug-monitors.h>
 #include <asm/esr.h>
 #include <asm/kprobes.h>
+#include <asm/mte.h>
 #include <asm/processor.h>
 #include <asm/sysreg.h>
 #include <asm/system_misc.h>
@@ -297,6 +298,44 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
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
+	static bool reported;
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
@@ -313,6 +352,12 @@ static void __do_kernel_fault(unsigned long addr, unsigned int esr,
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
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/86f8a9be5ab50af11e5b1203157a39f0d9902024.1605305705.git.andreyknvl%40google.com.
