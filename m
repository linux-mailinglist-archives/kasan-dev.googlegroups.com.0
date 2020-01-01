Return-Path: <kasan-dev+bncBAABBWG6WHYAKGQE3DHBD6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-f184.google.com (mail-lj1-f184.google.com [209.85.208.184])
	by mail.lfdr.de (Postfix) with ESMTPS id DD4DD12DE74
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Jan 2020 11:07:20 +0100 (CET)
Received: by mail-lj1-f184.google.com with SMTP id a19sf4973606ljp.15
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Jan 2020 02:07:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1577873240; cv=pass;
        d=google.com; s=arc-20160816;
        b=RwMopeU86j/EIo12L2oPWm0vwfc9vAnvTG2HmzEUZk4Xdx6hYX09bDPjZ/YfI1SdoN
         w/mJuPPyKN8pIJn6PjsCVK0F6dnSMiI/6Oq86GGxt/SYxuyy0LzWo9gcpj4Yzp2rSI5Q
         Y3XnG0khKQ36XE1rzFKrbAZhXvIVcYam+BhZjLhQbGnzwlAfJPXaEkVPC7Unkrc72MoE
         KNZaTDT4J3M4M2zt/Y8ZjdZjBn1VdNjY3I6Fm0q3B5ZKYRQMSfvkOk5NanDrNpMCeFgY
         nyvEG6EnAPpxYwP1Ip7c31pC1yl64okeDVfdChzkqBjNu3gqlcdBuIyQCXCorlRWmN9z
         88Cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:robot-unsubscribe:robot-id
         :message-id:mime-version:references:in-reply-to:cc:subject:to
         :reply-to:sender:from:date;
        bh=zx7Y2iuQ9vNnFJdYhEjNbUYP+l+C5wQZGvgeobu3COw=;
        b=FSNrBrxeNw0b1yECfhxaFRkSqMGZBwIy/qdTsBKJwq38lYhY16bjPxSUkrml/7YsxZ
         L+a2PTML+QQ60i/xXpk7F5QJ8HdZJy1CyMd4tukYaWL8aQerYjU1A0Zw8lNeZ1tmDAVg
         ZM1RtnDN2GKWBC60c3RldJvZdM4huCgPVMt8tYyBOijMIFJs8eRDhcbMkZ0L2JZwlYMA
         txJvqJE460MLBP3tgoaKh6VKmBRsGyjSKdaFQkkPtfDnxMDE7Oy/EMMnmbYXk2HjP9SE
         Rd/ruiywl55s0HqPAF20z+3asNHPyyr9mns0NvrSyp83DN5f4JOkXvvK7Etq/30uI/7w
         5zkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tip-bot2@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tip-bot2@linutronix.de
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:sender:reply-to:to:subject:cc
         :in-reply-to:references:mime-version:message-id:robot-id
         :robot-unsubscribe:precedence:x-original-sender
         :x-original-authentication-results:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zx7Y2iuQ9vNnFJdYhEjNbUYP+l+C5wQZGvgeobu3COw=;
        b=rpcaaAwQQCatjN5/6RgvMyLxDvgEebRPqvzA9YFSSVDobtS7nFqY08J1lWJiVzumdG
         r2vH0Nof1oP7RTpR+enzXLYLH5vbMzVgYnLy5v9Zuni+FDZWV9s4tHM7Mp7rqZV/0TY5
         X95wVDTHUa344bM3yViYqFXLxAMIeE/mL/5MeKjPqVtITXB+CVOuDqi8DK/5m7fImtO6
         XKjzZo1XY3Lz7oIpSOTHeuBHBPtyJPeZ6Bo4UW71Zdo25bs05Mm2P9pg2Aa+pRPMMGoW
         EykQI7ShzX5uKq8SFVzPlAJM6Vz/vxtkhYqZ7AMOfORcOWr9BWPAqRHYDYQ935wh9FRB
         HOIg==
X-Gm-Message-State: APjAAAXWDpBtTbQ3iMlZMHDCxvFT61BIsgMZ86sbEfBlNLhCoCIX60IE
	HVKxo6jdEAomEzyiuKMnSdo=
X-Google-Smtp-Source: APXvYqw133zqPr1Yyd3qXKsmazM+lOqZ7SRiZPTkGvndAJ6C9/vw3RER62wT2yrTfy5IlurCLMbMiQ==
X-Received: by 2002:a2e:b4cb:: with SMTP id r11mr45326144ljm.68.1577873240436;
        Wed, 01 Jan 2020 02:07:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:95c7:: with SMTP id y7ls4379531ljh.16.gmail; Wed, 01 Jan
 2020 02:07:20 -0800 (PST)
X-Received: by 2002:a2e:9b03:: with SMTP id u3mr34390717lji.87.1577873240058;
        Wed, 01 Jan 2020 02:07:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1577873240; cv=none;
        d=google.com; s=arc-20160816;
        b=xRmN89daYNGihvYKB7NphYZ7qbkSiH9CC73Lbe8LP4u8FZs9IRAx9pBLrhKt5M119v
         DD6sLOUT1R3pU5wLeZT3jBNln9N+rbqq/TGCzwDWZZL6hV7hQ38yrJRYyvVJuzUpYrcW
         GUnpi2n38lS+Me3F5idbtJ5KX789RwNp5WwO7ll82VIs2PWFiULyAGXJeWkn1Z91HSwd
         9OfbdJ4a7ppAO9CYyAH61qh0SFXjV8UqnUjFSyKh/dRY5fVV6YLNzxFwyxoLb12n1Kxw
         +qQGw5+ihEdIGZ/2TrPhIxVE6TQeWEBzzWkH9iKfyVG50Onb5YC+t+bfHPtwdS8vM4OI
         AHxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:precedence:robot-unsubscribe:robot-id
         :message-id:mime-version:references:in-reply-to:cc:subject:to
         :reply-to:sender:from:date;
        bh=Ssm4B4JsmKgyFcnyGO0YhuLFzNtqCRmZd1l9ktePUIg=;
        b=flxXEsWHmS+TxPUxFgW5+uLDMQ/LR1ATCEy2vHNmmJGsyop9ChT8gRf8JDaEW8hm6s
         ZD086BTNy+0ewZG5P9OoUnp5pw8VaURcZOpEbbjUeKUgyP/+dWkHXmkftBcVA8mGn/YN
         oATExni1rfCLDYrrvmAGw2W4lqKgLzPgscmw8x6hVBookVJpSwhIcCg799dMhx4AZd6D
         uNOd6WS+93ZuJ/qIdOnyIGTo50yBb0FI5PfAcNuQtiBod7o3GW3nRzcPJ3auoysSz3ja
         1RbSZJnxCdSL05ZgZjqg79tYWacOram6lfZ9vEu1RYTSaMsGt9mRRGqtqrQOSXRTfLpG
         voGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tip-bot2@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tip-bot2@linutronix.de
Received: from Galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id e3si2151900ljg.2.2020.01.01.02.07.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=AES128-SHA bits=128/128);
        Wed, 01 Jan 2020 02:07:20 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of tip-bot2@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Received: from [5.158.153.53] (helo=tip-bot2.lab.linutronix.de)
	by Galois.linutronix.de with esmtpsa (TLS1.2:DHE_RSA_AES_256_CBC_SHA256:256)
	(Exim 4.80)
	(envelope-from <tip-bot2@linutronix.de>)
	id 1imauI-0004P7-2q; Wed, 01 Jan 2020 11:07:14 +0100
Received: from [127.0.1.1] (localhost [IPv6:::1])
	by tip-bot2.lab.linutronix.de (Postfix) with ESMTP id A273C1C2C2F;
	Wed,  1 Jan 2020 11:07:13 +0100 (CET)
Date: Wed, 01 Jan 2020 10:07:13 -0000
From: "tip-bot2 for Jann Horn" <tip-bot2@linutronix.de>
Sender: tip-bot2@linutronix.de
Reply-to: linux-kernel@vger.kernel.org
To: linux-tip-commits@vger.kernel.org
Subject: [tip: x86/core] x86/insn-eval: Add support for 64-bit kernel mode
Cc: Jann Horn <jannh@google.com>, Borislav Petkov <bp@suse.de>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>,
 "Gustavo A. R. Silva" <gustavo@embeddedor.com>,
 "H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
 kasan-dev@googlegroups.com, Oleg Nesterov <oleg@redhat.com>,
 Sean Christopherson <sean.j.christopherson@intel.com>,
 Thomas Gleixner <tglx@linutronix.de>, "x86-ml" <x86@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>
In-Reply-To: <20191218231150.12139-1-jannh@google.com>
References: <20191218231150.12139-1-jannh@google.com>
MIME-Version: 1.0
Message-ID: <157787323354.30329.6908978173787271263.tip-bot2@tip-bot2>
X-Mailer: tip-git-log-daemon
Robot-ID: <tip-bot2.linutronix.de>
Robot-Unsubscribe: Contact <mailto:tglx@linutronix.de> to get blacklisted from these emails
Precedence: list
Content-Type: text/plain; charset="UTF-8"
X-Linutronix-Spam-Score: -1.0
X-Linutronix-Spam-Level: -
X-Linutronix-Spam-Status: No , -1.0 points, 5.0 required,  ALL_TRUSTED=-1,SHORTCIRCUIT=-0.0001
X-Original-Sender: tip-bot2@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of tip-bot2@linutronix.de
 designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tip-bot2@linutronix.de
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

The following commit has been merged into the x86/core branch of tip:

Commit-ID:     7be4412721aee25e35583a20a896085dc6b99c3e
Gitweb:        https://git.kernel.org/tip/7be4412721aee25e35583a20a896085dc6b99c3e
Author:        Jann Horn <jannh@google.com>
AuthorDate:    Thu, 19 Dec 2019 00:11:47 +01:00
Committer:     Borislav Petkov <bp@suse.de>
CommitterDate: Mon, 30 Dec 2019 20:17:15 +01:00

x86/insn-eval: Add support for 64-bit kernel mode

To support evaluating 64-bit kernel mode instructions:

* Replace existing checks for user_64bit_mode() with a new helper that
checks whether code is being executed in either 64-bit kernel mode or
64-bit user mode.

* Select the GS base depending on whether the instruction is being
evaluated in kernel mode.

Signed-off-by: Jann Horn <jannh@google.com>
Signed-off-by: Borislav Petkov <bp@suse.de>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Andy Lutomirski <luto@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: "Gustavo A. R. Silva" <gustavo@embeddedor.com>
Cc: "H. Peter Anvin" <hpa@zytor.com>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: kasan-dev@googlegroups.com
Cc: Oleg Nesterov <oleg@redhat.com>
Cc: Sean Christopherson <sean.j.christopherson@intel.com>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: x86-ml <x86@kernel.org>
Link: https://lkml.kernel.org/r/20191218231150.12139-1-jannh@google.com
---
 arch/x86/include/asm/ptrace.h | 13 +++++++++++++
 arch/x86/lib/insn-eval.c      | 26 +++++++++++++++-----------
 2 files changed, 28 insertions(+), 11 deletions(-)

diff --git a/arch/x86/include/asm/ptrace.h b/arch/x86/include/asm/ptrace.h
index 5057a8e..ac45b06 100644
--- a/arch/x86/include/asm/ptrace.h
+++ b/arch/x86/include/asm/ptrace.h
@@ -159,6 +159,19 @@ static inline bool user_64bit_mode(struct pt_regs *regs)
 #endif
 }
 
+/*
+ * Determine whether the register set came from any context that is running in
+ * 64-bit mode.
+ */
+static inline bool any_64bit_mode(struct pt_regs *regs)
+{
+#ifdef CONFIG_X86_64
+	return !user_mode(regs) || user_64bit_mode(regs);
+#else
+	return false;
+#endif
+}
+
 #ifdef CONFIG_X86_64
 #define current_user_stack_pointer()	current_pt_regs()->sp
 #define compat_user_stack_pointer()	current_pt_regs()->sp
diff --git a/arch/x86/lib/insn-eval.c b/arch/x86/lib/insn-eval.c
index 306c3a0..31600d8 100644
--- a/arch/x86/lib/insn-eval.c
+++ b/arch/x86/lib/insn-eval.c
@@ -155,7 +155,7 @@ static bool check_seg_overrides(struct insn *insn, int regoff)
  */
 static int resolve_default_seg(struct insn *insn, struct pt_regs *regs, int off)
 {
-	if (user_64bit_mode(regs))
+	if (any_64bit_mode(regs))
 		return INAT_SEG_REG_IGNORE;
 	/*
 	 * Resolve the default segment register as described in Section 3.7.4
@@ -266,7 +266,7 @@ static int resolve_seg_reg(struct insn *insn, struct pt_regs *regs, int regoff)
 	 * which may be invalid at this point.
 	 */
 	if (regoff == offsetof(struct pt_regs, ip)) {
-		if (user_64bit_mode(regs))
+		if (any_64bit_mode(regs))
 			return INAT_SEG_REG_IGNORE;
 		else
 			return INAT_SEG_REG_CS;
@@ -289,7 +289,7 @@ static int resolve_seg_reg(struct insn *insn, struct pt_regs *regs, int regoff)
 	 * In long mode, segment override prefixes are ignored, except for
 	 * overrides for FS and GS.
 	 */
-	if (user_64bit_mode(regs)) {
+	if (any_64bit_mode(regs)) {
 		if (idx != INAT_SEG_REG_FS &&
 		    idx != INAT_SEG_REG_GS)
 			idx = INAT_SEG_REG_IGNORE;
@@ -646,23 +646,27 @@ unsigned long insn_get_seg_base(struct pt_regs *regs, int seg_reg_idx)
 		 */
 		return (unsigned long)(sel << 4);
 
-	if (user_64bit_mode(regs)) {
+	if (any_64bit_mode(regs)) {
 		/*
 		 * Only FS or GS will have a base address, the rest of
 		 * the segments' bases are forced to 0.
 		 */
 		unsigned long base;
 
-		if (seg_reg_idx == INAT_SEG_REG_FS)
+		if (seg_reg_idx == INAT_SEG_REG_FS) {
 			rdmsrl(MSR_FS_BASE, base);
-		else if (seg_reg_idx == INAT_SEG_REG_GS)
+		} else if (seg_reg_idx == INAT_SEG_REG_GS) {
 			/*
 			 * swapgs was called at the kernel entry point. Thus,
 			 * MSR_KERNEL_GS_BASE will have the user-space GS base.
 			 */
-			rdmsrl(MSR_KERNEL_GS_BASE, base);
-		else
+			if (user_mode(regs))
+				rdmsrl(MSR_KERNEL_GS_BASE, base);
+			else
+				rdmsrl(MSR_GS_BASE, base);
+		} else {
 			base = 0;
+		}
 		return base;
 	}
 
@@ -703,7 +707,7 @@ static unsigned long get_seg_limit(struct pt_regs *regs, int seg_reg_idx)
 	if (sel < 0)
 		return 0;
 
-	if (user_64bit_mode(regs) || v8086_mode(regs))
+	if (any_64bit_mode(regs) || v8086_mode(regs))
 		return -1L;
 
 	if (!sel)
@@ -948,7 +952,7 @@ static int get_eff_addr_modrm(struct insn *insn, struct pt_regs *regs,
 	 * following instruction.
 	 */
 	if (*regoff == -EDOM) {
-		if (user_64bit_mode(regs))
+		if (any_64bit_mode(regs))
 			tmp = regs->ip + insn->length;
 		else
 			tmp = 0;
@@ -1250,7 +1254,7 @@ static void __user *get_addr_ref_32(struct insn *insn, struct pt_regs *regs)
 	 * After computed, the effective address is treated as an unsigned
 	 * quantity.
 	 */
-	if (!user_64bit_mode(regs) && ((unsigned int)eff_addr > seg_limit))
+	if (!any_64bit_mode(regs) && ((unsigned int)eff_addr > seg_limit))
 		goto out;
 
 	/*

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/157787323354.30329.6908978173787271263.tip-bot2%40tip-bot2.
