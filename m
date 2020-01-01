Return-Path: <kasan-dev+bncBAABBVO6WHYAKGQEP3OULHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-f55.google.com (mail-ed1-f55.google.com [209.85.208.55])
	by mail.lfdr.de (Postfix) with ESMTPS id 03B5B12DE6F
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Jan 2020 11:07:18 +0100 (CET)
Received: by mail-ed1-f55.google.com with SMTP id n18sf15395331edo.17
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Jan 2020 02:07:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1577873237; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z8UfmT82ts99E2ae00ZZuriQSb1wxexQ2yNRNluADPfmwP8hn46kvNSs6N3uFUo6Zb
         dK28/wO7ebmslsZ+gp/pdWw6xrGt90H8zzSrxDCsv/+jUrBqGNm38OQ02ql4o5/y0+PB
         LLeNzaGgxUYSWwYS0W8Z0hFR60EG0IDjaUXItmfKZfzYomJQ7Z9OqkQLj5HFQbNEbPUn
         KZ/pow6BolHZPKi/Pp0GkAeFtlvrPaAJF6jw/RMhHVZvANPpsTLkQsItNy+K6MMkkdQ5
         MsttZ4lPuQfeTdP2RSOK0F5oMTNY8pyU82UQW9nMGc+OTb56R6CMp6oO3QsfCiKK5miA
         x/SA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:robot-unsubscribe:robot-id
         :message-id:mime-version:references:in-reply-to:cc:subject:to
         :reply-to:sender:from:date;
        bh=tDwyxGvopd49lzBUp85kZwcAaGoLxzuR5YCFNYJ2TPg=;
        b=KtUZ5nwtWEhJJq0pCELbY1m6VdRsSJqmFzEYTVJcwoJ65nacmkXtVaBUB0x3vtnkGs
         HmXIWl51UNCahh2W26KC51DUXYQ7rLjpivhyuC1vVsvnHkL+SYOZWcFNOLeiQ7btA0nu
         ZmW/ilwRWGdM7DFXO9sOvO1towxfnuFqlDYd7ljYpl67zo3TXb2NG8u3U2nEBwF35ltF
         I4ny+Bd052QGd57P4Iy0bNO4B3fxaLCfbjfNGVxDAEZhsppf4uLdJD11Bpjq5INftMJ8
         ZSj/pQ/Y2KWPEk64WcoRVO6XDSBngIMMh6AATtJJHfTw8nusZOZ936FrGyshIOax+DBU
         Wjiw==
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
        bh=tDwyxGvopd49lzBUp85kZwcAaGoLxzuR5YCFNYJ2TPg=;
        b=XoaVSn+MhUCVCE3+R+BC6a+D+RhBxbkQnTtuOaO4zLAAV355O+7c/UWqCixi3Pcc0l
         VVSv+hgXjbh98f3KzECM5J4lgskJ3TxBu4EFXqSYgFEHLc9r5/3cSXQ2yOE18sMA2rVs
         66x3Hn7mMuOk/5eNxvPBKrclcuBK8SlXkwimZJLRwgbkdPbQ1bhgFxZXeMDyyDEbyFjy
         pIuA1v+WGRSlsWv30QEEW/qBQCKDX5Juh69bsIAnYSeG+xY1sCcMnhJXmFbB0e7Mrgcs
         yKzbRMMYxwzHj9AWXhPQ70i394iEWy0CmomoiGTCcKj3dbvthZucyBMIg1Cys9DmAyy2
         GC6g==
X-Gm-Message-State: APjAAAVI5WExeICTlEbRYFMNhRt0RJcD/oTTABt0LMBBW8ggZHUVIor1
	wLj+lB+Wtb5S8wIfZ+MoF1c=
X-Google-Smtp-Source: APXvYqwIfdfQZ4PFZ60j709uUUmLoEwa/uuDoYUm3HpDt+/oCO2Jk6SWBES/YOPX/EnB+k5smnxLjg==
X-Received: by 2002:a17:906:31db:: with SMTP id f27mr46396434ejf.86.1577873237724;
        Wed, 01 Jan 2020 02:07:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:355a:: with SMTP id s26ls12050063eja.15.gmail; Wed,
 01 Jan 2020 02:07:17 -0800 (PST)
X-Received: by 2002:a17:906:d0c9:: with SMTP id bq9mr82030516ejb.56.1577873237349;
        Wed, 01 Jan 2020 02:07:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1577873237; cv=none;
        d=google.com; s=arc-20160816;
        b=hSvBQktLhzSg1ZfMvE8sjkumEoORLcv98w67bcMoVx0b84HGC4wpos5EiN4DpjKI9c
         4e7DsSbFcycbKHwEkP5LOPAoPvhhEhN4xFazKZgJY9JMNMtEBwRqOvqco1dRnv7t2q48
         ySdC4xCao4qrd61rEceTL0hafBxYmp1a2DZKwxD6qR97gS/O7FlbFI0gnMJI3jvF42vU
         8Lj4sW4KCITOOkCbmMvg7owHlVW5I1lPKnn9jSHhSi2a62Oc6Nb9zsxA8VIJbJ4/CIGq
         gkrxWCo8m+J7NR8sxuI0nZglHUeE/IzTVRo8YljCU8OCTxpmpAzq4c+jtrijhnsTDKtL
         Geeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:precedence:robot-unsubscribe:robot-id
         :message-id:mime-version:references:in-reply-to:cc:subject:to
         :reply-to:sender:from:date;
        bh=HXDzgsqNRlF3OXWsxqLfyBor8N+H8AfCNB4eWxQed9U=;
        b=eTpPGg6dd9rQQqZ3bTdPsvgeW3RJraIAUhuf3qk759Y/2XrtieAvpc/mBo9V0jS5Mt
         2wWwDzc/tMcBN7XXcBNIkmFCoikpv1GDWSWKuuAlV6qlZ8sn+3GdQyMdRnzEEWcl2ckL
         mcu/SoP3zsJVDhrWxCukMeTTCoOy7jcqwbHsc9KNEmat9UGyfqimM7kzmGzDEFSChRZB
         gCyCWompOmazKZqfuQ97W9MrdJ3ymGqrudwUCx10Kam2NaTLDloRl4gKDDcFgNDJgXFt
         HLOGbEgG+8nTQWIaVqDQJsS8ToHzDjDe5GvDPYBG2827p5S9xnhvrU9qnRUy+vmi+mqk
         Qy1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tip-bot2@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tip-bot2@linutronix.de
Received: from Galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id d29si1895488edj.0.2020.01.01.02.07.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=AES128-SHA bits=128/128);
        Wed, 01 Jan 2020 02:07:17 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of tip-bot2@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Received: from [5.158.153.53] (helo=tip-bot2.lab.linutronix.de)
	by Galois.linutronix.de with esmtpsa (TLS1.2:DHE_RSA_AES_256_CBC_SHA256:256)
	(Exim 4.80)
	(envelope-from <tip-bot2@linutronix.de>)
	id 1imauH-0004P4-Qi; Wed, 01 Jan 2020 11:07:14 +0100
Received: from [127.0.1.1] (localhost [IPv6:::1])
	by tip-bot2.lab.linutronix.de (Postfix) with ESMTP id 75A601C2C2C;
	Wed,  1 Jan 2020 11:07:13 +0100 (CET)
Date: Wed, 01 Jan 2020 10:07:13 -0000
From: "tip-bot2 for Jann Horn" <tip-bot2@linutronix.de>
Sender: tip-bot2@linutronix.de
Reply-to: linux-kernel@vger.kernel.org
To: linux-tip-commits@vger.kernel.org
Subject: [tip: x86/core] x86/traps: Print address on #GP
Cc: Jann Horn <jannh@google.com>, Borislav Petkov <bp@suse.de>,
 Sean Christopherson <sean.j.christopherson@intel.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>,
 "Eric W. Biederman" <ebiederm@xmission.com>, "H. Peter Anvin" <hpa@zytor.com>,
 Ingo Molnar <mingo@redhat.com>, kasan-dev@googlegroups.com,
 Masami Hiramatsu <mhiramat@kernel.org>, Peter Zijlstra <peterz@infradead.org>,
 Thomas Gleixner <tglx@linutronix.de>, "x86-ml" <x86@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>
In-Reply-To: <20191218231150.12139-2-jannh@google.com>
References: <20191218231150.12139-2-jannh@google.com>
MIME-Version: 1.0
Message-ID: <157787323335.30329.8702104659641784210.tip-bot2@tip-bot2>
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

Commit-ID:     59c1dcbed5b51cab543be8f47b6d7d9cf107ec94
Gitweb:        https://git.kernel.org/tip/59c1dcbed5b51cab543be8f47b6d7d9cf107ec94
Author:        Jann Horn <jannh@google.com>
AuthorDate:    Thu, 19 Dec 2019 00:11:48 +01:00
Committer:     Borislav Petkov <bp@suse.de>
CommitterDate: Tue, 31 Dec 2019 12:31:13 +01:00

x86/traps: Print address on #GP

A frequent cause of #GP exceptions are memory accesses to non-canonical
addresses. Unlike #PF, #GP doesn't report a fault address in CR2, so the
kernel doesn't currently print the fault address for a #GP.

Luckily, the necessary infrastructure for decoding x86 instructions and
computing the memory address being accessed is already present. Hook
it up to the #GP handler so that the address operand of the faulting
instruction can be figured out and printed.

Distinguish two cases:

  a) (Part of) the memory range being accessed lies in the non-canonical
     address range; in this case, it is likely that the decoded address
     is actually the one that caused the #GP.

  b) The entire memory range of the decoded operand lies in canonical
     address space; the #GP may or may not be related in some way to the
     computed address. Print it, but with hedging language in the message.

While it is already possible to compute the faulting address manually by
disassembling the opcode dump and evaluating the instruction against the
register dump, this should make it slightly easier to identify crashes
at a glance.

Note that the operand length which comes from the instruction decoder
and is used to determine whether the access straddles into non-canonical
address space, is currently somewhat unreliable; but it should be good
enough, considering that Linux on x86-64 never maps the page directly
before the start of the non-canonical range anyway, and therefore the
case where a memory range begins in that page and potentially straddles
into the non-canonical range should be fairly uncommon.

In the case the address is still computed wrongly, it only influences
whether the error message claims that the access is canonical.

 [ bp: Remove ambiguous "we", massage, reflow comments and spacing. ]

Signed-off-by: Jann Horn <jannh@google.com>
Signed-off-by: Borislav Petkov <bp@suse.de>
Reviewed-by: Sean Christopherson <sean.j.christopherson@intel.com>
Tested-by: Sean Christopherson <sean.j.christopherson@intel.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Andy Lutomirski <luto@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: "H. Peter Anvin" <hpa@zytor.com>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: kasan-dev@googlegroups.com
Cc: Masami Hiramatsu <mhiramat@kernel.org>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: x86-ml <x86@kernel.org>
Link: https://lkml.kernel.org/r/20191218231150.12139-2-jannh@google.com
---
 arch/x86/kernel/traps.c | 72 +++++++++++++++++++++++++++++++++++++---
 1 file changed, 67 insertions(+), 5 deletions(-)

diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index 05da6b5..108ab1e 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -56,6 +56,8 @@
 #include <asm/mpx.h>
 #include <asm/vm86.h>
 #include <asm/umip.h>
+#include <asm/insn.h>
+#include <asm/insn-eval.h>
 
 #ifdef CONFIG_X86_64
 #include <asm/x86_init.h>
@@ -518,10 +520,53 @@ exit_trap:
 	do_trap(X86_TRAP_BR, SIGSEGV, "bounds", regs, error_code, 0, NULL);
 }
 
-dotraplinkage void
-do_general_protection(struct pt_regs *regs, long error_code)
+enum kernel_gp_hint {
+	GP_NO_HINT,
+	GP_NON_CANONICAL,
+	GP_CANONICAL
+};
+
+/*
+ * When an uncaught #GP occurs, try to determine the memory address accessed by
+ * the instruction and return that address to the caller. Also, try to figure
+ * out whether any part of the access to that address was non-canonical.
+ */
+static enum kernel_gp_hint get_kernel_gp_address(struct pt_regs *regs,
+						 unsigned long *addr)
 {
-	const char *desc = "general protection fault";
+	u8 insn_buf[MAX_INSN_SIZE];
+	struct insn insn;
+
+	if (probe_kernel_read(insn_buf, (void *)regs->ip, MAX_INSN_SIZE))
+		return GP_NO_HINT;
+
+	kernel_insn_init(&insn, insn_buf, MAX_INSN_SIZE);
+	insn_get_modrm(&insn);
+	insn_get_sib(&insn);
+
+	*addr = (unsigned long)insn_get_addr_ref(&insn, regs);
+	if (*addr == -1UL)
+		return GP_NO_HINT;
+
+#ifdef CONFIG_X86_64
+	/*
+	 * Check that:
+	 *  - the operand is not in the kernel half
+	 *  - the last byte of the operand is not in the user canonical half
+	 */
+	if (*addr < ~__VIRTUAL_MASK &&
+	    *addr + insn.opnd_bytes - 1 > __VIRTUAL_MASK)
+		return GP_NON_CANONICAL;
+#endif
+
+	return GP_CANONICAL;
+}
+
+#define GPFSTR "general protection fault"
+
+dotraplinkage void do_general_protection(struct pt_regs *regs, long error_code)
+{
+	char desc[sizeof(GPFSTR) + 50 + 2*sizeof(unsigned long) + 1] = GPFSTR;
 	struct task_struct *tsk;
 
 	RCU_LOCKDEP_WARN(!rcu_is_watching(), "entry code didn't wake RCU");
@@ -540,6 +585,9 @@ do_general_protection(struct pt_regs *regs, long error_code)
 
 	tsk = current;
 	if (!user_mode(regs)) {
+		enum kernel_gp_hint hint = GP_NO_HINT;
+		unsigned long gp_addr;
+
 		if (fixup_exception(regs, X86_TRAP_GP, error_code, 0))
 			return;
 
@@ -556,8 +604,22 @@ do_general_protection(struct pt_regs *regs, long error_code)
 			return;
 
 		if (notify_die(DIE_GPF, desc, regs, error_code,
-			       X86_TRAP_GP, SIGSEGV) != NOTIFY_STOP)
-			die(desc, regs, error_code);
+			       X86_TRAP_GP, SIGSEGV) == NOTIFY_STOP)
+			return;
+
+		if (error_code)
+			snprintf(desc, sizeof(desc), "segment-related " GPFSTR);
+		else
+			hint = get_kernel_gp_address(regs, &gp_addr);
+
+		if (hint != GP_NO_HINT)
+			snprintf(desc, sizeof(desc), GPFSTR ", %s 0x%lx",
+				 (hint == GP_NON_CANONICAL) ?
+				 "probably for non-canonical address" :
+				 "maybe for address",
+				 gp_addr);
+
+		die(desc, regs, error_code);
 		return;
 	}
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/157787323335.30329.8702104659641784210.tip-bot2%40tip-bot2.
