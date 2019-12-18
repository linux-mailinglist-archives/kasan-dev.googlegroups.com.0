Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBS7E5LXQKGQEXFXVKMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id B8A4D125777
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 00:12:13 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id x21sf2290903pfp.12
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 15:12:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576710732; cv=pass;
        d=google.com; s=arc-20160816;
        b=QaKM/1071b3W1J3Q87p3kTq74hbR1A0tsyV0Drvz6NpdbMClAXL9WoVNIcAbrbcyGx
         3LqnM4Nz6RE8OdiWjGXh9IV6Ncks2Dj308FgK9+XDPACKYW9FvEP4Hofv9jjwNxwJnVN
         Jh46z8sAuzfhnA+VzqIVt/6R7hFI9A2P09uoiZHw1/14y1P9cHN9AZ9XU/z4hP7yykXE
         ukAWKvmyt7QlGvVX0j3Sc9irQgtMfT3ienmU3gVeLwCG0J8O+LSJ+xi53/+kpQqYEl0z
         xVaaJhY1ajxGOpHSAqnvKBUxfT5IrJao9x/ZVW3pX+BgloRU2pfN4jurJ7PcQc1TWkaD
         DYHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=SUS5UBp3EjM4PMEiYWY4VaggHGIfWXCfpPaSsAXcilE=;
        b=d2emDamYP61RYKd09T93nn3Fb8BUQqzuFZwS67cEGd+MjHMafm+J6Bs6+E8TOLXXwx
         FBwuuMNEHzDA7fWZ/iWrsnFUjZUSs7tBYeywV32XMF9PeY1i7xn3RLBf2dm/pdoWxAMv
         IHE46aFMash5Ttcb5fZkeU6HXjfxFvJceUjQx/yF+8SKQpcHfgBopUUOhYRlvPGmBpvx
         vCVXC2wbD/cP6MvK0b3BQchwrdB6J58lqhX9HzVPZSdqNqXc3IOA/KicU63UjEiKzMBg
         9HuBw6+CrNCfw37HFzE4965gAxGOFb62rH29LADHv/aVDOG8GOo8NLXPEEa8JW19xzUQ
         +U2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aMwJ5hLh;
       spf=pass (google.com: domain of 3srl6xqukcy82t660z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3SrL6XQUKCY82t660z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SUS5UBp3EjM4PMEiYWY4VaggHGIfWXCfpPaSsAXcilE=;
        b=nEaCn0kNnt9x8GejTaXl/Tjfl5fbM+Gm+vMhaPPJFkPfzdWvTWZUi22d/Sn/MVcX4H
         pV9fM3Re8RUV3sgERDqveTxb/zCzJ4T2OE9AfeUNCMob/0K+FbjWgvy8IEwEMZtEyks9
         mh2WEnkTfhL3jOhSZYkVtF7k4zn5wEzjqBogEDEbmLsVAydg5Q5l5OmphpdMluGwrRLQ
         t3dt2VfIjH5TFQKoRp8VwpqtDO/pGDvgByY0vnDGBfGmFkIu8mtYGHlrAKb09sINDjcR
         ueQM2tItePDj42BTpDB6nhwu5l2/EvuDuCRO+sNXdbvnpH0GWbMETVHxrPIylI+Fbhk6
         l4SA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SUS5UBp3EjM4PMEiYWY4VaggHGIfWXCfpPaSsAXcilE=;
        b=f/sL9GZtcjAOhB+kxPy3rJwRqqcTZkPYRM3NEalL4GuS3DHyPLK9y5KWnLhru3/3WF
         j4KuKpmAt5qPXQinID1eeH0XQ5aafX7+Cfz+CmuFriCQScSpfFl8y6vso3E0ZyuLg9OO
         b3NeSb662IvY048Y86fwefnXZ2Cfwd9ychK5h5hUzsHNc6C4UkwkOON9aGOEtt7Uq+yK
         Vpdn3Lvoy2TbpcqxNKyR6RGKBoNCVl093Jeth+jZrGhrN+TpEmhjzm9C1jispxPUYOSf
         ZGhhOVVBjCZjIVwkHXNtlzZpraA36sNDE+QO5mIWL3iYp/JKAbLgqH4AuFCSA5pd6RJJ
         EvZg==
X-Gm-Message-State: APjAAAXZlYnL58Hnm3gjrIGnNQtHLjrUHTIe6QFeiUTjlSvijW5RHN/y
	2fSgEJQDj40lniDEZkaVSgc=
X-Google-Smtp-Source: APXvYqwOgzE9hYrakbuJ9ufR/Y29z3jBUq8tjjEYcjgbMApzh/bASV1hYKkOYdpPOBYn9sxNunJ6cA==
X-Received: by 2002:a17:90a:b318:: with SMTP id d24mr6052101pjr.142.1576710731983;
        Wed, 18 Dec 2019 15:12:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b593:: with SMTP id a19ls532235pls.0.gmail; Wed, 18
 Dec 2019 15:12:11 -0800 (PST)
X-Received: by 2002:a17:902:8603:: with SMTP id f3mr5745455plo.198.1576710731492;
        Wed, 18 Dec 2019 15:12:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576710731; cv=none;
        d=google.com; s=arc-20160816;
        b=uXP6aXVR764o1hPY4wdTafunDIHQjF9baM4NYJHYblAyG/pMVprZ/FT/P+HSvFTLXM
         Kg87Xd9QeeMShMEu17SDQKuQVZxVrBJlWNF1Rca/LOl5JWDYtVOMcESMSfUjix42xo8h
         EdksIq/1CyPVuovNN5EHQSMygHUrGEEg8DNN6FLoEk5FOwkutTlxPQBrk/ozZ4zN+akD
         ejbVrkvqVT64F5Qg2tO4ps+CaofdIQxSibjpoFInAPXQDbxsGUcKdydAYki8MC/JxqRo
         sHbmoERYcUbDlsPZxQf3JBfqap+aeMy2Dsdik+R2NO0q+gMIQKyw0fMOT8Jbd88pMenO
         is2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=zwZD1xekAbBhcHcPHq3baE7/ncVh4IANCcYoRBC9tq4=;
        b=QSCU0+uCXaQj0fDMn/k4DdJFj8Y58mL97t2MTPagTZvwDlFKigtMk/l3FEtssnr39X
         c8gfdt10HW+/x0GzVEvy47oC3h+yU4i/T24J7bMbXB111M+/CEIym+liaOHMgRijYiqw
         GKtPFRzfZcXRkhjV6Hoj1f3o/1sdLo8FMMDvOI6zqsV9Xy2dOga9RwV4tyUadr6V9uaC
         oIw6DLKNPPUTxmDfY8jZNDKwPyGYSM0vGnxMhCk9xa6EXEX4EYdecVSk3ko2ID3J9Vqa
         rgLho3J8Epncjp3gRsFHKAT4/BgEoa5Q+PNijzFPahmkqiSHcfc9yDyTgVhDchIRZW12
         /hEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aMwJ5hLh;
       spf=pass (google.com: domain of 3srl6xqukcy82t660z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3SrL6XQUKCY82t660z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa4a.google.com (mail-vk1-xa4a.google.com. [2607:f8b0:4864:20::a4a])
        by gmr-mx.google.com with ESMTPS id x12si180638plv.3.2019.12.18.15.12.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Dec 2019 15:12:11 -0800 (PST)
Received-SPF: pass (google.com: domain of 3srl6xqukcy82t660z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) client-ip=2607:f8b0:4864:20::a4a;
Received: by mail-vk1-xa4a.google.com with SMTP id n9so1725058vkc.14
        for <kasan-dev@googlegroups.com>; Wed, 18 Dec 2019 15:12:11 -0800 (PST)
X-Received: by 2002:a1f:7d43:: with SMTP id y64mr3916801vkc.15.1576710730458;
 Wed, 18 Dec 2019 15:12:10 -0800 (PST)
Date: Thu, 19 Dec 2019 00:11:48 +0100
In-Reply-To: <20191218231150.12139-1-jannh@google.com>
Message-Id: <20191218231150.12139-2-jannh@google.com>
Mime-Version: 1.0
References: <20191218231150.12139-1-jannh@google.com>
X-Mailer: git-send-email 2.24.1.735.g03f4e72817-goog
Subject: [PATCH v7 2/4] x86/traps: Print address on #GP
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	jannh@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Sean Christopherson <sean.j.christopherson@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aMwJ5hLh;       spf=pass
 (google.com: domain of 3srl6xqukcy82t660z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--jannh.bounces.google.com
 designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3SrL6XQUKCY82t660z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

A frequent cause of #GP exceptions are memory accesses to non-canonical
addresses. Unlike #PF, #GP doesn't come with a fault address in CR2, so
the kernel doesn't currently print the fault address for #GP.
Luckily, we already have the necessary infrastructure for decoding X86
instructions and computing the memory address that is being accessed;
hook it up to the #GP handler so that we can figure out the address
operand of the faulting instruction and print it.

Distinguish two cases:
  a) (Part of) the memory range being accessed lies in the non-canonical
     address range; in this case, is is likely that the address we
     decoded is actually the one that caused the #GP.
  b) The entire memory range of the operand we decoded lies in canonical
     address space; the #GP may or may not be related in some way to the
     address we computed. We'll still print it, but with hedging
     language in the message.

While it is already possible to compute the faulting address manually by
disassembling the opcode dump and evaluating the instruction against the
register dump, this should make it slightly easier to identify crashes
at a glance.

Note that the operand length, which we get from the instruction decoder
and use to determine whether the access straddles into non-canonical
address space, is currently somewhat unreliable; but it should be good
enough, considering that Linux on x86-64 never maps the page directly
before the start of the non-canonical range anyway, and therefore the
case where a memory range begins in that page and potentially straddles
into the non-canonical range should be fairly uncommon.
And if we do get this wrong, it only influences whether the error
message claims that the access is canonical.

Reviewed-and-tested-by: Sean Christopherson <sean.j.christopherson@intel.com>
Signed-off-by: Jann Horn <jannh@google.com>
---

Notes:
    v2:
     - print different message for segment-related GP (Borislav)
     - rewrite check for non-canonical address (Sean)
     - make it clear we don't know for sure why the GP happened (Andy)
    v3:
     - change message format to one line (Borislav)
    v4:
     - rename insn_bytes to insn_buf (Ingo)
     - add space after GPFSTR (Ingo)
     - make sizeof(desc) clearer (Ingo, Borislav)
     - also print the address (with a different message) if it's canonical (Ingo)
    v5:
     - reword comment on get_kernel_gp_address() (Sean)
     - make get_kernel_gp_address() also work on 32-bit (Sean)
     - minor nits (Sean)
     - more hedging for canonical GP (Sean)
     - let get_kernel_gp_address() return an enum (Sean)
     - rewrite commit message
    v6:
     - add comma after GPFSTR (Sean)
     - reorder variable declarations (Sean)
    v7:
      no changes
    
    I have already sent a patch to syzkaller that relaxes their parsing of GPF
    messages (https://github.com/google/syzkaller/commit/432c7650) such that
    changes like the one in this patch don't break it.
    That patch has already made its way into syzbot's syzkaller instances
    according to <https://syzkaller.appspot.com/upstream>.

 arch/x86/kernel/traps.c | 70 +++++++++++++++++++++++++++++++++++++++--
 1 file changed, 67 insertions(+), 3 deletions(-)

diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index f19de6f45d48..c8b4ae6aed5b 100644
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
@@ -518,10 +520,55 @@ dotraplinkage void do_bounds(struct pt_regs *regs, long error_code)
 	do_trap(X86_TRAP_BR, SIGSEGV, "bounds", regs, error_code, 0, NULL);
 }
 
+enum kernel_gp_hint {
+	GP_NO_HINT,
+	GP_NON_CANONICAL,
+	GP_CANONICAL
+};
+
+/*
+ * When an uncaught #GP occurs, try to determine a memory address accessed by
+ * the instruction and return that address to the caller.
+ * Also try to figure out whether any part of the access to that address was
+ * non-canonical.
+ */
+static enum kernel_gp_hint get_kernel_gp_address(struct pt_regs *regs,
+						 unsigned long *addr)
+{
+	u8 insn_buf[MAX_INSN_SIZE];
+	struct insn insn;
+
+	if (probe_kernel_read(insn_buf, (void *)regs->ip, MAX_INSN_SIZE))
+		return GP_NO_HINT;
+
+	kernel_insn_init(&insn, insn_buf, MAX_INSN_SIZE);
+	insn_get_modrm(&insn);
+	insn_get_sib(&insn);
+	*addr = (unsigned long)insn_get_addr_ref(&insn, regs);
+
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
 dotraplinkage void
 do_general_protection(struct pt_regs *regs, long error_code)
 {
-	const char *desc = "general protection fault";
+	char desc[sizeof(GPFSTR) + 50 + 2*sizeof(unsigned long) + 1] = GPFSTR;
 	struct task_struct *tsk;
 
 	RCU_LOCKDEP_WARN(!rcu_is_watching(), "entry code didn't wake RCU");
@@ -540,6 +587,9 @@ do_general_protection(struct pt_regs *regs, long error_code)
 
 	tsk = current;
 	if (!user_mode(regs)) {
+		enum kernel_gp_hint hint = GP_NO_HINT;
+		unsigned long gp_addr;
+
 		if (fixup_exception(regs, X86_TRAP_GP, error_code, 0))
 			return;
 
@@ -556,8 +606,22 @@ do_general_protection(struct pt_regs *regs, long error_code)
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
2.24.1.735.g03f4e72817-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191218231150.12139-2-jannh%40google.com.
