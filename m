Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBRMX7TXAKGQEYGO6DCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 55DFC10C0CE
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Nov 2019 00:50:30 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id y125sf1767762wmg.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2019 15:50:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574898630; cv=pass;
        d=google.com; s=arc-20160816;
        b=W4KTfhnAyRmmu5pAQ48dXcCecPKg1Me39T/cg98lh54zlu13JrCqpk2eFCQq4UkbfD
         nnDNuaY/wHcyUM4yHVjigKX8sKpKB/NEOSCMlP4349NTYgKmh4BcTDCEUmD6KZe8EzOv
         NQ2f9Lkw+ZpUS2PfGdKAtWnqLxO95sSE5jO/Bf2eoTL8GnzfjMuTEj2GdxNWzQM2emuo
         F/EHJPKrA3Wm777V/EJYeWTN4SrFkDlYbadXKTW51eSKfh4GbcHldT9vOJAdG3kCk+k9
         18H3TlvGeKDR4gz1Cs9ad6f4GXpQfUvj+pmDSf2y00GVGvJAScNrqEybVVuIpX92/cSP
         Cqyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=8WPL6zcMG82KOUfIpsCHzjAoMOPa4M2+RXwBU3JHwco=;
        b=T7PPQkzJEVZaIAAhMxQ9lUJmiLLVBcLZ3F9YwYwW5hOWTywrtg87AFmM2in+OXjBw0
         xRfRkVJIn5OzKvYZJVr9uRkMFLfwch0QmI5DBxsfHelhdhmS7ztHf+HsRROLDHJBoJ7H
         GdIb3SWE1qYS2kg6As3RKt0UvXvFd+7zVeJ0wJepS2AkfX3MlPSSUb6rFKDiF51m6+IQ
         rq1eSkdkdzDU8wUVU81qr6hsMUUR4zB0wN+YgGltQHAc86Zj6PTNuQ+ri2H4FQQu2ne2
         qqNPuopzfFVFrVx48v23B1Y2Wkfk6DSLMUE2aUpTNOdxL1RgZIpjbttY4MV82oKOOZ+j
         D1RA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="AU/zJR+y";
       spf=pass (google.com: domain of 3xavfxqukcu0yp22wv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3xAvfXQUKCU0yp22wv33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8WPL6zcMG82KOUfIpsCHzjAoMOPa4M2+RXwBU3JHwco=;
        b=olrIW95MNMTbTGBoQitBdgm2F7P83koAs7/4l1s3QzQMA5GTS8mrY0TFv+n4L0W5Q5
         NXszyRlMtCKUjthMR3WGzRrzk8UxYGwYkub6BI0jGlv0ff9Xw28DuGGoar+7vDKee39U
         EvO5Rz3yaef9sTo9Zl42qCT64LPPvhC0kTuhL9sV51nTAxTnY6aGGgszQIF3IedmXsyI
         fPGQdOxk1cHKI7zHmw/4UXTLqnoR4n9Yasmpzzi7CvUsBRHzzA/8sWUodD65nmCrnJw+
         8VZEQYW3C+/wOMgjzYzoDc8PcAySI/hewu/WC9f/55lMEnD09Ld/4vAKltGQTHxDQBGo
         pb5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8WPL6zcMG82KOUfIpsCHzjAoMOPa4M2+RXwBU3JHwco=;
        b=UOmjndVnV8ZPBDlCauL8fZTucbc3+8ldaeICznDW8ygmewqbGZoHbfIGAkjRmkfKaB
         e3ysnUu0NgLwEG8Zk8TkAz4EDIeFZKzXeHEK5myHwII8GaCJ/XnTEU54i7kj7FdqzPJt
         UQE96dBjRFEBxpgSd/UQwUdpV6+HT+O9Ar80YhHCf1hsEUdrHt7q8fBXim1WlEKxqV6i
         Ziz9tkMDenuAw/VUr8w8DvG1BoUqjLXzgh3AnQ7HS386ZXOAqbyrcNyuWcLuwOJ/gb1+
         THprakRnhPTRi2J2f4qXr8f7+U9kuu+Sg4ki2t3qHJIYoNEq3He43QJErR97cG8DxFq6
         s76Q==
X-Gm-Message-State: APjAAAUHe0ARhCf4H/Lq7SIJC0tOs4RycNmqmXr8wInG0xwJF9vWRsOt
	TyYjtExb15o13URKQWUTKqA=
X-Google-Smtp-Source: APXvYqwo2BzCpFmwqmZSEMsP8PEWO1NoEUjzxzagQtFjqiAMKkUmWuxtrtjbLum2EcEJrkvq+/1rkQ==
X-Received: by 2002:a05:600c:d5:: with SMTP id u21mr2259707wmm.85.1574898629945;
        Wed, 27 Nov 2019 15:50:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f10c:: with SMTP id r12ls10630071wro.11.gmail; Wed, 27
 Nov 2019 15:50:29 -0800 (PST)
X-Received: by 2002:a5d:480b:: with SMTP id l11mr2383684wrq.129.1574898629444;
        Wed, 27 Nov 2019 15:50:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574898629; cv=none;
        d=google.com; s=arc-20160816;
        b=HBeWZ8qFe6x1YQJBbL0aoNqLb/7SfexYJA+ZftLseQVl6UMjhEJePPCzTwVMBaH/RP
         CfihLlz45RlKqYgiNPCI+o1QylSExWTBnqe7I2RZ7j7rTa04OpqI5FNffusMJms6ubw7
         uEqYFMXzMLzt5aSb9vMkW2tf7loS4gZZBk6ix11MzZqp0vsUisTVW7v7tRQzxG+XJ6dO
         IolvRdsFDjgSBIrtKQHYKBrJqR7NSlz94Q0GkIixHqbHIH4UOYlkboOH3OS862Ml7DHF
         b2YXPlnTn8kHTkvoGujrJ8vB4ixbfMXxajhTRMWmiTBca/6dQJQx3iauoJiaGBBl+YUT
         bsSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=QATXnoiDKCWC3WWAdN6sdIHlK8jnCgnJfnHnydMklE8=;
        b=yoaesQADlK1mXW81H8cIdAtjqWY30rgq9B1YSntKC0KI3LWgKM50tGhvg7qDvFZV8j
         xVCDC9mx7spuzIxB498l3CB/M3t8+xefVFjCUshq3LTVNDfn7xUJouw45HFFBR3wXvqJ
         zslM28GTnz8slyKRyLc/i4gtpqHIDCcuJYMqR2jWrx7RKZyJp+DUFVk9QgdbhW985eag
         UbU28YuUWkeobbcxrV0r0MAEHjV+UN3IpCWjCUVB+EggUBzTwUY8BR6n0RC6BASYl9im
         n+g4m2eT3QmYcitemqoHXlMdjD1SSN2xB7LgFW0fK2/nBO8VBzY8NvWApyY5b5gncNTs
         fWlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="AU/zJR+y";
       spf=pass (google.com: domain of 3xavfxqukcu0yp22wv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3xAvfXQUKCU0yp22wv33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id w6si445833wmk.3.2019.11.27.15.50.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Nov 2019 15:50:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xavfxqukcu0yp22wv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id e3so12873559wrs.17
        for <kasan-dev@googlegroups.com>; Wed, 27 Nov 2019 15:50:29 -0800 (PST)
X-Received: by 2002:a5d:6802:: with SMTP id w2mr1851016wru.353.1574898628777;
 Wed, 27 Nov 2019 15:50:28 -0800 (PST)
Date: Thu, 28 Nov 2019 00:49:14 +0100
In-Reply-To: <20191127234916.31175-1-jannh@google.com>
Message-Id: <20191127234916.31175-2-jannh@google.com>
Mime-Version: 1.0
References: <20191127234916.31175-1-jannh@google.com>
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v5 2/4] x86/traps: Print address on #GP
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
 header.i=@google.com header.s=20161025 header.b="AU/zJR+y";       spf=pass
 (google.com: domain of 3xavfxqukcu0yp22wv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--jannh.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3xAvfXQUKCU0yp22wv33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--jannh.bounces.google.com;
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
    
    I have already sent a patch to syzkaller that relaxes their parsing of GPF
    messages (https://github.com/google/syzkaller/commit/432c7650) such that
    changes like the one in this patch don't break it.
    That patch has already made its way into syzbot's syzkaller instances
    according to <https://syzkaller.appspot.com/upstream>.

 arch/x86/kernel/traps.c | 70 +++++++++++++++++++++++++++++++++++++++--
 1 file changed, 67 insertions(+), 3 deletions(-)

diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index f19de6f45d48..9b6e4d04112a 100644
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
@@ -518,11 +520,56 @@ dotraplinkage void do_bounds(struct pt_regs *regs, long error_code)
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
 	struct task_struct *tsk;
+	char desc[sizeof(GPFSTR) + 50 + 2*sizeof(unsigned long) + 1] = GPFSTR;
 
 	RCU_LOCKDEP_WARN(!rcu_is_watching(), "entry code didn't wake RCU");
 	cond_local_irq_enable(regs);
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
+			snprintf(desc, sizeof(desc), GPFSTR " %s 0x%lx",
+				 (hint == GP_NON_CANONICAL) ?
+				 "probably for non-canonical address" :
+				 "maybe for address",
+				 gp_addr);
+
+		die(desc, regs, error_code);
 		return;
 	}
 
-- 
2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191127234916.31175-2-jannh%40google.com.
