Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBO5O2TXAKGQEHWSSI6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 72C0B1037AA
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 11:36:43 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 2sf4899575wmd.3
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 02:36:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574246203; cv=pass;
        d=google.com; s=arc-20160816;
        b=GoXL0K9Mt0gCg2WW6i1HJSLvXoQDIlNTqXTxdCKFPO9l7wMWdCKyWK5nH1z01cx7CK
         HA9gb8680bIIHQuSG1Jbmb8FUcgpsb5Dl+3b4uTZwXh9sGSogq/OaIO6Lvo0hOTMqfbv
         VP9e6XFZUU8bpG91m7/ig4dgbtimhaBEZSvUF2IIQE3+KogQB9rWXhG28x5hXsDsEaad
         Z6x1/4JS5C1T5CvwojWeIqJ7S9mpqzcx7Tg3nCeTOz+Clkeng4zEDiWOOOWVbMUSxvdg
         T4BdG3R0d/XJLpieo5mImek6VNOyN8ge43C/FuylvL0pybKyZVV1LNpRKJj1gxefre2t
         6w+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=oJxUFDCliFGXqWgm6NgH6PT031kFbAwD/OGNDe1+QyA=;
        b=WDtzX43AyummboXl2S6HXeaIGgrFlwQWv4e0AZ+x7LRbgKmgnfeDGO104uFNqbvBTi
         Ex7hP2XHu7s247JWunbqw/uEvxc4Ol919o0eayW5NaxqqhFJMg6l95vWEYewN9bcG/os
         hlGWl1s/w8Mgcg5gTMlxvfsPSAYFZ0YYw9xDoKlRmmONaUphQGcwIZqlCV1IeuLvpmvw
         O5w5bxShTY3QUrji7NMxMB+n3Mbp/cSk/x1gYI4wpX/UwfESFZQ9WXyOtw3O0ijp5E6I
         ThPCB7cVqtGsNghp4m7UEafFYHO+cszdzoHzlswxUuI7khwpQznXrF1LScHnSkZqpdOX
         Fw1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=un18xq5O;
       spf=pass (google.com: domain of 3orfvxqukcbazqddxweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ORfVXQUKCbAZQddXWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oJxUFDCliFGXqWgm6NgH6PT031kFbAwD/OGNDe1+QyA=;
        b=mZr7HP//HqhVLEWuu364xscVqJBG1Po7rtYdbHzX5kSgnnkJVfQUaz7ItmTymfedgd
         xCxdFeJVb3HPCa1ohSP6w4IlX7LNJncTcqKdN2Di1LErt1lC/IYr1efnnkA+MAWHIIlG
         WKULKH92+l4oM597BzhIjYZbFbtc3Stn6kQU/Na2ctRpuxKzuPqhpkWcxw3SA9boLynp
         Uqd0X7zz8TOOaQOAmwi0go6DQ8wFb19ftwDH0TT3aByPOkf2tLjxhZjA7x4h2R4Yic4M
         MF0I9Sdg6qB0dDn/T5GRmErc0Hg2NAe+83MBN8A6rdwvWzkDjbg8gWderPn0j9ORZcCw
         +eIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oJxUFDCliFGXqWgm6NgH6PT031kFbAwD/OGNDe1+QyA=;
        b=sPxsZgT/W00Ze9ZFpwUPA/FIMapqLtfTdrVO+GhSxqrsUZLfcQ5i9Q4YJO5hC4Cfou
         pGMg3lJ0pXq6mvumQxGpLWRIlzRlDWuMp+GyyUK+H2aeenXr1JXNrkdpcwvQIcUfiA6h
         ViKSuCPT6oq8YlAmIDicmzfZmu91AqBHlPE4/s/GLnY1irexvFVN7abhNwLRUlq7hVDN
         IsCLGgFJafP1xuAKgFcndzh1MmqfUk6bz5EN7hxnS0Vyy6eftaOwMUSlKbbSehJb5kHT
         Rm8ejJmHZZMgmmQwno57D5u4Q9neDzasCqp7WvcCi2Uz1bMj8u86Jih/pQ5Ba9jDN7od
         Kp5Q==
X-Gm-Message-State: APjAAAVFDISu0w/x9x9DTn1El4W7Yjepz3rfeBwn0m7dyllPkbEvZGv8
	LA7JL+wOedfgXLFB+vwGcoQ=
X-Google-Smtp-Source: APXvYqyMcipL2GD87zLg/y0kUBh+PhUyLbqFdBwohZh38JLgnfWDCMMqfCEthzIWGlYwr1MaITwjqg==
X-Received: by 2002:a1c:28d4:: with SMTP id o203mr2310368wmo.147.1574246203094;
        Wed, 20 Nov 2019 02:36:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c941:: with SMTP id i1ls615503wml.0.canary-gmail; Wed,
 20 Nov 2019 02:36:42 -0800 (PST)
X-Received: by 2002:a1c:740a:: with SMTP id p10mr2276878wmc.121.1574246202561;
        Wed, 20 Nov 2019 02:36:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574246202; cv=none;
        d=google.com; s=arc-20160816;
        b=nrMwCYdXiO6OGz4U4AYmNz7HzQxK9z+/Fvx2l3QKbYePi0kIf86gNk21b8KRfPd0O3
         0GhZx2Bc1yw0UwPs50e8R8Tk5qDjht7kXGAbm8GOTjU5S/OFSfKBatCK0lKzREE/7CDZ
         OADnd7/l79Jocpie2RDFq4b7kXvbUYyy8RhidZQRCXpJ61m0dCz9Y1P0G7lLXe+pAFyc
         2Y952C45g3an0mReKKPED22tkW8yIW1siG/DrGknLFBe/0jHocmb4rPt4Xz2G7/Y+rmz
         +AUSxhtqE89hzm+W/JfPpL0nwnWrpMHmVMKVR29Z5ZhLFlfwyhUMR+4F6QpXpq9HIMYW
         wkuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=DuYnZAR8MB1c63ohOHf4MauzqJEQWPTDR3HCqzl6rd8=;
        b=H4EX7SSjdnvd3Vbkqk1smAdck0HQJZXYT8RT+EjB5zSewxnQwUInNs8m5AMExRWTzU
         18tY+cI/TkCk8nMeJeIDKJIhrOg/jyWZImYtSgucXe9EPIA9mQ16ePG6AiI+h41GrxGz
         vl7po1U3ugTmIlodb99Y6VTycQsQ6qU00fDXQ81J6lAeaM/4brNEbkfGnjYaFcIkISZj
         EUGCfT0iTcNqNuA/oPiYfSr9Axeu0raoEzntuabIIHcOTSSM74DcX/bzi1eDxDSTWkqe
         Zmkk8SG02ZqvvQLz/xOKdioANbJ9YBJEchwMBm5k8n73sbVj1Xv/twuXE2e1NyqBEMr1
         57ew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=un18xq5O;
       spf=pass (google.com: domain of 3orfvxqukcbazqddxweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ORfVXQUKCbAZQddXWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id w6si290537wmk.3.2019.11.20.02.36.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 02:36:42 -0800 (PST)
Received-SPF: pass (google.com: domain of 3orfvxqukcbazqddxweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id q12so20936143wrr.3
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 02:36:42 -0800 (PST)
X-Received: by 2002:a5d:522e:: with SMTP id i14mr2529588wra.27.1574246201957;
 Wed, 20 Nov 2019 02:36:41 -0800 (PST)
Date: Wed, 20 Nov 2019 11:36:11 +0100
In-Reply-To: <20191120103613.63563-1-jannh@google.com>
Message-Id: <20191120103613.63563-2-jannh@google.com>
Mime-Version: 1.0
References: <20191120103613.63563-1-jannh@google.com>
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v3 2/4] x86/traps: Print non-canonical address on #GP
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	jannh@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Sean Christopherson <sean.j.christopherson@intel.com>, 
	Andi Kleen <ak@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=un18xq5O;       spf=pass
 (google.com: domain of 3orfvxqukcbazqddxweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--jannh.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ORfVXQUKCbAZQddXWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--jannh.bounces.google.com;
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
hook it up to the #GP handler so that we can figure out whether the #GP
looks like it was caused by a non-canonical address, and if so, print
that address.

While it is already possible to compute the faulting address manually by
disassembling the opcode dump and evaluating the instruction against the
register dump, this should make it slightly easier to identify crashes
at a glance.

Signed-off-by: Jann Horn <jannh@google.com>
---

Notes:
    v2:
     - print different message for segment-related GP (Borislav)
     - rewrite check for non-canonical address (Sean)
     - make it clear we don't know for sure why the GP happened (Andy)
    v3:
     - change message format to one line (Borislav)
    
    I have already sent a patch to syzkaller that relaxes their parsing of GPF
    messages (https://github.com/google/syzkaller/commit/432c7650) such that
    changes like the one in this patch don't break it.
    That patch has already made its way into syzbot's syzkaller instances
    according to <https://syzkaller.appspot.com/upstream>.

 arch/x86/kernel/traps.c | 56 ++++++++++++++++++++++++++++++++++++++---
 1 file changed, 53 insertions(+), 3 deletions(-)

diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index c90312146da0..19afedcd6f4e 100644
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
@@ -509,11 +511,45 @@ dotraplinkage void do_bounds(struct pt_regs *regs, long error_code)
 	do_trap(X86_TRAP_BR, SIGSEGV, "bounds", regs, error_code, 0, NULL);
 }
 
+/*
+ * On 64-bit, if an uncaught #GP occurs while dereferencing a non-canonical
+ * address, return that address.
+ */
+static unsigned long get_kernel_gp_address(struct pt_regs *regs)
+{
+#ifdef CONFIG_X86_64
+	u8 insn_bytes[MAX_INSN_SIZE];
+	struct insn insn;
+	unsigned long addr_ref;
+
+	if (probe_kernel_read(insn_bytes, (void *)regs->ip, MAX_INSN_SIZE))
+		return 0;
+
+	kernel_insn_init(&insn, insn_bytes, MAX_INSN_SIZE);
+	insn_get_modrm(&insn);
+	insn_get_sib(&insn);
+	addr_ref = (unsigned long)insn_get_addr_ref(&insn, regs);
+
+	/* Bail out if insn_get_addr_ref() failed or we got a kernel address. */
+	if (addr_ref >= ~__VIRTUAL_MASK)
+		return 0;
+
+	/* Bail out if the entire operand is in the canonical user half. */
+	if (addr_ref + insn.opnd_bytes - 1 <= __VIRTUAL_MASK)
+		return 0;
+
+	return addr_ref;
+#else
+	return 0;
+#endif
+}
+
+#define GPFSTR "general protection fault"
 dotraplinkage void
 do_general_protection(struct pt_regs *regs, long error_code)
 {
-	const char *desc = "general protection fault";
 	struct task_struct *tsk;
+	char desc[90] = GPFSTR;
 
 	RCU_LOCKDEP_WARN(!rcu_is_watching(), "entry code didn't wake RCU");
 	cond_local_irq_enable(regs);
@@ -531,6 +567,8 @@ do_general_protection(struct pt_regs *regs, long error_code)
 
 	tsk = current;
 	if (!user_mode(regs)) {
+		unsigned long non_canonical_addr = 0;
+
 		if (fixup_exception(regs, X86_TRAP_GP, error_code, 0))
 			return;
 
@@ -547,8 +585,20 @@ do_general_protection(struct pt_regs *regs, long error_code)
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
+			non_canonical_addr = get_kernel_gp_address(regs);
+
+		if (non_canonical_addr)
+			snprintf(desc, sizeof(desc),
+			    GPFSTR " probably for non-canonical address 0x%lx",
+			    non_canonical_addr);
+
+		die(desc, regs, error_code);
 		return;
 	}
 
-- 
2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120103613.63563-2-jannh%40google.com.
