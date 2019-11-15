Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBWPTXPXAKGQEIIK4K2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 98800FE578
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 20:17:46 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id e6sf7975283pgc.8
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 11:17:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573845465; cv=pass;
        d=google.com; s=arc-20160816;
        b=qismX9xFg4qspXv4vQRflg+0tt8FNr8zqNF8l8MrGIwdznuUV3CymL2bCjdx7cSnJ4
         Tszu8OnG3gUEbdjjIi2Dry9tnPaJEc+BcbBD5qXZB535zl46IcHPf056f8Gy+ZoCw1WN
         eKuntVN1h1mOVNp5by2NqUr5wFsiiYb8tSv0fxvotKiKT/8Kas9mXh+OA0Zz5lEe5RCY
         PgBQCZC4ENRefzY1gB2De/O6e1hzj0IKNFXrL8sLi1IrCgc9ebpOQsvv55u++f+Muacx
         h2bG0EEyzPENdOVHhw0eWlcLC5254RbO9qMx6XXZluw9B8I8VBYFEOX1q6KFK/4r4NUk
         rjSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=DL0df6mU54v+IR/WIjGEsMWLEGt4V4a6HUzUhKvFryg=;
        b=eL5kRwjhzU1b8aIu5JAo3BB/pheWL7yZFEZ+GBw0+7L3iV+j/sI57pIdO2m1QFHQLP
         +c1eaIbajjS+QFvFU4ggAf5PdUBHnsAgCMMSZzYG8k3TpfVEg/acXdKPB3KX2dClhf1m
         Z+zjSjlFjIbyJTsjNnQAltjrOOaxgQ6lfAAfGVSmyXLRSYZwlSsVgD/9wciVInYSEUNW
         LTIC2ar8DSX2d5e6oyVKPIDPjNH0+WXzpWKKxSGypsGETMDGZi64Pd7MaO1dnIiCWXAS
         qpCGFK0dmRa8Bq6qZA8pNxPQZJvuAcYKh0XsqJZE/6ADY9iDr/lwMNbPj7LpQqK68zm7
         6ofg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qCPoUdJ0;
       spf=pass (google.com: domain of 31_noxqukcfolcppjiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=31_nOXQUKCfolcppjiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DL0df6mU54v+IR/WIjGEsMWLEGt4V4a6HUzUhKvFryg=;
        b=lLqK3jXAfJHqQiL7Vv27ebQ7t1n4XA4zhfojj3OLwM7fpp+nWW3gMRE0i6cWTsAIxe
         oap3Xs4QueB23/Qj5lv2sZxEvL6OstBlH+Yxmh7MVFOaza+8BmKCzbbJqmVYq+/Zbv7l
         qExvchXDk5+u4bjVfcy0jN3WzKBGQQ/vbDLylJkHw2hRNEUVlhDH9kZILXJYQA85X6yu
         3eqCoHcfswqTO9odeK9SkqVgAfLZBXx0aP+tWl4iIqego3ZIeJceRBfyRW3i7tMc83TA
         LTFUmJj3nK1j+0dNY+KE1JP1tRRloTeACQCYBLHTJ2n9U+KBbd16gAPeI0a4u/h+CKf2
         dGxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DL0df6mU54v+IR/WIjGEsMWLEGt4V4a6HUzUhKvFryg=;
        b=R3gfZhIWfSahyJ/Ne/Dtr2Hul+c3nBw5jhy7aH0B91wX90tGW8jcGAOkJ+EL4wf+s9
         JtOQGzSc4Ieug+Laq4bvp4DJDcTExAtOcL/89HKJPCALP2tk3JeShmEXUWe4CJ4geAob
         1q/LY1Yp8RAGhx80r8eAgeiQqWQxo7ZPYV2T6BMGkk+qFR8zyWqFN5WYbIS61Yz3eWPF
         K8s4nBfr3KiL60NeSS9Bps+sfdWZEtlJYWmr/5KcjpSNgAYd9PPmTb/32xASgpCkKk9W
         zFF5jb89ZGz/dyzT5CD68XHdfp4wQ9dUqu0Y3eIKAfufGoTmnG9e9oEgy969hRGfnout
         za4g==
X-Gm-Message-State: APjAAAWfF5OX92r0JRoox43ZcHwVY/UNls0amnR9n3JX/fN1C302JHmw
	IVY/hTQjj/Yzq5KVn2j08Tc=
X-Google-Smtp-Source: APXvYqy2BBU1i9pl5AXBWkSPaeKtI5W5FGCYlYDWce4/H/ZeEhWoFulm+m1SZThYYWnxhTIGo++teQ==
X-Received: by 2002:aa7:8e8d:: with SMTP id a13mr18758058pfr.241.1573845465080;
        Fri, 15 Nov 2019 11:17:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4948:: with SMTP id q8ls2007112pgs.12.gmail; Fri, 15 Nov
 2019 11:17:44 -0800 (PST)
X-Received: by 2002:a63:7448:: with SMTP id e8mr3541675pgn.268.1573845464574;
        Fri, 15 Nov 2019 11:17:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573845464; cv=none;
        d=google.com; s=arc-20160816;
        b=qmf7TT7oIQJmSOCRpXrKLLEy7fm9cllyG9wZswjBd9eF2yBM3QYEx2eus4Y4b4oKOW
         Uypld2I7rDfHunExwNJF5EPVe50D4IPbqB9p79fKcvuPyEbTvr436aH5zphUJqLWd3ey
         ujk3Kd2Ttvr0eyVOIyR+8ONbYPoQ4lDYaZfGMxp5IUKzKTr9XtNtShlRjRFA5KQr/h4q
         3emMAPvhdt6PKIoVf+dhGBPwJoBHC4IgIGH5JaMPRCM3q8Shmt/NXvYoZ/P1BZOA8mAC
         gWq+7taE4dNYRjXODzYv9WE4BCEe0za5pAEqIXlvTsIsnNbraJg8oW6IgDz2Sd5+rXA/
         nFDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Z4eVXgHWWbGRrH9BipYQn3sMDOkKflzbIVEAmfiSHc4=;
        b=yR3hjXCOFEXu35K37mMZaHnHgghGGUo3DGDx+fsMYas3zUWcA5ygmiW8sDZ7Erbxo+
         WDZ204wDn0SJ9MSzcl3ViPloHPXYfDTip4P3ZXw9Z+1sJP7FOH0qy05M6Tf9atuVLxVB
         P/9+pWRFcVCknngaBnczp1OlbKsauxIZAGnamTyJYridswxKUZfE68vZqYUI84X8lng7
         t2oKwN41cfFSIFcxkGqhBoCKoJQ2HfUVRJgVb5MDYwMRN8z+qneE02+svlH4SPvieBbw
         x8SHAjdgNTyJ6a1zoS+z34tIRtucjz1W3eH6sna3lwjLCQ2xaz3dd9vtqIfz2RLyZP3g
         348g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qCPoUdJ0;
       spf=pass (google.com: domain of 31_noxqukcfolcppjiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=31_nOXQUKCfolcppjiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa4a.google.com (mail-vk1-xa4a.google.com. [2607:f8b0:4864:20::a4a])
        by gmr-mx.google.com with ESMTPS id j12si139917pje.0.2019.11.15.11.17.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Nov 2019 11:17:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 31_noxqukcfolcppjiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) client-ip=2607:f8b0:4864:20::a4a;
Received: by mail-vk1-xa4a.google.com with SMTP id v71so4560009vkd.16
        for <kasan-dev@googlegroups.com>; Fri, 15 Nov 2019 11:17:44 -0800 (PST)
X-Received: by 2002:a1f:9705:: with SMTP id z5mr9652185vkd.46.1573845463473;
 Fri, 15 Nov 2019 11:17:43 -0800 (PST)
Date: Fri, 15 Nov 2019 20:17:27 +0100
In-Reply-To: <20191115191728.87338-1-jannh@google.com>
Message-Id: <20191115191728.87338-2-jannh@google.com>
Mime-Version: 1.0
References: <20191115191728.87338-1-jannh@google.com>
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v2 2/3] x86/traps: Print non-canonical address on #GP
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
 header.i=@google.com header.s=20161025 header.b=qCPoUdJ0;       spf=pass
 (google.com: domain of 31_noxqukcfolcppjiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--jannh.bounces.google.com
 designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=31_nOXQUKCfolcppjiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--jannh.bounces.google.com;
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

 arch/x86/kernel/traps.c | 45 +++++++++++++++++++++++++++++++++++++++--
 1 file changed, 43 insertions(+), 2 deletions(-)

diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index c90312146da0..12d42697a18e 100644
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
@@ -509,6 +511,38 @@ dotraplinkage void do_bounds(struct pt_regs *regs, long error_code)
 	do_trap(X86_TRAP_BR, SIGSEGV, "bounds", regs, error_code, 0, NULL);
 }
 
+/*
+ * On 64-bit, if an uncaught #GP occurs while dereferencing a non-canonical
+ * address, print that address.
+ */
+static void print_kernel_gp_address(struct pt_regs *regs)
+{
+#ifdef CONFIG_X86_64
+	u8 insn_bytes[MAX_INSN_SIZE];
+	struct insn insn;
+	unsigned long addr_ref;
+
+	if (probe_kernel_read(insn_bytes, (void *)regs->ip, MAX_INSN_SIZE))
+		return;
+
+	kernel_insn_init(&insn, insn_bytes, MAX_INSN_SIZE);
+	insn_get_modrm(&insn);
+	insn_get_sib(&insn);
+	addr_ref = (unsigned long)insn_get_addr_ref(&insn, regs);
+
+	/* Bail out if insn_get_addr_ref() failed or we got a kernel address. */
+	if (addr_ref >= ~__VIRTUAL_MASK)
+		return;
+
+	/* Bail out if the entire operand is in the canonical user half. */
+	if (addr_ref + insn.opnd_bytes - 1 <= __VIRTUAL_MASK)
+		return;
+
+	pr_alert("probably dereferencing non-canonical address 0x%016lx\n",
+		 addr_ref);
+#endif
+}
+
 dotraplinkage void
 do_general_protection(struct pt_regs *regs, long error_code)
 {
@@ -547,8 +581,15 @@ do_general_protection(struct pt_regs *regs, long error_code)
 			return;
 
 		if (notify_die(DIE_GPF, desc, regs, error_code,
-			       X86_TRAP_GP, SIGSEGV) != NOTIFY_STOP)
-			die(desc, regs, error_code);
+			       X86_TRAP_GP, SIGSEGV) == NOTIFY_STOP)
+			return;
+
+		if (error_code)
+			pr_alert("GPF is segment-related (see error code)\n");
+		else
+			print_kernel_gp_address(regs);
+
+		die(desc, regs, error_code);
 		return;
 	}
 
-- 
2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191115191728.87338-2-jannh%40google.com.
