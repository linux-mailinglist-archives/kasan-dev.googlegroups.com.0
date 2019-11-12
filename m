Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBON7VTXAKGQEL5CXNSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 47E92F9B7A
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Nov 2019 22:10:19 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id m7sf9983444otr.12
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Nov 2019 13:10:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573593018; cv=pass;
        d=google.com; s=arc-20160816;
        b=lzZF9iQSl/XMj+BhE1/xfg8a1nvcjiumX7HC1AkBejWm2loeA1+C8HFDm/wpDlpPy8
         inwtuPFoAHhBLyeY6zC6MHmiGO0rpOgHJlvtw+zpDk0rscbnMjY9jkZ8bEQhzEvLU4CJ
         PLq1Ti2dWpD92CW6uVd1sjXHaElpz7MiJS72ZSJZs+ghsBERvx9jZYTgllcPk43MZMKA
         m5v0yL6RAS7vZgliefRR4qXy7BHdfVxFs47d48MID+jG49lFB8MNC77QLaYpRb/Re99L
         sBELs0qp1UXCOOrhdye/7A3NFBwwMc4epxpUL5vtwaQBaqDwsz1NWEMupn5H5QqKTs1U
         47eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=18StaGfPuU/9+toazzdIX5wezYO78yygDzt6l0+fUb4=;
        b=DG+NVI3cxGBzQzmqF4pXasU3Id+8vwapaJr/30xGyGGf2tFILstZ+5RoCdafqinUlm
         wnlylGmZ7M05I1YWfzH+xSw8CyN0dWXqO4gLyfwzxj0XjK+Ohbuxbk6rTEiSU5nhV9Dr
         3SxTkuAWQgDQQk4N9AxFyHOb2S5a/1kMRzZ/9qAyS6g79dfLYpFkh3Qw5Oqe19Dvos11
         beYWAfd/34oygiMTNI6jmBslSa2ZP2a9QcKpL7ISE9LAkoQ67MWSIyYseIz1Om1BD7kG
         WbxHJnt1yZrTjV/1Kk9G+jl5u/b7inU9HG7CMnMiJAEyNoluvAr5z7pVdymjeEkLGBzs
         1HTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kh9kwelf;
       spf=pass (google.com: domain of 3ub_lxqukcrk8zcc65dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3uB_LXQUKCRk8zCC65DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=18StaGfPuU/9+toazzdIX5wezYO78yygDzt6l0+fUb4=;
        b=iIxMD4QkQQU6gx4bklQpxUPPSn7NzDV0/vcyrXTBn+PNyNgEwDhNnEEx8MP3l5O8JG
         n02MHGyjFt6VyIjFUPxsXTYtLp7Ff88zu6GhYvPA005ij31Vou80YsV5FgeLqjZ3Yi3Q
         uKcmWZETTTA88oHogTrua8Cz4PhTBlCmjU5OlPgNFJ+FBulCPIUC326IX7CHV+nKs5l9
         seH4P/Ae5LuMIYLy+x9ZuBBSCm4iVla90IuqiiZsoQj6gkEslHkk1mqo8GGtCzrjOewV
         rwTNOalelSqmaDv2A1L8XjeDI8WWP9L3ZahjPthkwmxqDQrfMicUlTeH8sNAb2/QPzGc
         E+bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=18StaGfPuU/9+toazzdIX5wezYO78yygDzt6l0+fUb4=;
        b=KdbGxif4184e4M4fxh4eLvScYERvRKTsPR2x+tdqUAtPvkAy/jezbbNu4GKBkmE+Kz
         IZ0rrDXA/rJ4YK9VbYkJ0rpHKXqx02Rk+sI07DpNLbDgCcPXYmK8jGjF52XKi/i2U8Ar
         c+V9GeHikkVPNH9we+eJzqTwDmuOyOF3OZb08O/eVWHzHywieWo/b2SvScVZD+RnHt/r
         kC/ehfwDyZyfF0tt7xtz8Dlir0cRM3UMJO6lr/AK+q0FYbOridBgzFyNZR7AAmWqELH4
         8OwMbnjISa1nnOR8D3sWSoKRtxyfhjPmT5TE1a9k0YMRWTknG0H3T6ZfPlTBXX9d8LCi
         FG0A==
X-Gm-Message-State: APjAAAWz80LbWCBnPTIQCMudJ6KDIn0bLysH/jr2ZnaGkWFbGiAzHbQr
	G95n7Nk+95fraOHtvYFhCic=
X-Google-Smtp-Source: APXvYqxQy+InXykASk/dRztbcqzYNMsKDx4xfrSxN40gYWt9Bab8KIxAtBC8Xbpybqw9aR3NIjsNfw==
X-Received: by 2002:aca:d8c5:: with SMTP id p188mr896538oig.140.1573593018041;
        Tue, 12 Nov 2019 13:10:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d1a:: with SMTP id 26ls3583137oin.7.gmail; Tue, 12 Nov
 2019 13:10:17 -0800 (PST)
X-Received: by 2002:aca:ef04:: with SMTP id n4mr969248oih.104.1573593017611;
        Tue, 12 Nov 2019 13:10:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573593017; cv=none;
        d=google.com; s=arc-20160816;
        b=UppXQenECTFnKUxnwwiDu6iAb3WN/3oOdtOLdkuppoqIKZT1ELkkHqriF8NNjYXMgY
         Cxwu8wM9XgAyHMihlHNyhfqSXtZVXFj/UjMHJOcjLFVKUI051glIosVmWYlaE9Uxk6ab
         snaUNatinwt0BxRjLjH8kFBXij6alKz/aNG1GI0OIYTT5M1z39fxdPT8eSv4fs3jQQ5f
         6PAnkvWVwKpwffuKMVcx9rpsg4wMnVsA0O8GB/KJk81Wt7Zbh0mMEm1gxqj/WSO61w54
         z3PfLvg3MADPV9UMlTbYqERZ3762AjAWZGeDNXG/rS5x7WZ27/q9XZvm3pVfYvfI1i0T
         w7Qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=QkH07eQfCocHLYn4Bb98KVzxf8ymHQPYHARKfS1aqN8=;
        b=sGDuh5YCKg1k1T7cdHUU5Tf9zvX6dVOziWlEnEB0VBqUQ7BNdKwTc17vEuDYbB4UN9
         Kg65JGyl2pDUXWiXFBfHJ1owdOByBl+z60dsv5b4B30p9lBATDF+Lnv74kA7BwTd8RXW
         RqYniff94JTj8a0U2ff0VZjjnBvPk4ToGqusIqcaDmfA4IuWCmkRo2ZvZrLODaK2xqAw
         QasnU1T9kXQdr4UAxRWllvMEyLarpSq6r/wPbb1vdMIun0h/KrMVdWKqXu8oiAaOZ8de
         jgxy/qnGIBZUSDN/15B2FhRk2PZNFlNDzC62ikvtUPtXLg4u5hXYpSw9sIH+g0bAfD9s
         D+bw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kh9kwelf;
       spf=pass (google.com: domain of 3ub_lxqukcrk8zcc65dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3uB_LXQUKCRk8zCC65DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id l141si907415oib.4.2019.11.12.13.10.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Nov 2019 13:10:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ub_lxqukcrk8zcc65dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id 22so11657947qtw.10
        for <kasan-dev@googlegroups.com>; Tue, 12 Nov 2019 13:10:17 -0800 (PST)
X-Received: by 2002:ad4:57a7:: with SMTP id g7mr30793924qvx.30.1573593016932;
 Tue, 12 Nov 2019 13:10:16 -0800 (PST)
Date: Tue, 12 Nov 2019 22:10:01 +0100
In-Reply-To: <20191112211002.128278-1-jannh@google.com>
Message-Id: <20191112211002.128278-2-jannh@google.com>
Mime-Version: 1.0
References: <20191112211002.128278-1-jannh@google.com>
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH 2/3] x86/traps: Print non-canonical address on #GP
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	jannh@google.com
Cc: linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Kh9kwelf;       spf=pass
 (google.com: domain of 3ub_lxqukcrk8zcc65dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--jannh.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3uB_LXQUKCRk8zCC65DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--jannh.bounces.google.com;
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
 arch/x86/kernel/traps.c | 45 +++++++++++++++++++++++++++++++++++++++--
 1 file changed, 43 insertions(+), 2 deletions(-)

diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index c90312146da0..479cfc6e9507 100644
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
@@ -509,6 +511,42 @@ dotraplinkage void do_bounds(struct pt_regs *regs, long error_code)
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
+	/*
+	 * If insn_get_addr_ref() failed or we got a canonical address in the
+	 * kernel half, bail out.
+	 */
+	if ((addr_ref | __VIRTUAL_MASK) == ~0UL)
+		return;
+	/*
+	 * For the user half, check against TASK_SIZE_MAX; this way, if the
+	 * access crosses the canonical address boundary, we don't miss it.
+	 */
+	if (addr_ref <= TASK_SIZE_MAX)
+		return;
+
+	pr_alert("dereferencing non-canonical address 0x%016lx\n", addr_ref);
+#endif
+}
+
 dotraplinkage void
 do_general_protection(struct pt_regs *regs, long error_code)
 {
@@ -547,8 +585,11 @@ do_general_protection(struct pt_regs *regs, long error_code)
 			return;
 
 		if (notify_die(DIE_GPF, desc, regs, error_code,
-			       X86_TRAP_GP, SIGSEGV) != NOTIFY_STOP)
-			die(desc, regs, error_code);
+			       X86_TRAP_GP, SIGSEGV) == NOTIFY_STOP)
+			return;
+
+		print_kernel_gp_address(regs);
+		die(desc, regs, error_code);
 		return;
 	}
 
-- 
2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191112211002.128278-2-jannh%40google.com.
