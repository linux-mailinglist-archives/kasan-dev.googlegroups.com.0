Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBH7D2XXAKGQEFQUIVZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id BDBEB1041A7
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 18:02:23 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id s26sf223643edi.4
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 09:02:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574269343; cv=pass;
        d=google.com; s=arc-20160816;
        b=DXodIZ/XJWVGII0xUbzmm95Is2rauo+qMmQaEMWi89kA97KIehHBsTE+UM+oKnUoOV
         KKZXLO0vc3AODvCAyWLJe95An1cGkLrLApl8N+VwHBbSACbaMlhog+02vX0LPxyL6icE
         FFv3Hzjy1740VEcN5Rlpt8oCCFKkOjalP4m/RVAgwbTkGP14D44zBMJmSzgppJwPsOTn
         qhGQGlGqsVWDZe26369LWzNjVqFZdPDgQOYH+UeqAJAoy0JGT2AexOh/0J1PU5PFdeu2
         B3hJ/PLJwdXIpyHYC1Egx5sA+w0NdvX6ctQN3ePqs5kCxGszkWoFnEA7Sq3VDT4qB6bW
         xMOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=wvZKc/OpOOp3dXmsftBt7tvKwNobeEI00/kmotdo9bM=;
        b=NVa12S4/npXLeE3Tfoe4E/TJ8yd14nOQcED3afTiTRJQlt7BWYkXz167f+0kpFWHWM
         zWiYVocia8sizaJda+u/wGm92k2iZ7RUNZ76fW+D9fPvz96+K6JlkKs5/k2TMKmzUA+u
         g0c3KkxfVZUaL09ExpgbcRVKqPTLWU0WU53nHa9s0sWOKjP2ShalnSruNTDA7ae3T6Fz
         5XEGDeG9qy07nACNUfywM58ExoNnTg/Q9mtPzy7WmCO8i1VA2LyaPedr/+XexZY3EdAO
         DQk+KlYc58fvqJrAQgBUU7F8DaloNorrDx6oiEzh+JjJxA39INQDWG6yhH0hW2sat7WU
         DgdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wG3Vrn8j;
       spf=pass (google.com: domain of 3nnhvxqukccs0r44yx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3nnHVXQUKCcs0r44yx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wvZKc/OpOOp3dXmsftBt7tvKwNobeEI00/kmotdo9bM=;
        b=WKl5BME9PjjhKucOsosM0F0/uEzi2rP/oMhtPHTTmtah/rz0lyVcq8EW4dBXDr97Bc
         C+z0gQfUza7oVAMxD5tkO6yy1l6aOy/m+j4fJ8Nprg16fBjSEEqf5c9Y8W0mtx1lYbEQ
         /tB4Cu/zCXTEopU6PhEqO+AeWwT1La2u9WqdI6tJr1zdHQSJa4G9VXGmQjnVYaKVqy+I
         wcn3UEvaB+V89BG12pyLNRTNYeFWYNNkV2fbcjSXhlXL9rueTfaLlu+fEEXNl6zLaLX5
         CAqN2LLFemT0/3B1zxl7wK0jSKx7U8yMrIbgtiJWf8lpNSap4VAnpDIlXMMu2o6pp97i
         lGGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wvZKc/OpOOp3dXmsftBt7tvKwNobeEI00/kmotdo9bM=;
        b=svhXQbmd5PzeH7Do9rC0hVo2dLzVO1DwQ3Zp4UUqDwgOoPZH5nnWAuzZzIe7c3EjED
         ZUW3my7OJQNBy+nNQEQCGgOm126GRmttt1RqXF9lHVhGlXjbl0DB3T0o7gy+zU7zr0N3
         zhkkXvbIyE4AgSZIIXRlhOFNRmGPloceLR/43H2bPPnlcmXD+r8d2+BTDDRKWwnW5CDy
         ff5ypHcM3lalMnQR3ryeVvJymS5sz8GpAnIRvya3GHELuVZFPaGF/1ZaO6DDPaT3WlRL
         VIemEWLIBZ3erf8EHuAbVORY6ERuJrRl2T5dkD5mgFEreAIg0/ucATiArT5i8W6TGeo8
         DjGA==
X-Gm-Message-State: APjAAAXfPcz+p+pmrXLPYmUEA2PwR4FicAL24qPr06rQS16B1oBWl1LL
	SLIx3nTTfvPjcZpDwh02WBo=
X-Google-Smtp-Source: APXvYqx5M24I2yQsKWKKf38+xiRD4NbkZwnJyg2eXf5TLsFHggU7AvUCIUCAktoz7dFyb50XJ6o/iw==
X-Received: by 2002:a17:906:27ca:: with SMTP id k10mr6336580ejc.242.1574269343395;
        Wed, 20 Nov 2019 09:02:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:115a:: with SMTP id i26ls1370758eja.12.gmail; Wed,
 20 Nov 2019 09:02:22 -0800 (PST)
X-Received: by 2002:a17:906:24d4:: with SMTP id f20mr6771812ejb.182.1574269342732;
        Wed, 20 Nov 2019 09:02:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574269342; cv=none;
        d=google.com; s=arc-20160816;
        b=EQsG0xMkcNMPfB394h1CPVFjTiRwODReOe76nFXH6PCZJQNrzhFBj0Su9Y7OVnPaLc
         /bfFdnDx0lbA9QSXY0/+XYOUMQzkkIMcZKYnd9VAgql17wpZ9WqZBuKxcJKEo1t+UoHn
         psYozZl4pa0xk0qwrrBGhFkjTsFkA/L3bwaJ/h2R48MKV0J5ItRhGiimKlK3x157wIZ/
         V8DA6pmIcmEgsXqMfLXyt2cOnxZPKsQwkphiWIuTiSzew2Q9uTNe+zKcbtMdLdmAhwgw
         7dfMg3H+kBUzTCPV10j+rXapSu+6dbRKgysxdDdfFnw7C4ebCsHyV3ksne9hZK56vsOZ
         uHKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=N36gCc3j7uExBVgM58L/MEwlkhhJunSvGseUI9gnnGU=;
        b=m9PQJNQgpcOgVKbn7T3zKwJtJd4ZNzsc84k6knDhAf+NC9fscGrquc18+eFhCvSmtM
         5XEhDU87zsrBLU1GEFHuuXMspoyDKycfLzXleuHJE3Novd3mabWaDaAr6JJbMTB5pKZK
         qQBnaKx/ly3YuJGxwSTaRsAq07uCgayBPQ2w39HZtY/OxOhCeL038iwlvCOPNxCjxH9U
         0MEizGQXu28lnP/bFA1mLyOGDUpVda2+BBhUBt/L7rdxET2UzfI9wzuag7RRKJbIiVGz
         MWcLtO5XB+WlreEiNuP7NkUDwVpGyPpbhoeIEuAW211JUoX9/xv4QtVteBMvrb8oZQRj
         q7/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wG3Vrn8j;
       spf=pass (google.com: domain of 3nnhvxqukccs0r44yx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3nnHVXQUKCcs0r44yx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id l26si1172853ejr.0.2019.11.20.09.02.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 09:02:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 3nnhvxqukccs0r44yx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id g13so3201745wme.0
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 09:02:22 -0800 (PST)
X-Received: by 2002:adf:ea8d:: with SMTP id s13mr4675039wrm.366.1574269342238;
 Wed, 20 Nov 2019 09:02:22 -0800 (PST)
Date: Wed, 20 Nov 2019 18:02:06 +0100
In-Reply-To: <20191120170208.211997-1-jannh@google.com>
Message-Id: <20191120170208.211997-2-jannh@google.com>
Mime-Version: 1.0
References: <20191120170208.211997-1-jannh@google.com>
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v4 2/4] x86/traps: Print non-canonical address on #GP
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
 header.i=@google.com header.s=20161025 header.b=wG3Vrn8j;       spf=pass
 (google.com: domain of 3nnhvxqukccs0r44yx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--jannh.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3nnHVXQUKCcs0r44yx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--jannh.bounces.google.com;
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
    v4:
     - rename insn_bytes to insn_buf (Ingo)
     - add space after GPFSTR (Ingo)
     - make sizeof(desc) clearer (Ingo, Borislav)
     - also print the address (with a different message) if it's canonical (Ingo)
    
    I have already sent a patch to syzkaller that relaxes their parsing of GPF
    messages (https://github.com/google/syzkaller/commit/432c7650) such that
    changes like the one in this patch don't break it.
    That patch has already made its way into syzbot's syzkaller instances
    according to <https://syzkaller.appspot.com/upstream>.

 arch/x86/kernel/traps.c | 64 +++++++++++++++++++++++++++++++++++++++--
 1 file changed, 61 insertions(+), 3 deletions(-)

diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index c90312146da0..b90635f29b9f 100644
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
@@ -509,11 +511,50 @@ dotraplinkage void do_bounds(struct pt_regs *regs, long error_code)
 	do_trap(X86_TRAP_BR, SIGSEGV, "bounds", regs, error_code, 0, NULL);
 }
 
+/*
+ * On 64-bit, if an uncaught #GP occurs while dereferencing a non-canonical
+ * address, return that address.
+ */
+static bool get_kernel_gp_address(struct pt_regs *regs, unsigned long *addr,
+					   bool *non_canonical)
+{
+#ifdef CONFIG_X86_64
+	u8 insn_buf[MAX_INSN_SIZE];
+	struct insn insn;
+
+	if (probe_kernel_read(insn_buf, (void *)regs->ip, MAX_INSN_SIZE))
+		return false;
+
+	kernel_insn_init(&insn, insn_buf, MAX_INSN_SIZE);
+	insn_get_modrm(&insn);
+	insn_get_sib(&insn);
+	*addr = (unsigned long)insn_get_addr_ref(&insn, regs);
+
+	if (*addr == (unsigned long)-1L)
+		return false;
+
+	/*
+	 * Check that:
+	 *  - the address is not in the kernel half or -1 (which means the
+	 *    decoder failed to decode it)
+	 *  - the last byte of the address is not in the user canonical half
+	 */
+	*non_canonical = *addr < ~__VIRTUAL_MASK &&
+			 *addr + insn.opnd_bytes - 1 > __VIRTUAL_MASK;
+
+	return true;
+#else
+	return false;
+#endif
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
@@ -531,6 +572,10 @@ do_general_protection(struct pt_regs *regs, long error_code)
 
 	tsk = current;
 	if (!user_mode(regs)) {
+		bool addr_resolved = false;
+		unsigned long gp_addr;
+		bool non_canonical;
+
 		if (fixup_exception(regs, X86_TRAP_GP, error_code, 0))
 			return;
 
@@ -547,8 +592,21 @@ do_general_protection(struct pt_regs *regs, long error_code)
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
+			addr_resolved = get_kernel_gp_address(regs, &gp_addr,
+							      &non_canonical);
+
+		if (addr_resolved)
+			snprintf(desc, sizeof(desc),
+			    GPFSTR " probably for %saddress 0x%lx",
+			    non_canonical ? "non-canonical " : "", gp_addr);
+
+		die(desc, regs, error_code);
 		return;
 	}
 
-- 
2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120170208.211997-2-jannh%40google.com.
