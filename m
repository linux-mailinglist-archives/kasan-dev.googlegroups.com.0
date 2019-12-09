Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBV5VXHXQKGQEHTIXP5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3b.google.com (mail-yw1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id E9884116EED
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Dec 2019 15:31:52 +0100 (CET)
Received: by mail-yw1-xc3b.google.com with SMTP id b70sf11906803ywa.15
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Dec 2019 06:31:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575901911; cv=pass;
        d=google.com; s=arc-20160816;
        b=cX2947bQgaS4hTC48Pkry03FHxHlZT6726MfSLdUc+wdV+lxjw7kbEKeepk8NinPIx
         +oYieC3Ld8ma6430AZKzyCuFgDfiNn6mOcjQ0ubNifaVJIq38stLx46BRnCU2fsRQXNx
         tOSX6zMjy7BKyFZJ0u7ilxkQPxTthS6FQ1zJ3s6foKXgScP8fND42xnCViqrHRljbORe
         ft8ERoPtBsa+AHhH3m2aUNKH4n+YDPafk+c0qUiXmprWjgbe4rZhZcwXl6otUlZQ2/D0
         VdEhpaf5kSBvXdjZqnnG2KaGdx6AgZQLKYumhH9KeTckpvuxw+mfRpz0MrMB9WWc9PoP
         q9BA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=YHQmSpppJhSKX0/bzt/1B38iWkJ9mkw3/5uYc9/r5Wo=;
        b=Z0+0y9xuDceWfyLKF9SYNGG5dJVS0pkFzXfb0+JYVInYSWU45Y0uazYr9XeEs35Oy2
         yAAUy0eLT4JU0ghOwID7KVrnKBqa/mcxU0tV5kAUIRp9JQbzsft8O8SrUqXAP/eaTpkV
         1qhvWYjrtuXVysKIgJgnaHu+qbgn1T81yWc7qvyoFDpIk14xUvfu7nPrZMOCCUGDbVtM
         xXlizlumro0nvhoKEHm6ekzwyRI+8L5fzqvMHaBwVv2VkkRJ2QkIvo0FZJKybcz8PxQx
         K/KAuzimppRK9XDn/zIh4K+aYdI1lvVQkuibKpeyEOvsk3H05eJlLR+Z6I3qDRkWOCz7
         13AA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V93v4RsD;
       spf=pass (google.com: domain of 31lruxqukctsgxkkedlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::c49 as permitted sender) smtp.mailfrom=31lruXQUKCTsgXkkedlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YHQmSpppJhSKX0/bzt/1B38iWkJ9mkw3/5uYc9/r5Wo=;
        b=rd7VAfOmtjU0odOPADwE82uUX8yYglLLM0yHLm4Yh8b1sZOaBV20pMExsrfi20UorR
         c3eK+tXCfdUSXUBPDFaRG6iCOraL07LmVHGHVzex5+t99nLDImlVHvvi8D9vB5nXExcb
         /1jluaL8vwKyD9aN4GvmEK6L1Y4fT+pbLbatNZLvo9rs5tkGSZJL0qP3z3FmpEuchsQI
         hYKjDZyXaRy4O+47NWaofCj0OWe7azPU17bIUTwGQRSywmfeI699XlVa0LWV5yUvUDUC
         oD5xAhUdB3FIZMFZobyqNd7i6jkEK96tEl8tswIIzsfAoeFHlqhRbL/7kjEZBwZu8Yf0
         06UQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YHQmSpppJhSKX0/bzt/1B38iWkJ9mkw3/5uYc9/r5Wo=;
        b=JP5ooEk9ChjaLylSoU6e9xxmYJ1WUfi0MloMI5OpR/CwQ32fD5vX0bO8EX2yop8AkN
         SQYHK+8wNmfH0Mk/DFe2N/VlnwgdLis0Q3ReT9XA9N+M1EEg5StjJiJvv+wLTfTH0vT5
         X8X2KJUyYmADPI2bI2lP92kUlQMNza2fBbYb4o44NUJXuJ7/YwmrAboVX/1MlhQ+RI0L
         JCAb2aGs0wEXK8ujOus/xpd/Qfzi6AzV8QMxLO3xJTdi/QGpk/mmIxiDoBTNlk6etp38
         WG21zF0QGqZT6mVLPbhFWorjZPVAjOcr5ZvNyST1ecnwy+KkKVadzYj6tRrp6bndVdwq
         q/tg==
X-Gm-Message-State: APjAAAVba6xQ50S4loWj8wu62YwARn3Fkag3IXmLFDoU4KFnbUQF4bsg
	TjA0ozNOAJXxVXs8h1fZU7U=
X-Google-Smtp-Source: APXvYqwC4GcGSVLNqDGCX4OVlb1b4NAj10Q3bCj8QuXgLd3Q40nwJiCrgt50EissDnhATZxjFmhbAg==
X-Received: by 2002:a0d:ca8e:: with SMTP id m136mr20702155ywd.346.1575901911719;
        Mon, 09 Dec 2019 06:31:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:fc85:: with SMTP id m127ls2010778ywf.8.gmail; Mon, 09
 Dec 2019 06:31:51 -0800 (PST)
X-Received: by 2002:a81:364a:: with SMTP id d71mr22172843ywa.312.1575901911220;
        Mon, 09 Dec 2019 06:31:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575901911; cv=none;
        d=google.com; s=arc-20160816;
        b=CR573V+1GVPCwFe3RPSTK9fgTQY5y1V6GbmXvptj8v5LQwk0Zo/FHfC0Erf4xw14Yo
         hWjQoCqX4t2U+3qPn4MVO2U3sA4zHa6YOLgftjih8mtKAJxIk2s0LSpx+PG4NLQajRlI
         LWaZovsQ9fPbbMXEyGzRLY5Dqu61R2jINt6NPyWB5Nkp/6R3ubmHXPfZnkXssIcFxGyr
         ao0jYVdXgw02IY3CQYSLYUOSSEfxfNPwKHPX4okqlAiVm80mbRcIV00tkfBAqJCyc7R2
         Qv6VsaI6ilzF1Zu0drl8mNpmqArL8JrWs0/QQUKTsLoJMyRwUbCYe8qku/voEE/cy0xJ
         JY0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=6dJeiKQWAfFPvcJSNpo7bPzgTA1iBxJQ7E6uNYT5cFk=;
        b=AGjQOVKcVNScJJ6e07Lh8Kxrx4/6W0UMSbrhqSGsrDQsrSglmIXAVZIGMG9Wbp0cbW
         9UBBL+N7e6ZTOLTogLbTMjnvjhksfO2jrzgP9E8xMRGGaYyepr2aUwZIk8bRRTrpVzz4
         WVKNN6hwURYufEotY8I1dyr5OJeN+F/nFhMCPMdWLl9VkC0gGJpxZ99kKNA0+7yZy14L
         kKzlMhlk1otughT9lxUIgx4O75znlsoovCcM5cliskCW+CZRnGp/KDXS4rm6lSQEOe+Q
         FFvG1FC8Wi9C6pM1kCHsGUaAmvOEqb0aZsXhuUD57gyXL3GEwxdsYy3Lz0cfdQP3gzlD
         uXKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V93v4RsD;
       spf=pass (google.com: domain of 31lruxqukctsgxkkedlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::c49 as permitted sender) smtp.mailfrom=31lruXQUKCTsgXkkedlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-xc49.google.com (mail-yw1-xc49.google.com. [2607:f8b0:4864:20::c49])
        by gmr-mx.google.com with ESMTPS id r1si215526ybr.3.2019.12.09.06.31.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Dec 2019 06:31:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 31lruxqukctsgxkkedlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::c49 as permitted sender) client-ip=2607:f8b0:4864:20::c49;
Received: by mail-yw1-xc49.google.com with SMTP id b70so11906770ywa.15
        for <kasan-dev@googlegroups.com>; Mon, 09 Dec 2019 06:31:51 -0800 (PST)
X-Received: by 2002:a0d:c187:: with SMTP id c129mr5509408ywd.389.1575901910795;
 Mon, 09 Dec 2019 06:31:50 -0800 (PST)
Date: Mon,  9 Dec 2019 15:31:18 +0100
In-Reply-To: <20191209143120.60100-1-jannh@google.com>
Message-Id: <20191209143120.60100-2-jannh@google.com>
Mime-Version: 1.0
References: <20191209143120.60100-1-jannh@google.com>
X-Mailer: git-send-email 2.24.0.393.g34dc348eaf-goog
Subject: [PATCH v6 2/4] x86/traps: Print address on #GP
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
 header.i=@google.com header.s=20161025 header.b=V93v4RsD;       spf=pass
 (google.com: domain of 31lruxqukctsgxkkedlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--jannh.bounces.google.com
 designates 2607:f8b0:4864:20::c49 as permitted sender) smtp.mailfrom=31lruXQUKCTsgXkkedlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--jannh.bounces.google.com;
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
2.24.0.393.g34dc348eaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191209143120.60100-2-jannh%40google.com.
