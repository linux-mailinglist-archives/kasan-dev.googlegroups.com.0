Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBY5VXHXQKGQEWQ66VTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 93108116EF1
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Dec 2019 15:32:04 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id h87sf11690407ild.11
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Dec 2019 06:32:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575901923; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vs5nQdUOkpoSAQtmqho6qvr/Nryuoq77mtltbjIMB7XkdTTrAqbVYfqJjeYHQrgBTy
         bbUVlkqBOQ/STQ6f8yGYLtZTedS3nh43hV600//rQHzht96r7oLMK8o8A6YMCh0SEBHm
         XnImcEtswPPP0awAGro5XPC3C5tqecaIoW+HvB2okJKZXsKaQHsfyIeg2Dt/gzSnA4NI
         VStzLa/jLRIsiyZgtF0lhrcYDo8epul2shsCCpgAbqxS0EpU3V+DXgXNFkyx18pfsdv+
         W4zTfbdbPaP+M2svv6SFSpPOeOiMgSsDG7dmlVYiPQbZ9hzkHsvWQJ3EVEozLEERSnqf
         Aodw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=iQs9sCGBaWXXlp1fwcR9PTLMfaQXsp9pbWT2wVjmqWc=;
        b=WjAyU6GkjQW4Bwz81BVSoFFVuJuN+DYZvYZduZVW7JGPsgEv4RuBTmDKksIgxycVOo
         0hQgKCL5yaU8ehbMJYl42QKecS7A91uXT+6lmiES8KzorTpFS+eW7Y14v0DcrNMHh83X
         5wx+1JNE9aj7gd9pdyJKtPDfA91NsSbErWXvG2klkxwWreu0kr+Wk9U+p+NHef1WiVSH
         5mXEZsctdPWTN7Pq/kH5me+vDrzR7jDmoCHlKC1ts4YlCgT7knK5ufrury1lXDcDY1V9
         avXzKFNCCYLI/GpZIqWmIAki0+h+PmVZn3fJEUX/zuTLyKxb5cZ2iLHprXq6xAXtagN7
         R4jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SO6uPoib;
       spf=pass (google.com: domain of 34lruxqukcucsjwwqpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=34lruXQUKCUcsjwwqpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iQs9sCGBaWXXlp1fwcR9PTLMfaQXsp9pbWT2wVjmqWc=;
        b=pyEwNnPHrNDgfJLeFYt1DeldrQSv34V8Q5uYlFHbaaTdBJkxmW9MhdjgAY4cN7t77h
         rQY78qgEbva0cEn9pFLF97vqQSLMSgTY+zLyXr0jwQT869/0yBno9+NhyX4kWhlI+pB6
         Jt/tswzigPGjEUbpWgAR6YGzDs5QippmjyOXSyF/dfw4Prct9fGqlOJpiBUvkjey6ao7
         wQvsweltplvVH5OPVqYiVq2T2W3TRTtXP3RJnI+YA+VoPSSs/BM7sle/Ef1s8aLYeFA0
         oQNJpKnRuu7yt6+lJ5OmwIDidchbOLd9Sdy7ChJPeebcVyLyl0vamezqpONCfX5YJ7PY
         JWuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iQs9sCGBaWXXlp1fwcR9PTLMfaQXsp9pbWT2wVjmqWc=;
        b=lLheKd2XDBpRozhivHAoqyLSQSEx+1SKhtzTA61f2dj70LX9BmNiCDNsTtYHJX9ZnV
         wZEvceYAPwit6p3UoYKUxFAT6ds8z4hC383CmE2mue/Ur458DPNRHul5sn5vJwaA/p4Y
         QXAIGfoVFuAUmk/hCAsc83qaJPBz0fExI9FWTv2EgeMHXenE8a/XEDoATMDvsPezZlPZ
         MyfUzBVC9pVwYC75PlVEhbk/iGYpZoo3Lu7a/iklRTRbNxeQeZ428oTv8WuQoJw2nCl9
         myxhyJd3hJ++mRAAAv5LtcqvZ5n5cOfHPXMw1GL2d81eeVrLnGwsA4Mwdw3W+3TnAl2r
         h8Fw==
X-Gm-Message-State: APjAAAWmKwOSGvKcC7LAfz8fPLPEZK5wMpTZ0nr/LWGtkCo7KrDxXbWI
	/EuUnyHpN2gIDzB6mVjREIQ=
X-Google-Smtp-Source: APXvYqzz9OfN/2J1aqLyO+2Zps3R3JPIokmGx3oaH8ggH8YE+Fp3pkS52HTKhTf8X+h9aE9bv4EPDA==
X-Received: by 2002:a92:7793:: with SMTP id s141mr28715215ilc.162.1575901923200;
        Mon, 09 Dec 2019 06:32:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:7205:: with SMTP id n5ls255235ioc.3.gmail; Mon, 09 Dec
 2019 06:32:02 -0800 (PST)
X-Received: by 2002:a5d:8413:: with SMTP id i19mr20323409ion.305.1575901922786;
        Mon, 09 Dec 2019 06:32:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575901922; cv=none;
        d=google.com; s=arc-20160816;
        b=nSYGQdixBReVwbWKguRG75enNK1oN+zHX2ddz3ObkC3L/PMplBT0XJCLMi2jk7jZgx
         mDXyGrSqAWBjjsFAT1e2PqudL83+JdGygL2pa/I0LAhUxoHOwZuuUNgdLrqy2HFbTAFQ
         x9R9u923hMvpzLvy590xLB/+rNNZ9LRsH6IBej8is9rMrLNFNJ9QyxK3/INIMkB0chxk
         RFzMaIKxDiyal/LnzaMcE7JPqj+HV034c7dMCHKtyPR2Q2b64C8oMZyE7mZa1amgLTfX
         +NQyuJGbv4LPTj3/CgC9ZWGMeVPJMNgXTZ0PRzMPKKs7w87fcDkpKXchn29fonrbH7bt
         maFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=yBHbIQvNCgun/fLqJAC7LW6t/3v3EtuoAoy5ROyL9Io=;
        b=cPTdMzzUBWAFzPlQBBHjTCFlNxki5uc7lSQIq5kt+gudFSxprZ4OQLtQqxAFB7vX/W
         dzXs4LUI/stTNRpJKrqNyt+k9411GT4kx3NiR+Ar1VParzNUKuJMFva9aQ2ZiV7oD6ib
         hdQNgdM9rVYw/q8Woreb0dkuL3TA8fSRYbxldIMXOXGgxnfP2ZpLhcZ8IhIoYlJLxUJZ
         Yaa27/Xtn06fuhD2jEXWKbV6JCVjPB6wceABdCyCPUsOqK1UGRamvCNzEyKyoOTTLA8k
         qrsX8hu756w8ralmMn5/b9ThwiqxiFSfe/Q1uL0lmfjl3KDNAE6UGnoL96dGwD35Epu+
         45rQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SO6uPoib;
       spf=pass (google.com: domain of 34lruxqukcucsjwwqpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=34lruXQUKCUcsjwwqpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id i4si1259759ioi.1.2019.12.09.06.32.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Dec 2019 06:32:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 34lruxqukcucsjwwqpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 191so11624923ybc.16
        for <kasan-dev@googlegroups.com>; Mon, 09 Dec 2019 06:32:02 -0800 (PST)
X-Received: by 2002:a81:7015:: with SMTP id l21mr21359313ywc.425.1575901922114;
 Mon, 09 Dec 2019 06:32:02 -0800 (PST)
Date: Mon,  9 Dec 2019 15:31:20 +0100
In-Reply-To: <20191209143120.60100-1-jannh@google.com>
Message-Id: <20191209143120.60100-4-jannh@google.com>
Mime-Version: 1.0
References: <20191209143120.60100-1-jannh@google.com>
X-Mailer: git-send-email 2.24.0.393.g34dc348eaf-goog
Subject: [PATCH v6 4/4] x86/kasan: Print original address on #GP
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
 header.i=@google.com header.s=20161025 header.b=SO6uPoib;       spf=pass
 (google.com: domain of 34lruxqukcucsjwwqpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jannh.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=34lruXQUKCUcsjwwqpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jannh.bounces.google.com;
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

Make #GP exceptions caused by out-of-bounds KASAN shadow accesses easier
to understand by computing the address of the original access and
printing that. More details are in the comments in the patch.

This turns an error like this:

    kasan: CONFIG_KASAN_INLINE enabled
    kasan: GPF could be caused by NULL-ptr deref or user memory access
    general protection fault, probably for non-canonical address
        0xe017577ddf75b7dd: 0000 [#1] PREEMPT SMP KASAN PTI

into this:

    general protection fault, probably for non-canonical address
        0xe017577ddf75b7dd: 0000 [#1] PREEMPT SMP KASAN PTI
    KASAN: maybe wild-memory-access in range
        [0x00badbeefbadbee8-0x00badbeefbadbeef]

The hook is placed in architecture-independent code, but is currently
only wired up to the X86 exception handler because I'm not sufficiently
familiar with the address space layout and exception handling mechanisms
on other architectures.

Signed-off-by: Jann Horn <jannh@google.com>
---

Notes:
    v2:
     - move to mm/kasan/report.c (Dmitry)
     - change hook name to be more generic
     - use TASK_SIZE instead of TASK_SIZE_MAX for compiling on non-x86
     - don't open-code KASAN_SHADOW_MASK (Dmitry)
     - add "KASAN: " prefix, but not "BUG: " (Andrey, Dmitry)
     - use same naming scheme as get_wild_bug_type (Andrey)
     - this version was "Reviewed-by: Dmitry Vyukov <dvyukov@google.com>"
    v3:
     - adjusted example output in commit message based on
       changes in preceding patch
     - ensure that KASAN output happens after bust_spinlocks(1)
     - moved hook in arch/x86/kernel/traps.c such that output
       appears after the first line of KASAN-independent error report
    v4:
     - adjust patch to changes in x86/traps patch
    v5:
     - adjust patch to changes in x86/traps patch
     - fix bug introduced in v3: remove die() call after oops_end()
    v6:
     - adjust sample output in commit message

 arch/x86/kernel/traps.c     | 12 ++++++++++-
 arch/x86/mm/kasan_init_64.c | 21 -------------------
 include/linux/kasan.h       |  6 ++++++
 mm/kasan/report.c           | 40 +++++++++++++++++++++++++++++++++++++
 4 files changed, 57 insertions(+), 22 deletions(-)

diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index c8b4ae6aed5b..7813592b4fb3 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -37,6 +37,7 @@
 #include <linux/mm.h>
 #include <linux/smp.h>
 #include <linux/io.h>
+#include <linux/kasan.h>
 #include <asm/stacktrace.h>
 #include <asm/processor.h>
 #include <asm/debugreg.h>
@@ -589,6 +590,8 @@ do_general_protection(struct pt_regs *regs, long error_code)
 	if (!user_mode(regs)) {
 		enum kernel_gp_hint hint = GP_NO_HINT;
 		unsigned long gp_addr;
+		unsigned long flags;
+		int sig;
 
 		if (fixup_exception(regs, X86_TRAP_GP, error_code, 0))
 			return;
@@ -621,7 +624,14 @@ do_general_protection(struct pt_regs *regs, long error_code)
 				 "maybe for address",
 				 gp_addr);
 
-		die(desc, regs, error_code);
+		flags = oops_begin();
+		sig = SIGSEGV;
+		__die_header(desc, regs, error_code);
+		if (hint == GP_NON_CANONICAL)
+			kasan_non_canonical_hook(gp_addr);
+		if (__die_body(desc, regs, error_code))
+			sig = 0;
+		oops_end(flags, regs, sig);
 		return;
 	}
 
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index cf5bc37c90ac..763e71abc0fe 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -288,23 +288,6 @@ static void __init kasan_shallow_populate_pgds(void *start, void *end)
 	} while (pgd++, addr = next, addr != (unsigned long)end);
 }
 
-#ifdef CONFIG_KASAN_INLINE
-static int kasan_die_handler(struct notifier_block *self,
-			     unsigned long val,
-			     void *data)
-{
-	if (val == DIE_GPF) {
-		pr_emerg("CONFIG_KASAN_INLINE enabled\n");
-		pr_emerg("GPF could be caused by NULL-ptr deref or user memory access\n");
-	}
-	return NOTIFY_OK;
-}
-
-static struct notifier_block kasan_die_notifier = {
-	.notifier_call = kasan_die_handler,
-};
-#endif
-
 void __init kasan_early_init(void)
 {
 	int i;
@@ -341,10 +324,6 @@ void __init kasan_init(void)
 	int i;
 	void *shadow_cpu_entry_begin, *shadow_cpu_entry_end;
 
-#ifdef CONFIG_KASAN_INLINE
-	register_die_notifier(&kasan_die_notifier);
-#endif
-
 	memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
 
 	/*
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 4f404c565db1..e0238af0388f 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -225,4 +225,10 @@ static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long free_region_end) {}
 #endif
 
+#ifdef CONFIG_KASAN_INLINE
+void kasan_non_canonical_hook(unsigned long addr);
+#else /* CONFIG_KASAN_INLINE */
+static inline void kasan_non_canonical_hook(unsigned long addr) { }
+#endif /* CONFIG_KASAN_INLINE */
+
 #endif /* LINUX_KASAN_H */
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 621782100eaa..5ef9f24f566b 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -512,3 +512,43 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
 
 	end_report(&flags);
 }
+
+#ifdef CONFIG_KASAN_INLINE
+/*
+ * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
+ * canonical half of the address space) cause out-of-bounds shadow memory reads
+ * before the actual access. For addresses in the low canonical half of the
+ * address space, as well as most non-canonical addresses, that out-of-bounds
+ * shadow memory access lands in the non-canonical part of the address space.
+ * Help the user figure out what the original bogus pointer was.
+ */
+void kasan_non_canonical_hook(unsigned long addr)
+{
+	unsigned long orig_addr;
+	const char *bug_type;
+
+	if (addr < KASAN_SHADOW_OFFSET)
+		return;
+
+	orig_addr = (addr - KASAN_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT;
+	/*
+	 * For faults near the shadow address for NULL, we can be fairly certain
+	 * that this is a KASAN shadow memory access.
+	 * For faults that correspond to shadow for low canonical addresses, we
+	 * can still be pretty sure - that shadow region is a fairly narrow
+	 * chunk of the non-canonical address space.
+	 * But faults that look like shadow for non-canonical addresses are a
+	 * really large chunk of the address space. In that case, we still
+	 * print the decoded address, but make it clear that this is not
+	 * necessarily what's actually going on.
+	 */
+	if (orig_addr < PAGE_SIZE)
+		bug_type = "null-ptr-deref";
+	else if (orig_addr < TASK_SIZE)
+		bug_type = "probably user-memory-access";
+	else
+		bug_type = "maybe wild-memory-access";
+	pr_alert("KASAN: %s in range [0x%016lx-0x%016lx]\n", bug_type,
+		 orig_addr, orig_addr + KASAN_SHADOW_MASK);
+}
+#endif
-- 
2.24.0.393.g34dc348eaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191209143120.60100-4-jannh%40google.com.
