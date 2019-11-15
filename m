Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBXHTXPXAKGQEPSF52GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 41BE8FE57A
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 20:17:49 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id s26sf6662314edi.4
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 11:17:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573845469; cv=pass;
        d=google.com; s=arc-20160816;
        b=EVWfuOaJNGQwoUpNSYG3eyM9wRV5WEVj4HjIZMCyVNZZ6KX3u2u24hd8IZB4QJXp/T
         7C3B6D//4M5HfaYRlTsf6F5OdRbAX0R6K4AxlFTnuyyTkgXnGPso29LoauqesC8KxqIo
         GEl9LkDBTSwbl2jrLNX5yOD6fVG1+bEArE9pgpxZm6+Mcn2uaj/lHalcEPzO8tDxV/ni
         PswXcaMkf2EJ7fDB3T0mnyqs7eix6g7Qck/2HM/4vmfe/oYjKhffG6zU26A5Tc86oQAw
         KFEC2I1xB4t8B8NXV5QgdZh3IjbIM38LZAjbYhdTyJT3uEZOzCnD5flwpybafDiZGmXJ
         a34A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=mhFHNSfPortnosyfgWkvcF+BgMVAm+YaYCj5zeZcpns=;
        b=Zdms2LggBA/V54k8IAZkb7m9qZvvZvoqJG45PFTwfDA2I/rgplwXvy6sh1CPftpMik
         JFd+BqRLhPb2XWM+K7Y459Sw5fE0y0sb9HVGN4TKg2h8DPwVSqNyhwviiC8ARutesO9p
         xM8I0ZzVNcW7NmBz2bJd/49jbforkVA6qJdEGc06ta40OkzQqxPhLHkEXg4Llu9O3jqP
         oCogZLh2ayiMRwtLhJAaLsl/JSh8k8uqRJZdCl5J8ok1xxZdb3GD9blR9FEdFZPEwXYx
         T36Af1F63RuX+97kNRzeUH25fNheUKKvHV/ocv+dJeF3d+6CjFaYKE3rp7GRxkSNtwb6
         bIeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iRv1X1m5;
       spf=pass (google.com: domain of 32_noxqukcf4pgttnmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=32_nOXQUKCf4pgttnmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mhFHNSfPortnosyfgWkvcF+BgMVAm+YaYCj5zeZcpns=;
        b=LsXkRDT+lBdYkxd/+l1qN7sto/q0L0tyofNzV/2mMCr/GA+s8jJ/v6Se2WWbq2YIZ+
         n5K7/BSlAfYJfl0UBpHQOnrf6DdNxr3pYBPYnpHLDKzJczvv9NqVnFjJR1o/c+G1ECND
         Y/EIu+RA2Nll+GgxxpIAsvO5YY4VmpqHnZXpdcJLSUjBaP2qSq/K0jj0l8LbeZy+mzox
         NHli46m8cLuZQJmQsamUokmgehvS/lfYMzA+4xYyAWrKIstwGfJ7pJeOOjl0SGZMvrz/
         WYH2J7DpyPPgBQnfqDiUEWP0fsuMQQR/nCtAyQGu9k8bBI3zNJwE5GkTFaJJfJFC4hH9
         jc4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mhFHNSfPortnosyfgWkvcF+BgMVAm+YaYCj5zeZcpns=;
        b=lffYdCR9+dNq7qP6IP5Wp4MX2xsoiDt594ru7Zb17nso5ta+mxSntpvH8cFeTGupEK
         t0P20zNgxcDw494yt8gf8Mn4mrM1LELMnfL0YuBcHQ5c15q0WLCLC9VHlNqfr4/Lox+1
         JsO/Ch4KHFs3gaUOe65jGcJ2Pml2Iqv+P061T0RZGdep5EElr/aqorFM/zORxPFk/Lr2
         WAOffzmY9kyrbVMII+Z5KX48QAgUY9dLdnqSNVmOnnDlrhR0GJIoNSvp7nggC9wn13eK
         rGcm8TxCjR5xsmbcQBPXFySUZ0JWGw08HqFK45j8xpXTg4dkgeNoH8AuupnLOR6hTojG
         dwEQ==
X-Gm-Message-State: APjAAAWpWRKKhUTVBpy/z+FmP08poiEeWEj0DCUvE3+h+dL1PUOcRnZ9
	mqsw8zSyQs6PuiMltzUqHjU=
X-Google-Smtp-Source: APXvYqwFQzLO713Ih2e1o3+7pc8ATIaAMggUhgQDDttFbO925RSgm5ceah2IG1wjjEZ2dRZqFqhDjQ==
X-Received: by 2002:a17:906:cb93:: with SMTP id mf19mr3067663ejb.87.1573845468933;
        Fri, 15 Nov 2019 11:17:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:2493:: with SMTP id e19ls650140ejb.4.gmail; Fri, 15
 Nov 2019 11:17:48 -0800 (PST)
X-Received: by 2002:a17:906:fad4:: with SMTP id lu20mr3132201ejb.9.1573845468331;
        Fri, 15 Nov 2019 11:17:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573845468; cv=none;
        d=google.com; s=arc-20160816;
        b=Gt1B2Oi4STRFvSNEmnlgPrrZ2jBbCCCm2kBtJrd3+p1aDdwAM1P/k/HH1ofPgx597W
         c2lZUehWmUd8zwl8ZdtVj8rf6NSGQs/L411aJhsnFc2yJOFfsFTCzUb2lobzlG8Sp92q
         i+vundUhPnlRPGXJuUyOFlBOBMk8q1owJIkajmNtaXdor3qXJf+yeJg7dJ32faBT/2qR
         OQWiXwZ+h23NRkyBT754B1TMcqZl6qs8jBPktghaRQtj94UQArPR4xZ+yHj9qoGKkg+g
         rZk0o+MWPo5Y+sSxk81YqBapt/Ps87FgZJCBBfxnWVtf45ik/ABMvKngt2HFgYOQypVP
         vYow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=N4fpC1TodnEcSewYt+/yvmv22slBXtQvqNTPw4dor7g=;
        b=rpdOkGyN8BwCfBV2m6pjTdfVu7/NoeRc6WYRJkoVu2TB+gNZrr1C7XtIR9oeCrGxAI
         L3T2+DahBUu7eeUckbMi7EKtrnMvejoW7pmD7ZsKBUY2Eher1o/Qeoi2Nn2DFOxc2cyu
         T2EJM2WlkhuEQcgs1i92LPDEKbh2fl3kJ7wnxb+fgariG2aoY2s4qreLqS9YlxtBCAEd
         UpkpYcRzGgHKA9cgTNZXul/ky+0fCGXVvxhHND/xZi5laB6s31xEXHLg61ZvnbsCYWwk
         sy3QEEs4BnPqq3sk2ygIznWH/dLMw7iqjcXj+75FKVrjuRTjpBCsfNPnDRVBt5CsYhiB
         qknw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iRv1X1m5;
       spf=pass (google.com: domain of 32_noxqukcf4pgttnmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=32_nOXQUKCf4pgttnmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id v57si950988edc.3.2019.11.15.11.17.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Nov 2019 11:17:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 32_noxqukcf4pgttnmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id m17so8301877wrn.23
        for <kasan-dev@googlegroups.com>; Fri, 15 Nov 2019 11:17:48 -0800 (PST)
X-Received: by 2002:adf:f40c:: with SMTP id g12mr7644150wro.356.1573845467801;
 Fri, 15 Nov 2019 11:17:47 -0800 (PST)
Date: Fri, 15 Nov 2019 20:17:28 +0100
In-Reply-To: <20191115191728.87338-1-jannh@google.com>
Message-Id: <20191115191728.87338-3-jannh@google.com>
Mime-Version: 1.0
References: <20191115191728.87338-1-jannh@google.com>
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v2 3/3] x86/kasan: Print original address on #GP
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
 header.i=@google.com header.s=20161025 header.b=iRv1X1m5;       spf=pass
 (google.com: domain of 32_noxqukcf4pgttnmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--jannh.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=32_nOXQUKCf4pgttnmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--jannh.bounces.google.com;
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
    traps: probably dereferencing non-canonical address 0xe017577ddf75b7dd
    general protection fault: 0000 [#1] PREEMPT SMP KASAN PTI

into this:

    traps: dereferencing non-canonical address 0xe017577ddf75b7dd
    traps: probably dereferencing non-canonical address 0xe017577ddf75b7dd
    KASAN: maybe wild-memory-access in range
            [0x00badbeefbadbee8-0x00badbeefbadbeef]
    general protection fault: 0000 [#1] PREEMPT SMP KASAN PTI

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

 arch/x86/kernel/traps.c     |  2 ++
 arch/x86/mm/kasan_init_64.c | 21 -------------------
 include/linux/kasan.h       |  6 ++++++
 mm/kasan/report.c           | 40 +++++++++++++++++++++++++++++++++++++
 4 files changed, 48 insertions(+), 21 deletions(-)

diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index 12d42697a18e..87b52682a37a 100644
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
@@ -540,6 +541,7 @@ static void print_kernel_gp_address(struct pt_regs *regs)
 
 	pr_alert("probably dereferencing non-canonical address 0x%016lx\n",
 		 addr_ref);
+	kasan_non_canonical_hook(addr_ref);
 #endif
 }
 
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 296da58f3013..69c437fb21cc 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -245,23 +245,6 @@ static void __init kasan_map_early_shadow(pgd_t *pgd)
 	} while (pgd++, addr = next, addr != end);
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
@@ -298,10 +281,6 @@ void __init kasan_init(void)
 	int i;
 	void *shadow_cpu_entry_begin, *shadow_cpu_entry_end;
 
-#ifdef CONFIG_KASAN_INLINE
-	register_die_notifier(&kasan_die_notifier);
-#endif
-
 	memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
 
 	/*
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index cc8a03cc9674..7305024b44e3 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -194,4 +194,10 @@ static inline void *kasan_reset_tag(const void *addr)
 
 #endif /* CONFIG_KASAN_SW_TAGS */
 
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
2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191115191728.87338-3-jannh%40google.com.
