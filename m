Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBPN7VTXAKGQENSPLYAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 390A3F9B7B
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Nov 2019 22:10:22 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id x14sf4314106lfq.15
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Nov 2019 13:10:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573593021; cv=pass;
        d=google.com; s=arc-20160816;
        b=VPMl7fKFQuYNmdDwZuX86M1EoxA8iaB2WZ0q+SEpOOjvGjYlgRtUwEKNM8CCthQmsY
         VnIHfBy6j9Y0GXVQMELEiKPNzZGqr6Nu0aiTM82s53U8ROHAmykMy0hyA5RzuWKTVFdM
         kVW56NkMbEopa1+biUuIN1dycBQrpq6ChB6Z8kOGs7/Q9aLt9Iy9aXs3fVqSkkc1Ab79
         D/FLlMJeLSlJzxjpt1fZVjmt19fY+mpbgBop36TB9E2xMA9UEcVvLj1qrfxG3vLr5pGa
         KevaJFJBAn6oXIlWujgIalhh1M8MWGXCutj53ZuvFDZBuSYpt7Xu3z1NqWrXdKX24WpV
         ppDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=sGz+pPB9XSHU3q9Mgy/DPnwxEeU+3e9ZRu30xnWc9UE=;
        b=tb4FcON+hAL1OrlvmtAjJWUgNJOR4MMUsCubQ09HCID5XUsguGw3QJWL8OSP0U9l3G
         wvPKI2OEKnrY8yKOssk8gkz1PlEVQ6GF/Bod/Q8LA+rppLn/f2gKkLd85V0VfBnZ1I3F
         RuG9y5cDYSXxHuB5tUONWhz+nvXR+JHGuV1fknumBDNw9gCBqSStMWwIhvWsyGKq5qnO
         OACsupdEd8VnPYxLHiE33c3VLEtW7VXHanJfynPUP8xAh3MQDechS+RCpSVK3jGp+SO0
         g4iO1u2OoZcOVlUTbxgJpRuCK/5WxzO50z2hcfXmr4ucapyGlx7y6S25qr+x+VbnRfHQ
         QfJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XgWSAD49;
       spf=pass (google.com: domain of 3vb_lxqukcr0c3gga9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3vB_LXQUKCR0C3GGA9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sGz+pPB9XSHU3q9Mgy/DPnwxEeU+3e9ZRu30xnWc9UE=;
        b=lr+ybyBOAo1yOvsr0AeDjYVEk4JZUTkNzEfbGWa/UISnrx/GA0y/lwVQnLawMa0iaI
         QE7VdEeB9vFq92xylP2KKP0/WFUtsfP4Y4iok0wD+msuWzk/G4Ve1cqkm4H/U4/SGVUP
         aafCQ4NvP0q0W5IrQhpa1NHnshUi4HWSy+/zt+IaJzodAfTcXs2JI6ZlxKyoSqilFpBH
         rUxyP3BQZGg101F+LpHXSS5VHJxQciqHW86mNTWFSQ3zExo/TQDAvXo85TLBiTnWNAFk
         YgG3iKm4SSOQaL9ObUbw3SzQWuHKAcFXbzLYSvgahwAUtsftLVc8T+w0SZYs95j+V/h5
         DClw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sGz+pPB9XSHU3q9Mgy/DPnwxEeU+3e9ZRu30xnWc9UE=;
        b=ZvRucQ8NfnNjUSkprq4QUOHkDa2afdmF5tlcwGLMC8oA9EhxDWvGMJcslJ8AAivaLv
         XUBzBru6otKoiKqjkWtbYMmr24DIT5ANFNP7veVDBFTNoXYFvdcJl5q47AKjCZ9S4mII
         mFOnTgFV5hybNWnjvmvUmuULzniBDFwFYWappJGvB0HYtoDw9VpV26NfaxIRbV/NS/Tj
         lAa4tpwOD2gqXCrXEvKvpk48Iji0xS8iVmC9FfUuVI4iUtyhsDQmdPj2AFN7sCuml3sg
         nPv7rokwXa39kyV1yPSKUwMRgKa0NB+MnWwBCdHNBvmnhmCDfhXWVohq9SlAFkfrB3Xn
         v+pw==
X-Gm-Message-State: APjAAAUGrZpWuViPGhqLclGtQwyGdktp/5G9uJU8Jk1zkd+f3SUt1A+O
	ZgzQLyDxRG19C2bHDUwLWWk=
X-Google-Smtp-Source: APXvYqzuedWIIq7pLIgFuviBQMfENk0XA3yDFNtBM7oQlfiWG+Gq+mvjI1hVjqJnHTFGkIwJEKgvYw==
X-Received: by 2002:ac2:5210:: with SMTP id a16mr2359915lfl.156.1573593021708;
        Tue, 12 Nov 2019 13:10:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:904c:: with SMTP id n12ls1934619ljg.8.gmail; Tue, 12 Nov
 2019 13:10:21 -0800 (PST)
X-Received: by 2002:a2e:575c:: with SMTP id r28mr21401684ljd.245.1573593021152;
        Tue, 12 Nov 2019 13:10:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573593021; cv=none;
        d=google.com; s=arc-20160816;
        b=igMjjiAUD/+5flRc61iOOw5rGdTGUmWGgXREdajBfa8w0mte4gFzILqrx/Grhga9aA
         YpFpH0bdwfa9HxUvEj29+Neod0foZq6RL5UlajICTyPReqiFyQ0+c8WC3TCJVA7rPwhV
         QW5kOC1eqhNpSYBwsmsBfo7OB0LmowA8IPuDAZqcNu3nfjnYN4lagf7cw2RLy0ict/Ed
         2ggA+Cl1sLVEpVCctiQSzdudO0J9TwCWeRMoB9hrfrfPA3CZ8qfpluyEZ7VXICMzA/5y
         5YKn26BMbd1YyshSnHgPebp556etzcer8wAicvLQCiv85l65lW+47g/JuZhHGi4nJBh4
         Al5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=AImRA0iAmIPP5MlLCN7f+WlpNxu0QRdC715vd3kJqjY=;
        b=Sc+VXQz/SXUbNIerH1JbPCCaf5BVAP0O99eEud9blnacwK8UDVtiuAjVR9UZuG7SjJ
         fYoUjvDIyaDQhr5WaE4JyJVEyA72yuBWqlCqfvFBVSp6vv9BCC1gUmJxXUDUJDz9AWZY
         S7Riz/rg4GCgx5vUEz+CZuYYYPfyL23RF+aF//Nl4sEQGVvGMqQ+XiZtWOyKM7l+jVln
         v50ZkSMRchpsamQE15b6aApwoK3lge3Oqc6RO8gLFLa/Z5BrNhLU6jxhByEl9VieI/ic
         ZjkFT4qx62vGqpfOrYk82RkjKNNypldCu4qlnswVKeua4SdBDoev0P+iNSOp6XNWn3rv
         sbCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XgWSAD49;
       spf=pass (google.com: domain of 3vb_lxqukcr0c3gga9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3vB_LXQUKCR0C3GGA9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id z9si1547619ljj.4.2019.11.12.13.10.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Nov 2019 13:10:21 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vb_lxqukcr0c3gga9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id f11so2385884wmc.8
        for <kasan-dev@googlegroups.com>; Tue, 12 Nov 2019 13:10:21 -0800 (PST)
X-Received: by 2002:adf:fb0b:: with SMTP id c11mr28542605wrr.50.1573593020286;
 Tue, 12 Nov 2019 13:10:20 -0800 (PST)
Date: Tue, 12 Nov 2019 22:10:02 +0100
In-Reply-To: <20191112211002.128278-1-jannh@google.com>
Message-Id: <20191112211002.128278-3-jannh@google.com>
Mime-Version: 1.0
References: <20191112211002.128278-1-jannh@google.com>
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH 3/3] x86/kasan: Print original address on #GP
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	jannh@google.com
Cc: linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XgWSAD49;       spf=pass
 (google.com: domain of 3vb_lxqukcr0c3gga9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--jannh.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3vB_LXQUKCR0C3GGA9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--jannh.bounces.google.com;
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
    traps: dereferencing non-canonical address 0xe017577ddf75b7dd
    general protection fault: 0000 [#1] PREEMPT SMP KASAN PTI

into this:

    traps: dereferencing non-canonical address 0xe017577ddf75b7dd
    kasan: maybe dereferencing invalid pointer in range
            [0x00badbeefbadbee8-0x00badbeefbadbeef]
    general protection fault: 0000 [#3] PREEMPT SMP KASAN PTI
    [...]

Signed-off-by: Jann Horn <jannh@google.com>
---
 arch/x86/include/asm/kasan.h |  6 +++++
 arch/x86/kernel/traps.c      |  2 ++
 arch/x86/mm/kasan_init_64.c  | 52 +++++++++++++++++++++++++-----------
 3 files changed, 44 insertions(+), 16 deletions(-)

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index 13e70da38bed..eaf624a758ed 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -25,6 +25,12 @@
 
 #ifndef __ASSEMBLY__
 
+#ifdef CONFIG_KASAN_INLINE
+void kasan_general_protection_hook(unsigned long addr);
+#else
+static inline void kasan_general_protection_hook(unsigned long addr) { }
+#endif
+
 #ifdef CONFIG_KASAN
 void __init kasan_early_init(void);
 void __init kasan_init(void);
diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index 479cfc6e9507..e271a5a1ddd4 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -58,6 +58,7 @@
 #include <asm/umip.h>
 #include <asm/insn.h>
 #include <asm/insn-eval.h>
+#include <asm/kasan.h>
 
 #ifdef CONFIG_X86_64
 #include <asm/x86_init.h>
@@ -544,6 +545,7 @@ static void print_kernel_gp_address(struct pt_regs *regs)
 		return;
 
 	pr_alert("dereferencing non-canonical address 0x%016lx\n", addr_ref);
+	kasan_general_protection_hook(addr_ref);
 #endif
 }
 
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 296da58f3013..9ef099309489 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -246,20 +246,44 @@ static void __init kasan_map_early_shadow(pgd_t *pgd)
 }
 
 #ifdef CONFIG_KASAN_INLINE
-static int kasan_die_handler(struct notifier_block *self,
-			     unsigned long val,
-			     void *data)
+/*
+ * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
+ * canonical half of the address space) cause out-of-bounds shadow memory reads
+ * before the actual access. For addresses in the low canonical half of the
+ * address space, as well as most non-canonical addresses, that out-of-bounds
+ * shadow memory access lands in the non-canonical part of the address space,
+ * causing #GP to be thrown.
+ * Help the user figure out what the original bogus pointer was.
+ */
+void kasan_general_protection_hook(unsigned long addr)
 {
-	if (val == DIE_GPF) {
-		pr_emerg("CONFIG_KASAN_INLINE enabled\n");
-		pr_emerg("GPF could be caused by NULL-ptr deref or user memory access\n");
-	}
-	return NOTIFY_OK;
-}
+	unsigned long orig_addr;
+	const char *addr_type;
+
+	if (addr < KASAN_SHADOW_OFFSET)
+		return;
 
-static struct notifier_block kasan_die_notifier = {
-	.notifier_call = kasan_die_handler,
-};
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
+		addr_type = "dereferencing kernel NULL pointer";
+	else if (orig_addr < TASK_SIZE_MAX)
+		addr_type = "probably dereferencing invalid pointer";
+	else
+		addr_type = "maybe dereferencing invalid pointer";
+	pr_alert("%s in range [0x%016lx-0x%016lx]\n", addr_type,
+		 orig_addr, orig_addr + (1 << KASAN_SHADOW_SCALE_SHIFT) - 1);
+}
 #endif
 
 void __init kasan_early_init(void)
@@ -298,10 +322,6 @@ void __init kasan_init(void)
 	int i;
 	void *shadow_cpu_entry_begin, *shadow_cpu_entry_end;
 
-#ifdef CONFIG_KASAN_INLINE
-	register_die_notifier(&kasan_die_notifier);
-#endif
-
 	memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
 
 	/*
-- 
2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191112211002.128278-3-jannh%40google.com.
