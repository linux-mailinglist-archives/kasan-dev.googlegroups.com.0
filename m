Return-Path: <kasan-dev+bncBDX4HWEMTEBRBH64QD6QKGQE6C4544Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id ADEFD2A2EFD
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:04:47 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id n14sf6599743wrp.1
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:04:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333087; cv=pass;
        d=google.com; s=arc-20160816;
        b=WgLHo6/DPtMWG0dY58WsCRXXKInmrevq1Bvs4aWLGFw2SuZSiTwlmwyvSrJKrDU/sW
         /hJuTrLT/z6fHMa5uug6PLSzpWRGQ4BxGoSNUo5yVwqVjyd2D2ivzSZXzWwmsGPrmDS3
         rKlKht9vAASTsNWeE+ankhk/gV4cdeuGe6AFD+BjAPVmRRi5uh0pwZ32KoyfNV+KUQ5D
         oQDl6iG3fgwukrsGwbfHnULjtipsRYw6mTqVMIQfTFDzM1lQGeePLrzleRIx1MUXYCt4
         0mDSDiFPPfnyov5cjYrPWuKnv5dYxml7u7gDb9zr+jTQV2PM/iHMSNWFCBi5floJJF8i
         +v8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=zMcU8IyJeDf+7jZc3X5LmTXoOqndCAoBpfBHyx4Cabs=;
        b=u/8J8ODIWACrifE7dRqgtnrVORJ2+LKYG0LcDImbDQ3WwJW3Yb+7KhrAww2m6NaqS+
         2/V+7PAup+1mjzPKm33TOksddAj9Cgqt4TKdrX4RWk/QPsRg1LoKGitscE3JiOh3a5Ye
         gYLt69yltsOsyupyELIux4ih0CPiF6vqDko5ZHYA1r2qYbqCL3Q6VEmrHw2WZNR4O0NG
         /H9qcsfDCz5DsGtqbeTvZH2bjxicc1KoJMSdKVqDV4h1xh3tZgoE9aLgvqkc2e0KxKV3
         hk5g/HsltwEt1lcS3OkCjAEsJpGUQcIRqUf6NTIXRaC10NTGjeN4nYhD2/rLEosIdbJZ
         ePCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H8q6qM0v;
       spf=pass (google.com: domain of 3hs6gxwokcfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HS6gXwoKCfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zMcU8IyJeDf+7jZc3X5LmTXoOqndCAoBpfBHyx4Cabs=;
        b=oE+GXAmv91rkpNPR5HI9njqG1NbkGY6K53p3x0onUaqu6idQU5zvZzHsOyAyDQaEM1
         sMr1l2ZjjyBrhvA7JuZyOf9N1KpbxRVWX1vBqd4yaMA8aH6k1+pqMEZ3hhkadX+LyJcf
         13Qbeqk6ba1CNatDhOLL3Ys3ThB8fT7kOtA4x9ZGHaW5XjHgcrstkSsr6oJ9SbP/UcED
         nKtu7mYG3fxFeid+SKROTWCXCCGVi/o1c7z5E0RGNL5MUISiVzo6SnlfB/uvMiq6dVIO
         nT3IizX0f4VE/jemi77vbaHjJHcApc6sdPKkl3bQCNeyww5wTGVwms7w7j1MYZSJdZga
         nXyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zMcU8IyJeDf+7jZc3X5LmTXoOqndCAoBpfBHyx4Cabs=;
        b=RyszoFGLd4b/fGA34nJ+63dE998ODTTCALmG3Poi86WUE4XjOUQxiJbvxtS+aTj5zp
         2rvkctEWdSGmOaeWjCDfjxhlOQRLYwp+NOKgAfdA2+SGCTj1rsDUDU4lU2kwYQKdezf2
         /fv9C42dgeS2yAUE6GdGWFI3/K9Y7MuPb7qLdlCZNeNRuBkzag0YBJmMb20By0wdqdqP
         O7y2l9zKwCHkqzwTfviEAw7BwG9yr4mNmsxvU5c00nemJ54aIGyGAdb5S+1hHkHi04Ue
         hD1XDYeLTexIoPhrsuqZ/X8YtWW50c/DNjmTOuUy01u6YBJ5kpid0XM+GseDsRGcSlku
         o1zw==
X-Gm-Message-State: AOAM532IeQfgoicuRFRvzpJQkFkhep6/F3i/9dKQa5GIgNlqBId+rnim
	kSe3U1YEpn40RB7Bcz1xTXo=
X-Google-Smtp-Source: ABdhPJzQIfc4tMeLYk4eYu2poNN0iXiRVSUQBbdcHtvEAdo1metCKNfciLx4frs1yH4nyjLovhKaPQ==
X-Received: by 2002:adf:dd0b:: with SMTP id a11mr22159362wrm.41.1604333087474;
        Mon, 02 Nov 2020 08:04:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f00f:: with SMTP id j15ls8285422wro.2.gmail; Mon, 02 Nov
 2020 08:04:46 -0800 (PST)
X-Received: by 2002:a05:6000:1252:: with SMTP id j18mr19698826wrx.18.1604333086510;
        Mon, 02 Nov 2020 08:04:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333086; cv=none;
        d=google.com; s=arc-20160816;
        b=sxcHw7QKbbNk/XruOPLBG/lehD+VmYvXvwpS8SHgRHJYFDy1LJ0gsPAD5KDTKJpDpz
         MKbt8M0aYG3FvK0CDxAQ1NA2xNzkHXxVmNkH3Vxn+KHvqlIVI/cUlJNz17oDWR8Qt4NZ
         /eOqTp3Q9Mf70guurF66JXxFfdSuUro91oyA6tFeegzWwVKx4rhR9oUY8t6AjIaWOR4K
         B6NaADXIQLI2c6mAY5juj5FaxvhJlCbYpF16IJ8Hj3cWYLOAXIfn0d/YSokB7Hg5uLeG
         G8BvvlDP7Hm7id9M6JKuJhCk1jMtqs9TDzp7yXEzOJXZWSk2v1SA5Y+oeMlIZbvVxf6A
         U/KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=8npALRXM9V5Mvv3YsaAMUfwUwZGn3p2jKYGnwn+XyqI=;
        b=fYp2sSNpUyErG/47cB+R90vI0Y9xWRCXVAuBfgxFli1od1h5z/IOL4O9WDz9TXIqB7
         jGr8Efkz3umyhUPFd4C7OkbYAkzS0PoZWdbFAoUWCioGuVqGe/puoquY+dek9YJ3loW+
         4aCnYU080daCx8xhzdrp5nseuMvOB2PRn4CPVVin9jfXNTG6Qo4JkVEfttNDvu4I8+Vm
         WcInKfK3HPoel5DSk4TLwXzhwspNsnYeTRzDJGQvcNfaWEMbOywmAITgiEI4oMIORQn4
         iwE03XNqGIASLFLbMqZh1PcAjn5bIazKqV3AFRjEgF/WYgOQXsbuHeEJabUjFwK8mg47
         rlqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H8q6qM0v;
       spf=pass (google.com: domain of 3hs6gxwokcfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HS6gXwoKCfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id f131si294689wme.1.2020.11.02.08.04.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:04:46 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hs6gxwokcfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 3so1040170wms.9
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:04:46 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6000:1085:: with SMTP id
 y5mr20927773wrw.283.1604333085953; Mon, 02 Nov 2020 08:04:45 -0800 (PST)
Date: Mon,  2 Nov 2020 17:03:48 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <46a1454e0cadea1da73a9f8c1222c1aa3742d4e6.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 08/41] arm64: mte: Switch GCR_EL1 in kernel entry and exit
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=H8q6qM0v;       spf=pass
 (google.com: domain of 3hs6gxwokcfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HS6gXwoKCfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

When MTE is present, the GCR_EL1 register contains the tags mask that
allows to exclude tags from the random generation via the IRG instruction.

With the introduction of the new Tag-Based KASAN API that provides a
mechanism to reserve tags for special reasons, the MTE implementation
has to make sure that the GCR_EL1 setting for the kernel does not affect
the userspace processes and viceversa.

Save and restore the kernel/user mask in GCR_EL1 in kernel entry and exit.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I0081cba5ace27a9111bebb239075c9a466af4c84
---
 arch/arm64/include/asm/mte-def.h   |  1 -
 arch/arm64/include/asm/mte-kasan.h |  6 +++++
 arch/arm64/include/asm/mte.h       |  2 ++
 arch/arm64/kernel/asm-offsets.c    |  3 +++
 arch/arm64/kernel/cpufeature.c     |  3 +++
 arch/arm64/kernel/entry.S          | 41 ++++++++++++++++++++++++++++++
 arch/arm64/kernel/mte.c            | 22 +++++++++++++---
 7 files changed, 74 insertions(+), 4 deletions(-)

diff --git a/arch/arm64/include/asm/mte-def.h b/arch/arm64/include/asm/mte-def.h
index 8401ac5840c7..2d73a1612f09 100644
--- a/arch/arm64/include/asm/mte-def.h
+++ b/arch/arm64/include/asm/mte-def.h
@@ -10,6 +10,5 @@
 #define MTE_TAG_SHIFT		56
 #define MTE_TAG_SIZE		4
 #define MTE_TAG_MASK		GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
-#define MTE_TAG_MAX		(MTE_TAG_MASK >> MTE_TAG_SHIFT)
 
 #endif /* __ASM_MTE_DEF_H  */
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 3a70fb1807fd..a4c61b926d4a 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -29,6 +29,8 @@ u8 mte_get_mem_tag(void *addr);
 u8 mte_get_random_tag(void);
 void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 
+void mte_init_tags(u64 max_tag);
+
 #else /* CONFIG_ARM64_MTE */
 
 static inline u8 mte_get_ptr_tag(void *ptr)
@@ -49,6 +51,10 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return addr;
 }
 
+static inline void mte_init_tags(u64 max_tag)
+{
+}
+
 #endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index cf1cd181dcb2..d02aff9f493d 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -18,6 +18,8 @@
 
 #include <asm/pgtable-types.h>
 
+extern u64 gcr_kernel_excl;
+
 void mte_clear_page_tags(void *addr);
 unsigned long mte_copy_tags_from_user(void *to, const void __user *from,
 				      unsigned long n);
diff --git a/arch/arm64/kernel/asm-offsets.c b/arch/arm64/kernel/asm-offsets.c
index 7d32fc959b1a..dfe6ed8446ac 100644
--- a/arch/arm64/kernel/asm-offsets.c
+++ b/arch/arm64/kernel/asm-offsets.c
@@ -47,6 +47,9 @@ int main(void)
 #ifdef CONFIG_ARM64_PTR_AUTH
   DEFINE(THREAD_KEYS_USER,	offsetof(struct task_struct, thread.keys_user));
   DEFINE(THREAD_KEYS_KERNEL,	offsetof(struct task_struct, thread.keys_kernel));
+#endif
+#ifdef CONFIG_ARM64_MTE
+  DEFINE(THREAD_GCR_EL1_USER,	offsetof(struct task_struct, thread.gcr_user_excl));
 #endif
   BLANK();
   DEFINE(S_X0,			offsetof(struct pt_regs, regs[0]));
diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
index c61f201042b2..8f83042726ff 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -1707,6 +1707,9 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
 
 	/* Enable in-kernel MTE only if KASAN_HW_TAGS is enabled */
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {
+		/* Enable the kernel exclude mask for random tags generation */
+		write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
+
 		/* Enable MTE Sync Mode for EL1 */
 		sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
 		isb();
diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
index b295fb912b12..07646ef4f184 100644
--- a/arch/arm64/kernel/entry.S
+++ b/arch/arm64/kernel/entry.S
@@ -173,6 +173,43 @@ alternative_else_nop_endif
 #endif
 	.endm
 
+	.macro mte_set_gcr, tmp, tmp2
+#ifdef CONFIG_ARM64_MTE
+	/*
+	 * Calculate and set the exclude mask preserving
+	 * the RRND (bit[16]) setting.
+	 */
+	mrs_s	\tmp2, SYS_GCR_EL1
+	bfi	\tmp2, \tmp, #0, #16
+	msr_s	SYS_GCR_EL1, \tmp2
+	isb
+#endif
+	.endm
+
+	.macro mte_set_kernel_gcr, tmp, tmp2
+#ifdef CONFIG_KASAN_HW_TAGS
+alternative_if_not ARM64_MTE
+	b	1f
+alternative_else_nop_endif
+	ldr_l	\tmp, gcr_kernel_excl
+
+	mte_set_gcr \tmp, \tmp2
+1:
+#endif
+	.endm
+
+	.macro mte_set_user_gcr, tsk, tmp, tmp2
+#ifdef CONFIG_ARM64_MTE
+alternative_if_not ARM64_MTE
+	b	1f
+alternative_else_nop_endif
+	ldr	\tmp, [\tsk, #THREAD_GCR_EL1_USER]
+
+	mte_set_gcr \tmp, \tmp2
+1:
+#endif
+	.endm
+
 	.macro	kernel_entry, el, regsize = 64
 	.if	\regsize == 32
 	mov	w0, w0				// zero upper 32 bits of x0
@@ -212,6 +249,8 @@ alternative_else_nop_endif
 
 	ptrauth_keys_install_kernel tsk, x20, x22, x23
 
+	mte_set_kernel_gcr x22, x23
+
 	scs_load tsk, x20
 	.else
 	add	x21, sp, #S_FRAME_SIZE
@@ -330,6 +369,8 @@ alternative_else_nop_endif
 	/* No kernel C function calls after this as user keys are set. */
 	ptrauth_keys_install_user tsk, x0, x1, x2
 
+	mte_set_user_gcr tsk, x0, x1
+
 	apply_ssbd 0, x0, x1
 	.endif
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index a9f03be75cef..ca8206b7f9a6 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -23,6 +23,8 @@
 #include <asm/ptrace.h>
 #include <asm/sysreg.h>
 
+u64 gcr_kernel_excl __ro_after_init;
+
 static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
 {
 	pte_t old_pte = READ_ONCE(*ptep);
@@ -121,6 +123,17 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return ptr;
 }
 
+void mte_init_tags(u64 max_tag)
+{
+	/*
+	 * The format of the tags in KASAN is 0xFF and in MTE is 0xF.
+	 * This conversion is required to extract the MTE tag from a KASAN one.
+	 */
+	u64 incl = GENMASK(FIELD_GET(MTE_TAG_MASK >> MTE_TAG_SHIFT, max_tag), 0);
+
+	gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
+}
+
 static void update_sctlr_el1_tcf0(u64 tcf0)
 {
 	/* ISB required for the kernel uaccess routines */
@@ -156,7 +169,11 @@ static void update_gcr_el1_excl(u64 excl)
 static void set_gcr_el1_excl(u64 excl)
 {
 	current->thread.gcr_user_excl = excl;
-	update_gcr_el1_excl(excl);
+
+	/*
+	 * SYS_GCR_EL1 will be set to current->thread.gcr_user_excl value
+	 * by mte_set_user_gcr() in kernel_exit,
+	 */
 }
 
 void flush_mte_state(void)
@@ -182,7 +199,6 @@ void mte_thread_switch(struct task_struct *next)
 	/* avoid expensive SCTLR_EL1 accesses if no change */
 	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
 		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
-	update_gcr_el1_excl(next->thread.gcr_user_excl);
 }
 
 void mte_suspend_exit(void)
@@ -190,7 +206,7 @@ void mte_suspend_exit(void)
 	if (!system_supports_mte())
 		return;
 
-	update_gcr_el1_excl(current->thread.gcr_user_excl);
+	update_gcr_el1_excl(gcr_kernel_excl);
 }
 
 long set_mte_ctrl(struct task_struct *task, unsigned long arg)
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/46a1454e0cadea1da73a9f8c1222c1aa3742d4e6.1604333009.git.andreyknvl%40google.com.
