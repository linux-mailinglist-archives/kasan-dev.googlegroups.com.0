Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNMT3P4QKGQEG4I4Q7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id A8C24244DD4
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:22 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id y22sf4679361oog.21
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426101; cv=pass;
        d=google.com; s=arc-20160816;
        b=HhKq1AzL6C9Uh0dpP0e5MvMndy2Sic77V6lOuMocjyYAqWzEVdl00cgaN2xam8Cm6U
         iWgIONZt5DliJRKxZ+wZeT2MilwspvxC0gdcrpL/esffRMULsOzFonhieWKk9BlEoB22
         rovb9ixI9+0VhSew1iDwLPXMTCBvXRjHuDF7Nwc9YrQEVFJahawDNzN2NimqefBVr54W
         8tyRdSClu6nrsWpMlwjXlvvmRg9e4Orj/YAs9QVlx3pQL/KuP/yvdqzY/GJpM5Cmb2ek
         Ry1U5GaFyVMZLiksov26pMN/AXYQ9BqWBuikhcordzEr57Hi6sQ22l2vYa3AIlp6uCOv
         wFcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=uMnb4tHPNYxYuUNNZSE1cq9JCqZoKgVNtQthAUIZqe0=;
        b=0XcRhzfKLdZ7tVnfvPSQb78hKb6f0ACN/NluJ3dhTy5OkI5qPNrnxqVgeq5y6ED2sK
         /XPNPSBeamssS83rJcjq9V0aDJgljhrb/zOi61QXLR2dF4FVafBi38gZIRnpj4gtGPXf
         VAScGtb32iMkjaNPi0xY7QJ5j1sUSMQm5BgO/mBh2kpjk+5KSBRSApsf2aKJrCakRzX/
         jg4TIBursUP9QkpuzF3MLGnf64oVqqx4y1f+8XTTbbqhBvd/lvZyd9erRv3kEUEzRHyn
         adJXP+dVEXF7t+tlBB1fkc/5/kPDy75OGbacllsQw9wWhZlqyA/jd48zm1jxrpJB3ejD
         XiMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k89gPw1h;
       spf=pass (google.com: domain of 3tmk2xwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3tMk2XwoKCSM9MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uMnb4tHPNYxYuUNNZSE1cq9JCqZoKgVNtQthAUIZqe0=;
        b=lig9eM0vw5/FklqVGuHnqHeie3dWtaaNhyBt+NEaEJM3ncn0xXWYlyG5GsxUwYRflD
         l7exD/g80vTU7MSaQ3uoNOmjFynLugtNilocmYpAebz1rkIkOQ/KHqOsp3nibnuwfeGz
         84Bd5S7DSpdOPKBGnCVRBJ/RtYOLRkBR7AtdxgE4VXqkdKZk7eNXjnnal/sB7+KH5m77
         MBsOttr6n6VqmrUjh8hnxtI/N/VZFARVWt+VpDPK1y9IqEsz4JStZ14Q5VoWA8CyLxRO
         U5kMw0kW7ye13G4V9BO+27w6RjSGfy7durYM1xgX1pTAyK9mVdLGOfe8v6KChhBC+WBD
         YfJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uMnb4tHPNYxYuUNNZSE1cq9JCqZoKgVNtQthAUIZqe0=;
        b=tLdCoFUA/9Va38EqtlSDuGnSb+HES6a1i5jTv7bMg+IiwW4YFnBGYRYc9u9+QNiIhj
         3T4D+f6/1oq/8CqX2DysyjFY6MOWQqx66YJX8Y6ot9xPdjarioFJOYGPr1wom6cutOSH
         OHMrSHlSaAjHcrH59rR9aolbU/lsmnICPjkc8FLxDXRmZYUiL8B6VBo5ddgcG8ORV9Q1
         Iiba4Mg6KCDPAu1v5iYwAvLiL9crmQG+WNm/CGW7xowQR8qNzsyXgfMrBW1RAVwjj8wd
         uOu1hR3BlVLQnE/qvURTzWROLhmBpFk6j3MDS9YavN3kpe8y90IbjkYRfZ4HTH+FuWgb
         FDKg==
X-Gm-Message-State: AOAM533IuJZ+SwJELPpDKJdAxCAA1qJ2ZJOFJGblkA5PyrEAQCAi8cvP
	y7frThebGtOXiEyvTWo/U8s=
X-Google-Smtp-Source: ABdhPJxPvtkaFbx//Y3KO1dqaGhHa1ZXgXIyvQJjtDtIaMfmf4Dzk4FIBFkFgM6no7DHDcPzYcLjQw==
X-Received: by 2002:a05:6830:1c2b:: with SMTP id f11mr2692715ote.79.1597426101607;
        Fri, 14 Aug 2020 10:28:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d9d4:: with SMTP id q203ls2041410oig.4.gmail; Fri, 14
 Aug 2020 10:28:21 -0700 (PDT)
X-Received: by 2002:a54:4196:: with SMTP id 22mr2252757oiy.23.1597426101323;
        Fri, 14 Aug 2020 10:28:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426101; cv=none;
        d=google.com; s=arc-20160816;
        b=VJwiC+ELjtvwYzU9qvt5JqbbCSyfU5ITB/KHzTFX+zdbXla0oEgA8lMVgY/vbLaL7v
         p02NU43jkxT+1Jw2iWDsVameUVzftLWruWAge8i8FtQRcB+oGuV9ticFRIci8jPpI7pX
         MBMjMXPpBJpQk37yK+RjHN8SvETastrzsLy6xu8yG5K4/T9q3FEf6UrdJMIZaIzzt1OS
         UXCYj4jjnaBiJZluDe+a0/iapRf0Plx6gCCGkfdg95YIRdxeZNaR3CPzkbzhUhch6x7p
         r470c68/3u5xXZJI1lQpxMYdtVjfD+zMC8N3bcukIp54moiZY9wpLIt5ouHoZQQgvCPM
         /BDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=r38RFVTSLd39a5IgqHvrDDhgXMykJLxcJUtVzw/ztLU=;
        b=iAs3piLkgQpVIlSPeaI9UmQgCCuVSUWXS3kjJE9dREl4JBKCf1c0iD0hD2phUhchTA
         f/j3CPPqplCq9cPA3nlilLE3VcydhwZTFXJF1CQxCmEbnYCuKEhEApqAyANQfchQyDvu
         mIH9pXu0BlDpfdhx3RhCJorFVxl4wmBKIfhUrVHqwDpeM5Qq92bUCge54QxwGIJNCgqi
         GWx4YRmjtgT6BQykYsNn5MKsxzukDiyB3lcun2ydOD6P3wQZkXw/fz0129cwCeC1QX/Y
         0nistypYDVHewDFpUed0c3pBWu2x/LGFfe+JmO4Gd3Nqw6J7uFLyRoTnDLLA/TK31nqK
         5K6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k89gPw1h;
       spf=pass (google.com: domain of 3tmk2xwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3tMk2XwoKCSM9MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id z12si465115oia.0.2020.08.14.10.28.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tmk2xwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id v16so6486203qka.18
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:21 -0700 (PDT)
X-Received: by 2002:a0c:fa92:: with SMTP id o18mr3670188qvn.182.1597426100756;
 Fri, 14 Aug 2020 10:28:20 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:27:06 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <ec314a9589ef8db18494d533b6eaf1fd678dc010.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 24/35] arm64: mte: Switch GCR_EL1 in kernel entry and exit
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=k89gPw1h;       spf=pass
 (google.com: domain of 3tmk2xwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3tMk2XwoKCSM9MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
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
---
 arch/arm64/include/asm/mte.h    |  8 ++++++++
 arch/arm64/kernel/asm-offsets.c |  3 +++
 arch/arm64/kernel/cpufeature.c  |  5 +++--
 arch/arm64/kernel/entry.S       | 28 ++++++++++++++++++++++++++++
 arch/arm64/kernel/mte.c         | 19 +++++++++++++++++--
 5 files changed, 59 insertions(+), 4 deletions(-)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 733be1cb5c95..4929f744d103 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -21,6 +21,8 @@
 
 #include <asm/pgtable-types.h>
 
+extern u64 gcr_kernel_excl;
+
 void mte_clear_page_tags(void *addr);
 unsigned long mte_copy_tags_from_user(void *to, const void __user *from,
 				      unsigned long n);
@@ -59,6 +61,8 @@ u8 mte_get_mem_tag(void *addr);
 u8 mte_get_random_tag(void);
 void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 
+void mte_init_tags(u64 max_tag);
+
 #else /* CONFIG_ARM64_MTE */
 
 /* unused if !CONFIG_ARM64_MTE, silence the compiler */
@@ -120,6 +124,10 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return addr;
 }
 
+static inline void mte_init_tags(u64 max_tag)
+{
+}
+
 #endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
diff --git a/arch/arm64/kernel/asm-offsets.c b/arch/arm64/kernel/asm-offsets.c
index 0577e2142284..a1ef256cad4f 100644
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
index 4d94af19d8f6..54bc3b315063 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -1665,14 +1665,15 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
 {
 	u64 mair;
 
-	/* all non-zero tags excluded by default */
-	write_sysreg_s(SYS_GCR_EL1_RRND | SYS_GCR_EL1_EXCL_MASK, SYS_GCR_EL1);
 	write_sysreg_s(0, SYS_TFSR_EL1);
 	write_sysreg_s(0, SYS_TFSRE0_EL1);
 
 	/* Enable Match-All at EL1 */
 	sysreg_clear_set(tcr_el1, 0, SYS_TCR_EL1_TCMA1);
 
+	/* Enable the kernel exclude mask for random tags generation */
+	write_sysreg_s((SYS_GCR_EL1_RRND | gcr_kernel_excl), SYS_GCR_EL1);
+
 	/*
 	 * CnP must be enabled only after the MAIR_EL1 register has been set
 	 * up. Inconsistent MAIR_EL1 between CPUs sharing the same TLB may
diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
index cde127508e38..a17fefb0571b 100644
--- a/arch/arm64/kernel/entry.S
+++ b/arch/arm64/kernel/entry.S
@@ -172,6 +172,29 @@ alternative_else_nop_endif
 #endif
 	.endm
 
+	/* Note: tmp should always be a callee-saved register */
+	.macro mte_restore_gcr, el, tsk, tmp, tmp2
+#ifdef CONFIG_ARM64_MTE
+alternative_if_not ARM64_MTE
+	b	1f
+alternative_else_nop_endif
+	.if	\el == 0
+	ldr	\tmp, [\tsk, #THREAD_GCR_EL1_USER]
+	.else
+	ldr_l	\tmp, gcr_kernel_excl
+	.endif
+	/*
+	 * Calculate and set the exclude mask preserving
+	 * the RRND (bit[16]) setting.
+	 */
+	mrs_s	\tmp2, SYS_GCR_EL1
+	bfi	\tmp2, \tmp, #0, #16
+	msr_s	SYS_GCR_EL1, \tmp2
+	isb
+1:
+#endif
+	.endm
+
 	.macro	kernel_entry, el, regsize = 64
 	.if	\regsize == 32
 	mov	w0, w0				// zero upper 32 bits of x0
@@ -209,6 +232,8 @@ alternative_else_nop_endif
 
 	ptrauth_keys_install_kernel tsk, x20, x22, x23
 
+	mte_restore_gcr 1, tsk, x22, x23
+
 	scs_load tsk, x20
 	.else
 	add	x21, sp, #S_FRAME_SIZE
@@ -386,6 +411,8 @@ alternative_else_nop_endif
 	/* No kernel C function calls after this as user keys are set. */
 	ptrauth_keys_install_user tsk, x0, x1, x2
 
+	mte_restore_gcr 0, tsk, x0, x1
+
 	apply_ssbd 0, x0, x1
 	.endif
 
@@ -957,6 +984,7 @@ SYM_FUNC_START(cpu_switch_to)
 	mov	sp, x9
 	msr	sp_el0, x1
 	ptrauth_keys_install_kernel x1, x8, x9, x10
+	mte_restore_gcr 1, x1, x8, x9
 	scs_save x0, x8
 	scs_load x1, x8
 	ret
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 7717ea9bc2a7..cfac7d02f032 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -18,10 +18,14 @@
 
 #include <asm/barrier.h>
 #include <asm/cpufeature.h>
+#include <asm/kasan.h>
+#include <asm/kprobes.h>
 #include <asm/mte.h>
 #include <asm/ptrace.h>
 #include <asm/sysreg.h>
 
+u64 gcr_kernel_excl __read_mostly;
+
 static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
 {
 	pte_t old_pte = READ_ONCE(*ptep);
@@ -115,6 +119,13 @@ void * __must_check mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return ptr;
 }
 
+void mte_init_tags(u64 max_tag)
+{
+	u64 incl = ((1ULL << ((max_tag & MTE_TAG_MAX) + 1)) - 1);
+
+	gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
+}
+
 static void update_sctlr_el1_tcf0(u64 tcf0)
 {
 	/* ISB required for the kernel uaccess routines */
@@ -150,7 +161,11 @@ static void update_gcr_el1_excl(u64 excl)
 static void set_gcr_el1_excl(u64 excl)
 {
 	current->thread.gcr_user_excl = excl;
-	update_gcr_el1_excl(excl);
+
+	/*
+	 * SYS_GCR_EL1 will be set to current->thread.gcr_user_incl value
+	 * by mte_restore_gcr() in kernel_exit,
+	 */
 }
 
 void flush_mte_state(void)
@@ -184,7 +199,7 @@ void mte_suspend_exit(void)
 	if (!system_supports_mte())
 		return;
 
-	update_gcr_el1_excl(current->thread.gcr_user_excl);
+	update_gcr_el1_excl(gcr_kernel_excl);
 }
 
 long set_mte_ctrl(struct task_struct *task, unsigned long arg)
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ec314a9589ef8db18494d533b6eaf1fd678dc010.1597425745.git.andreyknvl%40google.com.
