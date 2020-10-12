Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWMASP6AKGQEQKGYHII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id F335728C2EC
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:14 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id 9sf13341751pfj.22
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535513; cv=pass;
        d=google.com; s=arc-20160816;
        b=E4K5lnZHmYsw7y7kf7jLDdFhhhe6cztx3+Urmy9iY5Q3BDNofhcOzzyXImuCE4ocYp
         gW20MwQy5kAlhG/kNht/6/q4PlVSA2yc4CEWdJA47bBL2VjEqnl6jfxdURvXyeJI64Sn
         or7w2Dgj2wKgnCAm6SO7OB3DVKH6Vwe+nLX1xkEjcahISAXhWE+SVQkaglqzgN1hPyPY
         JWjMarBODPJfA4GEatrCvDWodOQFAmHy0UZtnaL4gzopgO2wUyCbbbFnLAiN6cmwIcjU
         PqL51ueBeaESLEPVka8EZ0dp/N/MmaSLu+1JisIWdYqr5xWvzUIet7qOQz9lG486rVlg
         n2ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=DSk5cuQRx8eTL2gSOHuWs7+CB715FuKIBORyRXNbDpQ=;
        b=q+dLle3OiCTSxSVShsIXn2TYX0dLorbDeInV9AzdkzD7cfSO98r4dnsq7ibmXEmDM/
         CWEOX36lvpMBbpjBx6MfYt1TZxOLB1u1KtD/N9+H13gBvudATXYvSC7EBtkdL+4gmrOl
         /PRpVjyD6S+/gtvxNrqZ7envkaDHDc/ZpbH8LqQn280DJWV8rK/xM37hQsoJ3XvGkWc5
         CBw5QyVmoHi3Iw6fANuXe9jZNdwajgw1GCsJtSN3CsqSMBlTAnQr1kz2ymcPvUnrRFT2
         JJrQJ0KVLwBexs0mqL/hcjtrJVUQRsgrSarFVj92UI2inYASCflgMDiJdABG55X8LnCW
         RBNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bsNspBj5;
       spf=pass (google.com: domain of 3wmcexwokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3WMCEXwoKCe0PcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DSk5cuQRx8eTL2gSOHuWs7+CB715FuKIBORyRXNbDpQ=;
        b=sEJmPl48AyYp9HJInDUHFhwSRlmUQZOyJxPHh4Y9B58KDRoGwI5gQ0oh4lbq04evhr
         JM785dYt3keREBbcjVkXmfORqdf6cSU/ec6dl4kiJGPYSlqXCaJkd9B29SAR6eThOnNp
         4VweJydRUpQuohbWJDZJ++IPfu0rRYOSjokGNGvzssMRO2nkQ0m2oKFb7Fsvyk21Dq3q
         Ku7+diekteIizPfDWBOBOd8fHVlBPg1R844dVijkBO1KHYmnoqO64EH94LwuxO9tTXFR
         A8Tm58Pz3VBCsYTB0lanf3Abwj6z7kdcerIdMWo7+1UTy340tbEyNANlLEa5I+9K6Gfx
         ZqxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DSk5cuQRx8eTL2gSOHuWs7+CB715FuKIBORyRXNbDpQ=;
        b=MRHYqjZOMeKTHiejIhFftICWZXmrpFoLKJhe9xlzg962hVmnmIEl6l0WFdIRtZaP5G
         RRE8FklPymJkFqkwsHL5f/S0mymGUf5CU3dfuYzcCoJ0jUJnKsuU/Pd8lIXlPoS2uYE5
         EIaXso+qUKETahV8M07lQ1/LyddH02jX/WCFGRYL9Oj3Tbpzac8DTd+lJ+JNgqu/g5gE
         snodTEUe1dP3ln4nn/52bFndmVz0vI8C2qzLbsvsIoLnPXwfeCDeR0VLOLRILPZ5dDye
         RCoTK36pHe9yrOZb3EeZz5KGe5fHN79icjpbgf4BST0sp2iXgCmmFWpBp90KS02Fy8/D
         TSaQ==
X-Gm-Message-State: AOAM5325jdXkx80eLW9ptqnsewtH8SfYwx2+oUcvHH38Nj931gUJHhx/
	0EJGd/b6aSIuybVqeoOrLsU=
X-Google-Smtp-Source: ABdhPJyfhskraddj4VO7fyNPtqfWemGmFh4Rbmv4B7mZOv8+1wCAckgc5Ofzv1O3X4hrNIkjbjFCRw==
X-Received: by 2002:aa7:908b:0:b029:142:2501:34ee with SMTP id i11-20020aa7908b0000b0290142250134eemr24652162pfa.71.1602535513674;
        Mon, 12 Oct 2020 13:45:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f993:: with SMTP id cq19ls9991067pjb.0.gmail; Mon,
 12 Oct 2020 13:45:13 -0700 (PDT)
X-Received: by 2002:a17:90a:3804:: with SMTP id w4mr21916055pjb.171.1602535513113;
        Mon, 12 Oct 2020 13:45:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535513; cv=none;
        d=google.com; s=arc-20160816;
        b=MKNvqRhHMTmWNFub7+2WonP8GR+THdjLP0wHthr61fhLJxYQSc0yyzI3vqp0XtCwLx
         4Q/K9A9TdLureUT3aY2Bwfo17sJ8LsnC071P6S9puTCXItqIVgHrjWWtS2GWNaVMreoK
         Flyx7UR9gVtiOX5PKXDcdpL7el4Zrc1zXoXvTnCluHRAOfmaQeNp0iMFKcdHoxjsWUkh
         /XVTjfVhJH7JdbzZUmNvxCPbrGOfEMFfwp5ZvpaEfFlyKMpisJF6o58EUY02cyVZeWua
         3YN5b9/0JYkiOxb8RkMTbOBoFV/6XB1U/s6nPH2eCF0rbh28opOkWcswz9a20VaKdTW8
         VSCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=zP1vkt2FuiCRBVXqofLa5u+JsrcDG5zW5QbHWZzCD+4=;
        b=LQlfNCpJL1/xYyP3yzA9FV0r0vPSYVfeTrZ8XVuWAdoTuoDDGCJEmkEv3+YJsxEnCA
         DFXPbacI4516i7SUIdsPwjLKIskeP5/SlU9c7EzISjdCApOkcj1/QWeNlYA/oYSPNJ9y
         G0SbtW2e1j6evY2rvHsSg56131P/0GmBD7kOuHE9X3/NPVzMK/YbSW2Ltyzdx+fjzQrd
         T9s8LcvmKRC/Ay+xblco46nNfjUs2FwRp5tUrzQnSHdVdfnExxclybgXVCyLAx79w0Yl
         BlSOOl+ipiwAsPVO4nZ36SYpJhzM1PT8KRx1NRZ6eVeDqawKMGrJfQW4DjTTY/ROfSFf
         eA+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bsNspBj5;
       spf=pass (google.com: domain of 3wmcexwokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3WMCEXwoKCe0PcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id u192si1261851pfc.6.2020.10.12.13.45.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wmcexwokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id es11so4066286qvb.10
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:13 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:848:: with SMTP id
 dg8mr27349055qvb.31.1602535512109; Mon, 12 Oct 2020 13:45:12 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:14 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <33c0811d707356b7b267b2de41b55b2728940723.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 08/40] arm64: mte: Switch GCR_EL1 in kernel entry and exit
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
 header.i=@google.com header.s=20161025 header.b=bsNspBj5;       spf=pass
 (google.com: domain of 3wmcexwokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3WMCEXwoKCe0PcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
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
index eca06b8c74db..e76634ad5bc7 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -1721,6 +1721,9 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
 
 	/* Enable in-kernel MTE only if KASAN_HW_TAGS is enabled */
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {
+		/* Enable the kernel exclude mask for random tags generation */
+		write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
+
 		/* Enable MTE Sync Mode for EL1 */
 		sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
 		isb();
diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
index ff34461524d4..eeaac91021bf 100644
--- a/arch/arm64/kernel/entry.S
+++ b/arch/arm64/kernel/entry.S
@@ -175,6 +175,43 @@ alternative_else_nop_endif
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
@@ -214,6 +251,8 @@ alternative_else_nop_endif
 
 	ptrauth_keys_install_kernel tsk, x20, x22, x23
 
+	mte_set_kernel_gcr x22, x23
+
 	scs_load tsk, x20
 	.else
 	add	x21, sp, #S_FRAME_SIZE
@@ -332,6 +371,8 @@ alternative_else_nop_endif
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/33c0811d707356b7b267b2de41b55b2728940723.1602535397.git.andreyknvl%40google.com.
