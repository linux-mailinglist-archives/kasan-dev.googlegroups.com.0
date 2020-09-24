Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFGGWT5QKGQESCQBFCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id DC50A277BEE
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:52:04 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id f16sf318325ljm.17
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:52:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987924; cv=pass;
        d=google.com; s=arc-20160816;
        b=SB391647I8nFjbINVz/HUAEEt9x9adZbNeMjJBPKA4x0G1XvHJ6hGCiMgyG2XK8f3a
         +3iZzWSvujbf6SoICX1YR9qbDza8iPPL/IHaMdvEKuzSWhyd5HaRpngNRarzzLUzUVM/
         hbXWREzkSIVXicQ2fvS7NVOtjxPMkToTstmIDnVLCEpx5trau87adOSTkOXx7SIzVNEZ
         /5sRvqx1O6WedZsrKbll2p+Fg4Y7atSF3+A1eAp5difUqDd893vmSKTc4nvT/tFC15//
         liUYIvwIqembBO2xJFI3EaFKei+wpBuCugQSPnyyvtOUrki8/hmStHaG71V2H46sNnfa
         mAZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=MKRD9RdvEPCwoWIzrmZrOAtgJK5cVv8WilOaL3w09sc=;
        b=lcwTGs/P6fLXVdnuH90TRTlIm5iq2n8qomQYiPHdOxll94TVJVgasf4I91zm9L7MVr
         F10aDYuzmxZeyhFqZ3LYEfhCAMk4BlgBfd3Th4NtB7X9tvVioZ4fxsiN+sXw63lMiXL5
         bsToysbylIyGnfEl8RaWnhrQNrdTT5tWd52i2Jttz5iqSyjNpDV+vb6QcNMRd7Jw8Oei
         33IBTNIthKIlyuntHVN9bHtpRb5nGdQcqhay9lz2SbchPNKxZTnpbiuwJ/5OqwhRM6ox
         W2+4nWtvNtzbQKCWT1yfpVEtDlQBP2J3jYeGsOrf33No27l7clQEflua7CDsQlOzrP8Z
         t8Cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="GmW/zNYR";
       spf=pass (google.com: domain of 3eintxwokcq8p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3EiNtXwoKCQ8p2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MKRD9RdvEPCwoWIzrmZrOAtgJK5cVv8WilOaL3w09sc=;
        b=QmZCoQ0wA5K+q3foUPF9ptPcLuU1hucNGwiPs1w8c30Q9YukhnHq2aDtwZFb9tSQBX
         h5sUTk5GlRXQd6SDggG+VeNj6WJIFfI3Bm3O4AQdCd3HGQsrtYqVW5ex9CwJkFTWtqwh
         D/uduztUqMOgtd5TMa1C6d/CeM1hvK+p8dHioXFMww56SMLBbej9TPSz4tXA+g0prrMM
         uyXlShCEZ+P2NLoFeHUwpqVcgl7jxd1SZig2XXWSM5VnvICd4eciqd39pc7/Yix9ctJU
         O4MVsfvyxFUBThQ9yLux27psUvNLIXkbt2aVLuVOocjn9T/ujvfXjJbuJ/o3u95v8nvU
         e1MQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MKRD9RdvEPCwoWIzrmZrOAtgJK5cVv8WilOaL3w09sc=;
        b=CvnnOpBww/3Bs2sR8MQzUOQFvgGHiUSGjGBw3nHqkxGAzDiGJVrYtzzcfKNSXpKBIx
         u9nxOQRRVG6/eyqgkD8v0JQHMdhElcTsT4H6wxldfJzQT88ZPVoyPEH2OhjjDqMJ6Q9g
         4GyIRYWp9Nshg2s4zvXSiQuqyOvYMudVef1qjB41ZqpFIJaqDBQOBw/qwiZAx9Djklp1
         q2p6kkXh+2cY0si4rlkbVAQC6zwY/daHShC/39fo6BVsFR5K42eERkZXex9RMwi5wb5T
         eK6TZZ/51kyhl/loq+qZx4rVrW1rLbV18ubhy0zz6XkhTL2y/fGvwhBPiEMhriG/LY2Q
         MeJg==
X-Gm-Message-State: AOAM531MEH8bclJOH/niPuIgLfU1nAdQWznjW0Q8+NcSYHqbMjDv7xPN
	T4VDb3hdwoHRtQSbdRfTLpw=
X-Google-Smtp-Source: ABdhPJzfAcw/gS2HZnTLL1aoY24O6GjJxwT3QPT6h2LcaYrd1fDdKrn8gL4TC0R3mtYJmPC1WW4+Cg==
X-Received: by 2002:a2e:810a:: with SMTP id d10mr399383ljg.302.1600987924431;
        Thu, 24 Sep 2020 15:52:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9a93:: with SMTP id p19ls91735lji.7.gmail; Thu, 24 Sep
 2020 15:52:03 -0700 (PDT)
X-Received: by 2002:a2e:83d7:: with SMTP id s23mr418211ljh.340.1600987923226;
        Thu, 24 Sep 2020 15:52:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987923; cv=none;
        d=google.com; s=arc-20160816;
        b=RVZv/8bXhbEK9PehVF5E76vYBPE3XI1rUowETRxL4bm6fji22vyhqJLh725s4hmX6R
         aCa1t0boJ5YhkEZg1FCDedo2jUauOTGs/Z6JjLahWv/PQxVjJJbuAjruUwfhOs7xGUuV
         i7DPoAk58i6piZqQQ09WbbaRBRIiuq9tgt7afC212Dfip3+8340jY+8zXreUpmJQ2naG
         ZF2wUpEqImeXlgK8sLZAyGnpBy9a93Y9hbac5bq3x50gQdF48MeeKEkdqAXzibzeIVHs
         wml+14nz8BNjh4wZPNMgxVI5zIebh+4QGYqSu34ZLBus/lmA3waw6nlF6NJU/lNO3A4H
         kL8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Ly+bj57ldRRD0C//yHfyyg/i7uFUjVGmXo7UI/fmS0E=;
        b=MaGNzzS4e4pxKXEb2pIbAweiGwWqJ3GOZbq9/lnulCdGti83m2Y7RniYFnewtbcRf1
         apm6L8Ry4Ye+vBFMAn6iBmQRC638wxFibqW7DrUlLH8OeaD2POl4dfan7ZM9wzRshLOa
         DoZUfLOrQvZo4vB1PlkBxgxb20ftQ8wQb9Qe80cIWfxDtqQVzuIVZZhG2MbSCzX6Tw9D
         i4d5JtX6IBRUMt6U8mCfboXm/WisNwIcmE0Mu+jiYdPRUBZON4u/XvfHqwSnvXjYD8I2
         I+LeMzIEQLZHGWE/USZkcE+py9a16fl+iuZdgYVQB4m6iBuMXrjlA7PQHJ7UYGngnwNs
         pQsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="GmW/zNYR";
       spf=pass (google.com: domain of 3eintxwokcq8p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3EiNtXwoKCQ8p2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id y17si22333lfg.2.2020.09.24.15.52.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:52:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3eintxwokcq8p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id f18so280302wrv.19
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:52:03 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:252:: with SMTP id
 18mr802602wmj.63.1600987922540; Thu, 24 Sep 2020 15:52:02 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:36 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <4e503a54297cf46ea1261f43aa325c598d9bd73e.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 29/39] arm64: mte: Switch GCR_EL1 in kernel entry and exit
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="GmW/zNYR";       spf=pass
 (google.com: domain of 3eintxwokcq8p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3EiNtXwoKCQ8p2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I0081cba5ace27a9111bebb239075c9a466af4c84
---
 arch/arm64/include/asm/mte-kasan.h |  6 ++++
 arch/arm64/include/asm/mte.h       |  2 ++
 arch/arm64/kernel/asm-offsets.c    |  3 ++
 arch/arm64/kernel/cpufeature.c     |  3 ++
 arch/arm64/kernel/entry.S          | 47 ++++++++++++++++++++++++++++++
 arch/arm64/kernel/mte.c            | 18 ++++++++++--
 6 files changed, 76 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index b0f27de8de33..88ccd8afbddb 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -33,6 +33,8 @@ u8 mte_get_mem_tag(void *addr);
 u8 mte_get_random_tag(void);
 void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 
+void mte_init_tags(u64 max_tag);
+
 #else /* CONFIG_ARM64_MTE */
 
 static inline u8 mte_get_ptr_tag(void *ptr)
@@ -53,6 +55,10 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return addr;
 }
 
+static inline void mte_init_tags(u64 max_tag)
+{
+}
+
 #endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 3a2bf3ccb26c..a27ec109ffe8 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -15,6 +15,8 @@
 
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
index ff34461524d4..c7cc1fdfbd1a 100644
--- a/arch/arm64/kernel/entry.S
+++ b/arch/arm64/kernel/entry.S
@@ -175,6 +175,49 @@ alternative_else_nop_endif
 #endif
 	.endm
 
+	.macro mte_set_gcr, tmp, tmp2
+#ifdef CONFIG_ARM64_MTE
+alternative_if_not ARM64_MTE
+	b	1f
+alternative_else_nop_endif
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
+	.macro mte_set_kernel_gcr, tsk, tmp, tmp2
+#ifdef CONFIG_KASAN_HW_TAGS
+#ifdef CONFIG_ARM64_MTE
+alternative_if_not ARM64_MTE
+	b	1f
+alternative_else_nop_endif
+	ldr_l	\tmp, gcr_kernel_excl
+
+	mte_set_gcr \tmp, \tmp2
+1:
+#endif
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
@@ -214,6 +257,8 @@ alternative_else_nop_endif
 
 	ptrauth_keys_install_kernel tsk, x20, x22, x23
 
+	mte_set_kernel_gcr tsk, x22, x23
+
 	scs_load tsk, x20
 	.else
 	add	x21, sp, #S_FRAME_SIZE
@@ -332,6 +377,8 @@ alternative_else_nop_endif
 	/* No kernel C function calls after this as user keys are set. */
 	ptrauth_keys_install_user tsk, x0, x1, x2
 
+	mte_set_user_gcr tsk, x0, x1
+
 	apply_ssbd 0, x0, x1
 	.endif
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 393d0c794be4..c3b4f056fc54 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -22,6 +22,8 @@
 #include <asm/ptrace.h>
 #include <asm/sysreg.h>
 
+u64 gcr_kernel_excl __ro_after_init;
+
 static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
 {
 	pte_t old_pte = READ_ONCE(*ptep);
@@ -116,6 +118,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return ptr;
 }
 
+void mte_init_tags(u64 max_tag)
+{
+	u64 incl = GENMASK(max_tag & MTE_TAG_MAX, 0);
+
+	gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
+}
+
 static void update_sctlr_el1_tcf0(u64 tcf0)
 {
 	/* ISB required for the kernel uaccess routines */
@@ -151,7 +160,11 @@ static void update_gcr_el1_excl(u64 excl)
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
@@ -177,7 +190,6 @@ void mte_thread_switch(struct task_struct *next)
 	/* avoid expensive SCTLR_EL1 accesses if no change */
 	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
 		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
-	update_gcr_el1_excl(next->thread.gcr_user_excl);
 }
 
 void mte_suspend_exit(void)
@@ -185,7 +197,7 @@ void mte_suspend_exit(void)
 	if (!system_supports_mte())
 		return;
 
-	update_gcr_el1_excl(current->thread.gcr_user_excl);
+	update_gcr_el1_excl(gcr_kernel_excl);
 }
 
 long set_mte_ctrl(struct task_struct *task, unsigned long arg)
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4e503a54297cf46ea1261f43aa325c598d9bd73e.1600987622.git.andreyknvl%40google.com.
