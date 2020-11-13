Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6ELXT6QKGQEUFS25PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 81B722B2826
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:29 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id y17sf7475315iot.1
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305848; cv=pass;
        d=google.com; s=arc-20160816;
        b=NFwirO7Qf0GfBkPknZjcYaMaeown8ghPdJp6CsIRRVE/mEuFFqeebpWHWa95shPxz5
         GLgK9IHuGmp7WaqG9RdwdDzfo00pzdK/SRCtKsMHUh6xVoJyp/ZD0iRZzkuKHVPtFm9v
         bLH8H3br/s8dkE1u7bPLS8mUBdqozegnjELompvfOuje/qUPzy/LnTkEpEWoykkvZKQK
         5antsA/X2hW4Ja2Ra6n8AEgDdKyp4zWMcp2dBd6Sfi5AHO+T6+jPT+/kQwI62lBCjZke
         haGGG/EmoTnrvrM9Q909EZ1+vuKn99jAbNoWwfdL8yNwy8ZVuP9I2ocEgXiYrqdhm0xI
         y8Fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=JP4cXAbw0Srf1VyueCrOctpO5CFdXamKLvfWIAmhxxU=;
        b=jec860Dglbt18McFOybK2jaznQKX7kOeVz9HKWVbssnO70YKXZR3+vK/sTUD6RIyIY
         wGzlNffGGZIhsKvIs/uHxZXThw07cfSekOE6d9En/WQBbfLCYnpO2jUdkj1yc8crAKE5
         mHfjleEMXUqQU6/OobHD7Waqi2SjyUCPVkU6E4YBzP/4wMPNm/eCoR16symNZqTamPYR
         FBsllFqwvO7EwwXHMgbhXhbrlOpGiWTrEifsmfqUY04X0Kx0WwLm+z2leCaOS4ylY5B5
         jsy08L0I96iEkWbmyxFgyhcf0MX7hlxGaMIcx1+kJsU8QPSxfDMtP6aMEz2LQe/AB8DN
         f19w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=j2wQ5L7G;
       spf=pass (google.com: domain of 39wwvxwokcciivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=39wWvXwoKCcIivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JP4cXAbw0Srf1VyueCrOctpO5CFdXamKLvfWIAmhxxU=;
        b=BA0aBLGPktrM6VbAo8j0nPAuHiSoB0und+g0wORjLOlhaigaWGq0zcUebnMkIzyumF
         +GolNWfk7CTIHP0qdw4w0rUY0ZUOehl1x0tfrUIQlQ2e/NehhBwGlUp2g/mtOtAAtYCL
         7xHrOgd888+Hgs12ctUZTqIG0yeGwdLr+Gx6nib9VPWL5++FFP6CN81Kwe+gzASlmIDO
         1NpQRmcCmIPJAGB7YTMuoG6aZa4assWzYaBHk0Im0fMg2BXJwaG3HiratVSNHKf2+u5d
         QLrGzfYcwNuAfj9QztWP+PttEtwQGGLXsOU/z10VIW64LrZpZRFE5b0lUPelTMos7U+D
         T31w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JP4cXAbw0Srf1VyueCrOctpO5CFdXamKLvfWIAmhxxU=;
        b=d3LF60ZZPyAvRyfudTCWHdIn35zeVIDUK0ibsMBXj/v/ZKacZIS22eP7+HE6Bcdcly
         FEychF7U7qtnLXsGSj41e6xjV31MJU4rViK7ueoKUHPO2DDV6/gLTypcK0RkYRQWuqr/
         EBC1VmkjBVa8w/nyfGWvM1wPVdxCatJFfGHddG4aVPRLFEqSAjXJW881lbDKf+nPjBXP
         AVmGutOnw2VulSIGN3EpwToPdkC81hCgjp47XSrUTBn8cb2f/QvyJjAORYBiT/Jx7/QG
         7K9w1Hhqpjb2mMKExzezwp2npxcaXgsaDduaVpFoyxmmM9jmv0NvgK+Xk+JwvxjtD91C
         PKRA==
X-Gm-Message-State: AOAM5321N+qS+BjyBpGrF5OoI2KIDkuijMm2x2Cv+jXbGWnPLNCQ7ZFO
	bQ4ilMYlkbdKhpIMAWpEG38=
X-Google-Smtp-Source: ABdhPJzcnfRpHCfvwJvHl4LkRy/v8ZLplKFG1kRTJOjJ3LN9riRWtOzrjw/a0iqdDEDGUGzmuQE+aQ==
X-Received: by 2002:a92:b653:: with SMTP id s80mr1567531ili.73.1605305848493;
        Fri, 13 Nov 2020 14:17:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:740c:: with SMTP id p12ls1869195ilc.2.gmail; Fri, 13 Nov
 2020 14:17:28 -0800 (PST)
X-Received: by 2002:a92:770f:: with SMTP id s15mr1564677ilc.227.1605305848135;
        Fri, 13 Nov 2020 14:17:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305848; cv=none;
        d=google.com; s=arc-20160816;
        b=fh7hwU1rzucNpfw82RTmHQxR5Saf1r/M4tmG6gQVPCwhNde1w6tKL/yByjIV388RmN
         qM6bVANtBe7Tm1fmemzoPw3cUAUCBbXKC1NrwnGN9/bw3oR1wSTP2tmsZoq/jmVWdwiE
         lL+fPpn8qBXebyq1viG5u9HdFd4Qbfgccnf6lvB3WsSDNzKVDC29DPbxuI0UMlJcThdE
         J6OgXFctEEExWXmjc1wDIVgxNPeIlygWxEr/kCxvP59mqB8uhR5Tcr2lywcThu7kpD8u
         8xGLsJO+HAMoYsihYm/2m+XHrK5jm4/Gq+F9ILG1fA4+CRV12wb4DW/Oet79U9K0IyrG
         /hAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=VB38GTxukpbyDO0optCuqHPWhKmIjr0MvF2hNC1HBK8=;
        b=KFWcIIsrFWtdyq1f7CvOtVJQM0mDciYhMoC1iukaOZ1t5MEKcArkjJa/xFyb6NOu60
         uM9MJ/WE3vcdiWb/OgE0HKhsUivwOYRA3D1YZGwYz0J+B+sAHuKVdLJ2TAwEOnakIg2d
         BNfeP4IDpaD5++0FGk3ZwOz00dDhGzbJxFWXn9v8PazQOybDlmaUQEEmc3SD7zph9wPt
         pTmhSbeWD/yjpb5CMvg7B+OdoNxJqhxlf3BxPvVqcVO7em/ZKaNXaHH6Z2iK87iv409u
         1ze8dgBDTM2ht4hu6DbRE2DTLYUzxsytRR6/9S35xTBq185ecyE37iH9QZmqXnxccqe9
         l0/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=j2wQ5L7G;
       spf=pass (google.com: domain of 39wwvxwokcciivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=39wWvXwoKCcIivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id j1si637462ilk.3.2020.11.13.14.17.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 39wwvxwokcciivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id 11so6602375qtx.10
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:28 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:a959:: with SMTP id
 z25mr4634040qva.51.1605305847433; Fri, 13 Nov 2020 14:17:27 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:58 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <555318f1f88288126b41e3b3d71da8ca8c9b69f2.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 30/42] arm64: mte: Switch GCR_EL1 in kernel entry and exit
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=j2wQ5L7G;       spf=pass
 (google.com: domain of 39wwvxwokcciivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=39wWvXwoKCcIivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
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
Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I0081cba5ace27a9111bebb239075c9a466af4c84
---
 arch/arm64/include/asm/mte-def.h   |  1 -
 arch/arm64/include/asm/mte-kasan.h |  5 ++++
 arch/arm64/include/asm/mte.h       |  2 ++
 arch/arm64/kernel/asm-offsets.c    |  3 +++
 arch/arm64/kernel/entry.S          | 41 ++++++++++++++++++++++++++++++
 arch/arm64/kernel/mte.c            | 31 +++++++++++++++++++---
 6 files changed, 79 insertions(+), 4 deletions(-)

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
index 71ff6c6786ac..26349a4b5e2e 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -30,6 +30,7 @@ u8 mte_get_random_tag(void);
 void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 
 void mte_enable_kernel(void);
+void mte_init_tags(u64 max_tag);
 
 #else /* CONFIG_ARM64_MTE */
 
@@ -55,6 +56,10 @@ static inline void mte_enable_kernel(void)
 {
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
diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
index 6f31c2c06788..2f4dca656b34 100644
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
index 6a7adb986b52..02d508391ec7 100644
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
@@ -129,6 +131,26 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return ptr;
 }
 
+void mte_init_tags(u64 max_tag)
+{
+	static bool gcr_kernel_excl_initialized;
+
+	if (!gcr_kernel_excl_initialized) {
+		/*
+		 * The format of the tags in KASAN is 0xFF and in MTE is 0xF.
+		 * This conversion extracts an MTE tag from a KASAN tag.
+		 */
+		u64 incl = GENMASK(FIELD_GET(MTE_TAG_MASK >> MTE_TAG_SHIFT,
+					     max_tag), 0);
+
+		gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
+		gcr_kernel_excl_initialized = true;
+	}
+
+	/* Enable the kernel exclude mask for random tags generation. */
+	write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
+}
+
 void mte_enable_kernel(void)
 {
 	/* Enable MTE Sync Mode for EL1. */
@@ -171,7 +193,11 @@ static void update_gcr_el1_excl(u64 excl)
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
@@ -197,7 +223,6 @@ void mte_thread_switch(struct task_struct *next)
 	/* avoid expensive SCTLR_EL1 accesses if no change */
 	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
 		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
-	update_gcr_el1_excl(next->thread.gcr_user_excl);
 }
 
 void mte_suspend_exit(void)
@@ -205,7 +230,7 @@ void mte_suspend_exit(void)
 	if (!system_supports_mte())
 		return;
 
-	update_gcr_el1_excl(current->thread.gcr_user_excl);
+	update_gcr_el1_excl(gcr_kernel_excl);
 }
 
 long set_mte_ctrl(struct task_struct *task, unsigned long arg)
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/555318f1f88288126b41e3b3d71da8ca8c9b69f2.1605305705.git.andreyknvl%40google.com.
