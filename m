Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZFO5T6AKGQEXBBZKNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id F2C8429F4E5
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:28 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id r15sf1655352ljn.16
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999588; cv=pass;
        d=google.com; s=arc-20160816;
        b=hSmVT+7zGTP7a9myzj5KHvqmOR63x0bOncjbVP2eJXwzqH6kRaWf5EZvu94hIoZlhY
         9MwhZHlX20JW6eeF7dlE433xacF9WlxR97/EJL+JJLpitdwmJXtwOWT2evxCFtcGd3eE
         fpxMCB3gF5TSK0/paWT9sGi/l2RL6paOVBzJBr+hC24RWDr7TVlozaJ0/Tt9L82UF0gW
         tO9RGvrTZxifVWXN7zswfdr3PVLOYS+M3ChjS+zSdFB4KP+Qmou4zQHvWX8+cPe8w8E4
         0zDumidaOK234Hn1wNGNzrKt5BZWw6Yokvd5p4d31vb7t0zPvxN4+Ph0CgmRi03dxFJd
         6dLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=oDWpQt2Z73Mnl6qDTyJqjtbNQ/8cxrvsxB8KFzkckJE=;
        b=z0uluQ1vEDQ5FkaOYqTiOkBP1yJENH4xxQ/1ace57ZnlC8Igcg4b+5cSFvJiIIXwxh
         6CgZP3cTrmeg7fRB/DwnHSmuZCWBJXfT2DloJOf4hlnsjaAs4BJdp7/EjOH9mZjtVrGY
         ghW0fYwHfT1X2UAPmRnmEpYzynSi786Rj99Sfw4ouhPOKga2f25kcmk/gxc8SeAiFjD7
         djPu8uOYpyWrVj855gyAhhykH2xYRFR5hBAyHo1+XVI6/2QNkqrSl+ieiR8idqrP2IAF
         m+rYR5QiMD2KOT1da+iqeN5GoxTkQzRqvfcraKVDnIxz3Qa9RMtqAVP0kmBV1tFFEqW3
         FSfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HlcFuVRq;
       spf=pass (google.com: domain of 3yhebxwokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3YhebXwoKCQEboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oDWpQt2Z73Mnl6qDTyJqjtbNQ/8cxrvsxB8KFzkckJE=;
        b=fO/YTKOx/yBzvDXTTX0Vi2sM/YhDOnEbpZsXDUCU7p9XR2MChrkjC0+VrBObIF3R5S
         F7vlWPhOFwd5dM1VeJnYs5cRamJmYTwHisTmu3dOPVYad7+36h9dGCI9fBxUuyV633OX
         ksSBOwAsRMD60c/onJ/xqem5qXW7tAlVCfHcXEa36CI8YfMF5Qw0QGWbXiXQCuiBtYAQ
         2OYkzpPG9KrKlsISndkMGz69NHrYJ1Utj9/eSUEXjwQQq9YTmnHMsvDYPdrBjkvgFVAC
         Lqfrnx5haT8scnDk/YMop+QDAIsXaZ0kcfPY+z5joEXZh6XYd6rdbVbJBzsybajhLcm0
         Pl0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oDWpQt2Z73Mnl6qDTyJqjtbNQ/8cxrvsxB8KFzkckJE=;
        b=dLFmC0jRSMdhT7BASo5DRR7atsdnbFWdrXfxHDTK5o/vbUMs3SfYLutMzN8cSOfQNV
         UdeMukMWK5byLCvO/FqPh/668J59Kz89xueqgKLv2eiD8nOEgymct77hYXTru/MzwXcO
         m7+Ltb/ID6LdYRtMZVfyS/9RAwQiEK+Ys0BZ0h4ZJazrFIfcnhRIZC+frHscuQizLiaq
         /FPCYCn9/yJy0GLJIFBVDYb0IAsjjlTbXez3+/p/g95CS0XYeOfxcTs6lIt1GEjndTrL
         29BdvIxkEotny8Ukg/d/yp6DKKjs9amDV0+YpAy0BubLUSZfwNusR6arYpPKuVJNeujI
         sNbQ==
X-Gm-Message-State: AOAM532j7k1r/s5gF+Wt2XeWYtsg/Z/C653LFHmubVpEwhSr67l5hGCc
	n3M3ulvgMGErgT8C0YB2B5c=
X-Google-Smtp-Source: ABdhPJzrr4FF6ehXSOBMWMrfJxNyWCzfL62v2RIOCmoNlfzlpRW1WeRMCB744SUWv9MQB7sX/gYAjA==
X-Received: by 2002:a2e:95ca:: with SMTP id y10mr2414447ljh.124.1603999588541;
        Thu, 29 Oct 2020 12:26:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8e89:: with SMTP id z9ls749889ljk.11.gmail; Thu, 29 Oct
 2020 12:26:27 -0700 (PDT)
X-Received: by 2002:a05:651c:22f:: with SMTP id z15mr2664997ljn.324.1603999587422;
        Thu, 29 Oct 2020 12:26:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999587; cv=none;
        d=google.com; s=arc-20160816;
        b=dsEo4D8hIIuNGME4wGSGUPYZMLkLBbWHDgXNPeZ2VnjmqrkPn4OtSK/ECfxe7JbvcM
         sLlqoF8vY25ChhcyiG04LRiramFTl79pxqCw0XKOxHpVUbADeNdz5CGCj7UX5m+HOm3O
         z+CPTqvXk5Jtd7iG3YBBTcYuxgPng181Dru6eJKjExchA3900IlLzztyAcgprA3KYMJx
         yVKEDH+2PMDsGXBKRmCrtAtglyv9HLr5O1Ti0k+g8SZiUfGEhtS+A7zg5bviy40UpGml
         VAj6E5/j3qrfbooWO8fyXMSIoI2z1Ob4lePFwN8EaFX8cRYp5o/G2PHAw8DyFxEcxiKc
         lx5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=yXTd6QwB8hL4UI1Vuoydq7OLKnZlEjvKHf/0NkuH7eI=;
        b=XbAwa1iwjkQor/lsgV0eZDPm5RARAH3ZjYcBO6/i8ktPQX6cHqi5/qJNPgG+niZ25s
         Met4PK0EVcgw3RhO6tug2G5h2PRWxzLTnWGON49ZCTbJNpIFb4tx5TUOpXE84yndQ8KD
         HKliHYdGpNysvjKT+hl0N1aFWLhnfFJ9HQuHyF3woscac3fHJrNHJNOu4Hvza3wvne+M
         2DaUEXvfJb6GOjeUyaf5FnqpRtJkGuvdKIzupMGAfXKAkP4837nQhncRfZwrAC5vq+1x
         uzwDAl+cIZGFHmB8+B/UfeuPbiP7PfnJIfBjVJjCGunSxnaKIZ5zW2BBLduWFU06BYZd
         2huQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HlcFuVRq;
       spf=pass (google.com: domain of 3yhebxwokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3YhebXwoKCQEboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id a1si95443lff.2.2020.10.29.12.26.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yhebxwokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id u207so305298wmu.4
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:27 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:cf25:: with SMTP id
 m5mr771161wmg.124.1603999586830; Thu, 29 Oct 2020 12:26:26 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:29 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <72e7482df3ea45aa939b501d8496449dc5383faf.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 08/40] arm64: mte: Switch GCR_EL1 in kernel entry and exit
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
 header.i=@google.com header.s=20161025 header.b=HlcFuVRq;       spf=pass
 (google.com: domain of 3yhebxwokcqeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3YhebXwoKCQEboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
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
index f30007dff35f..7d73c6deb15c 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/72e7482df3ea45aa939b501d8496449dc5383faf.1603999489.git.andreyknvl%40google.com.
