Return-Path: <kasan-dev+bncBDX4HWEMTEBRBA5O6D6QKGQEUJESY4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 42E582C1558
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:40 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id l17sf653000lfc.20
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162179; cv=pass;
        d=google.com; s=arc-20160816;
        b=PZgaExL6hvqLK5gDC6/Cr+/5P7wJzkx0l2Cw/XZLVgvePkrKbm/NwWbkqNMaoIAyke
         3mMEhaxAYHDoLde0ButmDveEXpqF+obqGLJlvf6ONOpUDOSaaoRxZ8VCq2+ZBJ+Ar1Ur
         YwqFrFZPv36m/0APyWmMqsXGBn++2iD8wW1vsRxFrrKoY/NNhnl4gKfy/vEHIc6nzh2J
         MElzDmut3VJu5j0PPVl8/fMuvVJ3FNdIYvCheR9pFG3MjOg7gYwaovLivncAhnLJhpIv
         MeHl5ssxtUurtcjRWNiJUoLegmuJ3/i0sKKl7ucjaPddgunNYbfF2D+x3c1TSiyaNRzN
         EnIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=IsIZkO4jKyDCG9W9JZeVnLpu1d2D1CPmgy4DKoZn0LE=;
        b=DM8ZcAtWfkB5Quro9QuhAEUpnBRVXxnskeWtrI+YeV6kyDyJlQmU+Gtc4hDjXG1b+4
         amzMsxCHa+IBX6QQ0R9mz3AzdtlbcWwHiiyOJwb6t5q4D8fKp3jDAWOqs7b8Z/7bCtO/
         YvjQZVJg0cyKwJr5w2VqM87NPTCHzWRz65ByO3yXDs58QM7KuDgIMm8L/2SRslet+29J
         h6KoFo4JDGtEL9f/pV69aE9wFHHBRyg4WXWJHklgMHJv3hJqXtTUt/Zx2MD0QtTL8KuG
         Dh7Ab49gW+SKAAbTjO+gvhh95zSH6K6jeKGcnwKH0zTi6IRaDjbVpoYI039nureA+5wU
         K9Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OfpIMOmR;
       spf=pass (google.com: domain of 3ahe8xwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Ahe8XwoKCSUBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=IsIZkO4jKyDCG9W9JZeVnLpu1d2D1CPmgy4DKoZn0LE=;
        b=EKTqL7QeXsoTgMEOT0sruxdTe3+wna1Yv6kJvkfC6r2pG3LisX8ZYpG9YQlDfGwA3V
         0db3q40NpiXxyRIRk2qodKa9L5NVg3u1L1Qz6QNP/TEtM1bd2950LsSAuG1hkuSxYihx
         83HxnO3Jl1ka6x8hfu/wmcAoaQBNOyRoTbIoA+I+9GZBqBJvOtUhVxGcQ33aGva4Ubx1
         De7cg3GBhJnYYRE1dafWHvO3jkiyCyLHLlS1lYcrQLSZuBnBsLGNQBWkjxmS8WS5h60I
         bCkMqbMnM+Kq9F9UbfvZ7NnKIKJvONFLvLJYHrYKTq79dNVXFjfXRdPm7Jv8p7pfFAS4
         YJSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IsIZkO4jKyDCG9W9JZeVnLpu1d2D1CPmgy4DKoZn0LE=;
        b=uMV58b+iNy9TEhLupeDleOTJktSmnQJeCUfUG+ah7RTszjRVCWluS5Ygwkxzt3x6Oj
         WSZtoCKSrHEqu4BHGO1cSkpFGQDDjyYXyWa0OQIFzO8ydQ83U3m3/c4WLsgoc2aPG53Z
         +rjcgvNompgqZ6rQOzfx2t7r9TjDMtNZ+6EwV8xvr+NmMzPoXKS2DiUkxrQvrX60KSjQ
         G37zv++Jkkthcu676kWpcvqrSEj4eJDc7iCwKUuC5d7wv1h4Z2FJinElA+wJhbX5d7rF
         YF2lVFA/f/UvksB98yelDmdrloczpuxQsfk3S2yj2PMIlWR4y9yxt+16W+gUEdWqyTjk
         /D8g==
X-Gm-Message-State: AOAM532qw3gw4EoIEQkBA+fR9an/UCD5fsZdTUBf3QAzqqgztbAelDFe
	cLJAf2cmfcwI+UTPlW4iVs8=
X-Google-Smtp-Source: ABdhPJy3wIQy/3443YoydVLtr1V8JK5C8+kAejd3GW0uCnAetTo89ap3LagrPsgfnPVsGAFwsIPq4A==
X-Received: by 2002:a2e:9b44:: with SMTP id o4mr445722ljj.143.1606162179828;
        Mon, 23 Nov 2020 12:09:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58ed:: with SMTP id v13ls2559513lfo.2.gmail; Mon, 23 Nov
 2020 12:09:38 -0800 (PST)
X-Received: by 2002:a05:6512:709:: with SMTP id b9mr378059lfs.188.1606162178836;
        Mon, 23 Nov 2020 12:09:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162178; cv=none;
        d=google.com; s=arc-20160816;
        b=bklRQ8mzqzl/CAq1MqFOku/mFWirIN4H5kVZu4/F0lZix0sdag8g1j37+o8P44mlwo
         lY6I86XX5oCFqwe75zkx9hmfNaCuS58503cjmPfJtl4SC8ghbdIB+JAyfp9WqEnkmQ74
         Lz7/lAsD4vE5SQM8glVY/g7NHhS9vGToxQIJR9HGtXRFaCEvwxdY+xtT+oDd1idH0DIw
         xSYS6kK9R17qKVbn3G8UVdkbCmNNT9OBwJp/JI7Di5vlZ/hzZLQttAxCXthVHUXhp/41
         ij+vGG0uC1gE8+yumtMBSWnU+4Ync8KUs2WdTPDPv27aIk6m5rdIvuAm/aOaGEsK+ObL
         uhtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=d+WAIvv3k1oHM88jeLSD6MonUW4Emn1BlhfJMVLN4ws=;
        b=OspWdhJwSotFRoF8V5hYGZD48tU42RfSKmIBLfUgGJ8QZz4ZlLi8VBYoruE6K1n5wP
         Uf01vp8fvFpUlYp3i8gzoOFFI/1rXD/QlCxu9b88z8ggp8dTV7No4VYLwBni+ykn0qpm
         i/6j4m29ZyzLY6lmOHk1GCVf6erjvEDXbCNlGsM4IpBzL5PEgwJ2i4wEVp8955fRCLAW
         Qc40SUMxAu3uV4xJ0xvtHu2OTWuWrYQqEYvY27YdilEGjgkzecrjjF0rk4aZ7NhbEEru
         2eLjhRAM6KcA16b7RoBkF+As0UrwPyxkJyeluJFNfSCDN9nXNTMUDF6OyKzEKOx/CdX9
         eE4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OfpIMOmR;
       spf=pass (google.com: domain of 3ahe8xwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Ahe8XwoKCSUBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id i12si442686lfl.0.2020.11.23.12.09.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:38 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ahe8xwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id q17so108494wmc.1
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:38 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:309:: with SMTP id
 9mr589163wmd.80.1606162178237; Mon, 23 Nov 2020 12:09:38 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:54 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <578b03294708cc7258fad0dc9c2a2e809e5a8214.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 30/42] arm64: mte: Switch GCR_EL1 in kernel entry and exit
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
 header.i=@google.com header.s=20161025 header.b=OfpIMOmR;       spf=pass
 (google.com: domain of 3ahe8xwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Ahe8XwoKCSUBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/578b03294708cc7258fad0dc9c2a2e809e5a8214.1606161801.git.andreyknvl%40google.com.
