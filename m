Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSFAVT6QKGQE5PXCQYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id E10B02AE2D6
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:24 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id b6sf6152779wrn.17
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046344; cv=pass;
        d=google.com; s=arc-20160816;
        b=JRFZs6TtcPIPjewyviZYysuVY45I5cMKcq30St/7TY6Pb/cgk36W1jzdXBc0Ol8h0h
         1ocd0E5afUkLGj8QIdIPqYZPJdNfpsSntsPvkoJuSmzYsaNcFVeJlyBHulJMJ9cZEuo2
         dNoZzuyC/rTxw1lyIKm+7meBNaz5r9wCTh/0xiRjTkSG7MVcOVZmr5ykdzXaeaOqwX/G
         G4YKI3Li9vMvXpn629CEb9SQr+59GCjS1GrXb4GaMVS8jLGYtDBQe7zoojY60RpLtZRi
         vHbrtqjBGx4PFj1dlZ9iXsSZRygjgQdKomHm3ioSILyEA56zPfYCUGwhkdki2Rn0Zd6m
         pSMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Fw6H+3KJ5bfow9B+9Cw+8+Wc+ScuY7CaayxTJyQqwkM=;
        b=Auqapi0UxT7bdlFZvuhJkADxJLP2NWxFHj6Fw6JamyZr+zGcUnOZKdb4iCc/E8WWtN
         5iD8y+fv9U3eoqSnE8zlTUc6RCc+CNqcWB6yAslR02yYfHVFPecnYCBHGC0N5FYz3tB6
         NCfzwhdyVqtJQetbIJ4KXX8se5SSsZ3RBhiRuICfCY+FrVMqBLReQQ0RPAP+NEXjAzUH
         AFvCygKU11O5RoxPIka1oZLfjvuAaiUfRo558QbEYI0dgk9+JM6KnfQy7EepZL5h6IYP
         pAxaEIv1iY2mAJCOoTeuMfWo7GAS6IVoX6y1a5U37bRUHaQzajnbIApzjKWDVErQO4sX
         GsmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kshtoNIA;
       spf=pass (google.com: domain of 3rxcrxwokcrgyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3RxCrXwoKCRgyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Fw6H+3KJ5bfow9B+9Cw+8+Wc+ScuY7CaayxTJyQqwkM=;
        b=h1dkPyHHMBaM/i6J/yw50EpgSGmVAPP3/uR7DYLJBbd4GqxAT5isFeo062rEIUke7w
         dXJssXbfDuPmd3Jchm6GXOmx6T84Jix90Wf1mLp+fuNVvioZxkhiubvIg9rAlm+Tc2b2
         rdiJONyiuXbDSRsD1/dePzc7C4OgWK46SdYTCwhXVMMBIlNVW9FgUjqPIVNTeOBqofoe
         cMogoq+s08Cnqxveq1Vl7jzxrMn1pJ+PHOzdtfhcgU2Ud+su3aw2pfR/WmWLMYD4PXEi
         jWvp8W5F1WWpjj0Mq6em0d94SDBgV+ImEofJ9G43aWlHz8sgh+GKruKDpfpCrTh0aPHr
         t0lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fw6H+3KJ5bfow9B+9Cw+8+Wc+ScuY7CaayxTJyQqwkM=;
        b=DcAOmHgLA8UqCHJ9e0IMpqgKgEX/NAtlBMY0b4y/hxePUU6Ig0Q6LWIE+9H+qCFNhw
         2/6NPlrEdLzEFdpe+o/MEqcPWcUQPxpLxsvbV6cc61STdEt7c4p5GlBgQtN7RsTPhD1k
         8b+keMr2skjOR3v1op6hHv7Is/uV+yzDOa+5/nWbSy++KvLJa+bVXz9oSXSPJhyLzzIN
         PFHvA6QUTzMATxqgK38FW8DBFdLVZh3E0l+4oToelComCotANfVdcmvhs7dKxrtLU2Fn
         jgE1g8DtTjkvEBfB8oah1jvT3wWwJ6T41/vMi/kS8eVQqNer1TA2KBO4Iojz0IsUNBwG
         qUDQ==
X-Gm-Message-State: AOAM530xiQ1l+KDMKLz2VYCDdHAgC8t/gJ3hazrOifQe7WZWSuw1yX5G
	1aIGAe3c/lJSF9sLnhhk4e4=
X-Google-Smtp-Source: ABdhPJzgUn2H/RJJIsXYr0Pb1GIh2/yZ58c5hf0tK0UTyuJZvDkzoAkiIWe4bGf/ONVUY4WyKwlHPg==
X-Received: by 2002:adf:ce07:: with SMTP id p7mr12881696wrn.39.1605046344564;
        Tue, 10 Nov 2020 14:12:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f70d:: with SMTP id r13ls461817wrp.1.gmail; Tue, 10 Nov
 2020 14:12:23 -0800 (PST)
X-Received: by 2002:adf:9e48:: with SMTP id v8mr28214082wre.55.1605046343841;
        Tue, 10 Nov 2020 14:12:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046343; cv=none;
        d=google.com; s=arc-20160816;
        b=ijEEVxyeibXa/JMXDFlm8l9eoe9mc9D6gag9A7oLDqqcLOtjsQVZL/vAhIO/VKo+SN
         jlIwPd7UeRkvRJAQY89iPb7ijICvcdBPdk7wBnKKucxc2iWWrTjrlf//pYiGiTl/5RfO
         OO3mIfcguJ4R3uo0/QkYwdhvdf/FRZEs1aXPVc+BgOM5SasZMaqf1KBa5CbXzQKd+l9Y
         UDK4NTVUSJAcNZfcgHvMjyN5PA35y7SDZ9IUEZDE1RoD+IHtGRqf8rRXH5z7zqgGIoKd
         skH6hVwY7MiN6O+Ln7XL8yv7GvNa1m2ILVB64TM1ZMgXZU3wPts1qpz+SWeLjKiAFTy4
         IOtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=IsfQh3yHGLrzGC0yVoxxE36rnbIAplq1b460fTF65PI=;
        b=RUec4T9WYwWW0aZrclwVDf3/3aQ4BP4W9iOE8OaXKcBsYqHDDBaguDOtiQfDpgir4z
         dP1bbBSwnoA5ZgeNBCY8FfqXAckD/2pMm9gyUQtSUrOeJFEb/ZGrxtvs3Gtpk9oytTcD
         h4eFoYOdf0Y9KOp71+KXjF3m3/nGwBeVxlBIDVae32N6ou0TWF9+jaRF34NmHs3d+uBb
         JNlczoKNvzJEfPVquqCf2cfYPfzbM8iEkw9hDZI5kkUe1ffqAer/EL+jcnGQgkoF7ut0
         PK09RGKuHSLdfsyewKNlYHTKWVvRRg6H8H7m6ROmtNK2gGYNYMr8i4hadc6kaafIP5cS
         DK4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kshtoNIA;
       spf=pass (google.com: domain of 3rxcrxwokcrgyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3RxCrXwoKCRgyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id c20si135278wmd.2.2020.11.10.14.12.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:23 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rxcrxwokcrgyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id 67so6229044wra.2
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:23 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:ce0c:: with SMTP id
 m12mr253214wmc.114.1605046343494; Tue, 10 Nov 2020 14:12:23 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:29 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <25401c15dc19c7b672771f5b49a208d6e77bfeb5.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 32/44] arm64: mte: Switch GCR_EL1 in kernel entry and exit
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kshtoNIA;       spf=pass
 (google.com: domain of 3rxcrxwokcrgyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3RxCrXwoKCRgyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
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
index aa3ea2e0b3a8..7c282758d78b 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -30,6 +30,7 @@ u8 mte_get_random_tag(void);
 void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 
 void mte_enable(void);
+void mte_init_tags(u64 max_tag);
 
 #else /* CONFIG_ARM64_MTE */
 
@@ -55,6 +56,10 @@ static inline void mte_enable(void)
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
index 664c968dc43c..dbda6598c19d 100644
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
+	static bool gcr_kernel_excl_initialized = false;
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
 void mte_enable(void)
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/25401c15dc19c7b672771f5b49a208d6e77bfeb5.1605046192.git.andreyknvl%40google.com.
