Return-Path: <kasan-dev+bncBDX4HWEMTEBRB2O6QT5QKGQE6TLCZCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 90C8126AF66
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:30 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id r6sf716969lfn.12
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204650; cv=pass;
        d=google.com; s=arc-20160816;
        b=LflxoYK6TnBeioSLPNYA3DhmmhZRKMZO6k8CEWyODHNd6c9Zd572KaU57kfmyMU1CG
         GbW61cXuwRyRFYGYi8Pv0arbcaBLbJcWCr+GjBNaBEQxGXg/7/XSE1GkbcrJ0a6dEsZ6
         mTpKb0qp28Byp6D7odu8r7QE9VMJSsExU1ZWPmZnj1VNmcC80cIxhckopa6m7K8QnioB
         Z5DIUhs2TXPa4ssIRrsef5FGGdY2IjrIUCpjTi3hhMR3298RFM/7PzgguykP7tUoO6Mt
         DS21IEg7CdQgkzwHppGG7jehJhpfYBKKW/Rqtqb8BMtw7SQHvU04ob4uihusVvaC3KMS
         r6oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=C+br7SLwBs9cplPnw6PKLLCE0N+tCUh+io8l1nJNuHM=;
        b=IgXjDhfJtV8MWTsWFC23xVkXUip+8NTYE5guzZip2eXgo3ZmN1y5khwUdCrNVtjMNL
         ARp8/Zw8BqJu3hrZ+3akFyDfduIAsSkYlEIJ3Fl3VuTmmISHJwvni47EgqIKbMZqQOMn
         yzmGIg8YKmLfchPWg4COyK/jgdXRuNPA0JoUl1sRfMQqhl2QEHt8r9WgirK3KaoaLiDa
         NMMk4gKQkDTyn26G22Hq42UW/MuIm8K1kvM6YjUEr91YQ69QMgPHIynnAupYNhMg3ISM
         xdXUd7sC57kmL8jPwoWOzw6P+Fpxs2Q0zzMQEU1uEbWPc+aSZnpSfjvUYfN0uAeK8dfi
         rO/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dj076h3H;
       spf=pass (google.com: domain of 3ac9hxwokcu0p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3aC9hXwoKCU0p2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=C+br7SLwBs9cplPnw6PKLLCE0N+tCUh+io8l1nJNuHM=;
        b=Wj66C5iefNtRZNIW/VJfPADkiD8hvFmpbuk0kPIlOlFXd+247O8zUxUBz15wcS9Bo2
         zqJru23WgHQbW78jlmccd2+erHsK+QrKxIOaylMM4lLfb1AmCVaIYuLcd3QrceRsfrUq
         NjYouRvfF3YyFi8SdlbNASQG0FvnIK7jZrc08TMZniAy1xssBpcmf0YFGiOMdvT6jB3r
         W2r4gM0VGZRFZvP1x3zrUN1WNbbrkj4BBfPVmnBXPQg1QUKPjD34YVw/xZaG3iKXavBd
         b+QaH8faeONINTDGVBxf/33vllt/p7IWqX68OGeU33wW4X7J4ZWZC0KoY4GH6k4jqkN2
         sv3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C+br7SLwBs9cplPnw6PKLLCE0N+tCUh+io8l1nJNuHM=;
        b=iTbI2d9+KbJUVvdu7F1EGnxbPnA0n4fr7EcLMc0DmKVe24/JPPqdiebrSk31IdqlIb
         vwG4aUw8M75x3ByNcAshXgxPP0bVqvZU/fah109A+T96l0OB5AnLJq/mEHn9eTUs7p9q
         Yx7rOAn4Q2XEswLMe8hqC8dRwan9nT0J0y0GJW08beO+iix5ew77yVGRr39DY4o6e8dj
         CA2z2w/Ii/m096KHfHZNnPNA6Uutt1cgdd15P1QKydueDPmjr8vGzo6DX81jhZDC7dti
         GtmCMUYZ75vM7ETJkbOA9/ZvX04Eed7bAoxDbPm0L+iPbESU2tRFYeDf5QwUBwfJ5gxk
         VASg==
X-Gm-Message-State: AOAM532+wMeUNm4ffgwJ3ifobVm+19LjEWw8xB3EiUEDdPKTbzW3oIC1
	m+lYcBZnVhBF7tDl17aWuDU=
X-Google-Smtp-Source: ABdhPJynuz0UzUv+vJv049YbAozBmuIo2USkNWrno2SHcUUhhByfMpZYGBsOCprYjKQBzA+2qgjhhQ==
X-Received: by 2002:a19:e602:: with SMTP id d2mr7400558lfh.514.1600204650096;
        Tue, 15 Sep 2020 14:17:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:544e:: with SMTP id d14ls12001lfn.2.gmail; Tue, 15 Sep
 2020 14:17:29 -0700 (PDT)
X-Received: by 2002:a19:4915:: with SMTP id w21mr7954150lfa.2.1600204649058;
        Tue, 15 Sep 2020 14:17:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204649; cv=none;
        d=google.com; s=arc-20160816;
        b=fFclCJFDD9TrFTpCm8ozE4/mKKZSHBT3dNWehiLx7zNOsf7igg54DbMeXz5IEw8ZBX
         kkYmZefcU/t7S4zpdDRNALEzkzp35gYr3zfVw+Job8i2C8eMql4BEZnU5KWjQCaGKrQj
         tObBZ8gqvMCu0EqKBht0tZR4ztMGObo6PDOOX6cO8QX+f61vTSxgBcxGYsjb+6hotKMB
         f+GaYVbPhlY76JxIdsIZrIAPYsR0uR4eqrfFCtI3jAGq0EMNmrREvSBrvHt4Fs/MLjOv
         UrNVPjB68gfqHshptZSWw5alS6nTVHHAcmycVQ20xwzHqE2IDhxPNliiDPIgPBEs41tW
         GvWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=bCscEPFr1p8biWaTnMvAabXKFPxq9bPZ2kCBns9eE1M=;
        b=I+oQab13+d/0Po/k/HCjgp+GaD1yBMKyt9zWU9jCBwLseM8ckv03INbKUmSifp02JL
         dTGTbA/mMQy+w/CxZOUS25cQamUKibZGSbDhFkUZ/lesimDgX2on18Ztfac3yCOwmBju
         65Kgs/F18+L1PbwFyoAOC4D4KXs96ceUXrpkMhHDOPtR4k/L6MQ/NObu+WHaWcpuaRst
         +zP8HYWdTOAwHN/tNlj+rPrWnlY859v1l9XVCnsDCuuIb7SjpJukcfifDwP3Bck6BCB6
         5zBrQr/vzV/3mnTkEXSAccSOh2D4cdSUc/je4LyMkTpTS4JfYkU5veopeTgBih3ll9FJ
         756Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dj076h3H;
       spf=pass (google.com: domain of 3ac9hxwokcu0p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3aC9hXwoKCU0p2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 14si459493lfq.5.2020.09.15.14.17.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ac9hxwokcu0p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id a10so1680685wrw.22
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:29 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:4d0c:: with SMTP id
 o12mr181612wmh.0.1600204648094; Tue, 15 Sep 2020 14:17:28 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:09 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <c801517c8c6c0b14ac2f5d9e189ff86fdbf1d495.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 27/37] arm64: mte: Switch GCR_EL1 in kernel entry and exit
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
 header.i=@google.com header.s=20161025 header.b=dj076h3H;       spf=pass
 (google.com: domain of 3ac9hxwokcu0p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3aC9hXwoKCU0p2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
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
 arch/arm64/include/asm/mte-helpers.h |  6 ++++++
 arch/arm64/include/asm/mte.h         |  2 ++
 arch/arm64/kernel/asm-offsets.c      |  3 +++
 arch/arm64/kernel/cpufeature.c       |  3 +++
 arch/arm64/kernel/entry.S            | 26 ++++++++++++++++++++++++++
 arch/arm64/kernel/mte.c              | 19 ++++++++++++++++---
 6 files changed, 56 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/include/asm/mte-helpers.h b/arch/arm64/include/asm/mte-helpers.h
index 5dc2d443851b..60a292fc747c 100644
--- a/arch/arm64/include/asm/mte-helpers.h
+++ b/arch/arm64/include/asm/mte-helpers.h
@@ -25,6 +25,8 @@ u8 mte_get_mem_tag(void *addr);
 u8 mte_get_random_tag(void);
 void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 
+void mte_init_tags(u64 max_tag);
+
 #else /* CONFIG_ARM64_MTE */
 
 #define mte_get_ptr_tag(ptr)	0xFF
@@ -41,6 +43,10 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return addr;
 }
 
+static inline void mte_init_tags(u64 max_tag)
+{
+}
+
 #endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 82cd7c89edec..3142a2de51ae 100644
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
index eca06b8c74db..3602ac45d093 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -1721,6 +1721,9 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
 
 	/* Enable in-kernel MTE only if KASAN_HW_TAGS is enabled */
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {
+		/* Enable the kernel exclude mask for random tags generation */
+		write_sysreg_s((SYS_GCR_EL1_RRND | gcr_kernel_excl), SYS_GCR_EL1);
+
 		/* Enable MTE Sync Mode for EL1 */
 		sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
 		isb();
diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
index ff34461524d4..79a6848840bd 100644
--- a/arch/arm64/kernel/entry.S
+++ b/arch/arm64/kernel/entry.S
@@ -175,6 +175,28 @@ alternative_else_nop_endif
 #endif
 	.endm
 
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
@@ -214,6 +236,8 @@ alternative_else_nop_endif
 
 	ptrauth_keys_install_kernel tsk, x20, x22, x23
 
+	mte_restore_gcr 1, tsk, x22, x23
+
 	scs_load tsk, x20
 	.else
 	add	x21, sp, #S_FRAME_SIZE
@@ -332,6 +356,8 @@ alternative_else_nop_endif
 	/* No kernel C function calls after this as user keys are set. */
 	ptrauth_keys_install_user tsk, x0, x1, x2
 
+	mte_restore_gcr 0, tsk, x0, x1
+
 	apply_ssbd 0, x0, x1
 	.endif
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 858e75cfcaa0..1c7d963b5038 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -18,10 +18,13 @@
 
 #include <asm/barrier.h>
 #include <asm/cpufeature.h>
+#include <asm/kprobes.h>
 #include <asm/mte.h>
 #include <asm/ptrace.h>
 #include <asm/sysreg.h>
 
+u64 gcr_kernel_excl __ro_after_init;
+
 static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
 {
 	pte_t old_pte = READ_ONCE(*ptep);
@@ -120,6 +123,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
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
@@ -155,7 +165,11 @@ static void update_gcr_el1_excl(u64 excl)
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
@@ -181,7 +195,6 @@ void mte_thread_switch(struct task_struct *next)
 	/* avoid expensive SCTLR_EL1 accesses if no change */
 	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
 		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
-	update_gcr_el1_excl(next->thread.gcr_user_excl);
 }
 
 void mte_suspend_exit(void)
@@ -189,7 +202,7 @@ void mte_suspend_exit(void)
 	if (!system_supports_mte())
 		return;
 
-	update_gcr_el1_excl(current->thread.gcr_user_excl);
+	update_gcr_el1_excl(gcr_kernel_excl);
 }
 
 long set_mte_ctrl(struct task_struct *task, unsigned long arg)
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c801517c8c6c0b14ac2f5d9e189ff86fdbf1d495.1600204505.git.andreyknvl%40google.com.
