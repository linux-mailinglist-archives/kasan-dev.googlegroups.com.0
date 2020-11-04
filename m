Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOHORT6QKGQE2427LBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 916932A7142
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:25 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id t19sf49859qta.21
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532024; cv=pass;
        d=google.com; s=arc-20160816;
        b=bYFLTN7H5CvCfxnhXSkSCk5vaOAudYuBZxpH8X1R6VAazUrjOdG5Qq78llchlsMKQG
         phDaZeqLK9dDaH22WvxWCNGa7T56NQ3ZpHrHMrqcaZyDvh2h5Vf/jaq7ne+PEQUfF3XJ
         yLMo0jQJhP/jrYCxuuWRsN1l70zGmaFZwbXMX+0NcYnG9yhwB05dbrC3ntqJHAkIOMFo
         IliErkl4qHq0/OmHJL200KoDjiaseThlfdsrOLmeiSXGoaRnFlPNNaBMNVKARxPY/POO
         h+ou7weBbM1ymgA6u0qPSULrivgRCfn1FcRNU5qSA83DtOmCWrV4zKaGMxYrUegzLr7u
         RuyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=pKubtCyUZFahGbiajre23WR1Zt1PDvWkBmYNrAp4N4s=;
        b=OR37T4/lbeBc8e1o5iZyrLHDJ5sncsrtNUJIneHaKPSydNJmStj9zvzfAV8RoXcwu4
         jsKXOlmaFnzoKtNGZu496emr076XjteSLSvJ7BKZ537D9CuoLNPtMsrEmWxT4gBXB3YB
         2KOj291r6lY1gbQ1gLuJx4UIJTFiCg3tvFffF26xL8Yza/5ifWbxsI9xO4DyCwWaIa73
         0OpGE1swtdvQ75mIpvUoxrDuV2ZcGrjIncFzALxjL0g+ocG1tsZgnHaaf1ig+6PGyM2w
         7T1uEMLCAL2IVUvmNLHCvk/tYBLTrzTnL3FS8AwtLSVGOxrk3rP5gWgifGw7U44LNNdv
         nIaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QOLfmd7s;
       spf=pass (google.com: domain of 3nzejxwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3NzejXwoKCTYSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pKubtCyUZFahGbiajre23WR1Zt1PDvWkBmYNrAp4N4s=;
        b=PS96vqe/rF+e6yTW16w7ukDIslZlYBcicnYesn+KBt/2Rg7A1e/95oark7qg+Xl5bc
         EUeIYRPb4g7PPIU810qwJ9wlQps3KALugf6ImRUyB96MULFBpfrCnDONyzzCHHLTQ3ko
         RW445a4unQNaVaNfg5BDwaSp6wuCHb6YgYtHsZCerMqsJXdNpD5jHB8Dftn8lXDRXj3M
         0lEs4tJPBkCeS4yQdtOlX5VER2FdctzMmdCvbEFZbErU/xpqMNHRmGWR8mCx3a3DTQLf
         s463u7E/V/06TNVwFuuYrg3wu17Omm19fA/2DwlRgAxl1hVNgk4I9xhfohuTNDU/BwBJ
         Q9cA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pKubtCyUZFahGbiajre23WR1Zt1PDvWkBmYNrAp4N4s=;
        b=OskZRkGvqtmzyji8g8hvuiUPbwE4H/mlbEuOfo39coikYoSNq/d5Ne35IfY4oQNi7A
         zToOu7yFxF1XBLSyyMnEd/7VjmuMAlPQV6oQpMKvTOZMsrySjF5MfSG9EWm6fWgD8KuZ
         SZhEwX3ybNGh0naKVkMIZucJluhbKjSOQT6PtF6McbjgbG9vcaP+PWRDjFiV+Tq4uWXb
         VBjdSSPdXPqSmeZVP1IJslBvVks5U4AqkIrqYv1q9Pxtdo12fhyKJRtsu2Y/wV8I4Y20
         eneJrUTBXVr/83FrArIo9JQn2UOaihXI9YDFw23yh/iYRYrbdVm8ie9/7p4W0/mX1WkU
         KLcg==
X-Gm-Message-State: AOAM532KLGv2ZvIzolWwutqBCrTJHufesRXQal13vaj00Mw1nJIxaNKf
	w60ugU++aUN86iRmrIYsSho=
X-Google-Smtp-Source: ABdhPJx4Ab7JRyJTLCCg+TdWlxcZtGjY6c5fuI8dOR9hRIX/wcp4Y4PRU8jerHLeHfoMDgDs6SbG2Q==
X-Received: by 2002:ac8:65c6:: with SMTP id t6mr410369qto.339.1604532024689;
        Wed, 04 Nov 2020 15:20:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1248:: with SMTP id a8ls2085849qkl.11.gmail; Wed,
 04 Nov 2020 15:20:24 -0800 (PST)
X-Received: by 2002:a37:7f83:: with SMTP id a125mr533276qkd.423.1604532024246;
        Wed, 04 Nov 2020 15:20:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532024; cv=none;
        d=google.com; s=arc-20160816;
        b=AzX3AOylbDcrmzaVYehj8SUIALUc6qAsyQqPiePe6X+5B3Hga0Uf8mi8jTJ2+EKA+8
         NWzCkzikSPyxqLbj3rXfmpqwXhuKD1QeiIcm/49txpiBrUzawiNZ6Un7yARHzcR50Knb
         ufM4S82aGiRQacmXFuTLTPoX71qyQ8cWhpYSAwzaGPH1Xv6eeDTC1Hoo5cXgsUe0heRd
         HJuRF6bSd07JeTWUscCW91v1W2Gd/FgIAwANQdUR06uoORZo/2oiHiGRhzta923jlBxa
         kYiv9kgz+qavPU1ttLthr1lwTJrf31AXC++DLa/pEU8cT8y8CCpiSbeZ2AL3jklc6cxc
         HfMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=1s7WiGrMcWP0bJ51auKgm3tMrSQZgmfW9W//QveyJyE=;
        b=avak5l5rbWO+7vzDXSXOUAUkDn07ZZ2x7+/HTqrITP9mkGU9scy7uU1pPk/jHsSySE
         b9kDYAK9lJmU2pugB7QbBZXftjSoY+PhGuNavltp8nvn/OfDDfUIicrYNKRBKaYNK4PW
         XZUvTaMiw+EhSg06dG0j+BUb6UZEKvpmRcd/m6XdwhOeZklJ/FmdgL8eDUmQk2vh8LYF
         OAL8bjfZfUfiCRamVIKHoV6dXZ/fegNkOIx2oFcIbgYZJ4XejsDR+G1BPf6Naujj215H
         vN68g6Qyrbs0wnR5hnMoi97G7sE+E3c6VUynQEdESG+bTFexkPLQpXHKGKQt/wZ/qYD0
         cHjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QOLfmd7s;
       spf=pass (google.com: domain of 3nzejxwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3NzejXwoKCTYSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id g16si82641qtp.0.2020.11.04.15.20.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:24 -0800 (PST)
Received-SPF: pass (google.com: domain of 3nzejxwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id d18so6550367qvp.15
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:24 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:55ea:: with SMTP id
 bu10mr282677qvb.28.1604532023877; Wed, 04 Nov 2020 15:20:23 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:47 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <5d9ece04df8e9d60e347a2f6f96b8c52316bfe66.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 32/43] arm64: mte: Switch GCR_EL1 in kernel entry and exit
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
 header.i=@google.com header.s=20161025 header.b=QOLfmd7s;       spf=pass
 (google.com: domain of 3nzejxwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3NzejXwoKCTYSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I0081cba5ace27a9111bebb239075c9a466af4c84
---
 arch/arm64/include/asm/mte-def.h |  1 -
 arch/arm64/include/asm/mte.h     |  2 ++
 arch/arm64/kernel/asm-offsets.c  |  3 +++
 arch/arm64/kernel/entry.S        | 41 ++++++++++++++++++++++++++++++++
 arch/arm64/kernel/mte.c          | 28 +++++++++++++++++++---
 5 files changed, 71 insertions(+), 4 deletions(-)

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
index 14b0c19a33e3..cc7e0f8707f7 100644
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
@@ -123,6 +125,23 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 
 void __init mte_init_tags(u64 max_tag)
 {
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
+
 	/* Enable MTE Sync Mode for EL1. */
 	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
 	isb();
@@ -163,7 +182,11 @@ static void update_gcr_el1_excl(u64 excl)
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
@@ -189,7 +212,6 @@ void mte_thread_switch(struct task_struct *next)
 	/* avoid expensive SCTLR_EL1 accesses if no change */
 	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
 		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
-	update_gcr_el1_excl(next->thread.gcr_user_excl);
 }
 
 void mte_suspend_exit(void)
@@ -197,7 +219,7 @@ void mte_suspend_exit(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5d9ece04df8e9d60e347a2f6f96b8c52316bfe66.1604531793.git.andreyknvl%40google.com.
