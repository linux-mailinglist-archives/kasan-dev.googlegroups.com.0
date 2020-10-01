Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOWE3H5QKGQEDE7HFRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id CFBED280B17
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:55 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id h8sf75564vsh.19
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593915; cv=pass;
        d=google.com; s=arc-20160816;
        b=NCG2s1Y4mlBOvbUHFGeOYc9Dkb71QTdg1uMr/mNxYFWhz1iENx6oLL1polp8/7Dngm
         0IuNKCt8nC5wBZjnBp0ONGZS+sZQqFhmeQK8u/CZuBGks1Ou8A5Bm0moWWPULjJbwmOB
         Twu18FCmdHi/wBXKMbT0b5L0SZlVltRcOeSgg4zcCBkKHTcG7KqHMaPx5/QESnIaSqAB
         67e3iSUD3IsheOa+kdfD/WcCjQX9JzgKErwmQyfox3/69xnlPEgOBUAmbZvK6GyVbQn0
         8EirUjOw8DDv6LcHq56LpgCXeHXtLD4rR9ZYjFhziGMtEJBTyC8rODuWmZvIRIKhv96m
         vYhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=UlUSMak7d8yi9ZtnMw/OGIDhVNWBZSGccBu4YuGjgbA=;
        b=c4oINR7SuS4UZHx1mdT2pKRwd2fb4C4qWxYsuLkdKQQKm/2pNI9Gar/CPgb6Nls+RY
         89Pzvg2bHRIALXYSEWiQYfte7NFPO1CWb8xwG/wQ/WA66q1i1WzkWBzdFaD36Ozu4D1J
         i1FvgJTZdDoB0IGgx23J95UzRvb4MQCHSIQbAyQMTAarmkmMyibRwCjnlVHcAanIgXCw
         3/zPBYx5FiRyQWonKu9vjjFFgqWIVYA7qHopvsIJplpiN8bDha9v6lDQ9GnPUj9cZr9s
         rUjKq9Y5/RXzVmIcRRGRPJWpGfDHMVJEff3YWxLB7tH/WegDJthM8uSSReIRiEOGYV88
         8N+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eqamaMyG;
       spf=pass (google.com: domain of 3owj2xwokcdg4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3OWJ2XwoKCdg4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UlUSMak7d8yi9ZtnMw/OGIDhVNWBZSGccBu4YuGjgbA=;
        b=rURgJ7ZwQkNjN7hslsuJUaxmoyTGkoXU1vAPLUSUCe5atykqsVGiOV1CFVQ8wfGG7p
         UMIKBEVojOd/SS6i2txr6G+R1GNF+W76z54tAQFJj/OXuPI0eLNCWT2U3aPQJLudwy5W
         ap6Emliy6VW6rN/wC0X1k6PxLxWeV+GxO1knXpszMy19HBa9IgYk6sQhAlidIcjooo9K
         fmSxnIOANSRwmkpYHmK0XrM7a5y9k/E54mFEP5lULY35mGXw7e+2KmIikqznds6GTsM5
         zibkGED73aKnV8Omt4xTKLzxbBwG1jaVXjhRlEg4cJWA0A7RblXhQVJvwwjzAXkWBiuP
         ZXcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UlUSMak7d8yi9ZtnMw/OGIDhVNWBZSGccBu4YuGjgbA=;
        b=MQSZaMocyye/vgHGkjE8U6QfNLmIuEpQL/ifykxDYXf9/dnBcmTSm9l+sH8fXOyd9A
         ttyo8Sy4pwP+O3A7DYtXbOINhiIB4p0m4aFXA4cXOQbO+uhhaQbOAQDSy8A6si8ypu8M
         8/k7+CNzpGyfd5X1KFOnNQAJFpPOtKDmzLbsX34z8lDcpCl0OJTE8D7fB7APOVIixO1U
         JaxVAvti9PyBuyoaD5Je44AuLVGDsDKLDMOKenh8GAxcExfW+HeQEo+QOetFox/Q1mtp
         4Qr12wYmsPOjvX7ct2dL2AuwehCzPq/YsYzDR012488f1oPbSMSkOoGItCUvOi/Qx3UA
         skpQ==
X-Gm-Message-State: AOAM532wrvqtkY9Ye2gv9ua7ARKP0d5EzKEToV6iCOTz0nZM3i8cDmLA
	lX4nVdSp86DfjqNomVcGIhA=
X-Google-Smtp-Source: ABdhPJwpZs6eZGom+CnyL4M0ysSD4lbiCh4RUpk1Wq+DDtzXc5AMOglKV0Wfs8HLHoYn7emkFS30cA==
X-Received: by 2002:ab0:6708:: with SMTP id q8mr6915924uam.139.1601593914897;
        Thu, 01 Oct 2020 16:11:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:bfcb:: with SMTP id p194ls384455vkf.8.gmail; Thu, 01 Oct
 2020 16:11:54 -0700 (PDT)
X-Received: by 2002:a1f:a94c:: with SMTP id s73mr6817904vke.19.1601593914398;
        Thu, 01 Oct 2020 16:11:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593914; cv=none;
        d=google.com; s=arc-20160816;
        b=TvpgChKZ6Yww2TD0lnh9C0dyL78z1sbUng/vEMAz4OgiYi+PG6sflnqbD3c6d+zdDm
         WoAne3cEn13PKkmCjcgqpdqZEAJ3Q4vWH4Ebnu6rMgEyl//+Q58L39jbClR7Ik0HgRQd
         eqoQciL64FTgDSX8ELwclwyj4ZjCR/dVlh4Io3QIeSTk7m9HWGDjN4Ir37gOgKNWUm+v
         nlN1GSKT/bcdrRIr8ewUrPYewMj7a3eqKTTR+s17jCj9kr2MtJv5FmWfWAt7/96xG5LZ
         jmMB3KMqRZUU44tQ7r2W7tZq10fuRLeWF0KHWf2qWepvjG+MiGauG6KNnj8RE4ANEgeK
         OXcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=eriXeedY9+UywDi2qWo7RghhjAzjAQSNbHMqcD58SBQ=;
        b=NJb1E8qllOZF2s5Yz+rRXa7GNWlxhB+6OlQMkJNWaeXqyVQw6254+t1izeyekblgI6
         O2XEeCdIMIPZzm64GEvb/VPo+UEW6KSl7ItA2oBza6nBtghUjEyiI1JPaUnc4T+6UP01
         3FZYv7V6uz7akaLR9zEmF7peQqXsqPe98VN4CN+KO4v4MnTvKbgj65Jy+iO9bfq1x5/X
         83zehMCfGHQHaSWIRgEtI6KIdMf/WVR5bJmLq+oUKGjWWbA3exFbZjBXvK6hv1drMKJP
         7k7gYTHAbAyJwvPL6NR3vIFveJZNHwmsptcKpNcukICg3HbSjiZ+9bCF4inBClzXt3oj
         ZgOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eqamaMyG;
       spf=pass (google.com: domain of 3owj2xwokcdg4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3OWJ2XwoKCdg4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id p129si404260vkg.3.2020.10.01.16.11.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3owj2xwokcdg4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id e19so79113qtq.17
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:54 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:58aa:: with SMTP id
 ea10mr10043170qvb.58.1601593913975; Thu, 01 Oct 2020 16:11:53 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:30 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <1f2681fdff1aa1096df949cb8634a9be6bf4acc4.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 29/39] arm64: mte: Switch GCR_EL1 in kernel entry and exit
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
 header.i=@google.com header.s=20161025 header.b=eqamaMyG;       spf=pass
 (google.com: domain of 3owj2xwokcdg4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3OWJ2XwoKCdg4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
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
 arch/arm64/include/asm/mte-kasan.h |  6 +++++
 arch/arm64/include/asm/mte.h       |  2 ++
 arch/arm64/kernel/asm-offsets.c    |  3 +++
 arch/arm64/kernel/cpufeature.c     |  3 +++
 arch/arm64/kernel/entry.S          | 41 ++++++++++++++++++++++++++++++
 arch/arm64/kernel/mte.c            | 18 ++++++++++---
 6 files changed, 70 insertions(+), 3 deletions(-)

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
index 7c67ac6f08df..d1847f29f59b 100644
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
@@ -120,6 +122,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
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
@@ -155,7 +164,11 @@ static void update_gcr_el1_excl(u64 excl)
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
@@ -181,7 +194,6 @@ void mte_thread_switch(struct task_struct *next)
 	/* avoid expensive SCTLR_EL1 accesses if no change */
 	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
 		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
-	update_gcr_el1_excl(next->thread.gcr_user_excl);
 }
 
 void mte_suspend_exit(void)
@@ -189,7 +201,7 @@ void mte_suspend_exit(void)
 	if (!system_supports_mte())
 		return;
 
-	update_gcr_el1_excl(current->thread.gcr_user_excl);
+	update_gcr_el1_excl(gcr_kernel_excl);
 }
 
 long set_mte_ctrl(struct task_struct *task, unsigned long arg)
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1f2681fdff1aa1096df949cb8634a9be6bf4acc4.1601593784.git.andreyknvl%40google.com.
