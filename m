Return-Path: <kasan-dev+bncBCT4XGV33UIBBXMD56BAMGQERUFOD4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id BDD6D3484E5
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 23:49:02 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id j19sf4107512ybg.5
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 15:49:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616626141; cv=pass;
        d=google.com; s=arc-20160816;
        b=A778Y8qQxcE19E5pPNaqUCk3zplNcB1kMFDCSE6RllkYpiGZg9NzE4oBhCSe3nZlue
         NWjP4DY6cAWzocWU4+6OCEDjlrjY9ZL0JFfyyUvLUxOYy1s08APNEL7b0ymcUTqwo3HI
         KlPYxelNlkWqEITx9IBpR3ekHg14yuIgH+NG0d3ABtT9dA5I7JrV9Lig4tvtHBrlPDA6
         LLN+MtXY0yRjXqr3ifgvHzhyCjsFUjzgKlWsHyQCOtOf0D5oFwhhPdx3c6VyWftOZY89
         Gvuv6Z7LFLUDW7rpW0LrqpeqPxcZNtOVD2RKmvMhED4rxfVGFcHFT0FqG0m4FbVZBX4v
         0qKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=a/B2ZvlalWJYY9apOM+yHOawRolqJojMEvFEJkcIkfw=;
        b=qM4Xt6A/Gz5ioMXF8ckuUkmOPk3OC98a4jVfvkigDFf00J6deTxz+poMJ5kzs0FYnO
         NRLJqe1vtZTmcaDGENUQ4jjcoPeCFI/PoeDNw5STeLuL1ZIdOtpDpf/b45sLq856CkOS
         0W24YRxxpGurtRL2wOO7u0skEixG1N4k5Tn4oCqjWdnA6/LycSc3+hB9bPEY9dKnc9do
         CfTuZ4l8Ted7C4vwKT1OZAcD4WdnujVu8hlKz/w3wPLHJf7shDH4YFiPwYirhPTE35t/
         JMHhHAlpA0cfv1bRVcJe9jWL3GkrHbtmYLuBTvRv8XWMaN5BKHFT4ZnnP34MiGP6BtTE
         Y8/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=nq2n5Hk6;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a/B2ZvlalWJYY9apOM+yHOawRolqJojMEvFEJkcIkfw=;
        b=IcZNgxwWR2I8m0H5QygfQnXmcn7agBuHXtWFoxjZWAQMuf3JsZb0Fo5YLVsevC6Jbb
         EBq9L7Kaebdm84IQk+s96GK3fTbOLxgiVGPZnwC9+7ke5y8qwvlNxyMoKiTQNzadlG2C
         0Mzv5+z87pBY+1HufVsPk3EKm332bTLvVIG4BucMsYi+0RSXzmTL3ETQh9Utfhw9cRud
         J8taowhhRrhRPHiB4It1Ynb32bVqZ7SSY/sDf4HVcvx8l7EziEgWqrQuIv3Zv732+FVi
         c7y5czSVfqWcP5wAKPzws45I0yux/ZMVGmaSqFFQcGCiif87VBsw39aaore72FvOmgJk
         p9Cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a/B2ZvlalWJYY9apOM+yHOawRolqJojMEvFEJkcIkfw=;
        b=DELyv6PhPE2EZvoV2IDZRuLlBPdLKCni8HWRh/JsaYG8/pO1aR9nuVi8oDogoHj74Q
         yh+BDu1i6Qzu5q1P48TriIF8ZP+iKULZiLzs0lb+hZtkw/2jvmv3Qz69z5OV4zhHbT7R
         c0zOUni47pMH8s48AV1azXhl/KEiKenAW5UEmoASldzkN92nKF1HKs0ZPFyV2C+wM7Ys
         6VFAxGpKORdS+nALKBk5vVYq2TUsAtrQ/8arqcPjTK2LEBitPy1EK6FliA26BZFgoLgx
         RVOxuOKNeupJduQ48DJU/efPc6blGlWefxpMsuxAc48+dqjS5mwQxZrDq+fz650BVJZg
         sL0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533JVeHE8bgImRxySPNQzJzhtnnLS/6yVCtHSKjd8cDL/112QLfy
	WOtNuNhfnpMFwLxk4+zYBRc=
X-Google-Smtp-Source: ABdhPJzbb8GL39AVf17AQEdyDPy2HiuNfL38Ta0nDEnbtWvY7T0e2A0ZMgg4ejMTOqUWDk1NGLhrQQ==
X-Received: by 2002:a25:5f46:: with SMTP id h6mr8171293ybm.255.1616626141661;
        Wed, 24 Mar 2021 15:49:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7807:: with SMTP id t7ls1759068ybc.10.gmail; Wed, 24 Mar
 2021 15:49:01 -0700 (PDT)
X-Received: by 2002:a25:5704:: with SMTP id l4mr8764461ybb.338.1616626141170;
        Wed, 24 Mar 2021 15:49:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616626141; cv=none;
        d=google.com; s=arc-20160816;
        b=cC/ovJylScI6Qn/XR5+HjiuRVlTX8RO2byIG4fFauIpTIi+59ztV/D2DITgLDarbuv
         P21ZXuo2UjWM3zukvujzCyROPS7HopL/w5XbhMhTHFWrJZVE0M/Gtq44blstCiec/Ly1
         eaQoNdYwhTjHdazcjNsvM1A9nHKPZYIHt46mRDUyXJj5yGOZ0E5mJog+49jHdgHbtyFY
         Jwsu+geZz0R++XW/wvDrOWiKSmS2x5biRQTKA84MrjE9AHxHwQpAQhJqVqcMoe0AMffH
         pUyJRuKXRrqp1EIr2ecdsN/DtIOJDMEwy2f+PZ6GJVCE4kXUSfYzqyIf08ER5vfOGGo9
         tHFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=+ZNmOfQDDMY13VM98iI+bF8kJZR5rrH4L+X1c1p3QRo=;
        b=fI59Fg+qVCYlJ+6iWZtwGeFpKqiSboI2s/unE4Ywvaq31YFFYV4pn/KbSbfJqLCrha
         YmrQ0bW8h10bCSca4yw7ig1Ujx2T67PWieZRftX/yopszi7omAiGyHRzHotOEhIU2hO3
         WTTdSnN6z+sIRpP44GPsS40BomV19ij6G+19IEbRQlCY5vMBx5CSjE7os6LFHwecYpAN
         zijEEmhpO2gUTGn3qn6el6uqCIKNFQ1ysQZja9o6X4y7T7oOdT1DK2t/04NhskwHKDJQ
         tE8YlsICCVAn2/9uQoq5K7kcwJhSX52CKv9KbN9UlfWz7mYANGmwmjVBZ6opZr2EtErk
         XNlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=nq2n5Hk6;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x7si248789ybm.0.2021.03.24.15.49.01
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Mar 2021 15:49:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id B852561A0A;
	Wed, 24 Mar 2021 22:48:59 +0000 (UTC)
Date: Wed, 24 Mar 2021 15:48:59 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@kernel.org>, Masahiro Yamada <masahiroy@kernel.org>,
 Michal Marek <michal.lkml@markovi.net>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Nathan Chancellor <nathan@kernel.org>, Nick
 Desaulniers <ndesaulniers@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Alexander Potapenko <glider@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Linux Kbuild
 mailing list <linux-kbuild@vger.kernel.org>, kasan-dev
 <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>,
 clang-built-linux <clang-built-linux@googlegroups.com>
Subject: Re: [PATCH] kasan: fix hwasan build for gcc
Message-Id: <20210324154859.4de61fdafd1b4ea85bec869f@linux-foundation.org>
In-Reply-To: <CANpmjNM8D+yp==DmKP0aa+g6=P38o0v6gd7y5iV52yyDUv91qw@mail.gmail.com>
References: <20210323124112.1229772-1-arnd@kernel.org>
	<CANpmjNM8D+yp==DmKP0aa+g6=P38o0v6gd7y5iV52yyDUv91qw@mail.gmail.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=nq2n5Hk6;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 23 Mar 2021 13:51:32 +0100 Marco Elver <elver@google.com> wrote:

> On Tue, 23 Mar 2021 at 13:41, Arnd Bergmann <arnd@kernel.org> wrote:
> >
> > From: Arnd Bergmann <arnd@arndb.de>
> >
> > gcc-11 adds support for -fsanitize=kernel-hwaddress, so it becomes
> > possible to enable CONFIG_KASAN_SW_TAGS.
> >
> > Unfortunately this fails to build at the moment, because the
> > corresponding command line arguments use llvm specific syntax.
> >
> > Change it to use the cc-param macro instead, which works on both
> > clang and gcc.
> >
> > Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> 
> Reviewed-by: Marco Elver <elver@google.com>
> 
> Although I think you need to rebase against either -mm or -next,
> because there have been changes to the CONFIG_KASAN_STACK variable.

This fix is applicable to 5.12, so it's better than the 5.13 patches in
-mm be changed to accomodate this patch.

afaict the only needed change was to update
kasan-remove-redundant-config-option.patch as below.  The
scripts/Makefile.kasan part was changed:

@@ -42,7 +48,7 @@ else
 endif
 
 CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
-		$(call cc-param,hwasan-instrument-stack=$(CONFIG_KASAN_STACK)) \
+		$(call cc-param,hwasan-instrument-stack=$(stack_enable)) \
 		$(call cc-param,hwasan-use-short-granules=0) \
 		$(instrumentation_flags)
 


Whole patch:

--- a/arch/arm64/kernel/sleep.S~kasan-remove-redundant-config-option
+++ a/arch/arm64/kernel/sleep.S
@@ -134,7 +134,7 @@ SYM_FUNC_START(_cpu_resume)
 	 */
 	bl	cpu_do_resume
 
-#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
+#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
 	mov	x0, sp
 	bl	kasan_unpoison_task_stack_below
 #endif
--- a/arch/x86/kernel/acpi/wakeup_64.S~kasan-remove-redundant-config-option
+++ a/arch/x86/kernel/acpi/wakeup_64.S
@@ -115,7 +115,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
 	movq	pt_regs_r14(%rax), %r14
 	movq	pt_regs_r15(%rax), %r15
 
-#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
+#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
 	/*
 	 * The suspend path may have poisoned some areas deeper in the stack,
 	 * which we now need to unpoison.
--- a/include/linux/kasan.h~kasan-remove-redundant-config-option
+++ a/include/linux/kasan.h
@@ -330,7 +330,7 @@ static inline bool kasan_check_byte(cons
 
 #endif /* CONFIG_KASAN */
 
-#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
+#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
 void kasan_unpoison_task_stack(struct task_struct *task);
 #else
 static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
--- a/lib/Kconfig.kasan~kasan-remove-redundant-config-option
+++ a/lib/Kconfig.kasan
@@ -138,9 +138,10 @@ config KASAN_INLINE
 
 endchoice
 
-config KASAN_STACK_ENABLE
+config KASAN_STACK
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
 	depends on KASAN_GENERIC || KASAN_SW_TAGS
+	default y if CC_IS_GCC
 	help
 	  The LLVM stack address sanitizer has a know problem that
 	  causes excessive stack usage in a lot of functions, see
@@ -155,7 +156,7 @@ config KASAN_STACK_ENABLE
 	  to use and enabled by default.
 
 config KASAN_STACK
-	int
+	bool
 	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
 	default 0
--- a/mm/kasan/common.c~kasan-remove-redundant-config-option
+++ a/mm/kasan/common.c
@@ -63,7 +63,7 @@ void __kasan_unpoison_range(const void *
 	kasan_unpoison(address, size);
 }
 
-#if CONFIG_KASAN_STACK
+#ifdef CONFIG_KASAN_STACK
 /* Unpoison the entire stack for a task. */
 void kasan_unpoison_task_stack(struct task_struct *task)
 {
--- a/mm/kasan/kasan.h~kasan-remove-redundant-config-option
+++ a/mm/kasan/kasan.h
@@ -231,7 +231,7 @@ void *kasan_find_first_bad_addr(void *ad
 const char *kasan_get_bug_type(struct kasan_access_info *info);
 void kasan_metadata_fetch_row(char *buffer, void *row);
 
-#if defined(CONFIG_KASAN_GENERIC) && CONFIG_KASAN_STACK
+#if defined(CONFIG_KASAN_GENERIC) && defined(CONFIG_KASAN_STACK)
 void kasan_print_address_stack_frame(const void *addr);
 #else
 static inline void kasan_print_address_stack_frame(const void *addr) { }
--- a/mm/kasan/report_generic.c~kasan-remove-redundant-config-option
+++ a/mm/kasan/report_generic.c
@@ -128,7 +128,7 @@ void kasan_metadata_fetch_row(char *buff
 	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
 }
 
-#if CONFIG_KASAN_STACK
+#ifdef CONFIG_KASAN_STACK
 static bool __must_check tokenize_frame_descr(const char **frame_descr,
 					      char *token, size_t max_tok_len,
 					      unsigned long *value)
--- a/scripts/Makefile.kasan~kasan-remove-redundant-config-option
+++ a/scripts/Makefile.kasan
@@ -2,6 +2,12 @@
 CFLAGS_KASAN_NOSANITIZE := -fno-builtin
 KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
 
+ifdef CONFIG_KASAN_STACK
+	stack_enable := 1
+else
+	stack_enable := 0
+endif
+
 ifdef CONFIG_KASAN_GENERIC
 
 ifdef CONFIG_KASAN_INLINE
@@ -27,7 +33,7 @@ else
 	CFLAGS_KASAN := $(CFLAGS_KASAN_SHADOW) \
 	 $(call cc-param,asan-globals=1) \
 	 $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
-	 $(call cc-param,asan-stack=$(CONFIG_KASAN_STACK)) \
+	 $(call cc-param,asan-stack=$(stack_enable)) \
 	 $(call cc-param,asan-instrument-allocas=1)
 endif
 
@@ -42,7 +48,7 @@ else
 endif
 
 CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
-		$(call cc-param,hwasan-instrument-stack=$(CONFIG_KASAN_STACK)) \
+		$(call cc-param,hwasan-instrument-stack=$(stack_enable)) \
 		$(call cc-param,hwasan-use-short-granules=0) \
 		$(instrumentation_flags)
 
--- a/security/Kconfig.hardening~kasan-remove-redundant-config-option
+++ a/security/Kconfig.hardening
@@ -64,7 +64,7 @@ choice
 	config GCC_PLUGIN_STRUCTLEAK_BYREF
 		bool "zero-init structs passed by reference (strong)"
 		depends on GCC_PLUGINS
-		depends on !(KASAN && KASAN_STACK=1)
+		depends on !(KASAN && KASAN_STACK)
 		select GCC_PLUGIN_STRUCTLEAK
 		help
 		  Zero-initialize any structures on the stack that may
@@ -82,7 +82,7 @@ choice
 	config GCC_PLUGIN_STRUCTLEAK_BYREF_ALL
 		bool "zero-init anything passed by reference (very strong)"
 		depends on GCC_PLUGINS
-		depends on !(KASAN && KASAN_STACK=1)
+		depends on !(KASAN && KASAN_STACK)
 		select GCC_PLUGIN_STRUCTLEAK
 		help
 		  Zero-initialize any stack variables that may be passed
_

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324154859.4de61fdafd1b4ea85bec869f%40linux-foundation.org.
