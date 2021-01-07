Return-Path: <kasan-dev+bncBDGPTM5BQUDRBBWR3L7QKGQETD636HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id A24902ECA70
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Jan 2021 07:21:59 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id m9sf3866973ioa.9
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jan 2021 22:21:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610000518; cv=pass;
        d=google.com; s=arc-20160816;
        b=M1y9L+8zFaJCp0qwkyLrVIHfGPTcb1g3ZdyRdpBZL94D2Eq1mTDRcgb2DkTUwh6v/D
         rnm5dQa29eTVKn/+uyFwY3Pc8UPrFXXVuq1uWuzLqVy0yV6t8PBXiemySiQW8bKa4S9Z
         mJILf2KcQLc4Ezv6KUL5rY8TAtxsvmq6J9144Qh7khXvH+G23SQCaolTaRpEE+zVquYL
         035cifng++vcOjZ4ugmmgzeqzp6Y+DN2LLWpc5Xo1exRIseQj1hxdeve/WFx8zHaf1wd
         7ff0wSoxG1nD0btVajX7Lc1vzCLee/co9ThznCQnBjykc86P5Oyn6axdcd5wb2e0rbmT
         LkUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=SOpIV11h3G2+C6sHnE62LQUmrRYkM276vTkbw4SmyTI=;
        b=0GT3hxlEpzSJrxP2DttAZFv3DU62dT92XzF/hqhUOkpjatep5blBGfDwQGrZWSbNK7
         Si+HMnW+rbQPF3NdEhlIIi38DxlHMkqlVY/BrFMaj9oaslxenAKkDe5HK2YBUrlq+1qE
         9ytNIDs1sNXYRpLnkRhfkuRDR/gPPj+sGvvD+o75GxO+756J6o82mW+dWO1yQyeb8Ldj
         WZyVN6UKr8WVrQitXP6NQNskijiPMsXK4NYnd/KUdlBCwgjhjmiXxNZ7VSom7w6Ab/gs
         xJvSuydRFMpxirgTw4En6NoPH3BH3sIGpbXtwv/gXKK2QrNdJaRJODiO9D+8ur1BrFUX
         mfBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SOpIV11h3G2+C6sHnE62LQUmrRYkM276vTkbw4SmyTI=;
        b=MBv4LndQ7RxHuMXtUNGs2bVPr8kY9iYlUVthlNb/7nslRIcEi20ihy74nXMz9qQxBI
         coKwHRnYv/4IdQPcJu2AXxfLjs7E7reJRuwZyOWsiwFxp4LNo2ZNurUIvLzIsOq3++al
         tgXAmbx+pDSYMuI9inmZcSu4KrvlIPWml8leZqm6zELQVc/CEjQaXKQHGNpUSU10WMDf
         1zPVyywI+zqNXHV1ibyV462/ntEPFeIM3mXR4giccZW0ltKbhOdnmNfKVDR3n+VcUCl1
         qasnDD/Oz6NeArvFcQQXzZNzuXDrGHqVgZpa9r1W9d8WkGbs/cQZxcsms/I7F+zisFwX
         P7Zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SOpIV11h3G2+C6sHnE62LQUmrRYkM276vTkbw4SmyTI=;
        b=TA3RIrMTUOjd7O6JduFGcuW1/Lhz0DB144fiUV7yk3nzg6DOKyroX0EdX/eMqE6+Yv
         8AN+4Yix78mzIz2/cPs9+txpw05499aiguOuyJ6LK6L1UuxaMG+dltMWUdRxE+M/zKhq
         KaOVb1WZTtmSca7L6tpU7PRuw0D2AsflfUBD+IKUhFqG3XJY6lJjeNUHwCJyVEnMr2s1
         aS6gAVUa2+IZNm+Y+19l8godGmkUCI0xzBYAwJY1AzevjNv+iR5cTn81WngT3B1QdNgZ
         fHodp4UcJ2RP0E1AWZ1xElZHrGACcfcET2M/wxx8UjjvEMeVnvo4GH+Gq0Jf0MtbEW+g
         gsGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531cQUHtUaIYqCi96tvhK1Kf+KBRWuFrhKZtGG8MzigMBCbrp/ZT
	F91B2Lk9UBvnuObRK9pv7IE=
X-Google-Smtp-Source: ABdhPJxAtmTYBwrL9/ByGHAjAV2Yg/OH6p+Luxnj2aEXDX1gtedgzJW4heiIDcNwV2PfQNmKpQme5Q==
X-Received: by 2002:a92:9806:: with SMTP id l6mr8112586ili.304.1610000518658;
        Wed, 06 Jan 2021 22:21:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a0c:: with SMTP id s12ls1649825ild.8.gmail; Wed,
 06 Jan 2021 22:21:58 -0800 (PST)
X-Received: by 2002:a05:6e02:12ce:: with SMTP id i14mr7734100ilm.248.1610000518224;
        Wed, 06 Jan 2021 22:21:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610000518; cv=none;
        d=google.com; s=arc-20160816;
        b=OGgY7dEYXJ9ZzRrKBgVhPM9CSme8XLXsJVCVfOJZ7DR+7p6lHHyYvYIgBhhqralHZx
         dMiWpHAO2A0aRQ6ULIQmCQgNmrkpUr3mlRY6Mk+RErdoatyU4c5E7Rh9iE2Mg/BEnh4f
         xg98D9pzSslSOaBRTrgFg0nE3ljqbhQCpGb2humML41ra0N/ZxS2KiY44e24tVF+2ckY
         SHIFmP8v0kGozrfns4z5eMxc4wDus/Ai5TVfPmWa+pnbRsrEBglpcjz0vWcoJvUGGssG
         j7/g+r8k0qoCUKmbAsrqYxdgfhvUylAYXUUZLdnyl7vfRctVqtvCkdxv3Yoo12qddih6
         ZYXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=/RtcymSInVuJ7KntFDE3qUuasWKFL/7LFHTGLVWArdE=;
        b=xE8xcNYoCqkJkYjpgMLntLYWtJEsNi4LcBTQHub7L44UklLUg4qQJzLVQh7HVNGlvg
         Ou0NTWDvKPNbI2t9LFUKf2sbmnqMXMYx2d05lotyrbsDqhZVb6jeoLUqprG/2ZIaNmMm
         PhCRsG668+3NAYp+qkF7dEZrBvGGTgPhGyFmtS0XGaAixbVkeimzM0LkvraJWzs8xr0B
         LnSxmGGCkwnmehUDi9M4SXxYijbpHHpXXdyY7u6io7rQPlELUMw0p/Yptr0XhR/G6jaH
         oyAcGq4vqC214QVQxeq/dkFopM3X6ozihpWtS1jKP9lFzl0vnsfWMKkOhGGeKHe5M6V0
         n8FA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id u14si479452ilv.0.2021.01.06.22.21.57
        for <kasan-dev@googlegroups.com>;
        Wed, 06 Jan 2021 22:21:57 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: d9acb21fcb16438098fa051995d53966-20210107
X-UUID: d9acb21fcb16438098fa051995d53966-20210107
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1659296278; Thu, 07 Jan 2021 14:21:55 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 7 Jan 2021 14:21:53 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 7 Jan 2021 14:21:54 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov
	<andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH] kasan: remove redundant config option
Date: Thu, 7 Jan 2021 14:21:52 +0800
Message-ID: <20210107062152.2015-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

CONFIG_KASAN_STACK and CONFIG_KASAN_STACK_ENABLE both enable KASAN
stack instrumentation, but we should only need one config option,
so that we remove CONFIG_KASAN_STACK_ENABLE. see [1].

For gcc we could do no prompt and default value y, and for clang
prompt and default value n.

[1]: https://bugzilla.kernel.org/show_bug.cgi?id=210221

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---
 arch/arm64/kernel/sleep.S        |  2 +-
 arch/x86/kernel/acpi/wakeup_64.S |  2 +-
 include/linux/kasan.h            |  2 +-
 lib/Kconfig.kasan                | 11 ++++-------
 mm/kasan/common.c                |  2 +-
 mm/kasan/kasan.h                 |  2 +-
 mm/kasan/report_generic.c        |  2 +-
 scripts/Makefile.kasan           | 10 ++++++++--
 8 files changed, 18 insertions(+), 15 deletions(-)

diff --git a/arch/arm64/kernel/sleep.S b/arch/arm64/kernel/sleep.S
index 6bdef7362c0e..7c44ede122a9 100644
--- a/arch/arm64/kernel/sleep.S
+++ b/arch/arm64/kernel/sleep.S
@@ -133,7 +133,7 @@ SYM_FUNC_START(_cpu_resume)
 	 */
 	bl	cpu_do_resume
 
-#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
+#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
 	mov	x0, sp
 	bl	kasan_unpoison_task_stack_below
 #endif
diff --git a/arch/x86/kernel/acpi/wakeup_64.S b/arch/x86/kernel/acpi/wakeup_64.S
index 5d3a0b8fd379..c7f412f4e07d 100644
--- a/arch/x86/kernel/acpi/wakeup_64.S
+++ b/arch/x86/kernel/acpi/wakeup_64.S
@@ -112,7 +112,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
 	movq	pt_regs_r14(%rax), %r14
 	movq	pt_regs_r15(%rax), %r15
 
-#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
+#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
 	/*
 	 * The suspend path may have poisoned some areas deeper in the stack,
 	 * which we now need to unpoison.
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 5e0655fb2a6f..35d1e9b2cbfa 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -302,7 +302,7 @@ static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
 
 #endif /* CONFIG_KASAN */
 
-#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
+#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
 void kasan_unpoison_task_stack(struct task_struct *task);
 #else
 static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index f5fa4ba126bf..59de74293454 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -138,9 +138,11 @@ config KASAN_INLINE
 
 endchoice
 
-config KASAN_STACK_ENABLE
-	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
+config KASAN_STACK
+	bool "Enable stack instrumentation (unsafe)"
 	depends on KASAN_GENERIC || KASAN_SW_TAGS
+	default y if CC_IS_GCC
+	default n if CC_IS_CLANG
 	help
 	  The LLVM stack address sanitizer has a know problem that
 	  causes excessive stack usage in a lot of functions, see
@@ -154,11 +156,6 @@ config KASAN_STACK_ENABLE
 	  CONFIG_COMPILE_TEST.	On gcc it is assumed to always be safe
 	  to use and enabled by default.
 
-config KASAN_STACK
-	int
-	default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
-	default 0
-
 config KASAN_SW_TAGS_IDENTIFY
 	bool "Enable memory corruption identification"
 	depends on KASAN_SW_TAGS
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 38ba2aecd8f4..02ec7f81dc16 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -63,7 +63,7 @@ void __kasan_unpoison_range(const void *address, size_t size)
 	unpoison_range(address, size);
 }
 
-#if CONFIG_KASAN_STACK
+#if defined(CONFIG_KASAN_STACK)
 /* Unpoison the entire stack for a task. */
 void kasan_unpoison_task_stack(struct task_struct *task)
 {
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index cc4d9e1d49b1..bdfdb1cff653 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -224,7 +224,7 @@ void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
 void metadata_fetch_row(char *buffer, void *row);
 
-#if defined(CONFIG_KASAN_GENERIC) && CONFIG_KASAN_STACK
+#if defined(CONFIG_KASAN_GENERIC) && defined(CONFIG_KASAN_STACK)
 void print_address_stack_frame(const void *addr);
 #else
 static inline void print_address_stack_frame(const void *addr) { }
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 8a9c889872da..137a1dba1978 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -128,7 +128,7 @@ void metadata_fetch_row(char *buffer, void *row)
 	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
 }
 
-#if CONFIG_KASAN_STACK
+#if defined(CONFIG_KASAN_STACK)
 static bool __must_check tokenize_frame_descr(const char **frame_descr,
 					      char *token, size_t max_tok_len,
 					      unsigned long *value)
diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 1e000cc2e7b4..abf231d209b1 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
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
-		-mllvm -hwasan-instrument-stack=$(CONFIG_KASAN_STACK) \
+		-mllvm -hwasan-instrument-stack=$(stack_enable) \
 		-mllvm -hwasan-use-short-granules=0 \
 		$(instrumentation_flags)
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210107062152.2015-1-walter-zh.wu%40mediatek.com.
