Return-Path: <kasan-dev+bncBDGPTM5BQUDRBE444GAQMGQEDX5B36Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B79A325B40
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Feb 2021 02:25:40 +0100 (CET)
Received: by mail-vk1-xa3d.google.com with SMTP id u123sf1501901vku.15
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 17:25:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614302739; cv=pass;
        d=google.com; s=arc-20160816;
        b=0X0Dwb1GCBeodPguxIBp/EVuoRMfxc13Yl2VIs8Vw3e2N7b48uljzzpAoxIgBVygx6
         glPYs5Ruch+j+c4h6TNp4TH9Fg0oaMKrhGPPVjteuRXK5eXdfVo3AWV0EZc8leEc20d3
         bb03h2+wvZwixHTq+X72hWjTLdP6fVuMFpE5g98XK3g+7/Kg5m6dW/Q0jrQQYHJRBtHh
         R+AYVc7px0Ekjbr/tfVdKs2+7CEuvi8z36FMyRNUphWRo21dN3MKbsOaVHQLM9fT/Cqi
         LP1fhguAmt9UmH1sv7/Q4ScVDeK2XX7hQJiqCfCsriTFEp8idN0JKwHzIyUtmpylUO9Q
         p+sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=OMZWo/wKMNqYBXBoOxNwoQDZxVzpeWuGTPsMUHMplls=;
        b=GhOJeiT8/cUxupXNYskDwEZe7rGr4q8ItRbVJwnhu7/N45DasUS9x82n9HozaG96CG
         LByXKiQiu1GHmBGiK/+1AmMXNJAbSg9RTS3qCNLwgR+jgxtjP5Y2F+pIJ2sTX/7sXRo3
         1AvCGbjxrfBuqE0GoHWCXmk42due6Nr6nXoFcfW5PQZFUkNcliZKs6TwXd1AbtjFbTWT
         kbQPcHEtKP5pYTijIaipCWHH7kh3aLp6RWqotzi5kNn/WiiOJyeBVRI/EUFfEz4w1xBv
         vlbJNtL8qwtT/wmR6etPB/7YZAkV9dAfvfqzyCaWZC0h3/P9uAPeOa08n4E8DczbCtzo
         jGUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OMZWo/wKMNqYBXBoOxNwoQDZxVzpeWuGTPsMUHMplls=;
        b=EvVHY/k+/F6Ym8Qg0lV9tIm/wSyJCJr3FicO2PGV5RxWSa1VryRl/u1TQdv5nFqt8e
         c4iWizOrSfNf1d0k3a32tnW0JivzZ0refy0l1eSiSlTS3RK7Wl5tdOvAbREWBPK76zx4
         BxQU5/cNT51vkpnxnvvFAWGDlEqy8G3SihwFJvpuF/4WqqQTurisDLpB81Me6FQFx6MN
         pt7GAzOhFaS2g+xzwgJc2eneZedJ/7i+SsPYxMhgOhuKppppn+pwjOmflfbrsbGnY2Hj
         MLaDzHPExwzxuR96pfxKHZq00Pytl1w96F6nTZTSE8ANjEhJlso7gKgHxDHe+rWPQcF7
         R+hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OMZWo/wKMNqYBXBoOxNwoQDZxVzpeWuGTPsMUHMplls=;
        b=mxIaQL9achiV3N6KvjLj1m6ka30E50rBZU4MZFmHnboiF8qFlPHD6VlQ+Aj3TrABsl
         PgSj4HmR3NyXf/ZsHrDuA993fPgjBlc/aVhBMvVleVaiFhYyCyfeqAEQTbag8Zv0itg0
         +VJR/umNQtdWVy2VZ06aFSkT6iR7+YhC7ByH4wtXCGi1mkpM0GaF3GXIxAFpjVTfm0mv
         FPbc1UeGpAd9p7cHsDA3zCcl9A6OUqb3EJ8zt/zVCbBQb11Zu1HXc71hjBxVJV1CVjKC
         xW6yK+/BOzQc4dffs7HOf3EoWtEVXToojtT9aeae37CSHK2h2wYOC6kCIlAcMZ8uBWzW
         o7TQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533cilFmVRqm++0olz5ybjqffSXQ50W8d+F2BMER6ukZ8REiG7XP
	F1f8XwCk+TDKfZbyU1bEEVU=
X-Google-Smtp-Source: ABdhPJzPUlUFRNPpjBl6FA7bsGfMoi1CELJjcbDLaWUAO/0MNqL2SD0ShW/Osa6xSJu5AdjZLPd21A==
X-Received: by 2002:ab0:13eb:: with SMTP id n40mr496961uae.43.1614302739406;
        Thu, 25 Feb 2021 17:25:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3641:: with SMTP id s1ls594303uad.10.gmail; Thu, 25 Feb
 2021 17:25:38 -0800 (PST)
X-Received: by 2002:a9f:3fcf:: with SMTP id m15mr498911uaj.39.1614302738870;
        Thu, 25 Feb 2021 17:25:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614302738; cv=none;
        d=google.com; s=arc-20160816;
        b=Fyr7gbMpPqygslMRthlZfQImY4Exm+08KjDedg23s019P36oFoEjGxUufL+5kA+6hZ
         Wm1Yx7EhNJzpu/lcquXplC16v0au1qe3HPvgXV6IL0+qeUp+sw+9P+2JRfZ/G2+zZsDg
         fLAesNaL4ShNeh59YcsOGELa3oKIpyOjpVvYI/e/8ixo0r5uYVueUL6qs7T4O7rrro+M
         C12JFkno9ULBOkWqoeUWv84/SYzX8Bfoe6K91w2WWcxxDEgURhUhS4+GjQG+tdXMoV9B
         Cp46ivsTEcAXSl3o2u2ZjfxP3Q3Zp2Oxj+ZNvHGtbbVBntmbHylv53Uk3P7RViw5g4zr
         T0iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=5E070bp6VspeidZPDt3QTr8FOhpxIU3XMsjkZOnpuwA=;
        b=l4kp+U0rZL4Mcu2m0mS+zYJMr0gVvaEvvyOBETiAbkS+AqhlwQAp4RoPud6lpmXKd7
         9Eco6NPl0oWLLMfccdKDja6zM3WnBn5gTqN+llgRhRexacrDllaXOUNyHL6mxsMSscrp
         cgNX1ZSFtABdos375qmuY36l4XAO+KXK7alkqRHMyO55CADMYdz0nzzFYq/VNlUzD7q3
         gRZTWog8wMR5osTyY+PiHkiBSYxKYY3xLo3BesFR4vCY5am3Wn8DhlxJD/ciIVMqjkGp
         IPfi+EkD7lZrmujY7vv7PuFyC6MTz1AlqkBIW4yYE+yHO5vpNi0YmHPqrOG9u4u02cCr
         NJ8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id l11si398140vkr.5.2021.02.25.17.25.37
        for <kasan-dev@googlegroups.com>;
        Thu, 25 Feb 2021 17:25:37 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 1b0ae45546104be7867d5d65c317d4ed-20210226
X-UUID: 1b0ae45546104be7867d5d65c317d4ed-20210226
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 170220495; Fri, 26 Feb 2021 09:25:33 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Fri, 26 Feb 2021 09:25:32 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Fri, 26 Feb 2021 09:25:32 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Nathan Chancellor
	<natechancellor@gmail.com>, Arnd Bergmann <arnd@arndb.de>, Andrey Konovalov
	<andreyknvl@google.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: [PATCH v4] kasan: remove redundant config option
Date: Fri, 26 Feb 2021 09:25:31 +0800
Message-ID: <20210226012531.29231-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
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

CONFIG_KASAN_STACK and CONFIG_KASAN_STACK_ENABLE both enable KASAN stack
instrumentation, but we should only need one config, so that we remove
CONFIG_KASAN_STACK_ENABLE and make CONFIG_KASAN_STACK workable.  see [1].

When enable KASAN stack instrumentation, then for gcc we could do no
prompt and default value y, and for clang prompt and default value n.

[1]: https://bugzilla.kernel.org/show_bug.cgi?id=210221

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Nathan Chancellor <natechancellor@gmail.com>
Acked-by: Arnd Bergmann <arnd@arndb.de>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---

v4: After this patch sent, someone had modification about KASAN_STACK,
    so I need to rebase codebase. Thank Andrey for your pointing.

---
 arch/arm64/kernel/sleep.S        |  2 +-
 arch/x86/kernel/acpi/wakeup_64.S |  2 +-
 include/linux/kasan.h            |  2 +-
 lib/Kconfig.kasan                |  8 ++------
 mm/kasan/common.c                |  2 +-
 mm/kasan/kasan.h                 |  2 +-
 mm/kasan/report_generic.c        |  2 +-
 scripts/Makefile.kasan           | 10 ++++++++--
 security/Kconfig.hardening       |  4 ++--
 9 files changed, 18 insertions(+), 16 deletions(-)

diff --git a/arch/arm64/kernel/sleep.S b/arch/arm64/kernel/sleep.S
index 5bfd9b87f85d..4ea9392f86e0 100644
--- a/arch/arm64/kernel/sleep.S
+++ b/arch/arm64/kernel/sleep.S
@@ -134,7 +134,7 @@ SYM_FUNC_START(_cpu_resume)
 	 */
 	bl	cpu_do_resume
 
-#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
+#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
 	mov	x0, sp
 	bl	kasan_unpoison_task_stack_below
 #endif
diff --git a/arch/x86/kernel/acpi/wakeup_64.S b/arch/x86/kernel/acpi/wakeup_64.S
index 56b6865afb2a..d5d8a352eafa 100644
--- a/arch/x86/kernel/acpi/wakeup_64.S
+++ b/arch/x86/kernel/acpi/wakeup_64.S
@@ -115,7 +115,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
 	movq	pt_regs_r14(%rax), %r14
 	movq	pt_regs_r15(%rax), %r15
 
-#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
+#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
 	/*
 	 * The suspend path may have poisoned some areas deeper in the stack,
 	 * which we now need to unpoison.
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b91732bd05d7..14f72ec96492 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -330,7 +330,7 @@ static inline bool kasan_check_byte(const void *address)
 
 #endif /* CONFIG_KASAN */
 
-#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
+#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
 void kasan_unpoison_task_stack(struct task_struct *task);
 #else
 static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 624ae1df7984..cffc2ebbf185 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
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
@@ -154,11 +155,6 @@ config KASAN_STACK_ENABLE
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
index b5e08d4cefec..7b53291dafa1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -63,7 +63,7 @@ void __kasan_unpoison_range(const void *address, size_t size)
 	kasan_unpoison(address, size);
 }
 
-#if CONFIG_KASAN_STACK
+#ifdef CONFIG_KASAN_STACK
 /* Unpoison the entire stack for a task. */
 void kasan_unpoison_task_stack(struct task_struct *task)
 {
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8c55634d6edd..3436c6bf7c0c 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -231,7 +231,7 @@ void *kasan_find_first_bad_addr(void *addr, size_t size);
 const char *kasan_get_bug_type(struct kasan_access_info *info);
 void kasan_metadata_fetch_row(char *buffer, void *row);
 
-#if defined(CONFIG_KASAN_GENERIC) && CONFIG_KASAN_STACK
+#if defined(CONFIG_KASAN_GENERIC) && defined(CONFIG_KASAN_STACK)
 void kasan_print_address_stack_frame(const void *addr);
 #else
 static inline void kasan_print_address_stack_frame(const void *addr) { }
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 41f374585144..de732bc341c5 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -128,7 +128,7 @@ void kasan_metadata_fetch_row(char *buffer, void *row)
 	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
 }
 
-#if CONFIG_KASAN_STACK
+#ifdef CONFIG_KASAN_STACK
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
 
diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
index 269967c4fc1b..a56c36470cb1 100644
--- a/security/Kconfig.hardening
+++ b/security/Kconfig.hardening
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
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210226012531.29231-1-walter-zh.wu%40mediatek.com.
