Return-Path: <kasan-dev+bncBDGPTM5BQUDRB5H33L7QKGQEKOGEOKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id AD2E42ECB1E
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Jan 2021 08:53:25 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id p13sf5095259qki.14
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jan 2021 23:53:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610006004; cv=pass;
        d=google.com; s=arc-20160816;
        b=h5AfeejmaFZkkORA2tFMnr4lRsKawH/j4BgQZn/ztRzh7F6rYaMWjlYbgM2GC/zq+c
         j1CLFQ5eMWqVfTVJXsjC0FYRi8n/RxKjmGzrKJ36rekpVM0VR9QZuT+M6iysCYKlXNff
         c3+EnBTM20C1CJkz8gd9UNc8bH0a0HFeuBrst0RViuYVBd9KvdaAzM3blhmdBWzFbX/e
         oo0qDQG1ujOVPZN5xqeIPBWY3JTlmdcgAWXCZO6tm6KB2suWOzwXrgqxPR7TCUAatpcw
         YXlxERs7h6lvkqw/VBq0a4yI2pKaIaN3ZPWgbH9z6NrTbGCsNx+bOwinqlz+X4xwlZHl
         tgpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=/2GffhIL9KFGYNmQGOwzaOoeDMEZuftJPeTqVkFyduM=;
        b=RyZIqoZCClh8BCGpVuhgd65PjOugRV4c4BtX2PUWHIBbvb1tBdWI9v771KUI1Bpyco
         xfEImBYPYWHKm0Tjw6bA0x/mG4TfYJl1b3ctMkgmlu4H6Q5fOjTazzInkX3IgBmukMHi
         LLXh+zrSlFK9kC6Ey8Rt4dOICcGICfGGRSnu3g3Y8RL/23ZHKp0kCtpDZx0t6wCAwRJm
         hFUNk/yOMswh5HStnKpj4vlmytkRH2FyoTh4teMpiZqrbc4CBwtVbntj83XLr9zydg3r
         NqjY68qUXsj86bbVdfCWiOqx0P46eK41y3t/VNvJC4L6v+syeQ1bWeCQuksdrwQiFgpS
         GS2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/2GffhIL9KFGYNmQGOwzaOoeDMEZuftJPeTqVkFyduM=;
        b=qJR4aIliVB+tDsyCAXjG9siKtZ2AkWjqj8DrmuKDN7oZGhpw43XWnUNJo5tG2rJnOP
         qA/6fSU+iAnwVM4Pk4IxnPq+BC6cD056K0Vg0/vFdjPa53QwhM455yiHWZ87tyX1k/mh
         kvPiKPUszp+B+7YgZX+2KUkwnxG9NGhpYXayVMtTFfr9Vp9kOmYHS2VTf5LB0FDmwkJ7
         Gc5v+QXLZyt0JqDQAuAAxM2HbvVRCPPUSl8ZfJqyisyPlXaRy6sGdIEwSvJyG0vIxSoi
         oyVy1tWhXyEKQZRWqYGNG/mYL9MzP9xiXTjgdwKmYMbNI86J4PcEXqr92DIxzfiImq6s
         rIug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/2GffhIL9KFGYNmQGOwzaOoeDMEZuftJPeTqVkFyduM=;
        b=mC84igHSZwpw9SY6lZS3i2JoRchYSsguFv/W+9YOCXw9okxshp0a7b08xbWmgE4ZMI
         6t8yv44zXX6dnXPCUVIsyg3IjALlkV1TjlDKOmD+9fmYGmRQnfFghkv35rEFVvkgZTaU
         GVefpKZxa++lKqvk5NoNPDARjLScgDTmLScb8ye7TShFNLSPChg6LYQDqx7MIS8QVJnr
         bx4+Y0GK0Ud4QQdEGmpic5R7AUfhKo3XdZjFKO9F3TtLGDI/SA1nzbKhSPn8rXUUpgn5
         959c02JDcRGEi8kTVkmDxEgehZ+YH1Qy4FShhOL8dO6Vp9DjDLt/tjGBceDwnckpb4BL
         iIkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530csH4vKA03JW+yTSORxmg0fdre3adfSWLwafXLutH2ETr3ZsOH
	TOIoxG53XZl0nNWX28vdJds=
X-Google-Smtp-Source: ABdhPJzQOHZXMX/U0hFPuT86vHIDlPNYnkxeJZ00Nnj7g9Ezd9XHW23kd7e6lApT9WeRXOL+mJ9Pug==
X-Received: by 2002:a05:6214:1230:: with SMTP id p16mr7482057qvv.47.1610006004656;
        Wed, 06 Jan 2021 23:53:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:3763:: with SMTP id p32ls2372530qtb.11.gmail; Wed, 06
 Jan 2021 23:53:24 -0800 (PST)
X-Received: by 2002:ac8:6bc9:: with SMTP id b9mr7469858qtt.51.1610006004237;
        Wed, 06 Jan 2021 23:53:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610006004; cv=none;
        d=google.com; s=arc-20160816;
        b=0Js2yrNosRw7KXx/d2g2a0DseI2mijsy3dmvDhg1ik6TV3EaHQ1LTI2xAeBlv9eywV
         KGrO/nkaSL5MzPK7MoTWjCRcEjNaKOEYbtL4GQ/oAr2uoG+8ew8PkqczmTRr1Uc+laM1
         5pyaY9c1l8J4He+B4W+ChTa0QLXSQoljAJECVq9/POLD98/3teVjbW7uJs52D6S/qHCL
         Bwazv+JFg2H0iP1PtOmlnCaXgkKT793KuV+/6DiMvrd4LI0L3usVa2aRLb8rJXyMhror
         JItqw+ThouPDqLcscmG80x3IDy29WsxZhV00NpzPA0EKW64IWah7nr6yJkyzSPMQ92eP
         WLoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=l/L5jsgpjwm34ypcQsyL2KqpSeRTGQpviMKQQlxBRhU=;
        b=gCXWwOlW/Tr6+qL/D8vxLLHSdnW2dL0WJyBVJ7s/DcnI2NCCZueCmFSr/SFozrm7jt
         3bk0N2aN8HZJjhOVZ+wyp/USRzTUxCan8b7U9x4FBmDWFOeYK6b6Oe+ws7K5Wf9MEQJW
         QKhAIYNkRY9F2fmaZ3yCxH5m3waMTdr/VNeKJK5CXbTn5nYn5riGOKbag69oaKJwzpZM
         tQSDOD3TGrX7Eb1/UltRTEfnGNflRrammhKqf3nwyFkIA/AvZUe7bxN30tdliJ7Ala5l
         HGNRKAP0RT0bhEmDJJKoi3o6niDTxw0lZ9xwyQ/F+MxD0a/iPKBKb6mrzBg+Nktusnlt
         zZ1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id g2si342755qko.5.2021.01.06.23.53.23
        for <kasan-dev@googlegroups.com>;
        Wed, 06 Jan 2021 23:53:23 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: c245be9b5cf54722835efab911669774-20210107
X-UUID: c245be9b5cf54722835efab911669774-20210107
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1427673813; Thu, 07 Jan 2021 15:53:18 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 7 Jan 2021 15:53:16 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 7 Jan 2021 15:53:16 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov
	<andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v2] kasan: remove redundant config option
Date: Thu, 7 Jan 2021 15:53:15 +0800
Message-ID: <20210107075315.3482-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: E78C0B405E861FCE6BCE4616FBB772D33CB9E246196C4D61EC7F1C80699ACF402000:8
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
CONFIG_KASAN_STACK_ENABLE and make CONFIG_KASAN_STACK workable. see [1].

When enable KASAN stack instrumentation, then for gcc we could do no
prompt and default value y, and for clang prompt and default value n.

[1]: https://bugzilla.kernel.org/show_bug.cgi?id=210221

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---

v2: make commit log to be more readable.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210107075315.3482-1-walter-zh.wu%40mediatek.com.
