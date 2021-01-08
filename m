Return-Path: <kasan-dev+bncBDGPTM5BQUDRBC5W377QKGQEHN7TJ5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7524F2EEC4D
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Jan 2021 05:09:49 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id v26sf5701157pff.23
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Jan 2021 20:09:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610078988; cv=pass;
        d=google.com; s=arc-20160816;
        b=qte196g2izrJg8HsDxhCiZQ/Nqjg83qvwZgQpNmm2McmHvoawJ7GzB387i94kdFz+4
         JITd8vWsecoztziASk7asiI+XZBiulvd1XO4zIOzfBIF/6YMHkuFO69Cakc8oNt31y0N
         ktFl9yKB/RkmequUMDTX4bthzIZLekgZlDYeZbqwm/bLEcCgK3zbxJh+WXSjx88IwyhS
         C+nY6nObFnu0Dp8qeJ0XqjzxL5mC1w/SVdsFQ7j4S4lT95+yTFf5pYAnRMrj3L7SSjEM
         lD2SHpFrgB3GM0GkhjK4q/s48eSnf8VaUsmBAReUOoxkQxfK7TZnnE1TZKmaTM5qYil4
         Ee1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=+2viWvpzhLfyzZXzIe0rdLClnolQq8fBvvgIy6rO9Gc=;
        b=SbLLhC7EFkzHdfjF7RVfbGjQ4xqUiPvz4Ue3RZyX5vlnQ/5twlXAWC+cNBp0Znu711
         lNZ0sWDqS3PCnuP6sLyEGMnsD/W1jYu5M8Tm9VXe5MeF0T9PujNIHD9laSfAyHgPX/Co
         z6mZogKChSiRvMVZGEN2U5lsd0GD4Yo7CK35r6mOWMIH5x4WnOMw4RFH6gkN3/NnsgMy
         eoblukg9vZSDR4HAmINGXGzLDVwSxPyP6FuD6Ervr0f2K7yiQ0MQFZk8iCB41mtnNRVN
         AWQaCXUg/QPSS2RJV2NxhcMX7KceXgwoMc2qR/xL7yawbE5wifbDuYJgRqN9jV6L3s1O
         4bAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+2viWvpzhLfyzZXzIe0rdLClnolQq8fBvvgIy6rO9Gc=;
        b=e7ma/0i3wTZpuslaQ2eWYViVohfpRm2R1en5wJj5I/69EjA0S/VbThcUBk3xaREJFD
         zEXaJxXa9dBPlphZG438TCuLUjMnQZoeqN0ZVrikDa64CA2qf64zwSbiW9xHo1Cn7mj3
         nuxJRF7xgQXm/CgKumIdVXTm6ELNhr14FQm/FW/JHh/OT49DS6TctRu7hKOQBz4RJdrH
         /j6N7nQzS0oyiyRbBWwD4WXmepJhrZLNAxK5ubwj4z3MNLxFqFKa3utwCWru6fu2rKNI
         DmviXTHe2KONpbrsJqTOfXWWPL+1kzdIavg33V7QuG9vd/HeVLeod3SFqxm4VqRzKrWc
         x8iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+2viWvpzhLfyzZXzIe0rdLClnolQq8fBvvgIy6rO9Gc=;
        b=i7Or1o8OCJoBT6OFUZH2VHglp5LeJ1Qvm+TpmWFnMQpA5qhV02fdjMjohsJiAJwB5W
         k6YYHHJdXgeczC14RLnSEu+uJm4yD7atEUrcY72d/AkL6CKVxR7eLuFtPdggledoKtBV
         oyeOcoRbkgzdB9642Cyh0S4ECiNMuvRDz0CKSsgEaOUCRxMV89yjZl7HuTmpUQs83Xne
         STBQ9YJ5hGtWsNQqpLrQlJ6vN1HXUgMOF4OMCpi2ci1Y6OgrWhDn90KdTP2n3wc4s5rW
         O9m65uA/722GGzNijI5oHSi1kmpvNN+qfqHchcwXYp5axn7K2FxQYz0qWnWAtsMwsROK
         WbTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Luaey5JYujJ3PqQhuj8458Ukc+Tp6sTHtTDu0m3Dve26cD3Nv
	gBFst8A0T1jmB4dsxrB9QT8=
X-Google-Smtp-Source: ABdhPJxNFIcscGqQpUG72wirEqhLB35WwXOLQmgpaDSBaT48RH5ktEJfdIyYYFX62M1PKZ+1c9kJRQ==
X-Received: by 2002:a63:2d7:: with SMTP id 206mr5071688pgc.375.1610078987810;
        Thu, 07 Jan 2021 20:09:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2c94:: with SMTP id s142ls3786636pgs.9.gmail; Thu, 07
 Jan 2021 20:09:47 -0800 (PST)
X-Received: by 2002:aa7:9ec5:0:b029:19e:bfaf:1b24 with SMTP id r5-20020aa79ec50000b029019ebfaf1b24mr1706285pfq.51.1610078986995;
        Thu, 07 Jan 2021 20:09:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610078986; cv=none;
        d=google.com; s=arc-20160816;
        b=pBfs8QSiiT/gVPw0Re8vtmZB9SYGpIYAfK//1Q0qtFsIxCocrkAuS88ZKvmAcfW+pu
         CXsSciCFqzZIqER5M7KrW3rRGwA29NhC2FEWyB+B38AoT/Pnb0B8wQl88p5epk/YE+jP
         Bl+qEzCEM6eTi81FvrOvG/c8/m55QgXaOr4z0l+v3JGtCjUkG/9aw5/jLRZcDR7+zQ7U
         nfY479uovTJ/Bq6E56/t4O6XR4s5MewNthv2BwJfRkwS57fzEndQEqIJ/REbTSkzJdUa
         rrHkGZ3likPoQI2PS7rEkf/Xm9A3/Stq9VyxLdDEIgC8CBTTVet/C2pgc3r9wQcqRmP0
         51Og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=YNx5mVZPUPmOS4xpBXmTyHhhhBm5xCadXkxbs/3brdI=;
        b=l+ppEbyDIHcz6VBqcVNZbh3R5ojwDJ1g9pi0wKC3oB/DAPkliiKS8FvAT8KvVVxRIf
         cws6HhPu7T+epmgLaPEQXcTFVIe70Q5y47d1Kyh6MPzjvKIDsZDZFiv7oDlVvUfLBdd/
         Qtj/tT/CeJiceAcWRTUHNPyx169ueLvT6N2JKvOyd29R72SnvgNCIgn7GsucZiunoO3j
         2DfXopR9gkXl52qmAD5jgXjcv5XLXkNIWgB5rGl5w+7fpBWf717Kj5jAysBB9g+OW3Qb
         IxiAi7DwMpZb1KsGvaU0//jsJnN9NBMCHsJ1wpCz1ShmKsDPHHU23/t4+P1guDgleuhn
         ai5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id w6si702272pjr.2.2021.01.07.20.09.45
        for <kasan-dev@googlegroups.com>;
        Thu, 07 Jan 2021 20:09:45 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 95460ae080ac436fa08532eb34eb7458-20210108
X-UUID: 95460ae080ac436fa08532eb34eb7458-20210108
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 438929673; Fri, 08 Jan 2021 12:09:44 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Fri, 8 Jan 2021 12:09:41 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Fri, 8 Jan 2021 12:09:41 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov
	<andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>, Nathan
 Chancellor <natechancellor@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v3] kasan: remove redundant config option
Date: Fri, 8 Jan 2021 12:09:40 +0800
Message-ID: <20210108040940.1138-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: A0BC49EDB6B8B99BD15B778B5C0058C077F8B25104FB38FF69F13199E1903C002000:8
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

When enable KASAN stack instrumentation, then for gcc we could do
no prompt and default value y, and for clang prompt and default
value n.

[1]: https://bugzilla.kernel.org/show_bug.cgi?id=210221

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Nathan Chancellor <natechancellor@gmail.com>
---

v2: make commit log to be more readable.
v3: remain CONFIG_KASAN_STACK_ENABLE setting
    fix the pre-processors syntax

---
 arch/arm64/kernel/sleep.S        |  2 +-
 arch/x86/kernel/acpi/wakeup_64.S |  2 +-
 include/linux/kasan.h            |  2 +-
 lib/Kconfig.kasan                |  8 ++------
 mm/kasan/common.c                |  2 +-
 mm/kasan/kasan.h                 |  2 +-
 mm/kasan/report_generic.c        |  2 +-
 scripts/Makefile.kasan           | 10 ++++++++--
 8 files changed, 16 insertions(+), 14 deletions(-)

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
index f5fa4ba126bf..fde82ec85f8f 100644
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
index 38ba2aecd8f4..bf8b073eed62 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -63,7 +63,7 @@ void __kasan_unpoison_range(const void *address, size_t size)
 	unpoison_range(address, size);
 }
 
-#if CONFIG_KASAN_STACK
+#ifdef CONFIG_KASAN_STACK
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
index 8a9c889872da..4e16518d9877 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -128,7 +128,7 @@ void metadata_fetch_row(char *buffer, void *row)
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
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210108040940.1138-1-walter-zh.wu%40mediatek.com.
