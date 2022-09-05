Return-Path: <kasan-dev+bncBAABB6OL3GMAMGQEZSJXQPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C4255ADAC2
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:11:21 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id j22-20020a05600c485600b003a5e4420552sf7918370wmo.8
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:11:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412281; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uxz0D/y87f1X6QT9Cl0h3oIimwKxkHs7nrbPKYSbb8SuSSwGhJjR6tjZ3Ofls1yVoI
         a9ihBE1zwKRD7dReIH6nhqPAgp9Y6xyEZdPvXJKsluJpE+8cqbUVQCbpoqQ49eg1NvEu
         u7l0ACF6IQktCcOKVimM9CfSQp20jevNPVYz2aO446KcI7R78cpcd+SV69yirD31Dwlg
         4f4YWorlCci8uRj35VV9tvYUbjW9LSHOoA5pgLcJf9khD0r17FB5jO1tPgPr9232nt0V
         3PVhL1AMPtlP6wtgS6nCYpFMBZ8EfN94QPZbi/Ts7TG7tsGPXh2LtbkeUbkhakG9zZd9
         hHlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/xWGYYZ9uff30IFKdooDrUaUm6J6regneheku2bH3qU=;
        b=IdJRClRAlWV2XNXszpsyGuw2h1Bt4wZnr6GgmfMI4nBACcc83l73oWSpMh036mk8Gj
         eJkHFGTSDDdInegwRaZMIDKoyg7RNo/NjliYA5hoZFjXnsj1tSs1FWmrRINNBTMhC9Ku
         8Jz+TcWURJvsZHIJG32GE6wyoOMAuixaJFJNRLZz/jPIyvM3ymZT0iTWlLtzx7S4sbek
         BbyHC4vjM69kCmrwHRMrrEsXfMRF5ofTkz4NfeBqjwHsVTFrUDKYbqf6FJGCtaNuRdbv
         xqrsyFdUEH7mPRhVg4AkH0kgwbxVcKd8LVGHJ+5MGGQByYw5M4dPI/plxXJ/9ztPIKb4
         C/xA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=nfMvhWry;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=/xWGYYZ9uff30IFKdooDrUaUm6J6regneheku2bH3qU=;
        b=UkmkxLFP3FGIp8sbUdzW9V14LKCXjxm3KVyJsESRlFkel1M0IE2ZLgBoiMetZrpjjZ
         27k/JOm0/8o5r9Wq+Z9AxR4YyN3+AJGqOQPSitQEb9jKSvsTnY8XC4H6d+JJLYnsDpZr
         bJQ8DiPfvyCPS6eNkMcDsIjVfR2/pMx4v3d6/SxCNxilS6CkkQTOqWszy/kJjm5RJ0Df
         Pd46ebU7gvKFxZ0OHV39u6TUEOJjUwIJ1jTrqBGHH+lu+/b/1Ofd6Jsi30C+SbVeA8Qq
         cGN9BIcuuYoy7GA8uhl4xg5giv1X/nM+Z6z7e8llEQOyjtgWyOFwnfShJWsx12idHYGi
         iauQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=/xWGYYZ9uff30IFKdooDrUaUm6J6regneheku2bH3qU=;
        b=ddxG9/7H+nRCrbvV/vLzfFWC6fMXQz9chSZRmJK2wVjQWTwDe1b0t/sLDG9E2gcL31
         5hOb1dWmNMIANBCVjJBAcibAcAdL/9hMx7Z0CEZDDpeU8YH/7yYUGVwY7ll8EFckQ+DK
         Af3t5kIo27DAB5GO7z2cQJKwk5wSlCowl1GWN0VRgGqNf+vcyD2fUv7lIx5CuiLSnu+v
         IHVCZXPnl7FdjKqDsSobVrNbDpf0mWv3RaQYWh54tzeQbfQJ+lNTgjwAlvwNid8qSHXw
         z8ud4oC8L2JnxM/v3YEbzmgi9dR4ui1gubbNlyRL6Dki7o6grxpH4wmKHpspv8WO4ewv
         Qhbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo11CcxVRWxzcluXFh7ErJWpwW5Nybu9CGdGXr0gcgNGZi9nSlmP
	cUmQaLP28HNwPntu1KsZCxI=
X-Google-Smtp-Source: AA6agR6YuDcFMIxeahibiAbFMhxZbsTVQkk6UUH462wKMq6NzAGbc/Wq94/nGM2choWecepcj/fZZA==
X-Received: by 2002:a7b:c399:0:b0:3a5:f3fb:85e0 with SMTP id s25-20020a7bc399000000b003a5f3fb85e0mr11915349wmj.38.1662412281225;
        Mon, 05 Sep 2022 14:11:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:60c7:0:b0:228:c8fc:9de8 with SMTP id x7-20020a5d60c7000000b00228c8fc9de8ls205471wrt.1.-pod-prod-gmail;
 Mon, 05 Sep 2022 14:11:20 -0700 (PDT)
X-Received: by 2002:a05:6000:1acf:b0:222:cff7:3b6c with SMTP id i15-20020a0560001acf00b00222cff73b6cmr25416493wry.191.1662412280646;
        Mon, 05 Sep 2022 14:11:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412280; cv=none;
        d=google.com; s=arc-20160816;
        b=BSJygzuqDKytO+N46+wgzpcpoGUy44rCAtIv9gybcu8pQt7kn8xFrytOxC31q7n93c
         Cmdtug6PYGn2apitF4qeOY77lq4kdUao3WE3jEAfr64FrvI+mfdJsI5UYDy2PmkOrjl3
         FwbruDc3HoXS2O8im3rf51vIFvEkQrySfBD0Vg+rgWKJdyso7h5Q30CYguJocC9TsRd7
         T1eytLpuQTCbF3S5aE+3KmYBZQZOblNsznERHQK1FVXBk2X9kkOam9PSYFuGjPwfkPmH
         klVyP1Cq5lKNR5VKl/+Lkhjq6C5fUNW+X/oXPmqCputDVg+PuWlLFeaE+qmhB1dcWPHq
         iJxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XfFE8jEOhkH5dCwYAH+JNQItaGgxntna6JguV+wMSyA=;
        b=yZZMJGnocyUeDJ1aWx7IAWOH4prXGJ2ERKS9HdjTekLrRYFNjh8Hl6SYw7rtt9tUbN
         H9pc7TL/0vkDL3X2Spv5L0YmVal+3TtVwVjVzwuU5YFKz7l6KY82LXSJ8MiVMv0Dyy/2
         BH2UBPQtGT3ZM+ivF7845oMCO5JxREZWew6G3CU4WndvJO+HAIo44mPUOpCtpZMSt9VS
         F3B1li5APZr5Tmn/7OLlOnrhsmYMf0HTDrHBsUu20PT+EM6qdw29uqzeGCgU9NoqtCCw
         rot8xnBdm7qwllWuMRukADQKmiBVh1BSZ8blPlGa0DFS5qGlmbl7PcLeq11ltXnTmaHD
         zYIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=nfMvhWry;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id bi19-20020a05600c3d9300b003a6787eaf57si1261047wmb.2.2022.09.05.14.11.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:11:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 31/34] kasan: support kasan.stacktrace for SW_TAGS
Date: Mon,  5 Sep 2022 23:05:46 +0200
Message-Id: <3b43059103faa7f8796017847b7d674b658f11b5.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=nfMvhWry;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Add support for the kasan.stacktrace command-line argument for Software
Tag-Based KASAN.

The following patch adds a command-line argument for selecting the stack
ring size, and, as the stack ring is supported by both the Software and
the Hardware Tag-Based KASAN modes, it is natural that both of them have
support for kasan.stacktrace too.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- This is a new patch.
---
 Documentation/dev-tools/kasan.rst | 15 ++++++-----
 mm/kasan/hw_tags.c                | 39 +---------------------------
 mm/kasan/kasan.h                  | 36 +++++++++++++++++---------
 mm/kasan/sw_tags.c                |  5 +++-
 mm/kasan/tags.c                   | 43 +++++++++++++++++++++++++++++++
 5 files changed, 81 insertions(+), 57 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 1772fd457fed..7bd38c181018 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -111,9 +111,15 @@ parameter can be used to control panic and reporting behaviour:
   report or also panic the kernel (default: ``report``). The panic happens even
   if ``kasan_multi_shot`` is enabled.
 
-Hardware Tag-Based KASAN mode (see the section about various modes below) is
-intended for use in production as a security mitigation. Therefore, it supports
-additional boot parameters that allow disabling KASAN or controlling features:
+Software and Hardware Tag-Based KASAN modes (see the section about various
+modes below) support disabling stack trace collection:
+
+- ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
+  traces collection (default: ``on``).
+
+Hardware Tag-Based KASAN mode is intended for use in production as a security
+mitigation. Therefore, it supports additional boot parameters that allow
+disabling KASAN altogether or controlling its features:
 
 - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
 
@@ -132,9 +138,6 @@ additional boot parameters that allow disabling KASAN or controlling features:
 - ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
   allocations (default: ``on``).
 
-- ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
-  traces collection (default: ``on``).
-
 Error reports
 ~~~~~~~~~~~~~
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 9ad8eff71b28..b22c4f461cb0 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -38,16 +38,9 @@ enum kasan_arg_vmalloc {
 	KASAN_ARG_VMALLOC_ON,
 };
 
-enum kasan_arg_stacktrace {
-	KASAN_ARG_STACKTRACE_DEFAULT,
-	KASAN_ARG_STACKTRACE_OFF,
-	KASAN_ARG_STACKTRACE_ON,
-};
-
 static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
-static enum kasan_arg_stacktrace kasan_arg_stacktrace __initdata;
 
 /*
  * Whether KASAN is enabled at all.
@@ -66,9 +59,6 @@ EXPORT_SYMBOL_GPL(kasan_mode);
 /* Whether to enable vmalloc tagging. */
 DEFINE_STATIC_KEY_TRUE(kasan_flag_vmalloc);
 
-/* Whether to collect alloc/free stack traces. */
-DEFINE_STATIC_KEY_TRUE(kasan_flag_stacktrace);
-
 /* kasan=off/on */
 static int __init early_kasan_flag(char *arg)
 {
@@ -122,23 +112,6 @@ static int __init early_kasan_flag_vmalloc(char *arg)
 }
 early_param("kasan.vmalloc", early_kasan_flag_vmalloc);
 
-/* kasan.stacktrace=off/on */
-static int __init early_kasan_flag_stacktrace(char *arg)
-{
-	if (!arg)
-		return -EINVAL;
-
-	if (!strcmp(arg, "off"))
-		kasan_arg_stacktrace = KASAN_ARG_STACKTRACE_OFF;
-	else if (!strcmp(arg, "on"))
-		kasan_arg_stacktrace = KASAN_ARG_STACKTRACE_ON;
-	else
-		return -EINVAL;
-
-	return 0;
-}
-early_param("kasan.stacktrace", early_kasan_flag_stacktrace);
-
 static inline const char *kasan_mode_info(void)
 {
 	if (kasan_mode == KASAN_MODE_ASYNC)
@@ -213,17 +186,7 @@ void __init kasan_init_hw_tags(void)
 		break;
 	}
 
-	switch (kasan_arg_stacktrace) {
-	case KASAN_ARG_STACKTRACE_DEFAULT:
-		/* Default is specified by kasan_flag_stacktrace definition. */
-		break;
-	case KASAN_ARG_STACKTRACE_OFF:
-		static_branch_disable(&kasan_flag_stacktrace);
-		break;
-	case KASAN_ARG_STACKTRACE_ON:
-		static_branch_enable(&kasan_flag_stacktrace);
-		break;
-	}
+	kasan_init_tags();
 
 	/* KASAN is now initialized, enable it. */
 	static_branch_enable(&kasan_flag_enabled);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index cfff81139d67..447baf1a7a2e 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -8,13 +8,31 @@
 #include <linux/kfence.h>
 #include <linux/stackdepot.h>
 
-#ifdef CONFIG_KASAN_HW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 
 #include <linux/static_key.h>
+
+DECLARE_STATIC_KEY_TRUE(kasan_flag_stacktrace);
+
+static inline bool kasan_stack_collection_enabled(void)
+{
+	return static_branch_unlikely(&kasan_flag_stacktrace);
+}
+
+#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
+
+static inline bool kasan_stack_collection_enabled(void)
+{
+	return true;
+}
+
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
+
+#ifdef CONFIG_KASAN_HW_TAGS
+
 #include "../slab.h"
 
 DECLARE_STATIC_KEY_TRUE(kasan_flag_vmalloc);
-DECLARE_STATIC_KEY_TRUE(kasan_flag_stacktrace);
 
 enum kasan_mode {
 	KASAN_MODE_SYNC,
@@ -29,11 +47,6 @@ static inline bool kasan_vmalloc_enabled(void)
 	return static_branch_likely(&kasan_flag_vmalloc);
 }
 
-static inline bool kasan_stack_collection_enabled(void)
-{
-	return static_branch_unlikely(&kasan_flag_stacktrace);
-}
-
 static inline bool kasan_async_fault_possible(void)
 {
 	return kasan_mode == KASAN_MODE_ASYNC || kasan_mode == KASAN_MODE_ASYMM;
@@ -46,11 +59,6 @@ static inline bool kasan_sync_fault_possible(void)
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
-static inline bool kasan_stack_collection_enabled(void)
-{
-	return true;
-}
-
 static inline bool kasan_async_fault_possible(void)
 {
 	return false;
@@ -410,6 +418,10 @@ static inline void kasan_enable_tagging(void) { }
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
+void __init kasan_init_tags(void);
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
+
 #if defined(CONFIG_KASAN_HW_TAGS) && IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 void kasan_force_async_fault(void);
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 77f13f391b57..a3afaf2ad1b1 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -42,7 +42,10 @@ void __init kasan_init_sw_tags(void)
 	for_each_possible_cpu(cpu)
 		per_cpu(prng_state, cpu) = (u32)get_cycles();
 
-	pr_info("KernelAddressSanitizer initialized (sw-tags)\n");
+	kasan_init_tags();
+
+	pr_info("KernelAddressSanitizer initialized (sw-tags, stacktrace=%s)\n",
+		kasan_stack_collection_enabled() ? "on" : "off");
 }
 
 /*
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 07828021c1f5..0eb6cf6717db 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -19,11 +19,54 @@
 #include "kasan.h"
 #include "../slab.h"
 
+enum kasan_arg_stacktrace {
+	KASAN_ARG_STACKTRACE_DEFAULT,
+	KASAN_ARG_STACKTRACE_OFF,
+	KASAN_ARG_STACKTRACE_ON,
+};
+
+static enum kasan_arg_stacktrace kasan_arg_stacktrace __initdata;
+
+/* Whether to collect alloc/free stack traces. */
+DEFINE_STATIC_KEY_TRUE(kasan_flag_stacktrace);
+
 /* Non-zero, as initial pointer values are 0. */
 #define STACK_RING_BUSY_PTR ((void *)1)
 
 struct kasan_stack_ring stack_ring;
 
+/* kasan.stacktrace=off/on */
+static int __init early_kasan_flag_stacktrace(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "off"))
+		kasan_arg_stacktrace = KASAN_ARG_STACKTRACE_OFF;
+	else if (!strcmp(arg, "on"))
+		kasan_arg_stacktrace = KASAN_ARG_STACKTRACE_ON;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan.stacktrace", early_kasan_flag_stacktrace);
+
+void __init kasan_init_tags(void)
+{
+	switch (kasan_arg_stacktrace) {
+	case KASAN_ARG_STACKTRACE_DEFAULT:
+		/* Default is specified by kasan_flag_stacktrace definition. */
+		break;
+	case KASAN_ARG_STACKTRACE_OFF:
+		static_branch_disable(&kasan_flag_stacktrace);
+		break;
+	case KASAN_ARG_STACKTRACE_ON:
+		static_branch_enable(&kasan_flag_stacktrace);
+		break;
+	}
+}
+
 static void save_stack_info(struct kmem_cache *cache, void *object,
 			gfp_t gfp_flags, bool is_free)
 {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3b43059103faa7f8796017847b7d674b658f11b5.1662411799.git.andreyknvl%40google.com.
