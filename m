Return-Path: <kasan-dev+bncBAABBMPP26LAMGQEILVPIZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id D0933578F14
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:15:45 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id c17-20020a7bc011000000b003a2bfaf8d3dsf6073822wmb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:15:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189745; cv=pass;
        d=google.com; s=arc-20160816;
        b=uz8Ji3OZEQ/Tctp/sBDbTpHpLHnJVjOaZkjgRFXt1VAQQOIsrbfBfu+oQt/s4yZOqg
         kgTWJkpoDkqdrRZNQAungHWD6Ewanzmk2os8L6JJwepOJ96w7JDZR7toqI2YC+ZTIcN1
         rhA0WxBYLRdXzDrjeufu8+U5eSbIqUYyGPW8oX1OAuti5WkC6MW/Y2J6YvlxDSbbVLYB
         CZDomPGy4xaTG22JgLCQ3huFkmhO6uMALYtQVZE4e7w/Gfui0uCzqsMgSN6eDSaZx9E4
         XJiGcRkzuolFNFjlJ45o31RU4ekrXcFmpLn7DonAYo5Ft405MxaY8mf5DjOQTAA8KZgc
         0XaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=m11p1LAboGJ3O6+zkQPWJ8mRAHBmQsVIv3Kmd+qOFzk=;
        b=f3JR8mWP3ubNAUpHZUnvWoFGz6INUxzwEE8NMKeOn1u3LYlZalO0D6JnoIlliFc/pW
         /QquGu2o/Y8Q5Fq/4JnZRSyc2eVfFi3DlYx34FMk+6gRrC9nxI7KFqUOccMqf4ge4b3u
         Ww6kjQv7Z/qc6ZbMaMSaDhQKq29yKL0ExrznyiH/hSXYLDTOwe/wNqmudBUzQEaPih6i
         jsMh0vmzj8tgsyLgoCPFM8QrbaBlJQ0b/1K11EiH5eOzoqZLmPV1098ypIsO1tPVEeRl
         4HkLV/wN1g5WKyZ9nH72a5saZDIo2hsOo3nkFz27kzOWQgXTfGsJEIXPvLU9ArLKcrnP
         +7eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="AgpB1/Ah";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m11p1LAboGJ3O6+zkQPWJ8mRAHBmQsVIv3Kmd+qOFzk=;
        b=Tddfnmn0IUeHgDyMAtDriRiQDZ7ueyUGtyC+a1fe2EK9V+FOiwLF5ZCLDwI2i1aFID
         hTiNgRIHaQddqjAu2lmI4rVajJihmXVLkd6speM0HU6VIWsVjYfJi/bxoPq8EligDe3x
         JL3ItioUundrWjwq8k0h/OqY3zGkkU8iSDH06xKgJQ/vlOHWqEy5xI6IuzfkUCemoes6
         GRFHuCLYZvWsJPQJqUX+NMsC+xzpjP8Hvjz8LIC/kxCr3cYltAKAiz1MYlKHTvOppCLf
         pvnsk6xMmE9AWSkgakPVziY22/FuMJ/FiPJrwfMgZ+UXxpsHCuuOcTzwxkH1LJpCG/xf
         GY2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m11p1LAboGJ3O6+zkQPWJ8mRAHBmQsVIv3Kmd+qOFzk=;
        b=tmqKyuIRevLMyF4ZDnAVXe1awb5QZfvptqKqbEFz3WdilHLMC3b/Xrkunwu9OK5fIH
         MlnmWt4GLLIZEV+kphJiFvFptGekMsF9EU/iLujR+huynnD42jhiwcy6fc9l4wv8Ra+C
         tXbtQtWFNUoh+hs5Dn8jGxYmx4/SuD+buJjfaoOHGOLWBqvc1z0ta9KorFSFIv15YHgk
         4CGRZFSAW0dnine40p4OBcB7ilvE6M9t6WDflfwTzt3yWnEUc5dR0oYqAttpG8tw4x+q
         s0NsxutzP5A7y48a6f6biAK1PxifLXxXi8AlnSJMUbsqEfHTAKiXLiy4Dai60ncDDk1Y
         8daw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+fJXF4gLBpjEbLAGLmJl294NzFqs5F1gEE+0nvPKAM+1OPur2z
	tZ671+kvIBd8bIyKX5n//5g=
X-Google-Smtp-Source: AGRyM1vg0SjqtbCC7nUX4CSSfPds+ca+3uwFylh6mM2r4uvtPEvJNDdLmxshgWUT2MnEey19uR9xJg==
X-Received: by 2002:a5d:6d09:0:b0:21d:9846:259c with SMTP id e9-20020a5d6d09000000b0021d9846259cmr25152454wrq.212.1658189745407;
        Mon, 18 Jul 2022 17:15:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ce0f:0:b0:3a3:10c7:39f3 with SMTP id m15-20020a7bce0f000000b003a310c739f3ls42578wmc.2.-pod-control-gmail;
 Mon, 18 Jul 2022 17:15:44 -0700 (PDT)
X-Received: by 2002:a05:600c:3551:b0:3a3:1d4f:69ed with SMTP id i17-20020a05600c355100b003a31d4f69edmr4869294wmq.188.1658189744659;
        Mon, 18 Jul 2022 17:15:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189744; cv=none;
        d=google.com; s=arc-20160816;
        b=TkAZgCTSLX+BlZYiWPf/Iw16vJDyF2F/3YWIkljSTsIMeZHuFyaChgVnUUWId+fERc
         tmWJqIbCo1kGEDUNePOOyy5GEeLfEMoz6ypRVnWdEJALhvo+xCqGVYpbKKcHuCuAaPwa
         4QTb2mDOzMOpY+BEqvzDSaVmOcMi6nlQmoto8bfQEs20rRn+r6yGjTy4kBsZPgzgc2HT
         RQ8rXQcDWXRK15FOvDv0j2tHAUk8iPHn3Gmbjbtdu1y3+da5g1Y9RtnZQ1qKmJtMClrR
         UMviLjieLYzg9iL0o+RQacEHq2kbvyLhfQ4s+iT5CHoW+Kip+rfPhAUXVyjLoo6O9PvF
         345A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nn1wRmXGNlycId97pMK2GGK/DQj9IfbkBYQ3B2Fk9HA=;
        b=CtddE2hhfWWUlB/teKxS9it16YsFXs+cbACoUwTZ/eFSL8/8A22EuTHDguOv/eOVDC
         Cm9ZypjY7iE5tp7kj+8L/9fiCvCw/RoFlXBbmNLkTxvGIExkuLtYJyBuX4Zhtwvnjph4
         RzzEzkH3IP5VWzoHXuBhDwxsg8wggaE1Iskh/Jwp2ze8X4YglyEtb7HZzrBggQnYOJVa
         MBI7XaBFGN5PN9dqF2LYAMtms0ociRxDDz1GF+iUlLKjx12NStdY8TLWdxV5qmCn3GqI
         qnUx7Lh1u1ErXJM3c3W6Hhdq93o7SNrxHF7G/SUolba7wYFL5lIJsKpjtVpZH7JKtvJl
         qHEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="AgpB1/Ah";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id r126-20020a1c2b84000000b003a050f3073asi14683wmr.4.2022.07.18.17.15.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:15:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 31/33] kasan: support kasan.stacktrace for SW_TAGS
Date: Tue, 19 Jul 2022 02:10:11 +0200
Message-Id: <8db2d46b0e2c54aa7eaade18e39f68c0d9d09945.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="AgpB1/Ah";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8db2d46b0e2c54aa7eaade18e39f68c0d9d09945.1658189199.git.andreyknvl%40google.com.
