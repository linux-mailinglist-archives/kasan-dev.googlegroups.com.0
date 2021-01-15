Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOOJQ6AAMGQEFV5CYLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id BD9FB2F84C1
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 19:53:45 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id l13sf3389177ljc.20
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 10:53:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610736825; cv=pass;
        d=google.com; s=arc-20160816;
        b=thPrT4i7On7ahDdGqMPorzL0LwkcSpawQzD1YzuJKTe6eLLHTfkm1C4xXKB2/WeqlA
         9cVXFro3o6oM8CuEqwf/VmeyQOXEes+KoKyH+Sa7H2ZKqBNjM+PwxDOf/Va4MU+3+z6g
         p8WRXmI1ObbyGYweKh1D9RDQ5v4V/nb5h41xRIT4wwoRKVc2PhgkvM0u7iGRQEDvDZtw
         zPF8k+MQ0WKhyUpF8lKuI1Dy0smPsGo6aImc/BeOf+94H6iRLPay6/HIsQNc5ocMc8xB
         WWSaNdsDvqEIcGkNCP5NvjOhBekUjEZZShQli0tUQWquJvp62AZOeV7xPdzIBpz9qm+v
         9OWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=1dCzutqN6tVGw634dsidS7nPJXWlxZVU3XAy4zkZZJw=;
        b=bCG9Z2WMo5E2Bskn7GdLm05bNwQ6FIq3Rz4Soj5MrIz5T0V8MQsx7gNBatIiHDWC2g
         FCuTtBob+ftNxLGJsMhTbIdXdKsro/oV53H3uxRtUDJ2TtzpC4BEqRSAVZd1BoizFWqP
         QKhRkLoNlECE1qqqcjXWUXum8l5OHbcHtD3S+yBsACTfaArZjqdA+/h6dPnSN6jx4Nm4
         lkMoMehyL+TcJpgRWLkUfeZpDA5ZHGwMMx8tOQBEUQCYbSMzjbSRdJaPA+ib46Yut6pd
         RIrXS43NHbjxBnvuVQEYTUrAdiAM8/XuG/6tfRWE7s6cvXDxgLQTOf06Kl0g28ibrI0X
         AAsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CpUCd+iW;
       spf=pass (google.com: domain of 3t-qbyaokcy4s5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3t-QBYAoKCY4s5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1dCzutqN6tVGw634dsidS7nPJXWlxZVU3XAy4zkZZJw=;
        b=iEt/aJ7HRhoVTzJQad7v9pSY/6ggbxfnHt5rI1fddNLiT0D128CayMlkWcbS69ni8Z
         WiAcfefYZ+Nr8nhBinUw2StuwtQuZwXVhkakutySvNCq+P+uz2SzWc7qMKrDzJzM4Kw6
         xhmENx3dnyuDz0S9PwXIu6mzKiQkgF5/SUv4WLndiLPaTZT5V3E7pjSkRP8yoEOV0iPN
         e8ljG1re8Ged5UDV5YpIfgcK4VKmRAXYU0tutaqxyccYsLZJa6fe63jraOfrYXLmlnor
         IgQQ1N6zRV5EAWV403aAWnOWsjrJ6OfhLjoofh64/hzW6RfR0186cz0/HQaA5V8pAfPk
         wEVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1dCzutqN6tVGw634dsidS7nPJXWlxZVU3XAy4zkZZJw=;
        b=i8NKkav0q3BzE0UZ09qm2Q17ANigxpnzI4RyGAkif5imGHSJldPyvYGI/XVIJABc0q
         coPLq3MwpLzFO2cPsbHBpzGlyWVZ7+kDEau7AuQ5LUWlSYSJfOwZ1l1ZTtwFoTyWZsZI
         hPCc6x0GytFwmt/UwOs5yuAYLJK7uY0TqS+nxlb1Z6/9IsvoKYKkEr+LPWA65Gc9vY2L
         X2g9VxkSJGFaG0em18zebqLSbWF+qAlUlijLYp4mCAMfR7Sac3UuSGg1zwwwyFtK8jNt
         GCIYIhEwlRBrWdP5f5ZXrgr7oxkRjeebaIwWXi9KHXzrUXq+qGO/as7RhbmUcTOcpLRY
         jJvA==
X-Gm-Message-State: AOAM532zuRGfg71GeubPTBqxe7ZgCwF6mODvoDKuZh+RM3hkqvMSiADG
	BTKP90wmPY8hujQntJI1O48=
X-Google-Smtp-Source: ABdhPJw/OUHnjL/SjwxHK8/lYwBSfMb93LXFycQtHPDLIOIISLVkXhJa6zw+fV+o0L7cV7gIjuPBRg==
X-Received: by 2002:ac2:518d:: with SMTP id u13mr6047178lfi.169.1610736825365;
        Fri, 15 Jan 2021 10:53:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:5816:: with SMTP id m22ls1725894ljb.4.gmail; Fri, 15 Jan
 2021 10:53:44 -0800 (PST)
X-Received: by 2002:a2e:361a:: with SMTP id d26mr5915574lja.115.1610736824238;
        Fri, 15 Jan 2021 10:53:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610736824; cv=none;
        d=google.com; s=arc-20160816;
        b=kkLHlQriDrGoWFkIDDkdaAbZ38K0ClsvgpKPYHGtuOmwKOWZYUBuv/XXwphwk4xTGi
         nRX4rtyM3VpyPFbdC/igJus3Wa5ISV0A3FUruR5gUc19sejuE4d/wRWR9QVP6GQOvqnY
         zSGaBxWppP9MQs3t51wUGA3Vj8ZL7of0L5Q2tsY5sxJfUKyZ6c2gdPJjJedUAXP0bEs7
         wmTQc5criClGKNRUppvpLGz9CbPgSokeQ7QByKxGpUPC0p4Zqv/PlbMSs/Rs/Q4JLx5W
         tFmeGU2sIwEUM0lPisYYjyP1Z9iQ2FUG1Ad7pcJhPHP99GeGgqeJZ5PnBMb4jKDbiohW
         uuPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=HyFjKVacTlfQ2SeJeH1SRYEzw6mjil7hujgAd5x/9zk=;
        b=fVkKeAgFitpSokfzuLB2DufZDzD6+xPTVuctH30+2VOnz/S20cF3p9cUqJvpkLdiLa
         MiwhGMnLUlKE7/9KFOD8jABw5MPNXQgrU332H0PEdQKz+KmTm8ut84BB2LC3VsaSIvxY
         aY+rHGVRfFJhv0Nh5sN5ISFMz6Rfvdz6n9kriNLZDwV8515d8V2zf+FhLd3+nVH1g3FE
         mJsS2O0dmjxzpcHB1hqkakO9ekyo69bDpNsYQAp9t3mqZc8oXuthprqy5tR96gRPn2mT
         z6OS71ReAd2V6191J6l9Ep10xxFRtbY5JsaY7JY0FI0Uz+2dYxDqmY3QOYRthDEEtPU0
         Mucw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CpUCd+iW;
       spf=pass (google.com: domain of 3t-qbyaokcy4s5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3t-QBYAoKCY4s5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id z4si580306lfr.7.2021.01.15.10.53.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 10:53:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 3t-qbyaokcy4s5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id v5so4541424wrr.0
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 10:53:44 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:5112:: with SMTP id
 s18mr14384990wrt.267.1610736823686; Fri, 15 Jan 2021 10:53:43 -0800 (PST)
Date: Fri, 15 Jan 2021 19:53:09 +0100
Message-Id: <4e9c4a4bdcadc168317deb2419144582a9be6e61.1610736745.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH] kasan: fix HW_TAGS boot parameters
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CpUCd+iW;       spf=pass
 (google.com: domain of 3t-qbyaokcy4s5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3t-QBYAoKCY4s5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
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

The initially proposed KASAN command line parameters are redundant.

This change drops the complex "kasan.mode=off/prod/full" parameter
and adds a simpler kill switch "kasan=off/on" instead. The new parameter
together with the already existing ones provides a cleaner way to
express the same set of features.

The full set of parameters with this change:

kasan=off/on             - whether KASAN is enabled
kasan.fault=report/panic - whether to only print a report or also panic
kasan.stacktrace=off/on  - whether to collect alloc/free stack traces

Default values:

kasan=on
kasan.fault=report
kasan.stacktrace=on  (if CONFIG_DEBUG_KERNEL=y)
kasan.stacktrace=off (otherwise)

Link: https://linux-review.googlesource.com/id/Ib3694ed90b1e8ccac6cf77dfd301847af4aba7b8
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 27 +++--------
 mm/kasan/hw_tags.c                | 77 +++++++++++++------------------
 2 files changed, 38 insertions(+), 66 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 0fc3fb1860c4..1651d961f06a 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -160,29 +160,14 @@ intended for use in production as a security mitigation. Therefore it supports
 boot parameters that allow to disable KASAN competely or otherwise control
 particular KASAN features.
 
-The things that can be controlled are:
+- ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
 
-1. Whether KASAN is enabled at all.
-2. Whether KASAN collects and saves alloc/free stacks.
-3. Whether KASAN panics on a detected bug or not.
+- ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
+  traces collection (default: ``on`` for ``CONFIG_DEBUG_KERNEL=y``, otherwise
+  ``off``).
 
-The ``kasan.mode`` boot parameter allows to choose one of three main modes:
-
-- ``kasan.mode=off`` - KASAN is disabled, no tag checks are performed
-- ``kasan.mode=prod`` - only essential production features are enabled
-- ``kasan.mode=full`` - all KASAN features are enabled
-
-The chosen mode provides default control values for the features mentioned
-above. However it's also possible to override the default values by providing:
-
-- ``kasan.stacktrace=off`` or ``=on`` - enable alloc/free stack collection
-					(default: ``on`` for ``mode=full``,
-					 otherwise ``off``)
-- ``kasan.fault=report`` or ``=panic`` - only print KASAN report or also panic
-					 (default: ``report``)
-
-If ``kasan.mode`` parameter is not provided, it defaults to ``full`` when
-``CONFIG_DEBUG_KERNEL`` is enabled, and to ``prod`` otherwise.
+- ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
+  report or also panic the kernel (default: ``report``).
 
 For developers
 ~~~~~~~~~~~~~~
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 55bd6f09c70f..e529428e7a11 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -19,11 +19,10 @@
 
 #include "kasan.h"
 
-enum kasan_arg_mode {
-	KASAN_ARG_MODE_DEFAULT,
-	KASAN_ARG_MODE_OFF,
-	KASAN_ARG_MODE_PROD,
-	KASAN_ARG_MODE_FULL,
+enum kasan_arg {
+	KASAN_ARG_DEFAULT,
+	KASAN_ARG_OFF,
+	KASAN_ARG_ON,
 };
 
 enum kasan_arg_stacktrace {
@@ -38,7 +37,7 @@ enum kasan_arg_fault {
 	KASAN_ARG_FAULT_PANIC,
 };
 
-static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
+static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
 static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
 
@@ -52,26 +51,24 @@ DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
 /* Whether panic or disable tag checking on fault. */
 bool kasan_flag_panic __ro_after_init;
 
-/* kasan.mode=off/prod/full */
-static int __init early_kasan_mode(char *arg)
+/* kasan=off/on */
+static int __init early_kasan_flag(char *arg)
 {
 	if (!arg)
 		return -EINVAL;
 
 	if (!strcmp(arg, "off"))
-		kasan_arg_mode = KASAN_ARG_MODE_OFF;
-	else if (!strcmp(arg, "prod"))
-		kasan_arg_mode = KASAN_ARG_MODE_PROD;
-	else if (!strcmp(arg, "full"))
-		kasan_arg_mode = KASAN_ARG_MODE_FULL;
+		kasan_arg = KASAN_ARG_OFF;
+	else if (!strcmp(arg, "on"))
+		kasan_arg = KASAN_ARG_ON;
 	else
 		return -EINVAL;
 
 	return 0;
 }
-early_param("kasan.mode", early_kasan_mode);
+early_param("kasan", early_kasan_flag);
 
-/* kasan.stack=off/on */
+/* kasan.stacktrace=off/on */
 static int __init early_kasan_flag_stacktrace(char *arg)
 {
 	if (!arg)
@@ -113,8 +110,8 @@ void kasan_init_hw_tags_cpu(void)
 	 * as this function is only called for MTE-capable hardware.
 	 */
 
-	/* If KASAN is disabled, do nothing. */
-	if (kasan_arg_mode == KASAN_ARG_MODE_OFF)
+	/* If KASAN is disabled via command line, don't initialize it. */
+	if (kasan_arg == KASAN_ARG_OFF)
 		return;
 
 	hw_init_tags(KASAN_TAG_MAX);
@@ -124,43 +121,28 @@ void kasan_init_hw_tags_cpu(void)
 /* kasan_init_hw_tags() is called once on boot CPU. */
 void __init kasan_init_hw_tags(void)
 {
-	/* If hardware doesn't support MTE, do nothing. */
+	/* If hardware doesn't support MTE, don't initialize KASAN. */
 	if (!system_supports_mte())
 		return;
 
-	/* Choose KASAN mode if kasan boot parameter is not provided. */
-	if (kasan_arg_mode == KASAN_ARG_MODE_DEFAULT) {
-		if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
-			kasan_arg_mode = KASAN_ARG_MODE_FULL;
-		else
-			kasan_arg_mode = KASAN_ARG_MODE_PROD;
-	}
-
-	/* Preset parameter values based on the mode. */
-	switch (kasan_arg_mode) {
-	case KASAN_ARG_MODE_DEFAULT:
-		/* Shouldn't happen as per the check above. */
-		WARN_ON(1);
-		return;
-	case KASAN_ARG_MODE_OFF:
-		/* If KASAN is disabled, do nothing. */
+	/* If KASAN is disabled via command line, don't initialize it. */
+	if (kasan_arg == KASAN_ARG_OFF)
 		return;
-	case KASAN_ARG_MODE_PROD:
-		static_branch_enable(&kasan_flag_enabled);
-		break;
-	case KASAN_ARG_MODE_FULL:
-		static_branch_enable(&kasan_flag_enabled);
-		static_branch_enable(&kasan_flag_stacktrace);
-		break;
-	}
 
-	/* Now, optionally override the presets. */
+	/* Enable KASAN. */
+	static_branch_enable(&kasan_flag_enabled);
 
 	switch (kasan_arg_stacktrace) {
 	case KASAN_ARG_STACKTRACE_DEFAULT:
+		/*
+		 * Default to enabling stack trace collection for
+		 * debug kernels.
+		 */
+		if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
+			static_branch_enable(&kasan_flag_stacktrace);
 		break;
 	case KASAN_ARG_STACKTRACE_OFF:
-		static_branch_disable(&kasan_flag_stacktrace);
+		/* Do nothing, kasan_flag_stacktrace keeps its default value. */
 		break;
 	case KASAN_ARG_STACKTRACE_ON:
 		static_branch_enable(&kasan_flag_stacktrace);
@@ -169,11 +151,16 @@ void __init kasan_init_hw_tags(void)
 
 	switch (kasan_arg_fault) {
 	case KASAN_ARG_FAULT_DEFAULT:
+		/*
+		 * Default to no panic on report.
+		 * Do nothing, kasan_flag_panic keeps its default value.
+		 */
 		break;
 	case KASAN_ARG_FAULT_REPORT:
-		kasan_flag_panic = false;
+		/* Do nothing, kasan_flag_panic keeps its default value. */
 		break;
 	case KASAN_ARG_FAULT_PANIC:
+		/* Enable panic on report. */
 		kasan_flag_panic = true;
 		break;
 	}
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4e9c4a4bdcadc168317deb2419144582a9be6e61.1610736745.git.andreyknvl%40google.com.
