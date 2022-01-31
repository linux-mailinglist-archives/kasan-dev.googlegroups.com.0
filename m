Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX6N32HQMGQEUZYKIGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id B90914A3F08
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Jan 2022 10:07:44 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id e15-20020adf9bcf000000b001de055937d4sf4498181wrc.13
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jan 2022 01:07:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643620063; cv=pass;
        d=google.com; s=arc-20160816;
        b=KzgEmCDNKT6DKz/9KrtUw8L9FpKj/fz2CYmq1/hR/1L8D6SKWxOXgdW5eCr6bIQf/y
         IkDH8bgEEYNxd0zKRxgTHVp37s9w2H1se2gdlGRP8niDFkI1inXYaEVKOPf6rXF373Pc
         OjOVSUdg5oKX8ODiD3iN8hcCaHkrFTxYOlEi4/rtBT9iAnttV3SjAf2oCK1nX3+BhQzC
         2oOVp3+2QcNb2BI4fnwat22QeDFzEYE/ZLlCMKox/+DYeA67X7EuhySqoEeoDo/CS6YJ
         6NuPzw8pHvhx/HUTRTc5VZ7jmvo6cgXajsMRBbhXQGET8F78WDdFPZ3+qGBvMF2pYm82
         CLJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=gmO4FkMuJy76lkMaQFA5/9cyI4ccj/UnJ1A6POoQhRc=;
        b=Xd9u9Gb/ZOKa5gPVaVgcbo3pJpRjszeGOOR0VRXPCGwPrWL8iZFoxl0t6ldhf2GBqj
         hcX0iehcAd5UN38zgH9DWPHAIDPpMDn0A5S6tPVyLJXgk6v+agT/1Lqx1mvwJMAb2fHg
         9RpoeblgLMaJd5M+ASEQ8lGcS4Mg7pX/9DkHp7gKwGlXSz4otjPI91Fx6D1Hj0kTGQwK
         opXINbAsr/icMsNOJlRZVc8FfON2+kF/smFUOpfFPz3in5g1mhvjq3yxpch6xK8S9yhq
         XegVJeZWaZQ80GFAdNL5aRKW3sH/JHXd+dra5rAIQbqvfjwctmtJDmPGR6ElQalcBbuu
         BWkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YlfBbeCg;
       spf=pass (google.com: domain of 33ab3yqukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=33ab3YQUKCSAAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=gmO4FkMuJy76lkMaQFA5/9cyI4ccj/UnJ1A6POoQhRc=;
        b=MIMwlYAYw7VzusN6UbVvEPb2ULbxioVN9zo9ge9T8CLXfnd4S7nwDOUy0qv/TC9gqN
         eegg7mo0f7IYhaQ4EoaSgjkQxDFidTcdziyM1CLHDdQc8S13wWFRTqnL1gHiqFoj3eRc
         /GK+ZtUqwTPcIwW23UKRjRRlj5L7rDe7K4baRCqiJ9ScbVcz1nrk3Zw+rZ5Wa9IFPdQv
         dEGCzlb/gfJZTOWnAiNBvS9SXmBIs58ZsSzE81H0mMaFZTh8/SFc+cdyQrtoknry2sGr
         rUla3D1ldGU/Pnb2FdUnkb4tmugQ30dRxVf4QPmqJODG1BkqgJvwhc3oIs1fswFZRqj/
         74Yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gmO4FkMuJy76lkMaQFA5/9cyI4ccj/UnJ1A6POoQhRc=;
        b=uw28WgZB8ss6s5ThUYH57OPcvPxH1Fjd8S0io8sG4Zo3Dv7v6TkRliXRbKJv6SyN7G
         aJ16fj23LmCRol7qNpn9DmvMiL9viuKqDuheFwneMt2BT+cCRn4vinjJeWUTMspxyZZC
         Ur5ccRkiO7G17LP5yNeSdcHHjzZx9NmXTNd2Dm7WjpaBwmA//3tDarR5fjc1vF8RyZek
         tHbrB9Q0MKQBUHWj1S8pVZDAXGwKyPnRoPRRBpFqRGbfw94dWUF3b6mOmo9QH8f1f1Yq
         RKnjq/mYqcJzx+34CXNE6BWtO/iTyczMn60/eRc7MhjRemJW9HVj7s9DEKLeyrjY50BT
         pmjg==
X-Gm-Message-State: AOAM533BC/fXYXJ4CW3FB62sUZ14i7enekyhlGpuDMVsorLimNmoOGQf
	9hrdHPLqkX1AKln0YIAJnp0=
X-Google-Smtp-Source: ABdhPJy9S1pugvC99zF5A9T9v1y9gbqMM2ksKLUbr7Qkhx7ieodEMQZZMJbfjTWRfSNkrH465AsOCw==
X-Received: by 2002:adf:f046:: with SMTP id t6mr16238728wro.684.1643620063350;
        Mon, 31 Jan 2022 01:07:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2787:: with SMTP id n129ls7615829wmn.2.gmail; Mon, 31
 Jan 2022 01:07:42 -0800 (PST)
X-Received: by 2002:a1c:7918:: with SMTP id l24mr26133810wme.91.1643620062383;
        Mon, 31 Jan 2022 01:07:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643620062; cv=none;
        d=google.com; s=arc-20160816;
        b=xYJZnITAG3tj/wIxLhGLuIPXVSBqDjIDS+zdUM1vljoFtnELwv+FK+Mi7jM9xb0hQ5
         XEOso1JKz+zOyO5ByG+vY6pWF5lcCS3CdH7UbXa/o32xjjm+ussFjRCo5SYdd9L1U9Lt
         Tvu4Ts6PV3qnbXwA57+nbANDOy6Xq9Rnkqmg+ugiy8OAH64G72d8ZAmVZdq5Qdcu6ywU
         l9MAdgf+XmgQFXcoHqxR0CQQxmRXnCzBSGmYGKz10YSc3Sb2Y8Lm/YIlR2iN2N05HZZ5
         bxoN2cjIvUt0lNRhD3SzkUhrwhPy7e7mt4nZ5vMcc9X+J0WLh8gboZIawjRc9c+rg9OE
         HNeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=PGLVIgpx7K8YPtd39QgkpU42R1uwUVJe3VkPkvQuvOo=;
        b=W2RA+yopABfrA8xqfvckzukl+efUnzzjgHip/AmonOGxC/F3To2zH55SvPgYX6pcRS
         g0mc4z1FLC8NFCdEZFLNmdwJDqtBKtmw7Wzy6phYIlVYZhB/lKGXh3fWAyJHW3BAr6sC
         wcHK84syVqP7l67NSnh1bsRazQXYL5YpKllVK3A/q3H1FJeerAMhMdSWBvqL6btzGFe+
         ArdegACG8Rz6dtj3eLI0S/m+wIyGikg3lyG6WoC7GQ2YcjJZ+V1kxe2xt/deIYb95AcM
         dT10ANhBVqpEWki8UlnFw9HoTiX3amC08x8xIokJ+qg8yUOJrEraqsPPQ2UFNSHF51zu
         r/7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YlfBbeCg;
       spf=pass (google.com: domain of 33ab3yqukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=33ab3YQUKCSAAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id s10si1165617wrt.2.2022.01.31.01.07.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 Jan 2022 01:07:42 -0800 (PST)
Received-SPF: pass (google.com: domain of 33ab3yqukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id v185-20020a1cacc2000000b0034906580813so10070175wme.1
        for <kasan-dev@googlegroups.com>; Mon, 31 Jan 2022 01:07:42 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:9caa:cc34:599f:ecd4])
 (user=elver job=sendgmr) by 2002:a5d:4c88:: with SMTP id z8mr16383561wrs.209.1643620061954;
 Mon, 31 Jan 2022 01:07:41 -0800 (PST)
Date: Mon, 31 Jan 2022 10:05:20 +0100
Message-Id: <20220131090521.1947110-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.35.0.rc2.247.g8bbb082509-goog
Subject: [PATCH v2 1/2] stack: Introduce CONFIG_RANDOMIZE_KSTACK_OFFSET
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Thomas Gleixner <tglx@linutronix.de>, Kees Cook <keescook@chromium.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	Elena Reshetova <elena.reshetova@intel.com>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Alexander Potapenko <glider@google.com>, llvm@lists.linux.dev, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YlfBbeCg;       spf=pass
 (google.com: domain of 33ab3yqukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=33ab3YQUKCSAAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

The randomize_kstack_offset feature is unconditionally compiled in when
the architecture supports it.

To add constraints on compiler versions, we require a dedicated Kconfig
variable. Therefore, introduce RANDOMIZE_KSTACK_OFFSET.

Furthermore, this option is now also configurable by EXPERT kernels:
while the feature is supposed to have zero performance overhead when
disabled, due to its use of static branches, there are few cases where
giving a distribution the option to disable the feature entirely makes
sense. For example, in very resource constrained environments, which
would never enable the feature to begin with, in which case the
additional kernel code size increase would be redundant.

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Nathan Chancellor <nathan@kernel.org>
---
 arch/Kconfig                     | 23 ++++++++++++++++++-----
 include/linux/randomize_kstack.h |  5 +++++
 init/main.c                      |  2 +-
 3 files changed, 24 insertions(+), 6 deletions(-)

diff --git a/arch/Kconfig b/arch/Kconfig
index 678a80713b21..2cde48d9b77c 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -1159,16 +1159,29 @@ config HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
 	  to the compiler, so it will attempt to add canary checks regardless
 	  of the static branch state.
 
-config RANDOMIZE_KSTACK_OFFSET_DEFAULT
-	bool "Randomize kernel stack offset on syscall entry"
+config RANDOMIZE_KSTACK_OFFSET
+	bool "Support for randomizing kernel stack offset on syscall entry" if EXPERT
+	default y
 	depends on HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
 	help
 	  The kernel stack offset can be randomized (after pt_regs) by
 	  roughly 5 bits of entropy, frustrating memory corruption
 	  attacks that depend on stack address determinism or
-	  cross-syscall address exposures. This feature is controlled
-	  by kernel boot param "randomize_kstack_offset=on/off", and this
-	  config chooses the default boot state.
+	  cross-syscall address exposures.
+
+	  The feature is controlled via the "randomize_kstack_offset=on/off"
+	  kernel boot param, and if turned off has zero overhead due to its use
+	  of static branches (see JUMP_LABEL).
+
+	  If unsure, say Y.
+
+config RANDOMIZE_KSTACK_OFFSET_DEFAULT
+	bool "Default state of kernel stack offset randomization"
+	depends on RANDOMIZE_KSTACK_OFFSET
+	help
+	  Kernel stack offset randomization is controlled by kernel boot param
+	  "randomize_kstack_offset=on/off", and this config chooses the default
+	  boot state.
 
 config ARCH_OPTIONAL_KERNEL_RWX
 	def_bool n
diff --git a/include/linux/randomize_kstack.h b/include/linux/randomize_kstack.h
index bebc911161b6..91f1b990a3c3 100644
--- a/include/linux/randomize_kstack.h
+++ b/include/linux/randomize_kstack.h
@@ -2,6 +2,7 @@
 #ifndef _LINUX_RANDOMIZE_KSTACK_H
 #define _LINUX_RANDOMIZE_KSTACK_H
 
+#ifdef CONFIG_RANDOMIZE_KSTACK_OFFSET
 #include <linux/kernel.h>
 #include <linux/jump_label.h>
 #include <linux/percpu-defs.h>
@@ -50,5 +51,9 @@ void *__builtin_alloca(size_t size);
 		raw_cpu_write(kstack_offset, offset);			\
 	}								\
 } while (0)
+#else /* CONFIG_RANDOMIZE_KSTACK_OFFSET */
+#define add_random_kstack_offset()		do { } while (0)
+#define choose_random_kstack_offset(rand)	do { } while (0)
+#endif /* CONFIG_RANDOMIZE_KSTACK_OFFSET */
 
 #endif
diff --git a/init/main.c b/init/main.c
index 65fa2e41a9c0..560f45c27ffe 100644
--- a/init/main.c
+++ b/init/main.c
@@ -853,7 +853,7 @@ static void __init mm_init(void)
 	pti_init();
 }
 
-#ifdef CONFIG_HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
+#ifdef CONFIG_RANDOMIZE_KSTACK_OFFSET
 DEFINE_STATIC_KEY_MAYBE_RO(CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT,
 			   randomize_kstack_offset);
 DEFINE_PER_CPU(u32, kstack_offset);
-- 
2.35.0.rc2.247.g8bbb082509-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220131090521.1947110-1-elver%40google.com.
