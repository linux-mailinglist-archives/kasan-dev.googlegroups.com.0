Return-Path: <kasan-dev+bncBDAOBFVI5MIBB4PPXKGAMGQEFIQTOKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6700C44ECD6
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Nov 2021 19:52:34 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 205-20020a1c00d6000000b003335d1384f1sf3732551wma.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Nov 2021 10:52:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636743154; cv=pass;
        d=google.com; s=arc-20160816;
        b=IKg4vkm3hhRwi4caRO6lX64fP4RdO1A9yYmhHejZPvfvmwrM8IjAK4KZ9wp7ql1qTs
         srrTE/9ePNh6Kc1QnWpoSuWdzsKF0jFLPUqYU9outvp/SlNxy/LrlQmHfkMf6FSVml4D
         pHyfwUvWrYaQw7MENtnnjm3t2ksa9PhcAGkx21zHavJx9er4lAqqM/7WwMX1p+N74+uS
         ka5IalvOnUyiJbLN+F/W1rmqF3lMf4iZP8mIxIKQGin9pRXyj52EE+DDi+vPK2SMLwTt
         T5akZ1rjHL29r7Prrl3wdLoO1/8F4oZFDqTXkmwveswhyoFK84m7Q5iJauSLIGmqL+KY
         /fLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=M7dV0uh6HfosZIWCf8XNzm6FMhsruQRwyXIcHNMnXbU=;
        b=P0a6e9Ir4MpI33yI0br4H55my6tExeqYaYxgopuvG74YPZPC9FbXJEu35YTEJE2nZH
         U5RjjCbnycDSI5APmcp1b+1wzHQ1bW05gqmgc3sRckbmbw4GAipbA7U1qJdYOtO6JsLy
         jkgjhP5DDH6k1Ypv1KV21WrM8Y17IenKp+4WFS9n+J5/0H8CmSgIV0eaTPVazmso89Dg
         0vnaJUstQwydxx4rTSnA/DVsVksdsMYETKexHUkWAENa8kwajkxKoD+YwpH2wN/PffVI
         1XjBuGDmwpJjNTfp0ld5lO0WklFGdiNwryloxFucgUF9UlFqJdAWvTnfFTdJPOoQes/K
         dvKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M7dV0uh6HfosZIWCf8XNzm6FMhsruQRwyXIcHNMnXbU=;
        b=hCFgwqpKokF4ZmZ8fQf/lwPRkvtwzclKb4RXr+gU9wFXqukfv0g+Q6ODO69/S7Ddds
         baynoAk8LcZ+6uOnzsoIvGOwpgDdAVt4V/wrYEDNY73m9EukMhGfvWQpOl/eNlt0GwlI
         uaax7PBiOg8U5+fPH9ZUL1b98pGU1jRv5wIk0HWLN3u+D9LRlKmHz7kAdXTT/kwkbO/Y
         QvDUNBO1yjrAk/FZHFEL7rqs2YwnvPzGg4LRJJdkmcoSAMe40PX+6RZGfExXCXfyya8w
         DLvePrBQfqW2GGitZp/T1PWnyPv8k/5P+bTEThp4cz/ZvjpgVSDgvkY2jeHymn0Agefc
         W9+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M7dV0uh6HfosZIWCf8XNzm6FMhsruQRwyXIcHNMnXbU=;
        b=FGY3RXcouX2f+MveKrjsizOy+OJ5fH2dcbWnNNE5BzwOT+k04BgHkXfWYBqosL6aIX
         +hDWKhzM2Ilog1z5nN2Gh77+HPT4vM6RF+k+TNYsQrofjgWvwfOwNhxjowiEmGlIioRV
         GXnnyFXU+IvtECAbqKsORVy0GtLzh/r8UPhG6NU7MjrIcV94kI6m09hxeVtc+I5Sjtgy
         qY5b26Lz09Ui51ukQJDCAiDBC5n2xyEwKHHD7m1JTEul27EYeEgg5rnMtBgowb9IQbct
         LtqXnWbTDKo3+JlThFnh3wGf/mpr4sPykAi6ZGAxH+3T2Lq/FAubjiZA2yS0917GHRMN
         Chxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531S3L9/wHDXCp0AsgkrYNCcd6Ea+y6eHcVd2AgaKGWr3hIabFOB
	9uMKyza7UQuClqG6OO+oB5c=
X-Google-Smtp-Source: ABdhPJyIeW63wHGXtexpMCVQA+tn9J5UvoV8raN4Co+EVEu8uKqN5Ukym4nCDhmn6wIj5tFU0top0Q==
X-Received: by 2002:adf:fa0b:: with SMTP id m11mr21048340wrr.152.1636743154144;
        Fri, 12 Nov 2021 10:52:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7e16:: with SMTP id z22ls1979595wmc.2.canary-gmail; Fri,
 12 Nov 2021 10:52:33 -0800 (PST)
X-Received: by 2002:a7b:c119:: with SMTP id w25mr19363454wmi.70.1636743153274;
        Fri, 12 Nov 2021 10:52:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636743153; cv=none;
        d=google.com; s=arc-20160816;
        b=hvvDDtAg567IRpzJGhEgoGb8XcEP3UGQ5xIxEM2uWZH8pl5ioF3QtoDB7OWAZC6UCL
         TvNbMRcYcSvsP4S4DrWlc7Lf6I5YOsOxlaLR+E0WeMxZLFxWJrGYgtCEG+Hu6tWlKZN+
         HMMYhLGMTa2kB+czoWT0nNDI+cdSUgFeurzObPbjnijQaHlTuhb8bKgFNDgXiRCgmOVl
         rzNXbU5jhqTYvyKJbqHAVUzEtApFEiouteCpbxe82pY4kPhE5tW0Nwc9NUdxcEnPldRo
         EAVNhYRmxvAkVhtF1WnXJ8Pf4Dgz3hZ7aU8B6AOEZUOGZS/eZ10U53XBubqIaz5A5gm8
         qTsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=iVfsfVqOMS6+vwWKEzRkJOet2qKmN9jM9KJPE+ETw1E=;
        b=kMa+Dc13X2zYumWSiupDQf2pinb/uSUFAG/SgsLWc2608bmJdy0N7ImZ0+P/u5cvCH
         FDoVY+/HVZJX+g4Ms2E3hV/HddCFkTTioYUllvUfByDdi60/ttCIlf9ggzCKr7EfEk/y
         U+bmgFgnUATwrx2rrfYOv300o6rlW4N42zEsIsQX8lb4Yv08+/RCsr8Cgc8WqcqovxgI
         dtiJxvcOYWea9XQjLrvlM1zFfYIsi63aPytbaS2eMoHHVXhT0eelyhTZgaPSRsM/J4sz
         6Nd3zqKdYCIZjUqxSIe/yS7c+gf+899XvcB5oO6arJGj2PElQ1C9DSEVIQOMudDEH/l4
         0z1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i7si572134wrc.4.2021.11.12.10.52.33
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Nov 2021 10:52:33 -0800 (PST)
Received-SPF: pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6854D1063;
	Fri, 12 Nov 2021 10:52:32 -0800 (PST)
Received: from e113632-lin.cambridge.arm.com (e113632-lin.cambridge.arm.com [10.1.196.57])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 9FE363F70D;
	Fri, 12 Nov 2021 10:52:30 -0800 (PST)
From: Valentin Schneider <valentin.schneider@arm.com>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org
Cc: Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Mike Galbraith <efault@gmx.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Nick Desaulniers <ndesaulniers@google.com>
Subject: [PATCH v3 1/4] preempt: Restore preemption model selection configs
Date: Fri, 12 Nov 2021 18:52:00 +0000
Message-Id: <20211112185203.280040-2-valentin.schneider@arm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20211112185203.280040-1-valentin.schneider@arm.com>
References: <20211112185203.280040-1-valentin.schneider@arm.com>
MIME-Version: 1.0
X-Original-Sender: valentin.schneider@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Commit c597bfddc9e9 ("sched: Provide Kconfig support for default dynamic
preempt mode") changed the selectable config names for the preemption
model. This means a config file must now select

  CONFIG_PREEMPT_BEHAVIOUR=y

rather than

  CONFIG_PREEMPT=y

to get a preemptible kernel. This means all arch config files would need to
be updated - right now they'll all end up with the default
CONFIG_PREEMPT_NONE_BEHAVIOUR.

Rather than touch a good hundred of config files, restore usage of
CONFIG_PREEMPT{_NONE, _VOLUNTARY}. Make them configure:
o The build-time preemption model when !PREEMPT_DYNAMIC
o The default boot-time preemption model when PREEMPT_DYNAMIC

Add siblings of those configs with the _BUILD suffix to unconditionally
designate the build-time preemption model (PREEMPT_DYNAMIC is built with
the "highest" preemption model it supports, aka PREEMPT). Downstream
configs should by now all be depending / selected by CONFIG_PREEMPTION
rather than CONFIG_PREEMPT, so only a few sites need patching up.

Signed-off-by: Valentin Schneider <valentin.schneider@arm.com>
Acked-by: Marco Elver <elver@google.com>
---
 include/linux/kernel.h   |  2 +-
 include/linux/vermagic.h |  2 +-
 init/Makefile            |  2 +-
 kernel/Kconfig.preempt   | 42 ++++++++++++++++++++--------------------
 kernel/sched/core.c      |  6 +++---
 5 files changed, 27 insertions(+), 27 deletions(-)

diff --git a/include/linux/kernel.h b/include/linux/kernel.h
index 2776423a587e..9c7d774ef809 100644
--- a/include/linux/kernel.h
+++ b/include/linux/kernel.h
@@ -88,7 +88,7 @@
 struct completion;
 struct user;
 
-#ifdef CONFIG_PREEMPT_VOLUNTARY
+#ifdef CONFIG_PREEMPT_VOLUNTARY_BUILD
 
 extern int __cond_resched(void);
 # define might_resched() __cond_resched()
diff --git a/include/linux/vermagic.h b/include/linux/vermagic.h
index 1eaaa93c37bf..329d63babaeb 100644
--- a/include/linux/vermagic.h
+++ b/include/linux/vermagic.h
@@ -15,7 +15,7 @@
 #else
 #define MODULE_VERMAGIC_SMP ""
 #endif
-#ifdef CONFIG_PREEMPT
+#ifdef CONFIG_PREEMPT_BUILD
 #define MODULE_VERMAGIC_PREEMPT "preempt "
 #elif defined(CONFIG_PREEMPT_RT)
 #define MODULE_VERMAGIC_PREEMPT "preempt_rt "
diff --git a/init/Makefile b/init/Makefile
index 2846113677ee..04eeee12c076 100644
--- a/init/Makefile
+++ b/init/Makefile
@@ -30,7 +30,7 @@ $(obj)/version.o: include/generated/compile.h
 quiet_cmd_compile.h = CHK     $@
       cmd_compile.h = \
 	$(CONFIG_SHELL) $(srctree)/scripts/mkcompile_h $@	\
-	"$(UTS_MACHINE)" "$(CONFIG_SMP)" "$(CONFIG_PREEMPT)"	\
+	"$(UTS_MACHINE)" "$(CONFIG_SMP)" "$(CONFIG_PREEMPT_BUILD)"	\
 	"$(CONFIG_PREEMPT_RT)" $(CONFIG_CC_VERSION_TEXT) "$(LD)"
 
 include/generated/compile.h: FORCE
diff --git a/kernel/Kconfig.preempt b/kernel/Kconfig.preempt
index 60f1bfc3c7b2..ce77f0265660 100644
--- a/kernel/Kconfig.preempt
+++ b/kernel/Kconfig.preempt
@@ -1,12 +1,23 @@
 # SPDX-License-Identifier: GPL-2.0-only
 
+config PREEMPT_NONE_BUILD
+	bool
+
+config PREEMPT_VOLUNTARY_BUILD
+	bool
+
+config PREEMPT_BUILD
+	bool
+	select PREEMPTION
+	select UNINLINE_SPIN_UNLOCK if !ARCH_INLINE_SPIN_UNLOCK
+
 choice
 	prompt "Preemption Model"
-	default PREEMPT_NONE_BEHAVIOUR
+	default PREEMPT_NONE
 
-config PREEMPT_NONE_BEHAVIOUR
+config PREEMPT_NONE
 	bool "No Forced Preemption (Server)"
-	select PREEMPT_NONE if !PREEMPT_DYNAMIC
+	select PREEMPT_NONE_BUILD if !PREEMPT_DYNAMIC
 	help
 	  This is the traditional Linux preemption model, geared towards
 	  throughput. It will still provide good latencies most of the
@@ -18,10 +29,10 @@ config PREEMPT_NONE_BEHAVIOUR
 	  raw processing power of the kernel, irrespective of scheduling
 	  latencies.
 
-config PREEMPT_VOLUNTARY_BEHAVIOUR
+config PREEMPT_VOLUNTARY
 	bool "Voluntary Kernel Preemption (Desktop)"
 	depends on !ARCH_NO_PREEMPT
-	select PREEMPT_VOLUNTARY if !PREEMPT_DYNAMIC
+	select PREEMPT_VOLUNTARY_BUILD if !PREEMPT_DYNAMIC
 	help
 	  This option reduces the latency of the kernel by adding more
 	  "explicit preemption points" to the kernel code. These new
@@ -37,10 +48,10 @@ config PREEMPT_VOLUNTARY_BEHAVIOUR
 
 	  Select this if you are building a kernel for a desktop system.
 
-config PREEMPT_BEHAVIOUR
+config PREEMPT
 	bool "Preemptible Kernel (Low-Latency Desktop)"
 	depends on !ARCH_NO_PREEMPT
-	select PREEMPT
+	select PREEMPT_BUILD
 	help
 	  This option reduces the latency of the kernel by making
 	  all kernel code (that is not executing in a critical section)
@@ -58,7 +69,7 @@ config PREEMPT_BEHAVIOUR
 
 config PREEMPT_RT
 	bool "Fully Preemptible Kernel (Real-Time)"
-	depends on EXPERT && ARCH_SUPPORTS_RT && !PREEMPT_DYNAMIC
+	depends on EXPERT && ARCH_SUPPORTS_RT
 	select PREEMPTION
 	help
 	  This option turns the kernel into a real-time kernel by replacing
@@ -75,17 +86,6 @@ config PREEMPT_RT
 
 endchoice
 
-config PREEMPT_NONE
-	bool
-
-config PREEMPT_VOLUNTARY
-	bool
-
-config PREEMPT
-	bool
-	select PREEMPTION
-	select UNINLINE_SPIN_UNLOCK if !ARCH_INLINE_SPIN_UNLOCK
-
 config PREEMPT_COUNT
        bool
 
@@ -95,8 +95,8 @@ config PREEMPTION
 
 config PREEMPT_DYNAMIC
 	bool "Preemption behaviour defined on boot"
-	depends on HAVE_PREEMPT_DYNAMIC
-	select PREEMPT
+	depends on HAVE_PREEMPT_DYNAMIC && !PREEMPT_RT
+	select PREEMPT_BUILD
 	default y
 	help
 	  This option allows to define the preemption model on the kernel
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index f2611b9cf503..97047aa7b6c2 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -6625,13 +6625,13 @@ __setup("preempt=", setup_preempt_mode);
 static void __init preempt_dynamic_init(void)
 {
 	if (preempt_dynamic_mode == preempt_dynamic_undefined) {
-		if (IS_ENABLED(CONFIG_PREEMPT_NONE_BEHAVIOUR)) {
+		if (IS_ENABLED(CONFIG_PREEMPT_NONE)) {
 			sched_dynamic_update(preempt_dynamic_none);
-		} else if (IS_ENABLED(CONFIG_PREEMPT_VOLUNTARY_BEHAVIOUR)) {
+		} else if (IS_ENABLED(CONFIG_PREEMPT_VOLUNTARY)) {
 			sched_dynamic_update(preempt_dynamic_voluntary);
 		} else {
 			/* Default static call setting, nothing to do */
-			WARN_ON_ONCE(!IS_ENABLED(CONFIG_PREEMPT_BEHAVIOUR));
+			WARN_ON_ONCE(!IS_ENABLED(CONFIG_PREEMPT));
 			preempt_dynamic_mode = preempt_dynamic_full;
 			pr_info("Dynamic Preempt: full\n");
 		}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211112185203.280040-2-valentin.schneider%40arm.com.
