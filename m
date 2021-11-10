Return-Path: <kasan-dev+bncBDAOBFVI5MIBBNWVWCGAMGQENVEYLYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A1FB44CA85
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 21:25:27 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id z21-20020a05640240d500b003e3340a215asf3367403edb.10
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 12:25:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636575926; cv=pass;
        d=google.com; s=arc-20160816;
        b=XJ0IVWcjuYy65DWxP/Zr0RRV/srxQZDAT9XWAm69NV60HfaDZXbycfmjeqLMkoWVV+
         o93yyqqLzJHR6BxL6Fu4hrHmVfowvasS/MWnyL3xSn/82RnMj83nrh8+5zDEQoCr8I4M
         ehd2Zc+MPiCY/Gu/8E28GqfoA4x8B2ZRs4ft21SDv9HVsT/YFaVaMA2Hw2SeavifwaNw
         hkK7CU/WxbdGw6zFf4QQ/BtGcZWboOx+caPtYkhxDpqtC7DHv+fimuOZdFZzuq9LvxSq
         ziJAC06ALYY1aeNQCVpvdXj5kV8eOxIjlmy4/RLAcQWSmS9KbW9blddDvfW3O0sEMal9
         TNeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2tY7f+SDe9O12od7XozL/wGWLTFR4JUyJVKTAXYH/fI=;
        b=XOJXLHlxqvTuNLv22TxoUb881cga6W9MBrUK09YeZ2lxGJYz1tZ0Q5Nx6AWuozEcFw
         3luOc0KcSlQ8yPvEJ/DNga0jFUp37UnSkNYQnosmLKbgjExeYqBoZlCn87kzZJNd5JNZ
         OuWdyKZJhON6vpAJ8Mod7AEnRbd8ZUCKa6+aZT7tdWChzxxqHWfHIrYwAB/IsDa8JLOB
         sE9ZymfsLK/Ng3n0d58gH+Aih1eso6gvUd5ZHtvEmoOmXKHxg/emBQ4YPZT/SdNUFRs2
         Jl8ikmUmOKo/8VMobrGi1twCimOakXKYpnWb5+q7h4GX0a1RSPh6T3LC59yIiztA/+5W
         RKBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2tY7f+SDe9O12od7XozL/wGWLTFR4JUyJVKTAXYH/fI=;
        b=mLI2TY1KukHdDuCn89WPkA3weY1KYPk0Ubx3jJi4cKwMgk+2lTwB4yLxoeFL6vmWcy
         ObTA0OAZescaC7duy62EFgPSAkOJm6qXDjoFUYy3tAB5zbELKbw30nUObVtiSqoM/MNX
         gXvvgCZ/eTqq77wKp6kh8PYHD62iE2hrH7N0mafAexNF+oAD9vu2riM3/oSkmDNUgcjq
         CZu+ZQizFr5Jtl+KnqZ4oWQNcvOGnOYa7OSyt/0Iv7kHeiYfzwa3UkfDgLif2HUT4I2t
         9FPJ1oqcaOLjZwx46eYufmZu+PUkLmD5yso0W7L9dkjUmyIhyZHQNLdFU5I/YJf5SnKj
         MRuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2tY7f+SDe9O12od7XozL/wGWLTFR4JUyJVKTAXYH/fI=;
        b=ijtkF4cVsYDiJmL0Q5rHW0zkTggbo+akF31SriEwQSGonA3sh4vSTMFXmuniYD+dmL
         fGsWQVgMlMm+9c/6YD6KhQCuVhNmrCB3bDjrqYfeKVuaWTNhjgdhQg2JUh8vyuG5zTSr
         lc4QlG3CITk+CX/5gdDMO1QMP7oC/jzPuhs9z3Br6MS2otSxcGXMn3+/o1vloccjbP3m
         INVpVL2syNR1mx1HU9G1v7EXtuAWcxBeGlwpgNnhkDBhOieD+urkLabsJnXhZOHrQjz/
         Pc8i7Pd6FGo5VGS5+xyx+joIjI95rM+tS+ZdkLXasPfpClVloierCds14tPGNSUUO8Y4
         QzeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533gMrdGNACFYqSgNQXQagwHXrRCrAhKWJkgbCho/KeHL+QA2r1A
	LfeJynbBUlaYDGwoJWk73v4=
X-Google-Smtp-Source: ABdhPJwdX7kL801qP534+kVzXuISDFqs+0Ob4wW/0OYv665x3ItMD1jZdI+f1Op/53LLN0wacAyZRA==
X-Received: by 2002:a05:6402:270e:: with SMTP id y14mr2333249edd.140.1636575926887;
        Wed, 10 Nov 2021 12:25:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:d10:: with SMTP id gn16ls363822ejc.5.gmail; Wed, 10
 Nov 2021 12:25:25 -0800 (PST)
X-Received: by 2002:a17:906:4fc5:: with SMTP id i5mr2392274ejw.475.1636575925903;
        Wed, 10 Nov 2021 12:25:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636575925; cv=none;
        d=google.com; s=arc-20160816;
        b=ee/0cKv6UCMdsfeVnzhh/TvBde415Vb351Udg1JX8Dbg55UhrIc0Ekvy5r+fifu7CS
         ao5lyqGYDBgQ0GwVo90IYbn4tVfyuIYCgfeiI+0uzef0365oK1Oum1SAp0cveZW3db4K
         G8JUFQ+mF6EUZISS+2LytxY1zaMwdM7rJyNP6pBeljTwZwYKGRiQywK6IeQohqbBDmvH
         8KCQ7BHC/IuCf7vAnZflH79+CAGSxmHh8Nk+gwhMKVx6vurfToV2h1M3zxOTVtyv2nqt
         EKy6YxuCiBE4uxNpTR7ZHPwKbwUX4sdQ0hjS1gKvn6wf+qieNhCXeksQj8Ci0UB41hoe
         f//w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=A1eg+ddyxvGdqK+wV6P6KzvwAx/ukheotKt5KM+zucM=;
        b=vD/OhY0tooH6/jfHpiaNK4uaeqMXfblCI1JsguoK8W+QZs3AV8RvptkZ9Aq2L8f+eo
         I9DDpwNnZ+03eySVSD1+Vou5de9opqtZuCaL7DHEDC/10n/bYvZ/7w2dEKtQatyynvoY
         hr8zDBrX2QtoJ1bWLNsaRLaIrkN2LQ5sk/znJpbhUdxBv5CtRT+pUM4p4TkpY31sQ5PJ
         ulcl8lO0weFFnTKTysY+KeB7eLlOrCTad82ASFW9uiDcwr01oJDTdlYYriWVeaDnLbdP
         LrAIAewKKM4g/nUgKIdl2UiXCMKFWhngXqITpx9nXI5O3UdG/rO6E4VgsQdDSgUuX9VJ
         LHXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id u19si94177edo.5.2021.11.10.12.25.25
        for <kasan-dev@googlegroups.com>;
        Wed, 10 Nov 2021 12:25:25 -0800 (PST)
Received-SPF: pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 225C713A1;
	Wed, 10 Nov 2021 12:25:25 -0800 (PST)
Received: from e113632-lin.cambridge.arm.com (e113632-lin.cambridge.arm.com [10.1.196.57])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id E5F3D3F5A1;
	Wed, 10 Nov 2021 12:25:22 -0800 (PST)
From: Valentin Schneider <valentin.schneider@arm.com>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linuxppc-dev@lists.ozlabs.org,
	linux-kbuild@vger.kernel.org
Cc: Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Mike Galbraith <efault@gmx.de>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Nick Desaulniers <ndesaulniers@google.com>
Subject: [PATCH v2 1/5] preempt: Restore preemption model selection configs
Date: Wed, 10 Nov 2021 20:24:44 +0000
Message-Id: <20211110202448.4054153-2-valentin.schneider@arm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20211110202448.4054153-1-valentin.schneider@arm.com>
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211110202448.4054153-2-valentin.schneider%40arm.com.
