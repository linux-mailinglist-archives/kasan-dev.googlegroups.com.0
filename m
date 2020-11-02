Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWO4QD6QKGQEGOYWYOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id EA52B2A2F26
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:45 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id s22sf1439168ljs.10
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333145; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rlmme3IuNsoQ6hO3Prq3ZhdmVOM+a17dLdVwQh2w1UKqJp3Dfo1Mi/jLluG0uSNqDg
         ryIgrbwDUz8xtzBf4Vio3VLwUF3fv7Xq9xkZ+OgckVc3AEN2WnyCc5u42UXdXhZMwJxc
         3N2YwZgw/cASJQ5/mKO1xyqRSs+5qUiTa0DBLecFCYUbX83zS7L8owKiTRYgDIB4ax0d
         CbhF69SQAkS9dN0c4dTSHhQ626RHCF9nmN0cOh+XEumd3RfmY0aZAw0Ekgm+HtjoQpV9
         0D8+IFyZfBv9WZdVoGKVw8C0Bm6hsjeu3z3re9jbPAdMlxFlgE0p7O/ZnXvK33s7/r78
         uEuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=EBTH6Dt9RtGnfZ3ViKHMRzZJO+DJHKy9y8t7K7/Av0A=;
        b=r4snKpU2D0KdyZZhRyB7Y9f3DTpcLAjyAsHPthZMzQGQwUnPxbrB9Z3e9IwHOqIwsN
         5JGFBT4Rwb/nXLxZlYkRasN/QLHuKBqdB0UnUxtikaQfQzplXmWTjkByBhut+wJGy7IC
         SsgXXUqh8zBRkMiFEr0EyDUbZ+Q03m4oH4BNrR9cOYutRvVgwB1OviQaLKrlC4+ytoSE
         ZHbGC0tz+lFRPme8gTnFOpABty+Ku5W6cOyJdmotbox4kcrUAeEuM9zjNzkKkN2yj/Oj
         hR2XZbJ/uTUcJQ96svZ85VX1lYiUfZD8qEjKdN6scw0AS1oEzua3r/y9zmhWuOoYoyQd
         0PNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YBI03g9B;
       spf=pass (google.com: domain of 3vy6gxwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3Vy6gXwoKCTgUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EBTH6Dt9RtGnfZ3ViKHMRzZJO+DJHKy9y8t7K7/Av0A=;
        b=p8vJHQ87s2dIiLho962uVZsqFNNBAQqvmKpwIA8/aqTppQUlQdwLlRawMJLUJ7b5pG
         R/JDLtOxb1Co9lJHEODSzaEN07RQCuekGXse2zj73vuO6Q++GNmQ0jZNoa596zO3HOBH
         IbVEYjrVIvc1IGRM/BSd4YQa5vDDnEwtHToHkPTxKf0hqNioR3O9CtYS/eKx0P69kPnM
         FA7/xycLKKZNhlgtNNb9Sq4HHVGzAvnKe2SI9zabXvI/7YdRWJN6VFB1dC5N3Nn7fW94
         w5XJ4dfdjcbXVSQi76YkPTwInMu52KoSmXAN9NenFmLvDmk6hP8/xZu2qtG9FBeQUCO6
         1SCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EBTH6Dt9RtGnfZ3ViKHMRzZJO+DJHKy9y8t7K7/Av0A=;
        b=GtHBCqv4OM5SoKq9bCOKEjHnxSWMhTmVWBCZxdEHl4/U4RIsxd4pvf9yQCisR/aQXj
         Y024zRPPL6WxLvysNLzA/NxXMdcy49Q05KYkZqRwycZyWay53Mn0FI2RtfTqjdCR//lv
         TcaOL2T5l81EHnkKUipK2Ft57Kx87dQFF85KQ4hzSnzig+8ZyTzuyAeAmTYoOXK0TSOa
         t+i21dmfin5uTWT9SMC6cG30S6CIpU70wd1P0M7LUGLyOl0cA5Xd33qs0gQJxz0rcC+r
         J3rAwkbe6WJxeqCoORHot7PJB5I4adclYVoAtXcjz5+gpSD5miyKanWdpYHMNgYpKW1Z
         c1zg==
X-Gm-Message-State: AOAM532LUEluZPp2RNHQXq0lv23ZH0i1vLQNirGCBxcdgd/1gu+VzfB1
	xi8kiD+ouV2twHQfjRewkx4=
X-Google-Smtp-Source: ABdhPJwCBDlsGFh3FX9TP8ltnzn3zLn9AcYwMBSdBKbmVKafs6FVDXHTSK9ULl3I/k/7yPldGjcwGA==
X-Received: by 2002:a2e:515a:: with SMTP id b26mr7384486lje.262.1604333145530;
        Mon, 02 Nov 2020 08:05:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:998f:: with SMTP id w15ls2049004lji.4.gmail; Mon, 02 Nov
 2020 08:05:44 -0800 (PST)
X-Received: by 2002:a2e:8296:: with SMTP id y22mr6578778ljg.174.1604333144510;
        Mon, 02 Nov 2020 08:05:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333144; cv=none;
        d=google.com; s=arc-20160816;
        b=IxQNcaHJD4Lyuop/lz+qkMgppwAKKYjzn8HLFDU9KbhoqObKvnBlall0cqmUU/xNmK
         qWOjGLZinbGhumcNnnh2a85YrF6z5knS9gIjin6AYY0BavI15CEPhy8ALGGLZ0mPgRE1
         H1KfY6UrWhgnVurJUjHfa/RiCeI/cWT9cft1KyqKsItpQw3heW5IHR4mMv5vrK94t1Gc
         Vt9HuDPtpGaAGel0qtmSgdmNEmgfvITgEMh/cRBoOGsP+qgIl6dtzXhAhNI1tPccTzYq
         JLVZulNzfeYQe4JwUAEJT46pfhng9Gk/B2WVFNWy2W8v9+ZhMGwIPU0APF+v+kIfRJqH
         FHow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=VDtcX23y6dPJZ06sfD07OvqXxdMGED0dxQgWlB1yXT4=;
        b=TrL0eolTxjGbXB032/6emF17astxHsUMv/EI37nyoFKN98L5NKqLvs3S+RA/2lpj0A
         8l5pAW+QwRj4Z1HWxmEFXrbbcq7+Hj8OxVmmddaAQtB2IH54jRN4k+dmsuyiZ0b79EX5
         nJPeqyxPVZwtLmfJj8PwFaEBKXX/rF85+3rvjVknIwq/+Jef6t5v7oxTKi4WLoQBGbij
         oDxeaMOQwumCW3mNqtOdBog0Ttf6MiJh0Jzasxko0YGkGYZVc/osRq9lrDv7iMU/HGSV
         F/LsT5HkKDnsfE7ctqP9otzE3XQCPsMbQgQ6WEI0xWM6Ws/fPFUQkuuaLMX9JBRJcLp3
         IgSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YBI03g9B;
       spf=pass (google.com: domain of 3vy6gxwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3Vy6gXwoKCTgUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id l28si502203lfp.11.2020.11.02.08.05.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vy6gxwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id a73so6312902edf.16
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:44 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a50:c058:: with SMTP id
 u24mr3353028edd.28.1604333143941; Mon, 02 Nov 2020 08:05:43 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:12 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <9fd49bf636f1f9be56cf400c9ec8afc9b5bc2cfa.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 32/41] kasan: introduce CONFIG_KASAN_HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YBI03g9B;       spf=pass
 (google.com: domain of 3vy6gxwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3Vy6gXwoKCTgUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
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

This patch adds a configuration option for a new KASAN mode called
hardware tag-based KASAN. This mode uses the memory tagging approach
like the software tag-based mode, but relies on arm64 Memory Tagging
Extension feature for tag management and access checking.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I246c2def9fffa6563278db1bddfbe742ca7bdefe
---
 lib/Kconfig.kasan | 58 +++++++++++++++++++++++++++++++++--------------
 1 file changed, 41 insertions(+), 17 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index ec59a0e26d09..e5f27ec8b254 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -6,7 +6,10 @@ config HAVE_ARCH_KASAN
 config HAVE_ARCH_KASAN_SW_TAGS
 	bool
 
-config	HAVE_ARCH_KASAN_VMALLOC
+config HAVE_ARCH_KASAN_HW_TAGS
+	bool
+
+config HAVE_ARCH_KASAN_VMALLOC
 	bool
 
 config CC_HAS_KASAN_GENERIC
@@ -20,11 +23,11 @@ config CC_HAS_WORKING_NOSANITIZE_ADDRESS
 
 menuconfig KASAN
 	bool "KASAN: runtime memory debugger"
-	depends on (HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
-		   (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
+	depends on (((HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
+		     (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)) && \
+		    CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
+		   HAVE_ARCH_KASAN_HW_TAGS
 	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
-	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
-	select CONSTRUCTORS
 	select STACKDEPOT
 	help
 	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
@@ -37,18 +40,24 @@ choice
 	prompt "KASAN mode"
 	default KASAN_GENERIC
 	help
-	  KASAN has two modes: generic KASAN (similar to userspace ASan,
-	  x86_64/arm64/xtensa, enabled with CONFIG_KASAN_GENERIC) and
-	  software tag-based KASAN (a version based on software memory
-	  tagging, arm64 only, similar to userspace HWASan, enabled with
-	  CONFIG_KASAN_SW_TAGS).
+	  KASAN has three modes:
+	  1. generic KASAN (similar to userspace ASan,
+	     x86_64/arm64/xtensa, enabled with CONFIG_KASAN_GENERIC),
+	  2. software tag-based KASAN (arm64 only, based on software
+	     memory tagging (similar to userspace HWASan), enabled with
+	     CONFIG_KASAN_SW_TAGS), and
+	  3. hardware tag-based KASAN (arm64 only, based on hardware
+	     memory tagging, enabled with CONFIG_KASAN_HW_TAGS).
+
+	  All KASAN modes are strictly debugging features.
 
-	  Both generic and tag-based KASAN are strictly debugging features.
+	  For better error reports enable CONFIG_STACKTRACE.
 
 config KASAN_GENERIC
 	bool "Generic mode"
 	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
 	select SLUB_DEBUG if SLUB
+	select CONSTRUCTORS
 	help
 	  Enables generic KASAN mode.
 
@@ -61,8 +70,6 @@ config KASAN_GENERIC
 	  and introduces an overhead of ~x1.5 for the rest of the allocations.
 	  The performance slowdown is ~x3.
 
-	  For better error detection enable CONFIG_STACKTRACE.
-
 	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
 	  (the resulting kernel does not boot).
 
@@ -70,11 +77,15 @@ config KASAN_SW_TAGS
 	bool "Software tag-based mode"
 	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
 	select SLUB_DEBUG if SLUB
+	select CONSTRUCTORS
 	help
 	  Enables software tag-based KASAN mode.
 
-	  This mode requires Top Byte Ignore support by the CPU and therefore
-	  is only supported for arm64. This mode requires Clang.
+	  This mode require software memory tagging support in the form of
+	  HWASan-like compiler instrumentation.
+
+	  Currently this mode is only implemented for arm64 CPUs and relies on
+	  Top Byte Ignore. This mode requires Clang.
 
 	  This mode consumes about 1/16th of available memory at kernel start
 	  and introduces an overhead of ~20% for the rest of the allocations.
@@ -82,15 +93,27 @@ config KASAN_SW_TAGS
 	  casting and comparison, as it embeds tags into the top byte of each
 	  pointer.
 
-	  For better error detection enable CONFIG_STACKTRACE.
-
 	  Currently CONFIG_KASAN_SW_TAGS doesn't work with CONFIG_DEBUG_SLAB
 	  (the resulting kernel does not boot).
 
+config KASAN_HW_TAGS
+	bool "Hardware tag-based mode"
+	depends on HAVE_ARCH_KASAN_HW_TAGS
+	depends on SLUB
+	help
+	  Enables hardware tag-based KASAN mode.
+
+	  This mode requires hardware memory tagging support, and can be used
+	  by any architecture that provides it.
+
+	  Currently this mode is only implemented for arm64 CPUs starting from
+	  ARMv8.5 and relies on Memory Tagging Extension and Top Byte Ignore.
+
 endchoice
 
 choice
 	prompt "Instrumentation type"
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	default KASAN_OUTLINE
 
 config KASAN_OUTLINE
@@ -114,6 +137,7 @@ endchoice
 
 config KASAN_STACK_ENABLE
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	help
 	  The LLVM stack address sanitizer has a know problem that
 	  causes excessive stack usage in a lot of functions, see
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9fd49bf636f1f9be56cf400c9ec8afc9b5bc2cfa.1604333009.git.andreyknvl%40google.com.
