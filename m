Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEEBSP6AKGQE4QYNVTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 800DD28C311
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:46:09 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id r10sf13499511ilq.6
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:46:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535568; cv=pass;
        d=google.com; s=arc-20160816;
        b=0g4x1Wav08LCOjIUFBs9X+diEO7TwSf5B6c6B/wbh8O7N1tAKSboB13apFZxBVUqOF
         eYbOVxiYwARfxjX458PLz2BZLyYSS/UXI2ElcuCPksMDlPyDGg9BdAPYifa1OAVryHzH
         YFqGZ6/pkUsE+jGc7B+SojtRaTDpMByKtgxplWgshwYpgcOmAA8gshWPrAyQ3IixJi9m
         6hfprYDN1/R1UDmRAsjM2BGNP9q7i+RSeK8V5F0RInELlGXr8Ovoac/Fo9AByROaVD/V
         QsAKk49gqZjDGFHf7Jy8ucM4cb84aQtpMElH3ur8zmxlwhYm8ap2P2o5pe/bobzItM2R
         SLDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Ue+QpBfUazoVClWCfZSpfAHwoelPjNdK/tDSeScXRoI=;
        b=rb+nvjGzlwpKz7yJ2eeXxpJj2Ea3783lB68aLmz2bbLzPKtQlDg0Z4h59uv1Qdm1+M
         ks5UlQSLpWfcVuC+OzwxW2BKNBxl2oRyCvZ2u+eaj8zzF2SRL5CkTwlMA5Hs7yAL5K1C
         AR/sJS3uyXxB59cNGjzoXHls5ENDOihN/VoCQjIwJWRrIMt+uhfN/k9zsYvXIcQ9rta0
         8IUWcL8YoCdE9Hh+2g7zt8LcXTJIlMlhTeCivktiFNcNvqCSplFHA0otEbWqjB6oIYyZ
         fTjAcPYoHqByOLAx6L+iuJCdjVXMU8fU3oa6fB/6CeJAhntVC6cLlq/4YHubFeP3mcaT
         yt3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="FuUr3H/y";
       spf=pass (google.com: domain of 3j8cexwokcsycpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3j8CEXwoKCSYCPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Ue+QpBfUazoVClWCfZSpfAHwoelPjNdK/tDSeScXRoI=;
        b=nCLDN8zzYUmGg3yAOMFHhTfYQC5xhXjGM9h3hY7koYoKSJhzL7Z0VN8mlMpwOJkyj8
         c5V/nsK1CTRtFZnikWkjSg78b9+HkUwhHqAI1N+B7h0OCAJi38f67GyHdkE1dOOcZQRy
         NmL++Ls1p3AkkIOSF9pyxSyw/v6wQ8epOmirI2+IYiLtcPQoxqt2JLOgADQVy8aD9heg
         g9gUaZ5oWZMQCbl+1L5SgqsEcc/ofo+3dUzFgvP4YE4yFGJyKRjWfJkLsRf9az5dpW5v
         71mnfi+hQdHeGMIijcryTimqheyEE5rhFdXgvCdwKO88FIQpXJd+9wdHgKu2C0+lRvJW
         /vuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ue+QpBfUazoVClWCfZSpfAHwoelPjNdK/tDSeScXRoI=;
        b=sWuMN8UQ/UY1Bzn9Uo6TgJ0Bu7lG6/7KxqZVve8OxnOcjNYRGBwbZ8tUZkVHf6J+Dw
         UzoToSTR10MtsgiSShohzQXaKZCLxBxv8i26Sy/cYMq34jqpmNv71NzcBJE98WzLbP4R
         fi9i0FRrpTQHVSQMNaXldZVKT/jwkz+XPpN2w/qeR4+8xbJHcH0AbmqsOXJmkGZCXLmJ
         2wkdnG6L7mYKhJdUbbrTXqGmUNCAtmo1fQ7EXCGKqiidyxp53oWacqEHFx2NED+SfN79
         kjm7m2Vrwlw4XUl+pxG8vJLLbdIUQlF+uTLn4OqCCOQb6Q7xtD8Y/3jNItzo4nsPLkSc
         GztA==
X-Gm-Message-State: AOAM5319Iyw031faTd80BGioJDzDbuvjCEBC33Hax3bP3lAWe2iMYyib
	yzjsk5pxTUBuzqu8TNNUDzM=
X-Google-Smtp-Source: ABdhPJw2T6O7Q7ftjUyFSRCWERqxpywtd/gy7MOFpE9F+ZxGR+giDQLcaR60TJjNRN9yKqjdIPuJ3g==
X-Received: by 2002:a5e:d606:: with SMTP id w6mr18026775iom.67.1602535568392;
        Mon, 12 Oct 2020 13:46:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:14c7:: with SMTP id l7ls347645jak.0.gmail; Mon, 12
 Oct 2020 13:46:08 -0700 (PDT)
X-Received: by 2002:a05:6638:446:: with SMTP id r6mr15951926jap.60.1602535567971;
        Mon, 12 Oct 2020 13:46:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535567; cv=none;
        d=google.com; s=arc-20160816;
        b=gj9/TgV5Ji4cQRKjGQk9xmU5w0e/g5LPuDC7d8Q19zhtMh6Ucj94Es8WAlApHGFtCD
         SYJxPQdK6t7u6sZrCXU+4JBpJbeKCUTID4I7rA4/PtVcdrpKHhTJKfEj4FoCfdJftHGN
         6RyIuyhHebuvrBy6ZgoghOtjwg9JG4YcjRX5OsI4CsjlCg1hRBji8K1qICXIVxreyQKv
         XK2lQDjKVbpD/ZzSWqiJrNToi0DbkWnl3o4lLyemqW6jSZcD+tZozT5G/aowqNrgFGC2
         7U/6a5GwiDulmdkhT4pPdhE7si7vXEwFEvilu5Xt5tuDB1PqMndfpMI62dbYOu4VNjoG
         ZmRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=2Od/eV9S7z5C6jFMSAsqPcfiVzGh9kn75oygOkKJsEg=;
        b=E0Hs3e1YbfB9H1oyFKnio4KRUYY0FS56AUUccgkexi5Rx6gB8xF+okeXc8BU+0/PmR
         D88Oz1vgUzhxsCrb5thNykfyLDFBcJmldj/ImTytCaQPjfoYjpHliY8KnO/CQuXoFgVA
         EkUpWoMhDrdca1L9NnB6FpHmm0rWSGFf4O6CLpedwU0eHDG+/qBsYRymq6+u+SlAF1Ib
         UdOatB+Qi2cPc+DCMgNdr09kAnDvR4cu3KPsd00MrlGi4VOW5Sy9CMkfQ+ek8WozoRA3
         hE7IBpYPk7atQP0KMYHO+uYt080zI34XMSn32Ww4Fe+MR0lUoMOCWqITxzkqBhs93Ecm
         v9YA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="FuUr3H/y";
       spf=pass (google.com: domain of 3j8cexwokcsycpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3j8CEXwoKCSYCPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id b12si197778ile.3.2020.10.12.13.46.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:46:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3j8cexwokcsycpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id d5so12689803qkg.16
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:46:07 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:bb83:: with SMTP id
 i3mr27832276qvg.15.1602535567276; Mon, 12 Oct 2020 13:46:07 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:37 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <60e2934f57d1bd6fecc6b28b65c3a6968d101ec2.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 31/40] kasan: introduce CONFIG_KASAN_HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b="FuUr3H/y";       spf=pass
 (google.com: domain of 3j8cexwokcsycpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3j8CEXwoKCSYCPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
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
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I246c2def9fffa6563278db1bddfbe742ca7bdefe
---
 lib/Kconfig.kasan | 56 +++++++++++++++++++++++++++++++++--------------
 1 file changed, 39 insertions(+), 17 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index f73d5979575a..516d3a24f7d7 100644
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
@@ -20,10 +23,11 @@ config CC_HAS_WORKING_NOSANITIZE_ADDRESS
 
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
 	select CONSTRUCTORS
 	select STACKDEPOT
 	help
@@ -37,13 +41,18 @@ choice
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
@@ -61,8 +70,6 @@ config KASAN_GENERIC
 	  and introduces an overhead of ~x1.5 for the rest of the allocations.
 	  The performance slowdown is ~x3.
 
-	  For better error detection enable CONFIG_STACKTRACE.
-
 	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
 	  (the resulting kernel does not boot).
 
@@ -73,9 +80,11 @@ config KASAN_SW_TAGS
 	help
 	  Enables software tag-based KASAN mode.
 
-	  This mode requires Top Byte Ignore support by the CPU and therefore
-	  is only supported for arm64. This mode requires Clang version 7.0.0
-	  or later.
+	  This mode require software memory tagging support in the form of
+	  HWASan-like compiler instrumentation.
+
+	  Currently this mode is only implemented for arm64 CPUs and relies on
+	  Top Byte Ignore. This mode requires Clang version 7.0.0 or later.
 
 	  This mode consumes about 1/16th of available memory at kernel start
 	  and introduces an overhead of ~20% for the rest of the allocations.
@@ -83,15 +92,27 @@ config KASAN_SW_TAGS
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
@@ -115,6 +136,7 @@ endchoice
 
 config KASAN_STACK_ENABLE
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	help
 	  The LLVM stack address sanitizer has a know problem that
 	  causes excessive stack usage in a lot of functions, see
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/60e2934f57d1bd6fecc6b28b65c3a6968d101ec2.1602535397.git.andreyknvl%40google.com.
