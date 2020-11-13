Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZ4LXT6QKGQEF3UHLRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E6642B2819
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:12 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id n16sf5508064edw.19
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305832; cv=pass;
        d=google.com; s=arc-20160816;
        b=S+auDWSl/gCKtDTjkspLLtWhVkDLPf6rmR2z5oemMKwJ388FtixSo+obc6+zo4+POC
         lFAzcUQrKi8H9vG/0zhZ8/GceitjpW76BzsmTX29r8+IwfF1Q1oXIXKbRPRu+Ji2igrq
         5H7kRsn+7/x8u/8jm8z9QgfoJkUB46hioArT4LTC1SgfElJt9b59QdVWS45mOMzoIkmJ
         MwLr8SPJckPj03LWDfCrO22n4MucB2d6iRUIxWlO3ThZy0jNoSuJEKBJITYrT9PeGQLO
         pADnn4vOtDL0rYbeWUdVNF4VeAetTJ6ZSUKTiKjZTGSz1WavRWTXrR3hpDTq5mawxTmw
         KNGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ymKazf6SAgTnGIxFirz/lB3+/Nuul5+iTGjL/vM5hbY=;
        b=RTzg3rIZ5kXSnBdXTJy4QURasXNnFVgME6meC4/9FME4MjRa0q3YYl3o5PFbW2hASO
         KhHQzZ2BtytgZPf1Wea/7l7bWc4KmntfIC+IB1fKt0VahrLQ8ahYpAxvtYxYJyJvhZXj
         GUmW9lxHF9wQfWtdbbDyOxINhZGO5dCs1AsNGR5TV8SHYFz8n8UmZ4kA4mkI7ICqaGk5
         hmQypBtMO93HpYIepAsjKNVjui2MlOr0e0HmaUIQDHzbKDHfnHbEpP8ITCetuWhIB9jX
         6OSTm5pKRB1cTtWJZXsOnx/jmCZDoc595U3iCCWqg0GjbR6dl1XOuVtnOj9U2RqOhWWN
         PBnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AitFtvjP;
       spf=pass (google.com: domain of 35gwvxwokcbereuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35gWvXwoKCbEReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ymKazf6SAgTnGIxFirz/lB3+/Nuul5+iTGjL/vM5hbY=;
        b=amHPHyBUqICyFWkZUCMML7OeNV8lRHA+EWLzwwCJSRqX1VJSp1+vOK6upN2MUV76M1
         EpvEzTS1SOykq1DuzrvYn/fP8yhOHRu0V34V3Yj1yc1fnwOZmTwN1ELH9owakjN+IF/L
         jKU9O6wXFinKZp3yoABkZrXnyQrlu9q8vDofv9VtFol1eVGmKq2ZMfDBTY8k4Z0kgTkc
         3rBkBDeE3E1CsWr/054Xz6w1CpVgaxuNgKVLJ/hYCZCM8vkCiKeypYmyMZQGxYCcZyza
         c/XhgGwrIL+VRGjVWpJqgPlM465kOv/vmcUTcyWoFvIcIG1XqdDTQjlYQ2D9Bq8bAtek
         +KEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ymKazf6SAgTnGIxFirz/lB3+/Nuul5+iTGjL/vM5hbY=;
        b=UEP9cG1bWssG+SFAyiYM34tDMuzbAEsrS2HVTeDIiYumu5tErfFOmX5iH1IgIIsb8y
         VGqmIAK3nD/4eIJILpz/o4wglvbLrn4I2paTYhOXb8LoHA1Wgh6JWYqOsarUZ110iC5e
         3zoRdHYjIcwjP6O+WSL4wv15WvYofwfC0VbAOdBTvAse2EvWv3Zsvt5BJFfJmBhfLIQn
         8G5XkDT5w4DeNoTGoDZ730R6wv3DbJ7Vt3tdeysDTz3ZglnkMmsk1GYsFGbeqtPNQaPv
         nhQ3Ygjsiu6Z0drpLZwdGf0SvB6QUYVn9JPrPRGdskqhKG+h4jS74MgpbAO73lvI19p+
         zLKQ==
X-Gm-Message-State: AOAM532ZOwCupuCak+zTgD8g03RJUTof4TvTLmPyRKN1G8Uaj38yTldQ
	w2Gemh5lE7E/PwRVC0WhXiw=
X-Google-Smtp-Source: ABdhPJzYfrJVcZZdQhlzDA9fee6nXoT7CW5ND7YbxtWpaUFlzktuVi2B4gfeM/y+nperhAYUgJNxgQ==
X-Received: by 2002:aa7:cc0e:: with SMTP id q14mr4624515edt.326.1605305832084;
        Fri, 13 Nov 2020 14:17:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:417:: with SMTP id d23ls442241eja.7.gmail; Fri, 13
 Nov 2020 14:17:11 -0800 (PST)
X-Received: by 2002:a17:906:aacb:: with SMTP id kt11mr4471423ejb.12.1605305831088;
        Fri, 13 Nov 2020 14:17:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305831; cv=none;
        d=google.com; s=arc-20160816;
        b=J0nVlmcPJIxQOMP1ZEyV/eh1Qttem27bnKI28ChcQZzH9HsEsn2l/TSTmlofTy2cSM
         +V2WzL341U4YUBgho+l/J7ShobWDvoEhUK61pdAaCNAuiBE6VT7ZnTphXnb+9+Dg/REn
         HfanIArfeVy8x181ziXFiSGieEthOJrVC6IdeMr8csP0ieKJX12GqzB1iKM+92/+y1kL
         nttg1WY7TPS2v/uAuC/KgLu9APPy0codHa64lqhukkZWZ1pl2csG1RFcCOJXPUIDlR4p
         Kd8D3y6t2gnxrVGpGio3jzFP+wY9CyCqsDPrnq1Rax39w0z0WMe4YLoBN6PNAtO6Soek
         mClA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=4rzWjrKiYZNXmMUdZmlcBaQ0UpVVJfESdD9t64fiN78=;
        b=Y2AD0z9B12Go6/3/IWO7MR21PvWC7DgGj0phNdwxhFBiyA03HHmmyntBx1DEw29ibw
         hkJ/UnBNDsZvStSNMjmho+dbyLvWOcJuh8AHUDW+mysFb233qb6MMtwFwL5KTDzvJlZe
         bxAv4t/1sPciW+L8Bv9TPMS3idJbHbcGSGg+sLbLsA9z2vSGWYeS7tRQnIRd9yECpOvw
         q+8kcZpoLzlsPmhe6CpLEuAkjZh6K/VCG9MU4BGV5pFzD3v4thneVFNQ8oF2Qz+4II8A
         Qh2nIpwk4nMEGAsXIN4PiaPQR6+2GYB2kL+TABHgl92hoXTyHWffSh9oYVDkdkiy6Lj3
         ssHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AitFtvjP;
       spf=pass (google.com: domain of 35gwvxwokcbereuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35gWvXwoKCbEReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id l11si314289edi.3.2020.11.13.14.17.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:11 -0800 (PST)
Received-SPF: pass (google.com: domain of 35gwvxwokcbereuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id y26so3997661wmj.7
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:11 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:964d:: with SMTP id
 y74mr4390904wmd.129.1605305830806; Fri, 13 Nov 2020 14:17:10 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:51 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <da7fc94554c52c63f957d82e46c5bc8a718b2b96.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 23/42] kasan: introduce CONFIG_KASAN_HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AitFtvjP;       spf=pass
 (google.com: domain of 35gwvxwokcbereuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35gWvXwoKCbEReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
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
 lib/Kconfig.kasan | 61 ++++++++++++++++++++++++++++++++++-------------
 1 file changed, 44 insertions(+), 17 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index c0e9e7874122..f5fa4ba126bf 100644
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
@@ -15,16 +18,19 @@ config CC_HAS_KASAN_GENERIC
 config CC_HAS_KASAN_SW_TAGS
 	def_bool $(cc-option, -fsanitize=kernel-hwaddress)
 
+# This option is only required for software KASAN modes.
+# Old GCC versions don't have proper support for no_sanitize_address.
+# See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=89124 for details.
 config CC_HAS_WORKING_NOSANITIZE_ADDRESS
 	def_bool !CC_IS_GCC || GCC_VERSION >= 80300
 
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
@@ -37,18 +43,24 @@ choice
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
 
@@ -61,8 +73,6 @@ config KASAN_GENERIC
 	  and introduces an overhead of ~x1.5 for the rest of the allocations.
 	  The performance slowdown is ~x3.
 
-	  For better error detection enable CONFIG_STACKTRACE.
-
 	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
 	  (the resulting kernel does not boot).
 
@@ -70,11 +80,15 @@ config KASAN_SW_TAGS
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
@@ -82,15 +96,27 @@ config KASAN_SW_TAGS
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
@@ -114,6 +140,7 @@ endchoice
 
 config KASAN_STACK_ENABLE
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	help
 	  The LLVM stack address sanitizer has a know problem that
 	  causes excessive stack usage in a lot of functions, see
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/da7fc94554c52c63f957d82e46c5bc8a718b2b96.1605305705.git.andreyknvl%40google.com.
