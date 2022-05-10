Return-Path: <kasan-dev+bncBAABBMN65KJQMGQEZ24FARY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 28C46522250
	for <lists+kasan-dev@lfdr.de>; Tue, 10 May 2022 19:21:54 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id d28-20020adf9b9c000000b0020ad4a50e14sf7253749wrc.3
        for <lists+kasan-dev@lfdr.de>; Tue, 10 May 2022 10:21:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652203313; cv=pass;
        d=google.com; s=arc-20160816;
        b=S8zO6dOkyWPKPUxQfC2FBtSOZHA31oLG+Uq5VgkAVSnZfFJD06RhYAHP0iKuK+eDgL
         TNwvxsevTc+QI6Hjg689AXCDVb7j0JAE+xeZzgQWq2ZnLy7l0+LJmnPKOgLJYzpXZadf
         y55ajajGIkqVep2VpWRjDgFU7qk22wpP69gKNd4ns/mqMrVz9XW0DzkBgieMmTtwzkG+
         uNhx36xtdGU702bqmwbXnx2vRZn96hGN/U9xM9f/L9RwKq0FseyEAmp7b0G5PMxnRLtg
         0dvgRVGkLuz5aO8AZNFGF2xVpVidrNPH/7WHOweVQrIJWsCQ1zSqkm/qM0sgcQRFIaKQ
         CuqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JpSi7k3ClL6Z0MZxLHy4NPIocHSP7SvaKXyxHDqnL9g=;
        b=q7yPVgwY79uA5yZR+F2F9CFZyuMZsxfX0lDVrHYES0jerh0vDqKjjn0FoX3WcJcC+d
         BC/3TFG9Ye9lnsneFqCrQICaG0/TOL73mWOdaN1kWmwS7WM/rTQ4VkeZu1m7+WYBGfN1
         Wvb+VQzgcrRHd4vN90HJ3vgiJT6oe3i751YHuwqoh1EK+So4LD0TR9sTyA1ZmgGmxO7n
         5kFCVTZcH0CWwBtrchpT5nKV09OVI9wxqWNVEJuTQc0/jIObxb/gaieSe5TZjOD0LXAs
         fEDPE5Ejk1k+9Y/GcwTFQmzcumTvufr06E3cETzryabBgwX+q4m4r4sDlF4nctxj+23K
         GE8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Sc9ixXYn;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JpSi7k3ClL6Z0MZxLHy4NPIocHSP7SvaKXyxHDqnL9g=;
        b=GoSwgsFYwUn/i3JyUih5QM/qCc5BYZn9Px8T36Yq2LjiwFgM0n81mFLhCqiNAlg4fy
         vjffi/5i+LpdkM0P7JFv2GzfyWYeiQLfBrEiqJTSOK5pkS3TG+aqf3rrIChy3g1zYwqg
         dqKh/7U24LzEg91VTipY0/tlAblWw/OXzEDn0Iu7B+Zb1Jw1/8ret5kOlchp6Uhj4rJV
         44vOdzKKXW5qLQQekeKvV2hT/uSBVQ2ZtAgynLdowLBtKEAuPES1iIEUUnUrmD6o3VqB
         Jch17J6pVVzN8fQ6xe/abc5X2IbC8kk8hfhHS5a6SLGuS2PAF1vNW17a2e67JpUoOQ8o
         fCKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JpSi7k3ClL6Z0MZxLHy4NPIocHSP7SvaKXyxHDqnL9g=;
        b=MvvdQ8q8mMUhTcr3cG3BLSnl8A53Aq8ySXsmWJba5iGm7rvv8/low2lg+fVdM5QbVQ
         SZU5bIcDiec91VZV0JWbed6MRjoJ+cLmfeG4Iah7Tf5X0DUkFZZG3abUqDcj9BiKB7xp
         mFbOv2Km9/omIe8FTiQkegLtNToXfWMzT9ghOS8xr3ImAbjuWrhyRQFAIpwfXwGR8PHK
         /8yj12073vl/Nbv/5IfeH0TWTm0zjo/1lx3jO8y5fBX8WgVGEzFKbO6d+FOoUA7Hz6rD
         0oeeqJqK9jQcmgYU30crfNV5p5VJ10Ke4uRaP+vyFvh8Uz6VJLa24WyIbpOlPu8TZeK3
         26Dg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533J+V0Z5vsF1WcqsJci/oK4A9uxEWTBxld51YxbeNL3O8PNoMom
	2bebBa8whLG26mGfBq/ElBc=
X-Google-Smtp-Source: ABdhPJxfjHX31u2JNoTk2w9D7DqgSE6MqOBvHbonlITLwcEPrLcU3AnTNAMfnSF8i5wPPwVS9ZHi9A==
X-Received: by 2002:a05:600c:1c97:b0:394:7a2e:a83c with SMTP id k23-20020a05600c1c9700b003947a2ea83cmr997715wms.175.1652203313571;
        Tue, 10 May 2022 10:21:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6d84:0:b0:20c:7b09:42a4 with SMTP id l4-20020a5d6d84000000b0020c7b0942a4ls3486507wrs.2.gmail;
 Tue, 10 May 2022 10:21:52 -0700 (PDT)
X-Received: by 2002:a05:6000:168a:b0:20c:5bed:1c37 with SMTP id y10-20020a056000168a00b0020c5bed1c37mr19692840wrd.684.1652203312822;
        Tue, 10 May 2022 10:21:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652203312; cv=none;
        d=google.com; s=arc-20160816;
        b=rfdhpmeNWfq+JuQ0zsxJ4hQ+CUWCvbnBZvdZTLYNeX6EjEeJt0roRsTIUMMPcZyuS3
         V8tyXqiZVhNASdA2vg6+lYarJxPzogkmhhCRoZAGQi2AwMVahNSv57U9m6nTNySILhkK
         o0slul8qxtLUsPJeuy38JaDAWpuz9wixDJG84XO7sNBr1DyTaug0QeUyTzaOa1G0/e6E
         PIsUj+/w64gf3WTqKpu4xcF3ghOkjcgbjX/7BCoda+iLTP3wGsVkY+0csT445jl1Nef9
         BAoDMRURHscJo3Bw2/IMECi53iWuM3Nc8lmZMyJY18MSvc66O76pxtW2jNVZ0X1FfQwa
         By8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9BnUX9L7fFC6FZQH+Z8kfV4MrXVz/gU8TaLzj3GzwfE=;
        b=CQ8yQlzNOXpLIXAv0OEHAdIHc6P9vjy2wrMb77sGCSf4LO0DCUNrwAuZIeose5umjK
         lbe4hpzZmlLxgmiajDHrmRKGZG9Cp5GWYahwhvbterMKSTI8RqKhkPLO+c3J/f0k5kNm
         +IV68tuvRgaEDAmNGip1M8WBCCRn8wwJWlefvyiu8J0ubNPJ5nKovgUIXUc8R6+0qjVM
         RqzHhH2Ju2lg5ItSHNT3PlWuSGN6ddaB9g0RCCOCHgQ9NHx/eZOb/yFhsyPrjIs3q5rM
         0ev3orACQ1GbvqmiixrgL4W3IX6l2Qcam5QZiRFXsm851GwphyO5GfppLeEwInoXKo4p
         MfTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Sc9ixXYn;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id c2-20020a05600c0a4200b00393faebeaa1si354639wmq.4.2022.05.10.10.21.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 10 May 2022 10:21:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 3/3] kasan: clean-up kconfig options descriptions
Date: Tue, 10 May 2022 19:21:48 +0200
Message-Id: <c160840dd9e4b1ad5529ecfdb0bba35d9a14d826.1652203271.git.andreyknvl@google.com>
In-Reply-To: <896b2d914d6b50d677fd7b38f76967cc705c01ba.1652203271.git.andreyknvl@google.com>
References: <896b2d914d6b50d677fd7b38f76967cc705c01ba.1652203271.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Sc9ixXYn;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Various readability clean-ups of KASAN Kconfig options.

No functional changes.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/Kconfig.kasan | 168 ++++++++++++++++++++++------------------------
 1 file changed, 82 insertions(+), 86 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 1f3e620188a2..f0973da583e0 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -1,4 +1,5 @@
 # SPDX-License-Identifier: GPL-2.0-only
+
 # This config refers to the generic KASAN mode.
 config HAVE_ARCH_KASAN
 	bool
@@ -15,9 +16,8 @@ config HAVE_ARCH_KASAN_VMALLOC
 config ARCH_DISABLE_KASAN_INLINE
 	bool
 	help
-	  An architecture might not support inline instrumentation.
-	  When this option is selected, inline and stack instrumentation are
-	  disabled.
+	  Disables both inline and stack instrumentation. Selected by
+	  architectures that do not support these instrumentation types.
 
 config CC_HAS_KASAN_GENERIC
 	def_bool $(cc-option, -fsanitize=kernel-address)
@@ -26,13 +26,13 @@ config CC_HAS_KASAN_SW_TAGS
 	def_bool $(cc-option, -fsanitize=kernel-hwaddress)
 
 # This option is only required for software KASAN modes.
-# Old GCC versions don't have proper support for no_sanitize_address.
+# Old GCC versions do not have proper support for no_sanitize_address.
 # See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=89124 for details.
 config CC_HAS_WORKING_NOSANITIZE_ADDRESS
 	def_bool !CC_IS_GCC || GCC_VERSION >= 80300
 
 menuconfig KASAN
-	bool "KASAN: runtime memory debugger"
+	bool "KASAN: dynamic memory safety error detector"
 	depends on (((HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
 		     (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)) && \
 		    CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
@@ -40,10 +40,13 @@ menuconfig KASAN
 	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	select STACKDEPOT_ALWAYS_INIT
 	help
-	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
-	  designed to find out-of-bounds accesses and use-after-free bugs.
+	  Enables KASAN (Kernel Address Sanitizer) - a dynamic memory safety
+	  error detector designed to find out-of-bounds and use-after-free bugs.
+
 	  See Documentation/dev-tools/kasan.rst for details.
 
+	  For better error reports, also enable CONFIG_STACKTRACE.
+
 if KASAN
 
 choice
@@ -51,75 +54,71 @@ choice
 	default KASAN_GENERIC
 	help
 	  KASAN has three modes:
-	  1. generic KASAN (similar to userspace ASan,
-	     x86_64/arm64/xtensa, enabled with CONFIG_KASAN_GENERIC),
-	  2. software tag-based KASAN (arm64 only, based on software
-	     memory tagging (similar to userspace HWASan), enabled with
-	     CONFIG_KASAN_SW_TAGS), and
-	  3. hardware tag-based KASAN (arm64 only, based on hardware
-	     memory tagging, enabled with CONFIG_KASAN_HW_TAGS).
 
-	  All KASAN modes are strictly debugging features.
+	  1. Generic KASAN (supported by many architectures, enabled with
+	     CONFIG_KASAN_GENERIC, similar to userspace ASan),
+	  2. Software Tag-Based KASAN (arm64 only, based on software memory
+	     tagging, enabled with CONFIG_KASAN_SW_TAGS, similar to userspace
+	     HWASan), and
+	  3. Hardware Tag-Based KASAN (arm64 only, based on hardware memory
+	     tagging, enabled with CONFIG_KASAN_HW_TAGS).
 
-	  For better error reports enable CONFIG_STACKTRACE.
+	  See Documentation/dev-tools/kasan.rst for details about each mode.
 
 config KASAN_GENERIC
-	bool "Generic mode"
+	bool "Generic KASAN"
 	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
 	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
 	select SLUB_DEBUG if SLUB
 	select CONSTRUCTORS
 	help
-	  Enables generic KASAN mode.
+	  Enables Generic KASAN.
 
-	  This mode is supported in both GCC and Clang. With GCC it requires
-	  version 8.3.0 or later. Any supported Clang version is compatible,
-	  but detection of out-of-bounds accesses for global variables is
-	  supported only since Clang 11.
+	  Requires GCC 8.3.0+ or Clang.
 
-	  This mode consumes about 1/8th of available memory at kernel start
-	  and introduces an overhead of ~x1.5 for the rest of the allocations.
+	  Consumes about 1/8th of available memory at kernel start and adds an
+	  overhead of ~50% for dynamic allocations.
 	  The performance slowdown is ~x3.
 
-	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
-	  (the resulting kernel does not boot).
+	  (Incompatible with CONFIG_DEBUG_SLAB: the kernel does not boot.)
 
 config KASAN_SW_TAGS
-	bool "Software tag-based mode"
+	bool "Software Tag-Based KASAN"
 	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
 	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
 	select SLUB_DEBUG if SLUB
 	select CONSTRUCTORS
 	help
-	  Enables software tag-based KASAN mode.
+	  Enables Software Tag-Based KASAN.
 
-	  This mode require software memory tagging support in the form of
-	  HWASan-like compiler instrumentation.
+	  Requires GCC 11+ or Clang.
 
-	  Currently this mode is only implemented for arm64 CPUs and relies on
-	  Top Byte Ignore. This mode requires Clang.
+	  Supported only on arm64 CPUs and relies on Top Byte Ignore.
 
-	  This mode consumes about 1/16th of available memory at kernel start
-	  and introduces an overhead of ~20% for the rest of the allocations.
-	  This mode may potentially introduce problems relating to pointer
-	  casting and comparison, as it embeds tags into the top byte of each
-	  pointer.
+	  Consumes about 1/16th of available memory at kernel start and
+	  add an overhead of ~20% for dynamic allocations.
 
-	  Currently CONFIG_KASAN_SW_TAGS doesn't work with CONFIG_DEBUG_SLAB
-	  (the resulting kernel does not boot).
+	  May potentially introduce problems related to pointer casting and
+	  comparison, as it embeds a tag into the top byte of each pointer.
+
+	  (Incompatible with CONFIG_DEBUG_SLAB: the kernel does not boot.)
 
 config KASAN_HW_TAGS
-	bool "Hardware tag-based mode"
+	bool "Hardware Tag-Based KASAN"
 	depends on HAVE_ARCH_KASAN_HW_TAGS
 	depends on SLUB
 	help
-	  Enables hardware tag-based KASAN mode.
+	  Enables Hardware Tag-Based KASAN.
+
+	  Requires GCC 10+ or Clang 12+.
 
-	  This mode requires hardware memory tagging support, and can be used
-	  by any architecture that provides it.
+	  Supported only on arm64 CPUs starting from ARMv8.5 and relies on
+	  Memory Tagging Extension and Top Byte Ignore.
 
-	  Currently this mode is only implemented for arm64 CPUs starting from
-	  ARMv8.5 and relies on Memory Tagging Extension and Top Byte Ignore.
+	  Consumes about 1/32nd of available memory.
+
+	  May potentially introduce problems related to pointer casting and
+	  comparison, as it embeds a tag into the top byte of each pointer.
 
 endchoice
 
@@ -131,83 +130,80 @@ choice
 config KASAN_OUTLINE
 	bool "Outline instrumentation"
 	help
-	  Before every memory access compiler insert function call
-	  __asan_load*/__asan_store*. These functions performs check
-	  of shadow memory. This is slower than inline instrumentation,
-	  however it doesn't bloat size of kernel's .text section so
-	  much as inline does.
+	  Makes the compiler insert function calls that check whether the memory
+	  is accessible before each memory access. Slower than KASAN_INLINE, but
+	  does not bloat the size of the kernel's .text section so much.
 
 config KASAN_INLINE
 	bool "Inline instrumentation"
 	depends on !ARCH_DISABLE_KASAN_INLINE
 	help
-	  Compiler directly inserts code checking shadow memory before
-	  memory accesses. This is faster than outline (in some workloads
-	  it gives about x2 boost over outline instrumentation), but
-	  make kernel's .text size much bigger.
+	  Makes the compiler directly insert memory accessibility checks before
+	  each memory access. Faster than KASAN_OUTLINE (gives ~x2 boost for
+	  some workloads), but makes the kernel's .text size much bigger.
 
 endchoice
 
 config KASAN_STACK
-	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
+	bool "Stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
 	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	depends on !ARCH_DISABLE_KASAN_INLINE
 	default y if CC_IS_GCC
 	help
-	  The LLVM stack address sanitizer has a know problem that
-	  causes excessive stack usage in a lot of functions, see
-	  https://bugs.llvm.org/show_bug.cgi?id=38809
-	  Disabling asan-stack makes it safe to run kernels build
-	  with clang-8 with KASAN enabled, though it loses some of
-	  the functionality.
-	  This feature is always disabled when compile-testing with clang
-	  to avoid cluttering the output in stack overflow warnings,
-	  but clang users can still enable it for builds without
-	  CONFIG_COMPILE_TEST.	On gcc it is assumed to always be safe
-	  to use and enabled by default.
-	  If the architecture disables inline instrumentation, stack
-	  instrumentation is also disabled as it adds inline-style
-	  instrumentation that is run unconditionally.
+	  Disables stack instrumentation and thus KASAN's ability to detect
+	  out-of-bounds bugs in stack variables.
+
+	  With Clang, stack instrumentation has a problem that causes excessive
+	  stack usage, see https://bugs.llvm.org/show_bug.cgi?id=38809. Thus,
+	  with Clang, this option is deemed unsafe.
+
+	  This option is always disabled when compile-testing with Clang to
+	  avoid cluttering the log with stack overflow warnings.
+
+	  With GCC, enabling stack instrumentation is assumed to be safe.
+
+	  If the architecture disables inline instrumentation via
+	  ARCH_DISABLE_KASAN_INLINE, stack instrumentation gets disabled
+	  as well, as it adds inline-style instrumentation that is run
+	  unconditionally.
 
 config KASAN_TAGS_IDENTIFY
-	bool "Enable memory corruption identification"
+	bool "Memory corruption type identification"
 	depends on KASAN_SW_TAGS || KASAN_HW_TAGS
 	help
-	  This option enables best-effort identification of bug type
-	  (use-after-free or out-of-bounds) at the cost of increased
-	  memory consumption.
+	  Enables best-effort identification of the bug types (use-after-free
+	  or out-of-bounds) at the cost of increased memory consumption.
+	  Only applicable for the tag-based KASAN modes.
 
 config KASAN_VMALLOC
 	bool "Check accesses to vmalloc allocations"
 	depends on HAVE_ARCH_KASAN_VMALLOC
 	help
-	  This mode makes KASAN check accesses to vmalloc allocations for
-	  validity.
+	  Makes KASAN check the validity of accesses to vmalloc allocations.
 
-	  With software KASAN modes, checking is done for all types of vmalloc
-	  allocations. Enabling this option leads to higher memory usage.
+	  With software KASAN modes, all types vmalloc allocations are
+	  checked. Enabling this option leads to higher memory usage.
 
-	  With hardware tag-based KASAN, only VM_ALLOC mappings are checked.
-	  There is no additional memory usage.
+	  With Hardware Tag-Based KASAN, only non-executable VM_ALLOC mappings
+	  are checked. There is no additional memory usage.
 
 config KASAN_KUNIT_TEST
 	tristate "KUnit-compatible tests of KASAN bug detection capabilities" if !KUNIT_ALL_TESTS
 	depends on KASAN && KUNIT
 	default KUNIT_ALL_TESTS
 	help
-	  This is a KUnit test suite doing various nasty things like
-	  out of bounds and use after free accesses. It is useful for testing
-	  kernel debugging features like KASAN.
+	  A KUnit-based KASAN test suite. Triggers different kinds of
+	  out-of-bounds and use-after-free accesses. Useful for testing whether
+	  KASAN can detect certain bug types.
 
 	  For more information on KUnit and unit tests in general, please refer
-	  to the KUnit documentation in Documentation/dev-tools/kunit.
+	  to the KUnit documentation in Documentation/dev-tools/kunit/.
 
 config KASAN_MODULE_TEST
 	tristate "KUnit-incompatible tests of KASAN bug detection capabilities"
 	depends on m && KASAN && !KASAN_HW_TAGS
 	help
-	  This is a part of the KASAN test suite that is incompatible with
-	  KUnit. Currently includes tests that do bad copy_from/to_user
-	  accesses.
+	  A part of the KASAN test suite that is not integrated with KUnit.
+	  Incompatible with Hardware Tag-Based KASAN.
 
 endif # KASAN
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c160840dd9e4b1ad5529ecfdb0bba35d9a14d826.1652203271.git.andreyknvl%40google.com.
