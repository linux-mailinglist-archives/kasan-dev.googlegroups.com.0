Return-Path: <kasan-dev+bncBAABB3OM4WJQMGQETXML2FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F8A05204F2
	for <lists+kasan-dev@lfdr.de>; Mon,  9 May 2022 21:07:26 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id i18-20020a1c5412000000b0039491a8298csf18017wmb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 09 May 2022 12:07:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652123246; cv=pass;
        d=google.com; s=arc-20160816;
        b=BUG6JI0+ZU3AuZH4bH1rBAxBqZ/CEjDknHwJlRY5njitTj1FEBJmxeXLHrcrdpClKD
         o2nwqt7EWSbHUzR9TGSRqcFUoDOWYs3awc6cPvNmlqHRh7oNsHuBDmH+LBM20KibmTIT
         r95uHZ5kAXvvImlMFEyKSNgj4Z8Y91AzGdB2rX4mwojVPCJbj1/c5bkGOsa5y4+vLSkL
         2+1VmeIpndNpjdvUPASs1SXJhX0OCSkUfZPwW7pjioM3lGY+zK1y6zLVKttnIYAxhSYz
         1LsIPPIpQdOEIilLZlk3+R/PwbjOoABSLpp/PGpVk0zPGiBDijYJSyjfpyQT2dy2TX8D
         IQaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=A9UnvAemh/bxEENXJ7rXyqPpmrAzZSmiNFqAeA5NxNE=;
        b=L6vNDcp9tmRNeVmO04ZXJF2bH5ZtTatYVTbWnbL8AgTacYRGoI0q6FJBTWI0LcNd0j
         LN7AGEhYRE2EEn0uubul5M7icNvn9yOBx5J47eLrsbviyb8Hq3IHOKyU8VomcYnKK6lh
         /a/yi0r77h2bxeQyA3V5EVDFTr2hnJiScGj4n0vgMxg6EjeCf5pARpM2ejOb7o77NTfv
         fWF2Jx3ce1IvFU0Tv1dKDshiDUDLeulu/gsmbcoJPaxdlyoZxQgeICdjfeoLYmgQE3pp
         pyp6v4sWQI+VfbRNp/P2+D2Q0OAR63pZ0E4r11aXEkhlluppafTVUd+oAnWEBMnhhDv2
         dOjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bftOT1Pv;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A9UnvAemh/bxEENXJ7rXyqPpmrAzZSmiNFqAeA5NxNE=;
        b=Ip4hQqQnqO4156WwLyRHwYuNoEAJyb1Un379dm8bk09SXKBzomXieoga9iS0/zZxEO
         ZtRX5tJWDtqW8W6KJBuP0WMu5b2mrvVcaRZTW/rm+c+PvugCL5lxUaTtTDk6pZlK7C/C
         Hkd5n4g/9X6FMUpVMT9QN/bx4G86knlBkyWAPmJRxbx7+5srVZCBfRr5z6GEDXvQLZu3
         4xGGgGblfcxVVwkD7v4KvZxGrA96I4atQ+YfKjCRaixAXbu1UglanvueA7yGWxpUc9OM
         l2eY/HHtyzROGLpOjv2B9SIzMrM2KFPgJpHN+iqOGVqvWNGkWdcBrF6VJhPmudzfif8l
         BJSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A9UnvAemh/bxEENXJ7rXyqPpmrAzZSmiNFqAeA5NxNE=;
        b=lF7gjBNmm9FX3m1X/aCky6+759uAM+ersQeqjzZnNqAVMg5O9LshnwxZkBqi9bfxBi
         YypTsmI3CoyDHuxT33/9JZD18Z66GOQimZof+uWZKvYe12p97YrTcL23BldWz+IOM1G0
         OAPo3BiElUlGg79FjPoHPr/q+R429mPPwJKjarPT4o516nmvzlT0VT1eTHTRBJwPFVD7
         sqk02u8hOp4nhPTSnY7bB2qDGr8rRoI4e5UEj1fPpV90Cq2eTwiM4n64btHVa96BMEfT
         tTPB2Djl5k8iUpEvtHAS9hC5+p+9eM7NRku/H2QHDFZRKRwMrDGvgcZQkzvkPSVghp4u
         tE4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531CCfH39ueOFOSQnFfQUi+Sn4ZXTYHe0vl9fH8I1ht5DclvVsJ3
	RSUWxrdZBwmml8xM00VDtc8=
X-Google-Smtp-Source: ABdhPJzGp3Ul2mW+RZga+8qM3vbmDWaHKJXQvZrkcLSyQDBLXodM/x6pRMYqVgfFwJQZ7Dy7LHFBbg==
X-Received: by 2002:a05:600c:601c:b0:394:9595:d7f7 with SMTP id az28-20020a05600c601c00b003949595d7f7mr4643921wmb.98.1652123245868;
        Mon, 09 May 2022 12:07:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:64ca:0:b0:20c:bb44:bd7 with SMTP id f10-20020a5d64ca000000b0020cbb440bd7ls1970385wri.0.gmail;
 Mon, 09 May 2022 12:07:25 -0700 (PDT)
X-Received: by 2002:a5d:63ce:0:b0:20a:da1f:aac5 with SMTP id c14-20020a5d63ce000000b0020ada1faac5mr14952803wrw.589.1652123245250;
        Mon, 09 May 2022 12:07:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652123245; cv=none;
        d=google.com; s=arc-20160816;
        b=Gw7c+s4tc19Eid8AFnbpL4vdYIV+Ibx5YvzetciZQoHiz7jW1W5sC8/oX7GbRkjwwh
         MERsWLylM619wRV51HRY9ma1GfMUcQL6nSPNwIIP+lQhrXwPXO7iRL/wNN+4A6vlZq+X
         JhquTlvrRVpvmkkh+4WSxgwv8t+ASz62uUvV/bnBDJvzxpOLTagQiGU5DJxvyIh4pLAh
         Vi3E+B0iVdNkXTduo7YCorV0fHhXRPsupPLmfMPOVwYjfXYybaJUcrv8DKWlGvIhX/F/
         tLqEPvYbNH+OZhV54HuhX6O1hdSmMLekWFilfd+kVLFUE1MAj9gbO0STSwI90ZqaSoN2
         AAzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BhK1H3z2+ketkqp1P4tC+AWEWt56i9Blt1MkSXijGcg=;
        b=a9nmB1mmizI1a9Y7UXhFS4fLBxPbDqgcRUIDh4qAeXldqs6PNTGuYjdczNHo3nxhz2
         6smmwnU4Ay1L9McZW9WVXNYXj8EFLyIK+FHv7NyQKCeb3xvzXKgK4+WFFwfi4hA0XF8c
         kklBdFwD6KiY0jgbID+5SCtTnCQZSRZd81LifEt+MOH9lg4qkaU/VjXMcPx+vd9lnIQc
         /zGZjgO4B0VcT2SrLcCP0MUbzyXxNpKcAREzlZ/kz0MwfZgUx2+4mksJgP/Y5i/16hik
         Cy6oIVaMNC4A0c6SF5U/alIvw+IW3FQZYkADv839ScLY5K484hOvpgJYr/Cab/TEnS9I
         ArVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bftOT1Pv;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id n14-20020a05600c500e00b0038e70fa4e56si29606wmr.3.2022.05.09.12.07.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 09 May 2022 12:07:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 3/3] kasan: clean-up kconfig options descriptions
Date: Mon,  9 May 2022 21:07:19 +0200
Message-Id: <47afaecec29221347bee49f58c258ac1ced3b429.1652123204.git.andreyknvl@google.com>
In-Reply-To: <5bd58ebebf066593ce0e1d265d60278b5f5a1874.1652123204.git.andreyknvl@google.com>
References: <5bd58ebebf066593ce0e1d265d60278b5f5a1874.1652123204.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=bftOT1Pv;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/47afaecec29221347bee49f58c258ac1ced3b429.1652123204.git.andreyknvl%40google.com.
