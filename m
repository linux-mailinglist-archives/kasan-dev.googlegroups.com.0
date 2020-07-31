Return-Path: <kasan-dev+bncBC6OLHHDVUOBBWWCR34QKGQEKSCM2FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id E14EB233E66
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 06:43:07 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id l18sf1301383qvq.16
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jul 2020 21:43:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596170587; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pd6tBGLv23Tomc/pE44x0fmYZS028bHbUivf4SKVAfHd8EpZy9xgmSLAmaZgfapcKJ
         HggWgJSwuRGFT+10/QnmYxB8gLY/HlF1sCDcRGR3dM+Q1ulFtY67wjRGuu/icT/pqALq
         0Mt/hByzIKaDAdw67CuMVTd70R/T/7B3/HMrlPyNavXKhxF881VQd2WpZPzGUbxlzrRZ
         ZbVA/lGT+ZrS4D2uWStr5Gp1V+0Z0U4bO6DYXzjP+NOo3XWHlMnsEem05wb66ufn1XQF
         6oHdMFtdG5UDa8X+30Waf9sV+so/Jswc/rpVtc/+iyYEpyavRI7YvJS195LQs2J+ZeVm
         XprA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=CGthzPKR8fuGbltImfHm7UIa9LKXyM5g+Gf02JfQOqw=;
        b=UnQi4SLtwC7M4dJpkI9CY5yBAOsOv6QeCF6ttdRjuqJmBvtdLh/0Nxua63C4xsvp+J
         uMeaDnHTnY/2CPDdUrNQPXQOpgXzn4P16ArjAXyxcMoCVG4gWLloKq55NKiGUSZhZ6Kw
         csn9Qs4jOZycouiB0j0AQleQKmC5Z5vdKsPxSrf6ectIgvK93tDxl6pwKDkO+Fs53WAq
         NbGh17oUtTDQyS8GE/XnFLNT4XOjCVRGSj7dgqnTElr6KHDqsiuUtMwLpJkYrcoWwHVY
         BK0/jdDr8u8DcBHEF9HHx+UWhXEz8TddDeq0vjVmLRtyLt1/dRXR6n1Zgks4zG7/ulcK
         y59A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F3Nhp2LS;
       spf=pass (google.com: domain of 3waejxwgkcsojgbojmucmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3WaEjXwgKCSoJGbOJMUcMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CGthzPKR8fuGbltImfHm7UIa9LKXyM5g+Gf02JfQOqw=;
        b=kZiqUIWl0Hc+hX1UgVnxTHQsxhv0jkP5LsP/6T75EdJ4GPk5TT1DHV39iI3QV6ZuJI
         IT+8x746KnPEbMLYsnuN5dXfB6tOX8PDWFTI37LiWm5kIBLvzQKY64vGrBMsPt82fV1C
         mZ/DEpNm4px1d3whgwCap5Cb37fOkxKueIqL68otWNL5pDlkccUX2oVf5UFQGGGd0OEA
         b1nU003LbhgEMWmP7R5WUZ2GQpqkoPjKvb8yom9gBK1/cI/OMUFvPc6J+RI7qc30WI5G
         BiMOU7lHcrzkkxnt9PcjKyr4RQKrQoQFiYLf0QD716SRD0UAZkZgC9u5kzymqcsxxIo+
         vyPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CGthzPKR8fuGbltImfHm7UIa9LKXyM5g+Gf02JfQOqw=;
        b=bDNclSveefas0cWS2+QJSogqk3TVS1g06SRT6wqRrnkV/jpivy6bmc9EF4A9cco16z
         KOsTLHO3tvTysPc94np+VIbv/oJvFnH0gMBWXSWUqHaQejtrvw/4nPV1wT2Mm5lrpZuC
         DXRpXPzrTzZNMHT/QvI5TubUgsjlwd+GJuFMMzj4NLgkpipqk08EnmZ1A1c84obzqenf
         8J9ucauWFDM6ZUPlNkuYeFcUX6DsDjYo0uy0XPOKuQ2+jxn3vKJdLs17AH9fJZ0ZyBVo
         Y+0UH6k3cr2iwLQ+9CPMCu9VXPDZuVB8Dfe4oiYTIdGnF9wUsaZPtB1aQoLYk487YUb0
         42Tg==
X-Gm-Message-State: AOAM530j5o4j3HJVn/CdBz736Lsj46wucMMN9U1vVuPfr5RNRRHdu058
	zfusStfDcMM8IF2FDct528w=
X-Google-Smtp-Source: ABdhPJydNCvwCTHY68kkxD4j2s/yCMK0oGl+haPrZsIYdfqTWzJhgZeFaNSVNd3xoN92k14Bcsu8UA==
X-Received: by 2002:a0c:b39b:: with SMTP id t27mr2387159qve.168.1596170586784;
        Thu, 30 Jul 2020 21:43:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:13c9:: with SMTP id g9ls1943087qkl.4.gmail; Thu, 30
 Jul 2020 21:43:06 -0700 (PDT)
X-Received: by 2002:a37:7706:: with SMTP id s6mr2495733qkc.164.1596170586385;
        Thu, 30 Jul 2020 21:43:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596170586; cv=none;
        d=google.com; s=arc-20160816;
        b=C8UKVydGstninhFu+n2NuUQJbqvar+IMPCTsK2MyDTZjv9cB5zo82AH6ALbyWvCVOt
         slAhAvmxKyEmSchf7xa73gr/YgElSOQ12ICUk4J52gGxPkR2oMJgGqaqoGhMLjWIipk7
         JxF8vFw7JcYHuNtQspqKgHFP+U+4qyqgsFi/E9FDV6TwmdRZzP8PMxnxkxIiHGeH9rJ/
         qOEnvAQQQqL3B3Q9gcr9leeSQNJbCIOqhKOY/gjC4iTkudrVB7r5y2wvHRwnj80daaJa
         PZ4M1hN11iK2ZtAJ9Jg52kjcowuYdWL3qJPT4NKbOdS1W7dato4RXpOy+x2Nb2JA5C6r
         1zJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=7dFgQHjt7Usp0rqVZL95+8EYF1jmm5C7PyiIaSPxU24=;
        b=Warv5onKmCiiliu6YuapFXNgzcdK6SvSsYD2jJgLE9tDXD2P6ILIUVnWKP+KTPkMQd
         EX2LU1EwV5f+sGm3ZK6Hgm9k66V78tpbjd12cCtb5FP2jlnFMuUw7T2eELOmpYFQZxDs
         PtqUkbP7xVzBpjZ3Oe6gkb5MDVp6mFbXE/YRpNzLGwXmUqYMxefxScRNVsjPVOCxW0pA
         uMJSd824k4yBtIf8+tQqcYYEN79CiNqt91LPh7F7xujc4dYJsH1TTgfor6zInFseHsX1
         fBPHOld23u0FHS1fP1IKPIwIVuKeB01zNvaLDQxCeg4YxHcRUjgPXzZveFEnwsem8mba
         rsZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F3Nhp2LS;
       spf=pass (google.com: domain of 3waejxwgkcsojgbojmucmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3WaEjXwgKCSoJGbOJMUcMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id e16si325441qto.5.2020.07.30.21.43.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jul 2020 21:43:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3waejxwgkcsojgbojmucmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id r9so20205396qtp.7
        for <kasan-dev@googlegroups.com>; Thu, 30 Jul 2020 21:43:06 -0700 (PDT)
X-Received: by 2002:a05:6214:554:: with SMTP id ci20mr2421931qvb.108.1596170585932;
 Thu, 30 Jul 2020 21:43:05 -0700 (PDT)
Date: Thu, 30 Jul 2020 21:42:40 -0700
In-Reply-To: <20200731044242.1323143-1-davidgow@google.com>
Message-Id: <20200731044242.1323143-4-davidgow@google.com>
Mime-Version: 1.0
References: <20200731044242.1323143-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v9 3/5] KASAN: Port KASAN Tests to KUnit
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=F3Nhp2LS;       spf=pass
 (google.com: domain of 3waejxwgkcsojgbojmucmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3WaEjXwgKCSoJGbOJMUcMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

From: Patricia Alfonso <trishalfonso@google.com>

Transfer all previous tests for KASAN to KUnit so they can be run
more easily. Using kunit_tool, developers can run these tests with their
other KUnit tests and see "pass" or "fail" with the appropriate KASAN
report instead of needing to parse each KASAN report to test KASAN
functionalities. All KASAN reports are still printed to dmesg.

Stack tests do not work properly when KASAN_STACK is enabled so
those tests use a check for "if IS_ENABLED(CONFIG_KASAN_STACK)" so they
only run if stack instrumentation is enabled. If KASAN_STACK is not
enabled, KUnit will print a statement to let the user know this test
was not run with KASAN_STACK enabled.

copy_user_test cannot be run in KUnit so there is a separate test file
for those tests, which can be run as before as a module.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
Signed-off-by: David Gow <davidgow@google.com>
Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
 lib/Kconfig.kasan |  22 +-
 lib/Makefile      |   7 +-
 lib/test_kasan.c  | 901 ----------------------------------------------
 3 files changed, 21 insertions(+), 909 deletions(-)
 delete mode 100644 lib/test_kasan.c

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 34b84bcbd3d9..a9f7451c541d 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -162,10 +162,22 @@ config KASAN_VMALLOC
 	  for KASAN to detect more sorts of errors (and to support vmapped
 	  stacks), but at the cost of higher memory usage.
 
-config TEST_KASAN
-	tristate "Module for testing KASAN for bug detection"
-	depends on m && KASAN
+config KASAN_KUNIT_TEST
+	tristate "KUnit-compatible tests of KASAN bug detection capabilities" if !KUNIT_ALL_TESTS
+	depends on KASAN && KUNIT
+	default KUNIT_ALL_TESTS
 	help
-	  This is a test module doing various nasty things like
-	  out of bounds accesses, use after free. It is useful for testing
+	  This is a KUnit test suite doing various nasty things like
+	  out of bounds and use after free accesses. It is useful for testing
 	  kernel debugging features like KASAN.
+
+	  For more information on KUnit and unit tests in general, please refer
+	  to the KUnit documentation in Documentation/dev-tools/kunit
+
+config TEST_KASAN_MODULE
+	tristate "KUnit-incompatible tests of KASAN bug detection capabilities"
+	depends on m && KASAN
+	help
+	  This is a part of the KASAN test suite that is incompatible with
+	  KUnit. Currently includes tests that do bad copy_from/to_user
+	  accesses.
diff --git a/lib/Makefile b/lib/Makefile
index b1c42c10073b..24a5c3cc7262 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -64,9 +64,10 @@ CFLAGS_test_bitops.o += -Werror
 obj-$(CONFIG_TEST_SYSCTL) += test_sysctl.o
 obj-$(CONFIG_TEST_HASH) += test_hash.o test_siphash.o
 obj-$(CONFIG_TEST_IDA) += test_ida.o
-obj-$(CONFIG_TEST_KASAN) += test_kasan.o
-CFLAGS_test_kasan.o += -fno-builtin
-CFLAGS_test_kasan.o += $(call cc-disable-warning, vla)
+obj-$(CONFIG_KASAN_KUNIT_TEST) += kasan_kunit.o
+CFLAGS_kasan_kunit.o += -fno-builtin
+CFLAGS_kasan_kunit.o += $(call cc-disable-warning, vla)
+obj-$(CONFIG_TEST_KASAN_MODULE) += test_kasan_module.o
 obj-$(CONFIG_TEST_UBSAN) += test_ubsan.o
 CFLAGS_test_ubsan.o += $(call cc-disable-warning, vla)
 UBSAN_SANITIZE_test_ubsan.o := y
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
deleted file mode 100644
index 842adcd30943..000000000000
--- a/lib/test_kasan.c
+++ /dev/null
@@ -1,901 +0,0 @@
-// SPDX-License-Identifier: GPL-2.0-only
-/*
- *
- * Copyright (c) 2014 Samsung Electronics Co., Ltd.
- * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
- */
-
-#define pr_fmt(fmt) "kasan test: %s " fmt, __func__
-
-#include <linux/bitops.h>
-#include <linux/delay.h>
-#include <linux/kasan.h>
-#include <linux/kernel.h>
-#include <linux/mm.h>
-#include <linux/mman.h>
-#include <linux/module.h>
-#include <linux/printk.h>
-#include <linux/slab.h>
-#include <linux/string.h>
-#include <linux/uaccess.h>
-#include <linux/io.h>
-#include <linux/vmalloc.h>
-
-#include <asm/page.h>
-
-#include <kunit/test.h>
-
-/*
- * We assign some test results to these globals to make sure the tests
- * are not eliminated as dead code.
- */
-
-void *kasan_ptr_result;
-int kasan_int_result;
-
-static struct kunit_resource resource;
-static struct kunit_kasan_expectation fail_data;
-static bool multishot;
-
-static int kasan_test_init(struct kunit *test)
-{
-	/*
-	 * Temporarily enable multi-shot mode and set panic_on_warn=0.
-	 * Otherwise, we'd only get a report for the first case.
-	 */
-	multishot = kasan_save_enable_multi_shot();
-
-	return 0;
-}
-
-static void kasan_test_exit(struct kunit *test)
-{
-	kasan_restore_multi_shot(multishot);
-}
-
-/**
- * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
- * not cause a KASAN error. This uses a KUnit resource named "kasan_data." Do
- * Do not use this name for a KUnit resource outside here.
- *
- */
-#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do { \
-	fail_data.report_expected = true; \
-	fail_data.report_found = false; \
-	kunit_add_named_resource(test, \
-				NULL, \
-				NULL, \
-				&resource, \
-				"kasan_data", &fail_data); \
-	condition; \
-	KUNIT_EXPECT_EQ(test, \
-			fail_data.report_expected, \
-			fail_data.report_found); \
-} while (0)
-
-
-
-/*
- * Note: test functions are marked noinline so that their names appear in
- * reports.
- */
-static noinline void __init kmalloc_oob_right(void)
-{
-	char *ptr;
-	size_t size = 123;
-
-	pr_info("out-of-bounds to right\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	ptr[size] = 'x';
-	kfree(ptr);
-}
-
-static noinline void __init kmalloc_oob_left(void)
-{
-	char *ptr;
-	size_t size = 15;
-
-	pr_info("out-of-bounds to left\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	*ptr = *(ptr - 1);
-	kfree(ptr);
-}
-
-static noinline void __init kmalloc_node_oob_right(void)
-{
-	char *ptr;
-	size_t size = 4096;
-
-	pr_info("kmalloc_node(): out-of-bounds to right\n");
-	ptr = kmalloc_node(size, GFP_KERNEL, 0);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	ptr[size] = 0;
-	kfree(ptr);
-}
-
-#ifdef CONFIG_SLUB
-static noinline void __init kmalloc_pagealloc_oob_right(void)
-{
-	char *ptr;
-	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
-
-	/* Allocate a chunk that does not fit into a SLUB cache to trigger
-	 * the page allocator fallback.
-	 */
-	pr_info("kmalloc pagealloc allocation: out-of-bounds to right\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	ptr[size] = 0;
-	kfree(ptr);
-}
-
-static noinline void __init kmalloc_pagealloc_uaf(void)
-{
-	char *ptr;
-	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
-
-	pr_info("kmalloc pagealloc allocation: use-after-free\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	kfree(ptr);
-	ptr[0] = 0;
-}
-
-static noinline void __init kmalloc_pagealloc_invalid_free(void)
-{
-	char *ptr;
-	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
-
-	pr_info("kmalloc pagealloc allocation: invalid-free\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	kfree(ptr + 1);
-}
-#endif
-
-static noinline void __init kmalloc_large_oob_right(void)
-{
-	char *ptr;
-	size_t size = KMALLOC_MAX_CACHE_SIZE - 256;
-	/* Allocate a chunk that is large enough, but still fits into a slab
-	 * and does not trigger the page allocator fallback in SLUB.
-	 */
-	pr_info("kmalloc large allocation: out-of-bounds to right\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	ptr[size] = 0;
-	kfree(ptr);
-}
-
-static noinline void __init kmalloc_oob_krealloc_more(void)
-{
-	char *ptr1, *ptr2;
-	size_t size1 = 17;
-	size_t size2 = 19;
-
-	pr_info("out-of-bounds after krealloc more\n");
-	ptr1 = kmalloc(size1, GFP_KERNEL);
-	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
-	if (!ptr1 || !ptr2) {
-		pr_err("Allocation failed\n");
-		kfree(ptr1);
-		kfree(ptr2);
-		return;
-	}
-
-	ptr2[size2] = 'x';
-	kfree(ptr2);
-}
-
-static noinline void __init kmalloc_oob_krealloc_less(void)
-{
-	char *ptr1, *ptr2;
-	size_t size1 = 17;
-	size_t size2 = 15;
-
-	pr_info("out-of-bounds after krealloc less\n");
-	ptr1 = kmalloc(size1, GFP_KERNEL);
-	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
-	if (!ptr1 || !ptr2) {
-		pr_err("Allocation failed\n");
-		kfree(ptr1);
-		return;
-	}
-	ptr2[size2] = 'x';
-	kfree(ptr2);
-}
-
-static noinline void __init kmalloc_oob_16(void)
-{
-	struct {
-		u64 words[2];
-	} *ptr1, *ptr2;
-
-	pr_info("kmalloc out-of-bounds for 16-bytes access\n");
-	ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
-	ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
-	if (!ptr1 || !ptr2) {
-		pr_err("Allocation failed\n");
-		kfree(ptr1);
-		kfree(ptr2);
-		return;
-	}
-	*ptr1 = *ptr2;
-	kfree(ptr1);
-	kfree(ptr2);
-}
-
-static noinline void __init kmalloc_oob_memset_2(void)
-{
-	char *ptr;
-	size_t size = 8;
-
-	pr_info("out-of-bounds in memset2\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	memset(ptr+7, 0, 2);
-	kfree(ptr);
-}
-
-static noinline void __init kmalloc_oob_memset_4(void)
-{
-	char *ptr;
-	size_t size = 8;
-
-	pr_info("out-of-bounds in memset4\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	memset(ptr+5, 0, 4);
-	kfree(ptr);
-}
-
-
-static noinline void __init kmalloc_oob_memset_8(void)
-{
-	char *ptr;
-	size_t size = 8;
-
-	pr_info("out-of-bounds in memset8\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	memset(ptr+1, 0, 8);
-	kfree(ptr);
-}
-
-static noinline void __init kmalloc_oob_memset_16(void)
-{
-	char *ptr;
-	size_t size = 16;
-
-	pr_info("out-of-bounds in memset16\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	memset(ptr+1, 0, 16);
-	kfree(ptr);
-}
-
-static noinline void __init kmalloc_oob_in_memset(void)
-{
-	char *ptr;
-	size_t size = 666;
-
-	pr_info("out-of-bounds in memset\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	memset(ptr, 0, size+5);
-	kfree(ptr);
-}
-
-static noinline void __init kmalloc_memmove_invalid_size(void)
-{
-	char *ptr;
-	size_t size = 64;
-	volatile size_t invalid_size = -2;
-
-	pr_info("invalid size in memmove\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	memset((char *)ptr, 0, 64);
-	memmove((char *)ptr, (char *)ptr + 4, invalid_size);
-	kfree(ptr);
-}
-
-static noinline void __init kmalloc_uaf(void)
-{
-	char *ptr;
-	size_t size = 10;
-
-	pr_info("use-after-free\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	kfree(ptr);
-	*(ptr + 8) = 'x';
-}
-
-static noinline void __init kmalloc_uaf_memset(void)
-{
-	char *ptr;
-	size_t size = 33;
-
-	pr_info("use-after-free in memset\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	kfree(ptr);
-	memset(ptr, 0, size);
-}
-
-static noinline void __init kmalloc_uaf2(void)
-{
-	char *ptr1, *ptr2;
-	size_t size = 43;
-
-	pr_info("use-after-free after another kmalloc\n");
-	ptr1 = kmalloc(size, GFP_KERNEL);
-	if (!ptr1) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	kfree(ptr1);
-	ptr2 = kmalloc(size, GFP_KERNEL);
-	if (!ptr2) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	ptr1[40] = 'x';
-	if (ptr1 == ptr2)
-		pr_err("Could not detect use-after-free: ptr1 == ptr2\n");
-	kfree(ptr2);
-}
-
-static noinline void __init kfree_via_page(void)
-{
-	char *ptr;
-	size_t size = 8;
-	struct page *page;
-	unsigned long offset;
-
-	pr_info("invalid-free false positive (via page)\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	page = virt_to_page(ptr);
-	offset = offset_in_page(ptr);
-	kfree(page_address(page) + offset);
-}
-
-static noinline void __init kfree_via_phys(void)
-{
-	char *ptr;
-	size_t size = 8;
-	phys_addr_t phys;
-
-	pr_info("invalid-free false positive (via phys)\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	phys = virt_to_phys(ptr);
-	kfree(phys_to_virt(phys));
-}
-
-static noinline void __init kmem_cache_oob(void)
-{
-	char *p;
-	size_t size = 200;
-	struct kmem_cache *cache = kmem_cache_create("test_cache",
-						size, 0,
-						0, NULL);
-	if (!cache) {
-		pr_err("Cache allocation failed\n");
-		return;
-	}
-	pr_info("out-of-bounds in kmem_cache_alloc\n");
-	p = kmem_cache_alloc(cache, GFP_KERNEL);
-	if (!p) {
-		pr_err("Allocation failed\n");
-		kmem_cache_destroy(cache);
-		return;
-	}
-
-	*p = p[size];
-	kmem_cache_free(cache, p);
-	kmem_cache_destroy(cache);
-}
-
-static noinline void __init memcg_accounted_kmem_cache(void)
-{
-	int i;
-	char *p;
-	size_t size = 200;
-	struct kmem_cache *cache;
-
-	cache = kmem_cache_create("test_cache", size, 0, SLAB_ACCOUNT, NULL);
-	if (!cache) {
-		pr_err("Cache allocation failed\n");
-		return;
-	}
-
-	pr_info("allocate memcg accounted object\n");
-	/*
-	 * Several allocations with a delay to allow for lazy per memcg kmem
-	 * cache creation.
-	 */
-	for (i = 0; i < 5; i++) {
-		p = kmem_cache_alloc(cache, GFP_KERNEL);
-		if (!p)
-			goto free_cache;
-
-		kmem_cache_free(cache, p);
-		msleep(100);
-	}
-
-free_cache:
-	kmem_cache_destroy(cache);
-}
-
-static char global_array[10];
-
-static noinline void __init kasan_global_oob(void)
-{
-	volatile int i = 3;
-	char *p = &global_array[ARRAY_SIZE(global_array) + i];
-
-	pr_info("out-of-bounds global variable\n");
-	*(volatile char *)p;
-}
-
-static noinline void __init kasan_stack_oob(void)
-{
-	char stack_array[10];
-	volatile int i = 0;
-	char *p = &stack_array[ARRAY_SIZE(stack_array) + i];
-
-	pr_info("out-of-bounds on stack\n");
-	*(volatile char *)p;
-}
-
-static noinline void __init ksize_unpoisons_memory(void)
-{
-	char *ptr;
-	size_t size = 123, real_size;
-
-	pr_info("ksize() unpoisons the whole allocated chunk\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-	real_size = ksize(ptr);
-	/* This access doesn't trigger an error. */
-	ptr[size] = 'x';
-	/* This one does. */
-	ptr[real_size] = 'y';
-	kfree(ptr);
-}
-
-static noinline void __init copy_user_test(void)
-{
-	char *kmem;
-	char __user *usermem;
-	size_t size = 10;
-	int unused;
-
-	kmem = kmalloc(size, GFP_KERNEL);
-	if (!kmem)
-		return;
-
-	usermem = (char __user *)vm_mmap(NULL, 0, PAGE_SIZE,
-			    PROT_READ | PROT_WRITE | PROT_EXEC,
-			    MAP_ANONYMOUS | MAP_PRIVATE, 0);
-	if (IS_ERR(usermem)) {
-		pr_err("Failed to allocate user memory\n");
-		kfree(kmem);
-		return;
-	}
-
-	pr_info("out-of-bounds in copy_from_user()\n");
-	unused = copy_from_user(kmem, usermem, size + 1);
-
-	pr_info("out-of-bounds in copy_to_user()\n");
-	unused = copy_to_user(usermem, kmem, size + 1);
-
-	pr_info("out-of-bounds in __copy_from_user()\n");
-	unused = __copy_from_user(kmem, usermem, size + 1);
-
-	pr_info("out-of-bounds in __copy_to_user()\n");
-	unused = __copy_to_user(usermem, kmem, size + 1);
-
-	pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
-	unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
-
-	pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
-	unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
-
-	pr_info("out-of-bounds in strncpy_from_user()\n");
-	unused = strncpy_from_user(kmem, usermem, size + 1);
-
-	vm_munmap((unsigned long)usermem, PAGE_SIZE);
-	kfree(kmem);
-}
-
-static noinline void __init kasan_alloca_oob_left(void)
-{
-	volatile int i = 10;
-	char alloca_array[i];
-	char *p = alloca_array - 1;
-
-	pr_info("out-of-bounds to left on alloca\n");
-	*(volatile char *)p;
-}
-
-static noinline void __init kasan_alloca_oob_right(void)
-{
-	volatile int i = 10;
-	char alloca_array[i];
-	char *p = alloca_array + i;
-
-	pr_info("out-of-bounds to right on alloca\n");
-	*(volatile char *)p;
-}
-
-static noinline void __init kmem_cache_double_free(void)
-{
-	char *p;
-	size_t size = 200;
-	struct kmem_cache *cache;
-
-	cache = kmem_cache_create("test_cache", size, 0, 0, NULL);
-	if (!cache) {
-		pr_err("Cache allocation failed\n");
-		return;
-	}
-	pr_info("double-free on heap object\n");
-	p = kmem_cache_alloc(cache, GFP_KERNEL);
-	if (!p) {
-		pr_err("Allocation failed\n");
-		kmem_cache_destroy(cache);
-		return;
-	}
-
-	kmem_cache_free(cache, p);
-	kmem_cache_free(cache, p);
-	kmem_cache_destroy(cache);
-}
-
-static noinline void __init kmem_cache_invalid_free(void)
-{
-	char *p;
-	size_t size = 200;
-	struct kmem_cache *cache;
-
-	cache = kmem_cache_create("test_cache", size, 0, SLAB_TYPESAFE_BY_RCU,
-				  NULL);
-	if (!cache) {
-		pr_err("Cache allocation failed\n");
-		return;
-	}
-	pr_info("invalid-free of heap object\n");
-	p = kmem_cache_alloc(cache, GFP_KERNEL);
-	if (!p) {
-		pr_err("Allocation failed\n");
-		kmem_cache_destroy(cache);
-		return;
-	}
-
-	/* Trigger invalid free, the object doesn't get freed */
-	kmem_cache_free(cache, p + 1);
-
-	/*
-	 * Properly free the object to prevent the "Objects remaining in
-	 * test_cache on __kmem_cache_shutdown" BUG failure.
-	 */
-	kmem_cache_free(cache, p);
-
-	kmem_cache_destroy(cache);
-}
-
-static noinline void __init kasan_memchr(void)
-{
-	char *ptr;
-	size_t size = 24;
-
-	pr_info("out-of-bounds in memchr\n");
-	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
-	if (!ptr)
-		return;
-
-	kasan_ptr_result = memchr(ptr, '1', size + 1);
-	kfree(ptr);
-}
-
-static noinline void __init kasan_memcmp(void)
-{
-	char *ptr;
-	size_t size = 24;
-	int arr[9];
-
-	pr_info("out-of-bounds in memcmp\n");
-	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
-	if (!ptr)
-		return;
-
-	memset(arr, 0, sizeof(arr));
-	kasan_int_result = memcmp(ptr, arr, size + 1);
-	kfree(ptr);
-}
-
-static noinline void __init kasan_strings(void)
-{
-	char *ptr;
-	size_t size = 24;
-
-	pr_info("use-after-free in strchr\n");
-	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
-	if (!ptr)
-		return;
-
-	kfree(ptr);
-
-	/*
-	 * Try to cause only 1 invalid access (less spam in dmesg).
-	 * For that we need ptr to point to zeroed byte.
-	 * Skip metadata that could be stored in freed object so ptr
-	 * will likely point to zeroed byte.
-	 */
-	ptr += 16;
-	kasan_ptr_result = strchr(ptr, '1');
-
-	pr_info("use-after-free in strrchr\n");
-	kasan_ptr_result = strrchr(ptr, '1');
-
-	pr_info("use-after-free in strcmp\n");
-	kasan_int_result = strcmp(ptr, "2");
-
-	pr_info("use-after-free in strncmp\n");
-	kasan_int_result = strncmp(ptr, "2", 1);
-
-	pr_info("use-after-free in strlen\n");
-	kasan_int_result = strlen(ptr);
-
-	pr_info("use-after-free in strnlen\n");
-	kasan_int_result = strnlen(ptr, 1);
-}
-
-static noinline void __init kasan_bitops(void)
-{
-	/*
-	 * Allocate 1 more byte, which causes kzalloc to round up to 16-bytes;
-	 * this way we do not actually corrupt other memory.
-	 */
-	long *bits = kzalloc(sizeof(*bits) + 1, GFP_KERNEL);
-	if (!bits)
-		return;
-
-	/*
-	 * Below calls try to access bit within allocated memory; however, the
-	 * below accesses are still out-of-bounds, since bitops are defined to
-	 * operate on the whole long the bit is in.
-	 */
-	pr_info("out-of-bounds in set_bit\n");
-	set_bit(BITS_PER_LONG, bits);
-
-	pr_info("out-of-bounds in __set_bit\n");
-	__set_bit(BITS_PER_LONG, bits);
-
-	pr_info("out-of-bounds in clear_bit\n");
-	clear_bit(BITS_PER_LONG, bits);
-
-	pr_info("out-of-bounds in __clear_bit\n");
-	__clear_bit(BITS_PER_LONG, bits);
-
-	pr_info("out-of-bounds in clear_bit_unlock\n");
-	clear_bit_unlock(BITS_PER_LONG, bits);
-
-	pr_info("out-of-bounds in __clear_bit_unlock\n");
-	__clear_bit_unlock(BITS_PER_LONG, bits);
-
-	pr_info("out-of-bounds in change_bit\n");
-	change_bit(BITS_PER_LONG, bits);
-
-	pr_info("out-of-bounds in __change_bit\n");
-	__change_bit(BITS_PER_LONG, bits);
-
-	/*
-	 * Below calls try to access bit beyond allocated memory.
-	 */
-	pr_info("out-of-bounds in test_and_set_bit\n");
-	test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
-
-	pr_info("out-of-bounds in __test_and_set_bit\n");
-	__test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
-
-	pr_info("out-of-bounds in test_and_set_bit_lock\n");
-	test_and_set_bit_lock(BITS_PER_LONG + BITS_PER_BYTE, bits);
-
-	pr_info("out-of-bounds in test_and_clear_bit\n");
-	test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
-
-	pr_info("out-of-bounds in __test_and_clear_bit\n");
-	__test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
-
-	pr_info("out-of-bounds in test_and_change_bit\n");
-	test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
-
-	pr_info("out-of-bounds in __test_and_change_bit\n");
-	__test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
-
-	pr_info("out-of-bounds in test_bit\n");
-	kasan_int_result = test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
-
-#if defined(clear_bit_unlock_is_negative_byte)
-	pr_info("out-of-bounds in clear_bit_unlock_is_negative_byte\n");
-	kasan_int_result = clear_bit_unlock_is_negative_byte(BITS_PER_LONG +
-		BITS_PER_BYTE, bits);
-#endif
-	kfree(bits);
-}
-
-static noinline void __init kmalloc_double_kzfree(void)
-{
-	char *ptr;
-	size_t size = 16;
-
-	pr_info("double-free (kzfree)\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	kzfree(ptr);
-	kzfree(ptr);
-}
-
-#ifdef CONFIG_KASAN_VMALLOC
-static noinline void __init vmalloc_oob(void)
-{
-	void *area;
-
-	pr_info("vmalloc out-of-bounds\n");
-
-	/*
-	 * We have to be careful not to hit the guard page.
-	 * The MMU will catch that and crash us.
-	 */
-	area = vmalloc(3000);
-	if (!area) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	((volatile char *)area)[3100];
-	vfree(area);
-}
-#else
-static void __init vmalloc_oob(void) {}
-#endif
-
-static int __init kmalloc_tests_init(void)
-{
-	/*
-	 * Temporarily enable multi-shot mode. Otherwise, we'd only get a
-	 * report for the first case.
-	 */
-	bool multishot = kasan_save_enable_multi_shot();
-
-	kmalloc_oob_right();
-	kmalloc_oob_left();
-	kmalloc_node_oob_right();
-#ifdef CONFIG_SLUB
-	kmalloc_pagealloc_oob_right();
-	kmalloc_pagealloc_uaf();
-	kmalloc_pagealloc_invalid_free();
-#endif
-	kmalloc_large_oob_right();
-	kmalloc_oob_krealloc_more();
-	kmalloc_oob_krealloc_less();
-	kmalloc_oob_16();
-	kmalloc_oob_in_memset();
-	kmalloc_oob_memset_2();
-	kmalloc_oob_memset_4();
-	kmalloc_oob_memset_8();
-	kmalloc_oob_memset_16();
-	kmalloc_memmove_invalid_size();
-	kmalloc_uaf();
-	kmalloc_uaf_memset();
-	kmalloc_uaf2();
-	kfree_via_page();
-	kfree_via_phys();
-	kmem_cache_oob();
-	memcg_accounted_kmem_cache();
-	kasan_stack_oob();
-	kasan_global_oob();
-	kasan_alloca_oob_left();
-	kasan_alloca_oob_right();
-	ksize_unpoisons_memory();
-	copy_user_test();
-	kmem_cache_double_free();
-	kmem_cache_invalid_free();
-	kasan_memchr();
-	kasan_memcmp();
-	kasan_strings();
-	kasan_bitops();
-	kmalloc_double_kzfree();
-	vmalloc_oob();
-
-	kasan_restore_multi_shot(multishot);
-
-	return -EAGAIN;
-}
-
-module_init(kmalloc_tests_init);
-MODULE_LICENSE("GPL");
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200731044242.1323143-4-davidgow%40google.com.
