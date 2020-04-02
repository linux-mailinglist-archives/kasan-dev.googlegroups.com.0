Return-Path: <kasan-dev+bncBDK3TPOVRULBBPU6TH2AKGQEATSAUPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E94A19CBDB
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Apr 2020 22:46:55 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id p15sf4573385ils.12
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Apr 2020 13:46:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585860414; cv=pass;
        d=google.com; s=arc-20160816;
        b=xcUqJzNRDbODZvSXOixjAtDcGRIafrZEJplovyRzB6cd0a37BWZyDYBQbGUL1KuC4P
         tgxDrLMhqoAGjKruMToW+vFjnT75WhHrFfrhM/GcP8mf2Exy3uYsHpYAvR8gal1vG9W7
         i1s8hsOTWChglPrSbsstPTJ6dR1dEgjRBfoG3WzmcuUdLGzWXER3PqZ0tjU23/K86sBq
         yOkSz7IaXgSd0NCmEiTVCJyucvgUzzYMNNJcuRih/0RLiQ3x6mrXTZdtBwXSdl0VuopU
         /naa1xTgRSNV7yff11Ytz8P8cDdgyMaSykuteTfyqn16xfjlpZX9YkcV6xCu6M2BZVE/
         yCsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=7qD/gOx4pwgaQntECJTRoCuZV6SkNKYQCA8VlQI51ro=;
        b=YzcxXR2WYX8H3x+ZgYG5kYGKoUJda9nhimeE4LhUfzN7sB+7QJrUOcp6jFoIy+nc/P
         74VxBgUkHkIClyhD1LEXs8I31x9PPmOR99W7Yw5Hyx/F+6k3rM9o2Uurm4FHS6DPO147
         3MM95IDdowufuKWMKclqV+k3DCxEBM5B0NdtX1xQ3MH1GciE/2efGWjJ6pPU6benyF8Z
         SY0rwSOPWdoHZQStckgp9faG2u371mmxgJ2tknRap2/zbpssR0b/L9Vlh68pgmAX41cu
         27hE77CP2RJT/7fxRDsoSRxTcPQNPDxHzl6hX+Zg07Nni+1PzoSI8B1BhVAUyhIlk18N
         h8/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rlHO6fhX;
       spf=pass (google.com: domain of 3pu-gxgwkce4jhyixqbvedieweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3PU-GXgwKCe4jhYiXQbVedieWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7qD/gOx4pwgaQntECJTRoCuZV6SkNKYQCA8VlQI51ro=;
        b=JvN1YZXLWQzlMK/J8m6U50IpBRE5+DyESdv2dWcfi9odEvcYdo3Gf8fdZQHbotpTya
         FKMk10fh1q7Ov3R29fPIuGcLwiv6fB7padtskTypsiqfxw4A9o2/QyZre5FebDn7QScl
         vZGi/J0iVSAcjut9F7iBGmVZgSpLi9MF3H5xJ69XSmyyLHSxwHICkCtYn56c33NStlDc
         pI0EFKBedU5if0utxFLVc/dCvKTHRowEnpdRFGc5ELO8ropivtevUwR3L5eJHKWNciTj
         2A7HrpH3AtJ1hK2XS6g1xYwA1ylZIhz400/9rjufgQ2HcF3INILa3mcbCOfpjY1DQLQO
         wDGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7qD/gOx4pwgaQntECJTRoCuZV6SkNKYQCA8VlQI51ro=;
        b=cXZ4HcYFubU3d/UV/isT/kfNAecqzbknbpN9yDZArmRhiJMEAIvO1V4IiAaQkXqd+k
         TJ9SkRSeyOnWryYsfMS9HyEexEI6ME3sqjjYUpnG9mB8S1q1KuwRLtFviSKmjuFMcdpH
         dpw8U/FcJm92UIqvN5cxWBlHgSLRu6GeTp8etc1x/o1P58GK6mIvB74QYCc8SVmjfPnJ
         VTXdnwVisZfdCY7NhvhFQ6MzbuPeM0/+d7aA1LxzxtRDbQnwbtgFoZt19YdwqWr4WoJS
         66ZhQqsCfXq5AJtDIVcdOmiqNelW1w2r0JKLEA9daOxtD8MkzxuZonZDRuC98aP5Xkbh
         ljbw==
X-Gm-Message-State: AGi0PuZ06BvWiboSza61JciqSGDOBj21dAcwyKLJadRNanyUFjT6bqdv
	z7L2il/wQwx8oG0UbyE3Ato=
X-Google-Smtp-Source: APiQypIQQQ1V87vgCy7tqBJUhLX/BNuLxLxfUHQ72Nh6FdX09IcFMmQ82NdQEXc29F/S2duClwIbrw==
X-Received: by 2002:a92:ce0b:: with SMTP id b11mr4961528ilo.183.1585860414306;
        Thu, 02 Apr 2020 13:46:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8890:: with SMTP id d16ls1434352ioo.6.gmail; Thu, 02 Apr
 2020 13:46:53 -0700 (PDT)
X-Received: by 2002:a5d:891a:: with SMTP id b26mr3460200ion.194.1585860413757;
        Thu, 02 Apr 2020 13:46:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585860413; cv=none;
        d=google.com; s=arc-20160816;
        b=SK0+OuQNhIfFUdJZrf+YbrIsx93AgxFgTRPP0jQ6aj9J+XpndCPfawcVLDDOvJxS/v
         ncyOiju+SjuSB3/6K/b8qX7jfw+Ym4EUH7FQTW+zYf62zeT4e3nD3Us6lLiI/R1Vr40x
         9hTPyAVu1/1d+VGxLb/uBPN5O37YSbGnZrSB4M8ler/gyjsBQzfOWMtcps/n3ARikmr8
         VwDdJ1k6JR9sQuEv5rNCam5E2hC3jX6SrsemFpi/nV73LuAIjRFQDUjyPF8Izy67hCDv
         0MGSnWEFdjMDpLUUAxeHpsPNv+p2mI50YYQyVWPPhx2M1DsPhpGuogauOYLnGxOrlMTt
         voIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=kVgrvTSTGwgC45nOztAIIqQduMQR69VORNwL7JH1XiI=;
        b=uXSCtknXh0UWoMqGhvmDGJANIsQPhDn733iaadpA0ARpKu6/SA3PW4FUfwrCvB23DH
         sbZqvUGRUa8YTMSKT/jBeWCGZbALiVxtnfOdHyjfVhZHr8qUiX8SjhA3J4j/kHHAc9Jl
         WIQBPOONKRVAeQCpVa95Et+XpsXOjjm2Dilk8sv1UnRoVdS/meByr4ZmN/5KsSHewjkE
         eT4k0rAvW2WbI02jkqQxYcSXSLOWtED5QUpvNyWLfQCA0tb0F2sHfnLPjplelIuBjaSC
         oSYbegCec/suJS4jWBhpQy+IdPwklqYi5AMbY8pJxVvKnead0aDVObu4X+uHnqjTpWon
         iW+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rlHO6fhX;
       spf=pass (google.com: domain of 3pu-gxgwkce4jhyixqbvedieweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3PU-GXgwKCe4jhYiXQbVedieWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id t13si443459ilk.5.2020.04.02.13.46.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Apr 2020 13:46:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pu-gxgwkce4jhyixqbvedieweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id y7so3282576ybj.15
        for <kasan-dev@googlegroups.com>; Thu, 02 Apr 2020 13:46:53 -0700 (PDT)
X-Received: by 2002:a25:b21e:: with SMTP id i30mr7656437ybj.502.1585860413092;
 Thu, 02 Apr 2020 13:46:53 -0700 (PDT)
Date: Thu,  2 Apr 2020 13:46:39 -0700
In-Reply-To: <20200402204639.161637-1-trishalfonso@google.com>
Message-Id: <20200402204639.161637-5-trishalfonso@google.com>
Mime-Version: 1.0
References: <20200402204639.161637-1-trishalfonso@google.com>
X-Mailer: git-send-email 2.26.0.292.g33ef6b2f38-goog
Subject: [PATCH v4 3/4] KASAN: Port KASAN Tests to KUnit
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
To: davidgow@google.com, brendanhiggins@google.com, aryabinin@virtuozzo.com, 
	dvyukov@google.com, mingo@redhat.com, peterz@infradead.org, 
	juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	Patricia Alfonso <trishalfonso@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rlHO6fhX;       spf=pass
 (google.com: domain of 3pu-gxgwkce4jhyixqbvedieweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--trishalfonso.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3PU-GXgwKCe4jhYiXQbVedieWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
 lib/Kconfig.kasan       |  15 +-
 lib/Makefile            |   3 +-
 lib/test_kasan.c        | 622 ++++++++++++++++------------------------
 lib/test_kasan_module.c |  76 +++++
 4 files changed, 335 insertions(+), 381 deletions(-)
 create mode 100644 lib/test_kasan_module.c

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 81f5464ea9e1..c969ceb4586b 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -158,10 +158,17 @@ config KASAN_VMALLOC
 	  for KASAN to detect more sorts of errors (and to support vmapped
 	  stacks), but at the cost of higher memory usage.
 
-config TEST_KASAN
-	tristate "Module for testing KASAN for bug detection"
-	depends on m && KASAN
+config TEST_KASAN_KUNIT
+	tristate "KUnit testing KASAN for bug detection"
+	depends on KASAN && KUNIT
 	help
-	  This is a test module doing various nasty things like
+	  This is a test suite doing various nasty things like
 	  out of bounds accesses, use after free. It is useful for testing
 	  kernel debugging features like KASAN.
+
+config TEST_KASAN_MODULE
+	tristate "Module testing KASAN for bug detection on copy user tests"
+	depends on m && KASAN
+	help
+	  This is a test module for functions which cannot be tested by
+	  KUnit, like copy_user_tests.
diff --git a/lib/Makefile b/lib/Makefile
index 611872c06926..60e125555271 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -59,9 +59,10 @@ obj-$(CONFIG_TEST_FIRMWARE) += test_firmware.o
 obj-$(CONFIG_TEST_SYSCTL) += test_sysctl.o
 obj-$(CONFIG_TEST_HASH) += test_hash.o test_siphash.o
 obj-$(CONFIG_TEST_IDA) += test_ida.o
-obj-$(CONFIG_TEST_KASAN) += test_kasan.o
+obj-$(CONFIG_TEST_KASAN_KUNIT) += test_kasan.o
 CFLAGS_test_kasan.o += -fno-builtin
 CFLAGS_test_kasan.o += $(call cc-disable-warning, vla)
+obj-$(CONFIG_TEST_KASAN_MODULE) += test_kasan_module.o
 obj-$(CONFIG_TEST_UBSAN) += test_ubsan.o
 CFLAGS_test_ubsan.o += $(call cc-disable-warning, vla)
 UBSAN_SANITIZE_test_ubsan.o := y
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index dbfa0875ee09..4c3f57714bdf 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -5,8 +5,6 @@
  * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
  */
 
-#define pr_fmt(fmt) "kasan test: %s " fmt, __func__
-
 #include <linux/bitops.h>
 #include <linux/delay.h>
 #include <linux/kasan.h>
@@ -77,380 +75,311 @@ static void kasan_test_exit(struct kunit *test)
 	kunit_put_resource(res); \
 } while (0)
 
+static void kmalloc_oob_right(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 123;
 
-	pr_info("out-of-bounds to right\n");
 	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	ptr[size] = 'x';
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 'x');
 	kfree(ptr);
 }
 
-static noinline void __init kmalloc_oob_left(void)
+static void kmalloc_oob_left(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 15;
 
-	pr_info("out-of-bounds to left\n");
 	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	*ptr = *(ptr - 1);
+	KUNIT_EXPECT_KASAN_FAIL(test, *ptr = *(ptr - 1));
 	kfree(ptr);
 }
 
-static noinline void __init kmalloc_node_oob_right(void)
+static void kmalloc_node_oob_right(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 4096;
 
-	pr_info("kmalloc_node(): out-of-bounds to right\n");
 	ptr = kmalloc_node(size, GFP_KERNEL, 0);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	ptr[size] = 0;
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
 	kfree(ptr);
 }
 
-#ifdef CONFIG_SLUB
-static noinline void __init kmalloc_pagealloc_oob_right(void)
+static void kmalloc_pagealloc_oob_right(struct kunit *test)
 {
 	char *ptr;
 	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
 
+	if (!IS_ENABLED(CONFIG_SLUB)) {
+		kunit_info(test, "CONFIG_SLUB is not enabled.");
+		return;
+	}
+
 	/* Allocate a chunk that does not fit into a SLUB cache to trigger
 	 * the page allocator fallback.
 	 */
-	pr_info("kmalloc pagealloc allocation: out-of-bounds to right\n");
 	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	ptr[size] = 0;
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
 	kfree(ptr);
 }
 
-static noinline void __init kmalloc_pagealloc_uaf(void)
+static void kmalloc_pagealloc_uaf(struct kunit *test)
 {
 	char *ptr;
 	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
 
-	pr_info("kmalloc pagealloc allocation: use-after-free\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
+	if (!IS_ENABLED(CONFIG_SLUB)) {
+		kunit_info(test, "CONFIG_SLUB is not enabled.");
 		return;
 	}
 
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
 	kfree(ptr);
-	ptr[0] = 0;
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
 }
 
-static noinline void __init kmalloc_pagealloc_invalid_free(void)
+static void kmalloc_pagealloc_invalid_free(struct kunit *test)
 {
 	char *ptr;
 	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
 
-	pr_info("kmalloc pagealloc allocation: invalid-free\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
+	if (!IS_ENABLED(CONFIG_SLUB)) {
+		kunit_info(test, "CONFIG_SLUB is not enabled.");
 		return;
 	}
 
-	kfree(ptr + 1);
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, kfree(ptr + 1));
 }
-#endif
 
-static noinline void __init kmalloc_large_oob_right(void)
+static void kmalloc_large_oob_right(struct kunit *test)
 {
 	char *ptr;
 	size_t size = KMALLOC_MAX_CACHE_SIZE - 256;
 	/* Allocate a chunk that is large enough, but still fits into a slab
 	 * and does not trigger the page allocator fallback in SLUB.
 	 */
-	pr_info("kmalloc large allocation: out-of-bounds to right\n");
 	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	ptr[size] = 0;
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
 	kfree(ptr);
 }
 
-static noinline void __init kmalloc_oob_krealloc_more(void)
+static void kmalloc_oob_krealloc_more(struct kunit *test)
 {
 	char *ptr1, *ptr2;
 	size_t size1 = 17;
 	size_t size2 = 19;
 
-	pr_info("out-of-bounds after krealloc more\n");
 	ptr1 = kmalloc(size1, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
+
 	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
-	if (!ptr1 || !ptr2) {
-		pr_err("Allocation failed\n");
-		kfree(ptr1);
-		kfree(ptr2);
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
-	ptr2[size2] = 'x';
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2] = 'x');
 	kfree(ptr2);
 }
 
-static noinline void __init kmalloc_oob_krealloc_less(void)
+static void kmalloc_oob_krealloc_less(struct kunit *test)
 {
 	char *ptr1, *ptr2;
 	size_t size1 = 17;
 	size_t size2 = 15;
 
-	pr_info("out-of-bounds after krealloc less\n");
 	ptr1 = kmalloc(size1, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
+
 	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
-	if (!ptr1 || !ptr2) {
-		pr_err("Allocation failed\n");
-		kfree(ptr1);
-		return;
-	}
-	ptr2[size2] = 'x';
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2] = 'x');
 	kfree(ptr2);
 }
 
-static noinline void __init kmalloc_oob_16(void)
+static void kmalloc_oob_16(struct kunit *test)
 {
 	struct {
 		u64 words[2];
 	} *ptr1, *ptr2;
 
-	pr_info("kmalloc out-of-bounds for 16-bytes access\n");
 	ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
+
 	ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
-	if (!ptr1 || !ptr2) {
-		pr_err("Allocation failed\n");
-		kfree(ptr1);
-		kfree(ptr2);
-		return;
-	}
-	*ptr1 = *ptr2;
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
 	kfree(ptr1);
 	kfree(ptr2);
 }
 
-static noinline void __init kmalloc_oob_memset_2(void)
+static void kmalloc_oob_memset_2(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 8;
 
-	pr_info("out-of-bounds in memset2\n");
 	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	memset(ptr+7, 0, 2);
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr+7, 0, 2));
 	kfree(ptr);
 }
 
-static noinline void __init kmalloc_oob_memset_4(void)
+static void kmalloc_oob_memset_4(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 8;
 
-	pr_info("out-of-bounds in memset4\n");
 	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	memset(ptr+5, 0, 4);
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr+5, 0, 4));
 	kfree(ptr);
 }
 
 
-static noinline void __init kmalloc_oob_memset_8(void)
+static void kmalloc_oob_memset_8(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 8;
 
-	pr_info("out-of-bounds in memset8\n");
 	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	memset(ptr+1, 0, 8);
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr+1, 0, 8));
 	kfree(ptr);
 }
 
-static noinline void __init kmalloc_oob_memset_16(void)
+static void kmalloc_oob_memset_16(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 16;
 
-	pr_info("out-of-bounds in memset16\n");
 	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	memset(ptr+1, 0, 16);
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr+1, 0, 16));
 	kfree(ptr);
 }
 
-static noinline void __init kmalloc_oob_in_memset(void)
+static void kmalloc_oob_in_memset(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 666;
 
-	pr_info("out-of-bounds in memset\n");
 	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	memset(ptr, 0, size+5);
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr, 0, size+5));
 	kfree(ptr);
 }
 
-static noinline void __init kmalloc_uaf(void)
+static void kmalloc_uaf(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 10;
 
-	pr_info("use-after-free\n");
 	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	kfree(ptr);
-	*(ptr + 8) = 'x';
+	KUNIT_EXPECT_KASAN_FAIL(test, *(ptr + 8) = 'x');
 }
 
-static noinline void __init kmalloc_uaf_memset(void)
+static void kmalloc_uaf_memset(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 33;
 
-	pr_info("use-after-free in memset\n");
 	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	kfree(ptr);
-	memset(ptr, 0, size);
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr, 0, size));
 }
 
-static noinline void __init kmalloc_uaf2(void)
+static void kmalloc_uaf2(struct kunit *test)
 {
 	char *ptr1, *ptr2;
 	size_t size = 43;
 
-	pr_info("use-after-free after another kmalloc\n");
 	ptr1 = kmalloc(size, GFP_KERNEL);
-	if (!ptr1) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
 
 	kfree(ptr1);
+
 	ptr2 = kmalloc(size, GFP_KERNEL);
-	if (!ptr2) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr1[40] = 'x');
+	KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
 
-	ptr1[40] = 'x';
-	if (ptr1 == ptr2)
-		pr_err("Could not detect use-after-free: ptr1 == ptr2\n");
 	kfree(ptr2);
 }
 
-static noinline void __init kfree_via_page(void)
+static void kfree_via_page(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 8;
 	struct page *page;
 	unsigned long offset;
 
-	pr_info("invalid-free false positive (via page)\n");
 	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	page = virt_to_page(ptr);
 	offset = offset_in_page(ptr);
 	kfree(page_address(page) + offset);
 }
 
-static noinline void __init kfree_via_phys(void)
+static void kfree_via_phys(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 8;
 	phys_addr_t phys;
 
-	pr_info("invalid-free false positive (via phys)\n");
 	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	phys = virt_to_phys(ptr);
 	kfree(phys_to_virt(phys));
 }
 
-static noinline void __init kmem_cache_oob(void)
+static void kmem_cache_oob(struct kunit *test)
 {
 	char *p;
 	size_t size = 200;
 	struct kmem_cache *cache = kmem_cache_create("test_cache",
 						size, 0,
 						0, NULL);
-	if (!cache) {
-		pr_err("Cache allocation failed\n");
-		return;
-	}
-	pr_info("out-of-bounds in kmem_cache_alloc\n");
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
 	p = kmem_cache_alloc(cache, GFP_KERNEL);
 	if (!p) {
-		pr_err("Allocation failed\n");
+		kunit_err(test, "Allocation failed: %s\n", __func__);
 		kmem_cache_destroy(cache);
 		return;
 	}
 
-	*p = p[size];
+	KUNIT_EXPECT_KASAN_FAIL(test, *p = p[size]);
 	kmem_cache_free(cache, p);
 	kmem_cache_destroy(cache);
 }
 
-static noinline void __init memcg_accounted_kmem_cache(void)
+static void memcg_accounted_kmem_cache(struct kunit *test)
 {
 	int i;
 	char *p;
@@ -458,12 +387,8 @@ static noinline void __init memcg_accounted_kmem_cache(void)
 	struct kmem_cache *cache;
 
 	cache = kmem_cache_create("test_cache", size, 0, SLAB_ACCOUNT, NULL);
-	if (!cache) {
-		pr_err("Cache allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
 
-	pr_info("allocate memcg accounted object\n");
 	/*
 	 * Several allocations with a delay to allow for lazy per memcg kmem
 	 * cache creation.
@@ -483,134 +408,93 @@ static noinline void __init memcg_accounted_kmem_cache(void)
 
 static char global_array[10];
 
-static noinline void __init kasan_global_oob(void)
+static void kasan_global_oob(struct kunit *test)
 {
 	volatile int i = 3;
 	char *p = &global_array[ARRAY_SIZE(global_array) + i];
 
-	pr_info("out-of-bounds global variable\n");
-	*(volatile char *)p;
+	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
 
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
+static void ksize_unpoisons_memory(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 123, real_size;
 
-	pr_info("ksize() unpoisons the whole allocated chunk\n");
 	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	real_size = ksize(ptr);
 	/* This access doesn't trigger an error. */
 	ptr[size] = 'x';
 	/* This one does. */
-	ptr[real_size] = 'y';
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[real_size] = 'y');
 	kfree(ptr);
 }
 
-static noinline void __init copy_user_test(void)
+static void kasan_stack_oob(struct kunit *test)
 {
-	char *kmem;
-	char __user *usermem;
-	size_t size = 10;
-	int unused;
-
-	kmem = kmalloc(size, GFP_KERNEL);
-	if (!kmem)
-		return;
+	char stack_array[10];
+	volatile int i = 0;
+	char *p = &stack_array[ARRAY_SIZE(stack_array) + i];
 
-	usermem = (char __user *)vm_mmap(NULL, 0, PAGE_SIZE,
-			    PROT_READ | PROT_WRITE | PROT_EXEC,
-			    MAP_ANONYMOUS | MAP_PRIVATE, 0);
-	if (IS_ERR(usermem)) {
-		pr_err("Failed to allocate user memory\n");
-		kfree(kmem);
+	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
+		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
 		return;
 	}
 
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
+	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
 
-static noinline void __init kasan_alloca_oob_left(void)
+static void kasan_alloca_oob_left(struct kunit *test)
 {
 	volatile int i = 10;
 	char alloca_array[i];
 	char *p = alloca_array - 1;
 
-	pr_info("out-of-bounds to left on alloca\n");
-	*(volatile char *)p;
+	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
+		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
+		return;
+	}
+
+	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
 
-static noinline void __init kasan_alloca_oob_right(void)
+static void kasan_alloca_oob_right(struct kunit *test)
 {
 	volatile int i = 10;
 	char alloca_array[i];
 	char *p = alloca_array + i;
 
-	pr_info("out-of-bounds to right on alloca\n");
-	*(volatile char *)p;
+	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
+		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
+		return;
+	}
+
+	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
 
-static noinline void __init kmem_cache_double_free(void)
+static void kmem_cache_double_free(struct kunit *test)
 {
 	char *p;
 	size_t size = 200;
 	struct kmem_cache *cache;
 
 	cache = kmem_cache_create("test_cache", size, 0, 0, NULL);
-	if (!cache) {
-		pr_err("Cache allocation failed\n");
-		return;
-	}
-	pr_info("double-free on heap object\n");
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+
 	p = kmem_cache_alloc(cache, GFP_KERNEL);
 	if (!p) {
-		pr_err("Allocation failed\n");
+		kunit_err(test, "Allocation failed: %s\n", __func__);
 		kmem_cache_destroy(cache);
 		return;
 	}
 
 	kmem_cache_free(cache, p);
-	kmem_cache_free(cache, p);
+	KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_free(cache, p));
 	kmem_cache_destroy(cache);
 }
 
-static noinline void __init kmem_cache_invalid_free(void)
+static void kmem_cache_invalid_free(struct kunit *test)
 {
 	char *p;
 	size_t size = 200;
@@ -618,20 +502,17 @@ static noinline void __init kmem_cache_invalid_free(void)
 
 	cache = kmem_cache_create("test_cache", size, 0, SLAB_TYPESAFE_BY_RCU,
 				  NULL);
-	if (!cache) {
-		pr_err("Cache allocation failed\n");
-		return;
-	}
-	pr_info("invalid-free of heap object\n");
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+
 	p = kmem_cache_alloc(cache, GFP_KERNEL);
 	if (!p) {
-		pr_err("Allocation failed\n");
+		kunit_err(test, "Allocation failed: %s\n", __func__);
 		kmem_cache_destroy(cache);
 		return;
 	}
 
 	/* Trigger invalid free, the object doesn't get freed */
-	kmem_cache_free(cache, p + 1);
+	KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_free(cache, p + 1));
 
 	/*
 	 * Properly free the object to prevent the "Objects remaining in
@@ -642,45 +523,60 @@ static noinline void __init kmem_cache_invalid_free(void)
 	kmem_cache_destroy(cache);
 }
 
-static noinline void __init kasan_memchr(void)
+static void kasan_memchr(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 24;
 
-	pr_info("out-of-bounds in memchr\n");
-	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
-	if (!ptr)
+	// See https://bugzilla.kernel.org/show_bug.cgi?id=206337
+	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
+		kunit_info(test,
+			"str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
 		return;
+	}
 
-	memchr(ptr, '1', size + 1);
+	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, memchr(ptr, '1', size + 1));
 	kfree(ptr);
 }
 
-static noinline void __init kasan_memcmp(void)
+static void kasan_memcmp(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 24;
 	int arr[9];
 
-	pr_info("out-of-bounds in memcmp\n");
-	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
-	if (!ptr)
+	// See https://bugzilla.kernel.org/show_bug.cgi?id=206337
+	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
+		kunit_info(test,
+			"str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
 		return;
+	}
+
+	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	memset(arr, 0, sizeof(arr));
-	memcmp(ptr, arr, size+1);
+	KUNIT_EXPECT_KASAN_FAIL(test, memcmp(ptr, arr, size+1));
 	kfree(ptr);
 }
 
-static noinline void __init kasan_strings(void)
+static void kasan_strings(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 24;
 
-	pr_info("use-after-free in strchr\n");
-	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
-	if (!ptr)
+	// See https://bugzilla.kernel.org/show_bug.cgi?id=206337
+	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
+		kunit_info(test,
+			"str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
 		return;
+	}
+
+	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	kfree(ptr);
 
@@ -691,188 +587,162 @@ static noinline void __init kasan_strings(void)
 	 * will likely point to zeroed byte.
 	 */
 	ptr += 16;
-	strchr(ptr, '1');
+	KUNIT_EXPECT_KASAN_FAIL(test, strchr(ptr, '1'));
 
-	pr_info("use-after-free in strrchr\n");
-	strrchr(ptr, '1');
+	KUNIT_EXPECT_KASAN_FAIL(test, strrchr(ptr, '1'));
 
-	pr_info("use-after-free in strcmp\n");
-	strcmp(ptr, "2");
+	KUNIT_EXPECT_KASAN_FAIL(test, strcmp(ptr, "2"));
 
-	pr_info("use-after-free in strncmp\n");
-	strncmp(ptr, "2", 1);
+	KUNIT_EXPECT_KASAN_FAIL(test, strncmp(ptr, "2", 1));
 
-	pr_info("use-after-free in strlen\n");
-	strlen(ptr);
+	KUNIT_EXPECT_KASAN_FAIL(test, strlen(ptr));
 
-	pr_info("use-after-free in strnlen\n");
-	strnlen(ptr, 1);
+	KUNIT_EXPECT_KASAN_FAIL(test, strnlen(ptr, 1));
 }
 
-static noinline void __init kasan_bitops(void)
+static void kasan_bitops(struct kunit *test)
 {
 	/*
 	 * Allocate 1 more byte, which causes kzalloc to round up to 16-bytes;
 	 * this way we do not actually corrupt other memory.
 	 */
 	long *bits = kzalloc(sizeof(*bits) + 1, GFP_KERNEL);
-	if (!bits)
-		return;
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, bits);
 
 	/*
 	 * Below calls try to access bit within allocated memory; however, the
 	 * below accesses are still out-of-bounds, since bitops are defined to
 	 * operate on the whole long the bit is in.
 	 */
-	pr_info("out-of-bounds in set_bit\n");
-	set_bit(BITS_PER_LONG, bits);
+	KUNIT_EXPECT_KASAN_FAIL(test, set_bit(BITS_PER_LONG, bits));
 
-	pr_info("out-of-bounds in __set_bit\n");
-	__set_bit(BITS_PER_LONG, bits);
+	KUNIT_EXPECT_KASAN_FAIL(test, __set_bit(BITS_PER_LONG, bits));
 
-	pr_info("out-of-bounds in clear_bit\n");
-	clear_bit(BITS_PER_LONG, bits);
+	KUNIT_EXPECT_KASAN_FAIL(test, clear_bit(BITS_PER_LONG, bits));
 
-	pr_info("out-of-bounds in __clear_bit\n");
-	__clear_bit(BITS_PER_LONG, bits);
+	KUNIT_EXPECT_KASAN_FAIL(test, __clear_bit(BITS_PER_LONG, bits));
 
-	pr_info("out-of-bounds in clear_bit_unlock\n");
-	clear_bit_unlock(BITS_PER_LONG, bits);
+	KUNIT_EXPECT_KASAN_FAIL(test, clear_bit_unlock(BITS_PER_LONG, bits));
 
-	pr_info("out-of-bounds in __clear_bit_unlock\n");
-	__clear_bit_unlock(BITS_PER_LONG, bits);
+	KUNIT_EXPECT_KASAN_FAIL(test, __clear_bit_unlock(BITS_PER_LONG, bits));
 
-	pr_info("out-of-bounds in change_bit\n");
-	change_bit(BITS_PER_LONG, bits);
+	KUNIT_EXPECT_KASAN_FAIL(test, change_bit(BITS_PER_LONG, bits));
 
-	pr_info("out-of-bounds in __change_bit\n");
-	__change_bit(BITS_PER_LONG, bits);
+	KUNIT_EXPECT_KASAN_FAIL(test, __change_bit(BITS_PER_LONG, bits));
 
 	/*
 	 * Below calls try to access bit beyond allocated memory.
 	 */
-	pr_info("out-of-bounds in test_and_set_bit\n");
-	test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
 
-	pr_info("out-of-bounds in __test_and_set_bit\n");
-	__test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		__test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
 
-	pr_info("out-of-bounds in test_and_set_bit_lock\n");
-	test_and_set_bit_lock(BITS_PER_LONG + BITS_PER_BYTE, bits);
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		test_and_set_bit_lock(BITS_PER_LONG + BITS_PER_BYTE, bits));
 
-	pr_info("out-of-bounds in test_and_clear_bit\n");
-	test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
 
-	pr_info("out-of-bounds in __test_and_clear_bit\n");
-	__test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		__test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
 
-	pr_info("out-of-bounds in test_and_change_bit\n");
-	test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
 
-	pr_info("out-of-bounds in __test_and_change_bit\n");
-	__test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		__test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
 
-	pr_info("out-of-bounds in test_bit\n");
-	(void)test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits);
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		(void)test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
 
 #if defined(clear_bit_unlock_is_negative_byte)
-	pr_info("out-of-bounds in clear_bit_unlock_is_negative_byte\n");
-	clear_bit_unlock_is_negative_byte(BITS_PER_LONG + BITS_PER_BYTE, bits);
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		clear_bit_unlock_is_negative_byte(BITS_PER_LONG + BITS_PER_BYTE,
+						bits));
 #endif
 	kfree(bits);
 }
 
-static noinline void __init kmalloc_double_kzfree(void)
+static void kmalloc_double_kzfree(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 16;
 
-	pr_info("double-free (kzfree)\n");
 	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	kzfree(ptr);
-	kzfree(ptr);
+	KUNIT_EXPECT_KASAN_FAIL(test, kzfree(ptr));
 }
 
-#ifdef CONFIG_KASAN_VMALLOC
-static noinline void __init vmalloc_oob(void)
+static void vmalloc_oob(struct kunit *test)
 {
 	void *area;
 
-	pr_info("vmalloc out-of-bounds\n");
+	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
+		kunit_info(test, "CONFIG_KASAN_VMALLOC is not enabled.");
+		return;
+	}
 
 	/*
 	 * We have to be careful not to hit the guard page.
 	 * The MMU will catch that and crash us.
 	 */
 	area = vmalloc(3000);
-	if (!area) {
-		pr_err("Allocation failed\n");
-		return;
-	}
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, area);
 
-	((volatile char *)area)[3100];
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)area)[3100]);
 	vfree(area);
 }
-#else
-static void __init vmalloc_oob(void) {}
-#endif
 
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
+static struct kunit_case kasan_kunit_test_cases[] = {
+	KUNIT_CASE(kmalloc_oob_right),
+	KUNIT_CASE(kmalloc_oob_left),
+	KUNIT_CASE(kmalloc_node_oob_right),
+	KUNIT_CASE(kmalloc_pagealloc_oob_right),
+	KUNIT_CASE(kmalloc_pagealloc_uaf),
+	KUNIT_CASE(kmalloc_pagealloc_invalid_free),
+	KUNIT_CASE(kmalloc_large_oob_right),
+	KUNIT_CASE(kmalloc_oob_krealloc_more),
+	KUNIT_CASE(kmalloc_oob_krealloc_less),
+	KUNIT_CASE(kmalloc_oob_16),
+	KUNIT_CASE(kmalloc_oob_in_memset),
+	KUNIT_CASE(kmalloc_oob_memset_2),
+	KUNIT_CASE(kmalloc_oob_memset_4),
+	KUNIT_CASE(kmalloc_oob_memset_8),
+	KUNIT_CASE(kmalloc_oob_memset_16),
+	KUNIT_CASE(kmalloc_uaf),
+	KUNIT_CASE(kmalloc_uaf_memset),
+	KUNIT_CASE(kmalloc_uaf2),
+	KUNIT_CASE(kfree_via_page),
+	KUNIT_CASE(kfree_via_phys),
+	KUNIT_CASE(kmem_cache_oob),
+	KUNIT_CASE(memcg_accounted_kmem_cache),
+	KUNIT_CASE(kasan_global_oob),
+	KUNIT_CASE(kasan_stack_oob),
+	KUNIT_CASE(kasan_alloca_oob_left),
+	KUNIT_CASE(kasan_alloca_oob_right),
+	KUNIT_CASE(ksize_unpoisons_memory),
+	KUNIT_CASE(kmem_cache_double_free),
+	KUNIT_CASE(kmem_cache_invalid_free),
+	KUNIT_CASE(kasan_memchr),
+	KUNIT_CASE(kasan_memcmp),
+	KUNIT_CASE(kasan_strings),
+	KUNIT_CASE(kasan_bitops),
+	KUNIT_CASE(kmalloc_double_kzfree),
+	KUNIT_CASE(vmalloc_oob),
+	{}
+};
+
+static struct kunit_suite kasan_kunit_test_suite = {
+	.name = "kasan_kunit_test",
+	.init = kasan_test_init,
+	.test_cases = kasan_kunit_test_cases,
+	.exit = kasan_test_exit,
+};
+
+kunit_test_suite(kasan_kunit_test_suite);
 
-module_init(kmalloc_tests_init);
 MODULE_LICENSE("GPL");
diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
new file mode 100644
index 000000000000..87d7e4d8fc31
--- /dev/null
+++ b/lib/test_kasan_module.c
@@ -0,0 +1,76 @@
+// SPDX-License-Identifier: GPL-2.0-only
+/*
+ *
+ * Copyright (c) 2014 Samsung Electronics Co., Ltd.
+ * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
+ */
+
+#define pr_fmt(fmt) "kasan test: %s " fmt, __func__
+
+#include <linux/mman.h>
+#include <linux/module.h>
+#include <linux/printk.h>
+#include <linux/slab.h>
+#include <linux/uaccess.h>
+
+static noinline void __init copy_user_test(void)
+{
+	char *kmem;
+	char __user *usermem;
+	size_t size = 10;
+	int unused;
+
+	kmem = kmalloc(size, GFP_KERNEL);
+	if (!kmem)
+		return;
+
+	usermem = (char __user *)vm_mmap(NULL, 0, PAGE_SIZE,
+			    PROT_READ | PROT_WRITE | PROT_EXEC,
+			    MAP_ANONYMOUS | MAP_PRIVATE, 0);
+	if (IS_ERR(usermem)) {
+		pr_err("Failed to allocate user memory\n");
+		kfree(kmem);
+		return;
+	}
+
+	pr_info("out-of-bounds in copy_from_user()\n");
+	unused = copy_from_user(kmem, usermem, size + 1);
+
+	pr_info("out-of-bounds in copy_to_user()\n");
+	unused = copy_to_user(usermem, kmem, size + 1);
+
+	pr_info("out-of-bounds in __copy_from_user()\n");
+	unused = __copy_from_user(kmem, usermem, size + 1);
+
+	pr_info("out-of-bounds in __copy_to_user()\n");
+	unused = __copy_to_user(usermem, kmem, size + 1);
+
+	pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
+	unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
+
+	pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
+	unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
+
+	pr_info("out-of-bounds in strncpy_from_user()\n");
+	unused = strncpy_from_user(kmem, usermem, size + 1);
+
+	vm_munmap((unsigned long)usermem, PAGE_SIZE);
+	kfree(kmem);
+}
+
+static int __init test_kasan_module_init(void)
+{
+	/*
+	 * Temporarily enable multi-shot mode. Otherwise, we'd only get a
+	 * report for the first case.
+	 */
+	bool multishot = kasan_save_enable_multi_shot();
+
+	copy_user_test();
+
+	kasan_restore_multi_shot(multishot);
+	return -EAGAIN;
+}
+
+module_init(test_kasan_module_init);
+MODULE_LICENSE("GPL");
-- 
2.26.0.292.g33ef6b2f38-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200402204639.161637-5-trishalfonso%40google.com.
