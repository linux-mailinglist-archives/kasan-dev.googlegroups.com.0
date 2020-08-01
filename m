Return-Path: <kasan-dev+bncBC6OLHHDVUOBBUNKST4QKGQEYFU6IRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id AA9782350EB
	for <lists+kasan-dev@lfdr.de>; Sat,  1 Aug 2020 09:10:10 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id t79sf20933981ild.5
        for <lists+kasan-dev@lfdr.de>; Sat, 01 Aug 2020 00:10:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596265809; cv=pass;
        d=google.com; s=arc-20160816;
        b=wmBlCK7s0IdRj0sYzpGAoiaxmPJY26Zf+SUa+/9OUveipvZ3M0xGWToYDSocuGcQIx
         wXrqBDkQBcYg5hI1yOHx6QqaQxGx1MPrSOyYom42kM5U2YxfIFVrVoa2s44L0AZiHML6
         Gn+BPpEjSxdFEEdE1+yD1gQ8pxHd5xJtRCh77zo3iEWGq74lEQCjPQCtSppa8ivIUs+6
         ntc6IZuNfqCZKlL3A0H3bv7c8RYWrMWS7tY/nkcRv/orJ5PWXMDWyIfgxPsxmYBw4wPG
         hbGukqrlXOZx6fWlch0/VA9QFnijRU+SlyQj7BRzwdXoMie6DuUE+RJxe5IQYQ6SWeYg
         ycoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=S1YfMu/WBZsItIVIof0/gEFLMt0JcmxS1xFdAtyw54c=;
        b=LG5FbmVHuOMeUz5PpDcY/atvpU0fWckaMxP1M3MzkqApbM7povi+qE0pd7sclCbvRs
         RaCakPxjro7lJQC+PZoZRwOgABNS15v02j7Fjs0GX+tiDTYp4m/xnn3kcQ8Lcx+rATSS
         RwWTtw8GxAKcMvQ83TkzHtAGIGV1ICJLM5Cdcvr9x9PLZD7ot8+JXHl4zL7EwLA/jjpZ
         Wb14SgIXdmgm0DT2Ac8mrnLkSe0I71ZM+scEKP9atAkgl28BwniB1zTu3mpWsJnahQ+9
         j4omJZudf1L1+lDhsvfp1ZzllZSJ3Pzs9+BS6YFUfO5fEHxgL6vGuMdW90NA25oJn0u3
         emNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OTyGmWt6;
       spf=pass (google.com: domain of 3ubulxwgkcq8spaxsv3bv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3UBUlXwgKCQ8spAxsv3Bv33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S1YfMu/WBZsItIVIof0/gEFLMt0JcmxS1xFdAtyw54c=;
        b=krmijVb7uLgv8pDABX9cFCxfoWJEJYH7Kclx6mTiqvSiV2pZK9cZ7M0fZ1oKIGTeGy
         UApcPZJweWEsZERzT+OV1vORa+nvObA563mW530S71ilZ7+oFQj/BikRa9WzK7RR7juy
         58nONcAoAFqN15bBvodSlWUouuUMfhs4ukAToIN45MMj5MXJctFfPjl39wYL+7phwn4P
         SxHcVzjl/zsW25BuURpfI/8LcViNnga+nvNKUrGXnir54HDDtduCBOoO8h/oiMC/P9R6
         MgBYdoBX4NrPkjfKG8k16CZGIk2vdOXAUdByqyOPkbas+UKkmRxtjQVt6OpakK/+XKK0
         8VQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S1YfMu/WBZsItIVIof0/gEFLMt0JcmxS1xFdAtyw54c=;
        b=Nw9nNr+zI2qjLJJO91BcF+JAvmPVegFbwn/USvCFvQlsQmvqYsSTYPsikgCXlf8bX+
         01bgPXUwyz1O1FOkeJJc0Vge2F/eyHD7xdNBAXhuKRTTo8bwIt+uIITwV3LpO0/ec9k1
         HDqcKPgHcnGR4LJ3TtW0/4EFGuHIacQkq5qC/oU71j7HgtXp6iyajh1kCLMozCRaFb4D
         zvQvcWb3cEkNte3KI3NmLWT2PUDr0oxdoXFvFBPHKzlhlJM7YRJ+DDJiX6MGbLdUDANk
         9t6l87Rx7BVUGS+ruMkJXhRQH/06XYXbPoY/rbzhHdpPsvOLbmRHX9M2jj/ocAkFhu6r
         HYSg==
X-Gm-Message-State: AOAM531Yv53CX2y1TVZKtNJBbxUzIRtdUB88sCj+TA9Sviln5KpjoWjl
	7Nt2PSpAgWV4e54aIKMofC4=
X-Google-Smtp-Source: ABdhPJw66iYM+0LUNoT2eDQTkPLKatroW0aXV3rI9nuA0vIJtcfl13pLxv0VWKCnMu05lfML6Ejt7A==
X-Received: by 2002:a92:d1ce:: with SMTP id u14mr7251582ilg.270.1596265809643;
        Sat, 01 Aug 2020 00:10:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ab10:: with SMTP id v16ls3071284ilh.10.gmail; Sat, 01
 Aug 2020 00:10:09 -0700 (PDT)
X-Received: by 2002:a92:330f:: with SMTP id a15mr6987408ilf.158.1596265809241;
        Sat, 01 Aug 2020 00:10:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596265809; cv=none;
        d=google.com; s=arc-20160816;
        b=IcZ0fEHqpdw55wPW7S2gCprOWYzJ/wAxcOImZiBS0xEQAFjkStUes0U/wEuYgqUvpt
         9gAfdz4sj9n9B7u3usjjR1QrFfiJCG2sXGb5WgdwJiPJCZOIdYkPefxVfHRQR1GnlYWH
         qKl1JZChDi87EbdusGEzNx3fwVM+1KDqrNXxebBZCTBQjzg5kusj/Z3UABCERcAPYZQb
         1FcPLp/7ebti/AybkJdycyknEyUNaJff9F0lWXG1ITxTSTPEdiXZ8K8NXWUmfUMvqS5w
         jCfIHWNW2kmaBoPi/xaIMXBsXIrtom0LDO6Ymzf5l1OoPNDwA7JYJKxjP+bM6TkssHpX
         LSBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=fMsTtiLWraWx+qtRg3S1jHkCNvn3tCrc3TaWq+mkPqg=;
        b=quy3TYsjt3Knn08layWy+CQT++NosziWRV3Vu8JAB0d0m66BCd+Mdze8VAchkYOk7p
         3cIV1yecDnPtGSsngaudD3KEoa9i7jGh2qdeUqcvQTQGdso2kP78Wi2Svg/VUfghl+H+
         PtageZ/U4svoogcEQbgkZT5xZbNbaaFBA4qiRgyaoXs6+Ro+lBJ0ZCQJtTRh30++Qu5j
         WFg72pq4/KLDV/fOLei0ow0gfNPQLF+rjoYArGApC4ygTWvs6hlHn21r0M7D2T+4UO7J
         YkWZlQ3mZtksze47sJoRYFDnBtwTAb/TL1U4Jmwj+RhnFBRuCBlx0m4W6dyak6IqwdLb
         EJHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OTyGmWt6;
       spf=pass (google.com: domain of 3ubulxwgkcq8spaxsv3bv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3UBUlXwgKCQ8spAxsv3Bv33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id j127si182991iof.4.2020.08.01.00.10.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 01 Aug 2020 00:10:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ubulxwgkcq8spaxsv3bv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id v5so16949235qvr.1
        for <kasan-dev@googlegroups.com>; Sat, 01 Aug 2020 00:10:09 -0700 (PDT)
X-Received: by 2002:a0c:ffc6:: with SMTP id h6mr7594428qvv.251.1596265808465;
 Sat, 01 Aug 2020 00:10:08 -0700 (PDT)
Date: Sat,  1 Aug 2020 00:09:22 -0700
In-Reply-To: <20200801070924.1786166-1-davidgow@google.com>
Message-Id: <20200801070924.1786166-4-davidgow@google.com>
Mime-Version: 1.0
References: <20200801070924.1786166-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v10 3/5] KASAN: Port KASAN Tests to KUnit
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
 header.i=@google.com header.s=20161025 header.b=OTyGmWt6;       spf=pass
 (google.com: domain of 3ubulxwgkcq8spaxsv3bv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3UBUlXwgKCQ8spAxsv3Bv33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--davidgow.bounces.google.com;
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

copy_user_test and kasan_rcu_uaf cannot be run in KUnit so there is a
separate test file for those tests, which can be run as before as a
module.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
Signed-off-by: David Gow <davidgow@google.com>
Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
 lib/Kconfig.kasan       |  22 +-
 lib/Makefile            |   7 +-
 lib/kasan_kunit.c       | 770 ++++++++++++++++++++++++++++++++
 lib/test_kasan.c        | 946 ----------------------------------------
 lib/test_kasan_module.c | 111 +++++
 5 files changed, 902 insertions(+), 954 deletions(-)
 create mode 100644 lib/kasan_kunit.c
 delete mode 100644 lib/test_kasan.c
 create mode 100644 lib/test_kasan_module.c

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 047b53dbfd58..9a237887e52e 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -167,12 +167,24 @@ config KASAN_VMALLOC
 	  for KASAN to detect more sorts of errors (and to support vmapped
 	  stacks), but at the cost of higher memory usage.
 
-config TEST_KASAN
-	tristate "Module for testing KASAN for bug detection"
-	depends on m
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
+
 endif # KASAN
diff --git a/lib/Makefile b/lib/Makefile
index 46278be53cda..8a530bf7078c 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -60,9 +60,10 @@ CFLAGS_test_bitops.o += -Werror
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
diff --git a/lib/kasan_kunit.c b/lib/kasan_kunit.c
new file mode 100644
index 000000000000..8a01009d91e4
--- /dev/null
+++ b/lib/kasan_kunit.c
@@ -0,0 +1,770 @@
+// SPDX-License-Identifier: GPL-2.0-only
+/*
+ *
+ * Copyright (c) 2014 Samsung Electronics Co., Ltd.
+ * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
+ */
+
+#include <linux/bitops.h>
+#include <linux/delay.h>
+#include <linux/kasan.h>
+#include <linux/kernel.h>
+#include <linux/mm.h>
+#include <linux/mman.h>
+#include <linux/module.h>
+#include <linux/printk.h>
+#include <linux/slab.h>
+#include <linux/string.h>
+#include <linux/uaccess.h>
+#include <linux/io.h>
+#include <linux/vmalloc.h>
+
+#include <asm/page.h>
+
+#include <kunit/test.h>
+
+#include "../mm/kasan/kasan.h"
+
+#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_SHADOW_SCALE_SIZE)
+
+/*
+ * We assign some test results to these globals to make sure the tests
+ * are not eliminated as dead code.
+ */
+
+void *kasan_ptr_result;
+int kasan_int_result;
+
+static struct kunit_resource resource;
+static struct kunit_kasan_expectation fail_data;
+static bool multishot;
+
+static int kasan_test_init(struct kunit *test)
+{
+	/*
+	 * Temporarily enable multi-shot mode and set panic_on_warn=0.
+	 * Otherwise, we'd only get a report for the first case.
+	 */
+	multishot = kasan_save_enable_multi_shot();
+
+	return 0;
+}
+
+static void kasan_test_exit(struct kunit *test)
+{
+	kasan_restore_multi_shot(multishot);
+}
+
+/**
+ * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
+ * not cause a KASAN error. This uses a KUnit resource named "kasan_data." Do
+ * Do not use this name for a KUnit resource outside here.
+ *
+ */
+#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do { \
+	fail_data.report_expected = true; \
+	fail_data.report_found = false; \
+	kunit_add_named_resource(test, \
+				NULL, \
+				NULL, \
+				&resource, \
+				"kasan_data", &fail_data); \
+	condition; \
+	KUNIT_EXPECT_EQ(test, \
+			fail_data.report_expected, \
+			fail_data.report_found); \
+} while (0)
+
+static void kmalloc_oob_right(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 123;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 'x');
+	kfree(ptr);
+}
+
+static void kmalloc_oob_left(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 15;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, *ptr = *(ptr - 1));
+	kfree(ptr);
+}
+
+static void kmalloc_node_oob_right(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 4096;
+
+	ptr = kmalloc_node(size, GFP_KERNEL, 0);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
+	kfree(ptr);
+}
+
+static void kmalloc_pagealloc_oob_right(struct kunit *test)
+{
+	char *ptr;
+	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
+
+	if (!IS_ENABLED(CONFIG_SLUB)) {
+		kunit_info(test, "CONFIG_SLUB is not enabled.");
+		return;
+	}
+
+	/* Allocate a chunk that does not fit into a SLUB cache to trigger
+	 * the page allocator fallback.
+	 */
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 0);
+	kfree(ptr);
+}
+
+static void kmalloc_pagealloc_uaf(struct kunit *test)
+{
+	char *ptr;
+	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
+
+	if (!IS_ENABLED(CONFIG_SLUB)) {
+		kunit_info(test, "CONFIG_SLUB is not enabled.");
+		return;
+	}
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	kfree(ptr);
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
+}
+
+static void kmalloc_pagealloc_invalid_free(struct kunit *test)
+{
+	char *ptr;
+	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
+
+	if (!IS_ENABLED(CONFIG_SLUB)) {
+		kunit_info(test, "CONFIG_SLUB is not enabled.");
+		return;
+	}
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, kfree(ptr + 1));
+}
+
+static void kmalloc_large_oob_right(struct kunit *test)
+{
+	char *ptr;
+	size_t size = KMALLOC_MAX_CACHE_SIZE - 256;
+	/* Allocate a chunk that is large enough, but still fits into a slab
+	 * and does not trigger the page allocator fallback in SLUB.
+	 */
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
+	kfree(ptr);
+}
+
+static void kmalloc_oob_krealloc_more(struct kunit *test)
+{
+	char *ptr1, *ptr2;
+	size_t size1 = 17;
+	size_t size2 = 19;
+
+	ptr1 = kmalloc(size1, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
+
+	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2 + OOB_TAG_OFF] = 'x');
+	kfree(ptr2);
+}
+
+static void kmalloc_oob_krealloc_less(struct kunit *test)
+{
+	char *ptr1, *ptr2;
+	size_t size1 = 17;
+	size_t size2 = 15;
+
+	ptr1 = kmalloc(size1, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
+
+	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2 + OOB_TAG_OFF] = 'x');
+	kfree(ptr2);
+}
+
+static void kmalloc_oob_16(struct kunit *test)
+{
+	struct {
+		u64 words[2];
+	} *ptr1, *ptr2;
+
+	ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
+
+	ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
+	kfree(ptr1);
+	kfree(ptr2);
+}
+
+static void kmalloc_oob_memset_2(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 8;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 7 + OOB_TAG_OFF, 0, 2));
+	kfree(ptr);
+}
+
+static void kmalloc_oob_memset_4(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 8;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 5 + OOB_TAG_OFF, 0, 4));
+	kfree(ptr);
+}
+
+
+static void kmalloc_oob_memset_8(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 8;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 1 + OOB_TAG_OFF, 0, 8));
+	kfree(ptr);
+}
+
+static void kmalloc_oob_memset_16(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 16;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 1 + OOB_TAG_OFF, 0, 16));
+	kfree(ptr);
+}
+
+static void kmalloc_oob_in_memset(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 666;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr, 0, size + 5 + OOB_TAG_OFF));
+	kfree(ptr);
+}
+
+static void kmalloc_memmove_invalid_size(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 64;
+	volatile size_t invalid_size = -2;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	memset((char *)ptr, 0, 64);
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
+	kfree(ptr);
+}
+
+static void kmalloc_uaf(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 10;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	kfree(ptr);
+	KUNIT_EXPECT_KASAN_FAIL(test, *(ptr + 8) = 'x');
+}
+
+static void kmalloc_uaf_memset(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 33;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	kfree(ptr);
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr, 0, size));
+}
+
+static void kmalloc_uaf2(struct kunit *test)
+{
+	char *ptr1, *ptr2;
+	size_t size = 43;
+
+	ptr1 = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
+
+	kfree(ptr1);
+
+	ptr2 = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr1[40] = 'x');
+	KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
+
+	kfree(ptr2);
+}
+
+static void kfree_via_page(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 8;
+	struct page *page;
+	unsigned long offset;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	page = virt_to_page(ptr);
+	offset = offset_in_page(ptr);
+	kfree(page_address(page) + offset);
+}
+
+static void kfree_via_phys(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 8;
+	phys_addr_t phys;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	phys = virt_to_phys(ptr);
+	kfree(phys_to_virt(phys));
+}
+
+static void kmem_cache_oob(struct kunit *test)
+{
+	char *p;
+	size_t size = 200;
+	struct kmem_cache *cache = kmem_cache_create("test_cache",
+						size, 0,
+						0, NULL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+	p = kmem_cache_alloc(cache, GFP_KERNEL);
+	if (!p) {
+		kunit_err(test, "Allocation failed: %s\n", __func__);
+		kmem_cache_destroy(cache);
+		return;
+	}
+
+	KUNIT_EXPECT_KASAN_FAIL(test, *p = p[size + OOB_TAG_OFF]);
+	kmem_cache_free(cache, p);
+	kmem_cache_destroy(cache);
+}
+
+static void memcg_accounted_kmem_cache(struct kunit *test)
+{
+	int i;
+	char *p;
+	size_t size = 200;
+	struct kmem_cache *cache;
+
+	cache = kmem_cache_create("test_cache", size, 0, SLAB_ACCOUNT, NULL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+
+	/*
+	 * Several allocations with a delay to allow for lazy per memcg kmem
+	 * cache creation.
+	 */
+	for (i = 0; i < 5; i++) {
+		p = kmem_cache_alloc(cache, GFP_KERNEL);
+		if (!p)
+			goto free_cache;
+
+		kmem_cache_free(cache, p);
+		msleep(100);
+	}
+
+free_cache:
+	kmem_cache_destroy(cache);
+}
+
+static char global_array[10];
+
+static void kasan_global_oob(struct kunit *test)
+{
+	volatile int i = 3;
+	char *p = &global_array[ARRAY_SIZE(global_array) + i];
+
+	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
+}
+
+static void ksize_unpoisons_memory(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 123, real_size;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+	real_size = ksize(ptr);
+	/* This access doesn't trigger an error. */
+	ptr[size] = 'x';
+	/* This one does. */
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[real_size] = 'y');
+	kfree(ptr);
+}
+
+static void kasan_stack_oob(struct kunit *test)
+{
+	char stack_array[10];
+	volatile int i = OOB_TAG_OFF;
+	char *p = &stack_array[ARRAY_SIZE(stack_array) + i];
+
+	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
+		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
+		return;
+	}
+
+	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
+}
+
+static void kasan_alloca_oob_left(struct kunit *test)
+{
+	volatile int i = 10;
+	char alloca_array[i];
+	char *p = alloca_array - 1;
+
+	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
+		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
+		return;
+	}
+
+	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
+}
+
+static void kasan_alloca_oob_right(struct kunit *test)
+{
+	volatile int i = 10;
+	char alloca_array[i];
+	char *p = alloca_array + i;
+
+	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
+		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
+		return;
+	}
+
+	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
+}
+
+static void kmem_cache_double_free(struct kunit *test)
+{
+	char *p;
+	size_t size = 200;
+	struct kmem_cache *cache;
+
+	cache = kmem_cache_create("test_cache", size, 0, 0, NULL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+
+	p = kmem_cache_alloc(cache, GFP_KERNEL);
+	if (!p) {
+		kunit_err(test, "Allocation failed: %s\n", __func__);
+		kmem_cache_destroy(cache);
+		return;
+	}
+
+	kmem_cache_free(cache, p);
+	KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_free(cache, p));
+	kmem_cache_destroy(cache);
+}
+
+static void kmem_cache_invalid_free(struct kunit *test)
+{
+	char *p;
+	size_t size = 200;
+	struct kmem_cache *cache;
+
+	cache = kmem_cache_create("test_cache", size, 0, SLAB_TYPESAFE_BY_RCU,
+				  NULL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+
+	p = kmem_cache_alloc(cache, GFP_KERNEL);
+	if (!p) {
+		kunit_err(test, "Allocation failed: %s\n", __func__);
+		kmem_cache_destroy(cache);
+		return;
+	}
+
+	/* Trigger invalid free, the object doesn't get freed */
+	KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_free(cache, p + 1));
+
+	/*
+	 * Properly free the object to prevent the "Objects remaining in
+	 * test_cache on __kmem_cache_shutdown" BUG failure.
+	 */
+	kmem_cache_free(cache, p);
+
+	kmem_cache_destroy(cache);
+}
+
+static void kasan_memchr(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 24;
+
+	/* See https://bugzilla.kernel.org/show_bug.cgi?id=206337 */
+	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
+		kunit_info(test,
+			"str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
+		return;
+	}
+
+	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		kasan_ptr_result = memchr(ptr, '1', size + 1));
+
+	kasan_ptr_result = memchr(ptr, '1', size + 1);
+	kfree(ptr);
+}
+
+static void kasan_memcmp(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 24;
+	int arr[9];
+
+	/* See https://bugzilla.kernel.org/show_bug.cgi?id=206337 */
+	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
+		kunit_info(test,
+			"str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
+ 		return;
+	}
+
+	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+	memset(arr, 0, sizeof(arr));
+ 
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		kasan_int_result = memcmp(ptr, arr, size+1));
+	kfree(ptr);
+}
+
+static void kasan_strings(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 24;
+
+	/* See https://bugzilla.kernel.org/show_bug.cgi?id=206337 */
+	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
+		kunit_info(test,
+			"str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
+ 		return;
+	}
+
+	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	kfree(ptr);
+
+	/*
+	 * Try to cause only 1 invalid access (less spam in dmesg).
+	 * For that we need ptr to point to zeroed byte.
+	 * Skip metadata that could be stored in freed object so ptr
+	 * will likely point to zeroed byte.
+	 */
+	ptr += 16;
+	KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result = strchr(ptr, '1'));
+
+	KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result = strrchr(ptr, '1'));
+
+	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strcmp(ptr, "2"));
+
+	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strncmp(ptr, "2", 1));
+
+	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strlen(ptr));
+
+	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strnlen(ptr, 1));
+}
+
+static void kasan_bitops(struct kunit *test)
+{
+	/*
+	 * Allocate 1 more byte, which causes kzalloc to round up to 16-bytes;
+	 * this way we do not actually corrupt other memory.
+	 */
+	long *bits = kzalloc(sizeof(*bits) + 1, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, bits);
+
+	/*
+	 * Below calls try to access bit within allocated memory; however, the
+	 * below accesses are still out-of-bounds, since bitops are defined to
+	 * operate on the whole long the bit is in.
+	 */
+	KUNIT_EXPECT_KASAN_FAIL(test, set_bit(BITS_PER_LONG, bits));
+
+	KUNIT_EXPECT_KASAN_FAIL(test, __set_bit(BITS_PER_LONG, bits));
+
+	KUNIT_EXPECT_KASAN_FAIL(test, clear_bit(BITS_PER_LONG, bits));
+
+	KUNIT_EXPECT_KASAN_FAIL(test, __clear_bit(BITS_PER_LONG, bits));
+
+	KUNIT_EXPECT_KASAN_FAIL(test, clear_bit_unlock(BITS_PER_LONG, bits));
+
+	KUNIT_EXPECT_KASAN_FAIL(test, __clear_bit_unlock(BITS_PER_LONG, bits));
+
+	KUNIT_EXPECT_KASAN_FAIL(test, change_bit(BITS_PER_LONG, bits));
+
+	KUNIT_EXPECT_KASAN_FAIL(test, __change_bit(BITS_PER_LONG, bits));
+
+	/*
+	 * Below calls try to access bit beyond allocated memory.
+	 */
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		__test_and_set_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		test_and_set_bit_lock(BITS_PER_LONG + BITS_PER_BYTE, bits));
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		__test_and_clear_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		__test_and_change_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		kasan_int_result =
+			test_bit(BITS_PER_LONG + BITS_PER_BYTE, bits));
+
+#if defined(clear_bit_unlock_is_negative_byte)
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		kasan_int_result = clear_bit_unlock_is_negative_byte(
+			BITS_PER_LONG + BITS_PER_BYTE, bits));
+#endif
+	kfree(bits);
+}
+
+static void kmalloc_double_kzfree(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 16;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	kfree_sensitive(ptr);
+	KUNIT_EXPECT_KASAN_FAIL(test, kfree_sensitive(ptr));
+}
+
+static void vmalloc_oob(struct kunit *test)
+{
+	void *area;
+
+	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
+		kunit_info(test, "CONFIG_KASAN_VMALLOC is not enabled.");
+		return;
+	}
+
+	/*
+	 * We have to be careful not to hit the guard page.
+	 * The MMU will catch that and crash us.
+	 */
+	area = vmalloc(3000);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, area);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)area)[3100]);
+	vfree(area);
+}
+
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
+	KUNIT_CASE(kmalloc_memmove_invalid_size),
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
+	.name = "kasan",
+	.init = kasan_test_init,
+	.test_cases = kasan_kunit_test_cases,
+	.exit = kasan_test_exit,
+};
+
+kunit_test_suite(kasan_kunit_test_suite);
+
+MODULE_LICENSE("GPL");
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
deleted file mode 100644
index 58bffadd8367..000000000000
--- a/lib/test_kasan.c
+++ /dev/null
@@ -1,946 +0,0 @@
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
-#include "../mm/kasan/kasan.h"
-
-#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_SHADOW_SCALE_SIZE)
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
-	ptr[size + OOB_TAG_OFF] = 'x';
-
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
-	ptr[size + OOB_TAG_OFF] = 0;
-
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
-	ptr2[size2 + OOB_TAG_OFF] = 'x';
-
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
-
-	ptr2[size2 + OOB_TAG_OFF] = 'x';
-
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
-	memset(ptr + 7 + OOB_TAG_OFF, 0, 2);
-
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
-	memset(ptr + 5 + OOB_TAG_OFF, 0, 4);
-
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
-	memset(ptr + 1 + OOB_TAG_OFF, 0, 8);
-
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
-	memset(ptr + 1 + OOB_TAG_OFF, 0, 16);
-
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
-	memset(ptr, 0, size + 5 + OOB_TAG_OFF);
-
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
-	*p = p[size + OOB_TAG_OFF];
-
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
-	volatile int i = OOB_TAG_OFF;
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
-	unused = copy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
-
-	pr_info("out-of-bounds in copy_to_user()\n");
-	unused = copy_to_user(usermem, kmem, size + 1 + OOB_TAG_OFF);
-
-	pr_info("out-of-bounds in __copy_from_user()\n");
-	unused = __copy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
-
-	pr_info("out-of-bounds in __copy_to_user()\n");
-	unused = __copy_to_user(usermem, kmem, size + 1 + OOB_TAG_OFF);
-
-	pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
-	unused = __copy_from_user_inatomic(kmem, usermem, size + 1 + OOB_TAG_OFF);
-
-	pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
-	unused = __copy_to_user_inatomic(usermem, kmem, size + 1 + OOB_TAG_OFF);
-
-	pr_info("out-of-bounds in strncpy_from_user()\n");
-	unused = strncpy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
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
-	pr_info("double-free (kfree_sensitive)\n");
-	ptr = kmalloc(size, GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	kfree_sensitive(ptr);
-	kfree_sensitive(ptr);
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
-static struct kasan_rcu_info {
-	int i;
-	struct rcu_head rcu;
-} *global_rcu_ptr;
-
-static noinline void __init kasan_rcu_reclaim(struct rcu_head *rp)
-{
-	struct kasan_rcu_info *fp = container_of(rp,
-						struct kasan_rcu_info, rcu);
-
-	kfree(fp);
-	fp->i = 1;
-}
-
-static noinline void __init kasan_rcu_uaf(void)
-{
-	struct kasan_rcu_info *ptr;
-
-	pr_info("use-after-free in kasan_rcu_reclaim\n");
-	ptr = kmalloc(sizeof(struct kasan_rcu_info), GFP_KERNEL);
-	if (!ptr) {
-		pr_err("Allocation failed\n");
-		return;
-	}
-
-	global_rcu_ptr = rcu_dereference_protected(ptr, NULL);
-	call_rcu(&global_rcu_ptr->rcu, kasan_rcu_reclaim);
-}
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
-	kasan_rcu_uaf();
-
-	kasan_restore_multi_shot(multishot);
-
-	return -EAGAIN;
-}
-
-module_init(kmalloc_tests_init);
-MODULE_LICENSE("GPL");
diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
new file mode 100644
index 000000000000..2d68db6ae67b
--- /dev/null
+++ b/lib/test_kasan_module.c
@@ -0,0 +1,111 @@
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
+#include "../mm/kasan/kasan.h"
+
+#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_SHADOW_SCALE_SIZE)
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
+	unused = copy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
+
+	pr_info("out-of-bounds in copy_to_user()\n");
+	unused = copy_to_user(usermem, kmem, size + 1 + OOB_TAG_OFF);
+
+	pr_info("out-of-bounds in __copy_from_user()\n");
+	unused = __copy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
+
+	pr_info("out-of-bounds in __copy_to_user()\n");
+	unused = __copy_to_user(usermem, kmem, size + 1 + OOB_TAG_OFF);
+
+	pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
+	unused = __copy_from_user_inatomic(kmem, usermem, size + 1 + OOB_TAG_OFF);
+
+	pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
+	unused = __copy_to_user_inatomic(usermem, kmem, size + 1 + OOB_TAG_OFF);
+
+	pr_info("out-of-bounds in strncpy_from_user()\n");
+	unused = strncpy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
+
+	vm_munmap((unsigned long)usermem, PAGE_SIZE);
+	kfree(kmem);
+}
+
+static struct kasan_rcu_info {
+	int i;
+	struct rcu_head rcu;
+} *global_rcu_ptr;
+
+static noinline void __init kasan_rcu_reclaim(struct rcu_head *rp)
+{
+	struct kasan_rcu_info *fp = container_of(rp,
+						struct kasan_rcu_info, rcu);
+
+	kfree(fp);
+	fp->i = 1;
+}
+
+static noinline void __init kasan_rcu_uaf(void)
+{
+	struct kasan_rcu_info *ptr;
+
+	pr_info("use-after-free in kasan_rcu_reclaim\n");
+	ptr = kmalloc(sizeof(struct kasan_rcu_info), GFP_KERNEL);
+	if (!ptr) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	global_rcu_ptr = rcu_dereference_protected(ptr, NULL);
+	call_rcu(&global_rcu_ptr->rcu, kasan_rcu_reclaim);
+}
+
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
+	kasan_rcu_uaf();
+
+	kasan_restore_multi_shot(multishot);
+	return -EAGAIN;
+}
+
+module_init(test_kasan_module_init);
+MODULE_LICENSE("GPL");
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200801070924.1786166-4-davidgow%40google.com.
