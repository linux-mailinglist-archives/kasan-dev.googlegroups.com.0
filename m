Return-Path: <kasan-dev+bncBAABBO64ZSMQMGQE5KMSNLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id AE9055ECA81
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 19:09:16 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id e1-20020a2e9841000000b002602ebb584fsf2824861ljj.14
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 10:09:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664298556; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZfHDFPQnQHJLCScCkUzpEnwjSJLRI9Wty4yDsp+K9rw4SFREeHU/BFrMAP85myNmdS
         y1h1WGE0Tsoutq9edlP1wea8QFAk0NFEhUtr83sJlPd1fB/zjORQpkrs4qfZ4i477Vnz
         QriZ+3xqsqqdIcmEHyWNEhFxqv1XtEfP0hKhkC/iALI6USsDyGaAmLPvGiKgVJ8rFqEs
         nE5nKz5XtrRt/3FwOFnBdFvyFWNEmol70rNd/qwUXrm/pDCk0D1qkA/GdK+PvJgdJssr
         I14XjuPPZW9Ae8cMBVciSSfgXTcJH1PQrQWBqLHPO0xUS5vswQox87POzeh90fdt5Txn
         +QOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=bhPW7ok9Rh6kSzHvT9CGC7cq6dyD8ELaAcQoZkiCZec=;
        b=fYWUPMn/XHekdAraupdrbM1nR40LEFDWuGVn0D4DMyExivuBnfrWjeK2RQayAnLQ6i
         9B/eGZpTGgkmn/4DtxEvlPmDvpcAi0m8SNosZtG+ZULHo+oDI1ALzqknkB8mcqJ8i0Oi
         ed2OINRXp24nUX8a9I/yTE6Rw0dZMVhveJw22pZGWL5SMlBc1ZFMs0iVZ+f0kIvto/fN
         lG8zvdsnWry6DZHjbfw7FD2+uV3GQRYv5caxUcBiUS42g3LocWVF1R2ljN0qTxs1j6Zr
         JxtaeSffCYWS0zVB9jyA/4SoiWbiZ3II3DxjIMzJKOBTFmn/GCMjLBGvF7oKM+P0CZ34
         ayNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZN0iDdJd;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date;
        bh=bhPW7ok9Rh6kSzHvT9CGC7cq6dyD8ELaAcQoZkiCZec=;
        b=noZ9gKfNo9d9r4bel+ZhXO0IWudD8YtseV/JVU5IvAfXCqrZRb9oEhyxW+DMmdaH4v
         yRykp47AJE6yBRvwZAYBjJp2Iixm4jnQ3y7DLxP269M9vB/F+sQiHFPnJFRVvs/IHA5q
         neeJniyA6BSWbUULsiiroInsaKBZGfUp0YyPZRX/buZAslWssrnlAkkaSuyRWe7VmSnL
         wSAwkQ2W13JLRw5TnxJeNdCvw4Qn9/ExCr6aSs30lh8vHtpuv6ogjCD1WAipkHMInU9o
         2YsJ8t6/lM8Orxwcd6rlOb+OBne82yZZRB7CidlfebuzIFBNfDvZrF8GZJtOPi7IEAAz
         O7fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date;
        bh=bhPW7ok9Rh6kSzHvT9CGC7cq6dyD8ELaAcQoZkiCZec=;
        b=KU0UihiX/BjC1BkkJNnUtuSQ6r868+GnXuInjAvmpg96AVT0bc+GzJZ1X0/coFE7/W
         MsWK/Ehmn1EEE3BIvetDOV+J/FjSHKt2vFwbhf9YE0jr1GorhXHo47uiWIbaAEQUrP9o
         pzfHxVA6BZAX0jJmyjSZgjykuiie9XRe7Btjzb7xcSeFI4LpmGTBhd5QQdM4Esq6PSfj
         3dpL0xl2IDbRnUrhZsOjMNpKKpIdDeolvmVB3PLSdCfQm5bhn/hoqu+ku7J7zYrMQERB
         JpB6PjnKY4RioKjmYxq7TXQ7i9WGLC2VK0d0FxrvKZINqj5dgQlQ4QZOcwCUDuSMBfhW
         sqYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3GikwBlbH4nNEVEWFDaoJwaVx+IYbjSZGh/XHTRG1oPz5C/4OP
	Cuj6sYpIxwChvHv47qnRtpQ=
X-Google-Smtp-Source: AMsMyM6INXqXQgDSX233nNxc5QEsYZFgbATWyPbN3FT1Ie2iocyag2o1d1lHrgTV7snYUZglU30/6A==
X-Received: by 2002:a05:651c:1694:b0:26c:5624:6d37 with SMTP id bd20-20020a05651c169400b0026c56246d37mr10086770ljb.500.1664298555964;
        Tue, 27 Sep 2022 10:09:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:46da:0:b0:48b:2227:7787 with SMTP id p26-20020ac246da000000b0048b22277787ls1348983lfo.3.-pod-prod-gmail;
 Tue, 27 Sep 2022 10:09:15 -0700 (PDT)
X-Received: by 2002:a05:6512:1697:b0:4a0:d52d:af7 with SMTP id bu23-20020a056512169700b004a0d52d0af7mr8351950lfb.554.1664298555074;
        Tue, 27 Sep 2022 10:09:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664298555; cv=none;
        d=google.com; s=arc-20160816;
        b=ZY3BpC4qmqd8ckiIciY0/eTVApqC5axXKKw/abHlndz7iF6UcvAZ/rC+sU1B5Gzf2x
         n0JCGHxJ3lJaK6/6fR9jH5HceGHQ3DVCC7p1D5jgAHtowpLW+mKTs7mVJSVtJLMbT9GG
         UevJJ87kGF9ZEP2REtVYGp0jU7/DxGejm+D/SnEsWyOqVYNhGKGT2OL1WxVX2RMsLxI6
         +DXQtwoK0ZvhxE2Jg0KoMCBf46FD40B7GlM2Ynhw1AJLLP5qjSjazFPWnwfay5kTOahj
         T9dBoILDl0tnlrPIAGmTpwUcUOriuE3eNZxvzldj+R1M1nEEh544P4LqI4LjpDBCZ1Xb
         tK8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=DqjIhl52wYynPPWyKfKv9xe5zkU2UZKWhsfljx76tNo=;
        b=eSUzT3Hgn8s6iAkroo9cx1ci6regn0NyI0dCI6GgypdYQ7RhDIJVzEMfksv5PFTdxt
         dxGVHh32Ajlr193pcFZaNHflo0TLANjzgvXwsKIRA32c3NVh8Y0zVh5IawfddYWgkI/p
         MZ0dMKbrlGJSmWDoh+h8wnyrUpNfh9hZrKTTwfxT0X28gjrU4ew6SNSYaE01AoeDmz3e
         NUPPFUqaFY1vcdpH8W1HPMZtW+oT2GznMifaLbOMm3ti/voikI2csM6YNiAwA5DIZi2S
         LqN6fjThyyH+1dRD9yUGIAVSpMs3P4jAH0RQkRfA3/3wGEpDaCCxM9K+itZ7q2sXARN0
         ia+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZN0iDdJd;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id j15-20020a056512108f00b0048b38f379d7si87407lfg.0.2022.09.27.10.09.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Sep 2022 10:09:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 1/3] kasan: switch kunit tests to console tracepoints
Date: Tue, 27 Sep 2022 19:09:09 +0200
Message-Id: <9345acdd11e953b207b0ed4724ff780e63afeb36.1664298455.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ZN0iDdJd;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Switch KUnit-compatible KASAN tests from using per-task KUnit resources
to console tracepoints.

This allows for two things:

1. Migrating tests that trigger a KASAN report in the context of a task
   other than current to KUnit framework.
   This is implemented in the patches that follow.

2. Parsing and matching the contents of KASAN reports.
   This is not yet implemented.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Remove kunit_kasan_status struct definition.
---
 lib/Kconfig.kasan     |  2 +-
 mm/kasan/kasan.h      |  8 ----
 mm/kasan/kasan_test.c | 85 +++++++++++++++++++++++++++++++------------
 mm/kasan/report.c     | 31 ----------------
 4 files changed, 63 insertions(+), 63 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index ca09b1cf8ee9..ba5b27962c34 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -181,7 +181,7 @@ config KASAN_VMALLOC
 
 config KASAN_KUNIT_TEST
 	tristate "KUnit-compatible tests of KASAN bug detection capabilities" if !KUNIT_ALL_TESTS
-	depends on KASAN && KUNIT
+	depends on KASAN && KUNIT && TRACEPOINTS
 	default KUNIT_ALL_TESTS
 	help
 	  A KUnit-based KASAN test suite. Triggers different kinds of
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index abbcc1b0eec5..a84491bc4867 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -261,14 +261,6 @@ struct kasan_stack_ring {
 
 #endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
-#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
-/* Used in KUnit-compatible KASAN tests. */
-struct kunit_kasan_status {
-	bool report_found;
-	bool sync_fault;
-};
-#endif
-
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index f25692def781..3a2886f85e69 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -5,8 +5,12 @@
  * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
  */
 
+#define pr_fmt(fmt) "kasan_test: " fmt
+
+#include <kunit/test.h>
 #include <linux/bitops.h>
 #include <linux/delay.h>
+#include <linux/io.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
 #include <linux/mm.h>
@@ -14,21 +18,28 @@
 #include <linux/module.h>
 #include <linux/printk.h>
 #include <linux/random.h>
+#include <linux/set_memory.h>
 #include <linux/slab.h>
 #include <linux/string.h>
+#include <linux/tracepoint.h>
 #include <linux/uaccess.h>
-#include <linux/io.h>
 #include <linux/vmalloc.h>
-#include <linux/set_memory.h>
+#include <trace/events/printk.h>
 
 #include <asm/page.h>
 
-#include <kunit/test.h>
-
 #include "kasan.h"
 
 #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
 
+static bool multishot;
+
+/* Fields set based on lines observed in the console. */
+static struct {
+	bool report_found;
+	bool async_fault;
+} test_status;
+
 /*
  * Some tests use these global variables to store return values from function
  * calls that could otherwise be eliminated by the compiler as dead code.
@@ -36,35 +47,61 @@
 void *kasan_ptr_result;
 int kasan_int_result;
 
-static struct kunit_resource resource;
-static struct kunit_kasan_status test_status;
-static bool multishot;
+/* Probe for console output: obtains test_status lines of interest. */
+static void probe_console(void *ignore, const char *buf, size_t len)
+{
+	if (strnstr(buf, "BUG: KASAN: ", len))
+		WRITE_ONCE(test_status.report_found, true);
+	else if (strnstr(buf, "Asynchronous fault: ", len))
+		WRITE_ONCE(test_status.async_fault, true);
+}
 
-/*
- * Temporarily enable multi-shot mode. Otherwise, KASAN would only report the
- * first detected bug and panic the kernel if panic_on_warn is enabled. For
- * hardware tag-based KASAN also allow tag checking to be reenabled for each
- * test, see the comment for KUNIT_EXPECT_KASAN_FAIL().
- */
-static int kasan_test_init(struct kunit *test)
+static void register_tracepoints(struct tracepoint *tp, void *ignore)
+{
+	check_trace_callback_type_console(probe_console);
+	if (!strcmp(tp->name, "console"))
+		WARN_ON(tracepoint_probe_register(tp, probe_console, NULL));
+}
+
+static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
+{
+	if (!strcmp(tp->name, "console"))
+		tracepoint_probe_unregister(tp, probe_console, NULL);
+}
+
+static int kasan_suite_init(struct kunit_suite *suite)
 {
 	if (!kasan_enabled()) {
-		kunit_err(test, "can't run KASAN tests with KASAN disabled");
+		pr_err("Can't run KASAN tests with KASAN disabled");
 		return -1;
 	}
 
+	/*
+	 * Temporarily enable multi-shot mode. Otherwise, KASAN would only
+	 * report the first detected bug and panic the kernel if panic_on_warn
+	 * is enabled.
+	 */
 	multishot = kasan_save_enable_multi_shot();
-	test_status.report_found = false;
-	test_status.sync_fault = false;
-	kunit_add_named_resource(test, NULL, NULL, &resource,
-					"kasan_status", &test_status);
+
+	/*
+	 * Because we want to be able to build the test as a module, we need to
+	 * iterate through all known tracepoints, since the static registration
+	 * won't work here.
+	 */
+	for_each_kernel_tracepoint(register_tracepoints, NULL);
 	return 0;
 }
 
-static void kasan_test_exit(struct kunit *test)
+static void kasan_suite_exit(struct kunit_suite *suite)
 {
 	kasan_restore_multi_shot(multishot);
-	KUNIT_EXPECT_FALSE(test, test_status.report_found);
+	for_each_kernel_tracepoint(unregister_tracepoints, NULL);
+	tracepoint_synchronize_unregister();
+}
+
+static void kasan_test_exit(struct kunit *test)
+{
+	KUNIT_EXPECT_FALSE(test, READ_ONCE(test_status.report_found));
 }
 
 /**
@@ -106,11 +143,12 @@ static void kasan_test_exit(struct kunit *test)
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&				\
 	    kasan_sync_fault_possible()) {				\
 		if (READ_ONCE(test_status.report_found) &&		\
-		    READ_ONCE(test_status.sync_fault))			\
+		    !READ_ONCE(test_status.async_fault))		\
 			kasan_enable_tagging();				\
 		migrate_enable();					\
 	}								\
 	WRITE_ONCE(test_status.report_found, false);			\
+	WRITE_ONCE(test_status.async_fault, false);			\
 } while (0)
 
 #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {			\
@@ -1440,9 +1478,10 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 
 static struct kunit_suite kasan_kunit_test_suite = {
 	.name = "kasan",
-	.init = kasan_test_init,
 	.test_cases = kasan_kunit_test_cases,
 	.exit = kasan_test_exit,
+	.suite_init = kasan_suite_init,
+	.suite_exit = kasan_suite_exit,
 };
 
 kunit_test_suite(kasan_kunit_test_suite);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 39e8e5a80b82..f23d51a27414 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -30,8 +30,6 @@
 
 #include <asm/sections.h>
 
-#include <kunit/test.h>
-
 #include "kasan.h"
 #include "../slab.h"
 
@@ -114,41 +112,12 @@ EXPORT_SYMBOL_GPL(kasan_restore_multi_shot);
 
 #endif
 
-#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
-static void update_kunit_status(bool sync)
-{
-	struct kunit *test;
-	struct kunit_resource *resource;
-	struct kunit_kasan_status *status;
-
-	test = current->kunit_test;
-	if (!test)
-		return;
-
-	resource = kunit_find_named_resource(test, "kasan_status");
-	if (!resource) {
-		kunit_set_failure(test);
-		return;
-	}
-
-	status = (struct kunit_kasan_status *)resource->data;
-	WRITE_ONCE(status->report_found, true);
-	WRITE_ONCE(status->sync_fault, sync);
-
-	kunit_put_resource(resource);
-}
-#else
-static void update_kunit_status(bool sync) { }
-#endif
-
 static DEFINE_SPINLOCK(report_lock);
 
 static void start_report(unsigned long *flags, bool sync)
 {
 	/* Respect the /proc/sys/kernel/traceoff_on_warning interface. */
 	disable_trace_on_warning();
-	/* Update status of the currently running KASAN test. */
-	update_kunit_status(sync);
 	/* Do not allow LOCKDEP mangling KASAN reports. */
 	lockdep_off();
 	/* Make sure we don't end up in loop. */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9345acdd11e953b207b0ed4724ff780e63afeb36.1664298455.git.andreyknvl%40google.com.
