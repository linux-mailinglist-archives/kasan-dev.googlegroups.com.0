Return-Path: <kasan-dev+bncBAABBPU2XWMQMGQENXCBYVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 2188D5E8F57
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 20:32:31 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id c6-20020a05640227c600b004521382116dsf2301652ede.22
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 11:32:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664044350; cv=pass;
        d=google.com; s=arc-20160816;
        b=x+cOoOlPMWfFk6bYboLhze98rjmaCaKIAzD9W9ZQc6h75MbfRQjoI/NC156spSql49
         77OVtBgrs1Jyb06cPUu1un2/EeUtegiIkDsPEZ7vDd1ud5X9wqDtVlT0EHLMfcIdtxom
         BKrT122orGERRqpzuS/RvLltCZYpxUDwHGK7WbrF+8ngz3VuAMlLmuEJIbQHmamMOsXK
         Sme6vjYAP8DkrOpERjLmivYv+lIy/3Pz2LXOUdfRqL7Y6YyGTzT6gxe5uR3BQNHUodKg
         128HCPBkeXNFjyaP0X5uNqPmcBNQRmJPTsBW0jXnIZI2jnPQhBXKnJJmm9rL8Gr26N30
         WiTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=6H7NFKZktX8+eMBVr7dLqJiCKj4QEweIWqSBRRCtio0=;
        b=tDmgzJINkKueA/eJg2hVmSPJx+2vxRim2d6If6vKHAc2CZbYdetEz78xRxzYds77xX
         pW2f9huppfVcIQ0eTa8q5Zd2F3LojrJRL6+n5aeVCyjTLnqcrjHV62GGwArMe0wBonC7
         loPx8ODHQP5MS8D9VqCf7M+isxGUm2XzLbU372o6T5txM6DCkkKDy1158qRvIAoStVpu
         iYRgIcWPTfyXP/hrsDHH4LbqlK75Wl3vL24OHYblYzzwHgvAKpF3y/OniZYwtkpxZP7M
         /LYPX9q18MUgJN/KBbMuUqA0VGAxivrK+kX2lzH2z9I+AGCJDlV7OTs21b2HVVBP0+I8
         n0JA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZQl61kJN;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date;
        bh=6H7NFKZktX8+eMBVr7dLqJiCKj4QEweIWqSBRRCtio0=;
        b=dvcZP3tecB1+e3sUv/P6xwm9DvxBwCo5ssN0rB3C3KG0+cfZR8fonghtpJrwZF20Q+
         +Iw1YtyENOUU+ZmwpQKYGdRGPW89JIiQfEkzMOKVKqNDuMBAx2j6SgC5Lu5wHoVQWzY5
         gF7HCQ/0XvxUj4Yf0YX32Mv2zEAm8DbxbsUnEeotGB9T0mtm1WQYcw3UOn70/mOzZ6vT
         RTfoKAwZ0Z/o9s8Etq8bz45GTMRiPpo3NsC6cTsjujprmxww3xABJkoi4ShwH+tLrv1Q
         Q/p9mONSzqVQKjPBRz+CEPOpQAkgZDZIl5xJEOw0Ff7Kg3+F4A5VYIt3fkE6uNpdfGL0
         TbPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date;
        bh=6H7NFKZktX8+eMBVr7dLqJiCKj4QEweIWqSBRRCtio0=;
        b=4E8Zvt0nxF7CC3EV1uvXJj5cSHTbO9NplNyejYu5h505vQBtRmttptGkhAS+D3stiM
         qycgPc6nCIFUAHZOPuum08xPaXbasoxkYoUqc6svsaR5YFW/IYsRN0B4rg/UkySxUHG0
         /rOy5X9hqYgPDJZykgT0yvzY6xGW2l5KS+hn2Nzwyp3pHTSNsrpCAyw00tykCiRRkNVP
         6ZOdJqIXd5CpRPklfc/6lu3e5OsKVGwChF+O24aqhB/CLH+nHumHF6IMTY1nQeyLlnNN
         J+qibMUyvZye/yEgth87GMYuttPHt/fNyw+crE0MWzimmF171Hp5TJjQ9cBx+OVCWaOB
         22jA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3MDhMRDRSZPLXGsbxFczMKOpYt6wt7EMZwGDvJu1ytG/uLWtna
	UuOAIZzv9rdCttvcHomyeu8=
X-Google-Smtp-Source: AMsMyM7BlETIZvqAiuwWSm+Zexi3XIiQ4Rn9I1tleWUe8UKtvJLPwKg0qSVAJZcoKPj/IYfsvp8TMQ==
X-Received: by 2002:a17:907:2724:b0:779:7545:5df6 with SMTP id d4-20020a170907272400b0077975455df6mr11869215ejl.325.1664044350440;
        Sat, 24 Sep 2022 11:32:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:a84f:b0:780:2712:35d2 with SMTP id
 dx15-20020a170906a84f00b00780271235d2ls5029318ejb.4.-pod-prod-gmail; Sat, 24
 Sep 2022 11:32:29 -0700 (PDT)
X-Received: by 2002:a17:906:db0c:b0:77b:7d7d:5805 with SMTP id xj12-20020a170906db0c00b0077b7d7d5805mr12447731ejb.726.1664044349473;
        Sat, 24 Sep 2022 11:32:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664044349; cv=none;
        d=google.com; s=arc-20160816;
        b=xhkCFvSm7tPZdxtKchCIR/Q75D2cAc2TQoxG2a8EGx6JBQ2iweuVmbtdRtoVhzQ+rw
         H9RLNdvg8/YgyphoRKNSVvTkXGTnPcBMqkPFqy562GoYzFcHrQ+rzUdW1gdmoy2eN1Hb
         0yWnRpa/YPL+uW/2hhbHw9nnjojNKa5hwvXuQIit1XOvyzTOQLvRdCbTYNeEg4ocxpJ9
         HBpsDrRGDfti0OcowZThaSj3suTa/rPbvAV1/N3yzczP7RUMv+n5cuaUsX5+hcdHJf1F
         KJ5g4m/C7spYOdDd8Usw9zXy4BqBd+pX7XPleFCtYriAdYdxymr+Zgl0fcHkXRSGg8da
         q3DQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=LPWNXNjTpdk69QTCVlET8VJ/JJ9a2GtSBbDdH4cFLZE=;
        b=p6qKBMgoKNmGA7YSsdO11PIePgwh2BbZUQSLg9Z3L13YIbfRwRVwyodRz9vMWglKsg
         3ZsAPr1d8UuNVwDa15Ew9OpvDVGyBGsgMIUBcqir9AFTGi33j9IDWR2/sYCbk41l3Kb2
         RNbl4It8qySZRUUrGF0UFIu9SlHnb1zab3kAlrEV0SiMUj5p5l7/Gc2oToREuTeN4o6E
         nW5rx8KRHr9lTNq8ahymVyjHPG2Cun9o8F7FEPL88v9kW2vgWvKMiFBAfH20TNfPqRmg
         spKrt+Roilfxvs5aOKbS490jJueqrFK5SXApQ9PhnBAp7fiqllu7/0Z+zew0e5mfGnE5
         29/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZQl61kJN;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id o7-20020a056402038700b00450f1234f2csi475331edv.0.2022.09.24.11.32.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 24 Sep 2022 11:32:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH mm 1/3] kasan: switch kunit tests to console tracepoints
Date: Sat, 24 Sep 2022 20:31:51 +0200
Message-Id: <653d43e9a6d9aad2ae148a941dab048cb8e765a8.1664044241.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ZQl61kJN;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
 lib/Kconfig.kasan     |  2 +-
 mm/kasan/kasan_test.c | 85 +++++++++++++++++++++++++++++++------------
 mm/kasan/report.c     | 31 ----------------
 3 files changed, 63 insertions(+), 55 deletions(-)

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/653d43e9a6d9aad2ae148a941dab048cb8e765a8.1664044241.git.andreyknvl%40google.com.
