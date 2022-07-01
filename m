Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGUH7SKQMGQEHEIORZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 48830563526
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:27 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id q15-20020a5d61cf000000b0021bc2461141sf417424wrv.5
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685467; cv=pass;
        d=google.com; s=arc-20160816;
        b=yzwuXoAnc1XoydeDi7bE/MoJ98ddLCJGDKk9SsJ5ljYeogDkorFYvMk3lLxCEvHnJH
         VyBgAN8X0gecadlsbz0QeG9I3hFDA5fZ+8Khy1FtHNwypCa2ZIVYa764QhcF7SKLNry+
         m4ILuIvyUYTfVQDq806H7LP3bJonYnNOSILQH3RjJIP8TeqNt9HipjYohc+SahwiEs48
         WM4GlNQ8vJxBv3EmSJu+/hmrxd74gbR6V0XyNMxta6fuSDIfKe0KT0CYTwOoI8bImK8i
         zDRK0fRO4anV0pxgaVIgAJdqOXAwZDC9X8UonZcarPKuY2DN5G7hDplPvI6bquhSa5ac
         Avmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=7tguyddzZlXWD/8m4hFHZOOqu01tbeM3TxFjA4Ag94I=;
        b=dNbZTM7LI2Fq2qSUE6zu8YiJIQ5P4GJhrkTdo9F5rSYI1q1ZTuoXApFtPq4A8x4VA/
         uKigqEw574V7E1qq1P8D5O2SLZieXzC2GSPtbD+7N9m3cQvVQZu+7HxJlq2dA7T+9lo1
         a0YLVHJacb/qDIy0ElFSrf9zXiscRAgPqi7pozDtewbDI79y320L3WsPcU4vBh+4tR46
         b1Tzj2VlaLj7Ppn3NhM4ebjIvVeW4r76vvydyK6HzpCnnGZfnO3CKgEITlCFkfsizVAz
         EmaASBolN4hRqZ0SfXpB+l8YNe45uqAb0nr3wpxsVSnLDwJJCGarNfmlMdtL5t86rE1r
         DTKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mkSh1163;
       spf=pass (google.com: domain of 3mqo_ygykcbgejgbcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3mQO_YgYKCbgejgbcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7tguyddzZlXWD/8m4hFHZOOqu01tbeM3TxFjA4Ag94I=;
        b=fYngZ/iGxsXwY+S00LpX6TGmbQNL2yR+5ckKhKyT0cG4tgUFIQ9I9zESiDymtIn+59
         QeViA9wc9DGh7dbvFNlbGM00S/OYib3exM8viZ7CrnAMFtMGX6GHmF0hkNjakWJFiK19
         blfGfXZhNKm/8XKNB6vRpToCOMvX7jYuN/HEgcL8we/cHYhy0p047WvhGUm1F5iYgp/4
         1j06uYtzoYspD8stR+lTqj4+gIopYlnainMI8H+yyXnztB+vERXKUjx9rpgn6i/B/T7X
         1/yc4enl91IOhsy6cf3wTbv0Wb/sJONmFX8hhdsxhhrAHDe4HL3yVwkQ/L9CiG8KzdFd
         72Ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7tguyddzZlXWD/8m4hFHZOOqu01tbeM3TxFjA4Ag94I=;
        b=r32ZWJq3BWTrWfsYCq7XjeDq3o84EKp68eJlYaBkldtqwPpoy06GAXfRjw0oOJ4CAs
         P/OWRi7A6SGT4iR8a8vwQ3iqiGNLC3mqbTomGHnqMBwmD3pOdbmrkhhixnz6WipRoSNT
         qLMcRY+kc0G64RW879Gsro6W4hUvf+bSOeOQBWcyKadZxuBI7HQMY2C2CucNKswq1ohN
         /wPZpbQqX9SfwvhvO9IU+dhDZ/b4ztWuK4TJHODO3PWsmXRJaXAgAzrvQ1Dh8ieBeAEd
         LY0C/rVhnw6JV9us5ImEHRedyZh+mn7b4Yb+RYGs2hvO0jXJaorKVt8HdZE3dbSiGC1w
         B40g==
X-Gm-Message-State: AJIora/xJfm288Os2x+RtMEK23c+loqye3TiQteGCNgm/VfrESHL6POy
	KwkM5JIt+lYucwra6ufSl1U=
X-Google-Smtp-Source: AGRyM1vXKpkQcPTf3p7d25xVJOdeeG4K3oihsV2Efz5qzotei9bCn9AOdR6KOFs3cpuUlnif2PIPEw==
X-Received: by 2002:a05:6000:381:b0:21b:9a20:7edb with SMTP id u1-20020a056000038100b0021b9a207edbmr14688910wrf.71.1656685466980;
        Fri, 01 Jul 2022 07:24:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:156e:b0:21d:2eb7:c707 with SMTP id
 14-20020a056000156e00b0021d2eb7c707ls11374137wrz.3.gmail; Fri, 01 Jul 2022
 07:24:25 -0700 (PDT)
X-Received: by 2002:a05:6000:1446:b0:21d:27ea:5a01 with SMTP id v6-20020a056000144600b0021d27ea5a01mr14214152wrx.314.1656685465918;
        Fri, 01 Jul 2022 07:24:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685465; cv=none;
        d=google.com; s=arc-20160816;
        b=wPvgflv8TU2mw3T2jaKjxC5eVnYJD1eyViwlltgQMnGoZLMGkZ4gdVKvz2OzuNK6BD
         iTtCjKmJ/pu1NDZbjhJ/73BnJlhzwkJ3NH4g6Z331XZR+bMG90kAXxxRe1EqGlQneheX
         G0dFL46MPxSPeC2oqtFyRUdOFkod9GSKEKCarmG47uq1pZaxD7/Ibz1JfzyvBLf1o0BQ
         P+sWVAmJteMunMAvmWxASPrNQ+EkmEmd8Jo2I/fAGgNNzQNFwFNAUkDZAPRVAVXh1j1C
         ztV1lU1xx63TsmvlF7DZ4YulO2HxZ9LOpoNuNiMplYAXzFxCDLQ8jM/wyBQ/xMecUZqY
         xd1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=p+ekp6Bf711YmRVy7UlZIiEYvCGAcUihcnJb8tTtmyA=;
        b=y+fYZzIQ9wBIOUP3YtiyGjKf1ZEri/Kyg6dtfjosW1hbK7MRHVlw79wHLxvDZcld2Q
         PAG5NXSb90qxkIby8FMKP0PpmKvP0mPwZb1FeshjHGDTzLQE0IhHbv38XUUEFEouiVlZ
         Rt1ZQqvHCkoAdO9H8jmLvyeXuYWuq5Nr6/tikKTRBKrkN6t4Ar5exZ7geEUWH4MKw2Gq
         YQ5D1Hfhl26AlVxqxvRWcGuYZbvHx+Hks+XD1nfwYcpXnv068/Yn4k7Bz2aexwMQt8yg
         pCoM5xSojkHljJZLXctX80jjjJstz1sWf/iXQfwEVWDMvTrwFDYzsKL7bLHaXD/CTCIv
         GZVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mkSh1163;
       spf=pass (google.com: domain of 3mqo_ygykcbgejgbcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3mQO_YgYKCbgejgbcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id x11-20020adfdccb000000b0021bbdc3209asi781512wrm.1.2022.07.01.07.24.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mqo_ygykcbgejgbcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id qa41-20020a17090786a900b00722f313a60eso835568ejc.13
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:25 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6402:50f:b0:435:7996:e90f with SMTP id
 m15-20020a056402050f00b004357996e90fmr19229751edv.110.1656685465511; Fri, 01
 Jul 2022 07:24:25 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:50 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-26-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 25/45] kmsan: add tests for KMSAN
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=mkSh1163;       spf=pass
 (google.com: domain of 3mqo_ygykcbgejgbcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3mQO_YgYKCbgejgbcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

The testing module triggers KMSAN warnings in different cases and checks
that the errors are properly reported, using console probes to capture
the tool's output.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
 -- add memcpy tests

v4:
 -- change sizeof(type) to sizeof(*ptr)
 -- add test expectations for CONFIG_KMSAN_CHECK_PARAM_RETVAL

Link: https://linux-review.googlesource.com/id/I49c3f59014cc37fd13541c80beb0b75a75244650
---
 lib/Kconfig.kmsan     |  12 +
 mm/kmsan/Makefile     |   4 +
 mm/kmsan/kmsan_test.c | 552 ++++++++++++++++++++++++++++++++++++++++++
 3 files changed, 568 insertions(+)
 create mode 100644 mm/kmsan/kmsan_test.c

diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
index 8f768d4034e3c..f56ed7f7c7090 100644
--- a/lib/Kconfig.kmsan
+++ b/lib/Kconfig.kmsan
@@ -47,4 +47,16 @@ config KMSAN_CHECK_PARAM_RETVAL
 	  may potentially report errors in corner cases when non-instrumented
 	  functions call instrumented ones.
 
+config KMSAN_KUNIT_TEST
+	tristate "KMSAN integration test suite" if !KUNIT_ALL_TESTS
+	default KUNIT_ALL_TESTS
+	depends on TRACEPOINTS && KUNIT
+	help
+	  Test suite for KMSAN, testing various error detection scenarios,
+	  and checking that reports are correctly output to console.
+
+	  Say Y here if you want the test to be built into the kernel and run
+	  during boot; say M if you want the test to build as a module; say N
+	  if you are unsure.
+
 endif
diff --git a/mm/kmsan/Makefile b/mm/kmsan/Makefile
index 401acb1a491ce..98eab2856626f 100644
--- a/mm/kmsan/Makefile
+++ b/mm/kmsan/Makefile
@@ -22,3 +22,7 @@ CFLAGS_init.o := $(CC_FLAGS_KMSAN_RUNTIME)
 CFLAGS_instrumentation.o := $(CC_FLAGS_KMSAN_RUNTIME)
 CFLAGS_report.o := $(CC_FLAGS_KMSAN_RUNTIME)
 CFLAGS_shadow.o := $(CC_FLAGS_KMSAN_RUNTIME)
+
+obj-$(CONFIG_KMSAN_KUNIT_TEST) += kmsan_test.o
+KMSAN_SANITIZE_kmsan_test.o := y
+CFLAGS_kmsan_test.o += $(call cc-disable-warning, uninitialized)
diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
new file mode 100644
index 0000000000000..1b8da71ae0d4f
--- /dev/null
+++ b/mm/kmsan/kmsan_test.c
@@ -0,0 +1,552 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Test cases for KMSAN.
+ * For each test case checks the presence (or absence) of generated reports.
+ * Relies on 'console' tracepoint to capture reports as they appear in the
+ * kernel log.
+ *
+ * Copyright (C) 2021-2022, Google LLC.
+ * Author: Alexander Potapenko <glider@google.com>
+ *
+ */
+
+#include <kunit/test.h>
+#include "kmsan.h"
+
+#include <linux/jiffies.h>
+#include <linux/kernel.h>
+#include <linux/kmsan.h>
+#include <linux/mm.h>
+#include <linux/random.h>
+#include <linux/slab.h>
+#include <linux/spinlock.h>
+#include <linux/string.h>
+#include <linux/tracepoint.h>
+#include <trace/events/printk.h>
+
+static DEFINE_PER_CPU(int, per_cpu_var);
+
+/* Report as observed from console. */
+static struct {
+	spinlock_t lock;
+	bool available;
+	bool ignore; /* Stop console output collection. */
+	char header[256];
+} observed = {
+	.lock = __SPIN_LOCK_UNLOCKED(observed.lock),
+};
+
+/* Probe for console output: obtains observed lines of interest. */
+static void probe_console(void *ignore, const char *buf, size_t len)
+{
+	unsigned long flags;
+
+	if (observed.ignore)
+		return;
+	spin_lock_irqsave(&observed.lock, flags);
+
+	if (strnstr(buf, "BUG: KMSAN: ", len)) {
+		/*
+		 * KMSAN report and related to the test.
+		 *
+		 * The provided @buf is not NUL-terminated; copy no more than
+		 * @len bytes and let strscpy() add the missing NUL-terminator.
+		 */
+		strscpy(observed.header, buf,
+			min(len + 1, sizeof(observed.header)));
+		WRITE_ONCE(observed.available, true);
+		observed.ignore = true;
+	}
+	spin_unlock_irqrestore(&observed.lock, flags);
+}
+
+/* Check if a report related to the test exists. */
+static bool report_available(void)
+{
+	return READ_ONCE(observed.available);
+}
+
+/* Information we expect in a report. */
+struct expect_report {
+	const char *error_type; /* Error type. */
+	/*
+	 * Kernel symbol from the error header, or NULL if no report is
+	 * expected.
+	 */
+	const char *symbol;
+};
+
+/* Check observed report matches information in @r. */
+static bool report_matches(const struct expect_report *r)
+{
+	typeof(observed.header) expected_header;
+	unsigned long flags;
+	bool ret = false;
+	const char *end;
+	char *cur;
+
+	/* Doubled-checked locking. */
+	if (!report_available() || !r->symbol)
+		return (!report_available() && !r->symbol);
+
+	/* Generate expected report contents. */
+
+	/* Title */
+	cur = expected_header;
+	end = &expected_header[sizeof(expected_header) - 1];
+
+	cur += scnprintf(cur, end - cur, "BUG: KMSAN: %s", r->error_type);
+
+	scnprintf(cur, end - cur, " in %s", r->symbol);
+	/* The exact offset won't match, remove it; also strip module name. */
+	cur = strchr(expected_header, '+');
+	if (cur)
+		*cur = '\0';
+
+	spin_lock_irqsave(&observed.lock, flags);
+	if (!report_available())
+		goto out; /* A new report is being captured. */
+
+	/* Finally match expected output to what we actually observed. */
+	ret = strstr(observed.header, expected_header);
+out:
+	spin_unlock_irqrestore(&observed.lock, flags);
+
+	return ret;
+}
+
+/* ===== Test cases ===== */
+
+/* Prevent replacing branch with select in LLVM. */
+static noinline void check_true(char *arg)
+{
+	pr_info("%s is true\n", arg);
+}
+
+static noinline void check_false(char *arg)
+{
+	pr_info("%s is false\n", arg);
+}
+
+#define USE(x)                                                                 \
+	do {                                                                   \
+		if (x)                                                         \
+			check_true(#x);                                        \
+		else                                                           \
+			check_false(#x);                                       \
+	} while (0)
+
+#define EXPECTATION_ETYPE_FN(e, reason, fn)                                    \
+	struct expect_report e = {                                             \
+		.error_type = reason,                                          \
+		.symbol = fn,                                                  \
+	}
+
+#define EXPECTATION_NO_REPORT(e) EXPECTATION_ETYPE_FN(e, NULL, NULL)
+#define EXPECTATION_UNINIT_VALUE_FN(e, fn)                                     \
+	EXPECTATION_ETYPE_FN(e, "uninit-value", fn)
+#define EXPECTATION_UNINIT_VALUE(e) EXPECTATION_UNINIT_VALUE_FN(e, __func__)
+#define EXPECTATION_USE_AFTER_FREE(e)                                          \
+	EXPECTATION_ETYPE_FN(e, "use-after-free", __func__)
+
+/* Test case: ensure that kmalloc() returns uninitialized memory. */
+static void test_uninit_kmalloc(struct kunit *test)
+{
+	EXPECTATION_UNINIT_VALUE(expect);
+	int *ptr;
+
+	kunit_info(test, "uninitialized kmalloc test (UMR report)\n");
+	ptr = kmalloc(sizeof(*ptr), GFP_KERNEL);
+	USE(*ptr);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/*
+ * Test case: ensure that kmalloc'ed memory becomes initialized after memset().
+ */
+static void test_init_kmalloc(struct kunit *test)
+{
+	EXPECTATION_NO_REPORT(expect);
+	int *ptr;
+
+	kunit_info(test, "initialized kmalloc test (no reports)\n");
+	ptr = kmalloc(sizeof(*ptr), GFP_KERNEL);
+	memset(ptr, 0, sizeof(*ptr));
+	USE(*ptr);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/* Test case: ensure that kzalloc() returns initialized memory. */
+static void test_init_kzalloc(struct kunit *test)
+{
+	EXPECTATION_NO_REPORT(expect);
+	int *ptr;
+
+	kunit_info(test, "initialized kzalloc test (no reports)\n");
+	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
+	USE(*ptr);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/* Test case: ensure that local variables are uninitialized by default. */
+static void test_uninit_stack_var(struct kunit *test)
+{
+	EXPECTATION_UNINIT_VALUE(expect);
+	volatile int cond;
+
+	kunit_info(test, "uninitialized stack variable (UMR report)\n");
+	USE(cond);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/* Test case: ensure that local variables with initializers are initialized. */
+static void test_init_stack_var(struct kunit *test)
+{
+	EXPECTATION_NO_REPORT(expect);
+	volatile int cond = 1;
+
+	kunit_info(test, "initialized stack variable (no reports)\n");
+	USE(cond);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+static noinline void two_param_fn_2(int arg1, int arg2)
+{
+	USE(arg1);
+	USE(arg2);
+}
+
+static noinline void one_param_fn(int arg)
+{
+	two_param_fn_2(arg, arg);
+	USE(arg);
+}
+
+static noinline void two_param_fn(int arg1, int arg2)
+{
+	int init = 0;
+
+	one_param_fn(init);
+	USE(arg1);
+	USE(arg2);
+}
+
+static void test_params(struct kunit *test)
+{
+#ifdef CONFIG_KMSAN_CHECK_PARAM_RETVAL
+	/*
+	 * With eager param/retval checking enabled, KMSAN will report an error
+	 * before the call to two_param_fn().
+	 */
+	EXPECTATION_UNINIT_VALUE_FN(expect, "test_params");
+#else
+	EXPECTATION_UNINIT_VALUE_FN(expect, "two_param_fn");
+#endif
+	volatile int uninit, init = 1;
+
+	kunit_info(test,
+		   "uninit passed through a function parameter (UMR report)\n");
+	two_param_fn(uninit, init);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+static int signed_sum3(int a, int b, int c)
+{
+	return a + b + c;
+}
+
+/*
+ * Test case: ensure that uninitialized values are tracked through function
+ * arguments.
+ */
+static void test_uninit_multiple_params(struct kunit *test)
+{
+	EXPECTATION_UNINIT_VALUE(expect);
+	volatile char b = 3, c;
+	volatile int a;
+
+	kunit_info(test, "uninitialized local passed to fn (UMR report)\n");
+	USE(signed_sum3(a, b, c));
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/* Helper function to make an array uninitialized. */
+static noinline void do_uninit_local_array(char *array, int start, int stop)
+{
+	volatile char uninit;
+	int i;
+
+	for (i = start; i < stop; i++)
+		array[i] = uninit;
+}
+
+/*
+ * Test case: ensure kmsan_check_memory() reports an error when checking
+ * uninitialized memory.
+ */
+static void test_uninit_kmsan_check_memory(struct kunit *test)
+{
+	EXPECTATION_UNINIT_VALUE_FN(expect, "test_uninit_kmsan_check_memory");
+	volatile char local_array[8];
+
+	kunit_info(
+		test,
+		"kmsan_check_memory() called on uninit local (UMR report)\n");
+	do_uninit_local_array((char *)local_array, 5, 7);
+
+	kmsan_check_memory((char *)local_array, 8);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/*
+ * Test case: check that a virtual memory range created with vmap() from
+ * initialized pages is still considered as initialized.
+ */
+static void test_init_kmsan_vmap_vunmap(struct kunit *test)
+{
+	EXPECTATION_NO_REPORT(expect);
+	const int npages = 2;
+	struct page **pages;
+	void *vbuf;
+	int i;
+
+	kunit_info(test, "pages initialized via vmap (no reports)\n");
+
+	pages = kmalloc_array(npages, sizeof(*pages), GFP_KERNEL);
+	for (i = 0; i < npages; i++)
+		pages[i] = alloc_page(GFP_KERNEL);
+	vbuf = vmap(pages, npages, VM_MAP, PAGE_KERNEL);
+	memset(vbuf, 0xfe, npages * PAGE_SIZE);
+	for (i = 0; i < npages; i++)
+		kmsan_check_memory(page_address(pages[i]), PAGE_SIZE);
+
+	if (vbuf)
+		vunmap(vbuf);
+	for (i = 0; i < npages; i++)
+		if (pages[i])
+			__free_page(pages[i]);
+	kfree(pages);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/*
+ * Test case: ensure that memset() can initialize a buffer allocated via
+ * vmalloc().
+ */
+static void test_init_vmalloc(struct kunit *test)
+{
+	EXPECTATION_NO_REPORT(expect);
+	int npages = 8, i;
+	char *buf;
+
+	kunit_info(test, "vmalloc buffer can be initialized (no reports)\n");
+	buf = vmalloc(PAGE_SIZE * npages);
+	buf[0] = 1;
+	memset(buf, 0xfe, PAGE_SIZE * npages);
+	USE(buf[0]);
+	for (i = 0; i < npages; i++)
+		kmsan_check_memory(&buf[PAGE_SIZE * i], PAGE_SIZE);
+	vfree(buf);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/* Test case: ensure that use-after-free reporting works. */
+static void test_uaf(struct kunit *test)
+{
+	EXPECTATION_USE_AFTER_FREE(expect);
+	volatile int value;
+	volatile int *var;
+
+	kunit_info(test, "use-after-free in kmalloc-ed buffer (UMR report)\n");
+	var = kmalloc(80, GFP_KERNEL);
+	var[3] = 0xfeedface;
+	kfree((int *)var);
+	/* Copy the invalid value before checking it. */
+	value = var[3];
+	USE(value);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/*
+ * Test case: ensure that uninitialized values are propagated through per-CPU
+ * memory.
+ */
+static void test_percpu_propagate(struct kunit *test)
+{
+	EXPECTATION_UNINIT_VALUE(expect);
+	volatile int uninit, check;
+
+	kunit_info(test,
+		   "uninit local stored to per_cpu memory (UMR report)\n");
+
+	this_cpu_write(per_cpu_var, uninit);
+	check = this_cpu_read(per_cpu_var);
+	USE(check);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/*
+ * Test case: ensure that passing uninitialized values to printk() leads to an
+ * error report.
+ */
+static void test_printk(struct kunit *test)
+{
+#ifdef CONFIG_KMSAN_CHECK_PARAM_RETVAL
+	/*
+	 * With eager param/retval checking enabled, KMSAN will report an error
+	 * before the call to pr_info().
+	 */
+	EXPECTATION_UNINIT_VALUE_FN(expect, "test_printk");
+#else
+	EXPECTATION_UNINIT_VALUE_FN(expect, "number");
+#endif
+	volatile int uninit;
+
+	kunit_info(test, "uninit local passed to pr_info() (UMR report)\n");
+	pr_info("%px contains %d\n", &uninit, uninit);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/*
+ * Test case: ensure that memcpy() correctly copies uninitialized values between
+ * aligned `src` and `dst`.
+ */
+static void test_memcpy_aligned_to_aligned(struct kunit *test)
+{
+	EXPECTATION_UNINIT_VALUE_FN(expect, "test_memcpy_aligned_to_aligned");
+	volatile int uninit_src;
+	volatile int dst = 0;
+
+	kunit_info(test, "memcpy()ing aligned uninit src to aligned dst (UMR report)\n");
+	memcpy((void *)&dst, (void *)&uninit_src, sizeof(uninit_src));
+	kmsan_check_memory((void *)&dst, sizeof(dst));
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/*
+ * Test case: ensure that memcpy() correctly copies uninitialized values between
+ * aligned `src` and unaligned `dst`.
+ *
+ * Copying aligned 4-byte value to an unaligned one leads to touching two
+ * aligned 4-byte values. This test case checks that KMSAN correctly reports an
+ * error on the first of the two values.
+ */
+static void test_memcpy_aligned_to_unaligned(struct kunit *test)
+{
+	EXPECTATION_UNINIT_VALUE_FN(expect, "test_memcpy_aligned_to_unaligned");
+	volatile int uninit_src;
+	volatile char dst[8] = {0};
+
+	kunit_info(test, "memcpy()ing aligned uninit src to unaligned dst (UMR report)\n");
+	memcpy((void *)&dst[1], (void *)&uninit_src, sizeof(uninit_src));
+	kmsan_check_memory((void *)dst, 4);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/*
+ * Test case: ensure that memcpy() correctly copies uninitialized values between
+ * aligned `src` and unaligned `dst`.
+ *
+ * Copying aligned 4-byte value to an unaligned one leads to touching two
+ * aligned 4-byte values. This test case checks that KMSAN correctly reports an
+ * error on the second of the two values.
+ */
+static void test_memcpy_aligned_to_unaligned2(struct kunit *test)
+{
+	EXPECTATION_UNINIT_VALUE_FN(expect, "test_memcpy_aligned_to_unaligned2");
+	volatile int uninit_src;
+	volatile char dst[8] = {0};
+
+	kunit_info(test, "memcpy()ing aligned uninit src to unaligned dst - part 2 (UMR report)\n");
+	memcpy((void *)&dst[1], (void *)&uninit_src, sizeof(uninit_src));
+	kmsan_check_memory((void *)&dst[4], sizeof(uninit_src));
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+static struct kunit_case kmsan_test_cases[] = {
+	KUNIT_CASE(test_uninit_kmalloc),
+	KUNIT_CASE(test_init_kmalloc),
+	KUNIT_CASE(test_init_kzalloc),
+	KUNIT_CASE(test_uninit_stack_var),
+	KUNIT_CASE(test_init_stack_var),
+	KUNIT_CASE(test_params),
+	KUNIT_CASE(test_uninit_multiple_params),
+	KUNIT_CASE(test_uninit_kmsan_check_memory),
+	KUNIT_CASE(test_init_kmsan_vmap_vunmap),
+	KUNIT_CASE(test_init_vmalloc),
+	KUNIT_CASE(test_uaf),
+	KUNIT_CASE(test_percpu_propagate),
+	KUNIT_CASE(test_printk),
+	KUNIT_CASE(test_memcpy_aligned_to_aligned),
+	KUNIT_CASE(test_memcpy_aligned_to_unaligned),
+	KUNIT_CASE(test_memcpy_aligned_to_unaligned2),
+	{},
+};
+
+/* ===== End test cases ===== */
+
+static int test_init(struct kunit *test)
+{
+	unsigned long flags;
+
+	spin_lock_irqsave(&observed.lock, flags);
+	observed.header[0] = '\0';
+	observed.ignore = false;
+	observed.available = false;
+	spin_unlock_irqrestore(&observed.lock, flags);
+
+	return 0;
+}
+
+static void test_exit(struct kunit *test)
+{
+}
+
+static struct kunit_suite kmsan_test_suite = {
+	.name = "kmsan",
+	.test_cases = kmsan_test_cases,
+	.init = test_init,
+	.exit = test_exit,
+};
+static struct kunit_suite *kmsan_test_suites[] = { &kmsan_test_suite, NULL };
+
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
+/*
+ * We only want to do tracepoints setup and teardown once, therefore we have to
+ * customize the init and exit functions and cannot rely on kunit_test_suite().
+ */
+static int __init kmsan_test_init(void)
+{
+	/*
+	 * Because we want to be able to build the test as a module, we need to
+	 * iterate through all known tracepoints, since the static registration
+	 * won't work here.
+	 */
+	for_each_kernel_tracepoint(register_tracepoints, NULL);
+	return __kunit_test_suites_init(kmsan_test_suites);
+}
+
+static void kmsan_test_exit(void)
+{
+	__kunit_test_suites_exit(kmsan_test_suites);
+	for_each_kernel_tracepoint(unregister_tracepoints, NULL);
+	tracepoint_synchronize_unregister();
+}
+
+late_initcall_sync(kmsan_test_init);
+module_exit(kmsan_test_exit);
+
+MODULE_LICENSE("GPL v2");
+MODULE_AUTHOR("Alexander Potapenko <glider@google.com>");
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-26-glider%40google.com.
