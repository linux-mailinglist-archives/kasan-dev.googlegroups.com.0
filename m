Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWOX4D6AKGQEQ5XP4OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C81A29B024
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 15:16:58 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id i1sf786332wrb.18
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 07:16:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603808218; cv=pass;
        d=google.com; s=arc-20160816;
        b=rJLpDd1kUC2ywae+aO8cZzLM4eX+loWoVTXFFqIOA3MQ7dgZmm2x2rccBt2O4cJ4NZ
         9gU272wwXGtTxVLT9GXtZqfMIlvzyUhX/nw0iSmlzUylChUmZWjo/90oRtlVKA7l59Gx
         AC1f310PdRr6n/ALOPRZDEeFZL1FqRToNqkfIQq/x07VpqZVFPTJnM5eCz6i7qOGm2jk
         vj9ciUH3UYSlIi+Sox+jU1WtMla5uwdv0B3PTCOw24RcsQenzYmIVvCf3yNDzznsYvj0
         YBjoR7hhGHF1Mi4GgFL2HF8JLV3NoZ4EqvrHSCSoXgO3yxOxYSkSEXHa/uLenBrjuBo1
         2HBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=3T1hAaf6EsSWOaYIsHDXvj1Y9ZYvaJV6qmgAu1dZz44=;
        b=iBye2uD7vik2No43bun/N7tQxbAP8MXP3PJ8aktdYWV9RI/GHrM2Ey89axRBn9XqbK
         TKmUknb9yypAEvUq4vjw2ZU+L3odFkFHYMSsDC4nZcRyDdjqXqp3JYiAVyGa26f89JfW
         VAeHp+HLLfJFnp7q5p8XWPZjT8yVzH+HWxNmXhLvCvflChZMkQzIqPX8bryndxKT8FE4
         K7widQ3u+v54M12rBj4msY0Sh8i1nfFdbdoSjbipbU/HoO8fQAwWvofzccHCkL43Nm8K
         XJolQOqCM+Lr12fIVgILuaUY6KTMnn0VafmVgXPQ0tuFRSYIW/2h8ZiaXTlCGyJy7QPz
         9l+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ql2mXvM+;
       spf=pass (google.com: domain of 31yuyxwukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31yuYXwUKCZI07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3T1hAaf6EsSWOaYIsHDXvj1Y9ZYvaJV6qmgAu1dZz44=;
        b=H4zfQ8h3crsd18eU0Y+7qt446U9DOyc2Eqpc844Sx/BHMRc3QTyThA+uTi6vsOESfW
         T12fbpm7+i03FC8rvnuicFo5JJXisnK5QbesorJLu2JlLlxBZ4oJ/PNMqX10gxVXa/s+
         vs8bvi4Y9fDAvvwpGxGVg/2yg8Cu846l/20kMR3IT5G0/yFfggSJTmmgSMIyNETzrJFM
         Bw9FXXcImo8nhZi6XNl7z5TpOabIscKkxPjv8NBR0iW5igfjCfRAGtJN8QQ+I6ZAgmwC
         91Z0/EE1GhanEAnKsE+dJ3pHt0qaWDV/Ar4PiszueHhVPca3yxwppfV4hRZdnhiK6LYV
         rgYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3T1hAaf6EsSWOaYIsHDXvj1Y9ZYvaJV6qmgAu1dZz44=;
        b=jfintxsPokaGwo64s4qRrZCB3UjExEoznyIxB+8pSW9XP8h0WsNdH1VwS6qKzVshn2
         vqOtUCZk9JlLg/3VjwjFhbJVYfnw4WxYg22Xi8GNDlBxbrgodCeD+1ivfVPpqAO5gDwT
         /4VrqkTu3XqoW0zo9t0qFxe7mV7GCz75QVUbkyWb5C3vvhCMQqPuT1PhZL8wI3kLV5L7
         LsTyRrkCD0ep61FCI+xJ27AGOQ8dZluvYn0qXKVK7X8FE8ht0bkbxz7XgLdKe5Z7E4sT
         VGG7RKK/C2Y9Jv3PAoTLW0zMJgQPdER1HIVODKZqX+1GcRkrn9hN9TswOoIsrvbehWuF
         kBdg==
X-Gm-Message-State: AOAM533knPmxOaiIPlkoq7V3IvvkLe41FAJlSpaYhXVSfmY2p/sFk3TP
	5GM94W5LLjbLlQBQVpzEtOE=
X-Google-Smtp-Source: ABdhPJzlv/2jfwZhf4/BByQADufmUAS3/XNMATMSJnoavzCS3kwNxiKhshfkD9kaq9yFAqsq1J7tXQ==
X-Received: by 2002:a5d:4843:: with SMTP id n3mr3234397wrs.416.1603808217862;
        Tue, 27 Oct 2020 07:16:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1c2:: with SMTP id 185ls939904wmb.3.gmail; Tue, 27 Oct
 2020 07:16:56 -0700 (PDT)
X-Received: by 2002:a7b:c418:: with SMTP id k24mr3136918wmi.118.1603808216808;
        Tue, 27 Oct 2020 07:16:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603808216; cv=none;
        d=google.com; s=arc-20160816;
        b=0shbpz3L9MzE2GKlEOZXtBH2rq/RB/Cd0UDPU+8gc/ja325IxTTW8xj7Jn2O8C4BYj
         I076oPblnkf+N/mSszwoUTy5JFl8qT+EHXzD61G45G0ypiTxA1CXrGTxsuzC+Du82NDw
         ME2DpyzidT55Mrvc1W9oc80T/9dQhA4JhWU/DDuK5ZI9f0O3Rhsg6Wbp8R76zkjtHgMH
         ra2HFMtXZ83IDeL6InC6ghACw1YC570iT3hTd5xk+WrDMozpdLrhnB9Sb14gfF5vMUeV
         9Pti5sfEwlE+cW7DdYi5Xn5CzU0jHT2gVBV25IJ1Tso1ZSAwseQ7GOUkc/S9hiFiIiFU
         6gCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=BMXYYZLWDVf5Lzw92aI4//6k6ZFQ/UKU0+gJd7pGTRY=;
        b=uQuiqbdQwrsOXFm52zBNAcHR+cQ3nmnSSW4Drq/IYPyQmwgTjnzBqjv9uEFv+IQsOU
         J0czumkvh9DRm0lPIq+17xNqtKawYlfR++Iz0mNT2OidRo5bPs8sfZD/vB0JHZ2R2ffB
         WckZCQK0GWQ9rtPM/9r26vv/m39XFstOet4YNx8PumHSrp6SJVxROG3khpa+5WTtdnv6
         nGt9YGUOeP1FN25y4ccTcHcVoboL6JPs7nm6lLfdRgrK/V1Hqbey/t+SvQQQHdX8YppU
         q29e6sE9UT3C2WkX/ioNtw2lVKOq9RM/2l9fQOy15JnoyBs3A9f3NWc4/enitj0jIA91
         xQhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ql2mXvM+;
       spf=pass (google.com: domain of 31yuyxwukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31yuYXwUKCZI07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id f198si44933wme.2.2020.10.27.07.16.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Oct 2020 07:16:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31yuyxwukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id b68so386334wme.5
        for <kasan-dev@googlegroups.com>; Tue, 27 Oct 2020 07:16:56 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a1c:e2c1:: with SMTP id z184mr2928301wmg.36.1603808215938;
 Tue, 27 Oct 2020 07:16:55 -0700 (PDT)
Date: Tue, 27 Oct 2020 15:16:05 +0100
In-Reply-To: <20201027141606.426816-1-elver@google.com>
Message-Id: <20201027141606.426816-9-elver@google.com>
Mime-Version: 1.0
References: <20201027141606.426816-1-elver@google.com>
X-Mailer: git-send-email 2.29.0.rc2.309.g374f81d7ae-goog
Subject: [PATCH v5 8/9] kfence: add test suite
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, joern@purestorage.com, keescook@chromium.org, 
	mark.rutland@arm.com, penberg@kernel.org, peterz@infradead.org, 
	sjpark@amazon.com, tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, 
	x86@kernel.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ql2mXvM+;       spf=pass
 (google.com: domain of 31yuyxwukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31yuYXwUKCZI07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Add KFENCE test suite, testing various error detection scenarios. Makes
use of KUnit for test organization. Since KFENCE's interface to obtain
error reports is via the console, the test verifies that KFENCE outputs
expected reports to the console.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Co-developed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v5:
* Add better memory corruption test.
* Test sl*b_def.h primitives.

v4:
* Clarify RCU test comment [reported by Paul E. McKenney].

v3:
* Lower line buffer size to avoid warnings of using more than 1024 bytes
  stack usage [reported by kernel test robot <lkp@intel.com>].

v2:
* Update for shortened memory corruption report.
---
 lib/Kconfig.kfence      |  13 +
 mm/kfence/Makefile      |   3 +
 mm/kfence/kfence_test.c | 822 ++++++++++++++++++++++++++++++++++++++++
 3 files changed, 838 insertions(+)
 create mode 100644 mm/kfence/kfence_test.c

diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index 3c4066aca4fc..ebafb4538b6e 100644
--- a/lib/Kconfig.kfence
+++ b/lib/Kconfig.kfence
@@ -57,4 +57,17 @@ config KFENCE_STRESS_TEST_FAULTS
 
 	  The option is only to test KFENCE; set to 0 if you are unsure.
 
+config KFENCE_KUNIT_TEST
+	tristate "KFENCE integration test suite" if !KUNIT_ALL_TESTS
+	default KUNIT_ALL_TESTS
+	depends on TRACEPOINTS && KUNIT
+	help
+	  Test suite for KFENCE, testing various error detection scenarios with
+	  various allocation types, and checking that reports are correctly
+	  output to console.
+
+	  Say Y here if you want the test to be built into the kernel and run
+	  during boot; say M if you want the test to build as a module; say N
+	  if you are unsure.
+
 endif # KFENCE
diff --git a/mm/kfence/Makefile b/mm/kfence/Makefile
index d991e9a349f0..6872cd5e5390 100644
--- a/mm/kfence/Makefile
+++ b/mm/kfence/Makefile
@@ -1,3 +1,6 @@
 # SPDX-License-Identifier: GPL-2.0
 
 obj-$(CONFIG_KFENCE) := core.o report.o
+
+CFLAGS_kfence_test.o := -g -fno-omit-frame-pointer -fno-optimize-sibling-calls
+obj-$(CONFIG_KFENCE_KUNIT_TEST) += kfence_test.o
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
new file mode 100644
index 000000000000..5f1ba0e9e7b0
--- /dev/null
+++ b/mm/kfence/kfence_test.c
@@ -0,0 +1,822 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Test cases for KFENCE memory safety error detector. Since the interface with
+ * which KFENCE's reports are obtained is via the console, this is the output we
+ * should verify. For each test case checks the presence (or absence) of
+ * generated reports. Relies on 'console' tracepoint to capture reports as they
+ * appear in the kernel log.
+ *
+ * Copyright (C) 2020, Google LLC.
+ * Author: Alexander Potapenko <glider@google.com>
+ *         Marco Elver <elver@google.com>
+ */
+
+#include <kunit/test.h>
+#include <linux/jiffies.h>
+#include <linux/kernel.h>
+#include <linux/kfence.h>
+#include <linux/mm.h>
+#include <linux/random.h>
+#include <linux/slab.h>
+#include <linux/spinlock.h>
+#include <linux/string.h>
+#include <linux/tracepoint.h>
+#include <trace/events/printk.h>
+
+#include "kfence.h"
+
+/* Report as observed from console. */
+static struct {
+	spinlock_t lock;
+	int nlines;
+	char lines[2][256];
+} observed = {
+	.lock = __SPIN_LOCK_UNLOCKED(observed.lock),
+};
+
+/* Probe for console output: obtains observed lines of interest. */
+static void probe_console(void *ignore, const char *buf, size_t len)
+{
+	unsigned long flags;
+	int nlines;
+
+	spin_lock_irqsave(&observed.lock, flags);
+	nlines = observed.nlines;
+
+	if (strnstr(buf, "BUG: KFENCE: ", len) && strnstr(buf, "test_", len)) {
+		/*
+		 * KFENCE report and related to the test.
+		 *
+		 * The provided @buf is not NUL-terminated; copy no more than
+		 * @len bytes and let strscpy() add the missing NUL-terminator.
+		 */
+		strscpy(observed.lines[0], buf, min(len + 1, sizeof(observed.lines[0])));
+		nlines = 1;
+	} else if (nlines == 1 && (strnstr(buf, "at 0x", len) || strnstr(buf, "of 0x", len))) {
+		strscpy(observed.lines[nlines++], buf, min(len + 1, sizeof(observed.lines[0])));
+	}
+
+	WRITE_ONCE(observed.nlines, nlines); /* Publish new nlines. */
+	spin_unlock_irqrestore(&observed.lock, flags);
+}
+
+/* Check if a report related to the test exists. */
+static bool report_available(void)
+{
+	return READ_ONCE(observed.nlines) == ARRAY_SIZE(observed.lines);
+}
+
+/* Information we expect in a report. */
+struct expect_report {
+	enum kfence_error_type type; /* The type or error. */
+	void *fn; /* Function pointer to expected function where access occurred. */
+	char *addr; /* Address at which the bad access occurred. */
+};
+
+/* Check observed report matches information in @r. */
+static bool report_matches(const struct expect_report *r)
+{
+	bool ret = false;
+	unsigned long flags;
+	typeof(observed.lines) expect;
+	const char *end;
+	char *cur;
+
+	/* Doubled-checked locking. */
+	if (!report_available())
+		return false;
+
+	/* Generate expected report contents. */
+
+	/* Title */
+	cur = expect[0];
+	end = &expect[0][sizeof(expect[0]) - 1];
+	switch (r->type) {
+	case KFENCE_ERROR_OOB:
+		cur += scnprintf(cur, end - cur, "BUG: KFENCE: out-of-bounds");
+		break;
+	case KFENCE_ERROR_UAF:
+		cur += scnprintf(cur, end - cur, "BUG: KFENCE: use-after-free");
+		break;
+	case KFENCE_ERROR_CORRUPTION:
+		cur += scnprintf(cur, end - cur, "BUG: KFENCE: memory corruption");
+		break;
+	case KFENCE_ERROR_INVALID:
+		cur += scnprintf(cur, end - cur, "BUG: KFENCE: invalid access");
+		break;
+	case KFENCE_ERROR_INVALID_FREE:
+		cur += scnprintf(cur, end - cur, "BUG: KFENCE: invalid free");
+		break;
+	}
+
+	scnprintf(cur, end - cur, " in %pS", r->fn);
+	/* The exact offset won't match, remove it; also strip module name. */
+	cur = strchr(expect[0], '+');
+	if (cur)
+		*cur = '\0';
+
+	/* Access information */
+	cur = expect[1];
+	end = &expect[1][sizeof(expect[1]) - 1];
+
+	switch (r->type) {
+	case KFENCE_ERROR_OOB:
+		cur += scnprintf(cur, end - cur, "Out-of-bounds access at");
+		break;
+	case KFENCE_ERROR_UAF:
+		cur += scnprintf(cur, end - cur, "Use-after-free access at");
+		break;
+	case KFENCE_ERROR_CORRUPTION:
+		cur += scnprintf(cur, end - cur, "Corrupted memory at");
+		break;
+	case KFENCE_ERROR_INVALID:
+		cur += scnprintf(cur, end - cur, "Invalid access at");
+		break;
+	case KFENCE_ERROR_INVALID_FREE:
+		cur += scnprintf(cur, end - cur, "Invalid free of");
+		break;
+	}
+
+	cur += scnprintf(cur, end - cur, " 0x" PTR_FMT, (void *)r->addr);
+
+	spin_lock_irqsave(&observed.lock, flags);
+	if (!report_available())
+		goto out; /* A new report is being captured. */
+
+	/* Finally match expected output to what we actually observed. */
+	ret = strstr(observed.lines[0], expect[0]) && strstr(observed.lines[1], expect[1]);
+out:
+	spin_unlock_irqrestore(&observed.lock, flags);
+	return ret;
+}
+
+/* ===== Test cases ===== */
+
+#define TEST_PRIV_WANT_MEMCACHE ((void *)1)
+
+/* Cache used by tests; if NULL, allocate from kmalloc instead. */
+static struct kmem_cache *test_cache;
+
+static size_t setup_test_cache(struct kunit *test, size_t size, slab_flags_t flags,
+			       void (*ctor)(void *))
+{
+	if (test->priv != TEST_PRIV_WANT_MEMCACHE)
+		return size;
+
+	kunit_info(test, "%s: size=%zu, ctor=%ps\n", __func__, size, ctor);
+
+	/*
+	 * Use SLAB_NOLEAKTRACE to prevent merging with existing caches. Any
+	 * other flag in SLAB_NEVER_MERGE also works. Use SLAB_ACCOUNT to
+	 * allocate via memcg, if enabled.
+	 */
+	flags |= SLAB_NOLEAKTRACE | SLAB_ACCOUNT;
+	test_cache = kmem_cache_create("test", size, 1, flags, ctor);
+	KUNIT_ASSERT_TRUE_MSG(test, test_cache, "could not create cache");
+
+	return size;
+}
+
+static void test_cache_destroy(void)
+{
+	if (!test_cache)
+		return;
+
+	kmem_cache_destroy(test_cache);
+	test_cache = NULL;
+}
+
+static inline size_t kmalloc_cache_alignment(size_t size)
+{
+	return kmalloc_caches[kmalloc_type(GFP_KERNEL)][kmalloc_index(size)]->align;
+}
+
+/* Must always inline to match stack trace against caller. */
+static __always_inline void test_free(void *ptr)
+{
+	if (test_cache)
+		kmem_cache_free(test_cache, ptr);
+	else
+		kfree(ptr);
+}
+
+/*
+ * If this should be a KFENCE allocation, and on which side the allocation and
+ * the closest guard page should be.
+ */
+enum allocation_policy {
+	ALLOCATE_ANY, /* KFENCE, any side. */
+	ALLOCATE_LEFT, /* KFENCE, left side of page. */
+	ALLOCATE_RIGHT, /* KFENCE, right side of page. */
+	ALLOCATE_NONE, /* No KFENCE allocation. */
+};
+
+/*
+ * Try to get a guarded allocation from KFENCE. Uses either kmalloc() or the
+ * current test_cache if set up.
+ */
+static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocation_policy policy)
+{
+	void *alloc;
+	unsigned long timeout, resched_after;
+	const char *policy_name;
+
+	switch (policy) {
+	case ALLOCATE_ANY:
+		policy_name = "any";
+		break;
+	case ALLOCATE_LEFT:
+		policy_name = "left";
+		break;
+	case ALLOCATE_RIGHT:
+		policy_name = "right";
+		break;
+	case ALLOCATE_NONE:
+		policy_name = "none";
+		break;
+	}
+
+	kunit_info(test, "%s: size=%zu, gfp=%x, policy=%s, cache=%i\n", __func__, size, gfp,
+		   policy_name, !!test_cache);
+
+	/*
+	 * 100x the sample interval should be more than enough to ensure we get
+	 * a KFENCE allocation eventually.
+	 */
+	timeout = jiffies + msecs_to_jiffies(100 * CONFIG_KFENCE_SAMPLE_INTERVAL);
+	/*
+	 * Especially for non-preemption kernels, ensure the allocation-gate
+	 * timer has time to catch up.
+	 */
+	resched_after = jiffies + msecs_to_jiffies(CONFIG_KFENCE_SAMPLE_INTERVAL);
+	do {
+		if (test_cache)
+			alloc = kmem_cache_alloc(test_cache, gfp);
+		else
+			alloc = kmalloc(size, gfp);
+
+		if (is_kfence_address(alloc)) {
+			struct page *page = virt_to_head_page(alloc);
+			struct kmem_cache *s = test_cache ?: kmalloc_caches[kmalloc_type(GFP_KERNEL)][kmalloc_index(size)];
+
+			/*
+			 * Verify that various helpers return the right values
+			 * even for KFENCE objects; these are required so that
+			 * memcg accounting works correctly.
+			 */
+			KUNIT_EXPECT_EQ(test, obj_to_index(s, page, alloc), 0U);
+			KUNIT_EXPECT_EQ(test, objs_per_slab_page(s, page), 1);
+
+			if (policy == ALLOCATE_ANY)
+				return alloc;
+			if (policy == ALLOCATE_LEFT && IS_ALIGNED((unsigned long)alloc, PAGE_SIZE))
+				return alloc;
+			if (policy == ALLOCATE_RIGHT &&
+			    !IS_ALIGNED((unsigned long)alloc, PAGE_SIZE))
+				return alloc;
+		} else if (policy == ALLOCATE_NONE)
+			return alloc;
+
+		test_free(alloc);
+
+		if (time_after(jiffies, resched_after))
+			cond_resched();
+	} while (time_before(jiffies, timeout));
+
+	KUNIT_ASSERT_TRUE_MSG(test, false, "failed to allocate from KFENCE");
+	return NULL; /* Unreachable. */
+}
+
+static void test_out_of_bounds_read(struct kunit *test)
+{
+	size_t size = 32;
+	struct expect_report expect = {
+		.type = KFENCE_ERROR_OOB,
+		.fn = test_out_of_bounds_read,
+	};
+	char *buf;
+
+	setup_test_cache(test, size, 0, NULL);
+
+	/*
+	 * If we don't have our own cache, adjust based on alignment, so that we
+	 * actually access guard pages on either side.
+	 */
+	if (!test_cache)
+		size = kmalloc_cache_alignment(size);
+
+	/* Test both sides. */
+
+	buf = test_alloc(test, size, GFP_KERNEL, ALLOCATE_LEFT);
+	expect.addr = buf - 1;
+	READ_ONCE(*expect.addr);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+	test_free(buf);
+
+	buf = test_alloc(test, size, GFP_KERNEL, ALLOCATE_RIGHT);
+	expect.addr = buf + size;
+	READ_ONCE(*expect.addr);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+	test_free(buf);
+}
+
+static void test_use_after_free_read(struct kunit *test)
+{
+	const size_t size = 32;
+	struct expect_report expect = {
+		.type = KFENCE_ERROR_UAF,
+		.fn = test_use_after_free_read,
+	};
+
+	setup_test_cache(test, size, 0, NULL);
+	expect.addr = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
+	test_free(expect.addr);
+	READ_ONCE(*expect.addr);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+static void test_double_free(struct kunit *test)
+{
+	const size_t size = 32;
+	struct expect_report expect = {
+		.type = KFENCE_ERROR_INVALID_FREE,
+		.fn = test_double_free,
+	};
+
+	setup_test_cache(test, size, 0, NULL);
+	expect.addr = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
+	test_free(expect.addr);
+	test_free(expect.addr); /* Double-free. */
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+static void test_invalid_addr_free(struct kunit *test)
+{
+	const size_t size = 32;
+	struct expect_report expect = {
+		.type = KFENCE_ERROR_INVALID_FREE,
+		.fn = test_invalid_addr_free,
+	};
+	char *buf;
+
+	setup_test_cache(test, size, 0, NULL);
+	buf = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
+	expect.addr = buf + 1; /* Free on invalid address. */
+	test_free(expect.addr); /* Invalid address free. */
+	test_free(buf); /* No error. */
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+static void test_corruption(struct kunit *test)
+{
+	size_t size = 32;
+	struct expect_report expect = {
+		.type = KFENCE_ERROR_CORRUPTION,
+		.fn = test_corruption,
+	};
+	char *buf;
+
+	setup_test_cache(test, size, 0, NULL);
+
+	/* Test both sides. */
+
+	buf = test_alloc(test, size, GFP_KERNEL, ALLOCATE_LEFT);
+	expect.addr = buf + size;
+	WRITE_ONCE(*expect.addr, 42);
+	test_free(buf);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+
+	buf = test_alloc(test, size, GFP_KERNEL, ALLOCATE_RIGHT);
+	expect.addr = buf - 1;
+	WRITE_ONCE(*expect.addr, 42);
+	test_free(buf);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/*
+ * KFENCE is unable to detect an OOB if the allocation's alignment requirements
+ * leave a gap between the object and the guard page. Specifically, an
+ * allocation of e.g. 73 bytes is aligned on 8 and 128 bytes for SLUB or SLAB
+ * respectively. Therefore it is impossible for the allocated object to adhere
+ * to either of the page boundaries.
+ *
+ * However, we test that an access to memory beyond the gap result in KFENCE
+ * detecting an OOB access.
+ */
+static void test_kmalloc_aligned_oob_read(struct kunit *test)
+{
+	const size_t size = 73;
+	const size_t align = kmalloc_cache_alignment(size);
+	struct expect_report expect = {
+		.type = KFENCE_ERROR_OOB,
+		.fn = test_kmalloc_aligned_oob_read,
+	};
+	char *buf;
+
+	buf = test_alloc(test, size, GFP_KERNEL, ALLOCATE_RIGHT);
+
+	/*
+	 * The object is offset to the right, so there won't be an OOB to the
+	 * left of it.
+	 */
+	READ_ONCE(*(buf - 1));
+	KUNIT_EXPECT_FALSE(test, report_available());
+
+	/*
+	 * @buf must be aligned on @align, therefore buf + size belongs to the
+	 * same page -> no OOB.
+	 */
+	READ_ONCE(*(buf + size));
+	KUNIT_EXPECT_FALSE(test, report_available());
+
+	/* Overflowing by @align bytes will result in an OOB. */
+	expect.addr = buf + size + align;
+	READ_ONCE(*expect.addr);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+
+	test_free(buf);
+}
+
+static void test_kmalloc_aligned_oob_write(struct kunit *test)
+{
+	const size_t size = 73;
+	struct expect_report expect = {
+		.type = KFENCE_ERROR_CORRUPTION,
+		.fn = test_kmalloc_aligned_oob_write,
+	};
+	char *buf;
+
+	buf = test_alloc(test, size, GFP_KERNEL, ALLOCATE_RIGHT);
+	/*
+	 * The object is offset to the right, so we won't get a page
+	 * fault immediately after it.
+	 */
+	expect.addr = buf + size;
+	WRITE_ONCE(*expect.addr, READ_ONCE(*expect.addr) + 1);
+	KUNIT_EXPECT_FALSE(test, report_available());
+	test_free(buf);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/* Test cache shrinking and destroying with KFENCE. */
+static void test_shrink_memcache(struct kunit *test)
+{
+	const size_t size = 32;
+	void *buf;
+
+	setup_test_cache(test, size, 0, NULL);
+	KUNIT_EXPECT_TRUE(test, test_cache);
+	buf = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
+	kmem_cache_shrink(test_cache);
+	test_free(buf);
+
+	KUNIT_EXPECT_FALSE(test, report_available());
+}
+
+static void ctor_set_x(void *obj)
+{
+	/* Every object has at least 8 bytes. */
+	memset(obj, 'x', 8);
+}
+
+/* Ensure that SL*B does not modify KFENCE objects on bulk free. */
+static void test_free_bulk(struct kunit *test)
+{
+	int iter;
+
+	for (iter = 0; iter < 5; iter++) {
+		const size_t size = setup_test_cache(test, 8 + prandom_u32_max(300), 0,
+						     (iter & 1) ? ctor_set_x : NULL);
+		void *objects[] = {
+			test_alloc(test, size, GFP_KERNEL, ALLOCATE_RIGHT),
+			test_alloc(test, size, GFP_KERNEL, ALLOCATE_NONE),
+			test_alloc(test, size, GFP_KERNEL, ALLOCATE_LEFT),
+			test_alloc(test, size, GFP_KERNEL, ALLOCATE_NONE),
+			test_alloc(test, size, GFP_KERNEL, ALLOCATE_NONE),
+		};
+
+		kmem_cache_free_bulk(test_cache, ARRAY_SIZE(objects), objects);
+		KUNIT_ASSERT_FALSE(test, report_available());
+		test_cache_destroy();
+	}
+}
+
+/* Test init-on-free works. */
+static void test_init_on_free(struct kunit *test)
+{
+	const size_t size = 32;
+	struct expect_report expect = {
+		.type = KFENCE_ERROR_UAF,
+		.fn = test_init_on_free,
+	};
+	int i;
+
+	if (!IS_ENABLED(CONFIG_INIT_ON_FREE_DEFAULT_ON))
+		return;
+	/* Assume it hasn't been disabled on command line. */
+
+	setup_test_cache(test, size, 0, NULL);
+	expect.addr = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
+	for (i = 0; i < size; i++)
+		expect.addr[i] = i + 1;
+	test_free(expect.addr);
+
+	for (i = 0; i < size; i++) {
+		/*
+		 * This may fail if the page was recycled by KFENCE and then
+		 * written to again -- this however, is near impossible with a
+		 * default config.
+		 */
+		KUNIT_EXPECT_EQ(test, expect.addr[i], (char)0);
+
+		if (!i) /* Only check first access to not fail test if page is ever re-protected. */
+			KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+	}
+}
+
+/* Ensure that constructors work properly. */
+static void test_memcache_ctor(struct kunit *test)
+{
+	const size_t size = 32;
+	char *buf;
+	int i;
+
+	setup_test_cache(test, size, 0, ctor_set_x);
+	buf = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
+
+	for (i = 0; i < 8; i++)
+		KUNIT_EXPECT_EQ(test, buf[i], (char)'x');
+
+	test_free(buf);
+
+	KUNIT_EXPECT_FALSE(test, report_available());
+}
+
+/* Test that memory is zeroed if requested. */
+static void test_gfpzero(struct kunit *test)
+{
+	const size_t size = PAGE_SIZE; /* PAGE_SIZE so we can use ALLOCATE_ANY. */
+	char *buf1, *buf2;
+	int i;
+
+	if (CONFIG_KFENCE_SAMPLE_INTERVAL > 100) {
+		kunit_warn(test, "skipping ... would take too long\n");
+		return;
+	}
+
+	setup_test_cache(test, size, 0, NULL);
+	buf1 = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
+	for (i = 0; i < size; i++)
+		buf1[i] = i + 1;
+	test_free(buf1);
+
+	/* Try to get same address again -- this can take a while. */
+	for (i = 0;; i++) {
+		buf2 = test_alloc(test, size, GFP_KERNEL | __GFP_ZERO, ALLOCATE_ANY);
+		if (buf1 == buf2)
+			break;
+		test_free(buf2);
+
+		if (i == CONFIG_KFENCE_NUM_OBJECTS) {
+			kunit_warn(test, "giving up ... cannot get same object back\n");
+			return;
+		}
+	}
+
+	for (i = 0; i < size; i++)
+		KUNIT_EXPECT_EQ(test, buf2[i], (char)0);
+
+	test_free(buf2);
+
+	KUNIT_EXPECT_FALSE(test, report_available());
+}
+
+static void test_invalid_access(struct kunit *test)
+{
+	const struct expect_report expect = {
+		.type = KFENCE_ERROR_INVALID,
+		.fn = test_invalid_access,
+		.addr = &__kfence_pool[10],
+	};
+
+	READ_ONCE(__kfence_pool[10]);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/* Test SLAB_TYPESAFE_BY_RCU works. */
+static void test_memcache_typesafe_by_rcu(struct kunit *test)
+{
+	const size_t size = 32;
+	struct expect_report expect = {
+		.type = KFENCE_ERROR_UAF,
+		.fn = test_memcache_typesafe_by_rcu,
+	};
+
+	setup_test_cache(test, size, SLAB_TYPESAFE_BY_RCU, NULL);
+	KUNIT_EXPECT_TRUE(test, test_cache); /* Want memcache. */
+
+	expect.addr = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
+	*expect.addr = 42;
+
+	rcu_read_lock();
+	test_free(expect.addr);
+	KUNIT_EXPECT_EQ(test, *expect.addr, (char)42);
+	/*
+	 * Up to this point, memory should not have been freed yet, and
+	 * therefore there should be no KFENCE report from the above access.
+	 */
+	rcu_read_unlock();
+
+	/* Above access to @expect.addr should not have generated a report! */
+	KUNIT_EXPECT_FALSE(test, report_available());
+
+	/* Only after rcu_barrier() is the memory guaranteed to be freed. */
+	rcu_barrier();
+
+	/* Expect use-after-free. */
+	KUNIT_EXPECT_EQ(test, *expect.addr, (char)42);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/* Test krealloc(). */
+static void test_krealloc(struct kunit *test)
+{
+	const size_t size = 32;
+	const struct expect_report expect = {
+		.type = KFENCE_ERROR_UAF,
+		.fn = test_krealloc,
+		.addr = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY),
+	};
+	char *buf = expect.addr;
+	int i;
+
+	KUNIT_EXPECT_FALSE(test, test_cache);
+	KUNIT_EXPECT_EQ(test, ksize(buf), size); /* Precise size match after KFENCE alloc. */
+	for (i = 0; i < size; i++)
+		buf[i] = i + 1;
+
+	/* Check that we successfully change the size. */
+	buf = krealloc(buf, size * 3, GFP_KERNEL); /* Grow. */
+	/* Note: Might no longer be a KFENCE alloc. */
+	KUNIT_EXPECT_GE(test, ksize(buf), size * 3);
+	for (i = 0; i < size; i++)
+		KUNIT_EXPECT_EQ(test, buf[i], (char)(i + 1));
+	for (; i < size * 3; i++) /* Fill to extra bytes. */
+		buf[i] = i + 1;
+
+	buf = krealloc(buf, size * 2, GFP_KERNEL * 2); /* Shrink. */
+	KUNIT_EXPECT_GE(test, ksize(buf), size * 2);
+	for (i = 0; i < size * 2; i++)
+		KUNIT_EXPECT_EQ(test, buf[i], (char)(i + 1));
+
+	buf = krealloc(buf, 0, GFP_KERNEL); /* Free. */
+	KUNIT_EXPECT_EQ(test, (unsigned long)buf, (unsigned long)ZERO_SIZE_PTR);
+	KUNIT_ASSERT_FALSE(test, report_available()); /* No reports yet! */
+
+	READ_ONCE(*expect.addr); /* Ensure krealloc() actually freed earlier KFENCE object. */
+	KUNIT_ASSERT_TRUE(test, report_matches(&expect));
+}
+
+/* Test that some objects from a bulk allocation belong to KFENCE pool. */
+static void test_memcache_alloc_bulk(struct kunit *test)
+{
+	const size_t size = 32;
+	bool pass = false;
+	unsigned long timeout;
+
+	setup_test_cache(test, size, 0, NULL);
+	KUNIT_EXPECT_TRUE(test, test_cache); /* Want memcache. */
+	/*
+	 * 100x the sample interval should be more than enough to ensure we get
+	 * a KFENCE allocation eventually.
+	 */
+	timeout = jiffies + msecs_to_jiffies(100 * CONFIG_KFENCE_SAMPLE_INTERVAL);
+	do {
+		void *objects[100];
+		int i, num = kmem_cache_alloc_bulk(test_cache, GFP_ATOMIC, ARRAY_SIZE(objects),
+						   objects);
+		if (!num)
+			continue;
+		for (i = 0; i < ARRAY_SIZE(objects); i++) {
+			if (is_kfence_address(objects[i])) {
+				pass = true;
+				break;
+			}
+		}
+		kmem_cache_free_bulk(test_cache, num, objects);
+		/*
+		 * kmem_cache_alloc_bulk() disables interrupts, and calling it
+		 * in a tight loop may not give KFENCE a chance to switch the
+		 * static branch. Call cond_resched() to let KFENCE chime in.
+		 */
+		cond_resched();
+	} while (!pass && time_before(jiffies, timeout));
+
+	KUNIT_EXPECT_TRUE(test, pass);
+	KUNIT_EXPECT_FALSE(test, report_available());
+}
+
+/*
+ * KUnit does not provide a way to provide arguments to tests, and we encode
+ * additional info in the name. Set up 2 tests per test case, one using the
+ * default allocator, and another using a custom memcache (suffix '-memcache').
+ */
+#define KFENCE_KUNIT_CASE(test_name)						\
+	{ .run_case = test_name, .name = #test_name },				\
+	{ .run_case = test_name, .name = #test_name "-memcache" }
+
+static struct kunit_case kfence_test_cases[] = {
+	KFENCE_KUNIT_CASE(test_out_of_bounds_read),
+	KFENCE_KUNIT_CASE(test_use_after_free_read),
+	KFENCE_KUNIT_CASE(test_double_free),
+	KFENCE_KUNIT_CASE(test_invalid_addr_free),
+	KFENCE_KUNIT_CASE(test_corruption),
+	KFENCE_KUNIT_CASE(test_free_bulk),
+	KFENCE_KUNIT_CASE(test_init_on_free),
+	KUNIT_CASE(test_kmalloc_aligned_oob_read),
+	KUNIT_CASE(test_kmalloc_aligned_oob_write),
+	KUNIT_CASE(test_shrink_memcache),
+	KUNIT_CASE(test_memcache_ctor),
+	KUNIT_CASE(test_invalid_access),
+	KUNIT_CASE(test_gfpzero),
+	KUNIT_CASE(test_memcache_typesafe_by_rcu),
+	KUNIT_CASE(test_krealloc),
+	KUNIT_CASE(test_memcache_alloc_bulk),
+	{},
+};
+
+/* ===== End test cases ===== */
+
+static int test_init(struct kunit *test)
+{
+	unsigned long flags;
+	int i;
+
+	spin_lock_irqsave(&observed.lock, flags);
+	for (i = 0; i < ARRAY_SIZE(observed.lines); i++)
+		observed.lines[i][0] = '\0';
+	observed.nlines = 0;
+	spin_unlock_irqrestore(&observed.lock, flags);
+
+	/* Any test with 'memcache' in its name will want a memcache. */
+	if (strstr(test->name, "memcache"))
+		test->priv = TEST_PRIV_WANT_MEMCACHE;
+	else
+		test->priv = NULL;
+
+	return 0;
+}
+
+static void test_exit(struct kunit *test)
+{
+	test_cache_destroy();
+}
+
+static struct kunit_suite kfence_test_suite = {
+	.name = "kfence",
+	.test_cases = kfence_test_cases,
+	.init = test_init,
+	.exit = test_exit,
+};
+static struct kunit_suite *kfence_test_suites[] = { &kfence_test_suite, NULL };
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
+static int __init kfence_test_init(void)
+{
+	/*
+	 * Because we want to be able to build the test as a module, we need to
+	 * iterate through all known tracepoints, since the static registration
+	 * won't work here.
+	 */
+	for_each_kernel_tracepoint(register_tracepoints, NULL);
+	return __kunit_test_suites_init(kfence_test_suites);
+}
+
+static void kfence_test_exit(void)
+{
+	__kunit_test_suites_exit(kfence_test_suites);
+	for_each_kernel_tracepoint(unregister_tracepoints, NULL);
+	tracepoint_synchronize_unregister();
+}
+
+late_initcall(kfence_test_init);
+module_exit(kfence_test_exit);
+
+MODULE_LICENSE("GPL v2");
+MODULE_AUTHOR("Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>");
-- 
2.29.0.rc2.309.g374f81d7ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201027141606.426816-9-elver%40google.com.
