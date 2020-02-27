Return-Path: <kasan-dev+bncBDK3TPOVRULBBHW23TZAKGQE3XHC74I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id D8B3E170E9B
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 03:44:47 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id r9sf1700208qvs.19
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2020 18:44:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582771486; cv=pass;
        d=google.com; s=arc-20160816;
        b=DfSO6DSMKe8a8jz8FTZeldbI9Wk6wxZOyGjxTsCsz4kbWHIqPTzOwSSkLAEu4ahsNy
         zjCLfwH0EzACmWlyYVE9OllFqiuFscWkWDx/hOKSBxtN816hQZM9NrvHP28u1BCFa7qr
         2EwkvqB5vRRBC6GSKRUcIFd2PJVFdJuTIpVPTmiH13rbvST6X4kowtHsvHjunwxPc7Mf
         DfMEJr0gBd1aZ+4zMGuUqtXxBPZRHPIFyoTlINshvlqcSZZOiZeZbReWHbHQJGlmRndY
         sJfbz9FqC1IJr8T+08R+7rl2FCNFAf7RTXihwafmFYm7N0ZQ3I3NCazxyuOMuV4mWLgK
         eE9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=VFG5dFwbryATP7Eyyc5ZAoRcCSbFTR4+yeCH8+Wa7pw=;
        b=CX/WOhVepKJxK6IoJR1q8uO7X7Yg/3LpGTvCkp2/cFZ8wSwedvHMMR/bj94ozuI3UU
         4bbfn0fNSQMoBp9HLsAz9vTUGxHwpIyP0Ga8CVHA3nKrtwZxdOvLLC1B+jdm8kzn3vFb
         fuxA4j2gAydcONoQKlv0B+AmJcR0nPAh030SJMOv3ma0hYKofC4Df6/AiH6Ck9Z7+OCR
         YRx9e6GL0NxSEaKTBQ0/zXZKTRM9Ugni7jD/9oZ0kUD3ym6noHA1qzw2P4Tuj2j16eg7
         PjIoiuxymO+M1sMr5DhCuVvG6c/FBonl7o+tu/8JD7MnoghUK3oy2QfpVrIcbIY6CGsX
         JEQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LpMFnRUF;
       spf=pass (google.com: domain of 3hs1xxgwkccwb90azs3x65a6y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::54a as permitted sender) smtp.mailfrom=3HS1XXgwKCcwB90Azs3x65A6y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VFG5dFwbryATP7Eyyc5ZAoRcCSbFTR4+yeCH8+Wa7pw=;
        b=cThJJalc991I+TCNTJaJMoHCErv2/zEQr9NH21T9GJSQpRedc0nfh7xbg8dP/07hz6
         3uqLrlpR+/+q0VjvY/GVKq39s1M3AqkzqaWzU7cwVYRK1OemN5wZWX9UnSJkJONI1WDu
         fPjyJMFNa0BdWmXLLNaXp02LKxwUWR0zrHaxH/CEvuG3FrWcnTltWNjXkpSLwY9CPtUb
         fSQLhOXZ4gJv91F1KVnB+AwNNNGM7iSy7REU5anCLBQ4xxr7V3GFzY7u6OHgDVfjPwq0
         qD57ilDj7mFFcHMS387SmpfKXJrfg4zpXl+rowBVW98+ajadEY/kuEYUAufBNHG1d6+C
         CEAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VFG5dFwbryATP7Eyyc5ZAoRcCSbFTR4+yeCH8+Wa7pw=;
        b=ch4hdnwnAbFnLe8pR1Mii3SvZq1bieccW+UyTqUl/u55x/B0Y6oQ4qGgcoGAo+w61/
         Ybe6LcyY1my6bM8CV51HLyiyXna+CaZOwb2wm7i3gym7CntmAB3pYuELe/lY2gmk1VhB
         bGUJ+brR+5yxEcxVnnw1z2ILIvI4JbGDxKcrNFMLzaG5rNN5k5qBfDGE1ugrjQc0UQRH
         d/QpYIhoT18blhkIQ3Ax+UH0S0x3XDBBG0kJ9HnoDeY3Xjx5dMvSvk87ML1E6Ril9M9x
         ggDKnx4/BNQKrF/G9oYfSDyhJRAhJ7gixvZyaYdNc/s+px+JEIqIgfiqjlbpDWTh1+3g
         B7GA==
X-Gm-Message-State: APjAAAWP7s6KaclYVTfhRnqcczTohz71ZCCSsju9CvBgS2VXJIcjfm80
	njKdQKWM2zo7hUreU91/fkY=
X-Google-Smtp-Source: APXvYqxcZUYa9LhrAQ40U+9wD3gO19KFqUSwcdYDzA9u8aQ2R/9F+BgOYz/DRWBLZQLG/EiwuZDevQ==
X-Received: by 2002:aed:2e02:: with SMTP id j2mr2119271qtd.370.1582771486519;
        Wed, 26 Feb 2020 18:44:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:6701:: with SMTP id e1ls439864qtp.8.gmail; Wed, 26 Feb
 2020 18:44:46 -0800 (PST)
X-Received: by 2002:ac8:6bc9:: with SMTP id b9mr2292341qtt.108.1582771486115;
        Wed, 26 Feb 2020 18:44:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582771486; cv=none;
        d=google.com; s=arc-20160816;
        b=SzHex0h7f/CFKCSnyMiHBYzsqvXI5hCmn63u4OxQHz385rKGYR2oBO2/VK9FnUMv0X
         ifr0bqrxPSfpWqAsAPXL+ewlgVKk+4DIqpcRbGN/UOrD9j3bDe939yx74TfjDMn+G0Wj
         SQ8spRMMfiM9tXQJMZ/sH45xr6o+gh/GTX1XvVlQVJql4AVpXtqvZ/EOmJ0dj52RPiNJ
         Hmq1sy/lRfN1dajOavTpa6Vik4UnwvvwRk50yO+dVhGDyO8XH3HClUqn2sTOaG1PVXj6
         UcA1ZkR7Gk3H1WbLtGUb73ElgN/Y7xOt58AqZvvi30160OEFWaxNDpLisRSJPH7apMOb
         2J3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=MzblV2B3yiELWZGgmDEXOGM+kFqZEnGt6N1xQ+fXD1M=;
        b=S9ca5kgu41pY4iz9AsR3xRSg3krPuSFO5kXpsJLoz3o0+wzf8zobAQCoWRkbObo0Nk
         5//5MqFYw/YLLY+RWscp6nXg+c/lbmu7tyrrkkW1lBXp0gFa6jSRE1l46k9ZppFL7ths
         Ht4MH3wXTGvvBkWjjd2uAzsYRB/Bfw1fv3wTJYMSI0IgOgb5E+LDu/7y4YdKKInrPqyj
         YNrlLXicQWQkrEVeRSvph1AwcNQyaZFw0iAxfBDWzkijnjETQajCciujDdrUPHO6sksC
         YtRxg2o80tbk+tlmNWHsKduvP5QMdnSHDPcFrclMYVeP6vBxq/xkAe8nWmhsNp0e/Zbf
         KQjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LpMFnRUF;
       spf=pass (google.com: domain of 3hs1xxgwkccwb90azs3x65a6y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::54a as permitted sender) smtp.mailfrom=3HS1XXgwKCcwB90Azs3x65A6y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x54a.google.com (mail-pg1-x54a.google.com. [2607:f8b0:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id f52si96065qtk.2.2020.02.26.18.44.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Feb 2020 18:44:46 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hs1xxgwkccwb90azs3x65a6y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::54a as permitted sender) client-ip=2607:f8b0:4864:20::54a;
Received: by mail-pg1-x54a.google.com with SMTP id h14so933717pgd.15
        for <kasan-dev@googlegroups.com>; Wed, 26 Feb 2020 18:44:46 -0800 (PST)
X-Received: by 2002:a63:3085:: with SMTP id w127mr1837386pgw.176.1582771485461;
 Wed, 26 Feb 2020 18:44:45 -0800 (PST)
Date: Wed, 26 Feb 2020 18:43:01 -0800
In-Reply-To: <20200227024301.217042-1-trishalfonso@google.com>
Message-Id: <20200227024301.217042-2-trishalfonso@google.com>
Mime-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com>
X-Mailer: git-send-email 2.25.0.265.gbab2e86ba0-goog
Subject: [RFC PATCH 2/2] KUnit: KASAN Integration
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
To: aryabinin@virtuozzo.com, dvyukov@google.com, brendanhiggins@google.com, 
	davidgow@google.com, mingo@redhat.com, peterz@infradead.org, 
	juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	Patricia Alfonso <trishalfonso@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LpMFnRUF;       spf=pass
 (google.com: domain of 3hs1xxgwkccwb90azs3x65a6y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--trishalfonso.bounces.google.com
 designates 2607:f8b0:4864:20::54a as permitted sender) smtp.mailfrom=3HS1XXgwKCcwB90Azs3x65A6y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--trishalfonso.bounces.google.com;
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

Integrate KASAN into KUnit testing framework.
 - Fail tests when KASAN reports an error that is not expected
 - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN tests
 - KUnit struct added to current task to keep track of the current test
from KASAN code
 - Booleans representing if a KASAN report is expected and if a KASAN
 report is found added to kunit struct
 - This prints "line# has passed" or "line# has failed"

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
---
If anyone has any suggestions on how best to print the failure
messages, please share!

One issue I have found while testing this is the allocation fails in
kmalloc_pagealloc_oob_right() sometimes, but not consistently. This
does cause the test to fail on the KUnit side, as expected, but it
seems to skip all the tests before this one because the output starts
with this failure instead of with the first test, kmalloc_oob_right().

 include/kunit/test.h                | 24 ++++++++++++++++++++++++
 include/linux/sched.h               |  7 ++++++-
 lib/kunit/test.c                    |  7 ++++++-
 mm/kasan/report.c                   | 19 +++++++++++++++++++
 tools/testing/kunit/kunit_kernel.py |  2 +-
 5 files changed, 56 insertions(+), 3 deletions(-)

diff --git a/include/kunit/test.h b/include/kunit/test.h
index 2dfb550c6723..2e388f8937f3 100644
--- a/include/kunit/test.h
+++ b/include/kunit/test.h
@@ -21,6 +21,8 @@ struct kunit_resource;
 typedef int (*kunit_resource_init_t)(struct kunit_resource *, void *);
 typedef void (*kunit_resource_free_t)(struct kunit_resource *);
 
+void kunit_set_failure(struct kunit *test);
+
 /**
  * struct kunit_resource - represents a *test managed resource*
  * @allocation: for the user to store arbitrary data.
@@ -191,6 +193,9 @@ struct kunit {
 	 * protect it with some type of lock.
 	 */
 	struct list_head resources; /* Protected by lock. */
+
+	bool kasan_report_expected;
+	bool kasan_report_found;
 };
 
 void kunit_init_test(struct kunit *test, const char *name);
@@ -941,6 +946,25 @@ do {									       \
 						ptr,			       \
 						NULL)
 
+/**
+ * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
+ * not cause a KASAN error.
+ *
+ */
+#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do {	\
+	test->kasan_report_expected = true;	\
+	test->kasan_report_found = false; \
+	condition; \
+	if (test->kasan_report_found == test->kasan_report_expected) { \
+		pr_info("%d has passed", __LINE__); \
+	} else { \
+		kunit_set_failure(test); \
+		pr_info("%d has failed", __LINE__); \
+	} \
+	test->kasan_report_expected = false;	\
+	test->kasan_report_found = false;	\
+} while (0)
+
 /**
  * KUNIT_EXPECT_TRUE() - Causes a test failure when the expression is not true.
  * @test: The test context object.
diff --git a/include/linux/sched.h b/include/linux/sched.h
index 04278493bf15..db23d56061e7 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -32,6 +32,8 @@
 #include <linux/posix-timers.h>
 #include <linux/rseq.h>
 
+#include <kunit/test.h>
+
 /* task_struct member predeclarations (sorted alphabetically): */
 struct audit_context;
 struct backing_dev_info;
@@ -1178,7 +1180,10 @@ struct task_struct {
 
 #ifdef CONFIG_KASAN
 	unsigned int			kasan_depth;
-#endif
+#ifdef CONFIG_KUNIT
+	struct kunit *kasan_kunit_test;
+#endif /* CONFIG_KUNIT */
+#endif /* CONFIG_KASAN */
 
 #ifdef CONFIG_FUNCTION_GRAPH_TRACER
 	/* Index of current stored address in ret_stack: */
diff --git a/lib/kunit/test.c b/lib/kunit/test.c
index 9242f932896c..d266b9495c67 100644
--- a/lib/kunit/test.c
+++ b/lib/kunit/test.c
@@ -9,11 +9,12 @@
 #include <kunit/test.h>
 #include <linux/kernel.h>
 #include <linux/sched/debug.h>
+#include <linux/sched.h>
 
 #include "string-stream.h"
 #include "try-catch-impl.h"
 
-static void kunit_set_failure(struct kunit *test)
+void kunit_set_failure(struct kunit *test)
 {
 	WRITE_ONCE(test->success, false);
 }
@@ -236,6 +237,10 @@ static void kunit_try_run_case(void *data)
 	struct kunit_suite *suite = ctx->suite;
 	struct kunit_case *test_case = ctx->test_case;
 
+#ifdef CONFIG_KASAN
+	current->kasan_kunit_test = test;
+#endif
+
 	/*
 	 * kunit_run_case_internal may encounter a fatal error; if it does,
 	 * abort will be called, this thread will exit, and finally the parent
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 5ef9f24f566b..5554d23799a5 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -32,6 +32,8 @@
 
 #include <asm/sections.h>
 
+#include <kunit/test.h>
+
 #include "kasan.h"
 #include "../slab.h"
 
@@ -461,6 +463,15 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	u8 tag = get_tag(object);
 
 	object = reset_tag(object);
+
+	if (current->kasan_kunit_test) {
+		if (current->kasan_kunit_test->kasan_report_expected) {
+			current->kasan_kunit_test->kasan_report_found = true;
+			return;
+		}
+		kunit_set_failure(current->kasan_kunit_test);
+	}
+
 	start_report(&flags);
 	pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
 	print_tags(tag, object);
@@ -481,6 +492,14 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
 	if (likely(!report_enabled()))
 		return;
 
+	if (current->kasan_kunit_test) {
+		if (current->kasan_kunit_test->kasan_report_expected) {
+			current->kasan_kunit_test->kasan_report_found = true;
+			return;
+		}
+		kunit_set_failure(current->kasan_kunit_test);
+	}
+
 	disable_trace_on_warning();
 
 	tagged_addr = (void *)addr;
diff --git a/tools/testing/kunit/kunit_kernel.py b/tools/testing/kunit/kunit_kernel.py
index cc5d844ecca1..63eab18a8c34 100644
--- a/tools/testing/kunit/kunit_kernel.py
+++ b/tools/testing/kunit/kunit_kernel.py
@@ -141,7 +141,7 @@ class LinuxSourceTree(object):
 		return True
 
 	def run_kernel(self, args=[], timeout=None, build_dir=''):
-		args.extend(['mem=256M'])
+		args.extend(['mem=256M', 'kasan_multi_shot'])
 		process = self._ops.linux_bin(args, timeout, build_dir)
 		with open(os.path.join(build_dir, 'test.log'), 'w') as f:
 			for line in process.stdout:
-- 
2.25.0.265.gbab2e86ba0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227024301.217042-2-trishalfonso%40google.com.
