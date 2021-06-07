Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLNP7CCQMGQEXBR3FVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id D956F39DD1A
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jun 2021 14:57:18 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id o11-20020a62f90b0000b02902db3045f898sf7637432pfh.23
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jun 2021 05:57:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623070637; cv=pass;
        d=google.com; s=arc-20160816;
        b=jVqecczrj7ZS+MMmfaWRDgcXQdww6Hhj90xhtdZ0AHIfTlvAQexG4OrpiTXIf+z5Zv
         GYOyy2Zmg+QbHh8Oi7n/XAs/aTec9wUR7kIop8p6SX2daoyydLtNpL2PgdVoRek57jUh
         V7LLHPyHnrplp0VwhI0ioPB63de5vfCDbra4cMZG43nzHuWXkb6xPZFlfittgoO5D0hQ
         aQcPSaBT9KnsyY2OHH+h6MTxosbzk68wADteu4T0xT1BoCy3tnglBNtepNpp4MZya5nN
         NzR8SNdcPjxTdMTP/XD/JhUhKMHIRk2ISWGln/J+nlsTSYPUx9MST7r1Ne5RhaAb8hzH
         4iVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=SMHM3ZIBg+LOiWgtIAuC+D/arE34clfe33ryT0Z8TqE=;
        b=Sykjk1tCTJecqXpZVbeRb9n3HkDHGY3LYXgPRAwAK8kSXDS1nZctT7xCXiJSr7AB2v
         anpuvUhHL05UTZjRRe1+PJ9eElDqHtGvM+u9U3VsWy5oFtR9LE5Pzf2btfKLG7e7rvd9
         SC6OoLI20lmd1Ekvyz9AgDxwP1MyMgPRKO9ayeHjadrIyrvHfW+gcoqORWGQGhCEFegs
         E189qqWERLKjsKMUGq8n4ReGGq5cCxbLRXxVd2JofZCvJPM/ldiJDc9M8w5syFLsmuuF
         wSWTP0B5YSNqE1UIVdPjidcZBGssrsckIGFMNLgU1wJYSawEhyhLo1zVsN/KPrynGeUL
         cLYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lyslfoE3;
       spf=pass (google.com: domain of 3rbe-yaukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3rBe-YAUKCd8FMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SMHM3ZIBg+LOiWgtIAuC+D/arE34clfe33ryT0Z8TqE=;
        b=oXz9l6wusiS8yvBsKIRiPD8LP/iCv889OvQg99uZ7f1nByOGXTxvcAGBcKK/ld3vIz
         B943eDu9q2WdwhikMfLny265J+6dMIJDt107ymC3yeiBzgvDcftNLk3C8S9wLUp/9FnP
         PCOfJrKqp5D7ntegvptoHnC28QI6y1/vdjzzBpxYkBNapM4VgcA2W7bcPHUcIr9eTD3+
         /SFsCfFtl/DQKLd/6fzMARMc2U/RuSAGeR46Skgu2UW/BQKN8WnnWAwO91fy81OK2gkA
         O6tkfrX/6WWS7mAWn7TYLOgY5P2MhO0kPdt7puOd5lSZ7hu1KuIuSmF68UPMWBYGPepg
         ljbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SMHM3ZIBg+LOiWgtIAuC+D/arE34clfe33ryT0Z8TqE=;
        b=RFuHeu2FnsFplIR1p+sxtdnaHXCTUe/0vDKwtWSD8zYJQhR49Mfqj8TXOXFdb5Gghq
         Rqi6CP9jyLFhloTkN6fWNScerZ5yP5HCElMVInOdhry/LB7fCqEBTdgA3X5NWS/8J7ZE
         XVtmTTTlovy4ToXwh8cPE2RaCSNdRdWXdiyNHkd4spYw6xWJgYp8ztNpoVh5/fa9YSBz
         tolSirJh5Myvy7/GXn5QAY2KNrXiYyzmTu5bhg7QMFm278sCj48vh/svLXc4ioBLQSTN
         fFXsDnmw6P3ObQig6kMZZodW3gPxvU2TDfbP7rOlFWUq3Anz4JZ9sVkwUJmOoxtL+dP2
         t34g==
X-Gm-Message-State: AOAM530/uEvqRlzPJM+sn0An7DxN0UX/oAZ8YaOx46og7gVbqzMsttxW
	Nvy0zw7ZxQL7cvEcygNrxV8=
X-Google-Smtp-Source: ABdhPJwujJBVSgsSqY0zuZ+cbbQr/pKUDTvrP6TrXlefevC943R+1jVcgUS70eGmFB1uQQKqNKDYaw==
X-Received: by 2002:a17:90a:6d82:: with SMTP id a2mr10597587pjk.150.1623070637594;
        Mon, 07 Jun 2021 05:57:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:aa8d:: with SMTP id d13ls8351352plr.5.gmail; Mon, 07
 Jun 2021 05:57:17 -0700 (PDT)
X-Received: by 2002:a17:90a:a00f:: with SMTP id q15mr15160198pjp.193.1623070637060;
        Mon, 07 Jun 2021 05:57:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623070637; cv=none;
        d=google.com; s=arc-20160816;
        b=efV/Gvtr6V6tZUW8YY4sixXUXfTP/V+wvFFHSHnzAYbliXuvN8bLnCdu/B40PaaM7U
         sIiZOEvqDUDharVBcTyQocBCJazrPFd3jw2KckSr9uOTDMN7Hltd6y2lGtRdPDT8DdS/
         FdkK+vjqePcRY1rsBjJyQXJx7k0j02h7KKVsY1IueAQf3V+pLUhKeDCNd0c/KSfHEMpo
         Mh5195AhfRrfuMg0Q1w/vJ0n/hx3pT1lwSZekGmOBw0nqFt2lyMtL80ZB9VSO7QEtTRQ
         RZnfb4el+F9wVDGDS2uieEHAvi1kq1fYLx9UU5QpPrReQmTUojHuspA620ugc7FBIVov
         ZE+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=LQ3tKh70kw7RBhOdaRUlWmTt0SET4qyIX4Ra2qoSZ0I=;
        b=Mk+ZKVrethnhLMV5BhxCgu2nzzmCAuddOx7A3QUaLz0Z+l3nzMkaZKPLv5uvlc0v+r
         2TvjmKXx0Z4YTaXvVgvT3xkYPEmbEf1Scp7HpccpD4MQO2z2PrQ6YRM26jubMEi2hgxk
         QIwSPs4fNiHt6CoXN09As9/ujrwEsXufMT+7Bcg/X7caCZNg+oAVwe4LnllYr9bl5elE
         Zaalgu+LmJXpyhvfkTwUKHIyPv6QJMGEzrGFYYuFXweJnTI+rR+NnKH/f4VZxh62M3Xh
         q+0Gm3j3JdC0V94+w3wmL4Cd8RPpPsCOsF1evWRno0pYpPWjD8O1r75Ha5J8cAGV87KC
         JxGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lyslfoE3;
       spf=pass (google.com: domain of 3rbe-yaukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3rBe-YAUKCd8FMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id b3si59868pjz.1.2021.06.07.05.57.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jun 2021 05:57:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rbe-yaukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id k12-20020a0cfd6c0000b029020df9543019so10748525qvs.14
        for <kasan-dev@googlegroups.com>; Mon, 07 Jun 2021 05:57:17 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:2587:50:741c:6fde])
 (user=elver job=sendgmr) by 2002:a0c:ab52:: with SMTP id i18mr17507070qvb.23.1623070636590;
 Mon, 07 Jun 2021 05:57:16 -0700 (PDT)
Date: Mon,  7 Jun 2021 14:56:51 +0200
In-Reply-To: <20210607125653.1388091-1-elver@google.com>
Message-Id: <20210607125653.1388091-6-elver@google.com>
Mime-Version: 1.0
References: <20210607125653.1388091-1-elver@google.com>
X-Mailer: git-send-email 2.32.0.rc1.229.g3e70b5a671-goog
Subject: [PATCH 5/7] kcsan: Rework atomic.h into permissive.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: boqun.feng@gmail.com, mark.rutland@arm.com, will@kernel.org, 
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lyslfoE3;       spf=pass
 (google.com: domain of 3rbe-yaukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3rBe-YAUKCd8FMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
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

Rework atomic.h into permissive.h to better reflect its purpose, and
introduce kcsan_ignore_address() and kcsan_ignore_data_race().

Introduce CONFIG_KCSAN_PERMISSIVE and update the stub functions in
preparation for subsequent changes.

As before, developers who choose to use KCSAN in "strict" mode will see
all data races and are not affected. Furthermore, by relying on the
value-change filter logic for kcsan_ignore_data_race(), even if the
permissive rules are enabled, the opt-outs in report.c:skip_report()
override them (such as for RCU-related functions by default).

The option CONFIG_KCSAN_PERMISSIVE is disabled by default, so that the
documented default behaviour of KCSAN does not change. Instead, like
CONFIG_KCSAN_IGNORE_ATOMICS, the option needs to be explicitly opted in.

Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kcsan.rst |  8 ++++++
 kernel/kcsan/atomic.h             | 23 ---------------
 kernel/kcsan/core.c               | 33 ++++++++++++++++------
 kernel/kcsan/permissive.h         | 47 +++++++++++++++++++++++++++++++
 lib/Kconfig.kcsan                 | 10 +++++++
 5 files changed, 89 insertions(+), 32 deletions(-)
 delete mode 100644 kernel/kcsan/atomic.h
 create mode 100644 kernel/kcsan/permissive.h

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index 17f974213b88..9df98a48e69d 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -124,6 +124,14 @@ Kconfig options:
   causes KCSAN to not report data races due to conflicts where the only plain
   accesses are aligned writes up to word size.
 
+* ``CONFIG_KCSAN_PERMISSIVE``: Enable additional permissive rules to ignore
+  certain classes of common data races. Unlike the above, the rules are more
+  complex involving value-change patterns, access type, and address. This
+  option depends on ``CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=y``. For details
+  please see the ``kernel/kcsan/permissive.h``. Testers and maintainers that
+  only focus on reports from specific subsystems and not the whole kernel are
+  recommended to disable this option.
+
 To use the strictest possible rules, select ``CONFIG_KCSAN_STRICT=y``, which
 configures KCSAN to follow the Linux-kernel memory consistency model (LKMM) as
 closely as possible.
diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
deleted file mode 100644
index 530ae1bda8e7..000000000000
--- a/kernel/kcsan/atomic.h
+++ /dev/null
@@ -1,23 +0,0 @@
-/* SPDX-License-Identifier: GPL-2.0 */
-/*
- * Rules for implicitly atomic memory accesses.
- *
- * Copyright (C) 2019, Google LLC.
- */
-
-#ifndef _KERNEL_KCSAN_ATOMIC_H
-#define _KERNEL_KCSAN_ATOMIC_H
-
-#include <linux/types.h>
-
-/*
- * Special rules for certain memory where concurrent conflicting accesses are
- * common, however, the current convention is to not mark them; returns true if
- * access to @ptr should be considered atomic. Called from slow-path.
- */
-static bool kcsan_is_atomic_special(const volatile void *ptr)
-{
-	return false;
-}
-
-#endif /* _KERNEL_KCSAN_ATOMIC_H */
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 906100923b88..439edb9dcbb1 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -20,9 +20,9 @@
 #include <linux/sched.h>
 #include <linux/uaccess.h>
 
-#include "atomic.h"
 #include "encoding.h"
 #include "kcsan.h"
+#include "permissive.h"
 
 static bool kcsan_early_enable = IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE);
 unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
@@ -353,6 +353,7 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 					    atomic_long_t *watchpoint,
 					    long encoded_watchpoint)
 {
+	const bool is_assert = (type & KCSAN_ACCESS_ASSERT) != 0;
 	struct kcsan_ctx *ctx = get_ctx();
 	unsigned long flags;
 	bool consumed;
@@ -374,6 +375,16 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 	if (ctx->access_mask)
 		return;
 
+	/*
+	 * If the other thread does not want to ignore the access, and there was
+	 * a value change as a result of this thread's operation, we will still
+	 * generate a report of unknown origin.
+	 *
+	 * Use CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=n to filter.
+	 */
+	if (!is_assert && kcsan_ignore_address(ptr))
+		return;
+
 	/*
 	 * Consuming the watchpoint must be guarded by kcsan_is_enabled() to
 	 * avoid erroneously triggering reports if the context is disabled.
@@ -396,7 +407,7 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_REPORT_RACES]);
 	}
 
-	if ((type & KCSAN_ACCESS_ASSERT) != 0)
+	if (is_assert)
 		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ASSERT_FAILURES]);
 	else
 		atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_DATA_RACES]);
@@ -427,12 +438,10 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		goto out;
 
 	/*
-	 * Special atomic rules: unlikely to be true, so we check them here in
-	 * the slow-path, and not in the fast-path in is_atomic(). Call after
-	 * kcsan_is_enabled(), as we may access memory that is not yet
-	 * initialized during early boot.
+	 * Check to-ignore addresses after kcsan_is_enabled(), as we may access
+	 * memory that is not yet initialized during early boot.
 	 */
-	if (!is_assert && kcsan_is_atomic_special(ptr))
+	if (!is_assert && kcsan_ignore_address(ptr))
 		goto out;
 
 	if (!check_encodable((unsigned long)ptr, size)) {
@@ -518,8 +527,14 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	if (access_mask)
 		diff &= access_mask;
 
-	/* Were we able to observe a value-change? */
-	if (diff != 0)
+	/*
+	 * Check if we observed a value change.
+	 *
+	 * Also check if the data race should be ignored (the rules depend on
+	 * non-zero diff); if it is to be ignored, the below rules for
+	 * KCSAN_VALUE_CHANGE_MAYBE apply.
+	 */
+	if (diff && !kcsan_ignore_data_race(size, type, old, new, diff))
 		value_change = KCSAN_VALUE_CHANGE_TRUE;
 
 	/* Check if this access raced with another. */
diff --git a/kernel/kcsan/permissive.h b/kernel/kcsan/permissive.h
new file mode 100644
index 000000000000..f90e30800c11
--- /dev/null
+++ b/kernel/kcsan/permissive.h
@@ -0,0 +1,47 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Special rules for ignoring entire classes of data-racy memory accesses. None
+ * of the rules here imply that such data races are generally safe!
+ *
+ * All rules in this file can be configured via CONFIG_KCSAN_PERMISSIVE. Keep
+ * them separate from core code to make it easier to audit.
+ *
+ * Copyright (C) 2019, Google LLC.
+ */
+
+#ifndef _KERNEL_KCSAN_PERMISSIVE_H
+#define _KERNEL_KCSAN_PERMISSIVE_H
+
+#include <linux/types.h>
+
+/*
+ * Access ignore rules based on address.
+ */
+static __always_inline bool kcsan_ignore_address(const volatile void *ptr)
+{
+	if (!IS_ENABLED(CONFIG_KCSAN_PERMISSIVE))
+		return false;
+
+	return false;
+}
+
+/*
+ * Data race ignore rules based on access type and value change patterns.
+ */
+static bool
+kcsan_ignore_data_race(size_t size, int type, u64 old, u64 new, u64 diff)
+{
+	if (!IS_ENABLED(CONFIG_KCSAN_PERMISSIVE))
+		return false;
+
+	/*
+	 * Rules here are only for plain read accesses, so that we still report
+	 * data races between plain read-write accesses.
+	 */
+	if (type || size > sizeof(long))
+		return false;
+
+	return false;
+}
+
+#endif /* _KERNEL_KCSAN_PERMISSIVE_H */
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index c76fbb3ee09e..26f03c754d39 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -231,4 +231,14 @@ config KCSAN_IGNORE_ATOMICS
 	  due to two conflicting plain writes will be reported (aligned and
 	  unaligned, if CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=n).
 
+config KCSAN_PERMISSIVE
+	bool "Enable all additional permissive rules"
+	depends on KCSAN_REPORT_VALUE_CHANGE_ONLY
+	help
+	  Enable additional permissive rules to ignore certain classes of data
+	  races (also see kernel/kcsan/permissive.h). None of the permissive
+	  rules imply that such data races are generally safe, but can be used
+	  to further reduce reported data races due to data-racy patterns
+	  common across the kernel.
+
 endif # KCSAN
-- 
2.32.0.rc1.229.g3e70b5a671-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210607125653.1388091-6-elver%40google.com.
