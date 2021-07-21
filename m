Return-Path: <kasan-dev+bncBCJZRXGY5YJBBQEZ4KDQMGQE3HOEQXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 317293D18AB
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 23:08:17 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id j186-20020a25d2c30000b029055ed6ffbea6sf4831170ybg.14
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 14:08:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626901696; cv=pass;
        d=google.com; s=arc-20160816;
        b=MTzeLJzQA6A6hDC2aj04TSKTwSCtBQ10Sz0Gj8NVP6Q/eaB7EHdf9v4eift5s5T3bH
         1nM+SyNLch0jONjTM5m4l25MJ0ggABZ9j6KrICG/0eyOPg6TJAbq79R/RBylM8kPzmjO
         w8h0qh+OLqSBiba863nIXN7h5gEdj9JHeQ5qx41kbWJrHYuNs6h1pIS69D/6mAhmP8KU
         LLGmMVE84fK0lZPcoZ/hY7ajsvAae3U/qXMPKbDEQBotP7CWbmmWQBrISNy1NtORx1Mi
         XviZ+69YcwTMXre2d9f7jcSgFDSvViS7XjcEkJj1zYYDLn8A6dK1uGaM9A1UNaUsXWNe
         H5pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=x4lya8IpRkYZdLw8yPTu5CVY+XIhtbmi6TUU2AIFYOo=;
        b=FPHiVVurwUKBhUfG1GzE6v0lR7oRK10N9qKADlOhYl6JibG6W/mCvMW18118333k5m
         CxamSSW16gPyIXoCpCWW6kpr8MliqxmLY+uyrzRob0naDMyrLHOooQrJGpWCTRyVoecM
         eYZtJ3Rg3kmyaDxHa2SpeMeuURAXxOtlz8EvP75JMbueGFANGFi+ksZN65Sz9vpQA2zS
         KgbqOCN7J0InWyA5mHxwrtVFWrfvekh75oi6kM9tGFOSsCZpC0K3SjZvCdkXT0r8QYQy
         /wVm08v7agj9L3XZKzDAr3WZdK0MKiXBuBnFvrPYKcQrHwTTvKX4rMSmHlYGcNl4UmDF
         T4Vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SKsQ4Hl4;
       spf=pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x4lya8IpRkYZdLw8yPTu5CVY+XIhtbmi6TUU2AIFYOo=;
        b=iDVqXrDTSdoKtK4AsZjz8dxVLxwqLIMMesZf57HflIbimh8sf6bc6WRiVbCtKUPgTF
         hAg/mt0ASQkeX+2USIyANFjJ4F24ziTJ5YYQd9tVkAS23alyytAHfo4AeKCSLlzB7dbs
         cmvyD7nyDgLcHf/CaEY3Nrx02WspjGPtWA0tyWKqSaZPXou5+SbVOeZbYYXj5+hz3ido
         OVg/+wlvVWjHWKFushVHIa1+Hr83oRuxaiIIz8BeHRT0ht5F7Uwax3+Bap8q+W7mktp+
         VFm1tNLzRJk/iCDvT3MdqTZ878tIAhD65+L7zPhyF5p0xgiANTzbB/6xr7+BdEDavLhA
         FTIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x4lya8IpRkYZdLw8yPTu5CVY+XIhtbmi6TUU2AIFYOo=;
        b=NB/UU2COjH+i4lbaVrZnYFQIRpKQOgZJVHc4Ccy1LJihE560Cs34oyOogn4oKqaNuB
         fY7gHN5JbRPLWA8l5q4UrU9t0tHVk1IYTQJO3JuRBWh/BYUcIuJmB1g1nnsz6ubXAdBw
         XxuvMlPfkXcMLt7qDil0sXDBeQAU0aXISNYEd0Dbtz9sTrKDIQAgRKtm7JwDk+HOIf61
         Fojml0qdiEt1XCTt4uzMR6GKW0wMXUDy/uJq7qbHMwHV4Oajo9Q3NqL7IoKeP20E8gUC
         1PCA9oQT+rinF/2iHbJipsajRYJpH2MVEoxC7SIOwEn7mbPpdFsPmCGaen6DCoR8xWMw
         M/Bg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5322+uW+VsSBMznCKUEpOBVviNIWM5p7Mh7Nu9rtn2MoyuXJ1qt4
	EBsUSI2d+zLFWams5VAVXM4=
X-Google-Smtp-Source: ABdhPJxCZAfURphgMiBBwXrhUrpsrEqR3kw6o1P/zf4ZWoI9PqVkWPB13h79vfEadVpzgT+Na4HxiQ==
X-Received: by 2002:a5b:4c8:: with SMTP id u8mr48830430ybp.255.1626901696287;
        Wed, 21 Jul 2021 14:08:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9307:: with SMTP id f7ls2080635ybo.10.gmail; Wed, 21 Jul
 2021 14:08:15 -0700 (PDT)
X-Received: by 2002:a5b:586:: with SMTP id l6mr49266599ybp.352.1626901695778;
        Wed, 21 Jul 2021 14:08:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626901695; cv=none;
        d=google.com; s=arc-20160816;
        b=OSTrcg8Mw/2zcFvR1wbmfvc80FD0GJlcU9aLtEXuWYAsaazfS6Cjtv0IrQtoJdXTbj
         TVPRNrJ3rBihpDxn9wkWFZlBRR7uUs72AGGtEY/rfARKR3aXB3shZXf2WrLZRY+yhWB7
         e2+tLdz0Qp+aIoNtvvsbUFjfbjiVrn28F7l1MEOiDvM01kY/317Mp4aRTbQdg/EQlxzB
         +4jPwYvteDiPJb1mJJF7bsXwFb8XSSwJ36XVJiRmzru71AeM5oQ5FPiOngPttA5ZNYYZ
         QtHMDq9jOisMu0Da7EPNrMTCpJa/Fmpi2c8Chnty/xHIqVKhEznkJmJmKutPcga3JqA6
         a6Dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=o1qkAFZUDyZsoAxLYgc0wTHkJYqjDPui/YeYbjGcdcQ=;
        b=nQ+dh72h4rLF3SO8mqI3R9O81SvxeYQSJLUmRC1thbcym8Q8uUBHekI0c1g/zWll/s
         fIC5uMq74iAXLIf3y88U6EZ0smYLh9zz3kJzuMrPzKFjvaziXnW81A4DgsRgzpXlmzbm
         KzmVOcMLscNPZJKo5/o+WholBMDINFNu3R3jMoXoNKS9GpxDhJEHtpslkBqrJ6g0Hy8W
         xwAEJf10ZUHc0BukWXvK3WBLKMjSRqCCAifB8cKSUL6RwVeOf6KT8ZdIeUpUmmfxyOOw
         nwOCf6+TxB436yqj7EHCZCUorYSb3YS/P6IP9aX+flaIfGI8Fz3DqcPfh/wTR+mk+99T
         7+Mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SKsQ4Hl4;
       spf=pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r3si3496497ybc.1.2021.07.21.14.08.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Jul 2021 14:08:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id A5A4361402;
	Wed, 21 Jul 2021 21:08:14 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 66C4E5C0BF4; Wed, 21 Jul 2021 14:08:14 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 5/8] kcsan: Rework atomic.h into permissive.h
Date: Wed, 21 Jul 2021 14:08:09 -0700
Message-Id: <20210721210812.844740-5-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1>
References: <20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SKsQ4Hl4;       spf=pass
 (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

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
Acked-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
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
index 69dc9c502ccc5..7db43c7c09b8c 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -127,6 +127,14 @@ Kconfig options:
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
index 530ae1bda8e75..0000000000000
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
index 906100923b888..439edb9dcbb13 100644
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
index 0000000000000..f90e30800c11b
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
index c76fbb3ee09ec..26f03c754d39b 100644
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
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210721210812.844740-5-paulmck%40kernel.org.
