Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRPL6DYQKGQEKLJUVBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FF1515487E
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2020 16:50:30 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id y15sf1149999ljh.22
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2020 07:50:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581004230; cv=pass;
        d=google.com; s=arc-20160816;
        b=pCoVVBRzs6123dFyocDUMbNXEyyoUZ+ZcQkfOG+WQZvYY6GSkFPodyOp9cSFaPDqgl
         MKB1b1zshIFYMi5XxxcAbk3UTiXl+dJefM9AbmYg8vs5NXru4xnpC5ZEUKyh2KuVLrvE
         +JZ0aLevtf80czYb6Pu4dMO/bhWPJ109yosB4V+/cNAnLxEyp0ibRs+OICNtVZOuUo/N
         a8sAx2DW6DJbiBoL2BqzrrMCrVA5VeOncJw2udwHef6bUqEqyhi66dptsrAhcKdagxOq
         DQOEp7hmvWJ14OEVWpxFTF8CPPcMBeHbz7T16H0iK46TPhbxGixgISmtotN6Pc6YaHpJ
         Xg1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=U6xIVRbHV4RclouhpxmkqNob+fCrjdNQNwBdCLk1oHw=;
        b=CUkpaEaXQowCYFpbMagfiuabNctFbsqnPZKv8sEtwx9DIZio4H8pPmnXhJBrN48Utg
         L5V34qk0HJDTkbhwfTRx0bOzw256U8mjnMs1kgeNL1mTc6YBovfPf3ytzwOXDvszmH3z
         UhhhU0/4eqpDVPmJAhTttrlqrVe2Lc0vl5uUA8VCLM2VCX+DNYDVc5bmh02j11JdfPVm
         3lD+hO5zNLMSNow/6NAI4AlFHcBUDXrdnVYlA97Z3v7LzWXAHgGS7nyaU4zdSW3u6p8+
         t1HYE5Zy/rQ0NaLbPXm2er95SCF8AZyO2Uicltk9b/gQ885G1rBv8ZBPXNvLY64Ij3Ee
         uqdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T4ko0QwI;
       spf=pass (google.com: domain of 3xdu8xgukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3xDU8XgUKCRk3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=U6xIVRbHV4RclouhpxmkqNob+fCrjdNQNwBdCLk1oHw=;
        b=Cx87K+X55UILbY4gtqNw9PC/6MpajzJSn+BSPpi3LQyB4phq6E2du6ygEJtCHXWM0m
         AZjCc2j4WRFKdhwO6DgJGd7moiltmSqF9yOEzxhtnHflDAjy69XPPAPWiKKESYReLsir
         5UOjFDlNA60Az6yh9D9tUYBhd+j9tDeiYLqHDaw2i2DEPhbQ0thZXhokODBXE5YXRvvn
         22qAnX5BT4+4evtzx6whfZ3N0kbdJCOfdddl7JeJVBY57LhLmdt8pk+pMpfCRgwUCQBS
         ZAkp8kNuGElBJRK5R9ZzV04dbe28XakegneWVwBIeC96ABC3aHykwp+B/JXBH4ayHRD7
         dY7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=U6xIVRbHV4RclouhpxmkqNob+fCrjdNQNwBdCLk1oHw=;
        b=IEutdWg8Zn6muqt/5c8CC1HLY1RDeiPmgwnvTgAQsdlf+Sf0nt0eo4iXTQv6T8LeSs
         RY7ItZk8KR/VVoqpqXC0aEuJ1Cz5bC/qM+yQKC3MuXIPhQzJR9SfO5r13kb8Zw4WJZG4
         Nmyp5r07W1JoveNZF7yrTF9zh+i9Zf7JAdMcH4ujkntFJD02mMTLqX9CPaw9RK5XnUzT
         ll8TZfMuyQk0X3FBWGwr+Emm+CV9Ho+GaBUTQbnlUGH57MHp59qJJPUCRwg5G4EeN7wy
         uQBemZI7PBH6BD0AlK6pvthOtZtbPv9DwviukOrQHV4CQ+agSSNwaLdL/+uJoo2IhZCn
         /GKw==
X-Gm-Message-State: APjAAAXMMkOqPU5HLRl1pu7KMQ7H4d3sb4OQ8bBPJ3CrcOABMlrfU6Lt
	NrsmFZVlQQnxBAJtrKydb+Y=
X-Google-Smtp-Source: APXvYqwqZoNwRF0ZJ1EUOY59vVhLWuohXf78OLGH+eQMFDe4JxC/w+i/Tx7aEBBRn2ZrcGkzYoFvjQ==
X-Received: by 2002:ac2:44d5:: with SMTP id d21mr2140720lfm.188.1581004229925;
        Thu, 06 Feb 2020 07:50:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:2247:: with SMTP id i68ls989600lfi.5.gmail; Thu, 06 Feb
 2020 07:50:29 -0800 (PST)
X-Received: by 2002:a19:f514:: with SMTP id j20mr2179566lfb.31.1581004228799;
        Thu, 06 Feb 2020 07:50:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581004228; cv=none;
        d=google.com; s=arc-20160816;
        b=uDUWFcSfrBQI6wsLe5HgYLK3R3XDcCE6YwsyHLK0tHrxokoX5O8tcf0ZgzZW4E+nDe
         rEJn3KhhBrE42rpMoDeUUfv87y0dBLkAOnqf6hMYyNlatf1BU54aggWumeXzh3htT02a
         NMrSuQxBeUmx8tdoVxc/21yA9hGyNjXljx+8qT1IUUwgp6zKftb0aJzzmTjXv/GuWDWC
         DUs8a7HcmUE+OAfGhl8yvex7LmD51fxE1TnRY83IljKFu/4ea6bE1WpHwAQEYMCj9ytE
         GfXl4A11wxntxjjSxwLA4+8KSPifhRGedAq0HyILViYVMZl+KclJ8M7jaPKuPTWw6+0y
         mNqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=3Gfnz+tIXog3sdZ5QXRWp8P2M7Buzp6H7vTqH3O8Vf8=;
        b=jp5BRzHcKz9xNyyRctKm94dHb9yWRZ5KZkIeX9ZKgyyAeQ34PRbzOYRpBJuV8qqJMV
         4KZLF9eSv8X1n9V9VrveYlz6mMFMELtPA241Ndjp751adDylLUIJUaQaZC/8ahmoYt1B
         TyrrRr8TJ3fIk0XoDUzMITwaLBFfXwldKf5M3M/gMtqxWmlZJTzlrh6huy1pv0lFzJWE
         U7iKv/WJSQVP0+2hSe1t4kEFDl6AxW8pTOnNWWcub4PI4aLC4WTIXV2TjJCHOKan6F46
         A0wcdhs9WeBNfNC62WHbbefz1d0j83DhkN6AUoqyjb5pmNFdG1Glz59kuK95aECJEI0f
         5pvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T4ko0QwI;
       spf=pass (google.com: domain of 3xdu8xgukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3xDU8XgUKCRk3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id o24si143222lji.4.2020.02.06.07.50.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2020 07:50:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xdu8xgukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id y24so182989wmj.8
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2020 07:50:28 -0800 (PST)
X-Received: by 2002:adf:d0c1:: with SMTP id z1mr4662654wrh.371.1581004228065;
 Thu, 06 Feb 2020 07:50:28 -0800 (PST)
Date: Thu,  6 Feb 2020 16:46:24 +0100
Message-Id: <20200206154626.243230-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH v2 1/3] kcsan: Introduce KCSAN_ACCESS_ASSERT access type
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=T4ko0QwI;       spf=pass
 (google.com: domain of 3xdu8xgukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3xDU8XgUKCRk3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
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

The KCSAN_ACCESS_ASSERT access type may be used to introduce dummy reads
and writes to assert certain properties of concurrent code, where bugs
could not be detected as normal data races.

For example, a variable that is only meant to be written by a single
CPU, but may be read (without locking) by other CPUs must still be
marked properly to avoid data races. However, concurrent writes,
regardless if WRITE_ONCE() or not, would be a bug. Using
kcsan_check_access(&x, sizeof(x), KCSAN_ACCESS_ASSERT) would allow
catching such bugs.

To support KCSAN_ACCESS_ASSERT the following notable changes were made:
  * If an access is of type KCSAN_ASSERT_ACCESS, disable various filters
    that only apply to data races, so that all races that KCSAN observes are
    reported.
  * Bug reports that involve an ASSERT access type will be reported as
    "KCSAN: assert: race in ..." instead of "data-race"; this will help
    more easily distinguish them.
  * Update a few comments to just mention 'races' where we do not always
    mean pure data races.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Update comments to just say 'races' where we do not just mean data races.
* Distinguish bug-type in title of reports.
* Count assertion failures separately.
* Update comment on skip_report.
---
 include/linux/kcsan-checks.h | 18 ++++++++++-----
 kernel/kcsan/core.c          | 44 +++++++++++++++++++++++++++++++-----
 kernel/kcsan/debugfs.c       |  1 +
 kernel/kcsan/kcsan.h         |  7 ++++++
 kernel/kcsan/report.c        | 43 +++++++++++++++++++++++++----------
 lib/Kconfig.kcsan            | 24 ++++++++++++--------
 6 files changed, 103 insertions(+), 34 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index ef3ee233a3fa9..5dcadc221026e 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -6,10 +6,16 @@
 #include <linux/types.h>
 
 /*
- * Access type modifiers.
+ * ACCESS TYPE MODIFIERS
+ *
+ *   <none>: normal read access;
+ *   WRITE : write access;
+ *   ATOMIC: access is atomic;
+ *   ASSERT: access is not a regular access, but an assertion;
  */
 #define KCSAN_ACCESS_WRITE  0x1
 #define KCSAN_ACCESS_ATOMIC 0x2
+#define KCSAN_ACCESS_ASSERT 0x4
 
 /*
  * __kcsan_*: Always calls into the runtime when KCSAN is enabled. This may be used
@@ -18,7 +24,7 @@
  */
 #ifdef CONFIG_KCSAN
 /**
- * __kcsan_check_access - check generic access for data races
+ * __kcsan_check_access - check generic access for races
  *
  * @ptr address of access
  * @size size of access
@@ -43,7 +49,7 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
 #endif
 
 /**
- * __kcsan_check_read - check regular read access for data races
+ * __kcsan_check_read - check regular read access for races
  *
  * @ptr address of access
  * @size size of access
@@ -51,7 +57,7 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
 #define __kcsan_check_read(ptr, size) __kcsan_check_access(ptr, size, 0)
 
 /**
- * __kcsan_check_write - check regular write access for data races
+ * __kcsan_check_write - check regular write access for races
  *
  * @ptr address of access
  * @size size of access
@@ -60,7 +66,7 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
 	__kcsan_check_access(ptr, size, KCSAN_ACCESS_WRITE)
 
 /**
- * kcsan_check_read - check regular read access for data races
+ * kcsan_check_read - check regular read access for races
  *
  * @ptr address of access
  * @size size of access
@@ -68,7 +74,7 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
 #define kcsan_check_read(ptr, size) kcsan_check_access(ptr, size, 0)
 
 /**
- * kcsan_check_write - check regular write access for data races
+ * kcsan_check_write - check regular write access for races
  *
  * @ptr address of access
  * @size size of access
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 82c2bef827d42..87ef01e40199d 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -56,7 +56,7 @@ static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx) = {
 
 /*
  * SLOT_IDX_FAST is used in the fast-path. Not first checking the address's primary
- * slot (middle) is fine if we assume that data races occur rarely. The set of
+ * slot (middle) is fine if we assume that races occur rarely. The set of
  * indices {SLOT_IDX(slot, i) | i in [0, NUM_SLOTS)} is equivalent to
  * {SLOT_IDX_FAST(slot, i) | i in [0, NUM_SLOTS)}.
  */
@@ -178,6 +178,14 @@ is_atomic(const volatile void *ptr, size_t size, int type)
 	if ((type & KCSAN_ACCESS_ATOMIC) != 0)
 		return true;
 
+	/*
+	 * Unless explicitly declared atomic, never consider an assertion access
+	 * as atomic. This allows using them also in atomic regions, such as
+	 * seqlocks, without implicitly changing their semantics.
+	 */
+	if ((type & KCSAN_ACCESS_ASSERT) != 0)
+		return false;
+
 	if (IS_ENABLED(CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC) &&
 	    (type & KCSAN_ACCESS_WRITE) != 0 && size <= sizeof(long) &&
 	    IS_ALIGNED((unsigned long)ptr, size))
@@ -298,7 +306,11 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 		 */
 		kcsan_counter_inc(KCSAN_COUNTER_REPORT_RACES);
 	}
-	kcsan_counter_inc(KCSAN_COUNTER_DATA_RACES);
+
+	if ((type & KCSAN_ACCESS_ASSERT) != 0)
+		kcsan_counter_inc(KCSAN_COUNTER_ASSERT_FAILURES);
+	else
+		kcsan_counter_inc(KCSAN_COUNTER_DATA_RACES);
 
 	user_access_restore(flags);
 }
@@ -307,6 +319,7 @@ static noinline void
 kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 {
 	const bool is_write = (type & KCSAN_ACCESS_WRITE) != 0;
+	const bool is_assert = (type & KCSAN_ACCESS_ASSERT) != 0;
 	atomic_long_t *watchpoint;
 	union {
 		u8 _1;
@@ -429,13 +442,32 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		/*
 		 * No need to increment 'data_races' counter, as the racing
 		 * thread already did.
+		 *
+		 * Count 'assert_failures' for each failed ASSERT access,
+		 * therefore both this thread and the racing thread may
+		 * increment this counter.
 		 */
-		kcsan_report(ptr, size, type, size > 8 || value_change,
-			     smp_processor_id(), KCSAN_REPORT_RACE_SIGNAL);
+		if (is_assert)
+			kcsan_counter_inc(KCSAN_COUNTER_ASSERT_FAILURES);
+
+		/*
+		 * - If we were not able to observe a value change due to size
+		 *   constraints, always assume a value change.
+		 * - If the access type is an assertion, we also always assume a
+		 *   value change to always report the race.
+		 */
+		value_change = value_change || size > 8 || is_assert;
+
+		kcsan_report(ptr, size, type, value_change, smp_processor_id(),
+			     KCSAN_REPORT_RACE_SIGNAL);
 	} else if (value_change) {
 		/* Inferring a race, since the value should not have changed. */
+
 		kcsan_counter_inc(KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN);
-		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN))
+		if (is_assert)
+			kcsan_counter_inc(KCSAN_COUNTER_ASSERT_FAILURES);
+
+		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN) || is_assert)
 			kcsan_report(ptr, size, type, true,
 				     smp_processor_id(),
 				     KCSAN_REPORT_RACE_UNKNOWN_ORIGIN);
@@ -471,7 +503,7 @@ static __always_inline void check_access(const volatile void *ptr, size_t size,
 				     &encoded_watchpoint);
 	/*
 	 * It is safe to check kcsan_is_enabled() after find_watchpoint in the
-	 * slow-path, as long as no state changes that cause a data race to be
+	 * slow-path, as long as no state changes that cause a race to be
 	 * detected and reported have occurred until kcsan_is_enabled() is
 	 * checked.
 	 */
diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index bec42dab32ee8..a9dad44130e62 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -44,6 +44,7 @@ static const char *counter_to_name(enum kcsan_counter_id id)
 	case KCSAN_COUNTER_USED_WATCHPOINTS:		return "used_watchpoints";
 	case KCSAN_COUNTER_SETUP_WATCHPOINTS:		return "setup_watchpoints";
 	case KCSAN_COUNTER_DATA_RACES:			return "data_races";
+	case KCSAN_COUNTER_ASSERT_FAILURES:		return "assert_failures";
 	case KCSAN_COUNTER_NO_CAPACITY:			return "no_capacity";
 	case KCSAN_COUNTER_REPORT_RACES:		return "report_races";
 	case KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN:	return "races_unknown_origin";
diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
index 8492da45494bf..50078e7d43c32 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -39,6 +39,13 @@ enum kcsan_counter_id {
 	 */
 	KCSAN_COUNTER_DATA_RACES,
 
+	/*
+	 * Total number of ASSERT failures due to races. If the observed race is
+	 * due to two conflicting ASSERT type accesses, then both will be
+	 * counted.
+	 */
+	KCSAN_COUNTER_ASSERT_FAILURES,
+
 	/*
 	 * Number of times no watchpoints were available.
 	 */
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 7cd34285df740..3bc590e6be7e3 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -34,11 +34,11 @@ static struct {
 } other_info = { .ptr = NULL };
 
 /*
- * Information about reported data races; used to rate limit reporting.
+ * Information about reported races; used to rate limit reporting.
  */
 struct report_time {
 	/*
-	 * The last time the data race was reported.
+	 * The last time the race was reported.
 	 */
 	unsigned long time;
 
@@ -57,7 +57,7 @@ struct report_time {
  *
  * Therefore, we use a fixed-size array, which at most will occupy a page. This
  * still adequately rate limits reports, assuming that a) number of unique data
- * races is not excessive, and b) occurrence of unique data races within the
+ * races is not excessive, and b) occurrence of unique races within the
  * same time window is limited.
  */
 #define REPORT_TIMES_MAX (PAGE_SIZE / sizeof(struct report_time))
@@ -74,7 +74,7 @@ static struct report_time report_times[REPORT_TIMES_SIZE];
 static DEFINE_SPINLOCK(report_lock);
 
 /*
- * Checks if the data race identified by thread frames frame1 and frame2 has
+ * Checks if the race identified by thread frames frame1 and frame2 has
  * been reported since (now - KCSAN_REPORT_ONCE_IN_MS).
  */
 static bool rate_limit_report(unsigned long frame1, unsigned long frame2)
@@ -90,7 +90,7 @@ static bool rate_limit_report(unsigned long frame1, unsigned long frame2)
 
 	invalid_before = jiffies - msecs_to_jiffies(CONFIG_KCSAN_REPORT_ONCE_IN_MS);
 
-	/* Check if a matching data race report exists. */
+	/* Check if a matching race report exists. */
 	for (i = 0; i < REPORT_TIMES_SIZE; ++i) {
 		struct report_time *rt = &report_times[i];
 
@@ -114,7 +114,7 @@ static bool rate_limit_report(unsigned long frame1, unsigned long frame2)
 		if (time_before(rt->time, invalid_before))
 			continue; /* before KCSAN_REPORT_ONCE_IN_MS ago */
 
-		/* Reported recently, check if data race matches. */
+		/* Reported recently, check if race matches. */
 		if ((rt->frame1 == frame1 && rt->frame2 == frame2) ||
 		    (rt->frame1 == frame2 && rt->frame2 == frame1))
 			return true;
@@ -142,11 +142,12 @@ skip_report(bool value_change, unsigned long top_frame)
 	 * 3. write watchpoint, conflicting write (value_change==true): report;
 	 * 4. write watchpoint, conflicting write (value_change==false): skip;
 	 * 5. write watchpoint, conflicting read (value_change==false): skip;
-	 * 6. write watchpoint, conflicting read (value_change==true): impossible;
+	 * 6. write watchpoint, conflicting read (value_change==true): report;
 	 *
 	 * Cases 1-4 are intuitive and expected; case 5 ensures we do not report
-	 * data races where the write may have rewritten the same value; and
-	 * case 6 is simply impossible.
+	 * data races where the write may have rewritten the same value; case 6
+	 * is possible either if the size is larger than what we check value
+	 * changes for or the access type is KCSAN_ACCESS_ASSERT.
 	 */
 	if (IS_ENABLED(CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY) && !value_change) {
 		/*
@@ -178,11 +179,27 @@ static const char *get_access_type(int type)
 		return "write";
 	case KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
 		return "write (marked)";
+
+	/*
+	 * ASSERT variants:
+	 */
+	case KCSAN_ACCESS_ASSERT:
+	case KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_ATOMIC:
+		return "assert no writes";
+	case KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_WRITE:
+	case KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
+		return "assert no accesses";
+
 	default:
 		BUG();
 	}
 }
 
+static const char *get_bug_type(int type)
+{
+	return (type & KCSAN_ACCESS_ASSERT) != 0 ? "assert: race" : "data-race";
+}
+
 /* Return thread description: in task or interrupt. */
 static const char *get_thread_desc(int task_id)
 {
@@ -268,13 +285,15 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
 		 * Do not print offset of functions to keep title short.
 		 */
 		cmp = sym_strcmp((void *)other_frame, (void *)this_frame);
-		pr_err("BUG: KCSAN: data-race in %ps / %ps\n",
+		pr_err("BUG: KCSAN: %s in %ps / %ps\n",
+		       get_bug_type(access_type | other_info.access_type),
 		       (void *)(cmp < 0 ? other_frame : this_frame),
 		       (void *)(cmp < 0 ? this_frame : other_frame));
 	} break;
 
 	case KCSAN_REPORT_RACE_UNKNOWN_ORIGIN:
-		pr_err("BUG: KCSAN: data-race in %pS\n", (void *)this_frame);
+		pr_err("BUG: KCSAN: %s in %pS\n", get_bug_type(access_type),
+		       (void *)this_frame);
 		break;
 
 	default:
@@ -427,7 +446,7 @@ void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 	/*
 	 * With TRACE_IRQFLAGS, lockdep's IRQ trace state becomes corrupted if
 	 * we do not turn off lockdep here; this could happen due to recursion
-	 * into lockdep via KCSAN if we detect a data race in utilities used by
+	 * into lockdep via KCSAN if we detect a race in utilities used by
 	 * lockdep.
 	 */
 	lockdep_off();
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 9785bbf9a1d11..f0b791143c6ab 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -4,13 +4,17 @@ config HAVE_ARCH_KCSAN
 	bool
 
 menuconfig KCSAN
-	bool "KCSAN: dynamic data race detector"
+	bool "KCSAN: dynamic race detector"
 	depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN
 	select STACKTRACE
 	help
-	  The Kernel Concurrency Sanitizer (KCSAN) is a dynamic data race
-	  detector, which relies on compile-time instrumentation, and uses a
-	  watchpoint-based sampling approach to detect data races.
+	  The Kernel Concurrency Sanitizer (KCSAN) is a dynamic race detector,
+	  which relies on compile-time instrumentation, and uses a
+	  watchpoint-based sampling approach to detect races.
+
+	  KCSAN's primary purpose is to detect data races. KCSAN can also be
+	  used to check properties, with the help of provided assertions, of
+	  concurrent code where bugs do not manifest as data races.
 
 	  See <file:Documentation/dev-tools/kcsan.rst> for more details.
 
@@ -85,14 +89,14 @@ config KCSAN_SKIP_WATCH_RANDOMIZE
 	  KCSAN_WATCH_SKIP.
 
 config KCSAN_REPORT_ONCE_IN_MS
-	int "Duration in milliseconds, in which any given data race is only reported once"
+	int "Duration in milliseconds, in which any given race is only reported once"
 	default 3000
 	help
-	  Any given data race is only reported once in the defined time window.
-	  Different data races may still generate reports within a duration
-	  that is smaller than the duration defined here. This allows rate
-	  limiting reporting to avoid flooding the console with reports.
-	  Setting this to 0 disables rate limiting.
+	  Any given race is only reported once in the defined time window.
+	  Different races may still generate reports within a duration that is
+	  smaller than the duration defined here. This allows rate limiting
+	  reporting to avoid flooding the console with reports.  Setting this
+	  to 0 disables rate limiting.
 
 # The main purpose of the below options is to control reported data races (e.g.
 # in fuzzer configs), and are not expected to be switched frequently by other
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200206154626.243230-1-elver%40google.com.
