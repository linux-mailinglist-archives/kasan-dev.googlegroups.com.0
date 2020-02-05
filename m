Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIGS5TYQKGQEWAIQJGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id ABDA21539B1
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Feb 2020 21:44:16 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id dd24sf2447934edb.1
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2020 12:44:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580935456; cv=pass;
        d=google.com; s=arc-20160816;
        b=pRTfOH5pY7sg+clMMtbijpyMROxGyV3AntH567BxUz6xRZp7ha92aLj7MzUMPT+HA+
         Cdim6ZkKxaN7lWITLqGAEsBAJhW5/SIjh6Y06ztXU3Hjq3R/n2ep/Ze1fU4WxAS9WliJ
         GqJhgASzVJyCoaPoMmCoK0LZaof0SREXQw5111+NziIcFI3Mw7c7ZoDITh4GvqUNzT6d
         QR/dSlbYl7SCRZ88aLXs8j9UhGhgaRO0nBZqPlXWcNRVyqnbSdP6BbEiIRwNMdGveCL3
         dQ3MBTNNaawWjVyyUkXQXfiC7hzij+6si/Ln/b50jI7iB5+PeWZ3BCIMLnsN/8UdqzrA
         0DYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=U4SvT2qlxeWr3xdef7Nsj/uh++JGdXaI+twabyLKLew=;
        b=I0rpRbQChC2bYoYo4X//Sod+ob3j7vRv3APkldejYEiXWHI/E9kuXQnX5ixTi0e+pT
         z6kxmMGlHzJRpw3Fa+3ORW3tT3LzLudkZiDOGL2M1Ie5fKwAZJXaymmh1JA84ld1olyH
         pD4e9ajifEmC+pVpxIx8ecpERlo5pepHXpV0MHothzCIrrIUgvl7+8InWv3qsrP0aCBi
         mHiXvR7p/qOfOptqDA4dFUyV3pYAnI3iBZNsVE6sJpBmHGtfDt2/Hbt7iIXZwT+3wSsk
         7hq20A7kk3FTOluNkbo3cBObQG5uFGQDYjPuoiU/WKAJCHTSg/ow3OGgS3QUm8KFD08v
         /z8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N9O2+F8H;
       spf=pass (google.com: domain of 3hyk7xgukcvy29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Hyk7XgUKCVY29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=U4SvT2qlxeWr3xdef7Nsj/uh++JGdXaI+twabyLKLew=;
        b=HZqU8RnCzV4Ap+WxGsKCFlfTpROx4ORnqvtski2e66n1YETL7b+TXqjVZrZqCbJNus
         /cJBvkAWZsfIxN5JD4RvvKzFa7qpRihAPHWocSVfYFKdOXP8ItvTiXqEXXq/hblG15b/
         f7v3XKcLIXqCZ18z2HyywYDXHc1rW7KgmsJONKJWN7JmrYCPeILqxJ0o50kW6359qtbj
         cdLlXg5jTuhLX8QUXkXbKLjnh7xGY3VN0Ql1QxzPhiPwsj0veFq6ZvbAQZN/d1yuVz5I
         IqFtjdlxlz9Np7SB55NKcXgmi1iS4+7SoJ6Wvo59Eg2MQcvCcI0CXDa3ssSzFUgS4Bdg
         yEng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=U4SvT2qlxeWr3xdef7Nsj/uh++JGdXaI+twabyLKLew=;
        b=pg3kfMveBXhKxAgfW8O+wYB6Pd1Lw7LDpfPyCMl5qBH9NocCXDz2NPg2mWX4WN4/E5
         58Buoq8+X9BubrjKKQAvYC3Pr1nasYu0M8py3IS4ns5uIywMyxXMqkxTs2n+TDQ/Dwmk
         i2RlYRcj77fufjL0V+J94ncUS2nZgfxC+vQkcl/n7Wa1SrUh+xuD2KBImvsIlX4BHjQb
         4w1hSZ8kAzEqrDMhBYOIV+ceG8X+kMtQOeytRvRw3693B0momCRuwzElUeAQ9kM9M7yF
         rn2kw7xweyz6Ngnk33spSGJ03643WAKiDaokw+DL8vOF5ZXpD+nXpiWFEHXZEwjffleF
         BQLg==
X-Gm-Message-State: APjAAAV8VY+b9fM30GO4SmIbDMagqRZoUgoj49tuE2hxbbNm4Vlhp/+7
	JM3Wy2D/JYUx3089C8gRCLc=
X-Google-Smtp-Source: APXvYqwMmBjJRk827/qHZLVSav8mkZRfbaXW8ErI5mMrznnqUK6E5B099JZ9AEwhicTNwRryXcxrVw==
X-Received: by 2002:a05:6402:228c:: with SMTP id cw12mr6600535edb.151.1580935456396;
        Wed, 05 Feb 2020 12:44:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:584f:: with SMTP id h15ls1422004ejs.9.gmail; Wed, 05
 Feb 2020 12:44:15 -0800 (PST)
X-Received: by 2002:a17:906:1117:: with SMTP id h23mr32661525eja.88.1580935455733;
        Wed, 05 Feb 2020 12:44:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580935455; cv=none;
        d=google.com; s=arc-20160816;
        b=xg/TUA48NrdI5V6n1GXeE7kfvF6y3k16PVNBn+s6CzW8PxNmmbmCwkbY6q4NQLQQKV
         e5wLBYUNvQAC5qzr+dqXP3LinI2QCpmLv7eNLDQbdIH6jx/s6xMWAf3dV7fVrQG0wQTe
         z+dbfqb/Z20WK9mEyhh6JzvPWhs3mv5FU0gwcwuk493mJvIon5WuVzQMBWOFlYnCxPLV
         ZElEKnPwjlpAhXARGLPvO6SILnPM/lHlHPERtrSSplLJW0bDhPZkv/IDEmdecFqKr4TC
         Y7tRpOF0ag4P/kHmBfNihw9/38st4TsCZ8sGg7Wh+QfnonWnBVFKbyZ4ozE4yBFoD9KL
         RYuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=n91DHyeQsL6KJi+PzY/lmETuokxLoyCiTyEI3zpbN6o=;
        b=vVxavJEq5MI3dQrykKseEXIc01Qsdz4jQ/v5kRw5iqT07EsVfr4tvu0AH4v9gu2yZ7
         RS0hfnWVrTHnL07hegMj+iLmwSvVzqXz62bF2O4xMvZvWCMNFyA63zBR0oMrlS8Y2e8J
         ZzMApdcCYAnFTzfLKa7azu7ZFYggWLmiFV1Nn4bEkG7BO3oqeiWQfkYTfkYkJ5Liehu4
         ilQMWi9B126DJQU8oIih1WwVpjH1YEKgs4cnC+wU7cVPzgpqGCGS9IOyeredp4/4IzD4
         8YFVteWHLwy5H8vX9eiPa0ombByTrm19bYIYRtG8toI1+nyk7fcdhmHZHOJsMyUp7AUL
         Oe/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N9O2+F8H;
       spf=pass (google.com: domain of 3hyk7xgukcvy29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Hyk7XgUKCVY29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id n21si44873eja.0.2020.02.05.12.44.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Feb 2020 12:44:15 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hyk7xgukcvy29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id a12so2080897wrn.19
        for <kasan-dev@googlegroups.com>; Wed, 05 Feb 2020 12:44:15 -0800 (PST)
X-Received: by 2002:a05:6000:50:: with SMTP id k16mr331765wrx.145.1580935455011;
 Wed, 05 Feb 2020 12:44:15 -0800 (PST)
Date: Wed,  5 Feb 2020 21:43:31 +0100
Message-Id: <20200205204333.30953-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH 1/3] kcsan: Introduce KCSAN_ACCESS_ASSERT access type
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=N9O2+F8H;       spf=pass
 (google.com: domain of 3hyk7xgukcvy29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Hyk7XgUKCVY29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
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
and writes to assert certain properties of synchronization logic, where
bugs could not be detected as normal data races.

For example, a variable that is only meant to be written by a single
CPU, but may be read (without locking) by other CPUs must still be
marked properly to avoid data races. However, concurrent writes,
regardless if WRITE_ONCE() or not, would be a bug. Using
kcsan_check_access(&x, sizeof(x), KCSAN_ACCESS_ASSERT) would allow
catching such bugs.

Notably, the KCSAN_ACCESS_ASSERT type disables various filters, so that
all races that KCSAN observes are reported.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kcsan-checks.h |  8 +++++++-
 kernel/kcsan/core.c          | 24 +++++++++++++++++++++---
 kernel/kcsan/report.c        | 11 +++++++++++
 3 files changed, 39 insertions(+), 4 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index ef3ee233a3fa9..21b1d1f214ad5 100644
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
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 82c2bef827d42..190fb5c958fe3 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
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
@@ -307,6 +315,7 @@ static noinline void
 kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 {
 	const bool is_write = (type & KCSAN_ACCESS_WRITE) != 0;
+	const bool is_assertion = (type & KCSAN_ACCESS_ASSERT) != 0;
 	atomic_long_t *watchpoint;
 	union {
 		u8 _1;
@@ -430,12 +439,21 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		 * No need to increment 'data_races' counter, as the racing
 		 * thread already did.
 		 */
-		kcsan_report(ptr, size, type, size > 8 || value_change,
-			     smp_processor_id(), KCSAN_REPORT_RACE_SIGNAL);
+
+		/*
+		 * - If we were not able to observe a value change due to size
+		 *   constraints, always assume a value change.
+		 * - If the access type is an assertion, we also always assume a
+		 *   value change to always report the race.
+		 */
+		value_change = value_change || size > 8 || is_assertion;
+
+		kcsan_report(ptr, size, type, value_change, smp_processor_id(),
+			     KCSAN_REPORT_RACE_SIGNAL);
 	} else if (value_change) {
 		/* Inferring a race, since the value should not have changed. */
 		kcsan_counter_inc(KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN);
-		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN))
+		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN) || is_assertion)
 			kcsan_report(ptr, size, type, true,
 				     smp_processor_id(),
 				     KCSAN_REPORT_RACE_UNKNOWN_ORIGIN);
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 7cd34285df740..938146104e046 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -178,6 +178,17 @@ static const char *get_access_type(int type)
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
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200205204333.30953-1-elver%40google.com.
