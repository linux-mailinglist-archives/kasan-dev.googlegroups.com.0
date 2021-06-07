Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMVP7CCQMGQE5A52YAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CE3839DD1D
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jun 2021 14:57:23 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id m27-20020a056000025bb0290114d19822edsf7815715wrz.21
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jun 2021 05:57:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623070643; cv=pass;
        d=google.com; s=arc-20160816;
        b=sXRUO3qfczJAZID36euDVJPviQY4Bp1f1l5lZFdbU1t+Q+cPRlSJCzoc7JNHS9xhSG
         JcA00o9k1YzB6XGWz2wyY8YDLf7ECZav69PgaIjscSCChzttSEapo4NEE8sWdsAXiJlN
         DI8DEv0Q5UqDDd8ZcHiuZGvQhIJCqf7d/XPH7QL6JR8O6vM9yvXaSygmkfqPAK6aLD7k
         nselCiZyzaf2OyElPqftSnUy5pzF/KVWQf2gmO4Zohn+S8H/3gfQKlTVVR2gADOo2JwX
         LpInV9AkgnnPo/1rB31IQ6kofaQPqMDJxFl5i6DRM32pw1X6o8D5WUR+f29icZltw27s
         eFbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=yKTNXdp+X1Z1GXZSYpPFdt2ZbD+64vDEeXuKuwTEvP8=;
        b=OUeiBLA+mu5mZl4FIhcYcg3RodAUbY28oLAnVCPULriDNJt9HYf/BtwzoXjX1Qm0hn
         CNzJveV3a7xZa7ri1PrWGIJbG2iYbmF8+2V+Dmq2R202CPCqY9xIWcEZPIJTSF5Tzs5z
         rMUubgXIcySdLYgTH4Aqe0y4nS0DTtZyksWU9nfZxOye3rEdChGKBc6iCdyg+uUO8G7M
         bBVa1fDbKmUxAasn+t466NtX9qRsudG1XAQttBxS/DtSUAUGLCemIgGa5A+x/l5NAaqE
         Tf5DIEtCgIJf6ANEKxxdDbf3ZC7OPSHuXPXUA8FP0Lbs80pezJcug2BGAMv4C3Ayu1qn
         SYgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OornHdIc;
       spf=pass (google.com: domain of 3sre-yaukceqkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3sRe-YAUKCeQKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yKTNXdp+X1Z1GXZSYpPFdt2ZbD+64vDEeXuKuwTEvP8=;
        b=L6tTGRV0WeV0yPNp/E9DgFNBJBXGfec87Vgle4+a5xqBlnSeOvPJVmSSU92yHDzpDM
         PSBYUfpnZvcH3HhSchaiOYe5kku2JySD1YjG/PHFrBC5KBhPNGS+61rtJOvtUnIBemwj
         5KBOJWe3JAae7zu7YtJTTB1pfltxZFj68rJQKniIEljI2/CfAqB84YYH1bDI2OAWAM9r
         dAgvMEoMb218LRGOEkOEjWWC1za0mbEpy5wkJgpXGDTz6LGXR97CPdEQ6aPEwU+mAAs5
         fIsLYk8Fq+8gfeWDi1IHg4mzlhNRenZKMzPoRY4MRssM8XX3VmjxZ4crHpWjiZrYfKKl
         E5Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yKTNXdp+X1Z1GXZSYpPFdt2ZbD+64vDEeXuKuwTEvP8=;
        b=qUVvJClmvXdI9N7X8loGzLw5+dl9dlMaEyWE1m/bTx9bZLth661AJQrjVNpqfszaYi
         qO2FYp82fn5OD0pdWRAT/64lVcks2zdvCGyOgycpzNCGGkzPeqOcg6TxEeWeNa8oPADP
         snWUNph24qbADGFTtbaubOZTMORWTu0IUSYJv/cK/ZH8qhhOvDG1uEJRHp2jcK85mmkG
         WMxZx9X8DWwlrN7brboxwGwqWlj7Rj/yZXpcBw0Ja0VjSUD7WrsNl6Ct0hVyHTQ7GD59
         OtTlbjA1MQfNaYgbHE0ygqY/U0/yQpXM//jhv0+0MGMMoHWiVaRrwvSTQZg5mEPuH3s3
         1WFA==
X-Gm-Message-State: AOAM530vPkZrWXLJn2cI98xK9PNR68qbm+rRdAv4ZADGweUD7E0EBQ2Q
	yxhTvF8F7MZkuC/MuIbOdwo=
X-Google-Smtp-Source: ABdhPJxPN9Bf11qCjQYXkCm4EZAKUsN7To6AO3Sqv0ftAWCvDXH8ml75WYzWwEVSMbha3uxk9iaQ6A==
X-Received: by 2002:adf:ba07:: with SMTP id o7mr13528953wrg.160.1623070643134;
        Mon, 07 Jun 2021 05:57:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f418:: with SMTP id z24ls554728wma.1.gmail; Mon, 07 Jun
 2021 05:57:22 -0700 (PDT)
X-Received: by 2002:a05:600c:2248:: with SMTP id a8mr17124462wmm.5.1623070642197;
        Mon, 07 Jun 2021 05:57:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623070642; cv=none;
        d=google.com; s=arc-20160816;
        b=KtePH7M5GXlX6vrJ+GlRQan6BAbwEQKOkmKC6kguPvJB9JP9nc/b65ixpcx80T1mG3
         Iv7olwAO6Hmlftx98ZbGZevGsJ6dN/f/vYlHYIE4AnKnMpm5puurGhDhmk+qEsx0O0CD
         QAP+1ZXd4qtDnfH5vI7NlbIeh7wy2YUv6AZkHW3rm2t1T8QI+5FoOTzELNwdVuWJ19p6
         3MDgdZSzAppud17FYVdAh0XLrmkcYj6Co1EuElAKL5qAxyan4l80fvhjj5ZhpKIQPV2e
         3tMttl7FrLfDzaiypFAkJT6sI+dpzL7SaC1VC/u03rMp5/TO5fqs0VZPvlkJk4DDzVTZ
         V3wA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=E19dPyijryKX8oHPsQVCw55m+yv2afCj/5+25DTbMh0=;
        b=fneEn6+NNhrIXqoTH4nNGccul6xtQCKyHXOWu91Lop2UbNGwizb7+QR+bHOakJ75fn
         7w+hmCUyLpiTKciJ6SpbuTQb6ckdojC0IivyplCWBMw01/utbf0mpAu5tGD61BPF1eXh
         v3R5nfL3ZWVVHxznqBzC7KL/jyFvqoxifjLdvYzuhWLDTjNiI/DL7kDR5L0XBGV2YdaU
         uk3Mb0olk79isPaFHYU6nZEOe9KhagPqxgwBsCF2bS5H65NICBcsWFo5tmvnrRhkyTOb
         31d+RctYIGryn9eJzmpt9pLhMUTN1x+xSYxjQxwOtZKeOXrEajfP+Js4RqutF4WaqoTh
         Rj7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OornHdIc;
       spf=pass (google.com: domain of 3sre-yaukceqkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3sRe-YAUKCeQKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id f23si58729wmh.2.2021.06.07.05.57.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jun 2021 05:57:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3sre-yaukceqkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id c21-20020a0564021015b029038c3f08ce5aso9301279edu.18
        for <kasan-dev@googlegroups.com>; Mon, 07 Jun 2021 05:57:22 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:2587:50:741c:6fde])
 (user=elver job=sendgmr) by 2002:a05:6402:5a:: with SMTP id
 f26mr19874084edu.306.1623070641707; Mon, 07 Jun 2021 05:57:21 -0700 (PDT)
Date: Mon,  7 Jun 2021 14:56:53 +0200
In-Reply-To: <20210607125653.1388091-1-elver@google.com>
Message-Id: <20210607125653.1388091-8-elver@google.com>
Mime-Version: 1.0
References: <20210607125653.1388091-1-elver@google.com>
X-Mailer: git-send-email 2.32.0.rc1.229.g3e70b5a671-goog
Subject: [PATCH 7/7] kcsan: permissive: Ignore data-racy 1-bit value changes
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: boqun.feng@gmail.com, mark.rutland@arm.com, will@kernel.org, 
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OornHdIc;       spf=pass
 (google.com: domain of 3sre-yaukceqkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3sRe-YAUKCeQKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
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

Add rules to ignore data-racy reads with only 1-bit value changes.
Details about the rules are captured in comments in
kernel/kcsan/permissive.h. More background follows.

While investigating a number of data races, we've encountered data-racy
accesses on flags variables to be very common. The typical pattern is a
reader masking all but one bit, and/or the writer setting/clearing only
1 bit (current->flags being a frequently encountered case; more examples
in mm/sl[au]b.c, which disable KCSAN for this reason).

Since these types of data-racy accesses are common (with the assumption
they are intentional and hard to miscompile) having the option (with
CONFIG_KCSAN_PERMISSIVE=y) to filter them will avoid forcing everyone to
mark them, and deliberately left to preference at this time.

One important motivation for having this option built-in is to move
closer to being able to enable KCSAN on CI systems or for testers
wishing to test the whole kernel, while more easily filtering
less interesting data races with higher probability.

For the implementation, we considered several alternatives, but had one
major requirement: that the rules be kept together with the Linux-kernel
tree. Adding them to the compiler would preclude us from making changes
quickly; if the rules require tweaks, having them part of the compiler
requires waiting another ~1 year for the next release -- that's not
realistic. We are left with the following options:

	1. Maintain compiler plugins as part of the kernel-tree that
	   removes instrumentation for some accesses (e.g. plain-& with
	   1-bit mask). The analysis would be reader-side focused, as
	   no assumption can be made about racing writers.

Because it seems unrealistic to maintain 2 plugins, one for LLVM and
GCC, we would likely pick LLVM. Furthermore, no kernel infrastructure
exists to maintain LLVM plugins, and the build-system implications and
maintenance overheads do not look great (historically, plugins written
against old LLVM APIs are not guaranteed to work with newer LLVM APIs).

	2. Find a set of rules that can be expressed in terms of
	   observed value changes, and make it part of the KCSAN runtime.
	   The analysis is writer-side focused, given we rely on observed
	   value changes.

The approach taken here is (2). While a complete approach requires both
(1) and (2), experiments show that the majority of data races involving
trivial bit operations on flags variables can be removed with (2) alone.

It goes without saying that the filtering of data races using (1) or (2)
does _not_ guarantee they are safe! Therefore, limiting ourselves to (2)
for now is the conservative choice for setups that wish to enable
CONFIG_KCSAN_PERMISSIVE=y.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/kcsan_test.c | 32 +++++++++++++++++++++++++
 kernel/kcsan/permissive.h | 49 ++++++++++++++++++++++++++++++++++++++-
 2 files changed, 80 insertions(+), 1 deletion(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 8bcffbdef3d3..dc55fd5a36fc 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -414,6 +414,14 @@ static noinline void test_kernel_atomic_builtins(void)
 	__atomic_load_n(&test_var, __ATOMIC_RELAXED);
 }
 
+static noinline void test_kernel_xor_1bit(void)
+{
+	/* Do not report data races between the read-writes. */
+	kcsan_nestable_atomic_begin();
+	test_var ^= 0x10000;
+	kcsan_nestable_atomic_end();
+}
+
 /* ===== Test cases ===== */
 
 /* Simple test with normal data race. */
@@ -952,6 +960,29 @@ static void test_atomic_builtins(struct kunit *test)
 	KUNIT_EXPECT_FALSE(test, match_never);
 }
 
+__no_kcsan
+static void test_1bit_value_change(struct kunit *test)
+{
+	const struct expect_report expect = {
+		.access = {
+			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
+			{ test_kernel_xor_1bit, &test_var, sizeof(test_var), __KCSAN_ACCESS_RW(KCSAN_ACCESS_WRITE) },
+		},
+	};
+	bool match = false;
+
+	begin_test_checks(test_kernel_read, test_kernel_xor_1bit);
+	do {
+		match = IS_ENABLED(CONFIG_KCSAN_PERMISSIVE)
+				? report_available()
+				: report_matches(&expect);
+	} while (!end_test_checks(match));
+	if (IS_ENABLED(CONFIG_KCSAN_PERMISSIVE))
+		KUNIT_EXPECT_FALSE(test, match);
+	else
+		KUNIT_EXPECT_TRUE(test, match);
+}
+
 /*
  * Generate thread counts for all test cases. Values generated are in interval
  * [2, 5] followed by exponentially increasing thread counts from 8 to 32.
@@ -1024,6 +1055,7 @@ static struct kunit_case kcsan_test_cases[] = {
 	KCSAN_KUNIT_CASE(test_jiffies_noreport),
 	KCSAN_KUNIT_CASE(test_seqlock_noreport),
 	KCSAN_KUNIT_CASE(test_atomic_builtins),
+	KCSAN_KUNIT_CASE(test_1bit_value_change),
 	{},
 };
 
diff --git a/kernel/kcsan/permissive.h b/kernel/kcsan/permissive.h
index f90e30800c11..2c01fe4a59ee 100644
--- a/kernel/kcsan/permissive.h
+++ b/kernel/kcsan/permissive.h
@@ -12,6 +12,8 @@
 #ifndef _KERNEL_KCSAN_PERMISSIVE_H
 #define _KERNEL_KCSAN_PERMISSIVE_H
 
+#include <linux/bitops.h>
+#include <linux/sched.h>
 #include <linux/types.h>
 
 /*
@@ -22,7 +24,11 @@ static __always_inline bool kcsan_ignore_address(const volatile void *ptr)
 	if (!IS_ENABLED(CONFIG_KCSAN_PERMISSIVE))
 		return false;
 
-	return false;
+	/*
+	 * Data-racy bitops on current->flags are too common, ignore completely
+	 * for now.
+	 */
+	return ptr == &current->flags;
 }
 
 /*
@@ -41,6 +47,47 @@ kcsan_ignore_data_race(size_t size, int type, u64 old, u64 new, u64 diff)
 	if (type || size > sizeof(long))
 		return false;
 
+	/*
+	 * A common pattern is checking/setting just 1 bit in a variable; for
+	 * example:
+	 *
+	 *	if (flags & SOME_FLAG) { ... }
+	 *
+	 * and elsewhere flags is updated concurrently:
+	 *
+	 *	flags |= SOME_OTHER_FLAG; // just 1 bit
+	 *
+	 * While it is still recommended that such accesses be marked
+	 * appropriately, in many cases these types of data races are so common
+	 * that marking them all is often unrealistic and left to maintainer
+	 * preference.
+	 *
+	 * The assumption in all cases is that with all known compiler
+	 * optimizations (including those that tear accesses), because no more
+	 * than 1 bit changed, the plain accesses are safe despite the presence
+	 * of data races.
+	 *
+	 * The rules here will ignore the data races if we observe no more than
+	 * 1 bit changed.
+	 *
+	 * Of course many operations can effecively change just 1 bit, but the
+	 * general assuption that data races involving 1-bit changes can be
+	 * tolerated still applies.
+	 *
+	 * And in case a true bug is missed, the bug likely manifests as a
+	 * reportable data race elsewhere.
+	 */
+	if (hweight64(diff) == 1) {
+		/*
+		 * Exception: Report data races where the values look like
+		 * ordinary booleans (one of them was 0 and the 0th bit was
+		 * changed) More often than not, they come with interesting
+		 * memory ordering requirements, so let's report them.
+		 */
+		if (!((!old || !new) && diff == 1))
+			return true;
+	}
+
 	return false;
 }
 
-- 
2.32.0.rc1.229.g3e70b5a671-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210607125653.1388091-8-elver%40google.com.
