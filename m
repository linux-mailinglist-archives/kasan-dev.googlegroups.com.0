Return-Path: <kasan-dev+bncBCJZRXGY5YJBBQEZ4KDQMGQE3HOEQXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 843D63D18B0
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 23:08:17 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id g9-20020a05620a40c9b02903b9a74cee72sf2383781qko.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 14:08:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626901696; cv=pass;
        d=google.com; s=arc-20160816;
        b=yaq4Ci2U1anWtwDMMMPgnFIi3kEyDE6xeBd4e5Qb4/G9m1SrCRI4cSVDzvPK6oy1xC
         vI8afi9k4/GYV0zYIy2Ex+CVWxEJnSWd2LXTIIGG7G9mL5IWcsa5QDYzh1coFJHGuiuM
         HQdJmVkovJ8XDG9RGEUNCoGEfeo1NGoaq9oe46fTzImcCUHYY41gvdOVJF/4o1YUwGMB
         Dpl4gOd2AncGHT/KQcNOIF22cq1KVFzi1+sSBf5wVEfsIM73hJP3cH3WyCzqgt7mnV4w
         MtP6pYDjm+ErtFn3sNM2ccjRGImvoI3eVU4eTD/0klRvrcTNg7i2OAq4VWWTYGO/PTfS
         3Ovg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=M3RpX+amF/L9CjfSAr09VvbGC65/ECB2Pt+GZE22YmU=;
        b=k2kCzKwh0FLJmheDNnxfHGvP0sdecnMjdt7mgIogWAMutxfrhDz25C9mdZ/PRmcCyX
         yYRcprV3X1ONQ7J+l1RHmskfpan3Cu858qTpWjyuBn0oqPkLE3THkfYKMIXdq/vyT90j
         7ampLqmw9sasyP9SaZM18H9bAkWeOhmqpmg31Ww186d72KuRVUY7CYn406xhvdRZqrxE
         jvO2eRIyOrLbhjvx9+u4vLMsQHHf835zZmfqSqJi4itHUVIlYWcXHwybcxEdbPIK9HGq
         2guujSbpHVx8GlMiALsVLhm78mvnuyHqLqESJ7C49Ziy4rN37KpduyfCfaWfszdMd7WC
         V+0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PPcUrc12;
       spf=pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M3RpX+amF/L9CjfSAr09VvbGC65/ECB2Pt+GZE22YmU=;
        b=QVPu8SgmfZGafyqvQx0KaZk5F/r1CwMGF0SztMwmeE1tSYEBJxwqyHWz8mEd4RatSz
         mbPb/bxjFp+G/8uHnVIMrv0qzKyC3yFJv5NyDl46D42V2qbHJfvG+i0Cw6PMAd6XDOUU
         Tg1UZybtIavJx0u0hIlnAFW9/vimxtMokHbtjRGS02VtHehgOoQrCEacamFJKAbyNU+x
         ZZdjQRqzB8HKVzgiDlPVzW4SDmfw7Iixvh2dloEjU4liL45HORYox59wPlC8eqMXgvpM
         qFAZ123JeS6SV7zVaiUeB7goc0SiBdxzrQYdC9xnGkk3bXip9IxvGV0BSTHLZyFtuNF6
         hrlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M3RpX+amF/L9CjfSAr09VvbGC65/ECB2Pt+GZE22YmU=;
        b=eNINaTv2FTzZ7lSeZNxK4wZq8OC3aqg3fl8SuhlZ18tzDO4qKu7NZ5gkf5tVl87cf5
         cAfAmsqIXETzZJuV4ZJwUmnvaKiNuUupebXf82bVbbTT7cCrh45/Wuw9SXkgnTKyOWy9
         8SrGAAQj8Uf9uW92vBMpW5N4crk+r4cgQVvElWV5IcH3ZFpdfm91igAM2qO2yCiVRojB
         iySCC/ng5bpONP/v/WOgNGnqpnDXQ6T6fP2NJBUR0QuFhXAUt1iKigvLDccALqAjHVG2
         eo/RmSjpBL9Azc05hxLPT08CAoJup0XAs/6GrP5D3th51s4g7Dr2VPFoBXncmqXWqskf
         irzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530uExVSaTzjj2odrmJ4y+JWjWdhSr0YP2ueDiGVWRy0v0iLQRBO
	K+H35ByTVJSel1PZbG05xzg=
X-Google-Smtp-Source: ABdhPJxncE+tczi4wkaMej24+PN6DBQ3zNgwmdpBrloTzv2hWhYIGpK0LLle7dRkQ43kbpB6sNKcXg==
X-Received: by 2002:ac8:7087:: with SMTP id y7mr24728713qto.91.1626901696649;
        Wed, 21 Jul 2021 14:08:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a786:: with SMTP id q128ls2737654qke.10.gmail; Wed, 21
 Jul 2021 14:08:16 -0700 (PDT)
X-Received: by 2002:a05:620a:294b:: with SMTP id n11mr9829234qkp.145.1626901696220;
        Wed, 21 Jul 2021 14:08:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626901696; cv=none;
        d=google.com; s=arc-20160816;
        b=0UuAF1wDv3yaOW4TtWt3kCeP9F4w5qqAWADFNdDThHJDwQ3+imN0kbMDXD0u1NV4ea
         MCZsImMORoP09pHScD85OJxeSHx4cCVRyprvrIah7we3IKPpnh+FHrq1qVhB+Z0hr6mr
         1ByTaSbunWAUvrzygtsnFhhIvY4+Icd3nlFB2SOIM8YZYlFaBqnTsd2WnxxQlu+qyYGb
         c2D5OCaZ8YcirIDBunrJ69FO7Lai6OLiAreUk58szyOL8ezO4SkKt4dRK/831dAF3J4Y
         qaKyqpNajDq4mjl8qSsWbRjt1nemiI9RJkDALsDaO78KQcdCZ473pvd/+/g+AGKDvPAQ
         5cFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GjCTeiUbJoixXWqIhu+gqinIRyy7xsLWSrldbjtFn50=;
        b=N8J1oiponyFAGxhE8BZ6HbnE1jVoNrIbE2cOPv4W8koRCg+QRxIDGfDRD0KbhZmpIk
         fUh7UKzgrLuD9F7G7/eQaNiYqb4z7QZl5bmbk3O6uZl2rRTeC6B3A4uGwLFe8PfXUFys
         vfNR7UBFpjOySgMHfJE/UaH7sM+VOAdTjzgOLRQAgyTy3qdZO9esgckQn9g+rJ8ULOZT
         qjhbq4wQR7Rk3/dRh4WUQMhKn6fT16Js6BWFL7Z5Ymo6KInQ319wFTi29NuXjkOubIlP
         h6TlCDbui/ygI6tZFPUrafA83zWnSNHon547TNkHK6Y5uMHB16crQhZutnoQ8PziXw7c
         WHOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PPcUrc12;
       spf=pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 138si2191778qkl.5.2021.07.21.14.08.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Jul 2021 14:08:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id E654261411;
	Wed, 21 Jul 2021 21:08:14 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 6FE745C007F; Wed, 21 Jul 2021 14:08:14 -0700 (PDT)
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
Subject: [PATCH kcsan 7/8] kcsan: permissive: Ignore data-racy 1-bit value changes
Date: Wed, 21 Jul 2021 14:08:11 -0700
Message-Id: <20210721210812.844740-7-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1>
References: <20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PPcUrc12;       spf=pass
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
Acked-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/kcsan_test.c | 32 +++++++++++++++++++++++++
 kernel/kcsan/permissive.h | 49 ++++++++++++++++++++++++++++++++++++++-
 2 files changed, 80 insertions(+), 1 deletion(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 8bcffbdef3d36..dc55fd5a36fcc 100644
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
index f90e30800c11b..2c01fe4a59ee7 100644
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
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210721210812.844740-7-paulmck%40kernel.org.
