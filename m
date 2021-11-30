Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWE5TCGQMGQEGFEUBNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 54AA54632D9
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:29 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id c15-20020a05651200cf00b0040524451deesf7712961lfp.20
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272729; cv=pass;
        d=google.com; s=arc-20160816;
        b=0HCp7j+YPLzdhW2usN/WaCXtyxeBA65uf80CB6dT4zrpZS5KfSCdL8CRrpzlfe1RT8
         UKS8qQ8OF1ySsg7gs/29uPxLCCK71NlMPwcoOVfP5Wx0hUrFgJV5GJBcoPbb4EzNwXCV
         cEDA+DMj9/NWXDTr5uCXgdPG+iFtMc+5a21B5VjY2R3TdjG4kE5x+KMew16XFcgB3B6n
         ZB8tEunX0mBwa6s6eKgjIW6OjUe7tPDkBr8GVNH/TMl44X79RcQERcT7lJp17Dho+MLf
         PB8eU4qJNA+sLj26ss9Y2q4JxOwpKWmVlsnoW1ATULkbnJemJPRdTGKrDIzQ10hxCgpE
         7CjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=l+uvq8Gma/K/CqNi0qPJ5MW464DFsJkj/rLugAbhIOs=;
        b=sROAG7HjPohrMHT5LDAQqFoRASX4o1mSbwYlGJBt5Snif4+AblXbjgq2aYnLsX2+gc
         0BoHLoJtp3bb0Ipna8aSaUc11a6BbjBFazKFKn/FBKS0/VkaOy2sDPajMlk+PRgvxZI3
         FowFgslfCLnOdSBZbVIJJHHW2NQNhH6cQL7+bnhso7am/8oZ7KK6yn2FeNAd+L4pTULw
         TA5qvE75uG/G8gjmV6X3j2XjsmX35wDDqFWL5boT9Yc8o4+Ymat2SZsJEkZmtlj1Whvh
         65SywDf1IZt8qOhsAEegVxMbQubDdYBytAXDEdnI4X8a7Q0GSIkj33m0EK74MABIlj0I
         Vt1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Qf1SuGMO;
       spf=pass (google.com: domain of 31w6myqukcaaelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31w6mYQUKCaAELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l+uvq8Gma/K/CqNi0qPJ5MW464DFsJkj/rLugAbhIOs=;
        b=l6Mh45D/EqxWFBp2mzp1Z9beZRmz520m/x0G+pEPh1sm2ZmK8SiVCjHT1cLWionJM0
         0KShKs3jUYSJwqN7PHo7pvljNmTgB1qNo/2XeWtdJQTAnLg16oL+ZsM5YP/Mt2ihE7bF
         jnQ3aRh8Qv7JZZzhUTgi4o7NMIzqw5I3gEivl3c0jvCv2rilwVhBeZPLg3/pyhOUksGu
         qmQqddzRG+fgqeemybhoEXSA1mG1GTyES5k/XwXqlbwgxR1gVEX84SNkK5MGpN+C4CQl
         6A8J3rSwnu0iNVxkLnw6fYFZSGOcfwL/K0laXf/bLZ/KQ+3K8bf1UnTbY7OfBQVsxCdK
         vexw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l+uvq8Gma/K/CqNi0qPJ5MW464DFsJkj/rLugAbhIOs=;
        b=CBQ2xJvo/vmVfMonTsxzPKCGdrxgHpTsaUEYzDQ23jOOD3WBIB+Wh2PXLBJVT914E/
         bzLeoVyZJmj1pMkJSEqSWhsFOvRGbDa8SRfEmoQy2g7K2iiVT05ruPMZc7EeGAh4VIM6
         wJ2hq3av2RjqDIVaRsXtaLyQ3uZKjU5EeFaBOHmMaWZPZI88U3w2zWCySEIXLn9/WJoa
         B5kHqs4u9QoPXjT9WZvt8EZhDzkR2f826GawiDtsntHql5L/0D+bpl/gV0tvTw/bDeLS
         L23ifRlv8UuouUPFgmSf5ngmiy2SjbvRJDZ/mUX0EQtSc/YvGElMXaWrpuOB6qgO3iXo
         YP5A==
X-Gm-Message-State: AOAM531ChskdLMiEkyg2SF/nZ3QfMUgnA64u8W2ElFnY1BSaveyDzC8H
	s6PA4W8BubzaCIp2RLIYdY4=
X-Google-Smtp-Source: ABdhPJxWxQxsTQSXg+oynDNF/9J+/64s3LqLXsmHQwFsu44pBgFtCwQoOatS6W/z8ESuJd4HPJpPSg==
X-Received: by 2002:a2e:8189:: with SMTP id e9mr54674841ljg.333.1638272728960;
        Tue, 30 Nov 2021 03:45:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls453000lfu.0.gmail; Tue, 30
 Nov 2021 03:45:28 -0800 (PST)
X-Received: by 2002:a19:9157:: with SMTP id y23mr54922332lfj.277.1638272728040;
        Tue, 30 Nov 2021 03:45:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272728; cv=none;
        d=google.com; s=arc-20160816;
        b=0qG4DSmG3b2nTWE9vQ0PoGkA9pWRag+YMyOmFnrKFWeF13/IYTmMaJ+Mvhfg0YA8fi
         TpuazWG2Uc+mL/5cDzqsEzxRArcF9sWhiiixB2Zoxw9ecFZ8PEuzVQEEh8scXU/xCV0I
         X6zcGYuzDnow4y8nwGPGB3GUVgroq2aOymWjNjtbvuwOlpnGTUfC/5AIg1neSf+NDWxj
         c8CxWiMGq1geUELVAz0zrc5Tk+VmqHJB08S1FwAmmSp8Z3M0n9Kc5YxWtD09GmP4qX3P
         y4Zp0AHDPanj7VfSYGqXn0qtm24NqWwm6ZGdP5TfUXvj9DpoGnqQlfYeN0NPMHdFXm6s
         Ct4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=UU4Lhk72EIyuCjy+G0t4z2bUBJwzL7HcimRlPhkjEC4=;
        b=ckt9a4WTjjMlNRyzns6s5JPuBos54SYigIBGqJQ+GvvRQ/HAzwyXWm166h8Z2pP/dm
         hvRBPR/g7/vPQfsyvgzfBKt+P6KR7NcVUIXgTv3OfMkf06SIvmaepoSJZKrqKEr1fhVc
         imYi6Zblu5uaEqPPft0HpPpdBCow/j/l79okuExdfg8sXF+EMn/54HWzaNXMk7bN+GTY
         7tEX/KSjOzsf6Rcdo+yyuoWB5FIDlwIXTQrPRSh+fbmqMfJZGj+CWaR+DMiQ7x+f7QER
         IHgeK86iVymLIChXdzNrwPfL3mbI0vB8RHHzD8Z1DMuC1A0p0xCtf19+kkDfKKQAGKRb
         dEIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Qf1SuGMO;
       spf=pass (google.com: domain of 31w6myqukcaaelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31w6mYQUKCaAELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id b9si1840940lji.2.2021.11.30.03.45.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 31w6myqukcaaelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id n16-20020a05600c3b9000b003331973fdbbso12722917wms.0
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:28 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a05:600c:2252:: with SMTP id
 a18mr4415894wmm.133.1638272727443; Tue, 30 Nov 2021 03:45:27 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:18 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-11-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 10/25] kcsan: test: Match reordered or normal accesses
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Qf1SuGMO;       spf=pass
 (google.com: domain of 31w6myqukcaaelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31w6mYQUKCaAELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
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

Due to reordering accesses with weak memory modeling, any access can now
appear as "(reordered)".

Match any permutation of accesses if CONFIG_KCSAN_WEAK_MEMORY=y, so that
we effectively match an access if it is denoted "(reordered)" or not.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/kcsan_test.c | 92 +++++++++++++++++++++++++++------------
 1 file changed, 63 insertions(+), 29 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 6e3c2b8bc608..ec054879201b 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -151,7 +151,7 @@ struct expect_report {
 
 /* Check observed report matches information in @r. */
 __no_kcsan
-static bool report_matches(const struct expect_report *r)
+static bool __report_matches(const struct expect_report *r)
 {
 	const bool is_assert = (r->access[0].type | r->access[1].type) & KCSAN_ACCESS_ASSERT;
 	bool ret = false;
@@ -253,6 +253,40 @@ static bool report_matches(const struct expect_report *r)
 	return ret;
 }
 
+static __always_inline const struct expect_report *
+__report_set_scoped(struct expect_report *r, int accesses)
+{
+	BUILD_BUG_ON(accesses > 3);
+
+	if (accesses & 1)
+		r->access[0].type |= KCSAN_ACCESS_SCOPED;
+	else
+		r->access[0].type &= ~KCSAN_ACCESS_SCOPED;
+
+	if (accesses & 2)
+		r->access[1].type |= KCSAN_ACCESS_SCOPED;
+	else
+		r->access[1].type &= ~KCSAN_ACCESS_SCOPED;
+
+	return r;
+}
+
+__no_kcsan
+static bool report_matches_any_reordered(struct expect_report *r)
+{
+	return __report_matches(__report_set_scoped(r, 0)) ||
+	       __report_matches(__report_set_scoped(r, 1)) ||
+	       __report_matches(__report_set_scoped(r, 2)) ||
+	       __report_matches(__report_set_scoped(r, 3));
+}
+
+#ifdef CONFIG_KCSAN_WEAK_MEMORY
+/* Due to reordering accesses, any access may appear as "(reordered)". */
+#define report_matches report_matches_any_reordered
+#else
+#define report_matches __report_matches
+#endif
+
 /* ===== Test kernels ===== */
 
 static long test_sink;
@@ -438,13 +472,13 @@ static noinline void test_kernel_xor_1bit(void)
 __no_kcsan
 static void test_basic(struct kunit *test)
 {
-	const struct expect_report expect = {
+	struct expect_report expect = {
 		.access = {
 			{ test_kernel_write, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
 			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
 		},
 	};
-	static const struct expect_report never = {
+	struct expect_report never = {
 		.access = {
 			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
 			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
@@ -469,14 +503,14 @@ static void test_basic(struct kunit *test)
 __no_kcsan
 static void test_concurrent_races(struct kunit *test)
 {
-	const struct expect_report expect = {
+	struct expect_report expect = {
 		.access = {
 			/* NULL will match any address. */
 			{ test_kernel_rmw_array, NULL, 0, __KCSAN_ACCESS_RW(KCSAN_ACCESS_WRITE) },
 			{ test_kernel_rmw_array, NULL, 0, __KCSAN_ACCESS_RW(0) },
 		},
 	};
-	static const struct expect_report never = {
+	struct expect_report never = {
 		.access = {
 			{ test_kernel_rmw_array, NULL, 0, 0 },
 			{ test_kernel_rmw_array, NULL, 0, 0 },
@@ -498,13 +532,13 @@ static void test_concurrent_races(struct kunit *test)
 __no_kcsan
 static void test_novalue_change(struct kunit *test)
 {
-	const struct expect_report expect_rw = {
+	struct expect_report expect_rw = {
 		.access = {
 			{ test_kernel_write_nochange, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
 			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
 		},
 	};
-	const struct expect_report expect_ww = {
+	struct expect_report expect_ww = {
 		.access = {
 			{ test_kernel_write_nochange, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
 			{ test_kernel_write_nochange, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
@@ -530,13 +564,13 @@ static void test_novalue_change(struct kunit *test)
 __no_kcsan
 static void test_novalue_change_exception(struct kunit *test)
 {
-	const struct expect_report expect_rw = {
+	struct expect_report expect_rw = {
 		.access = {
 			{ test_kernel_write_nochange_rcu, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
 			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
 		},
 	};
-	const struct expect_report expect_ww = {
+	struct expect_report expect_ww = {
 		.access = {
 			{ test_kernel_write_nochange_rcu, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
 			{ test_kernel_write_nochange_rcu, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
@@ -556,7 +590,7 @@ static void test_novalue_change_exception(struct kunit *test)
 __no_kcsan
 static void test_unknown_origin(struct kunit *test)
 {
-	const struct expect_report expect = {
+	struct expect_report expect = {
 		.access = {
 			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
 			{ NULL },
@@ -578,7 +612,7 @@ static void test_unknown_origin(struct kunit *test)
 __no_kcsan
 static void test_write_write_assume_atomic(struct kunit *test)
 {
-	const struct expect_report expect = {
+	struct expect_report expect = {
 		.access = {
 			{ test_kernel_write, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
 			{ test_kernel_write, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
@@ -604,7 +638,7 @@ static void test_write_write_assume_atomic(struct kunit *test)
 __no_kcsan
 static void test_write_write_struct(struct kunit *test)
 {
-	const struct expect_report expect = {
+	struct expect_report expect = {
 		.access = {
 			{ test_kernel_write_struct, &test_struct, sizeof(test_struct), KCSAN_ACCESS_WRITE },
 			{ test_kernel_write_struct, &test_struct, sizeof(test_struct), KCSAN_ACCESS_WRITE },
@@ -626,7 +660,7 @@ static void test_write_write_struct(struct kunit *test)
 __no_kcsan
 static void test_write_write_struct_part(struct kunit *test)
 {
-	const struct expect_report expect = {
+	struct expect_report expect = {
 		.access = {
 			{ test_kernel_write_struct, &test_struct, sizeof(test_struct), KCSAN_ACCESS_WRITE },
 			{ test_kernel_write_struct_part, &test_struct.val[3], sizeof(test_struct.val[3]), KCSAN_ACCESS_WRITE },
@@ -658,7 +692,7 @@ static void test_read_atomic_write_atomic(struct kunit *test)
 __no_kcsan
 static void test_read_plain_atomic_write(struct kunit *test)
 {
-	const struct expect_report expect = {
+	struct expect_report expect = {
 		.access = {
 			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
 			{ test_kernel_write_atomic, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC },
@@ -679,7 +713,7 @@ static void test_read_plain_atomic_write(struct kunit *test)
 __no_kcsan
 static void test_read_plain_atomic_rmw(struct kunit *test)
 {
-	const struct expect_report expect = {
+	struct expect_report expect = {
 		.access = {
 			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
 			{ test_kernel_atomic_rmw, &test_var, sizeof(test_var),
@@ -701,13 +735,13 @@ static void test_read_plain_atomic_rmw(struct kunit *test)
 __no_kcsan
 static void test_zero_size_access(struct kunit *test)
 {
-	const struct expect_report expect = {
+	struct expect_report expect = {
 		.access = {
 			{ test_kernel_write_struct, &test_struct, sizeof(test_struct), KCSAN_ACCESS_WRITE },
 			{ test_kernel_write_struct, &test_struct, sizeof(test_struct), KCSAN_ACCESS_WRITE },
 		},
 	};
-	const struct expect_report never = {
+	struct expect_report never = {
 		.access = {
 			{ test_kernel_write_struct, &test_struct, sizeof(test_struct), KCSAN_ACCESS_WRITE },
 			{ test_kernel_read_struct_zero_size, &test_struct.val[3], 0, 0 },
@@ -741,7 +775,7 @@ static void test_data_race(struct kunit *test)
 __no_kcsan
 static void test_assert_exclusive_writer(struct kunit *test)
 {
-	const struct expect_report expect = {
+	struct expect_report expect = {
 		.access = {
 			{ test_kernel_assert_writer, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT },
 			{ test_kernel_write_nochange, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
@@ -759,7 +793,7 @@ static void test_assert_exclusive_writer(struct kunit *test)
 __no_kcsan
 static void test_assert_exclusive_access(struct kunit *test)
 {
-	const struct expect_report expect = {
+	struct expect_report expect = {
 		.access = {
 			{ test_kernel_assert_access, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_WRITE },
 			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
@@ -777,19 +811,19 @@ static void test_assert_exclusive_access(struct kunit *test)
 __no_kcsan
 static void test_assert_exclusive_access_writer(struct kunit *test)
 {
-	const struct expect_report expect_access_writer = {
+	struct expect_report expect_access_writer = {
 		.access = {
 			{ test_kernel_assert_access, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_WRITE },
 			{ test_kernel_assert_writer, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT },
 		},
 	};
-	const struct expect_report expect_access_access = {
+	struct expect_report expect_access_access = {
 		.access = {
 			{ test_kernel_assert_access, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_WRITE },
 			{ test_kernel_assert_access, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_WRITE },
 		},
 	};
-	const struct expect_report never = {
+	struct expect_report never = {
 		.access = {
 			{ test_kernel_assert_writer, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT },
 			{ test_kernel_assert_writer, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT },
@@ -813,7 +847,7 @@ static void test_assert_exclusive_access_writer(struct kunit *test)
 __no_kcsan
 static void test_assert_exclusive_bits_change(struct kunit *test)
 {
-	const struct expect_report expect = {
+	struct expect_report expect = {
 		.access = {
 			{ test_kernel_assert_bits_change, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT },
 			{ test_kernel_change_bits, &test_var, sizeof(test_var),
@@ -844,13 +878,13 @@ static void test_assert_exclusive_bits_nochange(struct kunit *test)
 __no_kcsan
 static void test_assert_exclusive_writer_scoped(struct kunit *test)
 {
-	const struct expect_report expect_start = {
+	struct expect_report expect_start = {
 		.access = {
 			{ test_kernel_assert_writer_scoped, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_SCOPED },
 			{ test_kernel_write_nochange, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
 		},
 	};
-	const struct expect_report expect_inscope = {
+	struct expect_report expect_inscope = {
 		.access = {
 			{ test_enter_scope, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_SCOPED },
 			{ test_kernel_write_nochange, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
@@ -871,16 +905,16 @@ static void test_assert_exclusive_writer_scoped(struct kunit *test)
 __no_kcsan
 static void test_assert_exclusive_access_scoped(struct kunit *test)
 {
-	const struct expect_report expect_start1 = {
+	struct expect_report expect_start1 = {
 		.access = {
 			{ test_kernel_assert_access_scoped, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_SCOPED },
 			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
 		},
 	};
-	const struct expect_report expect_start2 = {
+	struct expect_report expect_start2 = {
 		.access = { expect_start1.access[0], expect_start1.access[0] },
 	};
-	const struct expect_report expect_inscope = {
+	struct expect_report expect_inscope = {
 		.access = {
 			{ test_enter_scope, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_SCOPED },
 			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
@@ -985,7 +1019,7 @@ static void test_atomic_builtins(struct kunit *test)
 __no_kcsan
 static void test_1bit_value_change(struct kunit *test)
 {
-	const struct expect_report expect = {
+	struct expect_report expect = {
 		.access = {
 			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
 			{ test_kernel_xor_1bit, &test_var, sizeof(test_var), __KCSAN_ACCESS_RW(KCSAN_ACCESS_WRITE) },
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-11-elver%40google.com.
