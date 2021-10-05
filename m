Return-Path: <kasan-dev+bncBC7OBJGL2MHBBN7A6CFAMGQEQUH47DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D09E422424
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:00:08 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id a19-20020a9d3e13000000b0054d67e67b64sf14109132otd.22
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:00:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431607; cv=pass;
        d=google.com; s=arc-20160816;
        b=VBbK7MByDfer1NroEw0kqK95A9NMuf3Ab6s93BGjYq6tb8kKevVOmgaHTym6xo7TUx
         stkZHiAbXU/oVTfwNPHSQa+G1smyv9LPKoG9tKIwgJbXC3ebgEntywqShKwdpMdNnt9E
         YCiNwD7AhxgRmUfL2Tf30U5ETp2Zeq8lxwkLDx1/8SujYoxB+oouruOH4sA5jE3hL970
         J8ihgqwGC93kYTpGA+mzH2hSIB8mnnFHICXjCXVV4lNQWe/JcVZwsGBqu910z5YNnhu1
         fMvaLJwWIv9AwTdyqPB9R2ftl8MGk6EZbrwotl+TDINMFPORjo1HcC8DrzCJ5mAK1J8V
         4bUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=4KSjPqLxBBQkvO1t1hUAMbrJUSYQ5MpFsEPHaqIHBT8=;
        b=M6wdREbvwcbKFhn0x7PgjUVBzFWEomSsic+/ks3/0nnJoXPd+moxdIciv4yOvm1xRF
         IFzdlHvg14swfTh7KjmCmpBlRRlHlOWLP3GtsbZ1VhEJzP7TiZ8jRzv+259neFcGxmMS
         XRHQ3YpfnR/SpXmG4MDzt5hJe5nGROet/7mhNvHDXIoONbErLdESXHVvY0BzsoRuuxSk
         i4S8k66ufLW9TFASz3ZE2fnyEHzG4xOiPovGar0vXg/P7Ny/XW5muEwppZzaawP+eZVV
         yTHB56+reDKSUwvejlAHLBxx7iiMDaKK0aJpmhbCy9J5YsCnKv+4UH3nLhXtaJ27qcE+
         MyEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VqUHau3t;
       spf=pass (google.com: domain of 3njbcyqukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3NjBcYQUKCRk3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4KSjPqLxBBQkvO1t1hUAMbrJUSYQ5MpFsEPHaqIHBT8=;
        b=IoZe+irQ2Ym+atM8lOWk+ZVQfZsiCO468weRCGbp/tZD1ZNr5wM4SvXYxJ/GW0b8a8
         WjasgPKrr2wJDHJe660rdTfImLIEWF/h7sHZeUIG1p3rBsp/nw4FG1qGXGt9P7MLmWlW
         dvnlTN/iFDXz3p4RnJS+qR9nV3tqOeQ70N1y/1mSLjC4Mwn3loRG+cgSMK5lLwSk+Mls
         ucl8a8rg+SY+yt0xlaQUpAUxBT3OJHCQ1HVLBdnHEd1q0pLHGBZDu+h+mj05O5HIPHl+
         fFyFCCZumaMpHtoarH1rk444C8axaqTEpnbwyPEUe1L6KQDf8pkRl8yguMkbP6XTiaeR
         /jzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4KSjPqLxBBQkvO1t1hUAMbrJUSYQ5MpFsEPHaqIHBT8=;
        b=AbH/NgX6M7X91ANjl4mBl1AeDLA1O6ixaneVL6wicyOXVpyShMUBfPwOe7sRqF+nuM
         0e8I++4CyntIDMcJdzjLffHjb/7mSWvqhJAxUi2ESo5zjQjII+is3YjP7Czt7hiJEEM4
         q5H2i1+2lVm04XthULHkWBXD2A3gcvNHApHgBkJ0CVdOvjn6Mwt3TFKjRdxLjYGm58WU
         W5hnZXAWjkA5EvV5VLZ6l2+HXJeyo56yPgC/SvajXOA9vX1yC5rx8utjwcAGmLF4zB/O
         9oFJ2jcpFAIyZwtANe88JnWrEZLcerhS9/YtCH0oLktIeRVRpebkQ+h5xjj42UhXqRQZ
         rfyw==
X-Gm-Message-State: AOAM533sg0ff3dDdSMmrGf2lybbQIbL0uvRNuNY3eYoMWAY+nNpDGJU1
	9iHJ2vflXmATTufGye6yBcE=
X-Google-Smtp-Source: ABdhPJzSD1wYAQCtcMa3aBHgTAo3doVEuueMda5rYiCiblq/e0/6A8sO8I6lweTg0rWP8ZTe22yc6w==
X-Received: by 2002:aca:c46:: with SMTP id i6mr1895973oiy.62.1633431607318;
        Tue, 05 Oct 2021 04:00:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:cb8c:: with SMTP id y12ls1464172ooq.0.gmail; Tue, 05 Oct
 2021 04:00:07 -0700 (PDT)
X-Received: by 2002:a4a:da41:: with SMTP id f1mr13004696oou.45.1633431606950;
        Tue, 05 Oct 2021 04:00:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431606; cv=none;
        d=google.com; s=arc-20160816;
        b=YisBNdQhUgHwIzzeY9+5UAp57aPk7KDvh4tVMU568N4t8LEKM7g1uurDg0N44nC9iK
         rRGlapAM8wylH2He0SyB0T9DHTrRzLBuUb2+8nklrZ40RhEgqm3QvQYJRx/joj30fmXd
         RAmHcpiArX6kaVmekYeYBetqBxILo2WapBidf/b/ZhA2I+1TBoa7eeECFdfYTRV6nwPH
         KP4a1b4HEKxnqB6r9rjqpjHBRHZaceoDobGPnFivPRDUyZEj3aV3W5FBxZU/E2ke8YSX
         NviWXn7UnmBWcH2K/FvCA03wmvYsejmN1fghQm6XZsVqrB3mDHhoG200ubcka+Nxr8CW
         wYkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=rJFOB4F2I3Uhw/IG/H4qYMYPgwEvxNpylG6MakN87zU=;
        b=Kh8v+LHqEWoRM0rlG8TU+SHMQGpTfoMhbnEtMUxp5q1C6jCDN/s6Y62jlAXCHd3vKM
         Xb4QiFDbDNvnRPXbwH7CJKWr7wXr1V1x0tyUciXOzjPoisOec1TODGr4XO4pg7DrRG06
         WrNKZdc4MGVm1oPpeUa5I+e5p49YWttVrLM0Gy1iXRI1bf7iCVrdtG9ZG11reyBzEotc
         S3GJzii6GulrPsptcqkcuQEAYLHf9ZTTqmrZs/Lhk8BaZ/hQ8WIgY3oWxb2PXZO5CbSD
         RrNXW3gfUbjSHSAk1NsMr/lsbaq1F81TJ+OxWpNDK1BmP4TlTt4l7vsfGLm+NVCV7H7K
         ebHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VqUHau3t;
       spf=pass (google.com: domain of 3njbcyqukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3NjBcYQUKCRk3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id e12si528917otf.1.2021.10.05.04.00.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 04:00:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3njbcyqukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id p75-20020a0c90d1000000b0037efc8547d4so20765387qvp.16
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 04:00:06 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a05:6214:3ea:: with SMTP id
 cf10mr27289434qvb.53.1633431606422; Tue, 05 Oct 2021 04:00:06 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:58:52 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-11-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 10/23] kcsan: test: Match reordered or normal accesses
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=VqUHau3t;       spf=pass
 (google.com: domain of 3njbcyqukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3NjBcYQUKCRk3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
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
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-11-elver%40google.com.
