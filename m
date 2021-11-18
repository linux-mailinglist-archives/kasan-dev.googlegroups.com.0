Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKUV3CGAMGQEPRCZKMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 3678E45566B
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:23 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 145-20020a1c0197000000b0032efc3eb9bcsf4005989wmb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223083; cv=pass;
        d=google.com; s=arc-20160816;
        b=FjWTyHlFPDcJKA20Z++Gj6aKiJvW1NnXnJekSkPsQKYhI9cXZYrWcwlEW/u4EBXIW0
         8G+E4h1jqrzV/SggqTC7RVQ+wlf1zIBLHB36aZcRT3Rr88pYWrlnROj0bPcBmZi7u3lF
         FwniApcAWdrZA0yOoUiHCpTcVs6jlts8yg4oMpOJfRdOQ72jQoFzOjHzMe6kihERvUPA
         X4dpx9hoAMc+2hPis7nHlqrR4jaT3DVVFZHwj0AFL4knEyTkjiUHzjDHIx3MimEIs/Fx
         hufjb2fd/+vpTRFsakDipqQinxYh1z7kRytc173MpZ7OPj6gLzeovKsRmYPNM5MCZjHh
         ugew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=gh96vCGoFnh77FpXHCYgegVz34NdGIw4cG3LjC4jQ/g=;
        b=SGZBgg6ujHHCyENwmFXqR1g2Ck6SBLCYC19EFrvlRMp5h2it8xt+2Qn1SwuNZPKtj1
         GvjatH/qXtP6QgNYugHYDc7kdJrvWmJa7Jv9H8MOJMwD5UqtfrMKSE+LWZHhBz0BVlbB
         MXT9MSJZxYEVYFSoIHllWmzMe9BYDlEyErB/xhd2PmysLSWoiY5Rjl6UcGP5t8UbbFuP
         zH3V9qblkvmJsDNA/OQKA5NTC+JlX01/TpnNiGOBnQomrN/glutrrZqX6HQncE+VMwvT
         weP4wOIWGYtEFNJaNpx2YFQMO78Rtsvp+YC9wnu70q/IhLH1EYayRg5tAqrGb2+JKHGK
         qULA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Pl3A/KdX";
       spf=pass (google.com: domain of 3qqqwyqukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3qQqWYQUKCSoKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gh96vCGoFnh77FpXHCYgegVz34NdGIw4cG3LjC4jQ/g=;
        b=ZbOb9WEHM6pKNmX+3mlkQAJGGKXJSrUzNd5+Rr4GrOsV8a51ma6y4e8JcUKNuTD9o7
         P36j5XieYoJXFSwUeWasQ7TtYFgtameacMkYw6Dwnh3lpFVtorTM33SPfzHmsdtW30w6
         /EiEUhQYjbNdRL5Zpa4flDMRp0CdkgDV0Cc1o/GNvDIon25LL/OcThuhAw/nCO7TEUmQ
         c/SRuWl4f95u1Pic+cpKE3f9/1lXq6tUysQbdV7yheC01sMPfn0tYWR1+QQIIlmK7o9n
         Jb2XBkpZjSRaujYTaHfuH6qRTZxZExkuxB/NhniBt9j3x+yX8WSw5hvU+0402jKvP7GD
         551g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gh96vCGoFnh77FpXHCYgegVz34NdGIw4cG3LjC4jQ/g=;
        b=XR+Sz0sYpC7SY1gQCLjr1oGf0AOTAbvVw0Upvd4WTmTaamq4oywK6l+3IN55d9NkQk
         h18qs6BdA13M8irAYiUXudhqMoK7IeWeOPoC3gaNrnY8ahTpUscN8cf7j69eVyE5WTxj
         nPLoPR29Nna0/EGfJfBopFTDdorTkvApgO0yhE+twXhGVF/hOc+L47G/DENlQqQqwHXi
         lZowT6FpifgpheDQLvoxUBRKfNSigLrdG1xgBzbWnt8PPVSXfU9DDU7XoRrbpxZgAxez
         yzg2TbjuPTKlYXIVrcadKX61EtPEEdS60OA0qxIzxiZrpzs+97MDrCAwTbKrWYVZbJ2z
         f5vw==
X-Gm-Message-State: AOAM533eMY1MNK7oUWDn7a/H/3jImeLqV1abQ7MppxMYEp/DLTg3JWAS
	nxbrkqFEiLeB/sAMZ8D2enw=
X-Google-Smtp-Source: ABdhPJzIJCobnkEKnyBnnXY3juETuVgm2GDcRrP6Wg9KhcFRsKTgFIb1oCMk1QnlttEA/AT7i3KATQ==
X-Received: by 2002:a7b:c744:: with SMTP id w4mr8014291wmk.50.1637223082979;
        Thu, 18 Nov 2021 00:11:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls2319694wrr.0.gmail; Thu, 18 Nov
 2021 00:11:22 -0800 (PST)
X-Received: by 2002:a05:6000:1889:: with SMTP id a9mr29922618wri.68.1637223082018;
        Thu, 18 Nov 2021 00:11:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223082; cv=none;
        d=google.com; s=arc-20160816;
        b=iAeptpZKaNTw3cLYpwSAMlNFZZgDxGZnI9PwxwTKMSMGBeWjVLelH2vX+6z+Qd/3K9
         Ju7HliaYxFEOKBLv9NbNSPypktOBKySHnNOWJ2bDmzjqfukqcRDwFb+eKwNI7hq1qfi7
         xkQ5ZcY7OqjbuZWM8rotQRaJWEJ8mlyR4Fu7np6jp1uFnEdH+T/FBjc7It70wasLzgOD
         ZYxQgekU8jWQo9LwLK760acROsz+Yb6FBGOEwB+10zfyeNDcqdKUoXURJpVx0APsy2K4
         dHfYiH12XTR5TdTXGQvxbqwGlzbrqLORxZQXdg6JVAl/o79laAG94qeA1HiAaFsKrDFy
         XEPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=UU4Lhk72EIyuCjy+G0t4z2bUBJwzL7HcimRlPhkjEC4=;
        b=oDToQSRiJp1wgZOLOJExIoqVtJqgjKTq1YvKyImcUDmwQJxili526KfEbNQNXStF86
         MWU1BqMsn8a7EMnDEDQy+OkcJx/FVF6eM18hD8sEYahtyR0rMMf/muU8PWt76XWe97J6
         Q2p1t24HWb0RWeytBMgQRD8iG04hAkKuvFb2ivMuZI5On3lowM245P9y40BgmbwvUNoA
         2NBQHB6ltGS2kcGDyDK8CtPhbEesR6IglmcVYHLivob9mezePCg0/z8W35E9800IddCY
         Fc6/G4t6ZFf+0lGD0PnZhCsOAYBTPrFXc2HXB0dEbNandp2ZgDBoWUgtWZMMSpgN1dEG
         C6kw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Pl3A/KdX";
       spf=pass (google.com: domain of 3qqqwyqukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3qQqWYQUKCSoKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id q74si600325wme.0.2021.11.18.00.11.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qqqwyqukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id k25-20020a05600c1c9900b00332f798ba1dso3992628wms.4
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:21 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a5d:4443:: with SMTP id x3mr29290572wrr.189.1637223081578;
 Thu, 18 Nov 2021 00:11:21 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:14 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-11-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 10/23] kcsan: test: Match reordered or normal accesses
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
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
 header.i=@google.com header.s=20210112 header.b="Pl3A/KdX";       spf=pass
 (google.com: domain of 3qqqwyqukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3qQqWYQUKCSoKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-11-elver%40google.com.
