Return-Path: <kasan-dev+bncBC7OBJGL2MHBBN5BYSEAMGQE7N4OTHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id EDA793E44BD
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 13:25:44 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id u5-20020a4a97050000b029026a71f65966sf6051986ooi.2
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Aug 2021 04:25:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628508344; cv=pass;
        d=google.com; s=arc-20160816;
        b=DN5lc6AqGg/jZc9CED+fdZFPNGqzO3IMY9IB54JeD4A+u08KkZp3iQJ3N5Zq9wqn3A
         roAkHMGNAou6hieK9FoULLMzGnHKHtmR9pgx9x0USuHKz9PKPCg+GFae1mr04iLQIPPk
         SdKOrClFrGrlpiITy/HYUZVPYzzUndcIiWTAujv5QK0MQJlfPaRbG58Jvr4tWMJm/otJ
         MsWtZx16O9hr49tIBZ4US7kOpEJRTUQfgJV4pwC3cIClnEkvyWGGevHRC8ZNEj8gI5bU
         34nfXWcQ10N+Fc1BB0CeVBC1G64ZKYStXHoQRbmVpUnPEBxPkHX2sA0xsnitlIAyUH4z
         0svQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=lW/CrBEpZDot3iGkXTsqrA37zwbOlvoPgYDPxJI4rYY=;
        b=JgUjLRI1FiRC2kaQUViA5nfXQSNj68mcJsdM9aLSJmPe5tgZo6Wug6VytRW35MbePm
         JGq4X8mc3PBaBBZIvsPUecq/YAuVIb8fmR7odWy0M8uSdEtHMrUKXVgEHkXO89iv2EdL
         UEVc0ZesYwndG8E9ODHAu7nGizK9z3jh3mPegDwf3yDykcI0suDOq6Fn7NlyqdfeE0md
         xKAot4JGuqkfzAAk6Jfiw5wN+6+ZrX4AhSRTrw2YkU9uBmaX0tyRkirToUS4S4mAWzkR
         mvo98bBXRQ9qv819EPmOuaUJU4vZJRBXDxpwVueLgJfm/ZyN/k9lb6yXpVqYousG862S
         4I+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ACFrOCrP;
       spf=pass (google.com: domain of 3txaryqukcswmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3txARYQUKCSwMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lW/CrBEpZDot3iGkXTsqrA37zwbOlvoPgYDPxJI4rYY=;
        b=Ddg/9ONEu6kKkUfwy88un+HZJq9WS7/ox+H0i1hFOUHD5NqTiX11p7yPc79KeIZG/A
         aTTQFFb447rF2o4UcJtNwm6ivnxj102bN42wb2YXQ+J6BoI5RqYs5ifJmwqYhhtbrCKv
         SBqnVMZ1HEpm3VpvIPsUQ4dpr9NqpQDmUV2YMdIb9Gpz/Q0I9Wd/bsSIZ9yRClD/0Gyr
         XzZQ7uUVICb/nj50N0LIKxCeblb0nV8qRGj2aKTsjwThfvPTHsQG3FT6SN3447kHexaG
         lURt2Pk4dybCoDDZI70qo6PUE8D+POv49iW6Qu5IOhXBLxULFzUIYNoUa257ljOWoTAZ
         fJ8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lW/CrBEpZDot3iGkXTsqrA37zwbOlvoPgYDPxJI4rYY=;
        b=REdtZ60DrDdhiEXoRtgbSkXxmYHDyBiR/fMa3bS1leSCREUq9efYVWu+qtyaZBsFLs
         uaPaqd3Qub8IAgPx7143ap9PECInEEOMWnHTOgybXuoOierl7iK3Y81CoXNaG2uY8Ptm
         kFPBPnw1tgAesDrvga5IXIq4MTJ4O4MT+X7KoNDvfIYT1Mw/JsODqwGq6gmumnF4a/ov
         kZPn1LUdtzeDHgYF7Pqwd0FWAGHZAMPhKtMOfNv0PVRQTzpgWYwj9NkUygPsmDUdoBfa
         PDE3JhhrzMta9541PUgfUerORChP6sviW5mF+9UTNWvOPpElPxw1c+eXc5935o8geHCJ
         vvZw==
X-Gm-Message-State: AOAM532ueGvDGNCwakNerun2Z4iRLteRdupsLCi5528eBUsCZRlG3cA/
	VuJiqeAB2UkgFTp7W9gJDXo=
X-Google-Smtp-Source: ABdhPJzT6ewRtnkCbBT0lf2mPFjyGXhpdKY8gdQqBkNlleaXBvSwCXMhjVEy61nkt4bBVgmROV51XA==
X-Received: by 2002:a05:6808:1508:: with SMTP id u8mr650425oiw.170.1628508343963;
        Mon, 09 Aug 2021 04:25:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:c502:: with SMTP id i2ls206731ooq.6.gmail; Mon, 09 Aug
 2021 04:25:43 -0700 (PDT)
X-Received: by 2002:a4a:3651:: with SMTP id p17mr3113265ooe.92.1628508343565;
        Mon, 09 Aug 2021 04:25:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628508343; cv=none;
        d=google.com; s=arc-20160816;
        b=PYO5XU7fJRzgpJrapolO+iZEmGJrmq9rijSzjXvvJAATuweh4p5X+IEpPNMwoj4k9j
         4nJfWNxMLd+NEoYSLLl35vsvb8gtFOy5S5Lr/ZSVsYNGN1qpJ5vCbtJeQSZfzo1H6pGx
         CsGdmgJlDt2agljBI91HtpE3Ww+uNMEAeXWA2Knv6QW5kT/Bxmsxs9j5RPvxStBEAaGl
         bGg0T++oTxTKD+2oTSLiZ90842LuGRlmtTEps7BuC1Jkh75uN6nuq8w3XBSIW8ugMw5E
         l8S9Wk0NtunA0+vnUDcTLEjsEQhh8IqHSyJ/sR6YKMIkHuDhBhRdfyHc5IXtSDU3HW6j
         V6jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ydXqiAdNSjBzhuq33PSd4SOBXITdQ3zj3AJIcpBrcC0=;
        b=UCTlLVsaxxAvmIRQSaAULWMui2GuFQhGz4lMEFylNPvbvJmTlJt/Oe62sBO648AxTT
         VvxwhZpVBpoS8X3HHcpuWfmbjrLRb1S5YWTMw1xvcYJa7d39NuHwB7yPYeQsNbFQ3xms
         62gbfZiGMDd7C4ugOaZNzOM5B/HvKfPpGyg22SYhbMIAGHZwoiGVrC3+SxC9JPl9ztS1
         wISqCAGebKcXOnIEjwairmQGX4tgTPX/XND/QZzNLueBDD+ssQAQsekNOolETq/p2gdF
         jE7S7AU3O1irxqYcL3qefds2PMLp+y3Vnz1LI8Z+d3pKUsi9C46oVku13ajM33z/19CA
         HDsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ACFrOCrP;
       spf=pass (google.com: domain of 3txaryqukcswmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3txARYQUKCSwMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id 72si229764otu.2.2021.08.09.04.25.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Aug 2021 04:25:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3txaryqukcswmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id b8-20020a0562141148b02902f1474ce8b7so12048128qvt.20
        for <kasan-dev@googlegroups.com>; Mon, 09 Aug 2021 04:25:43 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e5a3:e652:2b8b:ef12])
 (user=elver job=sendgmr) by 2002:a0c:e908:: with SMTP id a8mr23093025qvo.61.1628508343117;
 Mon, 09 Aug 2021 04:25:43 -0700 (PDT)
Date: Mon,  9 Aug 2021 13:25:11 +0200
In-Reply-To: <20210809112516.682816-1-elver@google.com>
Message-Id: <20210809112516.682816-4-elver@google.com>
Mime-Version: 1.0
References: <20210809112516.682816-1-elver@google.com>
X-Mailer: git-send-email 2.32.0.605.g8dce9f2422-goog
Subject: [PATCH 3/8] kcsan: test: Fix flaky test case
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, dvyukov@google.com, glider@google.com, 
	boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ACFrOCrP;       spf=pass
 (google.com: domain of 3txaryqukcswmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3txARYQUKCSwMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
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

If CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=n, then we may also see data
races between the writers only. If we get unlucky and never capture a
read-write data race, but only the write-write data races, then the
test_no_value_change* test cases may incorrectly fail.

The second problem is that the initial value needs to be reset, as
otherwise we might actually observe a value change at the start.

Fix it by also looking for the write-write data races, and resetting the
value to what will be written.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/kcsan_test.c | 22 ++++++++++++++++++----
 1 file changed, 18 insertions(+), 4 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index d93f226327af..e282c1166373 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -493,17 +493,24 @@ static void test_concurrent_races(struct kunit *test)
 __no_kcsan
 static void test_novalue_change(struct kunit *test)
 {
-	const struct expect_report expect = {
+	const struct expect_report expect_rw = {
 		.access = {
 			{ test_kernel_write_nochange, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
 			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
 		},
 	};
+	const struct expect_report expect_ww = {
+		.access = {
+			{ test_kernel_write_nochange, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
+			{ test_kernel_write_nochange, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
+		},
+	};
 	bool match_expect = false;
 
+	test_kernel_write_nochange(); /* Reset value. */
 	begin_test_checks(test_kernel_write_nochange, test_kernel_read);
 	do {
-		match_expect = report_matches(&expect);
+		match_expect = report_matches(&expect_rw) || report_matches(&expect_ww);
 	} while (!end_test_checks(match_expect));
 	if (IS_ENABLED(CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY))
 		KUNIT_EXPECT_FALSE(test, match_expect);
@@ -518,17 +525,24 @@ static void test_novalue_change(struct kunit *test)
 __no_kcsan
 static void test_novalue_change_exception(struct kunit *test)
 {
-	const struct expect_report expect = {
+	const struct expect_report expect_rw = {
 		.access = {
 			{ test_kernel_write_nochange_rcu, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
 			{ test_kernel_read, &test_var, sizeof(test_var), 0 },
 		},
 	};
+	const struct expect_report expect_ww = {
+		.access = {
+			{ test_kernel_write_nochange_rcu, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
+			{ test_kernel_write_nochange_rcu, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
+		},
+	};
 	bool match_expect = false;
 
+	test_kernel_write_nochange_rcu(); /* Reset value. */
 	begin_test_checks(test_kernel_write_nochange_rcu, test_kernel_read);
 	do {
-		match_expect = report_matches(&expect);
+		match_expect = report_matches(&expect_rw) || report_matches(&expect_ww);
 	} while (!end_test_checks(match_expect));
 	KUNIT_EXPECT_TRUE(test, match_expect);
 }
-- 
2.32.0.605.g8dce9f2422-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210809112516.682816-4-elver%40google.com.
