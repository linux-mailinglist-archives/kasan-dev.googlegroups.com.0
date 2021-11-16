Return-Path: <kasan-dev+bncBC5JXFXXVEGRBUMB2CGAMGQESHIJ4UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 06B2F4539BC
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 20:04:51 +0100 (CET)
Received: by mail-vk1-xa3a.google.com with SMTP id j20-20020a056122217400b002facf017a12sf71456vkr.10
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 11:04:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637089490; cv=pass;
        d=google.com; s=arc-20160816;
        b=rqOigvjX08WWKgHiSac+nKdKg2rA8XkdtJz30snGxLQG9mjLn/JbPA5XIkI3ZoQBdM
         eqNFRDKUkmNhTLIOVOqHoaFN5F14XdxFJ8Gf83XL/1V3yl6KarQZvOKOzfev/QLuHmWt
         FjCZLgPynmrbc+x0z8tcoos3Ube7gmda+PSqCrm+GBJOF2NgRW7OSDfM4ex7CbEAp710
         65YCyBr3CklCxqjx414OQgBs7Lt6gVNrqx6kIdlP5GjEO1di5RIXtax2rg+ZYq8SIhVC
         HNWSxT/Yj7VVnG+Zrh4uk4iRm1dr1xda0TfDaq4FnfEpm25p/8rx+qtTKuFJZcssEwua
         r2YQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tBXQHH+kunjF7GUAqgn9uziB6/aDFqhg7cZcTLlZbp0=;
        b=BqdU322A7T2/YPjlWyrSRjo07KDC+1rWZvKgonoJ9cih/eJ24nloeVROQ9wrcmXCwd
         skLtlgULLpt2CuKHbHMmk5LX469f9s1uxcLLowIuspE+o465mJ/bG9dA/jZ7eh3mULEe
         5zCCELdFIswCQwdeTlRS8umK9j4FGA0hPWzFZ4vhCxcL523smMHeLD7kxH4efewaZ0P1
         7Ny4TsYGYFAZ2raaG1DwgkK7J8FGMNyZMx85JdZfPcTe0okG1cXcu5ct1T0mVjPfW2pb
         mfFkpanh3bZXDoO8DTjiFb+MU2zKkTBWlU86qNLsv2Ws/FmOS179vqnAd7RGT5yuqdHw
         gikA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=q98FMqmo;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tBXQHH+kunjF7GUAqgn9uziB6/aDFqhg7cZcTLlZbp0=;
        b=r8AmdtQ6T5DSxj5nigSqldFtfygLsGko6DKGoJ6r+Swx6vZK+cGZ2b4dEB2r6cwWIE
         dQcibWLCV6tPGxuXMNVBn5BF5/nHRmM9YB9EjXS3CHqgD7+RfkkdLsUH9KepRuJGYtC7
         tB7E8DzYyEURjojEbpR8PCUtExXoh/UPbWrTVTCBWxSSdkdgOr3O3ZiruVspFeNZk5wf
         X0ejvtdDqtxmtIc66XdM2Ix9vNEuVb8AL4unTf1Rk2qDDtSHtqSKCtzF0+AqvDSo6Rsi
         klen6Zci1nN8YvffYWmzsyqbzXCHHqm5quY52P0PJuy1jjU5xJxgaR6ogUKH75eABBTi
         vLJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tBXQHH+kunjF7GUAqgn9uziB6/aDFqhg7cZcTLlZbp0=;
        b=R0ZcgOy6LezWSMCJ5jk2pGoJjhKgRaSpOcMYWG0zVpuVdxXe8iZ/9DsDc+qJbEROJv
         BuohEbkKOiijd7U3wKkodEbdKqRxIbCo5kjfqivZg2JIDnjZy7UUFZrCOKPUSsKMpHyJ
         ZHIa16TROsib6ZKAH2lsDK9xgFO8w0vkFpyGfNoeTcr1Lh9PUz3GxXgtDoh02E9dFEUY
         imra6dmN70aXCj6EBv1yDqbzMP6zC2s1GHGZ5+bOnmh2eLX7eOr91GRssVHlBttjq/a7
         jKiUaM3fCgwuHiNPYGEcF6yRP+vUF/76ZwN5vW2KBQ51bJhgUo3DOKRSgEs2mJ6iRN5p
         yXWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531w06BVO7FNQNwLthFe4TO/2geUm0618MpBpRBYNeQIFYXqdGrk
	3TJzO1gTSUQItbasSOtelF4=
X-Google-Smtp-Source: ABdhPJzd4StLJMFuoXklMZM+FpIGl/ABMLq1s7A0HmIb600eEUAdbYhLgAEbWlbPdH3UOMV4tMQoZQ==
X-Received: by 2002:ab0:458e:: with SMTP id u14mr14111311uau.104.1637089489720;
        Tue, 16 Nov 2021 11:04:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6130:309:: with SMTP id ay9ls3880882uab.11.gmail; Tue,
 16 Nov 2021 11:04:49 -0800 (PST)
X-Received: by 2002:ab0:15a1:: with SMTP id i30mr14297666uae.122.1637089489148;
        Tue, 16 Nov 2021 11:04:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637089489; cv=none;
        d=google.com; s=arc-20160816;
        b=oKVSaYe4ifwzfOf9XHrUzaVIf8/umCwXab5tTgg1ON0UZbxM0sJqulcnwQips4oKhl
         +VdRa9bgGiPVpA3ACSyIwGDhmVf+OhErz+h7J7KIeTlPzFi6aX68B7G5N8CvW1A2mbKu
         ZdiNVbK/9aD0IMT0Fd45+1Apq0tcoTYDmDnd1GS4RT4I3222Pz/nsCbwQKUSH8iu9CKf
         02bskzUauByWpABNxLBApqaS/TOb4TcDOfteBYPGa3hX4kWAarjeNXFGwDIZvm/mG3In
         q4BawmUx3Z4Iq9mzCdqXuQa/LBxAQcOIiSTZFhjyfaU2DsjTSTKWNrPc38xauvvdqHsK
         1ByQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3z0tHT+ZL8wblMaMtAPLvCc8i96dhpBBf6irzjyPCA0=;
        b=GDfNKFVE0CKnV2yZghFLVfsw593k7nW2umfs31icKRMsoquFHOglTRHr6dQ8kHs4kW
         KURQY6W+vu+KPSU1h/FJUIyCscIR/sRJfJAcbwaxPuLZTl9PDw2Kobg4dweBF9kTScfM
         SN5KlHw5CCA1tCX9iZQudDlOHYZj6DpjSPmLU+UjzlCX/nBKmIz2HjWuD3/PhNh8V+RS
         q4mZj/8XjyMu0huz/caeEP8YZ3b/TBqOtWty0cpnJer7RXPW/I3jDDgIBDfUHqWeEtzw
         htwGlCW3gMNJ1XI4Q2mLfo+0qERNNaYXXRkUqQGeY3dT36v1rxR65V5ZjA9M3V3P3hUz
         7kDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=q98FMqmo;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r20si150870vsn.2.2021.11.16.11.04.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Nov 2021 11:04:49 -0800 (PST)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 7FF4463214;
	Tue, 16 Nov 2021 19:04:47 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Marco Elver <elver@google.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.15 02/65] kcsan: test: Fix flaky test case
Date: Tue, 16 Nov 2021 14:03:22 -0500
Message-Id: <20211116190443.2418144-2-sashal@kernel.org>
X-Mailer: git-send-email 2.33.0
In-Reply-To: <20211116190443.2418144-1-sashal@kernel.org>
References: <20211116190443.2418144-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=q98FMqmo;       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

[ Upstream commit ade3a58b2d40555701143930ead3d44d0b52ca9e ]

If CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=n, then we may also see data
races between the writers only. If we get unlucky and never capture a
read-write data race, but only the write-write data races, then the
test_no_value_change* test cases may incorrectly fail.

The second problem is that the initial value needs to be reset, as
otherwise we might actually observe a value change at the start.

Fix it by also looking for the write-write data races, and resetting the
value to what will be written.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 kernel/kcsan/kcsan_test.c | 22 ++++++++++++++++++----
 1 file changed, 18 insertions(+), 4 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index dc55fd5a36fcc..ada4a7a403b8d 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -488,17 +488,24 @@ static void test_concurrent_races(struct kunit *test)
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
@@ -513,17 +520,24 @@ static void test_novalue_change(struct kunit *test)
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
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211116190443.2418144-2-sashal%40kernel.org.
