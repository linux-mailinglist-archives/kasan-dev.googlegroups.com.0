Return-Path: <kasan-dev+bncBCJZRXGY5YJBB5NARKFAMGQEK4LQ5WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D31D40D0E0
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 02:31:50 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id z18-20020a9d71d2000000b0053b1b34084bsf11782597otj.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 17:31:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631752309; cv=pass;
        d=google.com; s=arc-20160816;
        b=igQax8W9CDd59IOnfpyXww18lbG8cdPNsPkMCLUUoIEo3600419j8UWyIADZLC/BcM
         DK4yWNxxf2x3ygkCRUW4geXd2kpQFzUNHW2fiQUBPaV8r03r9yGVEpZ87z01qkpmXRbM
         xQ+W5MRyWuJqckqHP1AXX5iIomPpAsXdQHb2CjfiIeLdzvJuEhirKIitoVaNgnIA/kAq
         eBYxDZpyCsEvOnqbvAS/ggmH5oCA6E27HW30iqT3Uq9dW5Qc5m0FkkRr568D5n0MDG/Z
         tBfZa3FP/mt/Z7vyMZPgOG7QAwuZgq/SudyqKXpKHTveTfGHuU+pT8si7euw/lPlnJOv
         2UBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7yCvamsAAyhu0jQjTAMouOfMvQtdlZZaZk7mF8woqt4=;
        b=szs+NxDeyrO2VjCYLJxZDxOOlwsxWlxQXwdeHazgjqRlD+zHoyN9FxlU/UiaCehb0Q
         RIZUB7GwOes0++Fl7wSdkC5ezTCHQhhqxCUgXyBABpTt0wuvZPBY7mlRdxIewYVhWdUW
         4XJu7eupVG5cG+xDpGrnixp5cGkwpsCKtnAfnNur1uhlmb7nlwEc7pLuiVKkIFWrRA53
         Kvrft/tmQB9RO+eZSLUKwBwJGC4+0jhxLrimp0riZdkdB93Mmb16lk5wSUmgWRAIRC2W
         fJVZ8jRexZzD7k0jqz12FcxdWPpa/7lAj55j8Xq4vXek1uwwibz48naOx1oxpQGJecah
         viEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NPxKcZ1J;
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7yCvamsAAyhu0jQjTAMouOfMvQtdlZZaZk7mF8woqt4=;
        b=H2WG2E71IQ7c4ZBbLzUJnPfkpCoKD2ysH834hYr2WvQ6fvNfelG7eR5M2+AwnQfEHA
         66yverFV2KnB9Js+CiI4az9QMTsKd1CO4nlNm+6RZ83aPO++EbKgX/g2XQeGTVjwVZnb
         iXvI7ZuIuPIc9aOEGf9ShKwlRQ5cIjqyZCRLsiJtkooomFrIedYoxpQ0yKHoNSitTVgX
         f3l9cKm3DgF/Y30VA6riL1oOVcLCBOU2g4EcXntk3mR0/a+AlzYDy9tJDCkQBrt0qq5F
         K757YUFEP6/4L1sqqT9dXxrFKp6IuqeJrzOavBG6Gpy6lrgpeLpQHHq4XfmXmm4ViMLQ
         0lCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7yCvamsAAyhu0jQjTAMouOfMvQtdlZZaZk7mF8woqt4=;
        b=hQreckxD6ZFg01RPjWYUB1177+kDrSp2T1AVK3jV6moyRBRm0W6kDZxc9ky/XJxdCI
         uaq8QYCMVu1YmS+Al3q9xqgaN74+hB7Im6iS5qbFu+F2yKSyganOApPBUu3+vAlYpRaz
         0GYPC23Tk2e9pHNKFqLyuTX7BT7v8caPbLcr7x7cqOklhBU5GNF5jVc1BBh/GSKPQRVx
         tPVukQFvXpx1PppNpwXRYwDQ4qUzJV2HYX95TDzeIwAT8ItY7LbYmFrujyW19QQ0K98p
         SDWZ6KmBtV2cPeJG6HTrCJV6BLjB2QzRrjZJY39KaklqlJVLU2tMY1HQh2FHROOS51a+
         HLdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530vrrDiRGlvZW7U0JtcRS5MNOm4NQCAaIZRUTtpeaSvcSvrtIxY
	skL1RPgGFVD9MQm2Elr3YwY=
X-Google-Smtp-Source: ABdhPJyp4JCjiSFl/6PF0nwwJvWIfpby8sDJ4p0XQHEKtZPpnbEo9hF2Q9sR0RNWA4dZzItcZjwQmg==
X-Received: by 2002:aca:b80b:: with SMTP id i11mr7206756oif.26.1631752309056;
        Wed, 15 Sep 2021 17:31:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1415:: with SMTP id w21ls1212711oiv.6.gmail; Wed,
 15 Sep 2021 17:31:48 -0700 (PDT)
X-Received: by 2002:a05:6808:1a19:: with SMTP id bk25mr6988798oib.62.1631752308717;
        Wed, 15 Sep 2021 17:31:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631752308; cv=none;
        d=google.com; s=arc-20160816;
        b=JWhSx6pnzTpo+2cCHrKjksVVyO+uhd0tuz/DOL1b7sGaUinHF5vn0e0XJdZmdzXVBa
         PIf+ZFh5yIw7uiWsJYVt5VrSrgnzAVLOa1SVwHabm+SAMYv651Eros7xiw5RjArEuzJs
         pYS6EkHXnYD2Yp5mIqTKlE/cAj+6AR+N/17O5r4XRltSBM/W4IWQHNM7sRCGlhkKSkBI
         3SIo3s85jQTzrfC+y6Jek3kQGuELFI/cyYbaliNzwD3ed99q/P1GgJo8qxFheFQGe1PK
         hqk9X1EUn4pH0aOBcc9LmNkvGtofzneIxfnREJifsxZEDWJW8XsYDSWEoh33Bh5yzqrw
         FP/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gCJbNHEt96rkAKLIbSxqAJNC23/KAy1vA61DyIfov8g=;
        b=0hb+iUsQYcSC4gh3TJIzGZxc86L/uRRoO3CX0w2kvYA4LCaWWk9DqQBvS7+M/eKldj
         TsIHZUFqcEMqthWt3NtBo6LUtrOsBONDdGmcVC/3MmTXB1tTQjNbx4fWXYhVLgCdih5s
         eN29vAea5XFoTczS+bjK6x4fs1MVDr3NWgeG/r45VaGWY8MHqGiW0OfJyXCfkLnsysAo
         ANhBsL0qgCAAtFPWNNcKx5jN9036TaFxXlXQu+WlGufWvsi6DB/nlsFJiGNpd9vOCqGT
         MN8Vfx6wrCnt3OlJyr2Ere16wqkHIqdBKCqU5QRnn9UrmHIMKyy6mFRTLS/cxc1uwnbu
         tTMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NPxKcZ1J;
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id bg35si183551oib.3.2021.09.15.17.31.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Sep 2021 17:31:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id CE4F5610A6;
	Thu, 16 Sep 2021 00:31:47 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id AFFB15C08DB; Wed, 15 Sep 2021 17:31:47 -0700 (PDT)
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
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 3/9] kcsan: test: Fix flaky test case
Date: Wed, 15 Sep 2021 17:31:40 -0700
Message-Id: <20210916003146.3910358-3-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
References: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NPxKcZ1J;       spf=pass
 (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210916003146.3910358-3-paulmck%40kernel.org.
