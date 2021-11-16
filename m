Return-Path: <kasan-dev+bncBC5JXFXXVEGRBZ4H2CGAMGQEFU3PA5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id A9E1B4539F5
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 20:18:00 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id r13-20020a0562140c8d00b003bde7a2b8e2sf353695qvr.6
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 11:18:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637090279; cv=pass;
        d=google.com; s=arc-20160816;
        b=WhcIx2RpmmzjPgb7kU2hGG58JaoCFGLyrCQTei0v/SV2jjjkQe6DAU775AuJ7vbpjz
         L22MfO2HNnfdyI9m1YKyJFfStmEZH1lM3GwwpsusCQQEUNmeawh67fDaMo0uFBSt3UA4
         MLVwLMPOYFzYV8fGlRVAzaAH8vVk1JO49niHFpUTXiyyoLEep5SWYemWfgP46wZrR4Fg
         FquBaxVKn/KZiyxqMISBWv525d8XKeUwZs+VU/8IJyJ6VMgGR1Fpapa9r+0l5y89rA5e
         mI5T2r5I6RjaBddUcRlfTHqWR4FSebXAjwNFXp+MuboAtlVk0xFrW0XeeSxdmoFmM9of
         6ZzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Zta7RpyUda5cc+s1Zpibqs1PibZu1vVi1jH69MzF+3E=;
        b=UN8fyHEmdamXOZ77gSa83u8xEvgkVwe+LA5KO7ojNx94qWjt/XNQAYmlUdiShedFeP
         eoriaj68PMsNJtejkKnTvKHgBPODIsESharpnLqtECz1toxsCAQ8VNIrKX+4unB15pJC
         W+UArfmXlbFTklU8ZSBZYjwc+7fIM2LM98yJQONdJxs5btJCV1ymRz69D6rDDNOolTVt
         Xm+w6KX8LT0ckhhCEghhnn+BmrxDfxFUtBRlSmNN7z38yeAd2Ooh91+KCHoaA1QjcabR
         Ydz87Qsn2LJzYxWvI43Qak9Qs2/btwgw7ivRtqi5L2rveaEO00r+lIBP8tUjxdpB+Xws
         gDeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iE64KSyn;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zta7RpyUda5cc+s1Zpibqs1PibZu1vVi1jH69MzF+3E=;
        b=ZS0zRagYL/gzKTommeSkE5lzt9a7Q76RuldOUimrVElAelxrB74E3uZkScCIytGbiw
         IqCaI33xPluWhjclLwVZFEdTOxsPuUbGLwDXbpuvYm9WZHWV7FiQxoBilbtBsbjJA0SZ
         bRJIKeQf1lnK7H3DU9Y7fOfjK0IrYy+RP/MCjTZ25eE6WhROt4YxpmV+VOMOL6fpOG0F
         8Ku/8aYWTVmcihBCr04X5caaA8gkWsvjvKE72CI44R+826NkkFwLxw9LPJktmTBaf+iw
         /rkemAg1W3tU5yfy0eLiYCnFHx6hAAWgaCsrntqDOcZjc2SDvsEZttwJ/jqcox1gFbdu
         nFpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zta7RpyUda5cc+s1Zpibqs1PibZu1vVi1jH69MzF+3E=;
        b=wIVKbH2A3/o47GINXeEF3q0jXATAimM2DLshPOv3wDdbcn8jpIWsLcPMXORqFmuI0d
         rsa8WtoVZ3Sg5CyX90uOFW9H77/gJ1EA0jCGdLW3ctuOlNjKASfje55UW88OwShw0OIb
         6o80OcxZ1ehRe3OxEQBNhUIZP5cvjNgcXYwZi/nsHFH95Xe6qdrhJwEwzhxuCUhGmOni
         5fYcYJtmFDKYiKmXpkKoOACrCO/WJLU4cIuohtcVc+CgH5cOr4cNWANkUX/8aL+3IA34
         Rakeex2C9V+7tvVPbWhv4CnPfTjXXBj03HOCtExJq5HbP8cRZjxAu/zMGUmV3Jxfc3Tp
         3ahw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533sKnsNKlYhXCbTtCDHWAY8UKsYEbGNwTBM7VAcAPgSY9LxTqXA
	xPdU14r4t7cMnhZt9Sl3X5g=
X-Google-Smtp-Source: ABdhPJxHzUnEnINvFUSEgB0VKLdymTI39nMYCP9SUN0s5sEETsby1zJulOtt9wlmWUr0STRePgTtdQ==
X-Received: by 2002:ac8:5809:: with SMTP id g9mr10438318qtg.411.1637090279648;
        Tue, 16 Nov 2021 11:17:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:180f:: with SMTP id t15ls7055331qtc.2.gmail; Tue,
 16 Nov 2021 11:17:59 -0800 (PST)
X-Received: by 2002:ac8:5991:: with SMTP id e17mr10154938qte.344.1637090279224;
        Tue, 16 Nov 2021 11:17:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637090279; cv=none;
        d=google.com; s=arc-20160816;
        b=Zd3gZ7pL7H2wi3lq7OTLVM5q9nNKpKKntxzzCTUGMG/R3vW1xEMkvSCxNpAm8fQ4Gr
         gfkkjw1X1mfLjJ3hi9ic6ZlX9hLNyYFvcpmjv/l55Kn6EOjOxDA6wbGttZItX+yuEmzO
         mq7RtAvIWRf8pGIf8ViPOuNJMQQhd6NQ3FHakb9QETil3opFnswEqH2foXCT6T85gV/u
         joWVmSJRvj/8d40UHN05S/JsKkqcyIuSmZWDShMtenl3zFa4mpIwCGs90Sf1d0fk6sks
         voJbAqb/g3jeJsVNDNWqN6ww5ZfMxwOoj8XCdq90uxoDBFHMIQz7DSjVurnZtMkRiA1t
         T5/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3z0tHT+ZL8wblMaMtAPLvCc8i96dhpBBf6irzjyPCA0=;
        b=Kpgri1nyzQ45oqjPKQAkxcdh/4HcBJpS+HUJNlLVCb3hUN86zCYNkgpoST+04PeufZ
         boUB9KqJsoyqHk2uacJEt9zd9x+++WUhHRzFAgY4ULX7jpBV0XBEg9JiCZ58i4DCUuEn
         KD3ZKO6hAQ/HTEuBgaiZ3ALeWnP/y+49QDM6DppFcVGSPWnqjGWvsj9NRmd9Yv0++xIv
         UykPavKEk7BwdZxTV4O4xV0OqTh0RAzc059J8TBqjrOE085llb0h7TKcWgo3kR8drfw9
         KSzqm0WR1nDCRE48QlAybCJrIOadQNV7GdsMVV6OyQKhmjfgZg8B4lwpMCIYne5lVqPs
         qgvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iE64KSyn;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u7si12654qki.5.2021.11.16.11.17.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Nov 2021 11:17:59 -0800 (PST)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 68A506322C;
	Tue, 16 Nov 2021 19:17:57 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Marco Elver <elver@google.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.15 02/65] kcsan: test: Fix flaky test case
Date: Tue, 16 Nov 2021 14:16:47 -0500
Message-Id: <20211116191754.2419097-2-sashal@kernel.org>
X-Mailer: git-send-email 2.33.0
In-Reply-To: <20211116191754.2419097-1-sashal@kernel.org>
References: <20211116191754.2419097-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iE64KSyn;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211116191754.2419097-2-sashal%40kernel.org.
