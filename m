Return-Path: <kasan-dev+bncBDHK3V5WYIERB2VPRGIAMGQEKV5BLII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id BBB3B4AD7B9
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 12:45:46 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id y10-20020adfc7ca000000b001e30ed3a496sf2643320wrg.15
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 03:45:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644320746; cv=pass;
        d=google.com; s=arc-20160816;
        b=uOuYNeNmNru9i+43WiWIuTP1rC50xquJgRzxdhivb8bIbjsWmmawf43HGMSxkHgOGg
         0ndM4r/RGmrqIl2DhlXWuykSETQCAX5VTl79YCOcXYLXLaW3VrNWjSjoiHGa6+H2Aczj
         nd6L+sLw7mA0cQ2o873FhcMWkND6nxTyS3tXBbExwiN1Z9m7C+WA0X8Ri3mK4VlIisno
         +1x0I/3T2jsurQC3GswkQMbzJqH5jXFzt8wV+RPMYiksJFWemgbVj4EFTYeQjvYwVdrF
         /TvwKSelOJzsyTwMetbKyENukBT6S+0/o5VrK4Wh7wLvcSyCHQLXUDH8fphIhdUAu2zB
         APDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xo8O1VrCAGSwJPkSEWCTi/7ieQ8iCXNwruPFGiAadqk=;
        b=ZBVj03tngVlxfSKrVq7cwDcGqDKUDdNJDj488uJUS81QqcCJpbenPSawcm7/C+5D04
         5qUtoGe1aJr5QqP3Rl7EO6vDDOFGcP33jLGC3XavI93HBRYCt1RqBZPr1SRpt3R/KtDQ
         VLXu/EBwbwsDwowgP5F1UOzgdWZOTV1zja/IxlW4vq0ClMr+wx+nplF7mWAK9TJvia0v
         0V1bGDUUVdNIgYZuOhrfz+AFXZ87Katow2us5k4Btgb0+lYyu+BdOAz0WUkE0wwoXxEY
         PSgDJUMkBIFvnuFJTSTxt/T/vwn4Utcwie9fgwueQ0O5XuAeLyuT8p2QrQQZ9FOJq75f
         PB/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=nciZK8XK;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xo8O1VrCAGSwJPkSEWCTi/7ieQ8iCXNwruPFGiAadqk=;
        b=YUipSERGU/4pPU35LOnAHXCTQVq/6xey/7KMIrwcmCFdXteo2/90vNCB7rHn1OqHdt
         y4jGu1nzsQ5Nlk0tx758xSPEoN/Ng2PR77JN7q9mMjKgBcNRxXLmrZleGKJzT3nnyz42
         GEw79eHINpJfRIW4VrgeQoJI6I/A3I0TZU1EX2X22GrLTLo8JZiJWgDztPkXx+ECCum7
         Q9blSCw9JxyED6cVOuVEhx0JmKiJg5ltGU8EsFlAwk07aw3uQPdM3jhLiShnAdvDT38M
         rw76O4BGTZCrTJKZx5QPP0SxBDI77B3wj8LedikwDEjiMASbGs9awwibbVIWFAKIRxkt
         JmGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xo8O1VrCAGSwJPkSEWCTi/7ieQ8iCXNwruPFGiAadqk=;
        b=3PdcYIzhfZ7pj7rGErPag5SuBziQ1xDvq9XYbPaQM/1yad0bH5xLKbUjVCeMSVJUAF
         j8HtEoZAhah+Ozgp+eEkdXTnfTt8OJechex/QUKoqDZh0l6Aaq/iSIRI5vbL2XVueUHQ
         0i8bFIZ3sNgWr6Wyf4mfaqxKOt4N+uEMch3QlrKl2+TkFHIsVyYdLFzrocdWh8DXSals
         qqimbkwrQdTKXzIstMilKaQUKs/DcHuc5KGDtERyp+g0DqrXf41hyyWbU9zXMLcN+ST6
         Mc/Cbvst6sJaF5DcAKdmIahJKlGfPsRnN6i8vMjE5A/qerYrEjjjw4z9pio7LOd/Smdj
         ZdUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5308H+7yIQ+AoclLpnGP0bZUlRGEkdDlPax0KTO7r0dB1LP4yQ/k
	z6RNIRiXtZFqSE9hXYmA0aY=
X-Google-Smtp-Source: ABdhPJx6ABumU9GZ4fYWqjPRpMHFZDI+o5GbnO27lPCfFYFaBrQeKBU3zztuvdlAREYt2RuYDEjxkw==
X-Received: by 2002:a1c:4c19:: with SMTP id z25mr790185wmf.105.1644320746439;
        Tue, 08 Feb 2022 03:45:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2787:: with SMTP id n129ls1001976wmn.2.gmail; Tue, 08
 Feb 2022 03:45:45 -0800 (PST)
X-Received: by 2002:a5d:6486:: with SMTP id o6mr3353717wri.36.1644320745619;
        Tue, 08 Feb 2022 03:45:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644320745; cv=none;
        d=google.com; s=arc-20160816;
        b=0YgGjlbqApSZ5Yjxse2Iy4+5Wh3TxyvXWY4MDinqSf9ERH+t5h77c31nUj/pDudfC1
         jwr9A1zA2tWXyTKk8sTuG+xBexFYqx2IMV4soiQZqZdVJLtlci2ASuDuJQEn2yPjWbtR
         AwlL5XBJZMgdGQdn7Vg3K+owBnx0ydQqQVXzhPQJZ5TjJiEr2R5SF/PaMhNxuX9sxv73
         Up7x2KIl6DNdmNq8w/ldtgUshCSacpxzHQ3n8Kq16E6D8Z5ETiy/4gCEHkfCHNOfQfGj
         TvEamgjjvZLLTVVYNxd2KkP6TgFkazIGByIZpKem9BnTOSq9VVO55qcP/KzftHbe7rx6
         trmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=S9VMyC++vTek0pyoJ8XF9UlZhDAZzB3BunnVOUcavb4=;
        b=qLcOgxKj58EmLd38bnp1qu91dKYh9HgINYX1bBr9wOGIGaHSmJHBQH7X4L0VsdYdAU
         RGxaJduVCx7nJHHpYwjLjj+dh4Jcjtb8XpNe6c48ruz14H7GQ1pejP0iuj07dtuNZpOg
         QidGhtwGCMFgc9F8KSeRjl4OYjZ9mmG6bPSEMnAJXA+8lQSxaWJOpOJLtfsloEC8BaH7
         8RE4P4OWeIIXJwV4tFVO8yrzdL4Bq6IMMLy3pAqvknZyh4mrE5KzkybAe88h87JlWJkp
         4r9Ue++jkGfFUk/ZJ8Pi9veYKYpIEgKyXzvweO3/Yccm7GB45/uF1bqYnw2DjuhgsrqK
         01zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=nciZK8XK;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ed1-x52a.google.com (mail-ed1-x52a.google.com. [2a00:1450:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id h81si106307wmh.2.2022.02.08.03.45.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Feb 2022 03:45:45 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52a as permitted sender) client-ip=2a00:1450:4864:20::52a;
Received: by mail-ed1-x52a.google.com with SMTP id u18so36533816edt.6
        for <kasan-dev@googlegroups.com>; Tue, 08 Feb 2022 03:45:45 -0800 (PST)
X-Received: by 2002:aa7:da51:: with SMTP id w17mr4111043eds.8.1644320745410;
        Tue, 08 Feb 2022 03:45:45 -0800 (PST)
Received: from alco.corp.google.com ([2620:0:1059:10:5d0f:d242:ddbf:a8a6])
        by smtp.gmail.com with ESMTPSA id y2sm4151902edt.54.2022.02.08.03.45.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Feb 2022 03:45:45 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v4 2/6] kunit: use NULL macros
Date: Tue,  8 Feb 2022 12:45:37 +0100
Message-Id: <20220208114541.2046909-2-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
In-Reply-To: <20220208114541.2046909-1-ribalda@chromium.org>
References: <20220208114541.2046909-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=nciZK8XK;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52a
 as permitted sender) smtp.mailfrom=ribalda@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Replace the NULL checks with the more specific and idiomatic NULL macros.

Reviewed-by: Daniel Latypov <dlatypov@google.com>
Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 lib/kunit/kunit-example-test.c | 2 ++
 lib/kunit/kunit-test.c         | 2 +-
 2 files changed, 3 insertions(+), 1 deletion(-)

diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-test.c
index 4bbf37c04eba..91b1df7f59ed 100644
--- a/lib/kunit/kunit-example-test.c
+++ b/lib/kunit/kunit-example-test.c
@@ -91,6 +91,8 @@ static void example_all_expect_macros_test(struct kunit *test)
 	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, test);
 	KUNIT_EXPECT_PTR_EQ(test, NULL, NULL);
 	KUNIT_EXPECT_PTR_NE(test, test, NULL);
+	KUNIT_EXPECT_NULL(test, NULL);
+	KUNIT_EXPECT_NOT_NULL(test, test);
 
 	/* String assertions */
 	KUNIT_EXPECT_STREQ(test, "hi", "hi");
diff --git a/lib/kunit/kunit-test.c b/lib/kunit/kunit-test.c
index 555601d17f79..8e2fe083a549 100644
--- a/lib/kunit/kunit-test.c
+++ b/lib/kunit/kunit-test.c
@@ -435,7 +435,7 @@ static void kunit_log_test(struct kunit *test)
 	KUNIT_EXPECT_NOT_ERR_OR_NULL(test,
 				     strstr(suite.log, "along with this."));
 #else
-	KUNIT_EXPECT_PTR_EQ(test, test->log, (char *)NULL);
+	KUNIT_EXPECT_NULL(test, test->log);
 #endif
 }
 
-- 
2.35.0.263.gb82422642f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220208114541.2046909-2-ribalda%40chromium.org.
