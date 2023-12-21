Return-Path: <kasan-dev+bncBAABBMNVSKWAMGQET6RSXRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DEA981BF60
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:06:10 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-40c3cea4c19sf10077035e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:06:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189170; cv=pass;
        d=google.com; s=arc-20160816;
        b=qNqsmo5lU9W+EYAarynCVv+i9HhGIqoAfgQWnsG1ri8kZTdeO/XZNlR1hzsfskK4aC
         nJTYeaLSXhO6TFU5AyFpTf7MNMrvb4VDxMGniYC1yz9Op9zTF0b415qmDw+tYzGrdD/t
         GQ+ePStEM36UJgF1fE2iA61xJrXi/DD3QuNjR0D1j/smes48QMYpsAJbNy2nOzmUjRAw
         OJpwZ+hNkZBTV7YLoF1G3ZPGOCSX3AcCMZSvwXKMB68NPTlM45LHzT2fXGlVvm4ys4Jq
         puNE5WtLTpzzFEmXe4y+K3nTg6IDLO4ikEqqfLmTiclm8SHwruxvv/A6qWFAhg3KeKlo
         iiHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=VpnuhMb6UBuSoFAecmib8GNF3CCszQzOE5CoeDYaoKg=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=PYzilzuF3sO+8tXo8gvz+lH7ySn8MX7DvPiK/vcCAILar6nmI7P7f6X1gsd5Ce6pOe
         33aDJsQT8F5RJg7c/reBNHsg8/r6XJ8KnM4SOeCBw2XxXFwY7n0jNh3bJ4wf2AiAIinx
         5bXWLIQNWSHIwodsME1fo/LrJuqb/ub/T5KZB6DCCS5YqC/y2c6RIndhFOWEM/30yrd1
         WXseLjqa4FtrICS3N0DByrtS2WzSWxTcefZjSnZtUME0s7NyscdLQEKPp0MPNrPWz3y2
         08cZ+04utUOPv1Xp5EUVAwRf498s7syw+UV+kOuCFknSa5+ih8YWzo5v57tTnVH93Kua
         JnwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UstQbyfW;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::ad as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189170; x=1703793970; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VpnuhMb6UBuSoFAecmib8GNF3CCszQzOE5CoeDYaoKg=;
        b=luJJV8jMOTVmQ41PbxWHnAlHbzSTZ7w/smWDdf6UBV0NaH21xn3dUxA+jujKGlkcfA
         or0E8zN45Pd+rTMtGNZvQciCPaTHR2ayrPLcDQ9sEiA462HUZnx7XUnPpuc4SZ93DTIp
         i6nY4s7yC+/J5ErW3kO/Yb1uqRRFWyZx0h2scjT4n9rxp7vbRiyuUMfBXLE9SBiwBAeA
         FGKZlSRPll8DVtA1vDzVV9CsMmM8/3WVN/7fhktcoHLnibAKqG6iY/BCoi2GV80kPw9y
         jcoA8qZGrCs5fJYR5CJ26V7Ntj2Kg2F3b28bTwxtCnmn78smhndrDGMazgE4SG3PmX2Q
         lt4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189170; x=1703793970;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VpnuhMb6UBuSoFAecmib8GNF3CCszQzOE5CoeDYaoKg=;
        b=CYLKWIctEP1fhKLeWA6wyya9OxabJpzEvEKFUPpe04wHYgo2LFRD7y7SmgGk1yUnWM
         n/Fratqh4U0TVWLuE2RLW1x7+6+Y7zGG1u/aTB0sc8gFmd+Ie2N4Rgcch6BDqYlQGc9t
         OqaUhsqcY93xZTPkef1th433QxejM49HqhSgTpTr5Ts91Ux0dhfLthhVtvYKQzq+E7nE
         7xjHWgmxasxHoqtJswiyb6AIlDB0LtlKhIyYGDh4MKMFf6iJNh4eWD7As0MfNWS1Gt1e
         eu9//LELhB7GtjuSYrotGtzKfqz3YkMsGYNSlTJdnc2byyIGdzgJGMhMVOUvAuXilfnb
         buBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz5uVozoI99N7Sz74WnmJo3GWpEfJG8SylBVZX56/jwrpfEfC5K
	BWpX4maC19w8J6Q+HEaTTJ4=
X-Google-Smtp-Source: AGHT+IHwa0LSWiDq2sAmyQrBccP9yqXXt9+qcQA++fHp5OEKcNVKQ9rRR9B/PIg79d1F80/ShpLdqA==
X-Received: by 2002:a05:600c:468f:b0:40c:26a4:b2de with SMTP id p15-20020a05600c468f00b0040c26a4b2demr132315wmo.236.1703189169606;
        Thu, 21 Dec 2023 12:06:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f4cc:0:b0:336:8b8e:5dfb with SMTP id h12-20020adff4cc000000b003368b8e5dfbls379867wrp.0.-pod-prod-01-eu;
 Thu, 21 Dec 2023 12:06:08 -0800 (PST)
X-Received: by 2002:a05:600c:6d3:b0:40b:578d:248e with SMTP id b19-20020a05600c06d300b0040b578d248emr154013wmn.27.1703189168035;
        Thu, 21 Dec 2023 12:06:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189168; cv=none;
        d=google.com; s=arc-20160816;
        b=KVE99J8Ql8Md3GrligScE22gDucZArMAQJWtbHacNB0FCo/yFvL6P3Mqvb5LNYOhMI
         XP+yLw6v0QcdIyxySZJ4/ahkjNW+Onj1eFUZ1AWEzV3U2FBZ2xUn6O2K1hwxkc2leb35
         JWpJ2ByqZ+rF7e/bS9K32Q/ex+69XvIoE4yiHrSlAeHpRr9bOuusy0Z/I7KR7BNh8hQb
         uPEMQzS1dScuxZBcMbMP4toP5vETj5mEjFMxNd5pZqxS8U/zPNPDyr72e4r790GLJzYD
         xOcH1wILxUtRhxRXWlTseGjxaCu887D+YIWlc6xzMK/JKCvAPSuTIFxT9QArb0ngcj5k
         26fA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jLiJLNrkVOviOAnhN8fsOfgjq7KcvOUpOIZZlqspNbg=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=OdixEYAqWHaRhm85E5cp+quTxKqZuSJEmAH06krxRdX2vugBY1/zkwha1DAShL/1g2
         ld5jJcrnRWOQBtbcb9s+N87HefgmwMp9NHkZ7L6WdFy7AIJY4U4eCBPHZc8azWgv/r7J
         +3UfIAAl/V3/JQp2D0AgBw5IEuah4mEP13Ebv7YBpP4tW0AkFThswmcLqVfR+umx8zGV
         lI3hACfRkvhqiUQLCqejJ0M5SVH05CYDDkYxx9BTzO46nYM90xWusMN4ww5uqBPNKdiL
         Klmhr0/6vw7PEq7M5UMFPOJtm7+mkKq0cfFMFmXEyi13OmNhMlhRA/WqJfICyEczN8Mm
         p9lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UstQbyfW;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::ad as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-173.mta0.migadu.com (out-173.mta0.migadu.com. [2001:41d0:1004:224b::ad])
        by gmr-mx.google.com with ESMTPS id i15-20020a05600c354f00b0040d381feaebsi99147wmq.1.2023.12.21.12.06.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 12:06:08 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::ad as permitted sender) client-ip=2001:41d0:1004:224b::ad;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 11/11] kasan: speed up match_all_mem_tag test for SW_TAGS
Date: Thu, 21 Dec 2023 21:04:53 +0100
Message-Id: <6fe51262defd80cdc1150c42404977aafd1b6167.1703188911.git.andreyknvl@google.com>
In-Reply-To: <cover.1703188911.git.andreyknvl@google.com>
References: <cover.1703188911.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=UstQbyfW;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::ad as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Checking all 256 possible tag values in the match_all_mem_tag KASAN test
is slow and produces 256 reports. Instead, just check the first 8 and the
last 8.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan_test.c | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 798df4983858..9c3a1aaab21b 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -1785,6 +1785,14 @@ static void match_all_mem_tag(struct kunit *test)
 
 	/* For each possible tag value not matching the pointer tag. */
 	for (tag = KASAN_TAG_MIN; tag <= KASAN_TAG_KERNEL; tag++) {
+		/*
+		 * For Software Tag-Based KASAN, skip the majority of tag
+		 * values to avoid the test printing too many reports.
+		 */
+		if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) &&
+		    tag >= KASAN_TAG_MIN + 8 && tag <= KASAN_TAG_KERNEL - 8)
+			continue;
+
 		if (tag == get_tag(ptr))
 			continue;
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6fe51262defd80cdc1150c42404977aafd1b6167.1703188911.git.andreyknvl%40google.com.
