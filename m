Return-Path: <kasan-dev+bncBC5JXFXXVEGRBRGI5KEQMGQEW454ZBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 163414060B2
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 02:18:14 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id a13-20020a170902b58d00b001326cab1084sf26965pls.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 17:18:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631233092; cv=pass;
        d=google.com; s=arc-20160816;
        b=IcouTyO49tTHZBulLh93dY/zU8JT5TbivUwQcj0/u5hPa/dP28ORz/96/Dh53cu7by
         EsSdnrb2cFWG8t2E4gXfvg1QUnHXBo4fun3U4/dzOn8f/t/9OX598L1J53BdwMTY7LhJ
         +vMqQXcc9S3MAagoh8rWCC5Ulz65JZUmV6cuRw717VMbS3zt6uqvUkfdy7WBBlaIsjVy
         9FCVA2Rwo9Jn60QwJzOsiFutFL8BnbfbQ9ntCKMqwK41cGbh8VXDXIIFap5x/dHDppqo
         hNCjC1ITWlLC9qoFFqIfk8PNRGf/QNklfYMv+zwWwyXxyfs1CWaSPvRZHo1iS0AKm4ta
         x6qQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=HafaTxNKEZq9xjVrGdIdg5h21d033bRl8DQl7CRWTFk=;
        b=NCi3C9xOqaK+EmsGkL56YuLwf9wLI45J8bMlgjWH8aJYaLaRo36O9B6fczmcg1ht9f
         7bK141zIcrTyaR7lKpR9g/OslObFtqmNA/HVD7/CSBcVo8El0XIXlg/g/qRTdtbPdqth
         ENvv4GZFUrUOzevSML9DB6qiOYbpRaYH+NvyOStrO+abBdzyz0nN8QfXLSQ48GZnP0Fe
         TOLMBdJtssgjaoV3IEqSJhERLfdo6bl6kylQ6MwUq2gKHWo3e5g4u4kkTYMEHqwZuhg3
         BAVA47kHh3/mRvbnZ0pXgq2KgARfaQ/05tUjKViyfAslAMvJ7Nnq+hbdPnMC1HJuviQ6
         z31A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="LY/SnYnM";
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HafaTxNKEZq9xjVrGdIdg5h21d033bRl8DQl7CRWTFk=;
        b=Er3PRtg4HWE+BaZHZ8vEqOnSJ7aEUwfiJCkPOPoH6klL7w0icFP3bHQ2fAmSdUWJwU
         ODzMJGF85aLxCntn79azm+e6lIr8kx/HS1+JqJ7lp996slCYtfobYAmyZko/Cvga9PLC
         2wtlC7FhFccc8/gq6/FXmbbUBGRyE60V4arOpNLIWIrrHMWja385A24LHrdAZvmY1bDX
         5eRIbSg/69/ctIvV2HsuWEm0ntWmnLW6UdRuxTGw3ajppaUkdknxudDmK9gVQfMk5PL1
         TgYvaBs8X3Btcinsm30Xjmat2uHxdGqyqJLg9/8mT8el6krQTyQLQxN94++rxxA+EsKh
         ZoyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HafaTxNKEZq9xjVrGdIdg5h21d033bRl8DQl7CRWTFk=;
        b=uJdNJHiaxLjo+9fyG+y+dQW5ig597ue4+9hkmF+b6TJxpQcO18ukx7IPzPGN7coMM6
         khK5dG8PDnESUZrb1ML7+qPDjkBjHtBrjj6efvSvLr+5htfYVoqsGGI/qvvgWRJlRuOy
         TZVKu0Oqj6stlXNQuDnZeKb9+MQMGK1uR1iHeEJ9w3Vbl3i1ct4ycKhRvBRNK4KCmvPH
         4/EL6uAdFbXfoHmuyDuGFsFyXUqocXb+hKBAoFh3khPWhkLs6jij8c9Te5Z10r5JNZPm
         IwukzCa/KafwnKhNKjKNHjWvAPkffq8XFZ7tABdM90xjSm7i22io+mfq3ry2c8Sba/rb
         Sjfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533haM5QQEEnB7py30NU4onetzVeATgBA3ilUZ6qvudzTFYfYyeo
	7GX+PEqfRycgzdYuZBSNO60=
X-Google-Smtp-Source: ABdhPJwFYMBBjTqO+aKpHp0Pf0Kn1kOuo2/QypP6KXbqw2+EaVKyoccjosm9qcQllaI/QJp/xHuxPQ==
X-Received: by 2002:a17:903:183:b0:13a:1a0c:35f6 with SMTP id z3-20020a170903018300b0013a1a0c35f6mr5045345plg.69.1631233092784;
        Thu, 09 Sep 2021 17:18:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6643:: with SMTP id z3ls1559459pgv.3.gmail; Thu, 09 Sep
 2021 17:18:12 -0700 (PDT)
X-Received: by 2002:a63:e057:: with SMTP id n23mr5041077pgj.183.1631233092124;
        Thu, 09 Sep 2021 17:18:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631233092; cv=none;
        d=google.com; s=arc-20160816;
        b=N6IFu8GvPwasWGoIwNx88ue4dbAjqhmvR1MI7XvAc8/A8dhnOTV9l+bJwJ86UXyiWr
         7mQQymiuotj+mLkSwWPZCT+ca/MkuDTkIwnOq3D6otF/n5Ikn1YIZ2Xrr4qenE7aoyTC
         gog5K3LMBegh3mV8Br4pKAF7It+wCUN/9T456mTdpt1JDgy201A9xpqn35pScGE5kFBy
         WVBAo9buQ9yYZ2OLchftzpN7Ot2/6yu84nSjoAMHNtjVE1pKEFhlN0foJNgtthVirzAG
         DKQ89dGoqJhYaIOav0ahman2hoHnpkkNX/Kk95HG2bqChPwIejTRS3TaJ5YA1pDrUU0m
         b9MA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rflFb2Hyy3AF2sjPv9uEetynMRScYgbrna6ktwPejhI=;
        b=MBPYWqfKEApHttwcPQIvMinA491CpjCbT9Jqz/7i5LAM7T04BEqiEj8x89vd9xy5Oj
         SRJiYbCbnb0M1qVshdvpqEK1uj8v7H99KIBnPRM11TF+qMKbwkStjY5SliTHIoBh8lTQ
         9IAOqp+PwrbxAOgJ9qEYA7wyGX8DRB83F/DfFmUeWF/sn8YFyC1bnq6tBT0TdgUReNVx
         tb9X0SKUCXdMrTGJ10nzf/4whg5L/0nRTbzYFHec71mNvVxDTtPfrui0iCeWz9bSldkJ
         sMZSUqR7zYcsCFecE90D6XY72K81z8ZX3bX/ajUszernPdxlLVQG/fqloFs7BLImBnD4
         Ndkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="LY/SnYnM";
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r14si373780pgv.3.2021.09.09.17.18.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 17:18:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id C2D5F611BD;
	Fri, 10 Sep 2021 00:18:10 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.14 95/99] kasan: test: disable kmalloc_memmove_invalid_size for HW_TAGS
Date: Thu,  9 Sep 2021 20:15:54 -0400
Message-Id: <20210910001558.173296-95-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210910001558.173296-1-sashal@kernel.org>
References: <20210910001558.173296-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="LY/SnYnM";       spf=pass
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

From: Andrey Konovalov <andreyknvl@gmail.com>

[ Upstream commit 1b0668be62cfa394903bb368641c80533bf42d5a ]

The HW_TAGS mode doesn't check memmove for negative size.  As a result,
the kmalloc_memmove_invalid_size test corrupts memory, which can result in
a crash.

Disable this test with HW_TAGS KASAN.

Link: https://lkml.kernel.org/r/088733a06ac21eba29aa85b6f769d2abd74f9638.1628779805.git.andreyknvl@gmail.com
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan.c | 8 +++++++-
 1 file changed, 7 insertions(+), 1 deletion(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index b298edb325ab..c149675300bd 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -485,11 +485,17 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
 	size_t size = 64;
 	volatile size_t invalid_size = -2;
 
+	/*
+	 * Hardware tag-based mode doesn't check memmove for negative size.
+	 * As a result, this test introduces a side-effect memory corruption,
+	 * which can result in a crash.
+	 */
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_HW_TAGS);
+
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	memset((char *)ptr, 0, 64);
-
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
 	kfree(ptr);
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910001558.173296-95-sashal%40kernel.org.
