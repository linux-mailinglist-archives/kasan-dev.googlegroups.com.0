Return-Path: <kasan-dev+bncBC5JXFXXVEGRBROJ5KEQMGQEMANC3DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 74BD14060D1
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 02:20:22 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id et12-20020a056214176c00b0037279a2ce4csf586376qvb.13
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 17:20:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631233221; cv=pass;
        d=google.com; s=arc-20160816;
        b=nQ7CnwJyWBcL287FusVlPrF08Y8FTfSp1W2EWjXzNSZfQMTdN3zuRC2Qp7Sn1cReNf
         BeuV1Oo9/dzWT3NY9ShEahkuaW7uEAUmuNqyb+zENVoeOq83hKpi+x0T3/uqbVqNmUH1
         V749Yv2WkOWek5au7yBRAnN0FxflHTEEoIAduiI++DTNPRJNSuwvX3o3i6PEKZ2Uftv6
         A4wTpxdy7IFtgHSsjYVjw83c5Q5rZiBHD5NNlrPN5XnX24ZV1IsnPKzz53KALhtpTvrz
         /hu5NJyRanO/A+Vq+gwlaVPKBEs01r2luGAqv5febatls0F4KDHhQ5XJy9nPG0JjHgZE
         MOkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wAbOULzPl5bDu2ZiYtWH72opg0Xzr9YvsG2kONfI/lU=;
        b=Bz8tLW3SFLbNjYPwwILxVuQ01rALr4dHkPKy6tXR55OUEb9iyQqEUaUMaaC8prFE0A
         9r2fWROE3EL6YG+cInGCBbNflFqwvK5S+xT1AMTlSMy7qNKqgSBAVSypEqMCeStGHQ1C
         uf67XDMIj6wb12AhaPNfZ1CpyEasWEccsQMlG1JwXJ371q8MMOQK1/eBuL3zWWKP1P3H
         iBjC+PZYuugbrXlJUFUAVb7cVnEXOZQz+AGdKqnCKZaVN9ai3H/QifyEFE7Itst3Fh8D
         jmJmHXr0X87j7gTMKvtGLjPeq6AZCcel+MDp3WjmLiyWoUeTRlERW2xyYzL72BQQSLX7
         zvjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iccTo1h6;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wAbOULzPl5bDu2ZiYtWH72opg0Xzr9YvsG2kONfI/lU=;
        b=ECC1JjYFlOdhLQWbv4Vf3F9/8KwCxFajBsmw+lojtfIxWULHDL7ZF+/WDpxncQFMsF
         i/x7j5uoTLlWJgKh5ND1QmnlZ36Ekogs4HzK2CXZcgviTeJE6tJeQHWdkmS/CG2kkEGg
         TUe/p/LZ6UBsYZlcZIUL7uV1CYYllMjctehRFmAJsLcNKkFiG0MOmNhSJbJkJALzsJpC
         vuCQ6GL819OborVzAFTcUtghqw+nXrTDJIdiUjV509li6xk2pYHYkJid9B+twUPlSYj8
         QBxtVy78q31L8FWHLFB6W3wR3gEIYSXwaFqnF2WOaFP0OkTNJ9nGs8XY6OZXzm8Y7mee
         s6dA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wAbOULzPl5bDu2ZiYtWH72opg0Xzr9YvsG2kONfI/lU=;
        b=ldHiJKSl0ryC5atBWuC5BDF8/Gfdv+cPXcdL3iaYOyaB+xS9JWpseOb98xgoti1MYm
         4NE0vuwDKAuEPlyJa+4gewbYIhKkS98+aWJTsSyOTxv1gBGp5iWuuMwkx022P0hDmJ+1
         SzEc2kQwRiEvJtDY2tFypy0JfD9aj3MhGmSO+zr+xA2Yk6g8SsbNGe3gFbq5UAzApwnc
         +Ee4yKm99QDmb38eWDOti2wiPo8leR+WbXpOQe1Gy7re2pvtzxkZWABJ4WruIIlSSg3q
         8xHZ+kXApRyC6OUYdNea7FtURE5cMrX5h+m+OS8RLoq6tg8kTB2b8i0h0ZcJ1+qBcInz
         Vgog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532tvZpULMPFaarbj+3p7i3N31H42x+qyQBWGvT02nP0xeSjBiaC
	ZXvRsm6A1OlduAU4PzTWIYU=
X-Google-Smtp-Source: ABdhPJz+3ay0O+Gb9tUBa/eCJBe7JqxjIMNWYARzzSGCqJyEO3w0T0opmlj5O2J7TZ54+0nC5UCVQQ==
X-Received: by 2002:a37:9ed3:: with SMTP id h202mr5331028qke.184.1631233221612;
        Thu, 09 Sep 2021 17:20:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:404b:: with SMTP id j11ls2105717qtl.2.gmail; Thu, 09 Sep
 2021 17:20:21 -0700 (PDT)
X-Received: by 2002:a05:622a:1107:: with SMTP id e7mr5472347qty.28.1631233221117;
        Thu, 09 Sep 2021 17:20:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631233221; cv=none;
        d=google.com; s=arc-20160816;
        b=txfNuglonOEIArTOyPBOR2NaQptIxeZnHzKqQvBcph2UrT7/mLVmzWzs7JUAXIiRoQ
         2rgJ9EBcE2XpOruVbMHN9Iql9BwW02lRVsxAdt3iUe1iycS2Ad073U7HKF+UPs2hRBHq
         nyj/UzlrSYIGoAiUn/atOmpSsfdmMmXNctv5R2TaUIkXQ8d6gz5dt5Yz8SuPbkzsTs6n
         A0fkCJ1YPgDRmONG3OV27xsTDOI3YJUoQaow3YyKmpkpUgBUmAHqk/T9iqFlfYnfV+lt
         a81qbye0MZpcdjtBErtD+txuQ+svKK3cRJGbN3rAJ4hbcr0eT/eyeIYUEvxmIFoBSIlr
         DurA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7gr/9ULOUlcQxkELkhyYoj1NZ13m+GpQo4CMHF1AEj8=;
        b=HKvMNQlexDKKcbPVdgf22VBFg1ArF5AnKwj+p9saHP37d76GJcnwdvVA97yb2haAEt
         Ds9pZyQALI6Oq0OSXLDREHlK1O677MVHSyxYECVNN2olaFFgLe3Tgz8w6fYjCpDvSBLH
         wEqkdcu7S8egdZpPSHMAo8dBVoPX+ayeESSylpFeTkXh1lzhgKokkvBaN4GYPdXrlmMb
         zOzsj62r1TVZhamoZQc0AfDnG3/0nUDfsae0/q8iJviuxOdTOKP/slYQmYZvBLH9e2Cr
         omWWfcwGTD+notpDQBmjAaZ4fs5suk7OIaIrJGfM9eFupZJKqWv39acP/aBtPj0JuCpW
         1K0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iccTo1h6;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 6si253602qkh.3.2021.09.09.17.20.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 17:20:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 0462661101;
	Fri, 10 Sep 2021 00:20:18 +0000 (UTC)
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
Subject: [PATCH AUTOSEL 5.13 84/88] kasan: test: disable kmalloc_memmove_invalid_size for HW_TAGS
Date: Thu,  9 Sep 2021 20:18:16 -0400
Message-Id: <20210910001820.174272-84-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210910001820.174272-1-sashal@kernel.org>
References: <20210910001820.174272-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iccTo1h6;       spf=pass
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
index 9a6eb3c9dc49..00b7061edf59 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -490,11 +490,17 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910001820.174272-84-sashal%40kernel.org.
