Return-Path: <kasan-dev+bncBDHK3V5WYIERBJ4BQ2IAMGQENCNT6TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id A15974ACA61
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 21:27:20 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id s25-20020a056512215900b004406a28c08bsf273667lfr.10
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 12:27:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644265640; cv=pass;
        d=google.com; s=arc-20160816;
        b=b33JqB4D1TOjFdhAVRHAKwYbvKLVGDQ6FsYm7XqMuss+h9vYOl9INGFw7n40JhQOqk
         4GAQW1mzKxGYQS0KKmZTcWbSCJtT4vWB/ve16RMtzgVf8NYH9wiH20B4ykrZFhfweEMY
         MKyxEJdF23Aa5ACdci/mFSvxzzbBlbN9I6DntpprDozgkfMCpCyQQAVxy57AK78L3rZX
         sjI855dFuL+FOIb9kw6zfX9SXQmBLZgNWwoN0Kw5B5wU5zxLnUw5o4Bw6gzGF9QM0q9O
         wzh11jIWCDTlcnd8LHEf6iifaaPpfV4oL7iZlphFdC9kjIJCu+wokM4BY3J4eigrhraG
         BrWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WSLRJ2z1P8bIFT7RUkaUZlGF0sH7wEBzIZgtDe8BY34=;
        b=sVnXOEuPKfwbns/9ZuTuAROTus0aB1Y/AUuKnM9HWC7VIsBlwQsLz4N8255xm5QEDK
         VG6dNAmx77Twaz/ei/a2oLYRbv+WIYJ4yHgt9WiKJZSj5AOL+DlyhcyRxlISmmIHtqZC
         GvHlz7Eph/POc8RAM45hBqF2Wolqrfp+1bEfcxom1xeRzulsx2fbxgbHFPXG3W3FJIpx
         BSKl+6xNQPM1c59AchDr/Ws0RC14Fr9d/wWm0enlu6jXpRjBhsgXzZYBBKqRAmfitBW6
         T/7wvdwty8BUcva79TK1eIdtgLu+W/n3jk4gL5laBFShYm0QHduI27g8WLNYgo11Qzqt
         ol6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=NlftQC1Q;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WSLRJ2z1P8bIFT7RUkaUZlGF0sH7wEBzIZgtDe8BY34=;
        b=ZzhoXzwV3XE2sslTCJO2L/6rmxkMtMAcGIBYZ5vyIagPwX525OeQigP1VYc5Tv7qcc
         tIMP0bg0jMbf0OZRQpwYpZV4h55E+e6HfVPy7+Tb2+JIvdslTkIa12lcgjtcTK0fUPEK
         c0M5FWLbpF63vQtqCVVsdF7RCZ1oSH84WLJnYtLBSU0E/OtPayf4L4vkqlK8Rr2qVcew
         Q2qKTWW77233rdJ9ioZrgQ37TEpQJ3oJ0907VSzEMq5eml9Erv/1PzXbuWoNoCShRQP+
         bVTwFL2OhWqTryxaAb0m3y46eQwc0WdceowscUDn+ZQdgEHoC2AFs0+guoKhASrin1rL
         Ysxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WSLRJ2z1P8bIFT7RUkaUZlGF0sH7wEBzIZgtDe8BY34=;
        b=NE4cYVu+1uwIhUCUK+1yJD6EAyU0NW2Drg58FPsIn4IlupbTWGLBYSsa5ajztl7tZN
         XEcjvDbsckvQN+ps0pMf/Q0oQQTJwWvfUEN7oWOllOIeeOtOJ/CzKXsLV7s9pfpJk+yj
         SGNWmGCQhfG7i4bAtgtxg1r2MIKKhzdVkpfbcacrlk5eHuPSMTH7BU47yYvQFHcyDGTM
         u97AS7XYAbic+3lVqqOO3+asmtv7T0PAvIxaAwCpaQ6cGv6efSC2FQbKxMrtl86kpBIS
         4lb4LYEbadjudtqSiM9GyclBayCDbOZ2pIrPrgHduoWE6iuJp2gzexsJJDVwiFPHLDA+
         APKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5325DcobZX4Z6HNnqzmyrZH/riy6KD0I/NAyMSqi8J6BYegU1Gcz
	MFWFmtAsZ7C7AnaDv/CtrZs=
X-Google-Smtp-Source: ABdhPJxAFgneDWvqPgOhBReH6Vo5hvTcP+Z+pvsA1f1hkx3swq16+2zqMyq/q0Btw9gH8cSyc+HBtg==
X-Received: by 2002:ac2:4c4b:: with SMTP id o11mr802497lfk.253.1644265640047;
        Mon, 07 Feb 2022 12:27:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e11:: with SMTP id e17ls6403060lfr.1.gmail; Mon, 07 Feb
 2022 12:27:18 -0800 (PST)
X-Received: by 2002:a05:6512:3ca5:: with SMTP id h37mr800383lfv.421.1644265638710;
        Mon, 07 Feb 2022 12:27:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644265638; cv=none;
        d=google.com; s=arc-20160816;
        b=QvhIp5GSjhFt3hYg2jyxbwUivpK1Ipiib3hBFWr3rM46czE/8GMS7Xtz4jAbitvW6f
         HwB+SqWEW6IBeIHP1QoaNRTjXkRVaWlrQ5oNsKxiRdb+hQk+TDbmdTCWuBcs/3q7dLjv
         l5u5fVWUNNqbhHuzdfWD+Xtpt6zRmLbrd32g0t2xyNS7ijErWHoohJZZLajZv9L0jX17
         loIBSWEv9kcgmJHlCsQlVnMJEE/Lx6cILgsNbDxyABPNbNEFYCY9AsoAx6dLXQHZoAKQ
         wB5oU135sHJ9u2b6q6/kKhsha4bD7zGxBvBIJbWFJLtZ6f5dSuPoL5nS77mC5GK63+tE
         WiXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KXm+9Zz7kQqt2EFBwAfIC5XooSw7CB+RPRatZ+DKukY=;
        b=ZmuzlF6cIbr1uRehZH7R3LMkWtFbjI6+AtaJTb5UUBMhBP0PIppw5ej/jtBA3086pP
         VkkWt654DJrLPxe1u6LIfx7403ds5pid1FwPYrjS+7xCHiAnsDShGGkjltv2elp2if8k
         jSNTFtNxPTOuYjz8hlHLyKHgmnNqKXTMtrU9Bxe9ZBHXjESibbadnIY7rKPpUW4OCbyI
         uQ7pfd3u0CrVAwYmoxPAiTKRfftcLkH2X/rSN537NWxVuX2yncJWA1moTDvTYBY7G0aQ
         /3N0hTENxOX2L4EoC7Q6Q4CocIG9ofoy0x1LQXQ8rx9WzF6J9iuqrj9kt9IVxhQugYu5
         HutQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=NlftQC1Q;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ed1-x52d.google.com (mail-ed1-x52d.google.com. [2a00:1450:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id o2si446635lfr.7.2022.02.07.12.27.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 12:27:18 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52d as permitted sender) client-ip=2a00:1450:4864:20::52d;
Received: by mail-ed1-x52d.google.com with SMTP id co28so5613350edb.1
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 12:27:18 -0800 (PST)
X-Received: by 2002:a05:6402:448f:: with SMTP id er15mr1246579edb.222.1644265638490;
        Mon, 07 Feb 2022 12:27:18 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id t8sm787893eji.94.2022.02.07.12.27.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Feb 2022 12:27:18 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v2 4/6] kasan: test: Use NULL macros
Date: Mon,  7 Feb 2022 21:27:12 +0100
Message-Id: <20220207202714.1890024-4-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
In-Reply-To: <20220207202714.1890024-1-ribalda@chromium.org>
References: <20220207202714.1890024-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=NlftQC1Q;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::52d
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

Replace PTR_EQ checks with the more idiomatic and specific NULL macros.

Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 lib/test_kasan.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 847cdbefab46..d680f46740b8 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -385,7 +385,7 @@ static void krealloc_uaf(struct kunit *test)
 	kfree(ptr1);
 
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr2 = krealloc(ptr1, size2, GFP_KERNEL));
-	KUNIT_ASSERT_PTR_EQ(test, (void *)ptr2, NULL);
+	KUNIT_ASSERT_NULL(test, ptr2);
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1);
 }
 
-- 
2.35.0.263.gb82422642f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220207202714.1890024-4-ribalda%40chromium.org.
