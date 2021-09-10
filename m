Return-Path: <kasan-dev+bncBC5JXFXXVEGRBSOJ5KEQMGQE2UBM4FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id DE9BA4060D3
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 02:20:26 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id n3-20020a17090a394300b0019765b9bd7bsf173902pjf.8
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 17:20:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631233225; cv=pass;
        d=google.com; s=arc-20160816;
        b=qk4dorLHHzEkuVTs3/K4fnRz8Nup7qABHbTYO3g6FYINzhQSD5+B1aHOWkCxXlhqCN
         0uF9dhwaQ8l4psk6gfnkfvUF+0n3OI0kGe4iT9Shm0lOsyg2mDzXDGqppCWQLn83plsc
         udil9dBDlLwPZRd/QxYc1urS02GmsEDhXBIcMqp/hfE8+889tJV8tsC2jR+oq+iwaLWw
         N+fdNgMU8/oMsHXg2LhcfxlErV7jMBTw1GYMvNGaI9qUUze9PRjaoJa+d1W8Un25FQDC
         +/FgxhdXHf6pLlVRsfG0Zj8m5PqR3hkk9ci1YHWTq09rgftQ52cm5FuVkfD89MMkrfgi
         sFKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/dFqi5o+LPL02ZhyAq0602dHCI4Vtz+XBEdM8B53rkA=;
        b=ZhpX0KYg8yrVzuDR0thYw5a4vYYvttKLpdUVZwYh8lwX8pkH/lw3z5Ivtc5E3fZibA
         lq16JJQNtKXJ9NvdRVJP05UKJzlzJRrSbscWWC0sT2NapzpK6z+goU1DaLOiu3MWSjne
         UQRNTjWdUuq5z2qmj+rV/Hs8sJ1Vngr1gKijTmQZnsXGf2dYIbYkwRdF6U6PwSJSvAL/
         bHo2lv58zvpQS1678zraA2Qypnnfhc7sFhw2QPwt3z/KM15EnPXYbpoQqCKSUDdnJa6B
         paTGA2KI+HjHThzfFnV2w2GQTYMrtKFyPWoX3ZUGXhLWGO8uzwlFtwLGSC6cs7qQzAZ9
         VevA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Qt4XGzAP;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/dFqi5o+LPL02ZhyAq0602dHCI4Vtz+XBEdM8B53rkA=;
        b=tTZf3EpW/FKX7JhMVBW9MfyPEcFqiY5p2QmWfWaoZVsm6Qdi2Smzvk+kGjxhJ9zazl
         hjSdrGhyRQYrA2u2eWKMpdh6HlNrS89kgB56O3q7Pv/Cy8EHJvYCetFniFtPHUC2GTkp
         JersVl76I6cZJ8LPPNNI1hdTp9/FjCewAwUyQurBsfCQZ64tTXNw7z0q48L4x/ZrONqk
         JNWS7WExftWewgSX+TGSmXnKt2KT93i6S/NsR2U6zAZr7cizcYPeg49LMW09luKbzJBl
         keIgK0BYlZy65adTl5gEyFrVGljISSfTxtY5sM0i02zc+cXPMfKQdoV8h4p/QFUR2OOp
         ARog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/dFqi5o+LPL02ZhyAq0602dHCI4Vtz+XBEdM8B53rkA=;
        b=Bm1b/3i1tvxRc9yFZs/nQhk/CQM5KhufV36hTLK8UICmY6btLFl8zXKzaViM0tfEXv
         9TMjpcuOvmQt8b1isilfYOHpNjU2PxGvBzFsVMJ72yY8wZ2dw6OiqeWtuq4Xc0a5xiVL
         QXHPtnMfHR1ZYPTRB9g2uwjHCDw6/MlPWwOmRIvxkkI4b4kv95uW4tFA4HGzAR9pMANQ
         H5RXJI1w0SBVvajunTzER/zGZGIxdPLw5Oaf1qwwyUrSZDe0GbJDP1lACGYZBJBhzXo5
         HVEin3NZbf6CvkozHAsVop+VSAYXdsJdpRWBGsOA5eWCJ6bKHoteP0yo9FdMFAzlz00r
         XR2A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532PwLiKOJ1oSM+3rAvAFtwVQ4rgCk1VBBpF9NNhB1RGVCP2Oo9X
	D21MZJeVOBsM8ofLRCI6xkg=
X-Google-Smtp-Source: ABdhPJw3pYTUC0TB7C8l4u7IGI8WhqaJDiyP028xt32qmF0/nBktGq6IINq9XDSSacF6FoIjH9EmGA==
X-Received: by 2002:a05:6a00:21c7:b0:412:bb0b:850d with SMTP id t7-20020a056a0021c700b00412bb0b850dmr5569328pfj.33.1631233225662;
        Thu, 09 Sep 2021 17:20:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2445:: with SMTP id l5ls2083841pls.8.gmail; Thu, 09
 Sep 2021 17:20:23 -0700 (PDT)
X-Received: by 2002:a17:902:e293:b0:13a:4f14:f24 with SMTP id o19-20020a170902e29300b0013a4f140f24mr5207180plc.4.1631233223554;
        Thu, 09 Sep 2021 17:20:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631233223; cv=none;
        d=google.com; s=arc-20160816;
        b=LHDD7qM4wLKNfaC1F7/WwI0webIb7nYaaAu3eYsdwkD1eXD24gY5qBXLkkV0brcFJI
         fPHHS2reakF6p+a6bNINVbAB6ABCDBp3yIoLCyFwxTEu1n5j9ObxSqI/0RKGpp2Jmb4o
         zWkyn4AhEWOM70quo20hDa7xbSHWFF+xSVNVINxvWe5Zq0C6mBR7/5UuvB5Zgi8RQZBH
         isLSYKoshLJ3YvsSoVTuwakvcttYRXK7P6X7oYYHQu3SVeplsbgkppHiVrqWFiiaZ/ik
         /pxiogz2XLWGR1SIB3eiVl8DBOB8xLehe0k+N+mJiR/sDziRoXLTxM6j/IR0nVSs/+cZ
         WOlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vMzA6+vNmTiGC1DJtXCUAFUxM8rAgmzoOMMdfbiD6a4=;
        b=qV74fYPJLw6+XDzZuTOkQvmpaP+ocixnK0G3hJx3a2vQwYx7QHH3OOAN9IppZWfY6q
         kVEsZiUp3Djb5IKl6IWTDspARwa+yGa11OzCKrSdjBmdHOGs4BVqo2TcZoKhUIWrIIM/
         9RYbohpLLyMB5nvxkoW/HTOkvBNpFPq2obrE7CapYtOZgZhcm4VvW/T/X4z+e5NN2KrK
         BvvCJWgIPcL7FECUNS+cKYYWBUPGRl0cO4BFRhK4ZS0IQve8lgg8mqUHJ9t6kFOSGk1g
         q427mrXqsqS4Yo0fpuEgJKgRGLvRkajN7ia67iwLybheoMxXyrgjDO3op9DnU1FdHFnu
         4BGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Qt4XGzAP;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y2si284048pjp.2.2021.09.09.17.20.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 17:20:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 32A26611BD;
	Fri, 10 Sep 2021 00:20:22 +0000 (UTC)
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
Subject: [PATCH AUTOSEL 5.13 86/88] kasan: test: clean up ksize_uaf
Date: Thu,  9 Sep 2021 20:18:18 -0400
Message-Id: <20210910001820.174272-86-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210910001820.174272-1-sashal@kernel.org>
References: <20210910001820.174272-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Qt4XGzAP;       spf=pass
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

[ Upstream commit b38fcca339dbcf680c9e43054502608fabc81508 ]

Some KASAN tests use global variables to store function returns values so
that the compiler doesn't optimize away these functions.

ksize_uaf() doesn't call any functions, so it doesn't need to use
kasan_int_result.  Use volatile accesses instead, to be consistent with
other similar tests.

Link: https://lkml.kernel.org/r/a1fc34faca4650f4a6e4dfb3f8d8d82c82eb953a.1628779805.git.andreyknvl@gmail.com
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index c8ca85fd5e16..7a02ecc63b7b 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -726,8 +726,8 @@ static void ksize_uaf(struct kunit *test)
 	kfree(ptr);
 
 	KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = *ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = *(ptr + size));
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
 }
 
 static void kasan_stack_oob(struct kunit *test)
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910001820.174272-86-sashal%40kernel.org.
