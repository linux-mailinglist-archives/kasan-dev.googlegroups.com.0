Return-Path: <kasan-dev+bncBCJZRXGY5YJBB5FARKFAMGQENFZUCEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 361B840D0DF
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 02:31:50 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id t1-20020a4ad0a1000000b0028bbf04eae9sf11262606oor.10
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 17:31:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631752309; cv=pass;
        d=google.com; s=arc-20160816;
        b=vKhi7aUFL8Fa/zMemYa6omKZpDythGb+k+9KCdRkOpHzO+gyXETXXw7ZvzqICFgU7C
         N2JyL1eb7YdepWTvYT4X848plBcE0cpAEivlAJ+TQrN9azhpquG2gkiiF7zXvudkwZZZ
         Nuw6aVhjlBNdZUI86lMyg1u4dS4rfgdcStugX6Pj4h973s+uu8Ohje37B8szpL4VtINW
         9OflxPr9L8apeu7w9X/YuhKfRZ7ZofF5Vb85vYkmfgAXGRssbFJOJYjoXbF5DDYdR3Xx
         49YX7U+qnq9zYdqFLAwoPNyujL6kls7ymbcWvF7LqC2sOrV+NNexaYaoKXRROg4SGVYx
         Eb6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Sqmr4TMRXLSoWcpJeUrYY16gGoNXrv0muLKtg9MxHUg=;
        b=isUPfpQr7n4Tt8ynRHGTdem6AMjg3cL4XDC78+3IUAux7QkHAJ5pe84yKNoNsxMIzH
         r61029u+ioW+WaFaCogWqBysR6S4pn5YkM753VForJImZzi/uWEPlHv3FjeWjPwMpROI
         8lq8h92pNfMdJ0b2b7N0VebhIHJ+Y0hYNbiThIr3FxdiZKue9i9huExvsWG1Uyy/axIX
         Y92sL//MrK8m+qd6RYJ2XUR8GAS8pfEHn6W1gjGBgWcF64caxT38PUExBq9B/n2o2J47
         u7C15CJ8wvONL695Ybm1doSt8APNoHZMu9GN1V6MRypBAkUoywzrteaWp+MzDu4A8HpP
         prrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IR0lq1JI;
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Sqmr4TMRXLSoWcpJeUrYY16gGoNXrv0muLKtg9MxHUg=;
        b=PBXdRegTjXL9bX8GE0drfcBd9TrCD+5NYbszZ8HmIuTGZVeUd6fifiMO9MuLa6l9qY
         Plnm9Jevb4E/sAIT7pAhdSIjFPWk8I/M0gx8DlAG8jhmex5OKkKUkiv3XvB5gL9eGdel
         CWQET3HxL2A8vrWvL7Y5xOwcbyHvJae7P87qln/vpChjgS7vvRbMbme+wMMuvzRpM/yR
         n39Zi6vq8Ge77+IURICPnYv/LvRgZWsb1dW4wuQyTAGcj/H/vP2wq2NBebFxUcO1/tjW
         ePVlTf5vYZXt+lpMgbdmqhgtSyjxdF9B3qSoaFoc7Pj1QwKXT436gfB8hl9lojXx851J
         gddw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Sqmr4TMRXLSoWcpJeUrYY16gGoNXrv0muLKtg9MxHUg=;
        b=owYn583qcNcmvIIcqkSw/P6/TtOK3k2LivWRhX3F5tKe+zqm7zX3aun78VauiCFbhF
         EVwa9DSB/RHf/hEhPHOfVNWb5MfKrxJMlEtobrNbW8jqw19LR5MOVwevckw9gk6rW4J5
         hM6r2nbEo9/wHcIGLEnlR+xMkrFYS2TTvLyXI+XSaCWAHxkSBUk2ya74y2Z83ZWkeSzv
         CMlofMMyVwutL3MKk8RVVvOaqZbgYAgbZ/wKyO06c2T10s7ljwf8BxWYJ4PDaIshBHfw
         udtLG0EUXMXoi5II0NHJ2xkOM1IrRfbdwvsQUV3zzIVJe+CrKCqsaHTsx+jmhLaQ4xuP
         GLbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531lmh62csqNKXLBgMD6Aw7GL9L2hKvR6NdW7e3+ZfDztutSNzTh
	yglNsj0FuUpXCIIbybUjzDw=
X-Google-Smtp-Source: ABdhPJzftlTC5WWu2kEL8iCuERYfJEZC5b7giQ5SOLi+PXVWap37MZ4oYwB9XS1R02UeWeZFeQddyA==
X-Received: by 2002:a54:459a:: with SMTP id z26mr1753245oib.165.1631752308942;
        Wed, 15 Sep 2021 17:31:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7b4d:: with SMTP id f13ls1159136oto.11.gmail; Wed, 15
 Sep 2021 17:31:48 -0700 (PDT)
X-Received: by 2002:a9d:4e98:: with SMTP id v24mr2573463otk.228.1631752308551;
        Wed, 15 Sep 2021 17:31:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631752308; cv=none;
        d=google.com; s=arc-20160816;
        b=VySLPCx69BIa8gft46TbVi7PjY+QHvEb6NqTy0n6OGyydnCDLt+OLc9I7vD8awKq9x
         jGISzMHK2g71I8RZGZ0cQKUQDMFrBj8bk360LzTVg2y6SdCM/53Cka1ulkjmItZgW5L0
         2p3P6Nq8sW9hr/Fk5NxKZjMNcFbs8+1ob4Ikcxd87U7RRuvKPQAEhONRq1mnipQNYNNP
         guYOYmqVP7n9+HPBAQ9vCrzSz6v5nPTzm+7AVOM8t6vDHIhjKe8UYXDmzE0ollIg/lPR
         lOERl9HXqjMx9SYhzOQcIFoz2Y0lLStGkZrtgX2FVvn+NYioRbr5eQ2Y0Tc5qLkaT+qo
         Bd8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nrLWQsBmnMpOdiS/+YEYyUcBNHHCO1FuFkRVcwMcdZc=;
        b=OKutzO27gjONRH17ErWqsTctJaQE27nK8i26KPFqgksv9D/XsQwqZ1RUbpv3rEw5Au
         7sFx3v2YB8IJiJunc2v8KysfaeaoO+72cVxnsavTcEb0mvFlmFzLtbjlJZy53mVotTVJ
         vyjDCZ4tCDY177hZU8RdSwm8C44BDRCEWyTHr+6lysiXVGzaDBHMk+J8AcKgogC8F5vR
         o2HkFFLSyNeMjLO4qo2GtHek6BPn+4Q935AMKiw2CPr5Ys7WzhBBGwXDE3uJZerJssIS
         kG60FNN8haCiev++s9+OOIixXcRexgMdJGtHhXi+XwnlbVeWn9WDolrV5XM3n431Xxv3
         AnQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IR0lq1JI;
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w16si323498oti.5.2021.09.15.17.31.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Sep 2021 17:31:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id CB55260F6D;
	Thu, 16 Sep 2021 00:31:47 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id AE0BB5C06B9; Wed, 15 Sep 2021 17:31:47 -0700 (PDT)
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
Subject: [PATCH kcsan 2/9] kcsan: test: Use kunit_skip() to skip tests
Date: Wed, 15 Sep 2021 17:31:39 -0700
Message-Id: <20210916003146.3910358-2-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
References: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IR0lq1JI;       spf=pass
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

Use the new kunit_skip() to skip tests if requirements were not met.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/kcsan_test.c | 11 +++++++----
 1 file changed, 7 insertions(+), 4 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index df041bdb6088..d93f226327af 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -29,6 +29,11 @@
 #include <linux/types.h>
 #include <trace/events/printk.h>
 
+#define KCSAN_TEST_REQUIRES(test, cond) do {			\
+	if (!(cond))						\
+		kunit_skip((test), "Test requires: " #cond);	\
+} while (0)
+
 #ifdef CONFIG_CC_HAS_TSAN_COMPOUND_READ_BEFORE_WRITE
 #define __KCSAN_ACCESS_RW(alt) (KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE)
 #else
@@ -642,8 +647,7 @@ static void test_read_plain_atomic_write(struct kunit *test)
 	};
 	bool match_expect = false;
 
-	if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))
-		return;
+	KCSAN_TEST_REQUIRES(test, !IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS));
 
 	begin_test_checks(test_kernel_read, test_kernel_write_atomic);
 	do {
@@ -665,8 +669,7 @@ static void test_read_plain_atomic_rmw(struct kunit *test)
 	};
 	bool match_expect = false;
 
-	if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))
-		return;
+	KCSAN_TEST_REQUIRES(test, !IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS));
 
 	begin_test_checks(test_kernel_read, test_kernel_atomic_rmw);
 	do {
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210916003146.3910358-2-paulmck%40kernel.org.
