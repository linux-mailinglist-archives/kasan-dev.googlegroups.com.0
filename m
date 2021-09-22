Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOHKVWFAMGQEE5UWDHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 31711414FD3
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Sep 2021 20:26:01 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id c6-20020a05651200c600b003fc6d39efa4sf3670065lfp.12
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Sep 2021 11:26:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632335160; cv=pass;
        d=google.com; s=arc-20160816;
        b=uGOwFMqWGaGby+2VAQ1HJLx+mmB0Vb2hmIrf3e6479eWT85l2YRc6kNGN1JqWCK+ze
         xIMSZjti/SG9WDXJZFVmOel+/0Z8ad831OQkekND18aKQveCvG3KkMTB///enY1Qeqci
         NfkBk08AQ/NB+rx0zW7FgKXSDR8OU4nQ/H/mCRvxv1SPY4ELCi1eUbrmiLQF5suMNL8R
         5ClEtMcELoklXI3qUG2iUHBxtl8gmJ3AVHPyYxrHUN2Cax5IhE6Pj0XupwyDbncU+iA8
         uh7J9AtdhCEUxRGiPGsRhlTafZz8CcnambnKD+gihY5sn84oG2sOW4V5YQOU78fcRxtU
         LoXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=MpKpP/tCQ6R005meS18fltjfIAC73Szs5HKRGdw98OE=;
        b=Mqx+fimVaW+7O7Z0AUN6dpsthQtQKo2s4k9FL5VJJTKOYRCw5IEU728FFUN9BwcRjn
         OVoXRDRxL0URV/U+9wyG8JMgjLPeRdIUnINhiN7SH6295kHRAtJN+IAcFpimau5ZKDAN
         PfGdX0jzVAzCxR4F7WgrEhylwT9GoD72nOV7tt4i17LkLe7GRwyjt/eK80YYGLdy+DRR
         5kEFe/1TlD6O8/wq1fFy3kxWJO4E348ml9zWIRh7HFQQ5fGnuro0XCelCSz+ejk/7n1R
         oG0Z2LFC5unyesIwrGDlfnvPG+L5h+TWG7yioXEONweo/S4kAIO16FQDEEecOt6oow68
         UkaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tT1s4L2x;
       spf=pass (google.com: domain of 3n3vlyqukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3N3VLYQUKCWACJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=MpKpP/tCQ6R005meS18fltjfIAC73Szs5HKRGdw98OE=;
        b=O+uzKwSYbmBVrWG3q0F3Tf+FPBxUNWSVxQFs2vKwrdoifw2jS6FT11mOfGyyo+wxwq
         1jusZHfGmb+fSGadsicviHzpDual56qiBHWoHINmol5effX18dD8vp7eDOgTz5E2UMb/
         8OtYP2ZUEsDdH1GwIMbWQOQTSdLAyT5nQIN1yDlF20gPIPutWLU22PLIfIfQ/FXBjGmx
         /HsviP7omXB+Yi+fZ59TgZv56DURERsRPa/EmZv+oqyzLsDgWToZWuBQhZB2OFL+BCJ0
         HOHUToTx01W4gc/KKgu/qC7m+4HBCI0bmePHBupuSKb4YNC7ziY9f/x38B9RUaeK4xCG
         mTug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MpKpP/tCQ6R005meS18fltjfIAC73Szs5HKRGdw98OE=;
        b=tN0iEJDPnymo9LXUEf4ljdBd3RcC6L88uK8h4Szmd0Hxg8CmIVsE8G3oksZ5+Wa5oC
         8wmChWjFnjAmxBn62780bVPOdt0VGWBmLY375lIxkChP9EbX2/I8EXP6ANJzg8MuCvoX
         d6OHnuswGMbYqVt+9Gq10cN9LLy4F8aPIhm41JC6JmUb7AsfmQxtkaUuRqAS4tn1QB+E
         bstYdBvjtvHpI6hho5FqT79BFV3lJ7wL+J5jOzialrJil2lRo7LECf3WYAL9jCx8z0H+
         HVbfAdE73O5xtnOCzik8JiGUphw3wjzTrsbo482kbEybXyUjF4sNOrAzOePXOwtiLD53
         zJnQ==
X-Gm-Message-State: AOAM532RW88Bkvqk+OD71bbsOiUw3bYjtYY9tTlprwWfMWx5nZPayGoO
	1WGlHE2Pcx5bjU4nqX3b4CI=
X-Google-Smtp-Source: ABdhPJwDhTOHZWf1ewkAWJiH3mVNVbYs3XTeW1MqU7J+26JARUY3cVRcvVBarg6i5PXGe9UlrER4Lw==
X-Received: by 2002:a05:6512:3096:: with SMTP id z22mr349607lfd.167.1632335160730;
        Wed, 22 Sep 2021 11:26:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3a83:: with SMTP id q3ls1121457lfu.2.gmail; Wed, 22
 Sep 2021 11:25:59 -0700 (PDT)
X-Received: by 2002:ac2:4466:: with SMTP id y6mr348127lfl.17.1632335159595;
        Wed, 22 Sep 2021 11:25:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632335159; cv=none;
        d=google.com; s=arc-20160816;
        b=us1Ha4jmPqhZXlP8Xhptf/VVYVF2zCxJMA4Oy0L6ZSC5HghzUAi7Eer4E8o6KpEufk
         jn5WsifJLYZbADjWSXTqA8vuAFbxfqkwqRR7r5iU8n7CrE6CfGEB49GalpvVFPCmQmVe
         vd9wrl/nxNUAac3ml/eTF9rCsc+VLJOlgFU/6Z1277wImafTt0+FKSBWD3KzUND+Dlor
         4z++A+gZEKMIOo37it9/ohJhDQxIbwCRxNQxeB8KmLSizJ3tSubHDffTnqW7rYafwi8a
         70n5W7rKLhV3Vmp3s/G1e6LDAOBALSrXXEyx90/yQf9MNN6biBuNimOGV3jWZ7m+rc+t
         ln9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=hROscUrgx82P/DRIV1g6rbQ4KwPphWmoM+tTMU2qK8E=;
        b=cIiYZB7ZwMXlyEKrd3pez2kXnBOA3YJ6XDEAdOhity48aHgM1VAQFjdO4FpFej7Sbj
         aiUl6trwoE+4oYNPh/AuaU0fVsQx8/4q2Y80/6oYtUysJK+SKBkLBMN8LjO5zgjDnGUP
         8PW6xTEngZiqbIJ0F9xX2vr6dIw30R3/xeCxZBJcyTK7CFIZTWxyPdOYCrGillf5saqR
         g2IJ1+Z2nXPV6RTMZOSL8nR/utxnpv1S9TN3JsgB6N+iM2Z8neKnNWoWi5VJ0Zft9YJV
         ioSvMxxfuzOTHUUAazu/zdRnPnIl/1GJ0SWwPU7PkyQZiWzl5MF47Tup/wVF7a0EXAoK
         Cg5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tT1s4L2x;
       spf=pass (google.com: domain of 3n3vlyqukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3N3VLYQUKCWACJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id f20si150369ljn.4.2021.09.22.11.25.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Sep 2021 11:25:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3n3vlyqukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id z6-20020a50cd06000000b003d2c2e38f1fso4130911edi.1
        for <kasan-dev@googlegroups.com>; Wed, 22 Sep 2021 11:25:59 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:d1cb:58a8:28e2:c853])
 (user=elver job=sendgmr) by 2002:a17:906:6c94:: with SMTP id
 s20mr722795ejr.152.1632335159064; Wed, 22 Sep 2021 11:25:59 -0700 (PDT)
Date: Wed, 22 Sep 2021 20:25:41 +0200
Message-Id: <20210922182541.1372400-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.33.0.464.g1972c5931b-goog
Subject: [PATCH] kfence: test: use kunit_skip() to skip tests
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=tT1s4L2x;       spf=pass
 (google.com: domain of 3n3vlyqukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3N3VLYQUKCWACJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Use the new kunit_skip() to skip tests if requirements were not met. It
makes it easier to see in KUnit's summary if there were skipped tests.

Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/kfence_test.c | 14 ++++++++------
 1 file changed, 8 insertions(+), 6 deletions(-)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index f1690cf54199..695030c1fff8 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -32,6 +32,11 @@
 #define arch_kfence_test_address(addr) (addr)
 #endif
 
+#define KFENCE_TEST_REQUIRES(test, cond) do {			\
+	if (!(cond))						\
+		kunit_skip((test), "Test requires: " #cond);	\
+} while (0)
+
 /* Report as observed from console. */
 static struct {
 	spinlock_t lock;
@@ -555,8 +560,7 @@ static void test_init_on_free(struct kunit *test)
 	};
 	int i;
 
-	if (!IS_ENABLED(CONFIG_INIT_ON_FREE_DEFAULT_ON))
-		return;
+	KFENCE_TEST_REQUIRES(test, IS_ENABLED(CONFIG_INIT_ON_FREE_DEFAULT_ON));
 	/* Assume it hasn't been disabled on command line. */
 
 	setup_test_cache(test, size, 0, NULL);
@@ -603,10 +607,8 @@ static void test_gfpzero(struct kunit *test)
 	char *buf1, *buf2;
 	int i;
 
-	if (CONFIG_KFENCE_SAMPLE_INTERVAL > 100) {
-		kunit_warn(test, "skipping ... would take too long\n");
-		return;
-	}
+	/* Skip if we think it'd take too long. */
+	KFENCE_TEST_REQUIRES(test, CONFIG_KFENCE_SAMPLE_INTERVAL <= 100);
 
 	setup_test_cache(test, size, 0, NULL);
 	buf1 = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
-- 
2.33.0.464.g1972c5931b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210922182541.1372400-1-elver%40google.com.
