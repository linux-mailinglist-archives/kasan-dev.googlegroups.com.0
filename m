Return-Path: <kasan-dev+bncBC5JXFXXVEGRBZORYGLQMGQEHDICNOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6EB1058BF47
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Aug 2022 03:37:42 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 131-20020a1c0289000000b003a52a0c70b0sf2315414wmc.2
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Aug 2022 18:37:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659922662; cv=pass;
        d=google.com; s=arc-20160816;
        b=QgDuSoj2hw9cqU2sXWJCn48xVEai3SlEkozImzVxVnTTE5HvVfn4mQiVJOMEO+rBYP
         07DUXw3oAEUbU4p8So5H+wanaLdcMTwX8TtcsIh7v+I7p7ctZwe0odNG+1+BQpJcQ3os
         s+8BtL/x4deUqu0582DsJhILwP4eI1A7WEmlJXpQPfS7WdS+SDABE96OOAKIF7it4O8W
         L4RIRRS8p5v4wVrp56NqJ8gPejltAT/IddM8svPTQC3qFbJxIFlhNRudOVLemiOCeBYG
         oPcJUbQI5SKgJdLPxpxzi7IheXNVzOdIZzkC+Qjqj214qFgMKya60KHOTfy0myHC/Ytl
         sLDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ykRClUQ64klc45m2iSGMw1U1bTApiJajRTSKIlyrh8U=;
        b=MqvnVDiMDeDpDJaZ2psT/TPUQIqh10EPquKtRLoBRJaeHML6c74pU4PNin4fi5ZLAs
         t5YgZl+x/km6jaRCWlB7hrgOD7hoTgkLqe2Mex74Jw0BaDmxg1acJmxiwLjzJOPvDSMk
         BHllHLpX2W7iPovUhIBwAgw7DsGA/bj8+y2taFDPwudf2AwsHnlNItZNVR4BPM9hjXYV
         Et6t4AY68mJZJGCh2rDxKSiWRgwPyKIzTxbnL3ZsgZiBrF0ZldUbOylS2hoigR8xe5cd
         8kobrB9V1Q5VEtQCXwtZV5L3yfPL9W4HURO3n+x/gFnKY06uFzHBLViThSXiddaZBBPu
         pFTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kXPJ1ZRY;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc;
        bh=ykRClUQ64klc45m2iSGMw1U1bTApiJajRTSKIlyrh8U=;
        b=pTbnGTTVgBiEqqbtYrCMN9EMeRsNV++dp2UZWk1p9cvSj/p3j2XPYxkVHZAvhUjwHK
         w0xWakAc3AAbTSRjSrtTNfaDDzWyXP7jb85XMyDdACA3+PHEGnnra40rB9cj+Rx+GfQe
         VtMogNXSFLjG0KkrLpoP/lxMb8jw/2KJbmqOb/uNCOSPBoH1J3LJ/+cBLRW1WwoAmig9
         sbhqPlQgDRKTaClCcB2LXHSOzUSmWwkAToEcoGLIB8Xl3Wr0k78nU2VtF8jGvgk3lv0f
         xFN4BOqm8f55UQHcgg7AE1lg0CTLH4OsOJG891KycX/+aiqdMswEfz3771JowSK9VzNY
         yn+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc;
        bh=ykRClUQ64klc45m2iSGMw1U1bTApiJajRTSKIlyrh8U=;
        b=gSvhCWMzuXC+fkTX40Z+Ap4hhIFTHm3Say7FjpTHvaJv74Mtsf+Ty3lo72Xa+1L1uM
         lSuV51jS1GFnPqYne1Yaj/XVmD66dWQfUilhDSLbvzr+wrn7n5M82LP9UfnpBE23rfU5
         Z7nOamp7OW35iPwywI5hgZSP4OCxEFGFePazSADOEYIoi4QdP4qsAnPucEkSoZr/mXQq
         7G3l+mn3o2hKBIPZ7KWIbK1zdzDNQTMNCX4edYgVm9CNj7YhgWpEx0Re/GhEKC9hVHDw
         u414bZ9WPaND1lRO11IhKrj9pVghh8yEhpJdG+h+lisYV8nHskHRZeQWUy6FT16svMbJ
         rq8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0T1Lyoqw909xztGQCHM9CkVdex34oN5pX6wBcyyw7qXIr0V2iY
	CiScOV7jBv5FYwJm8Hj+vxw=
X-Google-Smtp-Source: AA6agR52u/abJbLU8y47+MNZgc9+TN4zCTWo8V2zlEzpAjkgzT+I0rjN37zpoKmFkcBajYBZug9CCA==
X-Received: by 2002:adf:edc1:0:b0:21d:7157:f4aa with SMTP id v1-20020adfedc1000000b0021d7157f4aamr10165412wro.454.1659922661958;
        Sun, 07 Aug 2022 18:37:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:ed13:0:b0:3a5:24fe:28ff with SMTP id l19-20020a1ced13000000b003a524fe28ffls1449250wmh.0.-pod-control-gmail;
 Sun, 07 Aug 2022 18:37:40 -0700 (PDT)
X-Received: by 2002:a05:600c:a146:b0:3a3:1e79:4446 with SMTP id ib6-20020a05600ca14600b003a31e794446mr11304891wmb.158.1659922660739;
        Sun, 07 Aug 2022 18:37:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659922660; cv=none;
        d=google.com; s=arc-20160816;
        b=TYMOiBlDwHzWGCAHmE98FekjKApePPTV9DAjV401lJVPEfkTg2BN8zVM4b3qdy/nic
         JBaluXdcdekjqqcZquGXVor2NGyafSjp3JHc1YuUrMby5qFrnUtGHgL7ooOOIhaoe3p+
         t9VOlzp3IhFyjhLEzyOBAKK2hyP2tn9nbo7YXC2ygiEr7XeRz9+w777AIRg18uu2Tbmm
         2PatB0cL7+/sC5FIgbYLagxLOD/NIZFN40KoUegKm6/xljElGiFd7DpC8EwVL3/U8d2k
         7H6mVRLswTtMLypkOxL2+3pVpyVS2gSdnM1INw+2ac1N0lhXiJud9araFu3XTpqXkVNU
         xRsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eOFmZIKwdWPayM/IbFRh/n2EQwtjiau2JhlUjiXFPmY=;
        b=DBMyYVRscqm/g2j5mJ2EPfUsIVX8gYJxeDMauONzN23rJuByLKINpW3/PQrqpCClED
         UnWQDvzNG8a3l9WC0kDHhxK/pyTgHjR/BgVbyJqWvoQh3fd4qIfGa/oWlvdajsTVIwTT
         XKBSsehRVazV+v0pMesZFbtMQpZKPQKv21k9Q0igeYzDxj+wA5+kLvtS1rgTkEDX2wQ6
         5fwp2b6NZqc1bgboNMw4AZRBVww8iOpNyHeI/hL2RkRV9+mEfuuMMfl02JgGYcP6oLAi
         WQPKYgtOvoIedSljUyL9CPVDyEljP5pfotuP+dE8H2ccCC761P/TTh7AlektWHPpZDK1
         9Grg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kXPJ1ZRY;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id bg28-20020a05600c3c9c00b003a4fbf53413si300637wmb.2.2022.08.07.18.37.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 07 Aug 2022 18:37:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 6F179B80DDF;
	Mon,  8 Aug 2022 01:37:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id EDE1EC433D7;
	Mon,  8 Aug 2022 01:37:37 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Sasha Levin <sashal@kernel.org>
Subject: [PATCH AUTOSEL 5.15 45/45] kasan: test: Silence GCC 12 warnings
Date: Sun,  7 Aug 2022 21:35:49 -0400
Message-Id: <20220808013551.315446-45-sashal@kernel.org>
X-Mailer: git-send-email 2.35.1
In-Reply-To: <20220808013551.315446-1-sashal@kernel.org>
References: <20220808013551.315446-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kXPJ1ZRY;       spf=pass
 (google.com: domain of sashal@kernel.org designates 2604:1380:4601:e00::1 as
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

From: Kees Cook <keescook@chromium.org>

[ Upstream commit aaf50b1969d7933a51ea421b11432a7fb90974e3 ]

GCC 12 continues to get smarter about array accesses. The KASAN tests
are expecting to explicitly test out-of-bounds conditions at run-time,
so hide the variable from GCC, to avoid warnings like:

../lib/test_kasan.c: In function 'ksize_uaf':
../lib/test_kasan.c:790:61: warning: array subscript 120 is outside array bounds of 'void[120]' [-Warray-bounds]
  790 |         KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
      |                                       ~~~~~~~~~~~~~~~~~~~~~~^~~~~~
../lib/test_kasan.c:97:9: note: in definition of macro 'KUNIT_EXPECT_KASAN_FAIL'
   97 |         expression; \
      |         ^~~~~~~~~~

Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: kasan-dev@googlegroups.com
Signed-off-by: Kees Cook <keescook@chromium.org>
Link: https://lore.kernel.org/r/20220608214024.1068451-1-keescook@chromium.org
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan.c | 10 ++++++++++
 1 file changed, 10 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 8835e0784578..89f444cabd4a 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -125,6 +125,7 @@ static void kmalloc_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	/*
 	 * An unaligned access past the requested kmalloc size.
 	 * Only generic KASAN can precisely detect these.
@@ -153,6 +154,7 @@ static void kmalloc_oob_left(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, *ptr = *(ptr - 1));
 	kfree(ptr);
 }
@@ -165,6 +167,7 @@ static void kmalloc_node_oob_right(struct kunit *test)
 	ptr = kmalloc_node(size, GFP_KERNEL, 0);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
 	kfree(ptr);
 }
@@ -185,6 +188,7 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 0);
 
 	kfree(ptr);
@@ -265,6 +269,7 @@ static void kmalloc_large_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
 	kfree(ptr);
 }
@@ -404,6 +409,8 @@ static void kmalloc_oob_16(struct kunit *test)
 	ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
+	OPTIMIZER_HIDE_VAR(ptr1);
+	OPTIMIZER_HIDE_VAR(ptr2);
 	KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
 	kfree(ptr1);
 	kfree(ptr2);
@@ -712,6 +719,8 @@ static void ksize_unpoisons_memory(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	real_size = ksize(ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
+
 	/* This access shouldn't trigger a KASAN report. */
 	ptr[size] = 'x';
 
@@ -734,6 +743,7 @@ static void ksize_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	kfree(ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
 	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220808013551.315446-45-sashal%40kernel.org.
