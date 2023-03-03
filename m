Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWUBRCQAMGQEULOX64Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BF376A992F
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Mar 2023 15:14:51 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id f14-20020a7bcc0e000000b003dd41ad974bsf1069988wmh.3
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Mar 2023 06:14:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677852891; cv=pass;
        d=google.com; s=arc-20160816;
        b=XTnjiLuupaTCfF6/jKluiE+VZuw7SEC14uttE0s9pNSwKcESR7rHczEyAmQTV0gjno
         QF8HC6fUL0rk+O240yogFtOB4wOXC60/HwwwwzOmMHw3eTxDixi9S3WZTYSFyNgtTK9O
         S3QoTzOTtkUtJi/vABbh/+F6OcsXKbbYczEH8Hjtp3rfU05S9DIuvF5F1pVKt3bw0lyP
         Btq/du+ivs4B0H1EQArrI33wsKiJ0gEtoIAh3tKsEK1aXDUegPZ+oxYqIPYEv/z9BuYA
         Fi810MXwBF/SchSunS3SRQfv27R8WM+nhA+nUsytIhHEMrKzB0UPV8x7NWY+pyfeWcTn
         sJKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=YEczxXsAgX5STYClAtM5Ke4s0v9AQv45+SBvuLiduEY=;
        b=eT6KKGGnRdnyB5zCPR1bEGt2Qnpvtx30oewRVtoiZf1ClOHpyRsw0tOlfsJsnT3WhY
         FRtpJ5+V4ETGqJdCUuBM5/As/FiZY5Ho/E/jVLGrXCg99fSJn8SHP6mhOvFys/MqOyb1
         g8adxndDo1Gqju+n7m4+gwvsWrewKjkTIUL2oERj3OApnDgzS3RzyPgLNczES+FVuLO2
         TAWGbzarZuxwL/wTrISwoTdDMYo0fbsJgETiSgrFxUaIZ+PYvHJqjJcN3shLQZAIf95S
         9WBjev0tUKGyftzRMMKCDrJK5X8chZ//h7LPudM6+LZ7oRZbuu8WXG+GO2XwUNB7j9IF
         gnBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XZGeQDWe;
       spf=pass (google.com: domain of 32qaczaykcqoqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=32QACZAYKCQoqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1677852891;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=YEczxXsAgX5STYClAtM5Ke4s0v9AQv45+SBvuLiduEY=;
        b=dn46QR1KYmGUUgPK5PR73I8VNaGIg5cIGWbZ1G7dLLaefItZpXgaeb3wIkLCY1cJoI
         xDshtu84D++Oyk4o8DAQBmd/yXWcU/bD3FkC0YAZSF/RPhs2gnazKvErlknFCqiNUALk
         jQ0+FBKLS0yr4RLPrnAdDhCeu3lSykpQT2nx9ZNnLd2VWm+Px2DYGUM5E7Lk5BblU2Zc
         rnuz+7aCgcyNhFvxKUJmNASM1WPpj7JCPOD+o4dWb/zFiUZ+tvIdNt5GgmW+2GzEnvCD
         zq9TkyNXl1P1ybL8TLRsFgJwNGK3y7rO9VIQ3+rh3TQBJ7XYDMUu3HO1FJDZO7KTsZcK
         YPxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1677852891;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=YEczxXsAgX5STYClAtM5Ke4s0v9AQv45+SBvuLiduEY=;
        b=LSfnzU2JZK8Ej4JKE0GMevj0ilAfExis6lcdhjQbPL+BSwltWk5LQQrIWkv0iDvBmj
         cuEfREPTo/6wY9hG6YeFeg2L9ASm6Sfyk1eLS937VaNHZ++ZFyp0mK1OBGwsP1id236t
         wMMTqd7tNc4NGuYTwbRTzaZBsgghLQSUD5yaktXWKd4YNmLiJrdGRAm0MEYD8aoSOyF7
         J0R2V0451wq7EA3rowuctm518g/s5W7zAqgOfM09+xyaZu1p1ndQnEz0eKcVWOtA1FPH
         3KCjaZc/fEdkNwuFfS8GtnUUMptCOLjQDeOZPVQInzRoSWjgLoKSnGm0whMP7pOtPEu4
         +Tpg==
X-Gm-Message-State: AO0yUKWZWmw3dH01hIhOD8yAwivslaWoP3rU/oYvOnzVKB59p3bQVBbT
	m4KQUDMEhWu/6R3K3lF8kmI=
X-Google-Smtp-Source: AK7set9FnUWpODbCH9ySi/9zafXi0fkTguBnUGatuUETX/siDxIWlu4acVU6CkaXacWMJg2wVjEqmg==
X-Received: by 2002:a5d:4b02:0:b0:2c9:bd6e:83c0 with SMTP id v2-20020a5d4b02000000b002c9bd6e83c0mr425564wrq.3.1677852890675;
        Fri, 03 Mar 2023 06:14:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c01:b0:3dc:5300:3d83 with SMTP id
 j1-20020a05600c1c0100b003dc53003d83ls1635839wms.0.-pod-control-gmail; Fri, 03
 Mar 2023 06:14:49 -0800 (PST)
X-Received: by 2002:a05:600c:3510:b0:3ea:d620:579b with SMTP id h16-20020a05600c351000b003ead620579bmr1750763wmq.0.1677852889384;
        Fri, 03 Mar 2023 06:14:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677852889; cv=none;
        d=google.com; s=arc-20160816;
        b=UTmLmQ20zG3LZaHn8kmAaIREwi7/yCbnRwwFt66vtBcZXu5choaLx4XN5ULD34xsPc
         OW3ogw58W/Xh8IiAueJQ3W+zn/4u1FwhMP/54H0W/4npRbyYDo9zsqTQpWwgAsarzqUF
         KTCrysee/xKbqTEaFe+o/qMDgpGarQFijrqrbwSCkFFzEHxNI8hKTxq/n5RO6H/uLCS5
         K1evC1nPdUykbFdZ3O0wze/JSS7PG3fdZSNL3HmX9sMlAdVCOElG2+rIDDNuQWynztHR
         M2r8UsaEUtV4uGjj5JU9ofU7az+08r7u3L5zBnLdsCdPIvPh5W7SEM+Ih5m3TOGF7HEk
         N1pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=rwOqGFiMpxVm/Yf2TCVg/tAOnz+fk0oI0q2ct+QMnRo=;
        b=aDTGEvTDCDKCrs16UMgK+PhJKfOWQGBcm3WC/TrsGBNMImqYVEyk6bKshtVScF4cFH
         8FsWYLPX8F0Y2LFwkR2jsbtFVazHyvOsJqn2M30M7jHsFLgPGGAz7ECF9qyi/aAktRRc
         qZ4ZONa9EmJ23jFzF54bWpYtn9HeZ82e2o73uahJGCZnJDsUDVB+MBVInF4nxi0RQdtx
         zTVQPu9ElyeLCuSkmlOeXj8VLMI224jHBSFxcBD7ThXJ+bYTGbpqTz5KhQdmYgMkq0H8
         8YEKiN/fK61WG5o/3ns4fSHfzgVa1MRTb0RkCjihYJX/n99IyW8gPJyOrQ7BSEExgT8E
         hVsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XZGeQDWe;
       spf=pass (google.com: domain of 32qaczaykcqoqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=32QACZAYKCQoqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id n30-20020a05600c501e00b003eaedc7aa48si271678wmr.0.2023.03.03.06.14.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Mar 2023 06:14:49 -0800 (PST)
Received-SPF: pass (google.com: domain of 32qaczaykcqoqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id w11-20020a05640234cb00b004b3247589b3so4207216edc.23
        for <kasan-dev@googlegroups.com>; Fri, 03 Mar 2023 06:14:49 -0800 (PST)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:f11e:2fac:5069:a04d])
 (user=glider job=sendgmr) by 2002:a50:cd81:0:b0:4af:6e08:30c with SMTP id
 p1-20020a50cd81000000b004af6e08030cmr962152edi.4.1677852889146; Fri, 03 Mar
 2023 06:14:49 -0800 (PST)
Date: Fri,  3 Mar 2023 15:14:33 +0100
In-Reply-To: <20230303141433.3422671-1-glider@google.com>
Mime-Version: 1.0
References: <20230303141433.3422671-1-glider@google.com>
X-Mailer: git-send-email 2.40.0.rc0.216.gc4246ad0f0-goog
Message-ID: <20230303141433.3422671-4-glider@google.com>
Subject: [PATCH 4/4] kmsan: add memsetXX tests
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, elver@google.com, 
	dvyukov@google.com, nathan@kernel.org, ndesaulniers@google.com, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=XZGeQDWe;       spf=pass
 (google.com: domain of 32qaczaykcqoqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=32QACZAYKCQoqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Add tests ensuring that memset16()/memset32()/memset64() are
instrumented by KMSAN and correctly initialize the memory.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
 - drop a redundant parameter of DEFINE_TEST_MEMSETXX()
---
 mm/kmsan/kmsan_test.c | 22 ++++++++++++++++++++++
 1 file changed, 22 insertions(+)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index aeddfdd4f679f..7095d3fbb23ac 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -504,6 +504,25 @@ static void test_memcpy_aligned_to_unaligned2(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
+/* Generate test cases for memset16(), memset32(), memset64(). */
+#define DEFINE_TEST_MEMSETXX(size)                                          \
+	static void test_memset##size(struct kunit *test)                   \
+	{                                                                   \
+		EXPECTATION_NO_REPORT(expect);                              \
+		volatile uint##size##_t uninit;                             \
+                                                                            \
+		kunit_info(test,                                            \
+			   "memset" #size "() should initialize memory\n"); \
+		DO_NOT_OPTIMIZE(uninit);                                    \
+		memset##size((uint##size##_t *)&uninit, 0, 1);              \
+		kmsan_check_memory((void *)&uninit, sizeof(uninit));        \
+		KUNIT_EXPECT_TRUE(test, report_matches(&expect));           \
+	}
+
+DEFINE_TEST_MEMSETXX(16)
+DEFINE_TEST_MEMSETXX(32)
+DEFINE_TEST_MEMSETXX(64)
+
 static noinline void fibonacci(int *array, int size, int start)
 {
 	if (start < 2 || (start == size))
@@ -550,6 +569,9 @@ static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_memcpy_aligned_to_aligned),
 	KUNIT_CASE(test_memcpy_aligned_to_unaligned),
 	KUNIT_CASE(test_memcpy_aligned_to_unaligned2),
+	KUNIT_CASE(test_memset16),
+	KUNIT_CASE(test_memset32),
+	KUNIT_CASE(test_memset64),
 	KUNIT_CASE(test_long_origin_chain),
 	{},
 };
-- 
2.40.0.rc0.216.gc4246ad0f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230303141433.3422671-4-glider%40google.com.
