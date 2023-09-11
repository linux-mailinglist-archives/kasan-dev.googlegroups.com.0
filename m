Return-Path: <kasan-dev+bncBCCMH5WKTMGRBT6V7STQMGQEFQO4NIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5500679A930
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 16:57:21 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-57617c2528dsf4563232eaf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 07:57:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694444240; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZH4Ag0J3HDrEQGLj2QiCCeCTvFAjNiRxjso4E+JFeiNW9xr8SG9xmKATXZajYXB/PW
         Iq+tREOnTx69qEnvTzIhaMWkrzBGsJQXtSyv7+E1+2xHjVIk2kywNIbl1S8iECrlyKgo
         dVUCXdv4pACb6S5RSHfMBqc/YZIv22WOcHTGDpgjV0Cq3TY2nB4LfuAQZNurqNAKBUZA
         I0J7eOuUw2Vsj1Qy+EKcroLEtsVkE5LUnfbuGyDhrXEYngmDzCbYRESqWjIpyJkdTTNp
         DNx9xa6mH/+hANIXRcAwRXARHKJdtZ814Zu7GZgamIMI78oVYtxY1uRWOOG8vVGpJiZN
         gXFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=nX0mjkeG4aHcCs43+hNW5s7tXWDmJ1hiXG1MvDjm1ew=;
        fh=x/Eq99+ICi7e9grjZNFq4mA7WJOkDm5ZB5wM283JjUk=;
        b=NeAfR/FOnt1tOZErOJZB7WTRlohafsb7q66x7dF2ProtWZYJWl2o9P7lToFdqJSalw
         E7gWH/qYq8JC7T8VmvqphoG8rs5H0CwHAqSxpIAroOgnavIMRlT23wUunPokqjoWkeJ9
         smu/VG6gw39htwbdt5Iw8RMvwVAvTn1i4/l8d2w+OD/Qvhm0cryC7a6x6dPaQLFtsXvV
         pgo13DGFuZNmRluyNUhs5KxAUG1WSKtGbHMKgL4wqqJc7NFfEQkysCp+bbNHyyb8j10l
         Gpf7EJ4tfDb1dL0609yNMeUmik6BfI2Julku1ia+kj+kUwfyHB5I3WXbNH0ZDd5pkrjS
         XimA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="fAi/BI4X";
       spf=pass (google.com: domain of 3zir_zaykcu8x2zuv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3zir_ZAYKCU8x2zuv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694444240; x=1695049040; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=nX0mjkeG4aHcCs43+hNW5s7tXWDmJ1hiXG1MvDjm1ew=;
        b=nLF6Qs9XP2zhntkNGtpALToMwq2ZHNUyawzCOZDPUorGcj+DbZ+nr8TNGXdNbR9BHZ
         eS79rQd6Vyyzj/eMU+yaqid5TCkFM4TB8rQOd4SmOAFVjlQ1vl5z24J1Hko7kOASuCVR
         yI9LqhDZJ7ZREeiHPiIOXZmToH4K4mjYteKwGgSb0ZhcrkXn08+6UYzs/NCRFoxtiG8b
         mqYoOS+9bjjsFO9bghEAiplO8fMPv5s6g2pT6llJnJsiuk+l7LaLFaV1YUtbkjrPwkGd
         8/+YVPWqDWtngT3wcVmHkKKUblpGXZjAZjOiMs23RK93JmJelDa6XxuhKsAaghdmWWfy
         aAPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694444240; x=1695049040;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nX0mjkeG4aHcCs43+hNW5s7tXWDmJ1hiXG1MvDjm1ew=;
        b=bE7nccaJLdAxgYebjUEgK+E+60Jz9bKMs3llk/eWvrSXedhzAAp57lO0wfQ+uVaXd6
         em1FT4tiv6AXqvaVo95ETt24t9bcA5WNJ4H9KEZ9ekdzTXvBnUGhf9wlomAt+ZlUIOxc
         tmM89JqbZGV0QtZHRA+K5DMuwHX6iOCAu5A/A58bY8Z+H4r8uDUpIijwtgj54x7L2RL7
         sQkUlRFpRi3IHCF3vwopqAeIzsqw1ms/Loi5//rorkXXGYpgXB7iHGNtTbeCl0TMwldF
         JOD7AQgKDSCMCbls2wg8iNvSTn76xBEEZj9A44gtoJa8TDiXANHB8P9X2Yn9JsUfJaRg
         lBNQ==
X-Gm-Message-State: AOJu0Yxm+iieMPe9nuOYPXfr80QP41vAy8FeGYanYi/mmd7pbU9YBxpZ
	2Lj9yH6UakNTU9HtAjuHAoI=
X-Google-Smtp-Source: AGHT+IHdC9jwYi3QATRzrj9Pl8ryHRxwB0OmfHK1e4yfhSg6EeZnwEuI1r9igsvxg9sOq0LxCEBU6A==
X-Received: by 2002:a4a:9089:0:b0:570:c136:fa3c with SMTP id j9-20020a4a9089000000b00570c136fa3cmr8192049oog.2.1694444239905;
        Mon, 11 Sep 2023 07:57:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:4951:0:b0:573:2cbd:3295 with SMTP id z78-20020a4a4951000000b005732cbd3295ls830600ooa.1.-pod-prod-03-us;
 Mon, 11 Sep 2023 07:57:19 -0700 (PDT)
X-Received: by 2002:a05:6808:10cc:b0:3a7:36f9:51aa with SMTP id s12-20020a05680810cc00b003a736f951aamr12367363ois.17.1694444239154;
        Mon, 11 Sep 2023 07:57:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694444239; cv=none;
        d=google.com; s=arc-20160816;
        b=EXsqWK9Ap9Lmg587vkmnRhhM+5aokmqzPy+rsrKkmf77UvimwyFThPiuEw/qddg+nm
         jVTTuxO/z+6wri450AaC6lj+nN6U16AY0VQPOsjtFQ6dRLr+/FeT3THm8BpBTASVNCfX
         tpDn2kPagZcnGpGy0BdbAFrxxBdcIUqxxalntaFsv1oT6uiW0p5xksHeisjZM14sIVUB
         tU5tPbY3bmy7gmi6+bFu/Yb9TS6JM2asoD9BLGodqcoqfMCiNWqVmpF1If5YWR7BcqPt
         xJkg+k8Bg3da1jDdTKSwE00hSEBWfUJ0Sc+vwX87T1bPMDI1/JTo27O6utLo5LbLGtbC
         ovEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=35Wzlz8R5vpRX3Qc5T9eOyq5a0RR6jvjL1w5jIKVlmg=;
        fh=x/Eq99+ICi7e9grjZNFq4mA7WJOkDm5ZB5wM283JjUk=;
        b=w3R+HT7/KHkMNLIoEPKW20c95+xNFAwJ1DZFAH5T8O8o5NQfXU7vq/1Xq8XPz9twQi
         HhQFxcp4z1b0e/OT6XMVZ3xMJZuozJxxJO+tIhNAfdhA0ntADc/iRPl8UQ0egO15msZU
         2ZYA8B33zgayCGI4EySVigumfSGB7nxDLZDo0ZTzNjgEsuA2NNKhuOPXIOz0yanRCnZu
         JE339GYO5e9a52fv937ptyv5Q53iOWFVQnv8SwRWCTS3njw0T8KXX2RqC24oDmMSzFWW
         WQEdwDOer9s4w2Wpiz8G2ZMu965CxsxXgp97Kl55PWQ3QDt9TdBE2wMcRdJuwASqdA8v
         enng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="fAi/BI4X";
       spf=pass (google.com: domain of 3zir_zaykcu8x2zuv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3zir_ZAYKCU8x2zuv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id gt7-20020a0568082e8700b003ab8803fd7dsi531914oib.2.2023.09.11.07.57.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Sep 2023 07:57:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zir_zaykcu8x2zuv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-59593051dd8so46733917b3.0
        for <kasan-dev@googlegroups.com>; Mon, 11 Sep 2023 07:57:19 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:62e7:6658:cb4:b858])
 (user=glider job=sendgmr) by 2002:a81:7647:0:b0:57a:e0b:f66 with SMTP id
 j7-20020a817647000000b0057a0e0b0f66mr249145ywk.7.1694444238744; Mon, 11 Sep
 2023 07:57:18 -0700 (PDT)
Date: Mon, 11 Sep 2023 16:57:01 +0200
In-Reply-To: <20230911145702.2663753-1-glider@google.com>
Mime-Version: 1.0
References: <20230911145702.2663753-1-glider@google.com>
X-Mailer: git-send-email 2.42.0.283.g2d96d420d3-goog
Message-ID: <20230911145702.2663753-3-glider@google.com>
Subject: [PATCH v2 3/4] kmsan: merge test_memcpy_aligned_to_unaligned{,2}() together
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com, dvyukov@google.com, elver@google.com, 
	akpm@linux-foundation.org, linux-mm@kvack.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b="fAi/BI4X";       spf=pass
 (google.com: domain of 3zir_zaykcu8x2zuv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3zir_ZAYKCU8x2zuv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--glider.bounces.google.com;
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

Introduce report_reset() that allows checking for more than one KMSAN
report per testcase.
Fold test_memcpy_aligned_to_unaligned2() into
test_memcpy_aligned_to_unaligned(), so that they share the setup phase
and check the behavior of a single memcpy() call.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kmsan/kmsan_test.c | 37 +++++++++++++------------------------
 1 file changed, 13 insertions(+), 24 deletions(-)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index a8d4ca4a1066d..6eb1e1a4d08f9 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -67,6 +67,17 @@ static bool report_available(void)
 	return READ_ONCE(observed.available);
 }
 
+/* Reset observed.available, so that the test can trigger another report. */
+static void report_reset(void)
+{
+	unsigned long flags;
+
+	spin_lock_irqsave(&observed.lock, flags);
+	WRITE_ONCE(observed.available, false);
+	observed.ignore = false;
+	spin_unlock_irqrestore(&observed.lock, flags);
+}
+
 /* Information we expect in a report. */
 struct expect_report {
 	const char *error_type; /* Error type. */
@@ -454,7 +465,7 @@ static void test_memcpy_aligned_to_aligned(struct kunit *test)
  *
  * Copying aligned 4-byte value to an unaligned one leads to touching two
  * aligned 4-byte values. This test case checks that KMSAN correctly reports an
- * error on the first of the two values.
+ * error on the mentioned two values.
  */
 static void test_memcpy_aligned_to_unaligned(struct kunit *test)
 {
@@ -470,28 +481,7 @@ static void test_memcpy_aligned_to_unaligned(struct kunit *test)
 			sizeof(uninit_src));
 	kmsan_check_memory((void *)dst, 4);
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
-}
-
-/*
- * Test case: ensure that memcpy() correctly copies uninitialized values between
- * aligned `src` and unaligned `dst`.
- *
- * Copying aligned 4-byte value to an unaligned one leads to touching two
- * aligned 4-byte values. This test case checks that KMSAN correctly reports an
- * error on the second of the two values.
- */
-static void test_memcpy_aligned_to_unaligned2(struct kunit *test)
-{
-	EXPECTATION_UNINIT_VALUE_FN(expect,
-				    "test_memcpy_aligned_to_unaligned2");
-	volatile int uninit_src;
-	volatile char dst[8] = { 0 };
-
-	kunit_info(
-		test,
-		"memcpy()ing aligned uninit src to unaligned dst - part 2 (UMR report)\n");
-	memcpy_noinline((void *)&dst[1], (void *)&uninit_src,
-			sizeof(uninit_src));
+	report_reset();
 	kmsan_check_memory((void *)&dst[4], sizeof(uninit_src));
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
@@ -589,7 +579,6 @@ static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_init_memcpy),
 	KUNIT_CASE(test_memcpy_aligned_to_aligned),
 	KUNIT_CASE(test_memcpy_aligned_to_unaligned),
-	KUNIT_CASE(test_memcpy_aligned_to_unaligned2),
 	KUNIT_CASE(test_memset16),
 	KUNIT_CASE(test_memset32),
 	KUNIT_CASE(test_memset64),
-- 
2.42.0.283.g2d96d420d3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230911145702.2663753-3-glider%40google.com.
