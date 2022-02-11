Return-Path: <kasan-dev+bncBDHK3V5WYIERBCNETKIAMGQEQKHHVZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CF0B4B2AAA
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 17:42:50 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id q12-20020ac25a0c000000b004389613e0f7sf2371475lfn.9
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 08:42:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644597770; cv=pass;
        d=google.com; s=arc-20160816;
        b=OpD309cyQ/VA7ASJfO+dtsnImGGdvbH+wC3MRydTWY4BufrHeuzzoPRyEw5XfJnevG
         JBj4xPw2Cxb7mxIr4qdWP8Qkide8/AryCI/jxOrU2mZuKEp01W+9PmAGjIJhdSExZ3aH
         rE/AhRW7kDEFsObR9jj5XlI1QEXSEiuki12hgYaLe5khh6BMFf4ZHyJUEOGtew6VVlv9
         IV1fgQw4yQApTBiCPP3TMLVyiecZ4TfnytK19ZTTvly+cYTHlWXh5dU8SujCU66twMke
         crWXJZV97PiuONAqdGiXVRN25DrKO7NBzDGl5OiRkntNOtqiVMxv47UzfNPtmTqwjvXH
         hbcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=2wSUm+V9rqH9MGFfQdf+idrj8ibOxvRhxDe9hEjsDq8=;
        b=eQQ/bzdzClATad/3Sz6VaWA0Qw+Yv7EOkCq9Q0jaJ+ak9oeoqvCkCKOE//vhqaI5UB
         tU7/lEkCgH+i1BJELlF5mh597sZnV8lYkHu2xIBGubpr2FqT90/JdQk0/kJszRJJuE86
         omNTaetfflunCa6vDDNN+3KoVb3ky/9T0SoIESLgy8S2XtlSFtOjRoT1BZjyXDFtQQPc
         9326A6g0PLKJmH0Bv9p91m6LmE9QdMIz6c7IWxkZ44EZG8KKyW0tZlgarC85scNs6TAr
         hur+0veJP84avw32u0LSmmhVviy6alDUqmamOjjIGNHKjclCrR7JiWPbV6EJvTeS93uT
         2W9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=IuNoXsuK;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2wSUm+V9rqH9MGFfQdf+idrj8ibOxvRhxDe9hEjsDq8=;
        b=Q3HbL8IC9IpVB87mwfFEBXgzMcdb+u6KE2A/6NyIxqKTN/owNINAeYL36rr2Lair7s
         onSTcAEAOyKLBgLKlvwx4qssSdMFoTmH2zYNPo1O8uYlK9aH8sEzJRtX7OnhoJocGKve
         mgmzCVXI1sh86XPHsq/uxwTUw+QbB75tBMYGvRzXgTdDPfROKV94aH1nMVZ3Qw6gDf9q
         17JI0C21eTqWOROr8JqHgxZligR2W+fLtiUMJxukWO1uG7jrLQ8jBdU2CZZ9l3Y/ehRg
         TSB5xNasTN9oWv1rMfqs+9Ehsxl7hn0Lu4pAb4iuoytm12igGa/3NnlxtdF3rsVDhOpC
         f9qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2wSUm+V9rqH9MGFfQdf+idrj8ibOxvRhxDe9hEjsDq8=;
        b=CNBdnDeo48YKb5UMh+y/OhpczBAifbnwr86COOQuuS7JqcIo4QM+r9JRIix7pWECxz
         jo9gdr49yWIwSHpRGDsft7ckk3nYsx7EB41gliDzgxicwyY8T5kPUGlCmqNvQx6Hsa9M
         oldpEpzm+DUyIR8rj3xbliDolNKGxUinkSYN9qWSmEmlh+NTc3qQkHLBuAXy7gZFfQ1w
         hEPXLt1x9g7OS9DX1/EOfW6taKA9CDEr5wHEIgWMNhkhU8F8tSVQwvbzzNydHhLpKTu2
         OIJ5XuD8cxqPb/bDqxMmbZHvVM0kH9QW+9Jg19Mhvze04DuZr+pqK/tNcbfUxsxYsFL+
         tJPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531PB8UN0za35f9qm2qGBH0VKpjWVt1V7VReowQUIqYV4SiXQHwG
	cE/8oVWiU4y1yR/y+nWUpZs=
X-Google-Smtp-Source: ABdhPJx5gzMo6f71XktSnKhyEG/6S8RkNY1lxfy0G3EvkigvtGQNz8Ift/30BLrb4EiVhyOdvBzFpg==
X-Received: by 2002:a2e:8447:: with SMTP id u7mr1496516ljh.516.1644597769914;
        Fri, 11 Feb 2022 08:42:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2128:: with SMTP id a40ls1615772ljq.9.gmail; Fri,
 11 Feb 2022 08:42:49 -0800 (PST)
X-Received: by 2002:a2e:a786:: with SMTP id c6mr1462102ljf.225.1644597768924;
        Fri, 11 Feb 2022 08:42:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644597768; cv=none;
        d=google.com; s=arc-20160816;
        b=Vr+evhMQs8YI2PGD9beXsSCq0MKnC9OfMZR8epNhVTKAGDgYwVHo/D21GsTOJjjVVm
         4Aytv6Hmu1Vqu11NVqqETDTQnXRcYLkcbd1yGVzo4RvK0G70kuT0u7XEhKKBJaF0wH2s
         Sj3OPQF4VfLYlozpz1Mux3gutOzS6IKxRyIDKXaguPn/qu36c2Pmeap+UdNqzB2ighhk
         hD0QwWTz5kMWFl72UG9YEo9MxoUx8X/Jz+sWPq6l1Y+pA6TmPlHya0mizG34RLSuHN3l
         fNIWUaJMAl+J5IP2gbo9YAxGKPxwFZ4/oDbuR8JFH+YFezjatZo7K7pypVFfq1Y0VgZv
         sI8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=vsf2QgtdatJ2wExDY4gvcboSixkFghVOFaraVlgt+kM=;
        b=SKLmXU0iKDWmK0pbq3dhwxy13CZyl4hOZY0UMsr9OJSAN4u6Z1QV0av/TcFMqpJySs
         gUYCnjkBHSjpO8cUyiXzWMdL+B9wsXW0n/wXaW11yLGEzjochVgREZiA5JJWulOUJEfz
         64PzYmy5BswT/kk0EWSrJm5UIFadgAO79nnsayBWng+xClqg6MYAdEp50bxCJPzgImBz
         A08hh7s5MBdNJBTETkSXKfL2ObwPzYpXxnMGeXhrmv3UltPSc+K1MxFxyR4svBIN+ewj
         sDO9710WDw9lWN7zA94oqF60iyai6C045zL+HCtK7IhHiUXa6PEZAdHr4Vf6OQbxWii/
         3etg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=IuNoXsuK;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id z2si910827ljh.2.2022.02.11.08.42.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Feb 2022 08:42:48 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id b13so17513362edn.0
        for <kasan-dev@googlegroups.com>; Fri, 11 Feb 2022 08:42:48 -0800 (PST)
X-Received: by 2002:a05:6402:3608:: with SMTP id el8mr2759937edb.193.1644597768422;
        Fri, 11 Feb 2022 08:42:48 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id i24sm4981233edt.86.2022.02.11.08.42.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Feb 2022 08:42:48 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v6 1/6] kunit: Introduce _NULL and _NOT_NULL macros
Date: Fri, 11 Feb 2022 17:42:41 +0100
Message-Id: <20220211164246.410079-1-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.1.265.g69c8d7142f-goog
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=IuNoXsuK;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::532
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

Today, when we want to check if a pointer is NULL and not ERR we have
two options:

KUNIT_EXPECT_TRUE(test, ptr == NULL);

or

KUNIT_EXPECT_PTR_NE(test, ptr, (struct mystruct *)NULL);

Create a new set of macros that take care of NULL checks.

Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
Reviewed-by: Daniel Latypov <dlatypov@google.com>
Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 include/kunit/test.h | 84 ++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 84 insertions(+)

diff --git a/include/kunit/test.h b/include/kunit/test.h
index 00b9ff7783ab..e6c18b609b47 100644
--- a/include/kunit/test.h
+++ b/include/kunit/test.h
@@ -1218,6 +1218,48 @@ do {									       \
 				   fmt,					       \
 				   ##__VA_ARGS__)
 
+/**
+ * KUNIT_EXPECT_NULL() - Expects that @ptr is null.
+ * @test: The test context object.
+ * @ptr: an arbitrary pointer.
+ *
+ * Sets an expectation that the value that @ptr evaluates to is null. This is
+ * semantically equivalent to KUNIT_EXPECT_PTR_EQ(@test, ptr, NULL).
+ * See KUNIT_EXPECT_TRUE() for more information.
+ */
+#define KUNIT_EXPECT_NULL(test, ptr)				               \
+	KUNIT_EXPECT_NULL_MSG(test,					       \
+			      ptr,					       \
+			      NULL)
+
+#define KUNIT_EXPECT_NULL_MSG(test, ptr, fmt, ...)	                       \
+	KUNIT_BINARY_PTR_ASSERTION(test,				       \
+				   KUNIT_EXPECTATION,			       \
+				   ptr, ==, NULL,			       \
+				   fmt,					       \
+				   ##__VA_ARGS__)
+
+/**
+ * KUNIT_EXPECT_NOT_NULL() - Expects that @ptr is not null.
+ * @test: The test context object.
+ * @ptr: an arbitrary pointer.
+ *
+ * Sets an expectation that the value that @ptr evaluates to is not null. This
+ * is semantically equivalent to KUNIT_EXPECT_PTR_NE(@test, ptr, NULL).
+ * See KUNIT_EXPECT_TRUE() for more information.
+ */
+#define KUNIT_EXPECT_NOT_NULL(test, ptr)			               \
+	KUNIT_EXPECT_NOT_NULL_MSG(test,					       \
+				  ptr,					       \
+				  NULL)
+
+#define KUNIT_EXPECT_NOT_NULL_MSG(test, ptr, fmt, ...)	                       \
+	KUNIT_BINARY_PTR_ASSERTION(test,				       \
+				   KUNIT_EXPECTATION,			       \
+				   ptr, !=, NULL,			       \
+				   fmt,					       \
+				   ##__VA_ARGS__)
+
 /**
  * KUNIT_EXPECT_NOT_ERR_OR_NULL() - Expects that @ptr is not null and not err.
  * @test: The test context object.
@@ -1485,6 +1527,48 @@ do {									       \
 				   fmt,					       \
 				   ##__VA_ARGS__)
 
+/**
+ * KUNIT_ASSERT_NULL() - Asserts that pointers @ptr is null.
+ * @test: The test context object.
+ * @ptr: an arbitrary pointer.
+ *
+ * Sets an assertion that the values that @ptr evaluates to is null. This is
+ * the same as KUNIT_EXPECT_NULL(), except it causes an assertion
+ * failure (see KUNIT_ASSERT_TRUE()) when the assertion is not met.
+ */
+#define KUNIT_ASSERT_NULL(test, ptr) \
+	KUNIT_ASSERT_NULL_MSG(test,					       \
+			      ptr,					       \
+			      NULL)
+
+#define KUNIT_ASSERT_NULL_MSG(test, ptr, fmt, ...) \
+	KUNIT_BINARY_PTR_ASSERTION(test,				       \
+				   KUNIT_ASSERTION,			       \
+				   ptr, ==, NULL,			       \
+				   fmt,					       \
+				   ##__VA_ARGS__)
+
+/**
+ * KUNIT_ASSERT_NOT_NULL() - Asserts that pointers @ptr is not null.
+ * @test: The test context object.
+ * @ptr: an arbitrary pointer.
+ *
+ * Sets an assertion that the values that @ptr evaluates to is not null. This
+ * is the same as KUNIT_EXPECT_NOT_NULL(), except it causes an assertion
+ * failure (see KUNIT_ASSERT_TRUE()) when the assertion is not met.
+ */
+#define KUNIT_ASSERT_NOT_NULL(test, ptr) \
+	KUNIT_ASSERT_NOT_NULL_MSG(test,					       \
+				  ptr,					       \
+				  NULL)
+
+#define KUNIT_ASSERT_NOT_NULL_MSG(test, ptr, fmt, ...) \
+	KUNIT_BINARY_PTR_ASSERTION(test,				       \
+				   KUNIT_ASSERTION,			       \
+				   ptr, !=, NULL,			       \
+				   fmt,					       \
+				   ##__VA_ARGS__)
+
 /**
  * KUNIT_ASSERT_NOT_ERR_OR_NULL() - Assertion that @ptr is not null and not err.
  * @test: The test context object.
-- 
2.35.1.265.g69c8d7142f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220211164246.410079-1-ribalda%40chromium.org.
