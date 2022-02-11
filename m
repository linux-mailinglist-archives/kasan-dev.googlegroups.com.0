Return-Path: <kasan-dev+bncBDHK3V5WYIERBVO6TCIAMGQEZRWYQPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id C257A4B223E
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 10:41:41 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id l20-20020a05600c1d1400b0035153bf34c3sf5656408wms.2
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 01:41:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644572501; cv=pass;
        d=google.com; s=arc-20160816;
        b=jVQo2C8RZBMxGNaU0Lo3v0I9MNDdkaU1mMw9vCUtQzWOJUD7xMIx9NEyNKE5ESb6Z2
         lEJB42rer0TekFGBNa6/qdyJYety2ZlfocdUZ0iT7cufCWlszwWKybOVefWaEAmFe9Ev
         gS46RgynVjYlOZ2yCTvSQdwuf9N+X3AyI5W8VbvUQ4OLJku+BHZw/o1vfAJi/im/7QpG
         UJSIEsGnKhVd4pgNEWJDuaJ9qNa9AQ4S9nc4tUINMg6u4+N0HhPH4O4KsBGgsEeHv08g
         0kAz9apy1hFYHx0XL5HIZBVj+wwNMj/ZRnVytw0Dd4LPMveBAdIyr6rbTEq2FBpmiuOI
         eYMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=JPXHJ+a/cpxyBB8EzeBnNDFPbDIoFhnqn8wFinNAhjA=;
        b=PrqBA4HUmXlCXGQfWkR9HxC6PST5gXzrkQNdsS6WusbBYxCCzGZ3QGJUAKEkBQu7Ze
         nt9EBcOUOfUpOzDIkEJDtfWYYsRkJYFqY7CI2x2qV1gDLpDrLFZmBQSlRzQykJsw6ilb
         haGeb3eP4wN7VLoCEjLdcgNgoluQE0LmLR5yZZEXfcB4GG6nYdO1Gidlg6X6vTE2C7Lc
         fOfeXbrHRPSOemczWJ68cCwrFIkCuF+LR4Kr6QWLT02c7wWgA4EFG1Nw7z7ZRoWqed6R
         iNxATCM0hIRk6T+UY7lLimGSG8wwECEu7Ettg1sZaIUmL4zwseJ1fVwxqgwrFyxTnBUM
         gX2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=aNwI2IxJ;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JPXHJ+a/cpxyBB8EzeBnNDFPbDIoFhnqn8wFinNAhjA=;
        b=GhFdns2Iw5Jyl6Dh0OcHZT/iSgA4RSeeprQe7IY1cZhmJxSQNvdjxD67dn7JHcBQUa
         H9JHR8vt+xXbTQb6DbyaaSqjP0JyvbmXII3mJMG+KFlWMNpmjFpKqzfhiXRyePzDerN0
         J8+Q4ucI4aXBNaZiRnt7uCfV4UA5tXeYRD9M8UtSQlLWXkdHaaggmh9Axrm4rmYbdaVs
         ch6bY6zeMkQp79syJT2PbiQbU6Wso3sVe2ECMkWixNaHQu8PVVu/d568tgEyAezJ9MkW
         0c1XgOMW+ZDF+DOjIB9xLTIjQHZHxi57xI/gwBe1ARCuiL64YTYocRmEWQJFVJ2raSuv
         l4ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JPXHJ+a/cpxyBB8EzeBnNDFPbDIoFhnqn8wFinNAhjA=;
        b=neHsAU7SRWXWdXPMBf5dN1iNggcK+JYJpsrGWppScFR0NYTH7+3haTC3ojd0GL/TUg
         FfVN6kn54uG9ktm5iePbwuTID4mqzINGpab/9g3i0m8NTPIyuSaNRGPWP4Ftc/fjkx8w
         cCOok+S2Ibhm7kdFBwmH2lk0HHvzsrpNX0uFM1kbVxx8pXQGEVbTau7Yt1G9FtRHa2wb
         wA92tjmGps6H1gr8IuF4yrla11BM+jpCy8qXYaFx3oKg7FC21fMVBOALNoi0DHpFKo2s
         lazXx1hv9Rulo8bOkfXSWJEQo85PwAOwbUWcaLtQfQIwcnlAxp0J+lbUQ3RxCGANj7aG
         +HDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533amKfkzLorEoJbg07pQPnZOHFJF+nacfYLMGVffPxxVQqGSrnf
	A2pE2tlRbCcduGNcaH6yfko=
X-Google-Smtp-Source: ABdhPJxqQgw8SPwZRsvwhh/YK0UpspVHu1oN1pKytfSEf4Zn1YOncDfxLJ9Oos6y+5i9dn6XfEK+dQ==
X-Received: by 2002:a5d:5692:: with SMTP id f18mr683674wrv.285.1644572501361;
        Fri, 11 Feb 2022 01:41:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2787:: with SMTP id n129ls2135371wmn.2.gmail; Fri, 11
 Feb 2022 01:41:40 -0800 (PST)
X-Received: by 2002:a05:600c:3baa:: with SMTP id n42mr1377849wms.128.1644572500489;
        Fri, 11 Feb 2022 01:41:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644572500; cv=none;
        d=google.com; s=arc-20160816;
        b=dw66DtL3B++IeoS4CSG1GsZ95yzgRWyn84BfTLSWxyR8YaLsTXdRyNxao88a4XqADx
         MU1vosd8Fa4I/o7k3SV4z61HpR1X7UF3NrOqGNLGcxykCWTu0oBGyokFGmFO7Fr9x4uv
         XWgbj2IX21dfrtZs9SV7b/9Gr6CJSfq0Igz5gomqxn5UIgPwJiAwc+f5aPtipMabaKF4
         ZiGqxxJ2vBj+KB6Jd/ZQR0tSHqW9L/WzAthau4e7Gp12x1+3ZBXZU/XbM+yDYItuI+Tm
         oOk5jjtWqVqJAj+rfJrHS/pLBVaeReLM7n8JMcsHhnhn6Xsc+KinieiUowwd2dUFtp12
         ZmWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=vsf2QgtdatJ2wExDY4gvcboSixkFghVOFaraVlgt+kM=;
        b=UAKQdrSpBR5eTCWIka2XzPS6MubUkd1tzvH3Zo/QBGLk9CTI/0B/N2dbLlx6mDj8mM
         JHVbrDpBSUXFBWN9ZfaJ7izMXbjY1W7BPKblgWr/zIYiuG7e8Tz0RLY2JHOWCfEhm7Q4
         3buyIz69HgCeexhD7d3AbTnXa9GB3jq9xTGbnSm6tcI6LYQ8IbjaD0y7DI14+gKSafJo
         rpYw7IXd+Wb3zi9/6vHw8ZBNmROjXLFxZWE+ytBi0c6yfesxo6JaS9dY6mtQja9Rk0tB
         xMQxLdXKmCUv2a1Of+mWrRbMUKCA+ik36AS4uLeb+gvQ8GGZOgEqwU4mWEiOZdqd21Ay
         45oQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=aNwI2IxJ;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x62f.google.com (mail-ej1-x62f.google.com. [2a00:1450:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id v13si44535wro.0.2022.02.11.01.41.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Feb 2022 01:41:40 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62f as permitted sender) client-ip=2a00:1450:4864:20::62f;
Received: by mail-ej1-x62f.google.com with SMTP id a8so21610542ejc.8
        for <kasan-dev@googlegroups.com>; Fri, 11 Feb 2022 01:41:40 -0800 (PST)
X-Received: by 2002:a17:906:7948:: with SMTP id l8mr663890ejo.752.1644572500145;
        Fri, 11 Feb 2022 01:41:40 -0800 (PST)
Received: from alco.corp.google.com ([2620:0:1059:10:83e3:abbd:d188:2cc5])
        by smtp.gmail.com with ESMTPSA id e8sm603196ejl.68.2022.02.11.01.41.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Feb 2022 01:41:39 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v5 1/6] kunit: Introduce _NULL and _NOT_NULL macros
Date: Fri, 11 Feb 2022 10:41:28 +0100
Message-Id: <20220211094133.265066-1-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.1.265.g69c8d7142f-goog
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=aNwI2IxJ;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62f
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220211094133.265066-1-ribalda%40chromium.org.
