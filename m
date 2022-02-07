Return-Path: <kasan-dev+bncBDHK3V5WYIERBJMBQ2IAMGQEXJ7SJXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EC324ACA5D
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 21:27:18 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id cr7-20020a056402222700b0040f59dae606sf3277256edb.11
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 12:27:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644265638; cv=pass;
        d=google.com; s=arc-20160816;
        b=W3lOJxxih4BBxn4zo46+P+85WV0NhN3RcJ8TE/0VLUFbR84W0V76aI3bJ5ZAuqnS3P
         mteq/LjyYe3dwVxiCTUWtRWyv3NlBJwMOGsCRANC9brl8VOqaTKDVI03gUGnBQjCShzU
         LO2DD4EZwi8wArchEj7SKClr7LFrxnoEcMWQQ/w/Z1TobFNcchlmIveVgTb+mfPZJfVH
         VPKiEi/z6i1ZfxOW9Pm/uDn/nGkm5AJh1c2Mi6schd0lfTzoZ4UB4vH/ATbfo0oHkxiR
         TAffGS2oVeGxty29knAT+zv2siZYQxz+fs5hIE0IrSSHXSUehlFvLbNThEgUEwg02fHU
         hYyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=E1bVSmFXNoxSRqCmJz+BvwDfvnEMZvhxUUBUdSNHuNI=;
        b=OufQBRnz5K2xMIPjRoLwfB3hIIyHRlqTc+A60rkWhHmI8deZARJ9t5JLjJKGD+p/7a
         m2uAs8Y6LHYHS2z8R7+Cs+fCRlC/dr9MlQMP7okL2RXlE7Uxq6Ua8VW1fDzpXr8/Xcw6
         zJnrtre8PzSwzPDvFGMUHtP1k6L/1qv5o5EQQmbWThojiEpWAO64wvnO5F7KZNBYhi4/
         UskUuc/UoNWC7gCOPfInh3C8rrDJwb85fMwLffm073pH2xjyNMItxIkjlLWA4NA30YXN
         eFYcB0larFcJ43vWVQdInFInjSoT6pxp90b0Lo89IkmN1ia9Rxk2NNZQGIj6wW+Hrhm3
         skpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=BgHPAL5t;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E1bVSmFXNoxSRqCmJz+BvwDfvnEMZvhxUUBUdSNHuNI=;
        b=XdUuCB1ZMbP1Fi1dW+qda6/KKNOLH/as3wo/qLCYXHltL1e0AS+0gRNf489G+KPHKz
         0MJvPSXmV4DcFYPnzR5h26ldFNfuXCBoB0Ly1O5It4QPDC3ZXw8dEFmSs74KXOmBUy9J
         5wap0MGh3lyzTgfM12wwm3NNukADsJ/bIiKC6l+jI0JzF+MSdCB1Wltrk9+UvIrF0+AY
         ZWCVWxCUgHExTN0Xgx/t0u6K3Fl72h5xZFmY6DShAc9vVggO2/M9vKJkLkh6t2cscBLi
         l7gOsOt3N+31mvDbCGHTpEQznu3tdRxvPZyF/wT9PXpp3NWO+7L7MbR0n6QzeBjV+vu9
         jP3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=E1bVSmFXNoxSRqCmJz+BvwDfvnEMZvhxUUBUdSNHuNI=;
        b=pyuQFoPDKcug19SujG47tx3lomERUpmS8JXANSzq8crYiwxJCRm314vxVmsVGyq0iD
         6yXthw/8Hak8zyedFCAnmbMPq1zaZJoKIy/zup1ViBClVV3mVf+toxKFoIfkAkoWtPGH
         GBMFMhihHX8lMhNMJ2PaWPqq/uZA3zje4CxUW+Goqg6qXihWhqb9iwPze+TpRiGknHEL
         z91iNJGPDPW4Kcq47/D2rn6u9+niLqBm1dZxEhsDsjtZQ7wEllRKJfr7RiXFfJNeO/cB
         KSRZ1zFjQp9uGRV6WHGHC1E3QKu1KWHLEnu28kMidu5dF1+l89DK9hQ9GEgm38yMc85h
         DIQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Y8tEPbsrj+S6PfyRl9jBZyrF8tLqOXKChQkl46oUzsyTbFJIy
	iuZqB1vW1A5K5uap9sN/MYQ=
X-Google-Smtp-Source: ABdhPJyN3YQjgh7lZGpHK9xo77dGXrKuetvQz1diFlbyU35uOJMw1sKT/x3r7SByjPuFK3yJiI/wHA==
X-Received: by 2002:a17:907:6d9b:: with SMTP id sb27mr357455ejc.85.1644265637732;
        Mon, 07 Feb 2022 12:27:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:3e1d:: with SMTP id hp29ls1672076ejc.11.gmail; Mon,
 07 Feb 2022 12:27:16 -0800 (PST)
X-Received: by 2002:a17:907:6298:: with SMTP id nd24mr1096342ejc.76.1644265636743;
        Mon, 07 Feb 2022 12:27:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644265636; cv=none;
        d=google.com; s=arc-20160816;
        b=PO0ORdNMBxyyZSLjWlZXDZGGUrfayJw7MPZu8d10y7U9CnUXwg+Kax6w1G5Wt67r81
         qbk8M9xY1Q1J2mYMaFaDaPXuadvBKHZkbobVik3rlApm6H4LnFNnGmPCUgrIhHoeR2e1
         NwUwMYY1+Az6kUGtn3NrvGYpZBcvb3Ut0JYjloRyei50Se7aWJtrLRZE0YUMijWJIo7g
         AWyKuDjv6XCJrMSk410Wu5z616l01A3SkX86wM5F0fsym1Uya5IcKnH+NP4O+0Yy9EvC
         HWrBpSRD/nXgbHPuyqDshHUMauq4YVnmKpRJkKDgr+/WRtJF5fsVG42LdSCDNqgE4y2N
         PCMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Gw9IRN9hr1+gfksXu4AOlVdfj3U7WJgk2YL6BR1ySok=;
        b=XF5cE+EgUdoNHwIxxfMandQzvNA6tNZNajXv8F/wRMEM97baO60OR7T3b3v8gxoS2p
         MXZOaZJWFxC3L96P4Os+OByCp5IODAzgoi69UUBrh4AptN/7GrHM/45Knv2qut5/mZ2r
         q8XekfA1aGGLxIfi6eo/yWAVl9CMwIwgVY1/A7HJws6p8gyvIHniWhYjZOEM0DT2TmiF
         YniEZx+qOefs+h08V9HU7nhj1TEZV851u/shPyDnrEKQ6e0eovzITq9i1IJMsA5AZQ2b
         DEP2156yn8sjFtkUQhoIsAtQTFMLkMLo9fPs3nKnwLX7QGtVLWK1gCTQ3rUSBhNbzaLs
         v5/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=BgHPAL5t;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x62d.google.com (mail-ej1-x62d.google.com. [2a00:1450:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id y8si602604edc.0.2022.02.07.12.27.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 12:27:16 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62d as permitted sender) client-ip=2a00:1450:4864:20::62d;
Received: by mail-ej1-x62d.google.com with SMTP id s13so45511221ejy.3
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 12:27:16 -0800 (PST)
X-Received: by 2002:a17:906:8696:: with SMTP id g22mr1078583ejx.436.1644265636538;
        Mon, 07 Feb 2022 12:27:16 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id t8sm787893eji.94.2022.02.07.12.27.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Feb 2022 12:27:16 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v2 1/6] kunit: Introduce _NULL and _NOT_NULL macros
Date: Mon,  7 Feb 2022 21:27:09 +0100
Message-Id: <20220207202714.1890024-1-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=BgHPAL5t;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62d
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

EXPECT_TRUE(test, ptr == NULL);

or

EXPECT_PTR_NE(test, ptr, (struct mystruct *)NULL);

Create a new set of macros that take care of NULL checks.

Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 include/kunit/test.h | 88 ++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 88 insertions(+)

diff --git a/include/kunit/test.h b/include/kunit/test.h
index 00b9ff7783ab..5970d3a0e4af 100644
--- a/include/kunit/test.h
+++ b/include/kunit/test.h
@@ -1218,6 +1218,50 @@ do {									       \
 				   fmt,					       \
 				   ##__VA_ARGS__)
 
+/**
+ * KUNIT_EXPECT_NULL() - Expects that @ptr is null.
+ * @test: The test context object.
+ * @ptr: an arbitrary pointer.
+ *
+ * Sets an expectation that the value that @ptr evaluates to is null. This is
+ * semantically equivalent to KUNIT_EXPECT_PTR_EQ(@test, NULL, ptr).
+ * See KUNIT_EXPECT_TRUE() for more information.
+ */
+#define KUNIT_EXPECT_NULL(test, ptr)				               \
+	KUNIT_EXPECT_PTR_EQ_MSG(test,					       \
+				(typeof(ptr))NULL,			       \
+				ptr,					       \
+				NULL)
+
+#define KUNIT_EXPECT_NULL_MSG(test, ptr, fmt, ...)	                       \
+	KUNIT_BINARY_PTR_ASSERTION(test,				       \
+				   KUNIT_EXPECTATION,			       \
+				   (typeof(ptr))NULL, ==, ptr,		       \
+				   fmt,					       \
+				   ##__VA_ARGS__)
+
+/**
+ * KUNIT_EXPECT_NOT_NULL() - Expects that @ptr is not null.
+ * @test: The test context object.
+ * @ptr: an arbitrary pointer.
+ *
+ * Sets an expectation that the value that @ptr evaluates to is not null. This
+ * is semantically equivalent to KUNIT_EXPECT_PTR_NE(@test, NULL, ptr).
+ * See KUNIT_EXPECT_TRUE() for more information.
+ */
+#define KUNIT_EXPECT_NOT_NULL(test, ptr)			               \
+	KUNIT_EXPECT_PTR_NE_MSG(test,					       \
+				(typeof(ptr))NULL,			       \
+				ptr,					       \
+				NULL)
+
+#define KUNIT_EXPECT_NOT_NULL_MSG(test, ptr, fmt, ...)	                       \
+	KUNIT_BINARY_PTR_ASSERTION(test,				       \
+				   KUNIT_EXPECTATION,			       \
+				   (typeof(ptr))NULL, !=, ptr,		       \
+				   fmt,					       \
+				   ##__VA_ARGS__)
+
 /**
  * KUNIT_EXPECT_NOT_ERR_OR_NULL() - Expects that @ptr is not null and not err.
  * @test: The test context object.
@@ -1485,6 +1529,50 @@ do {									       \
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
+	KUNIT_ASSERT_PTR_EQ_MSG(test,					       \
+				(typeof(ptr))NULL,			       \
+				ptr,					       \
+				NULL)
+
+#define KUNIT_ASSERT_NULL_MSG(test, ptr, fmt, ...) \
+	KUNIT_BINARY_PTR_ASSERTION(test,				       \
+				   KUNIT_ASSERTION,			       \
+				   (typeof(ptr))NULL, ==, ptr,		       \
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
+	KUNIT_ASSERT_PTR_NE_MSG(test,					       \
+				(typeof(ptr))NULL,			       \
+				ptr,					       \
+				NULL)
+
+#define KUNIT_ASSERT_NOT_NULL_MSG(test, ptr, fmt, ...) \
+	KUNIT_BINARY_PTR_ASSERTION(test,				       \
+				   KUNIT_ASSERTION,			       \
+				   (typeof(ptr))NULL, !=, ptr,		       \
+				   fmt,					       \
+				   ##__VA_ARGS__)
+
 /**
  * KUNIT_ASSERT_NOT_ERR_OR_NULL() - Assertion that @ptr is not null and not err.
  * @test: The test context object.
-- 
2.35.0.263.gb82422642f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220207202714.1890024-1-ribalda%40chromium.org.
