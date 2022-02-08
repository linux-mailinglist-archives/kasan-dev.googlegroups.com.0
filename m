Return-Path: <kasan-dev+bncBDHK3V5WYIERB2NPRGIAMGQERVF6UJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BAEE4AD7B8
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 12:45:46 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id n18-20020adfc612000000b001e3310ca453sf1447772wrg.2
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 03:45:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644320745; cv=pass;
        d=google.com; s=arc-20160816;
        b=T/JPJnJEsjc653J/eWkE9VUHDTyTD/rAq7KV1+vBWr6jCl41U6+uSdJsTKCBwK8Ny2
         nGM4otWNADRQ1VkFYe4ue4vxOVPExk8Psiunkf3/PT7MXF/uAdtdUXSSNDz6bOyrTDBL
         +YroMLf+QhytAHhqBxnMeg5pMaJN+J4RNvwbau4MCvWWY1MEi2KrgOjT1daZZhuMta/J
         ZzpgYPKmOD7APr6+juGy8j1p+QMmehm0hwJ/G2Wlg7Y1lZJM6ock9DRfqyas9F6yMMUI
         DEIZlY9+Glg3NgsT4Rf8hF1k0YRmBAzbW39MTKgYqpuoWlAxkTmvdFIkU2zexdTMIV1A
         jgHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=wwePREXie7r0aFBBwaR9wQfACC3CdHMjGSWSrzbl2LY=;
        b=UOM1psxtwjnV6Q3WXzSq/qeWCU5lda0qm4Dq3M5kyhGqApcj0K3OWhsOGCFZMt25Ak
         s8zyq8NdbIGMtLiiO8WO/R9Q6mQ0oBBGLiBwnZWKdSj49SpdCdQa7nWmjO3HTK2oRea5
         cOPjDficUz9HkZxmC8ThPzzLBceo56jfqmEoHo++WFTljjKOnlqVqaeZuWnqNmkPbFhA
         1nROqOr3HLXhzXdT1RbbD/nersKk7L8HA5Bf4L9LpTeI08UDT6Jie5mkW+2pmIpvMNoQ
         hFAfxRFBwDvpOcl6NxgrKBTVD3Gidfr43a+M5oNUj7hGJ0biuxbZh7woYCO1D4RU58Ji
         MHHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Lf2vtVvi;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wwePREXie7r0aFBBwaR9wQfACC3CdHMjGSWSrzbl2LY=;
        b=scdlpoAnjktJoH5PHeVvaC8onM8mjdI3mCRhmt1Pb1Rdpgmqfp34j+ipCOfymLK7NW
         NYwzDXZQ4VhNhDxL9WmYhiws5ImqQDK2IZjagMvkDF3rYEmiK5WqSTaiiqrxpuHtl3TP
         U7LeVuZTLs6Tjn8JsY9DF4UGSLklS0UXNR+Smu9EuZfxu/0epSmhRYqphgQ26OQRD44v
         mTCngxzj6AgesnM4tzAPW/6Is/0Jf/+1mQ5cgUNz5wR3U1JIg6gddVSz742oNKQld1KJ
         rpOkfVqJ8OPdO4u7QxTtbVSzrGVTUbScog3LyELwsZ7la3ObqOfCC7CqRjtT8qf+nsm2
         vfxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wwePREXie7r0aFBBwaR9wQfACC3CdHMjGSWSrzbl2LY=;
        b=U3hzDqTw6NdJmwH15rFG9VNX942cuZyFUmATE+X3Zrk7B76/H/fBO2Z/78+UL/+0ag
         fSNUfMObWZtXl0qJZbsVpwgVI8RgFzquN3Mquxl0mbUPXtwjHpPFkUJLoK5S6vg3lFN5
         nVFt4qyMidDM/jECM7/yOy7+8bZIyV/rBxoqMzOe0pOrUE4O4jvYBWTBkbOzlj3KKr1S
         0hfiK1F3ax6rM/xeivKy16kH1HLf5cW74+vbUxZzvKMoRJYIM7BvAQ7xRCEVFY4TmApe
         d9hKWHwA26Q8FVHaxBOPvnlhdb7rs5S1DDejXw0v3YjSODXjGXkbIZ3vz0J74RuXLFHD
         aWrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530gQjUdSFpqcusxRY6aCbcVuaOgTjwOXLwBo03PWqLAMgJBscNj
	qHpNGXPQmGPANKLsL2qQ6C0=
X-Google-Smtp-Source: ABdhPJzJZZJc0+KzXXzGI59VMPC4c5oOA7MD7BjSu0erGNRx1g49qIQn7UlpU63iv3dIGzAYJ1SBkg==
X-Received: by 2002:a1c:7c0b:: with SMTP id x11mr809743wmc.192.1644320745645;
        Tue, 08 Feb 2022 03:45:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3596:: with SMTP id p22ls1000554wmq.3.gmail; Tue,
 08 Feb 2022 03:45:44 -0800 (PST)
X-Received: by 2002:adf:ea50:: with SMTP id j16mr3258595wrn.213.1644320744802;
        Tue, 08 Feb 2022 03:45:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644320744; cv=none;
        d=google.com; s=arc-20160816;
        b=in3zdv/+2Tc9h2vieDn68j7mOrTBW012kSUut0FP287JkVIQYiKWefXNmPJ0U8KtuD
         EPWkwd9x5D+L4rTLiuBpHomgAwuonsNHdNUvlqlNYW/5BELphDEFovQ8Xju6i8tWy1PA
         kW5m75l/5wG3wRV2d0jBj9tNgJ3xxsatLgQe90lgX2xwLAMaHEvWo1cTNa0pMkm/wzsQ
         kk2xNOXIqKdSFuQk0l2Ysx3mM84aoAStzDKDMVn80jlQsY13udDbD0cLIeAFGJzxHzCc
         6gfs3lwayXI+N37B2Zrvc/LihnPdiErx11LU6QD20t5XsmZfLWuvc7w//po0+Kb4rNZ+
         7jIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Fk7CgUzK9iGLnQH4r+eaSpgT+/fVBEfFahsh5Ie73gs=;
        b=DiFhTxhGi+k0A35jBHxc5Ck+5SR4KCp1Eq7vKT349cSDEbtEMuvJZCEsMUp0tInBe1
         bCy+0MhJcMZ9yuv/La6NHe+HNdCYkamo4rEoj0h3sCX3bwmhxrvPD8xRBn4xUX2Pk2xW
         MRC8SzpAE3W7CYNHIPTEJE1Jd4PI/0A0yUj+KjEmLXlbcK4J5NBr+W8Dhhe45kYPsb8Y
         FSyUvaRAcCsfnn+BbEJPBVN0HOsFUMwMwCQR9gRmCUXp2xfF85SRogyc5256IeL9Lwah
         Ydjdohki04/OchGJyB3kdmduNfQ+z/4w8ojStbsi1bRvpt5nK+by2Pci+QnPlhG2imrT
         M+Qw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Lf2vtVvi;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x635.google.com (mail-ej1-x635.google.com. [2a00:1450:4864:20::635])
        by gmr-mx.google.com with ESMTPS id k26si612975wrh.6.2022.02.08.03.45.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Feb 2022 03:45:44 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::635 as permitted sender) client-ip=2a00:1450:4864:20::635;
Received: by mail-ej1-x635.google.com with SMTP id a8so51418383ejc.8
        for <kasan-dev@googlegroups.com>; Tue, 08 Feb 2022 03:45:44 -0800 (PST)
X-Received: by 2002:a17:907:6088:: with SMTP id ht8mr3165020ejc.619.1644320744531;
        Tue, 08 Feb 2022 03:45:44 -0800 (PST)
Received: from alco.corp.google.com ([2620:0:1059:10:5d0f:d242:ddbf:a8a6])
        by smtp.gmail.com with ESMTPSA id y2sm4151902edt.54.2022.02.08.03.45.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Feb 2022 03:45:44 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v4 1/6] kunit: Introduce _NULL and _NOT_NULL macros
Date: Tue,  8 Feb 2022 12:45:36 +0100
Message-Id: <20220208114541.2046909-1-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Lf2vtVvi;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::635
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
2.35.0.263.gb82422642f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220208114541.2046909-1-ribalda%40chromium.org.
